use rusqlite::Connection;

use super::apply::run_dep_and_projection_stages;
use super::decision::ProjectionDecision;
use crate::crypto::event_id_to_base64;
pub use crate::crypto::{
    decrypt_event_blob, encrypt_event_blob, unwrap_key_from_sender, wrap_key_for_recipient,
};
use crate::event_modules::{self as events, EncryptedEvent, EVENT_TYPE_ENCRYPTED};

/// Project an encrypted event: decrypt, parse inner, verify admissibility,
/// then hand off to shared pipeline stages (dep check, signer verify,
/// projector dispatch).
///
/// Wrapper-specific concerns handled here:
///   1. Secret-key resolve and decrypt
///   2. inner_type_code consistency check
///   3. Nested-encrypted prohibition
///   4. Admissible-inner-family check
///
/// Block/reject/valid state is anchored to the outer encrypted `event_id_b64`.
pub fn project_encrypted(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    enc: &EncryptedEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    // 1. Resolve key from secret_keys table
    let key_bytes: Vec<u8> = match conn.query_row(
        "SELECT key_bytes FROM secret_keys WHERE recorded_by = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, event_id_to_base64(&enc.key_event_id)],
        |row| row.get(0),
    ) {
        Ok(k) => k,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok(ProjectionDecision::Reject {
                reason: "secret key not found in secret_keys table".to_string(),
            });
        }
        Err(e) => return Err(e.into()),
    };

    if key_bytes.len() != 32 {
        return Ok(ProjectionDecision::Reject {
            reason: format!("secret key has wrong length: {}", key_bytes.len()),
        });
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    // 2. Decrypt
    let plaintext = match decrypt_event_blob(&key_arr, &enc.nonce, &enc.ciphertext, &enc.auth_tag) {
        Ok(pt) => pt,
        Err(_) => {
            return Ok(ProjectionDecision::Reject {
                reason: "decryption failed (wrong key or corrupted)".to_string(),
            });
        }
    };

    // 3. Parse inner event
    let inner_parsed = match events::parse_event(&plaintext) {
        Ok(p) => p,
        Err(e) => {
            return Ok(ProjectionDecision::Reject {
                reason: format!("inner event parse error: {}", e),
            });
        }
    };

    // 4. Verify inner type matches inner_type_code
    if inner_parsed.event_type_code() != enc.inner_type_code {
        return Ok(ProjectionDecision::Reject {
            reason: format!(
                "inner type mismatch: outer declares {}, inner is {}",
                enc.inner_type_code,
                inner_parsed.event_type_code()
            ),
        });
    }

    // 5. Reject nested encryption
    if enc.inner_type_code == EVENT_TYPE_ENCRYPTED {
        return Ok(ProjectionDecision::Reject {
            reason: "nested encryption not allowed".to_string(),
        });
    }

    // 6. Reject disallowed inner families via registry metadata
    let inner_code = inner_parsed.event_type_code();
    let inner_meta = events::registry().lookup(inner_code);
    match inner_meta {
        Some(m) if m.encryptable => {}
        _ => {
            return Ok(ProjectionDecision::Reject {
                reason: format!(
                    "event type {} is not admissible inside encrypted wrappers",
                    inner_code
                ),
            });
        }
    }

    // Shared dep/signer/projection stages (outer event_id anchors block/reject rows).
    // Dep type checking remains disabled for decrypted inners because their deps may
    // intentionally target encrypted wrapper type-codes.
    run_dep_and_projection_stages(
        conn,
        recorded_by,
        event_id_b64,
        &plaintext,
        &inner_parsed,
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let mut rng = rand::thread_rng();
        let sender_key = SigningKey::generate(&mut rng);
        let recipient_key = SigningKey::generate(&mut rng);

        let plaintext_key = [0x42u8; 32];

        let wrapped =
            wrap_key_for_recipient(&sender_key, &recipient_key.verifying_key(), &plaintext_key);

        // Wrapped key should differ from plaintext
        assert_ne!(wrapped, plaintext_key);

        let unwrapped =
            unwrap_key_from_sender(&recipient_key, &sender_key.verifying_key(), &wrapped);

        assert_eq!(unwrapped, plaintext_key);
    }

    #[test]
    fn test_wrap_wrong_recipient_fails() {
        let mut rng = rand::thread_rng();
        let sender_key = SigningKey::generate(&mut rng);
        let recipient_key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng);

        let plaintext_key = [0xAB; 32];

        let wrapped =
            wrap_key_for_recipient(&sender_key, &recipient_key.verifying_key(), &plaintext_key);

        // Wrong recipient cannot unwrap
        let bad_unwrap = unwrap_key_from_sender(&wrong_key, &sender_key.verifying_key(), &wrapped);
        assert_ne!(bad_unwrap, plaintext_key);
    }

    #[test]
    fn test_wrap_different_keys_produce_different_wrapped() {
        let mut rng = rand::thread_rng();
        let sender_key = SigningKey::generate(&mut rng);
        let recipient_key = SigningKey::generate(&mut rng);

        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];

        let wrapped_a = wrap_key_for_recipient(&sender_key, &recipient_key.verifying_key(), &key_a);
        let wrapped_b = wrap_key_for_recipient(&sender_key, &recipient_key.verifying_key(), &key_b);

        assert_ne!(wrapped_a, wrapped_b);
    }

    #[test]
    fn test_encrypt_decrypt_event_blob_roundtrip() {
        let key = [0xCC; 32];
        let plaintext = b"hello world, this is a test payload!";

        let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key, plaintext).unwrap();
        let decrypted = decrypt_event_blob(&key, &nonce, &ciphertext, &auth_tag).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
