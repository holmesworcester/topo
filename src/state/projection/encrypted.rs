use rusqlite::Connection;

use super::apply::run_dep_and_projection_stages;
use super::decision::ProjectionDecision;
use crate::crypto::event_id_to_base64;
pub use crate::crypto::{
    decrypt_event_blob, encrypt_event_blob, unwrap_key_from_sender, wrap_key_for_recipient,
};
use crate::event_modules::{self as events, EncryptedEvent, ParsedEvent, EVENT_TYPE_ENCRYPTED};

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
) -> Result<(ProjectionDecision, Option<ParsedEvent>), Box<dyn std::error::Error>> {
    use topo_verus_proofs::state::projection::encrypted::{
        decide_encrypted_decryption_core, EncryptedDecryptionCore, EncryptedDecryptionFlags,
    };

    // --- Extract every primitive flag the verified decision depends on.
    // This runs every upstream query/operation, captures the outcomes, and
    // then hands the booleans to the verified decider. Real state in; real
    // outcomes observed; verified decision binds which action the runtime
    // takes.
    let key_bytes_opt: Option<Vec<u8>> = match conn.query_row(
        "SELECT key_bytes FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, event_id_to_base64(&enc.key_event_id)],
        |row| crate::db::sql_types::get_blob(row, 0),
    ) {
        Ok(k) => Some(k),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };
    let key_bytes_present = key_bytes_opt.is_some();
    let key_bytes_length_valid = key_bytes_opt.as_ref().map(|k| k.len() == 32).unwrap_or(false);

    // Decryption only runs if key present and right length. We eagerly run
    // it so we can fill the corresponding flag; if the verified decision
    // says Block, the plaintext is never used.
    let (decryption_succeeded, plaintext_opt) = if key_bytes_present && key_bytes_length_valid {
        let key_bytes = key_bytes_opt.as_ref().expect("checked above");
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key_bytes);
        match decrypt_event_blob(&key_arr, &enc.nonce, &enc.ciphertext, &enc.auth_tag) {
            Ok(pt) => (true, Some(pt)),
            Err(_) => (false, None),
        }
    } else {
        (false, None)
    };

    let inner_parsed_opt = plaintext_opt
        .as_ref()
        .and_then(|pt| events::parse_event(pt).ok());
    let inner_parse_succeeded = inner_parsed_opt.is_some();
    let inner_type_matches_outer_claim = inner_parsed_opt
        .as_ref()
        .map(|p| p.event_type_code() == enc.inner_type_code)
        .unwrap_or(false);
    let inner_type_not_encrypted = enc.inner_type_code != EVENT_TYPE_ENCRYPTED;
    let inner_type_is_encryptable = inner_parsed_opt
        .as_ref()
        .and_then(|p| events::registry().lookup(p.event_type_code()))
        .map(|m| m.encryptable)
        .unwrap_or(false);

    let flags = EncryptedDecryptionFlags {
        key_bytes_present,
        key_bytes_length_valid,
        decryption_succeeded,
        inner_parse_succeeded,
        inner_type_matches_outer_claim,
        inner_type_not_encrypted,
        inner_type_is_encryptable,
    };

    // --- Delegate the decision to the verified core.
    match decide_encrypted_decryption_core(flags) {
        EncryptedDecryptionCore::BlockOnMissingKeySecret => {
            return Ok((
                ProjectionDecision::BlockOnMissingDeps { missing: Vec::new() },
                None,
            ));
        }
        EncryptedDecryptionCore::RejectKeyWrongLength => {
            let len = key_bytes_opt.as_ref().map(|k| k.len()).unwrap_or(0);
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!("secret key has wrong length: {}", len),
                },
                None,
            ));
        }
        EncryptedDecryptionCore::RejectDecryptionFailed => {
            return Ok((
                ProjectionDecision::Reject {
                    reason: "decryption failed (wrong key or corrupted)".to_string(),
                },
                None,
            ));
        }
        EncryptedDecryptionCore::RejectInnerParseFailed => {
            // Re-run parse to get the specific error message (the flag was
            // computed with the same input, so this will fail identically).
            let err = plaintext_opt
                .as_ref()
                .and_then(|pt| events::parse_event(pt).err())
                .map(|e| format!("{}", e))
                .unwrap_or_else(|| "unknown parse error".to_string());
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!("inner event parse error: {}", err),
                },
                None,
            ));
        }
        EncryptedDecryptionCore::RejectInnerTypeMismatch => {
            let actual = inner_parsed_opt.as_ref().map(|p| p.event_type_code()).unwrap_or(0);
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!(
                        "inner type mismatch: outer declares {}, inner is {}",
                        enc.inner_type_code, actual,
                    ),
                },
                None,
            ));
        }
        EncryptedDecryptionCore::RejectNestedEncryption => {
            return Ok((
                ProjectionDecision::Reject {
                    reason: "nested encryption not allowed".to_string(),
                },
                None,
            ));
        }
        EncryptedDecryptionCore::RejectInnerNotEncryptable => {
            let code = inner_parsed_opt
                .as_ref()
                .map(|p| p.event_type_code())
                .unwrap_or(0);
            return Ok((
                ProjectionDecision::Reject {
                    reason: format!(
                        "event type {} is not admissible inside encrypted wrappers",
                        code,
                    ),
                },
                None,
            ));
        }
        EncryptedDecryptionCore::ProceedToDecryptAndProject => {}
    }

    // --- Verified Proceed: all gates passed. Unwrap the computed values.
    let plaintext = plaintext_opt.expect("verified Proceed requires plaintext");
    let inner_parsed = inner_parsed_opt.expect("verified Proceed requires parsed inner");

    // Shared dep/signer/projection stages (outer event_id anchors block/reject rows).
    // Dep type checking now uses tenant-scoped valid_events.semantic_type_code,
    // so encrypted deps are validated by semantic inner type rather than outer
    // wrapper type code.
    let transport_key_event_id_b64 = event_id_to_base64(&enc.key_event_id);
    let (decision, _, _) = run_dep_and_projection_stages(
        conn,
        recorded_by,
        event_id_b64,
        &plaintext,
        &inner_parsed,
        true,
        true,
        Some(&transport_key_event_id_b64),
    )?;

    // Return the inner parsed event so the caller (project_one_step) can fire
    // the subscription hook after the valid_events write, avoiding duplicate
    // delivery on projection retry.
    let inner = if matches!(decision, ProjectionDecision::Valid) {
        Some(inner_parsed)
    } else {
        None
    };

    Ok((decision, inner))
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
