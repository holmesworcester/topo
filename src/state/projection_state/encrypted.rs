use rusqlite::Connection;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

use crate::crypto::event_id_to_base64;
use crate::event_modules::{self as events, EncryptedEvent, EVENT_TYPE_ENCRYPTED};
use super::decision::ProjectionDecision;
use super::apply::run_dep_and_projection_stages;

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

    // 2. Decrypt: AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&key_arr)
        .map_err(|e| format!("aes-gcm key init: {}", e))?;
    let nonce = Nonce::from_slice(&enc.nonce);

    // Combine ciphertext + auth_tag for aes-gcm crate (it expects tag appended)
    let mut ct_with_tag = Vec::with_capacity(enc.ciphertext.len() + 16);
    ct_with_tag.extend_from_slice(&enc.ciphertext);
    ct_with_tag.extend_from_slice(&enc.auth_tag);

    let plaintext = match cipher.decrypt(nonce, ct_with_tag.as_slice()) {
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

/// Encrypt a plaintext blob using AES-256-GCM with a random nonce.
/// Returns (nonce, ciphertext, auth_tag).
pub fn encrypt_event_blob(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<([u8; 12], Vec<u8>, [u8; 16]), Box<dyn std::error::Error>> {
    use rand::RngCore;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("aes-gcm key init: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("aes-gcm encrypt: {}", e))?;

    // aes-gcm appends the 16-byte tag to the ciphertext
    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);

    Ok((nonce_bytes, ciphertext, auth_tag))
}

// ─── Key-wrap/unwrap for invite bootstrap ───
//
// At invite creation the inviter wraps a content secret key for the invitee's
// invite public key using AES-256-GCM keyed by a shared secret derived from
// X25519(invite_private, recipient_public).
//
// At invite acceptance the joiner unwraps using X25519(invite_private, sender_public).
//
// This reuses the existing SecretSharedEvent wire format: the `wrapped_key`
// field (32 bytes) holds the AES-256-GCM ciphertext of the 32-byte symmetric key.
// The 12-byte nonce is deterministically derived from key_event_id so that
// wrap/unwrap are stateless (no separate nonce field needed in SecretShared).

use ed25519_dalek::{SigningKey, VerifyingKey};

/// Derive a 32-byte shared wrap key from a local Ed25519 private key and
/// a remote Ed25519 public key via X25519 Diffie-Hellman.
///
/// Converts Ed25519 keys to X25519 (Montgomery form), performs DH,
/// and hashes the shared point with BLAKE2b-256 for domain separation.
/// Both sender and recipient derive the same key from their own private
/// key and the other's public key.
fn derive_wrap_key(
    local_private: &SigningKey,
    remote_public: &VerifyingKey,
) -> [u8; 32] {
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    // Convert Ed25519 keys to X25519 (Montgomery form)
    let local_scalar = local_private.to_scalar();
    let remote_point = remote_public.to_montgomery();

    // X25519 DH: shared_point = local_scalar * remote_montgomery_point
    let shared_point = &remote_point * &local_scalar;

    // Hash to uniform 32-byte key with domain separation
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"poc7-key-wrap-v1");
    hasher.update(shared_point.as_bytes());
    let hash = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

/// Wrap a 32-byte secret key for a recipient identified by their Ed25519 public key.
///
/// Simplified wrap for POC: XOR plaintext key with a derived wrap key.
/// Authentication is provided by the SecretShared event signature.
pub fn wrap_key_for_recipient(
    sender_private: &SigningKey,
    recipient_public: &VerifyingKey,
    plaintext_key: &[u8; 32],
) -> [u8; 32] {
    let wrap_key = derive_wrap_key(sender_private, recipient_public);
    let mut wrapped = [0u8; 32];
    for i in 0..32 {
        wrapped[i] = plaintext_key[i] ^ wrap_key[i];
    }
    wrapped
}

/// Unwrap a 32-byte wrapped key using the recipient's private key and sender's public key.
///
/// Mirror of `wrap_key_for_recipient`: derives the same wrap key and XORs
/// to recover the plaintext key.
pub fn unwrap_key_from_sender(
    recipient_private: &SigningKey,
    sender_public: &VerifyingKey,
    wrapped_key: &[u8; 32],
) -> [u8; 32] {
    let wrap_key = derive_wrap_key(recipient_private, sender_public);
    let mut plaintext = [0u8; 32];
    for i in 0..32 {
        plaintext[i] = wrapped_key[i] ^ wrap_key[i];
    }
    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let mut rng = rand::thread_rng();
        let sender_key = SigningKey::generate(&mut rng);
        let recipient_key = SigningKey::generate(&mut rng);

        let plaintext_key = [0x42u8; 32];

        let wrapped = wrap_key_for_recipient(
            &sender_key,
            &recipient_key.verifying_key(),
            &plaintext_key,
        );

        // Wrapped key should differ from plaintext
        assert_ne!(wrapped, plaintext_key);

        let unwrapped = unwrap_key_from_sender(
            &recipient_key,
            &sender_key.verifying_key(),
            &wrapped,
        );

        assert_eq!(unwrapped, plaintext_key);
    }

    #[test]
    fn test_wrap_wrong_recipient_fails() {
        let mut rng = rand::thread_rng();
        let sender_key = SigningKey::generate(&mut rng);
        let recipient_key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng);

        let plaintext_key = [0xAB; 32];

        let wrapped = wrap_key_for_recipient(
            &sender_key,
            &recipient_key.verifying_key(),
            &plaintext_key,
        );

        // Wrong recipient cannot unwrap
        let bad_unwrap = unwrap_key_from_sender(
            &wrong_key,
            &sender_key.verifying_key(),
            &wrapped,
        );
        assert_ne!(bad_unwrap, plaintext_key);
    }

    #[test]
    fn test_wrap_different_keys_produce_different_wrapped() {
        let mut rng = rand::thread_rng();
        let sender_key = SigningKey::generate(&mut rng);
        let recipient_key = SigningKey::generate(&mut rng);

        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];

        let wrapped_a = wrap_key_for_recipient(
            &sender_key,
            &recipient_key.verifying_key(),
            &key_a,
        );
        let wrapped_b = wrap_key_for_recipient(
            &sender_key,
            &recipient_key.verifying_key(),
            &key_b,
        );

        assert_ne!(wrapped_a, wrapped_b);
    }

    #[test]
    fn test_encrypt_decrypt_event_blob_roundtrip() {
        let key = [0xCC; 32];
        let plaintext = b"hello world, this is a test payload!";

        let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key, plaintext).unwrap();

        // Decrypt manually
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_obj = Nonce::from_slice(&nonce);
        let mut ct_with_tag = ciphertext.clone();
        ct_with_tag.extend_from_slice(&auth_tag);
        let decrypted = cipher.decrypt(nonce_obj, ct_with_tag.as_slice()).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
