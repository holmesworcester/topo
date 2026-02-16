use rusqlite::Connection;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

use crate::crypto::event_id_to_base64;
use crate::events::{self, EncryptedEvent, EVENT_TYPE_ENCRYPTED};
use super::decision::ProjectionDecision;
use super::pipeline::{apply_projection, check_deps_and_block};

/// Admissible inner event type codes for encrypted wrappers.
/// Identity events, encrypted (nested), and bench_dep are not permitted.
const ADMISSIBLE_INNER_TYPES: &[u8] = &[
    1,  // message
    2,  // reaction
    4,  // signed_memo
    6,  // secret_key
    7,  // message_deletion
    24, // message_attachment
    25, // file_slice
];

/// Project an encrypted event: decrypt, parse inner, verify admissibility,
/// then hand off to shared pipeline stages (dep check, dep type check,
/// signer verify, projector dispatch).
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

    // 6. Reject disallowed inner families (identity events, bench_dep)
    if !ADMISSIBLE_INNER_TYPES.contains(&inner_parsed.event_type_code()) {
        return Ok(ProjectionDecision::Reject {
            reason: "identity events cannot appear inside encrypted wrappers".to_string(),
        });
    }

    // --- Shared pipeline stages (using outer event_id for block/reject anchoring) ---

    // 7. Check inner dep presence (block rows keyed to outer event_id)
    let inner_deps = inner_parsed.dep_field_values();
    if let Some(block) = check_deps_and_block(conn, recorded_by, event_id_b64, &inner_deps)? {
        return Ok(block);
    }

    // Note: dep type checking is intentionally NOT applied to inner events.
    // Inner deps may target encrypted wrapper events (type 5) rather than the
    // raw inner type code expected by the registry. For example, an encrypted
    // deletion's target_event_id points to an encrypted message wrapper (type 5),
    // not a raw message (type 1). The dep type check is designed for cleartext
    // events where dep targets have their actual type codes in the events table.

    // 8. Signer verification + projector dispatch (shared stage).
    //    Passes decrypted plaintext as the signing bytes source.
    apply_projection(conn, recorded_by, event_id_b64, &plaintext, &inner_parsed)
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
