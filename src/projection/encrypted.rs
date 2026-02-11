use rusqlite::Connection;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

use crate::crypto::event_id_to_base64;
use crate::events::{self, EncryptedEvent, ParsedEvent, EVENT_TYPE_ENCRYPTED};
use super::decision::ProjectionDecision;
use super::projectors::{project_message, project_message_attachment, project_message_deletion, project_file_slice, project_reaction, project_secret_key, project_signed_memo};
use super::signer::{resolve_signer_key, verify_ed25519_signature, SignerResolution};

/// Project an encrypted event: decrypt, parse inner, check inner deps, dispatch to inner projector.
/// Returns Valid, Block, or Reject.
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

    // 6. Check inner deps via valid_events (tenant-scoped)
    let inner_deps = inner_parsed.dep_field_values();
    let mut missing = Vec::new();
    for (_field_name, dep_id) in &inner_deps {
        let dep_b64 = event_id_to_base64(dep_id);
        let dep_valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &dep_b64],
            |row| row.get(0),
        )?;
        if !dep_valid {
            missing.push(*dep_id);
        }
    }

    if !missing.is_empty() {
        // Write blocked_event_deps using OUTER event_id
        for dep_id in &missing {
            let dep_b64 = event_id_to_base64(dep_id);
            conn.execute(
                "INSERT OR IGNORE INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![recorded_by, event_id_b64, &dep_b64],
            )?;
        }
        return Ok(ProjectionDecision::Block { missing });
    }

    // 7. If inner type has signer_required: verify signer
    let inner_meta = events::registry().lookup(inner_parsed.event_type_code())
        .ok_or_else(|| format!("unknown inner type code {}", inner_parsed.event_type_code()))?;

    if inner_meta.signer_required {
        let (signer_event_id, signer_type) = inner_parsed.signer_fields()
            .ok_or("inner type signer_required but no signer_fields")?;
        let resolution = resolve_signer_key(conn, recorded_by, signer_type, &signer_event_id)?;
        match resolution {
            SignerResolution::NotFound => {
                return Ok(ProjectionDecision::Reject {
                    reason: "inner event signer key not found".to_string(),
                });
            }
            SignerResolution::Invalid(msg) => {
                return Ok(ProjectionDecision::Reject {
                    reason: format!("inner event signer resolution invalid: {}", msg),
                });
            }
            SignerResolution::Found(key) => {
                let sig_len = inner_meta.signature_byte_len;
                if plaintext.len() < sig_len {
                    return Ok(ProjectionDecision::Reject {
                        reason: "inner blob too short for signature".to_string(),
                    });
                }
                let signing_bytes = &plaintext[..plaintext.len() - sig_len];
                let sig_bytes = &plaintext[plaintext.len() - sig_len..];
                if !verify_ed25519_signature(&key, signing_bytes, sig_bytes) {
                    return Ok(ProjectionDecision::Reject {
                        reason: "inner event invalid signature".to_string(),
                    });
                }
            }
        }
    }

    // 8. Dispatch to inner projector
    match &inner_parsed {
        ParsedEvent::Message(msg) => {
            project_message(conn, recorded_by, event_id_b64, msg)?;
        }
        ParsedEvent::Reaction(rxn) => {
            project_reaction(conn, recorded_by, event_id_b64, rxn)?;
        }
        ParsedEvent::PeerKey(_) => {
            return Ok(ProjectionDecision::Reject {
                reason: "peer_key events are deprecated; use peer_shared signer chain".to_string(),
            });
        }
        ParsedEvent::SignedMemo(memo) => {
            project_signed_memo(conn, recorded_by, event_id_b64, memo)?;
        }
        ParsedEvent::SecretKey(sk) => {
            project_secret_key(conn, recorded_by, event_id_b64, sk)?;
        }
        ParsedEvent::MessageDeletion(del) => {
            return project_message_deletion(conn, recorded_by, event_id_b64, del);
        }
        ParsedEvent::MessageAttachment(att) => {
            project_message_attachment(conn, recorded_by, event_id_b64, att)?;
        }
        ParsedEvent::FileSlice(fs) => {
            return Ok(project_file_slice(conn, recorded_by, event_id_b64, fs)?);
        }
        ParsedEvent::Encrypted(_) => {
            // Already rejected above (nested encryption)
            unreachable!();
        }
        // Identity events cannot appear inside encrypted wrappers
        ParsedEvent::Workspace(_)
        | ParsedEvent::InviteAccepted(_)
        | ParsedEvent::UserInviteBoot(_)
        | ParsedEvent::UserInviteOngoing(_)
        | ParsedEvent::DeviceInviteFirst(_)
        | ParsedEvent::DeviceInviteOngoing(_)
        | ParsedEvent::UserBoot(_)
        | ParsedEvent::UserOngoing(_)
        | ParsedEvent::PeerSharedFirst(_)
        | ParsedEvent::PeerSharedOngoing(_)
        | ParsedEvent::AdminBoot(_)
        | ParsedEvent::AdminOngoing(_)
        | ParsedEvent::UserRemoved(_)
        | ParsedEvent::PeerRemoved(_)
        | ParsedEvent::SecretShared(_)
        | ParsedEvent::TransportKey(_)
        | ParsedEvent::BenchDep(_) => {
            return Ok(ProjectionDecision::Reject {
                reason: "identity events cannot appear inside encrypted wrappers".to_string(),
            });
        }
    }

    // 9. Return Valid
    Ok(ProjectionDecision::Valid)
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
