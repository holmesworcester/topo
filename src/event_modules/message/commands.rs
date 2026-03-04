use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::EventId;
use crate::event_modules::file_slice::{FILE_SLICE_CIPHERTEXT_BYTES, FILE_SLICE_PLAINTEXT_BYTES};
use crate::projection::create::create_encrypted_event_synchronous;
use crate::projection::create::create_event_synchronous;
use crate::projection::create::create_signed_event_synchronous;
use crate::service::open_db_for_peer;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::super::message_deletion::MessageDeletionEvent;
use super::super::peer_shared;
use super::super::workspace;
use super::super::{FileSliceEvent, MessageAttachmentEvent, SecretKeyEvent};
use super::super::ParsedEvent;
use super::wire::MessageEvent;

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Resolve the workspace content key for content encryption.
/// Ensures a content key exists (creates one if needed) and returns its event_id.
fn resolve_content_key(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by, signing_key, signer_eid)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub target: String,
}

pub struct CreateMessageCmd {
    pub workspace_id: [u8; 32],
    pub author_id: [u8; 32],
    pub content: String,
}

/// Create an encrypted message event. The inner message is signed and then
/// wrapped in an `encrypted` event using the workspace content key.
pub fn create(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateMessageCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let key_event_id = resolve_content_key(db, recorded_by, signer_eid, signing_key)?;
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms,
        workspace_id: cmd.workspace_id,
        author_id: cmd.author_id,
        content: cmd.content,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_encrypted_event_synchronous(
        db,
        recorded_by,
        &key_event_id,
        &msg,
        Some(signing_key),
    )?;
    Ok(eid)
}

/// High-level send command: creates an encrypted message event and returns a SendResponse.
pub fn send(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    workspace_id: [u8; 32],
    author_id: [u8; 32],
    content: &str,
) -> Result<super::SendResponse, String> {
    let eid = create(
        db,
        recorded_by,
        signer_eid,
        signing_key,
        created_at_ms,
        CreateMessageCmd {
            workspace_id,
            author_id,
            content: content.to_string(),
        },
    )
    .map_err(|e| format!("{}", e))?;

    Ok(super::SendResponse {
        content: content.to_string(),
        event_id: hex::encode(eid),
    })
}

// ---------------------------------------------------------------------------
// Message deletion commands
// ---------------------------------------------------------------------------

pub struct CreateMessageDeletionCmd {
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
}

/// Create an encrypted message deletion event.
pub fn create_deletion(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateMessageDeletionCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let key_event_id = resolve_content_key(db, recorded_by, signer_eid, signing_key)?;
    let del = ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms,
        target_event_id: cmd.target_event_id,
        author_id: cmd.author_id,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_encrypted_event_synchronous(
        db,
        recorded_by,
        &key_event_id,
        &del,
        Some(signing_key),
    )?;
    Ok(eid)
}

/// High-level delete command: creates an encrypted message_deletion event.
pub fn delete_message(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    author_id: [u8; 32],
    target_event_id: [u8; 32],
) -> Result<String, String> {
    create_deletion(
        db,
        recorded_by,
        signer_eid,
        signing_key,
        created_at_ms,
        CreateMessageDeletionCmd {
            target_event_id,
            author_id,
        },
    )
    .map_err(|e| format!("{}", e))?;

    Ok(hex::encode(target_event_id))
}

// ---------------------------------------------------------------------------
// Peer-level command wrappers
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateResponse {
    pub count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateFilesResponse {
    pub files: usize,
    pub file_size_mib: usize,
    pub slices_per_file: usize,
    pub total_slices: usize,
}

fn slices_for_file_size_mib(file_size_mib: usize) -> Result<usize, String> {
    if file_size_mib == 0 {
        return Err("file_size_mib must be >= 1".to_string());
    }
    let file_size_bytes = file_size_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "file_size_mib overflow".to_string())?;
    // Chunk by plaintext capacity (ciphertext - GCM tag)
    Ok(file_size_bytes.div_ceil(FILE_SLICE_PLAINTEXT_BYTES))
}

/// Send a message as a specific peer (daemon provides the peer_id).
pub fn send_for_peer(
    db_path: &str,
    peer_id: &str,
    content: &str,
) -> Result<super::SendResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    let (signer_eid, signing_key) =
        peer_shared::load_local_peer_signer_required(&db, &recorded_by)?;
    let workspace_id = workspace::resolve_workspace_for_peer(&db, &recorded_by)?;
    let author_id = peer_shared::resolve_user_event_id(&db, &recorded_by, &signer_eid)?;

    send(
        &db,
        &recorded_by,
        &signer_eid,
        &signing_key,
        current_timestamp_ms(),
        workspace_id,
        author_id,
        content,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })
}

/// Delete a message as a specific peer.
pub fn delete_message_for_peer(
    db_path: &str,
    peer_id: &str,
    target_hex: &str,
) -> Result<DeleteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    let (signer_eid, signing_key) =
        peer_shared::load_local_peer_signer_required(&db, &recorded_by)?;
    let target_event_id = super::resolve(&db, &recorded_by, target_hex)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    let author_id = peer_shared::resolve_user_event_id(&db, &recorded_by, &signer_eid)?;

    let target = delete_message(
        &db,
        &recorded_by,
        &signer_eid,
        &signing_key,
        current_timestamp_ms(),
        author_id,
        target_event_id,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    Ok(DeleteResponse { target })
}

/// Generate N test messages as a specific peer.
pub fn generate_for_peer(
    db_path: &str,
    peer_id: &str,
    count: usize,
) -> Result<GenerateResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    let (signer_eid, signing_key) =
        peer_shared::load_local_peer_signer_required(&db, &recorded_by)?;
    let workspace_id = workspace::resolve_workspace_for_peer(&db, &recorded_by)?;
    let author_id = peer_shared::resolve_user_event_id(&db, &recorded_by, &signer_eid)?;

    db.execute("BEGIN", [])?;
    for i in 0..count {
        create(
            &db,
            &recorded_by,
            &signer_eid,
            &signing_key,
            current_timestamp_ms(),
            CreateMessageCmd {
                workspace_id,
                author_id,
                content: format!("Message {}", i),
            },
        )
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("create event error: {}", e).into()
        })?;
    }
    db.execute("COMMIT", [])?;

    Ok(GenerateResponse { count })
}

/// Generate N synthetic files as a specific peer.
///
/// Each generated file creates:
/// - 1 parent `message` (encrypted wrapper with workspace content key)
/// - 1 per-attachment `secret_key` (local, unique per attachment)
/// - 1 `message_attachment` (encrypted wrapper with workspace content key)
/// - `slices_per_file` `file_slice` events (signed, ciphertext encrypted with attachment key)
pub fn generate_files_for_peer(
    db_path: &str,
    peer_id: &str,
    files: usize,
    file_size_mib: usize,
) -> Result<GenerateFilesResponse, Box<dyn std::error::Error + Send + Sync>> {
    let slices_per_file =
        slices_for_file_size_mib(file_size_mib).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    let total_slices = files
        .checked_mul(slices_per_file)
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "total_slices overflow".into()
        })?;

    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let (signer_eid, signing_key) =
        peer_shared::load_local_peer_signer_required(&db, &recorded_by)?;
    let workspace_id = workspace::resolve_workspace_for_peer(&db, &recorded_by)?;
    let author_id = peer_shared::resolve_user_event_id(&db, &recorded_by, &signer_eid)?;
    let content_key_eid = resolve_content_key(&db, &recorded_by, &signer_eid, &signing_key)?;
    db.execute("BEGIN", [])?;
    for i in 0..files {
        // Encrypted parent message (workspace content key)
        let message_event_id = create(
            &db,
            &recorded_by,
            &signer_eid,
            &signing_key,
            current_timestamp_ms(),
            CreateMessageCmd {
                workspace_id,
                author_id,
                content: format!("File {}", i),
            },
        )
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("create parent message error: {}", e).into()
        })?;

        // Per-attachment secret key (unique per attachment, never reused)
        let file_key_bytes: [u8; 32] = rand::random();
        let file_key_event_id = create_event_synchronous(
            &db,
            &recorded_by,
            &ParsedEvent::SecretKey(SecretKeyEvent {
                created_at_ms: current_timestamp_ms(),
                key_bytes: file_key_bytes,
            }),
        )
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("create secret_key error: {}", e).into()
        })?;

        // Wrap attachment key for all workspace peers via SecretShared events.
        workspace::identity_ops::wrap_attachment_key_for_peers(
            &db, &recorded_by, &signing_key, &signer_eid,
            &file_key_event_id, &file_key_bytes,
        ).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("wrap attachment key error: {}", e).into()
        })?;

        let file_id = rand::random::<[u8; 32]>();
        let blob_bytes = (slices_per_file as u64)
            .checked_mul(FILE_SLICE_PLAINTEXT_BYTES as u64)
            .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                "blob_bytes overflow".into()
            })?;

        // Encrypted message_attachment metadata (workspace content key)
        let attachment_inner = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
            created_at_ms: current_timestamp_ms(),
            message_id: message_event_id,
            file_id,
            blob_bytes,
            total_slices: slices_per_file as u32,
            slice_bytes: FILE_SLICE_CIPHERTEXT_BYTES as u32,
            root_hash: [0xAA; 32],
            key_event_id: file_key_event_id,
            filename: format!("file-{}.bin", i),
            mime_type: "application/octet-stream".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        create_encrypted_event_synchronous(
            &db,
            &recorded_by,
            &content_key_eid,
            &attachment_inner,
            Some(&signing_key),
        )
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("create message_attachment error: {}", e).into()
        })?;

        // File slices: ciphertext encrypted directly with per-attachment key.
        // Slices are signed events (not encrypted wrappers) — the ciphertext field
        // carries real AES-256-GCM encrypted file data using the attachment key.
        for slice_number in 0..slices_per_file {
            let plaintext_chunk = vec![0xAB; FILE_SLICE_PLAINTEXT_BYTES];
            let ciphertext =
                encrypt_file_slice(&file_key_bytes, &file_id, slice_number as u32, &plaintext_chunk)?;

            create_signed_event_synchronous(
                &db,
                &recorded_by,
                &ParsedEvent::FileSlice(FileSliceEvent {
                    created_at_ms: current_timestamp_ms(),
                    file_id,
                    slice_number: slice_number as u32,
                    ciphertext,
                    signed_by: signer_eid,
                    signer_type: 5,
                    signature: [0u8; 64],
                }),
                &signing_key,
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("create file_slice error: {}", e).into()
            })?;
        }
    }
    db.execute("COMMIT", [])?;

    Ok(GenerateFilesResponse {
        files,
        file_size_mib,
        slices_per_file,
        total_slices,
    })
}

/// Encrypt a file slice with the attachment key using AES-256-GCM.
///
/// Nonce derivation (deterministic):
///   nonce = Blake2b-96("poc7-file-slice-nonce" || file_id || slice_number_le)
///
/// AAD (additional authenticated data):
///   aad = file_id (32 bytes) || slice_number (4 bytes LE)
///   This cryptographically binds the file_id and slice_number to the ciphertext,
///   preventing an attacker from transplanting ciphertext between different file_id
///   or slice_number values — any such tampering fails AEAD verification.
///
/// Returns ciphertext || auth_tag (AES-GCM appends the 16-byte tag).
///
/// Safety argument for deterministic nonce:
///   The nonce is unique per (key, file_id, slice_number) triple. Since each
///   attachment uses a unique key, and (file_id, slice_number) pairs are unique
///   within a file, no two encrypt calls under the same key share a nonce.
pub fn encrypt_file_slice(
    key: &[u8; 32],
    file_id: &[u8; 32],
    slice_number: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit, Nonce};
    use blake2::digest::consts::U12;
    use blake2::{Blake2b, Digest};

    // Deterministic nonce: Blake2b-96("poc7-file-slice-nonce" || file_id || slice_number_le)
    let mut hasher = Blake2b::<U12>::new();
    hasher.update(b"poc7-file-slice-nonce");
    hasher.update(file_id);
    hasher.update(&slice_number.to_le_bytes());
    let nonce_bytes: [u8; 12] = hasher.finalize().into();

    // AAD: file_id || slice_number_le — binds metadata to ciphertext integrity.
    let mut aad = Vec::with_capacity(36);
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(&slice_number.to_le_bytes());

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("{}", e).into() })?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("{}", e).into() })?;

    Ok(ciphertext)
}

/// Decrypt a file slice with the attachment key using AES-256-GCM.
/// Uses the same deterministic nonce and AAD derivation as `encrypt_file_slice`.
pub fn decrypt_file_slice(
    key: &[u8; 32],
    file_id: &[u8; 32],
    slice_number: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit, Nonce};
    use blake2::digest::consts::U12;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U12>::new();
    hasher.update(b"poc7-file-slice-nonce");
    hasher.update(file_id);
    hasher.update(&slice_number.to_le_bytes());
    let nonce_bytes: [u8; 12] = hasher.finalize().into();

    // AAD must match encryption — file_id || slice_number_le.
    let mut aad = Vec::with_capacity(36);
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(&slice_number.to_le_bytes());

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("{}", e).into() })?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { format!("{}", e).into() })?;

    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// send-file: message + attachment from a real file on disk
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct SendFileResponse {
    pub content: String,
    pub event_id: String,
    pub filename: String,
    pub file_size: u64,
}

fn mime_from_extension(ext: &str) -> &'static str {
    match ext {
        "txt" | "log" | "md" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        _ => "application/octet-stream",
    }
}

/// Send a message with a file attachment as a specific peer.
///
/// Message and attachment metadata → encrypted wrappers (workspace content key).
/// File slices → signed events with ciphertext encrypted directly by attachment key.
pub fn send_file_for_peer(
    db_path: &str,
    peer_id: &str,
    content: &str,
    file_path: &str,
) -> Result<SendFileResponse, Box<dyn std::error::Error + Send + Sync>> {
    let path = Path::new(file_path);
    let file_data = std::fs::read(path)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("failed to read {}: {}", file_path, e).into()
        })?;
    let file_size = file_data.len() as u64;
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let mime_type = mime_from_extension(&ext).to_string();

    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let (signer_eid, signing_key) =
        peer_shared::load_local_peer_signer_required(&db, &recorded_by)?;
    let workspace_id = workspace::resolve_workspace_for_peer(&db, &recorded_by)?;
    let author_id = peer_shared::resolve_user_event_id(&db, &recorded_by, &signer_eid)?;
    let content_key_eid = resolve_content_key(&db, &recorded_by, &signer_eid, &signing_key)?;

    // Encrypted parent message (workspace content key)
    let message_event_id = create(
        &db,
        &recorded_by,
        &signer_eid,
        &signing_key,
        current_timestamp_ms(),
        CreateMessageCmd {
            workspace_id,
            author_id,
            content: content.to_string(),
        },
    )?;

    // Per-attachment secret key (unique, never reused across attachments)
    let file_key_bytes: [u8; 32] = rand::random();
    let file_key_event_id = create_event_synchronous(
        &db,
        &recorded_by,
        &ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: current_timestamp_ms(),
            key_bytes: file_key_bytes,
        }),
    )?;

    // Wrap attachment key for all workspace peers via SecretShared events.
    workspace::identity_ops::wrap_attachment_key_for_peers(
        &db, &recorded_by, &signing_key, &signer_eid,
        &file_key_event_id, &file_key_bytes,
    )?;

    let file_id = rand::random::<[u8; 32]>();
    let num_slices = if file_size == 0 {
        1
    } else {
        (file_size as usize).div_ceil(FILE_SLICE_PLAINTEXT_BYTES)
    };

    // Encrypted message_attachment metadata (workspace content key)
    let attachment_inner = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
        created_at_ms: current_timestamp_ms(),
        message_id: message_event_id,
        file_id,
        blob_bytes: file_size,
        total_slices: num_slices as u32,
        slice_bytes: FILE_SLICE_CIPHERTEXT_BYTES as u32,
        root_hash: [0u8; 32],
        key_event_id: file_key_event_id,
        filename: filename.clone(),
        mime_type,
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    create_encrypted_event_synchronous(
        &db,
        &recorded_by,
        &content_key_eid,
        &attachment_inner,
        Some(&signing_key),
    )?;

    // File slices: ciphertext encrypted directly with per-attachment key.
    for slice_number in 0..num_slices {
        let start = slice_number * FILE_SLICE_PLAINTEXT_BYTES;
        let mut plaintext = vec![0u8; FILE_SLICE_PLAINTEXT_BYTES];
        let end = (start + FILE_SLICE_PLAINTEXT_BYTES).min(file_data.len());
        if start < file_data.len() {
            plaintext[..end - start].copy_from_slice(&file_data[start..end]);
        }

        let ciphertext =
            encrypt_file_slice(&file_key_bytes, &file_id, slice_number as u32, &plaintext)?;

        create_signed_event_synchronous(
            &db,
            &recorded_by,
            &ParsedEvent::FileSlice(FileSliceEvent {
                created_at_ms: current_timestamp_ms(),
                file_id,
                slice_number: slice_number as u32,
                ciphertext,
                signed_by: signer_eid,
                signer_type: 5,
                signature: [0u8; 64],
            }),
            &signing_key,
        )?;
    }

    Ok(SendFileResponse {
        content: content.to_string(),
        event_id: hex::encode(message_event_id),
        filename,
        file_size,
    })
}

#[cfg(test)]
mod file_slice_encryption_tests {
    use super::{decrypt_file_slice, encrypt_file_slice};

    /// SC-7: Round-trip encrypt→decrypt produces original plaintext.
    #[test]
    fn test_round_trip() {
        let key: [u8; 32] = rand::random();
        let file_id: [u8; 32] = rand::random();
        let plaintext = b"hello world file slice content";
        let ct = encrypt_file_slice(&key, &file_id, 0, plaintext).unwrap();
        assert_ne!(&ct[..plaintext.len()], plaintext, "ciphertext must differ from plaintext");
        let pt = decrypt_file_slice(&key, &file_id, 0, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// Determinism: same inputs produce identical ciphertext.
    #[test]
    fn test_deterministic() {
        let key: [u8; 32] = [42u8; 32];
        let file_id: [u8; 32] = [7u8; 32];
        let plaintext = vec![0xAB; 1024];
        let ct1 = encrypt_file_slice(&key, &file_id, 3, &plaintext).unwrap();
        let ct2 = encrypt_file_slice(&key, &file_id, 3, &plaintext).unwrap();
        assert_eq!(ct1, ct2);
    }

    /// Different slice numbers produce different ciphertext (nonce differs).
    #[test]
    fn test_different_slices_differ() {
        let key: [u8; 32] = [42u8; 32];
        let file_id: [u8; 32] = [7u8; 32];
        let plaintext = vec![0xAB; 1024];
        let ct0 = encrypt_file_slice(&key, &file_id, 0, &plaintext).unwrap();
        let ct1 = encrypt_file_slice(&key, &file_id, 1, &plaintext).unwrap();
        assert_ne!(ct0, ct1);
    }

    /// AAD binding: decrypting with wrong file_id fails.
    #[test]
    fn test_wrong_file_id_fails_decrypt() {
        let key: [u8; 32] = rand::random();
        let file_id: [u8; 32] = [1u8; 32];
        let wrong_file_id: [u8; 32] = [2u8; 32];
        let ct = encrypt_file_slice(&key, &file_id, 0, b"data").unwrap();
        // Nonce also changes with file_id, so decrypt should fail.
        let result = decrypt_file_slice(&key, &wrong_file_id, 0, &ct);
        assert!(result.is_err(), "decrypt with wrong file_id must fail");
    }

    /// AAD binding: decrypting with wrong slice_number fails.
    #[test]
    fn test_wrong_slice_number_fails_decrypt() {
        let key: [u8; 32] = rand::random();
        let file_id: [u8; 32] = rand::random();
        let ct = encrypt_file_slice(&key, &file_id, 5, b"data").unwrap();
        let result = decrypt_file_slice(&key, &file_id, 6, &ct);
        assert!(result.is_err(), "decrypt with wrong slice_number must fail");
    }

    /// Wrong key fails decrypt.
    #[test]
    fn test_wrong_key_fails_decrypt() {
        let key: [u8; 32] = [1u8; 32];
        let wrong_key: [u8; 32] = [2u8; 32];
        let file_id: [u8; 32] = rand::random();
        let ct = encrypt_file_slice(&key, &file_id, 0, b"secret").unwrap();
        let result = decrypt_file_slice(&wrong_key, &file_id, 0, &ct);
        assert!(result.is_err(), "decrypt with wrong key must fail");
    }

    /// SC-13: Different attachment keys produce different ciphertext for same content.
    #[test]
    fn test_different_keys_differ() {
        let key1: [u8; 32] = [1u8; 32];
        let key2: [u8; 32] = [2u8; 32];
        let file_id: [u8; 32] = [7u8; 32];
        let plaintext = b"same content";
        let ct1 = encrypt_file_slice(&key1, &file_id, 0, plaintext).unwrap();
        let ct2 = encrypt_file_slice(&key2, &file_id, 0, plaintext).unwrap();
        assert_ne!(ct1, ct2);
    }
}
