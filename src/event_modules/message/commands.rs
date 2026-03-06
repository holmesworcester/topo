use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::EventId;
use crate::event_modules::file_slice::FILE_SLICE_CIPHERTEXT_BYTES;
use crate::projection::create::create_signed_event_synchronous;
use crate::service::open_db_for_peer;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::super::message_deletion::MessageDeletionEvent;
use super::super::peer_shared;
use super::super::workspace;
use super::super::ParsedEvent;
use super::super::{FileSliceEvent, MessageAttachmentEvent};
use super::wire::MessageEvent;

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
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

pub fn create(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateMessageCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms,
        workspace_id: cmd.workspace_id,
        author_id: cmd.author_id,
        content: cmd.content,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_synchronous(db, recorded_by, &msg, signing_key)?;
    Ok(eid)
}

/// High-level send command: creates a message event and returns a SendResponse.
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
// Message deletion commands (moved from message_deletion/commands.rs)
// ---------------------------------------------------------------------------

pub struct CreateMessageDeletionCmd {
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
}

pub fn create_deletion(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateMessageDeletionCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let del = ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms,
        target_event_id: cmd.target_event_id,
        author_id: cmd.author_id,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_synchronous(db, recorded_by, &del, signing_key)?;
    Ok(eid)
}

/// High-level delete command: creates a message_deletion event and returns target hex.
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
// Peer-level command wrappers (moved from service.rs)
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
    Ok(file_size_bytes.div_ceil(FILE_SLICE_CIPHERTEXT_BYTES))
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
/// - 1 parent `message`
/// - 1 `key_secret`
/// - 1 `message_attachment`
/// - `slices_per_file` `file_slice` events
pub fn generate_files_for_peer(
    db_path: &str,
    peer_id: &str,
    files: usize,
    file_size_mib: usize,
) -> Result<GenerateFilesResponse, Box<dyn std::error::Error + Send + Sync>> {
    let slices_per_file = slices_for_file_size_mib(file_size_mib)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    let total_slices = files.checked_mul(slices_per_file).ok_or_else(
        || -> Box<dyn std::error::Error + Send + Sync> { "total_slices overflow".into() },
    )?;

    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let (signer_eid, signing_key) =
        peer_shared::load_local_peer_signer_required(&db, &recorded_by)?;
    let workspace_id = workspace::resolve_workspace_for_peer(&db, &recorded_by)?;
    let author_id = peer_shared::resolve_user_event_id(&db, &recorded_by, &signer_eid)?;
    let slice_bytes_u32 = FILE_SLICE_CIPHERTEXT_BYTES as u32;
    let ciphertext: Vec<u8> = vec![0xAB; FILE_SLICE_CIPHERTEXT_BYTES];

    db.execute("BEGIN", [])?;
    for i in 0..files {
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

        let key_event_id = workspace::identity_ops::ensure_content_key_for_peer(&db, &recorded_by)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("resolve content key error: {}", e).into()
            })?;

        let file_id = rand::random::<[u8; 32]>();
        let blob_bytes = (slices_per_file as u64)
            .checked_mul(FILE_SLICE_CIPHERTEXT_BYTES as u64)
            .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                "blob_bytes overflow".into()
            })?;

        create_signed_event_synchronous(
            &db,
            &recorded_by,
            &ParsedEvent::MessageAttachment(MessageAttachmentEvent {
                created_at_ms: current_timestamp_ms(),
                message_id: message_event_id,
                file_id,
                blob_bytes,
                total_slices: slices_per_file as u32,
                slice_bytes: slice_bytes_u32,
                root_hash: [0xAA; 32],
                key_event_id,
                filename: format!("file-{}.bin", i),
                mime_type: "application/octet-stream".to_string(),
                signed_by: signer_eid,
                signer_type: 5,
                signature: [0u8; 64],
            }),
            &signing_key,
        )
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("create message_attachment error: {}", e).into()
        })?;

        for slice_number in 0..slices_per_file {
            create_signed_event_synchronous(
                &db,
                &recorded_by,
                &ParsedEvent::FileSlice(FileSliceEvent {
                    created_at_ms: current_timestamp_ms(),
                    file_id,
                    slice_number: slice_number as u32,
                    ciphertext: ciphertext.clone(),
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
pub fn send_file_for_peer(
    db_path: &str,
    peer_id: &str,
    content: &str,
    file_path: &str,
) -> Result<SendFileResponse, Box<dyn std::error::Error + Send + Sync>> {
    let path = Path::new(file_path);
    let file_data =
        std::fs::read(path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
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

    let key_event_id = workspace::identity_ops::ensure_content_key_for_peer(&db, &recorded_by)?;

    let file_id = rand::random::<[u8; 32]>();
    let num_slices = if file_size == 0 {
        1
    } else {
        (file_size as usize).div_ceil(FILE_SLICE_CIPHERTEXT_BYTES)
    };

    create_signed_event_synchronous(
        &db,
        &recorded_by,
        &ParsedEvent::MessageAttachment(MessageAttachmentEvent {
            created_at_ms: current_timestamp_ms(),
            message_id: message_event_id,
            file_id,
            blob_bytes: file_size,
            total_slices: num_slices as u32,
            slice_bytes: FILE_SLICE_CIPHERTEXT_BYTES as u32,
            root_hash: [0u8; 32],
            key_event_id,
            filename: filename.clone(),
            mime_type,
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        }),
        &signing_key,
    )?;

    for slice_number in 0..num_slices {
        let start = slice_number * FILE_SLICE_CIPHERTEXT_BYTES;
        let mut ciphertext = vec![0u8; FILE_SLICE_CIPHERTEXT_BYTES];
        let end = (start + FILE_SLICE_CIPHERTEXT_BYTES).min(file_data.len());
        if start < file_data.len() {
            ciphertext[..end - start].copy_from_slice(&file_data[start..end]);
        }

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
