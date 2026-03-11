use std::io::{BufReader, Read};
use std::path::Path;
use std::thread;
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::crypto::EventId;
use crate::event_modules::file_slice::FILE_SLICE_CIPHERTEXT_BYTES;
use crate::projection::create::create_encrypted_event_synchronous;
use crate::service::open_db_for_peer;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::super::message_deletion::MessageDeletionEvent;
use super::super::peer_shared;
use super::super::workspace;
use super::super::ParsedEvent;
use super::super::{FileEvent, FileSliceEvent};
use super::wire::MessageEvent;

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn generate_progress_logging_enabled() -> bool {
    std::env::var_os("TOPO_GENERATE_PROGRESS_LOG").is_some()
}

fn begin_immediate_with_retry(
    db: &Connection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const MAX_ATTEMPTS: usize = 8;
    let log_progress = generate_progress_logging_enabled();
    let retry_start = Instant::now();

    for attempt in 0..MAX_ATTEMPTS {
        match db.execute("BEGIN IMMEDIATE", []) {
            Ok(_) => return Ok(()),
            Err(err) => {
                let msg = err.to_string();
                let is_busy = msg.contains("database is locked") || msg.contains("SQLITE_BUSY");
                if is_busy && attempt + 1 < MAX_ATTEMPTS {
                    let backoff_ms = 25u64 << attempt;
                    if log_progress {
                        eprintln!(
                            "[generate] BEGIN IMMEDIATE busy attempt={} elapsed_ms={} backoff_ms={} err={}",
                            attempt + 1,
                            retry_start.elapsed().as_millis(),
                            backoff_ms,
                            msg
                        );
                    }
                    thread::sleep(Duration::from_millis(backoff_ms));
                    continue;
                }
                if log_progress {
                    eprintln!(
                        "[generate] BEGIN IMMEDIATE failed attempts={} elapsed_ms={} err={}",
                        attempt + 1,
                        retry_start.elapsed().as_millis(),
                        msg
                    );
                }
                return Err(err.into());
            }
        }
    }

    Err("BEGIN IMMEDIATE retry exhausted".into())
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
    let key_event_id = workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by)?;
    let eid = create_encrypted_event_synchronous(
        db,
        recorded_by,
        &key_event_id,
        &msg,
        Some(signing_key),
    )?;
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
    let key_event_id = workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by)?;
    let eid = create_encrypted_event_synchronous(
        db,
        recorded_by,
        &key_event_id,
        &del,
        Some(signing_key),
    )?;
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
    let log_progress = generate_progress_logging_enabled();
    let generate_start = Instant::now();

    let (signer_eid, signing_key) =
        peer_shared::load_local_peer_signer_required(&db, &recorded_by)?;
    let workspace_id = workspace::resolve_workspace_for_peer(&db, &recorded_by)?;
    let author_id = peer_shared::resolve_user_event_id(&db, &recorded_by, &signer_eid)?;

    // Break into smaller batches to avoid holding the write lock too long.
    // A single long transaction causes SQLITE_BUSY for the sync engine's
    // runtime manager, which treats it as a fatal error.
    const BATCH_SIZE: usize = 1000;
    if log_progress {
        eprintln!(
            "[generate] start kind=messages count={} batch_size={} db={} peer={}",
            count, BATCH_SIZE, db_path, peer_id
        );
    }
    let mut i = 0;
    while i < count {
        let batch_end = (i + BATCH_SIZE).min(count);
        let batch_start = Instant::now();
        begin_immediate_with_retry(&db)?;
        for j in i..batch_end {
            create(
                &db,
                &recorded_by,
                &signer_eid,
                &signing_key,
                current_timestamp_ms(),
                CreateMessageCmd {
                    workspace_id,
                    author_id,
                    content: format!("Message {}", j),
                },
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("create event error: {}", e).into()
            })?;
        }
        db.execute("COMMIT", [])?;
        i = batch_end;
        if log_progress && (i == count || i % 10_000 == 0 || i == BATCH_SIZE) {
            eprintln!(
                "[generate] progress kind=messages committed={} remaining={} batch_ms={} total_ms={}",
                i,
                count.saturating_sub(i),
                batch_start.elapsed().as_millis(),
                generate_start.elapsed().as_millis()
            );
        }
    }
    if log_progress {
        eprintln!(
            "[generate] done kind=messages count={} total_ms={}",
            count,
            generate_start.elapsed().as_millis()
        );
    }

    Ok(GenerateResponse { count })
}

/// Generate N synthetic files as a specific peer.
///
/// Each generated file creates:
/// - 1 parent `message`
/// - 1 `key_secret`
/// - 1 `file`
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
    let log_progress = generate_progress_logging_enabled();
    let generate_start = Instant::now();
    let (signer_eid, signing_key) =
        peer_shared::load_local_peer_signer_required(&db, &recorded_by)?;
    let workspace_id = workspace::resolve_workspace_for_peer(&db, &recorded_by)?;
    let author_id = peer_shared::resolve_user_event_id(&db, &recorded_by, &signer_eid)?;
    let slice_bytes_u32 = FILE_SLICE_CIPHERTEXT_BYTES as u32;
    let ciphertext: Vec<u8> = vec![0xAB; FILE_SLICE_CIPHERTEXT_BYTES];

    // Each file is its own transaction to avoid holding the write lock
    // too long and causing SQLITE_BUSY for the sync engine.
    if log_progress {
        eprintln!(
            "[generate] start kind=files files={} size_mib={} db={} peer={}",
            files, file_size_mib, db_path, peer_id
        );
    }
    for i in 0..files {
        let file_start = Instant::now();
        begin_immediate_with_retry(&db)?;
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

        create_encrypted_event_synchronous(
            &db,
            &recorded_by,
            &key_event_id,
            &ParsedEvent::File(FileEvent {
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
            Some(&signing_key),
        )
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("create file error: {}", e).into()
        })?;

        for slice_number in 0..slices_per_file {
            create_encrypted_event_synchronous(
                &db,
                &recorded_by,
                &key_event_id,
                &ParsedEvent::FileSlice(FileSliceEvent {
                    created_at_ms: current_timestamp_ms(),
                    file_id,
                    slice_number: slice_number as u32,
                    ciphertext: ciphertext.clone(),
                    signed_by: signer_eid,
                    signer_type: 5,
                    signature: [0u8; 64],
                }),
                Some(&signing_key),
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("create file_slice error: {}", e).into()
            })?;
        }
        db.execute("COMMIT", [])?;
        if log_progress && (i + 1 == files || (i + 1) % 10 == 0 || i == 0) {
            eprintln!(
                "[generate] progress kind=files committed={} remaining={} file_ms={} total_ms={}",
                i + 1,
                files.saturating_sub(i + 1),
                file_start.elapsed().as_millis(),
                generate_start.elapsed().as_millis()
            );
        }
    }
    if log_progress {
        eprintln!(
            "[generate] done kind=files files={} total_ms={}",
            files,
            generate_start.elapsed().as_millis()
        );
    }

    Ok(GenerateFilesResponse {
        files,
        file_size_mib,
        slices_per_file,
        total_slices,
    })
}

// ---------------------------------------------------------------------------
// send-file: message + file from a real file on disk
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

fn read_padded_file_slice<R: Read>(
    reader: &mut R,
    bytes_this_slice: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut ciphertext = vec![0u8; FILE_SLICE_CIPHERTEXT_BYTES];
    if bytes_this_slice > 0 {
        reader.read_exact(&mut ciphertext[..bytes_this_slice])?;
    }
    Ok(ciphertext)
}

/// Send a message with a file as a specific peer.
pub fn send_file_for_peer(
    db_path: &str,
    peer_id: &str,
    content: &str,
    file_path: &str,
) -> Result<SendFileResponse, Box<dyn std::error::Error + Send + Sync>> {
    let path = Path::new(file_path);
    let file =
        std::fs::File::open(path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("failed to open {}: {}", file_path, e).into()
        })?;
    let file_size = file
        .metadata()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("failed to stat {}: {}", file_path, e).into()
        })?
        .len();
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
        1usize
    } else {
        usize::try_from(file_size.div_ceil(FILE_SLICE_CIPHERTEXT_BYTES as u64)).map_err(
            |_| -> Box<dyn std::error::Error + Send + Sync> {
                "file too large: slice count exceeds usize".into()
            },
        )?
    };
    let total_slices_u32 =
        u32::try_from(num_slices).map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
            "file too large: slice count exceeds u32".into()
        })?;

    create_encrypted_event_synchronous(
        &db,
        &recorded_by,
        &key_event_id,
        &ParsedEvent::File(FileEvent {
            created_at_ms: current_timestamp_ms(),
            message_id: message_event_id,
            file_id,
            blob_bytes: file_size,
            total_slices: total_slices_u32,
            slice_bytes: FILE_SLICE_CIPHERTEXT_BYTES as u32,
            root_hash: [0u8; 32],
            key_event_id,
            filename: filename.clone(),
            mime_type,
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        }),
        Some(&signing_key),
    )?;

    let mut reader = BufReader::new(file);
    let mut remaining_bytes = file_size;
    for slice_number in 0..num_slices {
        let bytes_this_slice = remaining_bytes.min(FILE_SLICE_CIPHERTEXT_BYTES as u64) as usize;
        let ciphertext = read_padded_file_slice(&mut reader, bytes_this_slice)?;
        remaining_bytes = remaining_bytes.saturating_sub(bytes_this_slice as u64);

        create_encrypted_event_synchronous(
            &db,
            &recorded_by,
            &key_event_id,
            &ParsedEvent::FileSlice(FileSliceEvent {
                created_at_ms: current_timestamp_ms(),
                file_id,
                slice_number: slice_number as u32,
                ciphertext,
                signed_by: signer_eid,
                signer_type: 5,
                signature: [0u8; 64],
            }),
            Some(&signing_key),
        )?;
    }
    if remaining_bytes != 0 {
        return Err(format!(
            "file read incomplete: {} bytes remained unread for {}",
            remaining_bytes, file_path
        )
        .into());
    }

    Ok(SendFileResponse {
        content: content.to_string(),
        event_id: hex::encode(message_event_id),
        filename,
        file_size,
    })
}
