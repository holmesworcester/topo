use std::fs::File;
use std::io::{Seek, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::crypto::bao_verify;
use crate::crypto::EventId;
use crate::event_modules::file_slice::{
    BAO_PLAINTEXT_CAPACITY, FILE_SLICE_CIPHERTEXT_BYTES, FILE_SLICE_DATA_BYTES, MAX_FILE_BYTES,
};
use crate::projection::create::{
    create_encrypted_event, create_encrypted_event_with_owner,
};
use crate::service::open_db_for_peer;
use crate::state::db::queue::current_timestamp_ms_u64;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::super::message_deletion::MessageDeletionEvent;
use super::super::workspace;
use super::super::ParsedEvent;
use super::super::{FileEvent, FileSliceEvent};
use super::wire::MessageEvent;

fn generate_progress_logging_enabled() -> bool {
    std::env::var_os("TOPO_GENERATE_PROGRESS_LOG").is_some()
}

pub(crate) const DEFAULT_GENERATE_HISTORY_SPAN_MS: u64 = 3 * 365 * 24 * 60 * 60 * 1000;

pub(crate) fn parse_history_span_ms(spec: &str) -> Option<u64> {
    let trimmed = spec.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    let (number, unit_ms) = if let Some(value) = trimmed.strip_suffix("ms") {
        (value, 1u64)
    } else if let Some(value) = trimmed.strip_suffix("min") {
        (value, 60_000u64)
    } else if let Some(value) = trimmed.strip_suffix("mo") {
        (value, 30 * 24 * 60 * 60 * 1000u64)
    } else if let Some(value) = trimmed.strip_suffix('s') {
        (value, 1_000u64)
    } else if let Some(value) = trimmed.strip_suffix('m') {
        (value, 60_000u64)
    } else if let Some(value) = trimmed.strip_suffix('h') {
        (value, 60 * 60 * 1000u64)
    } else if let Some(value) = trimmed.strip_suffix('d') {
        (value, 24 * 60 * 60 * 1000u64)
    } else if let Some(value) = trimmed.strip_suffix('w') {
        (value, 7 * 24 * 60 * 60 * 1000u64)
    } else if let Some(value) = trimmed.strip_suffix('y') {
        (value, 365 * 24 * 60 * 60 * 1000u64)
    } else {
        (trimmed.as_str(), 1u64)
    };
    number
        .parse::<u64>()
        .ok()
        .map(|count| count.saturating_mul(unit_ms))
}

fn generate_message_spread_ms() -> Option<u64> {
    std::env::var("TOPO_GENERATE_MESSAGE_SPREAD_MS")
        .ok()
        .and_then(|value| parse_history_span_ms(&value).or_else(|| value.parse::<u64>().ok()))
        .filter(|value| *value > 0)
}

fn resolve_generate_history_span_ms(history_span: Option<&str>) -> u64 {
    history_span
        .and_then(parse_history_span_ms)
        .or_else(generate_message_spread_ms)
        .unwrap_or(DEFAULT_GENERATE_HISTORY_SPAN_MS)
}

fn next_monotonic_timestamp_ms(next_timestamp_ms: &mut u64) -> u64 {
    let now_ms = current_timestamp_ms_u64();
    if now_ms > *next_timestamp_ms {
        *next_timestamp_ms = now_ms;
    }
    let assigned = *next_timestamp_ms;
    *next_timestamp_ms = next_timestamp_ms.saturating_add(1);
    assigned
}

pub(crate) fn generate_messages_for_recorded_by_between(
    db: &Connection,
    recorded_by: &str,
    count: usize,
    start_at_ms: u64,
    end_at_ms: u64,
) -> Result<GenerateResponse, Box<dyn std::error::Error + Send + Sync>> {
    let log_progress = generate_progress_logging_enabled();
    let generate_start = Instant::now();
    let ctx = workspace::load_local_authoring_context(db, recorded_by)?;
    let (start_at_ms, end_at_ms) = if start_at_ms <= end_at_ms {
        (start_at_ms, end_at_ms)
    } else {
        (end_at_ms, start_at_ms)
    };
    let span_ms = end_at_ms.saturating_sub(start_at_ms);
    let timestamp_for_index = |index: usize| -> u64 {
        if count <= 1 {
            return start_at_ms;
        }
        let numerator = (index as u128).saturating_mul(span_ms as u128);
        let step = numerator / u128::try_from(count - 1).unwrap_or(1);
        start_at_ms.saturating_add(u64::try_from(step).unwrap_or(u64::MAX))
    };

    const BATCH_SIZE: usize = 1000;
    if log_progress {
        eprintln!(
            "[generate] start kind=messages count={} batch_size={} recorded_by={}",
            count, BATCH_SIZE, recorded_by
        );
    }
    let mut i = 0;
    while i < count {
        let batch_end = (i + BATCH_SIZE).min(count);
        let batch_start = Instant::now();
        begin_immediate_with_retry(db)?;
        for j in i..batch_end {
            create(
                db,
                recorded_by,
                &ctx.signer_event_id,
                &ctx.signing_key,
                timestamp_for_index(j),
                CreateMessageCmd {
                    workspace_id: ctx.workspace_id,
                    author_id: ctx.author_id,
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

pub(crate) fn generate_messages_for_recorded_by(
    db: &Connection,
    recorded_by: &str,
    count: usize,
    history_span_ms: u64,
    end_at_ms: u64,
) -> Result<GenerateResponse, Box<dyn std::error::Error + Send + Sync>> {
    let start_at_ms = end_at_ms.saturating_sub(history_span_ms);
    generate_messages_for_recorded_by_between(db, recorded_by, count, start_at_ms, end_at_ms)
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
    pub event_id: String,
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
    });
    let key_event_id = workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by)?;
    let eid = create_encrypted_event(
        db,
        recorded_by,
        &key_event_id,
        &msg,
        Some((signer_eid, signing_key)),
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
    });
    let key_event_id = workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by)?;
    let eid = create_encrypted_event(
        db,
        recorded_by,
        &key_event_id,
        &del,
        Some((signer_eid, signing_key)),
    )?;
    Ok(eid)
}

/// High-level delete command: creates a message_deletion event and returns (event_id_hex, target_hex).
pub fn delete_message(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    target_event_id: [u8; 32],
) -> Result<(String, String), String> {
    let event_id = create_deletion(
        db,
        recorded_by,
        signer_eid,
        signing_key,
        created_at_ms,
        CreateMessageDeletionCmd { target_event_id },
    )
    .map_err(|e| format!("{}", e))?;

    Ok((hex::encode(event_id), hex::encode(target_event_id)))
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
    Ok(file_size_bytes.div_ceil(FILE_SLICE_DATA_BYTES))
}

/// Send a message as a specific peer (daemon provides the peer_id).
pub fn send_for_peer(
    db_path: &str,
    peer_id: &str,
    content: &str,
) -> Result<super::SendResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let ctx = workspace::load_local_authoring_context(&db, &recorded_by)?;

    send(
        &db,
        &recorded_by,
        &ctx.signer_event_id,
        &ctx.signing_key,
        current_timestamp_ms_u64(),
        ctx.workspace_id,
        ctx.author_id,
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
    let ctx = workspace::load_local_authoring_context(&db, &recorded_by)?;
    let target_event_id = super::resolve(&db, &recorded_by, target_hex)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    let (event_id, target) = delete_message(
        &db,
        &recorded_by,
        &ctx.signer_event_id,
        &ctx.signing_key,
        current_timestamp_ms_u64(),
        target_event_id,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    Ok(DeleteResponse { event_id, target })
}

/// Generate N test messages as a specific peer.
pub fn generate_for_peer(
    db_path: &str,
    peer_id: &str,
    count: usize,
    history_span: Option<&str>,
) -> Result<GenerateResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let history_span_ms = resolve_generate_history_span_ms(history_span);
    generate_messages_for_recorded_by(
        &db,
        &recorded_by,
        count,
        history_span_ms,
        current_timestamp_ms_u64(),
    )
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
    let ctx = workspace::load_local_authoring_context(&db, &recorded_by)?;
    // Generated files use sentinel root_hash [0;32] → skip bao verification.
    // Payload uses encoding_len=0 so unpack_bao_payload returns raw data.
    let effective_cap = BAO_PLAINTEXT_CAPACITY;
    let slice_bytes_u32 = effective_cap as u32;
    let ciphertext: Vec<u8> = {
        let mut payload = vec![0u8; FILE_SLICE_CIPHERTEXT_BYTES];
        // encoding_len = 0 (first 4 bytes already zero)
        for b in payload[4..4 + effective_cap].iter_mut() {
            *b = 0xAB;
        }
        payload
    };

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
        let mut next_created_at_ms = current_timestamp_ms_u64();
        let message_event_id = create(
            &db,
            &recorded_by,
            &ctx.signer_event_id,
            &ctx.signing_key,
            next_monotonic_timestamp_ms(&mut next_created_at_ms),
            CreateMessageCmd {
                workspace_id: ctx.workspace_id,
                author_id: ctx.author_id,
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
            .checked_mul(effective_cap as u64)
            .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                "blob_bytes overflow".into()
            })?;

        create_encrypted_event_with_owner(
            &db,
            &recorded_by,
            &key_event_id,
            Some(&message_event_id),
            &ParsedEvent::File(FileEvent {
                created_at_ms: next_monotonic_timestamp_ms(&mut next_created_at_ms),
                message_id: message_event_id,
                file_id,
                blob_bytes,
                total_slices: slices_per_file as u32,
                slice_bytes: slice_bytes_u32,
                root_hash: [0u8; 32],
                key_event_id,
                filename: format!("file-{}.bin", i),
                mime_type: "application/octet-stream".to_string(),
            }),
            Some((&ctx.signer_event_id, &ctx.signing_key)),
        )
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("create file error: {}", e).into()
        })?;

        for slice_number in 0..slices_per_file {
            create_encrypted_event_with_owner(
                &db,
                &recorded_by,
                &key_event_id,
                Some(&message_event_id),
                &ParsedEvent::FileSlice(FileSliceEvent {
                    created_at_ms: next_monotonic_timestamp_ms(&mut next_created_at_ms),
                    file_id,
                    slice_number: slice_number as u32,
                    ciphertext: ciphertext.clone(),
                }),
                Some((&ctx.signer_event_id, &ctx.signing_key)),
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

/// Send a message with a file as a specific peer.
///
/// Computes a bao (BLAKE3 verified streaming) root hash over the file
/// contents. The root hash is stored in the File descriptor event. At receive
/// time, the reassembled file is verified against this root hash, catching
/// any corruption or tampering in the slice data.
///
/// Each file slice carries 256 KiB of logical plaintext plus bao proof bytes
/// in a larger fixed payload slot.
pub fn send_file_for_peer(
    db_path: &str,
    peer_id: &str,
    content: &str,
    file_path: &str,
    add_bad_slices: usize,
) -> Result<SendFileResponse, Box<dyn std::error::Error + Send + Sync>> {
    send_file_for_peer_inner(db_path, peer_id, content, file_path, add_bad_slices, None)
}

fn send_file_for_peer_inner(
    db_path: &str,
    peer_id: &str,
    content: &str,
    file_path: &str,
    add_bad_slices: usize,
    fail_after_successful_slices: Option<usize>,
) -> Result<SendFileResponse, Box<dyn std::error::Error + Send + Sync>> {
    let path = Path::new(file_path);
    let file_size = std::fs::metadata(path)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("failed to stat {}: {}", file_path, e).into()
        })?
        .len();
    if file_size > MAX_FILE_BYTES {
        return Err(format!(
            "file too large: {} bytes exceeds {} byte limit",
            file_size, MAX_FILE_BYTES
        )
        .into());
    }
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
    let ctx = workspace::load_local_authoring_context(&db, &recorded_by)?;

    let file_id = rand::random::<[u8; 32]>();

    // Compute bao outboard + root hash over plaintext for per-slice verification
    // without buffering the whole file in memory.
    let (root_hash, mut outboard_file) = if file_size > 0 {
        let mut source =
            File::open(path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("failed to open {}: {}", file_path, e).into()
            })?;
        let mut outboard_file =
            tempfile::tempfile().map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("failed to create temporary bao outboard: {}", e).into()
            })?;
        let root_hash = bao_verify::compute_outboard_to_writer(&mut source, &mut outboard_file)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("bao outboard computation failed: {}", e).into()
            })?;
        outboard_file
            .flush()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("failed to flush bao outboard: {}", e).into()
            })?;
        outboard_file
            .rewind()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("failed to rewind bao outboard: {}", e).into()
            })?;
        (root_hash, Some(outboard_file))
    } else {
        ([0u8; 32], None)
    };

    let effective_capacity = BAO_PLAINTEXT_CAPACITY;
    let num_slices = if file_size == 0 {
        1usize
    } else {
        usize::try_from(file_size.div_ceil(effective_capacity as u64)).map_err(
            |_| -> Box<dyn std::error::Error + Send + Sync> {
                "file too large: slice count exceeds usize".into()
            },
        )?
    };
    let total_slices_u32 =
        u32::try_from(num_slices).map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
            "file too large: slice count exceeds u32".into()
        })?;

    let mut source_for_slices = if file_size > 0 {
        Some(
            File::open(path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("failed to reopen {} for slicing: {}", file_path, e).into()
            })?,
        )
    } else {
        None
    };

    let message_event_id = crate::state::db::queue::with_immediate_tx_result(
        &db,
        || -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
            let mut next_created_at_ms = current_timestamp_ms_u64();
            let message_event_id = create(
                &db,
                &recorded_by,
                &ctx.signer_event_id,
                &ctx.signing_key,
                next_monotonic_timestamp_ms(&mut next_created_at_ms),
                CreateMessageCmd {
                    workspace_id: ctx.workspace_id,
                    author_id: ctx.author_id,
                    content: content.to_string(),
                },
            )?;

            let key_event_id =
                workspace::identity_ops::ensure_content_key_for_peer(&db, &recorded_by)?;

            create_encrypted_event_with_owner(
                &db,
                &recorded_by,
                &key_event_id,
                Some(&message_event_id),
                &ParsedEvent::File(FileEvent {
                    created_at_ms: next_monotonic_timestamp_ms(&mut next_created_at_ms),
                    message_id: message_event_id,
                    file_id,
                    blob_bytes: file_size,
                    total_slices: total_slices_u32,
                    slice_bytes: effective_capacity as u32,
                    root_hash,
                    key_event_id,
                    filename: filename.clone(),
                    mime_type: mime_type.clone(),
                }),
                Some((&ctx.signer_event_id, &ctx.signing_key)),
            )?;

            let mut remaining_bytes = file_size;
            let mut successful_slices = 0usize;
            for slice_number in 0..num_slices {
                let bytes_this_slice = remaining_bytes.min(effective_capacity as u64) as usize;
                let data_start = slice_number * effective_capacity;

                let proof = if file_size > 0 {
                    bao_verify::extract_slice_proof_from_readers(
                        source_for_slices
                            .as_mut()
                            .expect("source file must exist for non-empty input"),
                        outboard_file
                            .as_mut()
                            .expect("outboard file must exist for non-empty input"),
                        data_start as u64,
                        bytes_this_slice as u64,
                    )
                    .map_err(
                        |e| -> Box<dyn std::error::Error + Send + Sync> {
                            format!("bao slice proof extraction failed: {}", e).into()
                        },
                    )?
                } else {
                    Vec::new()
                };

                let ciphertext =
                    crate::event_modules::file_slice::wire::pack_bao_payload(&proof, &[]).map_err(
                        |e| -> Box<dyn std::error::Error + Send + Sync> {
                            format!("bao slice payload packing failed: {}", e).into()
                        },
                    )?;
                remaining_bytes = remaining_bytes.saturating_sub(bytes_this_slice as u64);

                create_encrypted_event_with_owner(
                    &db,
                    &recorded_by,
                    &key_event_id,
                    Some(&message_event_id),
                    &ParsedEvent::FileSlice(FileSliceEvent {
                        created_at_ms: next_monotonic_timestamp_ms(&mut next_created_at_ms),
                        file_id,
                        slice_number: slice_number as u32,
                        ciphertext,
                    }),
                    Some((&ctx.signer_event_id, &ctx.signing_key)),
                )?;
                successful_slices += 1;
                if fail_after_successful_slices == Some(successful_slices) {
                    return Err(format!(
                        "injected send-file failure after {} slices",
                        successful_slices
                    )
                    .into());
                }
            }
            for bad_idx in 0..add_bad_slices {
                let slice_number = total_slices_u32.checked_add(bad_idx as u32).ok_or_else(
                    || -> Box<dyn std::error::Error + Send + Sync> {
                        "too many bad slices: slice number exceeds u32".into()
                    },
                )?;
                let ciphertext =
                    vec![(bad_idx as u8).wrapping_add(0xA5); FILE_SLICE_CIPHERTEXT_BYTES];
                create_encrypted_event_with_owner(
                    &db,
                    &recorded_by,
                    &key_event_id,
                    Some(&message_event_id),
                    &ParsedEvent::FileSlice(FileSliceEvent {
                        created_at_ms: next_monotonic_timestamp_ms(&mut next_created_at_ms),
                        file_id,
                        slice_number,
                        ciphertext,
                    }),
                    Some((&ctx.signer_event_id, &ctx.signing_key)),
                )?;
            }

            Ok(message_event_id)
        },
    )?;

    Ok(SendFileResponse {
        content: content.to_string(),
        event_id: hex::encode(message_event_id),
        filename,
        file_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_connection;
    use crate::event_modules::workspace::commands::create_workspace_for_db;
    use std::sync::{Mutex, OnceLock};

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn parse_history_span_supports_human_units() {
        assert_eq!(parse_history_span_ms("1500ms"), Some(1_500));
        assert_eq!(parse_history_span_ms("2h"), Some(2 * 60 * 60 * 1000));
        assert_eq!(parse_history_span_ms("3d"), Some(3 * 24 * 60 * 60 * 1000));
        assert_eq!(
            parse_history_span_ms("3y"),
            Some(DEFAULT_GENERATE_HISTORY_SPAN_MS)
        );
    }

    #[test]
    fn resolve_generate_history_span_defaults_to_three_years() {
        let _guard = env_guard();
        std::env::remove_var("TOPO_GENERATE_MESSAGE_SPREAD_MS");
        assert_eq!(
            resolve_generate_history_span_ms(None),
            DEFAULT_GENERATE_HISTORY_SPAN_MS
        );
    }

    #[test]
    fn resolve_generate_history_span_prefers_explicit_argument_over_env() {
        let _guard = env_guard();
        std::env::set_var("TOPO_GENERATE_MESSAGE_SPREAD_MS", "30d");
        assert_eq!(
            resolve_generate_history_span_ms(Some("7d")),
            7 * 24 * 60 * 60 * 1000
        );
        std::env::remove_var("TOPO_GENERATE_MESSAGE_SPREAD_MS");
    }

    #[test]
    fn send_file_rolls_back_all_rows_on_mid_send_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("send-file-rollback.db");
        let db_path = db_path.to_str().unwrap();
        let source_path = tmp.path().join("payload.bin");
        std::fs::write(&source_path, vec![0x5Au8; FILE_SLICE_DATA_BYTES * 2]).unwrap();

        crate::transport::materialize_daemon_identity_from_db(db_path)
            .expect("materialize daemon identity");
        let created = create_workspace_for_db(db_path, "ws", "alice", "laptop").unwrap();
        let err = send_file_for_peer_inner(
            db_path,
            &created.peer_id,
            "rollback me",
            source_path.to_str().unwrap(),
            0,
            Some(1),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("injected send-file failure"),
            "unexpected error: {err}"
        );

        let conn = open_connection(db_path).unwrap();
        let (messages, files, file_slices): (i64, i64, i64) = conn
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM messages),
                     (SELECT COUNT(*) FROM files),
                     (SELECT COUNT(*) FROM file_slices)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(messages, 0, "message row must roll back");
        assert_eq!(files, 0, "file descriptor must roll back");
        assert_eq!(file_slices, 0, "file slices must roll back");
    }

    #[test]
    fn next_monotonic_timestamp_ms_advances_across_ties_and_saturates() {
        let mut next_timestamp_ms = u64::MAX - 2;

        let first = next_monotonic_timestamp_ms(&mut next_timestamp_ms);
        let second = next_monotonic_timestamp_ms(&mut next_timestamp_ms);
        let third = next_monotonic_timestamp_ms(&mut next_timestamp_ms);

        assert_eq!(first, u64::MAX - 2);
        assert_eq!(second, u64::MAX - 1);
        assert_eq!(third, u64::MAX);
        assert_eq!(next_timestamp_ms, u64::MAX);
    }
}
