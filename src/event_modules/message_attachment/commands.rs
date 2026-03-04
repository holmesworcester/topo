use std::time::{SystemTime, UNIX_EPOCH};

use crate::event_modules::file_slice::FILE_SLICE_CIPHERTEXT_BYTES;
use crate::event_modules::{
    message, peer_shared, workspace, FileSliceEvent, ParsedEvent, SecretKeyEvent,
};
use crate::projection::create::{create_event_synchronous, create_signed_event_synchronous};
use crate::service::open_db_for_peer;
use serde::{Deserialize, Serialize};

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
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

/// Generate N synthetic files as a specific peer.
///
/// Each generated file creates:
/// - 1 parent `message`
/// - 1 `secret_key`
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
        let message_event_id = message::create(
            &db,
            &recorded_by,
            &signer_eid,
            &signing_key,
            current_timestamp_ms(),
            message::CreateMessageCmd {
                workspace_id,
                author_id,
                content: format!("File {}", i),
            },
        )
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("create parent message error: {}", e).into()
        })?;

        let key_event_id = create_event_synchronous(
            &db,
            &recorded_by,
            &ParsedEvent::SecretKey(SecretKeyEvent {
                created_at_ms: current_timestamp_ms(),
                key_bytes: rand::random::<[u8; 32]>(),
            }),
        )
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("create secret_key error: {}", e).into()
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
            &ParsedEvent::MessageAttachment(crate::event_modules::MessageAttachmentEvent {
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
