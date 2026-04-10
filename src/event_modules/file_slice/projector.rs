use super::super::ParsedEvent;
use super::wire::{unpack_bao_payload, FILE_SLICE_CIPHERTEXT_BYTES};
use crate::crypto::bao_verify;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};
use crate::projection::queries::{ContextLoadResult, ProjectionFrameContext, ProjectionQueries};

pub fn build_projector_context(
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    let file_slice = match parsed {
        ParsedEvent::FileSlice(file_slice) => file_slice,
        _ => return Err("file_slice context loader called for non-file_slice event".into()),
    };

    let ctx = queries.load_file_slice_context(frame, recorded_by, event_id_b64, file_slice)?;
    if let Some(message_event_id) = &ctx.purge_message_event_id {
        return Ok(ContextLoadResult::purge(message_event_id.clone()));
    }
    Ok(ContextLoadResult::ready(ctx))
}

/// Pure projector: FileSlice → file_slices table insert.
///
/// Uses ProjectorDecisionContext.file_descriptors to determine authorization:
/// - No descriptors → dep-block on file_id
/// - Multiple descriptors → reject
/// - Signer mismatch → reject
/// - Encrypted wrapper key mismatch → reject
/// - Success → insert file_slice row
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let fs = match parsed {
        ParsedEvent::FileSlice(f) => f,
        _ => return ProjectorResult::reject("not a file_slice event".to_string()),
    };
    let owner_event_id_b64 = ctx.current_owner_event_id.as_deref();

    let file_id_b64 = event_id_to_base64(&fs.file_id);
    let Some(current_signer) = ctx.current_signer.as_ref() else {
        return ProjectorResult::reject("file_slice missing current signer envelope".to_string());
    };
    let slice_signer_b64 = current_signer.event_id.clone();

    if ctx.file_descriptors.is_empty() {
        // No descriptor yet — block on file_id as a synthetic dep.
        // When the File event projects, cascade resolves events blocked
        // on this file_id through the normal dep-unblocking path.
        return ProjectorResult::block(vec![fs.file_id]);
    }

    if ctx.file_descriptors.len() > 1 {
        return ProjectorResult::reject(format!(
            "file_id {} maps to multiple descriptors ({}), cannot authorize file_slice",
            file_id_b64,
            ctx.file_descriptors.len()
        ));
    }

    let descriptor = &ctx.file_descriptors[0];
    if let Some(owner_event_id_b64) = owner_event_id_b64 {
        if descriptor.message_id != owner_event_id_b64 {
            return ProjectorResult::reject(format!(
                "file_slice owner_event_id {} does not match file descriptor message_id {}",
                owner_event_id_b64, descriptor.message_id
            ));
        }
    }
    if descriptor.signer_event_id != slice_signer_b64 {
        return ProjectorResult::reject(format!(
            "file_slice signer {} does not match file descriptor signer {}",
            slice_signer_b64, descriptor.signer_event_id
        ));
    }
    if let Some(wrapper_key_event_id) = ctx.current_transport_key_event_id.as_deref() {
        if descriptor.key_event_id != wrapper_key_event_id {
            return ProjectorResult::reject(format!(
                "file_slice wrapper key {} does not match file descriptor key {}",
                wrapper_key_event_id, descriptor.key_event_id
            ));
        }
    }

    // Verify bao slice encoding if root_hash is present (non-zero sentinel).
    if descriptor.root_hash != [0u8; 32] && fs.ciphertext.len() == FILE_SLICE_CIPHERTEXT_BYTES {
        let (bao_encoding, _) = unpack_bao_payload(&fs.ciphertext);
        if !bao_encoding.is_empty() {
            let slice_start = fs.slice_number as u64 * descriptor.slice_bytes as u64;
            if slice_start < descriptor.blob_bytes {
                let remaining = descriptor.blob_bytes.saturating_sub(slice_start);
                let slice_len = remaining.min(descriptor.slice_bytes as u64);
                if let Err(e) = bao_verify::verify_slice(
                    &descriptor.root_hash,
                    &bao_encoding,
                    slice_start,
                    slice_len,
                ) {
                    return ProjectorResult::reject(format!(
                        "bao verification failed for slice {}: {}",
                        fs.slice_number, e
                    ));
                }
            }
        }
    }

    // Check for existing slice in same slot (idempotent replay or conflict)
    if let Some((ref existing_event_id, ref existing_descriptor)) = ctx.existing_file_slice {
        if existing_event_id == event_id_b64 {
            if existing_descriptor != &descriptor.event_id {
                return ProjectorResult::reject(format!(
                    "file_slice descriptor mismatch: existing {} vs authorized {}",
                    existing_descriptor, descriptor.event_id
                ));
            }
            return ProjectorResult::valid(vec![]); // idempotent replay
        } else {
            return ProjectorResult::reject(format!(
                "duplicate file_slice: slot ({}, {}, {}) already claimed by event {}",
                recorded_by, file_id_b64, fs.slice_number, existing_event_id
            ));
        }
    }

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "file_slices",
        columns: vec![
            "recorded_by",
            "file_id",
            "slice_number",
            "event_id",
            "created_at",
            "descriptor_event_id",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(file_id_b64),
            SqlVal::Int(fs.slice_number as i64),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Int(fs.created_at_ms as i64),
            SqlVal::Text(descriptor.event_id.clone()),
        ],
    }];
    ProjectorResult::valid(ops)
}
