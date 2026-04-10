use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp};
use crate::projection::queries::define_query_context_loader;

define_query_context_loader!(build_projector_context, File, load_file_context, "file");

/// Pure projector: File → files table insert.
/// File_slice unblocking is handled by cascade_file_id_if_file in cascade.rs.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ProjectorDecisionContext,
) -> ProjectorResult {
    let att = match parsed {
        ParsedEvent::File(a) => a,
        _ => return ProjectorResult::reject("not a file event".to_string()),
    };

    let message_id_b64 = event_id_to_base64(&att.message_id);
    let key_event_id_b64 = event_id_to_base64(&att.key_event_id);
    if let Some(owner_event_id_b64) = ctx.current_owner_event_id.as_deref() {
        if owner_event_id_b64 != message_id_b64 {
            return ProjectorResult::reject(format!(
                "file owner_event_id {} does not match message_id {}",
                owner_event_id_b64, message_id_b64
            ));
        }
    }
    let Some(current_signer) = ctx.current_signer.as_ref() else {
        return ProjectorResult::reject("file missing current signer envelope".to_string());
    };
    let signer_event_id_b64 = current_signer.event_id.clone();

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "files",
        columns: vec![
            "recorded_by",
            "event_id",
            "message_id",
            "file_id",
            "blob_bytes",
            "total_slices",
            "slice_bytes",
            "root_hash",
            "key_event_id",
            "filename",
            "mime_type",
            "created_at",
            "signer_event_id",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(message_id_b64),
            SqlVal::Text(event_id_to_base64(&att.file_id)),
            SqlVal::Int(att.blob_bytes as i64),
            SqlVal::Int(att.total_slices as i64),
            SqlVal::Int(att.slice_bytes as i64),
            SqlVal::Blob(att.root_hash.to_vec()),
            SqlVal::Text(key_event_id_b64),
            SqlVal::Text(att.filename.clone()),
            SqlVal::Text(att.mime_type.clone()),
            SqlVal::Int(att.created_at_ms as i64),
            SqlVal::Text(signer_event_id_b64),
        ],
    }];

    ProjectorResult::valid(ops)
}
