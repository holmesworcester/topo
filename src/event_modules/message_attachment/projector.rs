use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: MessageAttachment → message_attachments table insert.
/// Emits RetryFileSliceGuards command so pending file_slices can unblock.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let att = match parsed {
        ParsedEvent::MessageAttachment(a) => a,
        _ => return ProjectorResult::reject("not a message_attachment event".to_string()),
    };

    let message_id_b64 = event_id_to_base64(&att.message_id);
    let file_id_b64 = event_id_to_base64(&att.file_id);
    let key_event_id_b64 = event_id_to_base64(&att.key_event_id);
    let signer_event_id_b64 = event_id_to_base64(&att.signed_by);

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "message_attachments",
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
            SqlVal::Text(file_id_b64.clone()),
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

    ProjectorResult::valid_with_commands(
        ops,
        vec![EmitCommand::RetryFileSliceGuards {
            file_id: file_id_b64,
        }],
    )
}
