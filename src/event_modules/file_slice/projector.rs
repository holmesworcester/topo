use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::decision::ProjectionDecision;
use crate::projection::result::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

/// Build projector-local context for FileSlice projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let fs = match parsed {
        ParsedEvent::FileSlice(fs) => fs,
        _ => return Err("file_slice context loader called for non-file_slice event".into()),
    };

    let mut ctx = ContextSnapshot::default();
    let file_id_b64 = event_id_to_base64(&fs.file_id);

    let mut desc_stmt = conn.prepare(
        "SELECT event_id, signer_event_id
         FROM message_attachments
         WHERE recorded_by = ?1 AND file_id = ?2
         ORDER BY created_at ASC, event_id ASC",
    )?;
    ctx.file_descriptors = desc_stmt
        .query_map(rusqlite::params![recorded_by, &file_id_b64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    ctx.existing_file_slice = match conn.query_row(
        "SELECT event_id, descriptor_event_id
         FROM file_slices
         WHERE recorded_by = ?1 AND file_id = ?2 AND slice_number = ?3",
        rusqlite::params![recorded_by, &file_id_b64, fs.slice_number as i64],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    ) {
        Ok(v) => Some(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    Ok(ctx)
}

/// Pure projector: FileSlice → file_slices table insert.
///
/// Uses ContextSnapshot.file_descriptors to determine authorization:
/// - No descriptors → guard-block (emit RecordFileSliceGuardBlock command)
/// - Multiple signers → reject
/// - Signer mismatch → reject
/// - Success → insert file_slice row
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let fs = match parsed {
        ParsedEvent::FileSlice(f) => f,
        _ => return ProjectorResult::reject("not a file_slice event".to_string()),
    };

    let file_id_b64 = event_id_to_base64(&fs.file_id);
    let slice_signer_b64 = event_id_to_base64(&fs.signed_by);

    if ctx.file_descriptors.is_empty() {
        // No descriptor yet — guard-block
        return ProjectorResult {
            decision: ProjectionDecision::Block { missing: vec![] },
            write_ops: Vec::new(),
            emit_commands: vec![EmitCommand::RecordFileSliceGuardBlock {
                file_id: file_id_b64,
                event_id: event_id_b64.to_string(),
            }],
        };
    }

    // Check for conflicting descriptor signers
    let mut descriptor_signers = std::collections::BTreeSet::new();
    for (_, signer) in &ctx.file_descriptors {
        descriptor_signers.insert(signer.clone());
    }
    if descriptor_signers.len() > 1 {
        return ProjectorResult::reject(format!(
            "file_id {} maps to multiple attachment signers ({}), cannot authorize file_slice",
            file_id_b64,
            descriptor_signers.len()
        ));
    }

    let (descriptor_event_id, descriptor_signer) = ctx.file_descriptors[0].clone();
    if descriptor_signer != slice_signer_b64 {
        return ProjectorResult::reject(format!(
            "file_slice signer {} does not match attachment descriptor signer {}",
            slice_signer_b64, descriptor_signer
        ));
    }

    // Check for existing slice in same slot (idempotent replay or conflict)
    if let Some((ref existing_event_id, ref existing_descriptor)) = ctx.existing_file_slice {
        if existing_event_id == event_id_b64 {
            if existing_descriptor != &descriptor_event_id {
                return ProjectorResult::reject(format!(
                    "file_slice descriptor mismatch: existing {} vs authorized {}",
                    existing_descriptor, descriptor_event_id
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
            SqlVal::Text(descriptor_event_id),
        ],
    }];
    ProjectorResult::valid(ops)
}
