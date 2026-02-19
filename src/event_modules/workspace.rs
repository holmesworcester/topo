use super::layout::common::{COMMON_HEADER_BYTES, NAME_BYTES, read_text_slot, write_text_slot};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_WORKSPACE};

// ─── Layout (owned by this module) ───

/// Workspace (type 8): type(1) + created_at(8) + public_key(32) + name(64) = 105
pub const WORKSPACE_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + NAME_BYTES;

mod workspace_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const PUBLIC_KEY: usize = 9;
    pub const NAME: usize = 41;
}

use workspace_offsets as off;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],  // Ed25519 verifying key for the workspace
    pub name: String,           // Workspace display name (64-byte text slot)
}

/// Wire format (105 bytes fixed):
/// [0]      type_code = 8
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  public_key (32 bytes)
/// [41..105] name (64 bytes, UTF-8 zero-padded)
pub fn parse_workspace(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < WORKSPACE_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: WORKSPACE_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > WORKSPACE_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: WORKSPACE_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_WORKSPACE {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_WORKSPACE,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::PUBLIC_KEY].try_into().unwrap());

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[off::PUBLIC_KEY..off::NAME]);

    let name = read_text_slot(&blob[off::NAME..off::NAME + NAME_BYTES])
        .map_err(EventError::TextSlot)?;

    Ok(ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms,
        public_key,
        name,
    }))
}

pub fn encode_workspace(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ws = match event {
        ParsedEvent::Workspace(w) => w,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = vec![0u8; WORKSPACE_WIRE_SIZE];
    buf[off::TYPE_CODE] = EVENT_TYPE_WORKSPACE;
    buf[off::CREATED_AT..off::PUBLIC_KEY].copy_from_slice(&ws.created_at_ms.to_le_bytes());
    buf[off::PUBLIC_KEY..off::NAME].copy_from_slice(&ws.public_key);
    write_text_slot(&ws.name, &mut buf[off::NAME..off::NAME + NAME_BYTES])
        .map_err(EventError::TextSlot)?;
    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::projection::result::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Workspace guard — trust_anchors must match workspace event_id.
/// Returns Block if no trust anchor yet, Reject if mismatch.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ws = match parsed {
        ParsedEvent::Workspace(w) => w,
        _ => return ProjectorResult::reject("not a workspace event".to_string()),
    };

    let workspace_id_b64 = event_id_b64.to_string();

    match &ctx.trust_anchor_workspace_id {
        None => {
            // Guard-block: no trust anchor yet. Returns Block with empty
            // missing vec because the blocker is the trust anchor (set by
            // invite_accepted), not a specific event dep. Recovery:
            // invite_accepted emits RetryWorkspaceEvent { workspace_id }
            // which re-projects this event after the anchor is written.
            ProjectorResult::block(vec![])
        }
        Some(anchor_wid) if anchor_wid == &workspace_id_b64 => {
            // Trust anchor matches — project
            let ops = vec![
                WriteOp::InsertOrIgnore {
                    table: "workspaces",
                    columns: vec!["recorded_by", "event_id", "workspace_id", "public_key", "name"],
                    values: vec![
                        SqlVal::Text(recorded_by.to_string()),
                        SqlVal::Text(event_id_b64.to_string()),
                        SqlVal::Text(workspace_id_b64),
                        SqlVal::Blob(ws.public_key.to_vec()),
                        SqlVal::Text(ws.name.clone()),
                    ],
                },
            ];
            ProjectorResult::valid(ops)
        }
        Some(_) => {
            // Foreign workspace — reject
            ProjectorResult::reject("workspace_id does not match trust anchor".to_string())
        }
    }
}

pub static WORKSPACE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_WORKSPACE,
    type_name: "workspace",
    projection_table: "workspaces",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_workspace,
    encode: encode_workspace,
    projector: project_pure,
};

// === Query APIs (event-module locality) ===

use rusqlite::Connection;

pub struct WorkspaceRow {
    pub event_id: String,
    pub workspace_id: String,
}

pub fn list(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<WorkspaceRow>, rusqlite::Error> {
    let mut stmt =
        db.prepare("SELECT event_id, workspace_id FROM workspaces WHERE recorded_by = ?1")?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(WorkspaceRow {
                event_id: row.get(0)?,
                workspace_id: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Return the workspace display name for the first workspace, or empty string.
pub fn name(
    db: &Connection,
    recorded_by: &str,
) -> Result<String, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    Ok(db
        .query_row(
            "SELECT COALESCE(name, '') FROM workspaces WHERE recorded_by = ?1 LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_default())
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use super::super::layout;
    #[test]
    fn offsets_consistent() {
        assert_eq!(workspace_offsets::NAME + layout::common::NAME_BYTES, WORKSPACE_WIRE_SIZE);
    }
}
