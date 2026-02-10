use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_WORKSPACE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32],  // Ed25519 verifying key for the workspace
    pub workspace_id: [u8; 32],  // unique workspace identifier
}

/// Wire format (73 bytes fixed):
/// [0]      type_code = 8
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  public_key (32 bytes)
/// [41..73] workspace_id (32 bytes)
pub fn parse_workspace(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < 73 {
        return Err(EventError::TooShort {
            expected: 73,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_WORKSPACE {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_WORKSPACE,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&blob[9..41]);

    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[41..73]);

    Ok(ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms,
        public_key,
        workspace_id,
    }))
}

pub fn encode_workspace(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ws = match event {
        ParsedEvent::Workspace(w) => w,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(73);
    buf.push(EVENT_TYPE_WORKSPACE);
    buf.extend_from_slice(&ws.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&ws.public_key);
    buf.extend_from_slice(&ws.workspace_id);
    Ok(buf)
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
    parse: parse_workspace,
    encode: encode_workspace,
};
