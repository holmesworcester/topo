use super::fixed_layout::{self, WORKSPACE_WIRE_SIZE, NAME_BYTES, workspace_offsets as off};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_WORKSPACE};

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

    let name = fixed_layout::read_text_slot(&blob[off::NAME..off::NAME + NAME_BYTES])
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
    fixed_layout::write_text_slot(&ws.name, &mut buf[off::NAME..off::NAME + NAME_BYTES])
        .map_err(EventError::TextSlot)?;
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
    encryptable: false,
    parse: parse_workspace,
    encode: encode_workspace,
};
