use crate::event_modules::layout::common::NAME_BYTES;
use crate::event_modules::layout::field_spec::{decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent, EVENT_TYPE_WORKSPACE};

// ─── Layout (owned by this module) ───

/// Workspace (type 8): type(1) + created_at(8) + public_key(32) + name(64) = 105
pub const WORKSPACE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::FixedBytes("public_key", 32),
    FieldSpec::Text("name", NAME_BYTES),
];
pub const WORKSPACE_WIRE_SIZE: usize = wire_size_for_fields(WORKSPACE_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEvent {
    pub created_at_ms: u64,
    pub public_key: [u8; 32], // Ed25519 verifying key for the workspace
    pub name: String,         // Workspace display name (64-byte text slot)
}

impl super::super::Describe for WorkspaceEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("name", self.name.clone()),
            ("public_key", super::super::trunc_hex(&self.public_key, 16)),
        ]
    }
}

/// Wire format (105 bytes fixed):
/// [0]      type_code = 8
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  public_key (32 bytes)
/// [41..105] name (64 bytes, UTF-8 zero-padded)
pub fn parse_workspace(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_WORKSPACE, WORKSPACE_FIELDS, blob)?;
    let created_at_ms = values[0].as_timestamp().unwrap();
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(values[1].as_fixed_bytes().unwrap());
    let name = values[2].as_text().unwrap().to_string();

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

    let values = vec![
        FieldValue::Timestamp(ws.created_at_ms),
        FieldValue::FixedBytes(ws.public_key.to_vec()),
        FieldValue::Text(ws.name.clone()),
    ];
    Ok(encode_fields(EVENT_TYPE_WORKSPACE, WORKSPACE_FIELDS, &values)?)
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
    projector: super::projector::project_pure,
    context_loader: super::projection_context::build_projector_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn wire_size_consistent() {
        // type(1) + created_at(8) + public_key(32) + name(64) = 105
        assert_eq!(WORKSPACE_WIRE_SIZE, 105);
    }
}
