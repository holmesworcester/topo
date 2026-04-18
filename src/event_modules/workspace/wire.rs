use crate::event_modules::layout::common::NAME_BYTES;
use crate::event_modules::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent, EVENT_TYPE_WORKSPACE};

// ─── Layout (owned by this module) ───

pub const WORKSPACE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("public_key"),
    FieldSpec::Text("name", NAME_BYTES),
];

/// Workspace (type 8): type(1) + created_at(8) + public_key(32) + name(64) = 105
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
    // Verified byte-level parser for [type][u64 ts][id:32][fb:64]; UTF-8 validation
    // of the 64-byte text slot is layered on top via read_text_slot.
    if let Some((ts, public_key, name_slot)) =
        topo_verus_proofs::state::event_codec_shapes::parse_ts_id_fb64(EVENT_TYPE_WORKSPACE, blob)
    {
        let name = crate::event_modules::layout::common::read_text_slot(&name_slot)
            .map_err(EventError::TextSlot)?;
        return Ok(ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: ts,
            public_key,
            name,
        }));
    }
    let values = decode_fields(EVENT_TYPE_WORKSPACE, WORKSPACE_FIELDS, blob)?;
    Ok(ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        public_key: values[1].as_event_id().unwrap(),
        name: values[2].as_text().unwrap().to_string(),
    }))
}

pub fn encode_workspace(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ws = match event {
        ParsedEvent::Workspace(w) => w,
        _ => return Err(EventError::WrongVariant),
    };
    // Prepare the 64-byte text slot (UTF-8 bytes + zero padding) via the trusted
    // write_text_slot helper, then hand the fixed-size byte array to the verified
    // byte-level encoder for the rest of the blob.
    let mut name_slot: [u8; NAME_BYTES] = [0u8; NAME_BYTES];
    crate::event_modules::layout::common::write_text_slot(&ws.name, &mut name_slot)
        .map_err(EventError::TextSlot)?;
    Ok(
        topo_verus_proofs::state::event_codec_shapes::encode_ts_id_fb64(
            EVENT_TYPE_WORKSPACE,
            ws.created_at_ms,
            &ws.public_key,
            &name_slot,
        ),
    )
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
    context_loader: super::projector::build_projector_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    use crate::event_modules::layout::field_spec::field_offset;
    #[test]
    fn offsets_consistent() {
        // name field starts at offset 41, name(64) ends at 105 = WORKSPACE_WIRE_SIZE
        assert_eq!(
            field_offset(WORKSPACE_FIELDS, 2) + NAME_BYTES,
            WORKSPACE_WIRE_SIZE
        );
    }
}
