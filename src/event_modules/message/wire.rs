use super::super::layout::field_spec::{decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE};

/// Message content: fixed UTF-8 slot (1024 bytes, zero-padded)
pub const MESSAGE_CONTENT_BYTES: usize = 1024;

pub const MESSAGE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("author_id"),
    FieldSpec::Text("content", MESSAGE_CONTENT_BYTES),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];
pub const MESSAGE_WIRE_SIZE: usize = wire_size_for_fields(MESSAGE_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub created_at_ms: u64,
    pub workspace_id: [u8; 32],
    pub author_id: [u8; 32],
    pub content: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for MessageEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("content", self.content.clone())]
    }
}

/// Wire format (1194 bytes fixed, signed):
/// [0]            type=1
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        workspace_id (32 bytes)
/// [41..73]       author_id (32 bytes)
/// [73..1097]     content (1024 bytes, UTF-8 zero-padded)
/// [1097..1129]   signed_by (32 bytes)
/// [1129]         signer_type (1 byte)
/// [1130..1194]   signature (64 bytes)
pub fn parse_message(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_MESSAGE, MESSAGE_FIELDS, blob)?;
    let created_at_ms = values[0].as_timestamp().unwrap();
    let workspace_id = values[1].as_event_id().unwrap();
    let author_id = values[2].as_event_id().unwrap();
    let content = values[3].as_text().unwrap().to_string();
    let signed_by = values[4].as_event_id().unwrap();
    let signer_type = values[5].as_u8().unwrap();
    let mut signature = [0u8; 64];
    signature.copy_from_slice(values[6].as_fixed_bytes().unwrap());

    Ok(ParsedEvent::Message(MessageEvent {
        created_at_ms,
        workspace_id,
        author_id,
        content,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_message(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let msg = match event {
        ParsedEvent::Message(m) => m,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(msg.created_at_ms),
        FieldValue::EventId(msg.workspace_id),
        FieldValue::EventId(msg.author_id),
        FieldValue::Text(msg.content.clone()),
        FieldValue::EventId(msg.signed_by),
        FieldValue::U8(msg.signer_type),
        FieldValue::FixedBytes(msg.signature.to_vec()),
    ];
    Ok(encode_fields(EVENT_TYPE_MESSAGE, MESSAGE_FIELDS, &values)?)
}

pub static MESSAGE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE,
    type_name: "message",
    projection_table: "messages",
    share_scope: ShareScope::Shared,
    dep_fields: &["author_id", "signed_by"],
    dep_field_type_codes: &[&[14, 15], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_message,
    encode: encode_message,
    projector: super::projector::project_pure,
    context_loader: super::projection_context::build_projector_context,
};
