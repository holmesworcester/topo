use super::super::layout::field_spec::{decode_fields, encode_fields, FieldValue};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE};
use super::layout::MESSAGE_FIELDS;
pub use super::layout::{MESSAGE_CONTENT_BYTES, MESSAGE_WIRE_SIZE};

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

pub fn parse_message(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_MESSAGE, MESSAGE_FIELDS, blob)?;

    Ok(ParsedEvent::Message(MessageEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        workspace_id: values[1].as_event_id().unwrap(),
        author_id: values[2].as_event_id().unwrap(),
        content: values[3].as_text().unwrap().to_string(),
        signed_by: values[4].as_event_id().unwrap(),
        signer_type: values[5].as_u8().unwrap(),
        signature: {
            let bytes = values[6].as_fixed_bytes().unwrap();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(bytes);
            sig
        },
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
