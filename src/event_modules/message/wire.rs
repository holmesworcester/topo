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
}

impl super::super::Describe for MessageEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("content", self.content.clone())]
    }
}

pub fn parse_message(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if let Some((ts, workspace_id, author_id, content_slot)) =
        topo_verus_proofs::event_modules::layout::shapes::parse_ts_id2_fb1024(
            EVENT_TYPE_MESSAGE,
            blob,
        )
    {
        let content = crate::event_modules::layout::common::read_text_slot(&content_slot)
            .map_err(EventError::TextSlot)?;
        return Ok(ParsedEvent::Message(MessageEvent {
            created_at_ms: ts,
            workspace_id,
            author_id,
            content,
        }));
    }
    let values = decode_fields(EVENT_TYPE_MESSAGE, MESSAGE_FIELDS, blob)?;
    Ok(ParsedEvent::Message(MessageEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        workspace_id: values[1].as_event_id().unwrap(),
        author_id: values[2].as_event_id().unwrap(),
        content: values[3].as_text().unwrap().to_string(),
    }))
}

pub fn encode_message(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let msg = match event {
        ParsedEvent::Message(m) => m,
        _ => return Err(EventError::WrongVariant),
    };
    let mut content_slot: [u8; MESSAGE_CONTENT_BYTES] = [0u8; MESSAGE_CONTENT_BYTES];
    crate::event_modules::layout::common::write_text_slot(&msg.content, &mut content_slot)
        .map_err(EventError::TextSlot)?;
    Ok(
        topo_verus_proofs::event_modules::layout::shapes::encode_ts_id2_fb1024(
            EVENT_TYPE_MESSAGE,
            msg.created_at_ms,
            &msg.workspace_id,
            &msg.author_id,
            &content_slot,
        ),
    )
}

pub static MESSAGE_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_MESSAGE,
    type_name: "message",
    projection_table: "messages",
    share_scope: ShareScope::Shared,
    dep_fields: &["author_id"],
    dep_field_type_codes: &[&[14, 15]],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: true,
    parse: parse_message,
    encode: encode_message,
    projector: super::projector::project_pure,
    context_loader: super::projector::build_projector_context,
};
