use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE_DELETION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32], // message being deleted
}

impl super::super::Describe for MessageDeletionEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("target", super::super::short_id_b64(&self.target_event_id))]
    }
}

pub const MESSAGE_DELETION_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("target_event_id"),
];

/// MessageDeletion (type 7): type(1) + created_at(8) + target_event_id(32) = 41
pub const MESSAGE_DELETION_WIRE_SIZE: usize = wire_size_for_fields(MESSAGE_DELETION_FIELDS);

/// Wire format (138 bytes fixed, signed):
/// [0]      type_code = 7
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  target_event_id (32 bytes)
pub fn parse_message_deletion(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if let Some((created_at_ms, target_event_id)) =
        topo_verus_proofs::event_modules::layout::ts_id::parse_ts_id(
            EVENT_TYPE_MESSAGE_DELETION,
            blob,
        )
    {
        return Ok(ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms,
            target_event_id,
        }));
    }
    let values = decode_fields(EVENT_TYPE_MESSAGE_DELETION, MESSAGE_DELETION_FIELDS, blob)?;
    Ok(ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        target_event_id: values[1].as_event_id().unwrap(),
    }))
}

pub fn encode_message_deletion(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let del = match event {
        ParsedEvent::MessageDeletion(d) => d,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(topo_verus_proofs::event_modules::layout::ts_id::encode_ts_id(
        EVENT_TYPE_MESSAGE_DELETION,
        del.created_at_ms,
        &del.target_event_id,
    ))
}

pub static MESSAGE_DELETION_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_MESSAGE_DELETION,
    type_name: "message_deletion",
    projection_table: "deleted_messages",
    share_scope: ShareScope::Shared,
    // Two-stage deletion intent model: do not dep-block on target.
    // The projector validates target/signer from context and records intent first.
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: true,
    parse: parse_message_deletion,
    encode: encode_message_deletion,
    projector: super::projector::project_pure,
    context_loader: super::projector::build_projector_context,
};
