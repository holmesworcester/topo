use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE_DELETION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32], // message being deleted
    pub author_id: [u8; 32],       // must match message author (enables cross-device deletion)
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for MessageDeletionEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("target", super::super::short_id_b64(&self.target_event_id))]
    }
}

pub const MESSAGE_DELETION_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("target_event_id"),
    FieldSpec::EventId("author_id"),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

/// MessageDeletion (type 7): type(1) + created_at(8) + target_event_id(32) + author_id(32)
///                          + signed_by(32) + signer_type(1) + signature(64) = 170
pub const MESSAGE_DELETION_WIRE_SIZE: usize = wire_size_for_fields(MESSAGE_DELETION_FIELDS);

/// Wire format (170 bytes fixed, signed):
/// [0]      type_code = 7
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  target_event_id (32 bytes)
/// [41..73] author_id (32 bytes)
/// --- signature trailer (97 bytes) ---
/// [73..105] signed_by (32 bytes)
/// [105]     signer_type (1 byte)
/// [106..170] signature (64 bytes)
pub fn parse_message_deletion(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_MESSAGE_DELETION, MESSAGE_DELETION_FIELDS, blob)?;

    Ok(ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        target_event_id: values[1].as_event_id().unwrap(),
        author_id: values[2].as_event_id().unwrap(),
        signed_by: values[3].as_event_id().unwrap(),
        signer_type: values[4].as_u8().unwrap(),
        signature: {
            let bytes = values[5].as_fixed_bytes().unwrap();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(bytes);
            sig
        },
    }))
}

pub fn encode_message_deletion(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let del = match event {
        ParsedEvent::MessageDeletion(d) => d,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(del.created_at_ms),
        FieldValue::EventId(del.target_event_id),
        FieldValue::EventId(del.author_id),
        FieldValue::EventId(del.signed_by),
        FieldValue::U8(del.signer_type),
        FieldValue::FixedBytes(del.signature.to_vec()),
    ];

    Ok(encode_fields(EVENT_TYPE_MESSAGE_DELETION, MESSAGE_DELETION_FIELDS, &values)?)
}

pub static MESSAGE_DELETION_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE_DELETION,
    type_name: "message_deletion",
    projection_table: "deleted_messages",
    share_scope: ShareScope::Shared,
    // Two-stage deletion intent model: do not dep-block on target or author.
    // The projector validates target/author from context and records intent first.
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_message_deletion,
    encode: encode_message_deletion,
    projector: super::projector::project_pure,
    context_loader: super::projection_context::build_projector_context,
};
