use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_REACTION};

// --- Declarative field layout ---

/// Reaction emoji: fixed UTF-8 slot (64 bytes, zero-padded)
pub const REACTION_EMOJI_BYTES: usize = 64;

pub const REACTION_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("target_event_id"),
    FieldSpec::EventId("author_id"),
    FieldSpec::Text("emoji", 64),
];

/// Reaction (type 2): type(1) + created_at(8) + target_event_id(32) + author_id(32)
///                   + emoji(64) = 137
pub const REACTION_WIRE_SIZE: usize = wire_size_for_fields(REACTION_FIELDS);

// Field offsets are computed from REACTION_FIELDS via field_offset().
// No hand-written offset constants needed.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
    pub emoji: String,
}

impl super::super::Describe for ReactionEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![("emoji", self.emoji.clone())]
    }
}

pub fn parse_reaction(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_REACTION, REACTION_FIELDS, blob)?;

    Ok(ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        target_event_id: values[1].as_event_id().unwrap(),
        author_id: values[2].as_event_id().unwrap(),
        emoji: values[3].as_text().unwrap().to_string(),
    }))
}

pub fn encode_reaction(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let rxn = match event {
        ParsedEvent::Reaction(r) => r,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(rxn.created_at_ms),
        FieldValue::EventId(rxn.target_event_id),
        FieldValue::EventId(rxn.author_id),
        FieldValue::Text(rxn.emoji.clone()),
    ];

    Ok(encode_fields(
        EVENT_TYPE_REACTION,
        REACTION_FIELDS,
        &values,
    )?)
}

pub static REACTION_TYPE_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_REACTION,
    type_name: "reaction",
    projection_table: "reactions",
    share_scope: ShareScope::Shared,
    dep_fields: &["target_event_id", "author_id"],
    dep_field_type_codes: &[&[1], &[14, 15]],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: true,
    parse: parse_reaction,
    encode: encode_reaction,
    projector: super::projector::project_pure,
    context_loader: super::projector::build_projector_context,
};
