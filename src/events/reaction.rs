use super::fixed_layout::{self, REACTION_WIRE_SIZE, REACTION_EMOJI_BYTES, reaction_offsets as off};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_REACTION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub created_at_ms: u64,
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
    pub emoji: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

/// Wire format (234 bytes fixed, signed):
/// [0]            type=2
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        target_event_id (32 bytes)
/// [41..73]       author_id (32 bytes)
/// [73..137]      emoji (64 bytes, UTF-8 zero-padded)
/// [137..169]     signed_by (32 bytes)
/// [169]          signer_type (1 byte)
/// [170..234]     signature (64 bytes)
pub fn parse_reaction(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < REACTION_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: REACTION_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > REACTION_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: REACTION_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_REACTION {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_REACTION,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::TARGET_EVENT_ID].try_into().unwrap());

    let mut target_event_id = [0u8; 32];
    target_event_id.copy_from_slice(&blob[off::TARGET_EVENT_ID..off::AUTHOR_ID]);

    let mut author_id = [0u8; 32];
    author_id.copy_from_slice(&blob[off::AUTHOR_ID..off::EMOJI]);

    let emoji = fixed_layout::read_text_slot(&blob[off::EMOJI..off::EMOJI + REACTION_EMOJI_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);

    let signer_type = blob[off::SIGNER_TYPE];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    Ok(ParsedEvent::Reaction(ReactionEvent {
        created_at_ms,
        target_event_id,
        author_id,
        emoji,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_reaction(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let rxn = match event {
        ParsedEvent::Reaction(r) => r,
        _ => return Err(EventError::WrongVariant),
    };

    let emoji_bytes = rxn.emoji.as_bytes();
    if emoji_bytes.len() > REACTION_EMOJI_BYTES {
        return Err(EventError::ContentTooLong(emoji_bytes.len()));
    }

    let mut buf = vec![0u8; REACTION_WIRE_SIZE];

    buf[off::TYPE_CODE] = EVENT_TYPE_REACTION;
    buf[off::CREATED_AT..off::TARGET_EVENT_ID].copy_from_slice(&rxn.created_at_ms.to_le_bytes());
    buf[off::TARGET_EVENT_ID..off::AUTHOR_ID].copy_from_slice(&rxn.target_event_id);
    buf[off::AUTHOR_ID..off::EMOJI].copy_from_slice(&rxn.author_id);
    fixed_layout::write_text_slot(&rxn.emoji, &mut buf[off::EMOJI..off::EMOJI + REACTION_EMOJI_BYTES])
        .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&rxn.signed_by);
    buf[off::SIGNER_TYPE] = rxn.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&rxn.signature);

    Ok(buf)
}

pub static REACTION_META: ReactionMeta = ReactionMeta;

// Use a wrapper to produce the static EventTypeMeta
pub struct ReactionMeta;

pub static REACTION_TYPE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_REACTION,
    type_name: "reaction",
    projection_table: "reactions",
    share_scope: ShareScope::Shared,
    dep_fields: &["target_event_id", "signed_by"],
    dep_field_type_codes: &[&[1], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_reaction,
    encode: encode_reaction,
};
