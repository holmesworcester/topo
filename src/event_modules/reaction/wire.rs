use super::super::layout::common::{
    read_text_slot, write_text_slot, COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_REACTION};

// --- Layout (owned by this module) ---

/// Reaction emoji: fixed UTF-8 slot (64 bytes, zero-padded)
pub const REACTION_EMOJI_BYTES: usize = 64;

/// Reaction (type 2): type(1) + created_at(8) + target_event_id(32) + author_id(32)
///                   + emoji(64) + signed_by(32) + signer_type(1) + signature(64) = 234
pub const REACTION_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 32 + REACTION_EMOJI_BYTES + SIGNATURE_TRAILER_BYTES;

pub mod offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const TARGET_EVENT_ID: usize = 9;
    pub const AUTHOR_ID: usize = 41;
    pub const EMOJI: usize = 73;
    pub const SIGNED_BY: usize = 73 + super::REACTION_EMOJI_BYTES; // 137
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32; // 169
    pub const SIGNATURE: usize = SIGNER_TYPE + 1; // 170
}

use offsets as off;

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

    let created_at_ms = u64::from_le_bytes(
        blob[off::CREATED_AT..off::TARGET_EVENT_ID]
            .try_into()
            .unwrap(),
    );

    let mut target_event_id = [0u8; 32];
    target_event_id.copy_from_slice(&blob[off::TARGET_EVENT_ID..off::AUTHOR_ID]);

    let mut author_id = [0u8; 32];
    author_id.copy_from_slice(&blob[off::AUTHOR_ID..off::EMOJI]);

    let emoji = read_text_slot(&blob[off::EMOJI..off::EMOJI + REACTION_EMOJI_BYTES])
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
    write_text_slot(
        &rxn.emoji,
        &mut buf[off::EMOJI..off::EMOJI + REACTION_EMOJI_BYTES],
    )
    .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&rxn.signed_by);
    buf[off::SIGNER_TYPE] = rxn.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&rxn.signature);

    Ok(buf)
}

pub static REACTION_TYPE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_REACTION,
    type_name: "reaction",
    projection_table: "reactions",
    share_scope: ShareScope::Shared,
    dep_fields: &["target_event_id", "author_id", "signed_by"],
    dep_field_type_codes: &[&[1], &[14, 15], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_reaction,
    encode: encode_reaction,
    projector: super::projector::project_pure,
    context_loader: super::projection_context::build_projector_context,
};
