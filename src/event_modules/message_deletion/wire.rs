use super::super::layout::common::{COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES};
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

/// MessageDeletion (type 7): type(1) + created_at(8) + target_event_id(32) + author_id(32)
///                          + signed_by(32) + signer_type(1) + signature(64) = 170
pub const MESSAGE_DELETION_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 32 + SIGNATURE_TRAILER_BYTES;

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
    if blob.len() < MESSAGE_DELETION_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: MESSAGE_DELETION_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > MESSAGE_DELETION_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: MESSAGE_DELETION_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_MESSAGE_DELETION {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_MESSAGE_DELETION,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut target_event_id = [0u8; 32];
    target_event_id.copy_from_slice(&blob[9..41]);

    let mut author_id = [0u8; 32];
    author_id.copy_from_slice(&blob[41..73]);

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[73..105]);

    let signer_type = blob[105];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[106..170]);

    Ok(ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms,
        target_event_id,
        author_id,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_message_deletion(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let del = match event {
        ParsedEvent::MessageDeletion(d) => d,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(MESSAGE_DELETION_WIRE_SIZE);
    buf.push(EVENT_TYPE_MESSAGE_DELETION);
    buf.extend_from_slice(&del.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&del.target_event_id);
    buf.extend_from_slice(&del.author_id);
    buf.extend_from_slice(&del.signed_by);
    buf.push(del.signer_type);
    buf.extend_from_slice(&del.signature);
    Ok(buf)
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
