use super::super::fixed_layout::{self, MESSAGE_ATTACHMENT_WIRE_SIZE, ATTACHMENT_FILENAME_BYTES, ATTACHMENT_MIME_BYTES, attachment_offsets as off};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE_ATTACHMENT};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAttachmentEvent {
    pub created_at_ms: u64,
    pub message_id: [u8; 32],
    pub file_id: [u8; 32],
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: [u8; 32],
    pub key_event_id: [u8; 32],
    pub filename: String,
    pub mime_type: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

/// Wire format (633 bytes fixed, signed):
/// [0]            type=24
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        message_id (32 bytes)
/// [41..73]       file_id (32 bytes)
/// [73..81]       blob_bytes (u64 LE)
/// [81..85]       total_slices (u32 LE)
/// [85..89]       slice_bytes (u32 LE)
/// [89..121]      root_hash (32 bytes)
/// [121..153]     key_event_id (32 bytes)
/// [153..408]     filename (255 bytes, UTF-8 zero-padded)
/// [408..536]     mime_type (128 bytes, UTF-8 zero-padded)
/// [536..568]     signed_by (32 bytes)
/// [568]          signer_type (1 byte)
/// [569..633]     signature (64 bytes)
pub fn parse_message_attachment(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < MESSAGE_ATTACHMENT_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: MESSAGE_ATTACHMENT_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > MESSAGE_ATTACHMENT_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: MESSAGE_ATTACHMENT_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_MESSAGE_ATTACHMENT {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_MESSAGE_ATTACHMENT,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::MESSAGE_ID].try_into().unwrap());

    let mut message_id = [0u8; 32];
    message_id.copy_from_slice(&blob[off::MESSAGE_ID..off::FILE_ID]);

    let mut file_id = [0u8; 32];
    file_id.copy_from_slice(&blob[off::FILE_ID..off::BLOB_BYTES]);

    let blob_bytes = u64::from_le_bytes(blob[off::BLOB_BYTES..off::TOTAL_SLICES].try_into().unwrap());
    let total_slices = u32::from_le_bytes(blob[off::TOTAL_SLICES..off::SLICE_BYTES].try_into().unwrap());
    let slice_bytes = u32::from_le_bytes(blob[off::SLICE_BYTES..off::ROOT_HASH].try_into().unwrap());

    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&blob[off::ROOT_HASH..off::KEY_EVENT_ID]);

    let mut key_event_id = [0u8; 32];
    key_event_id.copy_from_slice(&blob[off::KEY_EVENT_ID..off::FILENAME]);

    let filename = fixed_layout::read_text_slot(&blob[off::FILENAME..off::FILENAME + ATTACHMENT_FILENAME_BYTES])
        .map_err(EventError::TextSlot)?;

    let mime_type = fixed_layout::read_text_slot(&blob[off::MIME_TYPE..off::MIME_TYPE + ATTACHMENT_MIME_BYTES])
        .map_err(EventError::TextSlot)?;

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);

    let signer_type = blob[off::SIGNER_TYPE];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

    validate_attachment_metadata(blob_bytes, total_slices, slice_bytes)?;

    Ok(ParsedEvent::MessageAttachment(MessageAttachmentEvent {
        created_at_ms,
        message_id,
        file_id,
        blob_bytes,
        total_slices,
        slice_bytes,
        root_hash,
        key_event_id,
        filename,
        mime_type,
        signed_by,
        signer_type,
        signature,
    }))
}

fn validate_attachment_metadata(blob_bytes: u64, total_slices: u32, slice_bytes: u32) -> Result<(), EventError> {
    if blob_bytes > 0 && total_slices == 0 {
        return Err(EventError::InvalidMetadata("blob_bytes > 0 but total_slices == 0"));
    }
    if total_slices > 0 && slice_bytes == 0 {
        return Err(EventError::InvalidMetadata("total_slices > 0 but slice_bytes == 0"));
    }
    if total_slices > 0 {
        let expected = (blob_bytes + slice_bytes as u64 - 1) / slice_bytes as u64;
        if total_slices as u64 != expected {
            return Err(EventError::InvalidMetadata(
                "total_slices inconsistent with blob_bytes/slice_bytes",
            ));
        }
    }
    Ok(())
}

pub fn encode_message_attachment(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let att = match event {
        ParsedEvent::MessageAttachment(a) => a,
        _ => return Err(EventError::WrongVariant),
    };

    validate_attachment_metadata(att.blob_bytes, att.total_slices, att.slice_bytes)?;

    if att.filename.as_bytes().len() > ATTACHMENT_FILENAME_BYTES {
        return Err(EventError::ContentTooLong(att.filename.as_bytes().len()));
    }
    if att.mime_type.as_bytes().len() > ATTACHMENT_MIME_BYTES {
        return Err(EventError::ContentTooLong(att.mime_type.as_bytes().len()));
    }

    let mut buf = vec![0u8; MESSAGE_ATTACHMENT_WIRE_SIZE];

    buf[off::TYPE_CODE] = EVENT_TYPE_MESSAGE_ATTACHMENT;
    buf[off::CREATED_AT..off::MESSAGE_ID].copy_from_slice(&att.created_at_ms.to_le_bytes());
    buf[off::MESSAGE_ID..off::FILE_ID].copy_from_slice(&att.message_id);
    buf[off::FILE_ID..off::BLOB_BYTES].copy_from_slice(&att.file_id);
    buf[off::BLOB_BYTES..off::TOTAL_SLICES].copy_from_slice(&att.blob_bytes.to_le_bytes());
    buf[off::TOTAL_SLICES..off::SLICE_BYTES].copy_from_slice(&att.total_slices.to_le_bytes());
    buf[off::SLICE_BYTES..off::ROOT_HASH].copy_from_slice(&att.slice_bytes.to_le_bytes());
    buf[off::ROOT_HASH..off::KEY_EVENT_ID].copy_from_slice(&att.root_hash);
    buf[off::KEY_EVENT_ID..off::FILENAME].copy_from_slice(&att.key_event_id);
    fixed_layout::write_text_slot(&att.filename, &mut buf[off::FILENAME..off::FILENAME + ATTACHMENT_FILENAME_BYTES])
        .map_err(EventError::TextSlot)?;
    fixed_layout::write_text_slot(&att.mime_type, &mut buf[off::MIME_TYPE..off::MIME_TYPE + ATTACHMENT_MIME_BYTES])
        .map_err(EventError::TextSlot)?;
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&att.signed_by);
    buf[off::SIGNER_TYPE] = att.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&att.signature);

    Ok(buf)
}

pub static MESSAGE_ATTACHMENT_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MESSAGE_ATTACHMENT,
    type_name: "message_attachment",
    projection_table: "message_attachments",
    share_scope: ShareScope::Shared,
    dep_fields: &["message_id", "key_event_id", "signed_by"],
    dep_field_type_codes: &[&[1], &[6], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_message_attachment,
    encode: encode_message_attachment,
    projector: super::projector::project_pure,
};
