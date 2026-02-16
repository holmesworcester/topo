use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_MESSAGE_ATTACHMENT};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAttachmentEvent {
    pub created_at_ms: u64,
    pub message_id: [u8; 32],      // dep: parent message
    pub file_id: [u8; 32],         // random ID (NOT an event_id dep)
    pub blob_bytes: u64,            // total plaintext file size
    pub total_slices: u32,
    pub slice_bytes: u32,           // bytes per non-final slice
    pub root_hash: [u8; 32],       // Blake2b-256 of concatenated plaintext
    pub key_event_id: [u8; 32],    // dep: decrypt key
    pub filename: String,
    pub mime_type: String,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

/// Wire format (min 254 bytes, signed):
/// [0]            type=24
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        message_id (32 bytes)
/// [41..73]       file_id (32 bytes)
/// [73..81]       blob_bytes (u64 LE)
/// [81..85]       total_slices (u32 LE)
/// [85..89]       slice_bytes (u32 LE)
/// [89..121]      root_hash (32 bytes)
/// [121..153]     key_event_id (32 bytes)
/// [153..155]     filename_len (u16 LE)
/// [155..155+N]   filename (UTF-8)
/// [155+N..157+N] mime_len (u16 LE)
/// [157+N..157+N+M] mime_type (UTF-8)
/// --- signature trailer (97 bytes) ---
/// [157+N+M..157+N+M+32]  signed_by (32 bytes)
/// [157+N+M+32]            signer_type (1 byte)
/// [157+N+M+33..157+N+M+97] signature (64 bytes)
pub fn parse_message_attachment(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    // Minimum: type(1) + created_at(8) + message_id(32) + file_id(32) + blob_bytes(8)
    //        + total_slices(4) + slice_bytes(4) + root_hash(32) + key_event_id(32)
    //        + filename_len(2) + mime_len(2) + signed_by(32) + signer_type(1) + signature(64) = 254
    if blob.len() < 254 {
        return Err(EventError::TooShort {
            expected: 254,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_MESSAGE_ATTACHMENT {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_MESSAGE_ATTACHMENT,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut message_id = [0u8; 32];
    message_id.copy_from_slice(&blob[9..41]);

    let mut file_id = [0u8; 32];
    file_id.copy_from_slice(&blob[41..73]);

    let blob_bytes = u64::from_le_bytes(blob[73..81].try_into().unwrap());
    let total_slices = u32::from_le_bytes(blob[81..85].try_into().unwrap());
    let slice_bytes = u32::from_le_bytes(blob[85..89].try_into().unwrap());

    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&blob[89..121]);

    let mut key_event_id = [0u8; 32];
    key_event_id.copy_from_slice(&blob[121..153]);

    let filename_len = u16::from_le_bytes(blob[153..155].try_into().unwrap()) as usize;
    if blob.len() < 157 + filename_len + 97 {
        return Err(EventError::TooShort {
            expected: 157 + filename_len + 97,
            actual: blob.len(),
        });
    }
    let filename = String::from_utf8_lossy(&blob[155..155 + filename_len]).to_string();

    let mime_offset = 155 + filename_len;
    if blob.len() < mime_offset + 2 {
        return Err(EventError::TooShort {
            expected: mime_offset + 2,
            actual: blob.len(),
        });
    }
    let mime_len = u16::from_le_bytes(blob[mime_offset..mime_offset + 2].try_into().unwrap()) as usize;
    let expected_total = mime_offset + 2 + mime_len + 97;
    if blob.len() < expected_total {
        return Err(EventError::TooShort {
            expected: expected_total,
            actual: blob.len(),
        });
    }
    if blob.len() > expected_total {
        return Err(EventError::TrailingData {
            expected: expected_total,
            actual: blob.len(),
        });
    }
    let mime_type = String::from_utf8_lossy(&blob[mime_offset + 2..mime_offset + 2 + mime_len]).to_string();

    let trailer_start = mime_offset + 2 + mime_len;
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[trailer_start..trailer_start + 32]);

    let signer_type = blob[trailer_start + 32];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[trailer_start + 33..trailer_start + 97]);

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

    let filename_bytes = att.filename.as_bytes();
    let mime_bytes = att.mime_type.as_bytes();
    if filename_bytes.len() > 65535 {
        return Err(EventError::ContentTooLong(filename_bytes.len()));
    }
    if mime_bytes.len() > 65535 {
        return Err(EventError::ContentTooLong(mime_bytes.len()));
    }

    let total = 157 + filename_bytes.len() + mime_bytes.len() + 97;
    let mut buf = Vec::with_capacity(total);

    buf.push(EVENT_TYPE_MESSAGE_ATTACHMENT);
    buf.extend_from_slice(&att.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&att.message_id);
    buf.extend_from_slice(&att.file_id);
    buf.extend_from_slice(&att.blob_bytes.to_le_bytes());
    buf.extend_from_slice(&att.total_slices.to_le_bytes());
    buf.extend_from_slice(&att.slice_bytes.to_le_bytes());
    buf.extend_from_slice(&att.root_hash);
    buf.extend_from_slice(&att.key_event_id);
    buf.extend_from_slice(&(filename_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(filename_bytes);
    buf.extend_from_slice(&(mime_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(mime_bytes);
    buf.extend_from_slice(&att.signed_by);
    buf.push(att.signer_type);
    buf.extend_from_slice(&att.signature);

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
};
