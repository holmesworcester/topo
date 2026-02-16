use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_FILE_SLICE};

/// Maximum ciphertext size per file slice.
/// Derived: EVENT_MAX_BLOB_BYTES(1_048_576) - wire_overhead(146) = 1_048_430.
/// This guarantees the max encoded file_slice event fits within the sync frame limit.
pub const FILE_SLICE_MAX_BYTES: usize = 1_048_576 - 146;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSliceEvent {
    pub created_at_ms: u64,
    pub file_id: [u8; 32],         // matches attachment's file_id
    pub slice_number: u32,
    pub ciphertext: Vec<u8>,        // up to ~1 MiB, uses u32 length prefix
    pub signed_by: [u8; 32],       // dep: signer key
    pub signer_type: u8,
    pub signature: [u8; 64],       // trailing Ed25519
}

/// Wire format (min 146 bytes, signed):
/// [0]            type=25
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        file_id (32 bytes)
/// [41..45]       slice_number (u32 LE)
/// [45..49]       ciphertext_len (u32 LE)
/// [49..49+N]     ciphertext
/// --- signature trailer (97 bytes) ---
/// [49+N..49+N+32]  signed_by (32 bytes)
/// [49+N+32]        signer_type (1 byte)
/// [49+N+33..49+N+97] signature (64 bytes)
pub fn parse_file_slice(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    // Minimum: type(1) + created_at(8) + file_id(32) + slice_number(4) + ciphertext_len(4)
    //        + signed_by(32) + signer_type(1) + signature(64) = 146
    if blob.len() < 146 {
        return Err(EventError::TooShort {
            expected: 146,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_FILE_SLICE {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_FILE_SLICE,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());

    let mut file_id = [0u8; 32];
    file_id.copy_from_slice(&blob[9..41]);

    let slice_number = u32::from_le_bytes(blob[41..45].try_into().unwrap());

    let ciphertext_len = u32::from_le_bytes(blob[45..49].try_into().unwrap()) as usize;
    if ciphertext_len > FILE_SLICE_MAX_BYTES {
        return Err(EventError::ContentTooLong(ciphertext_len));
    }

    let expected_len = 49 + ciphertext_len + 97; // 97 = signed_by(32) + signer_type(1) + signature(64)
    if blob.len() < expected_len {
        return Err(EventError::TooShort {
            expected: expected_len,
            actual: blob.len(),
        });
    }
    if blob.len() > expected_len {
        return Err(EventError::TrailingData {
            expected: expected_len,
            actual: blob.len(),
        });
    }

    let ciphertext = blob[49..49 + ciphertext_len].to_vec();

    let trailer_start = 49 + ciphertext_len;
    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[trailer_start..trailer_start + 32]);

    let signer_type = blob[trailer_start + 32];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[trailer_start + 33..trailer_start + 97]);

    Ok(ParsedEvent::FileSlice(FileSliceEvent {
        created_at_ms,
        file_id,
        slice_number,
        ciphertext,
        signed_by,
        signer_type,
        signature,
    }))
}

pub fn encode_file_slice(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let fs = match event {
        ParsedEvent::FileSlice(f) => f,
        _ => return Err(EventError::WrongVariant),
    };

    if fs.ciphertext.len() > FILE_SLICE_MAX_BYTES {
        return Err(EventError::ContentTooLong(fs.ciphertext.len()));
    }

    let total = 49 + fs.ciphertext.len() + 97;
    let mut buf = Vec::with_capacity(total);

    buf.push(EVENT_TYPE_FILE_SLICE);
    buf.extend_from_slice(&fs.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&fs.file_id);
    buf.extend_from_slice(&fs.slice_number.to_le_bytes());
    buf.extend_from_slice(&(fs.ciphertext.len() as u32).to_le_bytes());
    buf.extend_from_slice(&fs.ciphertext);
    buf.extend_from_slice(&fs.signed_by);
    buf.push(fs.signer_type);
    buf.extend_from_slice(&fs.signature);

    Ok(buf)
}

pub static FILE_SLICE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_FILE_SLICE,
    type_name: "file_slice",
    projection_table: "file_slices",
    share_scope: ShareScope::Shared,
    dep_fields: &["signed_by"],
    dep_field_type_codes: &[&[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_file_slice,
    encode: encode_file_slice,
};
