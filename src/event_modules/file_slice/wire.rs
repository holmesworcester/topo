use super::super::layout::common::{COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_FILE_SLICE};

// --- Layout (owned by this module) ---

/// FileSlice: canonical fixed ciphertext size (256 KiB)
pub const FILE_SLICE_CIPHERTEXT_BYTES: usize = 262_144;

/// FileSlice (type 25): type(1) + created_at(8) + file_id(32) + slice_number(4)
///   + ciphertext(262144) + signed_by(32) + signer_type(1) + signature(64) = 262286
pub const FILE_SLICE_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 4 + FILE_SLICE_CIPHERTEXT_BYTES + SIGNATURE_TRAILER_BYTES;

mod file_slice_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const FILE_ID: usize = 9;
    pub const SLICE_NUMBER: usize = 41;
    pub const CIPHERTEXT: usize = 45;
    pub const SIGNED_BY: usize = 45 + super::FILE_SLICE_CIPHERTEXT_BYTES; // 262189
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32; // 262221
    pub const SIGNATURE: usize = SIGNER_TYPE + 1; // 262222
}

use file_slice_offsets as off;

/// Maximum ciphertext size per file slice: canonical fixed 256 KiB.
/// Final plaintext chunks are zero-padded before encryption.
/// Receiver uses blob_bytes from File for final truncation.
pub const FILE_SLICE_MAX_BYTES: usize = FILE_SLICE_CIPHERTEXT_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSliceEvent {
    pub created_at_ms: u64,
    pub file_id: [u8; 32],
    pub slice_number: u32,
    pub ciphertext: Vec<u8>,
    pub signed_by: [u8; 32],
    pub signer_type: u8,
    pub signature: [u8; 64],
}

impl super::super::Describe for FileSliceEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("file_id", super::super::short_id_b64(&self.file_id)),
            ("slice_number", self.slice_number.to_string()),
            ("data", format!("{} bytes", self.ciphertext.len())),
        ]
    }
}

pub fn parse_file_slice(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < FILE_SLICE_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: FILE_SLICE_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > FILE_SLICE_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: FILE_SLICE_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_FILE_SLICE {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_FILE_SLICE,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[off::CREATED_AT..off::FILE_ID].try_into().unwrap());

    let mut file_id = [0u8; 32];
    file_id.copy_from_slice(&blob[off::FILE_ID..off::SLICE_NUMBER]);

    let slice_number =
        u32::from_le_bytes(blob[off::SLICE_NUMBER..off::CIPHERTEXT].try_into().unwrap());

    let ciphertext = blob[off::CIPHERTEXT..off::CIPHERTEXT + FILE_SLICE_CIPHERTEXT_BYTES].to_vec();

    let mut signed_by = [0u8; 32];
    signed_by.copy_from_slice(&blob[off::SIGNED_BY..off::SIGNER_TYPE]);

    let signer_type = blob[off::SIGNER_TYPE];

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[off::SIGNATURE..off::SIGNATURE + 64]);

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

    if fs.ciphertext.len() != FILE_SLICE_CIPHERTEXT_BYTES {
        return Err(EventError::ContentTooLong(fs.ciphertext.len()));
    }

    let mut buf = vec![0u8; FILE_SLICE_WIRE_SIZE];

    buf[off::TYPE_CODE] = EVENT_TYPE_FILE_SLICE;
    buf[off::CREATED_AT..off::FILE_ID].copy_from_slice(&fs.created_at_ms.to_le_bytes());
    buf[off::FILE_ID..off::SLICE_NUMBER].copy_from_slice(&fs.file_id);
    buf[off::SLICE_NUMBER..off::CIPHERTEXT].copy_from_slice(&fs.slice_number.to_le_bytes());
    buf[off::CIPHERTEXT..off::CIPHERTEXT + FILE_SLICE_CIPHERTEXT_BYTES]
        .copy_from_slice(&fs.ciphertext);
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&fs.signed_by);
    buf[off::SIGNER_TYPE] = fs.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&fs.signature);

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
    projector: super::projector::project_pure,
    context_loader: super::projection_context::build_projector_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn offsets_consistent() {
        assert_eq!(file_slice_offsets::SIGNATURE + 64, FILE_SLICE_WIRE_SIZE);
    }
}
