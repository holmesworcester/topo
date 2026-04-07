use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_FILE_SLICE};
use std::fmt;

// --- Layout (owned by this module) ---

/// Maximum supported attachment size for bao-verified file sends.
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Logical plaintext bytes carried by each file slice.
pub const FILE_SLICE_DATA_BYTES: usize = 256 * 1024;

/// Bytes reserved at the front of the payload for the bao encoding length.
pub const BAO_PAYLOAD_LEN_BYTES: usize = 4;

/// Maximum bao payload bytes per slice, including the 4-byte length prefix.
///
/// With a 10 GiB file cap and 256 KiB logical slices, the worst-case bao
/// overhead for a full slice is 17_352 bytes. We round that up to 17 KiB for a
/// small alignment margin while keeping the field size fixed and predictable.
pub const BAO_ENCODING_BUDGET: usize = 17 * 1024;

/// FileSlice: canonical fixed payload size (256 KiB data + bao proof budget).
pub const FILE_SLICE_CIPHERTEXT_BYTES: usize = FILE_SLICE_DATA_BYTES + BAO_ENCODING_BUDGET;

pub const FILE_SLICE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("file_id"),
    FieldSpec::U32("slice_number"),
    FieldSpec::FixedBytes("ciphertext", FILE_SLICE_CIPHERTEXT_BYTES),
];

/// FileSlice (type 25): type(1) + created_at(8) + file_id(32) + slice_number(4)
///   + payload(FILE_SLICE_CIPHERTEXT_BYTES)
pub const FILE_SLICE_WIRE_SIZE: usize = wire_size_for_fields(FILE_SLICE_FIELDS);

/// Maximum stored payload size per file slice.
pub const FILE_SLICE_MAX_BYTES: usize = FILE_SLICE_CIPHERTEXT_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSliceEvent {
    pub created_at_ms: u64,
    pub file_id: [u8; 32],
    pub slice_number: u32,
    pub ciphertext: Vec<u8>,
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
    let mut values = decode_fields(EVENT_TYPE_FILE_SLICE, FILE_SLICE_FIELDS, blob)?;

    // Move the large ciphertext vec out to avoid a 256 KiB copy.
    let ciphertext = match std::mem::replace(&mut values[3], FieldValue::Bool(false)) {
        FieldValue::FixedBytes(v) => v,
        _ => unreachable!("decode_fields guarantees FixedBytes for FixedBytes spec"),
    };
    Ok(ParsedEvent::FileSlice(FileSliceEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        file_id: values[1].as_event_id().unwrap(),
        slice_number: values[2].as_u32().unwrap(),
        ciphertext,
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

    let values = vec![
        FieldValue::Timestamp(fs.created_at_ms),
        FieldValue::EventId(fs.file_id),
        FieldValue::U32(fs.slice_number),
        FieldValue::FixedBytes(fs.ciphertext.clone()),
    ];

    Ok(encode_fields(
        EVENT_TYPE_FILE_SLICE,
        FILE_SLICE_FIELDS,
        &values,
    )?)
}

pub static FILE_SLICE_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_FILE_SLICE,
    type_name: "file_slice",
    projection_table: "file_slices",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: true,
    parse: parse_file_slice,
    encode: encode_file_slice,
    projector: super::projector::project_pure,
    context_loader: super::projector::build_projector_context,
};

/// Maximum encoded bao slice bytes excluding the 4-byte length prefix.
pub const BAO_MAX_ENCODING_BYTES: usize = FILE_SLICE_CIPHERTEXT_BYTES - BAO_PAYLOAD_LEN_BYTES;

/// Plaintext capacity per slice after enlarging the wire payload to hold the
/// bao proof budget.
pub const BAO_PLAINTEXT_CAPACITY: usize = FILE_SLICE_DATA_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaoPayloadTooLarge {
    pub actual: usize,
    pub max: usize,
}

impl fmt::Display for BaoPayloadTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bao encoding too large: {} bytes > {} bytes",
            self.actual, self.max
        )
    }
}

impl std::error::Error for BaoPayloadTooLarge {}

/// Pack a bao slice encoding into the fixed-size ciphertext field.
///
/// Format: `[encoding_len: u32 LE][bao slice encoding, zero-padded]`.
/// The bao slice encoding contains the plaintext data interleaved with
/// BLAKE3 tree verification nodes (~6% overhead).
pub fn pack_bao_payload(
    bao_encoding: &[u8],
    _plaintext: &[u8],
) -> Result<Vec<u8>, BaoPayloadTooLarge> {
    if bao_encoding.len() > BAO_MAX_ENCODING_BYTES {
        return Err(BaoPayloadTooLarge {
            actual: bao_encoding.len(),
            max: BAO_MAX_ENCODING_BYTES,
        });
    }
    let enc_len = bao_encoding.len() as u32;
    let mut payload = vec![0u8; FILE_SLICE_CIPHERTEXT_BYTES];
    payload[0..BAO_PAYLOAD_LEN_BYTES].copy_from_slice(&enc_len.to_le_bytes());
    payload[BAO_PAYLOAD_LEN_BYTES..BAO_PAYLOAD_LEN_BYTES + bao_encoding.len()]
        .copy_from_slice(bao_encoding);
    Ok(payload)
}

/// Unpack a bao payload.  Returns (bao_encoding, raw_data_fallback).
///
/// If `encoding_len == 0`, the payload has no bao encoding and the raw
/// plaintext starts at offset 4 (legacy/generated data).
pub fn unpack_bao_payload(payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if payload.len() < BAO_PAYLOAD_LEN_BYTES {
        return (Vec::new(), payload.to_vec());
    }
    let enc_len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if enc_len == 0 {
        let raw_len = payload
            .len()
            .saturating_sub(BAO_PAYLOAD_LEN_BYTES)
            .min(FILE_SLICE_DATA_BYTES);
        return (
            Vec::new(),
            payload[BAO_PAYLOAD_LEN_BYTES..BAO_PAYLOAD_LEN_BYTES + raw_len].to_vec(),
        );
    }
    let end = (BAO_PAYLOAD_LEN_BYTES + enc_len).min(payload.len());
    let encoding = payload[BAO_PAYLOAD_LEN_BYTES..end].to_vec();
    (encoding, Vec::new())
}

/// Effective plaintext capacity per slice (convenience alias).
pub fn effective_plaintext_capacity(_bao_overhead: usize) -> usize {
    BAO_PLAINTEXT_CAPACITY
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use crate::event_modules::layout::field_spec::field_offset;

    #[test]
    fn offsets_consistent() {
        assert_eq!(
            field_offset(FILE_SLICE_FIELDS, 3) + FILE_SLICE_CIPHERTEXT_BYTES,
            FILE_SLICE_WIRE_SIZE
        );
    }
}
