use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_FILE_SLICE};

// --- Layout (owned by this module) ---

/// FileSlice: canonical fixed ciphertext size (256 KiB)
pub const FILE_SLICE_CIPHERTEXT_BYTES: usize = 262_144;

pub const FILE_SLICE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("file_id"),
    FieldSpec::U32("slice_number"),
    FieldSpec::FixedBytes("ciphertext", 262_144),
];

/// FileSlice (type 25): type(1) + created_at(8) + file_id(32) + slice_number(4)
///   + ciphertext(262144) = 262189
pub const FILE_SLICE_WIRE_SIZE: usize = wire_size_for_fields(FILE_SLICE_FIELDS);

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
