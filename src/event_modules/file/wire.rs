use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_FILE};

// ─── Layout (owned by this module) ───

/// File filename: fixed UTF-8 slot (255 bytes, zero-padded)
pub const FILE_FILENAME_BYTES: usize = 255;

/// File MIME type: fixed UTF-8 slot (128 bytes, zero-padded)
pub const FILE_MIME_BYTES: usize = 128;

pub const FILE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),  // 0
    FieldSpec::EventId("message_id"),       // 1
    FieldSpec::EventId("file_id"),          // 2
    FieldSpec::U64("blob_bytes"),           // 3
    FieldSpec::U32("total_slices"),         // 4
    FieldSpec::U32("slice_bytes"),          // 5
    FieldSpec::EventId("root_hash"),        // 6
    FieldSpec::EventId("key_event_id"),     // 7
    FieldSpec::Text("filename", 255),       // 8
    FieldSpec::Text("mime_type", 128),      // 9
    FieldSpec::EventId("signed_by"),        // 10
    FieldSpec::U8("signer_type"),           // 11
    FieldSpec::FixedBytes("signature", 64), // 12
];

/// File (type 24): type(1) + created_at(8) + message_id(32) + file_id(32)
///   + blob_bytes(8) + total_slices(4) + slice_bytes(4) + root_hash(32) + key_event_id(32)
///   + filename(255) + mime_type(128) + signed_by(32) + signer_type(1) + signature(64) = 633
pub const FILE_WIRE_SIZE: usize = wire_size_for_fields(FILE_FIELDS);

/// Offset constants kept for external test use (canonical_wire_tests.rs).
/// Values match field_offset(FILE_FIELDS, index).
pub mod file_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const MESSAGE_ID: usize = 9;
    pub const FILE_ID: usize = 41;
    pub const BLOB_BYTES: usize = 73;
    pub const TOTAL_SLICES: usize = 81;
    pub const SLICE_BYTES: usize = 85;
    pub const ROOT_HASH: usize = 89;
    pub const KEY_EVENT_ID: usize = 121;
    pub const FILENAME: usize = 153;
    pub const MIME_TYPE: usize = 153 + super::FILE_FILENAME_BYTES; // 408
    pub const SIGNED_BY: usize = MIME_TYPE + super::FILE_MIME_BYTES; // 536
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32; // 568
    pub const SIGNATURE: usize = SIGNER_TYPE + 1; // 569

    /// Verify offsets match field_spec at test time.
    #[cfg(test)]
    pub fn verify_against_field_spec() {
        use super::super::super::layout::field_spec::field_offset;
        use super::FILE_FIELDS;
        assert_eq!(CREATED_AT, field_offset(FILE_FIELDS, 0));
        assert_eq!(MESSAGE_ID, field_offset(FILE_FIELDS, 1));
        assert_eq!(FILE_ID, field_offset(FILE_FIELDS, 2));
        assert_eq!(BLOB_BYTES, field_offset(FILE_FIELDS, 3));
        assert_eq!(TOTAL_SLICES, field_offset(FILE_FIELDS, 4));
        assert_eq!(SLICE_BYTES, field_offset(FILE_FIELDS, 5));
        assert_eq!(ROOT_HASH, field_offset(FILE_FIELDS, 6));
        assert_eq!(KEY_EVENT_ID, field_offset(FILE_FIELDS, 7));
        assert_eq!(FILENAME, field_offset(FILE_FIELDS, 8));
        assert_eq!(MIME_TYPE, field_offset(FILE_FIELDS, 9));
        assert_eq!(SIGNED_BY, field_offset(FILE_FIELDS, 10));
        assert_eq!(SIGNER_TYPE, field_offset(FILE_FIELDS, 11));
        assert_eq!(SIGNATURE, field_offset(FILE_FIELDS, 12));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
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

impl super::super::Describe for FileEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("filename", self.filename.clone()),
            ("mime_type", self.mime_type.clone()),
            ("file_id", super::super::short_id_b64(&self.file_id)),
            (
                "size",
                format!("{} bytes, {} slices", self.blob_bytes, self.total_slices),
            ),
        ]
    }
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
pub fn parse_file(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_FILE, FILE_FIELDS, blob)?;

    let blob_bytes = values[3].as_u64().unwrap();
    let total_slices = values[4].as_u32().unwrap();
    let slice_bytes = values[5].as_u32().unwrap();

    validate_file_metadata(blob_bytes, total_slices, slice_bytes)?;

    Ok(ParsedEvent::File(FileEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        message_id: values[1].as_event_id().unwrap(),
        file_id: values[2].as_event_id().unwrap(),
        blob_bytes,
        total_slices,
        slice_bytes,
        root_hash: values[6].as_event_id().unwrap(),
        key_event_id: values[7].as_event_id().unwrap(),
        filename: values[8].as_text().unwrap().to_string(),
        mime_type: values[9].as_text().unwrap().to_string(),
        signed_by: values[10].as_event_id().unwrap(),
        signer_type: values[11].as_u8().unwrap(),
        signature: {
            let bytes = values[12].as_fixed_bytes().unwrap();
            let mut sig = [0u8; 64];
            sig.copy_from_slice(bytes);
            sig
        },
    }))
}

fn validate_file_metadata(
    blob_bytes: u64,
    total_slices: u32,
    slice_bytes: u32,
) -> Result<(), EventError> {
    if blob_bytes > 0 && total_slices == 0 {
        return Err(EventError::InvalidMetadata(
            "blob_bytes > 0 but total_slices == 0",
        ));
    }
    if total_slices > 0 && slice_bytes == 0 {
        return Err(EventError::InvalidMetadata(
            "total_slices > 0 but slice_bytes == 0",
        ));
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

pub fn encode_file(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let att = match event {
        ParsedEvent::File(a) => a,
        _ => return Err(EventError::WrongVariant),
    };

    validate_file_metadata(att.blob_bytes, att.total_slices, att.slice_bytes)?;

    if att.filename.as_bytes().len() > FILE_FILENAME_BYTES {
        return Err(EventError::ContentTooLong(att.filename.as_bytes().len()));
    }
    if att.mime_type.as_bytes().len() > FILE_MIME_BYTES {
        return Err(EventError::ContentTooLong(att.mime_type.as_bytes().len()));
    }

    let values = vec![
        FieldValue::Timestamp(att.created_at_ms),
        FieldValue::EventId(att.message_id),
        FieldValue::EventId(att.file_id),
        FieldValue::U64(att.blob_bytes),
        FieldValue::U32(att.total_slices),
        FieldValue::U32(att.slice_bytes),
        FieldValue::EventId(att.root_hash),
        FieldValue::EventId(att.key_event_id),
        FieldValue::Text(att.filename.clone()),
        FieldValue::Text(att.mime_type.clone()),
        FieldValue::EventId(att.signed_by),
        FieldValue::U8(att.signer_type),
        FieldValue::FixedBytes(att.signature.to_vec()),
    ];

    Ok(encode_fields(EVENT_TYPE_FILE, FILE_FIELDS, &values)?)
}

pub static FILE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_FILE,
    type_name: "file",
    projection_table: "files",
    share_scope: ShareScope::Shared,
    dep_fields: &["message_id", "key_event_id", "signed_by"],
    dep_field_type_codes: &[&[1], &[6], &[]],
    signer_required: true,
    signature_byte_len: 64,
    encryptable: true,
    parse: parse_file,
    encode: encode_file,
    projector: super::projector::project_pure,
    context_loader: super::projection_context::build_projector_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn offsets_consistent() {
        assert_eq!(file_offsets::SIGNATURE + 64, FILE_WIRE_SIZE);
    }
    #[test]
    fn offsets_match_field_spec() {
        file_offsets::verify_against_field_spec();
    }
}
