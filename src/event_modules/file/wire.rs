use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_FILE, EVENT_TYPE_KEY_SECRET, EVENT_TYPE_MESSAGE};

// ─── Layout (owned by this module) ───

/// File filename: fixed UTF-8 slot (255 bytes, zero-padded)
pub const FILE_FILENAME_BYTES: usize = 255;

/// File MIME type: fixed UTF-8 slot (128 bytes, zero-padded)
pub const FILE_MIME_BYTES: usize = 128;

pub const FILE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"), // 0
    FieldSpec::EventId("message_id"),      // 1
    FieldSpec::EventId("file_id"),         // 2
    FieldSpec::U64("blob_bytes"),          // 3
    FieldSpec::U32("total_slices"),        // 4
    FieldSpec::U32("slice_bytes"),         // 5
    FieldSpec::EventId("root_hash"),       // 6
    FieldSpec::EventId("key_event_id"),    // 7
    FieldSpec::Text("filename", 255),      // 8
    FieldSpec::Text("mime_type", 128),     // 9
];

/// File (type 24): type(1) + created_at(8) + message_id(32) + file_id(32)
///   + blob_bytes(8) + total_slices(4) + slice_bytes(4) + root_hash(32) + key_event_id(32)
///   + filename(255) + mime_type(128) = 536
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

    let mut filename_slot: [u8; FILE_FILENAME_BYTES] = [0u8; FILE_FILENAME_BYTES];
    crate::event_modules::layout::common::write_text_slot(&att.filename, &mut filename_slot)
        .map_err(EventError::TextSlot)?;
    let mut mime_slot: [u8; FILE_MIME_BYTES] = [0u8; FILE_MIME_BYTES];
    crate::event_modules::layout::common::write_text_slot(&att.mime_type, &mut mime_slot)
        .map_err(EventError::TextSlot)?;
    Ok(topo_verus_proofs::event_modules::layout::shapes::encode_file_v1(
        EVENT_TYPE_FILE,
        att.created_at_ms,
        &att.message_id,
        &att.file_id,
        att.blob_bytes,
        att.total_slices,
        att.slice_bytes,
        &att.root_hash,
        &att.key_event_id,
        &filename_slot,
        &mime_slot,
    ))
}

pub static FILE_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
    type_code: EVENT_TYPE_FILE,
    type_name: "file",
    projection_table: "files",
    share_scope: ShareScope::Shared,
    dep_fields: &["message_id", "key_event_id"],
    dep_field_type_codes: &[&[EVENT_TYPE_MESSAGE], &[EVENT_TYPE_KEY_SECRET]],
    signer_required: true,
    signature_byte_len: 0,
    encryptable: true,
    parse: parse_file,
    encode: encode_file,
    projector: super::projector::project_pure,
    context_loader: super::projector::build_projector_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn offsets_consistent() {
        assert_eq!(file_offsets::MIME_TYPE + FILE_MIME_BYTES, FILE_WIRE_SIZE);
    }
    #[test]
    fn offsets_match_field_spec() {
        file_offsets::verify_against_field_spec();
    }
}
