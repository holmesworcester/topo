use super::super::layout::field_spec::{decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_FILE};

// ─── Layout (owned by this module) ───

/// File filename: fixed UTF-8 slot (255 bytes, zero-padded)
pub const FILE_FILENAME_BYTES: usize = 255;

/// File MIME type: fixed UTF-8 slot (128 bytes, zero-padded)
pub const FILE_MIME_BYTES: usize = 128;

/// File (type 24): type(1) + created_at(8) + message_id(32) + file_id(32)
///   + blob_bytes(8) + total_slices(4) + slice_bytes(4) + root_hash(32) + key_event_id(32)
///   + filename(255) + mime_type(128) + signed_by(32) + signer_type(1) + signature(64) = 633
pub const FILE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("message_id"),
    FieldSpec::EventId("file_id"),
    FieldSpec::U64("blob_bytes"),
    FieldSpec::U32("total_slices"),
    FieldSpec::U32("slice_bytes"),
    FieldSpec::EventId("root_hash"),
    FieldSpec::EventId("key_event_id"),
    FieldSpec::Text("filename", FILE_FILENAME_BYTES),
    FieldSpec::Text("mime_type", FILE_MIME_BYTES),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];
pub const FILE_WIRE_SIZE: usize = wire_size_for_fields(FILE_FIELDS);

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
    let created_at_ms = values[0].as_timestamp().unwrap();
    let message_id = values[1].as_event_id().unwrap();
    let file_id = values[2].as_event_id().unwrap();
    let blob_bytes = values[3].as_u64().unwrap();
    let total_slices = values[4].as_u32().unwrap();
    let slice_bytes = values[5].as_u32().unwrap();
    let root_hash = values[6].as_event_id().unwrap();
    let key_event_id = values[7].as_event_id().unwrap();
    let filename = values[8].as_text().unwrap().to_string();
    let mime_type = values[9].as_text().unwrap().to_string();
    let signed_by = values[10].as_event_id().unwrap();
    let signer_type = values[11].as_u8().unwrap();
    let mut signature = [0u8; 64];
    signature.copy_from_slice(values[12].as_fixed_bytes().unwrap());

    validate_file_metadata(blob_bytes, total_slices, slice_bytes)?;

    Ok(ParsedEvent::File(FileEvent {
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
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn offsets_consistent() {
        assert_eq!(FILE_WIRE_SIZE, 633);
    }
}
