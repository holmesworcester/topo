use super::fixed_layout::{FILE_SLICE_WIRE_SIZE, FILE_SLICE_CIPHERTEXT_BYTES, file_slice_offsets as off};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_FILE_SLICE};

/// Maximum ciphertext size per file slice: canonical fixed 256 KiB.
/// Final plaintext chunks are zero-padded before encryption.
/// Receiver uses blob_bytes from MessageAttachment for final truncation.
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

/// Wire format (262286 bytes fixed, signed):
/// [0]            type=25
/// [1..9]         created_at_ms (u64 LE)
/// [9..41]        file_id (32 bytes)
/// [41..45]       slice_number (u32 LE)
/// [45..262189]   ciphertext (262144 bytes, canonical fixed size)
/// [262189..262221] signed_by (32 bytes)
/// [262221]       signer_type (1 byte)
/// [262222..262286] signature (64 bytes)
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

    let slice_number = u32::from_le_bytes(blob[off::SLICE_NUMBER..off::CIPHERTEXT].try_into().unwrap());

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
    buf[off::CIPHERTEXT..off::CIPHERTEXT + FILE_SLICE_CIPHERTEXT_BYTES].copy_from_slice(&fs.ciphertext);
    buf[off::SIGNED_BY..off::SIGNER_TYPE].copy_from_slice(&fs.signed_by);
    buf[off::SIGNER_TYPE] = fs.signer_type;
    buf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&fs.signature);

    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::crypto::event_id_to_base64;
use crate::projection::decision::ProjectionDecision;
use crate::projection::result::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: FileSlice → file_slices table insert.
///
/// Uses ContextSnapshot.file_descriptors to determine authorization:
/// - No descriptors → guard-block (emit RecordFileSliceGuardBlock command)
/// - Multiple signers → reject
/// - Signer mismatch → reject
/// - Success → insert file_slice row
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let fs = match parsed {
        ParsedEvent::FileSlice(f) => f,
        _ => return ProjectorResult::reject("not a file_slice event".to_string()),
    };

    let file_id_b64 = event_id_to_base64(&fs.file_id);
    let slice_signer_b64 = event_id_to_base64(&fs.signed_by);

    if ctx.file_descriptors.is_empty() {
        // No descriptor yet — guard-block
        return ProjectorResult {
            decision: ProjectionDecision::Block { missing: vec![] },
            write_ops: Vec::new(),
            emit_commands: vec![EmitCommand::RecordFileSliceGuardBlock {
                file_id: file_id_b64,
                event_id: event_id_b64.to_string(),
            }],
        };
    }

    // Check for conflicting descriptor signers
    let mut descriptor_signers = std::collections::BTreeSet::new();
    for (_, signer) in &ctx.file_descriptors {
        descriptor_signers.insert(signer.clone());
    }
    if descriptor_signers.len() > 1 {
        return ProjectorResult::reject(format!(
            "file_id {} maps to multiple attachment signers ({}), cannot authorize file_slice",
            file_id_b64,
            descriptor_signers.len()
        ));
    }

    let (descriptor_event_id, descriptor_signer) = ctx.file_descriptors[0].clone();
    if descriptor_signer != slice_signer_b64 {
        return ProjectorResult::reject(format!(
            "file_slice signer {} does not match attachment descriptor signer {}",
            slice_signer_b64, descriptor_signer
        ));
    }

    // Check for existing slice in same slot (idempotent replay or conflict)
    if let Some((ref existing_event_id, ref existing_descriptor)) = ctx.existing_file_slice {
        if existing_event_id == event_id_b64 {
            if existing_descriptor != &descriptor_event_id {
                return ProjectorResult::reject(format!(
                    "file_slice descriptor mismatch: existing {} vs authorized {}",
                    existing_descriptor, descriptor_event_id
                ));
            }
            return ProjectorResult::valid(vec![]); // idempotent replay
        } else {
            return ProjectorResult::reject(format!(
                "duplicate file_slice: slot ({}, {}, {}) already claimed by event {}",
                recorded_by, file_id_b64, fs.slice_number, existing_event_id
            ));
        }
    }

    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "file_slices",
            columns: vec!["recorded_by", "file_id", "slice_number", "event_id", "created_at", "descriptor_event_id"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(file_id_b64),
                SqlVal::Int(fs.slice_number as i64),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Int(fs.created_at_ms as i64),
                SqlVal::Text(descriptor_event_id),
            ],
        },
    ];
    ProjectorResult::valid(ops)
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
    projector: project_pure,
};
