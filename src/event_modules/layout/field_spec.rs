//! Generic field-spec-driven wire codec for fixed-size events.
//!
//! Every fixed-size event in the system follows the same wire pattern:
//! `type_byte(1) + field_1 + field_2 + ... + field_n`. Fields are packed
//! at deterministic offsets with no gaps. This module replaces per-event
//! hand-written parse/encode/offset code with a declarative field list.
//!
//! Usage:
//! ```ignore
//! const REACTION_FIELDS: &[FieldSpec] = &[
//!     FieldSpec::Timestamp("created_at_ms"),
//!     FieldSpec::EventId("target_event_id"),
//!     FieldSpec::EventId("author_id"),
//!     FieldSpec::Text("emoji", 64),
//!     FieldSpec::EventId("signed_by"),
//!     FieldSpec::U8("signer_type"),
//!     FieldSpec::FixedBytes("signature", 64),
//! ];
//!
//! let wire_size = wire_size_for_fields(REACTION_FIELDS); // 234
//! let blob = encode_fields(EVENT_TYPE_REACTION, REACTION_FIELDS, &values)?;
//! let values = decode_fields(EVENT_TYPE_REACTION, REACTION_FIELDS, &blob)?;
//! ```

use super::common::{read_text_slot, write_text_slot, TextSlotError};

/// A single field in a fixed-size wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSpec {
    /// 8-byte little-endian u64 timestamp (created_at_ms).
    Timestamp(&'static str),
    /// 32-byte event ID (SHA-256 hash).
    EventId(&'static str),
    /// Fixed-size zero-padded UTF-8 text slot.
    Text(&'static str, usize),
    /// Fixed-size zero-padded UTF-8 text slot, empty string treated as None.
    OptionalText(&'static str, usize),
    /// 1-byte boolean (0 = false, nonzero = true).
    Bool(&'static str),
    /// 1-byte unsigned integer.
    U8(&'static str),
    /// 4-byte little-endian u32.
    U32(&'static str),
    /// 8-byte little-endian u64.
    U64(&'static str),
    /// 8-byte little-endian i64.
    I64(&'static str),
    /// Fixed-size raw byte array (e.g., signatures, public keys).
    FixedBytes(&'static str, usize),
}

impl FieldSpec {
    /// Wire size of this field in bytes.
    pub const fn wire_size(&self) -> usize {
        match self {
            Self::Timestamp(_) => 8,
            Self::EventId(_) => 32,
            Self::Text(_, n) | Self::OptionalText(_, n) => *n,
            Self::Bool(_) | Self::U8(_) => 1,
            Self::U32(_) => 4,
            Self::U64(_) | Self::I64(_) => 8,
            Self::FixedBytes(_, n) => *n,
        }
    }

    /// Field name for lookup.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Timestamp(n)
            | Self::EventId(n)
            | Self::Text(n, _)
            | Self::OptionalText(n, _)
            | Self::Bool(n)
            | Self::U8(n)
            | Self::U32(n)
            | Self::U64(n)
            | Self::I64(n)
            | Self::FixedBytes(n, _) => n,
        }
    }
}

/// Decoded field value from wire format.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Timestamp(u64),
    EventId([u8; 32]),
    Text(String),
    OptionalText(Option<String>),
    Bool(bool),
    U8(u8),
    U32(u32),
    U64(u64),
    I64(i64),
    FixedBytes(Vec<u8>),
}

impl FieldValue {
    pub fn as_timestamp(&self) -> Option<u64> {
        match self {
            Self::Timestamp(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_event_id(&self) -> Option<[u8; 32]> {
        match self {
            Self::EventId(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_optional_text(&self) -> Option<Option<&str>> {
        match self {
            Self::OptionalText(v) => Some(v.as_deref()),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            Self::U8(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::U32(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_fixed_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::FixedBytes(v) => Some(v),
            _ => None,
        }
    }
    /// Move the inner Vec out of a FixedBytes value, avoiding a copy.
    pub fn into_fixed_bytes(self) -> Option<Vec<u8>> {
        match self {
            Self::FixedBytes(v) => Some(v),
            _ => None,
        }
    }
}

/// Total wire size for a type_byte + field list.
pub const fn wire_size_for_fields(fields: &[FieldSpec]) -> usize {
    let mut size = 1; // type_byte
    let mut i = 0;
    while i < fields.len() {
        size += fields[i].wire_size();
        i += 1;
    }
    size
}

/// Compute the byte offset of field at `index` within the wire blob.
/// Offset 0 is the type_byte; fields start at offset 1.
pub fn field_offset(fields: &[FieldSpec], index: usize) -> usize {
    let mut offset = 1; // skip type_byte
    for (i, field) in fields.iter().enumerate() {
        if i == index {
            return offset;
        }
        offset += field.wire_size();
    }
    offset
}

/// Decode all fields from a wire blob. Validates type_byte and exact length.
pub fn decode_fields(
    type_code: u8,
    fields: &[FieldSpec],
    blob: &[u8],
) -> Result<Vec<FieldValue>, DecodeError> {
    let expected_size = wire_size_for_fields(fields);
    if blob.len() < expected_size {
        return Err(DecodeError::TooShort {
            expected: expected_size,
            actual: blob.len(),
        });
    }
    if blob.len() > expected_size {
        return Err(DecodeError::TrailingData {
            expected: expected_size,
            actual: blob.len(),
        });
    }
    if blob[0] != type_code {
        return Err(DecodeError::WrongType {
            expected: type_code,
            actual: blob[0],
        });
    }

    let mut values = Vec::with_capacity(fields.len());
    let mut offset = 1; // skip type_byte
    for field in fields {
        let size = field.wire_size();
        let slice = &blob[offset..offset + size];
        let value = match field {
            FieldSpec::Timestamp(_) => {
                FieldValue::Timestamp(u64::from_le_bytes(slice.try_into().unwrap()))
            }
            FieldSpec::EventId(_) => {
                let mut id = [0u8; 32];
                id.copy_from_slice(slice);
                FieldValue::EventId(id)
            }
            FieldSpec::Text(_, _) => {
                FieldValue::Text(read_text_slot(slice).map_err(DecodeError::TextSlot)?)
            }
            FieldSpec::OptionalText(_, _) => {
                let text = read_text_slot(slice).map_err(DecodeError::TextSlot)?;
                FieldValue::OptionalText(if text.is_empty() { None } else { Some(text) })
            }
            FieldSpec::Bool(_) => FieldValue::Bool(slice[0] != 0),
            FieldSpec::U8(_) => FieldValue::U8(slice[0]),
            FieldSpec::U32(_) => FieldValue::U32(u32::from_le_bytes(slice.try_into().unwrap())),
            FieldSpec::U64(_) => FieldValue::U64(u64::from_le_bytes(slice.try_into().unwrap())),
            FieldSpec::I64(_) => FieldValue::I64(i64::from_le_bytes(slice.try_into().unwrap())),
            FieldSpec::FixedBytes(_, _) => FieldValue::FixedBytes(slice.to_vec()),
        };
        values.push(value);
        offset += size;
    }
    Ok(values)
}

/// Encode field values into a wire blob. Returns a blob of exactly
/// `wire_size_for_fields(fields)` bytes.
pub fn encode_fields(
    type_code: u8,
    fields: &[FieldSpec],
    values: &[FieldValue],
) -> Result<Vec<u8>, EncodeError> {
    if values.len() != fields.len() {
        return Err(EncodeError::FieldCountMismatch {
            expected: fields.len(),
            actual: values.len(),
        });
    }

    let total_size = wire_size_for_fields(fields);
    let mut buf = vec![0u8; total_size];
    buf[0] = type_code;

    let mut offset = 1;
    for (field, value) in fields.iter().zip(values.iter()) {
        let size = field.wire_size();
        let slot = &mut buf[offset..offset + size];
        match (field, value) {
            (FieldSpec::Timestamp(_), FieldValue::Timestamp(v)) => {
                slot.copy_from_slice(&v.to_le_bytes());
            }
            (FieldSpec::EventId(_), FieldValue::EventId(v)) => {
                slot.copy_from_slice(v);
            }
            (FieldSpec::Text(_, _), FieldValue::Text(v)) => {
                write_text_slot(v, slot).map_err(EncodeError::TextSlot)?;
            }
            (FieldSpec::OptionalText(_, _), FieldValue::OptionalText(v)) => {
                write_text_slot(v.as_deref().unwrap_or(""), slot).map_err(EncodeError::TextSlot)?;
            }
            (FieldSpec::Bool(_), FieldValue::Bool(v)) => {
                slot[0] = *v as u8;
            }
            (FieldSpec::U8(_), FieldValue::U8(v)) => {
                slot[0] = *v;
            }
            (FieldSpec::U32(_), FieldValue::U32(v)) => {
                slot.copy_from_slice(&v.to_le_bytes());
            }
            (FieldSpec::U64(_), FieldValue::U64(v)) => {
                slot.copy_from_slice(&v.to_le_bytes());
            }
            (FieldSpec::I64(_), FieldValue::I64(v)) => {
                slot.copy_from_slice(&v.to_le_bytes());
            }
            (FieldSpec::FixedBytes(_, _), FieldValue::FixedBytes(v)) => {
                if v.len() != size {
                    return Err(EncodeError::FixedBytesMismatch {
                        expected: size,
                        actual: v.len(),
                    });
                }
                slot.copy_from_slice(v);
            }
            _ => {
                return Err(EncodeError::TypeMismatch {
                    field_name: field.name(),
                });
            }
        }
        offset += size;
    }
    Ok(buf)
}

/// Look up a field value by name from a decoded value list.
pub fn get_field<'a>(
    fields: &[FieldSpec],
    values: &'a [FieldValue],
    name: &str,
) -> Option<&'a FieldValue> {
    fields
        .iter()
        .position(|f| f.name() == name)
        .map(|i| &values[i])
}

/// Convert DecodeError to EventError for use in parse functions.
impl From<DecodeError> for super::super::EventError {
    fn from(e: DecodeError) -> Self {
        match e {
            DecodeError::TooShort { expected, actual } => Self::TooShort { expected, actual },
            DecodeError::TrailingData { expected, actual } => {
                Self::TrailingData { expected, actual }
            }
            DecodeError::WrongType { expected, actual } => Self::WrongType { expected, actual },
            DecodeError::TextSlot(e) => Self::TextSlot(e),
        }
    }
}

/// Convert EncodeError to EventError for use in encode functions.
impl From<EncodeError> for super::super::EventError {
    fn from(e: EncodeError) -> Self {
        match e {
            EncodeError::TextSlot(e) => Self::TextSlot(e),
            EncodeError::FixedBytesMismatch { expected, .. } => Self::ContentTooLong(expected),
            EncodeError::FieldCountMismatch { .. } | EncodeError::TypeMismatch { .. } => {
                Self::WrongVariant
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShort { expected: usize, actual: usize },
    TrailingData { expected: usize, actual: usize },
    WrongType { expected: u8, actual: u8 },
    TextSlot(TextSlotError),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { expected, actual } => {
                write!(f, "blob too short: expected {expected}, got {actual}")
            }
            Self::TrailingData { expected, actual } => {
                write!(f, "trailing data: expected {expected}, got {actual}")
            }
            Self::WrongType { expected, actual } => {
                write!(f, "wrong type code: expected {expected}, got {actual}")
            }
            Self::TextSlot(e) => write!(f, "text slot error: {e}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    FieldCountMismatch { expected: usize, actual: usize },
    TextSlot(TextSlotError),
    FixedBytesMismatch { expected: usize, actual: usize },
    TypeMismatch { field_name: &'static str },
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FieldCountMismatch { expected, actual } => {
                write!(f, "field count mismatch: expected {expected}, got {actual}")
            }
            Self::TextSlot(e) => write!(f, "text slot error: {e}"),
            Self::FixedBytesMismatch { expected, actual } => {
                write!(
                    f,
                    "fixed bytes size mismatch: expected {expected}, got {actual}"
                )
            }
            Self::TypeMismatch { field_name } => {
                write!(f, "type mismatch for field {field_name}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Define a test event matching the Reaction wire format
    const REACTION_FIELDS: &[FieldSpec] = &[
        FieldSpec::Timestamp("created_at_ms"),
        FieldSpec::EventId("target_event_id"),
        FieldSpec::EventId("author_id"),
        FieldSpec::Text("emoji", 64),
        FieldSpec::EventId("signed_by"),
        FieldSpec::U8("signer_type"),
        FieldSpec::FixedBytes("signature", 64),
    ];

    #[test]
    fn wire_size_matches_reaction() {
        assert_eq!(wire_size_for_fields(REACTION_FIELDS), 234);
    }

    #[test]
    fn field_offsets_match_reaction() {
        assert_eq!(field_offset(REACTION_FIELDS, 0), 1); // created_at_ms
        assert_eq!(field_offset(REACTION_FIELDS, 1), 9); // target_event_id
        assert_eq!(field_offset(REACTION_FIELDS, 2), 41); // author_id
        assert_eq!(field_offset(REACTION_FIELDS, 3), 73); // emoji
        assert_eq!(field_offset(REACTION_FIELDS, 4), 137); // signed_by
        assert_eq!(field_offset(REACTION_FIELDS, 5), 169); // signer_type
        assert_eq!(field_offset(REACTION_FIELDS, 6), 170); // signature
    }

    #[test]
    fn encode_decode_roundtrip() {
        let values = vec![
            FieldValue::Timestamp(1234567890),
            FieldValue::EventId([0xAA; 32]),
            FieldValue::EventId([0xBB; 32]),
            FieldValue::Text("👍".to_string()),
            FieldValue::EventId([0xCC; 32]),
            FieldValue::U8(3),
            FieldValue::FixedBytes(vec![0xDD; 64]),
        ];

        let blob = encode_fields(2, REACTION_FIELDS, &values).unwrap();
        assert_eq!(blob.len(), 234);
        assert_eq!(blob[0], 2); // type code

        let decoded = decode_fields(2, REACTION_FIELDS, &blob).unwrap();
        assert_eq!(decoded, values);
    }

    #[test]
    fn decode_rejects_wrong_type() {
        let blob = vec![0u8; 234];
        let err = decode_fields(2, REACTION_FIELDS, &blob).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::WrongType {
                expected: 2,
                actual: 0
            }
        ));
    }

    #[test]
    fn decode_rejects_short_blob() {
        let blob = vec![2u8; 100];
        let err = decode_fields(2, REACTION_FIELDS, &blob).unwrap_err();
        assert!(matches!(err, DecodeError::TooShort { .. }));
    }

    #[test]
    fn decode_rejects_long_blob() {
        let blob = vec![2u8; 300];
        let err = decode_fields(2, REACTION_FIELDS, &blob).unwrap_err();
        assert!(matches!(err, DecodeError::TrailingData { .. }));
    }

    #[test]
    fn get_field_by_name() {
        let values = vec![
            FieldValue::Timestamp(42),
            FieldValue::EventId([0; 32]),
            FieldValue::EventId([0; 32]),
            FieldValue::Text("hello".to_string()),
            FieldValue::EventId([0; 32]),
            FieldValue::U8(0),
            FieldValue::FixedBytes(vec![0; 64]),
        ];
        let emoji = get_field(REACTION_FIELDS, &values, "emoji").unwrap();
        assert_eq!(emoji.as_text(), Some("hello"));
    }

    // Test with a simpler event shape to prove the codec is generic
    const SIMPLE_FIELDS: &[FieldSpec] = &[
        FieldSpec::Timestamp("created_at_ms"),
        FieldSpec::Text("name", 32),
        FieldSpec::Bool("active"),
        FieldSpec::OptionalText("detail", 64),
        FieldSpec::U64("count"),
    ];

    #[test]
    fn simple_event_roundtrip() {
        let values = vec![
            FieldValue::Timestamp(999),
            FieldValue::Text("test".to_string()),
            FieldValue::Bool(true),
            FieldValue::OptionalText(None),
            FieldValue::U64(42),
        ];

        let type_code = 99;
        let blob = encode_fields(type_code, SIMPLE_FIELDS, &values).unwrap();
        assert_eq!(blob.len(), wire_size_for_fields(SIMPLE_FIELDS));

        let decoded = decode_fields(type_code, SIMPLE_FIELDS, &blob).unwrap();
        assert_eq!(decoded, values);
    }

    #[test]
    fn optional_text_some_roundtrip() {
        let values = vec![
            FieldValue::Timestamp(1),
            FieldValue::Text("x".to_string()),
            FieldValue::Bool(false),
            FieldValue::OptionalText(Some("present".to_string())),
            FieldValue::U64(0),
        ];

        let blob = encode_fields(99, SIMPLE_FIELDS, &values).unwrap();
        let decoded = decode_fields(99, SIMPLE_FIELDS, &blob).unwrap();
        assert_eq!(decoded, values);
    }

    #[test]
    fn encode_rejects_field_count_mismatch() {
        let err = encode_fields(99, SIMPLE_FIELDS, &[FieldValue::Timestamp(1)]).unwrap_err();
        assert!(matches!(err, EncodeError::FieldCountMismatch { .. }));
    }

    #[test]
    fn encode_rejects_type_mismatch() {
        let values = vec![
            FieldValue::Text("not a timestamp".to_string()), // wrong type
            FieldValue::Text("x".to_string()),
            FieldValue::Bool(false),
            FieldValue::OptionalText(None),
            FieldValue::U64(0),
        ];
        let err = encode_fields(99, SIMPLE_FIELDS, &values).unwrap_err();
        assert!(matches!(err, EncodeError::TypeMismatch { .. }));
    }

    #[test]
    fn i64_roundtrip() {
        const FIELDS: &[FieldSpec] = &[FieldSpec::Timestamp("ts"), FieldSpec::I64("val")];
        let values = vec![FieldValue::Timestamp(1), FieldValue::I64(-42)];
        let blob = encode_fields(88, FIELDS, &values).unwrap();
        let decoded = decode_fields(88, FIELDS, &blob).unwrap();
        assert_eq!(decoded[1].as_i64(), Some(-42));
    }

    #[test]
    fn u32_roundtrip() {
        const FIELDS: &[FieldSpec] = &[FieldSpec::Timestamp("ts"), FieldSpec::U32("val")];
        let values = vec![FieldValue::Timestamp(1), FieldValue::U32(999_999)];
        let blob = encode_fields(77, FIELDS, &values).unwrap();
        let decoded = decode_fields(77, FIELDS, &blob).unwrap();
        assert_eq!(decoded[1].as_u32(), Some(999_999));
    }

    #[test]
    fn encode_rejects_fixed_bytes_size_mismatch() {
        const FIELDS: &[FieldSpec] =
            &[FieldSpec::Timestamp("ts"), FieldSpec::FixedBytes("sig", 64)];
        let values = vec![
            FieldValue::Timestamp(1),
            FieldValue::FixedBytes(vec![0; 32]), // wrong size: 32 instead of 64
        ];
        let err = encode_fields(50, FIELDS, &values).unwrap_err();
        assert!(matches!(
            err,
            EncodeError::FixedBytesMismatch {
                expected: 64,
                actual: 32
            }
        ));
    }

    #[test]
    fn encode_error_maps_fixed_bytes_mismatch_to_content_too_long() {
        use crate::event_modules::EventError;
        let err = EncodeError::FixedBytesMismatch {
            expected: 64,
            actual: 32,
        };
        let event_err: EventError = err.into();
        assert!(matches!(event_err, EventError::ContentTooLong(64)));
    }

    #[test]
    fn into_fixed_bytes_moves_without_copy() {
        let val = FieldValue::FixedBytes(vec![0xAB; 100]);
        let moved = val.into_fixed_bytes().unwrap();
        assert_eq!(moved.len(), 100);
        assert_eq!(moved[0], 0xAB);
    }

    #[test]
    fn into_fixed_bytes_returns_none_for_wrong_type() {
        let val = FieldValue::Timestamp(42);
        assert!(val.into_fixed_bytes().is_none());
    }
}
