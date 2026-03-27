use super::super::layout::field_spec::{wire_size_for_fields, FieldSpec};

/// Message content: fixed UTF-8 slot (1024 bytes, zero-padded)
pub const MESSAGE_CONTENT_BYTES: usize = 1024;

pub const MESSAGE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("author_id"),
    FieldSpec::Text("content", 1024),
    FieldSpec::EventId("signed_by"),
    FieldSpec::U8("signer_type"),
    FieldSpec::FixedBytes("signature", 64),
];

/// Message (type 1): type(1) + created_at(8) + workspace_id(32) + author_id(32)
///                  + content(1024) + signed_by(32) + signer_type(1) + signature(64) = 1194
pub const MESSAGE_WIRE_SIZE: usize = wire_size_for_fields(MESSAGE_FIELDS);

pub mod offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const WORKSPACE_ID: usize = 9;
    pub const AUTHOR_ID: usize = 41;
    pub const CONTENT: usize = 73;
    pub const SIGNED_BY: usize = 73 + super::MESSAGE_CONTENT_BYTES; // 1097
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32; // 1129
    pub const SIGNATURE: usize = SIGNER_TYPE + 1; // 1130
}

#[cfg(test)]
mod tests {
    use super::super::super::layout::field_spec::field_offset;
    use super::*;
    #[test]
    fn offsets_consistent() {
        assert_eq!(offsets::SIGNATURE + 64, MESSAGE_WIRE_SIZE);
    }
    #[test]
    fn offsets_match_field_spec() {
        assert_eq!(offsets::CREATED_AT, field_offset(MESSAGE_FIELDS, 0));
        assert_eq!(offsets::WORKSPACE_ID, field_offset(MESSAGE_FIELDS, 1));
        assert_eq!(offsets::AUTHOR_ID, field_offset(MESSAGE_FIELDS, 2));
        assert_eq!(offsets::CONTENT, field_offset(MESSAGE_FIELDS, 3));
        assert_eq!(offsets::SIGNED_BY, field_offset(MESSAGE_FIELDS, 4));
        assert_eq!(offsets::SIGNER_TYPE, field_offset(MESSAGE_FIELDS, 5));
        assert_eq!(offsets::SIGNATURE, field_offset(MESSAGE_FIELDS, 6));
    }
}
