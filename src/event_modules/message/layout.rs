use super::super::layout::field_spec::{wire_size_for_fields, FieldSpec};

/// Message content: fixed UTF-8 slot (1024 bytes, zero-padded)
pub const MESSAGE_CONTENT_BYTES: usize = 1024;

pub const MESSAGE_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::EventId("author_id"),
    FieldSpec::Text("content", 1024),
];

/// Message (type 1): type(1) + created_at(8) + workspace_id(32) + author_id(32)
///                  + content(1024) = 1097
pub const MESSAGE_WIRE_SIZE: usize = wire_size_for_fields(MESSAGE_FIELDS);

pub mod offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const WORKSPACE_ID: usize = 9;
    pub const AUTHOR_ID: usize = 41;
    pub const CONTENT: usize = 73;
}

#[cfg(test)]
mod tests {
    use super::super::super::layout::field_spec::field_offset;
    use super::*;
    #[test]
    fn offsets_consistent() {
        assert_eq!(offsets::CONTENT + MESSAGE_CONTENT_BYTES, MESSAGE_WIRE_SIZE);
    }
    #[test]
    fn offsets_match_field_spec() {
        assert_eq!(offsets::CREATED_AT, field_offset(MESSAGE_FIELDS, 0));
        assert_eq!(offsets::WORKSPACE_ID, field_offset(MESSAGE_FIELDS, 1));
        assert_eq!(offsets::AUTHOR_ID, field_offset(MESSAGE_FIELDS, 2));
        assert_eq!(offsets::CONTENT, field_offset(MESSAGE_FIELDS, 3));
    }
}
