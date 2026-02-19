use super::super::layout::common::{COMMON_HEADER_BYTES, SIGNATURE_TRAILER_BYTES};

/// Message content: fixed UTF-8 slot (1024 bytes, zero-padded)
pub const MESSAGE_CONTENT_BYTES: usize = 1024;

/// Message (type 1): type(1) + created_at(8) + workspace_id(32) + author_id(32)
///                  + content(1024) + signed_by(32) + signer_type(1) + signature(64) = 1194
pub const MESSAGE_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 32 + MESSAGE_CONTENT_BYTES + SIGNATURE_TRAILER_BYTES;

pub mod offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const WORKSPACE_ID: usize = 9;
    pub const AUTHOR_ID: usize = 41;
    pub const CONTENT: usize = 73;
    pub const SIGNED_BY: usize = 73 + super::MESSAGE_CONTENT_BYTES; // 1097
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32;                   // 1129
    pub const SIGNATURE: usize = SIGNER_TYPE + 1;                    // 1130
}
