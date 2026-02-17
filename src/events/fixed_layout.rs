//! Fixed layout constants for all canonical event wire formats.
//!
//! Every canonical event type has a deterministic wire size.
//! No parser control flow uses untrusted length or count fields
//! to determine body boundaries.
//!
//! Text slots: fixed-size UTF-8, zero-padded after content.
//! No non-zero bytes after the first 0x00 byte in a text slot.

// ─── Text slot budgets ───

/// Message content: fixed UTF-8 slot (1024 bytes, zero-padded)
pub const MESSAGE_CONTENT_BYTES: usize = 1024;

/// Reaction emoji: fixed UTF-8 slot (64 bytes, zero-padded)
pub const REACTION_EMOJI_BYTES: usize = 64;

/// SignedMemo content: fixed UTF-8 slot (1024 bytes, zero-padded)
pub const SIGNED_MEMO_CONTENT_BYTES: usize = 1024;

/// MessageAttachment filename: fixed UTF-8 slot (255 bytes, zero-padded)
pub const ATTACHMENT_FILENAME_BYTES: usize = 255;

/// MessageAttachment MIME type: fixed UTF-8 slot (128 bytes, zero-padded)
pub const ATTACHMENT_MIME_BYTES: usize = 128;

// ─── Dep slot budgets ───

/// BenchDep: fixed number of dep slots (unused slots are all-zeros)
pub const BENCH_DEP_MAX_SLOTS: usize = 10;

/// BenchDep: total bytes for dep slots (10 × 32)
pub const BENCH_DEP_SLOTS_BYTES: usize = BENCH_DEP_MAX_SLOTS * 32;

// ─── File slice ───

/// FileSlice: canonical fixed ciphertext size (256 KiB)
pub const FILE_SLICE_CIPHERTEXT_BYTES: usize = 262_144;

// ─── Signature trailer ───

/// Signature trailer: signed_by(32) + signer_type(1) + signature(64) = 97
pub const SIGNATURE_TRAILER_BYTES: usize = 97;

// ─── Common header ───

/// Common header: type_code(1) + created_at_ms(8) = 9
pub const COMMON_HEADER_BYTES: usize = 9;

// ─── Per-type total wire sizes ───

/// Message (type 1): type(1) + created_at(8) + workspace_id(32) + author_id(32)
///                  + content(1024) + signed_by(32) + signer_type(1) + signature(64) = 1194
pub const MESSAGE_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 32 + MESSAGE_CONTENT_BYTES + SIGNATURE_TRAILER_BYTES;

/// Reaction (type 2): type(1) + created_at(8) + target_event_id(32) + author_id(32)
///                   + emoji(64) + signed_by(32) + signer_type(1) + signature(64) = 234
pub const REACTION_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 32 + REACTION_EMOJI_BYTES + SIGNATURE_TRAILER_BYTES;

/// SignedMemo (type 4): type(1) + created_at(8) + signed_by(32) + signer_type(1)
///                    + content(1024) + signature(64) = 1130
pub const SIGNED_MEMO_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 1 + SIGNED_MEMO_CONTENT_BYTES + 64;

/// Encrypted (type 5) header before ciphertext:
///   type(1) + created_at(8) + key_event_id(32) + inner_type_code(1) + nonce(12) = 54
pub const ENCRYPTED_HEADER_BYTES: usize = COMMON_HEADER_BYTES + 32 + 1 + 12;

/// Encrypted (type 5) auth_tag after ciphertext: 16 bytes
pub const ENCRYPTED_AUTH_TAG_BYTES: usize = 16;

/// Encrypted (type 5) overhead around ciphertext: header(54) + auth_tag(16) = 70
pub const ENCRYPTED_OVERHEAD_BYTES: usize = ENCRYPTED_HEADER_BYTES + ENCRYPTED_AUTH_TAG_BYTES;

/// MessageAttachment (type 24): type(1) + created_at(8) + message_id(32) + file_id(32)
///   + blob_bytes(8) + total_slices(4) + slice_bytes(4) + root_hash(32) + key_event_id(32)
///   + filename(255) + mime_type(128) + signed_by(32) + signer_type(1) + signature(64) = 633
pub const MESSAGE_ATTACHMENT_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 32 + 8 + 4 + 4 + 32 + 32
    + ATTACHMENT_FILENAME_BYTES + ATTACHMENT_MIME_BYTES
    + SIGNATURE_TRAILER_BYTES;

/// FileSlice (type 25): type(1) + created_at(8) + file_id(32) + slice_number(4)
///   + ciphertext(262144) + signed_by(32) + signer_type(1) + signature(64) = 262286
pub const FILE_SLICE_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 4 + FILE_SLICE_CIPHERTEXT_BYTES + SIGNATURE_TRAILER_BYTES;

/// BenchDep (type 26): type(1) + created_at(8) + dep_slots(320) + payload(16) = 345
pub const BENCH_DEP_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + BENCH_DEP_SLOTS_BYTES + 16;

// ─── Per-type field offsets (Message, type 1) ───

pub mod message_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const WORKSPACE_ID: usize = 9;
    pub const AUTHOR_ID: usize = 41;
    pub const CONTENT: usize = 73;
    pub const SIGNED_BY: usize = 73 + super::MESSAGE_CONTENT_BYTES; // 1097
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32;                   // 1129
    pub const SIGNATURE: usize = SIGNER_TYPE + 1;                    // 1130
}

// ─── Per-type field offsets (Reaction, type 2) ───

pub mod reaction_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const TARGET_EVENT_ID: usize = 9;
    pub const AUTHOR_ID: usize = 41;
    pub const EMOJI: usize = 73;
    pub const SIGNED_BY: usize = 73 + super::REACTION_EMOJI_BYTES;  // 137
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32;                   // 169
    pub const SIGNATURE: usize = SIGNER_TYPE + 1;                    // 170
}

// ─── Per-type field offsets (SignedMemo, type 4) ───

pub mod signed_memo_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const SIGNED_BY: usize = 9;
    pub const SIGNER_TYPE: usize = 41;
    pub const CONTENT: usize = 42;
    pub const SIGNATURE: usize = 42 + super::SIGNED_MEMO_CONTENT_BYTES; // 1066
}

// ─── Per-type field offsets (Encrypted, type 5) ───

pub mod encrypted_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const KEY_EVENT_ID: usize = 9;
    pub const INNER_TYPE_CODE: usize = 41;
    pub const NONCE: usize = 42;
    pub const CIPHERTEXT: usize = 54;
    // auth_tag follows ciphertext at CIPHERTEXT + ciphertext_size
}

// ─── Per-type field offsets (MessageAttachment, type 24) ───

pub mod attachment_offsets {
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
    pub const MIME_TYPE: usize = 153 + super::ATTACHMENT_FILENAME_BYTES;  // 408
    pub const SIGNED_BY: usize = MIME_TYPE + super::ATTACHMENT_MIME_BYTES; // 536
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32;                         // 568
    pub const SIGNATURE: usize = SIGNER_TYPE + 1;                          // 569
}

// ─── Per-type field offsets (FileSlice, type 25) ───

pub mod file_slice_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const FILE_ID: usize = 9;
    pub const SLICE_NUMBER: usize = 41;
    pub const CIPHERTEXT: usize = 45;
    pub const SIGNED_BY: usize = 45 + super::FILE_SLICE_CIPHERTEXT_BYTES; // 262189
    pub const SIGNER_TYPE: usize = SIGNED_BY + 32;                         // 262221
    pub const SIGNATURE: usize = SIGNER_TYPE + 1;                          // 262222
}

// ─── Per-type field offsets (BenchDep, type 26) ───

pub mod bench_dep_offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const DEP_SLOTS: usize = 9;
    pub const PAYLOAD: usize = 9 + super::BENCH_DEP_SLOTS_BYTES; // 329
}

/// Compute the total encrypted event wire size for a given inner type wire size.
pub const fn encrypted_wire_size(inner_wire_size: usize) -> usize {
    ENCRYPTED_OVERHEAD_BYTES + inner_wire_size
}

/// Look up the fixed wire size for a given inner_type_code.
/// Returns None for types that cannot be encrypted (encrypted, secret_key, local-only, unknown).
pub fn encrypted_inner_wire_size(inner_type_code: u8) -> Option<usize> {
    match inner_type_code {
        1 => Some(MESSAGE_WIRE_SIZE),           // Message
        2 => Some(REACTION_WIRE_SIZE),          // Reaction
        4 => Some(SIGNED_MEMO_WIRE_SIZE),       // SignedMemo
        7 => Some(170),                         // MessageDeletion (already fixed: 170B)
        // Identity types (already fixed sizes)
        8 => Some(41),                          // Workspace
        10 => Some(170),                        // UserInviteBoot
        11 => Some(170),                        // UserInviteOngoing
        12 => Some(138),                        // DeviceInviteFirst
        13 => Some(138),                        // DeviceInviteOngoing
        14 => Some(138),                        // UserBoot
        15 => Some(138),                        // UserOngoing
        16 => Some(138),                        // PeerSharedFirst
        17 => Some(138),                        // PeerSharedOngoing
        18 => Some(170),                        // AdminBoot
        19 => Some(170),                        // AdminOngoing
        20 => Some(138),                        // UserRemoved
        21 => Some(138),                        // PeerRemoved
        22 => Some(202),                        // SecretShared
        23 => Some(138),                        // TransportKey
        24 => Some(MESSAGE_ATTACHMENT_WIRE_SIZE), // MessageAttachment
        25 => Some(FILE_SLICE_WIRE_SIZE),       // FileSlice
        26 => Some(BENCH_DEP_WIRE_SIZE),        // BenchDep
        // Cannot encrypt: encrypted(5), secret_key(6), invite_accepted(9)
        _ => None,
    }
}

/// Read a fixed-size UTF-8 text slot, stripping trailing zero padding.
/// Returns Err if the slot contains invalid UTF-8 or non-zero bytes after a zero.
pub fn read_text_slot(slot: &[u8]) -> Result<String, TextSlotError> {
    // Find first zero byte (NUL terminator)
    let content_end = slot.iter().position(|&b| b == 0).unwrap_or(slot.len());

    // Verify all bytes after NUL are zero
    if slot[content_end..].iter().any(|&b| b != 0) {
        return Err(TextSlotError::NonZeroPadding);
    }

    // Validate UTF-8
    let text = std::str::from_utf8(&slot[..content_end])
        .map_err(|_| TextSlotError::InvalidUtf8)?;

    Ok(text.to_string())
}

/// Write text into a fixed-size slot with zero-padding.
/// Returns Err if text bytes exceed slot capacity.
pub fn write_text_slot(text: &str, slot: &mut [u8]) -> Result<(), TextSlotError> {
    let bytes = text.as_bytes();
    if bytes.len() > slot.len() {
        return Err(TextSlotError::ContentTooLong {
            max: slot.len(),
            actual: bytes.len(),
        });
    }
    slot[..bytes.len()].copy_from_slice(bytes);
    // Zero-fill remainder (slot is expected to start as zeroed, but be explicit)
    slot[bytes.len()..].fill(0);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextSlotError {
    InvalidUtf8,
    NonZeroPadding,
    ContentTooLong { max: usize, actual: usize },
}

impl std::fmt::Display for TextSlotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextSlotError::InvalidUtf8 => write!(f, "invalid UTF-8 in text slot"),
            TextSlotError::NonZeroPadding => write!(f, "non-zero bytes after NUL in text slot"),
            TextSlotError::ContentTooLong { max, actual } => {
                write!(f, "text too long for slot: {} bytes, max {}", actual, max)
            }
        }
    }
}

impl std::error::Error for TextSlotError {}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Wire size sanity checks ───

    #[test]
    fn test_message_wire_size() {
        assert_eq!(MESSAGE_WIRE_SIZE, 1194);
    }

    #[test]
    fn test_reaction_wire_size() {
        assert_eq!(REACTION_WIRE_SIZE, 234);
    }

    #[test]
    fn test_signed_memo_wire_size() {
        assert_eq!(SIGNED_MEMO_WIRE_SIZE, 1130);
    }

    #[test]
    fn test_message_attachment_wire_size() {
        assert_eq!(MESSAGE_ATTACHMENT_WIRE_SIZE, 633);
    }

    #[test]
    fn test_file_slice_wire_size() {
        assert_eq!(FILE_SLICE_WIRE_SIZE, 262286);
    }

    #[test]
    fn test_bench_dep_wire_size() {
        assert_eq!(BENCH_DEP_WIRE_SIZE, 345);
    }

    #[test]
    fn test_encrypted_overhead() {
        assert_eq!(ENCRYPTED_OVERHEAD_BYTES, 70);
    }

    #[test]
    fn test_encrypted_wire_size_message() {
        assert_eq!(encrypted_wire_size(MESSAGE_WIRE_SIZE), 1264);
    }

    #[test]
    fn test_encrypted_wire_size_reaction() {
        assert_eq!(encrypted_wire_size(REACTION_WIRE_SIZE), 304);
    }

    // ─── Offset non-overlap checks ───

    #[test]
    fn test_message_offsets_consistent() {
        assert_eq!(message_offsets::CONTENT, 73);
        assert_eq!(message_offsets::SIGNED_BY, 73 + MESSAGE_CONTENT_BYTES);
        assert_eq!(message_offsets::SIGNATURE + 64, MESSAGE_WIRE_SIZE);
    }

    #[test]
    fn test_reaction_offsets_consistent() {
        assert_eq!(reaction_offsets::EMOJI, 73);
        assert_eq!(reaction_offsets::SIGNED_BY, 73 + REACTION_EMOJI_BYTES);
        assert_eq!(reaction_offsets::SIGNATURE + 64, REACTION_WIRE_SIZE);
    }

    #[test]
    fn test_signed_memo_offsets_consistent() {
        assert_eq!(signed_memo_offsets::CONTENT, 42);
        assert_eq!(signed_memo_offsets::SIGNATURE, 42 + SIGNED_MEMO_CONTENT_BYTES);
        assert_eq!(signed_memo_offsets::SIGNATURE + 64, SIGNED_MEMO_WIRE_SIZE);
    }

    #[test]
    fn test_attachment_offsets_consistent() {
        assert_eq!(attachment_offsets::FILENAME, 153);
        assert_eq!(attachment_offsets::MIME_TYPE, 153 + ATTACHMENT_FILENAME_BYTES);
        assert_eq!(attachment_offsets::SIGNED_BY, attachment_offsets::MIME_TYPE + ATTACHMENT_MIME_BYTES);
        assert_eq!(attachment_offsets::SIGNATURE + 64, MESSAGE_ATTACHMENT_WIRE_SIZE);
    }

    #[test]
    fn test_file_slice_offsets_consistent() {
        assert_eq!(file_slice_offsets::CIPHERTEXT, 45);
        assert_eq!(file_slice_offsets::SIGNED_BY, 45 + FILE_SLICE_CIPHERTEXT_BYTES);
        assert_eq!(file_slice_offsets::SIGNATURE + 64, FILE_SLICE_WIRE_SIZE);
    }

    #[test]
    fn test_bench_dep_offsets_consistent() {
        assert_eq!(bench_dep_offsets::DEP_SLOTS, 9);
        assert_eq!(bench_dep_offsets::PAYLOAD, 9 + BENCH_DEP_SLOTS_BYTES);
        assert_eq!(bench_dep_offsets::PAYLOAD + 16, BENCH_DEP_WIRE_SIZE);
    }

    // ─── Encrypted inner wire size lookup ───

    #[test]
    fn test_encrypted_inner_wire_size_known() {
        assert_eq!(encrypted_inner_wire_size(1), Some(MESSAGE_WIRE_SIZE));
        assert_eq!(encrypted_inner_wire_size(2), Some(REACTION_WIRE_SIZE));
        assert_eq!(encrypted_inner_wire_size(4), Some(SIGNED_MEMO_WIRE_SIZE));
        assert_eq!(encrypted_inner_wire_size(24), Some(MESSAGE_ATTACHMENT_WIRE_SIZE));
        assert_eq!(encrypted_inner_wire_size(25), Some(FILE_SLICE_WIRE_SIZE));
        assert_eq!(encrypted_inner_wire_size(26), Some(BENCH_DEP_WIRE_SIZE));
    }

    #[test]
    fn test_encrypted_inner_wire_size_rejected() {
        // Cannot encrypt: encrypted(5), secret_key(6), invite_accepted(9), unknown
        assert_eq!(encrypted_inner_wire_size(5), None);
        assert_eq!(encrypted_inner_wire_size(6), None);
        assert_eq!(encrypted_inner_wire_size(9), None);
        assert_eq!(encrypted_inner_wire_size(0), None);
        assert_eq!(encrypted_inner_wire_size(255), None);
    }

    // ─── Text slot read/write ───

    #[test]
    fn test_read_text_slot_normal() {
        let mut slot = [0u8; 64];
        let text = "hello";
        slot[..5].copy_from_slice(text.as_bytes());
        assert_eq!(read_text_slot(&slot).unwrap(), "hello");
    }

    #[test]
    fn test_read_text_slot_full() {
        let slot = [b'x'; 64];
        assert_eq!(read_text_slot(&slot).unwrap(), "x".repeat(64));
    }

    #[test]
    fn test_read_text_slot_empty() {
        let slot = [0u8; 64];
        assert_eq!(read_text_slot(&slot).unwrap(), "");
    }

    #[test]
    fn test_read_text_slot_non_zero_padding() {
        let mut slot = [0u8; 64];
        slot[0] = b'a';
        slot[1] = 0;
        slot[2] = b'b'; // non-zero after NUL
        assert_eq!(read_text_slot(&slot), Err(TextSlotError::NonZeroPadding));
    }

    #[test]
    fn test_read_text_slot_invalid_utf8() {
        let mut slot = [0u8; 64];
        slot[0] = 0xFF;
        slot[1] = 0xFE;
        assert_eq!(read_text_slot(&slot), Err(TextSlotError::InvalidUtf8));
    }

    #[test]
    fn test_write_text_slot_normal() {
        let mut slot = [0xFFu8; 64];
        write_text_slot("hello", &mut slot).unwrap();
        assert_eq!(&slot[..5], b"hello");
        assert!(slot[5..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_write_text_slot_too_long() {
        let mut slot = [0u8; 4];
        let err = write_text_slot("hello", &mut slot).unwrap_err();
        assert_eq!(err, TextSlotError::ContentTooLong { max: 4, actual: 5 });
    }

    #[test]
    fn test_write_then_read_roundtrip() {
        let mut slot = [0u8; 1024];
        let text = "Hello, \u{1f30d}!"; // "Hello, 🌍!"
        write_text_slot(text, &mut slot).unwrap();
        assert_eq!(read_text_slot(&slot).unwrap(), text);
    }
}
