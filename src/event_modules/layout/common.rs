//! Shared cross-event wire layout primitives.
//!
//! This module contains only items that are genuinely shared across multiple
//! event types. Per-event wire sizes, text-slot budgets, and field offsets
//! belong in the owning event module (inline for single-file modules,
//! `layout.rs` for folderized modules).

// ─── Common header ───

/// Common header: type_code(1) + created_at_ms(8) = 9
pub const COMMON_HEADER_BYTES: usize = 9;

// ─── Signature trailer ───

/// Signature trailer: signed_by(32) + signer_type(1) + signature(64) = 97
pub const SIGNATURE_TRAILER_BYTES: usize = 97;

// ─── Shared text-slot budget ───

/// Display name: fixed UTF-8 slot (64 bytes, zero-padded).
/// Used for workspace name, username, device name.
pub const NAME_BYTES: usize = 64;

// ─── Identity-pubkey-with-signer shared wire size ───

/// Identity-pubkey-with-signer layout: type(1) + created_at(8) + public_key(32)
///   + signed_by(32) + signer_type(1) + signature(64) = 138
/// Used by: UserRemoved(20), PeerRemoved(21)
pub const IDENTITY_PUBKEY_SIGNED_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + SIGNATURE_TRAILER_BYTES;

// ─── Encrypted envelope helpers ───

/// Encrypted (type 5) header before ciphertext:
///   type(1) + created_at(8) + key_event_id(32) + inner_type_code(1) + nonce(12) = 54
pub const ENCRYPTED_HEADER_BYTES: usize = COMMON_HEADER_BYTES + 32 + 1 + 12;

/// Encrypted (type 5) auth_tag after ciphertext: 16 bytes
pub const ENCRYPTED_AUTH_TAG_BYTES: usize = 16;

/// Encrypted (type 5) overhead around ciphertext: header(54) + auth_tag(16) = 70
pub const ENCRYPTED_OVERHEAD_BYTES: usize = ENCRYPTED_HEADER_BYTES + ENCRYPTED_AUTH_TAG_BYTES;

/// Compute the total encrypted event wire size for a given inner type wire size.
pub const fn encrypted_wire_size(inner_wire_size: usize) -> usize {
    ENCRYPTED_OVERHEAD_BYTES + inner_wire_size
}

/// Look up the fixed wire size for a given inner_type_code.
/// Returns None for types that cannot be encrypted (encrypted, secret_key, local-only, unknown).
pub fn encrypted_inner_wire_size(inner_type_code: u8) -> Option<usize> {
    use super::super::admin::ADMIN_WIRE_SIZE;
    use super::super::bench_dep::BENCH_DEP_WIRE_SIZE;
    use super::super::device_invite::DEVICE_INVITE_WIRE_SIZE;
    use super::super::file_slice::FILE_SLICE_WIRE_SIZE;
    use super::super::message::wire::MESSAGE_WIRE_SIZE;
    use super::super::message_attachment::MESSAGE_ATTACHMENT_WIRE_SIZE;
    use super::super::message_deletion::MESSAGE_DELETION_WIRE_SIZE;
    use super::super::peer_shared::PEER_SHARED_WIRE_SIZE;
    use super::super::reaction::REACTION_WIRE_SIZE;
    use super::super::secret_shared::SECRET_SHARED_WIRE_SIZE;
    use super::super::user::USER_WIRE_SIZE;
    use super::super::user_invite::USER_INVITE_WIRE_SIZE;
    use super::super::workspace::WORKSPACE_WIRE_SIZE;

    match inner_type_code {
        1 => Some(MESSAGE_WIRE_SIZE),                 // Message
        2 => Some(REACTION_WIRE_SIZE),                // Reaction
        7 => Some(MESSAGE_DELETION_WIRE_SIZE),        // MessageDeletion
        8 => Some(WORKSPACE_WIRE_SIZE),               // Workspace
        10 => Some(USER_INVITE_WIRE_SIZE),            // UserInvite
        12 => Some(DEVICE_INVITE_WIRE_SIZE),          // DeviceInvite
        14 => Some(USER_WIRE_SIZE),                   // User
        16 => Some(PEER_SHARED_WIRE_SIZE),            // PeerShared
        18 => Some(ADMIN_WIRE_SIZE),                  // Admin
        20 => Some(IDENTITY_PUBKEY_SIGNED_WIRE_SIZE), // UserRemoved
        21 => Some(IDENTITY_PUBKEY_SIGNED_WIRE_SIZE), // PeerRemoved
        22 => Some(SECRET_SHARED_WIRE_SIZE),          // SecretShared
        24 => Some(MESSAGE_ATTACHMENT_WIRE_SIZE),     // MessageAttachment
        25 => Some(FILE_SLICE_WIRE_SIZE),             // FileSlice
        26 => Some(BENCH_DEP_WIRE_SIZE),              // BenchDep
        // Cannot encrypt: encrypted(5), secret_key(6), invite_accepted(9)
        _ => None,
    }
}

// ─── Text slot helpers ───

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
    let text = std::str::from_utf8(&slot[..content_end]).map_err(|_| TextSlotError::InvalidUtf8)?;

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
    fn test_common_header_bytes() {
        assert_eq!(COMMON_HEADER_BYTES, 9);
    }

    #[test]
    fn test_signature_trailer_bytes() {
        assert_eq!(SIGNATURE_TRAILER_BYTES, 97);
    }

    #[test]
    fn test_encrypted_overhead() {
        assert_eq!(ENCRYPTED_OVERHEAD_BYTES, 70);
    }

    #[test]
    fn test_identity_pubkey_signed_wire_size() {
        assert_eq!(IDENTITY_PUBKEY_SIGNED_WIRE_SIZE, 138);
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

    // ─── Per-event wire size sanity (guards against formula drift) ───

    #[test]
    fn test_per_event_wire_sizes() {
        use super::super::super::admin::ADMIN_WIRE_SIZE;
        use super::super::super::bench_dep::BENCH_DEP_WIRE_SIZE;
        use super::super::super::device_invite::DEVICE_INVITE_WIRE_SIZE;
        use super::super::super::file_slice::FILE_SLICE_WIRE_SIZE;
        use super::super::super::invite_accepted::INVITE_ACCEPTED_WIRE_SIZE;
        use super::super::super::invite_privkey::INVITE_PRIVKEY_WIRE_SIZE;
        use super::super::super::message::MESSAGE_WIRE_SIZE;
        use super::super::super::message_attachment::MESSAGE_ATTACHMENT_WIRE_SIZE;
        use super::super::super::message_deletion::MESSAGE_DELETION_WIRE_SIZE;
        use super::super::super::peer::PEER_WIRE_SIZE;
        use super::super::super::peer_shared::PEER_SHARED_WIRE_SIZE;
        use super::super::super::reaction::REACTION_WIRE_SIZE;
        use super::super::super::secret_key::SECRET_KEY_WIRE_SIZE;
        use super::super::super::secret_shared::SECRET_SHARED_WIRE_SIZE;
        use super::super::super::tenant::TENANT_WIRE_SIZE;
        use super::super::super::user::USER_WIRE_SIZE;
        use super::super::super::user_invite::USER_INVITE_WIRE_SIZE;
        use super::super::super::workspace::WORKSPACE_WIRE_SIZE;

        assert_eq!(MESSAGE_WIRE_SIZE, 1194);
        assert_eq!(REACTION_WIRE_SIZE, 234);
        assert_eq!(MESSAGE_ATTACHMENT_WIRE_SIZE, 633);
        assert_eq!(FILE_SLICE_WIRE_SIZE, 262286);
        assert_eq!(BENCH_DEP_WIRE_SIZE, 345);
        assert_eq!(WORKSPACE_WIRE_SIZE, 105);
        assert_eq!(USER_WIRE_SIZE, 202);
        assert_eq!(PEER_SHARED_WIRE_SIZE, 234);
        assert_eq!(SECRET_KEY_WIRE_SIZE, 41);
        assert_eq!(MESSAGE_DELETION_WIRE_SIZE, 170);
        assert_eq!(INVITE_ACCEPTED_WIRE_SIZE, 105);
        assert_eq!(USER_INVITE_WIRE_SIZE, 202);
        assert_eq!(DEVICE_INVITE_WIRE_SIZE, 170);
        assert_eq!(ADMIN_WIRE_SIZE, 170);
        assert_eq!(PEER_WIRE_SIZE, 73);
        assert_eq!(TENANT_WIRE_SIZE, 41);
        assert_eq!(SECRET_SHARED_WIRE_SIZE, 234);
        assert_eq!(INVITE_PRIVKEY_WIRE_SIZE, 73);
        assert_eq!(IDENTITY_PUBKEY_SIGNED_WIRE_SIZE, 138);
    }

    // ─── Encrypted inner wire size lookup ───

    #[test]
    fn test_encrypted_inner_wire_size_known() {
        use super::super::super::bench_dep::BENCH_DEP_WIRE_SIZE;
        use super::super::super::file_slice::FILE_SLICE_WIRE_SIZE;
        use super::super::super::message::wire::MESSAGE_WIRE_SIZE;
        use super::super::super::message_attachment::MESSAGE_ATTACHMENT_WIRE_SIZE;
        use super::super::super::reaction::REACTION_WIRE_SIZE;

        assert_eq!(encrypted_inner_wire_size(1), Some(MESSAGE_WIRE_SIZE));
        assert_eq!(encrypted_inner_wire_size(2), Some(REACTION_WIRE_SIZE));
        assert_eq!(
            encrypted_inner_wire_size(24),
            Some(MESSAGE_ATTACHMENT_WIRE_SIZE)
        );
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

    #[test]
    fn test_encrypted_wire_size_message() {
        use super::super::super::message::wire::MESSAGE_WIRE_SIZE;
        use super::super::super::reaction::REACTION_WIRE_SIZE;
        assert_eq!(encrypted_wire_size(MESSAGE_WIRE_SIZE), 1264);
        assert_eq!(encrypted_wire_size(REACTION_WIRE_SIZE), 304);
    }
}
