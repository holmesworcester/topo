pub mod admin;
pub mod bench_dep;
pub mod device_invite;
pub mod encrypted;
pub mod file_slice;
pub mod invite_accepted;
pub mod layout;
pub mod local_signer_secret;
pub mod message;
pub mod message_attachment;
pub mod message_deletion;
pub mod peer_removed;
pub mod peer_shared;
pub mod reaction;
pub mod registry;
pub mod secret_key;
pub mod secret_shared;
pub mod user;
pub mod user_invite;
pub mod user_removed;
pub mod subscription;
pub mod workspace;

use rusqlite::Connection;
use std::sync::OnceLock;

pub use admin::AdminEvent;
pub use bench_dep::BenchDepEvent;
pub use device_invite::DeviceInviteEvent;
pub use encrypted::EncryptedEvent;
pub use file_slice::FileSliceEvent;
pub use invite_accepted::InviteAcceptedEvent;
pub use local_signer_secret::LocalSignerSecretEvent;
pub use message::MessageEvent;
pub use message_attachment::MessageAttachmentEvent;
pub use message_deletion::MessageDeletionEvent;
pub use peer_removed::PeerRemovedEvent;
pub use peer_shared::PeerSharedEvent;
pub use reaction::ReactionEvent;
pub use registry::{EventRegistry, EventTypeMeta, ShareScope};
pub use secret_key::SecretKeyEvent;
pub use secret_shared::SecretSharedEvent;
pub use user::UserEvent;
pub use user_invite::UserInviteEvent;
pub use user_removed::UserRemovedEvent;
pub use workspace::WorkspaceEvent;

pub const EVENT_TYPE_MESSAGE: u8 = 1;
pub const EVENT_TYPE_REACTION: u8 = 2;
pub const EVENT_TYPE_ENCRYPTED: u8 = 5;
pub const EVENT_TYPE_SECRET_KEY: u8 = 6;
pub const EVENT_TYPE_MESSAGE_DELETION: u8 = 7;
pub const EVENT_TYPE_WORKSPACE: u8 = 8;
pub const EVENT_TYPE_INVITE_ACCEPTED: u8 = 9;
pub const EVENT_TYPE_USER_INVITE: u8 = 10;
pub const EVENT_TYPE_DEVICE_INVITE: u8 = 12;
pub const EVENT_TYPE_USER: u8 = 14;
pub const EVENT_TYPE_PEER_SHARED: u8 = 16;
pub const EVENT_TYPE_ADMIN: u8 = 18;
pub const EVENT_TYPE_USER_REMOVED: u8 = 20;
pub const EVENT_TYPE_PEER_REMOVED: u8 = 21;
pub const EVENT_TYPE_SECRET_SHARED: u8 = 22;
pub const EVENT_TYPE_MESSAGE_ATTACHMENT: u8 = 24;
pub const EVENT_TYPE_FILE_SLICE: u8 = 25;
pub const EVENT_TYPE_BENCH_DEP: u8 = 26;
pub const EVENT_TYPE_LOCAL_SIGNER_SECRET: u8 = 27;

/// Max event blob size: 1 MiB
pub const EVENT_MAX_BLOB_BYTES: usize = 1024 * 1024;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    workspace::ensure_schema(conn)?;
    invite_accepted::ensure_schema(conn)?;
    user_invite::ensure_schema(conn)?;
    device_invite::ensure_schema(conn)?;
    user::ensure_schema(conn)?;
    peer_shared::ensure_schema(conn)?;
    admin::ensure_schema(conn)?;
    peer_removed::ensure_schema(conn)?;
    message::ensure_schema(conn)?;
    reaction::ensure_schema(conn)?;
    message_deletion::ensure_schema(conn)?;
    message_attachment::ensure_schema(conn)?;
    file_slice::ensure_schema(conn)?;
    secret_key::ensure_schema(conn)?;
    secret_shared::ensure_schema(conn)?;
    local_signer_secret::ensure_schema(conn)?;
    subscription::ensure_schema(conn)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEvent {
    Message(MessageEvent),
    Reaction(ReactionEvent),
    Encrypted(EncryptedEvent),
    SecretKey(SecretKeyEvent),
    MessageDeletion(MessageDeletionEvent),
    Workspace(WorkspaceEvent),
    InviteAccepted(InviteAcceptedEvent),
    UserInvite(UserInviteEvent),
    DeviceInvite(DeviceInviteEvent),
    User(UserEvent),
    PeerShared(PeerSharedEvent),
    Admin(AdminEvent),
    UserRemoved(UserRemovedEvent),
    PeerRemoved(PeerRemovedEvent),
    SecretShared(SecretSharedEvent),
    MessageAttachment(MessageAttachmentEvent),
    FileSlice(FileSliceEvent),
    BenchDep(BenchDepEvent),
    LocalSignerSecret(LocalSignerSecretEvent),
}

impl ParsedEvent {
    pub fn created_at_ms(&self) -> u64 {
        match self {
            ParsedEvent::Message(m) => m.created_at_ms,
            ParsedEvent::Reaction(r) => r.created_at_ms,
            ParsedEvent::Encrypted(e) => e.created_at_ms,
            ParsedEvent::SecretKey(s) => s.created_at_ms,
            ParsedEvent::MessageDeletion(d) => d.created_at_ms,
            ParsedEvent::Workspace(w) => w.created_at_ms,
            ParsedEvent::InviteAccepted(a) => a.created_at_ms,
            ParsedEvent::UserInvite(u) => u.created_at_ms,
            ParsedEvent::DeviceInvite(d) => d.created_at_ms,
            ParsedEvent::User(u) => u.created_at_ms,
            ParsedEvent::PeerShared(p) => p.created_at_ms,
            ParsedEvent::Admin(a) => a.created_at_ms,
            ParsedEvent::UserRemoved(r) => r.created_at_ms,
            ParsedEvent::PeerRemoved(r) => r.created_at_ms,
            ParsedEvent::SecretShared(s) => s.created_at_ms,
            ParsedEvent::MessageAttachment(a) => a.created_at_ms,
            ParsedEvent::FileSlice(f) => f.created_at_ms,
            ParsedEvent::BenchDep(b) => b.created_at_ms,
            ParsedEvent::LocalSignerSecret(l) => l.created_at_ms,
        }
    }

    /// Extract dependency event IDs from schema-marked fields.
    /// Returns (field_name, raw_32_byte_id) pairs.
    ///
    /// Ordering is semantic: the most structural dep is listed first.
    pub fn dep_field_values(&self) -> Vec<(&'static str, [u8; 32])> {
        match self {
            ParsedEvent::Message(m) => vec![("author_id", m.author_id), ("signed_by", m.signed_by)],
            ParsedEvent::Reaction(r) => vec![
                ("target_event_id", r.target_event_id),
                ("author_id", r.author_id),
                ("signed_by", r.signed_by),
            ],
            ParsedEvent::Encrypted(e) => vec![("key_event_id", e.key_event_id)],
            ParsedEvent::SecretKey(_) => vec![],
            ParsedEvent::MessageDeletion(d) => vec![("signed_by", d.signed_by)],
            ParsedEvent::Workspace(_) => vec![],
            ParsedEvent::InviteAccepted(_) => vec![],
            ParsedEvent::UserInvite(u) => vec![("signed_by", u.signed_by)],
            ParsedEvent::DeviceInvite(d) => vec![("signed_by", d.signed_by)],
            ParsedEvent::User(u) => vec![("signed_by", u.signed_by)],
            ParsedEvent::PeerShared(p) => {
                vec![("user_event_id", p.user_event_id), ("signed_by", p.signed_by)]
            }
            ParsedEvent::Admin(a) => {
                vec![("user_event_id", a.user_event_id), ("signed_by", a.signed_by)]
            }
            ParsedEvent::UserRemoved(r) => {
                vec![("target_event_id", r.target_event_id), ("signed_by", r.signed_by)]
            }
            ParsedEvent::PeerRemoved(r) => {
                vec![("target_event_id", r.target_event_id), ("signed_by", r.signed_by)]
            }
            ParsedEvent::SecretShared(s) => {
                vec![("recipient_event_id", s.recipient_event_id), ("signed_by", s.signed_by)]
            }
            ParsedEvent::MessageAttachment(a) => vec![
                ("message_id", a.message_id),
                ("key_event_id", a.key_event_id),
                ("signed_by", a.signed_by),
            ],
            ParsedEvent::FileSlice(f) => vec![("signed_by", f.signed_by)],
            ParsedEvent::BenchDep(b) => b.dep_ids.iter().map(|id| ("dep_id", *id)).collect(),
            ParsedEvent::LocalSignerSecret(l) => {
                if l.signer_kind == local_signer_secret::SIGNER_KIND_PENDING_INVITE_UNWRAP {
                    Vec::new()
                } else {
                    vec![("signer_event_id", l.signer_event_id)]
                }
            }
        }
    }

    pub fn event_type_code(&self) -> u8 {
        match self {
            ParsedEvent::Message(_) => EVENT_TYPE_MESSAGE,
            ParsedEvent::Reaction(_) => EVENT_TYPE_REACTION,
            ParsedEvent::Encrypted(_) => EVENT_TYPE_ENCRYPTED,
            ParsedEvent::SecretKey(_) => EVENT_TYPE_SECRET_KEY,
            ParsedEvent::MessageDeletion(_) => EVENT_TYPE_MESSAGE_DELETION,
            ParsedEvent::Workspace(_) => EVENT_TYPE_WORKSPACE,
            ParsedEvent::InviteAccepted(_) => EVENT_TYPE_INVITE_ACCEPTED,
            ParsedEvent::UserInvite(_) => EVENT_TYPE_USER_INVITE,
            ParsedEvent::DeviceInvite(_) => EVENT_TYPE_DEVICE_INVITE,
            ParsedEvent::User(_) => EVENT_TYPE_USER,
            ParsedEvent::PeerShared(_) => EVENT_TYPE_PEER_SHARED,
            ParsedEvent::Admin(_) => EVENT_TYPE_ADMIN,
            ParsedEvent::UserRemoved(_) => EVENT_TYPE_USER_REMOVED,
            ParsedEvent::PeerRemoved(_) => EVENT_TYPE_PEER_REMOVED,
            ParsedEvent::SecretShared(_) => EVENT_TYPE_SECRET_SHARED,
            ParsedEvent::MessageAttachment(_) => EVENT_TYPE_MESSAGE_ATTACHMENT,
            ParsedEvent::FileSlice(_) => EVENT_TYPE_FILE_SLICE,
            ParsedEvent::BenchDep(_) => EVENT_TYPE_BENCH_DEP,
            ParsedEvent::LocalSignerSecret(_) => EVENT_TYPE_LOCAL_SIGNER_SECRET,
        }
    }

    /// Return signer info for signed event types: (signer_event_id, signer_type).
    /// Returns None for unsigned types.
    pub fn signer_fields(&self) -> Option<([u8; 32], u8)> {
        match self {
            ParsedEvent::UserInvite(u) => Some((u.signed_by, u.signer_type)),
            ParsedEvent::DeviceInvite(d) => Some((d.signed_by, d.signer_type)),
            ParsedEvent::User(u) => Some((u.signed_by, u.signer_type)),
            ParsedEvent::PeerShared(p) => Some((p.signed_by, p.signer_type)),
            ParsedEvent::Admin(a) => Some((a.signed_by, a.signer_type)),
            ParsedEvent::UserRemoved(r) => Some((r.signed_by, r.signer_type)),
            ParsedEvent::PeerRemoved(r) => Some((r.signed_by, r.signer_type)),
            ParsedEvent::SecretShared(s) => Some((s.signed_by, s.signer_type)),
            ParsedEvent::FileSlice(f) => Some((f.signed_by, f.signer_type)),
            ParsedEvent::Message(m) => Some((m.signed_by, m.signer_type)),
            ParsedEvent::Reaction(r) => Some((r.signed_by, r.signer_type)),
            ParsedEvent::MessageDeletion(d) => Some((d.signed_by, d.signer_type)),
            ParsedEvent::MessageAttachment(a) => Some((a.signed_by, a.signer_type)),
            ParsedEvent::Encrypted(_)
            | ParsedEvent::SecretKey(_)
            | ParsedEvent::Workspace(_)
            | ParsedEvent::InviteAccepted(_)
            | ParsedEvent::BenchDep(_)
            | ParsedEvent::LocalSignerSecret(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    TooShort { expected: usize, actual: usize },
    TrailingData { expected: usize, actual: usize },
    WrongType { expected: u8, actual: u8 },
    WrongVariant,
    ContentTooLong(usize),
    InvalidMetadata(&'static str),
    UnknownType(u8),
    TextSlot(layout::common::TextSlotError),
    InvalidEncryptedInnerType(u8),
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventError::TooShort { expected, actual } => {
                write!(f, "blob too short: expected {} bytes, got {}", expected, actual)
            }
            EventError::TrailingData { expected, actual } => {
                write!(
                    f,
                    "blob has trailing data: expected exactly {} bytes, got {}",
                    expected, actual
                )
            }
            EventError::WrongType { expected, actual } => {
                write!(f, "wrong event type: expected {}, got {}", expected, actual)
            }
            EventError::WrongVariant => write!(f, "wrong ParsedEvent variant for encoder"),
            EventError::ContentTooLong(len) => write!(f, "content too long: {} bytes", len),
            EventError::InvalidMetadata(msg) => write!(f, "invalid metadata: {}", msg),
            EventError::UnknownType(t) => write!(f, "unknown event type: {}", t),
            EventError::TextSlot(e) => write!(f, "text slot error: {}", e),
            EventError::InvalidEncryptedInnerType(t) => {
                write!(f, "invalid encrypted inner type: {}", t)
            }
        }
    }
}

impl std::error::Error for EventError {}

/// Extract created_at_ms from the common 9-byte prefix without full parsing.
/// Returns None if blob is too short.
pub fn extract_created_at_ms(blob: &[u8]) -> Option<u64> {
    if blob.len() < 9 {
        return None;
    }
    Some(u64::from_le_bytes(blob[1..9].try_into().unwrap()))
}

/// Extract event_type from the first byte of the blob.
pub fn extract_event_type(blob: &[u8]) -> Option<u8> {
    blob.first().copied()
}

static REGISTRY: OnceLock<EventRegistry> = OnceLock::new();

pub fn registry() -> &'static EventRegistry {
    REGISTRY.get_or_init(|| {
        EventRegistry::new(&[
            &message::MESSAGE_META,
            &reaction::REACTION_TYPE_META,
            &encrypted::ENCRYPTED_META,
            &secret_key::SECRET_KEY_META,
            &message_deletion::MESSAGE_DELETION_META,
            &workspace::WORKSPACE_META,
            &invite_accepted::INVITE_ACCEPTED_META,
            &user_invite::USER_INVITE_META,
            &device_invite::DEVICE_INVITE_META,
            &user::USER_META,
            &peer_shared::PEER_SHARED_META,
            &admin::ADMIN_META,
            &user_removed::USER_REMOVED_META,
            &peer_removed::PEER_REMOVED_META,
            &secret_shared::SECRET_SHARED_META,
            &message_attachment::MESSAGE_ATTACHMENT_META,
            &file_slice::FILE_SLICE_META,
            &bench_dep::BENCH_DEP_META,
            &local_signer_secret::LOCAL_SIGNER_SECRET_META,
        ])
    })
}

/// Parse a blob using the global registry.
pub fn parse_event(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let type_code = blob.first().copied().ok_or(EventError::TooShort {
        expected: 1,
        actual: 0,
    })?;
    let meta = registry()
        .lookup(type_code)
        .ok_or(EventError::UnknownType(type_code))?;
    (meta.parse)(blob)
}

/// Encode a ParsedEvent using the global registry.
pub fn encode_event(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let type_code = event.event_type_code();
    let meta = registry()
        .lookup(type_code)
        .ok_or(EventError::UnknownType(type_code))?;
    (meta.encode)(event)
}

/// Generic post-projection-drain hooks.
pub fn post_drain_hooks(
    conn: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    workspace::commands::retry_pending_invite_content_key_unwraps(conn, recorded_by)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_roundtrip_user() {
        let e = UserEvent {
            created_at_ms: 500,
            public_key: [28u8; 32],
            username: "test-user".to_string(),
            signed_by: [29u8; 32],
            signer_type: 2,
            signature: [30u8; 64],
        };
        let event = ParsedEvent::User(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), user::USER_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_registry_encryptable_coverage() {
        let reg = registry();
        let encryptable_codes: Vec<u8> = (1..=27u8)
            .filter(|c| reg.lookup(*c).is_some_and(|m| m.encryptable))
            .collect();
        assert_eq!(encryptable_codes, vec![1, 2, 6, 7, 24, 25]);

        for code in [5, 8, 9, 10, 12, 14, 16, 18, 20, 21, 22, 26, 27] {
            let meta = reg.lookup(code).unwrap();
            assert!(
                !meta.encryptable,
                "type {} ({}) should not be encryptable",
                code,
                meta.type_name
            );
        }

        for removed in [11, 13, 15, 17, 19] {
            assert!(reg.lookup(removed).is_none());
        }
    }

    #[test]
    fn test_signer_fields_unsigned() {
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: 100,
            public_key: [0u8; 32],
            name: "test-workspace".to_string(),
        });
        assert!(ws.signer_fields().is_none());
    }
}
