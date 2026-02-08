pub mod admin;
pub mod device_invite;
pub mod encrypted;
pub mod invite_accepted;
pub mod message;
pub mod message_deletion;
pub mod network;
pub mod peer_key;
pub mod peer_removed;
pub mod peer_shared;
pub mod reaction;
pub mod registry;
pub mod secret_key;
pub mod secret_shared;
pub mod signed_memo;
pub mod user;
pub mod user_invite;
pub mod user_removed;

use std::sync::OnceLock;

pub use admin::{AdminBootEvent, AdminOngoingEvent};
pub use device_invite::{DeviceInviteFirstEvent, DeviceInviteOngoingEvent};
pub use encrypted::EncryptedEvent;
pub use invite_accepted::InviteAcceptedEvent;
pub use message::MessageEvent;
pub use message_deletion::MessageDeletionEvent;
pub use network::NetworkEvent;
pub use peer_key::PeerKeyEvent;
pub use peer_removed::PeerRemovedEvent;
pub use peer_shared::{PeerSharedFirstEvent, PeerSharedOngoingEvent};
pub use reaction::ReactionEvent;
pub use registry::{EventRegistry, EventTypeMeta, ShareScope};
pub use secret_key::SecretKeyEvent;
pub use secret_shared::SecretSharedEvent;
pub use signed_memo::SignedMemoEvent;
pub use user::{UserBootEvent, UserOngoingEvent};
pub use user_invite::{UserInviteBootEvent, UserInviteOngoingEvent};
pub use user_removed::UserRemovedEvent;

pub const EVENT_TYPE_MESSAGE: u8 = 1;
pub const EVENT_TYPE_REACTION: u8 = 2;
pub const EVENT_TYPE_PEER_KEY: u8 = 3;
pub const EVENT_TYPE_SIGNED_MEMO: u8 = 4;
pub const EVENT_TYPE_ENCRYPTED: u8 = 5;
pub const EVENT_TYPE_SECRET_KEY: u8 = 6;
pub const EVENT_TYPE_MESSAGE_DELETION: u8 = 7;
pub const EVENT_TYPE_NETWORK: u8 = 8;
pub const EVENT_TYPE_INVITE_ACCEPTED: u8 = 9;
pub const EVENT_TYPE_USER_INVITE_BOOT: u8 = 10;
pub const EVENT_TYPE_USER_INVITE_ONGOING: u8 = 11;
pub const EVENT_TYPE_DEVICE_INVITE_FIRST: u8 = 12;
pub const EVENT_TYPE_DEVICE_INVITE_ONGOING: u8 = 13;
pub const EVENT_TYPE_USER_BOOT: u8 = 14;
pub const EVENT_TYPE_USER_ONGOING: u8 = 15;
pub const EVENT_TYPE_PEER_SHARED_FIRST: u8 = 16;
pub const EVENT_TYPE_PEER_SHARED_ONGOING: u8 = 17;
pub const EVENT_TYPE_ADMIN_BOOT: u8 = 18;
pub const EVENT_TYPE_ADMIN_ONGOING: u8 = 19;
pub const EVENT_TYPE_USER_REMOVED: u8 = 20;
pub const EVENT_TYPE_PEER_REMOVED: u8 = 21;
pub const EVENT_TYPE_SECRET_SHARED: u8 = 22;

/// Max event blob size: 1 MiB
pub const EVENT_MAX_BLOB_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEvent {
    Message(MessageEvent),
    Reaction(ReactionEvent),
    PeerKey(PeerKeyEvent),
    SignedMemo(SignedMemoEvent),
    Encrypted(EncryptedEvent),
    SecretKey(SecretKeyEvent),
    MessageDeletion(MessageDeletionEvent),
    Network(NetworkEvent),
    InviteAccepted(InviteAcceptedEvent),
    UserInviteBoot(UserInviteBootEvent),
    UserInviteOngoing(UserInviteOngoingEvent),
    DeviceInviteFirst(DeviceInviteFirstEvent),
    DeviceInviteOngoing(DeviceInviteOngoingEvent),
    UserBoot(UserBootEvent),
    UserOngoing(UserOngoingEvent),
    PeerSharedFirst(PeerSharedFirstEvent),
    PeerSharedOngoing(PeerSharedOngoingEvent),
    AdminBoot(AdminBootEvent),
    AdminOngoing(AdminOngoingEvent),
    UserRemoved(UserRemovedEvent),
    PeerRemoved(PeerRemovedEvent),
    SecretShared(SecretSharedEvent),
}

impl ParsedEvent {
    pub fn created_at_ms(&self) -> u64 {
        match self {
            ParsedEvent::Message(m) => m.created_at_ms,
            ParsedEvent::Reaction(r) => r.created_at_ms,
            ParsedEvent::PeerKey(p) => p.created_at_ms,
            ParsedEvent::SignedMemo(s) => s.created_at_ms,
            ParsedEvent::Encrypted(e) => e.created_at_ms,
            ParsedEvent::SecretKey(s) => s.created_at_ms,
            ParsedEvent::MessageDeletion(d) => d.created_at_ms,
            ParsedEvent::Network(n) => n.created_at_ms,
            ParsedEvent::InviteAccepted(a) => a.created_at_ms,
            ParsedEvent::UserInviteBoot(u) => u.created_at_ms,
            ParsedEvent::UserInviteOngoing(u) => u.created_at_ms,
            ParsedEvent::DeviceInviteFirst(d) => d.created_at_ms,
            ParsedEvent::DeviceInviteOngoing(d) => d.created_at_ms,
            ParsedEvent::UserBoot(u) => u.created_at_ms,
            ParsedEvent::UserOngoing(u) => u.created_at_ms,
            ParsedEvent::PeerSharedFirst(p) => p.created_at_ms,
            ParsedEvent::PeerSharedOngoing(p) => p.created_at_ms,
            ParsedEvent::AdminBoot(a) => a.created_at_ms,
            ParsedEvent::AdminOngoing(a) => a.created_at_ms,
            ParsedEvent::UserRemoved(r) => r.created_at_ms,
            ParsedEvent::PeerRemoved(r) => r.created_at_ms,
            ParsedEvent::SecretShared(s) => s.created_at_ms,
        }
    }

    /// Extract dependency event IDs from schema-marked fields.
    /// Returns (field_name, raw_32_byte_id) pairs.
    pub fn dep_field_values(&self) -> Vec<(&'static str, [u8; 32])> {
        match self {
            ParsedEvent::Message(_) => vec![],
            ParsedEvent::Reaction(r) => vec![("target_event_id", r.target_event_id)],
            ParsedEvent::PeerKey(_) => vec![],
            ParsedEvent::SignedMemo(s) => vec![("signed_by", s.signed_by)],
            ParsedEvent::Encrypted(e) => vec![("key_event_id", e.key_event_id)],
            ParsedEvent::SecretKey(_) => vec![],
            ParsedEvent::MessageDeletion(d) => vec![("target_event_id", d.target_event_id)],
            ParsedEvent::Network(_) => vec![],
            ParsedEvent::InviteAccepted(_) => vec![],
            // UserInviteBoot: signed_by is a dep (network_id is reference, not dep)
            ParsedEvent::UserInviteBoot(u) => vec![("signed_by", u.signed_by)],
            ParsedEvent::UserInviteOngoing(u) => vec![
                ("admin_event_id", u.admin_event_id),
                ("signed_by", u.signed_by),
            ],
            ParsedEvent::DeviceInviteFirst(d) => vec![("signed_by", d.signed_by)],
            ParsedEvent::DeviceInviteOngoing(d) => vec![("signed_by", d.signed_by)],
            ParsedEvent::UserBoot(u) => vec![("signed_by", u.signed_by)],
            ParsedEvent::UserOngoing(u) => vec![("signed_by", u.signed_by)],
            ParsedEvent::PeerSharedFirst(p) => vec![("signed_by", p.signed_by)],
            ParsedEvent::PeerSharedOngoing(p) => vec![("signed_by", p.signed_by)],
            ParsedEvent::AdminBoot(a) => vec![
                ("user_event_id", a.user_event_id),
                ("signed_by", a.signed_by),
            ],
            ParsedEvent::AdminOngoing(a) => vec![
                ("admin_boot_event_id", a.admin_boot_event_id),
                ("signed_by", a.signed_by),
            ],
            ParsedEvent::UserRemoved(r) => vec![
                ("target_event_id", r.target_event_id),
                ("signed_by", r.signed_by),
            ],
            ParsedEvent::PeerRemoved(r) => vec![
                ("target_event_id", r.target_event_id),
                ("signed_by", r.signed_by),
            ],
            ParsedEvent::SecretShared(s) => vec![
                ("key_event_id", s.key_event_id),
                ("recipient_event_id", s.recipient_event_id),
                ("signed_by", s.signed_by),
            ],
        }
    }

    pub fn event_type_code(&self) -> u8 {
        match self {
            ParsedEvent::Message(_) => EVENT_TYPE_MESSAGE,
            ParsedEvent::Reaction(_) => EVENT_TYPE_REACTION,
            ParsedEvent::PeerKey(_) => EVENT_TYPE_PEER_KEY,
            ParsedEvent::SignedMemo(_) => EVENT_TYPE_SIGNED_MEMO,
            ParsedEvent::Encrypted(_) => EVENT_TYPE_ENCRYPTED,
            ParsedEvent::SecretKey(_) => EVENT_TYPE_SECRET_KEY,
            ParsedEvent::MessageDeletion(_) => EVENT_TYPE_MESSAGE_DELETION,
            ParsedEvent::Network(_) => EVENT_TYPE_NETWORK,
            ParsedEvent::InviteAccepted(_) => EVENT_TYPE_INVITE_ACCEPTED,
            ParsedEvent::UserInviteBoot(_) => EVENT_TYPE_USER_INVITE_BOOT,
            ParsedEvent::UserInviteOngoing(_) => EVENT_TYPE_USER_INVITE_ONGOING,
            ParsedEvent::DeviceInviteFirst(_) => EVENT_TYPE_DEVICE_INVITE_FIRST,
            ParsedEvent::DeviceInviteOngoing(_) => EVENT_TYPE_DEVICE_INVITE_ONGOING,
            ParsedEvent::UserBoot(_) => EVENT_TYPE_USER_BOOT,
            ParsedEvent::UserOngoing(_) => EVENT_TYPE_USER_ONGOING,
            ParsedEvent::PeerSharedFirst(_) => EVENT_TYPE_PEER_SHARED_FIRST,
            ParsedEvent::PeerSharedOngoing(_) => EVENT_TYPE_PEER_SHARED_ONGOING,
            ParsedEvent::AdminBoot(_) => EVENT_TYPE_ADMIN_BOOT,
            ParsedEvent::AdminOngoing(_) => EVENT_TYPE_ADMIN_ONGOING,
            ParsedEvent::UserRemoved(_) => EVENT_TYPE_USER_REMOVED,
            ParsedEvent::PeerRemoved(_) => EVENT_TYPE_PEER_REMOVED,
            ParsedEvent::SecretShared(_) => EVENT_TYPE_SECRET_SHARED,
        }
    }

    /// Return signer info for signed event types: (signer_event_id, signer_type).
    /// Returns None for unsigned types.
    pub fn signer_fields(&self) -> Option<([u8; 32], u8)> {
        match self {
            ParsedEvent::SignedMemo(m) => Some((m.signed_by, m.signer_type)),
            ParsedEvent::UserInviteBoot(u) => Some((u.signed_by, u.signer_type)),
            ParsedEvent::UserInviteOngoing(u) => Some((u.signed_by, u.signer_type)),
            ParsedEvent::DeviceInviteFirst(d) => Some((d.signed_by, d.signer_type)),
            ParsedEvent::DeviceInviteOngoing(d) => Some((d.signed_by, d.signer_type)),
            ParsedEvent::UserBoot(u) => Some((u.signed_by, u.signer_type)),
            ParsedEvent::UserOngoing(u) => Some((u.signed_by, u.signer_type)),
            ParsedEvent::PeerSharedFirst(p) => Some((p.signed_by, p.signer_type)),
            ParsedEvent::PeerSharedOngoing(p) => Some((p.signed_by, p.signer_type)),
            ParsedEvent::AdminBoot(a) => Some((a.signed_by, a.signer_type)),
            ParsedEvent::AdminOngoing(a) => Some((a.signed_by, a.signer_type)),
            ParsedEvent::UserRemoved(r) => Some((r.signed_by, r.signer_type)),
            ParsedEvent::PeerRemoved(r) => Some((r.signed_by, r.signer_type)),
            ParsedEvent::SecretShared(s) => Some((s.signed_by, s.signer_type)),
            ParsedEvent::Message(_)
            | ParsedEvent::Reaction(_)
            | ParsedEvent::PeerKey(_)
            | ParsedEvent::Encrypted(_)
            | ParsedEvent::SecretKey(_)
            | ParsedEvent::MessageDeletion(_)
            | ParsedEvent::Network(_)
            | ParsedEvent::InviteAccepted(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    TooShort { expected: usize, actual: usize },
    WrongType { expected: u8, actual: u8 },
    WrongVariant,
    ContentTooLong(usize),
    UnknownType(u8),
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventError::TooShort { expected, actual } => {
                write!(f, "blob too short: expected {} bytes, got {}", expected, actual)
            }
            EventError::WrongType { expected, actual } => {
                write!(f, "wrong event type: expected {}, got {}", expected, actual)
            }
            EventError::WrongVariant => write!(f, "wrong ParsedEvent variant for encoder"),
            EventError::ContentTooLong(len) => write!(f, "content too long: {} bytes", len),
            EventError::UnknownType(t) => write!(f, "unknown event type: {}", t),
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
            &peer_key::PEER_KEY_META,
            &signed_memo::SIGNED_MEMO_META,
            &encrypted::ENCRYPTED_META,
            &secret_key::SECRET_KEY_META,
            &message_deletion::MESSAGE_DELETION_META,
            &network::NETWORK_META,
            &invite_accepted::INVITE_ACCEPTED_META,
            &user_invite::USER_INVITE_BOOT_META,
            &user_invite::USER_INVITE_ONGOING_META,
            &device_invite::DEVICE_INVITE_FIRST_META,
            &device_invite::DEVICE_INVITE_ONGOING_META,
            &user::USER_BOOT_META,
            &user::USER_ONGOING_META,
            &peer_shared::PEER_SHARED_FIRST_META,
            &peer_shared::PEER_SHARED_ONGOING_META,
            &admin::ADMIN_BOOT_META,
            &admin::ADMIN_ONGOING_META,
            &user_removed::USER_REMOVED_META,
            &peer_removed::PEER_REMOVED_META,
            &secret_shared::SECRET_SHARED_META,
        ])
    })
}

/// Parse a blob using the global registry.
pub fn parse_event(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let type_code = blob.first().copied().ok_or(EventError::TooShort {
        expected: 1,
        actual: 0,
    })?;
    let meta = registry().lookup(type_code).ok_or(EventError::UnknownType(type_code))?;
    (meta.parse)(blob)
}

/// Encode a ParsedEvent using the global registry.
pub fn encode_event(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let type_code = event.event_type_code();
    let meta = registry().lookup(type_code).ok_or(EventError::UnknownType(type_code))?;
    (meta.encode)(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msg = MessageEvent {
            created_at_ms: 1234567890123,
            channel_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "Hello, world!".to_string(),
        };

        let event = ParsedEvent::Message(msg.clone());
        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_reaction_roundtrip() {
        let rxn = ReactionEvent {
            created_at_ms: 9876543210000,
            target_event_id: [3u8; 32],
            author_id: [4u8; 32],
            emoji: "\u{1f44d}".to_string(),
        };

        let event = ParsedEvent::Reaction(rxn.clone());
        let blob = encode_event(&event).unwrap();
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_peer_key_roundtrip() {
        let pk = PeerKeyEvent {
            created_at_ms: 1111111111111,
            public_key: [5u8; 32],
        };

        let event = ParsedEvent::PeerKey(pk.clone());
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 41);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_signed_memo_roundtrip() {
        let memo = SignedMemoEvent {
            created_at_ms: 2222222222222,
            signed_by: [6u8; 32],
            signer_type: 0,
            content: "signed content".to_string(),
            signature: [7u8; 64],
        };

        let event = ParsedEvent::SignedMemo(memo.clone());
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 44 + 14 + 64); // 122
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_message_deletion_roundtrip() {
        let del = MessageDeletionEvent {
            created_at_ms: 3333333333333,
            target_event_id: [8u8; 32],
            author_id: [9u8; 32],
        };

        let event = ParsedEvent::MessageDeletion(del.clone());
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 73);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_network_roundtrip() {
        let net = NetworkEvent {
            created_at_ms: 4444444444444,
            public_key: [10u8; 32],
            network_id: [11u8; 32],
        };
        let event = ParsedEvent::Network(net);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 73);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_invite_accepted_roundtrip() {
        let ia = InviteAcceptedEvent {
            created_at_ms: 5555555555555,
            invite_event_id: [12u8; 32],
            network_id: [13u8; 32],
        };
        let event = ParsedEvent::InviteAccepted(ia);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 73);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_user_invite_boot_roundtrip() {
        let e = UserInviteBootEvent {
            created_at_ms: 100,
            public_key: [14u8; 32],
            network_id: [15u8; 32],
            signed_by: [16u8; 32],
            signer_type: 1,
            signature: [17u8; 64],
        };
        let event = ParsedEvent::UserInviteBoot(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 170);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_user_invite_ongoing_roundtrip() {
        let e = UserInviteOngoingEvent {
            created_at_ms: 200,
            public_key: [18u8; 32],
            admin_event_id: [19u8; 32],
            signed_by: [20u8; 32],
            signer_type: 5,
            signature: [21u8; 64],
        };
        let event = ParsedEvent::UserInviteOngoing(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 170);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_device_invite_first_roundtrip() {
        let e = DeviceInviteFirstEvent {
            created_at_ms: 300,
            public_key: [22u8; 32],
            signed_by: [23u8; 32],
            signer_type: 4,
            signature: [24u8; 64],
        };
        let event = ParsedEvent::DeviceInviteFirst(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 138);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_device_invite_ongoing_roundtrip() {
        let e = DeviceInviteOngoingEvent {
            created_at_ms: 400,
            public_key: [25u8; 32],
            signed_by: [26u8; 32],
            signer_type: 5,
            signature: [27u8; 64],
        };
        let event = ParsedEvent::DeviceInviteOngoing(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 138);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_user_boot_roundtrip() {
        let e = UserBootEvent {
            created_at_ms: 500,
            public_key: [28u8; 32],
            signed_by: [29u8; 32],
            signer_type: 2,
            signature: [30u8; 64],
        };
        let event = ParsedEvent::UserBoot(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 138);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_user_ongoing_roundtrip() {
        let e = UserOngoingEvent {
            created_at_ms: 600,
            public_key: [31u8; 32],
            signed_by: [32u8; 32],
            signer_type: 2,
            signature: [33u8; 64],
        };
        let event = ParsedEvent::UserOngoing(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 138);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_peer_shared_first_roundtrip() {
        let e = PeerSharedFirstEvent {
            created_at_ms: 700,
            public_key: [34u8; 32],
            signed_by: [35u8; 32],
            signer_type: 3,
            signature: [36u8; 64],
        };
        let event = ParsedEvent::PeerSharedFirst(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 138);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_peer_shared_ongoing_roundtrip() {
        let e = PeerSharedOngoingEvent {
            created_at_ms: 800,
            public_key: [37u8; 32],
            signed_by: [38u8; 32],
            signer_type: 3,
            signature: [39u8; 64],
        };
        let event = ParsedEvent::PeerSharedOngoing(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 138);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_admin_boot_roundtrip() {
        let e = AdminBootEvent {
            created_at_ms: 900,
            public_key: [40u8; 32],
            user_event_id: [41u8; 32],
            signed_by: [42u8; 32],
            signer_type: 1,
            signature: [43u8; 64],
        };
        let event = ParsedEvent::AdminBoot(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 170);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_admin_ongoing_roundtrip() {
        let e = AdminOngoingEvent {
            created_at_ms: 1000,
            public_key: [44u8; 32],
            admin_boot_event_id: [45u8; 32],
            signed_by: [46u8; 32],
            signer_type: 5,
            signature: [47u8; 64],
        };
        let event = ParsedEvent::AdminOngoing(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 170);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_user_removed_roundtrip() {
        let e = UserRemovedEvent {
            created_at_ms: 1100,
            target_event_id: [48u8; 32],
            signed_by: [49u8; 32],
            signer_type: 5,
            signature: [50u8; 64],
        };
        let event = ParsedEvent::UserRemoved(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 138);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_peer_removed_roundtrip() {
        let e = PeerRemovedEvent {
            created_at_ms: 1200,
            target_event_id: [51u8; 32],
            signed_by: [52u8; 32],
            signer_type: 5,
            signature: [53u8; 64],
        };
        let event = ParsedEvent::PeerRemoved(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 138);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_secret_shared_roundtrip() {
        let e = SecretSharedEvent {
            created_at_ms: 1300,
            key_event_id: [54u8; 32],
            recipient_event_id: [55u8; 32],
            wrapped_key: [56u8; 32],
            signed_by: [57u8; 32],
            signer_type: 5,
            signature: [58u8; 64],
        };
        let event = ParsedEvent::SecretShared(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), 202);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_registry_lookup() {
        let reg = registry();
        let msg_meta = reg.lookup(EVENT_TYPE_MESSAGE).unwrap();
        assert_eq!(msg_meta.type_name, "message");
        assert_eq!(msg_meta.projection_table, "messages");

        let rxn_meta = reg.lookup(EVENT_TYPE_REACTION).unwrap();
        assert_eq!(rxn_meta.type_name, "reaction");
        assert_eq!(rxn_meta.projection_table, "reactions");

        let pk_meta = reg.lookup(EVENT_TYPE_PEER_KEY).unwrap();
        assert_eq!(pk_meta.type_name, "peer_key");
        assert_eq!(pk_meta.projection_table, "peer_keys");

        let sm_meta = reg.lookup(EVENT_TYPE_SIGNED_MEMO).unwrap();
        assert_eq!(sm_meta.type_name, "signed_memo");
        assert_eq!(sm_meta.projection_table, "signed_memos");
        assert!(sm_meta.signer_required);
        assert_eq!(sm_meta.signature_byte_len, 64);

        let del_meta = reg.lookup(EVENT_TYPE_MESSAGE_DELETION).unwrap();
        assert_eq!(del_meta.type_name, "message_deletion");
        assert_eq!(del_meta.projection_table, "deleted_messages");

        // Identity types
        let net_meta = reg.lookup(EVENT_TYPE_NETWORK).unwrap();
        assert_eq!(net_meta.type_name, "network");
        assert!(!net_meta.signer_required);

        let ia_meta = reg.lookup(EVENT_TYPE_INVITE_ACCEPTED).unwrap();
        assert_eq!(ia_meta.share_scope, ShareScope::Local);

        let uib_meta = reg.lookup(EVENT_TYPE_USER_INVITE_BOOT).unwrap();
        assert!(uib_meta.signer_required);
        assert_eq!(uib_meta.signature_byte_len, 64);

        let ss_meta = reg.lookup(EVENT_TYPE_SECRET_SHARED).unwrap();
        assert_eq!(ss_meta.dep_fields, &["key_event_id", "recipient_event_id", "signed_by"]);

        assert!(reg.lookup(99).is_none());
    }

    #[test]
    fn test_variable_length_content() {
        // Empty content
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: 100,
            channel_id: [0u8; 32],
            author_id: [0u8; 32],
            content: "".to_string(),
        });
        let blob = encode_event(&msg).unwrap();
        assert_eq!(blob.len(), 75); // minimum
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, msg);

        // Large content
        let big_content = "x".repeat(1000);
        let msg2 = ParsedEvent::Message(MessageEvent {
            created_at_ms: 200,
            channel_id: [0u8; 32],
            author_id: [0u8; 32],
            content: big_content.clone(),
        });
        let blob2 = encode_event(&msg2).unwrap();
        assert_eq!(blob2.len(), 75 + 1000);
        let parsed2 = parse_event(&blob2).unwrap();
        assert_eq!(parsed2, msg2);
    }

    #[test]
    fn test_extract_created_at_ms() {
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: 42424242424242,
            channel_id: [0u8; 32],
            author_id: [0u8; 32],
            content: "test".to_string(),
        });
        let blob = encode_event(&msg).unwrap();
        assert_eq!(extract_created_at_ms(&blob), Some(42424242424242));
    }

    #[test]
    fn test_dep_field_values_message() {
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: 100,
            channel_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "hello".to_string(),
        });
        assert!(msg.dep_field_values().is_empty());
    }

    #[test]
    fn test_dep_field_values_reaction() {
        let target = [42u8; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: 200,
            target_event_id: target,
            author_id: [3u8; 32],
            emoji: "\u{1f44d}".to_string(),
        });
        let deps = rxn.dep_field_values();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "target_event_id");
        assert_eq!(deps[0].1, target);
    }

    #[test]
    fn test_dep_field_values_peer_key() {
        let pk = ParsedEvent::PeerKey(PeerKeyEvent {
            created_at_ms: 100,
            public_key: [1u8; 32],
        });
        assert!(pk.dep_field_values().is_empty());
    }

    #[test]
    fn test_dep_field_values_signed_memo() {
        let signer_id = [42u8; 32];
        let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: 300,
            signed_by: signer_id,
            signer_type: 0,
            content: "test".to_string(),
            signature: [0u8; 64],
        });
        let deps = memo.dep_field_values();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "signed_by");
        assert_eq!(deps[0].1, signer_id);
    }

    #[test]
    fn test_dep_field_values_message_deletion() {
        let target = [55u8; 32];
        let del = ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: 400,
            target_event_id: target,
            author_id: [10u8; 32],
        });
        let deps = del.dep_field_values();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "target_event_id");
        assert_eq!(deps[0].1, target);
    }

    #[test]
    fn test_signer_fields_unsigned() {
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: 100,
            channel_id: [0u8; 32],
            author_id: [0u8; 32],
            content: "".to_string(),
        });
        assert!(msg.signer_fields().is_none());

        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: 100,
            target_event_id: [0u8; 32],
            author_id: [0u8; 32],
            emoji: "x".to_string(),
        });
        assert!(rxn.signer_fields().is_none());

        let pk = ParsedEvent::PeerKey(PeerKeyEvent {
            created_at_ms: 100,
            public_key: [0u8; 32],
        });
        assert!(pk.signer_fields().is_none());

        let net = ParsedEvent::Network(NetworkEvent {
            created_at_ms: 100,
            public_key: [0u8; 32],
            network_id: [0u8; 32],
        });
        assert!(net.signer_fields().is_none());

        let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: 100,
            invite_event_id: [0u8; 32],
            network_id: [0u8; 32],
        });
        assert!(ia.signer_fields().is_none());
    }

    #[test]
    fn test_signer_fields_signed() {
        let signer_id = [42u8; 32];
        let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: 300,
            signed_by: signer_id,
            signer_type: 0,
            content: "test".to_string(),
            signature: [0u8; 64],
        });
        let (id, st) = memo.signer_fields().unwrap();
        assert_eq!(id, signer_id);
        assert_eq!(st, 0);

        // Identity signed types
        let ub = ParsedEvent::UserBoot(UserBootEvent {
            created_at_ms: 100,
            public_key: [0u8; 32],
            signed_by: [99u8; 32],
            signer_type: 2,
            signature: [0u8; 64],
        });
        let (id, st) = ub.signer_fields().unwrap();
        assert_eq!(id, [99u8; 32]);
        assert_eq!(st, 2);
    }

    #[test]
    fn test_extract_event_type() {
        let msg_blob = encode_event(&ParsedEvent::Message(MessageEvent {
            created_at_ms: 0,
            channel_id: [0u8; 32],
            author_id: [0u8; 32],
            content: "".to_string(),
        }))
        .unwrap();
        assert_eq!(extract_event_type(&msg_blob), Some(EVENT_TYPE_MESSAGE));

        let rxn_blob = encode_event(&ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: 0,
            target_event_id: [0u8; 32],
            author_id: [0u8; 32],
            emoji: "x".to_string(),
        }))
        .unwrap();
        assert_eq!(extract_event_type(&rxn_blob), Some(EVENT_TYPE_REACTION));

        let pk_blob = encode_event(&ParsedEvent::PeerKey(PeerKeyEvent {
            created_at_ms: 0,
            public_key: [0u8; 32],
        }))
        .unwrap();
        assert_eq!(extract_event_type(&pk_blob), Some(EVENT_TYPE_PEER_KEY));

        let memo_blob = encode_event(&ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: 0,
            signed_by: [0u8; 32],
            signer_type: 0,
            content: "".to_string(),
            signature: [0u8; 64],
        }))
        .unwrap();
        assert_eq!(extract_event_type(&memo_blob), Some(EVENT_TYPE_SIGNED_MEMO));

        let net_blob = encode_event(&ParsedEvent::Network(NetworkEvent {
            created_at_ms: 0,
            public_key: [0u8; 32],
            network_id: [0u8; 32],
        }))
        .unwrap();
        assert_eq!(extract_event_type(&net_blob), Some(EVENT_TYPE_NETWORK));
    }
}
