pub mod admin;
pub mod bench_dep;
pub mod encrypted;
pub mod endpoint_secret;
pub mod endpoint_shared;
pub mod file;
pub mod file_slice;
pub mod invite_accepted;
pub mod invite_secret;
pub mod key_request;
pub mod key_rotation;
pub mod key_secret;
pub mod key_shared;
pub mod layout;
pub mod message;
pub mod message_deletion;
pub mod peer_invite_shared;
pub mod peer_secret;
pub mod peer_shared;
pub mod reaction;
pub mod registry;
pub mod removal;
pub mod signed;
pub mod tenant;
pub mod user;
pub mod user_invite_shared;
pub mod workspace;

use rusqlite::Connection;
use std::sync::OnceLock;

/// Human-readable field descriptions for CLI display.
/// Each event struct implements this to describe its "interesting" fields,
/// skipping IDs already shown as deps, signatures, and created_at.
pub trait Describe {
    fn human_fields(&self) -> Vec<(&'static str, String)>;
}

/// Format a 32-byte ID as short base64 (first 8 chars, parenthesized).
pub fn short_id_b64(id: &[u8; 32]) -> String {
    let b64 = crate::crypto::event_id_to_base64(id);
    let short = &b64[..b64.len().min(8)];
    format!("({})", short)
}

/// Truncated hex display for byte arrays.
pub fn trunc_hex(bytes: &[u8], max_hex_chars: usize) -> String {
    let h = hex::encode(bytes);
    if h.len() > max_hex_chars {
        format!("{}...", &h[..max_hex_chars])
    } else {
        h
    }
}

pub use admin::AdminEvent;
pub use bench_dep::BenchDepEvent;
pub use encrypted::EncryptedEvent;
pub use endpoint_secret::EndpointSecretEvent;
pub use endpoint_shared::EndpointSharedEvent;
pub use file::FileEvent;
pub use file_slice::FileSliceEvent;
pub use invite_accepted::InviteAcceptedEvent;
pub use invite_secret::InviteSecretEvent;
pub use key_request::KeyRequestEvent;
pub use key_rotation::KeyRotationEvent;
pub use key_secret::KeySecretEvent;
pub use key_shared::KeySharedEvent;
pub use message::MessageEvent;
pub use message_deletion::MessageDeletionEvent;
pub use peer_invite_shared::DeviceInviteEvent;
pub use peer_secret::PeerSecretEvent;
pub use peer_shared::PeerSharedEvent;
pub use reaction::ReactionEvent;
pub use registry::{EventRegistry, EventTypeMeta, ShareScope, TransportPrivacy};
pub use removal::RemovalEvent;
pub use signed::SignedEvent;
pub use tenant::TenantEvent;
pub use user::UserEvent;
pub use user_invite_shared::UserInviteEvent;
pub use workspace::WorkspaceEvent;

pub const EVENT_TYPE_MESSAGE: u8 = 1;
pub const EVENT_TYPE_REACTION: u8 = 2;
pub const EVENT_TYPE_ENCRYPTED: u8 = 5;
pub const EVENT_TYPE_KEY_SECRET: u8 = 6;
pub const EVENT_TYPE_MESSAGE_DELETION: u8 = 7;
pub const EVENT_TYPE_WORKSPACE: u8 = 8;
pub const EVENT_TYPE_INVITE_ACCEPTED: u8 = 9;
pub const EVENT_TYPE_USER_INVITE: u8 = 10;
pub const EVENT_TYPE_DEVICE_INVITE: u8 = 12;
pub const EVENT_TYPE_USER: u8 = 14;
pub const EVENT_TYPE_PEER_SHARED: u8 = 16;
pub const EVENT_TYPE_ADMIN: u8 = 18;
pub const EVENT_TYPE_KEY_SHARED: u8 = 22;
pub const EVENT_TYPE_PEER: u8 = 23; // reserved (retired local peer event)
pub const EVENT_TYPE_FILE: u8 = 24;
pub const EVENT_TYPE_FILE_SLICE: u8 = 25;
pub const EVENT_TYPE_BENCH_DEP: u8 = 26;
pub const EVENT_TYPE_PEER_SECRET: u8 = 27;
pub const EVENT_TYPE_INVITE_SECRET: u8 = 28;
pub const EVENT_TYPE_TENANT: u8 = 29;
pub const EVENT_TYPE_KEY_REQUEST: u8 = 30;
pub const EVENT_TYPE_REMOVAL: u8 = 31;
pub const EVENT_TYPE_KEY_ROTATION: u8 = 32;
pub const EVENT_TYPE_ENDPOINT_SECRET: u8 = 33;
pub const EVENT_TYPE_ENDPOINT_SHARED: u8 = 34;
pub const EVENT_TYPE_SIGNED: u8 = 35;

/// Max event blob size: 1 MiB
pub const EVENT_MAX_BLOB_BYTES: usize = 1024 * 1024;

pub fn outer_semantic_type_code(blob: &[u8]) -> Option<u8> {
    match blob.first().copied() {
        Some(EVENT_TYPE_SIGNED) => signed::outer_payload(blob).and_then(outer_semantic_type_code),
        Some(EVENT_TYPE_ENCRYPTED) => encrypted::outer_inner_type_code(blob),
        Some(type_code) => Some(type_code),
        None => None,
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    workspace::ensure_schema(conn)?;
    invite_accepted::ensure_schema(conn)?;
    user_invite_shared::ensure_schema(conn)?;
    peer_invite_shared::ensure_schema(conn)?;
    user::ensure_schema(conn)?;
    peer_shared::ensure_schema(conn)?;
    admin::ensure_schema(conn)?;
    message::ensure_schema(conn)?;
    reaction::ensure_schema(conn)?;
    message_deletion::ensure_schema(conn)?;
    file::ensure_schema(conn)?;
    file_slice::ensure_schema(conn)?;
    key_secret::ensure_schema(conn)?;
    key_shared::ensure_schema(conn)?;
    key_request::ensure_schema(conn)?;
    removal::ensure_schema(conn)?;
    key_rotation::ensure_schema(conn)?;
    tenant::ensure_schema(conn)?;
    peer_secret::ensure_schema(conn)?;
    invite_secret::ensure_schema(conn)?;
    endpoint_secret::ensure_schema(conn)?;
    endpoint_shared::ensure_schema(conn)?;
    crate::state::subscriptions::ensure_schema(conn)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEvent {
    Message(MessageEvent),
    Reaction(ReactionEvent),
    Signed(SignedEvent),
    Encrypted(EncryptedEvent),
    KeySecret(KeySecretEvent),
    MessageDeletion(MessageDeletionEvent),
    Workspace(WorkspaceEvent),
    InviteAccepted(InviteAcceptedEvent),
    Removal(RemovalEvent),
    KeyRotation(KeyRotationEvent),
    KeyRequest(KeyRequestEvent),
    UserInvite(UserInviteEvent),
    DeviceInvite(DeviceInviteEvent),
    User(UserEvent),
    PeerShared(PeerSharedEvent),
    Admin(AdminEvent),
    KeyShared(KeySharedEvent),
    Tenant(TenantEvent),
    File(FileEvent),
    FileSlice(FileSliceEvent),
    BenchDep(BenchDepEvent),
    PeerSecret(PeerSecretEvent),
    InviteSecret(InviteSecretEvent),
    EndpointSecret(EndpointSecretEvent),
    EndpointShared(EndpointSharedEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDepMode {
    Blocking,
    SyncOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventDepRef {
    pub field_name: &'static str,
    pub event_id: [u8; 32],
    pub allowed_type_codes: &'static [u8],
    pub mode: EventDepMode,
}

impl EventDepRef {
    pub const fn blocking(
        field_name: &'static str,
        event_id: [u8; 32],
        allowed_type_codes: &'static [u8],
    ) -> Self {
        Self {
            field_name,
            event_id,
            allowed_type_codes,
            mode: EventDepMode::Blocking,
        }
    }

    pub const fn sync_only(
        field_name: &'static str,
        event_id: [u8; 32],
        allowed_type_codes: &'static [u8],
    ) -> Self {
        Self {
            field_name,
            event_id,
            allowed_type_codes,
            mode: EventDepMode::SyncOnly,
        }
    }
}

impl ParsedEvent {
    pub fn created_at_ms(&self) -> u64 {
        match self {
            ParsedEvent::Message(m) => m.created_at_ms,
            ParsedEvent::Reaction(r) => r.created_at_ms,
            ParsedEvent::Signed(s) => s.inner_created_at_ms,
            ParsedEvent::Encrypted(e) => e.created_at_ms,
            ParsedEvent::KeySecret(s) => s.created_at_ms,
            ParsedEvent::MessageDeletion(d) => d.created_at_ms,
            ParsedEvent::Workspace(w) => w.created_at_ms,
            ParsedEvent::InviteAccepted(a) => a.created_at_ms,
            ParsedEvent::Removal(r) => r.created_at_ms,
            ParsedEvent::KeyRotation(k) => k.created_at_ms,
            ParsedEvent::KeyRequest(k) => k.created_at_ms,
            ParsedEvent::UserInvite(u) => u.created_at_ms,
            ParsedEvent::DeviceInvite(d) => d.created_at_ms,
            ParsedEvent::User(u) => u.created_at_ms,
            ParsedEvent::PeerShared(p) => p.created_at_ms,
            ParsedEvent::Admin(a) => a.created_at_ms,
            ParsedEvent::KeyShared(s) => s.created_at_ms,
            ParsedEvent::Tenant(t) => t.created_at_ms,
            ParsedEvent::File(a) => a.created_at_ms,
            ParsedEvent::FileSlice(f) => f.created_at_ms,
            ParsedEvent::BenchDep(b) => b.created_at_ms,
            ParsedEvent::PeerSecret(l) => l.created_at_ms,
            ParsedEvent::InviteSecret(k) => k.created_at_ms,
            ParsedEvent::EndpointSecret(e) => e.created_at_ms,
            ParsedEvent::EndpointShared(e) => e.created_at_ms,
        }
    }

    /// Extract dependency refs for this event payload or outer wrapper.
    /// For signed events this returns only the outer signer dep; callers that
    /// want the full visible outer graph should recurse into the signed payload.
    pub fn dep_refs(&self) -> Vec<EventDepRef> {
        match self {
            ParsedEvent::Message(m) => vec![EventDepRef::blocking("author_id", m.author_id, &[14, 15])],
            ParsedEvent::Reaction(r) => vec![
                EventDepRef::blocking("target_event_id", r.target_event_id, &[EVENT_TYPE_MESSAGE]),
                EventDepRef::blocking("author_id", r.author_id, &[14, 15]),
            ],
            ParsedEvent::Signed(s) => vec![EventDepRef::blocking(
                "signed_by",
                s.signer_event_id,
                &[EVENT_TYPE_WORKSPACE, EVENT_TYPE_USER_INVITE, EVENT_TYPE_DEVICE_INVITE, EVENT_TYPE_USER, EVENT_TYPE_PEER_SHARED, EVENT_TYPE_ADMIN],
            )],
            ParsedEvent::Encrypted(e) => {
                let mut deps = vec![EventDepRef::blocking(
                    "key_event_id",
                    e.key_event_id,
                    &[EVENT_TYPE_KEY_SECRET],
                )];
                if e.owner_event_id != encrypted::NO_OWNER_EVENT_ID {
                    deps.push(EventDepRef::blocking(
                        "owner_event_id",
                        e.owner_event_id,
                        &[EVENT_TYPE_MESSAGE],
                    ));
                }
                if e.outer_dep_event_id != encrypted::NO_OUTER_DEP_EVENT_ID {
                    if let Some(spec) = encrypted::outer_dep_spec(e.inner_type_code) {
                        let dep = match spec.mode {
                            EventDepMode::Blocking => EventDepRef::blocking(
                                spec.field_name,
                                e.outer_dep_event_id,
                                spec.allowed_type_codes,
                            ),
                            EventDepMode::SyncOnly => EventDepRef::sync_only(
                                spec.field_name,
                                e.outer_dep_event_id,
                                spec.allowed_type_codes,
                            ),
                        };
                        deps.push(dep);
                    }
                }
                deps
            }
            ParsedEvent::KeySecret(_) => vec![],
            ParsedEvent::MessageDeletion(d) => vec![EventDepRef::sync_only(
                "target_event_id",
                d.target_event_id,
                &[EVENT_TYPE_MESSAGE],
            )],
            ParsedEvent::Workspace(_) => vec![],
            ParsedEvent::InviteAccepted(a) => vec![EventDepRef::blocking(
                "tenant_event_id",
                a.tenant_event_id,
                &[EVENT_TYPE_TENANT],
            )],
            ParsedEvent::Removal(r) => {
                let slots = [r.parent_1, r.parent_2, r.parent_3, r.parent_4];
                removal::frontier_refs_from_slots(r.parent_count, &slots)
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(idx, id)| EventDepRef::blocking(
                        match idx {
                            0 => "parent_1",
                            1 => "parent_2",
                            2 => "parent_3",
                            _ => "parent_4",
                        },
                        id,
                        &[],
                    ))
                    .collect()
            }
            ParsedEvent::KeyRotation(k) => {
                let slots = [
                    k.frontier_ref_1,
                    k.frontier_ref_2,
                    k.frontier_ref_3,
                    k.frontier_ref_4,
                ];
                removal::frontier_refs_from_slots(k.frontier_count, &slots)
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(idx, id)| EventDepRef::blocking(
                        match idx {
                            0 => "frontier_ref_1",
                            1 => "frontier_ref_2",
                            2 => "frontier_ref_3",
                            _ => "frontier_ref_4",
                        },
                        id,
                        &[],
                    ))
                    .collect()
            }
            ParsedEvent::KeyRequest(_) => vec![],
            ParsedEvent::UserInvite(u) => vec![EventDepRef::blocking(
                "authority_event_id",
                u.authority_event_id,
                &[EVENT_TYPE_WORKSPACE, EVENT_TYPE_ADMIN],
            )],
            ParsedEvent::DeviceInvite(d) => vec![EventDepRef::blocking(
                "authority_event_id",
                d.authority_event_id,
                &[EVENT_TYPE_USER],
            )],
            ParsedEvent::User(_) => vec![],
            ParsedEvent::PeerShared(p) => vec![
                EventDepRef::blocking("user_event_id", p.user_event_id, &[EVENT_TYPE_USER]),
                EventDepRef::blocking(
                    "endpoint_shared_event_id",
                    p.endpoint_shared_event_id,
                    &[EVENT_TYPE_ENDPOINT_SHARED],
                ),
            ],
            ParsedEvent::Admin(a) => vec![EventDepRef::blocking(
                "user_event_id",
                a.user_event_id,
                &[EVENT_TYPE_USER],
            )],
            ParsedEvent::KeyShared(s) => {
                let slots = [
                    s.frontier_ref_1,
                    s.frontier_ref_2,
                    s.frontier_ref_3,
                    s.frontier_ref_4,
                ];
                let mut deps = vec![EventDepRef::blocking(
                    "recipient_event_id",
                    s.recipient_event_id,
                    &[EVENT_TYPE_USER_INVITE, EVENT_TYPE_DEVICE_INVITE],
                )];
                deps.extend(
                    removal::frontier_refs_from_slots(s.frontier_count, &slots)
                        .unwrap_or_default()
                        .into_iter()
                        .enumerate()
                        .map(|(idx, id)| EventDepRef::blocking(
                            match idx {
                                0 => "frontier_ref_1",
                                1 => "frontier_ref_2",
                                2 => "frontier_ref_3",
                                _ => "frontier_ref_4",
                            },
                            id,
                            &[],
                        )),
                );
                deps
            }
            ParsedEvent::Tenant(_) => vec![],
            ParsedEvent::File(a) => vec![
                EventDepRef::blocking("message_id", a.message_id, &[EVENT_TYPE_MESSAGE]),
                EventDepRef::blocking("key_event_id", a.key_event_id, &[EVENT_TYPE_KEY_SECRET]),
            ],
            ParsedEvent::FileSlice(_) => vec![],
            ParsedEvent::BenchDep(b) => b
                .dep_ids
                .iter()
                .copied()
                .map(|id| EventDepRef::blocking("dep_id", id, &[]))
                .collect(),
            ParsedEvent::PeerSecret(p) => vec![EventDepRef::blocking(
                "signer_event_id",
                p.signer_event_id,
                &[EVENT_TYPE_PEER_SHARED],
            )],
            ParsedEvent::InviteSecret(_) => vec![],
            ParsedEvent::EndpointSecret(_) => vec![],
            ParsedEvent::EndpointShared(_) => vec![],
        }
    }

    pub fn blocking_dep_refs(&self) -> Vec<EventDepRef> {
        self.dep_refs()
            .into_iter()
            .filter(|dep| dep.mode == EventDepMode::Blocking)
            .collect()
    }

    pub fn dep_field_values(&self) -> Vec<(&'static str, [u8; 32])> {
        self.dep_refs()
            .into_iter()
            .map(|dep| (dep.field_name, dep.event_id))
            .collect()
    }

    pub fn blocking_dep_field_values(&self) -> Vec<(&'static str, [u8; 32])> {
        self.blocking_dep_refs()
            .into_iter()
            .map(|dep| (dep.field_name, dep.event_id))
            .collect()
    }

    pub fn blocking_dep_field_type_codes(&self) -> Vec<&'static [u8]> {
        self.blocking_dep_refs()
            .into_iter()
            .map(|dep| dep.allowed_type_codes)
            .collect()
    }

    pub fn outer_sync_dep_refs_recursive(&self) -> Vec<EventDepRef> {
        let mut deps = self.dep_refs();
        if let ParsedEvent::Signed(signed) = self {
            if let Ok(inner) = parse_event(&signed.payload) {
                deps.extend(inner.outer_sync_dep_refs_recursive());
            }
        }
        deps
    }

    pub fn event_type_code(&self) -> u8 {
        match self {
            ParsedEvent::Message(_) => EVENT_TYPE_MESSAGE,
            ParsedEvent::Reaction(_) => EVENT_TYPE_REACTION,
            ParsedEvent::Signed(_) => EVENT_TYPE_SIGNED,
            ParsedEvent::Encrypted(_) => EVENT_TYPE_ENCRYPTED,
            ParsedEvent::KeySecret(_) => EVENT_TYPE_KEY_SECRET,
            ParsedEvent::MessageDeletion(_) => EVENT_TYPE_MESSAGE_DELETION,
            ParsedEvent::Workspace(_) => EVENT_TYPE_WORKSPACE,
            ParsedEvent::InviteAccepted(_) => EVENT_TYPE_INVITE_ACCEPTED,
            ParsedEvent::Removal(_) => EVENT_TYPE_REMOVAL,
            ParsedEvent::KeyRotation(_) => EVENT_TYPE_KEY_ROTATION,
            ParsedEvent::KeyRequest(_) => EVENT_TYPE_KEY_REQUEST,
            ParsedEvent::UserInvite(_) => EVENT_TYPE_USER_INVITE,
            ParsedEvent::DeviceInvite(_) => EVENT_TYPE_DEVICE_INVITE,
            ParsedEvent::User(_) => EVENT_TYPE_USER,
            ParsedEvent::PeerShared(_) => EVENT_TYPE_PEER_SHARED,
            ParsedEvent::Admin(_) => EVENT_TYPE_ADMIN,
            ParsedEvent::KeyShared(_) => EVENT_TYPE_KEY_SHARED,
            ParsedEvent::Tenant(_) => EVENT_TYPE_TENANT,
            ParsedEvent::File(_) => EVENT_TYPE_FILE,
            ParsedEvent::FileSlice(_) => EVENT_TYPE_FILE_SLICE,
            ParsedEvent::BenchDep(_) => EVENT_TYPE_BENCH_DEP,
            ParsedEvent::PeerSecret(_) => EVENT_TYPE_PEER_SECRET,
            ParsedEvent::InviteSecret(_) => EVENT_TYPE_INVITE_SECRET,
            ParsedEvent::EndpointSecret(_) => EVENT_TYPE_ENDPOINT_SECRET,
            ParsedEvent::EndpointShared(_) => EVENT_TYPE_ENDPOINT_SHARED,
        }
    }

    /// Human-readable field descriptions for CLI display.
    pub fn human_fields(&self) -> Vec<(&'static str, String)> {
        match self {
            ParsedEvent::Message(e) => e.human_fields(),
            ParsedEvent::Reaction(e) => e.human_fields(),
            ParsedEvent::Signed(e) => e.human_fields(),
            ParsedEvent::Encrypted(e) => e.human_fields(),
            ParsedEvent::KeySecret(e) => e.human_fields(),
            ParsedEvent::MessageDeletion(e) => e.human_fields(),
            ParsedEvent::Workspace(e) => e.human_fields(),
            ParsedEvent::InviteAccepted(e) => e.human_fields(),
            ParsedEvent::Removal(e) => e.human_fields(),
            ParsedEvent::KeyRotation(e) => e.human_fields(),
            ParsedEvent::KeyRequest(e) => e.human_fields(),
            ParsedEvent::UserInvite(e) => e.human_fields(),
            ParsedEvent::DeviceInvite(e) => e.human_fields(),
            ParsedEvent::User(e) => e.human_fields(),
            ParsedEvent::PeerShared(e) => e.human_fields(),
            ParsedEvent::Admin(e) => e.human_fields(),
            ParsedEvent::KeyShared(e) => e.human_fields(),
            ParsedEvent::File(e) => e.human_fields(),
            ParsedEvent::FileSlice(e) => e.human_fields(),
            ParsedEvent::BenchDep(e) => e.human_fields(),
            ParsedEvent::PeerSecret(e) => e.human_fields(),
            ParsedEvent::Tenant(e) => e.human_fields(),
            ParsedEvent::InviteSecret(e) => e.human_fields(),
            ParsedEvent::EndpointSecret(e) => e.human_fields(),
            ParsedEvent::EndpointShared(e) => e.human_fields(),
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
                write!(
                    f,
                    "blob too short: expected {} bytes, got {}",
                    expected, actual
                )
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
    if blob.first().copied() == Some(EVENT_TYPE_SIGNED) {
        return signed::outer_payload(blob).and_then(extract_created_at_ms);
    }
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
            &signed::SIGNED_META,
            &encrypted::ENCRYPTED_META,
            &key_secret::KEY_SECRET_META,
            &message_deletion::MESSAGE_DELETION_META,
            &workspace::WORKSPACE_META,
            &invite_accepted::INVITE_ACCEPTED_META,
            &removal::REMOVAL_META,
            &key_rotation::KEY_ROTATION_META,
            &key_request::KEY_REQUEST_META,
            &user_invite_shared::USER_INVITE_META,
            &peer_invite_shared::DEVICE_INVITE_META,
            &user::USER_META,
            &peer_shared::PEER_SHARED_META,
            &admin::ADMIN_META,
            &key_shared::KEY_SHARED_META,
            &tenant::TENANT_META,
            &file::FILE_META,
            &file_slice::FILE_SLICE_META,
            &bench_dep::BENCH_DEP_META,
            &peer_secret::PEER_SECRET_META,
            &invite_secret::INVITE_SECRET_META,
            &endpoint_secret::ENDPOINT_SECRET_META,
            &endpoint_shared::ENDPOINT_SHARED_META,
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
    _conn: &rusqlite::Connection,
    _recorded_by: &str,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    Ok(0)
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
        let encryptable_codes: Vec<u8> = (1..=35u8)
            .filter(|c| reg.lookup(*c).is_some_and(|m| m.encryptable))
            .collect();
        assert_eq!(encryptable_codes, vec![1, 2, 6, 7, 24, 25]);

        for code in [
            5, 8, 9, 10, 12, 14, 16, 18, 22, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
        ] {
            if let Some(meta) = reg.lookup(code) {
                assert!(
                    !meta.encryptable,
                    "type {} ({}) should not be encryptable",
                    code, meta.type_name
                );
            }
        }

        for removed in [11, 13, 15, 17, 19, 20, 21, 23] {
            assert!(reg.lookup(removed).is_none());
        }
    }

    #[test]
    fn test_registry_transport_privacy_coverage() {
        let reg = registry();
        let required_codes: Vec<u8> = (1..=35u8)
            .filter(|c| {
                reg.lookup(*c)
                    .is_some_and(|m| m.transport_privacy() == TransportPrivacy::RequireEncrypted)
            })
            .collect();
        assert_eq!(required_codes, vec![1, 2, 7, 24, 25]);

        assert_eq!(
            reg.lookup(EVENT_TYPE_KEY_SECRET)
                .unwrap()
                .transport_privacy(),
            TransportPrivacy::Optional
        );

        for code in [
            5, 8, 9, 10, 12, 14, 16, 18, 22, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
        ] {
            if let Some(meta) = reg.lookup(code) {
                assert_eq!(
                    meta.transport_privacy(),
                    TransportPrivacy::PlaintextOnly,
                    "type {} ({}) should remain plaintext-only",
                    code,
                    meta.type_name
                );
            }
        }
    }
}
