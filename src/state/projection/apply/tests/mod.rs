use super::project_one::project_one;
use crate::crypto::{event_id_from_base64, event_id_to_base64, hash_event, EventId};
use crate::db::{
    open_in_memory,
    schema::create_tables,
    store::{insert_event, insert_recorded_event, insert_shared_event_index_entry_if_shared},
    timeline::EventTimeline,
};
use crate::event_modules::{
    self as events, registry, BenchDepEvent, EncryptedEvent, FileEvent, FileSliceEvent,
    KeyRequestEvent, KeySecretEvent, KeySharedEvent, MessageDeletionEvent, MessageEvent,
    ParsedEvent, ReactionEvent, WorkspaceEvent, EVENT_TYPE_ENCRYPTED, EVENT_TYPE_FILE_SLICE,
    EVENT_TYPE_MESSAGE, EVENT_TYPE_MESSAGE_DELETION, EVENT_TYPE_REACTION,
};
use crate::projection::decision::ProjectionDecision;
use crate::projection::encrypted::encrypt_event_blob;
use crate::projection::signer::sign_event_bytes;
use crate::state::projection::create::{
    create_event_staged, create_event_synchronous, create_signed_event_synchronous, project_event,
    store_event_only,
};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

mod cascade;
mod core_projection;
mod deletion;
mod encryption;
mod file_slice;
mod identity;
mod invite;
mod removal_rotation;
mod tenant;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub(super) fn signer_user_map() -> &'static Mutex<HashMap<EventId, EventId>> {
    static MAP: OnceLock<Mutex<HashMap<EventId, EventId>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn register_signer_user(signer_eid: EventId, user_event_id: EventId) {
    signer_user_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(signer_eid, user_event_id);
}

pub(super) fn user_for_signer(signer_eid: &EventId) -> EventId {
    *signer_user_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(signer_eid)
        .expect("missing signer->user mapping for test identity chain")
}

pub(super) const TEST_CONTENT_KEY_CREATED_AT_MS: u64 = 4242;

pub(super) fn test_content_key_bytes() -> [u8; 32] {
    [0xA5; 32]
}

pub(super) fn encrypt_test_content_blob(plaintext: &[u8]) -> ([u8; 12], Vec<u8>, [u8; 16]) {
    let cipher = Aes256Gcm::new_from_slice(&test_content_key_bytes()).unwrap();
    let event_hash = hash_event(plaintext);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&event_hash[..12]);
    let ciphertext_with_tag = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .unwrap();
    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);
    (nonce, ciphertext, auth_tag)
}

pub(super) fn test_content_key_event() -> ParsedEvent {
    ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: TEST_CONTENT_KEY_CREATED_AT_MS,
        key_bytes: test_content_key_bytes(),
    })
}

pub(super) fn test_content_key_event_id() -> EventId {
    hash_event(&events::encode_event(&test_content_key_event()).unwrap())
}

pub(super) fn ensure_test_content_key(conn: &Connection, recorded_by: &str) -> EventId {
    let key_event_id = test_content_key_event_id();
    let key_event_id_b64 = event_id_to_base64(&key_event_id);
    let already_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &key_event_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    if already_valid {
        return key_event_id;
    }

    let key_event = test_content_key_event();
    let key_blob = events::encode_event(&key_event).unwrap();
    let ts = now_ms() as i64;
    insert_event(
        conn,
        &key_event_id,
        "key_secret",
        &key_blob,
        crate::event_modules::ShareScope::Local,
        key_event.created_at_ms() as i64,
        ts,
    )
    .unwrap();
    insert_recorded_event(conn, recorded_by, &key_event_id, ts, "test").unwrap();
    let decision = project_one(conn, recorded_by, &key_event_id).unwrap();
    assert_eq!(decision, ProjectionDecision::Valid);
    key_event_id
}

pub(super) fn wrap_test_content_blob(conn: &Connection, recorded_by: &str, blob: &[u8]) -> Vec<u8> {
    let type_code = match blob.first().copied() {
        Some(type_code) => type_code,
        None => return blob.to_vec(),
    };
    let Some(meta) = registry().lookup(type_code) else {
        return blob.to_vec();
    };
    if meta.transport_privacy() != crate::event_modules::TransportPrivacy::RequireEncrypted {
        return blob.to_vec();
    }

    let key_event_id = ensure_test_content_key(conn, recorded_by);
    let (nonce, ciphertext, auth_tag) = encrypt_test_content_blob(blob);
    let created_at_ms = events::parse_event(blob)
        .map(|event| event.created_at_ms())
        .unwrap_or_else(|_| now_ms());
    let wrapper = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms,
        key_event_id,
        inner_type_code: type_code,
        nonce,
        ciphertext,
        auth_tag,
    });
    events::encode_event(&wrapper).unwrap()
}

pub(super) fn canonical_test_event_id(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
) -> EventId {
    hash_event(&wrap_test_content_blob(conn, recorded_by, blob))
}

/// Insert a blob into events + shared_event_index + recorded_events (simulating what
/// batch_writer or create_event_synchronous does before calling project_one).
pub(super) fn insert_event_raw(conn: &Connection, recorded_by: &str, blob: &[u8]) -> EventId {
    let blob = wrap_test_content_blob(conn, recorded_by, blob);
    let event_id = hash_event(&blob);
    let ts = now_ms();
    let type_code = blob[0];
    let type_name = registry()
        .lookup(type_code)
        .map(|m| m.type_name)
        .unwrap_or("unknown");

    insert_event(
        conn,
        &event_id,
        type_name,
        &blob,
        crate::event_modules::ShareScope::Shared,
        ts as i64,
        ts as i64,
    )
    .unwrap();
    insert_shared_event_index_entry_if_shared(
        conn,
        crate::event_modules::ShareScope::Shared,
        ts as i64,
        &event_id,
        "",
    )
    .unwrap();
    insert_recorded_event(conn, recorded_by, &event_id, ts as i64, "test").unwrap();

    event_id
}

pub(super) fn mark_valid_for_test(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
    semantic_type_code: u8,
) {
    let eid_b64 = event_id_to_base64(event_id);
    conn.execute(
        "INSERT OR IGNORE INTO valid_events (peer_id, event_id, semantic_type_code)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, &eid_b64, i64::from(semantic_type_code)],
    )
    .unwrap();
}

use crate::event_modules::{
    DeviceInviteEvent, InviteAcceptedEvent, PeerSharedEvent, TenantEvent, UserEvent,
    UserInviteEvent,
};

/// Create a Workspace event, insert it, and mark it valid for this tenant.
/// Returns the event_id suitable for tests that need an existing workspace row.
pub(super) fn setup_workspace_event(conn: &Connection, recorded_by: &str) -> EventId {
    let ws = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: [0xAA; 32],
        name: "workspace".to_string(),
    });
    let blob = events::encode_event(&ws).unwrap();
    let eid = insert_event_raw(conn, recorded_by, &blob);
    mark_valid_for_test(conn, recorded_by, &eid, ws.event_type_code());
    eid
}

pub(super) fn setup_tenant_event(conn: &Connection, recorded_by: &str) -> EventId {
    let existing: Option<String> = conn
        .query_row(
            "SELECT event_id FROM tenants WHERE recorded_by = ?1 ORDER BY created_at ASC, event_id ASC LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .ok();
    if let Some(eid_b64) = existing {
        return event_id_from_base64(&eid_b64).expect("invalid tenants.event_id base64");
    }

    let mut rng = rand::thread_rng();
    let peer_key = SigningKey::generate(&mut rng);
    let tenant_event = ParsedEvent::Tenant(TenantEvent {
        created_at_ms: now_ms(),
        public_key: peer_key.verifying_key().to_bytes(),
    });
    create_event_synchronous(conn, recorded_by, &tenant_event).unwrap()
}

pub(super) fn append_invite_link_workspace_context(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: EventId,
    workspace_id: EventId,
) {
    let invite_event_id_b64 = event_id_to_base64(&invite_event_id);
    let workspace_id_b64 = event_id_to_base64(&workspace_id);
    crate::db::transport_trust::append_bootstrap_context(
        conn,
        recorded_by,
        &invite_event_id_b64,
        &workspace_id_b64,
        "",
        &[0xAB; 32],
    )
    .unwrap();
}

/// Create a minimal identity chain and return (peer_shared_event_id, signing_key).
/// Uses the normal create helpers for the happy path so fixture signing and
/// projection match production behavior.
pub(super) fn make_identity_chain(conn: &Connection, recorded_by: &str) -> (EventId, SigningKey) {
    let mut rng = rand::thread_rng();

    // 1. Local tenant root
    let tenant_eid = setup_tenant_event(conn, recorded_by);

    // 2. Workspace
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pub = workspace_key.verifying_key().to_bytes();
    let net_event = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_pub,
        name: "workspace".to_string(),
    });
    let net_eid = store_event_only(conn, recorded_by, &net_event).unwrap();

    // 3. InviteAccepted (local, binds trust anchor)
    let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        tenant_event_id: tenant_eid,
        invite_event_id: net_eid,
        workspace_id: net_eid,
    });
    create_event_synchronous(conn, recorded_by, &ia_event).unwrap();
    project_event(conn, recorded_by, &net_eid).unwrap();
    mark_valid_for_test(conn, recorded_by, &net_eid, net_event.event_type_code());

    // 4. UserInvite (signed by workspace key)
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pub = invite_key.verifying_key().to_bytes();
    let uib = UserInviteEvent {
        created_at_ms: now_ms(),
        public_key: invite_pub,
        workspace_id: net_eid,
        authority_event_id: net_eid,
        signed_by: net_eid,
        signer_type: 1,
        signature: [0u8; 64],
    };
    let uib_event = ParsedEvent::UserInvite(uib);
    let uib_eid =
        create_signed_event_synchronous(conn, recorded_by, &uib_event, &workspace_key).unwrap();

    // 5. User (signed by invite key)
    let user_key = SigningKey::generate(&mut rng);
    let user_pub = user_key.verifying_key().to_bytes();
    let ub = UserEvent {
        created_at_ms: now_ms(),
        public_key: user_pub,
        username: "user".to_string(),
        signed_by: uib_eid,
        signer_type: 2,
        signature: [0u8; 64],
    };
    let ub_event = ParsedEvent::User(ub);
    let ub_eid =
        create_signed_event_synchronous(conn, recorded_by, &ub_event, &invite_key).unwrap();

    // 6. DeviceInvite (signed by user key)
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pub = device_invite_key.verifying_key().to_bytes();
    let dif = DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_pub,
        authority_event_id: ub_eid,
        signed_by: ub_eid,
        signer_type: 4,
        signature: [0u8; 64],
    };
    let dif_event = ParsedEvent::DeviceInvite(dif);
    let dif_eid =
        create_signed_event_synchronous(conn, recorded_by, &dif_event, &user_key).unwrap();

    // 7. EndpointShared (self-signed, endpoint-scoped)
    let endpoint_key = SigningKey::generate(&mut rng);
    let endpoint_event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
        endpoint_key.to_bytes(),
    );
    let endpoint_id = hex::encode(endpoint_key.verifying_key().to_bytes());
    let endpoint_shared_event_id =
        create_event_synchronous(conn, &endpoint_id, &endpoint_event).unwrap();

    // 8. PeerShared (signed by device_invite key)
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared_pub = peer_shared_key.verifying_key().to_bytes();
    let psf = PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_pub,
        user_event_id: ub_eid,
        endpoint_shared_event_id,
        device_name: "device".to_string(),
        signed_by: dif_eid,
        signer_type: 3,
        signature: [0u8; 64],
    };
    let psf_event = ParsedEvent::PeerShared(psf);
    let psf_eid =
        create_signed_event_synchronous(conn, recorded_by, &psf_event, &device_invite_key).unwrap();

    register_signer_user(psf_eid, ub_eid);
    (psf_eid, peer_shared_key)
}

/// Build a full identity chain WITHOUT inserting or projecting.
/// Returns (signer_eid, signing_key, chain_blobs) where chain_blobs
/// are in dependency order (Network, InviteAccepted, UserInvite, etc.).
/// Caller must insert_event_raw + project_one each blob in order.
/// This stays synthetic because the deferred/order tests need exact raw blobs
/// before any create helper writes or retries projection.
pub(super) fn build_identity_chain_deferred(
    _recorded_by: &str,
) -> (EventId, SigningKey, Vec<(String, EventId, Vec<u8>)>) {
    let mut rng = rand::thread_rng();

    // 1. Local tenant root
    let peer_key = SigningKey::generate(&mut rng);
    let tenant_event = ParsedEvent::Tenant(TenantEvent {
        created_at_ms: now_ms(),
        public_key: peer_key.verifying_key().to_bytes(),
    });
    let tenant_blob = events::encode_event(&tenant_event).unwrap();
    let tenant_eid = hash_event(&tenant_blob);

    // 2. Workspace
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pub = workspace_key.verifying_key().to_bytes();
    let net_event = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_pub,
        name: "workspace".to_string(),
    });
    let net_blob = events::encode_event(&net_event).unwrap();
    let net_eid = hash_event(&net_blob);

    // 3. InviteAccepted
    let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        tenant_event_id: tenant_eid,
        invite_event_id: net_eid,
        workspace_id: net_eid,
    });
    let ia_blob = events::encode_event(&ia_event).unwrap();
    let ia_eid = hash_event(&ia_blob);

    // 4. UserInvite (signed by workspace key)
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pub = invite_key.verifying_key().to_bytes();
    let uib = UserInviteEvent {
        created_at_ms: now_ms(),
        public_key: invite_pub,
        workspace_id: net_eid,
        authority_event_id: net_eid,
        signed_by: net_eid,
        signer_type: 1,
        signature: [0u8; 64],
    };
    let uib_event = ParsedEvent::UserInvite(uib);
    let mut uib_blob = events::encode_event(&uib_event).unwrap();
    sign_blob(&workspace_key, &mut uib_blob);
    let uib_eid = hash_event(&uib_blob);

    // 5. User (signed by invite key)
    let user_key = SigningKey::generate(&mut rng);
    let user_pub = user_key.verifying_key().to_bytes();
    let ub = UserEvent {
        created_at_ms: now_ms(),
        public_key: user_pub,
        username: "user".to_string(),
        signed_by: uib_eid,
        signer_type: 2,
        signature: [0u8; 64],
    };
    let ub_event = ParsedEvent::User(ub);
    let mut ub_blob = events::encode_event(&ub_event).unwrap();
    sign_blob(&invite_key, &mut ub_blob);
    let ub_eid = hash_event(&ub_blob);

    // 6. DeviceInvite (signed by user key)
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pub = device_invite_key.verifying_key().to_bytes();
    let dif = DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_pub,
        authority_event_id: ub_eid,
        signed_by: ub_eid,
        signer_type: 4,
        signature: [0u8; 64],
    };
    let dif_event = ParsedEvent::DeviceInvite(dif);
    let mut dif_blob = events::encode_event(&dif_event).unwrap();
    sign_blob(&user_key, &mut dif_blob);
    let dif_eid = hash_event(&dif_blob);

    // 7. EndpointShared (self-signed, endpoint-scoped)
    let endpoint_key = SigningKey::generate(&mut rng);
    let endpoint_event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
        endpoint_key.to_bytes(),
    );
    let endpoint_blob = events::encode_event(&endpoint_event).unwrap();
    let endpoint_eid = hash_event(&endpoint_blob);
    let endpoint_recorded_by = hex::encode(endpoint_key.verifying_key().to_bytes());

    // 8. PeerShared (signed by device_invite key)
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared_pub = peer_shared_key.verifying_key().to_bytes();
    let psf = PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_pub,
        user_event_id: ub_eid,
        endpoint_shared_event_id: endpoint_eid,
        device_name: "device".to_string(),
        signed_by: dif_eid,
        signer_type: 3,
        signature: [0u8; 64],
    };
    let psf_event = ParsedEvent::PeerShared(psf);
    let mut psf_blob = events::encode_event(&psf_event).unwrap();
    sign_blob(&device_invite_key, &mut psf_blob);
    let psf_eid = hash_event(&psf_blob);

    register_signer_user(psf_eid, ub_eid);

    // Return blobs in dependency order.
    let chain_blobs = vec![
        (_recorded_by.to_string(), tenant_eid, tenant_blob),
        (_recorded_by.to_string(), ia_eid, ia_blob),
        (_recorded_by.to_string(), net_eid, net_blob),
        (_recorded_by.to_string(), uib_eid, uib_blob),
        (_recorded_by.to_string(), ub_eid, ub_blob),
        (_recorded_by.to_string(), dif_eid, dif_blob),
        (endpoint_recorded_by, endpoint_eid, endpoint_blob),
        (_recorded_by.to_string(), psf_eid, psf_blob),
    ];

    (psf_eid, peer_shared_key, chain_blobs)
}

/// Insert and project all events from a deferred identity chain.
pub(super) fn insert_and_project_identity_chain(
    conn: &Connection,
    _recorded_by: &str,
    chain_blobs: &[(String, EventId, Vec<u8>)],
) {
    for (recorded_by, eid, blob) in chain_blobs {
        insert_event_raw(conn, recorded_by, blob);
        project_one(conn, recorded_by, eid).unwrap();
    }
}

/// Helper: sign a blob in-place (overwrite last 64 bytes with Ed25519 signature).
pub(super) fn sign_blob(key: &SigningKey, blob: &mut Vec<u8>) {
    let len = blob.len();
    let sig = sign_event_bytes(key, &blob[..len - 64]);
    blob[len - 64..].copy_from_slice(&sig);
}

pub(super) fn ensure_test_endpoint_shared(conn: &Connection) -> EventId {
    let endpoint_key = SigningKey::generate(&mut rand::thread_rng());
    let endpoint_id = hex::encode(endpoint_key.verifying_key().to_bytes());
    let event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
        endpoint_key.to_bytes(),
    );
    create_event_synchronous(conn, &endpoint_id, &event).unwrap()
}

fn make_message_signed(
    signing_key: &SigningKey,
    signer_eid: &EventId,
    content: &str,
) -> (ParsedEvent, Vec<u8>) {
    let author_id = user_for_signer(signer_eid);
    let msg = MessageEvent {
        created_at_ms: now_ms(),
        workspace_id: [1u8; 32],
        author_id,
        content: content.to_string(),
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let event = ParsedEvent::Message(msg);
    let mut blob = events::encode_event(&event).unwrap();
    sign_blob(signing_key, &mut blob);
    let parsed = events::parse_event(&blob).unwrap();
    (parsed, blob)
}

/// Convenience: create identity chain + signed message in one call.
pub(super) fn make_message(
    conn: &Connection,
    recorded_by: &str,
    content: &str,
) -> (ParsedEvent, Vec<u8>) {
    let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
    make_message_signed(&signing_key, &signer_eid, content)
}

/// Create a signed reaction event blob.
pub(super) fn make_reaction_signed(
    signing_key: &SigningKey,
    signer_eid: &EventId,
    target: &EventId,
    emoji: &str,
) -> (ParsedEvent, Vec<u8>) {
    let author_id = user_for_signer(signer_eid);
    let rxn = ReactionEvent {
        created_at_ms: now_ms(),
        target_event_id: *target,
        author_id,
        emoji: emoji.to_string(),
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let event = ParsedEvent::Reaction(rxn);
    let mut blob = events::encode_event(&event).unwrap();
    sign_blob(signing_key, &mut blob);
    let parsed = events::parse_event(&blob).unwrap();
    (parsed, blob)
}

/// Convenience: create identity chain + signed reaction.
pub(super) fn make_reaction(
    conn: &Connection,
    recorded_by: &str,
    target: &EventId,
    emoji: &str,
) -> (ParsedEvent, Vec<u8>) {
    let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
    make_reaction_signed(&signing_key, &signer_eid, target, emoji)
}

/// Create a signed deletion event blob.
pub(super) fn make_deletion_signed(
    signing_key: &SigningKey,
    signer_eid: &EventId,
    target: &EventId,
    author_id: [u8; 32],
) -> (ParsedEvent, Vec<u8>) {
    let resolved_author_id = if author_id == [2u8; 32] {
        user_for_signer(signer_eid)
    } else {
        author_id
    };
    let del = MessageDeletionEvent {
        created_at_ms: now_ms(),
        target_event_id: *target,
        author_id: resolved_author_id,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let event = ParsedEvent::MessageDeletion(del);
    let mut blob = events::encode_event(&event).unwrap();
    sign_blob(signing_key, &mut blob);
    let parsed = events::parse_event(&blob).unwrap();
    (parsed, blob)
}

/// Create a signed attachment event blob.
pub(super) fn make_attachment_signed(
    signing_key: &SigningKey,
    signer_eid: &EventId,
    message_id: &EventId,
    key_event_id: &EventId,
) -> (ParsedEvent, Vec<u8>) {
    let att = FileEvent {
        created_at_ms: now_ms(),
        message_id: *message_id,
        file_id: rand::random(),
        blob_bytes: 204800,
        total_slices: 4,
        slice_bytes: 65536,
        root_hash: [12u8; 32],
        key_event_id: *key_event_id,
        filename: "photo.jpg".to_string(),
        mime_type: "image/jpeg".to_string(),
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let event = ParsedEvent::File(att);
    let mut blob = events::encode_event(&event).unwrap();
    sign_blob(signing_key, &mut blob);
    let parsed = events::parse_event(&blob).unwrap();
    (parsed, blob)
}

pub(super) fn setup() -> Connection {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    conn
}

// ===== Encrypted event helpers =====

pub(super) fn make_key_secret(key_bytes: [u8; 32]) -> (ParsedEvent, Vec<u8>) {
    let sk = ParsedEvent::KeySecret(KeySecretEvent {
        created_at_ms: now_ms(),
        key_bytes,
    });
    let blob = events::encode_event(&sk).unwrap();
    (sk, blob)
}

pub(super) fn make_encrypted_event(
    key_bytes: &[u8; 32],
    inner_blob: &[u8],
    inner_type_code: u8,
    key_event_id: &EventId,
) -> (ParsedEvent, Vec<u8>) {
    let (nonce, ciphertext, auth_tag) = encrypt_event_blob(key_bytes, inner_blob).unwrap();
    let enc = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: now_ms(),
        key_event_id: *key_event_id,
        inner_type_code,
        nonce,
        ciphertext,
        auth_tag,
    });
    let blob = events::encode_event(&enc).unwrap();
    (enc, blob)
}

// === File attachment helpers ===

pub(super) fn make_file_slice(
    signing_key: &SigningKey,
    signer_event_id: &EventId,
    file_id: [u8; 32],
    slice_number: u32,
    ciphertext_seed: &[u8],
) -> (ParsedEvent, Vec<u8>) {
    use crate::event_modules::file_slice::FILE_SLICE_CIPHERTEXT_BYTES;
    // Pad to canonical fixed size (short seeds are zero-extended)
    let mut ciphertext = vec![0u8; FILE_SLICE_CIPHERTEXT_BYTES];
    let len = ciphertext_seed.len().min(FILE_SLICE_CIPHERTEXT_BYTES);
    ciphertext[..len].copy_from_slice(&ciphertext_seed[..len]);
    let fs = FileSliceEvent {
        created_at_ms: now_ms(),
        file_id,
        slice_number,
        ciphertext,
        signed_by: *signer_event_id,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let event = ParsedEvent::FileSlice(fs);
    let mut blob = events::encode_event(&event).unwrap();
    sign_blob(signing_key, &mut blob);
    let parsed = events::parse_event(&blob).unwrap();
    (parsed, blob)
}

/// Convenience: create identity chain + signed attachment.
pub(super) fn make_file(
    conn: &Connection,
    recorded_by: &str,
    message_id: &EventId,
    key_event_id: &EventId,
) -> (ParsedEvent, Vec<u8>) {
    let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
    let att = FileEvent {
        created_at_ms: now_ms(),
        message_id: *message_id,
        file_id: [42u8; 32],
        blob_bytes: 1024,
        total_slices: 1,
        slice_bytes: 1024,
        root_hash: [0xABu8; 32],
        key_event_id: *key_event_id,
        filename: "test.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let event = ParsedEvent::File(att);
    let mut blob = events::encode_event(&event).unwrap();
    sign_blob(&signing_key, &mut blob);
    let parsed = events::parse_event(&blob).unwrap();
    (parsed, blob)
}

/// Helper: create a File descriptor with a specific file_id and signer,
/// along with its required deps (Message + KeySecret). Insert and project all of them.
/// Returns the attachment event_id.
pub(super) fn setup_descriptor_for_file(
    conn: &Connection,
    recorded_by: &str,
    signing_key: &SigningKey,
    signer_eid: &EventId,
    file_id: [u8; 32],
    file_key_event_id: &EventId,
) -> EventId {
    // Create message (dep for attachment)
    let (_msg, msg_blob) =
        make_message_signed(signing_key, signer_eid, "parent msg for descriptor");
    let msg_eid = insert_event_raw(conn, recorded_by, &msg_blob);
    project_one(conn, recorded_by, &msg_eid).unwrap();

    // Create File descriptor with the specific file_id
    let att = FileEvent {
        created_at_ms: now_ms(),
        message_id: msg_eid,
        file_id,
        blob_bytes: 204800,
        total_slices: 4,
        slice_bytes: 65536,
        root_hash: [12u8; 32],
        key_event_id: *file_key_event_id,
        filename: "test.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    };
    let event = ParsedEvent::File(att);
    let mut blob = events::encode_event(&event).unwrap();
    sign_blob(signing_key, &mut blob);
    let att_blob = blob;
    let att_eid = insert_event_raw(conn, recorded_by, &att_blob);
    let result = project_one(conn, recorded_by, &att_eid).unwrap();
    assert_eq!(
        result,
        ProjectionDecision::Valid,
        "descriptor should project Valid"
    );
    att_eid
}

pub(super) fn assert_projection_rejection_contains(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    expected_substring: &str,
) {
    let event_id = insert_event_raw(conn, recorded_by, blob);
    let result = project_one(conn, recorded_by, &event_id).unwrap();
    match result {
        ProjectionDecision::Reject { reason } => {
            assert!(
                reason.contains(expected_substring),
                "unexpected rejection reason: {}",
                reason
            );
        }
        other => panic!("expected Reject, got {:?}", other),
    }

    let event_id_b64 = event_id_to_base64(&event_id);
    let rej_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &event_id_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rej_count, 1, "rejected_events row must be recorded");
}
