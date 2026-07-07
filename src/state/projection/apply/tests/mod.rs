//! Pipeline-level integration tests for the projection apply engine. Each submodule
//! covers one concern area: `cascade` (Kahn unblock), `core_projection` (happy-path
//! projector dispatch), `dep_sync`, `deletion`, `encryption`, `file_slice`, `identity`,
//! `invite`, `removal_rotation`, `tenant`, and `verus_findings` (Verus-driven edge
//! cases). These run a real SQLite + real projectors, unlike unit tests in
//! `tests/projectors/` which stub the pipeline.

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
    KeyRequestEvent, KeyRotationEvent, KeySecretEvent, KeySharedEvent, MessageDeletionEvent,
    MessageEvent, ParsedEvent, PeerSecretEvent, ReactionEvent, WorkspaceEvent,
    EVENT_TYPE_ENCRYPTED, EVENT_TYPE_MESSAGE, EVENT_TYPE_REACTION,
};
use crate::projection::decision::ProjectionDecision;
use crate::projection::encrypted::encrypt_event_blob;
use crate::state::projection::create::{
    create_event, create_event_staged, create_signed_event, encode_signed_wrapper_blob,
    project_event, store_event_only,
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
mod dep_sync;
mod encryption;
mod file_slice;
mod identity;
mod invite;
mod removal_rotation;
mod tenant;
mod verus_findings;

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

fn test_content_key_blob() -> &'static Vec<u8> {
    static BLOB: OnceLock<Vec<u8>> = OnceLock::new();
    // Deterministic KeySecret blob for the fixed test key bytes. Encrypted
    // dep checks now require the wrapper `key_event_id` to resolve to a
    // KeySecret event (type 6), not a KeyRotation.
    BLOB.get_or_init(|| {
        let event = crate::event_modules::key_secret::deterministic_key_secret_event(
            test_content_key_bytes(),
        );
        events::encode_event(&event).unwrap()
    })
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
    events::parse_event(test_content_key_blob()).unwrap()
}

pub(super) fn test_content_key_event_id() -> EventId {
    hash_event(test_content_key_blob())
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

    let key_blob = test_content_key_blob();
    let ts = now_ms() as i64;
    insert_event(
        conn,
        &key_event_id,
        "key_secret",
        key_blob,
        crate::event_modules::ShareScope::Local,
        TEST_CONTENT_KEY_CREATED_AT_MS as i64,
        ts,
    )
    .unwrap();
    insert_recorded_event(conn, recorded_by, &key_event_id, ts, "test").unwrap();
    mark_valid_for_test(
        conn,
        recorded_by,
        &key_event_id,
        crate::event_modules::EVENT_TYPE_KEY_SECRET,
    );
    conn.execute(
        "INSERT OR IGNORE INTO key_secrets (event_id, key_bytes, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            &key_event_id_b64,
            test_content_key_bytes().to_vec(),
            TEST_CONTENT_KEY_CREATED_AT_MS as i64,
            recorded_by,
        ],
    )
    .unwrap();
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
    let parsed_event = events::parse_event(blob).ok();
    let created_at_ms = parsed_event
        .as_ref()
        .map(|event| event.created_at_ms())
        .unwrap_or_else(now_ms);
    let owner_event_id = parsed_event.as_ref().and_then(derived_outer_owner_event_id);
    let wrapper = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms,
        key_event_id,
        owner_event_id: owner_event_id
            .unwrap_or(crate::event_modules::encrypted::NO_OWNER_EVENT_ID),
        inner_type_code: type_code,
        nonce,
        ciphertext,
        auth_tag,
    });
    events::encode_event(&wrapper).unwrap()
}

fn ensure_test_wrapper_key_for_blob(conn: &Connection, recorded_by: &str, blob: &[u8]) {
    let encrypted = match events::parse_event(blob) {
        Ok(ParsedEvent::Encrypted(encrypted)) => Some(encrypted),
        Ok(ParsedEvent::Signed(signed)) => match events::parse_event(&signed.payload) {
            Ok(ParsedEvent::Encrypted(encrypted)) => Some(encrypted),
            _ => None,
        },
        _ => None,
    };
    let Some(encrypted) = encrypted else {
        return;
    };
    if encrypted.key_event_id == test_content_key_event_id() {
        let _ = ensure_test_content_key(conn, recorded_by);
    }
}

/// Create a synthetic-but-parseable Admin event for the signer's user
/// and make it visible to projection (events + valid_events + admins).
/// Returns the admin event id so removal fixtures can name it as
/// `admin_authority_event_id`.
pub(super) fn seed_admin_for_signer(
    conn: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
) -> EventId {
    use crate::event_modules::AdminEvent;
    let signer_b64 = event_id_to_base64(signer_eid);
    let (user_event_id_b64, public_key_vec): (String, Vec<u8>) = conn
        .query_row(
            "SELECT u.event_id, u.public_key
             FROM peers_shared ps
             JOIN users u
               ON u.recorded_by = ps.recorded_by
              AND u.event_id = ps.user_event_id
             WHERE ps.recorded_by = ?1
               AND ps.event_id = ?2",
            rusqlite::params![recorded_by, &signer_b64],
            |row| {
                Ok((
                    crate::db::sql_types::get_text(row, 0)?,
                    crate::db::sql_types::get_blob(row, 1)?,
                ))
            },
        )
        .unwrap();
    let user_event_id = event_id_from_base64(&user_event_id_b64).unwrap();
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&public_key_vec);

    let admin = ParsedEvent::Admin(AdminEvent {
        created_at_ms: now_ms(),
        public_key,
        authority_event_id: [0u8; 32],
        user_event_id,
    });
    let admin_blob = events::encode_event(&admin).unwrap();
    let admin_eid = hash_event(&admin_blob);
    let admin_eid_b64 = event_id_to_base64(&admin_eid);

    let _ = insert_event_raw(conn, recorded_by, &admin_blob);
    conn.execute(
        "INSERT OR IGNORE INTO valid_events (peer_id, event_id, semantic_type_code)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![
            recorded_by,
            &admin_eid_b64,
            i64::from(crate::event_modules::EVENT_TYPE_ADMIN)
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO admins (recorded_by, event_id, public_key)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, &admin_eid_b64, &public_key_vec],
    )
    .unwrap();
    admin_eid
}

pub(super) fn canonical_test_event_id(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
) -> EventId {
    hash_event(&wrap_test_content_blob(conn, recorded_by, blob))
}

/// Insert a blob into events + shared_event_index + recorded_events (simulating what
/// batch_writer or create_event does before calling project_one).
pub(super) fn insert_event_raw(conn: &Connection, recorded_by: &str, blob: &[u8]) -> EventId {
    let blob = wrap_test_content_blob(conn, recorded_by, blob);
    ensure_test_wrapper_key_for_blob(conn, recorded_by, &blob);
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
        &blob,
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
            |row| crate::db::sql_types::get_text(row, 0),
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
    create_event(conn, recorded_by, &tenant_event).unwrap()
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
    create_event(conn, recorded_by, &ia_event).unwrap();
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
        key_history_event_id: crate::event_modules::key_history::NO_KEY_HISTORY_EVENT_ID,
    };
    let uib_event = ParsedEvent::UserInvite(uib);
    let uib_eid =
        create_signed_event(conn, recorded_by, &net_eid, &uib_event, &workspace_key).unwrap();

    // 5. User (signed by invite key)
    let user_key = SigningKey::generate(&mut rng);
    let user_pub = user_key.verifying_key().to_bytes();
    let ub = UserEvent {
        created_at_ms: now_ms(),
        public_key: user_pub,
        username: "user".to_string(),
    };
    let ub_event = ParsedEvent::User(ub);
    let ub_eid = create_signed_event(conn, recorded_by, &uib_eid, &ub_event, &invite_key).unwrap();

    // 6. DeviceInvite (signed by user key)
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pub = device_invite_key.verifying_key().to_bytes();
    let dif = DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_pub,
        authority_event_id: ub_eid,
        key_history_event_id: crate::event_modules::key_history::NO_KEY_HISTORY_EVENT_ID,
    };
    let dif_event = ParsedEvent::DeviceInvite(dif);
    let dif_eid = create_signed_event(conn, recorded_by, &ub_eid, &dif_event, &user_key).unwrap();

    // 7. EndpointShared (self-signed, endpoint-scoped)
    let endpoint_key = SigningKey::generate(&mut rng);
    let endpoint_event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
        endpoint_key.to_bytes(),
    );
    let endpoint_id = hex::encode(endpoint_key.verifying_key().to_bytes());
    let endpoint_shared_event_id = create_event(conn, &endpoint_id, &endpoint_event).unwrap();

    // 8. PeerShared (signed by device_invite key)
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared_pub = peer_shared_key.verifying_key().to_bytes();
    let psf = PeerSharedEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_pub,
        user_event_id: ub_eid,
        endpoint_shared_event_id,
        device_name: "device".to_string(),
    };
    let psf_event = ParsedEvent::PeerShared(psf);
    let psf_eid =
        create_signed_event(conn, recorded_by, &dif_eid, &psf_event, &device_invite_key).unwrap();
    let peer_secret_event = ParsedEvent::PeerSecret(PeerSecretEvent {
        created_at_ms: now_ms(),
        signer_event_id: psf_eid,
        private_key_bytes: peer_shared_key.to_bytes(),
    });
    create_event(conn, recorded_by, &peer_secret_event).unwrap();

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
        key_history_event_id: crate::event_modules::key_history::NO_KEY_HISTORY_EVENT_ID,
    };
    let uib_event = ParsedEvent::UserInvite(uib);
    let uib_blob = sign_blob(&workspace_key, &net_eid, &uib_event);
    let uib_eid = hash_event(&uib_blob);

    // 5. User (signed by invite key)
    let user_key = SigningKey::generate(&mut rng);
    let user_pub = user_key.verifying_key().to_bytes();
    let ub = UserEvent {
        created_at_ms: now_ms(),
        public_key: user_pub,
        username: "user".to_string(),
    };
    let ub_event = ParsedEvent::User(ub);
    let ub_blob = sign_blob(&invite_key, &uib_eid, &ub_event);
    let ub_eid = hash_event(&ub_blob);

    // 6. DeviceInvite (signed by user key)
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pub = device_invite_key.verifying_key().to_bytes();
    let dif = DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_pub,
        authority_event_id: ub_eid,
        key_history_event_id: crate::event_modules::key_history::NO_KEY_HISTORY_EVENT_ID,
    };
    let dif_event = ParsedEvent::DeviceInvite(dif);
    let dif_blob = sign_blob(&user_key, &ub_eid, &dif_event);
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
    };
    let psf_event = ParsedEvent::PeerShared(psf);
    let psf_blob = sign_blob(&device_invite_key, &dif_eid, &psf_event);
    let psf_eid = hash_event(&psf_blob);
    let peer_secret_event = ParsedEvent::PeerSecret(PeerSecretEvent {
        created_at_ms: now_ms(),
        signer_event_id: psf_eid,
        private_key_bytes: peer_shared_key.to_bytes(),
    });
    let peer_secret_blob = events::encode_event(&peer_secret_event).unwrap();

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
        (
            _recorded_by.to_string(),
            hash_event(&peer_secret_blob),
            peer_secret_blob,
        ),
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

/// Helper: wrap a parsed event in a Signed envelope and sign the outer blob.
pub(super) fn sign_blob(
    signing_key: &SigningKey,
    signer_event_id: &EventId,
    event: &ParsedEvent,
) -> Vec<u8> {
    encode_signed_wrapper_blob(event, signer_event_id, signing_key).unwrap()
}

pub(super) fn ensure_test_endpoint_shared(conn: &Connection) -> EventId {
    let endpoint_key = SigningKey::generate(&mut rand::thread_rng());
    let endpoint_id = hex::encode(endpoint_key.verifying_key().to_bytes());
    let event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
        endpoint_key.to_bytes(),
    );
    create_event(conn, &endpoint_id, &event).unwrap()
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
    };
    let event = ParsedEvent::Message(msg);
    let blob = make_signed_encrypted_blob(signing_key, signer_eid, &event);
    (event, blob)
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
    };
    let event = ParsedEvent::Reaction(rxn);
    let blob = make_signed_encrypted_blob(signing_key, signer_eid, &event);
    (event, blob)
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
) -> (ParsedEvent, Vec<u8>) {
    let del = MessageDeletionEvent {
        created_at_ms: now_ms(),
        target_event_id: *target,
    };
    let event = ParsedEvent::MessageDeletion(del);
    let blob = make_signed_encrypted_blob(signing_key, signer_eid, &event);
    (event, blob)
}

/// Create a signed attachment event blob.
pub(super) fn make_attachment_signed(
    signing_key: &SigningKey,
    signer_eid: &EventId,
    message_id: &EventId,
    key_event_id: &EventId,
) -> (ParsedEvent, Vec<u8>) {
    let file_id: [u8; 32] = rand::random();
    let blob_bytes = 204800u64;
    let slice_bytes = 65536u32;
    let att = FileEvent {
        created_at_ms: now_ms(),
        message_id: *message_id,
        file_id,
        blob_bytes,
        total_slices: total_slices_for(blob_bytes, slice_bytes),
        slice_bytes,
        root_hash: deterministic_file_root_hash(file_id, blob_bytes),
        key_event_id: *key_event_id,
        filename: "photo.jpg".to_string(),
        mime_type: "image/jpeg".to_string(),
    };
    let event = ParsedEvent::File(att);
    let blob = make_signed_encrypted_blob(signing_key, signer_eid, &event);
    (event, blob)
}

pub(super) fn setup() -> Connection {
    signer_user_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
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

/// Deterministic KeySecret blob (stable event_id per `key_bytes`). Use when
/// tests need to reference the KeySecret event_id before inserting the blob
/// (e.g. cascade tests that insert and project in staged order).
pub(super) fn make_deterministic_key_secret_blob(key_bytes: [u8; 32]) -> (EventId, Vec<u8>) {
    let event = crate::event_modules::key_secret::deterministic_key_secret_event(key_bytes);
    let blob = events::encode_event(&event).unwrap();
    let eid = crate::event_modules::key_secret::deterministic_key_secret_event_id(&key_bytes);
    (eid, blob)
}

pub(super) fn make_self_key_rotation_blob(
    conn: &Connection,
    signer_event_id: &EventId,
    signing_key: &SigningKey,
    key_bytes: [u8; 32],
) -> (ParsedEvent, Vec<u8>) {
    let _ = conn;
    let mut recipient_slots = vec![[0u8; 32]; crate::event_modules::key_rotation::KEY_ROTATION_CAP];
    let mut wrapped_keys = vec![[0u8; 32]; crate::event_modules::key_rotation::KEY_ROTATION_CAP];
    recipient_slots[0] = *signer_event_id;
    wrapped_keys[0] = crate::projection::encrypted::wrap_key_for_recipient(
        signing_key,
        &signing_key.verifying_key(),
        &key_bytes,
    );
    let event = ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms: now_ms(),
        frontier_count: 0,
        frontier_ref_1: [0u8; 32],
        frontier_ref_2: [0u8; 32],
        frontier_ref_3: [0u8; 32],
        frontier_ref_4: [0u8; 32],
        frontier_hash: crate::event_modules::removal::frontier_hash_from_refs(&[]),
        rotated_by: *signer_event_id,
        recipient_slots,
        wrapped_keys,
    });
    let blob = encode_signed_wrapper_blob(&event, signer_event_id, signing_key).unwrap();
    (event, blob)
}

pub(super) fn insert_and_project_self_key_rotation(
    conn: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    signing_key: &SigningKey,
    key_bytes: [u8; 32],
) -> EventId {
    let (_event, blob) = make_self_key_rotation_blob(conn, signer_event_id, signing_key, key_bytes);
    let rotation_event_id = insert_event_raw(conn, recorded_by, &blob);
    let decision = project_one(conn, recorded_by, &rotation_event_id).unwrap();
    assert_eq!(decision, ProjectionDecision::Valid);
    // Post-migration: encrypted events depend on a KeySecret (type 6), not a
    // KeyRotation. Emit and project the deterministic KeySecret whose event_id
    // callers use as the wrapper `key_event_id`.
    let sk_blob = events::encode_event(
        &crate::event_modules::key_secret::deterministic_key_secret_event(key_bytes),
    )
    .unwrap();
    let key_secret_event_id =
        crate::event_modules::key_secret::deterministic_key_secret_event_id(&key_bytes);
    sk_evt_from_blob(conn, recorded_by, &sk_blob, &key_secret_event_id)
}

fn sk_evt_from_blob(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    expected_eid: &EventId,
) -> EventId {
    use rusqlite::OptionalExtension;
    let eid_b64 = event_id_to_base64(expected_eid);
    let already: Option<String> = conn
        .query_row(
            "SELECT event_id FROM events WHERE event_id = ?1",
            rusqlite::params![&eid_b64],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .optional()
        .unwrap();
    if already.is_some() {
        let _ = project_one(conn, recorded_by, expected_eid).unwrap();
        return *expected_eid;
    }
    let event_id = insert_event_raw(conn, recorded_by, blob);
    assert_eq!(event_id, *expected_eid);
    let decision = project_one(conn, recorded_by, &event_id).unwrap();
    assert_eq!(decision, ProjectionDecision::Valid);
    event_id
}

pub(super) fn make_key_rotation_blob_for_recipient(
    signer_event_id: &EventId,
    signing_key: &SigningKey,
    recipient_event_id: &EventId,
) -> (ParsedEvent, Vec<u8>) {
    let mut recipient_slots = vec![[0u8; 32]; crate::event_modules::key_rotation::KEY_ROTATION_CAP];
    let mut wrapped_keys = vec![[0u8; 32]; crate::event_modules::key_rotation::KEY_ROTATION_CAP];
    recipient_slots[0] = *recipient_event_id;
    wrapped_keys[0] = [0xAB; 32];
    let event = ParsedEvent::KeyRotation(KeyRotationEvent {
        created_at_ms: now_ms(),
        frontier_count: 0,
        frontier_ref_1: [0u8; 32],
        frontier_ref_2: [0u8; 32],
        frontier_ref_3: [0u8; 32],
        frontier_ref_4: [0u8; 32],
        frontier_hash: crate::event_modules::removal::frontier_hash_from_refs(&[]),
        rotated_by: *signer_event_id,
        recipient_slots,
        wrapped_keys,
    });
    let blob = encode_signed_wrapper_blob(&event, signer_event_id, signing_key).unwrap();
    (event, blob)
}

pub(super) fn insert_and_project_key_rotation_for_recipient(
    conn: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    signing_key: &SigningKey,
    recipient_event_id: &EventId,
) -> EventId {
    let (_event, blob) =
        make_key_rotation_blob_for_recipient(signer_event_id, signing_key, recipient_event_id);
    let event_id = insert_event_raw(conn, recorded_by, &blob);
    let decision = project_one(conn, recorded_by, &event_id).unwrap();
    assert_eq!(decision, ProjectionDecision::Valid);
    event_id
}

pub(super) fn make_encrypted_event(
    key_bytes: &[u8; 32],
    inner_blob: &[u8],
    inner_type_code: u8,
    key_event_id: &EventId,
) -> (ParsedEvent, Vec<u8>) {
    make_encrypted_event_with_owner(key_bytes, inner_blob, inner_type_code, key_event_id, None)
}

pub(super) fn make_encrypted_event_with_owner(
    key_bytes: &[u8; 32],
    inner_blob: &[u8],
    inner_type_code: u8,
    key_event_id: &EventId,
    owner_event_id: Option<&EventId>,
) -> (ParsedEvent, Vec<u8>) {
    let (nonce, ciphertext, auth_tag) = encrypt_event_blob(key_bytes, inner_blob).unwrap();
    let enc = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: now_ms(),
        key_event_id: *key_event_id,
        owner_event_id: owner_event_id
            .copied()
            .unwrap_or(crate::event_modules::encrypted::NO_OWNER_EVENT_ID),
        inner_type_code,
        nonce,
        ciphertext,
        auth_tag,
    });
    let blob = events::encode_event(&enc).unwrap();
    (enc, blob)
}

fn derived_outer_owner_event_id(inner_event: &ParsedEvent) -> Option<EventId> {
    match inner_event {
        ParsedEvent::Reaction(rxn) => Some(rxn.target_event_id),
        ParsedEvent::File(file) => Some(file.message_id),
        _ => None,
    }
}

fn make_signed_encrypted_blob(
    signing_key: &SigningKey,
    signer_event_id: &EventId,
    inner_event: &ParsedEvent,
) -> Vec<u8> {
    let inner_blob = events::encode_event(inner_event).unwrap();
    let owner_event_id = derived_outer_owner_event_id(inner_event);
    let (_enc, enc_blob) = make_encrypted_event_with_owner(
        &test_content_key_bytes(),
        &inner_blob,
        inner_event.event_type_code(),
        &test_content_key_event_id(),
        owner_event_id.as_ref(),
    );
    let enc_event = events::parse_event(&enc_blob).unwrap();
    encode_signed_wrapper_blob(&enc_event, signer_event_id, signing_key).unwrap()
}

pub(super) fn make_signed_encrypted_blob_with_key(
    signing_key: &SigningKey,
    signer_event_id: &EventId,
    inner_event: &ParsedEvent,
    key_bytes: &[u8; 32],
    key_event_id: &EventId,
) -> Vec<u8> {
    let inner_blob = events::encode_event(inner_event).unwrap();
    let owner_event_id = derived_outer_owner_event_id(inner_event);
    let (_enc, enc_blob) = make_encrypted_event_with_owner(
        key_bytes,
        &inner_blob,
        inner_event.event_type_code(),
        key_event_id,
        owner_event_id.as_ref(),
    );
    let enc_event = events::parse_event(&enc_blob).unwrap();
    encode_signed_wrapper_blob(&enc_event, signer_event_id, signing_key).unwrap()
}

// === File attachment helpers ===

fn total_slices_for(blob_bytes: u64, slice_bytes: u32) -> u32 {
    blob_bytes.div_ceil(slice_bytes as u64) as u32
}

fn deterministic_file_plaintext(file_id: [u8; 32], blob_bytes: u64) -> Vec<u8> {
    (0..blob_bytes as usize)
        .map(|i| (i as u8).wrapping_add(file_id[i % file_id.len()]))
        .collect()
}

pub(super) fn deterministic_file_root_hash(file_id: [u8; 32], blob_bytes: u64) -> [u8; 32] {
    let plaintext = deterministic_file_plaintext(file_id, blob_bytes);
    let (root_hash, _outboard) = crate::crypto::bao_verify::compute_outboard(&plaintext)
        .expect("deterministic test file root hash should compute");
    root_hash
}

pub(super) fn make_valid_file_slice_ciphertext(
    file_id: [u8; 32],
    slice_number: u32,
    blob_bytes: u64,
    slice_bytes: u32,
) -> Vec<u8> {
    let plaintext = deterministic_file_plaintext(file_id, blob_bytes);
    let (_root_hash, outboard) = crate::crypto::bao_verify::compute_outboard(&plaintext)
        .expect("deterministic test file outboard should compute");
    let slice_start = slice_number as u64 * slice_bytes as u64;
    let slice_len = blob_bytes
        .saturating_sub(slice_start)
        .min(slice_bytes as u64);
    let proof = crate::crypto::bao_verify::extract_slice_proof(
        &plaintext,
        &outboard,
        slice_start,
        slice_len,
    )
    .expect("deterministic test file slice proof should extract");
    crate::event_modules::file_slice::wire::pack_bao_payload(&proof, &plaintext)
        .expect("deterministic test file slice payload should fit")
}

pub(super) fn make_file_slice(
    signing_key: &SigningKey,
    signer_event_id: &EventId,
    file_id: [u8; 32],
    slice_number: u32,
    _ciphertext_seed: &[u8],
) -> (ParsedEvent, Vec<u8>) {
    let ciphertext = make_valid_file_slice_ciphertext(file_id, slice_number, 204800, 65536);
    let fs = FileSliceEvent {
        created_at_ms: now_ms(),
        file_id,
        slice_number,
        ciphertext,
    };
    let event = ParsedEvent::FileSlice(fs);
    let blob = make_signed_encrypted_blob(signing_key, signer_event_id, &event);
    (event, blob)
}

pub(super) fn make_file_slice_with_owner(
    signing_key: &SigningKey,
    signer_event_id: &EventId,
    owner_event_id: &EventId,
    file_id: [u8; 32],
    slice_number: u32,
    _ciphertext_seed: &[u8],
) -> (ParsedEvent, Vec<u8>) {
    let ciphertext = make_valid_file_slice_ciphertext(file_id, slice_number, 204800, 65536);
    let event = ParsedEvent::FileSlice(FileSliceEvent {
        created_at_ms: now_ms(),
        file_id,
        slice_number,
        ciphertext,
    });
    let inner_blob = events::encode_event(&event).unwrap();
    let (_enc, enc_blob) = make_encrypted_event_with_owner(
        &test_content_key_bytes(),
        &inner_blob,
        event.event_type_code(),
        &test_content_key_event_id(),
        Some(owner_event_id),
    );
    let enc_event = events::parse_event(&enc_blob).unwrap();
    let blob = encode_signed_wrapper_blob(&enc_event, signer_event_id, signing_key).unwrap();
    (event, blob)
}

/// Convenience: create identity chain + signed attachment.
pub(super) fn make_file(
    conn: &Connection,
    recorded_by: &str,
    message_id: &EventId,
    key_event_id: &EventId,
) -> (ParsedEvent, Vec<u8>) {
    let (signer_eid, signing_key) = make_identity_chain(conn, recorded_by);
    let file_id = [42u8; 32];
    let blob_bytes = 1024u64;
    let slice_bytes = 1024u32;
    let att = FileEvent {
        created_at_ms: now_ms(),
        message_id: *message_id,
        file_id,
        blob_bytes,
        total_slices: total_slices_for(blob_bytes, slice_bytes),
        slice_bytes,
        root_hash: deterministic_file_root_hash(file_id, blob_bytes),
        key_event_id: *key_event_id,
        filename: "test.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
    };
    let event = ParsedEvent::File(att);
    let blob = make_signed_encrypted_blob(&signing_key, &signer_eid, &event);
    (event, blob)
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
    let blob_bytes = 204800u64;
    let slice_bytes = 65536u32;
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
        blob_bytes,
        total_slices: total_slices_for(blob_bytes, slice_bytes),
        slice_bytes,
        root_hash: deterministic_file_root_hash(file_id, blob_bytes),
        key_event_id: *file_key_event_id,
        filename: "test.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
    };
    let event = ParsedEvent::File(att);
    let blob = make_signed_encrypted_blob(signing_key, signer_eid, &event);
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
