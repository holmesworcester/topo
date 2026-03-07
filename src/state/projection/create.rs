use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use super::apply::project_one;
use super::decision::ProjectionDecision;
use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::store::{
    insert_event, insert_neg_item_if_shared, insert_recorded_event, lookup_workspace_id,
};
use crate::event_modules::EncryptedEvent;
use crate::event_modules::{self as events, registry, ParsedEvent};
use crate::projection::encrypted::encrypt_event_blob;
use crate::projection::signer::sign_event_bytes;
use crate::state::shared_workspace_fanout::fanout_stored_shared_event_immediate;
use ed25519_dalek::SigningKey;

#[derive(Debug)]
pub enum CreateEventError {
    EncodeError(String),
    DbError(String),
    Blocked {
        event_id: EventId,
        missing: Vec<[u8; 32]>,
    },
    Rejected {
        event_id: EventId,
        reason: String,
    },
}

impl std::fmt::Display for CreateEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreateEventError::EncodeError(e) => write!(f, "encode error: {}", e),
            CreateEventError::DbError(e) => write!(f, "db error: {}", e),
            CreateEventError::Blocked { event_id, missing } => {
                write!(
                    f,
                    "event {} blocked on {} deps",
                    event_id_to_base64(event_id),
                    missing.len()
                )
            }
            CreateEventError::Rejected { event_id, reason } => {
                write!(
                    f,
                    "event {} rejected: {}",
                    event_id_to_base64(event_id),
                    reason
                )
            }
        }
    }
}

impl std::error::Error for CreateEventError {}

/// Extract event_id from Ok or Blocked (event is stored in both cases).
/// Returns Err only for true failures (encode, db, rejected).
///
/// Used by accept flows where chain events may block on prereqs that arrive
/// later via sync. The events are stored and will project when deps are met.
pub fn event_id_or_blocked(
    result: Result<EventId, CreateEventError>,
) -> Result<EventId, CreateEventError> {
    match result {
        Ok(eid) => Ok(eid),
        Err(CreateEventError::Blocked { event_id, .. }) => Ok(event_id),
        Err(e) => Err(e),
    }
}

/// Shared helper: hash blob, write to events/neg_items/recorded_events (no projection).
/// Returns the event_id. Callers must invoke `project_stored_event` to trigger projection.
fn store_blob_only(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    meta: &events::EventTypeMeta,
    created_at_ms: i64,
) -> Result<EventId, CreateEventError> {
    let event_id = hash_event(blob);

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    insert_event(
        conn,
        &event_id,
        meta.type_name,
        blob,
        meta.share_scope,
        created_at_ms,
        now_ms,
    )
    .map_err(|e| CreateEventError::DbError(e.to_string()))?;

    let ws_id_for_neg = if meta.type_name == "workspace" {
        Some(crate::crypto::event_id_to_base64(&event_id))
    } else {
        lookup_workspace_id(conn, recorded_by)
    };

    if let Some(ws_id) = ws_id_for_neg {
        insert_neg_item_if_shared(conn, meta.share_scope, created_at_ms, &event_id, &ws_id)
            .map_err(|e| CreateEventError::DbError(e.to_string()))?;
    } else if meta.share_scope == crate::event_modules::registry::ShareScope::Shared {
        tracing::warn!(
            "no accepted workspace binding for {}, shared event {} missing from neg_items",
            recorded_by,
            crate::crypto::event_id_to_base64(&event_id)
        );
    }

    insert_recorded_event(conn, recorded_by, &event_id, now_ms, "local_create")
        .map_err(|e| CreateEventError::DbError(e.to_string()))?;

    Ok(event_id)
}

/// Project a stored event and return the result.
fn project_stored_event(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<EventId, CreateEventError> {
    let decision = project_one(conn, recorded_by, event_id)
        .map_err(|e| CreateEventError::DbError(e.to_string()))?;

    match decision {
        ProjectionDecision::Valid | ProjectionDecision::AlreadyProcessed => {
            fanout_stored_shared_event_immediate(conn, recorded_by, event_id)
                .map_err(|e| CreateEventError::DbError(e.to_string()))?;
            Ok(*event_id)
        }
        ProjectionDecision::Block { missing } => Err(CreateEventError::Blocked {
            event_id: *event_id,
            missing,
        }),
        ProjectionDecision::Reject { reason } => Err(CreateEventError::Rejected {
            event_id: *event_id,
            reason,
        }),
    }
}

/// Shared helper: hash blob, write to events/neg_items/recorded_events, project via project_one.
fn store_blob_and_project(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    meta: &events::EventTypeMeta,
    created_at_ms: i64,
) -> Result<EventId, CreateEventError> {
    let event_id = store_blob_only(conn, recorded_by, blob, meta, created_at_ms)?;
    project_stored_event(conn, recorded_by, &event_id)
}

/// Create a new event: encode, hash, write to events/neg_items/recorded_events,
/// then project via `project_one`. Returns the event_id on success.
pub fn create_event_synchronous(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
) -> Result<EventId, CreateEventError> {
    let blob =
        events::encode_event(event).map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    let type_code = event.event_type_code();
    let reg = registry();
    let meta = reg
        .lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    let created_at_ms = event.created_at_ms() as i64;
    store_blob_and_project(conn, recorded_by, &blob, meta, created_at_ms)
}

/// Create a signed event: encode with zero-placeholder signature, sign the
/// canonical bytes, overwrite signature, then store and project.
pub fn create_signed_event_synchronous(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<EventId, CreateEventError> {
    let mut blob =
        events::encode_event(event).map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    let type_code = event.event_type_code();
    let reg = registry();
    let meta = reg
        .lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    if meta.signature_byte_len == 0 {
        return Err(CreateEventError::EncodeError(
            "create_signed_event_synchronous called for unsigned type".to_string(),
        ));
    }

    let sig_len = meta.signature_byte_len;
    let blob_len = blob.len();
    let signing_bytes = &blob[..blob_len - sig_len];
    let sig = sign_event_bytes(signing_key, signing_bytes);
    blob[blob_len - sig_len..].copy_from_slice(&sig);

    let created_at_ms = event.created_at_ms() as i64;
    store_blob_and_project(conn, recorded_by, &blob, meta, created_at_ms)
}

/// Store a signed event without projecting. Returns the event_id.
/// The caller must call `project_event` after writing any required context.
/// Used when projection depends on context that must be written after
/// the event_id is known (e.g., bootstrap_context for invite trust).
pub fn store_signed_event_only(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<EventId, CreateEventError> {
    let mut blob =
        events::encode_event(event).map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    let type_code = event.event_type_code();
    let reg = registry();
    let meta = reg
        .lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    if meta.signature_byte_len == 0 {
        return Err(CreateEventError::EncodeError(
            "store_signed_event_only called for unsigned type".to_string(),
        ));
    }

    let sig_len = meta.signature_byte_len;
    let blob_len = blob.len();
    let signing_bytes = &blob[..blob_len - sig_len];
    let sig = sign_event_bytes(signing_key, signing_bytes);
    blob[blob_len - sig_len..].copy_from_slice(&sig);

    let created_at_ms = event.created_at_ms() as i64;
    store_blob_only(conn, recorded_by, &blob, meta, created_at_ms)
}

/// Store an unsigned event without projecting. Returns the event_id.
/// The caller must call `project_event` after writing any required context.
pub fn store_event_only(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
) -> Result<EventId, CreateEventError> {
    let blob =
        events::encode_event(event).map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    let type_code = event.event_type_code();
    let reg = registry();
    let meta = reg
        .lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    let created_at_ms = event.created_at_ms() as i64;
    store_blob_only(conn, recorded_by, &blob, meta, created_at_ms)
}

/// Project a previously-stored event. Returns event_id on Valid/AlreadyProcessed,
/// or CreateEventError on Block/Reject.
pub fn project_event(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<EventId, CreateEventError> {
    project_stored_event(conn, recorded_by, event_id)
}

/// Project a previously-stored event, tolerating Block results (staged flow).
/// Returns event_id on Valid, AlreadyProcessed, or Block.
pub fn project_event_staged(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<EventId, CreateEventError> {
    event_id_or_blocked(project_stored_event(conn, recorded_by, event_id))
}

/// Create an encrypted event: encode inner event, optionally sign it,
/// resolve encryption key from key_secrets, encrypt, build EncryptedEvent
/// wrapper, then store and project.
///
/// If `signing_key` is provided, the inner blob is signed before encryption
/// (signature is inside the ciphertext — signer identity hidden from non-recipients).
pub fn create_encrypted_event_synchronous(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
    inner_event: &ParsedEvent,
    signing_key: Option<&SigningKey>,
) -> Result<EventId, CreateEventError> {
    // 1. Encode inner event
    let mut inner_blob = events::encode_event(inner_event)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    // 2. Sign inner blob if signing_key provided
    if let Some(key) = signing_key {
        let meta = events::registry()
            .lookup(inner_event.event_type_code())
            .ok_or_else(|| CreateEventError::EncodeError("unknown event type".to_string()))?;
        let sig_len = meta.signature_byte_len;
        if sig_len > 0 {
            let blob_len = inner_blob.len();
            let sig = sign_event_bytes(key, &inner_blob[..blob_len - sig_len]);
            inner_blob[blob_len - sig_len..].copy_from_slice(&sig);
        }
    }

    // 3. Resolve encryption key from key_secrets table
    let key_b64 = event_id_to_base64(key_event_id);
    let key_bytes: Vec<u8> = conn
        .query_row(
            "SELECT key_bytes FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &key_b64],
            |row| row.get(0),
        )
        .map_err(|e| CreateEventError::DbError(format!("key lookup: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(CreateEventError::EncodeError(format!(
            "secret key wrong length: {}",
            key_bytes.len()
        )));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    // 4. Encrypt
    let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key_arr, &inner_blob)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    // 5. Build EncryptedEvent wrapper
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let wrapper = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: now_ms,
        key_event_id: *key_event_id,
        inner_type_code: inner_event.event_type_code(),
        nonce,
        ciphertext,
        auth_tag,
    });

    // 6. Use existing create_event_synchronous for the wrapper
    create_event_synchronous(conn, recorded_by, &wrapper)
}

/// Staged create: persist and enqueue an event even if it is Blocked.
/// Returns the event_id on both Valid and Blocked outcomes.
/// Use this only for pre-accepted-binding events in bootstrap flows where blocking
/// is expected and will resolve via guard cascade after invite_accepted projects.
pub fn create_event_staged(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
) -> Result<EventId, CreateEventError> {
    event_id_or_blocked(create_event_synchronous(conn, recorded_by, event))
}

/// Staged signed create: persist and enqueue a signed event even if it is Blocked.
/// Returns the event_id on both Valid and Blocked outcomes.
/// Use this only for pre-accepted-binding events in bootstrap flows where blocking
/// is expected and will resolve via guard cascade after invite_accepted projects.
pub fn create_signed_event_staged(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<EventId, CreateEventError> {
    event_id_or_blocked(create_signed_event_synchronous(
        conn,
        recorded_by,
        event,
        signing_key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::{
        DeviceInviteEvent, InviteAcceptedEvent, MessageEvent, PeerSharedEvent, ReactionEvent,
        TenantEvent, UserEvent, UserInviteEvent, WorkspaceEvent,
    };
    use crate::testutil::SharedDbNode;
    use ed25519_dalek::SigningKey;

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn setup_workspace_event(conn: &Connection, recorded_by: &str) -> EventId {
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: [0xAA; 32],
            name: "test-workspace".to_string(),
        });
        create_event_staged(conn, recorded_by, &ws).unwrap()
    }

    /// Create a minimal identity chain for the given tenant.
    /// Returns (peer_shared_event_id, peer_shared_signing_key).
    fn make_identity_chain(conn: &Connection, recorded_by: &str) -> (EventId, SigningKey, EventId) {
        let mut rng = rand::thread_rng();

        let peer_key = SigningKey::generate(&mut rng);
        let tenant_evt = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: now_ms(),
            public_key: peer_key.verifying_key().to_bytes(),
        });
        let tenant_eid = create_event_synchronous(conn, recorded_by, &tenant_evt).unwrap();

        let workspace_key = SigningKey::generate(&mut rng);
        let workspace_pub = workspace_key.verifying_key().to_bytes();
        let net_event = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: workspace_pub,
            name: "test-workspace".to_string(),
        });
        // Workspace may block (needs accepted-workspace binding). Use staged API.
        let net_eid = create_event_staged(conn, recorded_by, &net_event).unwrap();

        let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: now_ms(),
            tenant_event_id: tenant_eid,
            invite_event_id: net_eid,
            workspace_id: net_eid,
        });
        let _ia_eid = create_event_synchronous(conn, recorded_by, &ia_event).unwrap();

        // Re-project workspace now that accepted-workspace binding exists
        project_one(conn, recorded_by, &net_eid).unwrap();

        let invite_key = SigningKey::generate(&mut rng);
        let uib = ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: now_ms(),
            public_key: invite_key.verifying_key().to_bytes(),
            workspace_id: net_eid,
            authority_event_id: net_eid,
            signed_by: net_eid,
            signer_type: 1,
            signature: [0u8; 64],
        });
        let uib_eid =
            create_signed_event_synchronous(conn, recorded_by, &uib, &workspace_key).unwrap();

        let user_key = SigningKey::generate(&mut rng);
        let ub = ParsedEvent::User(UserEvent {
            created_at_ms: now_ms(),
            public_key: user_key.verifying_key().to_bytes(),
            username: "test-user".to_string(),
            signed_by: uib_eid,
            signer_type: 2,
            signature: [0u8; 64],
        });
        let ub_eid = create_signed_event_synchronous(conn, recorded_by, &ub, &invite_key).unwrap();

        let device_invite_key = SigningKey::generate(&mut rng);
        let dif = ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: now_ms(),
            public_key: device_invite_key.verifying_key().to_bytes(),
            authority_event_id: ub_eid,
            signed_by: ub_eid,
            signer_type: 4,
            signature: [0u8; 64],
        });
        let dif_eid = create_signed_event_synchronous(conn, recorded_by, &dif, &user_key).unwrap();

        let peer_shared_key = SigningKey::generate(&mut rng);
        let psf = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: now_ms(),
            public_key: peer_shared_key.verifying_key().to_bytes(),
            user_event_id: ub_eid,
            device_name: "test-device".to_string(),
            signed_by: dif_eid,
            signer_type: 3,
            signature: [0u8; 64],
        });
        let psf_eid =
            create_signed_event_synchronous(conn, recorded_by, &psf, &device_invite_key).unwrap();

        (psf_eid, peer_shared_key, ub_eid)
    }

    #[test]
    fn test_create_message_synchronous() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: net_eid,
            author_id: user_event_id,
            content: "hello".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });

        let eid = create_signed_event_synchronous(&conn, recorded_by, &msg, &signing_key).unwrap();
        let eid_b64 = event_id_to_base64(&eid);

        // events table
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // messages table
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
                rusqlite::params![&eid_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // valid_events
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_create_reaction_chain() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: net_eid,
            author_id: user_event_id,
            content: "target".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        let msg_eid =
            create_signed_event_synchronous(&conn, recorded_by, &msg, &signing_key).unwrap();

        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: msg_eid,
            author_id: user_event_id,
            emoji: "\u{1f44d}".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        let rxn_eid =
            create_signed_event_synchronous(&conn, recorded_by, &rxn, &signing_key).unwrap();

        // Both valid
        let msg_b64 = event_id_to_base64(&msg_eid);
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        for b64 in [&msg_b64, &rxn_b64] {
            let valid: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                    rusqlite::params![recorded_by, b64],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(valid);
        }
    }

    #[test]
    fn test_create_reaction_before_target() {
        let conn = setup();
        let recorded_by = "peer1";

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);

        let fake_target = [99u8; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: user_event_id,
            emoji: "\u{1f44d}".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });

        // Event is stored but blocked — returns Blocked error with event_id
        let err =
            create_signed_event_synchronous(&conn, recorded_by, &rxn, &signing_key).unwrap_err();
        let (eid, missing) = match err {
            CreateEventError::Blocked { event_id, missing } => (event_id, missing),
            other => panic!("expected Blocked, got: {}", other),
        };
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], fake_target);
        let eid_b64 = event_id_to_base64(&eid);

        // Should be in events table but NOT in valid_events
        let in_events: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(in_events);

        let in_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!in_valid);

        // Should be in blocked_event_deps
        let blocked: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(blocked, 1);
    }

    #[test]
    fn test_create_signed_event_synchronous() {
        let conn = setup();
        let recorded_by = "peer1";

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);

        // Create signed message with PeerShared signer
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: [1u8; 32],
            author_id: user_event_id,
            content: "signed content".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64], // placeholder, will be overwritten
        });

        let msg_eid =
            create_signed_event_synchronous(&conn, recorded_by, &msg, &signing_key).unwrap();
        let msg_b64 = event_id_to_base64(&msg_eid);

        // Should be valid
        let valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &msg_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(valid);

        // Should be in messages table
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
                rusqlite::params![&msg_b64, recorded_by],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_create_signed_event_synchronous_returns_blocked_error() {
        // Verify strict API: create_signed_event_synchronous returns Err(Blocked) for
        // events with missing dependencies.
        let conn = setup();
        let recorded_by = "peer1";

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);

        // Reaction targeting a non-existent event → blocked on missing dep
        let fake_target = [0xDD; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: user_event_id,
            emoji: "x".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        let result = create_signed_event_synchronous(&conn, recorded_by, &rxn, &signing_key);
        match result {
            Err(CreateEventError::Blocked { event_id, missing }) => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], fake_target);
                // Event is stored even though blocked
                let eid_b64 = event_id_to_base64(&event_id);
                let in_events: bool = conn
                    .query_row(
                        "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                        rusqlite::params![&eid_b64],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(in_events, "event should be stored even when blocked");
            }
            Ok(_) => panic!("expected Blocked error, got Ok"),
            Err(e) => panic!("expected Blocked error, got: {}", e),
        }
    }

    #[test]
    fn test_create_signed_event_staged_returns_ok_on_blocked() {
        // Verify staged API: create_signed_event_staged returns Ok(event_id)
        // even when event is blocked.
        let conn = setup();
        let recorded_by = "peer1";

        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);

        let fake_target = [0xEE; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: user_event_id,
            emoji: "y".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        let eid = create_signed_event_staged(&conn, recorded_by, &rxn, &signing_key)
            .expect("staged API should return Ok even for blocked events");

        let eid_b64 = event_id_to_base64(&eid);
        let in_events: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(in_events, "event should be stored");

        // Should NOT be in valid_events (blocked)
        let in_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!in_valid, "blocked event should not be in valid_events");
    }

    /// PLAN §6.4 contract: `create_event_synchronous` returns Ok only for Valid events.
    /// A message with all deps satisfied must return Ok(event_id) and be in valid_events.
    #[test]
    fn test_create_event_sync_contract_valid_only() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);
        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_id: net_eid,
            author_id: user_event_id,
            content: "contract-valid".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        let result = create_signed_event_synchronous(&conn, recorded_by, &msg, &signing_key);
        assert!(
            result.is_ok(),
            "PLAN §6.4: valid event must return Ok, got: {:?}",
            result
        );

        let eid = result.unwrap();
        let eid_b64 = event_id_to_base64(&eid);
        let in_valid: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &eid_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            in_valid,
            "PLAN §6.4: Ok result implies event is in valid_events"
        );
    }

    /// PLAN §6.4 contract: `create_event_synchronous` returns Err(Blocked) with event_id
    /// and missing deps when a dependency is unresolved.
    #[test]
    fn test_create_event_sync_contract_blocked_returns_err_with_event_id() {
        let conn = setup();
        let recorded_by = "peer1";
        let (signer_eid, signing_key, user_event_id) = make_identity_chain(&conn, recorded_by);

        let fake_target = [0xCC; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: user_event_id,
            emoji: "z".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        let result = create_signed_event_synchronous(&conn, recorded_by, &rxn, &signing_key);

        match result {
            Err(CreateEventError::Blocked { event_id, missing }) => {
                // Error must contain the event_id so callers can reference it
                let eid_b64 = event_id_to_base64(&event_id);
                let stored: bool = conn
                    .query_row(
                        "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                        rusqlite::params![&eid_b64],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(
                    stored,
                    "PLAN §6.4: blocked event_id must reference a stored event"
                );
                assert!(
                    !missing.is_empty(),
                    "PLAN §6.4: Blocked error must list missing deps"
                );
                assert_eq!(missing[0], fake_target);
            }
            Ok(_) => panic!("PLAN §6.4: blocked event must NOT return Ok"),
            Err(e) => panic!("expected Blocked, got: {}", e),
        }
    }

    #[test]
    fn test_local_shared_create_fanout_is_same_workspace_only() {
        let mut node = SharedDbNode::new(2);
        node.add_tenant_in_workspace("same-ws", 0);

        let origin = &node.tenants[0];
        let other_workspace = &node.tenants[1];
        let sibling = &node.tenants[2];

        let message_id = origin.create_message("local fanout marker");
        let message_b64 = event_id_to_base64(&message_id);
        let db = crate::db::open_connection(&node.db_path).unwrap();

        let sibling_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![&sibling.identity, &message_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            sibling_count, 1,
            "same-workspace sibling should project message"
        );

        let other_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![&other_workspace.identity, &message_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            other_count, 0,
            "different-workspace tenant must not receive same-workspace fanout"
        );
    }
}
