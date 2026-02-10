use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{hash_event, event_id_to_base64, EventId};
use crate::events::{self, ParsedEvent, registry, ShareScope};
use crate::events::EncryptedEvent;
use crate::projection::encrypted::encrypt_event_blob;
use crate::projection::signer::sign_event_bytes;
use ed25519_dalek::SigningKey;
use super::decision::ProjectionDecision;
use super::pipeline::project_one;

#[derive(Debug)]
pub enum CreateEventError {
    EncodeError(String),
    DbError(String),
    Blocked { event_id: EventId, missing: Vec<[u8; 32]> },
    Rejected { event_id: EventId, reason: String },
}

impl std::fmt::Display for CreateEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreateEventError::EncodeError(e) => write!(f, "encode error: {}", e),
            CreateEventError::DbError(e) => write!(f, "db error: {}", e),
            CreateEventError::Blocked { event_id, missing } => {
                write!(f, "event {} blocked on {} deps", event_id_to_base64(event_id), missing.len())
            }
            CreateEventError::Rejected { event_id, reason } => {
                write!(f, "event {} rejected: {}", event_id_to_base64(event_id), reason)
            }
        }
    }
}

impl std::error::Error for CreateEventError {}

/// Extract event_id from Ok or Blocked (event is stored in both cases).
/// Returns Err only for true failures (encode, db, rejected).
pub fn event_id_or_blocked(result: Result<EventId, CreateEventError>) -> Result<EventId, CreateEventError> {
    match result {
        Ok(eid) => Ok(eid),
        Err(CreateEventError::Blocked { event_id, .. }) => Ok(event_id),
        Err(e) => Err(e),
    }
}

/// Require the event to be Valid (not Blocked). Use this for post-anchor events
/// in accept_user_invite / accept_device_link where Blocked means a prerequisite
/// chain is broken and the account will not be usable.
pub fn require_valid_event_id(result: Result<EventId, CreateEventError>) -> Result<EventId, CreateEventError> {
    result
}

/// Shared helper: hash blob, write to events/neg_items/recorded_events, project via project_one.
fn store_blob_and_project(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    meta: &events::EventTypeMeta,
    created_at_ms: i64,
) -> Result<EventId, CreateEventError> {
    let event_id = hash_event(blob);
    let event_id_b64 = event_id_to_base64(&event_id);

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Write to events table
    conn.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            &event_id_b64,
            meta.type_name,
            blob,
            meta.share_scope.as_str(),
            created_at_ms,
            now_ms
        ],
    ).map_err(|e| CreateEventError::DbError(e.to_string()))?;

    // Write to neg_items (only for shared events — local events must not sync)
    if meta.share_scope == ShareScope::Shared {
        conn.execute(
            "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
            rusqlite::params![created_at_ms, event_id.as_slice()],
        ).map_err(|e| CreateEventError::DbError(e.to_string()))?;
    }

    // Write to recorded_events
    conn.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, &event_id_b64, now_ms, "local_create"],
    ).map_err(|e| CreateEventError::DbError(e.to_string()))?;

    // Project
    let decision = project_one(conn, recorded_by, &event_id)
        .map_err(|e| CreateEventError::DbError(e.to_string()))?;

    match decision {
        ProjectionDecision::Valid
        | ProjectionDecision::AlreadyProcessed => Ok(event_id),
        ProjectionDecision::Block { missing } => {
            Err(CreateEventError::Blocked { event_id, missing })
        }
        ProjectionDecision::Reject { reason } => {
            Err(CreateEventError::Rejected { event_id, reason })
        }
    }
}

/// Create a new event: encode, hash, write to events/neg_items/recorded_events,
/// then project via `project_one`. Returns the event_id on success.
pub fn create_event_sync(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
) -> Result<EventId, CreateEventError> {
    let blob = events::encode_event(event)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    let type_code = event.event_type_code();
    let reg = registry();
    let meta = reg.lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    let created_at_ms = event.created_at_ms() as i64;
    store_blob_and_project(conn, recorded_by, &blob, meta, created_at_ms)
}

/// Create a signed event: encode with zero-placeholder signature, sign the
/// canonical bytes, overwrite signature, then store and project.
pub fn create_signed_event_sync(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<EventId, CreateEventError> {
    let mut blob = events::encode_event(event)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    let type_code = event.event_type_code();
    let reg = registry();
    let meta = reg.lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    if meta.signature_byte_len == 0 {
        return Err(CreateEventError::EncodeError(
            "create_signed_event_sync called for unsigned type".to_string(),
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

/// Create an encrypted event: encode inner event, optionally sign it,
/// resolve encryption key from secret_keys, encrypt, build EncryptedEvent
/// wrapper, then store and project.
///
/// If `signing_key` is provided, the inner blob is signed before encryption
/// (signature is inside the ciphertext — signer identity hidden from non-recipients).
pub fn create_encrypted_event_sync(
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
        let meta = events::registry().lookup(inner_event.event_type_code())
            .ok_or_else(|| CreateEventError::EncodeError("unknown event type".to_string()))?;
        let sig_len = meta.signature_byte_len;
        if sig_len > 0 {
            let blob_len = inner_blob.len();
            let sig = sign_event_bytes(key, &inner_blob[..blob_len - sig_len]);
            inner_blob[blob_len - sig_len..].copy_from_slice(&sig);
        }
    }

    // 3. Resolve encryption key from secret_keys table
    let key_b64 = event_id_to_base64(key_event_id);
    let key_bytes: Vec<u8> = conn.query_row(
        "SELECT key_bytes FROM secret_keys WHERE recorded_by = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &key_b64],
        |row| row.get(0),
    ).map_err(|e| CreateEventError::DbError(format!("key lookup: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(CreateEventError::EncodeError(
            format!("secret key wrong length: {}", key_bytes.len()),
        ));
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

    // 6. Use existing create_event_sync for the wrapper
    create_event_sync(conn, recorded_by, &wrapper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::events::{
        MessageEvent, ReactionEvent, PeerKeyEvent, SignedMemoEvent,
        WorkspaceEvent, InviteAcceptedEvent, UserInviteBootEvent,
        UserBootEvent, DeviceInviteFirstEvent, PeerSharedFirstEvent,
    };
    use crate::projection::signer::sign_event_bytes;
    use ed25519_dalek::SigningKey;

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
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
            workspace_id: [0xBB; 32],
        });
        event_id_or_blocked(create_event_sync(conn, recorded_by, &ws)).unwrap()
    }

    /// Helper: sign a blob in-place (overwrite last 64 bytes).
    fn sign_blob(key: &SigningKey, blob: &mut Vec<u8>) {
        let len = blob.len();
        let sig = sign_event_bytes(key, &blob[..len - 64]);
        blob[len - 64..].copy_from_slice(&sig);
    }

    /// Create a minimal identity chain for the given tenant.
    /// Returns (peer_shared_event_id, peer_shared_signing_key).
    fn make_identity_chain(conn: &Connection, recorded_by: &str) -> (EventId, SigningKey) {
        let mut rng = rand::thread_rng();

        let workspace_key = SigningKey::generate(&mut rng);
        let workspace_pub = workspace_key.verifying_key().to_bytes();
        let workspace_id: [u8; 32] = rand::random();
        let net_event = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: now_ms(),
            public_key: workspace_pub,
            workspace_id,
        });
        let net_blob = events::encode_event(&net_event).unwrap();
        let net_eid = create_event_sync(conn, recorded_by, &net_event);
        // Workspace may block (needs trust anchor). Create InviteAccepted first.
        let net_eid = event_id_or_blocked(net_eid).unwrap();

        let ia_event = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: now_ms(),
            invite_event_id: net_eid,
            workspace_id,
        });
        let _ia_eid = create_event_sync(conn, recorded_by, &ia_event).unwrap();

        // Re-project workspace now that trust anchor exists
        project_one(conn, recorded_by, &net_eid).unwrap();

        let invite_key = SigningKey::generate(&mut rng);
        let uib = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
            created_at_ms: now_ms(),
            public_key: invite_key.verifying_key().to_bytes(),
            workspace_id,
            signed_by: net_eid,
            signer_type: 1,
            signature: [0u8; 64],
        });
        let uib_eid = create_signed_event_sync(conn, recorded_by, &uib, &workspace_key).unwrap();

        let user_key = SigningKey::generate(&mut rng);
        let ub = ParsedEvent::UserBoot(UserBootEvent {
            created_at_ms: now_ms(),
            public_key: user_key.verifying_key().to_bytes(),
            signed_by: uib_eid,
            signer_type: 2,
            signature: [0u8; 64],
        });
        let ub_eid = create_signed_event_sync(conn, recorded_by, &ub, &invite_key).unwrap();

        let device_invite_key = SigningKey::generate(&mut rng);
        let dif = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
            created_at_ms: now_ms(),
            public_key: device_invite_key.verifying_key().to_bytes(),
            signed_by: ub_eid,
            signer_type: 4,
            signature: [0u8; 64],
        });
        let dif_eid = create_signed_event_sync(conn, recorded_by, &dif, &user_key).unwrap();

        let peer_shared_key = SigningKey::generate(&mut rng);
        let psf = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
            created_at_ms: now_ms(),
            public_key: peer_shared_key.verifying_key().to_bytes(),
            signed_by: dif_eid,
            signer_type: 3,
            signature: [0u8; 64],
        });
        let psf_eid = create_signed_event_sync(conn, recorded_by, &psf, &device_invite_key).unwrap();

        (psf_eid, peer_shared_key)
    }

    #[test]
    fn test_create_message_sync() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_event_id: net_eid,
            author_id: [2u8; 32],
            content: "hello".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });

        let eid = create_signed_event_sync(&conn, recorded_by, &msg, &signing_key).unwrap();
        let eid_b64 = event_id_to_base64(&eid);

        // events table
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE event_id = ?1",
            rusqlite::params![&eid_b64], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        // messages table
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&eid_b64, recorded_by], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        // valid_events
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &eid_b64], |row| row.get(0),
        ).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_create_reaction_chain() {
        let conn = setup();
        let recorded_by = "peer1";
        let net_eid = setup_workspace_event(&conn, recorded_by);

        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            workspace_event_id: net_eid,
            author_id: [2u8; 32],
            content: "target".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        let msg_eid = create_signed_event_sync(&conn, recorded_by, &msg, &signing_key).unwrap();

        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: msg_eid,
            author_id: [3u8; 32],
            emoji: "\u{1f44d}".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        let rxn_eid = create_signed_event_sync(&conn, recorded_by, &rxn, &signing_key).unwrap();

        // Both valid
        let msg_b64 = event_id_to_base64(&msg_eid);
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        for b64 in [&msg_b64, &rxn_b64] {
            let valid: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, b64], |row| row.get(0),
            ).unwrap();
            assert!(valid);
        }
    }

    #[test]
    fn test_create_reaction_before_target() {
        let conn = setup();
        let recorded_by = "peer1";

        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        let fake_target = [99u8; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: [3u8; 32],
            emoji: "\u{1f44d}".to_string(),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });

        // Event is stored but blocked — returns Blocked error with event_id
        let err = create_signed_event_sync(&conn, recorded_by, &rxn, &signing_key).unwrap_err();
        let (eid, missing) = match err {
            CreateEventError::Blocked { event_id, missing } => (event_id, missing),
            other => panic!("expected Blocked, got: {}", other),
        };
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], fake_target);
        let eid_b64 = event_id_to_base64(&eid);

        // Should be in events table but NOT in valid_events
        let in_events: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            rusqlite::params![&eid_b64], |row| row.get(0),
        ).unwrap();
        assert!(in_events);

        let in_valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &eid_b64], |row| row.get(0),
        ).unwrap();
        assert!(!in_valid);

        // Should be in blocked_event_deps
        let blocked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &eid_b64], |row| row.get(0),
        ).unwrap();
        assert_eq!(blocked, 1);
    }

    #[test]
    fn test_create_signed_event_sync() {
        let conn = setup();
        let recorded_by = "peer1";

        let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);

        // Create signed memo with PeerShared signer
        let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: now_ms(),
            signed_by: signer_eid,
            signer_type: 5,
            content: "signed content".to_string(),
            signature: [0u8; 64], // placeholder, will be overwritten
        });

        let memo_eid = create_signed_event_sync(&conn, recorded_by, &memo, &signing_key).unwrap();
        let memo_b64 = event_id_to_base64(&memo_eid);

        // Should be valid
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &memo_b64], |row| row.get(0),
        ).unwrap();
        assert!(valid);

        // Should be in signed_memos table
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM signed_memos WHERE event_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&memo_b64, recorded_by], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }
}
