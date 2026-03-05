//! Service layer: thin shell of DB helpers, utilities, and transport-level
//! orchestration. Event-domain command wrappers live in their respective
//! event modules (message/commands, reaction/commands, user/commands,
//! workspace/commands, workspace/queries).

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::crypto::EventId;
use crate::db::{open_connection, schema::create_tables, transport_trust::is_peer_allowed};
use crate::event_modules::peer_shared;
use crate::transport::create_dual_endpoint_dynamic;
use crate::transport::identity::{load_transport_cert_required, load_transport_peer_id};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

pub type ServiceResult<T> = Result<T, ServiceError>;

#[derive(Debug)]
pub struct ServiceError(pub String);

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ServiceError {}

impl From<String> for ServiceError {
    fn from(s: String) -> Self {
        ServiceError(s)
    }
}

impl From<&str> for ServiceError {
    fn from(s: &str) -> Self {
        ServiceError(s.to_string())
    }
}

impl From<rusqlite::Error> for ServiceError {
    fn from(e: rusqlite::Error) -> Self {
        ServiceError(e.to_string())
    }
}

impl From<hex::FromHexError> for ServiceError {
    fn from(e: hex::FromHexError) -> Self {
        ServiceError(e.to_string())
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ServiceError {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        ServiceError(e.to_string())
    }
}

impl From<crate::event_modules::workspace::invite_link::InviteLinkError> for ServiceError {
    fn from(e: crate::event_modules::workspace::invite_link::InviteLinkError) -> Self {
        ServiceError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// DB initialization helpers
// ---------------------------------------------------------------------------

/// Open DB, create tables, load existing transport peer ID.
/// For read-only commands that require an existing identity.
pub fn open_db_load(
    db_path: &str,
) -> Result<(String, rusqlite::Connection), Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    create_tables(&conn)?;
    let transport_peer_id = load_transport_peer_id(&conn)?;

    let has_scope: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM invites_accepted WHERE recorded_by = ?1",
        rusqlite::params![&transport_peer_id],
        |row| row.get(0),
    )?;
    if has_scope {
        return Ok((transport_peer_id, conn));
    }

    // POC fallback for non-finalized identity state: if exactly one scoped peer exists,
    // use it as the event/projection tenant.
    let scoped_peers: Vec<String> = {
        let mut stmt =
            conn.prepare("SELECT DISTINCT recorded_by FROM invites_accepted ORDER BY recorded_by")?;
        let peers = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        peers
    };

    if scoped_peers.len() == 1 {
        return Ok((scoped_peers[0].clone(), conn));
    }
    if scoped_peers.is_empty() {
        // Fresh DB / pre-workspace state: allow read paths to boot using
        // transport identity even before tenant-scoped accepted bindings exist.
        return Ok((transport_peer_id, conn));
    }

    Err(format!(
        "No unambiguous scoped tenant for transport peer_id {}; run `topo use-peer <N>`",
        transport_peer_id
    )
    .into())
}

/// Open DB for a specific peer_id (used when daemon provides the active peer).
pub fn open_db_for_peer(
    db_path: &str,
    peer_id: &str,
) -> Result<(String, rusqlite::Connection), Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    create_tables(&conn)?;
    Ok((peer_id.to_string(), conn))
}

// ---------------------------------------------------------------------------
// Response types (non-event-module types that stay here)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct TransportIdentityResponse {
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeTenantItem {
    pub peer_id: String,
    pub workspace_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IntroAttemptItem {
    pub intro_id: String,
    pub other_peer_id: String,
    pub introduced_by_peer_id: String,
    pub origin_ip: String,
    pub origin_port: u16,
    pub status: String,
    pub error: Option<String>,
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// Re-exports for backward compat
// ---------------------------------------------------------------------------

pub use crate::assert::{parse_predicate, query_field, AssertResponse, Op};
pub use crate::event_modules::message::GenerateResponse;
pub use crate::event_modules::message::{
    DeleteResponse, MessageItem, MessagesResponse, SendResponse,
};
pub use crate::event_modules::peer_shared::{AccountItem, IdentityResponse};
pub use crate::event_modules::reaction::{ReactResponse, ReactionItem};
pub use crate::event_modules::user::{BanResponse, UserItem};
pub use crate::event_modules::workspace::commands::{
    AcceptDeviceLinkResponse, AcceptInviteResponse, CreateInviteResponse, CreateWorkspaceResponse,
};
pub use crate::event_modules::workspace::{
    KeysResponse, StatusResponse, ViewMessage, ViewReaction, ViewResponse, WorkspaceItem,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Resolve the user_event_id for a specific signer from the peers_shared table.
pub fn resolve_user_event_id_for_signer(
    db: &rusqlite::Connection,
    recorded_by: &str,
    signer_eid: &EventId,
) -> ServiceResult<[u8; 32]> {
    peer_shared::resolve_user_event_id(db, recorded_by, signer_eid)
        .map_err(|e| ServiceError(e.to_string()))
}

/// Public accessor for loading the locally stored peer signer.
pub fn load_local_peer_signer_pub(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ServiceResult<Option<(EventId, SigningKey)>> {
    peer_shared::load_local_peer_signer(db, recorded_by).map_err(|e| ServiceError(e.to_string()))
}

pub fn load_local_user_key(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ServiceResult<Option<(EventId, SigningKey)>> {
    peer_shared::load_local_user_key(db, recorded_by).map_err(|e| ServiceError(e.to_string()))
}

// ---------------------------------------------------------------------------
// Service functions (transport-level, not event-module domain)
// ---------------------------------------------------------------------------

/// Node status: list local tenant identities discovered from DB.
pub fn svc_node_status(db_path: &str) -> ServiceResult<Vec<NodeTenantItem>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;
    let tenants = crate::db::transport_creds::discover_local_tenants(&db)?;
    Ok(tenants
        .into_iter()
        .map(|t| NodeTenantItem {
            peer_id: t.peer_id,
            workspace_id: t.workspace_id,
        })
        .collect())
}

pub async fn svc_intro(
    db_path: &str,
    peer_a: &str,
    peer_b: &str,
    ttl_ms: u64,
    attempt_window_ms: u32,
) -> ServiceResult<bool> {
    use std::sync::Arc;

    let conn = open_connection(db_path)?;
    create_tables(&conn)?;
    let (recorded_by, cert, key) = load_transport_cert_required(&conn)?;
    drop(conn);

    // Dynamic trust lookup from SQL at handshake time
    let db_path_for_lookup = db_path.to_string();
    let recorded_by_for_lookup = recorded_by.clone();
    let dynamic_allow = Arc::new(move |peer_fp: &[u8; 32]| {
        let db = open_connection(&db_path_for_lookup)?;
        is_peer_allowed(&db, &recorded_by_for_lookup, peer_fp)
    });
    let endpoint =
        create_dual_endpoint_dynamic("0.0.0.0:0".parse().unwrap(), cert, key, dynamic_allow)?;

    let result = crate::peering::workflows::intro::run_intro(
        &endpoint,
        db_path,
        &recorded_by,
        peer_a,
        peer_b,
        ttl_ms,
        attempt_window_ms,
    )
    .await
    .map_err(|e| ServiceError(format!("{}", e)))?;

    endpoint.close(0u32.into(), b"done");

    if result.sent_to_a && result.sent_to_b {
        Ok(true)
    } else {
        let errors: Vec<String> = result.errors.iter().map(|e| e.to_string()).collect();
        if !result.sent_to_a && !result.sent_to_b {
            Err(ServiceError(format!(
                "Failed to send to both peers: {}",
                errors.join("; ")
            )))
        } else {
            Err(ServiceError(format!("Partial send: {}", errors.join("; "))))
        }
    }
}

// ---------------------------------------------------------------------------
// Event list (workspace-scoped)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct EventListItem {
    pub id: String,
    pub event_type: String,
    pub created_at_ms: u64,
    pub blob_len: usize,
    pub deps: Vec<(String, String)>,
    pub fields: Vec<(String, String)>,
    pub decrypted_inner: Option<EventListDecrypted>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventListDecrypted {
    pub inner_type: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventListResponse {
    pub events: Vec<EventListItem>,
}

pub fn svc_event_list(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ServiceResult<EventListResponse> {
    use crate::crypto::{decrypt_event_blob, event_id_to_base64};
    use crate::event_modules::{parse_event, ParsedEvent};
    use std::collections::HashMap;

    // Load secret keys for this peer (for decryption attempts).
    let mut secret_keys: HashMap<String, Vec<u8>> = HashMap::new();
    if let Ok(mut stmt) =
        db.prepare("SELECT event_id, key_bytes FROM secret_keys WHERE recorded_by = ?1")
    {
        if let Ok(rows) = stmt.query_map(rusqlite::params![recorded_by], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        }) {
            for row in rows.flatten() {
                secret_keys.insert(row.0, row.1);
            }
        }
    }

    // Load events scoped to this workspace via recorded_events join.
    let mut stmt = db.prepare(
        "SELECT e.event_id, e.event_type, e.blob, e.created_at
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
         ORDER BY re.id",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        let id: String = row.get(0)?;
        let etype: String = row.get(1)?;
        let blob: Vec<u8> = row.get(2)?;
        let created_at: i64 = row.get(3)?;
        Ok((id, etype, blob, created_at as u64))
    })?;

    let registry = crate::event_modules::registry();
    let mut events = Vec::new();
    for row in rows {
        let (id_b64, event_type, blob, created_at_ms) = row?;
        let parsed = parse_event(&blob);

        let deps: Vec<(String, String)> = match &parsed {
            Ok(p) => p
                .dep_field_values()
                .into_iter()
                .map(|(field, raw_id)| (field.to_string(), event_id_to_base64(&raw_id)))
                .collect(),
            Err(_) => Vec::new(),
        };

        let fields: Vec<(String, String)> = match &parsed {
            Ok(p) => p
                .human_fields()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            Err(e) => vec![("parse_error".into(), format!("{}", e))],
        };

        // Attempt decryption for encrypted events.
        let decrypted_inner = if let Ok(ParsedEvent::Encrypted(enc)) = &parsed {
            let key_id_b64 = event_id_to_base64(&enc.key_event_id);
            secret_keys.get(&key_id_b64).and_then(|key_bytes| {
                if key_bytes.len() != 32 {
                    return None;
                }
                let mut key_arr = [0u8; 32];
                key_arr.copy_from_slice(key_bytes);
                let plaintext =
                    decrypt_event_blob(&key_arr, &enc.nonce, &enc.ciphertext, &enc.auth_tag)
                        .ok()?;
                let inner_parsed = parse_event(&plaintext).ok()?;
                let inner_type_name = registry
                    .lookup(inner_parsed.event_type_code())
                    .map(|m| m.type_name)
                    .unwrap_or("unknown");
                Some(EventListDecrypted {
                    inner_type: inner_type_name.to_string(),
                    fields: inner_parsed
                        .human_fields()
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                })
            })
        } else {
            None
        };

        events.push(EventListItem {
            id: id_b64,
            event_type,
            created_at_ms,
            blob_len: blob.len(),
            deps,
            fields,
            decrypted_inner,
        });
    }

    Ok(EventListResponse { events })
}

// ---------------------------------------------------------------------------
// Socket path helper
// ---------------------------------------------------------------------------

/// Derive the RPC socket path from a DB path.
/// Uses `<db_path>.topo.sock` — same directory as the database file.
pub fn socket_path_for_db(db_path: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(db_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    abs.with_extension("topo.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::{message, workspace};

    fn temp_db_path() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let path_str = path.to_str().unwrap().to_string();
        (dir, path_str)
    }

    fn setup_workspace(db_path: &str) -> String {
        let resp = workspace::commands::create_workspace_for_db(
            db_path,
            "test-workspace",
            "test-user",
            "test-device",
        )
        .unwrap();
        resp.peer_id
    }

    #[test]
    fn test_send_succeeds_on_valid() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);

        let resp = message::send_for_peer(&db_path, &peer_id, "hello").unwrap();
        assert_eq!(resp.content, "hello");
        assert!(!resp.event_id.is_empty());
    }

    #[test]
    fn test_react_errors_on_blocked() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);

        // React to a non-existent target — reaction will block on missing dep
        let fake_target = hex::encode([0xDD_u8; 32]);
        let result = crate::event_modules::reaction::react_for_peer(
            &db_path,
            &peer_id,
            &fake_target,
            "thumbsup",
        );
        assert!(
            result.is_err(),
            "reaction to missing target should error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_delete_of_missing_target_writes_intent() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);

        // Delete a non-existent message — writes deletion_intent, returns Ok
        let fake_target = hex::encode([0xEE_u8; 32]);
        let result = message::delete_message_for_peer(&db_path, &peer_id, &fake_target);
        assert!(
            result.is_ok(),
            "delete of missing target writes intent: {:?}",
            result
        );
    }

    #[test]
    fn test_resolve_message_selector_by_number() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);

        // Send two messages so we have numbered targets.
        let msg1 = message::send_for_peer(&db_path, &peer_id, "first").unwrap();
        let msg2 = message::send_for_peer(&db_path, &peer_id, "second").unwrap();

        let (recorded_by, db) = open_db_for_peer(&db_path, &peer_id).unwrap();

        // Resolve by 1-based number.
        let eid1 = message::resolve(&db, &recorded_by, "1")
            .map_err(ServiceError)
            .unwrap();
        assert_eq!(hex::encode(eid1), msg1.event_id);

        let eid2 = message::resolve(&db, &recorded_by, "2")
            .map_err(ServiceError)
            .unwrap();
        assert_eq!(hex::encode(eid2), msg2.event_id);

        // Resolve with # prefix.
        let eid1_hash = message::resolve(&db, &recorded_by, "#1")
            .map_err(ServiceError)
            .unwrap();
        assert_eq!(eid1, eid1_hash);

        // Resolve by raw hex.
        let eid_hex = message::resolve(&db, &recorded_by, &msg1.event_id)
            .map_err(ServiceError)
            .unwrap();
        assert_eq!(eid1, eid_hex);

        // Invalid index.
        let err = message::resolve(&db, &recorded_by, "99");
        assert!(err.is_err());
        let err_str = err.unwrap_err();
        assert!(err_str.contains("invalid message number"), "{}", err_str);

        // Zero index.
        let err = message::resolve(&db, &recorded_by, "0");
        assert!(err.is_err());
        let err_str = err.unwrap_err();
        assert!(err_str.contains("must be >= 1"), "{}", err_str);
    }

    #[test]
    fn test_ensure_identity_chain_tolerates_workspace_blocked() {
        let (_dir, db_path) = temp_db_path();
        let resp = workspace::commands::create_workspace_for_db(
            &db_path,
            "test-workspace",
            "test-user",
            "test-device",
        )
        .unwrap();
        assert!(!resp.peer_id.is_empty());
        assert!(!resp.workspace_id.is_empty());

        // Calling again should be idempotent (returns existing workspace).
        let resp2 = workspace::commands::create_workspace_for_db(
            &db_path,
            "test-workspace",
            "test-user",
            "test-device",
        )
        .unwrap();
        assert_eq!(resp.peer_id, resp2.peer_id);
        assert_eq!(resp.workspace_id, resp2.workspace_id);
    }

    #[test]
    fn test_assert_eventually_uses_scoped_peer_when_transport_differs() {
        let (_dir, db_path) = temp_db_path();
        let scoped_peer_id = setup_workspace(&db_path);

        let (resolved_peer_id, _db) = open_db_load(&db_path).unwrap();
        assert_eq!(
            resolved_peer_id, scoped_peer_id,
            "open_db_load should resolve to the scoped peer id"
        );

        message::send_for_peer(&db_path, &scoped_peer_id, "fallback-check").unwrap();
        let resp =
            crate::assert::assert_eventually(&db_path, "message_count >= 1", 2_000, 25).unwrap();
        assert!(
            resp.pass,
            "assert_eventually should read from the scoped peer"
        );
    }
}
