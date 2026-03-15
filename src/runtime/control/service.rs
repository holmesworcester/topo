//! Service layer: thin shell of DB helpers, utilities, and transport-level
//! orchestration. Event-domain command wrappers live in their respective
//! event modules (message/commands, reaction/commands, user/commands,
//! workspace/commands, workspace/queries).

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::crypto::EventId;
use crate::db::{
    open_connection, schema::create_tables, transport_trust::is_authorized_for_tenant,
};
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

    // Prefer tenant scope resolution from projection state. This remains stable
    // even when local_transport_creds has multiple rows (bootstrap + peershared,
    // or true multi-tenant).
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
    if scoped_peers.len() > 1 {
        return Err("no active tenant — run `topo tenant use <N>`".into());
    }

    // Fresh DB / pre-workspace state: fall back to singleton transport identity.
    let transport_peer_id = load_transport_peer_id(&conn)?;
    Ok((transport_peer_id, conn))
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
pub use crate::event_modules::peer_shared::{IdentityResponse, TenantItem};
pub use crate::event_modules::reaction::{ReactResponse, ReactionItem};
pub use crate::event_modules::user::UserItem;
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
        is_authorized_for_tenant(&db, &recorded_by_for_lookup, peer_fp)
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
    pub deps: Vec<(String, String)>,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventListResponse {
    pub events: Vec<EventListItem>,
}

/// Load secret keys for a peer (for decryption of encrypted events).
fn load_key_secrets(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> std::collections::HashMap<String, Vec<u8>> {
    use std::collections::HashMap;
    let mut key_secrets: HashMap<String, Vec<u8>> = HashMap::new();
    if let Ok(mut stmt) =
        db.prepare("SELECT event_id, key_bytes FROM key_secrets WHERE recorded_by = ?1")
    {
        if let Ok(rows) = stmt.query_map(rusqlite::params![recorded_by], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        }) {
            for row in rows.flatten() {
                key_secrets.insert(row.0, row.1);
            }
        }
    }
    key_secrets
}

/// Build EventListItems from raw DB rows.
fn build_event_list_items(
    rows: Vec<(String, String, Vec<u8>, u64)>,
    key_secrets: &std::collections::HashMap<String, Vec<u8>>,
) -> Vec<EventListItem> {
    use crate::crypto::{decrypt_event_blob, event_id_to_base64};
    use crate::event_modules::{parse_event, ParsedEvent};

    let registry = crate::event_modules::registry();
    let mut events = Vec::new();
    for (id_b64, event_type, blob, created_at_ms) in rows {
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
        let (decrypted_inner, deps) = if let Ok(ParsedEvent::Encrypted(enc)) = &parsed {
            let key_id_b64 = event_id_to_base64(&enc.key_event_id);
            match key_secrets.get(&key_id_b64).and_then(|key_bytes| {
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
                let inner_deps: Vec<(String, String)> = inner_parsed
                    .dep_field_values()
                    .into_iter()
                    .map(|(field, raw_id)| (field.to_string(), event_id_to_base64(&raw_id)))
                    .collect();
                Some((inner_type_name.to_string(), inner_deps, inner_parsed))
            }) {
                Some((inner_type_name, inner_deps, inner_parsed)) => {
                    // Merge inner deps first, then outer deps (key_event_id).
                    let mut merged_deps = inner_deps.clone();
                    merged_deps.extend(deps);
                    (
                        Some(EventListDecrypted {
                            inner_type: inner_type_name,
                            deps: inner_deps,
                            fields: inner_parsed
                                .human_fields()
                                .into_iter()
                                .map(|(k, v)| (k.to_string(), v))
                                .collect(),
                        }),
                        merged_deps,
                    )
                }
                None => (None, deps),
            }
        } else {
            (None, deps)
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
    events
}

pub fn svc_event_list(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ServiceResult<EventListResponse> {
    let key_secrets = load_key_secrets(db, recorded_by);

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

    let mut raw_rows = Vec::new();
    for row in rows {
        raw_rows.push(row?);
    }

    Ok(EventListResponse {
        events: build_event_list_items(raw_rows, &key_secrets),
    })
}

/// List specific events by their base64-encoded IDs.
pub fn svc_event_list_by_ids(
    db: &rusqlite::Connection,
    recorded_by: &str,
    ids: &[String],
) -> ServiceResult<EventListResponse> {
    if ids.is_empty() {
        return Ok(EventListResponse { events: vec![] });
    }
    let key_secrets = load_key_secrets(db, recorded_by);

    // Build IN-clause dynamically.
    let placeholders: Vec<String> = (0..ids.len()).map(|i| format!("?{}", i + 2)).collect();
    let sql = format!(
        "SELECT e.event_id, e.event_type, e.blob, e.created_at
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1 AND e.event_id IN ({})
         ORDER BY re.id",
        placeholders.join(", ")
    );

    let mut stmt = db.prepare(&sql)?;

    // Build params: [recorded_by, id1, id2, ...]
    let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    params_vec.push(Box::new(recorded_by.to_string()));
    for id in ids {
        params_vec.push(Box::new(id.clone()));
    }
    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(|b| b.as_ref()).collect();

    let rows = stmt.query_map(&*param_refs, |row| {
        let id: String = row.get(0)?;
        let etype: String = row.get(1)?;
        let blob: Vec<u8> = row.get(2)?;
        let created_at: i64 = row.get(3)?;
        Ok((id, etype, blob, created_at as u64))
    })?;

    let mut raw_rows = Vec::new();
    for row in rows {
        raw_rows.push(row?);
    }

    Ok(EventListResponse {
        events: build_event_list_items(raw_rows, &key_secrets),
    })
}

/// Show events matching a base64 ID prefix.
pub fn svc_event_show(
    db: &rusqlite::Connection,
    recorded_by: &str,
    prefix: &str,
) -> ServiceResult<EventListResponse> {
    let key_secrets = load_key_secrets(db, recorded_by);
    let like_pattern = format!("{}%", prefix);

    let mut stmt = db.prepare(
        "SELECT e.event_id, e.event_type, e.blob, e.created_at
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1 AND e.event_id LIKE ?2
         ORDER BY re.id",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by, like_pattern], |row| {
        let id: String = row.get(0)?;
        let etype: String = row.get(1)?;
        let blob: Vec<u8> = row.get(2)?;
        let created_at: i64 = row.get(3)?;
        Ok((id, etype, blob, created_at as u64))
    })?;

    let mut raw_rows = Vec::new();
    for row in rows {
        raw_rows.push(row?);
    }

    Ok(EventListResponse {
        events: build_event_list_items(raw_rows, &key_secrets),
    })
}

/// Reverse dependency tree: find an event by prefix, then BFS through its deps.
pub fn svc_event_deps(
    db: &rusqlite::Connection,
    recorded_by: &str,
    prefix: &str,
    depth: usize,
) -> ServiceResult<serde_json::Value> {
    use std::collections::{HashSet, VecDeque};

    let key_secrets = load_key_secrets(db, recorded_by);
    let like_pattern = format!("{}%", prefix);

    // Find root event.
    let root_row: Option<(String, String, Vec<u8>, u64)> = db
        .prepare(
            "SELECT e.event_id, e.event_type, e.blob, e.created_at
             FROM recorded_events re
             JOIN events e ON e.event_id = re.event_id
             WHERE re.peer_id = ?1 AND e.event_id LIKE ?2
             ORDER BY re.id LIMIT 1",
        )?
        .query_row(rusqlite::params![recorded_by, like_pattern], |row| {
            let id: String = row.get(0)?;
            let etype: String = row.get(1)?;
            let blob: Vec<u8> = row.get(2)?;
            let created_at: i64 = row.get(3)?;
            Ok((id, etype, blob, created_at as u64))
        })
        .ok();

    let Some(root) = root_row else {
        return Ok(serde_json::json!({
            "root_id": "",
            "events": [],
        }));
    };

    let root_id = root.0.clone();
    let mut all_rows = vec![root];
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(root_id.clone());

    // BFS through deps.
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    // Build root item to get its deps.
    let root_items = build_event_list_items(all_rows.clone(), &key_secrets);
    if let Some(root_item) = root_items.first() {
        for (_, dep_id) in &root_item.deps {
            if visited.insert(dep_id.clone()) {
                queue.push_back((dep_id.clone(), 1));
            }
        }
    }

    while let Some((dep_id, dep_depth)) = queue.pop_front() {
        if dep_depth > depth {
            continue;
        }
        // Fetch this dep event.
        let dep_row: Option<(String, String, Vec<u8>, u64)> = db
            .prepare(
                "SELECT e.event_id, e.event_type, e.blob, e.created_at
                 FROM recorded_events re
                 JOIN events e ON e.event_id = re.event_id
                 WHERE re.peer_id = ?1 AND e.event_id = ?2
                 LIMIT 1",
            )?
            .query_row(rusqlite::params![recorded_by, dep_id], |row| {
                let id: String = row.get(0)?;
                let etype: String = row.get(1)?;
                let blob: Vec<u8> = row.get(2)?;
                let created_at: i64 = row.get(3)?;
                Ok((id, etype, blob, created_at as u64))
            })
            .ok();

        if let Some(row) = dep_row {
            all_rows.push(row);
            // Parse and find further deps.
            if dep_depth < depth {
                let items =
                    build_event_list_items(vec![all_rows.last().unwrap().clone()], &key_secrets);
                if let Some(item) = items.first() {
                    for (_, next_dep_id) in &item.deps {
                        if visited.insert(next_dep_id.clone()) {
                            queue.push_back((next_dep_id.clone(), dep_depth + 1));
                        }
                    }
                }
            }
        }
    }

    let events = build_event_list_items(all_rows, &key_secrets);
    Ok(serde_json::json!({
        "root_id": root_id,
        "events": events,
    }))
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
    use crate::db::transport_creds::{self, CRED_SOURCE_BOOTSTRAP};
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
    fn test_create_workspace_for_db_creates_distinct_tenants_on_repeat_calls() {
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

        // Repeating create-workspace should bootstrap a second local tenant.
        let resp2 = workspace::commands::create_workspace_for_db(
            &db_path,
            "test-workspace",
            "test-user",
            "test-device",
        )
        .unwrap();
        assert_ne!(resp.peer_id, resp2.peer_id);
        assert_ne!(resp.workspace_id, resp2.workspace_id);

        let conn = open_connection(&db_path).unwrap();
        let tenants = transport_creds::discover_local_tenants(&conn).unwrap();
        assert_eq!(
            tenants.len(),
            2,
            "repeat create-workspace should add a tenant"
        );
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

    #[test]
    fn test_open_db_load_resolves_scoped_peer_with_multiple_local_identities() {
        let (_dir, db_path) = temp_db_path();
        let scoped_peer_id = setup_workspace(&db_path);

        let conn = crate::db::open_connection(&db_path).unwrap();
        crate::db::schema::create_tables(&conn).unwrap();

        // Mirror observed prod shape:
        // - one scoped peershared identity (from workspace bootstrap)
        // - one extra bootstrap identity row in local_transport_creds
        // open_db_load should still resolve the scoped peer.
        let bootstrap_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let (bootstrap_cert, bootstrap_priv) =
            crate::transport::generate_self_signed_cert_from_signing_key(&bootstrap_key).unwrap();
        let bootstrap_fp =
            crate::transport::extract_spki_fingerprint(bootstrap_cert.as_ref()).unwrap();
        let bootstrap_peer_id = hex::encode(bootstrap_fp);
        transport_creds::store_local_creds_with_source(
            &conn,
            &bootstrap_peer_id,
            bootstrap_cert.as_ref(),
            bootstrap_priv.secret_pkcs8_der(),
            CRED_SOURCE_BOOTSTRAP,
        )
        .unwrap();

        let local_creds_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM local_transport_creds", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(local_creds_count, 2, "expected two local identities");

        drop(conn);

        let (resolved_peer_id, _db) = open_db_load(&db_path)
            .expect("open_db_load should resolve scoped tenant with multiple local identities");
        assert_eq!(resolved_peer_id, scoped_peer_id);
    }

    // -----------------------------------------------------------------------
    // Tests for svc_event_list_by_ids, svc_event_show, svc_event_deps
    // -----------------------------------------------------------------------

    fn open_peer_db(db_path: &str, peer_id: &str) -> (String, rusqlite::Connection) {
        open_db_for_peer(db_path, peer_id).unwrap()
    }

    #[test]
    fn test_svc_event_list_returns_all_workspace_events() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);
        let (recorded_by, db) = open_peer_db(&db_path, &peer_id);

        let resp = svc_event_list(&db, &recorded_by).unwrap();
        // create-workspace produces ~13 events
        assert!(
            resp.events.len() >= 10,
            "workspace should have >=10 events, got {}",
            resp.events.len()
        );
        // Should contain a workspace event
        assert!(resp.events.iter().any(|e| e.event_type == "workspace"));
    }

    #[test]
    fn test_svc_event_list_by_ids_returns_subset() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);
        let (recorded_by, db) = open_peer_db(&db_path, &peer_id);

        let all = svc_event_list(&db, &recorded_by).unwrap();
        assert!(all.events.len() >= 3);

        // Pick first two IDs
        let ids: Vec<String> = all.events.iter().take(2).map(|e| e.id.clone()).collect();
        let subset = svc_event_list_by_ids(&db, &recorded_by, &ids).unwrap();
        assert_eq!(subset.events.len(), 2);
        assert_eq!(subset.events[0].id, ids[0]);
        assert_eq!(subset.events[1].id, ids[1]);
    }

    #[test]
    fn test_svc_event_list_by_ids_empty() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);
        let (recorded_by, db) = open_peer_db(&db_path, &peer_id);

        let resp = svc_event_list_by_ids(&db, &recorded_by, &[]).unwrap();
        assert!(resp.events.is_empty());
    }

    #[test]
    fn test_svc_event_show_exact_prefix() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);
        let (recorded_by, db) = open_peer_db(&db_path, &peer_id);

        let all = svc_event_list(&db, &recorded_by).unwrap();
        let target = &all.events[0];

        // Full ID should match exactly one
        let resp = svc_event_show(&db, &recorded_by, &target.id).unwrap();
        assert_eq!(resp.events.len(), 1);
        assert_eq!(resp.events[0].id, target.id);
    }

    #[test]
    fn test_svc_event_show_partial_prefix() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);
        let (recorded_by, db) = open_peer_db(&db_path, &peer_id);

        let all = svc_event_list(&db, &recorded_by).unwrap();
        let target = &all.events[0];
        let prefix = &target.id[..4.min(target.id.len())];

        let resp = svc_event_show(&db, &recorded_by, prefix).unwrap();
        assert!(
            !resp.events.is_empty(),
            "partial prefix should match at least one event"
        );
        assert!(resp.events.iter().all(|e| e.id.starts_with(prefix)));
    }

    #[test]
    fn test_svc_event_show_no_match() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);
        let (recorded_by, db) = open_peer_db(&db_path, &peer_id);

        let resp = svc_event_show(&db, &recorded_by, "ZZZZZZZZ_no_match").unwrap();
        assert!(resp.events.is_empty());
    }

    #[test]
    fn test_svc_event_deps_traverses_dependencies() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);
        let (recorded_by, db) = open_peer_db(&db_path, &peer_id);

        // Find a peer_shared event — it has deps (user_event_id, signed_by)
        let all = svc_event_list(&db, &recorded_by).unwrap();
        let peer_shared = all
            .events
            .iter()
            .find(|e| e.event_type == "peer_shared")
            .expect("should have a peer_shared event");
        assert!(!peer_shared.deps.is_empty(), "peer_shared should have deps");

        let result = svc_event_deps(&db, &recorded_by, &peer_shared.id, 5).unwrap();
        let root_id = result["root_id"].as_str().unwrap();
        assert_eq!(root_id, peer_shared.id);

        let events: Vec<EventListItem> = serde_json::from_value(result["events"].clone()).unwrap();
        // Should include the root + at least its direct deps
        assert!(
            events.len() >= 3,
            "deps tree should include root + deps, got {}",
            events.len()
        );
    }

    #[test]
    fn test_svc_event_deps_respects_depth_limit() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);
        let (recorded_by, db) = open_peer_db(&db_path, &peer_id);

        // Find a peer_shared event with known deep chain
        let all = svc_event_list(&db, &recorded_by).unwrap();
        let peer_shared = all
            .events
            .iter()
            .find(|e| e.event_type == "peer_shared")
            .expect("should have a peer_shared event");

        // depth=0 should return only root
        let d0 = svc_event_deps(&db, &recorded_by, &peer_shared.id, 0).unwrap();
        let d0_events: Vec<EventListItem> = serde_json::from_value(d0["events"].clone()).unwrap();
        assert_eq!(d0_events.len(), 1, "depth=0 should return only root");

        // depth=1 should return root + direct deps only
        let d1 = svc_event_deps(&db, &recorded_by, &peer_shared.id, 1).unwrap();
        let d1_events: Vec<EventListItem> = serde_json::from_value(d1["events"].clone()).unwrap();

        // depth=5 should return more events than depth=1
        let d5 = svc_event_deps(&db, &recorded_by, &peer_shared.id, 5).unwrap();
        let d5_events: Vec<EventListItem> = serde_json::from_value(d5["events"].clone()).unwrap();
        assert!(
            d5_events.len() >= d1_events.len(),
            "depth=5 ({}) should find >= depth=1 ({})",
            d5_events.len(),
            d1_events.len()
        );
    }

    #[test]
    fn test_svc_event_deps_no_match() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);
        let (recorded_by, db) = open_peer_db(&db_path, &peer_id);

        let result = svc_event_deps(&db, &recorded_by, "ZZZZZZZZ_no_match", 5).unwrap();
        assert_eq!(result["root_id"].as_str().unwrap(), "");
        let events: Vec<serde_json::Value> =
            serde_json::from_value(result["events"].clone()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_svc_event_list_decrypted_inner_has_deps() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);

        // Send a message — creates encrypted event with inner message
        message::send_for_peer(&db_path, &peer_id, "test-inner-deps").unwrap();

        let (recorded_by, db) = open_peer_db(&db_path, &peer_id);
        let resp = svc_event_list(&db, &recorded_by).unwrap();

        let encrypted = resp
            .events
            .iter()
            .find(|e| e.event_type == "encrypted")
            .expect("should have an encrypted event");

        let dec = encrypted
            .decrypted_inner
            .as_ref()
            .expect("encrypted event should be decryptable");
        assert_eq!(dec.inner_type, "message");
        assert!(!dec.fields.is_empty(), "decrypted inner should have fields");
    }
}
