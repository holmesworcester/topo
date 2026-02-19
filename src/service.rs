//! Service layer: business logic extracted from main.rs.
//!
//! Functions return structured, serializable types suitable for JSON RPC responses.
//! No printing to stdout — callers decide how to present results.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::{
    open_connection,
    schema::create_tables,
    transport_trust::is_peer_allowed,
};
use crate::event_modules::{
    DeviceInviteFirstEvent, InviteAcceptedEvent, ParsedEvent,
    PeerSharedFirstEvent, UserBootEvent, UserInviteBootEvent,
    WorkspaceEvent,
    message, reaction, message_deletion, user_removed,
    workspace, user, peer_shared, admin, transport_key,
};
use crate::projection::create::{create_event_sync, create_event_staged, create_signed_event_sync};
use crate::projection::apply::project_one;
use crate::transport::create_dual_endpoint_dynamic;
use crate::identity::transport::{
    install_peer_key_transport_identity, load_transport_cert_required, load_transport_peer_id,
};

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

impl From<crate::identity::invite_link::InviteLinkError> for ServiceError {
    fn from(e: crate::identity::invite_link::InviteLinkError) -> Self {
        ServiceError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// DB initialization helpers
// ---------------------------------------------------------------------------

/// Open DB, create tables, load existing transport peer ID.
/// For read-only commands that require an existing identity.
fn open_db_load(
    db_path: &str,
) -> Result<(String, rusqlite::Connection), Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    create_tables(&conn)?;
    let recorded_by = load_transport_peer_id(&conn)?;
    Ok((recorded_by, conn))
}

/// Open DB for a specific peer_id (used when daemon provides the active peer).
fn open_db_for_peer(
    db_path: &str,
    peer_id: &str,
) -> Result<(String, rusqlite::Connection), Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    create_tables(&conn)?;
    Ok((peer_id.to_string(), conn))
}

/// Require that a local peer signer exists for this recorded_by, or error.
fn require_local_peer_signer(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ServiceResult<(crate::crypto::EventId, ed25519_dalek::SigningKey)> {
    load_local_peer_signer(db, recorded_by)?
        .ok_or_else(|| ServiceError("no identity — run `topo create-workspace` first".into()))
}

/// Look up the workspace_id for a peer from trust_anchors.
pub fn resolve_workspace_for_peer(
    db: &rusqlite::Connection,
    peer_id: &str,
) -> ServiceResult<[u8; 32]> {
    let ws_b64: String = db
        .query_row(
            "SELECT workspace_id FROM trust_anchors WHERE peer_id = ?1",
            rusqlite::params![peer_id],
            |row| row.get(0),
        )
        .map_err(|_| ServiceError(format!("no workspace found for peer {}", peer_id)))?;
    event_id_from_base64(&ws_b64)
        .ok_or_else(|| ServiceError(format!("invalid workspace_id in trust_anchors: {}", ws_b64)))
}

// ---------------------------------------------------------------------------
// Response types (all Serialize for JSON output)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateWorkspaceResponse {
    pub peer_id: String,
    pub workspace_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransportIdentityResponse {
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeTenantItem {
    pub peer_id: String,
    pub workspace_id: String,
}

pub use crate::event_modules::message::{MessageItem, MessagesResponse, SendResponse};

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub events_count: i64,
    pub messages_count: i64,
    pub reactions_count: i64,
    pub recorded_events_count: i64,
    pub neg_items_count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateResponse {
    pub count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssertResponse {
    pub pass: bool,
    pub field: String,
    pub actual: i64,
    pub op: String,
    pub expected: i64,
    pub timed_out: bool,
}

pub use crate::event_modules::reaction::{ReactResponse, ReactionItem};

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub target: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserItem {
    pub event_id: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountItem {
    pub event_id: String,
    pub device_name: String,
    pub user_event_id: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewReaction {
    pub emoji: String,
    pub reactor_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewMessage {
    pub id: String,
    pub author_id: String,
    pub author_name: String,
    pub content: String,
    pub created_at: i64,
    pub reactions: Vec<ViewReaction>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewResponse {
    pub workspace_name: String,
    pub users: Vec<UserItem>,
    pub accounts: Vec<AccountItem>,
    pub own_user_event_id: String,
    pub messages: Vec<ViewMessage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysResponse {
    pub user_count: i64,
    pub peer_count: i64,
    pub admin_count: i64,
    pub transport_count: i64,
    pub users: Vec<String>,
    pub peers: Vec<String>,
    pub admins: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceItem {
    pub event_id: String,
    pub workspace_id: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInviteResponse {
    pub invite_link: String,
    pub invite_event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptInviteResponse {
    pub peer_id: String,
    pub user_event_id: String,
    pub peer_shared_event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptDeviceLinkResponse {
    pub peer_id: String,
    pub peer_shared_event_id: String,
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
// Helpers (extracted from main.rs, now pub for reuse)
// ---------------------------------------------------------------------------

pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Resolve the user_event_id for a specific signer from the peers_shared table.
/// This is the event ID of the User event in the identity chain — used as author_id
/// for messages, reactions, and deletions so they have a real dependency on the user.
pub fn resolve_user_event_id_for_signer(
    db: &rusqlite::Connection,
    recorded_by: &str,
    signer_eid: &EventId,
) -> ServiceResult<[u8; 32]> {
    let signer_b64 = crate::crypto::event_id_to_base64(signer_eid);
    let user_eid_b64: String = db
        .query_row(
            "SELECT COALESCE(user_event_id, '') FROM peers_shared WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &signer_b64],
            |row| row.get(0),
        )
        .map_err(|_| ServiceError("no peer_shared entry found for signer — identity chain incomplete".into()))?;
    if user_eid_b64.is_empty() {
        return Err(ServiceError("peer_shared entry has no user_event_id (legacy row) — recreate database".into()));
    }
    crate::crypto::event_id_from_base64(&user_eid_b64)
        .ok_or_else(|| ServiceError("invalid user_event_id in peers_shared".into()))
}

pub fn parse_workspace_hex(workspace_hex: &str) -> ServiceResult<[u8; 32]> {
    let workspace_bytes = hex::decode(workspace_hex)?;
    if workspace_bytes.len() > 32 {
        return Err("Workspace event ID must be at most 32 bytes".into());
    }
    let mut workspace_id = [0u8; 32];
    workspace_id[..workspace_bytes.len()].copy_from_slice(&workspace_bytes);
    Ok(workspace_id)
}

pub fn parse_hex_event_id(hex_str: &str) -> ServiceResult<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(ServiceError(format!(
            "Event ID must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut eid = [0u8; 32];
    eid.copy_from_slice(&bytes);
    Ok(eid)
}


fn ensure_local_signer_tables(
    db: &rusqlite::Connection,
) -> ServiceResult<()> {
    db.execute(
        "CREATE TABLE IF NOT EXISTS local_peer_signers (
            recorded_by TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            signing_key BLOB NOT NULL,
            updated_at INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

fn decode_signing_key(key_bytes: Vec<u8>) -> ServiceResult<SigningKey> {
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| ServiceError("bad signing key length in local signer table".into()))?;
    Ok(SigningKey::from_bytes(&key_arr))
}

fn persist_local_peer_signer(
    db: &rusqlite::Connection,
    recorded_by: &str,
    event_id_b64: &str,
    signing_key: &SigningKey,
) -> ServiceResult<()> {
    ensure_local_signer_tables(db)?;
    let now = current_timestamp_ms() as i64;
    db.execute(
        "INSERT INTO local_peer_signers (recorded_by, event_id, signing_key, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(recorded_by)
         DO UPDATE SET event_id = excluded.event_id,
                       signing_key = excluded.signing_key,
                       updated_at = excluded.updated_at",
        rusqlite::params![
            recorded_by,
            event_id_b64,
            signing_key.to_bytes().as_slice(),
            now
        ],
    )?;
    Ok(())
}

fn load_local_peer_signer(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ServiceResult<Option<(EventId, SigningKey)>> {
    ensure_local_signer_tables(db)?;

    if let Some((eid_b64, key_bytes)) = db
        .query_row(
            "SELECT l.event_id, l.signing_key
             FROM local_peer_signers l
             INNER JOIN peers_shared p
               ON p.recorded_by = l.recorded_by AND p.event_id = l.event_id
             WHERE l.recorded_by = ?1
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        let signing_key = decode_signing_key(key_bytes)?;
        let eid = event_id_from_base64(&eid_b64)
            .ok_or_else(|| ServiceError("bad local peer signer event_id".into()))?;
        return Ok(Some((eid, signing_key)));
    }

    Ok(None)
}

/// Public accessor for loading the locally stored peer signer.
/// Used by the interactive module to recover keys after service-layer operations.
pub fn load_local_peer_signer_pub(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ServiceResult<Option<(EventId, SigningKey)>> {
    ensure_local_signer_tables(db)?;

    if let Some((eid_b64, key_bytes)) = db
        .query_row(
            "SELECT event_id, signing_key FROM local_peer_signers WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        let signing_key = decode_signing_key(key_bytes)?;
        let eid = event_id_from_base64(&eid_b64)
            .ok_or_else(|| ServiceError("bad local peer signer event_id".into()))?;
        return Ok(Some((eid, signing_key)));
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// local_user_keys table — persists user signing keys for daemon device-link
// ---------------------------------------------------------------------------

fn ensure_local_user_key_table(db: &rusqlite::Connection) -> ServiceResult<()> {
    db.execute(
        "CREATE TABLE IF NOT EXISTS local_user_keys (
            recorded_by TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            signing_key BLOB NOT NULL,
            updated_at INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

pub fn persist_local_user_key(
    db: &rusqlite::Connection,
    recorded_by: &str,
    event_id_b64: &str,
    user_key: &SigningKey,
) -> ServiceResult<()> {
    ensure_local_user_key_table(db)?;
    let now = current_timestamp_ms() as i64;
    db.execute(
        "INSERT INTO local_user_keys (recorded_by, event_id, signing_key, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(recorded_by)
         DO UPDATE SET event_id = excluded.event_id,
                       signing_key = excluded.signing_key,
                       updated_at = excluded.updated_at",
        rusqlite::params![
            recorded_by,
            event_id_b64,
            user_key.to_bytes().as_slice(),
            now
        ],
    )?;
    Ok(())
}

pub fn load_local_user_key(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ServiceResult<Option<(EventId, SigningKey)>> {
    ensure_local_user_key_table(db)?;
    if let Some((eid_b64, key_bytes)) = db
        .query_row(
            "SELECT event_id, signing_key FROM local_user_keys WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        let signing_key = decode_signing_key(key_bytes)?;
        let eid = event_id_from_base64(&eid_b64)
            .ok_or_else(|| ServiceError("bad local user key event_id".into()))?;
        return Ok(Some((eid, signing_key)));
    }
    Ok(None)
}

pub fn svc_bootstrap_workspace_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
) -> ServiceResult<crate::identity::ops::IdentityChain> {
    crate::identity::ops::bootstrap_workspace(db, recorded_by, workspace_name, username, device_name)
        .map_err(|e| ServiceError(format!("{}", e)))
}
pub fn ensure_identity_chain(
    db: &rusqlite::Connection,
    recorded_by: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
) -> ServiceResult<(EventId, SigningKey)> {
    if let Some((eid, signing_key)) = load_local_peer_signer(db, recorded_by)? {
        return Ok((eid, signing_key));
    }

    let mut rng = rand::thread_rng();

    let workspace_key = SigningKey::generate(&mut rng);
    let ws = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: workspace_key.verifying_key().to_bytes(),
        name: workspace_name.to_string(),
    });
    let ws_eid = create_event_staged(db, recorded_by, &ws)
        .map_err(|e| ServiceError(format!("{}", e)))?;

    let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: current_timestamp_ms(),
        invite_event_id: ws_eid,
        workspace_id: ws_eid,
    });
    let _ia_eid = create_event_sync(db, recorded_by, &ia)
        .map_err(|e| ServiceError(format!("{}", e)))?;
    project_one(db, recorded_by, &ws_eid)
        .map_err(|e| ServiceError(format!("{}", e)))?;

    let invite_key = SigningKey::generate(&mut rng);
    let uib = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: invite_key.verifying_key().to_bytes(),
        workspace_id: ws_eid,
        signed_by: ws_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let uib_eid = create_signed_event_sync(db, recorded_by, &uib, &workspace_key)
        .map_err(|e| ServiceError(format!("{}", e)))?;

    let user_key = SigningKey::generate(&mut rng);
    let ub = ParsedEvent::UserBoot(UserBootEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        username: username.to_string(),
        signed_by: uib_eid,
        signer_type: 2,
        signature: [0u8; 64],
    });
    let ub_eid = create_signed_event_sync(db, recorded_by, &ub, &invite_key)
        .map_err(|e| ServiceError(format!("{}", e)))?;

    let device_invite_key = SigningKey::generate(&mut rng);
    let dif = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: device_invite_key.verifying_key().to_bytes(),
        signed_by: ub_eid,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let dif_eid = create_signed_event_sync(db, recorded_by, &dif, &user_key)
        .map_err(|e| ServiceError(format!("{}", e)))?;

    let peer_shared_key = SigningKey::generate(&mut rng);
    let psf = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        user_event_id: ub_eid,
        device_name: device_name.to_string(),
        signed_by: dif_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let psf_eid = create_signed_event_sync(db, recorded_by, &psf, &device_invite_key)
        .map_err(|e| ServiceError(format!("{}", e)))?;

    let psf_b64 = event_id_to_base64(&psf_eid);
    persist_local_peer_signer(db, recorded_by, &psf_b64, &peer_shared_key)?;

    // Persist user key for later device-link creation
    let ub_b64 = event_id_to_base64(&ub_eid);
    persist_local_user_key(db, recorded_by, &ub_b64, &user_key)?;

    // Seed deterministic local content-key material used by invite key-wrap.
    let _ = crate::identity::ops::ensure_content_key_for_peer(
        db,
        recorded_by,
        &peer_shared_key,
        &psf_eid,
    ).map_err(|e| ServiceError(format!("failed to ensure content key: {}", e)))?;

    // Persist workspace key for later invite creation
    persist_workspace_key(db, recorded_by, &workspace_key)?;

    Ok((psf_eid, peer_shared_key))
}

// ---------------------------------------------------------------------------
// Predicate parsing (for assert commands)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub enum Op {
    Eq,
    Ne,
    Ge,
    Le,
    Gt,
    Lt,
}

impl Op {
    pub fn eval(self, actual: i64, expected: i64) -> bool {
        match self {
            Op::Eq => actual == expected,
            Op::Ne => actual != expected,
            Op::Ge => actual >= expected,
            Op::Le => actual <= expected,
            Op::Gt => actual > expected,
            Op::Lt => actual < expected,
        }
    }

    pub fn symbol(self) -> &'static str {
        match self {
            Op::Eq => "==",
            Op::Ne => "!=",
            Op::Ge => ">=",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Lt => "<",
        }
    }
}

pub fn parse_predicate(s: &str) -> Result<(String, Op, i64), String> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(format!(
            "predicate must be \"field op value\", got {} parts: {:?}",
            parts.len(),
            s
        ));
    }
    let field = parts[0].to_string();
    let op = match parts[1] {
        "==" => Op::Eq,
        "!=" => Op::Ne,
        ">=" => Op::Ge,
        "<=" => Op::Le,
        ">" => Op::Gt,
        "<" => Op::Lt,
        other => return Err(format!("unknown operator: {}", other)),
    };
    let value: i64 = parts[2]
        .parse()
        .map_err(|e| format!("invalid value '{}': {}", parts[2], e))?;
    Ok((field, op, value))
}

pub fn query_field(db: &rusqlite::Connection, field: &str, recorded_by: &str) -> Result<i64, String> {
    match field {
        "store_count" | "events_count" => db
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "message_count" => message::count(db, recorded_by)
            .map_err(|e| format!("query failed: {}", e)),
        "reaction_count" => reaction::count(db, recorded_by)
            .map_err(|e| format!("query failed: {}", e)),
        "neg_items_count" => db
            .query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "recorded_events_count" => db
            .query_row(
                "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e)),
        other if other.starts_with("has_event:") => {
            let event_id = &other["has_event:".len()..];
            let direct_count: i64 = db
                .query_row(
                "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, event_id],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e))?;
            if direct_count > 0 {
                return Ok(direct_count);
            }
            if let Ok(event_id_bytes) = hex::decode(event_id) {
                if event_id_bytes.len() == 32 {
                    let mut eid = [0u8; 32];
                    eid.copy_from_slice(&event_id_bytes);
                    return db
                        .query_row(
                            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
                            rusqlite::params![recorded_by, event_id_to_base64(&eid)],
                            |row| row.get(0),
                        )
                        .map_err(|e| format!("query failed: {}", e));
                }
            }
            Ok(0)
        }
        other => Err(format!("unknown field: {}", other)),
    }
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

pub fn svc_create_workspace(db_path: &str, workspace_name: &str, username: &str, device_name: &str) -> ServiceResult<CreateWorkspaceResponse> {
    let conn = open_connection(db_path)?;
    create_tables(&conn)?;

    // Check if identity already exists
    if let Ok(peer_id) = load_transport_peer_id(&conn) {
        // Already bootstrapped — return existing workspace info
        let workspaces = svc_workspaces_conn(&conn, &peer_id)?;
        if let Some(ws) = workspaces.first() {
            return Ok(CreateWorkspaceResponse {
                peer_id,
                workspace_id: ws.event_id.clone(),
            });
        }
    }

    // Bootstrap new identity chain (creates Workspace + 5 identity events)
    let bootstrap_rb = format!("bootstrap-{}", current_timestamp_ms());
    let (_eid, peer_shared_key) = ensure_identity_chain(&conn, &bootstrap_rb, workspace_name, username, device_name)?;
    let derived = install_peer_key_transport_identity(&conn, &peer_shared_key)
        .map_err(|e| ServiceError(format!("install transport identity failed: {}", e)))?;
    if derived != bootstrap_rb {
        crate::db::migrate_recorded_by(&conn, &bootstrap_rb, &derived)
            .map_err(|e| ServiceError(format!("recorded_by migration failed: {}", e)))?;
    }

    let workspaces = svc_workspaces_conn(&conn, &derived)?;
    let workspace_id = workspaces
        .first()
        .map(|ws| ws.event_id.clone())
        .unwrap_or_default();

    Ok(CreateWorkspaceResponse {
        peer_id: derived,
        workspace_id,
    })
}

pub fn svc_transport_identity(db_path: &str) -> ServiceResult<TransportIdentityResponse> {
    let (fingerprint, _db) = open_db_load(db_path)
        .map_err(|e| ServiceError(format!("{}", e)))?;
    Ok(TransportIdentityResponse { fingerprint })
}

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

pub fn svc_messages_conn(db: &rusqlite::Connection, recorded_by: &str, limit: usize) -> ServiceResult<MessagesResponse> {
    Ok(message::list(db, recorded_by, limit)?)
}

pub fn svc_messages(db_path: &str, limit: usize) -> ServiceResult<MessagesResponse> {
    let (recorded_by, db) = open_db_load(db_path)?;
    svc_messages_conn(&db, &recorded_by, limit)
}

pub fn svc_send_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    workspace_id: [u8; 32],
    author_id: [u8; 32],
    content: &str,
) -> ServiceResult<SendResponse> {
    message::send(db, recorded_by, signer_eid, signing_key, current_timestamp_ms(), workspace_id, author_id, content)
        .map_err(ServiceError)
}

/// Send a message as a specific peer (daemon provides the peer_id).
pub fn svc_send_for_peer(
    db_path: &str,
    peer_id: &str,
    content: &str,
) -> ServiceResult<SendResponse> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    let (signer_eid, signing_key) = require_local_peer_signer(&db, &recorded_by)?;
    let workspace_id = resolve_workspace_for_peer(&db, &recorded_by)?;
    let author_id = resolve_user_event_id_for_signer(&db, &recorded_by, &signer_eid)?;

    svc_send_conn(&db, &recorded_by, &signer_eid, &signing_key, workspace_id, author_id, content)
}

pub fn svc_status_conn(db: &rusqlite::Connection, recorded_by: &str) -> ServiceResult<StatusResponse> {
    let events_count: i64 = db
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap_or(0);
    let messages_count = message::count(db, recorded_by).unwrap_or(0);
    let reactions_count = reaction::count(db, recorded_by).unwrap_or(0);
    let neg_items_count: i64 = db
        .query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
        .unwrap_or(0);
    let recorded_events_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);

    Ok(StatusResponse {
        events_count,
        messages_count,
        reactions_count,
        recorded_events_count,
        neg_items_count,
    })
}

pub fn svc_status(db_path: &str) -> ServiceResult<StatusResponse> {
    let (recorded_by, db) = open_db_load(db_path)?;
    svc_status_conn(&db, &recorded_by)
}

pub fn svc_generate_for_peer(
    db_path: &str,
    peer_id: &str,
    count: usize,
) -> ServiceResult<GenerateResponse> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    let (signer_eid, signing_key) = require_local_peer_signer(&db, &recorded_by)?;
    let workspace_id = resolve_workspace_for_peer(&db, &recorded_by)?;
    let author_id = resolve_user_event_id_for_signer(&db, &recorded_by, &signer_eid)?;

    db.execute("BEGIN", [])?;
    for i in 0..count {
        message::create(
            &db, &recorded_by, &signer_eid, &signing_key, current_timestamp_ms(),
            message::CreateMessageCmd {
                workspace_id,
                author_id,
                content: format!("Message {}", i),
            },
        ).map_err(|e| ServiceError(format!("create event error: {}", e)))?;
    }
    db.execute("COMMIT", [])?;

    Ok(GenerateResponse { count })
}

pub fn svc_assert_now(
    db_path: &str,
    predicate_str: &str,
) -> ServiceResult<AssertResponse> {
    let (recorded_by, db) = open_db_load(db_path)?;
    let (field, op, expected) =
        parse_predicate(predicate_str).map_err(ServiceError)?;
    let actual = query_field(&db, &field, &recorded_by).map_err(ServiceError)?;

    Ok(AssertResponse {
        pass: op.eval(actual, expected),
        field,
        actual,
        op: op.symbol().to_string(),
        expected,
        timed_out: false,
    })
}

pub fn svc_assert_eventually(
    db_path: &str,
    predicate_str: &str,
    timeout_ms: u64,
    interval_ms: u64,
) -> ServiceResult<AssertResponse> {
    let (recorded_by, db) = open_db_load(db_path)?;
    let (field, op, expected) =
        parse_predicate(predicate_str).map_err(ServiceError)?;
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let interval = Duration::from_millis(interval_ms);

    loop {
        let actual = query_field(&db, &field, &recorded_by).map_err(ServiceError)?;
        if op.eval(actual, expected) {
            return Ok(AssertResponse {
                pass: true,
                field,
                actual,
                op: op.symbol().to_string(),
                expected,
                timed_out: false,
            });
        }
        if start.elapsed() >= timeout {
            return Ok(AssertResponse {
                pass: false,
                field,
                actual,
                op: op.symbol().to_string(),
                expected,
                timed_out: true,
            });
        }
        std::thread::sleep(interval);
    }
}

pub fn svc_react_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    author_id: [u8; 32],
    target_event_id: [u8; 32],
    emoji: &str,
) -> ServiceResult<ReactResponse> {
    reaction::react(db, recorded_by, signer_eid, signing_key, current_timestamp_ms(), author_id, target_event_id, emoji)
        .map_err(ServiceError)
}

pub fn svc_react_for_peer(
    db_path: &str,
    peer_id: &str,
    target_hex: &str,
    emoji: &str,
) -> ServiceResult<ReactResponse> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    let (signer_eid, signing_key) = require_local_peer_signer(&db, &recorded_by)?;
    let target_event_id = message::resolve(&db, &recorded_by, target_hex)
        .map_err(ServiceError)?;
    let author_id = resolve_user_event_id_for_signer(&db, &recorded_by, &signer_eid)?;

    svc_react_conn(&db, &recorded_by, &signer_eid, &signing_key, author_id, target_event_id, emoji)
}

pub fn svc_delete_message_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    author_id: [u8; 32],
    target_event_id: [u8; 32],
) -> ServiceResult<DeleteResponse> {
    let target = message_deletion::delete_message(
        db, recorded_by, signer_eid, signing_key, current_timestamp_ms(), author_id, target_event_id,
    ).map_err(ServiceError)?;
    Ok(DeleteResponse { target })
}

pub fn svc_delete_message_for_peer(
    db_path: &str,
    peer_id: &str,
    target_hex: &str,
) -> ServiceResult<DeleteResponse> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    let (signer_eid, signing_key) = require_local_peer_signer(&db, &recorded_by)?;
    let target_event_id = message::resolve(&db, &recorded_by, target_hex)
        .map_err(ServiceError)?;
    let author_id = resolve_user_event_id_for_signer(&db, &recorded_by, &signer_eid)?;

    svc_delete_message_conn(&db, &recorded_by, &signer_eid, &signing_key, author_id, target_event_id)
}

/// Resolve a message selector: `N`, `#N` (1-based message number), or raw hex event ID.
/// Thin wrapper over message::resolve for test compatibility.
#[cfg(test)]
fn resolve_message_selector(
    db: &rusqlite::Connection,
    recorded_by: &str,
    selector: &str,
) -> ServiceResult<[u8; 32]> {
    message::resolve(db, recorded_by, selector)
        .map_err(ServiceError)
}

pub fn svc_reactions_conn(db: &rusqlite::Connection, recorded_by: &str) -> ServiceResult<Vec<ReactionItem>> {
    Ok(reaction::list(db, recorded_by)?)
}

pub fn svc_reactions(db_path: &str) -> ServiceResult<Vec<ReactionItem>> {
    let (recorded_by, db) = open_db_load(db_path)?;
    svc_reactions_conn(&db, &recorded_by)
}

pub fn svc_reactions_for_message_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
    target_event_id_b64: &str,
) -> ServiceResult<Vec<String>> {
    Ok(reaction::list_for_message(db, recorded_by, target_event_id_b64)?)
}

pub fn svc_deleted_message_ids_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ServiceResult<Vec<String>> {
    Ok(message_deletion::list_deleted_ids(db, recorded_by)?)
}

/// Resolve a 1-based message number to its event ID.
pub fn svc_message_event_id_by_num_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
    msg_num: usize,
) -> ServiceResult<crate::crypto::EventId> {
    message::resolve_number(db, recorded_by, msg_num)
        .map_err(ServiceError)
}

pub fn svc_remove_user_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
    signer_eid: &crate::crypto::EventId,
    signing_key: &SigningKey,
    target_event_id: crate::crypto::EventId,
) -> ServiceResult<DeleteResponse> {
    let target = user_removed::remove_user(
        db, recorded_by, signer_eid, signing_key, current_timestamp_ms(), target_event_id,
    ).map_err(ServiceError)?;
    Ok(DeleteResponse { target })
}

/// Create a user invite (conn-based variant for interactive use with in-memory keys).
pub fn svc_create_invite_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
    workspace_key: &SigningKey,
    workspace_id: &crate::crypto::EventId,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &crate::crypto::EventId,
    bootstrap_addr: &str,
    bootstrap_spki: &[u8; 32],
) -> ServiceResult<CreateInviteResponse> {
    let _ = crate::identity::ops::ensure_content_key_for_peer(
        db, recorded_by, peer_shared_key, peer_shared_event_id,
    ).map_err(|e| ServiceError(format!("Failed to ensure content key: {}", e)))?;

    let invite = crate::identity::ops::create_user_invite(
        db, recorded_by, workspace_key, workspace_id,
        Some(peer_shared_key), Some(peer_shared_event_id),
    ).map_err(|e| ServiceError(format!("Failed to create invite: {}", e)))?;

    let pending_spki = crate::identity::transport::expected_invite_bootstrap_spki_from_invite_key(
        &invite.invite_key,
    ).map_err(|e| ServiceError(format!("Failed to derive invite SPKI: {}", e)))?;

    crate::db::transport_trust::record_pending_invite_bootstrap_trust(
        db, recorded_by,
        &event_id_to_base64(&invite.invite_event_id),
        &event_id_to_base64(workspace_id),
        &pending_spki,
    )?;

    let invite_link = crate::identity::invite_link::create_invite_link(&invite, bootstrap_addr, bootstrap_spki)
        .map_err(|e| ServiceError(format!("Failed to create invite link: {}", e)))?;

    Ok(CreateInviteResponse {
        invite_link,
        invite_event_id: event_id_to_base64(&invite.invite_event_id),
    })
}

/// Create a device link invite (conn-based variant for interactive use with in-memory keys).
pub fn svc_create_device_link_invite_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
    user_key: &SigningKey,
    user_event_id: &crate::crypto::EventId,
    workspace_id: &crate::crypto::EventId,
    bootstrap_addr: &str,
    bootstrap_spki: &[u8; 32],
) -> ServiceResult<CreateInviteResponse> {
    let invite = crate::identity::ops::create_device_link_invite(
        db, recorded_by, user_key, user_event_id, workspace_id,
    ).map_err(|e| ServiceError(format!("Failed to create device link invite: {}", e)))?;

    let pending_spki = crate::identity::transport::expected_invite_bootstrap_spki_from_invite_key(
        &invite.invite_key,
    ).map_err(|e| ServiceError(format!("Failed to derive invite SPKI: {}", e)))?;

    crate::db::transport_trust::record_pending_invite_bootstrap_trust(
        db, recorded_by,
        &event_id_to_base64(&invite.invite_event_id),
        &event_id_to_base64(workspace_id),
        &pending_spki,
    )?;

    let invite_link = crate::identity::invite_link::create_invite_link(&invite, bootstrap_addr, bootstrap_spki)
        .map_err(|e| ServiceError(format!("Failed to create invite link: {}", e)))?;

    Ok(CreateInviteResponse {
        invite_link,
        invite_event_id: event_id_to_base64(&invite.invite_event_id),
    })
}

pub fn svc_users_conn(db: &rusqlite::Connection, recorded_by: &str) -> ServiceResult<Vec<UserItem>> {
    let rows = user::list(db, recorded_by)?;
    Ok(rows
        .into_iter()
        .map(|row| UserItem { event_id: row.event_id, username: row.username })
        .collect())
}

pub fn svc_users(db_path: &str) -> ServiceResult<Vec<UserItem>> {
    let (recorded_by, db) = open_db_load(db_path)?;
    svc_users_conn(&db, &recorded_by)
}

pub fn svc_view_conn(
    db: &rusqlite::Connection,
    recorded_by: &str,
    limit: usize,
) -> ServiceResult<ViewResponse> {
    // Workspace name
    let workspace_name: String = db
        .query_row(
            "SELECT COALESCE(name, '') FROM workspaces WHERE recorded_by = ?1 LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap_or_default();

    // Users
    let users = svc_users_conn(db, recorded_by)?;

    // Own user_event_id (for marking "you") — look up via local signer
    let own_user_eid: String = if let Ok(Some((signer_eid, _))) = load_local_peer_signer(db, recorded_by) {
        let signer_b64 = crate::crypto::event_id_to_base64(&signer_eid);
        db.query_row(
            "SELECT COALESCE(user_event_id, '') FROM peers_shared WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &signer_b64],
            |row| row.get(0),
        ).unwrap_or_default()
    } else {
        String::new()
    };

    // Accounts (peers)
    let mut acct_stmt = db.prepare(
        "SELECT ps.event_id, COALESCE(ps.device_name, ''), COALESCE(ps.user_event_id, ''),
                COALESCE(u.username, '')
         FROM peers_shared ps
         LEFT JOIN users u ON ps.user_event_id = u.event_id AND ps.recorded_by = u.recorded_by
         WHERE ps.recorded_by = ?1"
    )?;
    let accounts: Vec<AccountItem> = acct_stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(AccountItem {
                event_id: row.get(0)?,
                device_name: row.get(1)?,
                user_event_id: row.get(2)?,
                username: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(acct_stmt);

    // Messages with author names
    let msg_resp = svc_messages_conn(db, recorded_by, limit)?;

    // Reactions per message
    let mut view_messages = Vec::with_capacity(msg_resp.messages.len());
    for msg in msg_resp.messages {
        let mut rxn_stmt = db.prepare(
            "SELECT r.emoji, COALESCE(u.username, '') as reactor_name
             FROM reactions r
             LEFT JOIN users u ON r.author_id = u.event_id AND r.recorded_by = u.recorded_by
             WHERE r.target_event_id = ?1 AND r.recorded_by = ?2"
        )?;
        let reactions: Vec<ViewReaction> = rxn_stmt
            .query_map(rusqlite::params![&msg.id_b64, recorded_by], |row| {
                Ok(ViewReaction {
                    emoji: row.get(0)?,
                    reactor_name: row.get(1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        view_messages.push(ViewMessage {
            id: msg.id_b64,
            author_id: msg.author_id,
            author_name: msg.author_name,
            content: msg.content,
            created_at: msg.created_at,
            reactions,
        });
    }

    Ok(ViewResponse {
        workspace_name,
        users,
        accounts,
        own_user_event_id: own_user_eid,
        messages: view_messages,
    })
}

pub fn svc_view(db_path: &str, limit: usize) -> ServiceResult<ViewResponse> {
    let (recorded_by, db) = open_db_load(db_path)?;
    svc_view_conn(&db, &recorded_by, limit)
}

pub fn svc_view_for_peer(db_path: &str, peer_id: &str, limit: usize) -> ServiceResult<ViewResponse> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    svc_view_conn(&db, &recorded_by, limit)
}

pub fn svc_keys_conn(db: &rusqlite::Connection, recorded_by: &str, summary: bool) -> ServiceResult<KeysResponse> {
    let user_count = user::count(db, recorded_by).unwrap_or(0);
    let peer_count = peer_shared::count(db, recorded_by).unwrap_or(0);
    let admin_count = admin::count(db, recorded_by).unwrap_or(0);
    let transport_count = transport_key::count(db, recorded_by).unwrap_or(0);

    let mut users = Vec::new();
    let mut peers = Vec::new();
    let mut admins = Vec::new();

    if !summary {
        users = user::list(db, recorded_by)?
            .into_iter()
            .map(|row| row.event_id)
            .collect();

        let mut stmt = db.prepare("SELECT event_id FROM peers_shared WHERE recorded_by = ?1")?;
        peers = stmt
            .query_map(rusqlite::params![recorded_by], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut stmt = db.prepare("SELECT event_id FROM admins WHERE recorded_by = ?1")?;
        admins = stmt
            .query_map(rusqlite::params![recorded_by], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
    }

    Ok(KeysResponse {
        user_count,
        peer_count,
        admin_count,
        transport_count,
        users,
        peers,
        admins,
    })
}

pub fn svc_keys(db_path: &str, summary: bool) -> ServiceResult<KeysResponse> {
    let (recorded_by, db) = open_db_load(db_path)?;
    svc_keys_conn(&db, &recorded_by, summary)
}

pub fn svc_workspaces_conn(db: &rusqlite::Connection, recorded_by: &str) -> ServiceResult<Vec<WorkspaceItem>> {
    let rows = workspace::list(db, recorded_by)?;

    use base64::Engine;
    Ok(rows
        .into_iter()
        .map(|row| {
            let name =
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&row.workspace_id) {
                    String::from_utf8_lossy(&bytes)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    row.workspace_id.clone()
                };
            WorkspaceItem {
                event_id: row.event_id,
                workspace_id: row.workspace_id,
                name,
            }
        })
        .collect())
}

pub fn svc_workspaces(db_path: &str) -> ServiceResult<Vec<WorkspaceItem>> {
    let (recorded_by, db) = open_db_load(db_path)?;
    svc_workspaces_conn(&db, &recorded_by)
}

pub fn svc_intro_attempts(
    db_path: &str,
    peer: Option<&str>,
) -> ServiceResult<Vec<IntroAttemptItem>> {
    let (recorded_by, db) = open_db_load(db_path)?;

    let rows = crate::db::intro::list_intro_attempts(&db, &recorded_by, peer)?;
    Ok(rows
        .into_iter()
        .map(|r| IntroAttemptItem {
            intro_id: hex::encode(&r.intro_id),
            other_peer_id: r.other_peer_id,
            introduced_by_peer_id: r.introduced_by_peer_id,
            origin_ip: r.origin_ip,
            origin_port: r.origin_port,
            status: r.status,
            error: r.error,
            created_at: r.created_at,
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
    let endpoint = create_dual_endpoint_dynamic("0.0.0.0:0".parse().unwrap(), cert, key, dynamic_allow)?;

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
            Err(ServiceError(format!("Failed to send to both peers: {}", errors.join("; "))))
        } else {
            Err(ServiceError(format!("Partial send: {}", errors.join("; "))))
        }
    }
}

// ---------------------------------------------------------------------------
// Invite create / accept
// ---------------------------------------------------------------------------

/// Create a user invite for the active workspace.
///
/// Requires an existing bootstrapped identity (workspace + admin).
/// Returns an invite link with the bootstrap address and SPKI embedded.
pub fn svc_create_invite(
    db_path: &str,
    bootstrap_addr: &str,
) -> ServiceResult<CreateInviteResponse> {
    let (recorded_by, db) = open_db_load(db_path)
        .map_err(|e| ServiceError(format!("No transport identity: {}", e)))?;

    // Load workspace key from local_peer_signers + workspace lookup
    let workspace_id = db
        .query_row(
            "SELECT workspace_id FROM trust_anchors WHERE peer_id = ?1",
            [&recorded_by],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| ServiceError("No workspace found. Bootstrap a workspace first.".into()))?;

    let ws_eid = event_id_from_base64(&workspace_id)
        .ok_or_else(|| ServiceError("Invalid workspace_id in trust_anchors".into()))?;

    // Look up the workspace signing key from the workspace event's public key,
    // then find the matching signer. For invite creation we need the workspace
    // key stored during bootstrap (in local_peer_signers we only store peer_shared).
    // The workspace key is stored in a separate table by ensure_identity_chain.
    //
    // For now, we require the caller to have the workspace_key stored.
    // Check local_workspace_keys table (created by bootstrap).
    ensure_workspace_key_table(&db)?;
    let ws_key_bytes: Vec<u8> = db
        .query_row(
            "SELECT signing_key FROM local_workspace_keys WHERE recorded_by = ?1",
            [&recorded_by],
            |row| row.get(0),
        )
        .map_err(|_| ServiceError("No workspace signing key found. Only workspace creators can invite.".into()))?;

    if ws_key_bytes.len() != 32 {
        return Err(ServiceError("Corrupt workspace key".into()));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&ws_key_bytes);
    let workspace_key = SigningKey::from_bytes(&key_arr);

    let (sender_peer_eid, sender_peer_key) = load_local_peer_signer(&db, &recorded_by)?
        .ok_or_else(|| ServiceError("No local peer signer found for invite creation.".into()))?;
    let _ = crate::identity::ops::ensure_content_key_for_peer(
        &db,
        &recorded_by,
        &sender_peer_key,
        &sender_peer_eid,
    )
    .map_err(|e| ServiceError(format!("Failed to ensure content key: {}", e)))?;

    let invite = crate::identity::ops::create_user_invite(
        &db,
        &recorded_by,
        &workspace_key,
        &ws_eid,
        Some(&sender_peer_key),
        Some(&sender_peer_eid),
    )
    .map_err(|e| ServiceError(format!("Failed to create invite: {}", e)))?;

    // Record pending bootstrap trust so invitee can connect
    let pending_spki = crate::identity::transport::expected_invite_bootstrap_spki_from_invite_key(
        &invite.invite_key,
    )
    .map_err(|e| ServiceError(format!("Failed to derive invite SPKI: {}", e)))?;
    crate::db::transport_trust::record_pending_invite_bootstrap_trust(
        &db,
        &recorded_by,
        &event_id_to_base64(&invite.invite_event_id),
        &event_id_to_base64(&ws_eid),
        &pending_spki,
    )?;

    // Get local SPKI for the bootstrap address
    let spki_hex = &recorded_by;
    let spki_bytes = hex::decode(spki_hex)?;
    let mut bootstrap_spki = [0u8; 32];
    bootstrap_spki.copy_from_slice(&spki_bytes);

    let invite_link = crate::identity::invite_link::create_invite_link(&invite, bootstrap_addr, &bootstrap_spki)
        .map_err(|e| ServiceError(format!("Failed to create invite link: {}", e)))?;

    Ok(CreateInviteResponse {
        invite_link,
        invite_event_id: event_id_to_base64(&invite.invite_event_id),
    })
}

/// Accept a user invite via bootstrap sync + identity chain creation.
///
/// 1. Parses the invite link
/// 2. Installs bootstrap transport identity derived from invite key
/// 3. Connects to bootstrap address and syncs prerequisite events
/// 4. Creates identity chain (InviteAccepted → UserBoot → DeviceInvite → PeerShared)
/// 5. Records bootstrap trust and persists signer keys
pub async fn svc_accept_invite(
    db_path: &str,
    invite_link_str: &str,
    username: &str,
    devicename: &str,
) -> ServiceResult<AcceptInviteResponse> {
    let invite = crate::identity::invite_link::parse_invite_link(invite_link_str)
        .map_err(|e| ServiceError(format!("Invalid invite link: {}", e)))?;

    if invite.kind != crate::identity::invite_link::InviteLinkKind::User {
        return Err(ServiceError("Expected a user invite link (quiet://invite/...)".into()));
    }

    let invite_key = invite.invite_signing_key();
    let invite_event_id = invite.invite_event_id;
    let workspace_id = invite.workspace_id;

    // Initialize DB and install bootstrap transport identity
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }
    let recorded_by = crate::identity::transport::install_invite_bootstrap_transport_identity(
        db_path,
        &invite_key,
    )
    .map_err(|e| ServiceError(format!("Failed to install bootstrap identity: {}", e)))?;

    // Bootstrap sync: fetch prerequisite events from inviter
    let bootstrap_addr: std::net::SocketAddr =
        crate::identity::invite_link::resolve_bootstrap_socket_addr(&invite).map_err(|e| {
            ServiceError(format!(
                "Invalid bootstrap address '{}': {}",
                invite.bootstrap_addr, e
            ))
        })?;

    crate::peering::workflows::bootstrap::bootstrap_sync_from_invite(
        db_path,
        &recorded_by,
        bootstrap_addr,
        &invite.bootstrap_spki_fingerprint,
        15, // timeout seconds
        crate::event_pipeline::batch_writer,
    )
    .await
    .map_err(|e| ServiceError(format!("Bootstrap sync failed: {}", e)))?;

    // Verify prerequisite events arrived
    let db = open_connection(db_path)?;
    let ws_b64 = event_id_to_base64(&workspace_id);
    let ws_exists: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            [&ws_b64],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !ws_exists {
        return Err(ServiceError(
            "Bootstrap sync did not deliver workspace event. Ensure the inviter is running sync.".into(),
        ));
    }

    // Accept the invite: creates identity chain
    let join = crate::identity::ops::accept_user_invite(
        &db,
        &recorded_by,
        &invite_key,
        &invite_event_id,
        workspace_id,
        username,
        devicename,
    )
    .map_err(|e| ServiceError(format!("Failed to accept invite: {}", e)))?;
    if join.content_key_event_id.is_none() {
        return Err(ServiceError(
            "Invite acceptance missing wrapped content key material".into(),
        ));
    }

    // Record bootstrap trust
    crate::db::transport_trust::record_invite_bootstrap_trust(
        &db,
        &recorded_by,
        &event_id_to_base64(&join.invite_accepted_event_id),
        &event_id_to_base64(&invite_event_id),
        &event_id_to_base64(&workspace_id),
        &invite.bootstrap_addr,
        &invite.bootstrap_spki_fingerprint,
    )?;

    // Persist signer key so future commands can sign events
    let psf_b64 = event_id_to_base64(&join.peer_shared_event_id);
    persist_local_peer_signer(&db, &recorded_by, &psf_b64, &join.peer_shared_key)?;

    // Persist user key for device-link creation
    let ub_b64 = event_id_to_base64(&join.user_event_id);
    persist_local_user_key(&db, &recorded_by, &ub_b64, &join.user_key)?;

    // Push identity chain events back to inviter (while still using invite-derived
    // cert, which the inviter trusts via pending_invite_bootstrap_trust). This ensures
    // the inviter has our PeerShared event before we transition transport identity.
    drop(db);
    crate::peering::workflows::bootstrap::bootstrap_sync_from_invite(
        db_path,
        &recorded_by,
        bootstrap_addr,
        &invite.bootstrap_spki_fingerprint,
        15,
        crate::event_pipeline::batch_writer,
    )
    .await
    .map_err(|e| ServiceError(format!("Push-back sync failed: {}", e)))?;

    let db = open_connection(db_path)?;

    // Transition transport identity: replace invite-derived cert with
    // PeerShared-derived cert so transport and event-layer identities match.
    let new_peer_id = crate::identity::transport::install_peer_key_transport_identity(
        &db,
        &join.peer_shared_key,
    )
    .map_err(|e| ServiceError(format!("Failed to install peer key transport identity: {}", e)))?;
    crate::db::migrate_recorded_by(&db, &recorded_by, &new_peer_id)?;

    Ok(AcceptInviteResponse {
        peer_id: new_peer_id,
        user_event_id: event_id_to_base64(&join.user_event_id),
        peer_shared_event_id: psf_b64,
    })
}

/// Accept a device link invite via bootstrap sync + identity chain creation.
///
/// Mirrors `svc_accept_invite` but for device-link invites:
/// 1. Parses the invite link (expects `quiet://link/...`)
/// 2. Installs bootstrap transport identity derived from invite key
/// 3. Connects to bootstrap address and syncs prerequisite events
/// 4. Creates identity chain (InviteAccepted → PeerSharedFirst → TransportKey)
/// 5. Records bootstrap trust and persists signer keys
pub async fn svc_accept_device_link(
    db_path: &str,
    invite_link_str: &str,
    devicename: &str,
) -> ServiceResult<AcceptDeviceLinkResponse> {
    let invite = crate::identity::invite_link::parse_invite_link(invite_link_str)
        .map_err(|e| ServiceError(format!("Invalid invite link: {}", e)))?;

    if invite.kind != crate::identity::invite_link::InviteLinkKind::DeviceLink {
        return Err(ServiceError("Expected a device link (quiet://link/...)".into()));
    }

    let invite_key = invite.invite_signing_key();
    let invite_event_id = invite.invite_event_id;
    let workspace_id = invite.workspace_id;

    // Initialize DB and install bootstrap transport identity
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }
    let recorded_by = crate::identity::transport::install_invite_bootstrap_transport_identity(
        db_path,
        &invite_key,
    )
    .map_err(|e| ServiceError(format!("Failed to install bootstrap identity: {}", e)))?;

    // Bootstrap sync: fetch prerequisite events from inviter
    let bootstrap_addr: std::net::SocketAddr =
        crate::identity::invite_link::resolve_bootstrap_socket_addr(&invite).map_err(|e| {
            ServiceError(format!(
                "Invalid bootstrap address '{}': {}",
                invite.bootstrap_addr, e
            ))
        })?;

    crate::peering::workflows::bootstrap::bootstrap_sync_from_invite(
        db_path,
        &recorded_by,
        bootstrap_addr,
        &invite.bootstrap_spki_fingerprint,
        15,
        crate::event_pipeline::batch_writer,
    )
    .await
    .map_err(|e| ServiceError(format!("Bootstrap sync failed: {}", e)))?;

    // Accept the device link: creates identity chain
    let db = open_connection(db_path)?;
    let user_event_id = match invite.invite_type {
        crate::identity::ops::InviteType::DeviceLink { user_event_id } => user_event_id,
        _ => return Err(ServiceError("Expected DeviceLink invite type".into())),
    };
    let link = crate::identity::ops::accept_device_link(
        &db,
        &recorded_by,
        &invite_key,
        &invite_event_id,
        workspace_id,
        user_event_id,
        devicename,
    )
    .map_err(|e| ServiceError(format!("Failed to accept device link: {}", e)))?;

    // Record bootstrap trust
    crate::db::transport_trust::record_invite_bootstrap_trust(
        &db,
        &recorded_by,
        &event_id_to_base64(&link.invite_accepted_event_id),
        &event_id_to_base64(&invite_event_id),
        &event_id_to_base64(&workspace_id),
        &invite.bootstrap_addr,
        &invite.bootstrap_spki_fingerprint,
    )?;

    // Persist signer key
    let psf_b64 = event_id_to_base64(&link.peer_shared_event_id);
    persist_local_peer_signer(&db, &recorded_by, &psf_b64, &link.peer_shared_key)?;

    // Push identity chain events back to inviter (while still using invite-derived
    // cert, which the inviter trusts via pending_invite_bootstrap_trust).
    drop(db);
    crate::peering::workflows::bootstrap::bootstrap_sync_from_invite(
        db_path,
        &recorded_by,
        bootstrap_addr,
        &invite.bootstrap_spki_fingerprint,
        15,
        crate::event_pipeline::batch_writer,
    )
    .await
    .map_err(|e| ServiceError(format!("Push-back sync failed: {}", e)))?;

    let db = open_connection(db_path)?;

    // Transition transport identity: replace invite-derived cert with
    // PeerShared-derived cert so transport and event-layer identities match.
    let new_peer_id = crate::identity::transport::install_peer_key_transport_identity(
        &db,
        &link.peer_shared_key,
    )
    .map_err(|e| ServiceError(format!("Failed to install peer key transport identity: {}", e)))?;
    crate::db::migrate_recorded_by(&db, &recorded_by, &new_peer_id)?;

    Ok(AcceptDeviceLinkResponse {
        peer_id: new_peer_id,
        peer_shared_event_id: psf_b64,
    })
}

/// Ensure the local_workspace_keys table exists (stores workspace signing keys
/// for invite creation by workspace creators).
fn ensure_workspace_key_table(db: &rusqlite::Connection) -> ServiceResult<()> {
    db.execute(
        "CREATE TABLE IF NOT EXISTS local_workspace_keys (
            recorded_by TEXT PRIMARY KEY,
            signing_key BLOB NOT NULL,
            updated_at INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Persist the workspace signing key for later invite creation.
pub fn persist_workspace_key(
    db: &rusqlite::Connection,
    recorded_by: &str,
    workspace_key: &SigningKey,
) -> ServiceResult<()> {
    ensure_workspace_key_table(db)?;
    let now = current_timestamp_ms() as i64;
    db.execute(
        "INSERT INTO local_workspace_keys (recorded_by, signing_key, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(recorded_by)
         DO UPDATE SET signing_key = excluded.signing_key, updated_at = excluded.updated_at",
        rusqlite::params![recorded_by, workspace_key.to_bytes().as_slice(), now],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Response types for new daemon commands
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityResponse {
    pub transport_fingerprint: String,
    pub user_event_id: Option<String>,
    pub peer_shared_event_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BanResponse {
    pub target: String,
    pub banned: bool,
}

// ---------------------------------------------------------------------------
// Daemon-usable service wrappers (operate on peer_id, load keys from DB)
// ---------------------------------------------------------------------------

/// Create invite with an explicit SPKI hex (instead of using local transport SPKI).
pub fn svc_create_invite_with_spki(
    db_path: &str,
    public_addr: &str,
    public_spki_hex: &str,
) -> ServiceResult<CreateInviteResponse> {
    let (recorded_by, db) = open_db_load(db_path)
        .map_err(|e| ServiceError(format!("No transport identity: {}", e)))?;

    let workspace_id = db
        .query_row(
            "SELECT workspace_id FROM trust_anchors WHERE peer_id = ?1",
            [&recorded_by],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| ServiceError("No workspace found. Bootstrap a workspace first.".into()))?;

    let ws_eid = event_id_from_base64(&workspace_id)
        .ok_or_else(|| ServiceError("Invalid workspace_id in trust_anchors".into()))?;

    ensure_workspace_key_table(&db)?;
    let ws_key_bytes: Vec<u8> = db
        .query_row(
            "SELECT signing_key FROM local_workspace_keys WHERE recorded_by = ?1",
            [&recorded_by],
            |row| row.get(0),
        )
        .map_err(|_| ServiceError("No workspace signing key found.".into()))?;

    if ws_key_bytes.len() != 32 {
        return Err(ServiceError("Corrupt workspace key".into()));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&ws_key_bytes);
    let workspace_key = SigningKey::from_bytes(&key_arr);

    let (sender_peer_eid, sender_peer_key) = load_local_peer_signer(&db, &recorded_by)?
        .ok_or_else(|| ServiceError("No local peer signer found.".into()))?;

    let spki_bytes = hex::decode(public_spki_hex)?;
    let mut bootstrap_spki = [0u8; 32];
    if spki_bytes.len() != 32 {
        return Err(ServiceError("SPKI must be 32 bytes hex".into()));
    }
    bootstrap_spki.copy_from_slice(&spki_bytes);

    svc_create_invite_conn(
        &db,
        &recorded_by,
        &workspace_key,
        &ws_eid,
        &sender_peer_key,
        &sender_peer_eid,
        public_addr,
        &bootstrap_spki,
    )
}

/// Create a device link for a specific peer (daemon provides the peer_id).
/// Loads user_key from local_user_keys, workspace from trust_anchors.
pub fn svc_create_device_link_for_peer(
    db_path: &str,
    peer_id: &str,
    public_addr: &str,
    public_spki_hex: Option<&str>,
) -> ServiceResult<CreateInviteResponse> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    // Load user key from local_user_keys
    let (user_event_id, user_key) = load_local_user_key(&db, peer_id)?
        .ok_or_else(|| ServiceError("No local user key found. Only workspace creators/inviters can create device links.".into()))?;

    let workspace_id = resolve_workspace_for_peer(&db, peer_id)?;

    // Resolve SPKI: use provided or fall back to peer's transport SPKI
    let bootstrap_spki = if let Some(spki_hex) = public_spki_hex {
        let spki_bytes = hex::decode(spki_hex)?;
        if spki_bytes.len() != 32 {
            return Err(ServiceError("SPKI must be 32 bytes hex".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&spki_bytes);
        arr
    } else {
        let spki_bytes = hex::decode(peer_id)?;
        if spki_bytes.len() != 32 {
            return Err(ServiceError("peer_id is not valid 32-byte hex SPKI".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&spki_bytes);
        arr
    };

    svc_create_device_link_invite_conn(
        &db,
        peer_id,
        &user_key,
        &user_event_id,
        &workspace_id,
        public_addr,
        &bootstrap_spki,
    )
}

/// Ban (remove) a user for a specific peer.
/// Target selector: numeric (1-based user list index) or hex event ID.
pub fn svc_ban_for_peer(
    db_path: &str,
    peer_id: &str,
    target_selector: &str,
) -> ServiceResult<BanResponse> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let (signer_eid, signing_key) = require_local_peer_signer(&db, peer_id)?;

    // Resolve target: numeric → user list index, or hex event ID
    let target_event_id = if let Ok(num) = target_selector.parse::<usize>() {
        let users = svc_users_conn(&db, peer_id)?;
        if num == 0 || num > users.len() {
            return Err(ServiceError(format!(
                "Invalid user number {}. Available: 1-{}",
                num,
                users.len()
            )));
        }
        crate::crypto::event_id_from_base64(&users[num - 1].event_id)
            .ok_or_else(|| ServiceError("Invalid event ID for user".into()))?
    } else if target_selector.starts_with('#') {
        // #N syntax
        let num: usize = target_selector[1..]
            .parse()
            .map_err(|_| ServiceError(format!("Invalid user ref: {}", target_selector)))?;
        let users = svc_users_conn(&db, peer_id)?;
        if num == 0 || num > users.len() {
            return Err(ServiceError(format!(
                "Invalid user number {}. Available: 1-{}",
                num,
                users.len()
            )));
        }
        crate::crypto::event_id_from_base64(&users[num - 1].event_id)
            .ok_or_else(|| ServiceError("Invalid event ID for user".into()))?
    } else {
        // Hex event ID
        parse_hex_event_id(target_selector)?
    };

    svc_remove_user_conn(&db, peer_id, &signer_eid, &signing_key, target_event_id)?;

    Ok(BanResponse {
        target: hex::encode(target_event_id),
        banned: true,
    })
}

/// Get combined identity info for a specific peer.
pub fn svc_identity_for_peer(
    db_path: &str,
    peer_id: &str,
) -> ServiceResult<IdentityResponse> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    // User event ID from users table
    let user_event_id: Option<String> = db
        .query_row(
            "SELECT event_id FROM users WHERE recorded_by = ?1 LIMIT 1",
            rusqlite::params![peer_id],
            |row| row.get(0),
        )
        .optional()?;

    // Peer shared event ID from peers_shared table
    let peer_shared_event_id: Option<String> = db
        .query_row(
            "SELECT event_id FROM peers_shared WHERE recorded_by = ?1 LIMIT 1",
            rusqlite::params![peer_id],
            |row| row.get(0),
        )
        .optional()?;

    Ok(IdentityResponse {
        transport_fingerprint: peer_id.to_string(),
        user_event_id,
        peer_shared_event_id,
    })
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

    fn temp_db_path() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let path_str = path.to_str().unwrap().to_string();
        (dir, path_str)
    }

    fn setup_workspace(db_path: &str) -> String {
        let resp = svc_create_workspace(db_path, "test-workspace", "test-user", "test-device").unwrap();
        resp.peer_id
    }

    #[test]
    fn test_svc_send_succeeds_on_valid() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);

        let resp = svc_send_for_peer(&db_path, &peer_id, "hello").unwrap();
        assert_eq!(resp.content, "hello");
        assert!(!resp.event_id.is_empty());
    }

    #[test]
    fn test_svc_react_errors_on_blocked() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);

        // React to a non-existent target — reaction will block on missing dep
        let fake_target = hex::encode([0xDD_u8; 32]);
        let result = svc_react_for_peer(&db_path, &peer_id, &fake_target, "thumbsup");
        assert!(result.is_err(), "reaction to missing target should error, got: {:?}", result);
    }

    #[test]
    fn test_svc_delete_of_missing_target_writes_intent() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);

        // Delete a non-existent message — writes deletion_intent, returns Ok
        // (intent-only path for delete-before-create convergence)
        let fake_target = hex::encode([0xEE_u8; 32]);
        let result = svc_delete_message_for_peer(&db_path, &peer_id, &fake_target);
        assert!(result.is_ok(), "delete of missing target writes intent: {:?}", result);
    }

    #[test]
    fn test_resolve_message_selector_by_number() {
        let (_dir, db_path) = temp_db_path();
        let peer_id = setup_workspace(&db_path);

        // Send two messages so we have numbered targets.
        let msg1 = svc_send_for_peer(&db_path, &peer_id, "first").unwrap();
        let msg2 = svc_send_for_peer(&db_path, &peer_id, "second").unwrap();

        let (recorded_by, db) = open_db_for_peer(&db_path, &peer_id).unwrap();

        // Resolve by 1-based number.
        let eid1 = resolve_message_selector(&db, &recorded_by, "1").unwrap();
        assert_eq!(hex::encode(eid1), msg1.event_id);

        let eid2 = resolve_message_selector(&db, &recorded_by, "2").unwrap();
        assert_eq!(hex::encode(eid2), msg2.event_id);

        // Resolve with # prefix.
        let eid1_hash = resolve_message_selector(&db, &recorded_by, "#1").unwrap();
        assert_eq!(eid1, eid1_hash);

        // Resolve by raw hex.
        let eid_hex = resolve_message_selector(&db, &recorded_by, &msg1.event_id).unwrap();
        assert_eq!(eid1, eid_hex);

        // Invalid index.
        let err = resolve_message_selector(&db, &recorded_by, "99").unwrap_err();
        assert!(err.to_string().contains("invalid message number"), "{}", err);

        // Zero index.
        let err = resolve_message_selector(&db, &recorded_by, "0").unwrap_err();
        assert!(err.to_string().contains("must be >= 1"), "{}", err);
    }

    #[test]
    fn test_ensure_identity_chain_tolerates_workspace_blocked() {
        // Workspace is created before trust anchor exists, so it blocks.
        // ensure_identity_chain must handle this via staged API.
        // svc_create_workspace exercises this path.
        let (_dir, db_path) = temp_db_path();
        let resp = svc_create_workspace(&db_path, "test-workspace", "test-user", "test-device").unwrap();
        assert!(!resp.peer_id.is_empty());
        assert!(!resp.workspace_id.is_empty());

        // Calling again should be idempotent (returns existing workspace).
        let resp2 = svc_create_workspace(&db_path, "test-workspace", "test-user", "test-device").unwrap();
        assert_eq!(resp.peer_id, resp2.peer_id);
        assert_eq!(resp.workspace_id, resp2.workspace_id);
    }
}
