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
    transport_trust::{allowed_peers_from_db, import_cli_pins_to_sql, is_peer_allowed},
};
use crate::events::{
    DeviceInviteFirstEvent, InviteAcceptedEvent, MessageDeletionEvent, MessageEvent, ParsedEvent,
    PeerSharedFirstEvent, ReactionEvent, UserBootEvent, UserInviteBootEvent, WorkspaceEvent,
};
use crate::projection::create::{create_event_sync, create_signed_event_sync, CreateEventError};
use crate::projection::pipeline::project_one;
use crate::transport::{
    create_dual_endpoint, create_dual_endpoint_dynamic,
    AllowedPeers,
};
use crate::transport_identity::{
    ensure_transport_peer_id_from_db, ensure_transport_cert_from_db,
    load_transport_peer_id_from_db,
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

// ---------------------------------------------------------------------------
// Isolation wrapper for create-event helpers (Feedback item 1)
//
// Issue 3 may change the `event_id_or_blocked` API in projection::create.
// This local wrapper insulates the service layer from that churn — if the
// upstream signature changes we only need to update one site here.
// ---------------------------------------------------------------------------

/// Accept an event-creation result, treating `Blocked` as success (returns
/// the event_id) and propagating real errors.  Mirrors the semantics of
/// `projection::create::event_id_or_blocked` but is owned by the service
/// layer so upstream API changes don't ripple across every call site.
fn unwrap_event_id(result: Result<EventId, CreateEventError>) -> ServiceResult<EventId> {
    match result {
        Ok(eid) => Ok(eid),
        Err(CreateEventError::Blocked { event_id, .. }) => Ok(event_id),
        Err(e) => Err(ServiceError(format!("{}", e))),
    }
}

// ---------------------------------------------------------------------------
// Response types (all Serialize for JSON output)
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
pub struct MessageItem {
    pub id: String,
    pub author_id: String,
    pub content: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessagesResponse {
    pub messages: Vec<MessageItem>,
    pub total: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendResponse {
    pub content: String,
    pub event_id: String,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct ReactResponse {
    pub emoji: String,
    pub event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub target: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReactionItem {
    pub event_id: String,
    pub target_event_id: String,
    pub emoji: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserItem {
    pub event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysResponse {
    pub user_count: i64,
    pub peer_count: i64,
    pub admin_count: i64,
    pub transport_count: i64,
    pub users: Vec<String>,
    pub peers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceItem {
    pub event_id: String,
    pub workspace_id: String,
    pub name: String,
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

pub fn stable_author_id(peer_id: &str) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"author-id:");
    hasher.update(peer_id.as_bytes());
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
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

fn base64_to_hex(b64: &str) -> String {
    use base64::Engine;
    match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(bytes) => hex::encode(bytes),
        Err(_) => b64.to_string(),
    }
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

pub fn ensure_identity_chain(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ServiceResult<(EventId, SigningKey)> {
    if let Some((eid, signing_key)) = load_local_peer_signer(db, recorded_by)? {
        return Ok((eid, signing_key));
    }

    let mut rng = rand::thread_rng();

    let workspace_key = SigningKey::generate(&mut rng);
    let ws = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: workspace_key.verifying_key().to_bytes(),
    });
    let ws_eid = unwrap_event_id(create_event_sync(db, recorded_by, &ws))?;

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
        signed_by: dif_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let psf_eid = create_signed_event_sync(db, recorded_by, &psf, &device_invite_key)
        .map_err(|e| ServiceError(format!("{}", e)))?;

    let psf_b64 = event_id_to_base64(&psf_eid);
    persist_local_peer_signer(db, recorded_by, &psf_b64, &peer_shared_key)?;

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
        "message_count" => db
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e)),
        "reaction_count" => db
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
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
        other => Err(format!("unknown field: {}", other)),
    }
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

pub fn svc_transport_identity(db_path: &str) -> ServiceResult<TransportIdentityResponse> {
    let fingerprint = ensure_transport_peer_id_from_db(db_path)?;
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

pub fn svc_messages(db_path: &str, limit: usize) -> ServiceResult<MessagesResponse> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let limit_clause = if limit > 0 {
        format!("LIMIT {}", limit)
    } else {
        String::new()
    };

    let query = format!(
        "SELECT message_id, author_id, content, created_at
         FROM messages WHERE recorded_by = ?1 ORDER BY created_at ASC {}",
        limit_clause
    );

    let mut stmt = db.prepare(&query)?;
    let rows: Vec<(String, String, String, i64)> = stmt
        .query_map(rusqlite::params![&recorded_by], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let total: i64 = db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&recorded_by],
        |row| row.get(0),
    )?;

    let messages = rows
        .into_iter()
        .map(|(msg_id_b64, author_id, content, created_at)| MessageItem {
            id: base64_to_hex(&msg_id_b64),
            author_id,
            content,
            created_at,
        })
        .collect();

    Ok(MessagesResponse { messages, total })
}

pub fn svc_send(
    db_path: &str,
    workspace_hex: &str,
    content: &str,
) -> ServiceResult<SendResponse> {
    let recorded_by = ensure_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let (signer_eid, signing_key) = ensure_identity_chain(&db, &recorded_by)?;
    let workspace_id = parse_workspace_hex(workspace_hex)?;
    let author_id = stable_author_id(&recorded_by);

    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: current_timestamp_ms(),
        workspace_id,
        author_id,
        content: content.to_string(),
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = unwrap_event_id(create_signed_event_sync(&db, &recorded_by, &msg, &signing_key))?;

    Ok(SendResponse {
        content: content.to_string(),
        event_id: hex::encode(eid),
    })
}

pub fn svc_status(db_path: &str) -> ServiceResult<StatusResponse> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let events_count: i64 = db
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap_or(0);
    let messages_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let reactions_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let neg_items_count: i64 = db
        .query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
        .unwrap_or(0);
    let recorded_events_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![&recorded_by],
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

pub fn svc_generate(
    db_path: &str,
    count: usize,
    workspace_hex: &str,
) -> ServiceResult<GenerateResponse> {
    let recorded_by = ensure_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let (signer_eid, signing_key) = ensure_identity_chain(&db, &recorded_by)?;
    let workspace_id = parse_workspace_hex(workspace_hex)?;
    let author_id: [u8; 32] = rand::random();

    db.execute("BEGIN", [])?;
    for i in 0..count {
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: current_timestamp_ms(),
            workspace_id,
            author_id,
            content: format!("Message {}", i),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        create_signed_event_sync(&db, &recorded_by, &msg, &signing_key)
            .map_err(|e| ServiceError(format!("create event error: {}", e)))?;
    }
    db.execute("COMMIT", [])?;

    Ok(GenerateResponse { count })
}

pub fn svc_assert_now(
    db_path: &str,
    predicate_str: &str,
) -> ServiceResult<AssertResponse> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let (field, op, expected) =
        parse_predicate(predicate_str).map_err(ServiceError)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;
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
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let (field, op, expected) =
        parse_predicate(predicate_str).map_err(ServiceError)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;
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

pub fn svc_react(
    db_path: &str,
    target_hex: &str,
    emoji: &str,
) -> ServiceResult<ReactResponse> {
    let recorded_by = ensure_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let (signer_eid, signing_key) = ensure_identity_chain(&db, &recorded_by)?;
    let target_event_id = parse_hex_event_id(target_hex)?;
    let author_id = stable_author_id(&recorded_by);

    let rxn = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: current_timestamp_ms(),
        target_event_id,
        author_id,
        emoji: emoji.to_string(),
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = unwrap_event_id(create_signed_event_sync(&db, &recorded_by, &rxn, &signing_key))?;

    Ok(ReactResponse {
        emoji: emoji.to_string(),
        event_id: hex::encode(eid),
    })
}

pub fn svc_delete_message(
    db_path: &str,
    target_hex: &str,
) -> ServiceResult<DeleteResponse> {
    let recorded_by = ensure_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let (signer_eid, signing_key) = ensure_identity_chain(&db, &recorded_by)?;
    let target_event_id = parse_hex_event_id(target_hex)?;
    let author_id = stable_author_id(&recorded_by);

    let del = ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms: current_timestamp_ms(),
        target_event_id,
        author_id,
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    unwrap_event_id(create_signed_event_sync(&db, &recorded_by, &del, &signing_key))?;

    Ok(DeleteResponse {
        target: target_hex.to_string(),
    })
}

pub fn svc_reactions(db_path: &str) -> ServiceResult<Vec<ReactionItem>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let mut stmt = db
        .prepare("SELECT event_id, target_event_id, emoji FROM reactions WHERE recorded_by = ?1")?;
    let rows: Vec<(String, String, String)> = stmt
        .query_map(rusqlite::params![&recorded_by], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows
        .into_iter()
        .map(|(event_id, target_event_id, emoji)| ReactionItem {
            event_id,
            target_event_id,
            emoji,
        })
        .collect())
}

pub fn svc_users(db_path: &str) -> ServiceResult<Vec<UserItem>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let mut stmt = db.prepare("SELECT event_id FROM users WHERE recorded_by = ?1")?;
    let users: Vec<String> = stmt
        .query_map(rusqlite::params![&recorded_by], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(users
        .into_iter()
        .map(|event_id| UserItem { event_id })
        .collect())
}

pub fn svc_keys(db_path: &str, summary: bool) -> ServiceResult<KeysResponse> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let user_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let peer_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let admin_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM admins WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let transport_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM transport_keys WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let mut users = Vec::new();
    let mut peers = Vec::new();

    if !summary {
        let mut stmt = db.prepare("SELECT event_id FROM users WHERE recorded_by = ?1")?;
        users = stmt
            .query_map(rusqlite::params![&recorded_by], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut stmt = db.prepare("SELECT event_id FROM peers_shared WHERE recorded_by = ?1")?;
        peers = stmt
            .query_map(rusqlite::params![&recorded_by], |row| {
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
    })
}

pub fn svc_workspaces(db_path: &str) -> ServiceResult<Vec<WorkspaceItem>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let mut stmt =
        db.prepare("SELECT event_id, workspace_id FROM workspaces WHERE recorded_by = ?1")?;
    let workspaces: Vec<(String, String)> = stmt
        .query_map(rusqlite::params![&recorded_by], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    use base64::Engine;
    Ok(workspaces
        .into_iter()
        .map(|(eid, ws_id_b64)| {
            let name =
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&ws_id_b64) {
                    String::from_utf8_lossy(&bytes)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    ws_id_b64.clone()
                };
            WorkspaceItem {
                event_id: eid,
                workspace_id: ws_id_b64,
                name,
            }
        })
        .collect())
}

pub fn svc_intro_attempts(
    db_path: &str,
    peer: Option<&str>,
) -> ServiceResult<Vec<IntroAttemptItem>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let recorded_by = ensure_transport_peer_id_from_db(db_path)?;

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

// ---------------------------------------------------------------------------
// Sync (long-running, used by daemon)
// ---------------------------------------------------------------------------

pub async fn svc_sync(
    bind: std::net::SocketAddr,
    connect: Option<std::net::SocketAddr>,
    db_path: &str,
    pin_peers: &[String],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::Arc;
    use crate::sync::engine::{accept_loop, connect_loop};
    use tracing::info;

    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    let (recorded_by, cert, key) = ensure_transport_cert_from_db(db_path)?;

    let cli_pins = AllowedPeers::from_hex_strings(pin_peers)?;
    {
        let db = open_connection(db_path)?;
        import_cli_pins_to_sql(&db, &recorded_by, &cli_pins)?;
        let combined = allowed_peers_from_db(&db, &recorded_by)?;
        if combined.is_empty() {
            return Err("No allowed peers: provide --pin-peer for bootstrap, accept an invite link, or ensure identity events have synced. \
                Use `poc-7 transport-identity --db <peer-db>` to get a peer's fingerprint.".into());
        }
    }

    let db_path_for_lookup = db_path.to_string();
    let recorded_by_for_lookup = recorded_by.clone();
    let dynamic_allow = Arc::new(move |peer_fp: &[u8; 32]| {
        let db = open_connection(&db_path_for_lookup)?;
        is_peer_allowed(&db, &recorded_by_for_lookup, peer_fp)
    });
    let endpoint = create_dual_endpoint_dynamic(bind, cert, key, dynamic_allow)?;
    info!("Listening on {}", endpoint.local_addr()?);

    let db_owned = db_path.to_string();
    let recorded_by_clone = recorded_by.clone();
    let accept_endpoint = endpoint.clone();
    let accept_handle = tokio::task::spawn_blocking({
        let db = db_owned.clone();
        move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = accept_loop(
                    &db,
                    &recorded_by_clone,
                    accept_endpoint,
                )
                .await
                {
                    tracing::warn!("accept_loop exited: {}", e);
                }
            });
        }
    });

    if let Some(remote) = connect {
        let connect_endpoint = endpoint.clone();
        let db = db_owned.clone();
        let recorded_by_clone = recorded_by.clone();
        let connect_handle = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = connect_loop(
                    &db,
                    &recorded_by_clone,
                    connect_endpoint,
                    remote,
                )
                .await
                {
                    tracing::warn!("connect_loop exited: {}", e);
                }
            });
        });

        tokio::select! {
            _ = accept_handle => {}
            _ = connect_handle => {}
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down");
            }
        }
    } else {
        tokio::select! {
            _ = accept_handle => {}
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down");
            }
        }
    }

    Ok(())
}

pub async fn svc_intro(
    db_path: &str,
    peer_a: &str,
    peer_b: &str,
    pin_peers: &[String],
    ttl_ms: u64,
    attempt_window_ms: u32,
) -> ServiceResult<bool> {
    use std::sync::Arc;

    let db = open_connection(db_path)?;
    create_tables(&db)?;
    drop(db);

    let (recorded_by, cert, key) = ensure_transport_cert_from_db(db_path)?;

    let mut all_pins = pin_peers.to_vec();
    if !all_pins.contains(&peer_a.to_string()) {
        all_pins.push(peer_a.to_string());
    }
    if !all_pins.contains(&peer_b.to_string()) {
        all_pins.push(peer_b.to_string());
    }
    let cli_pins = AllowedPeers::from_hex_strings(&all_pins)?;
    let db = open_connection(db_path)?;
    import_cli_pins_to_sql(&db, &recorded_by, &cli_pins)?;
    let allowed = allowed_peers_from_db(&db, &recorded_by)?;
    drop(db);

    let endpoint = create_dual_endpoint("0.0.0.0:0".parse().unwrap(), cert, key, Arc::new(allowed))?;

    let result = crate::sync::intro::run_intro(
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
// Socket path helper
// ---------------------------------------------------------------------------

/// Derive the RPC socket path from a DB path.
/// Uses `<db_path>.p7d.sock` — same directory as the database file.
pub fn socket_path_for_db(db_path: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(db_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    abs.with_extension("p7d.sock")
}
