use rusqlite::{Connection, OptionalExtension};

use super::super::layout::field_spec::{decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{
    Describe, EventError, ParsedEvent, EVENT_TYPE_INBOUND_CONNECTION_AUTHENTICATED,
    EVENT_TYPE_OUTBOUND_CONNECTION_AUTHENTICATED, EVENT_TYPE_SYNC_ROUND_STARTED,
};
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{
    ContextSnapshot, ProjectorResult, SqlVal, SyncConnectionSnapshot, SyncRoundSnapshot, WriteOp,
};
use crate::projection::create::{create_event_synchronous, CreateEventError};

const CONNECTION_ID_BYTES: usize = 256;
const TENANT_ID_BYTES: usize = 64;
const PEER_ID_BYTES: usize = 64;
const WINDOW_KIND_BYTES: usize = 16;
const NONE_TS_SENTINEL: i64 = i64::MIN;

pub const SYNC_ROUND_STARTED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("basis_event_id"),
    FieldSpec::Text("connection_id", CONNECTION_ID_BYTES),
    FieldSpec::Text("tenant_id", TENANT_ID_BYTES),
    FieldSpec::Text("peer_id", PEER_ID_BYTES),
    FieldSpec::U64("session_id"),
    FieldSpec::U8("round_role"),
    FieldSpec::Text("window_kind", WINDOW_KIND_BYTES),
    FieldSpec::I64("ts_min_inclusive_ms"),
    FieldSpec::I64("ts_max_exclusive_ms"),
    FieldSpec::I64("planner_next_idx_before"),
    FieldSpec::I64("planner_cycle_anchor_now_ms"),
];
const SYNC_ROUND_STARTED_WIRE_SIZE: usize = wire_size_for_fields(SYNC_ROUND_STARTED_FIELDS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncRoundRole {
    Initiator,
    Responder,
}

impl SyncRoundRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Initiator => 1,
            Self::Responder => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Initiator),
            2 => Some(Self::Responder),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRoundStartedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub connection_id: String,
    pub tenant_id: String,
    pub peer_id: String,
    pub session_id: u64,
    pub round_role: SyncRoundRole,
    pub window_kind: String,
    pub ts_min_inclusive_ms: Option<i64>,
    pub ts_max_exclusive_ms: Option<i64>,
    pub planner_next_idx_before: Option<i64>,
    pub planner_cycle_anchor_now_ms: Option<i64>,
}

impl Describe for SyncRoundStartedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("connection_id", self.connection_id.clone()),
            ("tenant_id", self.tenant_id.clone()),
            ("peer_id", self.peer_id.clone()),
            ("session_id", self.session_id.to_string()),
            ("round_role", self.round_role.as_str().to_string()),
            ("window_kind", self.window_kind.clone()),
        ];
        if let Some(ts) = self.ts_min_inclusive_ms {
            fields.push(("ts_min_inclusive_ms", ts.to_string()));
        }
        if let Some(ts) = self.ts_max_exclusive_ms {
            fields.push(("ts_max_exclusive_ms", ts.to_string()));
        }
        fields
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRoundRow {
    pub latest_event_id: String,
    pub round_id: String,
    pub recorded_by: String,
    pub tenant_id: String,
    pub connection_id: String,
    pub peer_id: String,
    pub session_id: i64,
    pub round_role: String,
    pub window_kind: String,
    pub ts_min_inclusive_ms: Option<i64>,
    pub ts_max_exclusive_ms: Option<i64>,
    pub planner_next_idx_before: Option<i64>,
    pub planner_cycle_anchor_now_ms: Option<i64>,
    pub lifecycle_kind: String,
    pub outcome: Option<String>,
    pub detail: Option<String>,
    pub basis_event_id: String,
    pub created_at_ms: i64,
}

impl SyncRoundRow {
    pub fn snapshot(&self) -> SyncRoundSnapshot {
        SyncRoundSnapshot {
            event_id: self.latest_event_id.clone(),
            round_id: self.round_id.clone(),
            recorded_by: self.recorded_by.clone(),
            tenant_id: self.tenant_id.clone(),
            connection_id: self.connection_id.clone(),
            peer_id: self.peer_id.clone(),
            session_id: self.session_id,
            round_role: self.round_role.clone(),
            window_kind: self.window_kind.clone(),
            ts_min_inclusive_ms: self.ts_min_inclusive_ms,
            ts_max_exclusive_ms: self.ts_max_exclusive_ms,
            planner_next_idx_before: self.planner_next_idx_before,
            planner_cycle_anchor_now_ms: self.planner_cycle_anchor_now_ms,
            lifecycle_kind: self.lifecycle_kind.clone(),
            outcome: self.outcome.clone(),
            detail: self.detail.clone(),
            basis_event_id: self.basis_event_id.clone(),
            created_at_ms: self.created_at_ms,
        }
    }
}

fn query_round_row(
    conn: &Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> rusqlite::Result<Option<SyncRoundRow>> {
    conn.query_row(sql, params, |row| {
        Ok(SyncRoundRow {
            latest_event_id: row.get(0)?,
            round_id: row.get(1)?,
            recorded_by: row.get(2)?,
            tenant_id: row.get(3)?,
            connection_id: row.get(4)?,
            peer_id: row.get(5)?,
            session_id: row.get(6)?,
            round_role: row.get(7)?,
            window_kind: row.get(8)?,
            ts_min_inclusive_ms: row.get(9)?,
            ts_max_exclusive_ms: row.get(10)?,
            planner_next_idx_before: row.get(11)?,
            planner_cycle_anchor_now_ms: row.get(12)?,
            lifecycle_kind: row.get(13)?,
            outcome: row.get(14)?,
            detail: row.get(15)?,
            basis_event_id: row.get(16)?,
            created_at_ms: row.get(17)?,
        })
    })
    .optional()
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS sync_round_history (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            round_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            session_id INTEGER NOT NULL,
            round_role TEXT NOT NULL,
            window_kind TEXT NOT NULL,
            ts_min_inclusive_ms INTEGER,
            ts_max_exclusive_ms INTEGER,
            planner_next_idx_before INTEGER,
            planner_cycle_anchor_now_ms INTEGER,
            lifecycle_kind TEXT NOT NULL,
            outcome TEXT,
            detail TEXT,
            events_sent INTEGER,
            events_received INTEGER,
            neg_rounds INTEGER,
            bytes_sent INTEGER,
            bytes_received INTEGER,
            duration_ms INTEGER,
            basis_event_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sync_round_history_latest
            ON sync_round_history(recorded_by, round_id, created_at DESC, event_id DESC);
        ",
    )?;
    Ok(())
}

pub fn load_round(
    conn: &Connection,
    recorded_by: &str,
    round_id: &str,
) -> rusqlite::Result<Option<SyncRoundRow>> {
    query_round_row(
        conn,
        "SELECT
             event_id,
             round_id,
             recorded_by,
             tenant_id,
             connection_id,
             peer_id,
             session_id,
             round_role,
             window_kind,
             ts_min_inclusive_ms,
             ts_max_exclusive_ms,
             planner_next_idx_before,
             planner_cycle_anchor_now_ms,
             lifecycle_kind,
             outcome,
             detail,
             basis_event_id,
             created_at
         FROM sync_round_history
         WHERE recorded_by = ?1 AND round_id = ?2
           AND NOT EXISTS (
               SELECT 1
               FROM sync_round_history newer
               WHERE newer.recorded_by = sync_round_history.recorded_by
                 AND newer.round_id = sync_round_history.round_id
                 AND newer.basis_event_id = sync_round_history.event_id
           )
         ORDER BY created_at DESC, event_id DESC
         LIMIT 1",
        &[&recorded_by, &round_id],
    )
}

pub fn load_active_round_for_session(
    conn: &Connection,
    recorded_by: &str,
    session_id: i64,
) -> rusqlite::Result<Option<SyncRoundRow>> {
    query_round_row(
        conn,
        "SELECT
             event_id,
             round_id,
             recorded_by,
             tenant_id,
             connection_id,
             peer_id,
             session_id,
             round_role,
             window_kind,
             ts_min_inclusive_ms,
             ts_max_exclusive_ms,
             planner_next_idx_before,
             planner_cycle_anchor_now_ms,
             lifecycle_kind,
             outcome,
             detail,
             basis_event_id,
             created_at
         FROM sync_round_history
         WHERE recorded_by = ?1
           AND session_id = ?2
           AND lifecycle_kind = 'started'
           AND NOT EXISTS (
               SELECT 1
               FROM sync_round_history newer
               WHERE newer.recorded_by = sync_round_history.recorded_by
                 AND newer.basis_event_id = sync_round_history.event_id
           )
         ORDER BY created_at DESC, event_id DESC
         LIMIT 1",
        &[&recorded_by, &session_id],
    )
}

pub fn load_snapshot_by_event_id(
    conn: &Connection,
    recorded_by: &str,
    event_id: &str,
) -> rusqlite::Result<Option<SyncRoundRow>> {
    query_round_row(
        conn,
        "SELECT
             event_id,
             round_id,
             recorded_by,
             tenant_id,
             connection_id,
             peer_id,
             session_id,
             round_role,
             window_kind,
             ts_min_inclusive_ms,
             ts_max_exclusive_ms,
             planner_next_idx_before,
             planner_cycle_anchor_now_ms,
             lifecycle_kind,
             outcome,
             detail,
             basis_event_id,
             created_at
         FROM sync_round_history
         WHERE recorded_by = ?1 AND event_id = ?2",
        &[&recorded_by, &event_id],
    )
}

fn query_sync_connection_snapshot(
    conn: &Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> rusqlite::Result<Option<SyncConnectionSnapshot>> {
    conn.query_row(sql, params, |row| {
        Ok(SyncConnectionSnapshot {
            event_id: row.get(0)?,
            recorded_by: row.get(1)?,
            tenant_id: row.get(2)?,
            connection_id: row.get(3)?,
            lifecycle_kind: row.get(4)?,
            remote_peer_id: row.get(5)?,
            remote_addr: row.get(6)?,
            created_at_ms: row.get(7)?,
        })
    })
    .optional()
}

pub fn load_outbound_basis_for_peer(
    conn: &Connection,
    tenant_id: &str,
    peer_id: &str,
) -> rusqlite::Result<Option<SyncConnectionSnapshot>> {
    query_sync_connection_snapshot(
        conn,
        "SELECT
             event_id,
             tenant_id,
             tenant_id,
             connection_id,
             lifecycle_kind,
             remote_peer_id,
             remote_addr,
             created_at
         FROM outbound_connection_history
         WHERE tenant_id = ?1
           AND remote_peer_id = ?2
           AND lifecycle_kind = 'authenticated'
           AND NOT EXISTS (
               SELECT 1
               FROM outbound_connection_history newer
               WHERE newer.tenant_id = outbound_connection_history.tenant_id
                 AND newer.connection_id = outbound_connection_history.connection_id
                 AND newer.basis_event_id = outbound_connection_history.event_id
           )
         ORDER BY created_at DESC, event_id DESC
         LIMIT 1",
        &[&tenant_id, &peer_id],
    )
}

pub fn load_inbound_basis_for_peer(
    conn: &Connection,
    client_id: &str,
    tenant_id: &str,
    peer_id: &str,
) -> rusqlite::Result<Option<SyncConnectionSnapshot>> {
    query_sync_connection_snapshot(
        conn,
        "SELECT
             event_id,
             recorded_by,
             tenant_id,
             connection_id,
             lifecycle_kind,
             remote_peer_id,
             remote_addr,
             created_at
         FROM inbound_connection_history
         WHERE recorded_by = ?1
           AND tenant_id = ?2
           AND remote_peer_id = ?3
           AND lifecycle_kind = 'authenticated'
           AND NOT EXISTS (
               SELECT 1
               FROM inbound_connection_history newer
               WHERE newer.recorded_by = inbound_connection_history.recorded_by
                 AND newer.connection_id = inbound_connection_history.connection_id
                 AND newer.basis_event_id = inbound_connection_history.event_id
           )
         ORDER BY created_at DESC, event_id DESC
         LIMIT 1",
        &[&client_id, &tenant_id, &peer_id],
    )
}

pub fn parse_sync_round_started(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_SYNC_ROUND_STARTED, SYNC_ROUND_STARTED_FIELDS, blob)?;
    let created_at_ms = values[0].as_timestamp().unwrap();
    let basis_event_id = values[1].as_event_id().unwrap();
    let connection_id = values[2].as_text().unwrap().to_string();
    let tenant_id = values[3].as_text().unwrap().to_string();
    let peer_id = values[4].as_text().unwrap().to_string();
    let session_id = values[5].as_u64().unwrap();
    let round_role = SyncRoundRole::from_code(values[6].as_u8().unwrap())
        .ok_or(EventError::InvalidMetadata("invalid sync round role"))?;
    let window_kind = values[7].as_text().unwrap().to_string();
    let ts_min_raw = values[8].as_i64().unwrap();
    let ts_min_inclusive_ms = (ts_min_raw != NONE_TS_SENTINEL).then_some(ts_min_raw);
    let ts_max_raw = values[9].as_i64().unwrap();
    let ts_max_exclusive_ms = (ts_max_raw != NONE_TS_SENTINEL).then_some(ts_max_raw);
    let pnib_raw = values[10].as_i64().unwrap();
    let planner_next_idx_before = (pnib_raw != NONE_TS_SENTINEL).then_some(pnib_raw);
    let pcan_raw = values[11].as_i64().unwrap();
    let planner_cycle_anchor_now_ms = (pcan_raw != NONE_TS_SENTINEL).then_some(pcan_raw);

    Ok(ParsedEvent::SyncRoundStarted(SyncRoundStartedEvent {
        created_at_ms,
        basis_event_id,
        connection_id,
        tenant_id,
        peer_id,
        session_id,
        round_role,
        window_kind,
        ts_min_inclusive_ms,
        ts_max_exclusive_ms,
        planner_next_idx_before,
        planner_cycle_anchor_now_ms,
    }))
}
pub fn encode_sync_round_started(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let started = match event {
        ParsedEvent::SyncRoundStarted(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(started.created_at_ms),
        FieldValue::EventId(started.basis_event_id),
        FieldValue::Text(started.connection_id.clone()),
        FieldValue::Text(started.tenant_id.clone()),
        FieldValue::Text(started.peer_id.clone()),
        FieldValue::U64(started.session_id),
        FieldValue::U8(started.round_role.code()),
        FieldValue::Text(started.window_kind.clone()),
        FieldValue::I64(started.ts_min_inclusive_ms.unwrap_or(NONE_TS_SENTINEL)),
        FieldValue::I64(started.ts_max_exclusive_ms.unwrap_or(NONE_TS_SENTINEL)),
        FieldValue::I64(started.planner_next_idx_before.unwrap_or(NONE_TS_SENTINEL)),
        FieldValue::I64(started.planner_cycle_anchor_now_ms.unwrap_or(NONE_TS_SENTINEL)),
    ];
    Ok(encode_fields(EVENT_TYPE_SYNC_ROUND_STARTED, SYNC_ROUND_STARTED_FIELDS, &values)?)
}
fn validate(event: &SyncRoundStartedEvent) -> Result<(), String> {
    if event.connection_id.trim().is_empty() {
        return Err("sync_round_started requires non-empty connection_id".to_string());
    }
    if event.tenant_id.trim().is_empty() {
        return Err("sync_round_started requires non-empty tenant_id".to_string());
    }
    if event.peer_id.trim().is_empty() {
        return Err("sync_round_started requires non-empty peer_id".to_string());
    }
    if event.session_id == 0 {
        return Err("sync_round_started requires non-zero session_id".to_string());
    }
    if event.window_kind.trim().is_empty() {
        return Err("sync_round_started requires non-empty window_kind".to_string());
    }
    if let (Some(min), Some(max)) = (event.ts_min_inclusive_ms, event.ts_max_exclusive_ms) {
        if max < min {
            return Err("sync_round_started range max must be >= min".to_string());
        }
    }
    Ok(())
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let started = match parsed {
        ParsedEvent::SyncRoundStarted(event) => event,
        _ => return Err("sync_round_started context loader called for wrong event".into()),
    };

    let basis_event_id = event_id_to_base64(&started.basis_event_id);
    let mut ctx = ContextSnapshot::default();

    let outbound = query_sync_connection_snapshot(
        conn,
        "SELECT
             event_id,
             tenant_id,
             tenant_id,
             connection_id,
             lifecycle_kind,
             remote_peer_id,
             remote_addr,
             created_at
         FROM outbound_connection_history
         WHERE tenant_id = ?1 AND event_id = ?2",
        &[&recorded_by, &basis_event_id],
    )?;
    if let Some(snapshot) = outbound {
        let latest =
            load_outbound_basis_for_peer(conn, &snapshot.tenant_id, &snapshot.remote_peer_id)?;
        ctx.sync_connection_snapshot = Some(snapshot.clone());
        if let Some(latest) = latest {
            if latest.event_id != basis_event_id {
                ctx.sync_connection_basis_mismatch_reason = Some(format!(
                    "sync_round_started basis_event_id {} is stale; latest outbound connection event is {}",
                    basis_event_id, latest.event_id
                ));
            }
        }
        return Ok(ctx);
    }

    let inbound = query_sync_connection_snapshot(
        conn,
        "SELECT
             event_id,
             recorded_by,
             tenant_id,
             connection_id,
             lifecycle_kind,
             remote_peer_id,
             remote_addr,
             created_at
         FROM inbound_connection_history
         WHERE recorded_by = ?1 AND event_id = ?2",
        &[&recorded_by, &basis_event_id],
    )?;
    if let Some(snapshot) = inbound {
        let latest = load_inbound_basis_for_peer(
            conn,
            recorded_by,
            &snapshot.tenant_id,
            &snapshot.remote_peer_id,
        )?;
        ctx.sync_connection_snapshot = Some(snapshot.clone());
        if let Some(latest) = latest {
            if latest.event_id != basis_event_id {
                ctx.sync_connection_basis_mismatch_reason = Some(format!(
                    "sync_round_started basis_event_id {} is stale; latest inbound connection event is {}",
                    basis_event_id, latest.event_id
                ));
            }
        }
    }

    Ok(ctx)
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let started = match parsed {
        ParsedEvent::SyncRoundStarted(event) => event,
        _ => return ProjectorResult::reject("not a sync_round_started event".to_string()),
    };

    if let Err(reason) = validate(started) {
        return ProjectorResult::reject(reason);
    }
    if let Some(reason) = &ctx.sync_connection_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.sync_connection_snapshot else {
        return ProjectorResult::reject(
            "sync_round_started missing connection basis snapshot context".to_string(),
        );
    };
    if snapshot.connection_id != started.connection_id {
        return ProjectorResult::reject(
            "sync_round_started connection_id does not match basis snapshot".to_string(),
        );
    }
    if snapshot.tenant_id != started.tenant_id {
        return ProjectorResult::reject(
            "sync_round_started tenant_id does not match basis snapshot".to_string(),
        );
    }
    if snapshot.remote_peer_id != started.peer_id {
        return ProjectorResult::reject(
            "sync_round_started peer_id does not match basis snapshot".to_string(),
        );
    }

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "sync_round_history",
        columns: vec![
            "recorded_by",
            "event_id",
            "round_id",
            "tenant_id",
            "connection_id",
            "peer_id",
            "session_id",
            "round_role",
            "window_kind",
            "ts_min_inclusive_ms",
            "ts_max_exclusive_ms",
            "planner_next_idx_before",
            "planner_cycle_anchor_now_ms",
            "lifecycle_kind",
            "outcome",
            "detail",
            "events_sent",
            "events_received",
            "neg_rounds",
            "bytes_sent",
            "bytes_received",
            "duration_ms",
            "basis_event_id",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(started.tenant_id.clone()),
            SqlVal::Text(started.connection_id.clone()),
            SqlVal::Text(started.peer_id.clone()),
            SqlVal::Int(started.session_id as i64),
            SqlVal::Text(started.round_role.as_str().to_string()),
            SqlVal::Text(started.window_kind.clone()),
            started
                .ts_min_inclusive_ms
                .map(SqlVal::Int)
                .unwrap_or(SqlVal::Null),
            started
                .ts_max_exclusive_ms
                .map(SqlVal::Int)
                .unwrap_or(SqlVal::Null),
            started
                .planner_next_idx_before
                .map(SqlVal::Int)
                .unwrap_or(SqlVal::Null),
            started
                .planner_cycle_anchor_now_ms
                .map(SqlVal::Int)
                .unwrap_or(SqlVal::Null),
            SqlVal::Text("started".to_string()),
            SqlVal::Null,
            SqlVal::Null,
            SqlVal::Null,
            SqlVal::Null,
            SqlVal::Null,
            SqlVal::Null,
            SqlVal::Null,
            SqlVal::Null,
            SqlVal::Text(snapshot.event_id.clone()),
            SqlVal::Int(started.created_at_ms as i64),
        ],
    }])
}

pub static SYNC_ROUND_STARTED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_SYNC_ROUND_STARTED,
    type_name: "sync_round_started",
    projection_table: "sync_round_history",
    share_scope: ShareScope::Local,
    dep_fields: &["basis_event_id"],
    dep_field_type_codes: &[&[
        EVENT_TYPE_OUTBOUND_CONNECTION_AUTHENTICATED,
        EVENT_TYPE_INBOUND_CONNECTION_AUTHENTICATED,
    ]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_sync_round_started,
    encode: encode_sync_round_started,
    projector: project_pure,
    context_loader: build_projector_context,
};

#[allow(clippy::too_many_arguments)]
pub fn create_sync_round_started(
    conn: &Connection,
    recorded_by: &str,
    basis_event_id: [u8; 32],
    connection_id: &str,
    tenant_id: &str,
    peer_id: &str,
    session_id: u64,
    round_role: SyncRoundRole,
    window_kind: &str,
    ts_min_inclusive_ms: Option<i64>,
    ts_max_exclusive_ms: Option<i64>,
    planner_next_idx_before: Option<i64>,
    planner_cycle_anchor_now_ms: Option<i64>,
) -> Result<[u8; 32], CreateEventError> {
    let event = ParsedEvent::SyncRoundStarted(SyncRoundStartedEvent {
        created_at_ms: crate::db::queue::current_timestamp_ms() as u64,
        basis_event_id,
        connection_id: connection_id.to_string(),
        tenant_id: tenant_id.to_string(),
        peer_id: peer_id.to_string(),
        session_id,
        round_role,
        window_kind: window_kind.to_string(),
        ts_min_inclusive_ms,
        ts_max_exclusive_ms,
        planner_next_idx_before,
        planner_cycle_anchor_now_ms,
    });
    create_event_synchronous(conn, recorded_by, &event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::client_lifecycle::{mark_runtime_active, start_runtime};
    use crate::event_modules::operational::connection_plan_transitioned::create_connection_plan_transitioned;
    use crate::event_modules::operational::connection_planned::{
        create_connection_planned, discovery_connection_id, ConnectionPlanSourceKind,
        ConnectionPlanStatus,
    };
    use crate::event_modules::operational::inbound_connection_authenticated::{
        create_inbound_connection_authenticated, inbound_connection_id,
    };
    use crate::event_modules::operational::outbound_connection_authenticated::create_outbound_connection_authenticated;
    use crate::projection::create::CreateEventError;
    use std::net::SocketAddr;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse().unwrap(), port)
    }

    fn setup_outbound_basis(conn: &Connection, tenant_id: &str, peer_id: &str) -> [u8; 32] {
        let planned = create_connection_planned(
            conn,
            tenant_id,
            peer_id,
            addr(7443),
            ConnectionPlanSourceKind::Discovery,
            None,
        )
        .unwrap()
        .expect("plan should be created");
        let plan_active = create_connection_plan_transitioned(
            conn,
            tenant_id,
            planned,
            &discovery_connection_id(tenant_id, peer_id),
            ConnectionPlanStatus::Active,
            Some("dialing"),
            0,
        )
        .unwrap();
        let basis = create_outbound_connection_authenticated(
            conn,
            tenant_id,
            plan_active,
            &discovery_connection_id(tenant_id, peer_id),
            peer_id,
            addr(7443),
            false,
        )
        .unwrap();
        basis
    }

    #[test]
    fn started_projects_history_row() {
        let conn = setup();
        let tenant_id = "tenant-a";
        let peer_id = &"a".repeat(64);
        let basis = setup_outbound_basis(&conn, tenant_id, peer_id);

        let event_id = create_sync_round_started(
            &conn,
            tenant_id,
            basis,
            &discovery_connection_id(tenant_id, peer_id),
            tenant_id,
            peer_id,
            17,
            SyncRoundRole::Initiator,
            "last_day",
            Some(100),
            Some(200),
            Some(0),
            Some(1234),
        )
        .unwrap();

        let row = load_snapshot_by_event_id(
            &conn,
            tenant_id,
            &crate::crypto::event_id_to_base64(&event_id),
        )
        .unwrap()
        .unwrap();
        assert_eq!(row.lifecycle_kind, "started");
        assert_eq!(row.round_id, crate::crypto::event_id_to_base64(&event_id));
        assert_eq!(
            row.connection_id,
            discovery_connection_id(tenant_id, peer_id)
        );
    }

    #[test]
    fn started_rejects_stale_basis() {
        let conn = setup();
        let tenant_id = "tenant-a";
        let peer_id = &"a".repeat(64);
        let planned = create_connection_planned(
            &conn,
            tenant_id,
            peer_id,
            addr(7443),
            ConnectionPlanSourceKind::Discovery,
            None,
        )
        .unwrap()
        .expect("plan should be created");
        let plan_active = create_connection_plan_transitioned(
            &conn,
            tenant_id,
            planned,
            &discovery_connection_id(tenant_id, peer_id),
            ConnectionPlanStatus::Active,
            Some("dialing"),
            0,
        )
        .unwrap();
        let auth = create_outbound_connection_authenticated(
            &conn,
            tenant_id,
            plan_active,
            &discovery_connection_id(tenant_id, peer_id),
            peer_id,
            addr(7443),
            false,
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let _latest = create_outbound_connection_authenticated(
            &conn,
            tenant_id,
            plan_active,
            &discovery_connection_id(tenant_id, peer_id),
            peer_id,
            addr(7443),
            false,
        )
        .unwrap();

        let err = create_sync_round_started(
            &conn,
            tenant_id,
            auth,
            &discovery_connection_id(tenant_id, peer_id),
            tenant_id,
            peer_id,
            18,
            SyncRoundRole::Initiator,
            "last_day",
            Some(100),
            Some(200),
            Some(0),
            Some(1234),
        )
        .unwrap_err();
        match err {
            CreateEventError::Rejected { reason, .. } => assert!(reason.contains("stale")),
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn responder_started_accepts_inbound_basis() {
        let conn = setup();
        let db_path = "/tmp/topo-sync-round-started.db";
        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 1).unwrap();
        mark_runtime_active(&conn, &run, addr(7443), 1).unwrap();
        let client_id = run.client_id;
        let tenant_id = "tenant-a";
        let peer_id = &"b".repeat(64);
        let connection_id = inbound_connection_id(&"c".repeat(64), peer_id, 99);
        let basis = create_inbound_connection_authenticated(
            &conn,
            &client_id,
            tenant_id,
            crate::crypto::event_id_from_base64(
                &super::super::client_lifecycle::load_state(&conn, &client_id)
                    .unwrap()
                    .unwrap()
                    .latest_event_id,
            )
            .unwrap(),
            &connection_id,
            &"c".repeat(64),
            peer_id,
            addr(7444),
        )
        .unwrap();

        create_sync_round_started(
            &conn,
            &client_id,
            basis,
            &connection_id,
            tenant_id,
            peer_id,
            19,
            SyncRoundRole::Responder,
            "last_day",
            Some(100),
            Some(200),
            None,
            None,
        )
        .unwrap();
    }
}
