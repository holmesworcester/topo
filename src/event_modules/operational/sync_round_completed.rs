use rusqlite::Connection;

use super::super::layout::common::{read_text_slot, write_text_slot, COMMON_HEADER_BYTES};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{
    Describe, EventError, ParsedEvent, EVENT_TYPE_SYNC_ROUND_COMPLETED,
    EVENT_TYPE_SYNC_ROUND_STARTED,
};
use super::sync_round_started::SyncRoundRole;
use crate::db::open_connection;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::create::{create_event_synchronous, CreateEventError};

const DETAIL_BYTES: usize = 160;
const SYNC_ROUND_COMPLETED_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + 1 + DETAIL_BYTES + 8 + 8 + 8 + 8 + 8 + 8;

mod offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const BASIS_EVENT_ID: usize = 9;
    pub const OUTCOME: usize = BASIS_EVENT_ID + 32;
    pub const DETAIL: usize = OUTCOME + 1;
    pub const EVENTS_SENT: usize = DETAIL + super::DETAIL_BYTES;
    pub const EVENTS_RECEIVED: usize = EVENTS_SENT + 8;
    pub const NEG_ROUNDS: usize = EVENTS_RECEIVED + 8;
    pub const BYTES_SENT: usize = NEG_ROUNDS + 8;
    pub const BYTES_RECEIVED: usize = BYTES_SENT + 8;
    pub const DURATION_MS: usize = BYTES_RECEIVED + 8;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncRoundOutcome {
    Ok,
    Error,
    Cancelled,
}

impl SyncRoundOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Ok => 1,
            Self::Error => 2,
            Self::Cancelled => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Ok),
            2 => Some(Self::Error),
            3 => Some(Self::Cancelled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRoundCompletedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub outcome: SyncRoundOutcome,
    pub detail: Option<String>,
    pub events_sent: i64,
    pub events_received: i64,
    pub neg_rounds: i64,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub duration_ms: i64,
}

impl Describe for SyncRoundCompletedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("outcome", self.outcome.as_str().to_string()),
            ("events_sent", self.events_sent.to_string()),
            ("events_received", self.events_received.to_string()),
            ("bytes_sent", self.bytes_sent.to_string()),
            ("bytes_received", self.bytes_received.to_string()),
            ("duration_ms", self.duration_ms.to_string()),
        ];
        if let Some(detail) = &self.detail {
            fields.push(("detail", detail.clone()));
        }
        fields
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    super::sync_round_started::ensure_schema(conn)?;
    super::sync_window_selected::ensure_schema(conn)
}

pub fn parse_sync_round_completed(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < SYNC_ROUND_COMPLETED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: SYNC_ROUND_COMPLETED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > SYNC_ROUND_COMPLETED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: SYNC_ROUND_COMPLETED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[offsets::TYPE_CODE] != EVENT_TYPE_SYNC_ROUND_COMPLETED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_SYNC_ROUND_COMPLETED,
            actual: blob[offsets::TYPE_CODE],
        });
    }

    let created_at_ms = u64::from_le_bytes(
        blob[offsets::CREATED_AT..offsets::BASIS_EVENT_ID]
            .try_into()
            .unwrap(),
    );
    let mut basis_event_id = [0u8; 32];
    basis_event_id.copy_from_slice(&blob[offsets::BASIS_EVENT_ID..offsets::OUTCOME]);
    let outcome = SyncRoundOutcome::from_code(blob[offsets::OUTCOME])
        .ok_or(EventError::InvalidMetadata("invalid sync round outcome"))?;
    let detail = {
        let raw = read_text_slot(&blob[offsets::DETAIL..offsets::EVENTS_SENT])
            .map_err(EventError::TextSlot)?;
        if raw.is_empty() {
            None
        } else {
            Some(raw)
        }
    };

    Ok(ParsedEvent::SyncRoundCompleted(SyncRoundCompletedEvent {
        created_at_ms,
        basis_event_id,
        outcome,
        detail,
        events_sent: i64::from_le_bytes(
            blob[offsets::EVENTS_SENT..offsets::EVENTS_RECEIVED]
                .try_into()
                .unwrap(),
        ),
        events_received: i64::from_le_bytes(
            blob[offsets::EVENTS_RECEIVED..offsets::NEG_ROUNDS]
                .try_into()
                .unwrap(),
        ),
        neg_rounds: i64::from_le_bytes(
            blob[offsets::NEG_ROUNDS..offsets::BYTES_SENT]
                .try_into()
                .unwrap(),
        ),
        bytes_sent: i64::from_le_bytes(
            blob[offsets::BYTES_SENT..offsets::BYTES_RECEIVED]
                .try_into()
                .unwrap(),
        ),
        bytes_received: i64::from_le_bytes(
            blob[offsets::BYTES_RECEIVED..offsets::DURATION_MS]
                .try_into()
                .unwrap(),
        ),
        duration_ms: i64::from_le_bytes(
            blob[offsets::DURATION_MS..offsets::DURATION_MS + 8]
                .try_into()
                .unwrap(),
        ),
    }))
}

pub fn encode_sync_round_completed(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let completed = match event {
        ParsedEvent::SyncRoundCompleted(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = vec![0u8; SYNC_ROUND_COMPLETED_WIRE_SIZE];
    buf[offsets::TYPE_CODE] = EVENT_TYPE_SYNC_ROUND_COMPLETED;
    buf[offsets::CREATED_AT..offsets::BASIS_EVENT_ID]
        .copy_from_slice(&completed.created_at_ms.to_le_bytes());
    buf[offsets::BASIS_EVENT_ID..offsets::OUTCOME].copy_from_slice(&completed.basis_event_id);
    buf[offsets::OUTCOME] = completed.outcome.code();
    write_text_slot(
        completed.detail.as_deref().unwrap_or(""),
        &mut buf[offsets::DETAIL..offsets::EVENTS_SENT],
    )
    .map_err(EventError::TextSlot)?;
    buf[offsets::EVENTS_SENT..offsets::EVENTS_RECEIVED]
        .copy_from_slice(&completed.events_sent.to_le_bytes());
    buf[offsets::EVENTS_RECEIVED..offsets::NEG_ROUNDS]
        .copy_from_slice(&completed.events_received.to_le_bytes());
    buf[offsets::NEG_ROUNDS..offsets::BYTES_SENT]
        .copy_from_slice(&completed.neg_rounds.to_le_bytes());
    buf[offsets::BYTES_SENT..offsets::BYTES_RECEIVED]
        .copy_from_slice(&completed.bytes_sent.to_le_bytes());
    buf[offsets::BYTES_RECEIVED..offsets::DURATION_MS]
        .copy_from_slice(&completed.bytes_received.to_le_bytes());
    buf[offsets::DURATION_MS..offsets::DURATION_MS + 8]
        .copy_from_slice(&completed.duration_ms.to_le_bytes());
    Ok(buf)
}

fn validate(event: &SyncRoundCompletedEvent) -> Result<(), String> {
    if event.events_sent < 0
        || event.events_received < 0
        || event.neg_rounds < 0
        || event.bytes_sent < 0
        || event.bytes_received < 0
        || event.duration_ms < 0
    {
        return Err("sync_round_completed counters must be non-negative".to_string());
    }
    Ok(())
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let completed = match parsed {
        ParsedEvent::SyncRoundCompleted(event) => event,
        _ => return Err("sync_round_completed context loader called for wrong event".into()),
    };

    super::common::build_sync_round_basis_context(
        conn,
        recorded_by,
        &completed.basis_event_id,
        "sync_round_completed",
    )
}

fn next_planner_state(
    snapshot: &crate::projection::contract::SyncRoundSnapshot,
) -> Option<super::sync_window_selected::PlannerStateRow> {
    if snapshot.round_role != SyncRoundRole::Initiator.as_str() {
        return None;
    }
    let current = snapshot.planner_next_idx_before?;
    let next_idx = ((current + 1) % 4).max(0) as usize;
    let cycle_anchor_now_ms = if next_idx == 0 {
        None
    } else {
        snapshot.planner_cycle_anchor_now_ms
    };
    Some(super::sync_window_selected::PlannerStateRow {
        next_idx,
        cycle_anchor_now_ms,
    })
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let completed = match parsed {
        ParsedEvent::SyncRoundCompleted(event) => event,
        _ => return ProjectorResult::reject("not a sync_round_completed event".to_string()),
    };

    if let Err(reason) = validate(completed) {
        return ProjectorResult::reject(reason);
    }
    if let Some(reason) = &ctx.sync_round_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.sync_round_snapshot else {
        return ProjectorResult::reject(
            "sync_round_completed missing sync round snapshot context".to_string(),
        );
    };
    if snapshot.lifecycle_kind != "started" {
        return ProjectorResult::reject(
            "sync_round_completed basis event must reference a started round".to_string(),
        );
    }

    let mut writes = vec![WriteOp::InsertOrIgnore {
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
            SqlVal::Text(snapshot.round_id.clone()),
            SqlVal::Text(snapshot.tenant_id.clone()),
            SqlVal::Text(snapshot.connection_id.clone()),
            SqlVal::Text(snapshot.peer_id.clone()),
            SqlVal::Int(snapshot.session_id),
            SqlVal::Text(snapshot.round_role.clone()),
            SqlVal::Text(snapshot.window_kind.clone()),
            snapshot
                .ts_min_inclusive_ms
                .map(SqlVal::Int)
                .unwrap_or(SqlVal::Null),
            snapshot
                .ts_max_exclusive_ms
                .map(SqlVal::Int)
                .unwrap_or(SqlVal::Null),
            snapshot
                .planner_next_idx_before
                .map(SqlVal::Int)
                .unwrap_or(SqlVal::Null),
            snapshot
                .planner_cycle_anchor_now_ms
                .map(SqlVal::Int)
                .unwrap_or(SqlVal::Null),
            SqlVal::Text("completed".to_string()),
            SqlVal::Text(completed.outcome.as_str().to_string()),
            completed
                .detail
                .as_ref()
                .map(|detail| SqlVal::Text(detail.clone()))
                .unwrap_or(SqlVal::Null),
            SqlVal::Int(completed.events_sent),
            SqlVal::Int(completed.events_received),
            SqlVal::Int(completed.neg_rounds),
            SqlVal::Int(completed.bytes_sent),
            SqlVal::Int(completed.bytes_received),
            SqlVal::Int(completed.duration_ms),
            SqlVal::Text(snapshot.event_id.clone()),
            SqlVal::Int(completed.created_at_ms as i64),
        ],
    }];

    if completed.outcome == SyncRoundOutcome::Ok {
        if let Some(next_state) = next_planner_state(snapshot) {
            writes.push(super::sync_window_selected::planner_state_write_op(
                recorded_by,
                event_id_b64,
                &snapshot.peer_id,
                next_state,
                completed.created_at_ms as i64,
            ));
        }
    }

    ProjectorResult::valid(writes)
}

pub static SYNC_ROUND_COMPLETED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_SYNC_ROUND_COMPLETED,
    type_name: "sync_round_completed",
    projection_table: "sync_round_history",
    share_scope: ShareScope::Local,
    dep_fields: &["basis_event_id"],
    dep_field_type_codes: &[&[EVENT_TYPE_SYNC_ROUND_STARTED]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_sync_round_completed,
    encode: encode_sync_round_completed,
    projector: project_pure,
    context_loader: build_projector_context,
};

pub fn create_sync_round_completed(
    conn: &Connection,
    recorded_by: &str,
    basis_event_id: [u8; 32],
    outcome: SyncRoundOutcome,
    detail: Option<&str>,
    events_sent: i64,
    events_received: i64,
    neg_rounds: i64,
    bytes_sent: i64,
    bytes_received: i64,
    duration_ms: i64,
) -> Result<[u8; 32], CreateEventError> {
    let event = ParsedEvent::SyncRoundCompleted(SyncRoundCompletedEvent {
        created_at_ms: crate::db::queue::current_timestamp_ms() as u64,
        basis_event_id,
        outcome,
        detail: detail.map(str::to_string),
        events_sent,
        events_received,
        neg_rounds,
        bytes_sent,
        bytes_received,
        duration_ms,
    });
    create_event_synchronous(conn, recorded_by, &event)
}

pub fn record_terminal_sync_round_for_active_session(
    db_path: &str,
    recorded_by: &str,
    session_id: i64,
    outcome: SyncRoundOutcome,
    detail: Option<&str>,
    duration_ms: i64,
) -> Result<bool, String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    let Some(active_round) =
        super::sync_round_started::load_active_round_for_session(&conn, recorded_by, session_id)
            .map_err(|e| e.to_string())?
    else {
        return Ok(false);
    };
    let basis_event_id = crate::crypto::event_id_from_base64(&active_round.latest_event_id)
        .ok_or_else(|| {
            format!(
                "invalid active sync round event id {}",
                active_round.latest_event_id
            )
        })?;
    match create_sync_round_completed(
        &conn,
        recorded_by,
        basis_event_id,
        outcome,
        detail,
        0,
        0,
        0,
        0,
        0,
        duration_ms.max(0),
    ) {
        Ok(_) => Ok(true),
        Err(CreateEventError::Rejected { .. } | CreateEventError::Blocked { .. }) => Ok(false),
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_connection;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::connection_plan_transitioned::create_connection_plan_transitioned;
    use crate::event_modules::operational::connection_planned::{
        create_connection_planned, discovery_connection_id, ConnectionPlanSourceKind,
        ConnectionPlanStatus,
    };
    use crate::event_modules::operational::outbound_connection_authenticated::create_outbound_connection_authenticated;
    use crate::event_modules::operational::sync_round_started::{
        create_sync_round_started, SyncRoundRole,
    };
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

    fn started_round(conn: &Connection) -> ([u8; 32], String) {
        let tenant_id = "tenant-a";
        let peer_id = &"a".repeat(64);
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
        let started = create_sync_round_started(
            conn,
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
        (started, tenant_id.to_string())
    }

    #[test]
    fn completed_projects_history_and_advances_planner_state() {
        let conn = setup();
        let (started, tenant_id) = started_round(&conn);
        create_sync_round_completed(
            &conn,
            &tenant_id,
            started,
            SyncRoundOutcome::Ok,
            None,
            5,
            6,
            1,
            7,
            8,
            9,
        )
        .unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_round_history WHERE recorded_by = ?1",
                rusqlite::params![tenant_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);

        let planner =
            super::super::sync_window_selected::load(&conn, "tenant-a", &"a".repeat(64)).unwrap();
        assert_eq!(planner.next_idx, 1);
        assert_eq!(planner.cycle_anchor_now_ms, Some(1234));
    }

    #[test]
    fn completed_rejects_stale_basis() {
        let conn = setup();
        let (started, tenant_id) = started_round(&conn);
        let _ = create_sync_round_completed(
            &conn,
            &tenant_id,
            started,
            SyncRoundOutcome::Ok,
            None,
            1,
            1,
            1,
            1,
            1,
            1,
        )
        .unwrap();

        let err = create_sync_round_completed(
            &conn,
            &tenant_id,
            started,
            SyncRoundOutcome::Ok,
            Some("second_attempt"),
            2,
            2,
            2,
            2,
            2,
            2,
        )
        .unwrap_err();
        match err {
            CreateEventError::Rejected { reason, .. } => assert!(reason.contains("stale")),
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn record_terminal_for_active_session_appends_completed_round() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("sync-round-completed.db");
        let db_path = db_path.to_string_lossy().to_string();
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();
        let (_started, tenant_id) = started_round(&conn);

        let recorded = record_terminal_sync_round_for_active_session(
            &db_path,
            &tenant_id,
            17,
            SyncRoundOutcome::Cancelled,
            Some("cancelled"),
            12,
        )
        .unwrap();
        assert!(recorded);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_round_history
                 WHERE recorded_by = ?1 AND lifecycle_kind = 'completed'",
                rusqlite::params![tenant_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
