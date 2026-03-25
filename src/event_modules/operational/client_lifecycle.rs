use std::net::SocketAddr;
use std::path::PathBuf;

use rusqlite::{Connection, OptionalExtension, Result as SqliteResult};

use crate::crypto::{event_id_from_base64, event_id_to_base64, hash_event};
use crate::db::queue::with_sqlite_busy_retry;
use crate::event_modules::ParsedEvent;
use crate::projection::contract::ClientRuntimeSnapshot;
use crate::projection::create::{create_event_synchronous, CreateEventError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRun {
    pub client_id: String,
    pub run_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRuntimeStatus {
    IdleNoTenants,
    Starting,
    Active,
    Stopped,
}

impl ClientRuntimeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdleNoTenants => "idle_no_tenants",
            Self::Starting => "starting",
            Self::Active => "active",
            Self::Stopped => "stopped",
        }
    }

    fn parse(raw: &str) -> Self {
        match raw {
            "idle_no_tenants" => Self::IdleNoTenants,
            "starting" => Self::Starting,
            "active" => Self::Active,
            "stopped" => Self::Stopped,
            _ => Self::Stopped,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRuntimeStateRow {
    pub latest_event_id: String,
    pub client_id: String,
    pub db_path: String,
    pub configured_bind_addr: String,
    pub reserved_bind_addr: Option<String>,
    pub listen_addr: Option<String>,
    pub runtime_status: ClientRuntimeStatus,
    pub current_run_id: Option<String>,
    pub tenant_count: usize,
    pub started_at_ms: Option<i64>,
    pub stopped_at_ms: Option<i64>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRuntimeRunRow {
    pub latest_event_id: String,
    pub client_id: String,
    pub run_id: String,
    pub db_path: String,
    pub configured_bind_addr: String,
    pub reserved_bind_addr: Option<String>,
    pub listen_addr: Option<String>,
    pub runtime_status: ClientRuntimeStatus,
    pub tenant_count: usize,
    pub started_at_ms: i64,
    pub activated_at_ms: Option<i64>,
    pub stopped_at_ms: Option<i64>,
    pub stop_reason: Option<String>,
}

impl ClientRuntimeRunRow {
    pub fn snapshot(&self) -> ClientRuntimeSnapshot {
        ClientRuntimeSnapshot {
            event_id: self.latest_event_id.clone(),
            client_id: self.client_id.clone(),
            run_id: self.run_id.clone(),
            db_path: self.db_path.clone(),
            configured_bind_addr: self.configured_bind_addr.clone(),
            reserved_bind_addr: self.reserved_bind_addr.clone(),
            listen_addr: self.listen_addr.clone(),
            runtime_status: self.runtime_status.as_str().to_string(),
            tenant_count: self.tenant_count as i64,
            started_at_ms: self.started_at_ms,
            activated_at_ms: self.activated_at_ms,
            stopped_at_ms: self.stopped_at_ms,
            stop_reason: self.stop_reason.clone(),
            created_at_ms: self
                .stopped_at_ms
                .or(self.activated_at_ms)
                .unwrap_or(self.started_at_ms),
        }
    }
}

fn now_ms() -> i64 {
    crate::db::queue::current_timestamp_ms()
}

fn canonical_client_key(db_path: &str) -> String {
    let canonical = std::fs::canonicalize(db_path)
        .unwrap_or_else(|_| PathBuf::from(db_path))
        .to_string_lossy()
        .to_string();
    format!("client:{}", hex::encode(hash_event(canonical.as_bytes())))
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    super::client_started::ensure_schema(conn)
}

pub fn client_id_for_db_path(db_path: &str) -> String {
    canonical_client_key(db_path)
}

pub fn require_current_basis_event_id(
    conn: &Connection,
    client_id: &str,
) -> Result<[u8; 32], String> {
    let Some(state) = load_state(conn, client_id).map_err(|e| e.to_string())? else {
        return Err(format!("missing client runtime state for {client_id}"));
    };
    event_id_from_base64(&state.latest_event_id).ok_or_else(|| {
        format!(
            "invalid client runtime latest_event_id {} for {}",
            state.latest_event_id, client_id
        )
    })
}

pub fn record_idle_bind_reservation(
    conn: &Connection,
    db_path: &str,
    configured_bind_addr: SocketAddr,
    reserved_bind_addr: SocketAddr,
    tenant_count: usize,
) -> SqliteResult<String> {
    let client_id = client_id_for_db_path(db_path);
    let reserved_bind_addr_s = reserved_bind_addr.to_string();
    if let Some(existing) = load_state(conn, &client_id)? {
        if existing.runtime_status == ClientRuntimeStatus::IdleNoTenants
            && existing.configured_bind_addr == configured_bind_addr.to_string()
            && existing.reserved_bind_addr.as_deref() == Some(reserved_bind_addr_s.as_str())
            && existing.tenant_count == tenant_count
        {
            return Ok(client_id);
        }
    }

    let event =
        ParsedEvent::ClientIdleReserved(super::client_idle_reserved::ClientIdleReservedEvent {
            created_at_ms: now_ms() as u64,
            db_path: db_path.to_string(),
            configured_bind_addr: configured_bind_addr.to_string(),
            reserved_bind_addr: reserved_bind_addr_s,
            tenant_count: tenant_count as u64,
        });
    create_event_synchronous(conn, &client_id, &event)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    Ok(client_id)
}

pub fn start_runtime(
    conn: &Connection,
    db_path: &str,
    configured_bind_addr: SocketAddr,
    reserved_bind_addr: Option<SocketAddr>,
    tenant_count: usize,
) -> Result<ClientRun, CreateEventError> {
    let client_id = client_id_for_db_path(db_path);
    let event = ParsedEvent::ClientStarted(super::client_started::ClientStartedEvent {
        created_at_ms: now_ms() as u64,
        db_path: db_path.to_string(),
        configured_bind_addr: configured_bind_addr.to_string(),
        reserved_bind_addr: reserved_bind_addr.map(|addr| addr.to_string()),
        tenant_count: tenant_count as u64,
    });
    let event_id = create_event_synchronous(conn, &client_id, &event)?;
    Ok(ClientRun {
        client_id,
        run_id: event_id_to_base64(&event_id),
    })
}

pub fn mark_runtime_active(
    conn: &Connection,
    run: &ClientRun,
    listen_addr: SocketAddr,
    tenant_count: usize,
) -> Result<(), CreateEventError> {
    let basis_event_id = match load_run(conn, &run.client_id, &run.run_id)? {
        Some(row) => event_id_from_base64(&row.latest_event_id).ok_or_else(|| {
            CreateEventError::EncodeError("invalid client latest_event_id".to_string())
        })?,
        None => event_id_from_base64(&run.run_id).ok_or_else(|| {
            CreateEventError::EncodeError("invalid client run_id event id".to_string())
        })?,
    };
    let event = ParsedEvent::ClientActivated(super::client_activated::ClientActivatedEvent {
        created_at_ms: now_ms() as u64,
        basis_event_id,
        listen_addr: listen_addr.to_string(),
        tenant_count: tenant_count as u64,
    });
    let _ = create_event_synchronous(conn, &run.client_id, &event)?;
    Ok(())
}

pub fn mark_runtime_stopped(
    conn: &Connection,
    run: &ClientRun,
    stop_reason: &str,
) -> Result<(), CreateEventError> {
    let basis_event_id = match load_run(conn, &run.client_id, &run.run_id)? {
        Some(row) => event_id_from_base64(&row.latest_event_id).ok_or_else(|| {
            CreateEventError::EncodeError("invalid client latest_event_id".to_string())
        })?,
        None => event_id_from_base64(&run.run_id).ok_or_else(|| {
            CreateEventError::EncodeError("invalid client run_id event id".to_string())
        })?,
    };
    let event = ParsedEvent::ClientStopped(super::client_stopped::ClientStoppedEvent {
        created_at_ms: now_ms() as u64,
        basis_event_id,
        stop_reason: stop_reason.to_string(),
    });
    let _ = create_event_synchronous(conn, &run.client_id, &event)?;
    Ok(())
}

fn query_history_row(
    conn: &Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> SqliteResult<Option<ClientRuntimeRunRow>> {
    with_sqlite_busy_retry(|| {
        conn.query_row(sql, params, |row| {
            Ok(ClientRuntimeRunRow {
                latest_event_id: row.get(0)?,
                client_id: row.get(1)?,
                run_id: row.get(2)?,
                db_path: row.get(3)?,
                configured_bind_addr: row.get(4)?,
                reserved_bind_addr: row.get(5)?,
                listen_addr: row.get(6)?,
                runtime_status: ClientRuntimeStatus::parse(&row.get::<_, String>(7)?),
                tenant_count: row.get::<_, i64>(8)?.max(0) as usize,
                started_at_ms: row.get(9)?,
                activated_at_ms: row.get(10)?,
                stopped_at_ms: row.get(11)?,
                stop_reason: row.get(12)?,
            })
        })
        .optional()
    })
}

pub fn load_snapshot_by_event_id(
    conn: &Connection,
    client_id: &str,
    event_id: &str,
) -> SqliteResult<Option<ClientRuntimeRunRow>> {
    query_history_row(
        conn,
        "SELECT
             event_id,
             client_id,
             run_id,
             db_path,
             configured_bind_addr,
             reserved_bind_addr,
             listen_addr,
             runtime_status,
             tenant_count,
             started_at_ms,
             activated_at_ms,
             stopped_at_ms,
             stop_reason
         FROM client_runtime_history
         WHERE client_id = ?1 AND event_id = ?2",
        &[&client_id, &event_id],
    )
}

pub fn load_state(
    conn: &Connection,
    client_id: &str,
) -> SqliteResult<Option<ClientRuntimeStateRow>> {
    let row = query_history_row(
        conn,
        "SELECT
             event_id,
             client_id,
             run_id,
             db_path,
             configured_bind_addr,
             reserved_bind_addr,
             listen_addr,
             runtime_status,
             tenant_count,
             started_at_ms,
             activated_at_ms,
             stopped_at_ms,
             stop_reason
         FROM client_runtime_history
         WHERE client_id = ?1
           AND NOT EXISTS (
               SELECT 1
               FROM client_runtime_history newer
               WHERE newer.client_id = client_runtime_history.client_id
                 AND newer.basis_event_id = client_runtime_history.event_id
           )
         ORDER BY created_at DESC, event_id DESC
         LIMIT 1",
        &[&client_id],
    )?;

    Ok(row.map(|row| {
        let current_run_id = match row.runtime_status {
            ClientRuntimeStatus::Stopped | ClientRuntimeStatus::IdleNoTenants => None,
            ClientRuntimeStatus::Starting | ClientRuntimeStatus::Active => Some(row.run_id.clone()),
        };
        ClientRuntimeStateRow {
            latest_event_id: row.latest_event_id,
            client_id: row.client_id,
            db_path: row.db_path,
            configured_bind_addr: row.configured_bind_addr,
            reserved_bind_addr: row.reserved_bind_addr,
            listen_addr: row.listen_addr,
            runtime_status: row.runtime_status,
            current_run_id,
            tenant_count: row.tenant_count,
            started_at_ms: Some(row.started_at_ms),
            stopped_at_ms: row.stopped_at_ms,
            updated_at_ms: row
                .stopped_at_ms
                .or(row.activated_at_ms)
                .unwrap_or(row.started_at_ms),
        }
    }))
}

pub fn load_run(
    conn: &Connection,
    client_id: &str,
    run_id: &str,
) -> SqliteResult<Option<ClientRuntimeRunRow>> {
    query_history_row(
        conn,
        "SELECT
             event_id,
             client_id,
             run_id,
             db_path,
             configured_bind_addr,
             reserved_bind_addr,
             listen_addr,
             runtime_status,
             tenant_count,
             started_at_ms,
             activated_at_ms,
             stopped_at_ms,
             stop_reason
         FROM client_runtime_history
         WHERE client_id = ?1 AND run_id = ?2
           AND NOT EXISTS (
               SELECT 1
               FROM client_runtime_history newer
               WHERE newer.client_id = client_runtime_history.client_id
                 AND newer.run_id = client_runtime_history.run_id
                 AND newer.basis_event_id = client_runtime_history.event_id
           )
         ORDER BY created_at DESC, event_id DESC
         LIMIT 1",
        &[&client_id, &run_id],
    )
}

// ---------------------------------------------------------------------------
// Reconciler helpers: derive desired runtime action from projected state
// ---------------------------------------------------------------------------

/// Desired action for the host reconciler, derived entirely from projected
/// client runtime state and current tenant configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesiredRuntimeAction {
    /// No tenants configured — ensure idle bind reservation, no runtime needed.
    IdleNoTenants,
    /// A `client_started` event exists but no runtime is active yet. The
    /// reconciler should spawn the runtime for this run.
    SpawnRuntime { run_id: String },
    /// The runtime is already active — nothing to do for listener lifecycle.
    RuntimeActive,
    /// The latest state is stopped or unknown — record `client_started` to
    /// begin a new run.
    StartNewRun,
}

/// Derive the desired runtime action from projected client lifecycle state
/// and current tenant count. This is the single event-owned decision point
/// for the host reconciler.
pub fn desired_runtime_action(
    lifecycle_state: Option<&ClientRuntimeStateRow>,
    has_tenants: bool,
) -> DesiredRuntimeAction {
    if !has_tenants {
        return DesiredRuntimeAction::IdleNoTenants;
    }
    match lifecycle_state.map(|s| s.runtime_status) {
        Some(ClientRuntimeStatus::Starting) => {
            if let Some(run_id) = lifecycle_state.and_then(|s| s.current_run_id.clone()) {
                DesiredRuntimeAction::SpawnRuntime { run_id }
            } else {
                DesiredRuntimeAction::StartNewRun
            }
        }
        Some(ClientRuntimeStatus::Active) => DesiredRuntimeAction::RuntimeActive,
        Some(ClientRuntimeStatus::Stopped)
        | Some(ClientRuntimeStatus::IdleNoTenants)
        | None => DesiredRuntimeAction::StartNewRun,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::client_stopped;
    use crate::projection::create::CreateEventError;
    use rusqlite::params;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse().unwrap(), port)
    }

    #[test]
    fn client_id_is_stable_for_same_path() {
        let a = client_id_for_db_path("/tmp/topo-a.db");
        let b = client_id_for_db_path("/tmp/topo-a.db");
        assert_eq!(a, b);
    }

    #[test]
    fn lifecycle_events_project_history_and_latest_state() {
        let conn = setup();
        let db_path = "/tmp/topo-client-a.db";
        let client_id = client_id_for_db_path(db_path);

        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 2).unwrap();
        assert_eq!(run.client_id, client_id);

        let starting = load_state(&conn, &client_id).unwrap().unwrap();
        assert_eq!(starting.runtime_status, ClientRuntimeStatus::Starting);
        assert_eq!(
            starting.current_run_id.as_deref(),
            Some(run.run_id.as_str())
        );

        mark_runtime_active(&conn, &run, addr(7443), 2).unwrap();
        let active = load_state(&conn, &client_id).unwrap().unwrap();
        assert_eq!(active.runtime_status, ClientRuntimeStatus::Active);
        assert_eq!(active.listen_addr.as_deref(), Some("127.0.0.1:7443"));

        mark_runtime_stopped(&conn, &run, "graceful_shutdown").unwrap();
        let stopped = load_state(&conn, &client_id).unwrap().unwrap();
        assert_eq!(stopped.runtime_status, ClientRuntimeStatus::Stopped);
        assert!(stopped.current_run_id.is_none());

        let run_row = load_run(&conn, &client_id, &run.run_id).unwrap().unwrap();
        assert_eq!(run_row.runtime_status, ClientRuntimeStatus::Stopped);
        assert_eq!(run_row.stop_reason.as_deref(), Some("graceful_shutdown"));

        let history_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM client_runtime_history WHERE client_id = ?1",
                params![client_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history_count, 3);
    }

    #[test]
    fn idle_bind_reservation_projects_idle_state_and_dedupes() {
        let conn = setup();
        let db_path = "/tmp/topo-client-idle.db";
        let client_id = client_id_for_db_path(db_path);

        record_idle_bind_reservation(&conn, db_path, addr(7000), addr(7001), 0).unwrap();
        record_idle_bind_reservation(&conn, db_path, addr(7000), addr(7001), 0).unwrap();

        let state = load_state(&conn, &client_id).unwrap().unwrap();
        assert_eq!(state.runtime_status, ClientRuntimeStatus::IdleNoTenants);
        assert_eq!(state.reserved_bind_addr.as_deref(), Some("127.0.0.1:7001"));

        let history_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM client_runtime_history WHERE client_id = ?1",
                params![client_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history_count, 1);
    }

    #[test]
    fn activation_blocks_without_started_run() {
        let conn = setup();
        let err = mark_runtime_active(
            &conn,
            &ClientRun {
                client_id: "client:test".to_string(),
                run_id: event_id_to_base64(&[0x11; 32]),
            },
            addr(7443),
            1,
        )
        .unwrap_err();
        match err {
            CreateEventError::Blocked { .. } => {}
            other => panic!("expected blocked activation, got {other:?}"),
        }
    }

    #[test]
    fn desired_action_no_tenants_returns_idle() {
        assert_eq!(
            desired_runtime_action(None, false),
            DesiredRuntimeAction::IdleNoTenants
        );
    }

    #[test]
    fn desired_action_no_state_with_tenants_returns_start() {
        assert_eq!(
            desired_runtime_action(None, true),
            DesiredRuntimeAction::StartNewRun
        );
    }

    #[test]
    fn desired_action_starting_returns_spawn() {
        let conn = setup();
        let db_path = "/tmp/topo-client-desired-spawn.db";
        let client_id = client_id_for_db_path(db_path);
        start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 1).unwrap();
        let state = load_state(&conn, &client_id).unwrap();
        let action = desired_runtime_action(state.as_ref(), true);
        match action {
            DesiredRuntimeAction::SpawnRuntime { .. } => {}
            other => panic!("expected SpawnRuntime, got {other:?}"),
        }
    }

    #[test]
    fn desired_action_active_returns_active() {
        let conn = setup();
        let db_path = "/tmp/topo-client-desired-active.db";
        let client_id = client_id_for_db_path(db_path);
        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 1).unwrap();
        mark_runtime_active(&conn, &run, addr(7443), 1).unwrap();
        let state = load_state(&conn, &client_id).unwrap();
        assert_eq!(
            desired_runtime_action(state.as_ref(), true),
            DesiredRuntimeAction::RuntimeActive
        );
    }

    #[test]
    fn desired_action_stopped_with_tenants_returns_start() {
        let conn = setup();
        let db_path = "/tmp/topo-client-desired-restart.db";
        let client_id = client_id_for_db_path(db_path);
        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 1).unwrap();
        mark_runtime_active(&conn, &run, addr(7443), 1).unwrap();
        mark_runtime_stopped(&conn, &run, "graceful_shutdown").unwrap();
        let state = load_state(&conn, &client_id).unwrap();
        assert_eq!(
            desired_runtime_action(state.as_ref(), true),
            DesiredRuntimeAction::StartNewRun
        );
    }

    #[test]
    fn desired_action_stopped_no_tenants_returns_idle() {
        let conn = setup();
        let db_path = "/tmp/topo-client-desired-idle.db";
        let client_id = client_id_for_db_path(db_path);
        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 1).unwrap();
        mark_runtime_stopped(&conn, &run, "no_tenants").unwrap();
        let state = load_state(&conn, &client_id).unwrap();
        assert_eq!(
            desired_runtime_action(state.as_ref(), false),
            DesiredRuntimeAction::IdleNoTenants
        );
    }

    #[test]
    fn stale_client_transition_is_rejected() {
        let conn = setup();
        let db_path = "/tmp/topo-client-stale.db";
        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 1).unwrap();

        mark_runtime_active(&conn, &run, addr(7443), 1).unwrap();

        let stale_basis = event_id_from_base64(&run.run_id).unwrap();
        let err = create_event_synchronous(
            &conn,
            &run.client_id,
            &ParsedEvent::ClientStopped(client_stopped::ClientStoppedEvent {
                created_at_ms: now_ms() as u64,
                basis_event_id: stale_basis,
                stop_reason: "stale_basis".to_string(),
            }),
        )
        .unwrap_err();

        match err {
            CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("stale"));
            }
            other => panic!("expected stale rejection, got {other:?}"),
        }
    }
}
