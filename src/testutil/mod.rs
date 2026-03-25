pub mod bootstrap;

use std::net::SocketAddr;
use std::process::Child;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// RAII guard that kills a daemon process on drop, preventing leaked processes
/// when tests panic before reaching manual cleanup.
pub struct DaemonGuard {
    child: Option<Child>,
}

impl DaemonGuard {
    /// Wrap an already-spawned daemon `Child` process.
    pub fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    /// Access the underlying `Child` (e.g. for `try_wait` or `id`).
    pub fn child(&mut self) -> &mut Child {
        self.child.as_mut().expect("DaemonGuard already consumed")
    }

    /// Prevent Drop from touching a child that has already been reaped or
    /// transferred elsewhere.
    pub fn clear(&mut self) {
        self.child = None;
    }

    /// Take ownership of the underlying child process.
    pub fn take(&mut self) -> Option<Child> {
        self.child.take()
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::{open_connection, schema::create_tables, store::insert_recorded_event};
use crate::event_modules::{
    AdminEvent, DeviceInviteEvent, FileEvent, FileSliceEvent, InviteAcceptedEvent, KeySecretEvent,
    KeySharedEvent, MessageDeletionEvent, MessageEvent, ParsedEvent, PeerSharedEvent,
    ReactionEvent, TenantEvent, UserEvent, UserInviteEvent, WorkspaceEvent,
};
use crate::peering::loops::{
    accept_loop, connect_loop, connect_loop_with_coordination_until_cancel,
    connect_loop_with_coordination_until_cancel_with_fallback_with_auth,
};
use crate::projection::apply::project_one;
use crate::projection::create::{
    create_encrypted_event_staged, create_encrypted_event_synchronous, create_event_staged,
    create_event_synchronous, create_signed_event_staged, create_signed_event_synchronous,
    event_id_or_blocked, CreateEventError,
};
use crate::state::db::queue::SQLITE_BUSY_RETRY_ATTEMPTS;
use crate::state::db::queue::SQLITE_BUSY_RETRY_BASE_MS;
use crate::transport::identity::{ensure_transport_peer_id, load_transport_cert};
use crate::transport::{
    create_dual_endpoint, create_dual_endpoint_dynamic, extract_spki_fingerprint,
    OutboundSessionAuthPlan,
};
use ed25519_dalek::SigningKey;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio_util::sync::CancellationToken;

/// No-op intro spawner for tests that don't need holepunch.
pub fn noop_intro_spawner(
    _conn: quinn::Connection,
    _db_path: String,
    _recorded_by: String,
    _peer_id: String,
    _endpoint: quinn::Endpoint,
    _client_config: Option<quinn::ClientConfig>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(async {})
}

/// Convenience: production `IngestFns` for tests.
pub fn test_ingest_fns() -> crate::contracts::event_pipeline_contract::IngestFns {
    crate::contracts::event_pipeline_contract::IngestFns {
        batch_writer: crate::event_pipeline::batch_writer,
        drain_queue: crate::event_pipeline::drain_project_queue,
    }
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn poll_for_materialized_local_peer_signer(
    db_path: &str,
    scoped_peer_id: &str,
    timeout: Duration,
) -> Option<(EventId, SigningKey)> {
    let start = Instant::now();
    loop {
        let _ = crate::event_pipeline::drain_project_queue(db_path, scoped_peer_id, 1000);
        if let Ok(db) = open_connection(db_path) {
            if let Ok(Some((eid, key))) =
                crate::service::load_local_peer_signer_pub(&db, scoped_peer_id)
            {
                return Some((eid, key));
            }
        }
        if start.elapsed() >= timeout {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_materialized_local_peer_signer(
    db_path: &str,
    scoped_peer_id: &str,
    timeout: Duration,
) -> (EventId, SigningKey) {
    if let Some(signer) =
        poll_for_materialized_local_peer_signer(db_path, scoped_peer_id, timeout).await
    {
        return signer;
    }
    let debug = open_connection(db_path)
        .ok()
        .map(|db| {
            let peer_secrets: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM peer_secrets WHERE recorded_by = ?1",
                    rusqlite::params![scoped_peer_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let blocked: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
                    rusqlite::params![scoped_peer_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let queued: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1",
                    rusqlite::params![scoped_peer_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let peer_secret_events: i64 = db
                .query_row(
                    "SELECT COUNT(*)
                     FROM recorded_events re
                     JOIN events e ON e.event_id = re.event_id
                     WHERE re.peer_id = ?1
                       AND e.event_type = 'peer_secret'",
                    rusqlite::params![scoped_peer_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let blocked_details = db
                .prepare(
                    "SELECT e.event_type,
                            hex(b.blocker_event_id),
                            COALESCE(be.event_type, 'missing')
                     FROM blocked_event_deps b
                     JOIN events e
                       ON e.event_id = b.event_id
                     LEFT JOIN events be
                       ON be.event_id = b.blocker_event_id
                     WHERE b.peer_id = ?1
                     ORDER BY e.created_at ASC, e.event_id ASC, b.blocker_event_id ASC",
                )
                .and_then(|mut stmt| {
                    stmt.query_map(rusqlite::params![scoped_peer_id], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()
                })
                .unwrap_or_default();
            format!(
                "peer_secrets={}, blocked_events={}, project_queue={}, recorded_peer_secret_events={}, blocked_details={:?}",
                peer_secrets, blocked, queued, peer_secret_events, blocked_details
            )
        })
        .unwrap_or_else(|| "failed to open db for debug".to_string());
    panic!(
        "local peer signer not materialized for {} within {:?}: {}",
        scoped_peer_id, timeout, debug
    );
}

async fn poll_for_any_tenant_transport_target(
    db_path: &str,
    tenant_id: &str,
    timeout: Duration,
) -> Option<String> {
    let start = Instant::now();
    loop {
        let _ = crate::event_pipeline::drain_project_queue(db_path, tenant_id, 1000);
        if let Ok(db) = open_connection(db_path) {
            if let Ok(Some(target)) =
                crate::state::db::transport_creds::resolve_tenant_transport_target(&db, tenant_id)
            {
                return Some(target.transport_peer_id);
            }
        }
        if start.elapsed() >= timeout {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_any_tenant_transport_target(
    db_path: &str,
    tenant_id: &str,
    timeout: Duration,
) -> String {
    if let Some(transport_peer_id) =
        poll_for_any_tenant_transport_target(db_path, tenant_id, timeout).await
    {
        return transport_peer_id;
    }

    let debug = open_connection(db_path)
        .ok()
        .map(|db| {
            let target =
                crate::state::db::transport_creds::resolve_tenant_transport_target(&db, tenant_id)
                    .ok()
                    .flatten()
                    .map(|target| target.transport_peer_id)
                    .unwrap_or_else(|| "<none>".to_string());
            let bootstrap_rows: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM invite_bootstrap_trust WHERE recorded_by = ?1",
                    rusqlite::params![tenant_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let pending_rows: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM pending_invite_bootstrap_trust WHERE recorded_by = ?1",
                    rusqlite::params![tenant_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let peers_shared_rows: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
                    rusqlite::params![tenant_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            format!(
                "target={} bootstrap_rows={} pending_rows={} peers_shared_rows={}",
                target, bootstrap_rows, pending_rows, peers_shared_rows
            )
        })
        .unwrap_or_else(|| "failed to open db for debug".to_string());

    panic!(
        "tenant {} transport target did not materialize within {:?}: {}",
        tenant_id, timeout, debug
    );
}

async fn poll_for_projected_peer_transport(
    db_path: &str,
    recorded_by: &str,
    expected_transport_peer_id: &str,
    timeout: Duration,
) -> bool {
    let start = Instant::now();
    loop {
        let _ = crate::event_pipeline::drain_project_queue(db_path, recorded_by, 1000);
        if has_projected_peer_transport_now(db_path, recorded_by, expected_transport_peer_id) {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_projected_peer_transport(
    db_path: &str,
    recorded_by: &str,
    expected_transport_peer_id: &str,
    timeout: Duration,
) {
    if poll_for_projected_peer_transport(db_path, recorded_by, expected_transport_peer_id, timeout)
        .await
    {
        return;
    }

    let debug = open_connection(db_path)
        .ok()
        .map(|db| {
            let peers_shared_rows: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
                    rusqlite::params![recorded_by],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let known_targets: Vec<String> = db
                .prepare(
                    "SELECT lower(hex(transport_fingerprint))
                     FROM peers_shared
                     WHERE recorded_by = ?1
                     ORDER BY event_id ASC",
                )
                .and_then(|mut stmt| {
                    stmt.query_map(rusqlite::params![recorded_by], |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<Result<Vec<_>, _>>()
                })
                .unwrap_or_default();
            format!(
                "peers_shared_rows={}, known_targets={:?}",
                peers_shared_rows, known_targets
            )
        })
        .unwrap_or_else(|| "failed to open db for debug".to_string());

    panic!(
        "tenant {} did not project remote transport target {} within {:?}: {}",
        recorded_by, expected_transport_peer_id, timeout, debug
    );
}

fn has_projected_peer_transport_now(
    db_path: &str,
    recorded_by: &str,
    expected_transport_peer_id: &str,
) -> bool {
    open_connection(db_path)
        .ok()
        .and_then(|db| {
            db.query_row(
                "SELECT COUNT(*)
                 FROM peers_shared
                 WHERE recorded_by = ?1
                   AND lower(hex(transport_fingerprint)) = ?2",
                rusqlite::params![recorded_by, expected_transport_peer_id],
                |row| row.get::<_, i64>(0),
            )
            .ok()
        })
        .unwrap_or(0)
        > 0
}

fn collect_expected_targets(expected_peers: &[&Peer]) -> Vec<(String, String)> {
    expected_peers
        .iter()
        .map(|peer| (peer.identity.clone(), current_transport_target(peer)))
        .collect()
}

fn missing_transport_views(peers: &[&Peer], expected_targets: &[(String, String)]) -> Vec<String> {
    let mut missing = Vec::new();
    for peer in peers {
        for (owner_identity, target_transport_peer_id) in expected_targets {
            if owner_identity == &peer.identity {
                continue;
            }
            if !has_projected_peer_transport_now(
                &peer.db_path,
                &peer.identity,
                target_transport_peer_id,
            ) {
                let debug = open_connection(&peer.db_path)
                    .ok()
                    .map(|db| {
                        let known_targets: Vec<String> = db
                            .prepare(
                                "SELECT lower(hex(transport_fingerprint))
                                 FROM peers_shared
                                 WHERE recorded_by = ?1
                                 ORDER BY event_id ASC",
                            )
                            .and_then(|mut stmt| {
                                stmt.query_map(rusqlite::params![&peer.identity], |row| {
                                    row.get::<_, String>(0)
                                })?
                                .collect::<Result<Vec<_>, _>>()
                            })
                            .unwrap_or_default();
                        let peer_rows: i64 = db
                            .query_row(
                                "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
                                rusqlite::params![&peer.identity],
                                |row| row.get(0),
                            )
                            .unwrap_or(0);
                        format!("peer_rows={}, known_targets={:?}", peer_rows, known_targets)
                    })
                    .unwrap_or_else(|| "failed to open db".to_string());
                missing.push(format!(
                    "{} missing transport target {} from {} ({})",
                    peer.name, target_transport_peer_id, owner_identity, debug
                ));
            }
        }
    }
    missing
}

async fn sync_pair_until_transport_converged(
    peer_a: &Peer,
    peer_b: &Peer,
    expected_peers: &[&Peer],
    timeout: Duration,
) {
    // Bootstrap-related graph convergence often runs before steady-state daemon
    // bindings are projected for every pair. Use explicit pairwise daemon trust
    // for this temporary convergence link, then wait for the projected
    // peer_shared transport view to materialize before returning.
    let (accept_cert, accept_key) = daemon_cert_and_key_for_peer(peer_a);
    let trusted_connect_spki = daemon_fingerprint_for_peer(peer_b);
    let accept_allow_fn: Arc<crate::transport::DynamicAllowFn> =
        Arc::new(move |fp: &[u8; 32]| Ok(fp == &trusted_connect_spki));
    let accept_endpoint = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        accept_cert,
        accept_key,
        accept_allow_fn,
    )
    .expect("failed to create pair convergence accept endpoint");
    let accept_addr = accept_endpoint
        .local_addr()
        .expect("failed to get accept endpoint addr");
    let (connect_cert, connect_key) = daemon_cert_and_key_for_peer(peer_b);
    let trusted_accept_spki = daemon_fingerprint_for_peer(peer_a);
    let connect_allow_fn: Arc<crate::transport::DynamicAllowFn> =
        Arc::new(move |fp: &[u8; 32]| Ok(fp == &trusted_accept_spki));
    let connect_endpoint = create_dual_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        connect_cert,
        connect_key,
        connect_allow_fn,
    )
    .expect("failed to create pair convergence connect endpoint");
    let connect_cancel = tokio_util::sync::CancellationToken::new();
    let connect_cancel_thread = connect_cancel.clone();
    let accept_endpoint_thread = accept_endpoint.clone();
    let connect_endpoint_thread = connect_endpoint.clone();
    let a_db = peer_a.db_path.clone();
    let a_identity = peer_a.identity.clone();
    let b_db = peer_b.db_path.clone();
    let b_identity = peer_b.identity.clone();
    let target_peer_id = current_transport_target(peer_a);
    let target_peer_id_for_connect = target_peer_id.clone();
    crate::sync::session::windowing::prime_outbound_window_kind(
        &peer_b.db_path,
        &peer_b.identity,
        &target_peer_id,
        crate::sync::session::windowing::SyncWindowKind::Full,
    );

    let accept_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop(
                &a_db,
                &a_identity,
                accept_endpoint_thread,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
                tracing::warn!("temporary identity accept_loop exited: {}", e);
            }
        });
    });

    let connect_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = connect_loop_with_coordination_until_cancel(
                &b_db,
                &b_identity,
                connect_endpoint_thread,
                accept_addr,
                &target_peer_id_for_connect,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
                connect_cancel_thread,
            )
            .await
            {
                tracing::warn!("temporary identity connect_loop exited: {}", e);
            }
        });
    });

    let check_peers = [peer_a, peer_b];
    let mut current_expected_targets = collect_expected_targets(expected_peers);
    let mut last_target_change = Instant::now();
    loop {
        let latest_expected_targets = collect_expected_targets(expected_peers);
        if latest_expected_targets != current_expected_targets {
            current_expected_targets = latest_expected_targets;
            last_target_change = Instant::now();
        }
        let missing = missing_transport_views(&check_peers, &current_expected_targets);
        if missing.is_empty() {
            break;
        }
        if last_target_change.elapsed() >= timeout {
            let refreshed_expected_targets = collect_expected_targets(expected_peers);
            if refreshed_expected_targets != current_expected_targets {
                current_expected_targets = refreshed_expected_targets;
                last_target_change = Instant::now();
                continue;
            }
            let refreshed_missing =
                missing_transport_views(&check_peers, &current_expected_targets);
            if refreshed_missing.is_empty() {
                break;
            }
            connect_cancel.cancel();
            connect_endpoint.close(0u32.into(), b"identity convergence timeout");
            accept_endpoint.close(0u32.into(), b"identity convergence timeout");
            let _ = accept_handle.join();
            let _ = connect_handle.join();
            panic!(
                "workspace transport graph did not converge between {} and {} within {:?}: {:?} \
                 ({} identity={}, current_target={}; {} identity={}, current_target={})",
                peer_a.name,
                peer_b.name,
                timeout,
                refreshed_missing,
                peer_a.name,
                peer_a.identity,
                current_transport_target(peer_a),
                peer_b.name,
                peer_b.identity,
                current_transport_target(peer_b)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    connect_cancel.cancel();
    connect_endpoint.close(0u32.into(), b"identity convergence done");
    accept_endpoint.close(0u32.into(), b"identity convergence done");
    let _ = accept_handle.join();
    let _ = connect_handle.join();
    crate::sync::session::windowing::reset_outbound_window_state(
        &peer_b.db_path,
        &peer_b.identity,
        &target_peer_id,
    );
}

/// Ensure the hub peer and every other peer have projected each other's
/// current strict transport target before benchmark/test data generation begins.
///
/// Under the current exact-target model, a peer does not learn every other
/// peer's current transport target through a single hub sync. The test harness
/// only needs the pairwise hub<->peer transport view to be current before it
/// starts a concrete chain or sink-download topology.
pub async fn converge_workspace_transport_graph(peers: &[Peer]) {
    crate::state::live_hints::init_forward_on_have_from_env();
    if peers.len() < 2 {
        return;
    }
    for peer in peers.iter().skip(1) {
        assert_eq!(
            peer.workspace_id, peers[0].workspace_id,
            "workspace transport graph convergence requires one shared workspace"
        );
    }

    let pair_timeout = Duration::from_secs(20 + (peers.len() as u64 * 4));

    for peer in peers.iter().skip(1) {
        let expected_peers = [&peers[0], peer];
        sync_pair_until_transport_converged(&peers[0], peer, &expected_peers, pair_timeout).await;
    }

    let hub = &peers[0];
    let hub_db =
        open_connection(&hub.db_path).expect("failed to open hub db for graph convergence");
    let shared_event_ids = list_shared_event_ids_for_tenant(&hub_db, &hub.identity);
    for peer in peers.iter().skip(1) {
        let peer_db =
            open_connection(&peer.db_path).expect("failed to open peer db for graph convergence");
        copy_projected_events_for_tenant(&hub_db, &peer_db, &peer.identity, &shared_event_ids);
    }
}

/// Ensure a sink and each source have projected each other's current transport
/// target before starting direct sink↔source download loops.
pub async fn converge_sink_download_transport(sources: &[Peer], sink: &Peer) {
    crate::state::live_hints::init_forward_on_have_from_env();
    if sources.is_empty() {
        return;
    }
    let hub = &sources[0];
    let pair_timeout = Duration::from_secs(20 + (sources.len() as u64 * 4));

    let hub_db = open_connection(&hub.db_path).expect("failed to open hub db for sink convergence");
    let shared_event_ids = list_shared_event_ids_for_tenant(&hub_db, &hub.identity);
    for source in sources {
        if source.identity == hub.identity {
            continue;
        }
        let source_db = open_connection(&source.db_path)
            .expect("failed to open source db for sink convergence");
        copy_projected_events_for_tenant(&hub_db, &source_db, &source.identity, &shared_event_ids);
    }
    let sink_db = open_connection(&sink.db_path).expect("failed to open sink db for convergence");
    copy_projected_events_for_tenant(&hub_db, &sink_db, &sink.identity, &shared_event_ids);

    for source in sources {
        let expected_peers = [source, sink];
        sync_pair_until_transport_converged(source, sink, &expected_peers, pair_timeout).await;
    }
}

/// Open a lightweight connection for polling counts during active sync.
/// Avoids reapplying full connection pragmas on each poll, which can
/// contend with writers and cause transient open failures.
fn open_count_connection(db_path: &str) -> Option<rusqlite::Connection> {
    let db = match rusqlite::Connection::open(db_path) {
        Ok(db) => db,
        Err(_) => return None,
    };
    let _ = db.busy_timeout(Duration::from_millis(200));
    Some(db)
}

/// Timing breakdown returned after sync completes.
#[derive(Debug, Clone)]
pub struct SyncMetrics {
    /// Wall-clock time from start_sync to convergence.
    pub wall_secs: f64,
    /// Total events transferred (sum of both directions).
    pub events_transferred: u64,
    /// Events per second (events_transferred / wall_secs).
    pub events_per_sec: f64,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Throughput in MiB/s.
    pub throughput_mib_s: f64,
}

impl std::fmt::Display for SyncMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} events in {:.2}s ({:.0} events/s, {:.2} MiB/s)",
            self.events_transferred, self.wall_secs, self.events_per_sec, self.throughput_mib_s,
        )
    }
}

/// A test peer with its own database and identity.
pub struct Peer {
    pub name: String,
    pub db_path: String,
    pub identity: String,
    pub author_id: [u8; 32],
    pub workspace_id: EventId,
    /// PeerShared event_id used as signer for content events.
    pub peer_shared_event_id: Option<EventId>,
    /// PeerShared signing key for signing content events.
    pub peer_shared_signing_key: Option<SigningKey>,
    _tempdir: tempfile::TempDir,
}

impl Peer {
    /// Create a new peer with a fresh temp database (no identity chain).
    pub fn new(name: &str) -> Self {
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir
            .path()
            .join(format!("{}.db", name))
            .to_str()
            .unwrap()
            .to_string();

        let db = open_connection(&db_path).expect("failed to open db");
        create_tables(&db).expect("failed to create tables");

        let identity = ensure_transport_peer_id(&db).expect("failed to compute identity");
        let author_id: [u8; 32] = rand::random();

        Self {
            name: name.to_string(),
            db_path,
            identity,
            author_id,
            workspace_id: [0u8; 32],
            peer_shared_event_id: None,
            peer_shared_signing_key: None,
            _tempdir: tempdir,
        }
    }

    /// Create a new peer with a full identity chain via the production
    /// `create_workspace` flow (Workspace → InviteAccepted → UserInvite →
    /// User → DeviceInvite → PeerShared + local signer secrets).
    /// Content events (Message, Reaction, etc.) are signed with the PeerShared key.
    pub fn new_with_identity(name: &str) -> Self {
        let mut peer = Self::new(name);
        peer.bootstrap_identity_chain();
        peer
    }

    /// Bootstrap a full identity chain using the production `create_workspace` flow.
    fn bootstrap_identity_chain(&mut self) {
        use crate::event_modules::workspace::commands::create_workspace;

        let db = open_connection(&self.db_path).expect("failed to open db");
        let old_identity = self.identity.clone();
        let result = create_workspace(
            &db,
            &old_identity,
            "test-workspace",
            "test-user",
            "test-device",
        )
        .expect("failed to bootstrap workspace");

        // Derive identity directly from the returned PeerShared signer key.
        // This avoids singleton transport-identity assumptions in multi-tenant DBs.
        let new_identity = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
            &result.peer_shared_key.verifying_key().to_bytes(),
        ));
        self.identity = new_identity.clone();

        self.workspace_id = result.workspace_id;
        // Look up user_event_id from the created identity chain
        if let Ok(uid) = crate::service::resolve_user_event_id_for_signer(
            &db,
            &new_identity,
            &result.peer_shared_event_id,
        ) {
            self.author_id = uid;
        }
        self.peer_shared_event_id = Some(result.peer_shared_event_id);
        self.peer_shared_signing_key = Some(result.peer_shared_key);
    }

    /// Create a new peer that joins an existing workspace created by `creator`
    /// using the production invite flow with real QUIC bootstrap sync:
    /// creator issues `create_user_invite`, starts a temp sync endpoint,
    /// joiner fetches prerequisite events via bootstrap sync, then calls
    /// `accept_user_invite`. No direct DB-to-DB event copying.
    pub async fn new_in_workspace(name: &str, creator: &Peer) -> Self {
        use crate::db::transport_trust::record_pending_invite_bootstrap_trust;
        use crate::event_modules::workspace::commands::create_user_invite_raw;
        use crate::event_modules::workspace::identity_ops::expected_invite_bootstrap_spki_from_invite_key;
        use crate::event_modules::workspace::invite_link::{
            create_invite_link, parse_bootstrap_address,
        };

        // Create a bare peer with DB tables but NO transport identity.
        // svc_accept_invite will install the invite-derived identity.
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir
            .path()
            .join(format!("{}.db", name))
            .to_str()
            .unwrap()
            .to_string();
        {
            let db = open_connection(&db_path).expect("failed to open db");
            create_tables(&db).expect("failed to create tables");
        }
        let mut peer = Self {
            name: name.to_string(),
            db_path,
            identity: String::new(),
            author_id: rand::random(),
            workspace_id: [0u8; 32],
            peer_shared_event_id: None,
            peer_shared_signing_key: None,
            _tempdir: tempdir,
        };
        let creator_db = open_connection(&creator.db_path).expect("failed to open creator db");
        let creator_peer_key = creator
            .peer_shared_signing_key
            .as_ref()
            .expect("creator has no peer_shared_signing_key; use new_with_identity()");
        let creator_peer_eid = creator
            .peer_shared_event_id
            .expect("creator has no peer_shared_event_id; use new_with_identity()");
        let creator_admin_eid: EventId = creator_db
            .query_row(
                "SELECT event_id
                 FROM admins
                 WHERE recorded_by = ?1
                 ORDER BY event_id ASC
                 LIMIT 1",
                rusqlite::params![&creator.identity],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|b64| event_id_from_base64(&b64))
            .expect("creator has no admin event; use new_with_identity()");

        // Creator issues an invite via workspace::commands API
        let invite = create_user_invite_raw(
            &creator_db,
            &creator.identity,
            creator_peer_key,
            &creator_peer_eid,
            &creator_admin_eid,
            &creator.workspace_id,
        )
        .expect("failed to create user invite");

        // Register pending bootstrap trust so creator's endpoint allows the joiner
        let pending_spki = expected_invite_bootstrap_spki_from_invite_key(&invite.invite_key)
            .expect("failed to derive invite SPKI");
        record_pending_invite_bootstrap_trust(
            &creator_db,
            &creator.identity,
            &event_id_to_base64(&invite.invite_event_id),
            &event_id_to_base64(&creator.workspace_id),
            &pending_spki,
        )
        .expect("failed to record pending bootstrap trust");
        drop(creator_db);

        // Start a real dynamic-trust sync endpoint for the creator and use its
        // address in the invite link. The same endpoint then serves the
        // bootstrap sync loops below.
        let sync_endpoint = create_dynamic_endpoint_for_peer(creator);
        let sync_addr = sync_endpoint.local_addr().expect("failed to get sync addr");

        // Build invite link with creator's bootstrap address and SPKI
        let creator_spki = creator.spki_fingerprint();
        let bootstrap_addr = parse_bootstrap_address(&sync_addr.to_string())
            .expect("failed to parse bootstrap addr");
        let invite_link = create_invite_link(&invite, &[bootstrap_addr], &creator_spki)
            .expect("failed to create invite link");

        // Step 1: Accept invite — stores events (may block), materializes bootstrap trust
        let result = crate::event_modules::workspace::commands::accept_invite(
            &peer.db_path,
            &invite_link,
            name,
            "device",
        )
        .expect("failed to accept invite");

        let scoped_peer_id = result.peer_id.clone();
        peer.identity = scoped_peer_id.clone();
        peer.workspace_id = creator.workspace_id;
        let db = open_connection(&peer.db_path).expect("failed to open db");
        let creator_db = open_connection(&creator.db_path).expect("failed to reopen creator db");

        let creator_peer_b64 = event_id_to_base64(&creator_peer_eid);
        let creator_peer_blob: Vec<u8> = creator_db
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&creator_peer_b64],
                |row| row.get(0),
            )
            .expect("failed to load creator peer_shared blob");
        let creator_device_invite_eid = match crate::event_modules::parse_event(&creator_peer_blob)
            .expect("failed to parse creator peer_shared")
        {
            ParsedEvent::PeerShared(ps) => ps.signed_by,
            _ => panic!("creator peer_shared event has unexpected type"),
        };

        let creator_user_b64 = event_id_to_base64(&creator.author_id);
        let creator_user_blob: Vec<u8> = creator_db
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&creator_user_b64],
                |row| row.get(0),
            )
            .expect("failed to load creator user blob");
        let creator_user_invite_eid = match crate::event_modules::parse_event(&creator_user_blob)
            .expect("failed to parse creator user")
        {
            ParsedEvent::User(u) => u.signed_by,
            _ => panic!("creator user event has unexpected type"),
        };

        copy_projected_events_for_tenant(
            &creator_db,
            &db,
            &scoped_peer_id,
            &[
                creator.workspace_id,
                creator_user_invite_eid,
                creator.author_id,
                creator_device_invite_eid,
                creator_peer_eid,
                creator_admin_eid,
                invite.invite_event_id,
            ],
        );
        let creator_shared_event_ids =
            list_shared_event_ids_for_tenant(&creator_db, &creator.identity);
        copy_projected_events_for_tenant(
            &creator_db,
            &db,
            &scoped_peer_id,
            &creator_shared_event_ids,
        );
        let joiner_shared_event_ids = list_shared_event_ids_for_tenant(&db, &scoped_peer_id);
        copy_projected_events_for_tenant(
            &db,
            &creator_db,
            &creator.identity,
            &joiner_shared_event_ids,
        );

        // Step 2: Run the same ongoing sync loops the runtime would use until
        // the bootstrap chain materializes the joiner's local signer.
        let creator_ep = sync_endpoint.clone();
        let creator_db = creator.db_path.clone();
        let creator_id = creator.identity.clone();
        let _creator_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(err) = accept_loop(
                    &creator_db,
                    &creator_id,
                    creator_ep,
                    noop_intro_spawner,
                    test_ingest_fns(),
                )
                .await
                {
                    eprintln!("bootstrap accept_loop exited: {err}");
                }
            });
        });

        let peer_endpoint = create_dynamic_endpoint_for_peer(&peer);
        let peer_ep = peer_endpoint.clone();
        let peer_db = peer.db_path.clone();
        let peer_id = scoped_peer_id.clone();
        let creator_target_peer_id = hex::encode(creator.spki_fingerprint());
        let creator_target_peer_id_for_thread = creator_target_peer_id.clone();
        let invite_event_id_b64 = event_id_to_base64(&invite.invite_event_id);
        let _connector_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(err) =
                    connect_loop_with_coordination_until_cancel_with_fallback_with_auth(
                        &peer_db,
                        &peer_id,
                        peer_ep,
                        sync_addr,
                        &creator_target_peer_id_for_thread,
                        &creator_target_peer_id_for_thread,
                        OutboundSessionAuthPlan::InviteBootstrap {
                            invite_event_id: invite_event_id_b64,
                        },
                        None,
                        noop_intro_spawner,
                        test_ingest_fns(),
                        CancellationToken::new(),
                        None,
                        None,
                    )
                    .await
                {
                    eprintln!("bootstrap connect_loop exited: {err}");
                }
            });
        });

        // Load signing key and user_event_id from DB in a read-your-writes step.
        let (eid, key) = wait_for_materialized_local_peer_signer(
            &peer.db_path,
            &scoped_peer_id,
            Duration::from_secs(10),
        )
        .await;
        let local_transport_peer_id = wait_for_any_tenant_transport_target(
            &peer.db_path,
            &scoped_peer_id,
            Duration::from_secs(10),
        )
        .await;
        wait_for_projected_peer_transport(
            &peer.db_path,
            &scoped_peer_id,
            &creator.transport_peer_id(),
            Duration::from_secs(10),
        )
        .await;
        wait_for_projected_peer_transport(
            &creator.db_path,
            &creator.identity,
            &local_transport_peer_id,
            Duration::from_secs(10),
        )
        .await;
        peer_endpoint.close(0u32.into(), b"bootstrap done");
        sync_endpoint.close(0u32.into(), b"bootstrap done");

        peer.peer_shared_event_id = Some(eid);
        peer.peer_shared_signing_key = Some(key);
        if let Ok(uid) =
            crate::service::resolve_user_event_id_for_signer(&db, &scoped_peer_id, &eid)
        {
            peer.author_id = uid;
        }

        peer
    }

    /// Create a new device for an existing workspace user using the production
    /// device-link flow with real QUIC bootstrap sync.
    pub async fn new_device_in_workspace(name: &str, creator: &Peer) -> Self {
        use crate::db::transport_trust::record_pending_invite_bootstrap_trust;
        use crate::event_modules::workspace::commands::create_device_link_invite_raw;
        use crate::event_modules::workspace::identity_ops::expected_invite_bootstrap_spki_from_invite_key;
        use crate::event_modules::workspace::invite_link::{
            create_invite_link, parse_bootstrap_address,
        };

        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir
            .path()
            .join(format!("{}.db", name))
            .to_str()
            .unwrap()
            .to_string();
        {
            let db = open_connection(&db_path).expect("failed to open db");
            create_tables(&db).expect("failed to create tables");
        }
        let mut peer = Self {
            name: name.to_string(),
            db_path,
            identity: String::new(),
            author_id: rand::random(),
            workspace_id: [0u8; 32],
            peer_shared_event_id: None,
            peer_shared_signing_key: None,
            _tempdir: tempdir,
        };

        let creator_db = open_connection(&creator.db_path).expect("failed to open creator db");
        let creator_peer_key = creator
            .peer_shared_signing_key
            .as_ref()
            .expect("creator has no peer_shared_signing_key; use new_with_identity()");
        let creator_peer_eid = creator
            .peer_shared_event_id
            .expect("creator has no peer_shared_event_id; use new_with_identity()");
        let creator_admin_eid: EventId = creator_db
            .query_row(
                "SELECT event_id
                 FROM admins
                 WHERE recorded_by = ?1
                 ORDER BY event_id ASC
                 LIMIT 1",
                rusqlite::params![&creator.identity],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|b64| event_id_from_base64(&b64))
            .expect("creator has no admin event; use new_with_identity()");
        let invite = create_device_link_invite_raw(
            &creator_db,
            &creator.identity,
            creator_peer_key,
            &creator_peer_eid,
            &creator.author_id,
            &creator.workspace_id,
        )
        .expect("failed to create device link invite");

        let pending_spki = expected_invite_bootstrap_spki_from_invite_key(&invite.invite_key)
            .expect("failed to derive invite SPKI");
        record_pending_invite_bootstrap_trust(
            &creator_db,
            &creator.identity,
            &event_id_to_base64(&invite.invite_event_id),
            &event_id_to_base64(&creator.workspace_id),
            &pending_spki,
        )
        .expect("failed to record pending bootstrap trust");
        drop(creator_db);

        let sync_endpoint = create_dynamic_endpoint_for_peer(creator);
        let sync_addr = sync_endpoint.local_addr().expect("failed to get sync addr");

        let creator_spki = creator.spki_fingerprint();
        let bootstrap_addr = parse_bootstrap_address(&sync_addr.to_string())
            .expect("failed to parse bootstrap addr");
        let invite_link = create_invite_link(&invite, &[bootstrap_addr], &creator_spki)
            .expect("failed to create device-link invite link");

        let result = crate::event_modules::workspace::commands::accept_device_link(
            &peer.db_path,
            &invite_link,
            name,
        )
        .expect("failed to accept device link");

        let scoped_peer_id = result.peer_id.clone();
        peer.identity = scoped_peer_id.clone();
        peer.workspace_id = creator.workspace_id;
        let db = open_connection(&peer.db_path).expect("failed to open db");
        let creator_db = open_connection(&creator.db_path).expect("failed to reopen creator db");

        let creator_peer_b64 = event_id_to_base64(&creator_peer_eid);
        let creator_peer_blob: Vec<u8> = creator_db
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&creator_peer_b64],
                |row| row.get(0),
            )
            .expect("failed to load creator peer_shared blob");
        let creator_device_invite_eid = match crate::event_modules::parse_event(&creator_peer_blob)
            .expect("failed to parse creator peer_shared")
        {
            ParsedEvent::PeerShared(ps) => ps.signed_by,
            _ => panic!("creator peer_shared event has unexpected type"),
        };

        let creator_user_b64 = event_id_to_base64(&creator.author_id);
        let creator_user_blob: Vec<u8> = creator_db
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&creator_user_b64],
                |row| row.get(0),
            )
            .expect("failed to load creator user blob");
        let creator_user_invite_eid = match crate::event_modules::parse_event(&creator_user_blob)
            .expect("failed to parse creator user")
        {
            ParsedEvent::User(u) => u.signed_by,
            _ => panic!("creator user event has unexpected type"),
        };

        copy_projected_events_for_tenant(
            &creator_db,
            &db,
            &scoped_peer_id,
            &[
                creator.workspace_id,
                creator_user_invite_eid,
                creator.author_id,
                creator_device_invite_eid,
                creator_peer_eid,
                creator_admin_eid,
                invite.invite_event_id,
            ],
        );
        let creator_shared_event_ids =
            list_shared_event_ids_for_tenant(&creator_db, &creator.identity);
        copy_projected_events_for_tenant(
            &creator_db,
            &db,
            &scoped_peer_id,
            &creator_shared_event_ids,
        );
        let joiner_shared_event_ids = list_shared_event_ids_for_tenant(&db, &scoped_peer_id);
        copy_projected_events_for_tenant(
            &db,
            &creator_db,
            &creator.identity,
            &joiner_shared_event_ids,
        );

        let creator_ep = sync_endpoint.clone();
        let creator_db = creator.db_path.clone();
        let creator_id = creator.identity.clone();
        let _creator_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(err) = accept_loop(
                    &creator_db,
                    &creator_id,
                    creator_ep,
                    noop_intro_spawner,
                    test_ingest_fns(),
                )
                .await
                {
                    eprintln!("device bootstrap accept_loop exited: {err}");
                }
            });
        });

        let peer_endpoint = create_dynamic_endpoint_for_peer(&peer);
        let peer_ep = peer_endpoint.clone();
        let peer_db = peer.db_path.clone();
        let peer_id = scoped_peer_id.clone();
        let creator_target_peer_id = hex::encode(creator.spki_fingerprint());
        let creator_target_peer_id_for_thread = creator_target_peer_id.clone();
        let invite_event_id_b64 = event_id_to_base64(&invite.invite_event_id);
        let _connector_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(err) =
                    connect_loop_with_coordination_until_cancel_with_fallback_with_auth(
                        &peer_db,
                        &peer_id,
                        peer_ep,
                        sync_addr,
                        &creator_target_peer_id_for_thread,
                        &creator_target_peer_id_for_thread,
                        OutboundSessionAuthPlan::InviteBootstrap {
                            invite_event_id: invite_event_id_b64,
                        },
                        None,
                        noop_intro_spawner,
                        test_ingest_fns(),
                        CancellationToken::new(),
                        None,
                        None,
                    )
                    .await
                {
                    eprintln!("device bootstrap connect_loop exited: {err}");
                }
            });
        });

        let (eid, key) = wait_for_materialized_local_peer_signer(
            &peer.db_path,
            &scoped_peer_id,
            Duration::from_secs(10),
        )
        .await;
        let local_transport_peer_id = wait_for_any_tenant_transport_target(
            &peer.db_path,
            &scoped_peer_id,
            Duration::from_secs(10),
        )
        .await;
        wait_for_projected_peer_transport(
            &peer.db_path,
            &scoped_peer_id,
            &creator.transport_peer_id(),
            Duration::from_secs(10),
        )
        .await;
        wait_for_projected_peer_transport(
            &creator.db_path,
            &creator.identity,
            &local_transport_peer_id,
            Duration::from_secs(10),
        )
        .await;
        peer_endpoint.close(0u32.into(), b"bootstrap done");
        sync_endpoint.close(0u32.into(), b"bootstrap done");

        peer.peer_shared_event_id = Some(eid);
        peer.peer_shared_signing_key = Some(key);
        if let Ok(uid) =
            crate::service::resolve_user_event_id_for_signer(&db, &scoped_peer_id, &eid)
        {
            peer.author_id = uid;
        }

        peer
    }

    /// Get the PeerShared signer event_id. Panics if no identity chain.
    fn signer_eid(&self) -> EventId {
        self.peer_shared_event_id
            .expect("Peer has no identity chain; use new_with_identity()")
    }

    /// Get a reference to the PeerShared signing key. Panics if no identity chain.
    fn signing_key(&self) -> &SigningKey {
        self.peer_shared_signing_key
            .as_ref()
            .expect("Peer has no identity chain; use new_with_identity()")
    }

    /// Load (or generate) the transport certificate and private key for this peer.
    pub fn cert_and_key(&self) -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
        if let Some(signing_key) = self.peer_shared_signing_key.as_ref() {
            return crate::transport::generate_self_signed_cert_from_signing_key(signing_key)
                .expect("failed to derive cert from peer_shared signer");
        }

        let db = open_connection(&self.db_path).expect("failed to open db");
        let transport_peer_id =
            crate::state::db::transport_creds::resolve_tenant_transport_target(&db, &self.identity)
                .expect("failed to resolve tenant transport target")
                .map(|target| target.transport_peer_id)
                .unwrap_or_else(|| self.identity.clone());
        let (cert, key) =
            load_transport_cert(&db, &transport_peer_id).expect("failed to load cert");
        (cert, key)
    }

    /// Extract the SPKI fingerprint (SHA-256) from this peer's transport certificate.
    pub fn spki_fingerprint(&self) -> [u8; 32] {
        let (cert, _) = self.cert_and_key();
        extract_spki_fingerprint(cert.as_ref()).expect("failed to extract fingerprint")
    }

    /// Return the current exact transport target id (hex SPKI fingerprint) for this peer.
    pub fn transport_peer_id(&self) -> String {
        hex::encode(self.spki_fingerprint())
    }

    /// Create a message and insert it into all relevant tables.
    /// Returns the event ID. Requires identity chain (use new_with_identity).
    pub fn create_message(&self, content: &str) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let inner = ParsedEvent::Message(MessageEvent {
            created_at_ms: current_timestamp_ms(),
            workspace_id: self.workspace_id,
            author_id: self.author_id,
            content: content.to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        self.create_encrypted_signed_event_synchronous(&self.content_key_event_id(&db), &inner)
    }

    /// Create a reaction targeting a message event.
    /// Returns the reaction event ID. Requires identity chain.
    pub fn create_reaction(&self, target_event_id: &EventId, emoji: &str) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let inner = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            emoji: emoji.to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        self.create_encrypted_signed_event_synchronous(&self.content_key_event_id(&db), &inner)
    }

    /// Create a reaction, tolerating blocked projection when the target message
    /// is not valid locally yet. Returns the encrypted wrapper event_id.
    pub fn create_reaction_staged(&self, target_event_id: &EventId, emoji: &str) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let inner = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            emoji: emoji.to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        create_encrypted_event_staged(
            &db,
            &self.identity,
            &self.content_key_event_id(&db),
            &inner,
            Some(self.signing_key()),
        )
        .expect("failed to create staged encrypted reaction")
    }

    /// Create a KeySecret event with the given key bytes.
    /// Returns the event ID.
    pub fn create_key_secret(&self, key_bytes: [u8; 32]) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let sk = ParsedEvent::KeySecret(KeySecretEvent {
            created_at_ms: current_timestamp_ms(),
            key_bytes,
        });
        create_event_synchronous(&db, &self.identity, &sk).expect("failed to create key_secret")
    }

    /// Create a KeySecret event with deterministic key bytes and timestamp.
    /// Two peers calling this with the same args produce the same blob -> same event_id.
    /// This is used for PSK materialization in tests where both peers need the same key.
    pub fn create_key_secret_deterministic(
        &self,
        key_bytes: [u8; 32],
        created_at_ms: u64,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let sk = ParsedEvent::KeySecret(KeySecretEvent {
            created_at_ms,
            key_bytes,
        });
        create_event_synchronous(&db, &self.identity, &sk).expect("failed to create key_secret")
    }

    /// Create an encrypted message. The inner message is signed with the PeerShared key,
    /// then encrypted. Returns the encrypted event ID. Requires identity chain.
    pub fn create_encrypted_message(&self, key_event_id: &EventId, content: &str) -> EventId {
        let inner = ParsedEvent::Message(MessageEvent {
            created_at_ms: current_timestamp_ms(),
            workspace_id: self.workspace_id,
            author_id: self.author_id,
            content: content.to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        // Sign the inner event, then encrypt the signed blob
        self.create_encrypted_signed_event_synchronous(key_event_id, &inner)
    }

    /// Sign an inner event, encrypt the signed blob, wrap in EncryptedEvent, store + project.
    /// Uses event_id_or_blocked so events whose deps are missing are stored in blocked
    /// state rather than panicking, mirroring real ingestion behaviour.
    fn create_encrypted_signed_event_synchronous(
        &self,
        key_event_id: &EventId,
        inner_event: &ParsedEvent,
    ) -> EventId {
        for attempt in 0..TESTUTIL_SQLITE_BUSY_RETRY_ATTEMPTS {
            let db = open_connection(&self.db_path).expect("failed to open db");
            // Full-suite sync_graph runs can create substantial writer
            // contention on a single test DB. Use a fresh connection per
            // attempt and give it a longer wait budget before surfacing
            // SQLITE_BUSY so realistic graph tests remain stable under the
            // default cargo scheduler.
            let _ = db.busy_timeout(Duration::from_secs(30));
            match event_id_or_blocked(create_encrypted_event_synchronous(
                &db,
                &self.identity,
                key_event_id,
                inner_event,
                Some(self.signing_key()),
            )) {
                Ok(event_id) => return event_id,
                Err(CreateEventError::DbError(err))
                    if err.contains("database is locked")
                        && attempt + 1 < TESTUTIL_SQLITE_BUSY_RETRY_ATTEMPTS =>
                {
                    std::thread::sleep(Duration::from_millis(SQLITE_BUSY_RETRY_BASE_MS << attempt));
                }
                Err(err) => panic!("failed to create encrypted signed event: {err}"),
            }
        }

        unreachable!("loop returns on success or final error")
    }

    fn content_key_event_id(&self, db: &rusqlite::Connection) -> EventId {
        crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
            db,
            &self.identity,
        )
        .expect("failed to ensure content key")
    }

    pub fn ensure_content_key_event_id(&self) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        self.content_key_event_id(&db)
    }

    /// Create a MessageDeletion event targeting the given message event.
    /// Returns the deletion event ID. Requires identity chain.
    pub fn create_message_deletion(&self, target_event_id: &EventId) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let inner = ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        self.create_encrypted_signed_event_synchronous(&self.content_key_event_id(&db), &inner)
    }

    /// Create an encrypted MessageDeletion event.
    /// Returns the encrypted event ID. Requires identity chain.
    pub fn create_encrypted_deletion(
        &self,
        key_event_id: &EventId,
        target_event_id: &EventId,
    ) -> EventId {
        let inner = ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: current_timestamp_ms(),
            target_event_id: *target_event_id,
            author_id: self.author_id,
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        self.create_encrypted_signed_event_synchronous(key_event_id, &inner)
    }

    // --- Identity event helpers ---

    /// Create a Workspace event. Returns the event ID.
    ///
    /// Uses staged projection; workspace validity unblocks after invite_accepted
    /// projects and emits a retry command.
    pub fn create_workspace(&self, public_key: [u8; 32]) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
            name: "test-workspace".to_string(),
        });
        // Pre-compute event_id to assert deterministic staged write identity.
        let ws_blob =
            crate::event_modules::encode_event(&ws).expect("failed to encode workspace event");
        let ws_eid = crate::crypto::hash_event(&ws_blob);
        let ws_eid2 =
            create_event_staged(&db, &self.identity, &ws).expect("failed to create workspace");
        assert_eq!(ws_eid, ws_eid2, "pre-computed workspace event_id mismatch");
        ws_eid
    }

    /// Try to create a Workspace event. Returns Result to allow handling rejection.
    pub fn try_create_workspace(&self, public_key: [u8; 32]) -> Result<EventId, CreateEventError> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
            name: "test-workspace".to_string(),
        });
        create_event_synchronous(&db, &self.identity, &ws)
    }

    /// Record the local invite-link workspace binding that InviteAccepted
    /// projection uses to self-validate external accepts in tests.
    pub fn record_invite_link_workspace(&self, invite_event_id: &EventId, workspace_id: [u8; 32]) {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let invite_event_id_b64 = event_id_to_base64(invite_event_id);
        let workspace_id_b64 = event_id_to_base64(&workspace_id);
        crate::db::transport_trust::append_bootstrap_context(
            &db,
            &self.identity,
            &invite_event_id_b64,
            &workspace_id_b64,
            "",
            &[0xAB; 32],
        )
        .expect("failed to record invite-link workspace binding");
    }

    /// Create an InviteAccepted event (local). Returns the event ID.
    pub fn create_invite_accepted(
        &self,
        invite_event_id: &EventId,
        workspace_id: [u8; 32],
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let tenant_event_id = self.ensure_local_tenant_event_id(&db);
        let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: current_timestamp_ms(),
            tenant_event_id,
            invite_event_id: *invite_event_id,
            workspace_id,
        });
        create_event_synchronous(&db, &self.identity, &ia)
            .expect("failed to create invite_accepted")
    }

    /// Try to create an InviteAccepted event. Returns Result to allow handling rejection.
    pub fn try_create_invite_accepted(
        &self,
        invite_event_id: &EventId,
        workspace_id: [u8; 32],
    ) -> Result<EventId, CreateEventError> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let tenant_event_id = self.ensure_local_tenant_event_id(&db);
        let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: current_timestamp_ms(),
            tenant_event_id,
            invite_event_id: *invite_event_id,
            workspace_id,
        });
        create_event_synchronous(&db, &self.identity, &ia)
    }

    fn ensure_local_tenant_event_id(&self, db: &rusqlite::Connection) -> EventId {
        let existing: Option<String> = db
            .query_row(
                "SELECT event_id FROM tenants WHERE recorded_by = ?1 ORDER BY created_at ASC, event_id ASC LIMIT 1",
                rusqlite::params![&self.identity],
                |row| row.get(0),
            )
            .ok();
        if let Some(eid_b64) = existing {
            return event_id_from_base64(&eid_b64).expect("invalid tenants.event_id base64");
        }

        let peer_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let tenant_evt = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: peer_key.verifying_key().to_bytes(),
        });
        create_event_synchronous(db, &self.identity, &tenant_evt).expect("failed to create tenant")
    }

    /// Create a UserInvite event (signed by workspace key). Returns the event ID.
    pub fn create_user_invite(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        workspace_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let public_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key()
            .to_bytes();
        let evt = ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: current_timestamp_ms(),
            public_key,
            workspace_id: *workspace_id,
            authority_event_id: *workspace_id,
            signed_by: *workspace_id,
            signer_type: 1,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create user_invite")
    }

    /// Create a UserInvite with a specific public key. Returns the event ID.
    pub fn create_user_invite_with_key(
        &self,
        invite_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        workspace_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: invite_public_key,
            workspace_id: *workspace_id,
            authority_event_id: *workspace_id,
            signed_by: *workspace_id,
            signer_type: 1,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create user_invite")
    }

    /// Create a deterministic local invite_secret event for an invite.
    pub fn create_invite_secret(
        &self,
        invite_event_id: &EventId,
        invite_private_key: [u8; 32],
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = crate::event_modules::invite_secret::deterministic_invite_secret_event(
            *invite_event_id,
            invite_private_key,
        );
        create_event_staged(&db, &self.identity, &evt).expect("failed to create invite_secret")
    }

    /// Create a User event (signed by UserInvite key). Returns the event ID.
    pub fn create_user(
        &self,
        user_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        user_invite_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::User(UserEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: user_public_key,
            username: "test-user".to_string(),
            signed_by: *user_invite_event_id,
            signer_type: 2,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create user")
    }

    /// Create a DeviceInvite event (signed by User key). Returns the event ID.
    pub fn create_device_invite(
        &self,
        device_invite_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        user_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: device_invite_public_key,
            authority_event_id: *user_event_id,
            signed_by: *user_event_id,
            signer_type: 4,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create device_invite")
    }

    /// Create a PeerShared event (signed by DeviceInvite key). Returns the event ID.
    pub fn create_peer_shared(
        &self,
        peer_shared_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        device_invite_event_id: &EventId,
        user_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: peer_shared_public_key,
            user_event_id: *user_event_id,
            device_name: "test-device".to_string(),
            signed_by: *device_invite_event_id,
            signer_type: 3,
            signature: [0u8; 64],
        });
        create_signed_event_staged(&db, &self.identity, &evt, signing_key)
            .expect("failed to create peer_shared")
    }

    /// Create an Admin event (signed by Workspace key, dep on User). Returns the event ID.
    pub fn create_admin(
        &self,
        admin_public_key: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        user_event_id: &EventId,
        workspace_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::Admin(AdminEvent {
            created_at_ms: current_timestamp_ms(),
            public_key: admin_public_key,
            user_event_id: *user_event_id,
            signed_by: *workspace_id,
            signer_type: 1,
            signature: [0u8; 64],
        });
        create_signed_event_synchronous(&db, &self.identity, &evt, signing_key)
            .expect("failed to create admin")
    }

    /// Create a KeyShared event (signed by PeerShared key). Returns the event ID.
    pub fn create_key_shared(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        key_event_id: &EventId,
        recipient_event_id: &EventId,
        unwrap_key_event_id: &EventId,
        wrapped_key: [u8; 32],
        peer_shared_event_id: &EventId,
    ) -> EventId {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let evt = ParsedEvent::KeyShared(KeySharedEvent {
            created_at_ms: current_timestamp_ms(),
            key_event_id: *key_event_id,
            recipient_event_id: *recipient_event_id,
            unwrap_key_event_id: *unwrap_key_event_id,
            wrapped_key,
            signed_by: *peer_shared_event_id,
            signer_type: 5,
            signature: [0u8; 64],
        });
        create_signed_event_synchronous(&db, &self.identity, &evt, signing_key)
            .expect("failed to create key_shared")
    }

    /// Create multiple messages. Uses a transaction for speed at scale.
    /// Requires identity chain.
    pub fn batch_create_messages(&self, count: usize) {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let key_event_id = self.content_key_event_id(&db);
        db.execute("BEGIN", []).expect("failed to begin");
        for i in 0..count {
            let inner = ParsedEvent::Message(MessageEvent {
                created_at_ms: current_timestamp_ms(),
                workspace_id: self.workspace_id,
                author_id: self.author_id,
                content: format!("Message {} from {}", i, self.name),
                signed_by: self.signer_eid(),
                signer_type: 5,
                signature: [0u8; 64],
            });
            event_id_or_blocked(create_encrypted_event_synchronous(
                &db,
                &self.identity,
                &key_event_id,
                &inner,
                Some(self.signing_key()),
            ))
            .expect("failed to create batch message");
        }
        db.execute("COMMIT", []).expect("failed to commit");
    }

    /// Create multiple messages whose `created_at_ms` values are spread across
    /// a wall-clock span. Requires identity chain.
    pub fn batch_create_messages_spread(&self, count: usize, start_ms: u64, spread_ms: u64) {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let key_event_id = self.content_key_event_id(&db);
        db.execute("BEGIN", []).expect("failed to begin");
        for i in 0..count {
            let offset_ms = if count <= 1 {
                0
            } else {
                spread_ms.saturating_mul(i as u64) / (count.saturating_sub(1) as u64)
            };
            let inner = ParsedEvent::Message(MessageEvent {
                created_at_ms: start_ms.saturating_add(offset_ms),
                workspace_id: self.workspace_id,
                author_id: self.author_id,
                content: format!("Spread message {} from {}", i, self.name),
                signed_by: self.signer_eid(),
                signer_type: 5,
                signature: [0u8; 64],
            });
            event_id_or_blocked(create_encrypted_event_synchronous(
                &db,
                &self.identity,
                &key_event_id,
                &inner,
                Some(self.signing_key()),
            ))
            .expect("failed to create spread batch message");
        }
        db.execute("COMMIT", []).expect("failed to commit");
    }

    /// Create a file consisting of `total_slices` file slices.
    ///
    /// Builds all required prerequisites (message, key_secret, attachment
    /// descriptor) and then batch-creates the slices. Returns the file_id
    /// used for all slices. Requires identity chain (use new_with_identity).
    pub fn batch_create_file_slices(&self, total_slices: usize) -> [u8; 32] {
        use crate::event_modules::file_slice::FILE_SLICE_CIPHERTEXT_BYTES;
        use crate::projection::signer::sign_event_bytes;

        let db = open_connection(&self.db_path).expect("failed to open db");
        let workspace_id = crate::db::store::lookup_workspace_id(&db, &self.identity)
            .expect("missing trust anchor workspace_id for file-slice benchmark");

        // Parent message
        let key_event_id = self.content_key_event_id(&db);

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: current_timestamp_ms(),
            workspace_id: self.workspace_id,
            author_id: self.author_id,
            content: format!("file-parent-{}", self.name),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        let msg_eid = self.create_encrypted_signed_event_synchronous(&key_event_id, &msg);

        let file_id: [u8; 32] = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            self.name.hash(&mut hasher);
            current_timestamp_ms().hash(&mut hasher);
            let h = hasher.finish().to_le_bytes();
            let mut fid = [0u8; 32];
            fid[..8].copy_from_slice(&h);
            fid[8..16].copy_from_slice(&h);
            fid
        };

        let slice_size = FILE_SLICE_CIPHERTEXT_BYTES;
        let file_bytes = total_slices * slice_size;

        // Message attachment descriptor
        let att = ParsedEvent::File(FileEvent {
            created_at_ms: current_timestamp_ms(),
            message_id: msg_eid,
            file_id,
            blob_bytes: file_bytes as u64,
            total_slices: total_slices as u32,
            slice_bytes: slice_size as u32,
            root_hash: [0xAA; 32],
            key_event_id,
            filename: format!("bench-{}.bin", self.name),
            mime_type: "application/octet-stream".to_string(),
            signed_by: self.signer_eid(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        let _att_eid = self.create_encrypted_signed_event_synchronous(&key_event_id, &att);

        // Batch-create file slices inside a transaction
        let ciphertext: Vec<u8> = vec![0xAB; FILE_SLICE_CIPHERTEXT_BYTES];
        let signing_key = self.signing_key().clone();

        db.execute("BEGIN", []).expect("failed to begin");
        for i in 0..total_slices as u32 {
            // Use a single timestamp for both the blob's created_at and the
            // neg_items ts. If these diverge, the sink's batch_writer (which
            // extracts created_at from the blob) inserts a different neg_items
            // key than the source, causing negentropy to never converge.
            let created_at = current_timestamp_ms();
            let fs = ParsedEvent::FileSlice(FileSliceEvent {
                created_at_ms: created_at,
                file_id,
                slice_number: i,
                ciphertext: ciphertext.clone(),
                signed_by: self.signer_eid(),
                signer_type: 5,
                signature: [0u8; 64],
            });
            let mut inner_blob =
                crate::event_modules::encode_event(&fs).expect("failed to encode file_slice");
            let blob_len = inner_blob.len();
            let sig = sign_event_bytes(&signing_key, &inner_blob[..blob_len - 64]);
            inner_blob[blob_len - 64..].copy_from_slice(&sig);

            let key_bytes: Vec<u8> = db
                .query_row(
                    "SELECT key_bytes FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2",
                    rusqlite::params![&self.identity, event_id_to_base64(&key_event_id)],
                    |row| row.get(0),
                )
                .expect("failed to load content key bytes");
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key_bytes);
            let (nonce, ciphertext, auth_tag) =
                crate::projection::encrypted::encrypt_event_blob(&key_arr, &inner_blob)
                    .expect("failed to encrypt file_slice");
            let enc = ParsedEvent::Encrypted(crate::event_modules::EncryptedEvent {
                created_at_ms: current_timestamp_ms(),
                key_event_id,
                inner_type_code: crate::event_modules::EVENT_TYPE_FILE_SLICE,
                nonce,
                ciphertext,
                auth_tag,
            });
            let blob =
                crate::event_modules::encode_event(&enc).expect("failed to encode encrypted");

            let event_id = crate::crypto::hash_event(&blob);
            let event_id_b64 = event_id_to_base64(&event_id);

            // Insert into events, neg_items, recorded_events — all use the
            // same created_at that is embedded in the blob so that the
            // neg_items (ts, id) key matches what a receiving batch_writer
            // would extract from the blob.
            db.execute(
                "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, ?2, ?3, 'shared', ?4, ?5)",
                rusqlite::params![&event_id_b64, "encrypted", blob.as_slice(), created_at as i64, created_at as i64],
            ).expect("failed to insert file_slice event");
            db.execute(
                "INSERT OR IGNORE INTO neg_items (workspace_id, ts, id) VALUES (?1, ?2, ?3)",
                rusqlite::params![&workspace_id, created_at as i64, event_id.as_slice()],
            )
            .expect("failed to insert neg_item");
            db.execute(
                "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
                 VALUES (?1, ?2, ?3, 'local')",
                rusqlite::params![&self.identity, &event_id_b64, created_at as i64],
            )
            .expect("failed to insert recorded_event");

            // Project (validates decryption, signature, and authorization chain)
            project_one(&db, &self.identity, &event_id).expect("failed to project file_slice");
        }
        db.execute("COMMIT", []).expect("failed to commit");

        file_id
    }

    /// Query file-slice event counts grouped by ingest source.
    ///
    /// Returns a map of source_peer → event_count. Uses events + recorded_events
    /// tables (no projection required). Module-local query helper.
    pub fn file_slice_event_counts_by_source(&self) -> std::collections::HashMap<String, i64> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        crate::event_modules::file_slice::file_slice_event_counts_by_source(&db, &self.identity)
    }

    /// Count file_slice events received by this peer (no projection required).
    pub fn file_slice_event_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        crate::event_modules::file_slice::file_slice_event_count(&db, &self.identity)
    }

    /// Count events in the events table.
    /// Returns -1 if the database can't be opened (transient contention).
    pub fn store_count(&self) -> i64 {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return -1,
        };
        db.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Count sync-eligible shared-scope events in the events table.
    /// Returns -1 if the database can't be opened (transient contention).
    pub fn shared_store_count(&self) -> i64 {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return -1,
        };
        db.query_row(
            "SELECT COUNT(*) FROM events WHERE share_scope = 'shared'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rows in the messages projection table (all, unscoped).
    pub fn message_count(&self) -> i64 {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return -1,
        };
        db.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Count stored message events from canonical `events` by event_type.
    /// Includes local and synced remote message events.
    pub fn stored_message_event_count(&self) -> i64 {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return -1,
        };
        db.query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1 AND semantic_type_code = ?2",
            rusqlite::params![
                &self.identity,
                i64::from(crate::event_modules::EVENT_TYPE_MESSAGE)
            ],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count recorded message events using the encrypted wrapper's exposed
    /// inner semantic type. This works even when the local tenant cannot
    /// decrypt or validate another workspace's message payloads.
    pub fn recorded_message_event_count(&self) -> i64 {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return -1,
        };
        db.query_row(
            "SELECT COUNT(*)
             FROM recorded_events re
             JOIN events e ON e.event_id = re.event_id
             WHERE re.peer_id = ?1
               AND (
                    e.event_type = 'message'
                    OR (
                        e.event_type = 'encrypted'
                        AND substr(e.blob, 42, 1) = ?2
                    )
               )",
            rusqlite::params![
                &self.identity,
                vec![crate::event_modules::EVENT_TYPE_MESSAGE]
            ],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rows in the reactions projection table scoped to this peer.
    pub fn reaction_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rows in the key_secrets projection table scoped to this peer.
    pub fn key_secret_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM key_secrets WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rows in the neg_items table (events advertised for sync).
    pub fn neg_items_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Check if a specific event_id (base64) exists in the events table.
    pub fn has_event(&self, event_id_b64: &str) -> bool {
        let db = match open_count_connection(&self.db_path) {
            Some(db) => db,
            None => return false,
        };
        db.query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            rusqlite::params![event_id_b64],
            |row| row.get(0),
        )
        .unwrap_or(false)
    }

    /// Count rows in the deleted_messages projection table scoped to this peer.
    pub fn deleted_message_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM deleted_messages WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rows in the events table.
    pub fn events_table_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap_or(0)
    }

    /// Count rows in recorded_events scoped to this peer's identity.
    pub fn recorded_events_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count recorded events by `source` for a given event type.
    ///
    /// Uses `source LIKE '<prefix>%'` so callers can isolate transport-ingest
    /// rows (e.g. `quic_recv:`) from local-created rows.
    pub fn recorded_event_type_counts_by_source(
        &self,
        event_type: &str,
        source_prefix: &str,
    ) -> std::collections::BTreeMap<String, i64> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let like = format!("{}%", source_prefix);
        let mut stmt = db
            .prepare(
                "SELECT re.source, COUNT(*)
                   FROM recorded_events re
                   JOIN events e ON e.event_id = re.event_id
                  WHERE re.peer_id = ?1
                    AND e.event_type = ?2
                    AND re.source LIKE ?3
               GROUP BY re.source
               ORDER BY re.source",
            )
            .expect("prepare source histogram query");

        stmt.query_map(rusqlite::params![&self.identity, event_type, like], |row| {
            let source: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((source, count))
        })
        .expect("query source histogram")
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()
        .expect("collect source histogram")
    }

    /// Return sorted set of all store IDs (base64-encoded).
    pub fn store_ids(&self) -> std::collections::BTreeSet<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare("SELECT event_id FROM events ORDER BY event_id")
            .expect("prepare");
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .expect("collect");
        ids
    }

    /// Return sorted set of all shared-scope store IDs (base64-encoded).
    pub fn shared_store_ids(&self) -> std::collections::BTreeSet<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare("SELECT event_id FROM events WHERE share_scope = 'shared' ORDER BY event_id")
            .expect("prepare");
        stmt.query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .expect("collect")
    }

    /// Return sorted set of event IDs for a specific `event_type`.
    pub fn event_ids_by_type(&self, event_type: &str) -> std::collections::BTreeSet<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        if let Some(meta) = crate::event_modules::registry().lookup_by_name(event_type) {
            let mut stmt = db
                .prepare(
                    "SELECT event_id
                     FROM valid_events
                     WHERE peer_id = ?1 AND semantic_type_code = ?2
                     ORDER BY event_id",
                )
                .expect("prepare");
            return stmt
                .query_map(
                    rusqlite::params![&self.identity, i64::from(meta.type_code)],
                    |row| row.get::<_, String>(0),
                )
                .expect("query")
                .collect::<Result<std::collections::BTreeSet<_>, _>>()
                .expect("collect");
        }

        let mut stmt = db
            .prepare("SELECT event_id FROM events WHERE event_type = ?1 ORDER BY event_id")
            .expect("prepare");
        stmt.query_map(rusqlite::params![event_type], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .expect("collect")
    }

    /// Return recorded message event IDs using the encrypted wrapper's
    /// inner semantic type rather than decrypted validity.
    pub fn recorded_message_event_ids(&self) -> std::collections::BTreeSet<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare(
                "SELECT re.event_id
                 FROM recorded_events re
                 JOIN events e ON e.event_id = re.event_id
                 WHERE re.peer_id = ?1
                   AND (
                        e.event_type = 'message'
                        OR (
                            e.event_type = 'encrypted'
                            AND substr(e.blob, 42, 1) = ?2
                        )
                   )
                 ORDER BY re.event_id",
            )
            .expect("prepare");
        stmt.query_map(
            rusqlite::params![
                &self.identity,
                vec![crate::event_modules::EVENT_TYPE_MESSAGE]
            ],
            |row| row.get::<_, String>(0),
        )
        .expect("query")
        .collect::<Result<std::collections::BTreeSet<_>, _>>()
        .expect("collect")
    }

    /// Count messages scoped to this peer's recorded_by identity.
    pub fn scoped_message_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    // --- Identity projection count helpers ---

    /// Count valid events for this peer.
    pub fn valid_event_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count rejected events for this peer.
    pub fn rejected_event_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count blocked event deps for this peer.
    pub fn blocked_dep_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(DISTINCT event_id) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count workspaces projected for this peer.
    pub fn workspace_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM workspaces WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count user invites projected for this peer.
    pub fn user_invite_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM user_invites WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count users projected for this peer.
    pub fn user_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count device invites projected for this peer.
    pub fn device_invite_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM device_invites WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count peers_shared projected for this peer.
    pub fn peer_shared_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count admins projected for this peer.
    pub fn admin_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM admins WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Count invite_accepted projected for this peer.
    pub fn invite_accepted_count(&self) -> i64 {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT COUNT(*) FROM invites_accepted WHERE recorded_by = ?1",
            rusqlite::params![&self.identity],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Get the recorded_at timestamp for a specific event (by base64 event_id).
    pub fn recorded_at_for_event(&self, event_id_b64: &str) -> Option<i64> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.query_row(
            "SELECT recorded_at FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&self.identity, event_id_b64],
            |row| row.get(0),
        )
        .ok()
    }

    /// Get a random sample of event IDs (base64) from the events table.
    pub fn sample_event_ids(&self, count: usize) -> Vec<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare("SELECT event_id FROM events ORDER BY RANDOM() LIMIT ?1")
            .expect("prepare");
        stmt.query_map(rusqlite::params![count as i64], |row| {
            row.get::<_, String>(0)
        })
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect")
    }

    /// Get a random sample of sync-eligible (shared-scope) event IDs (base64).
    pub fn sample_shared_event_ids(&self, count: usize) -> Vec<String> {
        let db = open_connection(&self.db_path).expect("failed to open db");
        let mut stmt = db
            .prepare(
                "SELECT event_id
             FROM events
             WHERE share_scope = 'shared'
             ORDER BY RANDOM()
             LIMIT ?1",
            )
            .expect("prepare");
        stmt.query_map(rusqlite::params![count as i64], |row| {
            row.get::<_, String>(0)
        })
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect")
    }

    /// Insert `count` synthetic pending_invite_bootstrap_trust rows for this peer.
    /// Returns the generated SPKI fingerprints.
    pub fn seed_pending_bootstrap_trust(&self, count: usize) -> Vec<[u8; 32]> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let expires_at = now + 24 * 60 * 60 * 1000;
        let db = open_connection(&self.db_path).expect("failed to open db");
        db.execute("BEGIN", []).expect("failed to begin");
        let mut fps = Vec::with_capacity(count);
        for i in 0..count {
            let mut fp = [0u8; 32];
            let bytes = (i as u64).to_le_bytes();
            fp[..8].copy_from_slice(&bytes);
            fp[8] = 0xFE; // sentinel to distinguish synthetic keys
            fps.push(fp);
            db.execute(
                "INSERT OR IGNORE INTO pending_invite_bootstrap_trust
                 (recorded_by, invite_event_id, workspace_id, expected_bootstrap_spki_fingerprint, created_at, expires_at)
                 VALUES (?1, ?2, 'synthetic_ws', ?3, ?4, ?5)",
                rusqlite::params![&self.identity, format!("synthetic_inv_{}", i), fp.as_slice(), now, expires_at],
            ).expect("failed to insert pending_invite_bootstrap_trust");
        }
        db.execute("COMMIT", []).expect("failed to commit");
        fps
    }
}

// ---------------------------------------------------------------------------
// Deterministic projection fingerprinting
// ---------------------------------------------------------------------------

/// Projection tables included in deterministic fingerprinting.
/// Covers all content and identity projection tables.
/// Excludes operational/transient tables per PLAN §12.4.
const FINGERPRINT_TABLES: &[FingerprintTable] = &[
    // Content projections
    FingerprintTable {
        name: "messages",
        scope: Scope::RecordedBy,
        order: "ORDER BY message_id",
        columns: None,
    },
    FingerprintTable {
        name: "reactions",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "key_secrets",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "deleted_messages",
        scope: Scope::RecordedBy,
        order: "ORDER BY message_id",
        columns: None,
    },
    FingerprintTable {
        name: "files",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "file_slices",
        scope: Scope::RecordedBy,
        order: "ORDER BY file_id, slice_number",
        columns: None,
    },
    // Identity projections
    FingerprintTable {
        name: "workspaces",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "invites_accepted",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "user_invites",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "device_invites",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "users",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "peers_shared",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "admins",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    FingerprintTable {
        name: "key_shared",
        scope: Scope::RecordedBy,
        order: "ORDER BY event_id",
        columns: None,
    },
    // Transport identity (replay-derived via MaterializeTransportIdentity).
    // `created_at` is a wall-clock timestamp — excluded from fingerprint to
    // ensure replay produces identical hashes regardless of when it runs.
    FingerprintTable {
        name: "local_transport_targets",
        scope: Scope::TenantId,
        order: "ORDER BY tenant_id",
        columns: Some("tenant_id, transport_peer_id, source"),
    },
];

struct FingerprintTable {
    name: &'static str,
    scope: Scope,
    order: &'static str,
    /// Explicit column list for SELECT. `None` means `SELECT *`.
    /// Use when a table has non-deterministic columns (e.g. wall-clock `created_at`)
    /// that should be excluded from the fingerprint.
    columns: Option<&'static str>,
}

#[derive(Clone, Copy)]
enum Scope {
    RecordedBy,
    TenantId,
}

/// Per-table fingerprint diagnostic record.
#[derive(Debug)]
struct TableDigest {
    table: &'static str,
    hash: [u8; 32],
    row_count: i64,
}

/// Full projection fingerprint with per-table diagnostics.
#[derive(Debug)]
struct ProjectionFingerprint {
    overall: [u8; 32],
    tables: Vec<TableDigest>,
}

impl ProjectionFingerprint {
    /// Format per-table diagnostics for assertion failure messages.
    fn diff_report(
        &self,
        other: &ProjectionFingerprint,
        self_label: &str,
        other_label: &str,
    ) -> String {
        let mut lines = Vec::new();
        for (a, b) in self.tables.iter().zip(other.tables.iter()) {
            if a.hash != b.hash || a.row_count != b.row_count {
                lines.push(format!(
                    "  {}: {} rows={} hash={} | {} rows={} hash={}",
                    a.table,
                    self_label,
                    a.row_count,
                    hex(&a.hash[..8]),
                    other_label,
                    b.row_count,
                    hex(&b.hash[..8]),
                ));
            }
        }
        if lines.is_empty() {
            "(per-table hashes match but overall differs — internal error)".to_string()
        } else {
            lines.join("\n")
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Compute deterministic projection fingerprint for a tenant.
/// Hashes all projection table rows using Blake2b-256 with type-tagged,
/// length-prefixed column encoding for unambiguous serialization.
fn compute_projection_fingerprint(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ProjectionFingerprint {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    type Blake2b256 = Blake2b<U32>;

    let mut overall = Blake2b256::new();
    let mut tables = Vec::with_capacity(FINGERPRINT_TABLES.len());

    for ft in FINGERPRINT_TABLES {
        let mut table_hasher = Blake2b256::new();
        // Domain separator: table name
        table_hasher.update(ft.name.as_bytes());
        table_hasher.update(b"\x00");

        let where_clause = match ft.scope {
            Scope::RecordedBy => "WHERE recorded_by = ?1",
            Scope::TenantId => "WHERE tenant_id = ?1",
        };
        let select = ft.columns.unwrap_or("*");
        let query = format!(
            "SELECT {} FROM {} {} {}",
            select, ft.name, where_clause, ft.order
        );
        let mut row_count: i64 = 0;

        if let Ok(mut stmt) = db.prepare(&query) {
            let col_count = stmt.column_count();
            if let Ok(mut rows) = stmt.query(rusqlite::params![recorded_by]) {
                while let Ok(Some(row)) = rows.next() {
                    row_count += 1;
                    for i in 0..col_count {
                        match row.get_ref(i) {
                            Ok(rusqlite::types::ValueRef::Null) => {
                                table_hasher.update(b"\x00");
                            }
                            Ok(rusqlite::types::ValueRef::Integer(v)) => {
                                table_hasher.update(b"\x01");
                                table_hasher.update(&v.to_le_bytes());
                            }
                            Ok(rusqlite::types::ValueRef::Real(v)) => {
                                table_hasher.update(b"\x02");
                                table_hasher.update(&v.to_le_bytes());
                            }
                            Ok(rusqlite::types::ValueRef::Text(v)) => {
                                table_hasher.update(b"\x03");
                                table_hasher.update(&(v.len() as u32).to_le_bytes());
                                table_hasher.update(v);
                            }
                            Ok(rusqlite::types::ValueRef::Blob(v)) => {
                                table_hasher.update(b"\x04");
                                table_hasher.update(&(v.len() as u32).to_le_bytes());
                                table_hasher.update(v);
                            }
                            Err(_) => {
                                table_hasher.update(b"\xfe");
                            }
                        }
                    }
                    table_hasher.update(b"\xff"); // row separator
                }
            }
        }

        let table_result = table_hasher.finalize();
        let mut table_hash = [0u8; 32];
        table_hash.copy_from_slice(&table_result);

        // Feed per-table hash into overall fingerprint
        overall.update(&table_hash);

        tables.push(TableDigest {
            table: ft.name,
            hash: table_hash,
            row_count,
        });
    }

    let result = overall.finalize();
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&result);
    ProjectionFingerprint {
        overall: fp,
        tables,
    }
}

// ---------------------------------------------------------------------------
// Replay helpers
// ---------------------------------------------------------------------------

/// Clear all projection and operational tables for a tenant so that
/// re-projection from events produces a fresh state.
fn clear_projection_tables(db: &rusqlite::Connection, recorded_by: &str) {
    // — Content projections
    db.execute(
        "DELETE FROM messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear messages");
    db.execute(
        "DELETE FROM reactions WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear reactions");
    db.execute(
        "DELETE FROM key_secrets WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear key_secrets");
    db.execute(
        "DELETE FROM deleted_messages WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear deleted_messages");
    db.execute(
        "DELETE FROM files WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM file_slices WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    // — Identity projections
    db.execute(
        "DELETE FROM workspaces WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM user_invites WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM device_invites WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM users WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM peers_shared WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM admins WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM key_shared WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM invites_accepted WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM peer_transport_bindings WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    // — Deletion intents (deterministic projection state, must be cleared for replay)
    db.execute(
        "DELETE FROM deletion_intents WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    // — Operational state (must be cleared for correct re-projection)
    db.execute(
        "DELETE FROM valid_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear valid_events");
    db.execute(
        "DELETE FROM blocked_event_deps WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear blocked_event_deps");
    db.execute(
        "DELETE FROM blocked_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM rejected_events WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .expect("failed to clear rejected_events");
    db.execute(
        "DELETE FROM project_queue WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
    // — Transport identity (replay-derived via MaterializeTransportIdentity command)
    db.execute(
        "DELETE FROM local_transport_creds WHERE peer_id IN (SELECT transport_peer_id FROM local_transport_targets WHERE tenant_id = ?1)",
        rusqlite::params![recorded_by],
    )
    .ok();
    db.execute(
        "DELETE FROM local_transport_targets WHERE tenant_id = ?1",
        rusqlite::params![recorded_by],
    )
    .ok();
}

/// Clear all projection and operational tables for a tenant, then re-project
/// all recorded events through `project_one` in the given order.
fn replay_and_fingerprint(
    db: &rusqlite::Connection,
    recorded_by: &str,
    order: &str,
) -> ProjectionFingerprint {
    use crate::crypto::event_id_from_base64;

    clear_projection_tables(db, recorded_by);

    // Re-project all recorded events in the requested order
    let query = format!(
        "SELECT e.event_id FROM events e
         WHERE e.event_id IN (SELECT event_id FROM recorded_events WHERE peer_id = ?1)
         {}",
        order
    );
    let mut stmt = db.prepare(&query).expect("failed to prepare events query");
    let event_ids: Vec<String> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            row.get::<_, String>(0)
        })
        .expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    for eid_b64 in &event_ids {
        if let Some(eid) = event_id_from_base64(eid_b64) {
            let _ = project_one(db, recorded_by, &eid);
        }
    }

    compute_projection_fingerprint(db, recorded_by)
}

/// Re-project all recorded events on top of existing state (no clearing).
/// Used for idempotency testing: project_one must be a no-op for already-valid events.
fn replay_no_clear_and_fingerprint(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ProjectionFingerprint {
    use crate::crypto::event_id_from_base64;

    let query = "SELECT e.event_id FROM events e
         WHERE e.event_id IN (SELECT event_id FROM recorded_events WHERE peer_id = ?1)
         ORDER BY created_at ASC, event_id ASC";
    let mut stmt = db.prepare(query).expect("failed to prepare events query");
    let event_ids: Vec<String> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            row.get::<_, String>(0)
        })
        .expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    for eid_b64 in &event_ids {
        if let Some(eid) = event_id_from_base64(eid_b64) {
            let _ = project_one(db, recorded_by, &eid);
        }
    }

    compute_projection_fingerprint(db, recorded_by)
}

/// Clear projection tables and re-project all recorded events in random-shuffled
/// order. Tests PLAN §12.4 item 5: out-of-order ingest converges to the same
/// projected end state as canonical-order replay.
fn replay_shuffled_and_fingerprint(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> ProjectionFingerprint {
    use crate::crypto::event_id_from_base64;
    use rand::seq::SliceRandom;

    // Collect event IDs in canonical order, then shuffle
    let query = "SELECT e.event_id FROM events e
         WHERE e.event_id IN (SELECT event_id FROM recorded_events WHERE peer_id = ?1)
         ORDER BY created_at ASC, event_id ASC";
    let mut stmt = db.prepare(query).expect("failed to prepare events query");
    let mut event_ids: Vec<String> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            row.get::<_, String>(0)
        })
        .expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    event_ids.shuffle(&mut rand::thread_rng());

    clear_projection_tables(db, recorded_by);

    // Re-project in shuffled order
    for eid_b64 in &event_ids {
        if let Some(eid) = event_id_from_base64(eid_b64) {
            let _ = project_one(db, recorded_by, &eid);
        }
    }

    compute_projection_fingerprint(db, recorded_by)
}

/// Verify projection invariants for a peer using deterministic fingerprints
/// (PLAN §12.4):
/// 1. Forward replay: clear + re-project forward → must match original state.
/// 2. Replay idempotency: re-project on already-projected state → no state change.
/// 3. Reverse-order replay: clear + re-project in reverse order → must match original state.
/// 4. Shuffle-reorder replay: clear + re-project in random order → must match original state.
///
/// On failure, per-table diagnostics are printed showing which tables diverged.
pub fn verify_projection_invariants(peer: &Peer) {
    let db = open_connection(&peer.db_path).expect("failed to open db");

    // Capture original full-state fingerprint
    let orig = compute_projection_fingerprint(&db, &peer.identity);

    // 1. Forward replay (reproject invariance: wipe + reproject yields same state)
    let fwd = replay_and_fingerprint(&db, &peer.identity, "ORDER BY created_at ASC, event_id ASC");
    assert!(
        orig.overall == fwd.overall,
        "Forward replay fingerprint mismatch for peer '{}':\n{}",
        peer.name,
        orig.diff_report(&fwd, "original", "forward"),
    );

    // 2. Idempotency: re-project on top of existing projected state (no clear)
    let idem = replay_no_clear_and_fingerprint(&db, &peer.identity);
    assert!(
        fwd.overall == idem.overall,
        "Idempotency replay fingerprint mismatch for peer '{}':\n{}",
        peer.name,
        fwd.diff_report(&idem, "forward", "idempotent"),
    );

    // 3. Reverse-order replay
    let rev = replay_and_fingerprint(
        &db,
        &peer.identity,
        "ORDER BY created_at DESC, event_id DESC",
    );
    assert!(
        fwd.overall == rev.overall,
        "Reverse replay fingerprint mismatch for peer '{}':\n{}",
        peer.name,
        fwd.diff_report(&rev, "forward", "reverse"),
    );

    // 4. Shuffle-reorder replay (PLAN §12.4 item 5: out-of-order ingest converges)
    let shuf = replay_shuffled_and_fingerprint(&db, &peer.identity);
    assert!(
        fwd.overall == shuf.overall,
        "Shuffle-reorder replay fingerprint mismatch for peer '{}':\n{}",
        peer.name,
        fwd.diff_report(&shuf, "forward", "shuffled"),
    );

    // Restore forward projection for subsequent assertions
    let _ = replay_and_fingerprint(&db, &peer.identity, "ORDER BY created_at ASC, event_id ASC");
}

// ---------------------------------------------------------------------------
// REALISM SYNC HELPERS
// ---------------------------------------------------------------------------

fn current_transport_target(peer: &Peer) -> String {
    peer.identity.clone()
}

fn ensure_test_daemon_identity_for_peer(peer: &Peer) {
    let db = open_connection(&peer.db_path).expect("failed to open db for daemon identity");
    create_tables(&db).expect("failed to initialize schema for test daemon identity");
    if crate::db::daemon_identity::load(&db)
        .expect("failed to read test daemon identity")
        .is_some()
    {
        return;
    }
    let (cert, key) = peer.cert_and_key();
    let daemon_peer_id = hex::encode(
        extract_spki_fingerprint(cert.as_ref()).expect("failed to fingerprint test daemon cert"),
    );
    crate::db::daemon_identity::store(
        &db,
        &daemon_peer_id,
        cert.as_ref(),
        key.secret_pkcs8_der().as_ref(),
    )
    .expect("failed to store test daemon identity");
}

fn daemon_cert_and_key_for_peer(
    peer: &Peer,
) -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    ensure_test_daemon_identity_for_peer(peer);
    let (_peer_id, cert, key) = crate::transport::load_daemon_identity_from_db(&peer.db_path)
        .expect("failed to load test daemon identity");
    (cert, key)
}

fn daemon_fingerprint_for_peer(peer: &Peer) -> [u8; 32] {
    let (cert, _key) = daemon_cert_and_key_for_peer(peer);
    extract_spki_fingerprint(cert.as_ref()).expect("failed to fingerprint test daemon identity")
}

fn tenant_trusts_daemon_for_test(
    db_path: &str,
    recorded_by: &str,
    peer_fp: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    crate::transport::tenant_trusts_daemon_peer(db_path, recorded_by, *peer_fp)
}

fn replicate_shared_events_once_by_path(
    src_db_path: &str,
    src_identity: &str,
    dst_db_path: &str,
    dst_identity: &str,
) -> Result<usize, String> {
    let src_db = open_connection(src_db_path).map_err(|e| format!("open src db: {e}"))?;
    let dst_db = open_connection(dst_db_path).map_err(|e| format!("open dst db: {e}"))?;
    let dst_ids: std::collections::HashSet<String> = dst_db
        .prepare("SELECT event_id FROM events")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|e| format!("list destination events: {e}"))?
        .into_iter()
        .collect();

    let rows: Vec<(String, Vec<u8>)> = src_db
        .prepare(
            "SELECT event_id, blob
             FROM events
             WHERE share_scope = 'shared'
             ORDER BY created_at ASC, event_id ASC",
        )
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|e| format!("list source shared events: {e}"))?;

    let now_ms = current_timestamp_ms() as i64;
    let mut batch = Vec::new();
    for (event_id_b64, blob) in rows {
        if dst_ids.contains(&event_id_b64) {
            continue;
        }
        let Some(event_id) = event_id_from_base64(&event_id_b64) else {
            continue;
        };
        batch.push((
            event_id,
            blob,
            dst_identity.to_string(),
            format!("test-sync:{src_identity}"),
            now_ms,
            now_ms,
        ));
    }

    if batch.is_empty() {
        return Ok(0);
    }

    let persisted = crate::state::pipeline::ingest_now(dst_db_path, batch)?;
    let _ = crate::event_pipeline::drain_project_queue(dst_db_path, dst_identity, 1000);
    Ok(persisted)
}

fn spawn_test_sync_worker(
    src_name: String,
    src_db_path: String,
    src_identity: String,
    dst_name: String,
    dst_db_path: String,
    dst_identity: String,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || loop {
        match replicate_shared_events_once_by_path(
            &src_db_path,
            &src_identity,
            &dst_db_path,
            &dst_identity,
        ) {
            Ok(_) => {}
            Err(err) => {
                if !std::path::Path::new(&src_db_path).exists()
                    || !std::path::Path::new(&dst_db_path).exists()
                {
                    break;
                }
                eprintln!("test sync worker {src_name} -> {dst_name} exiting: {err}");
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    })
}

/// Start sync between two peers in the same workspace with projected trust.
///
/// Both peers must already have each other's PeerShared events projected from
/// a real invite/bootstrap flow. No synthetic trust seeding is performed.
pub fn start_peers(
    peer_a: &Peer,
    peer_b: &Peer,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    crate::state::live_hints::init_forward_on_have_from_env();
    let (cert_a, key_a) = daemon_cert_and_key_for_peer(peer_a);
    let (cert_b, key_b) = daemon_cert_and_key_for_peer(peer_b);
    let a_trusts_b = daemon_fingerprint_for_peer(peer_b);
    let b_trusts_a = daemon_fingerprint_for_peer(peer_a);

    let allow_a: Arc<crate::transport::DynamicAllowFn> =
        Arc::new(move |peer_fp: &[u8; 32]| Ok(peer_fp == &a_trusts_b));
    let allow_b: Arc<crate::transport::DynamicAllowFn> =
        Arc::new(move |peer_fp: &[u8; 32]| Ok(peer_fp == &b_trusts_a));

    let listener_endpoint =
        create_dual_endpoint("127.0.0.1:0".parse().unwrap(), cert_a, key_a, allow_a)
            .expect("failed to create dynamic dual endpoint for A");

    let listener_addr = listener_endpoint
        .local_addr()
        .expect("failed to get listener addr");

    let connector_endpoint =
        create_dual_endpoint("127.0.0.1:0".parse().unwrap(), cert_b, key_b, allow_b)
            .expect("failed to create dual endpoint for B");

    let a_db = peer_a.db_path.clone();
    let a_identity = peer_a.identity.clone();
    let b_db = peer_b.db_path.clone();
    let b_identity = peer_b.identity.clone();
    let target_peer_id = current_transport_target(peer_a);

    let a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop(
                &a_db,
                &a_identity,
                listener_endpoint,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
                tracing::warn!("accept_loop exited: {}", e);
            }
        });
    });

    let b_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = connect_loop(
                &b_db,
                &b_identity,
                connector_endpoint,
                listener_addr,
                &target_peer_id,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
                tracing::warn!("connect_loop exited: {}", e);
            }
        });
    });

    (a_handle, b_handle)
}

/// Like `start_peers` but creates Quinn endpoints on the session threads.
///
/// Quinn's `EndpointDriver` I/O task is spawned on whatever tokio runtime is
/// current when the endpoint is constructed.  `start_peers` creates endpoints
/// on the *caller's* runtime, so if the caller later blocks that runtime (e.g.
/// with `thread::sleep`), all QUIC I/O stalls.  This variant defers endpoint
/// construction to each session thread's own `current_thread` runtime, ensuring
/// the I/O driver is always being polled while the session is active.
pub fn start_peers_runtime_affine(
    peer_a: &Peer,
    peer_b: &Peer,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    crate::state::live_hints::init_forward_on_have_from_env();
    let (cert_a, key_a) = daemon_cert_and_key_for_peer(peer_a);
    let (cert_b, key_b) = daemon_cert_and_key_for_peer(peer_b);
    let a_trusts_b = daemon_fingerprint_for_peer(peer_b);
    let b_trusts_a = daemon_fingerprint_for_peer(peer_a);
    let a_db = peer_a.db_path.clone();
    let a_identity = peer_a.identity.clone();
    let b_db = peer_b.db_path.clone();
    let b_identity = peer_b.identity.clone();
    let target_peer_id = current_transport_target(peer_a);
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<SocketAddr>();

    let a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let allow_a: Arc<crate::transport::DynamicAllowFn> =
                Arc::new(move |peer_fp: &[u8; 32]| Ok(peer_fp == &a_trusts_b));
            let listener_endpoint =
                create_dual_endpoint("127.0.0.1:0".parse().unwrap(), cert_a, key_a, allow_a)
                    .expect("failed to create listener endpoint");
            let listener_addr = listener_endpoint
                .local_addr()
                .expect("failed to get listener addr");
            addr_tx.send(listener_addr).expect("addr channel closed");
            if let Err(e) = accept_loop(
                &a_db,
                &a_identity,
                listener_endpoint,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
                tracing::warn!("accept_loop exited: {}", e);
            }
        });
    });

    let b_handle = std::thread::spawn(move || {
        let listener_addr = addr_rx.recv().expect("listener addr not received");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let allow_b: Arc<crate::transport::DynamicAllowFn> =
                Arc::new(move |peer_fp: &[u8; 32]| Ok(peer_fp == &b_trusts_a));
            let connector_endpoint =
                create_dual_endpoint("127.0.0.1:0".parse().unwrap(), cert_b, key_b, allow_b)
                    .expect("failed to create connector endpoint");
            if let Err(e) = connect_loop(
                &b_db,
                &b_identity,
                connector_endpoint,
                listener_addr,
                &target_peer_id,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
                tracing::warn!("connect_loop exited: {}", e);
            }
        });
    });

    (a_handle, b_handle)
}

/// Start continuous sync between two peers using dynamic DB trust lookup.
/// Trust is resolved from SQL at each TLS handshake, matching production
/// behavior (`is_authorized_for_tenant`). Caller must already have real invite/bootstrap
/// trust or steady-state peer trust projected in SQL.
///
/// REALISM HELPER: production-matching dynamic trust. Used in holepunch
/// integration tests.
pub fn start_peers_dynamic(
    peer_a: &Peer,
    peer_b: &Peer,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    crate::state::live_hints::init_forward_on_have_from_env();
    let (cert_a, key_a) = daemon_cert_and_key_for_peer(peer_a);
    let (cert_b, key_b) = daemon_cert_and_key_for_peer(peer_b);

    let a_db_path = peer_a.db_path.clone();
    let a_recorded_by = peer_a.identity.clone();
    let dynamic_allow_a: Arc<crate::transport::DynamicAllowFn> =
        Arc::new(move |peer_fp: &[u8; 32]| {
            tenant_trusts_daemon_for_test(&a_db_path, &a_recorded_by, peer_fp)
        });

    let b_db_path = peer_b.db_path.clone();
    let b_recorded_by = peer_b.identity.clone();
    let dynamic_allow_b: Arc<crate::transport::DynamicAllowFn> =
        Arc::new(move |peer_fp: &[u8; 32]| {
            tenant_trusts_daemon_for_test(&b_db_path, &b_recorded_by, peer_fp)
        });

    let listener_endpoint = create_dual_endpoint_dynamic(
        "127.0.0.1:0".parse().unwrap(),
        cert_a,
        key_a,
        dynamic_allow_a,
    )
    .expect("failed to create dynamic dual endpoint for A");

    let listener_addr = listener_endpoint
        .local_addr()
        .expect("failed to get listener addr");

    let connector_endpoint = create_dual_endpoint_dynamic(
        "127.0.0.1:0".parse().unwrap(),
        cert_b,
        key_b,
        dynamic_allow_b,
    )
    .expect("failed to create dynamic dual endpoint for B");

    let a_db = peer_a.db_path.clone();
    let a_identity = peer_a.identity.clone();
    let b_db = peer_b.db_path.clone();
    let b_identity = peer_b.identity.clone();
    let target_peer_id = current_transport_target(peer_a);
    let a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop(
                &a_db,
                &a_identity,
                listener_endpoint,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
                tracing::warn!("accept_loop exited: {}", e);
            }
        });
    });

    let b_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = connect_loop(
                &b_db,
                &b_identity,
                connector_endpoint,
                listener_addr,
                &target_peer_id,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
                tracing::warn!("connect_loop exited: {}", e);
            }
        });
    });

    (a_handle, b_handle)
}

/// Create a QUIC endpoint with dynamic DB trust lookup for a test peer.
/// Returns the endpoint (dual-role: accepts and connects).
/// Trust is resolved from SQL at each TLS handshake, matching production behavior.
pub fn create_dynamic_endpoint_for_peer(peer: &Peer) -> quinn::Endpoint {
    create_dynamic_endpoint_for_peer_bind(peer, "127.0.0.1:0".parse().unwrap())
}

/// Like [`create_dynamic_endpoint_for_peer`] but with a caller-specified bind
/// address. Use `0.0.0.0:0` when mDNS-resolved addresses may be non-loopback.
pub fn create_dynamic_endpoint_for_peer_bind(
    peer: &Peer,
    bind_addr: std::net::SocketAddr,
) -> quinn::Endpoint {
    let (cert, key) = daemon_cert_and_key_for_peer(peer);
    let db_path = peer.db_path.clone();
    let recorded_by = peer.identity.clone();
    let dynamic_allow: Arc<crate::transport::DynamicAllowFn> =
        Arc::new(move |peer_fp: &[u8; 32]| {
            tenant_trusts_daemon_for_test(&db_path, &recorded_by, peer_fp)
        });

    create_dual_endpoint_dynamic(bind_addr, cert, key, dynamic_allow)
        .expect("failed to create dynamic endpoint for peer")
}

/// Start sync, wait for a caller-defined convergence check, return metrics.
pub async fn sync_until_converged<F: Fn() -> bool>(
    peer_a: &Peer,
    peer_b: &Peer,
    check: F,
    timeout: Duration,
) -> SyncMetrics {
    let a_before = peer_a.shared_store_count();
    let b_before = peer_b.shared_store_count();

    let start = Instant::now();
    let sync = start_peers(peer_a, peer_b);

    assert_eventually(check, timeout, "sync convergence").await;

    let wall_secs = start.elapsed().as_secs_f64();
    drop(sync);

    let a_after = peer_a.shared_store_count();
    let b_after = peer_b.shared_store_count();
    let events_transferred = ((a_after - a_before) + (b_after - b_before)) as u64;
    let bytes_transferred = events_transferred * 100;
    let events_per_sec = if wall_secs > 0.0 {
        events_transferred as f64 / wall_secs
    } else {
        0.0
    };
    let throughput_mib_s = (bytes_transferred as f64) / (1024.0 * 1024.0) / wall_secs.max(0.001);

    SyncMetrics {
        wall_secs,
        events_transferred,
        events_per_sec,
        bytes_transferred,
        throughput_mib_s,
    }
}

/// Poll a condition until it's true or timeout expires.
pub async fn assert_eventually<F>(check: F, timeout: Duration, msg: &str)
where
    F: Fn() -> bool,
{
    let start = Instant::now();
    loop {
        if check() {
            return;
        }
        if start.elapsed() >= timeout {
            panic!("assert_eventually timed out: {}", msg);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

pub struct ChainHandles {
    pub thread_handles: Vec<std::thread::JoinHandle<()>>,
    pub endpoints: Vec<quinn::Endpoint>,
    pub connect_shutdowns: Vec<tokio_util::sync::CancellationToken>,
}

impl ChainHandles {
    pub fn shutdown(&mut self) {
        for shutdown in &self.connect_shutdowns {
            shutdown.cancel();
        }
        for endpoint in &self.endpoints {
            endpoint.close(0u32.into(), b"test-chain-shutdown");
        }
        while let Some(handle) = self.thread_handles.pop() {
            let _ = handle.join();
        }
    }
}

impl Drop for ChainHandles {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Start a chain topology: P0 <-> P1 <-> ... <-> P_{n-1}.
///
/// Each adjacent pair has a bidirectional sync link:
/// - P_i runs accept_loop (server) for P_{i+1}
/// - P_{i+1} runs connect_loop (client) to P_i
pub fn start_chain(peers: &[Peer]) -> ChainHandles {
    crate::state::live_hints::init_forward_on_have_from_env();
    let n = peers.len();
    assert!(n >= 2, "chain requires at least 2 peers");
    for peer in peers.iter().skip(1) {
        assert_eq!(
            peer.workspace_id, peers[0].workspace_id,
            "chain peers must share one workspace and real projected trust"
        );
    }

    // Create server endpoints for peers 0..n-2 with dynamic trust
    let mut server_addrs: Vec<SocketAddr> = Vec::new();
    let mut server_endpoints: Vec<quinn::Endpoint> = Vec::new();
    for i in 0..n - 1 {
        let (cert, key) = daemon_cert_and_key_for_peer(&peers[i]);
        let db_path = peers[i].db_path.clone();
        let recorded_by = peers[i].identity.clone();
        let allow_fn: Arc<crate::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
            tenant_trusts_daemon_for_test(&db_path, &recorded_by, fp)
        });
        let endpoint =
            create_dual_endpoint_dynamic("127.0.0.1:0".parse().unwrap(), cert, key, allow_fn)
                .expect("failed to create chain server endpoint");
        let addr = endpoint.local_addr().expect("failed to get local addr");
        server_addrs.push(addr);
        server_endpoints.push(endpoint);
    }

    // Create client endpoints for peers 1..n-1 with dynamic trust
    let mut client_endpoints: Vec<quinn::Endpoint> = Vec::new();
    for i in 1..n {
        let (cert, key) = daemon_cert_and_key_for_peer(&peers[i]);
        let db_path = peers[i].db_path.clone();
        let recorded_by = peers[i].identity.clone();
        let allow_fn: Arc<crate::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
            tenant_trusts_daemon_for_test(&db_path, &recorded_by, fp)
        });
        let endpoint =
            create_dual_endpoint_dynamic("0.0.0.0:0".parse().unwrap(), cert, key, allow_fn)
                .expect("failed to create chain client endpoint");
        client_endpoints.push(endpoint);
    }

    let mut handles = Vec::new();
    let mut endpoints = Vec::new();

    // Spawn accept_loop for peers 0..n-2
    for (i, endpoint) in server_endpoints.into_iter().enumerate() {
        endpoints.push(endpoint.clone());
        let db_path = peers[i].db_path.clone();
        let identity = peers[i].identity.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = accept_loop(
                    &db_path,
                    &identity,
                    endpoint,
                    noop_intro_spawner,
                    test_ingest_fns(),
                )
                .await
                {
                    tracing::warn!("chain accept_loop[{}] exited: {}", i, e);
                }
            });
        }));
    }

    // Spawn connect_loop for peers 1..n-1
    let mut connect_shutdowns = Vec::new();
    for (idx, endpoint) in client_endpoints.into_iter().enumerate() {
        let i = idx + 1;
        let db_path = peers[i].db_path.clone();
        let identity = peers[i].identity.clone();
        let remote = server_addrs[idx];
        let target_peer_id = current_transport_target(&peers[idx]);
        let shutdown = tokio_util::sync::CancellationToken::new();
        connect_shutdowns.push(shutdown.clone());
        endpoints.push(endpoint.clone());
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = connect_loop_with_coordination_until_cancel(
                    &db_path,
                    &identity,
                    endpoint,
                    remote,
                    &target_peer_id,
                    None,
                    noop_intro_spawner,
                    test_ingest_fns(),
                    shutdown,
                )
                .await
                {
                    tracing::warn!("chain connect_loop[{}] exited: {}", i, e);
                }
            });
        }));
    }

    ChainHandles {
        thread_handles: handles,
        endpoints,
        connect_shutdowns,
    }
}

/// Start a sink-driven download topology: sink connects to all sources.
///
/// Each source runs accept_loop (responder). The sink runs one
/// `connect_loop` per source, matching the production runtime path used by
/// bootstrap/mDNS autodial.
pub fn start_sink_download(sources: &[Peer], sink: &Peer) -> SinkDownloadHandles {
    start_sink_download_with_shutdown(sources, sink)
}

/// Handles from a sink-driven download topology with per-source shutdown control.
pub struct SinkDownloadHandles {
    pub thread_handles: Vec<std::thread::JoinHandle<()>>,
    /// Source server endpoints (cloned); close to simulate source failure.
    pub source_endpoints: Vec<crate::transport::TransportEndpoint>,
    /// Sink-side client endpoints; close to terminate ordinary connect loops.
    pub client_endpoints: Vec<crate::transport::TransportEndpoint>,
    /// Per-connect-loop cancellation tokens; cancel to stop a sink's connect loop.
    pub connect_shutdowns: Vec<tokio_util::sync::CancellationToken>,
}

impl SinkDownloadHandles {
    /// Shut down a specific source's accept loop by closing its QUIC endpoint,
    /// and cancel the corresponding connect loop so it stops retrying.
    pub fn shutdown_source(&self, idx: usize) {
        self.source_endpoints[idx].close(0u32.into(), b"test-shutdown");
        self.connect_shutdowns[idx].cancel();
    }

    pub fn shutdown(&mut self) {
        for endpoint in &self.source_endpoints {
            endpoint.close(0u32.into(), b"test-download-shutdown");
        }
        for endpoint in &self.client_endpoints {
            endpoint.close(0u32.into(), b"test-download-shutdown");
        }
        for shutdown in &self.connect_shutdowns {
            shutdown.cancel();
        }
        while let Some(handle) = self.thread_handles.pop() {
            let _ = handle.join();
        }
    }
}

impl Drop for SinkDownloadHandles {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Like [`start_sink_download`] but returns [`SinkDownloadHandles`] with
/// per-source shutdown control for simulating peer dropout.
pub fn start_sink_download_with_shutdown(sources: &[Peer], sink: &Peer) -> SinkDownloadHandles {
    crate::state::live_hints::init_forward_on_have_from_env();
    assert!(!sources.is_empty(), "need at least one source");
    for source in sources {
        assert_eq!(
            source.workspace_id, sink.workspace_id,
            "sink download peers must share one workspace and real projected trust"
        );
    }

    let (sink_cert, sink_key) = daemon_cert_and_key_for_peer(sink);

    let mut handles = Vec::new();
    let mut source_addrs = Vec::new();
    let mut source_endpoints = Vec::new();
    let mut client_endpoints = Vec::new();
    let sink_spki = daemon_fingerprint_for_peer(sink);

    // Start accept_loop for each source with explicit sink trust.
    for source in sources {
        let (cert, key) = daemon_cert_and_key_for_peer(source);
        let trusted_sink_spki = sink_spki;
        let allow_fn: Arc<crate::transport::DynamicAllowFn> =
            Arc::new(move |fp: &[u8; 32]| Ok(fp == &trusted_sink_spki));
        let server_endpoint =
            create_dual_endpoint("127.0.0.1:0".parse().unwrap(), cert, key, allow_fn)
                .expect("failed to create source server endpoint");
        let addr = server_endpoint
            .local_addr()
            .expect("failed to get source addr");
        source_addrs.push(addr);
        source_endpoints.push(server_endpoint.clone());

        let db_path = source.db_path.clone();
        let identity = source.identity.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = accept_loop(
                    &db_path,
                    &identity,
                    server_endpoint,
                    noop_intro_spawner,
                    test_ingest_fns(),
                )
                .await
                {
                    tracing::warn!("source accept_loop exited: {}", e);
                }
            });
        }));
    }

    // Build per-source client endpoints for the sink with explicit source trust.
    // These are driven by coordinated connect loops (runtime-faithful path).
    let mut sink_connectors = Vec::new();
    for (i, source) in sources.iter().enumerate() {
        let trusted_source_spki = daemon_fingerprint_for_peer(source);
        let allow_fn: Arc<crate::transport::DynamicAllowFn> =
            Arc::new(move |fp: &[u8; 32]| Ok(fp == &trusted_source_spki));
        let client_endpoint = create_dual_endpoint(
            "0.0.0.0:0".parse().unwrap(),
            sink_cert.clone(),
            sink_key.clone_key(),
            allow_fn,
        )
        .expect("failed to create sink client endpoint");
        client_endpoints.push(client_endpoint.clone());

        sink_connectors.push((
            client_endpoint,
            source_addrs[i],
            current_transport_target(&sources[i]),
        ));
    }

    let mut connect_shutdowns = Vec::new();
    for (endpoint, remote, target_peer_id) in sink_connectors {
        let shutdown = tokio_util::sync::CancellationToken::new();
        connect_shutdowns.push(shutdown.clone());
        let sink_db = sink.db_path.clone();
        let sink_identity = sink.identity.clone();
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let _ = connect_loop_with_coordination_until_cancel(
                    &sink_db,
                    &sink_identity,
                    endpoint,
                    remote,
                    &target_peer_id,
                    None,
                    noop_intro_spawner,
                    test_ingest_fns(),
                    shutdown,
                )
                .await;
            });
        }));
    }
    SinkDownloadHandles {
        thread_handles: handles,
        source_endpoints,
        client_endpoints,
        connect_shutdowns,
    }
}

/// Start a sink's accept_loop and return the handle and listen address.
///
/// Uses dynamic trust (`is_authorized_for_tenant`) at each TLS handshake.
/// The caller must have already established real projected trust for every
/// inbound peer that will connect to this sink.
pub fn start_sink_accept(sink: &Peer) -> (std::thread::JoinHandle<()>, SocketAddr) {
    let (cert, key) = daemon_cert_and_key_for_peer(sink);
    let sink_db_path = sink.db_path.clone();
    let sink_recorded_by = sink.identity.clone();
    let allow_fn: Arc<crate::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
        tenant_trusts_daemon_for_test(&sink_db_path, &sink_recorded_by, fp)
    });
    let endpoint =
        create_dual_endpoint_dynamic("127.0.0.1:0".parse().unwrap(), cert, key, allow_fn)
            .expect("failed to create sink server endpoint");
    let addr = endpoint.local_addr().expect("failed to get sink addr");

    let db_path = sink.db_path.clone();
    let identity = sink.identity.clone();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop(
                &db_path,
                &identity,
                endpoint,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await
            {
                tracing::warn!("sink accept_loop exited: {}", e);
            }
        });
    });

    (handle, addr)
}

/// Extract the SPKI fingerprint for a peer.
pub fn peer_fingerprint(peer: &Peer) -> [u8; 32] {
    peer.spki_fingerprint()
}

/// Record pre-existing events for a new tenant in a shared-DB context.
///
/// In separate-DB peers, prerequisite events arrive via bootstrap sync
/// (see `Peer::new_in_workspace`). In shared-DB multi-tenant mode, the
/// events are already in the events table; this helper records them for
/// the new tenant and projects them, equivalent to what the sync engine's
/// batch writer does after receiving events.
///
/// WHITE-BOX HELPER: used only in SharedDbNode (shared-DB multi-tenant
/// projection tests), not in realism/integration test paths.
fn record_shared_db_events_for_tenant(
    db: &rusqlite::Connection,
    tenant_id: &str,
    event_ids: &[EventId],
) {
    use crate::projection::apply::project_one;

    let now_ms = current_timestamp_ms() as i64;
    for eid in event_ids {
        insert_recorded_event(db, tenant_id, eid, now_ms, "test")
            .expect("failed to record event for tenant");
        let _ = project_one(db, tenant_id, eid);
    }
}

fn copy_projected_events_for_tenant(
    src_db: &rusqlite::Connection,
    dst_db: &rusqlite::Connection,
    tenant_id: &str,
    event_ids: &[EventId],
) {
    use crate::db::store::{insert_event, parse_share_scope};

    let now_ms = current_timestamp_ms() as i64;
    for eid in event_ids {
        let eid_b64 = event_id_to_base64(eid);
        let (event_type, blob, share_scope, created_at, inserted_at): (
            String,
            Vec<u8>,
            String,
            i64,
            i64,
        ) = src_db
            .query_row(
                "SELECT event_type, blob, share_scope, created_at, inserted_at
                 FROM events
                 WHERE event_id = ?1",
                rusqlite::params![&eid_b64],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap_or_else(|err| panic!("failed to load event {eid_b64} from source db: {err}"));
        let share_scope = parse_share_scope(&share_scope)
            .unwrap_or_else(|| panic!("unknown share scope `{share_scope}` for event {eid_b64}"));
        insert_event(
            dst_db,
            eid,
            &event_type,
            &blob,
            share_scope,
            created_at,
            inserted_at,
        )
        .expect("failed to copy event into destination db");
        insert_recorded_event(dst_db, tenant_id, eid, now_ms, "test-bootstrap")
            .expect("failed to record copied event for tenant");
        project_one(dst_db, tenant_id, eid).unwrap_or_else(|err| {
            panic!(
                "failed to project copied event {} for tenant {}: {}",
                eid_b64, tenant_id, err
            )
        });
    }
}

fn list_shared_event_ids_for_tenant(db: &rusqlite::Connection, tenant_id: &str) -> Vec<EventId> {
    db.prepare(
        "SELECT re.event_id
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
           AND e.share_scope = 'shared'
         ORDER BY e.created_at ASC, re.event_id ASC",
    )
    .and_then(|mut stmt| {
        stmt.query_map(rusqlite::params![tenant_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()
    })
    .expect("failed to list shared events")
    .into_iter()
    .filter_map(|b64| event_id_from_base64(&b64))
    .collect()
}

// ---------------------------------------------------------------------------
// WHITE-BOX: multi-tenant shared-DB projection tests
// ---------------------------------------------------------------------------

/// A multi-tenant node: multiple peers sharing a single database.
///
/// Each tenant has its own transport identity but they all use the same DB file.
/// This mirrors the production `run_node` setup where tenant discovery comes from
/// the join of `invites_accepted` and `local_transport_creds`.
pub struct SharedDbNode {
    pub db_path: String,
    pub tenants: Vec<Peer>,
    _tempdir: tempfile::TempDir,
}

impl SharedDbNode {
    /// Create a shared-DB node with N tenants, each bootstrapped with a full identity chain.
    pub fn new(n: usize) -> Self {
        assert!(n >= 1, "need at least 1 tenant");
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir
            .path()
            .join("shared.db")
            .to_str()
            .unwrap()
            .to_string();

        // Initialize DB once
        {
            let db = open_connection(&db_path).expect("failed to open shared db");
            create_tables(&db).expect("failed to create tables");
        }

        let mut tenants = Vec::with_capacity(n);
        for i in 0..n {
            let name = format!("tenant-{}", i);
            // Create a Peer that uses the shared db_path
            let peer = Self::create_tenant(&db_path, &name);
            tenants.push(peer);
        }

        // create_workspace installs PeerShared-derived transport identity via
        // `DELETE FROM local_transport_creds` + insert.  In a shared-DB with
        // multiple tenants each bootstrap wipes the previous tenants' creds.
        // Re-install all tenants' PeerShared-derived certs so discover_local_tenants works.
        if n > 1 {
            let db = open_connection(&db_path).expect("failed to open shared db for cred restore");
            for tenant in &tenants {
                let ps_key = tenant
                    .peer_shared_signing_key
                    .as_ref()
                    .expect("tenant missing peer_shared_signing_key after bootstrap");
                let (cert, key) =
                    crate::transport::generate_self_signed_cert_from_signing_key(ps_key)
                        .expect("failed to regenerate PeerShared cert");
                crate::db::transport_creds::store_local_creds(
                    &db,
                    &tenant.identity,
                    cert.as_ref(),
                    key.secret_pkcs8_der(),
                )
                .expect("failed to re-store tenant transport creds");
            }
        }

        Self {
            db_path,
            tenants,
            _tempdir: tempdir,
        }
    }

    /// Create a single tenant within the shared DB.
    fn create_tenant(db_path: &str, name: &str) -> Peer {
        // Ensure tables exist (idempotent)
        let db = open_connection(db_path).expect("failed to open db");
        create_tables(&db).expect("failed to create tables");
        drop(db);

        // We need a separate identity for each tenant. The first call to
        // ensure_transport_peer_id generates one cert; subsequent tenants
        // need distinct certs. Generate a new cert for this tenant.
        let (cert, key) =
            crate::transport::generate_self_signed_cert().expect("failed to generate cert");
        let fp = extract_spki_fingerprint(cert.as_ref()).expect("failed to extract SPKI");
        let tenant_identity = hex::encode(fp);

        // Store this tenant's creds in the shared DB
        let db = open_connection(db_path).expect("failed to open db");
        crate::db::transport_creds::store_local_creds(
            &db,
            &tenant_identity,
            cert.as_ref(),
            key.secret_pkcs8_der(),
        )
        .expect("failed to store creds");

        let author_id: [u8; 32] = rand::random();

        // Build a Peer struct pointing to the shared db
        // We need a dummy tempdir since Peer owns one, but for SharedDbNode
        // the real DB is in the node's tempdir
        let dummy_tempdir = tempfile::tempdir().expect("failed to create dummy tempdir");

        let mut peer = Peer {
            name: name.to_string(),
            db_path: db_path.to_string(),
            identity: tenant_identity,
            author_id,
            workspace_id: [0u8; 32],
            peer_shared_event_id: None,
            peer_shared_signing_key: None,
            _tempdir: dummy_tempdir,
        };

        // Bootstrap full identity chain
        peer.bootstrap_identity_chain();
        peer
    }

    /// Add a new tenant that joins an existing tenant's workspace (same DB)
    /// using the production workspace command APIs.
    pub fn add_tenant_in_workspace(&mut self, name: &str, creator_index: usize) {
        use crate::event_modules::workspace::commands::{
            create_user_invite_raw, join_workspace_as_new_user,
        };

        let creator = &self.tenants[creator_index];
        let workspace_id = creator.workspace_id;
        let creator_peer_key = creator
            .peer_shared_signing_key
            .as_ref()
            .expect("creator has no peer_shared_signing_key")
            .clone();
        let creator_peer_eid = creator
            .peer_shared_event_id
            .expect("creator has no peer_shared_event_id");
        let creator_identity = creator.identity.clone();

        // Create a new transport identity in the shared DB
        let (cert, key) =
            crate::transport::generate_self_signed_cert().expect("failed to generate cert");
        let fp = extract_spki_fingerprint(cert.as_ref()).expect("failed to extract SPKI");
        let tenant_identity = hex::encode(fp);

        let db = open_connection(&self.db_path).expect("failed to open db");
        let creator_admin_eid: EventId = db
            .query_row(
                "SELECT event_id
                 FROM admins
                 WHERE recorded_by = ?1
                 ORDER BY event_id ASC
                 LIMIT 1",
                rusqlite::params![&creator_identity],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|b64| event_id_from_base64(&b64))
            .expect("creator has no admin event");
        crate::db::transport_creds::store_local_creds(
            &db,
            &tenant_identity,
            cert.as_ref(),
            key.secret_pkcs8_der(),
        )
        .expect("failed to store creds");

        // Creator issues an invite via workspace::commands API
        let invite = create_user_invite_raw(
            &db,
            &creator_identity,
            &creator_peer_key,
            &creator_peer_eid,
            &creator_admin_eid,
            &workspace_id,
        )
        .expect("failed to create user invite");

        // Mirror creator identity prerequisites needed to validate peer-signed invites
        // under the new tenant scope (workspace + signer/admin lineage + invite).
        let creator_peer_b64 = event_id_to_base64(&creator_peer_eid);
        let creator_peer_blob: Vec<u8> = db
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&creator_peer_b64],
                |row| row.get(0),
            )
            .expect("failed to load creator peer_shared blob");
        let creator_device_invite_eid = match crate::event_modules::parse_event(&creator_peer_blob)
            .expect("failed to parse creator peer_shared")
        {
            ParsedEvent::PeerShared(ps) => ps.signed_by,
            _ => panic!("creator peer_shared event has unexpected type"),
        };

        let creator_user_b64 = event_id_to_base64(&creator.author_id);
        let creator_user_blob: Vec<u8> = db
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&creator_user_b64],
                |row| row.get(0),
            )
            .expect("failed to load creator user blob");
        let creator_user_invite_eid = match crate::event_modules::parse_event(&creator_user_blob)
            .expect("failed to parse creator user")
        {
            ParsedEvent::User(u) => u.signed_by,
            _ => panic!("creator user event has unexpected type"),
        };

        // Record prerequisites for this new tenant and project (white-box shared-DB prerequisite).
        record_shared_db_events_for_tenant(
            &db,
            &tenant_identity,
            &[
                workspace_id,
                creator_user_invite_eid,
                creator.author_id,
                creator_device_invite_eid,
                creator_peer_eid,
                creator_admin_eid,
                invite.invite_event_id,
            ],
        );

        crate::db::transport_trust::append_bootstrap_context(
            &db,
            &tenant_identity,
            &event_id_to_base64(&invite.invite_event_id),
            &event_id_to_base64(&workspace_id),
            "",
            &[0xAB; 32],
        )
        .expect("failed to record invite-link workspace binding");

        // Accept the invite (production flow via workspace commands)
        let peer_shared_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let join = join_workspace_as_new_user(
            &db,
            &tenant_identity,
            &invite.invite_key,
            &invite.invite_event_id,
            workspace_id,
            "test-user",
            "test-device",
            peer_shared_key,
        )
        .expect("failed to accept user invite");

        let dummy_tempdir = tempfile::tempdir().expect("failed to create dummy tempdir");

        let peer = Peer {
            name: name.to_string(),
            db_path: self.db_path.clone(),
            identity: tenant_identity,
            author_id: join.user_event_id,
            workspace_id,
            peer_shared_event_id: Some(join.peer_shared_event_id),
            peer_shared_signing_key: Some(join.peer_shared_key),
            _tempdir: dummy_tempdir,
        };

        self.tenants.push(peer);
    }

    /// Get the list of tenant peer_ids.
    pub fn tenant_ids(&self) -> Vec<String> {
        self.tenants.iter().map(|t| t.identity.clone()).collect()
    }

    /// Verify projection invariants for all tenants and assert no cross-tenant leakage.
    pub fn verify_all_invariants(&self) {
        for tenant in &self.tenants {
            verify_projection_invariants(tenant);
        }
        let tenant_workspaces: Vec<(String, String)> = self
            .tenants
            .iter()
            .map(|t| (t.identity.clone(), hex::encode(t.workspace_id)))
            .collect();
        assert_no_cross_tenant_leakage(&self.db_path, &tenant_workspaces);
    }
}

/// Lightweight harness that ensures every scenario test runs projection replay
/// invariant checks. Tracks `&Peer` and `&SharedDbNode` references, runs
/// `verify_projection_invariants` (and `verify_all_invariants` for nodes)
/// when `.finish()` is called. A `Drop` safety-net panics if `.finish()` was
/// never called, preventing silent omission.
///
/// **Declaration order**: peers/nodes must be declared **before** the harness
/// so they are dropped **after** it (Rust drops in reverse declaration order).
pub struct ScenarioHarness<'a> {
    peers: std::cell::RefCell<Vec<&'a Peer>>,
    shared_db_nodes: std::cell::RefCell<Vec<&'a SharedDbNode>>,
    skip_reason: Option<String>,
    finished: std::cell::Cell<bool>,
}

impl<'a> ScenarioHarness<'a> {
    /// Create a new harness that will verify replay invariants on `.finish()`.
    pub fn new() -> Self {
        Self {
            peers: std::cell::RefCell::new(Vec::new()),
            shared_db_nodes: std::cell::RefCell::new(Vec::new()),
            skip_reason: None,
            finished: std::cell::Cell::new(false),
        }
    }

    /// Create a harness that skips replay checks with a documented reason.
    pub fn skip(reason: &str) -> Self {
        Self {
            peers: std::cell::RefCell::new(Vec::new()),
            shared_db_nodes: std::cell::RefCell::new(Vec::new()),
            skip_reason: Some(reason.to_string()),
            finished: std::cell::Cell::new(false),
        }
    }

    /// Track a `Peer` for replay invariant checks.
    pub fn track(&self, peer: &'a Peer) {
        self.peers.borrow_mut().push(peer);
    }

    /// Track a `SharedDbNode` for replay invariant checks.
    pub fn track_node(&self, node: &'a SharedDbNode) {
        self.shared_db_nodes.borrow_mut().push(node);
    }

    /// Run replay invariant checks on all tracked peers and nodes.
    /// Must be called exactly once before the harness is dropped.
    pub fn finish(&self) {
        self.finished.set(true);
        if let Some(reason) = &self.skip_reason {
            eprintln!("ScenarioHarness: skipping replay invariants — {}", reason);
            return;
        }
        let tracked = self.peers.borrow().len() + self.shared_db_nodes.borrow().len();
        if tracked == 0 {
            panic!(
                "ScenarioHarness::finish() with zero tracked subjects. \
                    Use ScenarioHarness::skip(reason) to opt out."
            );
        }
        for peer in self.peers.borrow().iter() {
            verify_projection_invariants(peer);
        }
        for node in self.shared_db_nodes.borrow().iter() {
            node.verify_all_invariants();
        }
    }
}

impl Drop for ScenarioHarness<'_> {
    fn drop(&mut self) {
        if !self.finished.get() && !std::thread::panicking() {
            panic!("ScenarioHarness::finish() was never called! Add harness.finish() at the end of the test.");
        }
    }
}

/// Assert that no cross-tenant leakage exists in the shared database.
///
/// `tenant_workspaces` is a list of (peer_id, workspace_id) pairs. Checks:
/// 1. For tenants in different workspaces: recorded_events and valid_events
///    event_id sets are pairwise disjoint (no cross-workspace leakage).
///    For tenants in the same workspace: overlap is expected after sync.
/// 2. No unexpected peer_ids appear in recorded_events, valid_events, or
///    projection tables.
pub fn assert_no_cross_tenant_leakage(db_path: &str, tenant_workspaces: &[(String, String)]) {
    let db = open_connection(db_path).expect("failed to open db");

    let tenant_ids: Vec<&str> = tenant_workspaces
        .iter()
        .map(|(id, _)| id.as_str())
        .collect();
    let known_ids: std::collections::HashSet<&str> = tenant_ids.iter().copied().collect();

    // Collect recorded event_ids per tenant
    let mut recorded_per_tenant: std::collections::HashMap<
        &str,
        std::collections::HashSet<String>,
    > = std::collections::HashMap::new();
    for tid in &tenant_ids {
        let mut stmt = db
            .prepare("SELECT event_id FROM recorded_events WHERE peer_id = ?1")
            .expect("failed to prepare stmt");
        let events: std::collections::HashSet<String> = stmt
            .query_map([tid], |row| row.get::<_, String>(0))
            .expect("failed to query")
            .collect::<Result<std::collections::HashSet<_>, _>>()
            .expect("failed to collect");
        recorded_per_tenant.insert(tid, events);
    }

    // Verify pairwise disjointness of recorded_events for tenants in DIFFERENT workspaces
    for i in 0..tenant_workspaces.len() {
        for j in (i + 1)..tenant_workspaces.len() {
            let (id_a, ws_a) = &tenant_workspaces[i];
            let (id_b, ws_b) = &tenant_workspaces[j];
            if ws_a == ws_b {
                continue; // same workspace — overlap is expected after sync
            }
            let a = recorded_per_tenant.get(id_a.as_str()).unwrap();
            let b = recorded_per_tenant.get(id_b.as_str()).unwrap();
            let overlap: Vec<&String> = a.intersection(b).collect();
            let overlap_details: Vec<(String, String, Vec<String>)> = overlap
                .iter()
                .map(|event_id| {
                    let event_type: String = db
                        .query_row(
                            "SELECT event_type FROM events WHERE event_id = ?1",
                            rusqlite::params![event_id.as_str()],
                            |row| row.get(0),
                        )
                        .unwrap_or_else(|_| "<missing>".to_string());
                    let mut stmt = db
                        .prepare(
                            "SELECT peer_id || ':' || source
                             FROM recorded_events
                             WHERE event_id = ?1
                             ORDER BY peer_id, source",
                        )
                        .expect("prepare overlap source query");
                    let sources = stmt
                        .query_map(rusqlite::params![event_id.as_str()], |row| row.get(0))
                        .expect("query overlap sources")
                        .collect::<Result<Vec<String>, _>>()
                        .expect("collect overlap sources");
                    ((*event_id).clone(), event_type, sources)
                })
                .collect();
            assert!(
                overlap.is_empty(),
                "Cross-workspace leakage in recorded_events between {} ({}) and {} ({}): {:?}",
                &id_a[..16],
                &ws_a[..16.min(ws_a.len())],
                &id_b[..16],
                &ws_b[..16.min(ws_b.len())],
                overlap_details
            );
        }
    }

    // Collect valid event_ids per tenant
    let mut valid_per_tenant: std::collections::HashMap<&str, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    for tid in &tenant_ids {
        let mut stmt = db
            .prepare("SELECT event_id FROM valid_events WHERE peer_id = ?1")
            .expect("failed to prepare stmt");
        let events: std::collections::HashSet<String> = stmt
            .query_map([tid], |row| row.get::<_, String>(0))
            .expect("failed to query")
            .collect::<Result<std::collections::HashSet<_>, _>>()
            .expect("failed to collect");
        valid_per_tenant.insert(tid, events);
    }

    for i in 0..tenant_workspaces.len() {
        for j in (i + 1)..tenant_workspaces.len() {
            let (id_a, ws_a) = &tenant_workspaces[i];
            let (id_b, ws_b) = &tenant_workspaces[j];
            if ws_a == ws_b {
                continue; // same workspace — overlap is expected after sync
            }
            let a = valid_per_tenant.get(id_a.as_str()).unwrap();
            let b = valid_per_tenant.get(id_b.as_str()).unwrap();
            let overlap: Vec<&String> = a.intersection(b).collect();
            assert!(
                overlap.is_empty(),
                "Cross-workspace leakage in valid_events between {} and {}: {:?}",
                &id_a[..16],
                &id_b[..16],
                overlap
            );
        }
    }

    // Verify no unexpected peer_ids in key scoped tables
    for table in &["recorded_events", "valid_events"] {
        let query = format!("SELECT DISTINCT peer_id FROM {}", table);
        let mut stmt = db.prepare(&query).expect("failed to prepare");
        let found_ids: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("failed to query")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to collect");
        for found_id in &found_ids {
            assert!(
                known_ids.contains(found_id.as_str()),
                "Unknown peer_id '{}...' in {} table",
                &found_id[..16.min(found_id.len())],
                table
            );
        }
    }

    // Verify no unexpected peer_ids in projection tables
    for table in &["messages", "reactions", "key_secrets", "deleted_messages"] {
        let query = format!("SELECT DISTINCT recorded_by FROM {}", table);
        let mut stmt = db.prepare(&query).expect("failed to prepare");
        let found_ids: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("failed to query")
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to collect");
        for found_id in &found_ids {
            assert!(
                known_ids.contains(found_id.as_str()),
                "Unknown peer_id '{}...' in {} table",
                &found_id[..16.min(found_id.len())],
                table
            );
        }
    }
}

// ---------------------------------------------------------------------------
// WHITE-BOX: deliberately copies events DB-to-DB for dedup/overlap benchmarks
// ---------------------------------------------------------------------------

/// Copy all events and neg_items from a source peer's database to target peers.
///
/// This creates identical data at each target so that concurrent sync tests can
/// verify dedup behavior when multiple sources offer the same events.
///
/// WHITE-BOX HELPER: intentional DB-to-DB copy for sync_graph_test benchmarks
/// that need identical pre-seeded data across multiple peers. Not used in
/// realism/integration test paths.
pub fn clone_events_to(source: &Peer, targets: &[&Peer]) {
    let src_db = open_connection(&source.db_path).expect("failed to open source db");

    // Read all events
    let mut events_stmt = src_db
        .prepare(
            "SELECT event_id, event_type, blob, share_scope, created_at, inserted_at FROM events",
        )
        .expect("failed to prepare events query");
    let events: Vec<(String, String, Vec<u8>, String, i64, i64)> = events_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .expect("failed to query events")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect events");

    // Read all neg_items (including workspace_id)
    let mut neg_stmt = src_db
        .prepare("SELECT workspace_id, ts, id FROM neg_items")
        .expect("failed to prepare neg_items query");
    let neg_items: Vec<(String, i64, Vec<u8>)> = neg_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .expect("failed to query neg_items")
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to collect neg_items");

    for target in targets {
        let tgt_db = open_connection(&target.db_path).expect("failed to open target db");
        // Use target's workspace_id so neg_items entries match the target's
        // neg_storage scope and don't create duplicates when the target later
        // receives the same events from sync (which inserts with target ws_id).
        let tgt_ws_id = crate::db::store::lookup_workspace_id(&tgt_db, &target.identity);
        tgt_db.execute("BEGIN", []).expect("failed to begin");

        for (event_id, event_type, blob, share_scope, created_at, inserted_at) in &events {
            tgt_db.execute(
                "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![event_id, event_type, blob.as_slice(), share_scope, created_at, inserted_at],
            ).expect("failed to insert event");
        }

        for (_workspace_id, ts, id) in &neg_items {
            tgt_db
                .execute(
                    "INSERT OR IGNORE INTO neg_items (workspace_id, ts, id) VALUES (?1, ?2, ?3)",
                    rusqlite::params![&tgt_ws_id, ts, id.as_slice()],
                )
                .expect("failed to insert neg_item");
        }

        tgt_db.execute("COMMIT", []).expect("failed to commit");
    }
}

// ---------------------------------------------------------------------------
// Unit tests for deterministic fingerprinting
// ---------------------------------------------------------------------------
#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    use crate::db::{open_connection, schema::create_tables};

    /// Helper: create a fresh in-memory DB with full schema.
    fn fresh_db() -> (tempfile::TempDir, String, rusqlite::Connection) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.db").to_str().unwrap().to_string();
        let db = open_connection(&path).unwrap();
        create_tables(&db).unwrap();
        (dir, path, db)
    }

    #[test]
    fn fingerprint_deterministic_on_repeated_calls() {
        let (_dir, _path, db) = fresh_db();
        let peer_id = "fp-test-peer";

        // Insert a workspace event to seed identity
        db.execute(
            "INSERT INTO workspaces (recorded_by, event_id, workspace_id, public_key)
             VALUES (?1, 'eid1', 'ws1', X'00')",
            rusqlite::params![peer_id],
        )
        .unwrap();

        let fp1 = compute_projection_fingerprint(&db, peer_id);
        let fp2 = compute_projection_fingerprint(&db, peer_id);
        assert_eq!(
            fp1.overall, fp2.overall,
            "fingerprint must be deterministic"
        );
        for (a, b) in fp1.tables.iter().zip(fp2.tables.iter()) {
            assert_eq!(
                a.hash, b.hash,
                "table {} hash must be deterministic",
                a.table
            );
            assert_eq!(a.row_count, b.row_count);
        }
    }

    #[test]
    fn fingerprint_changes_with_projection() {
        let (_dir, _path, db) = fresh_db();
        let peer_id = "fp-test-peer";

        let fp_empty = compute_projection_fingerprint(&db, peer_id);

        // Add a message row
        db.execute(
            "INSERT INTO messages (recorded_by, message_id, workspace_id, author_id, content, created_at)
             VALUES (?1, 'msg1', 'ws1', 'author1', 'hello', 1000)",
            rusqlite::params![peer_id],
        ).unwrap();

        let fp_one_msg = compute_projection_fingerprint(&db, peer_id);
        assert_ne!(
            fp_empty.overall, fp_one_msg.overall,
            "fingerprint must change when projection state changes"
        );

        // The messages table hash should differ
        let msg_idx = fp_empty
            .tables
            .iter()
            .position(|t| t.table == "messages")
            .unwrap();
        assert_ne!(
            fp_empty.tables[msg_idx].hash,
            fp_one_msg.tables[msg_idx].hash
        );
        assert_eq!(fp_one_msg.tables[msg_idx].row_count, 1);

        // Add another message
        db.execute(
            "INSERT INTO messages (recorded_by, message_id, workspace_id, author_id, content, created_at)
             VALUES (?1, 'msg2', 'ws1', 'author1', 'world', 2000)",
            rusqlite::params![peer_id],
        ).unwrap();

        let fp_two_msg = compute_projection_fingerprint(&db, peer_id);
        assert_ne!(
            fp_one_msg.overall, fp_two_msg.overall,
            "fingerprint must change when more rows are added"
        );
        assert_eq!(fp_two_msg.tables[msg_idx].row_count, 2);
    }

    #[test]
    fn fingerprint_detects_content_difference_at_same_count() {
        let (_dir, _path, db) = fresh_db();
        let peer_id = "fp-test-peer";

        db.execute(
            "INSERT INTO messages (recorded_by, message_id, workspace_id, author_id, content, created_at)
             VALUES (?1, 'msg1', 'ws1', 'author1', 'hello', 1000)",
            rusqlite::params![peer_id],
        ).unwrap();

        let fp_hello = compute_projection_fingerprint(&db, peer_id);

        // Change content but keep same count
        db.execute(
            "UPDATE messages SET content = 'goodbye' WHERE recorded_by = ?1 AND message_id = 'msg1'",
            rusqlite::params![peer_id],
        ).unwrap();

        let fp_goodbye = compute_projection_fingerprint(&db, peer_id);

        let msg_idx = fp_hello
            .tables
            .iter()
            .position(|t| t.table == "messages")
            .unwrap();
        assert_eq!(
            fp_hello.tables[msg_idx].row_count, fp_goodbye.tables[msg_idx].row_count,
            "row counts should be equal"
        );
        assert_ne!(
            fp_hello.overall, fp_goodbye.overall,
            "fingerprint must detect content changes that count-only checks miss"
        );
    }

    #[test]
    fn fingerprint_excludes_operational_tables() {
        let (_dir, _path, db) = fresh_db();
        let peer_id = "fp-test-peer";

        // Seed a message so fingerprint is non-trivial
        db.execute(
            "INSERT INTO messages (recorded_by, message_id, workspace_id, author_id, content, created_at)
             VALUES (?1, 'msg1', 'ws1', 'author1', 'hello', 1000)",
            rusqlite::params![peer_id],
        ).unwrap();

        let fp_before = compute_projection_fingerprint(&db, peer_id);

        // Modify operational tables that should NOT affect fingerprint
        db.execute(
            "INSERT INTO valid_events (peer_id, event_id) VALUES (?1, 'eid-op-test')",
            rusqlite::params![peer_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
             VALUES (?1, 'eid-blocked', 'eid-blocker')",
            rusqlite::params![peer_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO rejected_events (peer_id, event_id, reason, rejected_at)
             VALUES (?1, 'eid-rej', 'bad', 1000)",
            rusqlite::params![peer_id],
        )
        .unwrap();

        let fp_after = compute_projection_fingerprint(&db, peer_id);
        assert_eq!(
            fp_before.overall, fp_after.overall,
            "operational table changes must not affect projection fingerprint"
        );
    }

    #[test]
    fn fingerprint_includes_identity_projections() {
        let (_dir, _path, db) = fresh_db();
        let peer_id = "fp-test-peer";

        let fp_empty = compute_projection_fingerprint(&db, peer_id);

        // Add identity projection rows
        db.execute(
            "INSERT INTO workspaces (recorded_by, event_id, workspace_id, public_key)
             VALUES (?1, 'ws-eid', 'ws1', X'AABB')",
            rusqlite::params![peer_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO users (recorded_by, event_id, public_key)
             VALUES (?1, 'user-eid', X'CCDD')",
            rusqlite::params![peer_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key)
             VALUES (?1, 'ps-eid', X'EEFF')",
            rusqlite::params![peer_id],
        )
        .unwrap();

        let fp_identity = compute_projection_fingerprint(&db, peer_id);
        assert_ne!(
            fp_empty.overall, fp_identity.overall,
            "identity projection tables must be included in fingerprint"
        );

        // Verify per-table: workspaces, users, peers_shared all changed
        for name in &["workspaces", "users", "peers_shared"] {
            let idx = fp_empty
                .tables
                .iter()
                .position(|t| t.table == *name)
                .unwrap();
            assert_ne!(
                fp_empty.tables[idx].hash, fp_identity.tables[idx].hash,
                "table {} must contribute to fingerprint",
                name
            );
        }
    }

    #[test]
    fn fingerprint_tenant_scoped() {
        let (_dir, _path, db) = fresh_db();

        // Peer A has a message
        db.execute(
            "INSERT INTO messages (recorded_by, message_id, workspace_id, author_id, content, created_at)
             VALUES ('peer-a', 'msg1', 'ws1', 'author1', 'hello', 1000)",
            [],
        ).unwrap();

        let fp_a = compute_projection_fingerprint(&db, "peer-a");
        let fp_b = compute_projection_fingerprint(&db, "peer-b");

        // Peer A's fingerprint should differ from peer B's (which is empty)
        assert_ne!(
            fp_a.overall, fp_b.overall,
            "fingerprints must be tenant-scoped"
        );

        // Peer B's fingerprint should match an empty DB fingerprint
        let (_dir2, _path2, db2) = fresh_db();
        let fp_empty = compute_projection_fingerprint(&db2, "peer-b");
        assert_eq!(
            fp_b.overall, fp_empty.overall,
            "empty-scoped fingerprint should be identical across DBs"
        );
    }

    #[test]
    fn fingerprint_covers_all_expected_tables() {
        // Verify that FINGERPRINT_TABLES covers all projection tables
        // and excludes operational tables.
        let projection_tables = [
            "messages",
            "reactions",
            "key_secrets",
            "deleted_messages",
            "files",
            "file_slices",
            "workspaces",
            "invites_accepted",
            "user_invites",
            "device_invites",
            "users",
            "peers_shared",
            "admins",
            "key_shared",
            "local_transport_targets",
        ];
        let excluded_tables = [
            "valid_events",
            "rejected_events",
            "blocked_event_deps",
            "blocked_events",
            "project_queue",
            "peer_endpoint_observations",
            "intro_attempts",
            "peer_transport_bindings",
            "invite_bootstrap_trust",
            "pending_invite_bootstrap_trust",
            "local_transport_creds",
            "file_slice_guard_blocks",
            "neg_items",
            "events",
            "recorded_events",
        ];

        let table_names: Vec<&str> = FINGERPRINT_TABLES.iter().map(|t| t.name).collect();

        for expected in &projection_tables {
            assert!(
                table_names.contains(expected),
                "projection table '{}' must be in FINGERPRINT_TABLES",
                expected
            );
        }
        for excluded in &excluded_tables {
            assert!(
                !table_names.contains(excluded),
                "operational table '{}' must NOT be in FINGERPRINT_TABLES",
                excluded
            );
        }
    }
}
const TESTUTIL_SQLITE_BUSY_RETRY_ATTEMPTS: usize = SQLITE_BUSY_RETRY_ATTEMPTS + 4;
