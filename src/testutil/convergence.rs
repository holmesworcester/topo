use super::*;
use super::peer::Peer;

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

pub(super) async fn wait_for_materialized_local_peer_signer(
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

pub(super) async fn wait_for_any_tenant_transport_target(
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

pub(super) async fn wait_for_projected_peer_transport(
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
