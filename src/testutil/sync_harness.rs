use super::*;
use super::peer::Peer;

// ---------------------------------------------------------------------------
// REALISM SYNC HELPERS
// ---------------------------------------------------------------------------

pub(crate) fn current_transport_target(peer: &Peer) -> String {
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

pub(super) fn daemon_cert_and_key_for_peer(
    peer: &Peer,
) -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    ensure_test_daemon_identity_for_peer(peer);
    let (_peer_id, cert, key) = crate::transport::load_daemon_identity_from_db(&peer.db_path)
        .expect("failed to load test daemon identity");
    (cert, key)
}

pub(super) fn daemon_fingerprint_for_peer(peer: &Peer) -> [u8; 32] {
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

