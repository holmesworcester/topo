use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::testutil::{
    assert_eventually, noop_intro_spawner, test_ingest_fns, Peer, ScenarioHarness, SharedDbNode,
};
use topo::transport::{
    create_client_endpoint, create_server_endpoint, extract_spki_fingerprint,
    peer_identity_from_connection, AllowedPeers,
};

/// STATIC PINNING (intentional): this test validates TLS identity extraction
/// mechanics, not transport trust resolution. Static AllowedPeers is the
/// simplest way to stand up a handshake without DB state.
#[tokio::test]
async fn test_peer_identity_extraction_live_handshake() {
    let harness = ScenarioHarness::skip("transport handshake test, no projection state mutated");
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");

    let (cert_a, key_a) = alice.cert_and_key();
    let (cert_b, key_b) = bob.cert_and_key();

    let fp_a = alice.spki_fingerprint();
    let fp_b = bob.spki_fingerprint();
    let expected_a = hex::encode(fp_a);
    let expected_b = hex::encode(fp_b);

    let allowed_for_a = Arc::new(AllowedPeers::from_fingerprints(vec![fp_b]));
    let allowed_for_b = Arc::new(AllowedPeers::from_fingerprints(vec![fp_a]));

    let server_ep =
        create_server_endpoint("127.0.0.1:0".parse().unwrap(), cert_a, key_a, allowed_for_a)
            .unwrap();
    let addr = server_ep.local_addr().unwrap();

    let client_ep =
        create_client_endpoint("0.0.0.0:0".parse().unwrap(), cert_b, key_b, allowed_for_b).unwrap();

    // Client connects, server accepts
    let (client_conn, server_conn) = tokio::join!(
        async { client_ep.connect(addr, "localhost").unwrap().await.unwrap() },
        async { server_ep.accept().await.unwrap().await.unwrap() }
    );

    // Extract identities from live connections
    let client_sees_server = peer_identity_from_connection(&client_conn);
    let server_sees_client = peer_identity_from_connection(&server_conn);

    assert_eq!(
        client_sees_server.as_deref(),
        Some(expected_a.as_str()),
        "client should see server's (Alice's) fingerprint"
    );
    assert_eq!(
        server_sees_client.as_deref(),
        Some(expected_b.as_str()),
        "server should see client's (Bob's) fingerprint"
    );

    // Verify they match the Peer identities computed from DB
    assert_eq!(client_sees_server.unwrap(), alice.identity);
    assert_eq!(server_sees_client.unwrap(), bob.identity);

    harness.finish();
}

/// Regression: per-tenant outbound cert identity.
///
/// When `connect_with(workspace_client_config)` is used, the remote server
/// should see the tenant's cert, not the endpoint's default cert.
///
/// Before the fix, `connect()` would present the default cert (first tenant's),
/// causing the server to see the wrong identity for multi-tenant outbound dials.
///
/// STATIC PINNING (intentional): server uses static AllowedPeers because the
/// test validates per-tenant cert presentation, not transport trust resolution.
/// The client side already uses dynamic `DynamicAllowFn`.
#[tokio::test]
async fn test_connect_with_presents_correct_tenant_cert() {
    use topo::transport::{
        create_dual_endpoint, create_single_port_endpoint, generate_self_signed_cert,
        multi_workspace::WorkspaceCertResolver, workspace_client_config,
    };

    let harness =
        ScenarioHarness::skip("transport-layer cert presentation test, no projection peers");

    // Create two identities: "default" (first tenant) and "actual" (second tenant).
    let (default_cert, default_key) = generate_self_signed_cert().unwrap();

    let (actual_cert, actual_key) = generate_self_signed_cert().unwrap();
    let actual_fp = extract_spki_fingerprint(actual_cert.as_ref()).unwrap();

    // Server: dual endpoint that trusts only "actual" tenant, NOT "default"
    let (server_cert, server_key) = generate_self_signed_cert().unwrap();
    let server_fp = extract_spki_fingerprint(server_cert.as_ref()).unwrap();
    let server_allowed = Arc::new(AllowedPeers::from_fingerprints(vec![actual_fp]));
    let server_ep = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server_cert.clone(),
        server_key.clone_key(),
        server_allowed,
    )
    .unwrap();
    let server_addr = server_ep.local_addr().unwrap();

    // Spawn server accept
    let server_ep_clone = server_ep.clone();
    let server_accept = tokio::spawn(async move {
        let incoming = server_ep_clone.accept().await;
        match incoming {
            Some(inc) => inc.await.ok(),
            None => None,
        }
    });

    // Client endpoint: default cert is "default" (the wrong one for this test)
    let allow_server: Arc<topo::transport::DynamicAllowFn> =
        Arc::new(move |fp: &[u8; 32]| Ok(*fp == server_fp));
    let resolver = WorkspaceCertResolver::new();
    let client_ep = create_single_port_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(resolver),
        allow_server.clone(),
        default_cert.clone(),
        default_key.clone_key(),
    )
    .unwrap();

    // Build per-tenant client config for "actual" tenant (correct cert + trust)
    let sfp = server_fp;
    let tenant_config = workspace_client_config(
        actual_cert.clone(),
        actual_key.clone_key(),
        Arc::new(move |fp: &[u8; 32]| Ok(*fp == sfp)),
    )
    .unwrap();

    // connect_with: should present "actual" cert → server accepts
    let conn = client_ep
        .connect_with(tenant_config, server_addr, "localhost")
        .unwrap()
        .await
        .expect("connect_with should succeed: server trusts actual tenant cert");

    // Server side: verify the client presented "actual" cert identity
    let server_conn = server_accept
        .await
        .unwrap()
        .expect("server should have accepted");
    let server_saw_peer = peer_identity_from_connection(&server_conn)
        .expect("server should see client cert identity");
    assert_eq!(
        server_saw_peer,
        hex::encode(actual_fp),
        "server should see the actual tenant's identity, not the default"
    );

    // Key regression property: before the fix, connect_with did not exist in
    // the outbound path — connect() would be used, presenting default_cert
    // instead of actual_cert. The server (which only trusts actual_fp) would
    // have rejected the handshake, making the test fail at the connect_with
    // assertion above.

    drop(conn);
    drop(server_ep);
    drop(client_ep);
    harness.finish();
}

/// Regression: tenant-scoped outbound trust rejects untrusted servers.
///
/// When `workspace_client_config` is built with trust for peer A only,
/// connecting to peer B should fail (client rejects server cert).
///
/// Before the fix, the union-scoped trust check would accept ANY tenant's
/// trusted peer, allowing cross-tenant trust bleed on outbound connections.
///
/// STATIC PINNING (intentional): servers use static AllowedPeers because the
/// test validates client-side tenant-scoped trust rejection, not server trust
/// resolution. The pinning policy boundary is the thing under test.
#[tokio::test]
async fn test_tenant_scoped_outbound_trust_rejects_untrusted_server() {
    use topo::transport::{
        create_dual_endpoint, generate_self_signed_cert, workspace_client_config,
    };

    let harness =
        ScenarioHarness::skip("transport-layer trust rejection test, no projection peers");

    // Create client and two servers
    let (client_cert, client_key) = generate_self_signed_cert().unwrap();
    let client_fp = extract_spki_fingerprint(client_cert.as_ref()).unwrap();

    let (trusted_cert, trusted_key) = generate_self_signed_cert().unwrap();
    let trusted_fp = extract_spki_fingerprint(trusted_cert.as_ref()).unwrap();

    let (untrusted_cert, untrusted_key) = generate_self_signed_cert().unwrap();

    // Both servers trust the client (will accept its cert)
    let client_allowed = Arc::new(AllowedPeers::from_fingerprints(vec![client_fp]));
    let trusted_ep = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        trusted_cert.clone(),
        trusted_key.clone_key(),
        client_allowed.clone(),
    )
    .unwrap();
    let trusted_addr = trusted_ep.local_addr().unwrap();

    let untrusted_ep = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        untrusted_cert.clone(),
        untrusted_key.clone_key(),
        client_allowed,
    )
    .unwrap();
    let untrusted_addr = untrusted_ep.local_addr().unwrap();

    // Client: create endpoint + tenant config that ONLY trusts "trusted_server"
    let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let tenant_trust: Arc<topo::transport::DynamicAllowFn> = Arc::new(move |fp: &[u8; 32]| {
        Ok(*fp == trusted_fp) // only trusts the trusted server
    });
    let tenant_config =
        workspace_client_config(client_cert.clone(), client_key.clone_key(), tenant_trust).unwrap();

    // Spawn accept on both servers
    let te = trusted_ep.clone();
    tokio::spawn(async move {
        if let Some(inc) = te.accept().await {
            let _ = inc.await;
        }
    });
    let ue = untrusted_ep.clone();
    tokio::spawn(async move {
        if let Some(inc) = ue.accept().await {
            let _ = inc.await;
        }
    });

    // Connect to trusted server → should succeed
    let good_conn = client_ep
        .connect_with(tenant_config.clone(), trusted_addr, "localhost")
        .unwrap()
        .await;
    assert!(
        good_conn.is_ok(),
        "should succeed: client trusts this server"
    );

    // Connect to untrusted server → should fail (client rejects server cert)
    let bad_conn = client_ep
        .connect_with(tenant_config, untrusted_addr, "localhost")
        .unwrap()
        .await;
    assert!(
        bad_conn.is_err(),
        "should fail: client does NOT trust this server (tenant-scoped trust)"
    );

    drop(good_conn);
    drop(trusted_ep);
    drop(untrusted_ep);
    drop(client_ep);
    harness.finish();
}

/// Integration test: two multi-tenant nodes exercise run_node's per-tenant outbound
/// config pipeline (discover_local_tenants -> workspace_client_config -> connect_loop).
///
/// Setup: Node A (2 tenants: a0, a1) accepts connections. Node B (2 tenants: b0, b1)
/// connects with per-tenant configs. Trust seeded so b0 trusts a0 (the fallback cert)
/// and b1 trusts a1 only. Since A presents a0 as its fallback cert, b0's TLS handshake
/// succeeds and sync proceeds, while b1's per-tenant trust verifier correctly rejects
/// a0's cert and no sync occurs.
///
/// Proves: run_node's workspace_client_config correctly scopes outbound trust per-tenant.
#[tokio::test]
async fn test_run_node_multitenant_outbound_isolation() {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use rustls::sign::CertifiedKey;
    use std::sync::atomic::AtomicU64;
    use tokio::sync::mpsc;
    use topo::contracts::event_pipeline_contract::IngestItem;
    use topo::db::transport_creds::discover_local_tenants;
    use topo::db::transport_trust::{import_cli_pins_to_sql, is_peer_allowed};
    use topo::event_pipeline::batch_writer;
    use topo::peering::loops::accept_loop_with_ingest;
    use topo::peering::loops::connect_loop;
    use topo::transport::{
        create_single_port_endpoint,
        multi_workspace::{workspace_sni, WorkspaceCertResolver},
        workspace_client_config, DynamicAllowFn,
    };

    // --- Two multi-tenant nodes ---
    let node_a = SharedDbNode::new(2);
    let node_b = SharedDbNode::new(2);
    let harness = ScenarioHarness::skip(
        "multi-tenant outbound isolation: tests transport config pipeline, \
         not event projection (different workspace chains)",
    );

    let a0 = &node_a.tenants[0];
    let a1 = &node_a.tenants[1];
    let b0 = &node_b.tenants[0];
    let b1 = &node_b.tenants[1];

    // Decode SPKI fingerprints from hex identity strings
    let fp = |peer: &topo::testutil::Peer| -> [u8; 32] {
        hex::decode(&peer.identity).unwrap().try_into().unwrap()
    };

    // --- Seed cross-trust via CLI pins (SQL trust rows) ---
    // a0 trusts b0, a1 trusts b1 (inbound: A accepts both)
    {
        let db = open_connection(&node_a.db_path).unwrap();
        import_cli_pins_to_sql(
            &db,
            &a0.identity,
            &AllowedPeers::from_fingerprints(vec![fp(b0)]),
        )
        .unwrap();
        import_cli_pins_to_sql(
            &db,
            &a1.identity,
            &AllowedPeers::from_fingerprints(vec![fp(b1)]),
        )
        .unwrap();
    }
    // b0 trusts a0, b1 trusts a1 (outbound: per-tenant client trust)
    {
        let db = open_connection(&node_b.db_path).unwrap();
        import_cli_pins_to_sql(
            &db,
            &b0.identity,
            &AllowedPeers::from_fingerprints(vec![fp(a0)]),
        )
        .unwrap();
        import_cli_pins_to_sql(
            &db,
            &b1.identity,
            &AllowedPeers::from_fingerprints(vec![fp(a1)]),
        )
        .unwrap();
    }

    // Create marker events on a0 (to be synced to b0 if connection succeeds)
    let a0_marker = a0.create_message("a0-isolation-marker");
    let a0_marker_b64 = event_id_to_base64(&a0_marker);

    // --- Build Node A endpoint (same as run_node) ---
    let tenants_a = {
        let db = open_connection(&node_a.db_path).unwrap();
        discover_local_tenants(&db).unwrap()
    };
    assert_eq!(tenants_a.len(), 2, "node A should have 2 tenants");

    let provider = rustls::crypto::ring::default_provider();
    let mut cert_resolver_a = WorkspaceCertResolver::new();
    let mut default_cert_a: Option<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> = None;

    for t in &tenants_a {
        let cert_der = CertificateDer::from(t.cert_der.clone());
        let key_der = PrivatePkcs8KeyDer::from(t.key_der.clone());
        let ck = CertifiedKey::from_der(
            vec![cert_der.clone()],
            key_der.clone_key().into(),
            &provider,
        )
        .unwrap();
        let sni = workspace_sni(&t.workspace_id);
        cert_resolver_a.add(sni, Arc::new(ck));
        if default_cert_a.is_none() {
            default_cert_a = Some((cert_der, key_der));
        }
    }
    let (default_cert_der, default_key_der) = default_cert_a.unwrap();

    // Union trust for A's inbound (same as run_node)
    let db_path_a_trust = node_a.db_path.clone();
    let a_tenant_ids: Vec<String> = tenants_a.iter().map(|t| t.peer_id.clone()).collect();
    let union_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
        let db = open_connection(&db_path_a_trust)?;
        for tid in &a_tenant_ids {
            if is_peer_allowed(&db, tid, peer_fp)? {
                return Ok(true);
            }
        }
        Ok(false)
    });

    let endpoint_a = create_single_port_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(cert_resolver_a),
        union_allow,
        default_cert_der,
        default_key_der,
    )
    .unwrap();
    let addr_a = endpoint_a.local_addr().unwrap();

    // Shared batch_writer for A (same as run_node)
    let (ingest_tx, ingest_rx) = mpsc::channel::<IngestItem>(5000);
    let events_received = Arc::new(AtomicU64::new(0));
    let writer_events = events_received.clone();
    let writer_db = node_a.db_path.clone();
    let _writer = std::thread::spawn(move || {
        batch_writer(writer_db, ingest_rx, writer_events);
    });

    // Accept loop for A
    let a_db = node_a.db_path.clone();
    let a_ids: Vec<String> = tenants_a.iter().map(|t| t.peer_id.clone()).collect();
    let _accept = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = accept_loop_with_ingest(
                &a_db,
                &a_ids,
                endpoint_a,
                None,
                ingest_tx,
                HashMap::new(),
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await;
        });
    });

    // --- Build Node B per-tenant configs (same as run_node) ---
    let tenants_b = {
        let db = open_connection(&node_b.db_path).unwrap();
        discover_local_tenants(&db).unwrap()
    };
    assert_eq!(tenants_b.len(), 2, "node B should have 2 tenants");

    let mut b_configs: HashMap<String, quinn::ClientConfig> = HashMap::new();
    for t in &tenants_b {
        let cert_der = CertificateDer::from(t.cert_der.clone());
        let key_der = PrivatePkcs8KeyDer::from(t.key_der.clone());
        let db_path_t = node_b.db_path.clone();
        let tid = t.peer_id.clone();
        let tenant_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
            let db = open_connection(&db_path_t)?;
            is_peer_allowed(&db, &tid, peer_fp)
        });
        let cfg = workspace_client_config(cert_der, key_der, tenant_allow).unwrap();
        b_configs.insert(t.peer_id.clone(), cfg);
    }

    // Node B endpoint (for outbound connect_loop calls)
    let mut cert_resolver_b = WorkspaceCertResolver::new();
    let mut default_cert_b: Option<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> = None;
    for t in &tenants_b {
        let cert_der = CertificateDer::from(t.cert_der.clone());
        let key_der = PrivatePkcs8KeyDer::from(t.key_der.clone());
        let ck = CertifiedKey::from_der(
            vec![cert_der.clone()],
            key_der.clone_key().into(),
            &provider,
        )
        .unwrap();
        cert_resolver_b.add(workspace_sni(&t.workspace_id), Arc::new(ck));
        if default_cert_b.is_none() {
            default_cert_b = Some((cert_der, key_der));
        }
    }
    let (b_def_cert, b_def_key) = default_cert_b.unwrap();
    let db_path_b_trust = node_b.db_path.clone();
    let b_tenant_ids: Vec<String> = tenants_b.iter().map(|t| t.peer_id.clone()).collect();
    let b_union_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
        let db = open_connection(&db_path_b_trust)?;
        for tid in &b_tenant_ids {
            if is_peer_allowed(&db, tid, peer_fp)? {
                return Ok(true);
            }
        }
        Ok(false)
    });
    let endpoint_b = create_single_port_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(cert_resolver_b),
        b_union_allow,
        b_def_cert,
        b_def_key,
    )
    .unwrap();

    // --- Spawn connect_loops for each B tenant (same as run_node) ---
    // b0's config trusts a0 (= A's fallback cert) → should succeed
    let b0_cfg = b_configs.get(&b0.identity).unwrap().clone();
    let ep_b0 = endpoint_b.clone();
    let b0_db = node_b.db_path.clone();
    let b0_id = b0.identity.clone();
    let _b0_connect = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = connect_loop(
                &b0_db,
                &b0_id,
                ep_b0,
                addr_a,
                Some(b0_cfg),
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await;
        });
    });

    // b1's config trusts a1 only (NOT a0 = A's fallback cert) → TLS should fail
    let b1_cfg = b_configs.get(&b1.identity).unwrap().clone();
    let ep_b1 = endpoint_b.clone();
    let b1_db = node_b.db_path.clone();
    let b1_id = b1.identity.clone();
    let _b1_connect = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = connect_loop(
                &b1_db,
                &b1_id,
                ep_b1,
                addr_a,
                Some(b1_cfg),
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await;
        });
    });

    // --- Verify ---
    // b0 should sync with A. Since b0 and b1 share a DB (`events` table is shared),
    // we check `recorded_events` which tracks per-tenant sync state.
    assert_eventually(
        || {
            let db = open_connection(&node_b.db_path).unwrap();
            db.query_row(
                "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![&b0.identity, &a0_marker_b64],
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false)
        },
        Duration::from_secs(15),
        "b0 should record a0's marker (b0 trusts a0 = A's fallback cert)",
    )
    .await;

    // b1 should NOT have recorded a0's marker. b1's per-tenant workspace_client_config
    // only trusts a1's cert, but A presents a0 as its fallback — TLS fails, no sync.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let b1_has_marker: bool = {
        let db = open_connection(&node_b.db_path).unwrap();
        db.query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&b1.identity, &a0_marker_b64],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false)
    };
    assert!(
        !b1_has_marker,
        "b1 should NOT have recorded a0's marker: b1's per-tenant config only trusts a1, \
         but A presents a0 as its fallback cert. Per-tenant outbound isolation prevents \
         b1 from establishing a TLS connection."
    );

    harness.finish();
}
