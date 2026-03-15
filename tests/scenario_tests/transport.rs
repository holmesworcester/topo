use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use topo::crypto::{event_id_to_base64, AllowedPeers};
use topo::db::open_connection;
use topo::peering::loops::{accept_loop, connect_loop_with_coordination_until_cancel};
use topo::sync::CoordinationManager;
use topo::testutil::{
    assert_eventually, create_dynamic_endpoint_for_peer, noop_intro_spawner, test_ingest_fns, Peer,
    ScenarioHarness, SharedDbNode,
};
use topo::transport::{
    create_single_port_endpoint, multi_workspace::transport_sni,
    multi_workspace::WorkspaceCertResolver, peer_identity_from_connection, workspace_client_config,
    DynamicAllowFn,
};

fn allow_from_peer(peer: &Peer) -> Arc<DynamicAllowFn> {
    let db_path = peer.db_path.clone();
    let tenant_id = peer.identity.clone();
    Arc::new(move |peer_fp: &[u8; 32]| {
        let db = open_connection(&db_path)?;
        topo::db::transport_trust::is_authorized_for_tenant(&db, &tenant_id, peer_fp)
    })
}

#[tokio::test]
async fn test_bidirectional_connect_loops_do_not_deadlock_peer_session_gate() {
    use std::thread;
    use tokio_util::sync::CancellationToken;

    let alice = Peer::new_with_identity("transport-bidir-alice");
    let bob = Peer::new_in_workspace("transport-bidir-bob", &alice).await;
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    let alice_accept_ep = create_dynamic_endpoint_for_peer(&alice);
    let alice_accept_ep_guard = alice_accept_ep.clone();
    let alice_connect_ep = create_dynamic_endpoint_for_peer(&alice);
    let alice_connect_ep_guard = alice_connect_ep.clone();
    let bob_accept_ep = create_dynamic_endpoint_for_peer(&bob);
    let bob_accept_ep_guard = bob_accept_ep.clone();
    let bob_connect_ep = create_dynamic_endpoint_for_peer(&bob);
    let bob_connect_ep_guard = bob_connect_ep.clone();

    let alice_addr = alice_accept_ep.local_addr().expect("alice listen addr");
    let bob_addr = bob_accept_ep.local_addr().expect("bob listen addr");
    let alice_cancel = CancellationToken::new();
    let bob_cancel = CancellationToken::new();

    let alice_accept_db = alice.db_path.clone();
    let alice_accept_id = alice.identity.clone();
    let alice_accept = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = accept_loop(
                &alice_accept_db,
                &alice_accept_id,
                alice_accept_ep,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await;
        });
    });

    let bob_accept_db = bob.db_path.clone();
    let bob_accept_id = bob.identity.clone();
    let bob_accept = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = accept_loop(
                &bob_accept_db,
                &bob_accept_id,
                bob_accept_ep,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await;
        });
    });

    let alice_connect_db = alice.db_path.clone();
    let alice_connect_id = alice.identity.clone();
    let alice_connect_cancel = alice_cancel.clone();
    let bob_target = bob.identity.clone();
    let alice_connect = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = connect_loop_with_coordination_until_cancel(
                &alice_connect_db,
                &alice_connect_id,
                alice_connect_ep,
                bob_addr,
                &bob_target,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
                Arc::new(CoordinationManager::new()),
                alice_connect_cancel,
            )
            .await;
        });
    });

    let bob_connect_db = bob.db_path.clone();
    let bob_connect_id = bob.identity.clone();
    let bob_connect_cancel = bob_cancel.clone();
    let alice_target = alice.identity.clone();
    let bob_connect = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = connect_loop_with_coordination_until_cancel(
                &bob_connect_db,
                &bob_connect_id,
                bob_connect_ep,
                alice_addr,
                &alice_target,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
                Arc::new(CoordinationManager::new()),
                bob_connect_cancel,
            )
            .await;
        });
    });

    tokio::time::sleep(Duration::from_millis(750)).await;

    let alice_marker = alice.create_message("bidirectional-connect-regression");
    let alice_marker_b64 = event_id_to_base64(&alice_marker);
    assert_eventually(
        || bob.has_event(&alice_marker_b64),
        Duration::from_secs(8),
        "bidirectional connect loops should deliver fresh events without a 30s session deadlock",
    )
    .await;

    alice_cancel.cancel();
    bob_cancel.cancel();
    alice_accept_ep_guard.close(0u32.into(), b"test shutdown");
    alice_connect_ep_guard.close(0u32.into(), b"test shutdown");
    bob_accept_ep_guard.close(0u32.into(), b"test shutdown");
    bob_connect_ep_guard.close(0u32.into(), b"test shutdown");

    alice_accept.join().expect("join alice accept");
    bob_accept.join().expect("join bob accept");
    alice_connect.join().expect("join alice connect");
    bob_connect.join().expect("join bob connect");

    harness.finish();
}

#[tokio::test]
async fn test_peer_identity_extraction_live_handshake() {
    let alice = Peer::new_with_identity("transport-identity-alice");
    let bob = Peer::new_in_workspace("transport-identity-bob", &alice).await;
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    let server_ep = create_dynamic_endpoint_for_peer(&alice);
    let addr = server_ep.local_addr().expect("server addr");
    let client_ep = create_dynamic_endpoint_for_peer(&bob);
    let server_sni = transport_sni(&alice.identity);

    let (client_conn, server_conn) = tokio::join!(
        async { client_ep.connect(addr, &server_sni).unwrap().await.unwrap() },
        async { server_ep.accept().await.unwrap().await.unwrap() }
    );

    let client_sees_server = peer_identity_from_connection(&client_conn);
    let server_sees_client = peer_identity_from_connection(&server_conn);

    assert_eq!(client_sees_server.as_deref(), Some(alice.identity.as_str()));
    assert_eq!(server_sees_client.as_deref(), Some(bob.identity.as_str()));

    harness.finish();
}

#[tokio::test]
async fn test_connect_with_presents_correct_tenant_cert() {
    let server = Peer::new_with_identity("transport-server");
    let default_tenant = Peer::new_with_identity("transport-default-tenant");
    let actual_tenant = Peer::new_in_workspace("transport-actual-tenant", &server).await;
    let harness = ScenarioHarness::new();
    harness.track(&server);
    harness.track(&default_tenant);
    harness.track(&actual_tenant);

    let server_ep = create_dynamic_endpoint_for_peer(&server);
    let server_addr = server_ep.local_addr().expect("server addr");
    let server_target_sni = transport_sni(&server.identity);

    let server_ep_clone = server_ep.clone();
    let server_accept = tokio::spawn(async move {
        let incoming = server_ep_clone.accept().await;
        match incoming {
            Some(inc) => inc.await.ok(),
            None => None,
        }
    });

    let resolver = Arc::new(WorkspaceCertResolver::new());
    let (default_cert, default_key) = default_tenant.cert_and_key();
    let client_ep = create_single_port_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        resolver,
        allow_from_peer(&actual_tenant),
        default_cert,
        default_key,
    )
    .expect("client endpoint");

    let (actual_cert, actual_key) = actual_tenant.cert_and_key();
    let tenant_config =
        workspace_client_config(actual_cert, actual_key, allow_from_peer(&actual_tenant))
            .expect("tenant config");

    let conn = client_ep
        .connect_with(tenant_config, server_addr, &server_target_sni)
        .expect("start connect")
        .await
        .expect("connect_with should succeed");

    let server_conn = server_accept
        .await
        .unwrap()
        .expect("server should have accepted");
    let server_saw_peer = peer_identity_from_connection(&server_conn)
        .expect("server should see client cert identity");
    assert_eq!(
        server_saw_peer, actual_tenant.identity,
        "server should see the requested tenant cert, not the endpoint default cert"
    );

    drop(conn);
    drop(server_ep);
    drop(client_ep);
    harness.finish();
}

#[tokio::test]
async fn test_tenant_scoped_outbound_trust_rejects_untrusted_server() {
    let trusted_server = Peer::new_with_identity("transport-trusted-server");
    let client = Peer::new_in_workspace("transport-client", &trusted_server).await;
    let untrusted_server = Peer::new_with_identity("transport-untrusted-server");
    let harness = ScenarioHarness::new();
    harness.track(&trusted_server);
    harness.track(&client);
    harness.track(&untrusted_server);

    let trusted_ep = create_dynamic_endpoint_for_peer(&trusted_server);
    let trusted_addr = trusted_ep.local_addr().expect("trusted addr");
    let untrusted_ep = create_dynamic_endpoint_for_peer(&untrusted_server);
    let untrusted_addr = untrusted_ep.local_addr().expect("untrusted addr");

    let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let (client_cert, client_key) = client.cert_and_key();
    let tenant_config =
        workspace_client_config(client_cert, client_key, allow_from_peer(&client)).unwrap();

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

    let good_conn = client_ep
        .connect_with(
            tenant_config.clone(),
            trusted_addr,
            &transport_sni(&trusted_server.identity),
        )
        .unwrap()
        .await;
    assert!(
        good_conn.is_ok(),
        "client should trust the joined workspace server"
    );

    let bad_conn = client_ep
        .connect_with(
            tenant_config,
            untrusted_addr,
            &transport_sni(&untrusted_server.identity),
        )
        .unwrap()
        .await;
    assert!(
        bad_conn.is_err(),
        "client should reject a server that is not authorized for its tenant"
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
/// Setup: Node A (2 tenants) accepts connections. Node B (2 tenants) connects with
/// per-tenant configs. Trust is seeded so b0 trusts Node A's actual fallback cert
/// identity (the first tenant returned by discover_local_tenants), and b1 trusts only
/// A's other tenant cert. Since A presents the fallback cert on outbound/inbound
/// default paths, b0 succeeds while b1's per-tenant trust verifier rejects the cert.
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
        multi_workspace::{transport_sni, WorkspaceCertResolver},
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

    // --- Build Node A endpoint (same as run_node) ---
    let tenants_a = {
        let db = open_connection(&node_a.db_path).unwrap();
        discover_local_tenants(&db).unwrap()
    };
    assert_eq!(tenants_a.len(), 2, "node A should have 2 tenants");

    // Fallback cert identity is whichever tenant discover_local_tenants returns first.
    let fallback_a_id = tenants_a[0].peer_id.clone();
    let (fallback_a, nonfallback_a) = if fallback_a_id == a0.identity {
        (a0, a1)
    } else {
        (a1, a0)
    };

    // --- Seed cross-trust via CLI pins (SQL trust rows) ---
    // A inbound trust: fallback tenant trusts b0; non-fallback trusts b1.
    {
        let db = open_connection(&node_a.db_path).unwrap();
        import_cli_pins_to_sql(
            &db,
            &fallback_a.identity,
            &AllowedPeers::from_fingerprints(vec![fp(b0)]),
        )
        .unwrap();
        import_cli_pins_to_sql(
            &db,
            &nonfallback_a.identity,
            &AllowedPeers::from_fingerprints(vec![fp(b1)]),
        )
        .unwrap();
    }
    // B outbound trust: b0 trusts A fallback cert; b1 trusts only non-fallback cert.
    {
        let db = open_connection(&node_b.db_path).unwrap();
        import_cli_pins_to_sql(
            &db,
            &b0.identity,
            &AllowedPeers::from_fingerprints(vec![fp(fallback_a)]),
        )
        .unwrap();
        import_cli_pins_to_sql(
            &db,
            &b1.identity,
            &AllowedPeers::from_fingerprints(vec![fp(nonfallback_a)]),
        )
        .unwrap();
    }

    // Create marker event on A fallback identity (should sync to b0 only).
    let fallback_marker = fallback_a.create_message("fallback-isolation-marker");
    let fallback_marker_b64 = event_id_to_base64(&fallback_marker);

    let provider = rustls::crypto::ring::default_provider();
    let cert_resolver_a = WorkspaceCertResolver::new();
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
        let sni = transport_sni(&t.transport_peer_id);
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
    let cert_resolver_b = WorkspaceCertResolver::new();
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
        cert_resolver_b.add(transport_sni(&t.transport_peer_id), Arc::new(ck));
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
    // b0's config trusts A's fallback cert identity → should succeed
    let b0_cfg = b_configs.get(&b0.identity).unwrap().clone();
    let ep_b0 = endpoint_b.clone();
    let b0_db = node_b.db_path.clone();
    let b0_id = b0.identity.clone();
    let a_target_for_b0 = fallback_a.identity.clone();
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
                &a_target_for_b0,
                Some(b0_cfg),
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await;
        });
    });

    // b1's config trusts only A's non-fallback identity → TLS should fail
    let b1_cfg = b_configs.get(&b1.identity).unwrap().clone();
    let ep_b1 = endpoint_b.clone();
    let b1_db = node_b.db_path.clone();
    let b1_id = b1.identity.clone();
    let a_target_for_b1 = fallback_a.identity.clone();
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
                &a_target_for_b1,
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
                rusqlite::params![&b0.identity, &fallback_marker_b64],
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false)
        },
        Duration::from_secs(30),
        "b0 should record fallback marker (b0 trusts A fallback cert)",
    )
    .await;

    // b1 should NOT have recorded fallback marker. b1 trusts non-fallback cert only,
    // while A presents fallback cert on this path.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let b1_has_marker: bool = {
        let db = open_connection(&node_b.db_path).unwrap();
        db.query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&b1.identity, &fallback_marker_b64],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false)
    };
    assert!(
        !b1_has_marker,
        "b1 should NOT have recorded fallback marker: b1 trusts only non-fallback cert, \
         but A presents fallback cert. Per-tenant outbound isolation prevents \
         b1 from establishing a TLS connection."
    );

    harness.finish();
}
