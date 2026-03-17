use std::sync::Arc;
use std::time::Duration;

use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::peering::loops::{accept_loop, connect_loop_with_coordination_until_cancel};
use topo::sync::CoordinationManager;
use topo::testutil::{
    assert_eventually, create_dynamic_endpoint_for_peer, noop_intro_spawner, test_ingest_fns, Peer,
    ScenarioHarness,
};
use topo::transport::{
    create_single_port_endpoint, multi_workspace::transport_sni,
    multi_workspace::TransportTargetCertResolver, peer_identity_from_connection,
    workspace_client_config, DynamicAllowFn,
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

    let resolver = Arc::new(TransportTargetCertResolver::new());
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
