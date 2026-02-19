//! Integration test: three-peer intro + hole punch flow.
//!
//! Topology: I (introducer) <-> A, I <-> B. After I records endpoint
//! observations for A and B, it sends IntroOffer to both. A and B use
//! the offers to connect directly and sync messages.
//!
//! On localhost there's no NAT, so the "punch" is a regular connect.
//! This tests the full IntroOffer send/receive/validate/dial/sync path.

use std::sync::Arc;
use std::time::Duration;

use topo::crypto::event_id_from_base64;
use topo::db::open_connection;
use topo::db::intro::{list_intro_attempts, freshest_endpoint};
use topo::db::project_queue::ProjectQueue;
use topo::db::transport_trust::allowed_peers_from_db;
use topo::projection::apply::project_one;
use topo::peering::loops::{accept_loop, connect_loop};
use topo::sync::intro::{run_intro, send_intro_offer, build_intro_offer};
use topo::sync::punch::spawn_intro_listener;
use topo::testutil::{Peer, assert_eventually, create_dynamic_endpoint_for_peer, noop_intro_spawner};
use topo::transport::{
    AllowedPeers, create_dual_endpoint,
};

/// Force-drain the project_queue for a peer's DB, projecting any pending items.
/// This handles the race where the batch_writer committed events but hasn't
/// yet drained the project_queue (projection is a second pass after COMMIT).
fn drain_project_queue(db_path: &str, identity: &str) {
    let db = open_connection(db_path).expect("open db for projection drain");
    let pq = ProjectQueue::new(&db);
    let recorded_by = identity.to_string();
    let _ = pq.drain(&recorded_by, |conn, event_id_b64| {
        if let Some(eid) = event_id_from_base64(event_id_b64) {
            project_one(conn, &recorded_by, &eid)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        }
        Ok(())
    });
}

/// Functional intro test with realistic transport trust and endpoint discovery.
///
/// All three peers share the same workspace so identity chains validate
/// across peers through normal sync (TransportKey events project correctly).
/// Uses dynamic DB trust lookup (matching production behavior) and derives
/// endpoint observations from organic sync traffic (no manual DB writes).
///
/// Three-peer intro happy path:
/// 1. A <-> I, B <-> I sync via dynamic-trust dual endpoints
///    (gives I organic endpoint observations for A and B,
///    and relays identity chains so TransportKey events project at each peer)
/// 2. I sends IntroOffer to A and B using organically observed addresses
/// 3. A and B dial each other using identity-derived trust and sync messages
#[tokio::test]
async fn test_three_peer_intro_happy_path() {
    // Intro creates the workspace; A and B join it so all share one trust root.
    let intro = Peer::new_with_identity("introducer");
    let peer_a = Peer::new_in_workspace("peer_a", &intro).await;
    let peer_b = Peer::new_in_workspace("peer_b", &intro).await;

    // Publish TransportKey events binding each peer's TLS cert to its identity chain
    intro.publish_transport_key();
    peer_a.publish_transport_key();
    peer_b.publish_transport_key();

    // Each peer creates a unique event to sync.
    peer_a.create_message("peer_a bootstrap message");
    peer_b.create_message("peer_b bootstrap message");
    intro.create_message("introducer bootstrap message");

    let fp_i = intro.spki_fingerprint();
    let fp_a = peer_a.spki_fingerprint();
    let fp_b = peer_b.spki_fingerprint();

    // Trust is derived from PeerShared events synced during workspace join.
    // No CLI pins needed — all peers share the same workspace so identity chains
    // project TransportKey trust entries at each peer after sync.

    // Create dynamic dual endpoints for all three peers.
    // Trust is resolved from SQL at each TLS handshake (production behavior).
    // Dual endpoints use the same port for connect and accept, so I's organic
    // endpoint observations from Phase 1 sync point to A and B's listening addresses.
    let ep_i = create_dynamic_endpoint_for_peer(&intro);
    let ep_a = create_dynamic_endpoint_for_peer(&peer_a);
    let ep_b = create_dynamic_endpoint_for_peer(&peer_b);

    let addr_i = ep_i.local_addr().expect("addr_i");
    let addr_a = ep_a.local_addr().expect("addr_a");
    let addr_b = ep_b.local_addr().expect("addr_b");

    // --- Phase 1: Relay sync I<->A and I<->B ---
    // I runs accept_loop; A and B connect to I using their dual endpoints.
    // I's accept_loop organically records endpoint observations for A and B
    // at their dual endpoint source addresses (= their listening addresses).
    let i_ep1 = ep_i.clone();
    let i_db = intro.db_path.clone();
    let i_id = intro.identity.clone();
    let _i_accept = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&i_db, &i_id, i_ep1, spawn_intro_listener, topo::testutil::test_ingest_fns()).await;
        });
    });

    let a_ep1 = ep_a.clone();
    let a_db1 = peer_a.db_path.clone();
    let a_id1 = peer_a.identity.clone();
    let _a_connect = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = connect_loop(&a_db1, &a_id1, a_ep1, addr_i, None, spawn_intro_listener, topo::testutil::test_ingest_fns()).await;
        });
    });

    let b_ep1 = ep_b.clone();
    let b_db1 = peer_b.db_path.clone();
    let b_id1 = peer_b.identity.clone();
    let _b_connect = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = connect_loop(&b_db1, &b_id1, b_ep1, addr_i, None, spawn_intro_listener, topo::testutil::test_ingest_fns()).await;
        });
    });

    // Wait for full convergence: all 3 peers should have all shared events (20).
    assert_eventually(
        || peer_a.store_count() >= 20 && peer_b.store_count() >= 20 && intro.store_count() >= 20,
        Duration::from_secs(20),
        &format!("full convergence (I={}, A={}, B={})",
            intro.store_count(), peer_a.store_count(), peer_b.store_count()),
    ).await;

    // Verify I has organic endpoint observations for A and B that match
    // their actual dual endpoint addresses (no manual observation writes).
    {
        let db = open_connection(&intro.db_path).expect("open intro db");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap()
            .as_millis() as i64;
        let ep_a_obs = freshest_endpoint(&db, &intro.identity, &peer_a.identity, now_ms)
            .expect("query ep_a");
        let ep_b_obs = freshest_endpoint(&db, &intro.identity, &peer_b.identity, now_ms)
            .expect("query ep_b");
        assert!(ep_a_obs.is_some(), "I should have organic endpoint observation for A");
        assert!(ep_b_obs.is_some(), "I should have organic endpoint observation for B");
        let (ip_a, port_a, _) = ep_a_obs.unwrap();
        let (ip_b, port_b, _) = ep_b_obs.unwrap();
        eprintln!("I organically observed A at {}:{}, B at {}:{}", ip_a, port_a, ip_b, port_b);
        assert_eq!(port_a, addr_a.port(),
            "organic observation for A should match A's dual endpoint port");
        assert_eq!(port_b, addr_b.port(),
            "organic observation for B should match B's dual endpoint port");
    }

    // Wait for TransportKey projection to complete at A and B.
    {
        let a_path = peer_a.db_path.clone();
        let a_ident = peer_a.identity.clone();
        let b_path = peer_b.db_path.clone();
        let b_ident = peer_b.identity.clone();
        assert_eventually(
            || {
                drain_project_queue(&a_path, &a_ident);
                drain_project_queue(&b_path, &b_ident);
                let a_ok = open_connection(&a_path).ok()
                    .and_then(|c| allowed_peers_from_db(&c, &a_ident).ok())
                    .map(|ap| ap.contains(&fp_b) && ap.contains(&fp_i))
                    .unwrap_or(false);
                let b_ok = open_connection(&b_path).ok()
                    .and_then(|c| allowed_peers_from_db(&c, &b_ident).ok())
                    .map(|ap| ap.contains(&fp_a) && ap.contains(&fp_i))
                    .unwrap_or(false);
                a_ok && b_ok
            },
            Duration::from_secs(15),
            "TransportKey projection at A and B",
        ).await;
    }

    // Close I's endpoint to stop Phase 1 sync sessions.
    // A and B's connect_loop threads will fail to reconnect (expected).
    ep_i.close(0u32.into(), b"phase1-done");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Phase 2: I sends IntroOffer to A and B ---
    // A and B's dual endpoints are still alive at the same addresses.
    // Start accept_loops so they can receive intros and punched connections.
    // Dynamic trust now includes identity-derived entries (from TransportKey events).
    let a_ep2 = ep_a.clone();
    let a_db2 = peer_a.db_path.clone();
    let a_id2 = peer_a.identity.clone();
    let _a_accept = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&a_db2, &a_id2, a_ep2, spawn_intro_listener, topo::testutil::test_ingest_fns()).await;
        });
    });

    let b_ep2 = ep_b.clone();
    let b_db2 = peer_b.db_path.clone();
    let b_id2 = peer_b.identity.clone();
    let _b_accept = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&b_db2, &b_id2, b_ep2, spawn_intro_listener, topo::testutil::test_ingest_fns()).await;
        });
    });

    tokio::time::sleep(Duration::from_millis(300)).await;

    // I creates a fresh endpoint to send intros from (dynamic trust).
    let ep_i2 = create_dynamic_endpoint_for_peer(&intro);

    // Send intros — run_intro reads organic observations from I's DB.
    let result = run_intro(
        &ep_i2, &intro.db_path, &intro.identity,
        &peer_a.identity, &peer_b.identity,
        30_000, 4_000,
    ).await.expect("run_intro");

    assert!(result.sent_to_a, "IntroOffer should be sent to A");
    assert!(result.sent_to_b, "IntroOffer should be sent to B");
    eprintln!("IntroOffer sent: to_a={}, to_b={}", result.sent_to_a, result.sent_to_b);

    // --- Phase 3: Wait for A and B to process intros and sync ---
    // A and B create new events that should sync via punched connection.
    peer_a.create_message("peer_a post-intro message");
    peer_b.create_message("peer_b post-intro message");

    // After Phase 1 each peer had 20 events. Each created 1 new message = 21.
    // After punch sync each gets the other's new message = 22.
    assert_eventually(
        || {
            let a_count = peer_a.store_count();
            let b_count = peer_b.store_count();
            a_count >= 22 && b_count >= 22
        },
        Duration::from_secs(15),
        &format!("A<->B punch sync (A={}, B={})", peer_a.store_count(), peer_b.store_count()),
    ).await;

    eprintln!("SUCCESS: A has {} events, B has {} events", peer_a.store_count(), peer_b.store_count());

    // --- Phase 4: Verify intro_attempts were recorded ---
    {
        let db_a = open_connection(&peer_a.db_path).expect("open A db");
        let attempts_a = list_intro_attempts(&db_a, &peer_a.identity, None)
            .expect("list intro attempts A");
        eprintln!("A's intro attempts: {}", attempts_a.len());
        for a in &attempts_a {
            eprintln!("  {} -> status={}", &a.other_peer_id[..16], a.status);
        }
        assert!(!attempts_a.is_empty(), "A should have recorded intro attempts");
        assert!(
            attempts_a.iter().any(|a| a.status == "connected"),
            "A should have at least one 'connected' intro attempt, got: {:?}",
            attempts_a.iter().map(|a| &a.status).collect::<Vec<_>>()
        );
    }

    // --- Phase 5: Verify no intro artifacts in canonical event projections ---
    {
        let db_a = open_connection(&peer_a.db_path).expect("open A db");
        let intro_events: i64 = db_a.query_row(
            "SELECT COUNT(*) FROM events WHERE event_type = 'intro_offer'",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        assert_eq!(intro_events, 0, "intro offers should not appear in canonical events");
    }

    // Clean up
    ep_i2.close(0u32.into(), b"done");
    ep_a.close(0u32.into(), b"done");
    ep_b.close(0u32.into(), b"done");
}

/// TRUST BOUNDARY TEST: Dynamic trust rejects unknown peer at handshake.
/// When no SQL trust row exists for a peer, the dynamic trust lookup
/// should reject the TLS handshake (connection fails).
#[tokio::test]
async fn test_dynamic_trust_rejects_unknown_peer() {
    let peer_a = Peer::new("dyn_reject_a");
    let unknown = Peer::new("dyn_reject_unknown");

    // A has a dynamic-trust endpoint but NO trust rows seeded for `unknown`.
    let ep_a = create_dynamic_endpoint_for_peer(&peer_a);
    let addr_a = ep_a.local_addr().expect("addr_a");

    let a_db = peer_a.db_path.clone();
    let a_id = peer_a.identity.clone();
    let a_ep = ep_a.clone();
    let _a_accept = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&a_db, &a_id, a_ep, spawn_intro_listener, topo::testutil::test_ingest_fns()).await;
        });
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Unknown peer tries to connect to A — should fail at TLS handshake
    // because A's dynamic trust lookup finds no matching row.
    let ep_unknown = create_dynamic_endpoint_for_peer(&unknown);
    let result = ep_unknown.connect(addr_a, "localhost")
        .expect("initiate connect")
        .await;

    assert!(result.is_err(), "connection should fail: A has no trust row for unknown peer");
    eprintln!("Dynamic trust rejection confirmed: {:?}", result.unwrap_err());

    ep_a.close(0u32.into(), b"done");
    ep_unknown.close(0u32.into(), b"done");
}

/// TRUST BOUNDARY TEST: Stale intro rejected.
/// Expired expires_at_ms should result in status='expired'.
/// Uses static pinning — this test exercises intro validation logic,
/// not transport trust resolution.
#[tokio::test]
async fn test_stale_intro_rejected() {
    let intro = Peer::new("stale_introducer");
    let peer_a = Peer::new("stale_a");

    let fp_i = intro.spki_fingerprint();
    let fp_a = peer_a.spki_fingerprint();

    // Static pin: A trusts only I (pinning policy is the thing under test here)
    let (cert_a, key_a) = peer_a.cert_and_key();
    let allowed_a = Arc::new(AllowedPeers::from_fingerprints(vec![fp_i]));
    let ep_a = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_a, key_a, allowed_a,
    ).expect("ep_a");
    let addr_a = ep_a.local_addr().expect("addr_a");

    // Start A's accept loop with intro listener
    let a_db = peer_a.db_path.clone();
    let a_id = peer_a.identity.clone();
    let a_ep = ep_a.clone();
    let _a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&a_db, &a_id, a_ep, spawn_intro_listener, topo::testutil::test_ingest_fns()).await;
        });
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Build an expired IntroOffer (expires_at_ms in the past)
    let stale_offer = build_intro_offer(
        &hex::encode([0xBBu8; 32]),  // some peer
        "10.0.0.99", 9999,
        1000,  // observed long ago
        1,     // ttl of 1ms -> already expired
        4000,
    ).expect("build stale offer");

    // Connect to A and send the stale intro
    let (cert_i, key_i) = intro.cert_and_key();
    let allowed_i = Arc::new(AllowedPeers::from_fingerprints(vec![fp_a]));
    let ep_i = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_i, key_i, allowed_i,
    ).expect("ep_i");

    let conn = ep_i.connect(addr_a, "localhost").unwrap().await.expect("connect to A");
    send_intro_offer(&conn, &stale_offer).await.expect("send stale offer");
    // Allow time for the uni stream data to be delivered before closing
    tokio::time::sleep(Duration::from_millis(100)).await;
    conn.close(0u32.into(), b"sent");

    // Give A time to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check that A recorded the intro as expired
    let db_a = open_connection(&peer_a.db_path).expect("open A db");
    let attempts = list_intro_attempts(&db_a, &peer_a.identity, None)
        .expect("list attempts");
    eprintln!("Stale test: A has {} intro attempts", attempts.len());
    for a in &attempts {
        eprintln!("  status={}, error={:?}", a.status, a.error);
    }
    assert!(!attempts.is_empty(), "A should have recorded the stale intro");
    assert!(
        attempts.iter().any(|a| a.status == "expired"),
        "stale intro should have status='expired', got: {:?}",
        attempts.iter().map(|a| &a.status).collect::<Vec<_>>()
    );

    ep_i.close(0u32.into(), b"done");
}

/// TRUST BOUNDARY TEST: Untrusted target rejected.
/// other_peer_id not in allowed set.
/// Uses static pinning — this test exercises intro target trust validation,
/// not transport trust resolution.
#[tokio::test]
async fn test_untrusted_peer_intro_rejected() {
    let intro = Peer::new("untrust_introducer");
    let peer_a = Peer::new("untrust_a");

    let fp_i = intro.spki_fingerprint();
    let fp_a = peer_a.spki_fingerprint();

    // Static pin: A only trusts I, not the introduced peer (pinning policy under test)
    let (cert_a, key_a) = peer_a.cert_and_key();
    let allowed_a = Arc::new(AllowedPeers::from_fingerprints(vec![fp_i]));
    let ep_a = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_a, key_a, allowed_a,
    ).expect("ep_a");
    let addr_a = ep_a.local_addr().expect("addr_a");

    let a_db = peer_a.db_path.clone();
    let a_id = peer_a.identity.clone();
    let a_ep = ep_a.clone();
    let _a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&a_db, &a_id, a_ep, spawn_intro_listener, topo::testutil::test_ingest_fns()).await;
        });
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Build an IntroOffer for an unknown peer (not in A's SQL trust rows)
    let unknown_peer = [0xCC; 32];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap()
        .as_millis() as u64;
    let offer = build_intro_offer(
        &hex::encode(unknown_peer),
        "10.0.0.50", 5000,
        now_ms,
        30_000,
        4000,
    ).expect("build offer");

    let (cert_i, key_i) = intro.cert_and_key();
    let allowed_i = Arc::new(AllowedPeers::from_fingerprints(vec![fp_a]));
    let ep_i = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_i, key_i, allowed_i,
    ).expect("ep_i");

    let conn = ep_i.connect(addr_a, "localhost").unwrap().await.expect("connect to A");
    send_intro_offer(&conn, &offer).await.expect("send offer");
    // Allow time for the uni stream data to be delivered before closing
    tokio::time::sleep(Duration::from_millis(100)).await;
    conn.close(0u32.into(), b"sent");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let db_a = open_connection(&peer_a.db_path).expect("open A db");
    let attempts = list_intro_attempts(&db_a, &peer_a.identity, None)
        .expect("list attempts");
    eprintln!("Untrusted test: A has {} intro attempts", attempts.len());
    for a in &attempts {
        eprintln!("  status={}, error={:?}", a.status, a.error);
    }
    assert!(!attempts.is_empty(), "A should have recorded the untrusted intro");
    assert!(
        attempts.iter().any(|a| a.status == "rejected"),
        "untrusted intro should have status='rejected', got: {:?}",
        attempts.iter().map(|a| &a.status).collect::<Vec<_>>()
    );

    ep_i.close(0u32.into(), b"done");
}
