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

use poc_7::crypto::event_id_from_base64;
use poc_7::db::open_connection;
use poc_7::db::intro::{list_intro_attempts, freshest_endpoint};
use poc_7::db::project_queue::ProjectQueue;
use poc_7::db::transport_trust::{allowed_peers_from_db, import_cli_pins_to_sql};
use poc_7::projection::pipeline::project_one;
use poc_7::sync::engine::{accept_loop, connect_loop};
use poc_7::sync::intro::{run_intro, send_intro_offer, build_intro_offer};
use poc_7::testutil::{Peer, assert_eventually};
use poc_7::transport::{
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

/// Start an accept_loop + connect_loop pair between two peers.
/// Seeds SQL trust rows (via import_cli_pins_to_sql) so the intro listener
/// can verify peers from the DB. Returns handles and the listener address.
fn start_peers_with_intro(
    listener: &Peer,
    connector: &Peer,
    listener_trusts: Vec<[u8; 32]>,
    connector_trusts: Vec<[u8; 32]>,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>, std::net::SocketAddr) {
    // Seed SQL trust rows so the intro listener can verify peers from DB
    {
        let db = open_connection(&listener.db_path).expect("open listener db");
        let pins = AllowedPeers::from_fingerprints(listener_trusts.clone());
        import_cli_pins_to_sql(&db, &listener.identity, &pins).expect("import listener pins");
    }
    {
        let db = open_connection(&connector.db_path).expect("open connector db");
        let pins = AllowedPeers::from_fingerprints(connector_trusts.clone());
        import_cli_pins_to_sql(&db, &connector.identity, &pins).expect("import connector pins");
    }

    let (cert_l, key_l) = listener.cert_and_key();
    let (cert_c, key_c) = connector.cert_and_key();

    let allowed_l = Arc::new(AllowedPeers::from_fingerprints(listener_trusts));
    let allowed_c = Arc::new(AllowedPeers::from_fingerprints(connector_trusts));

    let ep_l = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_l, key_l, allowed_l,
    ).expect("create listener endpoint");
    let addr_l = ep_l.local_addr().expect("listener addr");

    let ep_c = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_c, key_c, allowed_c,
    ).expect("create connector endpoint");

    let l_db = listener.db_path.clone();
    let l_id = listener.identity.clone();
    let l_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&l_db, &l_id, ep_l).await;
        });
    });

    let c_db = connector.db_path.clone();
    let c_id = connector.identity.clone();
    let c_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = connect_loop(&c_db, &c_id, ep_c, addr_l).await;
        });
    });

    (l_handle, c_handle, addr_l)
}

/// Functional intro test. Phase 1 uses pinning bootstrap; Phase 2 uses
/// identity-derived trust via TransportKey events.
///
/// All three peers share the same workspace so identity chains validate
/// across peers through normal sync (TransportKey events project correctly).
///
/// Three-peer intro happy path:
/// 1. A <-> I, B <-> I sync (gives I endpoint observations for A and B,
///    and relays identity chains so TransportKey events project at each peer)
/// 2. I sends IntroOffer to A and B
/// 3. A and B dial each other using identity-derived trust and sync messages
#[tokio::test]
async fn test_three_peer_intro_happy_path() {
    // Intro creates the workspace; A and B join it so all share one trust root.
    let intro = Peer::new_with_identity("introducer");
    let peer_a = Peer::new_in_workspace("peer_a", &intro);
    let peer_b = Peer::new_in_workspace("peer_b", &intro);

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

    // --- Phase 1: Relay sync I<->A and I<->B (pinning bootstrap) ---
    // Uses manual fingerprint pinning for the initial connections.
    // After sync, each peer has the others' identity chains validated
    // (shared workspace means remote chains resolve through the common
    // Workspace event), so TransportKey events project into transport_keys.

    let sync_ia = start_peers_with_intro(
        &intro, &peer_a,
        vec![fp_a, fp_b],  // I trusts A and B
        vec![fp_i],        // A trusts I
    );
    // Intro has 8 own events (6 identity + 1 TransportKey + 1 message).
    // A has 8 events (W copied + 5 identity + 1 TransportKey + 1 message).
    // After I<->A sync: each gets the other's 6 shared events = 14 total.
    // (Workspace event is shared, already present at both.)
    assert_eventually(
        || intro.store_count() >= 14 && peer_a.store_count() >= 14,
        Duration::from_secs(10),
        &format!("I<->A sync (I={}, A={})", intro.store_count(), peer_a.store_count()),
    ).await;

    let sync_ib = start_peers_with_intro(
        &intro, &peer_b,
        vec![fp_a, fp_b],  // I trusts A and B
        vec![fp_i],        // B trusts I
    );
    // I now has all 3 peers' shared events. B gets I's + A's (relayed).
    assert_eventually(
        || intro.store_count() >= 20 && peer_b.store_count() >= 14,
        Duration::from_secs(10),
        &format!("I<->B sync (I={}, B={})", intro.store_count(), peer_b.store_count()),
    ).await;

    // Wait for full convergence: all 3 peers should have all shared events.
    // 1 shared Workspace + 7 shared per peer (UIB+UB+DIF+PSF+TK+Msg + IA is local) = 20.
    // Note: each peer has 8 in events table (Workspace + 6 identity + TK + Msg)
    // but only 7 are in neg_items (IA is local). Unique shared events across
    // all 3 peers: 1 Workspace + 3*6 = 19 shared. Total in events = 19 + 1 own IA = 20.
    assert_eventually(
        || peer_a.store_count() >= 20 && peer_b.store_count() >= 20 && intro.store_count() >= 20,
        Duration::from_secs(15),
        &format!("full convergence (I={}, A={}, B={})",
            intro.store_count(), peer_a.store_count(), peer_b.store_count()),
    ).await;

    // --- Verify I has endpoint observations for A and B ---
    {
        let db = open_connection(&intro.db_path).expect("open intro db");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap()
            .as_millis() as i64;
        let ep_a = freshest_endpoint(&db, &intro.identity, &peer_a.identity, now_ms)
            .expect("query ep_a");
        let ep_b = freshest_endpoint(&db, &intro.identity, &peer_b.identity, now_ms)
            .expect("query ep_b");
        assert!(ep_a.is_some(), "I should have endpoint observation for A");
        assert!(ep_b.is_some(), "I should have endpoint observation for B");
        let (ip_a, port_a, _) = ep_a.unwrap();
        let (ip_b, port_b, _) = ep_b.unwrap();
        eprintln!("I observed A at {}:{}, B at {}:{}", ip_a, port_a, ip_b, port_b);
    }

    // Wait for TransportKey projection to complete at A and B.
    // The batch_writer drains the project_queue after each event batch commit,
    // but items with blocked deps may need a retry pass. We poll + force-drain
    // to pick up any stragglers the batch_writer left behind.
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

    // Drop the I<->A and I<->B sync sessions
    drop(sync_ia);
    drop(sync_ib);

    // Give threads time to clean up
    tokio::time::sleep(Duration::from_millis(200)).await;

    // --- Phase 2: I sends IntroOffer to A and B ---
    // After Phase 1, remote identity chains validated through the shared workspace,
    // so TransportKey events projected at each peer. A and B now use
    // identity-derived trust (transport_keys table) instead of manual fingerprints.

    let (cert_a, key_a) = peer_a.cert_and_key();
    let (cert_b, key_b) = peer_b.cert_and_key();

    let db_a_conn = open_connection(&peer_a.db_path).expect("open A db");
    let allowed_a_peers = allowed_peers_from_db(&db_a_conn, &peer_a.identity)
        .expect("allowed peers for A");
    drop(db_a_conn);
    let db_b_conn = open_connection(&peer_b.db_path).expect("open B db");
    let allowed_b_peers = allowed_peers_from_db(&db_b_conn, &peer_b.identity)
        .expect("allowed peers for B");
    drop(db_b_conn);

    let allowed_a = Arc::new(allowed_a_peers);
    let allowed_b = Arc::new(allowed_b_peers);

    let ep_a = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_a, key_a, allowed_a.clone(),
    ).expect("ep_a");
    let ep_b = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_b, key_b, allowed_b.clone(),
    ).expect("ep_b");

    let addr_a = ep_a.local_addr().expect("addr_a");
    let addr_b = ep_b.local_addr().expect("addr_b");

    eprintln!("A listening on {}, B listening on {}", addr_a, addr_b);

    // Start accept loops for A and B with intro listeners (identity-derived trust via SQL)
    let a_db = peer_a.db_path.clone();
    let a_id = peer_a.identity.clone();
    let a_ep = ep_a.clone();
    let a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&a_db, &a_id, a_ep).await;
        });
    });

    let b_db = peer_b.db_path.clone();
    let b_id = peer_b.identity.clone();
    let b_ep = ep_b.clone();
    let b_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&b_db, &b_id, b_ep).await;
        });
    });

    // Give accept loops time to start
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Now I acts as introducer: manually record fresh observations for A and B
    // using the actual addresses A and B are listening on.
    {
        let db = open_connection(&intro.db_path).expect("open intro db");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap()
            .as_millis() as i64;
        poc_7::db::health::record_endpoint_observation(
            &db, &intro.identity, &peer_a.identity,
            &addr_a.ip().to_string(), addr_a.port(), now_ms, 60_000,
        ).expect("record ep_a");
        poc_7::db::health::record_endpoint_observation(
            &db, &intro.identity, &peer_b.identity,
            &addr_b.ip().to_string(), addr_b.port(), now_ms, 60_000,
        ).expect("record ep_b");
    }

    // I creates an endpoint to send intros from (manual pinning — I is the introducer)
    let (cert_i, key_i) = intro.cert_and_key();
    let allowed_i = Arc::new(AllowedPeers::from_fingerprints(vec![fp_a, fp_b]));
    let ep_i = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_i, key_i, allowed_i,
    ).expect("ep_i");

    // Send intros
    let result = run_intro(
        &ep_i, &intro.db_path, &intro.identity,
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
    ep_i.close(0u32.into(), b"done");
    drop(a_handle);
    drop(b_handle);
}

/// TRUST BOUNDARY TEST: Stale intro rejected.
/// Expired expires_at_ms should result in status='expired'.
#[tokio::test]
async fn test_stale_intro_rejected() {
    let intro = Peer::new("stale_introducer");
    let peer_a = Peer::new("stale_a");

    let fp_i = intro.spki_fingerprint();
    let fp_a = peer_a.spki_fingerprint();

    // Create an endpoint for A that trusts I
    let (cert_a, key_a) = peer_a.cert_and_key();
    let allowed_a = Arc::new(AllowedPeers::from_fingerprints(vec![fp_i]));
    let ep_a = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_a, key_a, allowed_a,
    ).expect("ep_a");
    let addr_a = ep_a.local_addr().expect("addr_a");

    // Seed SQL trust so the intro listener can verify I via DB
    {
        let db = open_connection(&peer_a.db_path).expect("open A db");
        let pins = AllowedPeers::from_fingerprints(vec![fp_i]);
        import_cli_pins_to_sql(&db, &peer_a.identity, &pins).expect("import A pins");
    }

    // Start A's accept loop with intro listener
    let a_db = peer_a.db_path.clone();
    let a_id = peer_a.identity.clone();
    let a_ep = ep_a.clone();
    let _a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&a_db, &a_id, a_ep).await;
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
#[tokio::test]
async fn test_untrusted_peer_intro_rejected() {
    let intro = Peer::new("untrust_introducer");
    let peer_a = Peer::new("untrust_a");

    let fp_i = intro.spki_fingerprint();
    let fp_a = peer_a.spki_fingerprint();

    let (cert_a, key_a) = peer_a.cert_and_key();
    // A only trusts I, not the introduced peer
    let allowed_a = Arc::new(AllowedPeers::from_fingerprints(vec![fp_i]));
    let ep_a = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(), cert_a, key_a, allowed_a,
    ).expect("ep_a");
    let addr_a = ep_a.local_addr().expect("addr_a");

    // Seed SQL trust: A only trusts I (fp_i), NOT the unknown peer
    {
        let db = open_connection(&peer_a.db_path).expect("open A db");
        let pins = AllowedPeers::from_fingerprints(vec![fp_i]);
        import_cli_pins_to_sql(&db, &peer_a.identity, &pins).expect("import A pins");
    }

    let a_db = peer_a.db_path.clone();
    let a_id = peer_a.identity.clone();
    let a_ep = ep_a.clone();
    let _a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let _ = accept_loop(&a_db, &a_id, a_ep).await;
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
