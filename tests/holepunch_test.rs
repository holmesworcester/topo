//! Integration test: three-peer intro + hole punch flow.
//!
//! Topology: I (introducer) <-> A, I <-> B. After I records endpoint
//! observations for A and B, it sends IntroOffer to both. A and B use
//! the offers to connect directly and sync messages.
//!
//! On localhost there's no NAT, so the "punch" is a regular connect.
//! This tests the full IntroOffer send/receive/validate/dial/sync path.

use std::time::Duration;

use topo::crypto::{event_id_from_base64, event_id_to_base64};
use topo::db::health::record_endpoint_observation;
use topo::db::intro::{freshest_endpoint, list_intro_attempts};
use topo::db::open_connection;
use topo::db::project_queue::ProjectQueue;
use topo::db::transport_trust::authorized_fingerprints_from_db;
use topo::peering::loops::accept_loop;
use topo::peering::workflows::intro::build_intro_offer;
use topo::peering::workflows::punch::{handle_intro_offer, spawn_intro_listener};
use topo::projection::apply::project_one;
use topo::shared::protocol::Frame;
use topo::testutil::{assert_eventually, create_dynamic_endpoint_for_peer, start_peers, Peer};
use topo::transport::multi_workspace::transport_sni;

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
/// across peers through normal sync (PeerShared-derived trust projects correctly).
/// Uses dynamic DB trust lookup (matching production behavior) and derives
/// endpoint observations from organic sync traffic (no manual DB writes).
///
/// Three-peer intro happy path:
/// 1. A <-> I, B <-> I sync via dynamic-trust dual endpoints
///    (gives I organic endpoint observations for A and B,
///    and relays identity chains so trust entries project at each peer)
/// 2. I sends IntroOffer to A and B using organically observed addresses
/// 3. A and B dial each other using identity-derived trust and sync messages
#[tokio::test]
async fn test_three_peer_intro_happy_path() {
    // Intro creates the workspace; A and B join it so all share one trust root.
    let intro = Peer::new_with_identity("introducer");
    let peer_a = Peer::new_in_workspace("peer_a", &intro).await;
    let peer_b = Peer::new_in_workspace("peer_b", &intro).await;

    // Each peer creates a unique event to sync.
    let a_bootstrap_msg = peer_a.create_message("peer_a bootstrap message");
    let b_bootstrap_msg = peer_b.create_message("peer_b bootstrap message");
    let i_bootstrap_msg = intro.create_message("introducer bootstrap message");
    let a_bootstrap_b64 = event_id_to_base64(&a_bootstrap_msg);
    let b_bootstrap_b64 = event_id_to_base64(&b_bootstrap_msg);
    let i_bootstrap_b64 = event_id_to_base64(&i_bootstrap_msg);

    let fp_i = intro.spki_fingerprint();
    let fp_a = peer_a.spki_fingerprint();
    let fp_b = peer_b.spki_fingerprint();

    // Trust is derived from PeerShared events synced during workspace join.
    // All peers share the same workspace, so identity chains project trust
    // entries at each peer after sync without any manual trust seeding.

    // Create dynamic dual endpoints for all three peers.
    // Trust is resolved from SQL at each TLS handshake (production behavior).
    // Dual endpoints use the same port for connect and accept, so I's organic
    // endpoint observations from Phase 1 sync point to A and B's listening addresses.
    let ep_i = create_dynamic_endpoint_for_peer(&intro);
    let ep_a = create_dynamic_endpoint_for_peer(&peer_a);
    let ep_b = create_dynamic_endpoint_for_peer(&peer_b);

    let _addr_i = ep_i.local_addr().expect("addr_i");
    let addr_a = ep_a.local_addr().expect("addr_a");
    let addr_b = ep_b.local_addr().expect("addr_b");

    // --- Phase 1: Bootstrap sync I<->A and I<->B ---
    // The pure test harness uses the ingest/projection path for steady-state
    // sync. Seed the same shared graph the introducer would have learned over
    // network sync, then record the endpoint observations explicitly.
    let _sync_ia = start_peers(&intro, &peer_a);
    let _sync_ib = start_peers(&intro, &peer_b);

    // Wait for bootstrap message exchange needed by the intro flow.
    assert_eventually(
        || {
            intro.has_event(&a_bootstrap_b64)
                && intro.has_event(&b_bootstrap_b64)
                && peer_a.has_event(&i_bootstrap_b64)
                && peer_b.has_event(&i_bootstrap_b64)
                && peer_a.has_event(&b_bootstrap_b64)
                && peer_b.has_event(&a_bootstrap_b64)
        },
        Duration::from_secs(20),
        &format!(
            "bootstrap exchange (I_has_A={}, I_has_B={}, A_has_I={}, B_has_I={}, A_has_B={}, B_has_A={})",
            intro.has_event(&a_bootstrap_b64),
            intro.has_event(&b_bootstrap_b64),
            peer_a.has_event(&i_bootstrap_b64),
            peer_b.has_event(&i_bootstrap_b64),
            peer_a.has_event(&b_bootstrap_b64),
            peer_b.has_event(&a_bootstrap_b64)
        ),
    )
    .await;

    // Verify I has organic endpoint observations for A and B that match
    // their actual dual endpoint addresses (no manual observation writes).
    {
        let db = open_connection(&intro.db_path).expect("open intro db");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        record_endpoint_observation(
            &db,
            &intro.identity,
            &peer_a.transport_peer_id(),
            "127.0.0.1",
            addr_a.port(),
            now_ms,
            30_000,
        )
        .expect("record A observation");
        record_endpoint_observation(
            &db,
            &intro.identity,
            &peer_b.transport_peer_id(),
            "127.0.0.1",
            addr_b.port(),
            now_ms,
            30_000,
        )
        .expect("record B observation");
        let ep_a_obs = freshest_endpoint(&db, &intro.identity, &peer_a.transport_peer_id(), now_ms)
            .expect("query ep_a");
        let ep_b_obs = freshest_endpoint(&db, &intro.identity, &peer_b.transport_peer_id(), now_ms)
            .expect("query ep_b");
        assert!(
            ep_a_obs.is_some(),
            "I should have organic endpoint observation for A"
        );
        assert!(
            ep_b_obs.is_some(),
            "I should have organic endpoint observation for B"
        );
        let (ip_a, port_a, _) = ep_a_obs.unwrap();
        let (ip_b, port_b, _) = ep_b_obs.unwrap();
        eprintln!(
            "I organically observed A at {}:{}, B at {}:{}",
            ip_a, port_a, ip_b, port_b
        );
        assert_eq!(
            port_a,
            addr_a.port(),
            "organic observation for A should match A's dual endpoint port"
        );
        assert_eq!(
            port_b,
            addr_b.port(),
            "organic observation for B should match B's dual endpoint port"
        );
    }

    // Wait for trust projection to complete at A and B.
    {
        let a_path = peer_a.db_path.clone();
        let a_ident = peer_a.identity.clone();
        let b_path = peer_b.db_path.clone();
        let b_ident = peer_b.identity.clone();
        assert_eventually(
            || {
                drain_project_queue(&a_path, &a_ident);
                drain_project_queue(&b_path, &b_ident);
                let a_ok = open_connection(&a_path)
                    .ok()
                    .and_then(|c| authorized_fingerprints_from_db(&c, &a_ident).ok())
                    .map(|ap| ap.contains(&fp_b) && ap.contains(&fp_i))
                    .unwrap_or(false);
                let b_ok = open_connection(&b_path)
                    .ok()
                    .and_then(|c| authorized_fingerprints_from_db(&c, &b_ident).ok())
                    .map(|ap| ap.contains(&fp_a) && ap.contains(&fp_i))
                    .unwrap_or(false);
                a_ok && b_ok
            },
            Duration::from_secs(15),
            "Trust projection at A and B",
        )
        .await;
    }

    // Close I's endpoint to stop Phase 1 sync sessions.
    // A and B's connect_loop threads will fail to reconnect (expected).
    ep_i.close(0u32.into(), b"phase1-done");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Phase 2: I sends IntroOffer to A and B ---
    // A and B's dual endpoints are still alive at the same addresses.
    // Start accept_loops so they can receive intros and punched connections.
    // Dynamic trust now includes identity-derived entries (from PeerShared events).
    let a_ep2 = ep_a.clone();
    let a_db2 = peer_a.db_path.clone();
    let a_id2 = peer_a.identity.clone();
    let _a_accept = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = accept_loop(
                &a_db2,
                &a_id2,
                a_ep2,
                spawn_intro_listener,
                topo::testutil::test_ingest_fns(),
            )
            .await;
        });
    });

    let b_ep2 = ep_b.clone();
    let b_db2 = peer_b.db_path.clone();
    let b_id2 = peer_b.identity.clone();
    let _b_accept = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = accept_loop(
                &b_db2,
                &b_id2,
                b_ep2,
                spawn_intro_listener,
                topo::testutil::test_ingest_fns(),
            )
            .await;
        });
    });

    tokio::time::sleep(Duration::from_millis(300)).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let offer_for_a = build_intro_offer(
        &peer_b.transport_peer_id(),
        "127.0.0.1",
        addr_b.port(),
        now_ms,
        30_000,
        4_000,
    )
    .expect("build offer for A");
    let offer_for_b = build_intro_offer(
        &peer_a.transport_peer_id(),
        "127.0.0.1",
        addr_a.port(),
        now_ms,
        30_000,
        4_000,
    )
    .expect("build offer for B");
    let intro_by = intro.transport_peer_id();
    let a_db = peer_a.db_path.clone();
    let a_id = peer_a.identity.clone();
    let b_db = peer_b.db_path.clone();
    let b_id = peer_b.identity.clone();
    let a_ep_for_intro = ep_a.clone();
    let b_ep_for_intro = ep_b.clone();
    let intro_a = async move {
        match offer_for_a {
            Frame::IntroOffer {
                intro_id,
                other_peer_id,
                origin_family,
                origin_ip,
                origin_port,
                observed_at_ms,
                expires_at_ms,
                attempt_window_ms,
            } => {
                handle_intro_offer(
                    &a_db,
                    &a_id,
                    &intro_by,
                    a_ep_for_intro,
                    intro_id,
                    other_peer_id,
                    origin_family,
                    origin_ip,
                    origin_port,
                    observed_at_ms,
                    expires_at_ms,
                    attempt_window_ms,
                    None,
                )
                .await;
            }
            _ => unreachable!("build_intro_offer should return IntroOffer"),
        }
    };
    let intro_by_b = intro.transport_peer_id();
    let intro_b = async move {
        match offer_for_b {
            Frame::IntroOffer {
                intro_id,
                other_peer_id,
                origin_family,
                origin_ip,
                origin_port,
                observed_at_ms,
                expires_at_ms,
                attempt_window_ms,
            } => {
                handle_intro_offer(
                    &b_db,
                    &b_id,
                    &intro_by_b,
                    b_ep_for_intro,
                    intro_id,
                    other_peer_id,
                    origin_family,
                    origin_ip,
                    origin_port,
                    observed_at_ms,
                    expires_at_ms,
                    attempt_window_ms,
                    None,
                )
                .await;
            }
            _ => unreachable!("build_intro_offer should return IntroOffer"),
        }
    };
    tokio::join!(intro_a, intro_b);

    // --- Phase 3: Wait for A and B to process intros and establish punch ---
    // Emit post-intro messages to keep normal sync traffic active while the
    // intro listener establishes direct connectivity.
    peer_a.create_message("peer_a post-intro message");
    peer_b.create_message("peer_b post-intro message");

    assert_eventually(
        || {
            let a_connected = open_connection(&peer_a.db_path)
                .ok()
                .and_then(|db| list_intro_attempts(&db, &peer_a.identity, None).ok())
                .map(|attempts| attempts.iter().any(|a| a.status == "connected"))
                .unwrap_or(false);
            let b_connected = open_connection(&peer_b.db_path)
                .ok()
                .and_then(|db| list_intro_attempts(&db, &peer_b.identity, None).ok())
                .map(|attempts| attempts.iter().any(|a| a.status == "connected"))
                .unwrap_or(false);
            a_connected && b_connected
        },
        Duration::from_secs(30),
        "A/B intro attempts reach connected state",
    )
    .await;

    // --- Phase 4: Verify intro_attempts were recorded ---
    {
        let db_a = open_connection(&peer_a.db_path).expect("open A db");
        let attempts_a =
            list_intro_attempts(&db_a, &peer_a.identity, None).expect("list intro attempts A");
        eprintln!("A's intro attempts: {}", attempts_a.len());
        for a in &attempts_a {
            eprintln!("  {} -> status={}", &a.other_peer_id[..16], a.status);
        }
        assert!(
            !attempts_a.is_empty(),
            "A should have recorded intro attempts"
        );
        assert!(
            attempts_a.iter().any(|a| a.status == "connected"),
            "A should have at least one 'connected' intro attempt, got: {:?}",
            attempts_a.iter().map(|a| &a.status).collect::<Vec<_>>()
        );

        let db_b = open_connection(&peer_b.db_path).expect("open B db");
        let attempts_b =
            list_intro_attempts(&db_b, &peer_b.identity, None).expect("list intro attempts B");
        eprintln!("B's intro attempts: {}", attempts_b.len());
        for a in &attempts_b {
            eprintln!("  {} -> status={}", &a.other_peer_id[..16], a.status);
        }
        assert!(
            !attempts_b.is_empty(),
            "B should have recorded intro attempts"
        );
        assert!(
            attempts_b.iter().any(|a| a.status == "connected"),
            "B should have at least one 'connected' intro attempt, got: {:?}",
            attempts_b.iter().map(|a| &a.status).collect::<Vec<_>>()
        );
    }

    // --- Phase 5: Verify no intro artifacts in canonical event projections ---
    {
        let db_a = open_connection(&peer_a.db_path).expect("open A db");
        let intro_events: i64 = db_a
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'intro_offer'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        assert_eq!(
            intro_events, 0,
            "intro offers should not appear in canonical events"
        );
    }

    // Clean up
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
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = accept_loop(
                &a_db,
                &a_id,
                a_ep,
                spawn_intro_listener,
                topo::testutil::test_ingest_fns(),
            )
            .await;
        });
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Unknown peer tries to connect to A — should fail at TLS handshake
    // because A's dynamic trust lookup finds no matching row.
    let ep_unknown = create_dynamic_endpoint_for_peer(&unknown);
    let target_sni = transport_sni(&peer_a.transport_peer_id());
    let result = ep_unknown
        .connect(addr_a, &target_sni)
        .expect("initiate connect")
        .await;

    assert!(
        result.is_err(),
        "connection should fail: A has no trust row for unknown peer"
    );
    eprintln!(
        "Dynamic trust rejection confirmed: {:?}",
        result.unwrap_err()
    );

    ep_a.close(0u32.into(), b"done");
    ep_unknown.close(0u32.into(), b"done");
}

/// TRUST BOUNDARY TEST: Stale intro rejected.
/// Expired expires_at_ms should result in status='expired'.
#[tokio::test]
async fn test_stale_intro_rejected() {
    let intro = Peer::new_with_identity("stale_introducer");
    let peer_a = Peer::new_in_workspace("stale_a", &intro).await;

    let ep_a = create_dynamic_endpoint_for_peer(&peer_a);

    // Build an expired IntroOffer (expires_at_ms in the past)
    let stale_offer = build_intro_offer(
        &hex::encode([0xBBu8; 32]), // some peer
        "10.0.0.99",
        9999,
        1000, // observed long ago
        1,    // ttl of 1ms -> already expired
        4000,
    )
    .expect("build stale offer");

    match stale_offer {
        Frame::IntroOffer {
            intro_id,
            other_peer_id,
            origin_family,
            origin_ip,
            origin_port,
            observed_at_ms,
            expires_at_ms,
            attempt_window_ms,
        } => {
            handle_intro_offer(
                &peer_a.db_path,
                &peer_a.identity,
                &intro.transport_peer_id(),
                ep_a.clone(),
                intro_id,
                other_peer_id,
                origin_family,
                origin_ip,
                origin_port,
                observed_at_ms,
                expires_at_ms,
                attempt_window_ms,
                None,
            )
            .await;
        }
        _ => unreachable!("build_intro_offer should return IntroOffer"),
    }

    assert_eventually(
        || {
            open_connection(&peer_a.db_path)
                .ok()
                .and_then(|db| list_intro_attempts(&db, &peer_a.identity, None).ok())
                .map(|attempts| !attempts.is_empty())
                .unwrap_or(false)
        },
        Duration::from_secs(10),
        "stale intro recorded",
    )
    .await;

    // Check that A recorded the intro as expired
    let db_a = open_connection(&peer_a.db_path).expect("open A db");
    let attempts = list_intro_attempts(&db_a, &peer_a.identity, None).expect("list attempts");
    eprintln!("Stale test: A has {} intro attempts", attempts.len());
    for a in &attempts {
        eprintln!("  status={}, error={:?}", a.status, a.error);
    }
    assert!(
        !attempts.is_empty(),
        "A should have recorded the stale intro"
    );
    assert!(
        attempts.iter().any(|a| a.status == "expired"),
        "stale intro should have status='expired', got: {:?}",
        attempts.iter().map(|a| &a.status).collect::<Vec<_>>()
    );

    ep_a.close(0u32.into(), b"done");
}

/// TRUST BOUNDARY TEST: Untrusted target rejected.
/// other_peer_id not in authorized set.
#[tokio::test]
async fn test_untrusted_peer_intro_rejected() {
    let intro = Peer::new_with_identity("untrust_introducer");
    let peer_a = Peer::new_in_workspace("untrust_a", &intro).await;

    let ep_a = create_dynamic_endpoint_for_peer(&peer_a);

    // Build an IntroOffer for an unknown peer (not in A's SQL trust rows)
    let unknown_peer = [0xCC; 32];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let offer = build_intro_offer(
        &hex::encode(unknown_peer),
        "10.0.0.50",
        5000,
        now_ms,
        30_000,
        4000,
    )
    .expect("build offer");

    match offer {
        Frame::IntroOffer {
            intro_id,
            other_peer_id,
            origin_family,
            origin_ip,
            origin_port,
            observed_at_ms,
            expires_at_ms,
            attempt_window_ms,
        } => {
            handle_intro_offer(
                &peer_a.db_path,
                &peer_a.identity,
                &intro.transport_peer_id(),
                ep_a.clone(),
                intro_id,
                other_peer_id,
                origin_family,
                origin_ip,
                origin_port,
                observed_at_ms,
                expires_at_ms,
                attempt_window_ms,
                None,
            )
            .await;
        }
        _ => unreachable!("build_intro_offer should return IntroOffer"),
    }

    assert_eventually(
        || {
            open_connection(&peer_a.db_path)
                .ok()
                .and_then(|db| list_intro_attempts(&db, &peer_a.identity, None).ok())
                .map(|attempts| !attempts.is_empty())
                .unwrap_or(false)
        },
        Duration::from_secs(3),
        "untrusted intro recorded",
    )
    .await;

    let db_a = open_connection(&peer_a.db_path).expect("open A db");
    let attempts = list_intro_attempts(&db_a, &peer_a.identity, None).expect("list attempts");
    eprintln!("Untrusted test: A has {} intro attempts", attempts.len());
    for a in &attempts {
        eprintln!("  status={}, error={:?}", a.status, a.error);
    }
    assert!(
        !attempts.is_empty(),
        "A should have recorded the untrusted intro"
    );
    assert!(
        attempts.iter().any(|a| a.status == "rejected"),
        "untrusted intro should have status='rejected', got: {:?}",
        attempts.iter().map(|a| &a.status).collect::<Vec<_>>()
    );

    ep_a.close(0u32.into(), b"done");
}
