use std::time::Duration;
use std::time::Instant;
use topo::crypto::event_id_to_base64;
use topo::peering::loops::{accept_loop, connect_loop};
use topo::testutil::{
    assert_eventually, noop_intro_spawner, test_ingest_fns, Peer, ScenarioHarness,
};

/// mDNS integration: two peers discover each other via mDNS and sync using
/// the discovered address. Exercises the full flow: advertise -> browse ->
/// discover -> connect -> sync -> verify convergence.
///
/// Uses dynamic DB trust lookup (production-matching `is_peer_allowed`).
/// Trust comes from PeerShared-derived identity chain (no CLI pin import).
#[cfg(feature = "discovery")]
#[tokio::test]
async fn test_mdns_two_peers_discover_and_sync() {
    use std::collections::HashSet;
    use topo::peering::discovery::{local_non_loopback_ipv4, TenantDiscovery};
    use topo::testutil::create_dynamic_endpoint_for_peer_bind;

    let advertise_ip = local_non_loopback_ipv4().expect("no routable IP");
    let alice = Peer::new_with_identity("mdns-alice");
    let bob = Peer::new_in_workspace("mdns-bob", &alice).await;

    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    alice.batch_create_messages(3);
    bob.batch_create_messages(2);

    // Create marker messages for sync convergence
    let alice_marker = alice.create_message("mdns-alice-marker");
    let alice_marker_b64 = event_id_to_base64(&alice_marker);
    let bob_marker = bob.create_message("mdns-bob-marker");
    let bob_marker_b64 = event_id_to_base64(&bob_marker);

    // Dynamic trust endpoints bound to 0.0.0.0 so mDNS-resolved addresses
    // (which may be non-loopback) are reachable.
    let ep_a = create_dynamic_endpoint_for_peer_bind(&alice, "0.0.0.0:0".parse().unwrap());
    let ep_b = create_dynamic_endpoint_for_peer_bind(&bob, "0.0.0.0:0".parse().unwrap());

    let port_a = ep_a.local_addr().unwrap().port();
    let port_b = ep_b.local_addr().unwrap().port();

    // Advertise both peers via mDNS
    let local_a: HashSet<String> = [alice.identity.clone()].into_iter().collect();
    let local_b: HashSet<String> = [bob.identity.clone()].into_iter().collect();

    let disc_a = TenantDiscovery::new(&alice.identity, port_a, local_a, &advertise_ip)
        .expect("mDNS registration A");
    let disc_b = TenantDiscovery::new(&bob.identity, port_b, local_b, &advertise_ip)
        .expect("mDNS registration B");

    // Bob browses for peers — should discover Alice (not self)
    let browse_rx = disc_b.browse().expect("browse B");
    let target_id = alice.identity.clone();
    let discovered = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            match browse_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(peer) if peer.peer_id == target_id => return Some(peer),
                Ok(_) => continue, // ignore discoveries from other tests
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break, // channel closed
            }
        }
        None
    })
    .await
    .expect("browse task panicked");

    let discovered_peer = discovered.expect("Bob should discover Alice via mDNS within 15s");
    assert_eq!(
        discovered_peer.peer_id, alice.identity,
        "discovered peer_id should match Alice"
    );
    assert_eq!(
        discovered_peer.addr.port(),
        port_a,
        "discovered port should match Alice's endpoint"
    );

    // Start sync using the mDNS-discovered address
    let a_db = alice.db_path.clone();
    let a_id = alice.identity.clone();
    let _a_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let _ = accept_loop(&a_db, &a_id, ep_a, noop_intro_spawner, test_ingest_fns()).await;
        });
    });

    let b_db = bob.db_path.clone();
    let b_id = bob.identity.clone();
    let remote = discovered_peer.addr;
    let _b_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let _ = connect_loop(
                &b_db,
                &b_id,
                ep_b,
                remote,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await;
        });
    });

    // Wait for sync convergence using marker events
    assert_eventually(
        || bob.has_event(&alice_marker_b64) && alice.has_event(&bob_marker_b64),
        Duration::from_secs(15),
        "peers should converge after mDNS-discovered sync",
    )
    .await;

    drop(disc_a);
    drop(disc_b);

    harness.finish();
}

/// mDNS multitenancy: verifies self-filtering (co-located tenants don't
/// discover each other), external discovery (remote peer discovers all
/// node tenants), and that sync works via the discovered address.
///
/// Uses dynamic DB trust lookup (production-matching `is_peer_allowed`).
/// Trust comes from PeerShared-derived identity chain (no CLI pin import).
#[cfg(feature = "discovery")]
#[tokio::test]
async fn test_mdns_multitenant_self_filtering_and_sync() {
    use std::collections::HashSet;
    use topo::peering::discovery::{local_non_loopback_ipv4, TenantDiscovery};
    use topo::testutil::create_dynamic_endpoint_for_peer_bind;

    let advertise_ip = local_non_loopback_ipv4().expect("no routable IP");
    // Three peers: t0 and t1 are "co-located" (share local_peer_ids), ext is external
    let t0 = Peer::new_with_identity("mdns-t0");
    let t1 = Peer::new_with_identity("mdns-t1"); // t1 only needs mDNS presence, no sync
    let ext = Peer::new_in_workspace("mdns-ext", &t0).await;

    let harness = ScenarioHarness::new();
    harness.track(&t0);
    harness.track(&ext);

    t0.batch_create_messages(2);
    ext.batch_create_messages(3);

    // Create marker messages for sync convergence
    let t0_marker = t0.create_message("mdns-t0-marker");
    let t0_marker_b64 = event_id_to_base64(&t0_marker);
    let ext_marker = ext.create_message("mdns-ext-marker");
    let ext_marker_b64 = event_id_to_base64(&ext_marker);

    // Dynamic trust endpoints bound to 0.0.0.0 so mDNS-resolved addresses are reachable.
    // t1 only needs mDNS presence — no actual endpoint needed.
    let ep_t0 = create_dynamic_endpoint_for_peer_bind(&t0, "0.0.0.0:0".parse().unwrap());
    let ep_ext = create_dynamic_endpoint_for_peer_bind(&ext, "0.0.0.0:0".parse().unwrap());

    let port_t0 = ep_t0.local_addr().unwrap().port();
    let port_t1 = 19999; // mDNS presence only — no actual endpoint needed
    let port_ext = ep_ext.local_addr().unwrap().port();

    // Node tenants share local_peer_ids (same-node self-filtering)
    let node_local: HashSet<String> = [t0.identity.clone(), t1.identity.clone()]
        .into_iter()
        .collect();
    let ext_local: HashSet<String> = [ext.identity.clone()].into_iter().collect();

    let disc_t0 = TenantDiscovery::new(&t0.identity, port_t0, node_local.clone(), &advertise_ip)
        .expect("mDNS t0");
    let disc_t1 =
        TenantDiscovery::new(&t1.identity, port_t1, node_local, &advertise_ip).expect("mDNS t1");
    let disc_ext =
        TenantDiscovery::new(&ext.identity, port_ext, ext_local, &advertise_ip).expect("mDNS ext");

    // --- Assertion 1: t0 discovers ext but NOT t1 (self-filtered) ---
    let browse_t0 = disc_t0.browse().expect("browse t0");
    let ext_id = ext.identity.clone();
    let t0_discoveries = tokio::task::spawn_blocking(move || {
        let mut found = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut found_ext = false;
        while Instant::now() < deadline {
            match browse_t0.recv_timeout(Duration::from_millis(500)) {
                Ok(peer) => {
                    if peer.peer_id == ext_id {
                        found_ext = true;
                    }
                    found.push(peer);
                    if found_ext {
                        // Wait a bit longer to catch any self-filtering failures
                        std::thread::sleep(Duration::from_secs(2));
                        while let Ok(p) = browse_t0.recv_timeout(Duration::from_millis(100)) {
                            found.push(p);
                        }
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }
        found
    })
    .await
    .expect("t0 browse panicked");

    let t0_found_ids: Vec<&str> = t0_discoveries.iter().map(|p| p.peer_id.as_str()).collect();
    assert!(
        t0_found_ids.contains(&ext.identity.as_str()),
        "t0 should discover external peer via mDNS"
    );
    assert!(
        !t0_found_ids.contains(&t1.identity.as_str()),
        "t0 should NOT discover co-located t1 (self-filtering)"
    );

    // --- Assertion 2: ext discovers both t0 and t1 ---
    let browse_ext = disc_ext.browse().expect("browse ext");
    let t0_id = t0.identity.clone();
    let t1_id2 = t1.identity.clone();
    let ext_discoveries = tokio::task::spawn_blocking(move || {
        let mut found = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match browse_ext.recv_timeout(Duration::from_millis(500)) {
                Ok(peer) => {
                    found.push(peer);
                    let ids: Vec<&str> = found.iter().map(|p| p.peer_id.as_str()).collect();
                    if ids.contains(&t0_id.as_str()) && ids.contains(&t1_id2.as_str()) {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }
        found
    })
    .await
    .expect("ext browse panicked");

    let ext_found_ids: Vec<&str> = ext_discoveries.iter().map(|p| p.peer_id.as_str()).collect();
    assert!(
        ext_found_ids.contains(&t0.identity.as_str()),
        "external should discover t0"
    );
    assert!(
        ext_found_ids.contains(&t1.identity.as_str()),
        "external should discover t1"
    );

    // --- Assertion 3: sync works via mDNS-discovered address ---
    // ext discovered t0 earlier; use t0's address for connect_loop.
    // Since we also discovered ext from t0, verify the ext address too.
    let ext_disc = t0_discoveries
        .iter()
        .find(|p| p.peer_id == ext.identity)
        .unwrap();
    eprintln!("mDNS: t0 discovered ext at {}", ext_disc.addr);

    // ext connects to t0 (not the other way around)
    let t0_disc = ext_discoveries
        .iter()
        .find(|p| p.peer_id == t0.identity)
        .unwrap();
    eprintln!("mDNS: ext discovered t0 at {}", t0_disc.addr);

    // Use 127.0.0.1 with t0's port (endpoints bound to 0.0.0.0)
    let t0_connect_addr =
        std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), t0_disc.addr.port());

    let t0_db = t0.db_path.clone();
    let t0_id = t0.identity.clone();
    let _t0_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let _ = accept_loop(&t0_db, &t0_id, ep_t0, noop_intro_spawner, test_ingest_fns()).await;
        });
    });

    let ext_db = ext.db_path.clone();
    let ext_identity = ext.identity.clone();
    let _ext_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let _ = connect_loop(
                &ext_db,
                &ext_identity,
                ep_ext,
                t0_connect_addr,
                None,
                noop_intro_spawner,
                test_ingest_fns(),
            )
            .await;
        });
    });

    // Wait for sync convergence using marker events
    assert_eventually(
        || ext.has_event(&t0_marker_b64) && t0.has_event(&ext_marker_b64),
        Duration::from_secs(15),
        "t0 and external should converge via mDNS-discovered sync",
    )
    .await;

    drop(disc_t0);
    drop(disc_t1);
    drop(disc_ext);

    harness.finish();
}
