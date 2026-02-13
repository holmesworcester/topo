//! Quick smoke test: does TenantDiscovery actually discover on this machine?
#[cfg(feature = "discovery")]
#[test]
fn mdns_smoke_tenant_discovery() {
    use poc_7::discovery::TenantDiscovery;
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    let local_ids: HashSet<String> = ["self-id".to_string()].into_iter().collect();

    let disc = TenantDiscovery::new("test-smoke-peer", 54321, local_ids)
        .expect("failed to create TenantDiscovery");

    let rx = disc.browse().expect("failed to browse");

    // We registered "test-smoke-peer" but it's in our own local_ids filter...
    // So we need a second discovery to advertise a different peer.
    let local_ids2: HashSet<String> = ["remote-id".to_string()].into_iter().collect();
    let disc2 = TenantDiscovery::new("remote-id", 54322, local_ids2)
        .expect("failed to create second TenantDiscovery");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut found = false;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(peer) => {
                eprintln!("Discovered: peer_id={}, addr={}", peer.peer_id, peer.addr);
                if peer.peer_id == "remote-id" {
                    assert_eq!(peer.addr.port(), 54322);
                    found = true;
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }

    drop(disc);
    drop(disc2);

    assert!(found, "TenantDiscovery did not discover remote peer within 15s");
}
