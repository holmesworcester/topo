//! Quick smoke test: does TenantDiscovery actually discover on this machine?

/// Helper: get a routable (non-loopback) IP for mDNS advertisement.
#[cfg(feature = "discovery")]
fn routable_ip() -> String {
    poc_7::discovery::local_non_loopback_ipv4()
        .expect("no routable IP available for mDNS test")
}

#[cfg(feature = "discovery")]
#[test]
fn mdns_smoke_tenant_discovery() {
    use poc_7::discovery::TenantDiscovery;
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    let ip = routable_ip();
    let local_ids: HashSet<String> = ["self-id".to_string()].into_iter().collect();

    let disc = TenantDiscovery::new("test-smoke-peer", 54321, local_ids, &ip)
        .expect("failed to create TenantDiscovery");

    let rx = disc.browse().expect("failed to browse");

    // We registered "test-smoke-peer" but it's in our own local_ids filter...
    // So we need a second discovery to advertise a different peer.
    let local_ids2: HashSet<String> = ["remote-id".to_string()].into_iter().collect();
    let disc2 = TenantDiscovery::new("remote-id", 54322, local_ids2, &ip)
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

/// Verify that two tenants with explicit advertise IPs discover each other.
#[cfg(feature = "discovery")]
#[test]
fn mdns_smoke_explicit_advertise_ip() {
    use poc_7::discovery::TenantDiscovery;
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    let ip = routable_ip();

    let local_a: HashSet<String> = ["exp-peer-a".to_string()].into_iter().collect();
    let local_b: HashSet<String> = ["exp-peer-b".to_string()].into_iter().collect();

    let disc_a = TenantDiscovery::new(
        "exp-peer-a", 55001, local_a, &ip,
    ).expect("disc_a");

    let disc_b = TenantDiscovery::new(
        "exp-peer-b", 55002, local_b, &ip,
    ).expect("disc_b");

    let rx_a = disc_a.browse().expect("browse a");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut found = false;
    while Instant::now() < deadline {
        match rx_a.recv_timeout(Duration::from_millis(500)) {
            Ok(peer) => {
                eprintln!("explicit-ip-test: peer_id={}, addr={}", peer.peer_id, peer.addr);
                if peer.peer_id == "exp-peer-b" {
                    assert_eq!(peer.addr.port(), 55002);
                    found = true;
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }

    drop(disc_a);
    drop(disc_b);

    assert!(found, "mDNS with explicit advertise IP did not discover peer within 15s");
}
