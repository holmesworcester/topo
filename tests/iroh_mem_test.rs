//! Isolate iroh's memory footprint: base cost vs our configuration.
//!
//! Measures VmRSS at each stage to determine how much memory iroh itself
//! consumes vs what our relay/portmapper/mDNS configuration adds.
//!
//! These tests are diagnostic only (no assertions).  They require network
//! access for relay stages and read /proc which is Linux-only.
//! Run explicitly: `cargo test --release --test iroh_mem_test -- --ignored --nocapture`

#[cfg(target_os = "linux")]
fn rss_mib() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            if let Some(kb) = line.split_whitespace().nth(1) {
                return kb.parse::<f64>().unwrap_or(0.0) / 1024.0;
            }
        }
    }
    0.0
}

#[cfg(target_os = "linux")]
fn peak_rss_mib() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmHWM:") {
            if let Some(kb) = line.split_whitespace().nth(1) {
                return kb.parse::<f64>().unwrap_or(0.0) / 1024.0;
            }
        }
    }
    0.0
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "diagnostic; requires network for relay stages"]
fn iroh_memory_isolation() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let rss_before_anything = rss_mib();
        eprintln!("  Before anything:       {:.1} MiB RSS", rss_before_anything);

        // Stage 1: Bare minimum iroh endpoint — no relay, no portmapper, no mDNS
        let secret_key = iroh::SecretKey::from_bytes(&rand::random());
        let ep_minimal = iroh::Endpoint::empty_builder()
            .secret_key(secret_key.clone())
            .alpns(vec![b"test/1".to_vec()])
            .relay_mode(iroh::endpoint::RelayMode::Disabled)
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let rss_after_minimal = rss_mib();
        eprintln!(
            "  After minimal endpoint (no relay/portmapper): {:.1} MiB RSS (+{:.1})",
            rss_after_minimal,
            rss_after_minimal - rss_before_anything
        );

        // Close minimal and measure
        ep_minimal.close().await;
        drop(ep_minimal);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let rss_after_close_minimal = rss_mib();
        eprintln!(
            "  After closing minimal:  {:.1} MiB RSS",
            rss_after_close_minimal
        );

        // Stage 2: Endpoint with default_relay_mode (what we currently use)
        let ep_relay = iroh::Endpoint::empty_builder()
            .secret_key(secret_key.clone())
            .alpns(vec![b"test/1".to_vec()])
            .relay_mode(iroh::endpoint::default_relay_mode())
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        // Give relay connections time to establish
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let rss_after_relay = rss_mib();
        eprintln!(
            "  After relay endpoint:   {:.1} MiB RSS (+{:.1} from relay)",
            rss_after_relay,
            rss_after_relay - rss_after_close_minimal
        );

        ep_relay.close().await;
        drop(ep_relay);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let rss_after_close_relay = rss_mib();
        eprintln!(
            "  After closing relay:    {:.1} MiB RSS",
            rss_after_close_relay
        );

        // Stage 3: Endpoint with relay + mDNS (close to our actual config)
        let ep_full = iroh::Endpoint::empty_builder()
            .secret_key(secret_key.clone())
            .alpns(vec![b"test/1".to_vec()])
            .relay_mode(iroh::endpoint::default_relay_mode())
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let mdns = iroh::address_lookup::MdnsAddressLookup::builder()
            .build(ep_full.id())
            .unwrap();
        ep_full.address_lookup().unwrap().add(mdns.clone());
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let rss_after_full = rss_mib();
        eprintln!(
            "  After relay+mDNS:       {:.1} MiB RSS (+{:.1} from mDNS)",
            rss_after_full,
            rss_after_full - rss_after_close_relay
        );

        ep_full.close().await;
        drop(ep_full);
        drop(mdns);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Summary
        let peak = peak_rss_mib();
        eprintln!();
        eprintln!("  === SUMMARY ===");
        eprintln!("  Baseline process RSS:           {:.1} MiB", rss_before_anything);
        eprintln!("  Minimal iroh endpoint cost:     +{:.1} MiB", rss_after_minimal - rss_before_anything);
        eprintln!("  default_relay_mode() added:     +{:.1} MiB", rss_after_relay - rss_after_close_minimal);
        eprintln!("  mDNS discovery added:           +{:.1} MiB", rss_after_full - rss_after_close_relay);
        eprintln!("  Peak RSS (VmHWM):               {:.1} MiB", peak);
    });
}

/// Measure with multi-threaded runtime (matching daemon)
#[test]
#[cfg(target_os = "linux")]
#[ignore = "diagnostic; requires network for relay stages"]
fn iroh_memory_isolation_multithread() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();

    rt.block_on(async {
        let rss_before = rss_mib();
        eprintln!("  Before (multi-thread rt): {:.1} MiB RSS", rss_before);

        let secret_key = iroh::SecretKey::from_bytes(&rand::random());

        // Minimal endpoint on multi-thread runtime
        let ep = iroh::Endpoint::empty_builder()
            .secret_key(secret_key.clone())
            .alpns(vec![b"test/1".to_vec()])
            .relay_mode(iroh::endpoint::RelayMode::Disabled)
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let rss_minimal_mt = rss_mib();
        eprintln!(
            "  Minimal (multi-thread):   {:.1} MiB RSS (+{:.1})",
            rss_minimal_mt,
            rss_minimal_mt - rss_before
        );

        ep.close().await;
        drop(ep);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // With relay on multi-thread runtime
        let ep = iroh::Endpoint::empty_builder()
            .secret_key(secret_key.clone())
            .alpns(vec![b"test/1".to_vec()])
            .relay_mode(iroh::endpoint::default_relay_mode())
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let rss_relay_mt = rss_mib();
        eprintln!(
            "  With relay (multi-thread): {:.1} MiB RSS (+{:.1} from relay)",
            rss_relay_mt,
            rss_relay_mt - rss_minimal_mt
        );

        let peak = peak_rss_mib();
        eprintln!("  Peak RSS (VmHWM):         {:.1} MiB", peak);

        ep.close().await;
    });
}
