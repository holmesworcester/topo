//! Linux `tc`-based validation of the userspace UDP traffic shaper.
//!
//! These tests run the same QUIC transport exercises as
//! `perf_network_transport_test.rs`, but use kernel `tc` (htb + netem) on the
//! loopback interface instead of the userspace `UdpTrafficShaper`.  The goal
//! is to confirm that both shaping approaches produce comparable results.
//!
//! **Requirements:**
//! - Linux with `tc` in PATH and CAP_NET_ADMIN (typically root)
//! - `PERF_LINUX_TC=1` environment variable
//!
//! All tests are `#[ignore]` so they never run in a default `cargo test`.
//!
//! ```bash
//! sudo PERF_LINUX_TC=1 cargo +stable test --release \
//!   --test tc_network_validation_test -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` is mandatory because each test installs and removes a
//! root qdisc on `lo`.

mod perf_network_shaper;
mod tc_network_shaper;

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use perf_network_shaper::NetworkProfile;
use tc_network_shaper::{tc_shaping_available, TcLoopbackShaper};
use topo::protocol::{encode_frame, parse_frame, Frame};
use topo::transport::multi_workspace::transport_sni;
use topo::transport::{
    accept_session_provider, create_dual_endpoint, dial_session_provider, extract_spki_fingerprint,
    generate_self_signed_cert, SessionProvider,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

struct TcConnectedProviders {
    _server_ep: topo::transport::TransportEndpoint,
    server_provider: SessionProvider,
    _client_ep: topo::transport::TransportEndpoint,
    client_provider: SessionProvider,
    _tc_shaper: TcLoopbackShaper,
}

/// Connect two QUIC endpoints on loopback with `tc` shaping applied.
///
/// Unlike the UDP-shaper variant, both endpoints connect directly to each
/// other — shaping is done by the kernel qdisc, not by a proxy.
async fn connect_with_tc(profile: NetworkProfile) -> TestResult<TcConnectedProviders> {
    let (server_cert, server_key) = generate_self_signed_cert()?;
    let server_fp = extract_spki_fingerprint(server_cert.as_ref())?;
    let (client_cert, client_key) = generate_self_signed_cert()?;
    let client_fp = extract_spki_fingerprint(client_cert.as_ref())?;
    let server_peer_id = hex::encode(server_fp);

    let server_allowed: Arc<topo::transport::DynamicAllowFn> =
        Arc::new(move |candidate| Ok(candidate == &client_fp));
    let client_allowed: Arc<topo::transport::DynamicAllowFn> =
        Arc::new(move |candidate| Ok(candidate == &server_fp));

    let server_ep = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server_cert,
        server_key,
        server_allowed,
    )?;
    let client_ep = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        client_cert,
        client_key,
        client_allowed,
    )?;

    let server_addr = server_ep.local_addr()?;
    let client_addr = client_ep.local_addr()?;

    // Install tc shaping for these two ports.
    let tc_shaper = TcLoopbackShaper::new(
        server_addr,
        client_addr,
        profile.bandwidth_mbps_per_direction,
        profile.rtt_ms,
        profile.jitter_ms,
        profile.loss_percent,
    )
    .map_err(|e| format!("tc setup failed: {e}"))?;

    let sni = transport_sni(&server_peer_id);
    let (server_provider_result, client_provider_result) = tokio::join!(
        accept_session_provider(&server_ep),
        dial_session_provider(&client_ep, server_addr, &sni, None)
    );
    let server_provider = server_provider_result?
        .ok_or_else(|| "server endpoint closed before accepting".to_string())?;
    let client_provider = client_provider_result?;

    Ok(TcConnectedProviders {
        _server_ep: server_ep,
        server_provider,
        _client_ep: client_ep,
        client_provider,
        _tc_shaper: tc_shaper,
    })
}

async fn exercise_roundtrip(
    providers: &TcConnectedProviders,
    rounds: usize,
    data_payload_len: usize,
) -> TestResult {
    for round in 0..rounds {
        let (client_session_result, server_session_result) = tokio::join!(
            providers.client_provider.next_session(),
            providers.server_provider.next_session()
        );
        let mut client_parts = client_session_result?.io.split();
        let mut server_parts = server_session_result?.io.split();

        // NegOpen: client → server
        let neg_open = encode_frame(&Frame::NegOpen {
            msg: vec![round as u8, 0xAA, 0x55],
        });
        client_parts.control.send(&neg_open).await?;
        client_parts.control.flush().await?;
        let received = server_parts.control.recv().await?;
        assert_eq!(
            parse_frame(&received)?.0,
            Frame::NegOpen {
                msg: vec![round as u8, 0xAA, 0x55]
            }
        );

        // NegMsg: server → client
        let neg_msg = encode_frame(&Frame::NegMsg {
            msg: vec![round as u8],
        });
        server_parts.control.send(&neg_msg).await?;
        server_parts.control.flush().await?;
        let received = client_parts.control.recv().await?;
        assert_eq!(
            parse_frame(&received)?.0,
            Frame::NegMsg {
                msg: vec![round as u8]
            }
        );

        // Event: client → server (bulk data)
        let payload = vec![round as u8; data_payload_len];
        let event = encode_frame(&Frame::Event {
            blob: payload.clone(),
        });
        client_parts.data_send.send(&event).await?;
        client_parts.data_send.flush().await?;
        let received = server_parts.data_recv.recv().await?;
        assert_eq!(parse_frame(&received)?.0, Frame::Event { blob: payload });
    }
    Ok(())
}

fn skip_unless_tc() -> bool {
    if !tc_shaping_available() {
        eprintln!("SKIP: tc shaping not available (set PERF_LINUX_TC=1 and run as root)");
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Validation tests
// ---------------------------------------------------------------------------

/// Direct QUIC with tc zero-impairment should be as fast as raw loopback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tc_zero_impairment_matches_direct() -> TestResult {
    if skip_unless_tc() {
        return Ok(());
    }
    let providers = tokio::time::timeout(
        Duration::from_secs(10),
        connect_with_tc(NetworkProfile {
            slug: "tc-zero",
            title: "tc-zero",
            note: "tc-zero",
            bandwidth_mbps_per_direction: 10_000.0,
            rtt_ms: 0,
            jitter_ms: 0,
            loss_percent: 0.0,
        }),
    )
    .await??;
    tokio::time::timeout(
        Duration::from_secs(10),
        exercise_roundtrip(&providers, 5, 32 * 1024),
    )
    .await??;
    eprintln!("[tc-validate] zero impairment: OK");
    Ok(())
}

/// tc netem with 200ms RTT should measurably delay round-trips — same
/// assertion as the userspace shaper's `high_latency_proxy_measurably_delays_roundtrip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tc_high_latency_delays_roundtrip() -> TestResult {
    if skip_unless_tc() {
        return Ok(());
    }
    let providers = tokio::time::timeout(
        Duration::from_secs(10),
        connect_with_tc(NetworkProfile {
            slug: "tc-latency",
            title: "tc-latency",
            note: "tc-latency",
            bandwidth_mbps_per_direction: 10_000.0,
            rtt_ms: 200,
            jitter_ms: 0,
            loss_percent: 0.0,
        }),
    )
    .await??;
    let start = std::time::Instant::now();
    tokio::time::timeout(
        Duration::from_secs(10),
        exercise_roundtrip(&providers, 1, 32),
    )
    .await??;
    let elapsed = start.elapsed();
    eprintln!(
        "[tc-validate] high latency: elapsed={}ms (expect >=250ms)",
        elapsed.as_millis()
    );
    assert!(
        elapsed >= Duration::from_millis(250),
        "3 one-way messages at 200ms RTT should take >=250ms via tc netem, took {}ms",
        elapsed.as_millis()
    );
    Ok(())
}

/// tc htb with 1 Mbps bandwidth cap should measurably throttle bulk transfer —
/// same assertion as the userspace shaper's
/// `low_bandwidth_proxy_measurably_throttles_transfer`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tc_low_bandwidth_throttles_transfer() -> TestResult {
    if skip_unless_tc() {
        return Ok(());
    }
    let providers = tokio::time::timeout(
        Duration::from_secs(10),
        connect_with_tc(NetworkProfile {
            slug: "tc-narrow",
            title: "tc-narrow",
            note: "tc-narrow",
            bandwidth_mbps_per_direction: 1.0,
            rtt_ms: 0,
            jitter_ms: 0,
            loss_percent: 0.0,
        }),
    )
    .await??;
    let start = std::time::Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        exercise_roundtrip(&providers, 1, 128 * 1024),
    )
    .await??;
    let elapsed = start.elapsed();
    eprintln!(
        "[tc-validate] low bandwidth: elapsed={}ms (expect >=800ms)",
        elapsed.as_millis()
    );
    assert!(
        elapsed >= Duration::from_millis(800),
        "128 KiB at 1 Mbps should take >=800ms via tc htb, took {}ms",
        elapsed.as_millis()
    );
    Ok(())
}

/// Cable-like profile (35 Mbps, 24ms RTT, 0.2% loss) should complete
/// repeated sessions within the same budget as the userspace shaper.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tc_cable_profile_sessions_succeed() -> TestResult {
    if skip_unless_tc() {
        return Ok(());
    }
    let providers = tokio::time::timeout(
        Duration::from_secs(10),
        connect_with_tc(NetworkProfile {
            slug: "tc-cable",
            title: "tc-cable",
            note: "tc-cable",
            bandwidth_mbps_per_direction: 35.0,
            rtt_ms: 24,
            jitter_ms: 2,
            loss_percent: 0.2,
        }),
    )
    .await??;
    let start = std::time::Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        exercise_roundtrip(&providers, 5, 32 * 1024),
    )
    .await??;
    let elapsed = start.elapsed();
    eprintln!(
        "[tc-validate] cable profile: elapsed={}ms for 5 rounds x 32KiB",
        elapsed.as_millis()
    );
    Ok(())
}

/// DSL-like profile (3 Mbps, 44ms RTT, 0.3% loss) should complete
/// repeated sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tc_dsl_profile_sessions_succeed() -> TestResult {
    if skip_unless_tc() {
        return Ok(());
    }
    let providers = tokio::time::timeout(
        Duration::from_secs(15),
        connect_with_tc(NetworkProfile {
            slug: "tc-dsl",
            title: "tc-dsl",
            note: "tc-dsl",
            bandwidth_mbps_per_direction: 3.0,
            rtt_ms: 44,
            jitter_ms: 4,
            loss_percent: 0.3,
        }),
    )
    .await??;
    let start = std::time::Instant::now();
    tokio::time::timeout(
        Duration::from_secs(60),
        exercise_roundtrip(&providers, 5, 32 * 1024),
    )
    .await??;
    let elapsed = start.elapsed();
    eprintln!(
        "[tc-validate] DSL profile: elapsed={}ms for 5 rounds x 32KiB",
        elapsed.as_millis()
    );
    Ok(())
}
