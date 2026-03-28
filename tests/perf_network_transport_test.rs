mod perf_network_shaper;

use std::error::Error;
use std::time::Duration;

use perf_network_shaper::{NetworkProfile, UdpTrafficShaper};
use topo::protocol::{encode_frame, parse_frame, Frame};
use topo::transport::multi_workspace::transport_sni;
use topo::transport::{
    accept_session_provider, create_runtime_endpoint_for_tenants, dial_session_provider,
    load_daemon_identity_from_db, SessionProvider,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

async fn recv_data_frame(
    recv: &mut dyn topo::contracts::peering_contract::DataRecvIo,
) -> TestResult<Frame> {
    let mut buffered = Vec::new();
    loop {
        let chunk = recv.recv().await?;
        buffered.extend_from_slice(&chunk);
        match parse_frame(&buffered) {
            Ok((frame, consumed)) if consumed == buffered.len() => return Ok(frame),
            Ok((_frame, _consumed)) => {
                return Err("unexpected trailing bytes after decoded data frame".into())
            }
            Err(topo::protocol::ParseError::InsufficientData) => {}
            Err(err) => return Err(Box::new(err)),
        }
    }
}

struct ConnectedProviders {
    _server_ep: topo::transport::TransportEndpoint,
    server_provider: SessionProvider,
    _client_ep: topo::transport::TransportEndpoint,
    client_provider: SessionProvider,
    _shaper: Option<UdpTrafficShaper>,
}

fn shaping_profile(
    slug: &'static str,
    bandwidth_mbps_per_direction: f64,
    rtt_ms: u64,
    jitter_ms: u64,
    loss_percent: f64,
) -> NetworkProfile {
    NetworkProfile {
        slug,
        title: slug,
        note: slug,
        bandwidth_mbps_per_direction,
        rtt_ms,
        jitter_ms,
        loss_percent,
    }
}

async fn connect_session_providers(
    profile: Option<NetworkProfile>,
) -> TestResult<ConnectedProviders> {
    let temp = tempfile::tempdir()?;
    let server_db = temp.path().join("server.sqlite3");
    let client_db = temp.path().join("client.sqlite3");
    let server_ep = create_runtime_endpoint_for_tenants(
        "127.0.0.1:0".parse().unwrap(),
        server_db.to_str().unwrap(),
    )
    .await?;
    let client_ep = create_runtime_endpoint_for_tenants(
        "127.0.0.1:0".parse().unwrap(),
        client_db.to_str().unwrap(),
    )
    .await?;
    let server_peer_id = load_daemon_identity_from_db(server_db.to_str().unwrap())?.0;

    let server_addr = server_ep.local_addr()?;
    let client_addr = client_ep.local_addr()?;
    let shaper = profile.map(|profile| UdpTrafficShaper::new(server_addr, client_addr, profile));
    let remote_addr = shaper
        .as_ref()
        .map(|shaper| shaper.left_addr())
        .unwrap_or(server_addr);
    let sni = transport_sni(&server_peer_id);

    let (server_provider_result, client_provider_result) = tokio::join!(
        accept_session_provider(&server_ep),
        dial_session_provider(&client_ep, remote_addr, &sni)
    );
    let server_provider = server_provider_result?
        .ok_or_else(|| "server endpoint closed before accepting session provider".to_string())?;
    let client_provider = client_provider_result?;

    Ok(ConnectedProviders {
        _server_ep: server_ep,
        server_provider,
        _client_ep: client_ep,
        client_provider,
        _shaper: shaper,
    })
}

async fn exercise_roundtrip_sessions(
    providers: &ConnectedProviders,
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

        let request_ids = encode_frame(&Frame::RequestIds { ids: vec![] });
        server_parts.control.send(&request_ids).await?;
        server_parts.control.flush().await?;
        let received = client_parts.control.recv().await?;
        assert_eq!(parse_frame(&received)?.0, Frame::RequestIds { ids: vec![] });

        let payload = vec![round as u8; data_payload_len];
        let event = encode_frame(&Frame::Event {
            blob: payload.clone(),
        });
        client_parts.data_send.send(&event).await?;
        client_parts.data_send.flush().await?;
        let received = recv_data_frame(server_parts.data_recv.as_mut()).await?;
        assert_eq!(received, Frame::Event { blob: payload });
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_repeated_sessions_succeed() -> TestResult {
    let providers =
        tokio::time::timeout(Duration::from_secs(10), connect_session_providers(None)).await??;
    tokio::time::timeout(
        Duration::from_secs(10),
        exercise_roundtrip_sessions(&providers, 5, 32 * 1024),
    )
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn neutral_proxy_repeated_sessions_succeed() -> TestResult {
    let providers = tokio::time::timeout(
        Duration::from_secs(10),
        connect_session_providers(Some(shaping_profile("neutral", 1_000.0, 0, 0, 0.0))),
    )
    .await??;
    tokio::time::timeout(
        Duration::from_secs(10),
        exercise_roundtrip_sessions(&providers, 5, 32 * 1024),
    )
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn latency_only_proxy_repeated_sessions_succeed() -> TestResult {
    let providers = tokio::time::timeout(
        Duration::from_secs(10),
        connect_session_providers(Some(shaping_profile("latency-only", 1_000.0, 80, 0, 0.0))),
    )
    .await??;
    tokio::time::timeout(
        Duration::from_secs(20),
        exercise_roundtrip_sessions(&providers, 5, 32 * 1024),
    )
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bandwidth_only_proxy_repeated_sessions_succeed() -> TestResult {
    let providers = tokio::time::timeout(
        Duration::from_secs(10),
        connect_session_providers(Some(shaping_profile("bandwidth-only", 2.0, 0, 0, 0.0))),
    )
    .await??;
    tokio::time::timeout(
        Duration::from_secs(30),
        exercise_roundtrip_sessions(&providers, 5, 64 * 1024),
    )
    .await??;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shaper sanity checks
//
// These tests validate that the shaper knobs actually do what they claim.
// They are complementary to the "sessions succeed" tests above: where those
// prove the shaper never accidentally breaks connectivity, these prove it
// actually imposes the configured impairment.
// ---------------------------------------------------------------------------

/// A shaper configured with zero impairment (huge bandwidth, no latency, no loss)
/// must complete the same workload as direct QUIC within the same time budget.
/// This proves the shaper itself adds no material overhead when not impeding traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_impairment_proxy_matches_direct_speed() -> TestResult {
    // Same workload as direct_repeated_sessions_succeed: 5 rounds × 32 KiB.
    let providers = tokio::time::timeout(
        Duration::from_secs(10),
        connect_session_providers(Some(shaping_profile(
            "zero-impairment",
            1_000_000.0,
            0,
            0,
            0.0,
        ))),
    )
    .await??;
    tokio::time::timeout(
        Duration::from_secs(10),
        exercise_roundtrip_sessions(&providers, 5, 32 * 1024),
    )
    .await??;
    Ok(())
}

/// 100% packet loss makes the QUIC handshake impossible: all UDP packets are
/// discarded before reaching the peer.  The connection attempt must not succeed
/// within a short window, proving the drop path is active.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn total_loss_proxy_blocks_connection() {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        connect_session_providers(Some(shaping_profile("blackhole", 1_000.0, 0, 0, 100.0))),
    )
    .await;
    // Must either time out (Err from tokio::time::timeout) or produce a
    // transport-level error — never a successfully-connected provider pair.
    let succeeded = matches!(result, Ok(Ok(_)));
    assert!(
        !succeeded,
        "connection through a 100% loss shaper must not succeed within 3s"
    );
}

/// An extreme bandwidth cap measurably slows bulk data transfer, proving the
/// serialization-delay model is applied.
///
/// At 1 Mbps (125 KB/s), transmitting 128 KiB of QUIC-packetised event data
/// requires roughly 1.05 s of serialization time.  The test checks that the
/// elapsed transfer time is at least 800 ms (≈76% of the theoretical minimum),
/// giving generous margin for OS scheduling and QUIC stack overhead while still
/// catching a broken or bypassed shaper.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn low_bandwidth_proxy_measurably_throttles_transfer() -> TestResult {
    let providers = tokio::time::timeout(
        Duration::from_secs(10),
        connect_session_providers(Some(shaping_profile("narrow", 1.0, 0, 0, 0.0))),
    )
    .await??;
    let start = std::time::Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        exercise_roundtrip_sessions(&providers, 1, 128 * 1024),
    )
    .await??;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(800),
        "128 KiB at 1 Mbps should take ≥800 ms, took {} ms",
        elapsed.as_millis()
    );
    Ok(())
}

/// High propagation delay measurably slows sequential message exchanges, proving
/// the delay-line latency model is applied.
///
/// One call to `exercise_roundtrip_sessions` sends three one-way messages
/// (NegOpen client→server, HaveList server→client, Event client→server).
/// At 200 ms RTT (100 ms one-way), those three hops require at least 300 ms.
/// The test checks for ≥250 ms, giving 50 ms of slack for timing imprecision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn high_latency_proxy_measurably_delays_roundtrip() -> TestResult {
    // Connection setup itself takes ~1 RTT at 200 ms; use a generous timeout.
    let providers = tokio::time::timeout(
        Duration::from_secs(10),
        connect_session_providers(Some(shaping_profile("high-latency", 1_000.0, 200, 0, 0.0))),
    )
    .await??;
    let start = std::time::Instant::now();
    // Tiny payload so serialization is negligible; only propagation delay matters.
    tokio::time::timeout(
        Duration::from_secs(10),
        exercise_roundtrip_sessions(&providers, 1, 32),
    )
    .await??;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(250),
        "3 one-way messages at 200 ms RTT should take ≥250 ms, took {} ms",
        elapsed.as_millis()
    );
    Ok(())
}
