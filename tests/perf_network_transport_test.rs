mod perf_network_shaper;

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use perf_network_shaper::{NetworkProfile, UdpTrafficShaper};
use topo::protocol::{encode_frame, parse_frame, Frame};
use topo::transport::multi_workspace::transport_sni;
use topo::transport::{
    accept_session_provider, create_dual_endpoint, dial_session_provider, extract_spki_fingerprint,
    generate_self_signed_cert, SessionProvider,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

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
    let shaper = profile.map(|profile| UdpTrafficShaper::new(server_addr, client_addr, profile));
    let remote_addr = shaper
        .as_ref()
        .map(|shaper| shaper.left_addr())
        .unwrap_or(server_addr);
    let sni = transport_sni(&server_peer_id);

    let (server_provider_result, client_provider_result) = tokio::join!(
        accept_session_provider(&server_ep),
        dial_session_provider(&client_ep, remote_addr, &sni, None)
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

        let have_list = encode_frame(&Frame::HaveList { ids: vec![] });
        server_parts.control.send(&have_list).await?;
        server_parts.control.flush().await?;
        let received = client_parts.control.recv().await?;
        assert_eq!(parse_frame(&received)?.0, Frame::HaveList { ids: vec![] });

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_quinn_repeated_sessions_succeed() -> TestResult {
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
async fn neutral_proxy_quinn_repeated_sessions_succeed() -> TestResult {
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
async fn latency_only_proxy_quinn_repeated_sessions_succeed() -> TestResult {
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
async fn bandwidth_only_proxy_quinn_repeated_sessions_succeed() -> TestResult {
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
