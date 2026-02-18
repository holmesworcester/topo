//! Hole punch receiver: handles incoming IntroOffer messages and attempts
//! direct connections to introduced peers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::network_contract::{
    PeerFingerprint, SessionDirection, SessionHandler, SessionMeta, TenantId, TrustDecision,
    TrustOracle,
};
use crate::db::{
    health::record_endpoint_observation,
    intro::{insert_intro_attempt, intro_already_seen, update_intro_status},
    open_connection,
};
use crate::contracts::network_contract::next_session_id;
use crate::replication::ReplicationSessionHandler;
use crate::sync::{parse_sync_message, SyncMessage};
use crate::transport::{
    peer_identity_from_connection, DualConnection, SqliteTrustOracle, SyncSessionIo,
};

const ENDPOINT_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Read an IntroOffer from a uni-directional recv stream.
pub async fn read_intro_from_uni(
    recv: &mut quinn::RecvStream,
) -> Result<SyncMessage, Box<dyn std::error::Error + Send + Sync>> {
    // IntroOffer is 88 bytes fixed
    let mut buf = vec![0u8; 88];
    recv.read_exact(&mut buf).await?;
    let (msg, _) = parse_sync_message(&buf)?;
    Ok(msg)
}

/// Extract SocketAddr from IntroOffer fields.
fn intro_offer_addr(
    origin_family: u8,
    origin_ip: &[u8; 16],
    origin_port: u16,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    let ip = match origin_family {
        4 => IpAddr::V4(Ipv4Addr::new(
            origin_ip[12],
            origin_ip[13],
            origin_ip[14],
            origin_ip[15],
        )),
        6 => IpAddr::V6(Ipv6Addr::from(*origin_ip)),
        _ => return Err(format!("unknown origin_family: {}", origin_family).into()),
    };
    Ok(SocketAddr::new(ip, origin_port))
}

/// Process an incoming IntroOffer:
/// 1. Validate expiry, trust, dedupe
/// 2. Record in intro_attempts
/// 3. Launch paced dial attempts
/// 4. On success, start sync
pub async fn handle_intro_offer(
    db_path: &str,
    recorded_by: &str,
    introduced_by: &str,
    endpoint: quinn::Endpoint,
    intro_id: [u8; 16],
    other_peer_id: [u8; 32],
    origin_family: u8,
    origin_ip: [u8; 16],
    origin_port: u16,
    observed_at_ms: u64,
    expires_at_ms: u64,
    attempt_window_ms: u32,
    client_config: Option<quinn::ClientConfig>,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let other_peer_hex = hex::encode(other_peer_id);

    // Validate expiry
    if now_ms > expires_at_ms as i64 {
        info!(
            "IntroOffer expired (now={}, expires={}), dropping",
            now_ms, expires_at_ms
        );
        let _ = try_record_intro(
            db_path,
            recorded_by,
            &intro_id,
            introduced_by,
            &other_peer_hex,
            &origin_ip,
            origin_family,
            origin_port,
            observed_at_ms as i64,
            expires_at_ms as i64,
            now_ms,
            "expired",
            None,
        );
        return;
    }

    // Validate trust from SQL only. No DB = no trust authority.
    let trusted = match SqliteTrustOracle::new(db_path)
        .check(
            &TenantId(recorded_by.to_string()),
            &PeerFingerprint(other_peer_id),
        )
        .await
    {
        Ok(TrustDecision::Allow) => true,
        Ok(TrustDecision::Deny) => false,
        Err(e) => {
            warn!("IntroOffer trust check failed: {}", e);
            false
        }
    };
    if !trusted {
        info!(
            "IntroOffer for untrusted peer {}, rejecting",
            &other_peer_hex[..16]
        );
        let _ = try_record_intro(
            db_path,
            recorded_by,
            &intro_id,
            introduced_by,
            &other_peer_hex,
            &origin_ip,
            origin_family,
            origin_port,
            observed_at_ms as i64,
            expires_at_ms as i64,
            now_ms,
            "rejected",
            Some("untrusted peer"),
        );
        return;
    }

    // Dedupe
    if let Ok(db) = open_connection(db_path) {
        if intro_already_seen(&db, recorded_by, &intro_id).unwrap_or(false) {
            info!(
                "IntroOffer {} already seen, skipping",
                hex::encode(&intro_id[..8])
            );
            return;
        }
    }

    // Parse target address
    let addr = match intro_offer_addr(origin_family, &origin_ip, origin_port) {
        Ok(a) => a,
        Err(e) => {
            warn!("IntroOffer bad address: {}", e);
            return;
        }
    };

    // Record as received
    let _ = try_record_intro(
        db_path,
        recorded_by,
        &intro_id,
        introduced_by,
        &other_peer_hex,
        &origin_ip,
        origin_family,
        origin_port,
        observed_at_ms as i64,
        expires_at_ms as i64,
        now_ms,
        "received",
        None,
    );

    // Transition to dialing
    update_status(db_path, recorded_by, &intro_id, "dialing", None);

    info!(
        "Attempting hole punch to {} at {} (local_addr={:?})",
        &other_peer_hex[..16],
        addr,
        endpoint.local_addr()
    );

    // Paced dial attempts within the attempt window
    let window = Duration::from_millis(attempt_window_ms as u64);
    let pace = Duration::from_millis(200); // send a packet every 200ms
    let start = std::time::Instant::now();
    let mut attempt = 0u32;

    loop {
        if start.elapsed() >= window {
            break;
        }
        attempt += 1;

        // Use per-tenant config when available (node multi-tenant path).
        // Fallback to endpoint default for single-tenant test endpoints.
        match if let Some(ref cfg) = client_config {
            endpoint.connect_with(cfg.clone(), addr, "localhost")
        } else {
            endpoint.connect(addr, "localhost")
        } {
            Ok(connecting) => {
                match tokio::time::timeout(pace, connecting).await {
                    Ok(Ok(connection)) => {
                        // Verify peer identity matches expected
                        let actual_peer = peer_identity_from_connection(&connection);
                        if actual_peer.as_deref() != Some(&other_peer_hex) {
                            warn!(
                                "Punch connected but wrong peer: expected {}, got {:?}",
                                &other_peer_hex[..16],
                                actual_peer.as_ref().map(|s| &s[..16])
                            );
                            update_status(
                                db_path,
                                recorded_by,
                                &intro_id,
                                "failed",
                                Some("wrong peer identity"),
                            );
                            return;
                        }

                        info!(
                            "Hole punch succeeded! Direct connection to {}",
                            &other_peer_hex[..16]
                        );
                        update_status(db_path, recorded_by, &intro_id, "connected", None);

                        // Preserve endpoint observations for peers reached via punched links.
                        // This enables future explicit intro calls between peers that were
                        // discovered through successful hole-punched connectivity.
                        let remote = connection.remote_address();
                        if let Ok(db) = open_connection(db_path) {
                            let now_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as i64;
                            let _ = record_endpoint_observation(
                                &db,
                                recorded_by,
                                &other_peer_hex,
                                &remote.ip().to_string(),
                                remote.port(),
                                now_ms,
                                ENDPOINT_TTL_MS,
                            );
                        }

                        // Run normal sync on the direct connection
                        run_sync_on_punched_connection(
                            connection,
                            db_path,
                            recorded_by,
                            &other_peer_hex,
                        )
                        .await;
                        return;
                    }
                    Ok(Err(e)) => {
                        info!("Punch attempt #{} connect error: {}", attempt, e);
                    }
                    Err(_) => {
                        if attempt <= 3 {
                            info!("Punch attempt #{} timed out (200ms)", attempt);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Punch connect error: {}", e);
                break;
            }
        }
    }

    info!("Hole punch timed out for {}", &other_peer_hex[..16]);
    update_status(db_path, recorded_by, &intro_id, "failed", Some("timeout"));
}

/// After a successful hole punch, run a sync initiator session.
async fn run_sync_on_punched_connection(
    connection: quinn::Connection,
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
) {
    // Open streams and run initiator sync
    let (ctrl_send, ctrl_recv) = match connection.open_bi().await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to open control stream on punched connection: {}", e);
            return;
        }
    };
    let (data_send, data_recv) = match connection.open_bi().await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to open data stream on punched connection: {}", e);
            return;
        }
    };
    let mut conn = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);

    // Send markers (same as connect_loop)
    let _ = conn
        .control
        .send(&SyncMessage::HaveList { ids: vec![] })
        .await;
    let _ = conn
        .data_send
        .send(&SyncMessage::HaveList { ids: vec![] })
        .await;
    let _ = conn.flush_control().await;
    let _ = conn.flush_data().await;

    let peer_fp = match hex::decode(peer_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&bytes);
            fp
        }
        _ => {
            warn!("Punched sync error: invalid peer id {}", peer_id);
            return;
        }
    };

    let session_id = next_session_id();
    let meta = SessionMeta {
        session_id,
        tenant: TenantId(recorded_by.to_string()),
        peer: PeerFingerprint(peer_fp),
        remote_addr: connection.remote_address(),
        direction: SessionDirection::Outbound,
    };
    let handler = ReplicationSessionHandler::initiator(db_path.to_string(), 60);
    let io = SyncSessionIo::new(session_id, conn);

    if let Err(e) = handler
        .on_session(meta, Box::new(io), CancellationToken::new())
        .await
    {
        warn!("Punched sync error: {}", e);
    } else {
        info!("Punched sync complete");
    }
}

/// Spawn a background task that listens for uni-directional streams on a
/// QUIC connection and processes IntroOffer messages.
///
/// Must be called from within a `tokio::task::LocalSet` context (both
/// `accept_loop` and `connect_loop` provide one). Uses `spawn_local`
/// so the punch handler can hold `!Send` types (rusqlite) across awaits
/// while sharing the same endpoint I/O driver as the parent runtime.
pub fn spawn_intro_listener(
    connection: quinn::Connection,
    db_path: String,
    recorded_by: String,
    introduced_by: String,
    endpoint: quinn::Endpoint,
    client_config: Option<quinn::ClientConfig>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(async move {
        loop {
            let mut recv = match connection.accept_uni().await {
                Ok(r) => r,
                Err(_) => {
                    // Connection closed
                    break;
                }
            };

            match read_intro_from_uni(&mut recv).await {
                Ok(SyncMessage::IntroOffer {
                    intro_id,
                    other_peer_id,
                    origin_family,
                    origin_ip,
                    origin_port,
                    observed_at_ms,
                    expires_at_ms,
                    attempt_window_ms,
                }) => {
                    info!(
                        "Received IntroOffer from {} for peer {}",
                        &introduced_by[..16],
                        hex::encode(&other_peer_id[..8])
                    );

                    let db_path = db_path.clone();
                    let recorded_by = recorded_by.clone();
                    let introduced_by = introduced_by.clone();
                    let endpoint = endpoint.clone();
                    let cfg = client_config.clone();

                    // Spawn punch attempt as a local task — runs on the same
                    // LocalSet / runtime that owns the endpoint I/O driver,
                    // so endpoint.connect_with() can properly send/receive UDP.
                    tokio::task::spawn_local(async move {
                        handle_intro_offer(
                            &db_path,
                            &recorded_by,
                            &introduced_by,
                            endpoint,
                            intro_id,
                            other_peer_id,
                            origin_family,
                            origin_ip,
                            origin_port,
                            observed_at_ms,
                            expires_at_ms,
                            attempt_window_ms,
                            cfg,
                        )
                        .await;
                    });
                }
                Ok(_) => {
                    // Not an IntroOffer, ignore
                }
                Err(e) => {
                    warn!("Failed to read from uni stream: {}", e);
                }
            }
        }
    })
}

fn try_record_intro(
    db_path: &str,
    recorded_by: &str,
    intro_id: &[u8; 16],
    introduced_by: &str,
    other_peer_hex: &str,
    origin_ip_bytes: &[u8; 16],
    origin_family: u8,
    origin_port: u16,
    observed_at_ms: i64,
    expires_at_ms: i64,
    now_ms: i64,
    status: &str,
    error: Option<&str>,
) {
    let ip_str = match intro_offer_addr(origin_family, origin_ip_bytes, origin_port) {
        Ok(addr) => addr.ip().to_string(),
        Err(_) => "unknown".to_string(),
    };

    if let Ok(db) = open_connection(db_path) {
        let _ = insert_intro_attempt(
            &db,
            recorded_by,
            intro_id,
            introduced_by,
            other_peer_hex,
            &ip_str,
            origin_port,
            observed_at_ms,
            expires_at_ms,
            now_ms,
        );
        if status != "received" {
            let _ = update_intro_status(&db, recorded_by, intro_id, status, error, now_ms);
        }
    }
}

fn update_status(
    db_path: &str,
    recorded_by: &str,
    intro_id: &[u8; 16],
    status: &str,
    error: Option<&str>,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    if let Ok(db) = open_connection(db_path) {
        let _ = update_intro_status(&db, recorded_by, intro_id, status, error, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intro_offer_addr_v4() {
        let mut ip = [0u8; 16];
        ip[12] = 192;
        ip[13] = 168;
        ip[14] = 1;
        ip[15] = 100;
        let addr = intro_offer_addr(4, &ip, 12345).unwrap();
        assert_eq!(addr, "192.168.1.100:12345".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_intro_offer_addr_v6() {
        let ip = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let addr = intro_offer_addr(6, &ip, 443).unwrap();
        assert_eq!(addr, "[fe80::1]:443".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_intro_offer_addr_invalid_family() {
        let ip = [0u8; 16];
        assert!(intro_offer_addr(7, &ip, 80).is_err());
    }
}
