//! Intro offer sending logic for QUIC hole punching.
//!
//! The introducer builds IntroOffer messages from endpoint observations
//! and sends them to peers over fresh QUIC streams.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::{info, warn};

use crate::sync::SyncMessage;
use crate::sync::protocol::encode_sync_message;

/// Build an IntroOffer message for `recipient` about `other_peer`.
pub fn build_intro_offer(
    other_peer_id_hex: &str,
    origin_ip: &str,
    origin_port: u16,
    observed_at_ms: u64,
    ttl_ms: u64,
    attempt_window_ms: u32,
) -> Result<SyncMessage, Box<dyn std::error::Error + Send + Sync>> {
    let other_peer_bytes = hex::decode(other_peer_id_hex)?;
    if other_peer_bytes.len() != 32 {
        return Err(format!("other_peer_id must be 32 bytes, got {}", other_peer_bytes.len()).into());
    }
    let mut other_peer_id = [0u8; 32];
    other_peer_id.copy_from_slice(&other_peer_bytes);

    let ip: IpAddr = origin_ip.parse()?;
    let (origin_family, origin_ip_bytes) = match ip {
        IpAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[12..16].copy_from_slice(&v4.octets());
            (4u8, buf)
        }
        IpAddr::V6(v6) => (6u8, v6.octets()),
    };

    let intro_id: [u8; 16] = rand::random();
    let expires_at_ms = observed_at_ms + ttl_ms;

    Ok(SyncMessage::IntroOffer {
        intro_id,
        other_peer_id,
        origin_family,
        origin_ip: origin_ip_bytes,
        origin_port,
        observed_at_ms,
        expires_at_ms,
        attempt_window_ms,
    })
}

/// Send an IntroOffer to a peer over an existing QUIC connection.
/// Opens a new uni-directional stream, writes the encoded message, and finishes.
pub async fn send_intro_offer(
    connection: &quinn::Connection,
    msg: &SyncMessage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encoded = encode_sync_message(msg);
    let mut send_stream = connection.open_uni().await?;
    send_stream.write_all(&encoded).await?;
    send_stream.finish()?;
    Ok(())
}

/// Run a one-shot intro: look up freshest endpoints for peer_a and peer_b,
/// connect to each, and send IntroOffer about the other.
pub async fn run_intro(
    endpoint: &quinn::Endpoint,
    db_path: &str,
    recorded_by: &str,
    peer_a_hex: &str,
    peer_b_hex: &str,
    ttl_ms: u64,
    attempt_window_ms: u32,
) -> Result<IntroResult, Box<dyn std::error::Error + Send + Sync>> {
    use crate::db::{open_connection, intro::freshest_endpoint};

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;

    let db = open_connection(db_path)?;

    // Look up freshest endpoint for each peer
    let ep_a = freshest_endpoint(&db, recorded_by, peer_a_hex, now_ms)?
        .ok_or_else(|| format!("no non-expired endpoint observation for peer A ({})", &peer_a_hex[..16]))?;
    let ep_b = freshest_endpoint(&db, recorded_by, peer_b_hex, now_ms)?
        .ok_or_else(|| format!("no non-expired endpoint observation for peer B ({})", &peer_b_hex[..16]))?;

    drop(db);

    // Build IntroOffer for A about B
    let offer_for_a = build_intro_offer(
        peer_b_hex, &ep_b.0, ep_b.1, ep_b.2 as u64, ttl_ms, attempt_window_ms,
    )?;
    // Build IntroOffer for B about A
    let offer_for_b = build_intro_offer(
        peer_a_hex, &ep_a.0, ep_a.1, ep_a.2 as u64, ttl_ms, attempt_window_ms,
    )?;

    let addr_a: SocketAddr = format!("{}:{}", ep_a.0, ep_a.1).parse()?;
    let addr_b: SocketAddr = format!("{}:{}", ep_b.0, ep_b.1).parse()?;

    let mut result = IntroResult { sent_to_a: false, sent_to_b: false, errors: Vec::new() };

    // Send to A
    match send_intro_to_peer(endpoint, addr_a, &offer_for_a).await {
        Ok(()) => {
            info!("Sent IntroOffer to peer A at {}", addr_a);
            result.sent_to_a = true;
        }
        Err(e) => {
            warn!("Failed to send IntroOffer to peer A at {}: {}", addr_a, e);
            result.errors.push(format!("peer A: {}", e));
        }
    }

    // Send to B
    match send_intro_to_peer(endpoint, addr_b, &offer_for_b).await {
        Ok(()) => {
            info!("Sent IntroOffer to peer B at {}", addr_b);
            result.sent_to_b = true;
        }
        Err(e) => {
            warn!("Failed to send IntroOffer to peer B at {}: {}", addr_b, e);
            result.errors.push(format!("peer B: {}", e));
        }
    }

    Ok(result)
}

async fn send_intro_to_peer(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    offer: &SyncMessage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connecting = endpoint.connect(addr, "localhost")?;
    let connection = tokio::time::timeout(Duration::from_secs(5), connecting).await
        .map_err(|_| "connection timeout")??;
    send_intro_offer(&connection, offer).await?;
    // Brief yield to let the QUIC stack flush the uni stream data before closing.
    // connection.close() is immediate and discards unsent data.
    tokio::time::sleep(Duration::from_millis(50)).await;
    connection.close(0u32.into(), b"intro-sent");
    Ok(())
}

#[derive(Debug)]
pub struct IntroResult {
    pub sent_to_a: bool,
    pub sent_to_b: bool,
    pub errors: Vec<String>,
}

/// Run continuous intro worker: periodically scan for peer pairs and send intros.
pub async fn run_intro_worker(
    endpoint: &quinn::Endpoint,
    db_path: &str,
    recorded_by: &str,
    interval_ms: u64,
    ttl_ms: u64,
    attempt_window_ms: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::db::open_connection;

    info!("Intro worker started (interval={}ms, ttl={}ms, window={}ms)",
        interval_ms, ttl_ms, attempt_window_ms);

    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;

        // Find all peers with non-expired endpoint observations
        let peers = {
            let db = open_connection(db_path)?;
            let mut stmt = db.prepare(
                "SELECT DISTINCT via_peer_id FROM peer_endpoint_observations
                 WHERE recorded_by = ?1 AND expires_at > ?2"
            )?;
            let peers: Vec<String> = stmt.query_map(
                rusqlite::params![recorded_by, now_ms],
                |row| row.get(0),
            )?.collect::<Result<Vec<_>, _>>()?;
            peers
        };

        if peers.len() >= 2 {
            // For each unordered pair, attempt intro
            for i in 0..peers.len() {
                for j in (i + 1)..peers.len() {
                    let peer_a = &peers[i];
                    let peer_b = &peers[j];
                    match run_intro(endpoint, db_path, recorded_by, peer_a, peer_b,
                                    ttl_ms, attempt_window_ms).await {
                        Ok(r) => {
                            info!("Intro {}<->{}: sent_a={}, sent_b={}",
                                &peer_a[..16], &peer_b[..16], r.sent_to_a, r.sent_to_b);
                        }
                        Err(e) => {
                            warn!("Intro {}<->{}: {}", &peer_a[..16], &peer_b[..16], e);
                        }
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
    }
}
