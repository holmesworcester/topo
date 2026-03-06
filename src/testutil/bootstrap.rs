//! Bootstrap sync helpers — test-only.
//!
//! Production bootstrap connectivity is driven by projected SQL trust state
//! and the ongoing autodial loop in `peering::runtime::target_planner`. These helpers
//! simulate the runtime bootstrap flow for test infrastructure only:
//! `start_bootstrap_responder` serves prerequisite events, and
//! `bootstrap_sync_from_invite` connects and fetches them.
//!
//! Moved from `peering::workflows::bootstrap` to enforce test-only ownership
//! (R2/SC2 of PEERING_READABILITY_AND_BOOTSTRAP_DISCOVERY_PLAN).

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::contracts::event_pipeline_contract::{BatchWriterFn, IngestItem};
use crate::contracts::peering_contract::{
    next_session_id, PeerFingerprint, SessionDirection, SessionHandler, SessionMeta, TenantId,
};
use crate::db::{open_connection, schema::create_tables};
use crate::event_modules::workspace::identity_ops::expected_invite_bootstrap_spki_from_invite_key;
use crate::sync::{CoordinationManager, SyncSessionHandler};

use crate::transport::identity::{load_transport_cert, load_transport_cert_required_from_db};
use crate::transport::{
    create_dual_endpoint, peer_identity_from_connection, AllowedPeers, DualConnection,
    QuicTransportSessionIo,
};

const BOOTSTRAP_CONNECT_ATTEMPTS: usize = 5;
const BOOTSTRAP_CONNECT_RETRY_DELAY: Duration = Duration::from_millis(250);
const BOOTSTRAP_CONNECT_TIMEOUT_CAP_SECS: u64 = 5;

fn peer_fingerprint_from_hex(
    peer_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(peer_id)?;
    if bytes.len() != 32 {
        return Err(format!(
            "peer_id must be 32-byte hex fingerprint, got {}",
            bytes.len()
        )
        .into());
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&bytes);
    Ok(fp)
}

/// Run a bootstrap sync session against a known bootstrap address.
///
/// Used by test infrastructure to simulate what the runtime autodial loop does
/// in production: connect to the bootstrap peer, run a negentropy sync session
/// to fetch prerequisite events, then close the connection. The batch_writer
/// handles projection cascade.
pub async fn bootstrap_sync_from_invite(
    db_path: &str,
    recorded_by: &str,
    bootstrap_addr: SocketAddr,
    bootstrap_spki: &[u8; 32],
    timeout_secs: u64,
    batch_writer: BatchWriterFn,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    let (_peer_id, cert, key) = load_transport_cert_required_from_db(db_path)?;

    let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![*bootstrap_spki]));
    let endpoint = create_dual_endpoint("0.0.0.0:0".parse().unwrap(), cert, key, allowed)?;

    info!(
        "Bootstrap sync: connecting to {} (spki {}...)",
        bootstrap_addr,
        hex::encode(&bootstrap_spki[..8])
    );

    // Retry connection setup to absorb transient listener startup or mDNS race windows.
    let dial_timeout_secs = timeout_secs.clamp(1, BOOTSTRAP_CONNECT_TIMEOUT_CAP_SECS);
    let connection = connect_bootstrap_with_retry(
        &endpoint,
        bootstrap_addr,
        BOOTSTRAP_CONNECT_ATTEMPTS,
        dial_timeout_secs,
    )
    .await?;

    let peer_id = peer_identity_from_connection(&connection)
        .ok_or("Bootstrap sync: could not extract peer identity")?;

    info!("Bootstrap sync: connected to peer {}", &peer_id[..16]);

    let (ctrl_send, ctrl_recv) = connection
        .open_bi()
        .await
        .map_err(|e| format!("Bootstrap sync: failed to open control stream: {}", e))?;
    let (data_send, data_recv) = connection
        .open_bi()
        .await
        .map_err(|e| format!("Bootstrap sync: failed to open data stream: {}", e))?;

    let conn = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);

    // Stream materialization markers are now sent by
    // SyncSessionHandler::on_session for outbound sessions.

    // Shared batch_writer for this one-shot bootstrap session.
    let (ingest_tx, ingest_rx) = mpsc::channel::<IngestItem>(5000);
    let writer_events = Arc::new(AtomicU64::new(0));
    let writer_db = db_path.to_string();
    let bw = batch_writer;
    let writer_handle = std::thread::spawn(move || {
        bw(writer_db, ingest_rx, writer_events);
    });
    let peer_fp = peer_fingerprint_from_hex(&peer_id)?;
    let session_id = next_session_id();
    let meta = SessionMeta {
        session_id,
        tenant: TenantId(recorded_by.to_string()),
        peer: PeerFingerprint(peer_fp),
        remote_addr: connection.remote_address(),
        direction: SessionDirection::Outbound,
    };
    let coordination_manager = Arc::new(CoordinationManager::new());
    let coordination = coordination_manager.register_peer();
    let handler =
        SyncSessionHandler::outbound(db_path.to_string(), timeout_secs, coordination, ingest_tx);
    let io = QuicTransportSessionIo::new(session_id, conn);
    handler
        .on_session(meta, Box::new(io), CancellationToken::new())
        .await
        .map_err(|e| format!("Bootstrap sync: {}", e))?;

    // Drop handler to close the ingest channel, then join the writer thread.
    drop(handler);
    let _ = writer_handle.join();

    info!("Bootstrap sync complete");

    endpoint.close(0u32.into(), b"bootstrap done");
    endpoint.wait_idle().await;

    Ok(())
}

async fn connect_bootstrap_with_retry(
    endpoint: &quinn::Endpoint,
    bootstrap_addr: SocketAddr,
    attempts: usize,
    dial_timeout_secs: u64,
) -> Result<quinn::Connection, Box<dyn std::error::Error + Send + Sync>> {
    let mut last_err = String::new();
    for attempt in 1..=attempts {
        let connecting = match endpoint.connect(bootstrap_addr, "localhost") {
            Ok(connecting) => connecting,
            Err(e) => {
                last_err = format!("initiate to {}: {}", bootstrap_addr, e);
                if attempt < attempts {
                    info!(
                        "Bootstrap sync dial attempt {}/{} failed ({}); retrying...",
                        attempt, attempts, last_err
                    );
                    tokio::time::sleep(BOOTSTRAP_CONNECT_RETRY_DELAY).await;
                    continue;
                }
                break;
            }
        };
        match tokio::time::timeout(Duration::from_secs(dial_timeout_secs), connecting).await {
            Ok(Ok(connection)) => return Ok(connection),
            Ok(Err(e)) => {
                last_err = format!("handshake to {}: {}", bootstrap_addr, e);
            }
            Err(_) => {
                last_err = format!(
                    "handshake to {} timed out after {}s",
                    bootstrap_addr, dial_timeout_secs
                );
            }
        }

        if attempt < attempts {
            info!(
                "Bootstrap sync dial attempt {}/{} failed ({}); retrying...",
                attempt, attempts, last_err
            );
            tokio::time::sleep(BOOTSTRAP_CONNECT_RETRY_DELAY).await;
        }
    }

    Err(format!(
        "Bootstrap sync: failed to connect to {} after {} attempts: {}",
        bootstrap_addr, attempts, last_err
    )
    .into())
}

/// Start a temporary QUIC sync endpoint that serves one bootstrap connection.
///
/// The endpoint allows only the invitee's SPKI (derived from the invite key).
/// A sync responder runs on a separate thread (rusqlite is not Send), accepts
/// one connection, syncs, and exits. Returns the bound address and endpoint
/// handle — caller must close the endpoint when done.
///
/// Used by test helpers to let an in-process inviter serve prerequisite
/// events to a joiner via real QUIC sync.
pub fn start_bootstrap_responder(
    inviter_db_path: &str,
    inviter_identity: &str,
    invite_key: &SigningKey,
    batch_writer: BatchWriterFn,
) -> Result<(SocketAddr, quinn::Endpoint), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(inviter_db_path)?;
    let (cert, key) = load_transport_cert(&db, inviter_identity)?;

    let joiner_spki = expected_invite_bootstrap_spki_from_invite_key(invite_key)?;
    let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![joiner_spki]));

    let endpoint = create_dual_endpoint("127.0.0.1:0".parse().unwrap(), cert, key, allowed)?;
    let local_addr = endpoint.local_addr()?;

    let db_path = inviter_db_path.to_string();
    let recorded_by = inviter_identity.to_string();
    let ep = endpoint.clone();

    std::thread::spawn(move || {
        // Shared batch_writer for bootstrap responder sessions.
        let (ingest_tx, ingest_rx) = mpsc::channel::<IngestItem>(5000);
        let writer_events = Arc::new(AtomicU64::new(0));
        let writer_db = db_path.clone();
        let bw = batch_writer;
        let writer_handle = std::thread::spawn(move || {
            bw(writer_db, ingest_rx, writer_events);
        });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create bootstrap responder runtime");
        rt.block_on(async move {
            let handler = SyncSessionHandler::responder(db_path.clone(), 30, ingest_tx);
            // Keep connections alive until the endpoint closes so QUIC can
            // deliver final frames (DoneAck, events) before the connection
            // is torn down. Dropping a quinn::Connection sends
            // CONNECTION_CLOSE which aborts in-flight stream data.
            let mut _connections = Vec::new();
            // Accept up to 2 connections: the initial bootstrap sync and an
            // optional push-back sync where the joiner pushes its identity
            // chain events back after creation.
            for _ in 0..2 {
                let connection = match ep.accept().await {
                    Some(incoming) => match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("Bootstrap responder: connection failed: {}", e);
                            return;
                        }
                    },
                    None => return,
                };

                let peer_id = peer_identity_from_connection(&connection).unwrap_or_default();
                let peer_fp = match peer_fingerprint_from_hex(&peer_id) {
                    Ok(fp) => fp,
                    Err(e) => {
                        tracing::warn!("Bootstrap responder: invalid peer_id: {}", e);
                        continue;
                    }
                };

                let (ctrl_send, ctrl_recv) = match connection.accept_bi().await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("Bootstrap responder: control stream failed: {}", e);
                        return;
                    }
                };
                let (data_send, data_recv) = match connection.accept_bi().await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("Bootstrap responder: data stream failed: {}", e);
                        return;
                    }
                };
                let conn = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);
                let session_id = next_session_id();
                let meta = SessionMeta {
                    session_id,
                    tenant: TenantId(recorded_by.clone()),
                    peer: PeerFingerprint(peer_fp),
                    remote_addr: connection.remote_address(),
                    direction: SessionDirection::Inbound,
                };
                let io = QuicTransportSessionIo::new(session_id, conn);

                if let Err(e) = handler
                    .on_session(meta, Box::new(io), CancellationToken::new())
                    .await
                {
                    tracing::warn!("Bootstrap responder: sync error: {}", e);
                }
                _connections.push(connection);
            }
        });
        let _ = writer_handle.join();
    });

    Ok((local_addr, endpoint))
}
