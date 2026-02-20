//! One-shot bootstrap sync for invite acceptance.
//!
//! When accepting an invite, the joiner needs prerequisite events (workspace,
//! invite) from the inviter before calling `accept_user_invite`. This module
//! provides a helper that connects to the bootstrap address from the invite
//! link, runs a single negentropy sync session, and returns.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::contracts::event_pipeline_contract::{BatchWriterFn, IngestItem};
use crate::contracts::peering_contract::{
    next_session_id, PeerFingerprint, SessionDirection, SessionHandler, SessionMeta, TenantId,
};
use crate::db::{open_connection, schema::create_tables};
use crate::sync::SyncSessionHandler;

use crate::transport::{
    create_dual_endpoint, peer_identity_from_connection, AllowedPeers, DualConnection,
    QuicTransportSessionIo,
};
use crate::identity::transport::{
    expected_invite_bootstrap_spki_from_invite_key, load_transport_cert_required_from_db,
};

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

/// Run a one-shot bootstrap sync from an invite link's bootstrap address.
///
/// Connects to `bootstrap_addr` using the local transport cert, with the
/// bootstrap peer's SPKI pinned as the only allowed peer. Runs a single
/// negentropy sync session to fetch shared events (workspace, invite, etc.),
/// then closes the connection and returns.
///
/// The caller should verify that the expected prerequisite events arrived
/// before proceeding with invite acceptance.
pub async fn bootstrap_sync_from_invite(
    db_path: &str,
    recorded_by: &str,
    bootstrap_addr: SocketAddr,
    bootstrap_spki: &[u8; 32],
    timeout_secs: u64,
    batch_writer: BatchWriterFn,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Ensure DB is initialized
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    let (_peer_id, cert, key) = load_transport_cert_required_from_db(db_path)?;

    // Pin only the bootstrap peer's SPKI for this one-shot connection
    let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![*bootstrap_spki]));
    let endpoint = create_dual_endpoint("0.0.0.0:0".parse().unwrap(), cert, key, allowed)?;

    info!(
        "Bootstrap sync: connecting to {} (spki {}...)",
        bootstrap_addr,
        hex::encode(&bootstrap_spki[..8])
    );

    let connection = endpoint
        .connect(bootstrap_addr, "localhost")?
        .await
        .map_err(|e| {
            format!(
                "Bootstrap sync: failed to connect to {}: {}",
                bootstrap_addr, e
            )
        })?;

    let peer_id = peer_identity_from_connection(&connection)
        .ok_or("Bootstrap sync: could not extract peer identity")?;

    info!("Bootstrap sync: connected to peer {}", &peer_id[..16]);

    // Open dual bi-directional streams (control + data)
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
    let handler = SyncSessionHandler::initiator(db_path.to_string(), timeout_secs, ingest_tx);
    let io = QuicTransportSessionIo::new(session_id, conn);
    handler
        .on_session(meta, Box::new(io), CancellationToken::new())
        .await
        .map_err(|e| format!("Bootstrap sync: {}", e))?;

    // Drop handler to close the ingest channel, then join the writer thread.
    drop(handler);
    let _ = writer_handle.join();

    info!("Bootstrap sync complete");

    // Close endpoint cleanly
    endpoint.close(0u32.into(), b"bootstrap done");
    endpoint.wait_idle().await;

    Ok(())
}

/// Start a temporary QUIC sync endpoint that serves one bootstrap connection.
///
/// The endpoint allows only the invitee's SPKI (derived from the invite key).
/// A sync responder runs on a separate thread (rusqlite is not Send), accepts
/// one connection, syncs, and exits. Returns the bound address and endpoint
/// handle — caller must close the endpoint when done.
///
/// Used by both interactive REPL and test helpers to let an in-process inviter
/// serve prerequisite events to a joiner via real QUIC sync.
pub fn start_bootstrap_responder(
    inviter_db_path: &str,
    inviter_identity: &str,
    invite_key: &SigningKey,
    batch_writer: BatchWriterFn,
) -> Result<(SocketAddr, quinn::Endpoint), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(inviter_db_path)?;
    let (_, cert, key) = crate::identity::transport::load_transport_cert_required(&db)?;

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
            let handler = SyncSessionHandler::responder(
                db_path.clone(),
                30,
                ingest_tx,
            );
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
