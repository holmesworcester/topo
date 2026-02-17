//! One-shot bootstrap sync for invite acceptance.
//!
//! When accepting an invite, the joiner needs prerequisite events (workspace,
//! invite) from the inviter before calling `accept_user_invite`. This module
//! provides a helper that connects to the bootstrap address from the invite
//! link, runs a single negentropy sync session, and returns.

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tracing::info;

use crate::db::{open_connection, schema::create_tables};
use crate::sync::engine::run_sync_initiator_dual;
use crate::sync::SyncMessage;
use crate::transport::{
    create_dual_endpoint, AllowedPeers, DualConnection, peer_identity_from_connection,
};
use crate::transport_identity::{
    ensure_transport_cert_from_db, expected_invite_bootstrap_spki_from_invite_key,
};

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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Ensure DB is initialized
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    let (_peer_id, cert, key) = ensure_transport_cert_from_db(db_path)?;

    // Pin only the bootstrap peer's SPKI for this one-shot connection
    let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![*bootstrap_spki]));
    let endpoint = create_dual_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        cert,
        key,
        allowed,
    )?;

    info!(
        "Bootstrap sync: connecting to {} (spki {}...)",
        bootstrap_addr,
        hex::encode(&bootstrap_spki[..8])
    );

    let connection = endpoint
        .connect(bootstrap_addr, "localhost")?
        .await
        .map_err(|e| format!("Bootstrap sync: failed to connect to {}: {}", bootstrap_addr, e))?;

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

    let mut conn = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);

    // Send markers to materialize lazy QUIC streams on the receiver
    conn.control.send(&SyncMessage::HaveList { ids: vec![] }).await?;
    conn.data_send.send(&SyncMessage::HaveList { ids: vec![] }).await?;
    conn.flush_control().await?;
    conn.flush_data().await?;

    // Run one sync session
    let stats = run_sync_initiator_dual(
        conn,
        db_path,
        timeout_secs,
        &peer_id,
        recorded_by,
        None, // no coordinator
        None, // no shared ingest (uses internal batch_writer)
    )
    .await?;

    info!(
        "Bootstrap sync complete: {} events received, {} sent",
        stats.events_received, stats.events_sent
    );

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
) -> Result<(SocketAddr, quinn::Endpoint), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(inviter_db_path)?;
    let (_, cert, key) = crate::transport_identity::load_transport_cert_required(&db)?;

    let joiner_spki = expected_invite_bootstrap_spki_from_invite_key(invite_key)?;
    let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![joiner_spki]));

    let endpoint = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert,
        key,
        allowed,
    )?;
    let local_addr = endpoint.local_addr()?;

    let db_path = inviter_db_path.to_string();
    let recorded_by = inviter_identity.to_string();
    let ep = endpoint.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create bootstrap responder runtime");
        rt.block_on(async move {
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

                let peer_id = peer_identity_from_connection(&connection)
                    .unwrap_or_default();

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

                let db_path_ref = &db_path;
                let recorded_by_ref = &recorded_by;
                if let Err(e) = crate::sync::engine::run_sync_responder_dual(
                    conn, db_path_ref, 30, &peer_id, recorded_by_ref, None,
                ).await {
                    tracing::warn!("Bootstrap responder: sync error: {}", e);
                }
            }
        });
    });

    Ok((local_addr, endpoint))
}
