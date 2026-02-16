//! One-shot bootstrap sync for invite acceptance.
//!
//! When accepting an invite, the joiner needs prerequisite events (workspace,
//! invite) from the inviter before calling `accept_user_invite`. This module
//! provides a helper that connects to the bootstrap address from the invite
//! link, runs a single negentropy sync session, and returns.

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::info;

use crate::db::{open_connection, schema::create_tables};
use crate::sync::engine::run_sync_initiator_dual;
use crate::sync::SyncMessage;
use crate::transport::{
    create_dual_endpoint, AllowedPeers, DualConnection, peer_identity_from_connection,
};
use crate::transport_identity::ensure_transport_cert_from_db;

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
