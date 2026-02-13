//! Multi-tenant node daemon.
//!
//! Discovers local tenant identities from the DB (trust_anchors JOIN
//! local_transport_creds), creates one QUIC endpoint per tenant with
//! dynamic trust, and routes all incoming events through a single
//! shared batch_writer.
//!
//! When the `discovery` feature is enabled, each tenant also advertises
//! via mDNS and auto-connects to discovered remote peers.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{info, warn, error};

use crate::db::{open_connection, schema::create_tables};
use crate::db::transport_creds::discover_local_tenants;
use crate::db::transport_trust::is_peer_allowed;
use crate::sync::engine::{IngestItem, accept_loop_with_ingest, batch_writer};
use crate::transport::{
    AllowedPeers, create_dual_endpoint_dynamic, extract_spki_fingerprint,
};

/// Run the multi-tenant node.
///
/// Discovers all local identities from the DB, verifies their SPKI fingerprints,
/// creates one QUIC endpoint per tenant, and runs accept loops sharing a single
/// batch_writer thread. With `discovery` feature, also advertises via mDNS and
/// auto-connects to discovered peers.
pub async fn run_node(
    db_path: &str,
    bind_ip: IpAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let tenants = discover_local_tenants(&db)?;
    drop(db);

    if tenants.is_empty() {
        return Err(
            "No local identities found. Bootstrap a workspace or accept an invite first.".into(),
        );
    }

    info!("Discovered {} local tenant(s)", tenants.len());

    // Collect all local peer_ids for mDNS self-filtering
    let _local_peer_ids: HashSet<String> = tenants.iter().map(|t| t.peer_id.clone()).collect();

    // Shared batch_writer: single writer thread for all tenants.
    let ingest_cap = if tenants.len() > 1 { 10000 } else { 5000 };
    let (shared_tx, shared_rx) = mpsc::channel::<IngestItem>(ingest_cap);
    let events_received = Arc::new(AtomicU64::new(0));
    let writer_events = events_received.clone();
    let writer_db = db_path.to_string();
    let _writer_handle = std::thread::spawn(move || {
        batch_writer(writer_db, shared_rx, writer_events);
    });

    let mut handles = Vec::new();
    // Keep discovery handles alive so mDNS services stay registered
    #[cfg(feature = "discovery")]
    let mut _discovery_handles: Vec<crate::discovery::TenantDiscovery> = Vec::new();

    for tenant in tenants {
        // Verify SPKI fingerprint matches peer_id
        let fp = match extract_spki_fingerprint(&tenant.cert_der) {
            Ok(fp) => fp,
            Err(e) => {
                error!(
                    "Failed to extract SPKI fingerprint for tenant {}: {}",
                    tenant.peer_id, e
                );
                continue;
            }
        };
        let expected_peer_id = hex::encode(fp);
        if expected_peer_id != tenant.peer_id {
            error!(
                "SPKI mismatch for tenant {}: cert yields {}",
                tenant.peer_id, expected_peer_id
            );
            continue;
        }

        // Build per-tenant dynamic trust closure
        let db_path_trust = db_path.to_string();
        let recorded_by = tenant.peer_id.clone();
        let empty_cli_pins = AllowedPeers::from_hex_strings(&[] as &[String])?;
        let dynamic_allow: Arc<
            dyn Fn(&[u8; 32]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
                + Send
                + Sync,
        > = Arc::new(move |peer_fp: &[u8; 32]| {
            let db = open_connection(&db_path_trust)?;
            is_peer_allowed(&db, &recorded_by, peer_fp, &empty_cli_pins)
        });

        // Create QUIC endpoint with auto-assigned port
        let bind_addr = std::net::SocketAddr::new(bind_ip, 0);
        let cert_der =
            rustls::pki_types::CertificateDer::from(tenant.cert_der);
        let key_der =
            rustls::pki_types::PrivatePkcs8KeyDer::from(tenant.key_der);

        let endpoint = match create_dual_endpoint_dynamic(bind_addr, cert_der, key_der, dynamic_allow) {
            Ok(ep) => ep,
            Err(e) => {
                error!(
                    "Failed to create endpoint for tenant {}: {}",
                    tenant.peer_id, e
                );
                continue;
            }
        };

        let local_addr = endpoint.local_addr().unwrap_or(bind_addr);
        let _actual_port = local_addr.port();
        info!(
            "Tenant {} (workspace {}) listening on {}",
            &tenant.peer_id[..16],
            &tenant.workspace_id[..16.min(tenant.workspace_id.len())],
            local_addr
        );

        // mDNS: advertise this tenant and browse for remote peers
        #[cfg(feature = "discovery")]
        {
            match crate::discovery::TenantDiscovery::new(
                &tenant.peer_id,
                _actual_port,
                _local_peer_ids.clone(),
            ) {
                Ok(disc) => {
                    // Start browsing and spawn connect_loop for discovered peers
                    match disc.browse() {
                        Ok(rx) => {
                            let ep_clone = endpoint.clone();
                            let db_path_disc = db_path.to_string();
                            let tenant_id = tenant.peer_id.clone();
                            std::thread::spawn(move || {
                                // Each discovered peer gets its own thread+runtime
                                // because connect_loop uses LocalSet (not Send).
                                while let Ok(peer) = rx.recv() {
                                    info!(
                                        "mDNS: tenant {} connecting to discovered peer {} at {}",
                                        &tenant_id[..16], &peer.peer_id[..16.min(peer.peer_id.len())], peer.addr
                                    );
                                    let ep = ep_clone.clone();
                                    let db = db_path_disc.clone();
                                    let tid = tenant_id.clone();
                                    std::thread::spawn(move || {
                                        let rt = tokio::runtime::Builder::new_current_thread()
                                            .enable_all()
                                            .build()
                                            .unwrap();
                                        rt.block_on(async move {
                                            let _ = crate::sync::engine::connect_loop(
                                                &db, &tid, ep, peer.addr, None,
                                            )
                                            .await;
                                        });
                                    });
                                }
                            });
                        }
                        Err(e) => warn!("mDNS browse failed for {}: {}", &tenant.peer_id[..16], e),
                    }
                    _discovery_handles.push(disc);
                }
                Err(e) => warn!("mDNS registration failed for {}: {}", &tenant.peer_id[..16], e),
            }
        }

        // Spawn accept loop for this tenant
        let db_path_owned = db_path.to_string();
        let tenant_peer_id = tenant.peer_id.clone();
        let ingest_tx = shared_tx.clone();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = accept_loop_with_ingest(
                    &db_path_owned,
                    &tenant_peer_id,
                    endpoint,
                    None, // dynamic trust is in the endpoint config
                    ingest_tx,
                )
                .await
                {
                    warn!("accept_loop for tenant {} exited: {}", tenant_peer_id, e);
                }
            });
        });
        handles.push(handle);
    }

    // Drop our copy so writer exits when all accept loops drop theirs
    drop(shared_tx);

    // Wait for Ctrl-C
    tokio::signal::ctrl_c().await?;
    info!(
        "Shutting down node ({} events received)",
        events_received.load(Ordering::Relaxed)
    );

    // Endpoints will be dropped when threads exit
    Ok(())
}
