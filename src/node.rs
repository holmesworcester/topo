//! Multi-tenant node daemon.
//!
//! Discovers local tenant identities from the DB (trust_anchors JOIN
//! local_transport_creds), creates one QUIC endpoint per tenant with
//! dynamic trust, and routes all incoming events through a single
//! shared batch_writer.
//!
//! When the `discovery` feature is enabled, each tenant also advertises
//! via mDNS and auto-connects to discovered remote peers.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{info, warn, error};

/// Dispatch decision for a discovered peer.
#[derive(Debug, PartialEq)]
enum DiscoveryAction {
    /// Same peer at same address — skip (dedupe).
    Skip,
    /// New peer — spawn connect_loop.
    Connect,
    /// Known peer at new address — cancel old loop, spawn new one.
    Reconnect,
}

/// Tracks discovered peers and manages cancellation of stale connect_loops.
/// Extracted for testability.
struct PeerDispatcher {
    known: HashMap<String, (SocketAddr, tokio::sync::watch::Sender<()>)>,
}

impl PeerDispatcher {
    fn new() -> Self {
        Self { known: HashMap::new() }
    }

    /// Evaluate a discovery event. Returns the action to take and (for Connect/Reconnect)
    /// a watch::Receiver that will be signalled when this entry is superseded.
    fn dispatch(&mut self, peer_id: &str, addr: SocketAddr) -> (DiscoveryAction, Option<tokio::sync::watch::Receiver<()>>) {
        if let Some((prev_addr, _)) = self.known.get(peer_id) {
            if *prev_addr == addr {
                return (DiscoveryAction::Skip, None);
            }
        }
        let action = if self.known.contains_key(peer_id) {
            DiscoveryAction::Reconnect
        } else {
            DiscoveryAction::Connect
        };
        // Drop old sender (if any) to cancel the old connect_loop
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(());
        self.known.insert(peer_id.to_string(), (addr, cancel_tx));
        (action, Some(cancel_rx))
    }
}

use crate::db::{open_connection, schema::create_tables};
use crate::db::transport_creds::discover_local_tenants;
use crate::db::transport_trust::is_peer_allowed;
use crate::sync::engine::{IngestItem, accept_loop_with_ingest, batch_writer};
use crate::transport::{
    create_dual_endpoint_dynamic, extract_spki_fingerprint,
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
        let dynamic_allow: Arc<
            dyn Fn(&[u8; 32]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
                + Send
                + Sync,
        > = Arc::new(move |peer_fp: &[u8; 32]| {
            let db = open_connection(&db_path_trust)?;
            is_peer_allowed(&db, &recorded_by, peer_fp)
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
                                let mut dispatcher = PeerDispatcher::new();
                                while let Ok(peer) = rx.recv() {
                                    let (action, cancel_rx) = dispatcher.dispatch(&peer.peer_id, peer.addr);
                                    match action {
                                        DiscoveryAction::Skip => continue,
                                        DiscoveryAction::Reconnect => {
                                            info!(
                                                "mDNS: tenant {} peer {} addr changed, reconnecting at {}",
                                                &tenant_id[..16],
                                                &peer.peer_id[..16.min(peer.peer_id.len())],
                                                peer.addr
                                            );
                                        }
                                        DiscoveryAction::Connect => {
                                            info!(
                                                "mDNS: tenant {} connecting to discovered peer {} at {}",
                                                &tenant_id[..16],
                                                &peer.peer_id[..16.min(peer.peer_id.len())],
                                                peer.addr
                                            );
                                        }
                                    }
                                    let mut cancel = cancel_rx.unwrap();
                                    let ep = ep_clone.clone();
                                    let db = db_path_disc.clone();
                                    let tid = tenant_id.clone();
                                    std::thread::spawn(move || {
                                        let rt = tokio::runtime::Builder::new_current_thread()
                                            .enable_all()
                                            .build()
                                            .unwrap();
                                        rt.block_on(async move {
                                            tokio::select! {
                                                _ = crate::sync::engine::connect_loop(
                                                    &db, &tid, ep, peer.addr,
                                                ) => {}
                                                _ = cancel.changed() => {}
                                            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse().unwrap(), port)
    }

    #[test]
    fn test_dispatch_new_peer_returns_connect() {
        let mut d = PeerDispatcher::new();
        let (action, rx) = d.dispatch("peer-a", addr(1000));
        assert_eq!(action, DiscoveryAction::Connect);
        assert!(rx.is_some(), "should return cancel receiver");
    }

    #[test]
    fn test_dispatch_same_addr_returns_skip() {
        let mut d = PeerDispatcher::new();
        d.dispatch("peer-a", addr(1000));

        let (action, rx) = d.dispatch("peer-a", addr(1000));
        assert_eq!(action, DiscoveryAction::Skip);
        assert!(rx.is_none());
    }

    #[test]
    fn test_dispatch_different_addr_returns_reconnect() {
        let mut d = PeerDispatcher::new();
        d.dispatch("peer-a", addr(1000));

        let (action, rx) = d.dispatch("peer-a", addr(2000));
        assert_eq!(action, DiscoveryAction::Reconnect);
        assert!(rx.is_some());
    }

    #[test]
    fn test_dispatch_addr_change_cancels_old_receiver() {
        let mut d = PeerDispatcher::new();
        let (_, old_rx) = d.dispatch("peer-a", addr(1000));
        let mut old_rx = old_rx.unwrap();

        // Address changes — old sender should be dropped
        let (action, _new_rx) = d.dispatch("peer-a", addr(2000));
        assert_eq!(action, DiscoveryAction::Reconnect);

        // Old receiver should detect sender was dropped (changed returns Err)
        // Use a runtime to check the async method
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let result = old_rx.changed().await;
            assert!(result.is_err(), "old receiver should see sender dropped");
        });
    }

    #[test]
    fn test_dispatch_repeated_churn_only_one_active() {
        let mut d = PeerDispatcher::new();
        let mut receivers = Vec::new();

        // Simulate 10 address changes for the same peer
        for port in 1000..1010 {
            let (action, rx) = d.dispatch("peer-a", addr(port));
            assert_ne!(action, DiscoveryAction::Skip);
            if let Some(rx) = rx {
                receivers.push(rx);
            }
        }

        // Only the last receiver should be live (sender not dropped)
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // All but the last should be cancelled
            for mut rx in receivers.drain(..receivers.len() - 1) {
                let result = rx.changed().await;
                assert!(result.is_err(), "old receiver should be cancelled");
            }
        });

        // Exactly one entry in the map
        assert_eq!(d.known.len(), 1);
        assert_eq!(d.known.get("peer-a").unwrap().0, addr(1009));
    }

    #[test]
    fn test_dispatch_multiple_peers_independent() {
        let mut d = PeerDispatcher::new();

        let (a1, _) = d.dispatch("peer-a", addr(1000));
        let (b1, _) = d.dispatch("peer-b", addr(2000));
        assert_eq!(a1, DiscoveryAction::Connect);
        assert_eq!(b1, DiscoveryAction::Connect);

        // Changing peer-a doesn't affect peer-b
        let (a2, _) = d.dispatch("peer-a", addr(1001));
        let (b2, _) = d.dispatch("peer-b", addr(2000));
        assert_eq!(a2, DiscoveryAction::Reconnect);
        assert_eq!(b2, DiscoveryAction::Skip);
    }
}
