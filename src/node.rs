//! Multi-tenant node daemon.
//!
//! Discovers local tenant identities from the DB (trust_anchors JOIN
//! local_transport_creds), creates a single QUIC endpoint with a
//! multi-workspace cert resolver, and routes all incoming events
//! through a single shared batch_writer.
//!
//! The TLS handshake determines the workspace: clients send the
//! workspace SNI, and the server selects the matching cert via
//! `WorkspaceCertResolver`. Post-handshake, the peer's SPKI fingerprint
//! is checked against the trust set to determine the `recorded_by` tenant.
//!
//! When the `discovery` feature is enabled, each tenant also advertises
//! via mDNS and auto-connects to discovered remote peers.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
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
    create_single_port_endpoint, extract_spki_fingerprint,
    multi_workspace::{WorkspaceCertResolver, workspace_sni},
    workspace_client_config, DynamicAllowFn,
};
use rustls::sign::CertifiedKey;

/// Run the sync node.
///
/// Discovers all local identities from the DB, verifies their SPKI fingerprints,
/// builds a single QUIC endpoint with multi-workspace cert resolver, and runs
/// a single accept loop sharing a batch_writer thread. If `connect` is provided,
/// also spawns a connect_loop to the specified peer. With `discovery` feature,
/// also advertises via mDNS and auto-connects to discovered peers.
pub async fn run_node(
    db_path: &str,
    bind: SocketAddr,
    connect: Option<SocketAddr>,
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

    // Build multi-workspace cert resolver + tenant metadata
    let provider = rustls::crypto::ring::default_provider();
    let mut cert_resolver = WorkspaceCertResolver::new();
    // Map: peer_id → workspace_id (for post-handshake tenant resolution)
    let mut peer_to_workspace: HashMap<String, String> = HashMap::new();
    // Keep first tenant's cert/key for the default client config
    let mut default_cert: Option<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivatePkcs8KeyDer<'static>)> = None;

    for tenant in &tenants {
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

        let cert_der = rustls::pki_types::CertificateDer::from(tenant.cert_der.clone());
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(tenant.key_der.clone());

        // Build CertifiedKey for the resolver
        let ck = match CertifiedKey::from_der(
            vec![cert_der.clone()],
            key_der.clone_key().into(),
            &provider,
        ) {
            Ok(ck) => Arc::new(ck),
            Err(e) => {
                error!(
                    "Failed to create CertifiedKey for tenant {}: {}",
                    tenant.peer_id, e
                );
                continue;
            }
        };

        let sni = workspace_sni(&tenant.workspace_id);
        cert_resolver.add(sni.clone(), ck);
        peer_to_workspace.insert(tenant.peer_id.clone(), tenant.workspace_id.clone());

        if default_cert.is_none() {
            default_cert = Some((cert_der, key_der));
        }

        info!(
            "Registered tenant {} (workspace {}, sni={})",
            &tenant.peer_id[..16],
            &tenant.workspace_id[..16.min(tenant.workspace_id.len())],
            sni
        );
    }

    let (default_cert_der, default_key_der) = default_cert
        .ok_or("No valid tenant certs found")?;

    // Union trust closure for inbound (server) connections: accept if ANY tenant trusts
    // the remote. Per-tenant outbound trust is handled by tenant_client_configs below.
    let db_path_trust = db_path.to_string();
    let tenant_peer_ids: Vec<String> = tenants.iter().map(|t| t.peer_id.clone()).collect();
    let dynamic_allow: Arc<
        dyn Fn(&[u8; 32]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
            + Send
            + Sync,
    > = Arc::new(move |peer_fp: &[u8; 32]| {
        let db = open_connection(&db_path_trust)?;
        for tenant_id in &tenant_peer_ids {
            if is_peer_allowed(&db, tenant_id, peer_fp)? {
                return Ok(true);
            }
        }
        Ok(false)
    });

    // Create single QUIC endpoint
    let endpoint = create_single_port_endpoint(
        bind,
        Arc::new(cert_resolver),
        dynamic_allow,
        default_cert_der,
        default_key_der,
    )?;

    let local_addr = endpoint.local_addr().unwrap_or(bind);
    info!(
        "Node listening on {} ({} workspace(s))",
        local_addr,
        tenants.len()
    );

    // Per-tenant outbound client configs: each presents the tenant's own cert
    // and verifies remote peers against that tenant's trust set only.
    let mut tenant_client_configs: HashMap<String, quinn::ClientConfig> = HashMap::new();
    for tenant in &tenants {
        let cert_der = rustls::pki_types::CertificateDer::from(tenant.cert_der.clone());
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(tenant.key_der.clone());
        let db_path_t = db_path.to_string();
        let tid = tenant.peer_id.clone();
        let tenant_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
            let db = open_connection(&db_path_t)?;
            is_peer_allowed(&db, &tid, peer_fp)
        });
        match workspace_client_config(cert_der, key_der, tenant_allow) {
            Ok(cfg) => { tenant_client_configs.insert(tenant.peer_id.clone(), cfg); }
            Err(e) => warn!("Failed to build client config for {}: {}", &tenant.peer_id[..16], e),
        }
    }

    // Shared batch_writer: single writer thread for all tenants.
    let ingest_cap = if tenants.len() > 1 { 10000 } else { 5000 };
    let (shared_tx, shared_rx) = mpsc::channel::<IngestItem>(ingest_cap);
    let events_received = Arc::new(AtomicU64::new(0));
    let writer_events = events_received.clone();
    let writer_db = db_path.to_string();
    let _writer_handle = std::thread::spawn(move || {
        batch_writer(writer_db, shared_rx, writer_events);
    });

    // Keep discovery handles alive so mDNS services stay registered
    #[cfg(feature = "discovery")]
    let mut _discovery_handles: Vec<crate::discovery::TenantDiscovery> = Vec::new();

    // mDNS: advertise all tenants and browse for remote peers
    #[cfg(feature = "discovery")]
    {
        let actual_port = local_addr.port();
        // Skip mDNS auto-connect to the explicit --connect target to avoid
        // duplicate connections (POC replacement policy: no dual paths).
        let explicit_connect_addr = connect;
        for tenant in &tenants {
            match crate::discovery::TenantDiscovery::new(
                &tenant.peer_id,
                actual_port,
                _local_peer_ids.clone(),
            ) {
                Ok(disc) => {
                    match disc.browse() {
                        Ok(rx) => {
                            let ep_clone = endpoint.clone();
                            let db_path_disc = db_path.to_string();
                            let tenant_id = tenant.peer_id.clone();
                            let disc_client_cfg = tenant_client_configs.get(&tenant.peer_id).cloned();
                            std::thread::spawn(move || {
                                let mut dispatcher = PeerDispatcher::new();
                                while let Ok(peer) = rx.recv() {
                                    // Skip if this is the explicit --connect target
                                    if let Some(explicit) = explicit_connect_addr {
                                        if peer.addr == explicit {
                                            continue;
                                        }
                                    }
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
                                    let cfg = disc_client_cfg.clone();
                                    std::thread::spawn(move || {
                                        let rt = tokio::runtime::Builder::new_current_thread()
                                            .enable_all()
                                            .build()
                                            .unwrap();
                                        rt.block_on(async move {
                                            tokio::select! {
                                                _ = crate::sync::engine::connect_loop(
                                                    &db, &tid, ep, peer.addr, cfg,
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
    }

    // Clone endpoint before moving into accept thread (needed for connect_loop).
    let connect_endpoint = endpoint.clone();

    // Single accept loop for all workspaces.
    // Post-handshake, each connection is routed to the tenant that trusts
    // the remote peer's SPKI fingerprint.
    let all_tenant_ids: Vec<String> = tenants.iter().map(|t| t.peer_id.clone()).collect();
    let db_path_owned = db_path.to_string();
    let ingest_tx = shared_tx.clone();
    let accept_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) = accept_loop_with_ingest(
                &db_path_owned,
                &all_tenant_ids,
                endpoint,
                None,
                ingest_tx,
            )
            .await
            {
                warn!("accept_loop exited: {}", e);
            }
        });
    });

    // Explicit --connect target: spawn connect_loop for each tenant.
    if let Some(remote) = connect {
        for tenant in &tenants {
            let ep = connect_endpoint.clone();
            let db = db_path.to_string();
            let tid = tenant.peer_id.clone();
            let cfg = tenant_client_configs.get(&tenant.peer_id).cloned();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async move {
                    if let Err(e) = crate::sync::engine::connect_loop(&db, &tid, ep, remote, cfg).await
                    {
                        warn!("connect_loop for {} exited: {}", &tid[..16], e);
                    }
                });
            });
        }
    }

    // Drop our copy so writer exits when all accept loops drop theirs
    drop(shared_tx);

    // Wait for Ctrl-C
    tokio::signal::ctrl_c().await?;
    info!(
        "Shutting down ({} events received)",
        events_received.load(Ordering::Relaxed)
    );

    drop(accept_handle);
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
