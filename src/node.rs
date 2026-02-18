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

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::upnp::UpnpMappingReport;

/// Runtime networking information collected during node startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRuntimeNetInfo {
    /// Actual bound listen address (after OS port assignment).
    pub listen_addr: String,
    /// UPnP port mapping attempt result (None until `topo upnp` is run).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upnp: Option<UpnpMappingReport>,
}

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
        Self {
            known: HashMap::new(),
        }
    }

    /// Evaluate a discovery event. Returns the action to take and (for Connect/Reconnect)
    /// a watch::Receiver that will be signalled when this entry is superseded.
    fn dispatch(
        &mut self,
        peer_id: &str,
        addr: SocketAddr,
    ) -> (DiscoveryAction, Option<tokio::sync::watch::Receiver<()>>) {
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

use crate::contracts::network_contract::{PeerFingerprint, TenantId, TrustDecision};
use crate::db::transport_creds::{discover_local_tenants, list_local_peers, load_local_creds};
use crate::db::transport_trust::list_active_invite_bootstrap_addrs;
use crate::db::{open_connection, schema::create_tables};
use crate::event_runtime::{batch_writer, IngestItem};
use crate::sync::engine::accept_loop_with_ingest;
use crate::transport::{
    create_single_port_endpoint, extract_spki_fingerprint,
    multi_workspace::{workspace_sni, WorkspaceCertResolver},
    workspace_client_config, DynamicAllowFn, SqliteTrustOracle,
};
use rustls::sign::CertifiedKey;

fn normalize_discovered_addr_for_local_bind(
    local_listen_ip: std::net::IpAddr,
    discovered: SocketAddr,
) -> SocketAddr {
    if local_listen_ip.is_loopback() && !discovered.ip().is_loopback() {
        match discovered {
            SocketAddr::V4(v4) => SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                v4.port(),
            ),
            SocketAddr::V6(v6) => SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                v6.port(),
            ),
        }
    } else {
        discovered
    }
}

fn spawn_connect_loop_thread(
    db_path: String,
    tenant_id: String,
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
    cfg: quinn::ClientConfig,
    source: &'static str,
) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            if let Err(e) =
                crate::sync::engine::connect_loop(&db_path, &tenant_id, endpoint, remote, Some(cfg))
                    .await
            {
                warn!(
                    "{} connect_loop for {} to {} exited: {}",
                    source,
                    &tenant_id[..16.min(tenant_id.len())],
                    remote,
                    e
                );
            }
        });
    });
}

/// Placeholder autodial source from accepted invite metadata.
///
/// This is intentionally minimal and temporary for realism test scaffolding.
/// It should be replaced by a unified persistent peer address manager.
fn load_placeholder_invite_autodial_targets(
    db_path: &str,
    tenant_ids: &[String],
) -> Result<Vec<(String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let mut seen: HashSet<(String, SocketAddr)> = HashSet::new();
    let mut out = Vec::new();
    for tenant_id in tenant_ids {
        for addr_text in list_active_invite_bootstrap_addrs(&db, tenant_id)? {
            match addr_text.parse::<SocketAddr>() {
                Ok(addr) => {
                    let key = (tenant_id.clone(), addr);
                    if seen.insert(key.clone()) {
                        out.push(key);
                    }
                }
                Err(e) => {
                    warn!(
                        "Skipping invalid invite bootstrap_addr '{}' for tenant {}: {}",
                        addr_text,
                        &tenant_id[..16.min(tenant_id.len())],
                        e
                    );
                }
            }
        }
    }
    Ok(out)
}

fn collect_placeholder_invite_autodial_targets(
    db_path: &str,
) -> Result<Vec<(String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let tenant_ids = list_local_peers(&db)?;
    drop(db);
    load_placeholder_invite_autodial_targets(db_path, &tenant_ids)
}

fn build_tenant_client_config(
    db_path: &str,
    tenant_id: &str,
) -> Result<quinn::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let (cert_der, key_der) = load_local_creds(&db, tenant_id)?
        .ok_or_else(|| format!("local creds missing for tenant {}", tenant_id))?;
    drop(db);

    let cert_der = rustls::pki_types::CertificateDer::from(cert_der);
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der);
    let oracle = SqliteTrustOracle::new(db_path);
    let tid = TenantId(tenant_id.to_string());
    let tenant_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
        match oracle.check_sync(&tid, &PeerFingerprint(*peer_fp)) {
            Ok(TrustDecision::Allow) => Ok(true),
            Ok(TrustDecision::Deny) => Ok(false),
            Err(e) => Err(e.to_string().into()),
        }
    });
    workspace_client_config(cert_der, key_der, tenant_allow)
}

fn spawn_placeholder_autodial_refresher(
    db_path: String,
    endpoint: quinn::Endpoint,
    mut launched: HashSet<(String, SocketAddr)>,
) {
    std::thread::spawn(move || loop {
        match collect_placeholder_invite_autodial_targets(&db_path) {
            Ok(targets) => {
                for (tenant_id, remote) in targets {
                    let key = (tenant_id.clone(), remote);
                    if !launched.insert(key) {
                        continue;
                    }
                    let cfg = match build_tenant_client_config(&db_path, &tenant_id) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(
                                "Skipping placeholder autodial refresh for {}: {}",
                                &tenant_id[..16.min(tenant_id.len())],
                                e
                            );
                            continue;
                        }
                    };
                    info!(
                        "PLACEHOLDER AUTODIAL REFRESH: tenant {} dialing invite bootstrap {}",
                        &tenant_id[..16.min(tenant_id.len())],
                        remote
                    );
                    spawn_connect_loop_thread(
                        db_path.clone(),
                        tenant_id,
                        endpoint.clone(),
                        remote,
                        cfg,
                        "placeholder-autodial-refresh",
                    );
                }
            }
            Err(e) => warn!("PLACEHOLDER AUTODIAL REFRESH failed: {}", e),
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    });
}

/// Run the sync node.
///
/// Discovers all local identities from the DB, verifies their SPKI fingerprints,
/// builds a single QUIC endpoint with multi-workspace cert resolver, and runs
/// a single accept loop sharing a batch_writer thread. With `discovery` feature,
/// also advertises via mDNS and auto-connects to discovered peers.
///
/// If `net_info_tx` is provided, runtime networking info (listen addr + UPnP
/// result) is sent as soon as the endpoint is bound and UPnP is attempted.
pub async fn run_node(
    db_path: &str,
    bind: SocketAddr,
    net_info_tx: Option<tokio::sync::oneshot::Sender<NodeRuntimeNetInfo>>,
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
    let mut default_cert: Option<(
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivatePkcs8KeyDer<'static>,
    )> = None;

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

    let (default_cert_der, default_key_der) = default_cert.ok_or("No valid tenant certs found")?;

    // Union trust closure for inbound (server) connections: accept if ANY tenant trusts
    // the remote. Per-tenant outbound trust is handled by tenant_client_configs below.
    let trust_oracle = SqliteTrustOracle::new(db_path);
    let tenant_peer_ids: Vec<String> = tenants.iter().map(|t| t.peer_id.clone()).collect();
    let dynamic_allow: Arc<
        dyn Fn(&[u8; 32]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    > = Arc::new(move |peer_fp: &[u8; 32]| {
        for tenant_id in &tenant_peer_ids {
            match trust_oracle.check_sync(&TenantId(tenant_id.clone()), &PeerFingerprint(*peer_fp))
            {
                Ok(TrustDecision::Allow) => return Ok(true),
                Ok(TrustDecision::Deny) => {}
                Err(e) => return Err(e.to_string().into()),
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

    // Send runtime networking info back to caller (e.g. DaemonState in main.rs).
    if let Some(tx) = net_info_tx {
        let info = NodeRuntimeNetInfo {
            listen_addr: local_addr.to_string(),
            upnp: None,
        };
        let _ = tx.send(info);
    }

    // Per-tenant outbound client configs: each presents the tenant's own cert
    // and verifies remote peers against that tenant's trust set only.
    let mut tenant_client_configs: HashMap<String, quinn::ClientConfig> = HashMap::new();
    for tenant in &tenants {
        let cert_der = rustls::pki_types::CertificateDer::from(tenant.cert_der.clone());
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(tenant.key_der.clone());
        let oracle = SqliteTrustOracle::new(db_path);
        let tid = TenantId(tenant.peer_id.clone());
        let tenant_allow: Arc<DynamicAllowFn> = Arc::new(move |peer_fp: &[u8; 32]| {
            match oracle.check_sync(&tid, &PeerFingerprint(*peer_fp)) {
                Ok(TrustDecision::Allow) => Ok(true),
                Ok(TrustDecision::Deny) => Ok(false),
                Err(e) => Err(e.to_string().into()),
            }
        });
        match workspace_client_config(cert_der, key_der, tenant_allow) {
            Ok(cfg) => {
                tenant_client_configs.insert(tenant.peer_id.clone(), cfg);
            }
            Err(e) => warn!(
                "Failed to build client config for {}: {}",
                &tenant.peer_id[..16],
                e
            ),
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
        // Derive an explicit advertise IP for mDNS from the bind address.
        //
        // mDNS multicast requires a routable (non-loopback) IP for peer
        // discovery to work — advertising 127.0.0.1 is not discoverable.
        // For loopback and wildcard binds, infer a routable IP from the
        // host's network interfaces. The browse side compensates via
        // `normalize_discovered_addr_for_local_bind`, which rewrites
        // discovered non-loopback addresses back to loopback when the
        // local daemon is bound to loopback.
        let advertise_ip = if local_addr.ip().is_unspecified() || local_addr.ip().is_loopback() {
            crate::discovery::local_non_loopback_ipv4().unwrap_or_else(|| "0.0.0.0".to_string())
        } else {
            local_addr.ip().to_string()
        };
        let local_listen_ip = local_addr.ip();
        for tenant in &tenants {
            match crate::discovery::TenantDiscovery::new(
                &tenant.peer_id,
                actual_port,
                _local_peer_ids.clone(),
                &advertise_ip,
            ) {
                Ok(disc) => {
                    match disc.browse() {
                        Ok(rx) => {
                            let ep_clone = endpoint.clone();
                            let db_path_disc = db_path.to_string();
                            let tenant_id = tenant.peer_id.clone();
                            let local_listen_ip_for_thread = local_listen_ip;
                            let disc_client_cfg =
                                match tenant_client_configs.get(&tenant.peer_id).cloned() {
                                    Some(c) => c,
                                    None => {
                                        warn!(
                                            "Skipping mDNS browse for {}: no client config",
                                            &tenant.peer_id[..16]
                                        );
                                        _discovery_handles.push(disc);
                                        continue;
                                    }
                                };
                            std::thread::spawn(move || {
                                let mut dispatcher = PeerDispatcher::new();
                                while let Ok(peer) = rx.recv() {
                                    let dial_addr = normalize_discovered_addr_for_local_bind(
                                        local_listen_ip_for_thread,
                                        peer.addr,
                                    );
                                    let (action, cancel_rx) =
                                        dispatcher.dispatch(&peer.peer_id, dial_addr);
                                    match action {
                                        DiscoveryAction::Skip => continue,
                                        DiscoveryAction::Reconnect => {
                                            info!(
                                                "mDNS: tenant {} peer {} addr changed, reconnecting at {}",
                                                &tenant_id[..16],
                                                &peer.peer_id[..16.min(peer.peer_id.len())],
                                                dial_addr
                                            );
                                        }
                                        DiscoveryAction::Connect => {
                                            info!(
                                                "mDNS: tenant {} connecting to discovered peer {} at {}",
                                                &tenant_id[..16],
                                                &peer.peer_id[..16.min(peer.peer_id.len())],
                                                dial_addr
                                            );
                                        }
                                    }
                                    let mut cancel = cancel_rx.unwrap();
                                    let ep = ep_clone.clone();
                                    let db = db_path_disc.clone();
                                    let tid = tenant_id.clone();
                                    let cfg = Some(disc_client_cfg.clone());
                                    std::thread::spawn(move || {
                                        let rt = tokio::runtime::Builder::new_current_thread()
                                            .enable_all()
                                            .build()
                                            .unwrap();
                                        rt.block_on(async move {
                                            tokio::select! {
                                                _ = crate::sync::engine::connect_loop(
                                                    &db, &tid, ep, dial_addr, cfg,
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
                Err(e) => warn!(
                    "mDNS registration failed for {}: {}",
                    &tenant.peer_id[..16],
                    e
                ),
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
    let accept_configs = tenant_client_configs.clone();
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
                accept_configs,
            )
            .await
            {
                warn!("accept_loop exited: {}", e);
            }
        });
    });

    // Placeholder invite-based autodial source for realism tests.
    // This is intentionally narrow and should be replaced by a unified
    // persistent address manager that merges invite, discovery, and intro data.
    let disable_placeholder_autodial = std::env::var("P7_DISABLE_PLACEHOLDER_AUTODIAL")
        .ok()
        .map(|v| {
            let lowered = v.to_ascii_lowercase();
            lowered == "1" || lowered == "true" || lowered == "yes"
        })
        .unwrap_or(false);
    if disable_placeholder_autodial {
        warn!("PLACEHOLDER AUTODIAL DISABLED by P7_DISABLE_PLACEHOLDER_AUTODIAL");
    } else {
        let autodial_targets = collect_placeholder_invite_autodial_targets(db_path)?;
        let mut launched_autodial: HashSet<(String, SocketAddr)> = HashSet::new();
        if !autodial_targets.is_empty() {
            warn!(
                "PLACEHOLDER AUTODIAL ENABLED: launching {} invite-seeded outbound dial(s)",
                autodial_targets.len()
            );
        }
        for (tenant_id, remote) in autodial_targets {
            launched_autodial.insert((tenant_id.clone(), remote));
            let cfg = match build_tenant_client_config(db_path, &tenant_id) {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        "Skipping placeholder autodial for {}: {}",
                        &tenant_id[..16.min(tenant_id.len())],
                        e
                    );
                    continue;
                }
            };
            info!(
                "PLACEHOLDER AUTODIAL: tenant {} dialing invite bootstrap {}",
                &tenant_id[..16.min(tenant_id.len())],
                remote
            );
            spawn_connect_loop_thread(
                db_path.to_string(),
                tenant_id,
                connect_endpoint.clone(),
                remote,
                cfg,
                "placeholder-autodial",
            );
        }
        // Keep polling for runtime invite acceptance: this allows daemons to pick up
        // new invite bootstrap targets without restart.
        spawn_placeholder_autodial_refresher(
            db_path.to_string(),
            connect_endpoint.clone(),
            launched_autodial,
        );
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

    #[test]
    fn test_normalize_discovered_addr_for_loopback_bind_rewrites_ipv4() {
        let local_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let discovered: SocketAddr = "192.168.10.42:4455".parse().unwrap();
        let out = normalize_discovered_addr_for_local_bind(local_ip, discovered);
        assert_eq!(out, "127.0.0.1:4455".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_normalize_discovered_addr_for_non_loopback_bind_keeps_addr() {
        let local_ip: std::net::IpAddr = "192.168.10.10".parse().unwrap();
        let discovered: SocketAddr = "192.168.10.42:4455".parse().unwrap();
        let out = normalize_discovered_addr_for_local_bind(local_ip, discovered);
        assert_eq!(out, discovered);
    }
}
