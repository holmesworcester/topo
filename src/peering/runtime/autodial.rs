//! Placeholder autodial refresher and invite-based autodial target resolution.
//!
//! Periodically polls the database for invite bootstrap addresses and
//! spawns connect_loop threads for newly discovered targets.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::{PeerFingerprint, TenantId, TrustDecision};
use crate::db::transport_creds::{list_local_peers, load_local_creds};
use crate::db::transport_trust::list_active_invite_bootstrap_addrs;
use crate::db::open_connection;
use crate::peering::loops::IntroSpawnerFn;
use crate::transport::{workspace_client_config, DynamicAllowFn, SqliteTrustOracle};

use super::peer_dispatch::spawn_connect_loop_thread;

/// Load invite-seeded autodial targets for a set of known tenant IDs.
pub(crate) fn load_placeholder_invite_autodial_targets(
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

pub(crate) fn collect_placeholder_invite_autodial_targets(
    db_path: &str,
) -> Result<Vec<(String, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    let tenant_ids = list_local_peers(&db)?;
    drop(db);
    load_placeholder_invite_autodial_targets(db_path, &tenant_ids)
}

pub(crate) fn build_tenant_client_config(
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

pub(crate) fn spawn_placeholder_autodial_refresher(
    db_path: String,
    endpoint: quinn::Endpoint,
    mut launched: HashSet<(String, SocketAddr)>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
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
                        intro_spawner,
                        ingest,
                    );
                }
            }
            Err(e) => warn!("PLACEHOLDER AUTODIAL REFRESH failed: {}", e),
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    });
}
