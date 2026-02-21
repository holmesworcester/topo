//! Bootstrap autodial refresher and invite-based autodial target resolution.
//!
//! Periodically polls the database for invite bootstrap addresses (materialized
//! by InviteAccepted projection) and spawns connect_loop threads for newly
//! discovered targets. This is the primary mechanism for bootstrap sync:
//! no one-shot service-level bootstrap sync is needed.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::{PeerFingerprint, TenantId, TrustDecision};
use crate::db::transport_creds::{list_local_peers, load_local_creds};
use crate::db::transport_trust::list_active_invite_bootstrap_addrs;
use crate::db::open_connection;
use crate::event_modules::workspace::invite_link::parse_bootstrap_address;
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
            match parse_bootstrap_address(&addr_text)
                .and_then(|addr| addr.to_socket_addr())
            {
                Ok(addr) => {
                    let key = (tenant_id.clone(), addr);
                    if seen.insert(key.clone()) {
                        out.push(key);
                    }
                }
                Err(e) => {
                    warn!(
                        "Skipping invalid/unresolvable invite bootstrap_addr '{}' for tenant {}: {}",
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

/// Spawns a background thread that polls for new bootstrap autodial targets
/// every second and starts connect loops for them. This is the primary
/// mechanism by which the runtime discovers and connects to bootstrap peers
/// after an invite is accepted (projection materializes trust rows → autodial
/// picks them up → connect loop syncs prerequisites).
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
                                "Skipping bootstrap autodial refresh for {}: {}",
                                &tenant_id[..16.min(tenant_id.len())],
                                e
                            );
                            continue;
                        }
                    };
                    info!(
                        "BOOTSTRAP AUTODIAL REFRESH: tenant {} dialing invite bootstrap {}",
                        &tenant_id[..16.min(tenant_id.len())],
                        remote
                    );
                    spawn_connect_loop_thread(
                        db_path.clone(),
                        tenant_id,
                        endpoint.clone(),
                        remote,
                        cfg,
                        "bootstrap-autodial-refresh",
                        intro_spawner,
                        ingest,
                    );
                }
            }
            Err(e) => warn!("BOOTSTRAP AUTODIAL REFRESH failed: {}", e),
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    });
}

#[cfg(test)]
mod tests {
    use super::load_placeholder_invite_autodial_targets;
    use crate::db::open_connection;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::db::transport_trust;

    /// After invite_bootstrap_trust rows exist (materialized by projection),
    /// `list_active_invite_bootstrap_addrs` must find the address and
    /// `is_peer_allowed` must allow the SPKI. This is what the autodial
    /// refresher polls to discover bootstrap targets.
    #[test]
    fn test_autodial_targets_from_bootstrap_trust_rows() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let recorded_by = "test-peer-1";

        let bootstrap_spki: [u8; 32] = [0xCC; 32];
        let bootstrap_addr = "192.168.1.100:4433";

        // Simulate what projection does: write invite_bootstrap_trust row directly
        // (in production, this is done by the WriteAcceptedBootstrapTrust emit command
        // triggered by InviteAccepted projection).
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia-eid-1",
            "invite-eid-1",
            "ws-1",
            bootstrap_addr,
            &bootstrap_spki,
        ).unwrap();

        // Autodial target must be discoverable
        let addrs = transport_trust::list_active_invite_bootstrap_addrs(&conn, recorded_by)
            .unwrap();
        assert_eq!(addrs.len(), 1, "must find one bootstrap addr");
        assert_eq!(addrs[0], bootstrap_addr);

        // Trust oracle must allow the bootstrap SPKI for connect to succeed
        assert!(
            transport_trust::is_peer_allowed(&conn, recorded_by, &bootstrap_spki).unwrap(),
            "bootstrap SPKI must be allowed for TLS handshake"
        );
    }

    /// After supersession, bootstrap trust rows must not appear in autodial targets.
    #[test]
    fn test_autodial_targets_cleared_after_supersession() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let recorded_by = "test-peer-2";

        let peer_pub: [u8; 32] = [0xDD; 32];
        let bootstrap_spki = crate::transport::cert::spki_fingerprint_from_ed25519_pubkey(&peer_pub);
        let bootstrap_addr = "10.0.0.1:5555";

        // Write bootstrap trust
        transport_trust::record_invite_bootstrap_trust(
            &conn, recorded_by, "ia-2", "inv-2", "ws-2", bootstrap_addr, &bootstrap_spki,
        ).unwrap();

        // Verify it's visible
        assert_eq!(
            transport_trust::list_active_invite_bootstrap_addrs(&conn, recorded_by).unwrap().len(),
            1
        );

        // Supersede (simulating PeerShared projection)
        transport_trust::supersede_bootstrap_for_peer_shared(&conn, recorded_by, &peer_pub)
            .unwrap();

        // Must be gone from autodial targets
        assert_eq!(
            transport_trust::list_active_invite_bootstrap_addrs(&conn, recorded_by).unwrap().len(),
            0,
            "superseded bootstrap trust must not appear in autodial"
        );
    }

    #[test]
    fn test_autodial_targets_resolve_hostname_bootstrap_addr() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("autodial-hostname.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();
        let recorded_by = "test-peer-hostname";

        let bootstrap_spki: [u8; 32] = [0xAB; 32];
        transport_trust::record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia-host",
            "inv-host",
            "ws-host",
            "localhost:4433",
            &bootstrap_spki,
        )
        .unwrap();
        drop(conn);

        let targets = load_placeholder_invite_autodial_targets(
            db_path.to_str().unwrap(),
            &[recorded_by.to_string()],
        )
        .unwrap();

        assert_eq!(targets.len(), 1, "hostname bootstrap should resolve");
        assert_eq!(targets[0].0, recorded_by);
        assert_eq!(targets[0].1.port(), 4433);
    }
}
