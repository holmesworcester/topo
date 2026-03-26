//! Bootstrap-phase authentication helpers.
//!
//! Decides whether a tenant is still in bootstrap phase, classifies
//! discovery/observed-endpoint auth posture, and resolves active
//! bootstrap session fallbacks.

use crate::db::open_connection;
use crate::db::transport_creds::{resolve_tenant_transport_target, CRED_SOURCE_BOOTSTRAP};
use crate::db::transport_trust::is_peer_shared_transport_fingerprint;

use super::target_dispatch::{should_initiate_connect_for_source, TargetIngressSource};

// ---- Types ---------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BootstrapDiscoveryAuth {
    None,
    AcceptedDiscoveryAndObserved,
    AcceptedObservedOnly,
    PendingOnly,
    SteadyStateOrMixed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BootstrapSessionFallback {
    pub(super) daemon_peer_id: String,
    pub(super) invite_event_id: String,
}

// ---- Helpers -------------------------------------------------------------

pub(super) fn local_transport_target_is_bootstrap(
    conn: &rusqlite::Connection,
    tenant_id: &str,
) -> bool {
    resolve_tenant_transport_target(conn, tenant_id)
        .ok()
        .flatten()
        .map(|target| target.source == CRED_SOURCE_BOOTSTRAP)
        .unwrap_or(false)
}

/// Check whether a tenant is still in bootstrap phase (its local transport
/// credential comes from an invite rather than steady-state PeerShared).
pub(super) fn is_tenant_in_bootstrap_phase(db_path: &str, tenant_id: &str) -> bool {
    open_connection(db_path)
        .ok()
        .map(|conn| local_transport_target_is_bootstrap(&conn, tenant_id))
        .unwrap_or(false)
}

pub(super) fn resolve_active_bootstrap_session_fallback(
    db_path: &str,
    tenant_id: &str,
    require_local_bootstrap_phase: bool,
) -> Option<BootstrapSessionFallback> {
    if require_local_bootstrap_phase && !is_tenant_in_bootstrap_phase(db_path, tenant_id) {
        return None;
    }

    let conn = open_connection(db_path).ok()?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let mut stmt = conn
        .prepare(
            "SELECT invite_event_id, bootstrap_spki_fingerprint
             FROM invite_bootstrap_trust
             WHERE recorded_by = ?1
               AND expires_at > ?2
             ORDER BY accepted_at DESC, invite_accepted_event_id DESC",
        )
        .ok()?;
    let mut fallbacks = stmt
        .query_map(rusqlite::params![tenant_id, now_ms], |row| {
            let invite_event_id: String = row.get(0)?;
            let fp_bytes: Vec<u8> = row.get(1)?;
            if fp_bytes.len() != 32 {
                return Err(rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Blob,
                    "bootstrap_spki_fingerprint is not 32 bytes".into(),
                ));
            }
            Ok(BootstrapSessionFallback {
                daemon_peer_id: hex::encode(fp_bytes),
                invite_event_id,
            })
        })
        .ok()?
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    fallbacks.sort_by(|a, b| {
        a.invite_event_id
            .cmp(&b.invite_event_id)
            .then_with(|| a.daemon_peer_id.cmp(&b.daemon_peer_id))
    });
    fallbacks.dedup();
    match fallbacks.as_slice() {
        [fallback] => Some(fallback.clone()),
        _ => return None,
    }
}

fn classify_bootstrap_discovery_auth(
    db_path: &str,
    tenant_id: &str,
    peer_id: &str,
) -> BootstrapDiscoveryAuth {
    let Ok(fp_bytes) = hex::decode(peer_id) else {
        return BootstrapDiscoveryAuth::None;
    };
    if fp_bytes.len() != 32 {
        return BootstrapDiscoveryAuth::None;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&fp_bytes);

    let Ok(conn) = open_connection(db_path) else {
        return BootstrapDiscoveryAuth::None;
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let accepted_bootstrap_authorized = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM invite_bootstrap_trust
                 WHERE recorded_by = ?1
                   AND bootstrap_spki_fingerprint = ?2
                   AND expires_at > ?3
             )",
            rusqlite::params![tenant_id, fp.as_slice(), now_ms],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);
    let pending_bootstrap_authorized = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM pending_invite_bootstrap_trust
                 WHERE recorded_by = ?1
                   AND expected_bootstrap_spki_fingerprint = ?2
                   AND expires_at > ?3
             )",
            rusqlite::params![tenant_id, fp.as_slice(), now_ms],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);
    let steady_state = is_peer_shared_transport_fingerprint(&conn, tenant_id, &fp).unwrap_or(false);
    let local_bootstrap_target = local_transport_target_is_bootstrap(&conn, tenant_id);

    match (
        accepted_bootstrap_authorized,
        pending_bootstrap_authorized,
        steady_state,
        local_bootstrap_target,
    ) {
        (_, _, true, _) => BootstrapDiscoveryAuth::SteadyStateOrMixed,
        (true, false, false, true) => BootstrapDiscoveryAuth::AcceptedDiscoveryAndObserved,
        (true, false, false, false) => BootstrapDiscoveryAuth::AcceptedObservedOnly,
        (false, true, false, _) => BootstrapDiscoveryAuth::PendingOnly,
        (false, false, false, _) => BootstrapDiscoveryAuth::None,
        (true, true, false, _) => BootstrapDiscoveryAuth::SteadyStateOrMixed,
    }
}

pub(super) fn should_initiate_connect_for_source_with_db(
    db_path: &str,
    tenant_id: &str,
    source: &TargetIngressSource,
) -> bool {
    match source {
        TargetIngressSource::Discovery { peer_id } => {
            if resolve_active_bootstrap_session_fallback(db_path, tenant_id, true).is_some() {
                return true;
            }
            match classify_bootstrap_discovery_auth(db_path, tenant_id, peer_id) {
                BootstrapDiscoveryAuth::AcceptedDiscoveryAndObserved => true,
                BootstrapDiscoveryAuth::PendingOnly => false,
                BootstrapDiscoveryAuth::AcceptedObservedOnly
                | BootstrapDiscoveryAuth::None
                | BootstrapDiscoveryAuth::SteadyStateOrMixed => {
                    should_initiate_connect_for_source(tenant_id, source)
                }
            }
        }
        TargetIngressSource::ObservedPeer { .. } => {
            should_initiate_connect_for_source(tenant_id, source)
                || resolve_active_bootstrap_session_fallback(db_path, tenant_id, false).is_some()
        }
        TargetIngressSource::Bootstrap { .. } => true,
    }
}

// ---- Tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::target_dispatch::should_ignore_target_event;
    use super::*;
    use crate::contracts::peering_contract::SessionDirection;
    use crate::db::open_connection;
    use crate::db::schema::create_tables;
    use crate::db::transport_creds::{set_local_transport_target, CRED_SOURCE_PEER_SHARED};
    use crate::db::transport_trust::{
        record_invite_bootstrap_trust, record_pending_invite_bootstrap_trust,
    };
    use crate::peering::loops::preferred_connection_direction;

    #[test]
    fn bootstrap_authorized_discovery_targets_override_preferred_side_gate() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bootstrap-discovery.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let peer = "0000000000000000000000000000000000000000000000000000000000000001";
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap local transport target");
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_invite_bootstrap_trust(
            &conn,
            tenant,
            "invite-accepted",
            "invite-event",
            "workspace",
            "",
            &fp_arr,
        )
        .expect("record invite bootstrap trust");
        drop(conn);

        assert!(
            !should_initiate_connect_for_source(
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "pure preferred-side gating should reject the non-preferred bootstrap peer"
        );
        assert!(
            should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "bootstrap-authorized discovery peer should be allowed to connect until steady-state trust supersedes it"
        );
    }

    #[test]
    fn pending_bootstrap_discovery_targets_stay_bottlenecked() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("pending-bootstrap-discovery.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "0000000000000000000000000000000000000000000000000000000000000001";
        let peer = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_pending_invite_bootstrap_trust(&conn, tenant, "invite-event", "workspace", &fp_arr)
            .expect("record pending invite bootstrap trust");
        drop(conn);

        assert!(
            should_initiate_connect_for_source(
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "pure preferred-side gating would allow the inviter side to dial here"
        );
        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "pending bootstrap trust should keep the inviter side bottlenecked"
        );
    }

    #[test]
    fn pending_bootstrap_observed_targets_can_reconnect_exact_peer() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("pending-bootstrap-observed.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "0000000000000000000000000000000000000000000000000000000000000001";
        let peer = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_pending_invite_bootstrap_trust(&conn, tenant, "invite-event", "workspace", &fp_arr)
            .expect("record pending invite bootstrap trust");
        drop(conn);

        assert!(
            should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::ObservedPeer {
                    peer_id: peer.to_string(),
                }
            ),
            "pending bootstrap trust should still allow exact observed-endpoint reconnects"
        );
        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "pending bootstrap trust must continue bottlenecking broad discovery dialing"
        );
    }

    #[test]
    fn bootstrap_authorized_observed_targets_override_preferred_side_gate() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bootstrap-observed.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let peer = "0000000000000000000000000000000000000000000000000000000000000001";
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap local transport target");
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_invite_bootstrap_trust(
            &conn,
            tenant,
            "invite-accepted",
            "invite-event",
            "workspace",
            "",
            &fp_arr,
        )
        .expect("record invite bootstrap trust");
        drop(conn);

        assert!(
            !matches!(
                preferred_connection_direction(tenant, peer),
                Some(SessionDirection::Outbound)
            ),
            "test setup requires the observed peer to be non-preferred"
        );
        assert!(
            !should_initiate_connect_for_source(
                tenant,
                &TargetIngressSource::ObservedPeer {
                    peer_id: peer.to_string(),
                }
            ),
            "pure preferred-side gating should reject the non-preferred observed peer"
        );
        assert!(
            should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::ObservedPeer {
                    peer_id: peer.to_string(),
                }
            ),
            "bootstrap-authorized observed endpoints should be allowed until steady-state trust supersedes them"
        );
    }

    #[test]
    fn converged_local_transport_target_keeps_bootstrap_authorized_discovery_bottlenecked() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bootstrap-discovery-converged.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let peer = "0000000000000000000000000000000000000000000000000000000000000001";
        set_local_transport_target(&conn, tenant, tenant, CRED_SOURCE_PEER_SHARED)
            .expect("set peershared local transport target");
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_invite_bootstrap_trust(
            &conn,
            tenant,
            "invite-accepted",
            "invite-event",
            "workspace",
            "",
            &fp_arr,
        )
        .expect("record invite bootstrap trust");
        drop(conn);

        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "once local transport has converged to peershared, bootstrap trust must not re-enable non-preferred discovery dialing"
        );
    }

    #[test]
    fn converged_local_transport_target_still_allows_bootstrap_authorized_observed_reconnects() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bootstrap-observed-converged.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let peer = "0000000000000000000000000000000000000000000000000000000000000001";
        set_local_transport_target(&conn, tenant, tenant, CRED_SOURCE_PEER_SHARED)
            .expect("set peershared local transport target");
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_invite_bootstrap_trust(
            &conn,
            tenant,
            "invite-accepted",
            "invite-event",
            "workspace",
            "",
            &fp_arr,
        )
        .expect("record invite bootstrap trust");
        drop(conn);

        assert!(
            should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::ObservedPeer {
                    peer_id: peer.to_string(),
                }
            ),
            "exact observed-endpoint reconnects should stay allowed until steady-state peer trust supersedes bootstrap auth"
        );
        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "broad discovery should still stay bottlenecked after local transport convergence"
        );
    }

    // -----------------------------------------------------------------------
    // Bootstrap-phase guards: during bootstrap, no source may suppress or
    // cancel Bootstrap workers because only Bootstrap carries the invite
    // fallback cert that the inviter will accept.
    // -----------------------------------------------------------------------

    #[test]
    fn bootstrap_phase_detected_for_bootstrap_transport_target() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bs-phase-detect.db");
        let db_str = db_path.to_str().expect("db path");
        let conn = open_connection(db_str).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        // No transport target -> not in bootstrap phase
        assert!(
            !is_tenant_in_bootstrap_phase(db_str, tenant),
            "tenant with no transport target should not be in bootstrap phase"
        );

        // Bootstrap transport target -> in bootstrap phase
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap target");
        drop(conn);
        assert!(
            is_tenant_in_bootstrap_phase(db_str, tenant),
            "tenant with bootstrap transport target must be detected as bootstrap phase"
        );

        // PeerShared transport target -> no longer in bootstrap phase
        let conn = open_connection(db_str).expect("open db");
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_PEER_SHARED)
            .expect("set peershared target");
        drop(conn);
        assert!(
            !is_tenant_in_bootstrap_phase(db_str, tenant),
            "tenant with peershared transport target must not be in bootstrap phase"
        );
    }

    /// During bootstrap phase, a Bootstrap connect event must never be
    /// suppressed by an existing Discovery or ObservedPeer worker.
    ///
    /// Only the Bootstrap source carries the invite fallback TLS cert.
    /// If Discovery or ObservedPeer suppress it, the invitee is stuck
    /// because those sources use the PeerShared cert the inviter does
    /// not yet trust.
    #[test]
    fn bootstrap_events_never_suppressed_during_bootstrap_phase() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bs-suppress-guard.db");
        let db_str = db_path.to_str().expect("db path");
        let conn = open_connection(db_str).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        // Put tenant in bootstrap phase
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap target");
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_invite_bootstrap_trust(
            &conn,
            tenant,
            "invite-accepted",
            "invite-event",
            "workspace",
            "",
            &fp_arr,
        )
        .expect("record invite bootstrap trust");
        drop(conn);

        let bootstrap = TargetIngressSource::Bootstrap {
            daemon_peer_id: peer.to_string(),
            invite_event_id: "invite".to_string(),
        };

        // Test against every non-Bootstrap source type
        let competing_sources = [
            TargetIngressSource::Discovery {
                peer_id: peer.to_string(),
            },
            TargetIngressSource::ObservedPeer {
                peer_id: peer.to_string(),
            },
        ];

        for existing in &competing_sources {
            // Precondition: the competing source has higher precedence
            assert!(
                should_ignore_target_event(existing, &bootstrap),
                "{:?} should have higher static precedence than Bootstrap",
                existing
            );

            // The dispatcher's combined suppression decision mirrors:
            //   suppress = should_ignore(existing, bootstrap)
            //              && !is_tenant_in_bootstrap_phase(db, tenant)
            let would_suppress = should_ignore_target_event(existing, &bootstrap)
                && !is_tenant_in_bootstrap_phase(db_str, tenant);
            assert!(
                !would_suppress,
                "during bootstrap phase, {:?} must NOT suppress Bootstrap events",
                existing
            );
        }

        // The dispatcher's cancellation decision mirrors:
        //   cancel_bootstrap = is_non_bootstrap_source
        //                      && !is_tenant_in_bootstrap_phase(db, tenant)
        assert!(
            !(!is_tenant_in_bootstrap_phase(db_str, tenant)),
            "during bootstrap phase, non-bootstrap events must not cancel bootstrap workers"
        );

        // After bootstrap completes, normal precedence resumes
        let conn = open_connection(db_str).expect("open db");
        set_local_transport_target(&conn, tenant, tenant, CRED_SOURCE_PEER_SHARED)
            .expect("transition to peershared");
        drop(conn);

        assert!(
            !is_tenant_in_bootstrap_phase(db_str, tenant),
            "tenant should have exited bootstrap phase"
        );
        for existing in &competing_sources {
            // After bootstrap, suppression IS allowed
            let would_suppress = should_ignore_target_event(existing, &bootstrap)
                && !is_tenant_in_bootstrap_phase(db_str, tenant);
            assert!(
                would_suppress,
                "after bootstrap, {:?} SHOULD suppress stale Bootstrap events",
                existing
            );
        }
        // After bootstrap, cancellation IS allowed
        assert!(
            !is_tenant_in_bootstrap_phase(db_str, tenant),
            "after bootstrap, non-bootstrap events may cancel bootstrap workers"
        );
    }

    /// During bootstrap phase, Discovery/ObservedPeer events must not
    /// cancel running Bootstrap workers.
    ///
    /// The dispatcher decides whether to cancel bootstrap workers via:
    ///   cancel = is_non_bootstrap_source && !is_tenant_in_bootstrap_phase(..)
    #[test]
    fn bootstrap_workers_not_cancelled_during_bootstrap_phase() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bs-cancel-guard.db");
        let db_str = db_path.to_str().expect("db path");
        let conn = open_connection(db_str).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let non_bootstrap_sources = [
            TargetIngressSource::Discovery {
                peer_id: peer.to_string(),
            },
            TargetIngressSource::ObservedPeer {
                peer_id: peer.to_string(),
            },
        ];

        // Bootstrap phase: cancellation must be blocked
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap target");
        drop(conn);

        for source in &non_bootstrap_sources {
            let would_cancel = matches!(
                source,
                TargetIngressSource::ObservedPeer { .. } | TargetIngressSource::Discovery { .. }
            ) && !is_tenant_in_bootstrap_phase(db_str, tenant);
            assert!(
                !would_cancel,
                "during bootstrap phase, {:?} must NOT cancel bootstrap workers",
                source
            );
        }

        // Steady state: cancellation is allowed
        let conn = open_connection(db_str).expect("open db");
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_PEER_SHARED)
            .expect("transition to peershared");
        drop(conn);

        for source in &non_bootstrap_sources {
            let would_cancel = matches!(
                source,
                TargetIngressSource::ObservedPeer { .. } | TargetIngressSource::Discovery { .. }
            ) && !is_tenant_in_bootstrap_phase(db_str, tenant);
            assert!(
                would_cancel,
                "after bootstrap, {:?} SHOULD cancel stale bootstrap workers",
                source
            );
        }
    }
}
