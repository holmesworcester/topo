//! Bootstrap-phase authentication helpers.
//!
//! Daemon-scoped `iroh` transport only needs two decisions here:
//! - is this tenant still in bootstrap phase?
//! - can the known-peer target use a bootstrap auth fallback?

use crate::db::open_connection;
use crate::db::transport_creds::{resolve_tenant_transport_target, CRED_SOURCE_BOOTSTRAP};
use crate::db::transport_trust::{
    list_active_bootstrap_session_fallback_candidates, BootstrapSessionFallbackCandidate,
};

use super::target_dispatch::{should_initiate_connect_for_source, TargetIngressSource};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BootstrapSessionFallback {
    pub(super) daemon_peer_id: String,
    pub(super) invite_event_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BootstrapSessionFallbackRawRows {
    require_local_bootstrap_phase: bool,
    local_bootstrap_phase: bool,
    candidates: Vec<BootstrapSessionFallbackCandidate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BootstrapSessionFallbackDecisionContext {
    RejectRequiresLocalBootstrapPhase,
    MissingCandidate,
    UniqueCandidate {
        fallback: BootstrapSessionFallback,
        workspace_already_local_before_candidate: bool,
    },
    AmbiguousCandidate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BootstrapSessionFallbackPlan {
    RejectRequiresLocalBootstrapPhase,
    RejectMissingCandidate,
    UseFallback(BootstrapSessionFallback),
    RejectAmbiguousCandidate,
    RejectAlreadyLocalWorkspaceCandidate,
}

fn decide_bootstrap_session_fallback_plan(
    context: &BootstrapSessionFallbackDecisionContext,
) -> BootstrapSessionFallbackPlan {
    match context {
        BootstrapSessionFallbackDecisionContext::RejectRequiresLocalBootstrapPhase => {
            BootstrapSessionFallbackPlan::RejectRequiresLocalBootstrapPhase
        }
        BootstrapSessionFallbackDecisionContext::MissingCandidate => {
            BootstrapSessionFallbackPlan::RejectMissingCandidate
        }
        BootstrapSessionFallbackDecisionContext::UniqueCandidate {
            fallback,
            workspace_already_local_before_candidate,
        } => {
            if *workspace_already_local_before_candidate {
                BootstrapSessionFallbackPlan::RejectAlreadyLocalWorkspaceCandidate
            } else {
                BootstrapSessionFallbackPlan::UseFallback(fallback.clone())
            }
        }
        BootstrapSessionFallbackDecisionContext::AmbiguousCandidate => {
            BootstrapSessionFallbackPlan::RejectAmbiguousCandidate
        }
    }
}

fn normalize_bootstrap_session_fallback_decision_context(
    raw_rows: BootstrapSessionFallbackRawRows,
) -> BootstrapSessionFallbackDecisionContext {
    if raw_rows.require_local_bootstrap_phase && !raw_rows.local_bootstrap_phase {
        return BootstrapSessionFallbackDecisionContext::RejectRequiresLocalBootstrapPhase;
    }

    let mut candidates = raw_rows.candidates;
    candidates.sort_by(|a, b| {
        a.invite_event_id
            .cmp(&b.invite_event_id)
            .then_with(|| a.daemon_peer_id.cmp(&b.daemon_peer_id))
    });
    let mut normalized: Vec<BootstrapSessionFallbackCandidate> = Vec::new();
    for candidate in candidates {
        if let Some(last) = normalized.last_mut() {
            if last.invite_event_id == candidate.invite_event_id
                && last.daemon_peer_id == candidate.daemon_peer_id
            {
                last.workspace_already_local_before_candidate |=
                    candidate.workspace_already_local_before_candidate;
                continue;
            }
        }
        normalized.push(candidate);
    }

    match normalized.as_slice() {
        [] => BootstrapSessionFallbackDecisionContext::MissingCandidate,
        [candidate] => BootstrapSessionFallbackDecisionContext::UniqueCandidate {
            fallback: BootstrapSessionFallback {
                daemon_peer_id: candidate.daemon_peer_id.clone(),
                invite_event_id: candidate.invite_event_id.clone(),
            },
            workspace_already_local_before_candidate: candidate
                .workspace_already_local_before_candidate,
        },
        _ => BootstrapSessionFallbackDecisionContext::AmbiguousCandidate,
    }
}

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
    let conn = open_connection(db_path).ok()?;
    let decision_context =
        normalize_bootstrap_session_fallback_decision_context(BootstrapSessionFallbackRawRows {
            require_local_bootstrap_phase,
            local_bootstrap_phase: local_transport_target_is_bootstrap(&conn, tenant_id),
            candidates: list_active_bootstrap_session_fallback_candidates(&conn, tenant_id).ok()?,
        });
    let plan = decide_bootstrap_session_fallback_plan(&decision_context);
    match plan {
        BootstrapSessionFallbackPlan::UseFallback(fallback) => Some(fallback),
        BootstrapSessionFallbackPlan::RejectRequiresLocalBootstrapPhase
        | BootstrapSessionFallbackPlan::RejectMissingCandidate
        | BootstrapSessionFallbackPlan::RejectAmbiguousCandidate
        | BootstrapSessionFallbackPlan::RejectAlreadyLocalWorkspaceCandidate => None,
    }
}

pub(crate) fn should_initiate_connect_for_source_with_db(
    _db_path: &str,
    tenant_id: &str,
    source: &TargetIngressSource,
) -> bool {
    match source {
        TargetIngressSource::Bootstrap { .. } => true,
        TargetIngressSource::KnownPeer { .. } => {
            should_initiate_connect_for_source(tenant_id, source)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_connection;
    use crate::db::schema::create_tables;
    use crate::db::transport_creds::{set_local_transport_target, CRED_SOURCE_BOOTSTRAP};
    use crate::db::transport_trust::record_invite_bootstrap_trust;

    #[test]
    fn bootstrap_source_always_initiates_connect() {
        assert!(should_initiate_connect_for_source_with_db(
            "/definitely/missing.db",
            "tenant",
            &TargetIngressSource::Bootstrap {
                daemon_peer_id: "peer".to_string(),
                invite_event_id: "invite".to_string(),
            }
        ));
    }

    #[test]
    fn bootstrap_phase_marks_tenant_as_bootstrap() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("bootstrap-phase.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();
        set_local_transport_target(
            &conn,
            "tenant",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            CRED_SOURCE_BOOTSTRAP,
        )
        .unwrap();
        drop(conn);

        assert!(is_tenant_in_bootstrap_phase(
            db_path.to_str().unwrap(),
            "tenant"
        ));
    }

    #[test]
    fn known_peer_initiates_when_bootstrap_fallback_exists() {
        let lower = "0000000000000000000000000000000000000000000000000000000000000001";
        let higher = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("bootstrap-fallback.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();
        record_invite_bootstrap_trust(
            &conn,
            higher,
            "accepted-1",
            "invite-1",
            "ws-1",
            "127.0.0.1:1",
            &[0xAA; 32],
        )
        .unwrap();
        drop(conn);

        assert!(should_initiate_connect_for_source_with_db(
            db_path.to_str().unwrap(),
            higher,
            &TargetIngressSource::KnownPeer {
                peer_id: lower.to_string(),
            }
        ));
    }

    #[test]
    fn known_peer_initiates_without_bootstrap_fallback() {
        let lower = "0000000000000000000000000000000000000000000000000000000000000001";
        let higher = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("no-bootstrap-fallback.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();
        drop(conn);

        assert!(should_initiate_connect_for_source_with_db(
            db_path.to_str().unwrap(),
            higher,
            &TargetIngressSource::KnownPeer {
                peer_id: lower.to_string(),
            }
        ));
    }

    #[test]
    fn bootstrap_session_fallback_is_deterministic_for_single_row() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("bootstrap-single.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();
        record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "accepted-1",
            "invite-1",
            "ws-1",
            "127.0.0.1:1",
            &[0xAB; 32],
        )
        .unwrap();
        drop(conn);

        let first =
            resolve_active_bootstrap_session_fallback(db_path.to_str().unwrap(), "tenant-a", false);
        let second =
            resolve_active_bootstrap_session_fallback(db_path.to_str().unwrap(), "tenant-a", false);
        assert_eq!(first, second);
        assert_eq!(
            first,
            Some(BootstrapSessionFallback {
                daemon_peer_id: hex::encode([0xAB; 32]),
                invite_event_id: "invite-1".to_string(),
            })
        );
    }

    #[test]
    fn bootstrap_session_fallback_returns_none_when_ambiguous() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("bootstrap-ambiguous.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();
        record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "accepted-1",
            "invite-1",
            "ws-1",
            "127.0.0.1:1",
            &[0xAB; 32],
        )
        .unwrap();
        record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "accepted-2",
            "invite-2",
            "ws-1",
            "127.0.0.1:2",
            &[0xCD; 32],
        )
        .unwrap();
        drop(conn);

        assert_eq!(
            resolve_active_bootstrap_session_fallback(db_path.to_str().unwrap(), "tenant-a", false),
            None
        );
    }

    #[test]
    fn bootstrap_session_fallback_skips_same_workspace_candidate_created_after_sibling() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("bootstrap-same-workspace-skip.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();
        conn.execute(
            "INSERT INTO invites_accepted
                 (event_id, tenant_event_id, invite_event_id, workspace_id, recorded_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "accepted-sibling",
                "tenant-event-sibling",
                "invite-sibling",
                "ws-1",
                "tenant-b",
                1_000i64
            ],
        )
        .unwrap();
        record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "accepted-a",
            "invite-a",
            "ws-1",
            "127.0.0.1:1",
            &[0xAB; 32],
        )
        .unwrap();
        drop(conn);

        assert_eq!(
            resolve_active_bootstrap_session_fallback(db_path.to_str().unwrap(), "tenant-a", false),
            None
        );
    }

    #[test]
    fn bootstrap_session_fallback_duplicate_rows_preserve_same_workspace_rejection() {
        let decision_context = normalize_bootstrap_session_fallback_decision_context(
            BootstrapSessionFallbackRawRows {
                require_local_bootstrap_phase: false,
                local_bootstrap_phase: true,
                candidates: vec![
                    BootstrapSessionFallbackCandidate {
                        daemon_peer_id: "daemon-a".to_string(),
                        invite_event_id: "invite-a".to_string(),
                        workspace_already_local_before_candidate: false,
                    },
                    BootstrapSessionFallbackCandidate {
                        daemon_peer_id: "daemon-a".to_string(),
                        invite_event_id: "invite-a".to_string(),
                        workspace_already_local_before_candidate: true,
                    },
                ],
            },
        );
        assert_eq!(
            decision_context,
            BootstrapSessionFallbackDecisionContext::UniqueCandidate {
                fallback: BootstrapSessionFallback {
                    daemon_peer_id: "daemon-a".to_string(),
                    invite_event_id: "invite-a".to_string(),
                },
                workspace_already_local_before_candidate: true,
            }
        );
        assert_eq!(
            decide_bootstrap_session_fallback_plan(&decision_context),
            BootstrapSessionFallbackPlan::RejectAlreadyLocalWorkspaceCandidate
        );
    }

    #[test]
    fn bootstrap_session_fallback_keeps_older_candidate_after_later_sibling() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("bootstrap-older-candidate-kept.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();
        record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "accepted-a",
            "invite-a",
            "ws-1",
            "127.0.0.1:1",
            &[0xAB; 32],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO invites_accepted
                 (event_id, tenant_event_id, invite_event_id, workspace_id, recorded_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "accepted-sibling",
                "tenant-event-sibling",
                "invite-sibling",
                "ws-1",
                "tenant-b",
                crate::db::queue::current_timestamp_ms() + 60_000
            ],
        )
        .unwrap();
        drop(conn);

        assert_eq!(
            resolve_active_bootstrap_session_fallback(db_path.to_str().unwrap(), "tenant-a", false),
            Some(BootstrapSessionFallback {
                daemon_peer_id: hex::encode([0xAB; 32]),
                invite_event_id: "invite-a".to_string(),
            })
        );
    }

    #[test]
    fn bootstrap_session_fallback_requires_local_bootstrap_phase_when_requested() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("bootstrap-phase-required.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();
        record_invite_bootstrap_trust(
            &conn,
            "tenant-a",
            "accepted-a",
            "invite-a",
            "ws-1",
            "127.0.0.1:1",
            &[0xAB; 32],
        )
        .unwrap();
        drop(conn);

        assert_eq!(
            resolve_active_bootstrap_session_fallback(db_path.to_str().unwrap(), "tenant-a", true),
            None
        );
    }
}
