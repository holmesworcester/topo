//! Bootstrap-phase authentication helpers.
//!
//! Daemon-scoped `iroh` transport only needs two decisions here:
//! - is this tenant still in bootstrap phase?
//! - does a known-peer target need bootstrap auth override instead of the
//!   normal preferred-side gate?

use crate::db::open_connection;
use crate::db::transport_creds::{resolve_tenant_transport_target, CRED_SOURCE_BOOTSTRAP};

use super::target_dispatch::{should_initiate_connect_for_source, TargetIngressSource};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BootstrapSessionFallback {
    pub(super) daemon_peer_id: String,
    pub(super) invite_event_id: String,
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
        _ => None,
    }
}

pub(crate) fn should_initiate_connect_for_source_with_db(
    db_path: &str,
    tenant_id: &str,
    source: &TargetIngressSource,
) -> bool {
    match source {
        TargetIngressSource::Bootstrap { .. } => true,
        TargetIngressSource::KnownPeer { .. } => {
            resolve_active_bootstrap_session_fallback(db_path, tenant_id, false).is_some()
                || should_initiate_connect_for_source(tenant_id, source)
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
    fn known_peer_uses_bootstrap_fallback_when_available() {
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
    fn known_peer_without_bootstrap_fallback_keeps_preferred_side_gate() {
        let lower = "0000000000000000000000000000000000000000000000000000000000000001";
        let higher = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("no-bootstrap-fallback.db");
        let conn = open_connection(db_path.to_str().unwrap()).unwrap();
        create_tables(&conn).unwrap();
        drop(conn);

        assert!(!should_initiate_connect_for_source_with_db(
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
}
