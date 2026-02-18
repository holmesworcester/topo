use async_trait::async_trait;
use std::path::{Path, PathBuf};

use crate::contracts::network_contract::{
    PeerFingerprint, TenantId, TrustDecision, TrustError, TrustOracle,
};
use crate::db::open_connection;
use crate::db::transport_trust::is_peer_allowed;

#[derive(Debug, Clone)]
pub struct SqliteTrustOracle {
    db_path: PathBuf,
}

impl SqliteTrustOracle {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
        }
    }

    pub fn check_sync(
        &self,
        tenant: &TenantId,
        peer: &PeerFingerprint,
    ) -> Result<TrustDecision, TrustError> {
        let db = open_connection(&self.db_path).map_err(|_| TrustError::StoreUnavailable)?;

        let allowed = is_peer_allowed(&db, &tenant.0, &peer.0)
            .map_err(|e| TrustError::Internal(format!("trust check failed: {e}")))?;

        Ok(if allowed {
            TrustDecision::Allow
        } else {
            TrustDecision::Deny
        })
    }
}

#[async_trait]
impl TrustOracle for SqliteTrustOracle {
    async fn check(
        &self,
        tenant: &TenantId,
        peer: &PeerFingerprint,
    ) -> Result<TrustDecision, TrustError> {
        self.check_sync(tenant, peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::create_tables;
    use crate::db::transport_trust::record_pending_invite_bootstrap_trust;

    #[tokio::test]
    async fn denies_untrusted_peer() {
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = temp.path().join("trust.sqlite3");
        let db = open_connection(&db_path).expect("open db");
        create_tables(&db).expect("create tables");
        drop(db);

        let oracle = SqliteTrustOracle::new(&db_path);
        let tenant = TenantId("tenant-a".to_string());
        let peer = PeerFingerprint([7u8; 32]);

        let decision = oracle.check(&tenant, &peer).await.expect("check");
        assert_eq!(decision, TrustDecision::Deny);
    }

    #[tokio::test]
    async fn allows_pending_bootstrap_peer() {
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = temp.path().join("trust.sqlite3");
        let db = open_connection(&db_path).expect("open db");
        create_tables(&db).expect("create tables");

        let tenant = TenantId("tenant-a".to_string());
        let peer = PeerFingerprint([9u8; 32]);
        record_pending_invite_bootstrap_trust(
            &db,
            &tenant.0,
            "invite-event-1",
            "workspace-1",
            &peer.0,
        )
        .expect("record pending trust");
        drop(db);

        let oracle = SqliteTrustOracle::new(&db_path);
        let decision = oracle.check(&tenant, &peer).await.expect("check");
        assert_eq!(decision, TrustDecision::Allow);
    }

    #[tokio::test]
    async fn returns_store_unavailable_error_when_store_unavailable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing_path = temp.path().join("missing").join("trust.sqlite3");
        let oracle = SqliteTrustOracle::new(&missing_path);
        let tenant = TenantId("tenant-a".to_string());
        let peer = PeerFingerprint([1u8; 32]);

        let err = oracle
            .check(&tenant, &peer)
            .await
            .expect_err("expected error");
        assert_eq!(err, TrustError::StoreUnavailable);
    }
}
