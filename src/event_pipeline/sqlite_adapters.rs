use std::path::{Path, PathBuf};

use crate::contracts::event_runtime_contract::{
    IngestError, IngestSink, ReplicationStore, StoreError,
};
use crate::contracts::network_contract::{PeerFingerprint, TenantId};
use crate::db::egress_queue::EgressQueue;
use crate::db::project_queue::ProjectQueue;
use crate::db::schema::create_tables;
use crate::db::store::{lookup_workspace_id, Store, SQL_INSERT_EVENT, SQL_INSERT_NEG_ITEM, SQL_INSERT_RECORDED_EVENT};
use crate::db::open_connection;
use crate::event_modules::{self as events, registry, ShareScope};

const DEFAULT_EGRESS_LEASE_MS: i64 = 30_000;

#[derive(Debug, Clone)]
pub struct SqliteIngestSink {
    db_path: PathBuf,
}

impl SqliteIngestSink {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
        }
    }
}

impl IngestSink for SqliteIngestSink {
    fn ingest_event(
        &self,
        tenant: &TenantId,
        event_id: [u8; 32],
        blob: Vec<u8>,
    ) -> Result<(), IngestError> {
        let db = open_connection(&self.db_path).map_err(|_| IngestError::StoreUnavailable)?;
        create_tables(&db).map_err(|e| IngestError::Internal(format!("schema init failed: {e}")))?;

        let created_at_ms = events::extract_created_at_ms(&blob)
            .ok_or_else(|| IngestError::Invalid("missing created_at".to_string()))?;
        let type_code = events::extract_event_type(&blob)
            .ok_or_else(|| IngestError::Invalid("missing event type".to_string()))?;
        let meta = registry()
            .lookup(type_code)
            .ok_or_else(|| IngestError::Invalid(format!("unknown event type code: {type_code}")))?;

        let event_id_b64 = crate::crypto::event_id_to_base64(&event_id);
        let inserted = db
            .execute(
                SQL_INSERT_EVENT,
                rusqlite::params![
                    &event_id_b64,
                    meta.type_name,
                    blob.as_slice(),
                    meta.share_scope.as_str(),
                    created_at_ms as i64,
                    current_timestamp_ms()
                ],
            )
            .map_err(|e| IngestError::Internal(format!("events insert failed: {e}")))?;
        if inserted == 0 {
            return Err(IngestError::AlreadyExists);
        }

        if meta.share_scope == ShareScope::Shared {
            let workspace_id = lookup_workspace_id(&db, &tenant.0);
            db.execute(
                SQL_INSERT_NEG_ITEM,
                rusqlite::params![workspace_id, created_at_ms as i64, event_id.as_slice()],
            )
            .map_err(|e| IngestError::Internal(format!("neg_items insert failed: {e}")))?;
        }

        let recorded_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        db.execute(
            SQL_INSERT_RECORDED_EVENT,
            rusqlite::params![&tenant.0, &event_id_b64, recorded_at, "quic_recv"],
        )
        .map_err(|e| IngestError::Internal(format!("recorded_events insert failed: {e}")))?;

        let pq = ProjectQueue::new(&db);
        pq.enqueue(&tenant.0, &event_id_b64)
            .map_err(|e| IngestError::Internal(format!("project_queue enqueue failed: {e}")))?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SqliteReplicationStore {
    db_path: PathBuf,
    lease_ms: i64,
}

impl SqliteReplicationStore {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
            lease_ms: DEFAULT_EGRESS_LEASE_MS,
        }
    }

    pub fn with_lease_ms<P: AsRef<Path>>(db_path: P, lease_ms: i64) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
            lease_ms,
        }
    }

    fn peer_key(peer: &PeerFingerprint) -> String {
        hex::encode(peer.0)
    }
}

impl ReplicationStore for SqliteReplicationStore {
    fn enqueue_outbound(
        &self,
        peer: &PeerFingerprint,
        ids: &[[u8; 32]],
    ) -> Result<(), StoreError> {
        let db = open_connection(&self.db_path).map_err(|_| StoreError::Unavailable)?;
        let queue = EgressQueue::new(&db);
        queue
            .enqueue_events(&Self::peer_key(peer), ids)
            .map_err(|e| StoreError::Internal(format!("egress enqueue failed: {e}")))?;
        Ok(())
    }

    fn claim_outbound(
        &self,
        peer: &PeerFingerprint,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>, StoreError> {
        let db = open_connection(&self.db_path).map_err(|_| StoreError::Unavailable)?;
        let queue = EgressQueue::new(&db);
        let rows = queue
            .claim_batch(&Self::peer_key(peer), limit, self.lease_ms)
            .map_err(|e| StoreError::Internal(format!("egress claim failed: {e}")))?;
        Ok(rows.into_iter().map(|(_, id)| id).collect())
    }

    fn load_shared_blob(&self, event_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let db = open_connection(&self.db_path).map_err(|_| StoreError::Unavailable)?;
        Store::new(&db)
            .get_shared(event_id)
            .map_err(|e| StoreError::Internal(format!("load shared blob failed: {e}")))
    }
}

fn current_timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
