use std::collections::BTreeMap;
use std::path::Path;

use tempfile::TempDir;

use crate::state::db::transport_creds::{load_local_creds, resolve_tenant_transport_target};
use crate::state::db::transport_trust::{
    list_active_invite_bootstrap_targets, list_authorized_transport_rows, AuthorizedTransportRow,
    InviteBootstrapTarget,
};

use super::virtual_daemon::VirtualDaemon;

type BridgeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// A temporary standalone peer DB materialized from a selected tenant view.
///
/// The bridge copies the peer's known event corpus plus the local durable
/// replay inputs required to rebuild projection and transport state, then
/// replays that tenant into a fresh DB so real daemon RPC commands can run.
pub struct PeerDbSnapshot {
    _tmpdir: TempDir,
    db_path: String,
}

impl PeerDbSnapshot {
    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    pub fn daemon(&self) -> VirtualDaemon {
        VirtualDaemon::new(&self.db_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedTenantState {
    pub peer_id: String,
    pub workspace_id: Option<String>,
    pub transport_peer_id: Option<String>,
    pub transport_source: Option<String>,
    pub has_local_transport_creds: bool,
    pub known_event_ids: Vec<String>,
    pub authorized_transport_rows: Vec<AuthorizedTransportRow>,
    pub bootstrap_targets: Vec<InviteBootstrapTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedPeerDbState {
    pub source_db_path: String,
    pub event_blobs: BTreeMap<String, Vec<u8>>,
    pub tenants: Vec<ImportedTenantState>,
}

impl ImportedPeerDbState {
    pub fn unique_event_count(&self) -> usize {
        self.event_blobs.len()
    }

    pub fn total_known_event_refs(&self) -> usize {
        self.tenants
            .iter()
            .map(|tenant| tenant.known_event_ids.len())
            .sum()
    }
}

pub fn snapshot_peer_db(source_db_path: &str, recorded_by: &str) -> BridgeResult<PeerDbSnapshot> {
    let tmpdir = tempfile::tempdir()?;
    let db_path = tmpdir
        .path()
        .join("peer-snapshot.db")
        .to_string_lossy()
        .into_owned();
    snapshot_peer_db_to_path(source_db_path, recorded_by, &db_path)?;
    Ok(PeerDbSnapshot {
        _tmpdir: tmpdir,
        db_path,
    })
}

pub fn snapshot_peer_db_to_path(
    source_db_path: &str,
    recorded_by: &str,
    dest_db_path: &str,
) -> BridgeResult<()> {
    if Path::new(dest_db_path).exists() {
        return Err(format!("destination db already exists: {dest_db_path}").into());
    }

    let source = crate::db::open_connection(source_db_path)?;
    let dest = crate::db::open_connection(dest_db_path)?;
    crate::db::schema::create_tables(&dest)?;

    dest.execute("BEGIN IMMEDIATE", [])?;
    let copy_result = (|| -> BridgeResult<()> {
        copy_known_event_store(&source, &dest, recorded_by)?;
        copy_shared_event_index(&source, &dest, recorded_by)?;
        copy_invite_secrets(&source, &dest, recorded_by)?;
        copy_peer_secrets(&source, &dest, recorded_by)?;
        copy_bootstrap_context(&source, &dest, recorded_by)?;
        copy_peer_endpoint_observations(&source, &dest, recorded_by)?;
        copy_daemon_transport_identity(&source, &dest)?;
        copy_local_client_ops(&source, &dest, recorded_by)?;
        Ok(())
    })();

    match copy_result {
        Ok(()) => {
            dest.execute("COMMIT", [])?;
        }
        Err(err) => {
            let _ = dest.execute("ROLLBACK", []);
            return Err(err);
        }
    }

    replay_recorded_events_into_projection(&dest, dest_db_path, recorded_by)?;
    Ok(())
}

pub fn import_peer_db_state(source_db_path: &str) -> BridgeResult<ImportedPeerDbState> {
    let source = crate::db::open_connection(source_db_path)?;
    crate::db::schema::create_tables(&source)?;

    let tenant_ids = collect_importable_tenant_ids(&source)?;
    let mut event_blobs = BTreeMap::new();
    let mut tenants = Vec::with_capacity(tenant_ids.len());

    for tenant_id in tenant_ids {
        let known_event_ids = collect_recorded_event_ids(&source, &tenant_id)?;
        for event_id in &known_event_ids {
            if event_blobs.contains_key(event_id) {
                continue;
            }
            let blob: Vec<u8> = source.query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![event_id],
                |row| row.get(0),
            )?;
            event_blobs.insert(event_id.clone(), blob);
        }

        let transport_target = resolve_tenant_transport_target(&source, &tenant_id)?;
        let has_local_transport_creds = match &transport_target {
            Some(target) => load_local_creds(&source, &target.transport_peer_id)?.is_some(),
            None => false,
        };

        tenants.push(ImportedTenantState {
            workspace_id: crate::db::store::lookup_workspace_id(&source, &tenant_id),
            peer_id: tenant_id.clone(),
            transport_peer_id: transport_target
                .as_ref()
                .map(|target| target.transport_peer_id.clone()),
            transport_source: transport_target
                .as_ref()
                .map(|target| target.source.clone()),
            has_local_transport_creds,
            known_event_ids,
            authorized_transport_rows: list_authorized_transport_rows(&source, &tenant_id)?,
            bootstrap_targets: list_active_invite_bootstrap_targets(&source, &tenant_id)?,
        });
    }

    Ok(ImportedPeerDbState {
        source_db_path: source_db_path.to_string(),
        event_blobs,
        tenants,
    })
}

fn collect_importable_tenant_ids(
    conn: &rusqlite::Connection,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT tenant_id AS id FROM local_transport_targets
         UNION
         SELECT recorded_by AS id FROM invites_accepted
         ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>()
}

fn collect_recorded_event_ids(
    conn: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT event_id
         FROM recorded_events
         WHERE peer_id = ?1
         ORDER BY id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        row.get::<_, String>(0)
    })?;
    rows.collect::<Result<Vec<_>, _>>()
}

fn copy_known_event_store(
    source: &rusqlite::Connection,
    dest: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<(), rusqlite::Error> {
    let mut stmt = source.prepare(
        "SELECT
             re.peer_id,
             re.event_id,
             re.recorded_at,
             re.source,
             e.event_type,
             e.blob,
             e.share_scope,
             e.created_at,
             e.inserted_at
         FROM recorded_events re
         JOIN events e
           ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
         ORDER BY re.id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, i64>(8)?,
        ))
    })?;

    for row in rows {
        let (
            peer_id,
            event_id,
            recorded_at,
            source_tag,
            event_type,
            blob,
            share_scope,
            created_at,
            inserted_at,
        ) = row?;
        dest.execute(
            "INSERT OR IGNORE INTO events
             (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                event_id,
                event_type,
                blob,
                share_scope,
                created_at,
                inserted_at
            ],
        )?;
        dest.execute(
            "INSERT OR IGNORE INTO recorded_events
             (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![peer_id, event_id, recorded_at, source_tag],
        )?;
    }

    Ok(())
}

fn copy_shared_event_index(
    source: &rusqlite::Connection,
    dest: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<(), rusqlite::Error> {
    let Some(workspace_id) = crate::db::store::lookup_workspace_id(source, recorded_by) else {
        return Ok(());
    };

    let mut stmt = source.prepare(
        "SELECT workspace_id, ts, id
         FROM shared_event_index
         WHERE workspace_id = ?1
         ORDER BY ts ASC, id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![workspace_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    for row in rows {
        let (workspace_id, ts, id) = row?;
        dest.execute(
            "INSERT OR IGNORE INTO shared_event_index (workspace_id, ts, id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![workspace_id, ts, id],
        )?;
    }
    Ok(())
}

fn copy_invite_secrets(
    source: &rusqlite::Connection,
    dest: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<(), rusqlite::Error> {
    let mut stmt = source.prepare(
        "SELECT recorded_by, event_id, invite_event_id, private_key, created_at
         FROM invite_secrets
         WHERE recorded_by = ?1
         ORDER BY created_at ASC, event_id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    for row in rows {
        let (recorded_by, event_id, invite_event_id, private_key, created_at) = row?;
        dest.execute(
            "INSERT OR IGNORE INTO invite_secrets
             (recorded_by, event_id, invite_event_id, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                recorded_by,
                event_id,
                invite_event_id,
                private_key,
                created_at
            ],
        )?;
    }
    Ok(())
}

fn copy_peer_secrets(
    source: &rusqlite::Connection,
    dest: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<(), rusqlite::Error> {
    let mut stmt = source.prepare(
        "SELECT recorded_by, event_id, signer_event_id, private_key, created_at
         FROM peer_secrets
         WHERE recorded_by = ?1
         ORDER BY created_at ASC, event_id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    for row in rows {
        let (recorded_by, event_id, signer_event_id, private_key, created_at) = row?;
        dest.execute(
            "INSERT OR IGNORE INTO peer_secrets
             (recorded_by, event_id, signer_event_id, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                recorded_by,
                event_id,
                signer_event_id,
                private_key,
                created_at
            ],
        )?;
    }
    Ok(())
}

fn copy_bootstrap_context(
    source: &rusqlite::Connection,
    dest: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<(), rusqlite::Error> {
    let mut stmt = source.prepare(
        "SELECT
             recorded_by,
             invite_event_id,
             workspace_id,
             bootstrap_addr,
             bootstrap_spki_fingerprint,
             observed_at
         FROM bootstrap_context
         WHERE recorded_by = ?1
         ORDER BY observed_at ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    for row in rows {
        let (
            recorded_by,
            invite_event_id,
            workspace_id,
            bootstrap_addr,
            bootstrap_spki_fingerprint,
            observed_at,
        ) = row?;
        dest.execute(
            "INSERT INTO bootstrap_context
             (recorded_by, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                invite_event_id,
                workspace_id,
                bootstrap_addr,
                bootstrap_spki_fingerprint,
                observed_at
            ],
        )?;
    }
    Ok(())
}

fn copy_peer_endpoint_observations(
    source: &rusqlite::Connection,
    dest: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<(), rusqlite::Error> {
    let mut stmt = source.prepare(
        "SELECT
             recorded_by,
             via_peer_id,
             origin_ip,
             origin_port,
             observed_at,
             expires_at
         FROM peer_endpoint_observations
         WHERE recorded_by = ?1
         ORDER BY observed_at ASC, rowid ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    for row in rows {
        let (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at) = row?;
        dest.execute(
            "INSERT OR IGNORE INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                via_peer_id,
                origin_ip,
                origin_port,
                observed_at,
                expires_at
            ],
        )?;
    }
    Ok(())
}

fn copy_daemon_transport_identity(
    source: &rusqlite::Connection,
    dest: &rusqlite::Connection,
) -> Result<(), rusqlite::Error> {
    let mut stmt = source.prepare(
        "SELECT peer_id, cert_der, key_der, created_at
         FROM daemon_transport_identity
         WHERE singleton_id = 1",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let peer_id: String = row.get(0)?;
        let cert_der: Vec<u8> = row.get(1)?;
        let key_der: Vec<u8> = row.get(2)?;
        let created_at: i64 = row.get(3)?;
        dest.execute(
            "INSERT OR REPLACE INTO daemon_transport_identity
             (singleton_id, peer_id, cert_der, key_der, created_at)
             VALUES (1, ?1, ?2, ?3, ?4)",
            rusqlite::params![peer_id, cert_der, key_der, created_at],
        )?;
    }
    Ok(())
}

fn copy_local_client_ops(
    source: &rusqlite::Connection,
    dest: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<(), rusqlite::Error> {
    let mut stmt = source.prepare(
        "SELECT recorded_by, client_op_id, event_id, op_kind, created_at_ms
         FROM local_client_ops
         WHERE recorded_by = ?1
         ORDER BY created_at_ms ASC, client_op_id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    for row in rows {
        let (recorded_by, client_op_id, event_id, op_kind, created_at_ms) = row?;
        dest.execute(
            "INSERT OR IGNORE INTO local_client_ops
             (recorded_by, client_op_id, event_id, op_kind, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![recorded_by, client_op_id, event_id, op_kind, created_at_ms],
        )?;
    }
    Ok(())
}

fn replay_recorded_events_into_projection(
    dest: &rusqlite::Connection,
    dest_db_path: &str,
    recorded_by: &str,
) -> BridgeResult<()> {
    crate::testutil::run_replay_pass(dest, recorded_by, "forward").map_err(|err| {
        format!("replay exported peer snapshot for tenant `{recorded_by}`: {err}")
    })?;

    const MAX_DRAIN_PASSES: usize = 64;
    for _ in 0..MAX_DRAIN_PASSES {
        let drained = crate::event_pipeline::drain_project_queue(dest_db_path, recorded_by, 1000);
        if drained == 0 {
            return Ok(());
        }
    }

    Err(format!(
        "projection queue did not drain while replaying peer snapshot for tenant `{recorded_by}`"
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::protocol::RpcMethod;

    #[test]
    fn replayed_peer_snapshot_supports_real_rpc_commands_and_queries() {
        let tmpdir = tempfile::tempdir().unwrap();
        let source_db = tmpdir.path().join("source.db");
        let source_daemon = VirtualDaemon::new(source_db.to_str().unwrap());

        let create = source_daemon.call(RpcMethod::CreateWorkspace {
            workspace_name: "snapshot".into(),
            username: "alice".into(),
            device_name: "laptop".into(),
            message_count: 0,
            network_age: None,
            device_chain_length: 0,
        });
        assert!(create.ok, "workspace creation failed: {:?}", create.error);

        let send = source_daemon.call(RpcMethod::Send {
            content: "hello snapshot".into(),
            client_op_id: Some("client-op-1".into()),
        });
        assert!(send.ok, "send failed: {:?}", send.error);

        let active = source_daemon
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("active tenant");
        let recorded_by = active["peer_id"].as_str().expect("active peer id");

        let snapshot = snapshot_peer_db(source_daemon.db_path(), recorded_by).expect("snapshot");
        let snapshot_daemon = snapshot.daemon();

        let source_messages = source_daemon
            .call_ok_value(RpcMethod::Messages { limit: 0 })
            .expect("source messages");
        let snapshot_messages = snapshot_daemon
            .call_ok_value(RpcMethod::Messages { limit: 0 })
            .expect("snapshot messages");
        assert_eq!(snapshot_messages, source_messages);

        let invite = snapshot_daemon
            .call_ok_value(RpcMethod::CreateInvite {
                public_addr: Some("127.0.0.1:7777".into()),
                public_spki: None,
            })
            .expect("create invite on snapshot");
        let invite_link = invite["invite_link"]
            .as_str()
            .expect("invite link")
            .to_string();

        let accepted = snapshot_daemon.call(RpcMethod::AcceptInvite {
            invite: invite_link,
            username: "bob".into(),
            devicename: "phone".into(),
        });
        assert!(accepted.ok, "accept invite failed: {:?}", accepted.error);

        let tenants = snapshot_daemon
            .call_ok_value(RpcMethod::Tenants)
            .expect("tenants on snapshot");
        let tenant_items = tenants.as_array().expect("tenant array");
        assert_eq!(
            tenant_items.len(),
            2,
            "accept invite should create a second tenant"
        );

        let imported = import_peer_db_state(snapshot.db_path()).expect("import snapshot db");
        assert_eq!(
            imported.tenants.len(),
            2,
            "import should see both local tenants"
        );
        assert!(
            imported.unique_event_count() >= 1,
            "import must extract the peer's known event corpus"
        );
        assert!(
            imported
                .tenants
                .iter()
                .all(|tenant| tenant.workspace_id.is_some()),
            "every imported tenant should retain its accepted workspace binding"
        );
        assert!(
            imported
                .tenants
                .iter()
                .any(|tenant| !tenant.authorized_transport_rows.is_empty()),
            "at least one imported tenant should expose transport auth rows for simulator connectivity"
        );
    }
}
