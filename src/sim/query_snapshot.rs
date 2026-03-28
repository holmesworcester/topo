use std::collections::BTreeSet;

use serde::Serialize;
use tempfile::TempDir;

use crate::db::open_connection;
use crate::rpc::protocol::RpcMethod;
use crate::runtime::peering::engine::target_planner::{
    load_bootstrap_targets, load_observed_endpoint_targets,
};
use crate::sim::virtual_daemon::VirtualDaemon;
use crate::state::db::store::lookup_workspace_id;
use crate::state::db::transport_creds::{discover_local_tenants, resolve_tenant_transport_target};
use crate::state::db::transport_trust::{
    list_active_invite_bootstrap_targets, list_authorized_transport_rows, AuthorizedTransportRow,
};

/// A temporary SQLite snapshot that can be queried through the real in-process
/// RPC read path for a selected virtual peer view.
pub struct QuerySnapshot {
    _tmpdir: TempDir,
    db_path: String,
    active_peer: Option<String>,
}

impl QuerySnapshot {
    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    pub fn daemon(&self) -> VirtualDaemon {
        let daemon = VirtualDaemon::new(&self.db_path);
        if let Some(peer_id) = &self.active_peer {
            *daemon.state().active_peer.write().unwrap() = Some(peer_id.clone());
        }
        daemon
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedKnownEvent {
    pub event_id: String,
    pub source: String,
    pub created_at_ms: i64,
    pub blob: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportedBootstrapTarget {
    pub invite_event_id: String,
    pub transport_peer_id: String,
    pub bootstrap_addr: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportedObservedTarget {
    pub transport_peer_id: String,
    pub remote: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportedConnectTarget {
    pub source: String,
    pub transport_peer_id: String,
    pub remote: String,
    pub invite_event_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportedBootstrapContextRow {
    pub invite_event_id: String,
    pub workspace_id: String,
    pub bootstrap_addr: String,
    pub bootstrap_spki_fingerprint: Vec<u8>,
    pub observed_at: i64,
}

#[derive(Clone, Debug)]
pub struct ImportedPeerState {
    pub recorded_by: String,
    pub workspace_id: Option<String>,
    pub daemon_peer_id: Option<String>,
    pub local_transport_peer_id: Option<String>,
    pub local_transport_source: Option<String>,
    pub authorized_transport_rows: Vec<AuthorizedTransportRow>,
    pub bootstrap_targets: Vec<ImportedBootstrapTarget>,
    pub bootstrap_context_rows: Vec<ImportedBootstrapContextRow>,
    pub observed_targets: Vec<ImportedObservedTarget>,
    pub connect_targets: Vec<ImportedConnectTarget>,
    pub known_events: Vec<ImportedKnownEvent>,
}

impl ImportedPeerState {
    pub fn connectable_transport_peer_ids(&self) -> BTreeSet<String> {
        self.connect_targets
            .iter()
            .map(|target| target.transport_peer_id.clone())
            .filter(|peer_id| self.local_transport_peer_id.as_ref() != Some(peer_id))
            .collect()
    }
}

/// Export a selected peer view into a fresh DB by copying the tenant's known
/// event corpus and required local replay inputs, then replaying that tenant in
/// the new DB. This produces a real per-peer DB suitable for RPC, CLI, and
/// import back into the simulator.
pub fn snapshot_replayed_peer_to_path(
    source_db_path: &str,
    recorded_by: &str,
    dest_db_path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    super::peer_db_bridge::snapshot_peer_db_to_path(source_db_path, recorded_by, dest_db_path)
}

/// Export a selected peer view into a temporary fresh DB and return an
/// in-process RPC/query harness for that DB.
pub fn snapshot_replayed_peer(
    source_db_path: &str,
    recorded_by: &str,
) -> Result<QuerySnapshot, Box<dyn std::error::Error + Send + Sync>> {
    let tmpdir = tempfile::tempdir()?;
    let db_path = tmpdir
        .path()
        .join("peer-snapshot.db")
        .to_string_lossy()
        .into_owned();
    snapshot_replayed_peer_to_path(source_db_path, recorded_by, &db_path)?;

    Ok(QuerySnapshot {
        _tmpdir: tmpdir,
        db_path,
        active_peer: Some(recorded_by.to_string()),
    })
}

pub fn snapshot_messages_via_rpc(
    source_db_path: &str,
    recorded_by: &str,
    limit: usize,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let snapshot = snapshot_replayed_peer(source_db_path, recorded_by)?;
    let daemon = snapshot.daemon();
    daemon
        .call_ok_value(RpcMethod::Messages { limit })
        .map_err(|err| err.into())
}

/// Import one tenant from a real daemon DB into sparse simulator state.
///
/// The imported structure carries the peer's known event corpus plus the
/// tenant-scoped transport auth and outgoing-target state that should drive
/// simulator connectivity.
pub fn import_peer_state(
    source_db_path: &str,
    recorded_by: &str,
) -> Result<ImportedPeerState, Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(source_db_path)?;
    crate::db::schema::create_tables(&conn)?;

    let daemon_peer_id = crate::db::daemon_identity::load(&conn)?.map(|row| row.peer_id);
    let local_target = resolve_tenant_transport_target(&conn, recorded_by)?;
    let workspace_id = lookup_workspace_id(&conn, recorded_by);
    let authorized_transport_rows = list_authorized_transport_rows(&conn, recorded_by)?;
    let bootstrap_targets = list_active_invite_bootstrap_targets(&conn, recorded_by)?
        .into_iter()
        .map(|target| ImportedBootstrapTarget {
            invite_event_id: target.invite_event_id,
            transport_peer_id: target.transport_peer_id,
            bootstrap_addr: target.bootstrap_addr,
        })
        .collect::<Vec<_>>();
    let mut bootstrap_context_stmt = conn.prepare(
        "SELECT invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, observed_at
         FROM bootstrap_context
         WHERE recorded_by = ?1
         ORDER BY observed_at ASC, rowid ASC",
    )?;
    let bootstrap_context_rows = bootstrap_context_stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(ImportedBootstrapContextRow {
                invite_event_id: row.get(0)?,
                workspace_id: row.get(1)?,
                bootstrap_addr: row.get(2)?,
                bootstrap_spki_fingerprint: row.get(3)?,
                observed_at: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let observed_targets =
        load_observed_endpoint_targets(source_db_path, &[recorded_by.to_string()])?
            .into_iter()
            .map(|(_, transport_peer_id, remote)| ImportedObservedTarget {
                transport_peer_id,
                remote: remote.to_string(),
            })
            .collect::<Vec<_>>();
    let mut connect_targets = Vec::new();
    let mut seen_connect_targets = BTreeSet::new();
    for (_, transport_peer_id, invite_event_id, remote) in
        load_bootstrap_targets(source_db_path, &[recorded_by.to_string()])?
    {
        let remote = remote.to_string();
        if seen_connect_targets.insert((
            "bootstrap".to_string(),
            transport_peer_id.clone(),
            remote.clone(),
        )) {
            connect_targets.push(ImportedConnectTarget {
                source: "bootstrap".into(),
                transport_peer_id,
                remote,
                invite_event_id: Some(invite_event_id),
            });
        }
    }
    for (_, transport_peer_id, remote) in
        load_observed_endpoint_targets(source_db_path, &[recorded_by.to_string()])?
    {
        let remote = remote.to_string();
        if seen_connect_targets.insert((
            "observed".to_string(),
            transport_peer_id.clone(),
            remote.clone(),
        )) {
            connect_targets.push(ImportedConnectTarget {
                source: "observed".into(),
                transport_peer_id,
                remote,
                invite_event_id: None,
            });
        }
    }

    let mut stmt = conn.prepare(
        "SELECT e.event_id, re.source, e.created_at, e.blob
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1
         ORDER BY re.id ASC",
    )?;
    let known_events = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(ImportedKnownEvent {
                event_id: row.get(0)?,
                source: row.get(1)?,
                created_at_ms: row.get(2)?,
                blob: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ImportedPeerState {
        recorded_by: recorded_by.to_string(),
        workspace_id,
        daemon_peer_id,
        local_transport_peer_id: local_target
            .as_ref()
            .map(|target| target.transport_peer_id.clone()),
        local_transport_source: local_target.as_ref().map(|target| target.source.clone()),
        authorized_transport_rows,
        bootstrap_targets,
        bootstrap_context_rows,
        observed_targets,
        connect_targets,
        known_events,
    })
}

pub fn import_local_tenants_from_db(
    source_db_path: &str,
) -> Result<Vec<ImportedPeerState>, Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(source_db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let tenants = discover_local_tenants(&conn)?;
    drop(conn);

    tenants
        .into_iter()
        .map(|tenant| import_peer_state(source_db_path, &tenant.peer_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::workspace::commands::CreateInviteResponse;

    #[test]
    fn replayed_peer_snapshot_supports_real_rpc_queries_and_local_writes() {
        let tmpdir = tempfile::tempdir().unwrap();
        let source_db = tmpdir.path().join("source.db");
        let source_daemon = VirtualDaemon::new(source_db.to_str().unwrap());

        let create = source_daemon.call_ok_value(RpcMethod::CreateWorkspace {
            workspace_name: "snapshot".into(),
            username: "alice".into(),
            device_name: "laptop".into(),
        });
        let creator_peer_id = create.expect("workspace creation through RPC")["peer_id"]
            .as_str()
            .expect("creator peer id")
            .to_string();

        let send = source_daemon
            .call_ok_value(RpcMethod::Send {
                content: "hello snapshot".into(),
                client_op_id: None,
            })
            .expect("send through RPC");
        let message_event_id = send["event_id"]
            .as_str()
            .expect("message event id")
            .to_string();
        let reacted = source_daemon.call(RpcMethod::React {
            target: message_event_id.clone(),
            emoji: ":+1:".into(),
            client_op_id: None,
        });
        assert!(reacted.ok, "react failed: {:?}", reacted.error);

        let generate = source_daemon.call(RpcMethod::Generate {
            count: 3,
            history_span: Some("1d".into()),
        });
        assert!(generate.ok, "generate failed: {:?}", generate.error);

        let invite = source_daemon.call(RpcMethod::CreateInvite {
            public_addr: Some("127.0.0.1:4242".into()),
            public_spki: Some(creator_peer_id),
        });
        assert!(invite.ok, "create invite failed: {:?}", invite.error);

        let active = source_daemon
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("active tenant");
        let recorded_by = active["peer_id"].as_str().expect("active peer id");

        let source_messages = source_daemon
            .call_ok_value(RpcMethod::Messages { limit: 0 })
            .expect("source messages via real RPC");
        let source_stats = source_daemon
            .call_ok_value(RpcMethod::Stats)
            .expect("source stats via real RPC");
        let source_transport_auth = source_daemon
            .call_ok_value(RpcMethod::TransportAuth)
            .expect("source transport auth via real RPC");
        let source_users = source_daemon
            .call_ok_value(RpcMethod::Users)
            .expect("source users via real RPC");
        let source_reactions = source_daemon
            .call_ok_value(RpcMethod::Reactions)
            .expect("source reactions via real RPC");
        let source_workspaces = source_daemon
            .call_ok_value(RpcMethod::Workspaces)
            .expect("source workspaces via real RPC");
        let source_identity = source_daemon
            .call_ok_value(RpcMethod::Identity)
            .expect("source identity via real RPC");
        let source_view = source_daemon
            .call_ok_value(RpcMethod::View { limit: 20 })
            .expect("source view via real RPC");
        let source_event_list = source_daemon
            .call_ok_value(RpcMethod::EventList)
            .expect("source event list via real RPC");

        let snapshot =
            snapshot_replayed_peer(source_daemon.db_path(), recorded_by).expect("snapshot");
        let snapshot_daemon = snapshot.daemon();

        let messages = snapshot_daemon
            .call_ok_value(RpcMethod::Messages { limit: 0 })
            .expect("messages via snapshot RPC");
        let stats = snapshot_daemon
            .call_ok_value(RpcMethod::Stats)
            .expect("stats via snapshot RPC");
        let transport_auth = snapshot_daemon
            .call_ok_value(RpcMethod::TransportAuth)
            .expect("transport auth via snapshot RPC");
        let users = snapshot_daemon
            .call_ok_value(RpcMethod::Users)
            .expect("users via snapshot RPC");
        let reactions = snapshot_daemon
            .call_ok_value(RpcMethod::Reactions)
            .expect("reactions via snapshot RPC");
        let workspaces = snapshot_daemon
            .call_ok_value(RpcMethod::Workspaces)
            .expect("workspaces via snapshot RPC");
        let identity = snapshot_daemon
            .call_ok_value(RpcMethod::Identity)
            .expect("identity via snapshot RPC");
        let view = snapshot_daemon
            .call_ok_value(RpcMethod::View { limit: 20 })
            .expect("view via snapshot RPC");
        let event_list = snapshot_daemon
            .call_ok_value(RpcMethod::EventList)
            .expect("event list via snapshot RPC");

        assert_eq!(messages, source_messages);
        assert_eq!(stats, source_stats);
        assert_eq!(transport_auth, source_transport_auth);
        assert_eq!(users, source_users);
        assert_eq!(reactions, source_reactions);
        assert_eq!(workspaces, source_workspaces);
        assert_eq!(identity, source_identity);
        assert_eq!(view, source_view);
        assert_eq!(event_list, source_event_list);

        let snapshot_send = snapshot_daemon.call(RpcMethod::Send {
            content: "hello from snapshot".into(),
            client_op_id: Some("snapshot-send".into()),
        });
        assert!(
            snapshot_send.ok,
            "send on exported peer snapshot failed: {:?}",
            snapshot_send.error
        );
        let snapshot_invite = snapshot_daemon.call(RpcMethod::CreateInvite {
            public_addr: Some("127.0.0.1:7777".into()),
            public_spki: None,
        });
        assert!(
            snapshot_invite.ok,
            "create invite on exported peer snapshot failed: {:?}",
            snapshot_invite.error
        );
    }

    #[test]
    fn imported_peer_state_derives_bootstrap_targets_from_real_invite_flow() {
        let tmpdir = tempfile::tempdir().unwrap();
        let creator_db = tmpdir.path().join("creator.db");
        let joiner_db = tmpdir.path().join("joiner.db");
        let creator = VirtualDaemon::new(creator_db.to_str().unwrap());
        let joiner = VirtualDaemon::new(joiner_db.to_str().unwrap());

        let created = creator
            .call_ok_value(RpcMethod::CreateWorkspace {
                workspace_name: "sim".into(),
                username: "alice".into(),
                device_name: "laptop".into(),
            })
            .expect("creator workspace");
        let creator_peer_id = created["peer_id"]
            .as_str()
            .expect("creator peer id")
            .to_string();

        let invite: CreateInviteResponse = creator
            .call_ok(RpcMethod::CreateInvite {
                public_addr: Some("127.0.0.1:4242".into()),
                public_spki: Some(creator_peer_id.clone()),
            })
            .expect("create invite");

        let accepted = joiner.call(RpcMethod::AcceptInvite {
            invite: invite.invite_link,
            username: "bob".into(),
            devicename: "phone".into(),
        });
        assert!(accepted.ok, "accept invite failed: {:?}", accepted.error);

        let creator_active = creator
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("creator active tenant");
        let creator_recorded_by = creator_active["peer_id"]
            .as_str()
            .expect("creator active peer id");
        let joiner_active = joiner
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("joiner active tenant");
        let joiner_recorded_by = joiner_active["peer_id"]
            .as_str()
            .expect("joiner active peer id");

        let creator_import =
            import_peer_state(creator.db_path(), creator_recorded_by).expect("import creator");
        let joiner_import =
            import_peer_state(joiner.db_path(), joiner_recorded_by).expect("import joiner");

        assert!(!creator_import.known_events.is_empty());
        assert!(!joiner_import.known_events.is_empty());
        assert_eq!(
            creator_import.local_transport_peer_id.as_deref(),
            Some(creator_recorded_by)
        );
        assert!(
            creator_import
                .authorized_transport_rows
                .iter()
                .any(|row| row.source == "pending_bootstrap"),
            "creator should authorize pending bootstrap invitee transport"
        );
        assert!(
            joiner_import
                .authorized_transport_rows
                .iter()
                .any(|row| row.source == "accepted_bootstrap"
                    && row.transport_peer_id == creator_peer_id),
            "joiner should authorize creator bootstrap transport"
        );
        assert!(
            joiner_import.bootstrap_targets.iter().any(|target| {
                target.transport_peer_id == creator_peer_id
                    && target.bootstrap_addr == "127.0.0.1:4242"
            }),
            "joiner should have a real bootstrap dial target to the creator"
        );
        assert!(
            joiner_import.connect_targets.iter().any(|target| {
                target.source == "bootstrap"
                    && target.transport_peer_id == creator_peer_id
                    && target.remote == "127.0.0.1:4242"
            }),
            "joiner connect targets should come from the real bootstrap planner"
        );
        assert!(
            joiner_import
                .connectable_transport_peer_ids()
                .contains(&creator_peer_id),
            "joiner outgoing connect set should include the creator transport peer"
        );
    }

    #[test]
    fn exported_peer_db_supports_same_db_join_and_reimported_bootstrap_connectivity() {
        let tmpdir = tempfile::tempdir().unwrap();
        let source_db = tmpdir.path().join("source.db");
        let export_db = tmpdir.path().join("user999999.db");
        let source_daemon = VirtualDaemon::new(source_db.to_str().unwrap());

        let created = source_daemon
            .call_ok_value(RpcMethod::CreateWorkspace {
                workspace_name: "snapshot".into(),
                username: "alice".into(),
                device_name: "laptop".into(),
            })
            .expect("workspace creation through RPC");
        let creator_peer_id = created["peer_id"]
            .as_str()
            .expect("creator peer id")
            .to_string();

        let recorded_by = source_daemon
            .call_ok_value(RpcMethod::ActiveTenant)
            .expect("active tenant")["peer_id"]
            .as_str()
            .expect("active peer id")
            .to_string();

        snapshot_replayed_peer_to_path(
            source_daemon.db_path(),
            &recorded_by,
            export_db.to_str().unwrap(),
        )
        .expect("export selected peer db");

        let exported = VirtualDaemon::new(export_db.to_str().unwrap());
        let tenants_before = exported
            .call_ok_value(RpcMethod::Tenants)
            .expect("tenants before join");
        assert_eq!(
            tenants_before.as_array().expect("tenant array").len(),
            1,
            "selected-peer export should start with one tenant"
        );

        let invite: CreateInviteResponse = exported
            .call_ok(RpcMethod::CreateInvite {
                public_addr: Some("127.0.0.1:4242".into()),
                public_spki: Some(creator_peer_id.clone()),
            })
            .expect("create invite on exported db");
        let accepted = exported
            .call_ok_value(RpcMethod::AcceptInvite {
                invite: invite.invite_link,
                username: "bob".into(),
                devicename: "phone".into(),
            })
            .expect("accept invite on exported db");
        let joiner_peer_id = accepted["peer_id"]
            .as_str()
            .expect("joiner peer id")
            .to_string();

        let tenants_after = exported
            .call_ok_value(RpcMethod::Tenants)
            .expect("tenants after join");
        assert_eq!(
            tenants_after.as_array().expect("tenant array").len(),
            2,
            "same-db invite acceptance should create a second tenant"
        );

        let imported = import_local_tenants_from_db(export_db.to_str().unwrap())
            .expect("re-import exported db");
        assert_eq!(
            imported.len(),
            2,
            "re-import should discover both local tenants"
        );
        let joiner_import = imported
            .iter()
            .find(|tenant| tenant.recorded_by == joiner_peer_id)
            .expect("imported joiner tenant");
        assert!(
            joiner_import
                .authorized_transport_rows
                .iter()
                .any(|row| row.source == "accepted_bootstrap"
                    && row.transport_peer_id == creator_peer_id),
            "joiner should import real accepted-bootstrap auth rows"
        );
        assert!(
            joiner_import.connect_targets.iter().any(|target| {
                target.source == "bootstrap"
                    && target.transport_peer_id == creator_peer_id
                    && target.remote == "127.0.0.1:4242"
            }),
            "joiner should import the real runtime bootstrap dial target"
        );
        assert!(
            joiner_import
                .connectable_transport_peer_ids()
                .contains(&creator_peer_id),
            "joiner outgoing connect set should include the creator transport peer"
        );

        let joiner_snapshot = snapshot_replayed_peer(export_db.to_str().unwrap(), &joiner_peer_id)
            .expect("snapshot exported joiner");
        let joiner_rpc = joiner_snapshot.daemon();
        let joiner_auth = joiner_rpc
            .call_ok_value(RpcMethod::TransportAuth)
            .expect("joiner transport auth on replayed exported snapshot");
        assert!(
            joiner_auth
                .as_array()
                .expect("transport auth rows")
                .iter()
                .any(|row| row["source"] == "accepted_bootstrap"),
            "replayed joiner snapshot should remain operational for transport-auth queries"
        );
    }
}
