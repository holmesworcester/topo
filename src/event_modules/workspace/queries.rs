use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::crypto::event_id_from_base64;
use crate::event_modules::{admin, message, peer_shared, reaction, user};
use crate::service::open_db_for_peer;

/// Look up the workspace_id for a peer from invites_accepted projection rows.
pub fn resolve_workspace_for_peer(
    db: &Connection,
    peer_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let ws_b64: String = db
        .query_row(
            "SELECT workspace_id
             FROM invites_accepted
             WHERE recorded_by = ?1
             ORDER BY created_at ASC, event_id ASC
             LIMIT 1",
            rusqlite::params![peer_id],
            |row| row.get(0),
        )
        .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
            format!("no workspace found for peer {}", peer_id).into()
        })?;
    event_id_from_base64(&ws_b64)
        .ok_or_else(|| format!("invalid workspace_id in invites_accepted: {}", ws_b64).into())
}

pub struct WorkspaceRow {
    pub event_id: String,
    pub workspace_id: String,
    pub name: String,
}

pub fn list(db: &Connection, recorded_by: &str) -> Result<Vec<WorkspaceRow>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT event_id, workspace_id, COALESCE(name, '')
         FROM workspaces
         WHERE recorded_by = ?1
         ORDER BY event_id",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(WorkspaceRow {
                event_id: row.get(0)?,
                workspace_id: row.get(1)?,
                name: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Return the workspace display name for the first workspace, or empty string.
pub fn name(db: &Connection, recorded_by: &str) -> Result<String, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    Ok(db
        .query_row(
            "SELECT COALESCE(name, '') FROM workspaces WHERE recorded_by = ?1 LIMIT 1",
            rusqlite::params![recorded_by],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .optional()?
        .unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Response types & high-level query functions
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceItem {
    pub event_id: String,
    pub workspace_id: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ViewTenant {
    pub event_id: String,
    pub peer_id: String,
    pub username: String,
    pub workspace_id: String,
    pub workspace_name: String,
    pub active: bool,
    pub ready: bool,
}

/// List workspace items (response type) from the database.
pub fn list_items(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<WorkspaceItem>, rusqlite::Error> {
    let rows = list(db, recorded_by)?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let name = if row.name.is_empty() {
                row.workspace_id.clone()
            } else {
                row.name
            };
            WorkspaceItem {
                event_id: row.event_id,
                workspace_id: row.workspace_id,
                name,
            }
        })
        .collect())
}

pub fn list_all_items(db: &Connection) -> Result<Vec<WorkspaceItem>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT MIN(event_id) AS event_id, workspace_id, COALESCE(MAX(name), '')
         FROM workspaces
         GROUP BY workspace_id
         ORDER BY MIN(event_id)",
    )?;
    let rows = stmt.query_map([], |row| {
        let workspace_id = crate::db::sql_types::get_text(row, 1)?;
        let name = crate::db::sql_types::get_text(row, 2)?;
        Ok(WorkspaceItem {
            event_id: row.get(0)?,
            workspace_id: workspace_id.clone(),
            name: if name.is_empty() { workspace_id } else { name },
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub events_count: i64,
    pub messages_count: i64,
    pub reactions_count: i64,
    pub recorded_events_count: i64,
    pub shared_event_index_count: i64,
    pub tenants: Vec<ViewTenant>,
}

/// Query workspace status counts.
pub fn status(db: &Connection, recorded_by: &str) -> StatusResponse {
    let events_count: i64 = db
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap_or(0);
    let messages_count = message::count(db, recorded_by).unwrap_or(0);
    let reactions_count = reaction::count(db, recorded_by).unwrap_or(0);
    let shared_event_index_count: i64 = db
        .query_row("SELECT COUNT(*) FROM shared_event_index", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    let recorded_events_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let tenants = list_tenants_for_display(db, recorded_by).unwrap_or_default();

    StatusResponse {
        events_count,
        messages_count,
        reactions_count,
        recorded_events_count,
        shared_event_index_count,
        tenants,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysResponse {
    pub user_count: i64,
    pub peer_count: i64,
    pub admin_count: i64,
    pub users: Vec<String>,
    pub peers: Vec<String>,
    pub admins: Vec<String>,
}

/// Query key counts and optionally list event IDs.
pub fn keys(
    db: &Connection,
    recorded_by: &str,
    summary: bool,
) -> Result<KeysResponse, rusqlite::Error> {
    let user_count = user::count(db, recorded_by).unwrap_or(0);
    let peer_count = peer_shared::count(db, recorded_by).unwrap_or(0);
    let admin_count = admin::count(db, recorded_by).unwrap_or(0);
    let mut users = Vec::new();
    let mut peers = Vec::new();
    let mut admins = Vec::new();

    if !summary {
        users = user::list(db, recorded_by)?
            .into_iter()
            .map(|row| row.event_id)
            .collect();
        peers = peer_shared::list_event_ids(db, recorded_by)?;
        admins = admin::list_event_ids(db, recorded_by)?;
    }

    Ok(KeysResponse {
        user_count,
        peer_count,
        admin_count,
        users,
        peers,
        admins,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContentKeysResponse {
    pub key_secret_count: i64,
    pub latest_key_event_id: Option<String>,
    pub keys: Vec<String>,
}

pub fn content_keys(
    db: &Connection,
    recorded_by: &str,
    summary: bool,
) -> Result<ContentKeysResponse, rusqlite::Error> {
    let key_secret_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM key_secrets WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )?;

    let mut stmt = db.prepare(
        "SELECT ks.event_id
         FROM key_secrets ks
         JOIN events e
           ON e.event_id = ks.event_id
         WHERE ks.recorded_by = ?1
         ORDER BY e.created_at DESC, ks.event_id DESC",
    )?;
    let keys = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let latest_key_event_id = keys.first().cloned();

    Ok(ContentKeysResponse {
        key_secret_count,
        latest_key_event_id,
        keys: if summary { Vec::new() } else { keys },
    })
}

// ---------------------------------------------------------------------------
// View types and functions (moved from service.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewReaction {
    pub emoji: String,
    pub reactor_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewFileSummary {
    pub filename: String,
    pub mime_type: String,
    pub blob_bytes: i64,
    pub total_slices: i64,
    pub slices_received: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewMessage {
    pub id: String,
    pub author_id: String,
    pub author_name: String,
    pub content: String,
    pub created_at: i64,
    pub reactions: Vec<ViewReaction>,
    pub files: Vec<ViewFileSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_op_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewUser {
    pub event_id: String,
    pub peer_event_id: String,
    pub username: String,
    pub device_name: String,
}

#[derive(Debug)]
struct ViewTenantScopeRow {
    peer_id: String,
    tenant_event_id: String,
    workspace_id: String,
}

fn list_view_users(db: &Connection, recorded_by: &str) -> Result<Vec<ViewUser>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT COALESCE(ps.user_event_id, ''),
                ps.event_id,
                COALESCE(u.username, ''),
                COALESCE(ps.device_name, '')
         FROM peers_shared ps
         LEFT JOIN users u
           ON ps.user_event_id = u.event_id
          AND ps.recorded_by = u.recorded_by
         WHERE ps.recorded_by = ?1
         ORDER BY LOWER(COALESCE(u.username, '')),
                  LOWER(COALESCE(ps.device_name, '')),
                  ps.event_id",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(ViewUser {
                event_id: row.get(0)?,
                peer_event_id: row.get(1)?,
                username: row.get(2)?,
                device_name: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn list_view_tenant_scopes(db: &Connection) -> Result<Vec<ViewTenantScopeRow>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT recorded_by, tenant_event_id, workspace_id
         FROM invites_accepted
         ORDER BY recorded_by, created_at ASC, event_id ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut scopes = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while let Some(row) = rows.next()? {
        let peer_id = crate::db::sql_types::get_text(row, 0)?;
        if !seen.insert(peer_id.clone()) {
            continue;
        }
        scopes.push(ViewTenantScopeRow {
            peer_id,
            tenant_event_id: row.get(1)?,
            workspace_id: row.get(2)?,
        });
    }
    Ok(scopes)
}

fn tenant_workspace_name(
    db: &Connection,
    recorded_by: &str,
    workspace_id: &str,
) -> Result<String, rusqlite::Error> {
    Ok(db
        .query_row(
            "SELECT COALESCE(name, '')
             FROM workspaces
             WHERE recorded_by = ?1
               AND workspace_id = ?2
             LIMIT 1",
            rusqlite::params![recorded_by, workspace_id],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .optional()?
        .unwrap_or_default())
}

fn tenant_local_username(db: &Connection, recorded_by: &str) -> Result<String, rusqlite::Error> {
    if let Some(username) = db
        .query_row(
            "SELECT COALESCE(u.username, '')
             FROM peers_shared ps
             JOIN local_transport_creds c
               ON c.peer_id = lower(hex(ps.transport_fingerprint))
              AND c.peer_id = ?1
             LEFT JOIN users u
               ON ps.user_event_id = u.event_id
              AND ps.recorded_by = u.recorded_by
             WHERE ps.recorded_by = ?1
             ORDER BY ps.event_id ASC
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .optional()?
    {
        return Ok(username);
    }

    Ok(db
        .query_row(
            "SELECT COALESCE(username, '')
             FROM users
             WHERE recorded_by = ?1
             ORDER BY event_id ASC
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .optional()?
        .unwrap_or_default())
}

pub fn list_tenants_for_display(
    db: &Connection,
    active_recorded_by: &str,
) -> Result<Vec<ViewTenant>, rusqlite::Error> {
    let mut tenants = list_view_tenant_scopes(db)?
        .into_iter()
        .map(|scope| {
            let workspace_name = tenant_workspace_name(db, &scope.peer_id, &scope.workspace_id)?;
            let username = tenant_local_username(db, &scope.peer_id)?;
            Ok(ViewTenant {
                event_id: scope.tenant_event_id,
                peer_id: scope.peer_id.clone(),
                username,
                workspace_id: scope.workspace_id,
                workspace_name,
                active: scope.peer_id == active_recorded_by,
                ready: super::load_local_authoring_context(db, &scope.peer_id).is_ok(),
            })
        })
        .collect::<Result<Vec<_>, rusqlite::Error>>()?;

    tenants.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then_with(|| a.workspace_name.cmp(&b.workspace_name))
            .then_with(|| a.username.cmp(&b.username))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });

    Ok(tenants)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewResponse {
    pub workspace_name: String,
    pub users: Vec<ViewUser>,
    #[serde(alias = "accounts")]
    pub tenants: Vec<ViewTenant>,
    pub own_user_event_id: String,
    pub messages: Vec<ViewMessage>,
}

/// Build the combined view: DB-global local tenants, active-workspace user/devices,
/// and messages with reactions/files.
pub fn view(
    db: &Connection,
    recorded_by: &str,
    limit: usize,
) -> Result<ViewResponse, Box<dyn std::error::Error + Send + Sync>> {
    // Workspace name
    let workspace_name = name(db, recorded_by).unwrap_or_default();

    // Workspace users/devices
    let users = list_view_users(db, recorded_by)?;

    // Own user_event_id (for marking "you")
    let own_user_eid: String =
        if let Some((signer_eid, _)) = peer_shared::load_local_peer_signer(db, recorded_by)? {
            peer_shared::resolve_user_event_id(db, recorded_by, &signer_eid)
                .map(|eid| crate::crypto::event_id_to_base64(&eid))
                .unwrap_or_default()
        } else {
            String::new()
        };

    // Top-level local tenants (DB-global, not workspace peers)
    let tenants = list_tenants_for_display(db, recorded_by)?;

    // Messages with author names, reactions, files, and client_op_ids
    // (message::list already loads all of these per message)
    let msg_resp = message::list(db, recorded_by, limit)?;

    let view_messages: Vec<ViewMessage> = msg_resp
        .messages
        .into_iter()
        .map(|msg| ViewMessage {
            id: msg.id_b64,
            author_id: msg.author_id,
            author_name: msg.author_name,
            content: msg.content,
            created_at: msg.created_at,
            reactions: msg
                .reactions
                .into_iter()
                .map(|r| ViewReaction {
                    emoji: r.emoji,
                    reactor_name: r.reactor_name,
                })
                .collect(),
            files: msg
                .files
                .into_iter()
                .map(|f| ViewFileSummary {
                    filename: f.filename,
                    mime_type: f.mime_type,
                    blob_bytes: f.blob_bytes,
                    total_slices: f.total_slices,
                    slices_received: f.slices_received,
                })
                .collect(),
            client_op_id: msg.client_op_id,
        })
        .collect();

    Ok(ViewResponse {
        workspace_name,
        users,
        tenants,
        own_user_event_id: own_user_eid,
        messages: view_messages,
    })
}

/// Build a full workspace view for a specific peer.
pub fn view_for_peer(
    db_path: &str,
    peer_id: &str,
    limit: usize,
) -> Result<ViewResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    view(&db, &recorded_by, limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::event_id_to_base64;
    use crate::db::{open_in_memory, schema::create_tables};

    fn insert_local_transport_cred(conn: &Connection, peer_id: &str, tf_byte: u8) {
        let tf_hex = hex::encode([tf_byte; 32]);
        conn.execute(
            "INSERT INTO local_transport_creds (peer_id, cert_der, key_der, created_at, source)
             VALUES (?1, X'AA', X'BB', 1, 'test')",
            rusqlite::params![if peer_id.is_empty() {
                tf_hex
            } else {
                peer_id.to_string()
            }],
        )
        .expect("insert local transport creds");
    }

    fn insert_ready_fixture(
        conn: &Connection,
        recorded_by: &str,
        tf_byte: u8,
        workspace_name: &str,
        username: &str,
        ready: bool,
    ) {
        let tenant_event_id = event_id_to_base64(&[tf_byte.wrapping_add(1); 32]);
        let invite_event_id = event_id_to_base64(&[tf_byte.wrapping_add(2); 32]);
        let workspace_id = event_id_to_base64(&[tf_byte.wrapping_add(3); 32]);
        let workspace_event_id = event_id_to_base64(&[tf_byte.wrapping_add(4); 32]);
        let user_event_id = event_id_to_base64(&[tf_byte.wrapping_add(5); 32]);
        let signer_event_id = event_id_to_base64(&[tf_byte.wrapping_add(6); 32]);

        conn.execute(
            "INSERT INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                event_id_to_base64(&[tf_byte; 32]),
                tenant_event_id,
                invite_event_id,
                workspace_id,
                i64::from(tf_byte),
            ],
        )
        .expect("insert invites_accepted");
        conn.execute(
            "INSERT INTO workspaces
             (recorded_by, event_id, workspace_id, public_key, name)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                recorded_by,
                workspace_event_id,
                workspace_id,
                vec![tf_byte; 32],
                workspace_name,
            ],
        )
        .expect("insert workspace");
        conn.execute(
            "INSERT INTO users (recorded_by, event_id, public_key, username)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                recorded_by,
                user_event_id,
                vec![tf_byte.wrapping_add(1); 32],
                username
            ],
        )
        .expect("insert user");
        conn.execute(
            "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint, user_event_id, device_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                signer_event_id.clone(),
                vec![tf_byte.wrapping_add(2); 32],
                vec![tf_byte; 32],
                user_event_id,
                "device",
            ],
        )
        .expect("insert peer_shared");
        insert_local_transport_cred(conn, recorded_by, tf_byte);
        if ready {
            conn.execute(
                "INSERT INTO peer_secrets
                 (recorded_by, event_id, signer_event_id, private_key, created_at)
                 VALUES (?1, ?2, ?3, ?4, 1)",
                rusqlite::params![
                    recorded_by,
                    signer_event_id.clone(),
                    signer_event_id,
                    vec![tf_byte; 32],
                ],
            )
            .expect("insert peer secret");
        }
    }

    #[test]
    fn view_separates_top_level_tenants_from_workspace_user_devices() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        conn.execute(
            "INSERT INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES
             ('tenant-a', 'ia-a', 'tenant-event-a', 'invite-a', 'ws-design', 1),
             ('tenant-b', 'ia-b', 'tenant-event-b', 'invite-b', 'ws-ops', 2)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspaces
             (recorded_by, event_id, workspace_id, public_key, name)
             VALUES
             ('tenant-a', 'ws-a', 'ws-design', X'AA', 'design'),
             ('tenant-b', 'ws-b', 'ws-ops', X'BB', 'ops')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO users (recorded_by, event_id, public_key, username)
             VALUES
             ('tenant-a', 'user-alice', X'01', 'alice'),
             ('tenant-a', 'user-carol', X'02', 'carol'),
             ('tenant-b', 'user-remote', X'03', 'remote-first'),
             ('tenant-b', 'user-bob', X'04', 'bob')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint, user_event_id, device_name)
             VALUES
             ('tenant-a', 'peer-alice-phone', X'11', ?1, 'user-alice', 'phone'),
             ('tenant-a', 'peer-carol-workstation', X'12', ?2, 'user-carol', 'workstation'),
             ('tenant-b', 'peer-remote', X'13', ?3, 'user-remote', 'shared-box'),
             ('tenant-b', 'peer-bob-laptop', X'14', ?4, 'user-bob', 'laptop')",
            rusqlite::params![
                vec![0x01u8; 32],
                vec![0x09u8; 32],
                vec![0x08u8; 32],
                vec![0x02u8; 32],
            ],
        )
        .unwrap();

        insert_local_transport_cred(&conn, "", 0x01);
        insert_local_transport_cred(&conn, "", 0x02);

        let resp = view(&conn, "tenant-a", 50).expect("view query");

        assert_eq!(resp.workspace_name, "design");
        assert_eq!(resp.users.len(), 2);
        assert_eq!(resp.users[0].username, "alice");
        assert_eq!(resp.users[0].device_name, "phone");
        assert_eq!(resp.users[0].event_id, "user-alice");
        assert_eq!(resp.users[1].username, "carol");
        assert_eq!(resp.users[1].device_name, "workstation");

        assert_eq!(resp.tenants.len(), 2);
        assert!(resp.tenants[0].active, "tenant-a (workspace 'design') should sort first alphabetically and happens to be active");
        assert_eq!(resp.tenants[0].event_id, "tenant-event-a");
        assert_eq!(resp.tenants[0].username, "alice");
        assert_eq!(resp.tenants[0].workspace_name, "design");

        let tenant_b = resp
            .tenants
            .iter()
            .find(|tenant| tenant.peer_id == "tenant-b")
            .expect("tenant-b present");
        assert_eq!(tenant_b.event_id, "tenant-event-b");
        assert_eq!(
            tenant_b.username, "bob",
            "top-level tenant label should use the tenant's local user, not an arbitrary workspace user"
        );
        assert_eq!(tenant_b.workspace_name, "ops");
        assert!(
            !tenant_b.ready,
            "without a local signer, accepted tenants should still render as joining"
        );
    }

    #[test]
    fn list_tenants_for_display_marks_ready_from_authoring_context() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        let joining_peer = hex::encode([0x21u8; 32]);
        let ready_peer = hex::encode([0x42u8; 32]);
        insert_ready_fixture(&conn, &joining_peer, 0x21, "alpha", "alice", false);
        insert_ready_fixture(&conn, &ready_peer, 0x42, "beta", "bob", true);

        let tenants = list_tenants_for_display(&conn, &joining_peer).expect("tenant list");
        let joining = tenants
            .iter()
            .find(|tenant| tenant.peer_id == joining_peer)
            .expect("joining tenant");
        let ready = tenants
            .iter()
            .find(|tenant| tenant.peer_id == ready_peer)
            .expect("ready tenant");

        assert!(joining.active, "active tenant should be marked");
        assert!(!joining.ready, "missing signer should keep tenant joining");
        assert!(
            ready.ready,
            "complete authoring context should mark tenant ready"
        );
    }

    #[test]
    fn status_includes_tenant_readiness() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        let joining_peer = hex::encode([0x31u8; 32]);
        insert_ready_fixture(&conn, &joining_peer, 0x31, "alpha", "alice", false);

        let status = status(&conn, &joining_peer);
        assert_eq!(status.tenants.len(), 1);
        assert_eq!(status.tenants[0].username, "alice");
        assert!(
            !status.tenants[0].ready,
            "status should surface the same joining state as the tenant list"
        );
    }
}
