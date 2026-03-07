use rusqlite::Connection;
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
            |row| row.get::<_, String>(0),
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
        let workspace_id: String = row.get(1)?;
        let name: String = row.get(2)?;
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
    pub neg_items_count: i64,
}

/// Query workspace status counts.
pub fn status(db: &Connection, recorded_by: &str) -> StatusResponse {
    let events_count: i64 = db
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap_or(0);
    let messages_count = message::count(db, recorded_by).unwrap_or(0);
    let reactions_count = reaction::count(db, recorded_by).unwrap_or(0);
    let neg_items_count: i64 = db
        .query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
        .unwrap_or(0);
    let recorded_events_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);

    StatusResponse {
        events_count,
        messages_count,
        reactions_count,
        recorded_events_count,
        neg_items_count,
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

// ---------------------------------------------------------------------------
// View types and functions (moved from service.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewReaction {
    pub emoji: String,
    pub reactor_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewMessage {
    pub id: String,
    pub author_id: String,
    pub author_name: String,
    pub content: String,
    pub created_at: i64,
    pub reactions: Vec<ViewReaction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_op_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewResponse {
    pub workspace_name: String,
    pub users: Vec<user::UserItem>,
    pub accounts: Vec<peer_shared::AccountItem>,
    pub own_user_event_id: String,
    pub messages: Vec<ViewMessage>,
}

/// Build a full workspace view: workspace name, users, accounts, messages with reactions.
pub fn view(
    db: &Connection,
    recorded_by: &str,
    limit: usize,
) -> Result<ViewResponse, Box<dyn std::error::Error + Send + Sync>> {
    // Workspace name
    let workspace_name = name(db, recorded_by).unwrap_or_default();

    // Users
    let users = user::list_items(db, recorded_by)?;

    // Own user_event_id (for marking "you")
    let own_user_eid: String =
        if let Some((signer_eid, _)) = peer_shared::load_local_peer_signer(db, recorded_by)? {
            peer_shared::resolve_user_event_id(db, recorded_by, &signer_eid)
                .map(|eid| crate::crypto::event_id_to_base64(&eid))
                .unwrap_or_default()
        } else {
            String::new()
        };

    // Accounts (peers)
    let accounts: Vec<peer_shared::AccountItem> = peer_shared::list_accounts(db, recorded_by)?
        .into_iter()
        .map(|row| peer_shared::AccountItem {
            event_id: row.event_id,
            device_name: row.device_name,
            user_event_id: row.user_event_id,
            username: row.username,
        })
        .collect();

    // Messages with author names
    let msg_resp = message::list(db, recorded_by, limit)?;

    // Load client_op_id mappings for annotation
    let client_ops = crate::db::local_client_ops::all_mappings(db, recorded_by).unwrap_or_default();

    // Reactions per message
    let mut view_messages = Vec::with_capacity(msg_resp.messages.len());
    for msg in msg_resp.messages {
        let reactions: Vec<ViewReaction> =
            reaction::list_for_message_with_authors(db, recorded_by, &msg.id_b64)?
                .into_iter()
                .map(|r| ViewReaction {
                    emoji: r.emoji,
                    reactor_name: r.reactor_name,
                })
                .collect();

        let client_op_id = client_ops.get(&msg.id_b64).cloned();

        view_messages.push(ViewMessage {
            id: msg.id_b64,
            author_id: msg.author_id,
            author_name: msg.author_name,
            content: msg.content,
            created_at: msg.created_at,
            reactions,
            client_op_id,
        });
    }

    Ok(ViewResponse {
        workspace_name,
        users,
        accounts,
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
