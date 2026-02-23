use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::crypto::event_id_from_base64;
use crate::event_modules::{admin, message, peer_shared, reaction, transport_key, user};

/// Look up the workspace_id for a peer from trust_anchors.
pub fn resolve_workspace_for_peer(
    db: &Connection,
    peer_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let ws_b64: String = db
        .query_row(
            "SELECT workspace_id FROM trust_anchors WHERE peer_id = ?1",
            rusqlite::params![peer_id],
            |row| row.get(0),
        )
        .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
            format!("no workspace found for peer {}", peer_id).into()
        })?;
    event_id_from_base64(&ws_b64)
        .ok_or_else(|| format!("invalid workspace_id in trust_anchors: {}", ws_b64).into())
}

pub struct WorkspaceRow {
    pub event_id: String,
    pub workspace_id: String,
}

pub fn list(
    db: &Connection,
    recorded_by: &str,
) -> Result<Vec<WorkspaceRow>, rusqlite::Error> {
    let mut stmt =
        db.prepare("SELECT event_id, workspace_id FROM workspaces WHERE recorded_by = ?1")?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(WorkspaceRow {
                event_id: row.get(0)?,
                workspace_id: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Return the workspace display name for the first workspace, or empty string.
pub fn name(
    db: &Connection,
    recorded_by: &str,
) -> Result<String, rusqlite::Error> {
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
    use base64::Engine;
    let rows = list(db, recorded_by)?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let name = if let Ok(bytes) =
                base64::engine::general_purpose::STANDARD.decode(&row.workspace_id)
            {
                String::from_utf8_lossy(&bytes)
                    .trim_end_matches('\0')
                    .to_string()
            } else {
                row.workspace_id.clone()
            };
            WorkspaceItem {
                event_id: row.event_id,
                workspace_id: row.workspace_id,
                name,
            }
        })
        .collect())
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
pub fn status(
    db: &Connection,
    recorded_by: &str,
) -> StatusResponse {
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
    pub transport_count: i64,
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
    let transport_count = transport_key::count(db, recorded_by).unwrap_or(0);

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
        transport_count,
        users,
        peers,
        admins,
    })
}
