use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, EventId};
use crate::db::store::{insert_recorded_event, lookup_workspace_id};
use crate::event_modules::ShareScope;
use crate::projection::apply::project_one;
use crate::state::db::project_queue::ProjectQueue;
use crate::transport::cert::extract_spki_fingerprint;

const FANOUT_SOURCE_PREFIX: &str = "same_workspace_fanout";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SharedEventFanout {
    pub origin_peer_id: String,
    pub workspace_id: String,
    pub event_id: EventId,
}

fn sibling_tenants_in_workspace(
    conn: &Connection,
    origin_peer_id: &str,
    workspace_id: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT recorded_by
         FROM invites_accepted
         WHERE workspace_id = ?1 AND recorded_by <> ?2
         ORDER BY recorded_by",
    )?;
    let rows = stmt.query_map(rusqlite::params![workspace_id, origin_peer_id], |row| {
        row.get::<_, String>(0)
    })?;
    rows.collect::<Result<Vec<_>, _>>()
}

fn fanout_source(origin_peer_id: &str) -> String {
    format!("{FANOUT_SOURCE_PREFIX}:{origin_peer_id}")
}

/// Check if a sibling tenant has been removed by looking up their local
/// transport cert's SPKI fingerprint and checking removal_watch.
fn is_sibling_removed(conn: &Connection, sibling_peer_id: &str) -> bool {
    // Load sibling's cert from local_transport_creds
    let cert_der: Option<Vec<u8>> = conn
        .query_row(
            "SELECT cert_der FROM local_transport_creds WHERE peer_id = ?1",
            rusqlite::params![sibling_peer_id],
            |row| row.get(0),
        )
        .ok();
    let Some(cert_der) = cert_der else {
        return false;
    };
    let Ok(spki) = extract_spki_fingerprint(&cert_der) else {
        return false;
    };
    crate::state::db::removal_watch::is_peer_removed(conn, sibling_peer_id, &spki).unwrap_or(false)
}

pub(crate) fn fanout_stored_shared_event_immediate(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let event_id_b64 = event_id_to_base64(event_id);
    let (event_type, share_scope): (String, String) = conn.query_row(
        "SELECT event_type, share_scope FROM events WHERE event_id = ?1",
        rusqlite::params![&event_id_b64],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if share_scope != ShareScope::Shared.as_str() {
        return Ok(());
    }

    let workspace_id = if event_type == "workspace" {
        event_id_b64
    } else if let Some(workspace_id) = lookup_workspace_id(conn, recorded_by) {
        workspace_id
    } else {
        tracing::warn!(
            "shared event {} valid for {} without workspace binding; skipping sibling fanout",
            event_id_to_base64(event_id),
            recorded_by
        );
        return Ok(());
    };

    fanout_shared_event_immediate(conn, recorded_by, &workspace_id, event_id)
}

pub(crate) fn fanout_shared_event_immediate(
    conn: &Connection,
    origin_peer_id: &str,
    workspace_id: &str,
    event_id: &EventId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let siblings = sibling_tenants_in_workspace(conn, origin_peer_id, workspace_id)?;
    if siblings.is_empty() {
        return Ok(());
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let source = fanout_source(origin_peer_id);

    let active_siblings: Vec<&String> = siblings
        .iter()
        .filter(|s| !is_sibling_removed(conn, s))
        .collect();
    for sibling in &active_siblings {
        insert_recorded_event(conn, sibling, event_id, now_ms, &source)?;
    }
    for sibling in &active_siblings {
        let _ = project_one(conn, sibling, event_id)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    }

    Ok(())
}

pub(crate) fn fanout_shared_event_enqueue(
    conn: &Connection,
    fanout: &SharedEventFanout,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let siblings =
        sibling_tenants_in_workspace(conn, &fanout.origin_peer_id, &fanout.workspace_id)?;
    if siblings.is_empty() {
        return Ok(Vec::new());
    }

    let pq = ProjectQueue::new(conn);
    let event_id_b64 = event_id_to_base64(&fanout.event_id);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let source = fanout_source(&fanout.origin_peer_id);

    let mut fanned = Vec::new();
    for sibling in &siblings {
        // Skip removed tenants: look up their SPKI from local creds and
        // check removal status to prevent leaking post-removal events.
        if is_sibling_removed(conn, sibling) {
            continue;
        }
        insert_recorded_event(conn, sibling, &fanout.event_id, now_ms, &source)?;
        let _ = pq.enqueue(sibling, &event_id_b64)?;
        fanned.push(sibling.clone());
    }

    Ok(fanned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn insert_tenant(conn: &Connection, peer_id: &str, workspace_id: &str) {
        conn.execute(
            "INSERT INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            rusqlite::params![
                peer_id,
                format!("ia-{peer_id}"),
                "tenant",
                "invite",
                workspace_id
            ],
        )
        .unwrap();
    }

    #[test]
    fn sibling_lookup_is_scoped_to_workspace() {
        let conn = setup();
        insert_tenant(&conn, "tenant-a", "ws-1");
        insert_tenant(&conn, "tenant-b", "ws-1");
        insert_tenant(&conn, "tenant-c", "ws-2");

        assert_eq!(
            sibling_tenants_in_workspace(&conn, "tenant-a", "ws-1").unwrap(),
            vec!["tenant-b".to_string()]
        );
        assert_eq!(
            sibling_tenants_in_workspace(&conn, "tenant-b", "ws-1").unwrap(),
            vec!["tenant-a".to_string()]
        );
        assert!(sibling_tenants_in_workspace(&conn, "tenant-c", "ws-2")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn enqueue_fanout_records_and_queues_same_workspace_siblings_only() {
        let conn = setup();
        insert_tenant(&conn, "origin", "ws-1");
        insert_tenant(&conn, "same-ws", "ws-1");
        insert_tenant(&conn, "other-ws", "ws-2");

        let fanout = SharedEventFanout {
            origin_peer_id: "origin".to_string(),
            workspace_id: "ws-1".to_string(),
            event_id: [7u8; 32],
        };

        let siblings = fanout_shared_event_enqueue(&conn, &fanout).unwrap();
        assert_eq!(siblings, vec!["same-ws".to_string()]);

        let event_id_b64 = event_id_to_base64(&fanout.event_id);
        let same_ws_recorded: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2 AND source = ?3",
                rusqlite::params![
                    "same-ws",
                    &event_id_b64,
                    "same_workspace_fanout:origin"
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(same_ws_recorded, 1);

        let other_ws_recorded: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params!["other-ws", &event_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(other_ws_recorded, 0);

        let queued: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params!["same-ws", &event_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(queued, 1);
    }
}
