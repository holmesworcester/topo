use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, EventId};
use crate::db::store::{insert_recorded_event, lookup_workspace_id};
use crate::event_modules::ShareScope;
use crate::projection::apply::project_one;
use crate::state::db::project_queue::ProjectQueue;

const FANOUT_SOURCE_PREFIX: &str = "same_workspace_fanout";

// ---------------------------------------------------------------------------
// Schema for durable pending fanout queue
// ---------------------------------------------------------------------------

pub(crate) fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pending_shared_fanouts (
            origin_peer_id TEXT NOT NULL,
            workspace_id   TEXT NOT NULL,
            event_id       BLOB NOT NULL,
            PRIMARY KEY (origin_peer_id, event_id)
        );",
    )?;
    Ok(())
}

/// Write fanout entries durably inside the current transaction.
/// Called from the persist phase so entries survive a crash.
pub(crate) fn persist_pending_fanouts(
    conn: &Connection,
    fanouts: &[SharedEventFanout],
) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "INSERT OR IGNORE INTO pending_shared_fanouts (origin_peer_id, workspace_id, event_id)
         VALUES (?1, ?2, ?3)",
    )?;
    for f in fanouts {
        stmt.execute(rusqlite::params![&f.origin_peer_id, &f.workspace_id, f.event_id.as_slice()])?;
    }
    Ok(())
}

/// Load all pending fanout entries, returning them as SharedEventFanout.
/// Callers must call `delete_pending_fanout` for each entry after
/// successful processing to avoid losing concurrent inserts.
pub(crate) fn take_pending_fanouts(
    conn: &Connection,
) -> Result<Vec<SharedEventFanout>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT origin_peer_id, workspace_id, event_id FROM pending_shared_fanouts",
    )?;
    let rows: Vec<SharedEventFanout> = stmt
        .query_map([], |row| {
            let origin: String = row.get(0)?;
            let ws: String = row.get(1)?;
            let blob: Vec<u8> = row.get(2)?;
            Ok((origin, ws, blob))
        })?
        .filter_map(|r| {
            let (origin, ws, blob) = r.ok()?;
            if blob.len() != 32 {
                return None;
            }
            let mut eid = [0u8; 32];
            eid.copy_from_slice(&blob);
            Some(SharedEventFanout {
                origin_peer_id: origin,
                workspace_id: ws,
                event_id: eid,
            })
        })
        .collect();
    Ok(rows)
}

/// Delete a single pending fanout entry after successful processing.
pub(crate) fn delete_pending_fanout(
    conn: &Connection,
    fanout: &SharedEventFanout,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM pending_shared_fanouts WHERE origin_peer_id = ?1 AND event_id = ?2",
        rusqlite::params![&fanout.origin_peer_id, fanout.event_id.as_slice()],
    )?;
    Ok(())
}

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
///
/// `check_scopes` lists all `recorded_by` scopes to check for removal.
/// During fanout the origin tenant's scope is already projected (drained),
/// so we check both the sibling's own scope AND the origin's scope to
/// catch same-batch removal+message scenarios.
fn is_sibling_removed(conn: &Connection, sibling_peer_id: &str, check_scopes: &[&str]) -> bool {
    // The sibling's peer_id is lower(hex(spki_fingerprint)). We can look up
    // their peers_shared row directly via transport_fingerprint without
    // needing local_transport_creds. This covers both fully bootstrapped
    // and still-bootstrapping tenants.
    for scope in check_scopes {
        let removed: bool = conn
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM peers_shared p
                    JOIN removed_entities r
                      ON r.recorded_by = p.recorded_by
                      AND (r.target_event_id = p.event_id
                           OR (r.removal_type = 'user'
                               AND p.user_event_id IS NOT NULL
                               AND r.target_event_id = p.user_event_id))
                    WHERE p.recorded_by = ?1
                      AND lower(hex(p.transport_fingerprint)) = ?2
                )",
                rusqlite::params![scope, sibling_peer_id],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if removed {
            return true;
        }
    }
    false
}

/// Returns true if the origin tenant rejected a non-encrypted event.
/// Encrypted events are NOT treated as globally rejected because the
/// rejection may be tenant-scoped (e.g. missing key_secret); a sibling
/// may have the key and be able to project the event.
fn is_origin_rejected(conn: &Connection, origin_peer_id: &str, event_id: &EventId) -> bool {
    let event_id_b64 = event_id_to_base64(event_id);
    // Check if rejected AND not an encrypted event type.
    let rejected_and_not_encrypted: bool = conn
        .query_row(
            "SELECT EXISTS (
                SELECT 1 FROM rejected_events r
                JOIN events e ON e.event_id = r.event_id
                WHERE r.peer_id = ?1 AND r.event_id = ?2
                  AND e.event_type <> 'encrypted'
            )",
            rusqlite::params![origin_peer_id, &event_id_b64],
            |row| row.get(0),
        )
        .unwrap_or(false);
    rejected_and_not_encrypted
}

/// Returns true if the event is a removal event (user_removed or peer_removed).
fn is_removal_event(conn: &Connection, event_id: &EventId) -> bool {
    let event_id_b64 = event_id_to_base64(event_id);
    conn.query_row(
        "SELECT event_type FROM events WHERE event_id = ?1",
        rusqlite::params![&event_id_b64],
        |row| row.get::<_, String>(0),
    )
    .map(|t| t == "user_removed" || t == "peer_removed")
    .unwrap_or(false)
}

/// Clock-skew tolerance for cross-device timestamp comparisons (30 seconds).
/// Timestamps come from different device clocks, so we allow a margin to
/// avoid dropping events that were logically pre-removal but whose
/// `created_at` compares as slightly newer due to clock drift.
const CLOCK_SKEW_TOLERANCE_MS: i64 = 30_000;

/// Returns true if the event was created before (or within clock-skew
/// tolerance of) the sibling's removal. Used to allow pre-removal events
/// through even when the sibling is currently marked as removed — this
/// handles out-of-order arrival where a removal is projected before older
/// events that logically predate it.
fn event_predates_sibling_removal(
    conn: &Connection,
    event_id: &EventId,
    sibling_peer_id: &str,
    check_scopes: &[&str],
) -> bool {
    let event_id_b64 = event_id_to_base64(event_id);
    let event_ts: Option<i64> = conn
        .query_row(
            "SELECT created_at FROM events WHERE event_id = ?1",
            rusqlite::params![&event_id_b64],
            |row| row.get(0),
        )
        .ok();
    let Some(event_ts) = event_ts else {
        return false;
    };

    // Find the earliest removal timestamp targeting this sibling across all scopes.
    for scope in check_scopes {
        let removal_ts: Option<i64> = conn
            .query_row(
                "SELECT MIN(e.created_at)
                 FROM removed_entities r
                 JOIN peers_shared p
                   ON r.recorded_by = p.recorded_by
                   AND (r.target_event_id = p.event_id
                        OR (r.removal_type = 'user'
                            AND p.user_event_id IS NOT NULL
                            AND r.target_event_id = p.user_event_id))
                 JOIN events e ON e.event_id = r.event_id
                 WHERE p.recorded_by = ?1
                   AND lower(hex(p.transport_fingerprint)) = ?2",
                rusqlite::params![scope, sibling_peer_id],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        if let Some(removal_created_at) = removal_ts {
            if event_ts <= removal_created_at + CLOCK_SKEW_TOLERANCE_MS {
                return true;
            }
        }
    }
    false
}

/// Returns true if the removal event targets the given sibling's peer or user.
/// Used to limit the removal exemption to only the tenant being removed.
fn is_removal_targeting_sibling(
    conn: &Connection,
    event_id: &EventId,
    sibling_peer_id: &str,
    check_scope: &str,
) -> bool {
    let event_id_b64 = event_id_to_base64(event_id);
    // Load the removal's target_event_id from the event blob.
    // Both peer_removed and user_removed have target_event_id at blob[9..41].
    let target: Option<[u8; 32]> = conn
        .query_row(
            "SELECT blob FROM events WHERE event_id = ?1",
            rusqlite::params![&event_id_b64],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .ok()
        .and_then(|blob| {
            if blob.len() >= 41 {
                let mut t = [0u8; 32];
                t.copy_from_slice(&blob[9..41]);
                Some(t)
            } else {
                None
            }
        });
    let Some(target_eid) = target else {
        return false;
    };
    let target_b64 = event_id_to_base64(&target_eid);
    // Check if the target is the sibling's peer_shared event or user event.
    conn.query_row(
        "SELECT EXISTS (
            SELECT 1 FROM peers_shared
            WHERE recorded_by = ?1
              AND lower(hex(transport_fingerprint)) = ?2
              AND (event_id = ?3 OR user_event_id = ?3)
        )",
        rusqlite::params![check_scope, sibling_peer_id, &target_b64],
        |row| row.get(0),
    )
    .unwrap_or(false)
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

    // Write a durable pending entry so the fanout survives a crash.
    let fanout_entry = SharedEventFanout {
        origin_peer_id: recorded_by.to_string(),
        workspace_id: workspace_id.clone(),
        event_id: *event_id,
    };
    let _ = persist_pending_fanouts(conn, &[fanout_entry]);

    let result = fanout_shared_event_immediate(conn, recorded_by, &workspace_id, event_id);

    // Only clean up the pending entry on success so failed fanouts
    // survive for retry on next startup.
    if result.is_ok() {
        let _ = conn.execute(
            "DELETE FROM pending_shared_fanouts WHERE origin_peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id.as_slice()],
        );
    }

    result
}

pub(crate) fn fanout_shared_event_immediate(
    conn: &Connection,
    origin_peer_id: &str,
    workspace_id: &str,
    event_id: &EventId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Skip fanout for events the origin tenant rejected (bad signature, etc.)
    if is_origin_rejected(conn, origin_peer_id, event_id) {
        return Ok(());
    }
    let siblings = sibling_tenants_in_workspace(conn, origin_peer_id, workspace_id)?;
    // Skip fanout from removed tenants — a removed local tenant must not
    // inject new shared events into sibling scopes. Removal events are
    // exempt so self-removal propagates to siblings.
    // Check all workspace scopes (origin + siblings) because another tenant
    // may have projected the removal before the origin scope has.
    if !is_removal_event(conn, event_id) {
        let all_scopes: Vec<&str> = siblings
            .iter()
            .map(|s| s.as_str())
            .chain(std::iter::once(origin_peer_id))
            .collect();
        if is_sibling_removed(conn, origin_peer_id, &all_scopes) {
            return Ok(());
        }
    }
    if siblings.is_empty() {
        return Ok(());
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let source = fanout_source(origin_peer_id);

    let removal = is_removal_event(conn, event_id);
    let check_scopes: Vec<&str> = siblings
        .iter()
        .map(|s| s.as_str())
        .chain(std::iter::once(origin_peer_id))
        .collect();
    let active_siblings: Vec<&String> = siblings
        .iter()
        .filter(|s| {
            if !is_sibling_removed(conn, s, &check_scopes) {
                return true;
            }
            // Allow pre-removal events that arrived out-of-order.
            if event_predates_sibling_removal(conn, event_id, s, &check_scopes) {
                return true;
            }
            // Only exempt the specific sibling targeted by this removal event.
            removal && is_removal_targeting_sibling(conn, event_id, s, origin_peer_id)
        })
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
    // Skip fanout for events the origin tenant rejected (bad signature, etc.)
    if is_origin_rejected(conn, &fanout.origin_peer_id, &fanout.event_id) {
        return Ok(Vec::new());
    }
    // No origin-removal check here. For wire-ingested events,
    // origin_peer_id is the local ingesting tenant, NOT the event author.
    // For local-create entries, the immediate path already blocks removed
    // tenants at creation time. If a pending entry survived a crash, the
    // event was created while the tenant was still valid and must fan out.
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

    // Removal events fan out only to the specific target sibling.
    let removal = is_removal_event(conn, &fanout.event_id);
    let check_scopes: Vec<&str> = siblings
        .iter()
        .map(|s| s.as_str())
        .chain(std::iter::once(fanout.origin_peer_id.as_str()))
        .collect();

    let mut fanned = Vec::new();
    for sibling in &siblings {
        if is_sibling_removed(conn, sibling, &check_scopes) {
            // Allow pre-removal events that arrived out-of-order.
            let predates =
                event_predates_sibling_removal(conn, &fanout.event_id, sibling, &check_scopes);
            // Only exempt the specific sibling targeted by this removal.
            let targeted_removal = removal
                && is_removal_targeting_sibling(
                    conn,
                    &fanout.event_id,
                    sibling,
                    &fanout.origin_peer_id,
                );
            if !predates && !targeted_removal {
                continue;
            }
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
