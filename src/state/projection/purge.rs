use std::collections::BTreeSet;

#[cfg(test)]
use std::cell::Cell;

use rusqlite::{params, Connection};

use crate::crypto::{event_id_from_base64, EventId};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PurgeManifest {
    event_ids: BTreeSet<String>,
    file_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HardPurgeRawRows {
    tombstoned: bool,
    manifest: PurgeManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HardPurgeDecisionContext {
    tombstoned: bool,
    manifest: PurgeManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HardPurgePlan {
    RejectMissingTombstone,
    ExecuteManifest {
        event_ids: BTreeSet<String>,
        file_ids: BTreeSet<String>,
    },
}

impl PurgeManifest {
    fn add_event_id(&mut self, event_id: impl Into<String>) -> bool {
        self.event_ids.insert(event_id.into())
    }

    fn add_file_id(&mut self, file_id: impl Into<String>) -> bool {
        self.file_ids.insert(file_id.into())
    }
}

fn normalize_hard_purge_context(raw_rows: HardPurgeRawRows) -> HardPurgeDecisionContext {
    // The tombstone-gated core is verified in verus-proofs; this runtime wrapper
    // simply carries the richer BTreeSet<String> manifest across the boundary.
    let core = topo_verus_proofs::state::projection::purge::normalize_hard_purge_context_core(
        topo_verus_proofs::state::projection::purge::HardPurgeRawRowsCore {
            tombstoned: raw_rows.tombstoned,
            manifest_event_count: raw_rows.manifest.event_ids.len() as u64,
            manifest_file_count: raw_rows.manifest.file_ids.len() as u64,
        },
    );
    let _ = core; // verified shape-preserving projection
    HardPurgeDecisionContext {
        tombstoned: raw_rows.tombstoned,
        manifest: raw_rows.manifest,
    }
}

fn decide_hard_purge_plan(context: &HardPurgeDecisionContext) -> HardPurgePlan {
    // Delegate tombstone-gated dispatch to the Verus-verified core; runtime rehydrates
    // the concrete BTreeSet<String> manifests into `ExecuteManifest` when the core
    // selects the execute branch.
    let core_plan = topo_verus_proofs::state::projection::purge::decide_hard_purge_plan_core(
        &topo_verus_proofs::state::projection::purge::HardPurgeDecisionContextCore {
            tombstoned: context.tombstoned,
            manifest_event_count: context.manifest.event_ids.len() as u64,
            manifest_file_count: context.manifest.file_ids.len() as u64,
        },
    );
    match core_plan {
        topo_verus_proofs::state::projection::purge::HardPurgePlanCore::RejectMissingTombstone => {
            HardPurgePlan::RejectMissingTombstone
        }
        topo_verus_proofs::state::projection::purge::HardPurgePlanCore::ExecuteManifest { .. } => {
            HardPurgePlan::ExecuteManifest {
                event_ids: context.manifest.event_ids.clone(),
                file_ids: context.manifest.file_ids.clone(),
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_STEP: Cell<Option<usize>> = const { Cell::new(None) };
    static FAIL_STEP_COUNTER: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn set_test_fail_after_steps(steps: Option<usize>) {
    FAIL_AFTER_STEP.with(|cell| cell.set(steps));
    FAIL_STEP_COUNTER.with(|cell| cell.set(0));
}

#[cfg(not(test))]
fn test_checkpoint(_label: &str) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(test)]
fn test_checkpoint(label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let should_fail = FAIL_AFTER_STEP.with(|fail_after| {
        FAIL_STEP_COUNTER.with(|counter| {
            let next = counter.get() + 1;
            counter.set(next);
            fail_after.get() == Some(next)
        })
    });
    if should_fail {
        return Err(format!("hard purge failpoint triggered at {}", label).into());
    }
    Ok(())
}

fn event_id_bytes(event_id_b64: &str) -> Result<EventId, Box<dyn std::error::Error>> {
    event_id_from_base64(event_id_b64)
        .ok_or_else(|| format!("invalid base64 event id: {}", event_id_b64).into())
}

fn collect_projection_dependents(
    conn: &Connection,
    recorded_by: &str,
    root_message_event_id: &str,
    manifest: &mut PurgeManifest,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut changed = false;

    {
        let mut stmt = conn.prepare(
            "SELECT event_id
             FROM reactions
             WHERE recorded_by = ?1 AND target_event_id = ?2",
        )?;
        let rows = stmt.query_map(params![recorded_by, root_message_event_id], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?;
        for event_id in rows {
            changed |= manifest.add_event_id(event_id?);
        }
    }

    // Per-Message FS: enumerate message_key rows pointing at this
    // message, adding them to the purge manifest so the cascade
    // removes the per-message K_m wrap alongside the message blob.
    // The K_m row in key_secrets is keyed by the message_key's own
    // event id, so cascade-purging the message_key row covers
    // matching K_m state via the event_id deletion path.
    {
        let mut stmt = conn.prepare(
            "SELECT event_id
             FROM message_keys
             WHERE recorded_by = ?1 AND owning_message_event_id = ?2",
        )?;
        let rows = stmt.query_map(params![recorded_by, root_message_event_id], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?;
        for event_id in rows {
            changed |= manifest.add_event_id(event_id?);
        }
    }

    {
        let mut stmt = conn.prepare(
            "SELECT event_id, file_id
             FROM files
             WHERE recorded_by = ?1 AND message_id = ?2",
        )?;
        let rows = stmt.query_map(params![recorded_by, root_message_event_id], |row| {
            Ok((
                crate::db::sql_types::get_text(row, 0)?,
                crate::db::sql_types::get_text(row, 1)?,
            ))
        })?;
        for row in rows {
            let (event_id, file_id) = row?;
            changed |= manifest.add_event_id(event_id);
            changed |= manifest.add_file_id(file_id);
        }
    }

    for file_id in manifest.file_ids.clone() {
        let mut stmt = conn.prepare(
            "SELECT event_id
             FROM file_slices
             WHERE recorded_by = ?1 AND file_id = ?2",
        )?;
        let rows = stmt.query_map(params![recorded_by, &file_id], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?;
        for row in rows {
            changed |= manifest.add_event_id(row?);
        }

        // Collect file_slices blocked on this file_id (dep-blocked with
        // file_id as the blocker key in blocked_event_deps).
        let mut stmt = conn.prepare(
            "SELECT event_id
             FROM blocked_event_deps
             WHERE peer_id = ?1 AND blocker_event_id = ?2",
        )?;
        let rows = stmt.query_map(params![recorded_by, &file_id], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?;
        for row in rows {
            changed |= manifest.add_event_id(row?);
        }
    }

    Ok(changed)
}

fn collect_recorded_dependents(
    conn: &Connection,
    recorded_by: &str,
    root_message_event_id: &str,
    manifest: &mut PurgeManifest,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut changed = false;
    let root_message_event_bytes = event_id_bytes(root_message_event_id)?;
    let mut stmt = conn.prepare(
        "SELECT event_id
         FROM recorded_event_owners
         WHERE peer_id = ?1 AND owner_event_id = ?2",
    )?;
    let rows = stmt.query_map(
        params![recorded_by, root_message_event_bytes.as_slice()],
        |row| crate::db::sql_types::get_text(row, 0),
    )?;

    for row in rows {
        changed |= manifest.add_event_id(row?);
    }

    Ok(changed)
}

fn collect_blocked_dependents(
    conn: &Connection,
    recorded_by: &str,
    manifest: &mut PurgeManifest,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut changed = false;
    for blocker_event_id in manifest.event_ids.clone() {
        let mut stmt = conn.prepare(
            "SELECT event_id
             FROM blocked_event_deps
             WHERE peer_id = ?1 AND blocker_event_id = ?2",
        )?;
        let rows = stmt.query_map(params![recorded_by, &blocker_event_id], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?;
        for row in rows {
            changed |= manifest.add_event_id(row?);
        }
    }
    Ok(changed)
}

fn build_manifest(
    conn: &Connection,
    recorded_by: &str,
    root_message_event_id: &str,
) -> Result<PurgeManifest, Box<dyn std::error::Error>> {
    let mut manifest = PurgeManifest::default();
    manifest.add_event_id(root_message_event_id.to_string());

    loop {
        let mut changed = false;
        changed |=
            collect_projection_dependents(conn, recorded_by, root_message_event_id, &mut manifest)?;
        changed |=
            collect_recorded_dependents(conn, recorded_by, root_message_event_id, &mut manifest)?;
        changed |= collect_blocked_dependents(conn, recorded_by, &mut manifest)?;
        if !changed {
            break;
        }
    }

    Ok(manifest)
}

fn delete_subscription_feed_rows(
    conn: &Connection,
    recorded_by: &str,
    manifest: &PurgeManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut affected_subscriptions = BTreeSet::new();
    for event_id in &manifest.event_ids {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT subscription_id
             FROM local_subscription_feed
             WHERE recorded_by = ?1 AND event_id = ?2",
        )?;
        let rows = stmt.query_map(params![recorded_by, event_id], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?;
        for row in rows {
            affected_subscriptions.insert(row?);
        }
    }

    for event_id in &manifest.event_ids {
        conn.execute(
            "DELETE FROM local_subscription_feed WHERE recorded_by = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
        )?;
    }

    let now = crate::db::queue::current_timestamp_ms();
    for subscription_id in affected_subscriptions {
        let pending_count: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM local_subscription_feed
             WHERE recorded_by = ?1 AND subscription_id = ?2",
            params![recorded_by, &subscription_id],
            |row| row.get(0),
        )?;
        let latest: Option<(String, i64)> = conn
            .query_row(
                "SELECT event_id, created_at_ms
                 FROM local_subscription_feed
                 WHERE recorded_by = ?1 AND subscription_id = ?2
                 ORDER BY seq DESC
                 LIMIT 1",
                params![recorded_by, &subscription_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();
        let (latest_event_id, latest_created_at_ms) = latest.unwrap_or_else(|| ("".to_string(), 0));
        conn.execute(
            "UPDATE local_subscription_state
             SET pending_count = ?3,
                 dirty = CASE WHEN ?3 = 0 THEN 0 ELSE 1 END,
                 latest_event_id = ?4,
                 latest_created_at_ms = ?5,
                 updated_at_ms = ?6
             WHERE recorded_by = ?1 AND subscription_id = ?2",
            params![
                recorded_by,
                &subscription_id,
                pending_count,
                latest_event_id,
                latest_created_at_ms,
                now,
            ],
        )?;
    }

    Ok(())
}

fn delete_tenant_scoped_rows(
    conn: &Connection,
    recorded_by: &str,
    manifest: &PurgeManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    delete_subscription_feed_rows(conn, recorded_by, manifest)?;

    test_checkpoint("after_subscription_feed_cleanup")?;

    for event_id in &manifest.event_ids {
        let event_bytes = event_id_bytes(event_id)?;
        conn.execute(
            "DELETE FROM local_client_ops WHERE recorded_by = ?1 AND event_id = ?2",
            params![recorded_by, event_bytes.as_slice()],
        )?;
        conn.execute(
            "DELETE FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
        )?;
        conn.execute(
            "DELETE FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
        )?;
        conn.execute(
            "DELETE FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
        )?;
        conn.execute(
            "DELETE FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
        )?;
        conn.execute(
            "DELETE FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
        )?;
        conn.execute(
            "DELETE FROM pending_shared_fanouts
             WHERE origin_peer_id = ?1 AND event_id = ?2",
            params![recorded_by, event_bytes.as_slice()],
        )?;
    }

    for event_id in &manifest.event_ids {
        conn.execute(
            "DELETE FROM blocked_event_deps
             WHERE peer_id = ?1 AND (event_id = ?2 OR blocker_event_id = ?2)",
            params![recorded_by, event_id],
        )?;
    }

    for event_id in &manifest.event_ids {
        conn.execute(
            "DELETE FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            params![recorded_by, event_id],
        )?;
        conn.execute(
            "DELETE FROM reactions
             WHERE recorded_by = ?1 AND (event_id = ?2 OR target_event_id = ?2)",
            params![recorded_by, event_id],
        )?;
        conn.execute(
            "DELETE FROM files
             WHERE recorded_by = ?1 AND (event_id = ?2 OR message_id = ?2)",
            params![recorded_by, event_id],
        )?;
        // Per-Message FS: a tombstoned message_key drops the K_m row
        // from key_secrets (keyed by the message_key's own event id)
        // and the message_keys index row.
        conn.execute(
            "DELETE FROM message_keys
             WHERE recorded_by = ?1 AND (event_id = ?2 OR owning_message_event_id = ?2)",
            params![recorded_by, event_id],
        )?;
        conn.execute(
            "DELETE FROM key_secrets
             WHERE recorded_by = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
        )?;
    }

    for file_id in &manifest.file_ids {
        conn.execute(
            "DELETE FROM files WHERE recorded_by = ?1 AND file_id = ?2",
            params![recorded_by, file_id],
        )?;
        conn.execute(
            "DELETE FROM file_slices WHERE recorded_by = ?1 AND file_id = ?2",
            params![recorded_by, file_id],
        )?;
    }

    for event_id in &manifest.event_ids {
        conn.execute(
            "DELETE FROM file_slices WHERE recorded_by = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
        )?;
    }

    Ok(())
}

fn delete_global_rows(
    conn: &Connection,
    manifest: &PurgeManifest,
) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let mut orphaned_event_ids = BTreeSet::new();

    for event_id in &manifest.event_ids {
        let remaining_refs: i64 = conn.query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE event_id = ?1",
            params![event_id],
            |row| row.get(0),
        )?;
        if remaining_refs != 0 {
            continue;
        }
        let event_bytes = event_id_bytes(event_id)?;
        orphaned_event_ids.insert(event_id.clone());
        conn.execute("DELETE FROM events WHERE event_id = ?1", params![event_id])?;
        conn.execute(
            "DELETE FROM event_timeline WHERE event_id = ?1",
            params![event_id],
        )?;
        conn.execute(
            "DELETE FROM sync_run_rx_events WHERE event_id = ?1",
            params![event_id],
        )?;
        conn.execute(
            "DELETE FROM deferred_need_events WHERE id = ?1",
            params![event_bytes.as_slice()],
        )?;
        conn.execute(
            "DELETE FROM shared_event_index WHERE id = ?1",
            params![event_bytes.as_slice()],
        )?;
    }

    for event_id in &manifest.event_ids {
        conn.execute(
            "UPDATE event_timeline
             SET unblocked_by_event_id = NULL
             WHERE unblocked_by_event_id = ?1",
            params![event_id],
        )?;
    }

    Ok(orphaned_event_ids)
}

fn verify_purge(
    conn: &Connection,
    recorded_by: &str,
    root_message_event_id: &str,
    manifest: &PurgeManifest,
    orphaned_event_ids: &BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    for event_id in &manifest.event_ids {
        let recorded: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
            |row| row.get(0),
        )?;
        if recorded {
            return Err(format!("purge left recorded_events row for {}", event_id).into());
        }

        let owner_indexed: bool = conn.query_row(
            "SELECT COUNT(*) > 0
             FROM recorded_event_owners
             WHERE peer_id = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
            |row| row.get(0),
        )?;
        if owner_indexed {
            return Err(format!("purge left recorded_event_owners row for {}", event_id).into());
        }

        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
            |row| row.get(0),
        )?;
        if valid {
            return Err(format!("purge left valid_events row for {}", event_id).into());
        }
    }

    let root_message_left: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
        params![recorded_by, root_message_event_id],
        |row| row.get(0),
    )?;
    if root_message_left {
        return Err(format!("purge left message row for {}", root_message_event_id).into());
    }

    let root_reactions_left: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM reactions WHERE recorded_by = ?1 AND target_event_id = ?2",
        params![recorded_by, root_message_event_id],
        |row| row.get(0),
    )?;
    if root_reactions_left {
        return Err(format!("purge left reactions targeting {}", root_message_event_id).into());
    }

    let root_files_left: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM files WHERE recorded_by = ?1 AND message_id = ?2",
        params![recorded_by, root_message_event_id],
        |row| row.get(0),
    )?;
    if root_files_left {
        return Err(format!("purge left files targeting {}", root_message_event_id).into());
    }

    for file_id in &manifest.file_ids {
        let slices_left: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM file_slices WHERE recorded_by = ?1 AND file_id = ?2",
            params![recorded_by, file_id],
            |row| row.get(0),
        )?;
        if slices_left {
            return Err(format!("purge left file_slices for file_id {}", file_id).into());
        }
    }

    let blocked_left: bool = conn.query_row(
        "SELECT COUNT(*) > 0
         FROM blocked_event_deps
         WHERE peer_id = ?1
           AND (event_id IN (SELECT event_id FROM blocked_events WHERE peer_id = ?1)
                OR blocker_event_id = ?2)",
        params![recorded_by, root_message_event_id],
        |row| row.get(0),
    )?;
    if blocked_left {
        return Err("purge left blocked dependency edges".into());
    }

    for event_id in &manifest.event_ids {
        let feed_left: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM local_subscription_feed WHERE recorded_by = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
            |row| row.get(0),
        )?;
        if feed_left {
            return Err(format!("purge left subscription feed rows for {}", event_id).into());
        }
    }

    for event_id in orphaned_event_ids {
        let global_left: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            params![event_id],
            |row| row.get(0),
        )?;
        if global_left {
            return Err(format!("purge left global events row for {}", event_id).into());
        }
    }

    let root_message_event_bytes = event_id_bytes(root_message_event_id)?;
    let indexed_owner_left: bool = conn.query_row(
        "SELECT COUNT(*) > 0
         FROM recorded_event_owners
         WHERE peer_id = ?1 AND owner_event_id = ?2",
        params![recorded_by, root_message_event_bytes.as_slice()],
        |row| row.get(0),
    )?;
    if indexed_owner_left {
        return Err(format!(
            "purge left recorded_event_owners rows for owner {}",
            root_message_event_id
        )
        .into());
    }

    Ok(())
}

pub(crate) fn hard_purge_deleted_message_graph(
    conn: &Connection,
    recorded_by: &str,
    root_message_event_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(test)]
    FAIL_STEP_COUNTER.with(|counter| counter.set(0));

    let tombstoned: bool = conn.query_row(
        "SELECT COUNT(*) > 0
         FROM deleted_messages
         WHERE recorded_by = ?1 AND message_id = ?2",
        params![recorded_by, root_message_event_id],
        |row| row.get(0),
    )?;
    if !tombstoned {
        return Err(format!(
            "hard purge requires tombstone for message {}",
            root_message_event_id
        )
        .into());
    }

    let manifest = build_manifest(conn, recorded_by, root_message_event_id)?;
    let purge_context = normalize_hard_purge_context(HardPurgeRawRows {
        tombstoned,
        manifest,
    });
    match decide_hard_purge_plan(&purge_context) {
        HardPurgePlan::RejectMissingTombstone => {
            return Err(format!(
                "hard purge requires tombstone for message {}",
                root_message_event_id
            )
            .into());
        }
        HardPurgePlan::ExecuteManifest { .. } => {}
    }
    test_checkpoint("after_manifest_build")?;
    delete_tenant_scoped_rows(conn, recorded_by, &purge_context.manifest)?;
    test_checkpoint("after_tenant_scoped_delete")?;
    let orphaned_event_ids = delete_global_rows(conn, &purge_context.manifest)?;
    test_checkpoint("after_global_delete")?;
    verify_purge(
        conn,
        recorded_by,
        root_message_event_id,
        &purge_context.manifest,
        &orphaned_event_ids,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_purge_plan_rejects_missing_tombstone() {
        let mut manifest = PurgeManifest::default();
        manifest.add_event_id("message".to_string());
        let context = normalize_hard_purge_context(HardPurgeRawRows {
            tombstoned: false,
            manifest,
        });
        assert_eq!(
            context,
            HardPurgeDecisionContext {
                tombstoned: false,
                manifest: PurgeManifest {
                    event_ids: BTreeSet::from(["message".to_string()]),
                    file_ids: BTreeSet::new(),
                },
            }
        );
        assert_eq!(
            decide_hard_purge_plan(&context),
            HardPurgePlan::RejectMissingTombstone
        );
    }

    #[test]
    fn hard_purge_plan_executes_exact_manifest() {
        let mut manifest = PurgeManifest::default();
        manifest.add_event_id("message".to_string());
        manifest.add_file_id("file".to_string());
        assert_eq!(
            decide_hard_purge_plan(&normalize_hard_purge_context(HardPurgeRawRows {
                tombstoned: true,
                manifest,
            })),
            HardPurgePlan::ExecuteManifest {
                event_ids: BTreeSet::from(["message".to_string()]),
                file_ids: BTreeSet::from(["file".to_string()]),
            }
        );
    }
}
