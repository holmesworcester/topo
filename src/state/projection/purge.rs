use std::collections::BTreeSet;

#[cfg(test)]
use std::cell::Cell;

use rusqlite::{params, Connection};

use crate::crypto::{decrypt_event_blob, event_id_from_base64, event_id_to_base64, EventId};
use crate::event_modules::{
    self as events, ParsedEvent, EVENT_TYPE_FILE, EVENT_TYPE_FILE_SLICE, EVENT_TYPE_REACTION,
};

#[derive(Debug, Default, Clone)]
struct PurgeManifest {
    event_ids: BTreeSet<String>,
    file_ids: BTreeSet<String>,
}

impl PurgeManifest {
    fn add_event_id(&mut self, event_id: impl Into<String>) -> bool {
        self.event_ids.insert(event_id.into())
    }

    fn add_file_id(&mut self, file_id: impl Into<String>) -> bool {
        self.file_ids.insert(file_id.into())
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

fn inspect_relevant_event(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
) -> Result<Option<ParsedEvent>, Box<dyn std::error::Error>> {
    let Some(semantic_type) = events::outer_semantic_type_code(blob) else {
        return Ok(None);
    };
    if !matches!(
        semantic_type,
        EVENT_TYPE_REACTION | EVENT_TYPE_FILE | EVENT_TYPE_FILE_SLICE
    ) {
        return Ok(None);
    }

    let parsed = events::parse_event(blob)?;
    match parsed {
        ParsedEvent::Reaction(_) | ParsedEvent::File(_) | ParsedEvent::FileSlice(_) => {
            Ok(Some(parsed))
        }
        ParsedEvent::Encrypted(enc) => {
            let key_id_b64 = event_id_to_base64(&enc.key_event_id);
            let key_bytes: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT key_bytes
                     FROM key_secrets
                     WHERE recorded_by = ?1 AND event_id = ?2",
                    params![recorded_by, &key_id_b64],
                    |row| row.get(0),
                )
                .ok();
            let Some(key_bytes) = key_bytes else {
                return Ok(None);
            };
            if key_bytes.len() != 32 {
                return Ok(None);
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key_bytes);
            let plaintext =
                decrypt_event_blob(&key_arr, &enc.nonce, &enc.ciphertext, &enc.auth_tag).ok();
            let Some(plaintext) = plaintext else {
                return Ok(None);
            };
            let inner = events::parse_event(&plaintext)?;
            match inner {
                ParsedEvent::Reaction(_) | ParsedEvent::File(_) | ParsedEvent::FileSlice(_) => {
                    Ok(Some(inner))
                }
                _ => Ok(None),
            }
        }
        _ => Ok(None),
    }
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
            row.get::<_, String>(0)
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
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
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
            row.get::<_, String>(0)
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
            row.get::<_, String>(0)
        })?;
        for row in rows {
            changed |= manifest.add_event_id(row?);
        }
        // Legacy: also check old guard table for pre-migration data.
        let mut stmt = conn.prepare(
            "SELECT event_id
             FROM file_slice_guard_blocks
             WHERE peer_id = ?1 AND file_id = ?2",
        )?;
        let rows = stmt.query_map(params![recorded_by, &file_id], |row| {
            row.get::<_, String>(0)
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
    let mut stmt = conn.prepare(
        "SELECT re.event_id, e.blob
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1",
    )?;
    let rows = stmt.query_map(params![recorded_by], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;

    let file_ids = manifest.file_ids.clone();
    for row in rows {
        let (event_id, blob) = row?;
        let Some(parsed) = inspect_relevant_event(conn, recorded_by, &blob)? else {
            continue;
        };
        match parsed {
            ParsedEvent::Reaction(rxn)
                if event_id_to_base64(&rxn.target_event_id) == root_message_event_id =>
            {
                changed |= manifest.add_event_id(event_id);
            }
            ParsedEvent::File(file)
                if event_id_to_base64(&file.message_id) == root_message_event_id =>
            {
                changed |= manifest.add_event_id(event_id);
                changed |= manifest.add_file_id(event_id_to_base64(&file.file_id));
            }
            ParsedEvent::FileSlice(file_slice)
                if file_ids.contains(&event_id_to_base64(&file_slice.file_id)) =>
            {
                changed |= manifest.add_event_id(event_id);
            }
            _ => {}
        }
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
            row.get::<_, String>(0)
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
        {
            let mut stmt = conn.prepare(
                "SELECT file_id
                 FROM deleted_files
                 WHERE recorded_by = ?1 AND message_id = ?2",
            )?;
            let rows = stmt.query_map(params![recorded_by, root_message_event_id], |row| {
                row.get::<_, String>(0)
            })?;
            for row in rows {
                changed |= manifest.add_file_id(row?);
            }
        }
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

fn persist_deleted_file_mappings(
    conn: &Connection,
    recorded_by: &str,
    root_message_event_id: &str,
    manifest: &PurgeManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    for file_id in &manifest.file_ids {
        conn.execute(
            "INSERT OR IGNORE INTO deleted_files (recorded_by, file_id, message_id)
             VALUES (?1, ?2, ?3)",
            params![recorded_by, file_id, root_message_event_id],
        )?;
    }
    Ok(())
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
            row.get::<_, String>(0)
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
        conn.execute(
            "DELETE FROM file_slice_guard_blocks WHERE peer_id = ?1 AND file_id = ?2",
            params![recorded_by, file_id],
        )?;
    }

    for event_id in &manifest.event_ids {
        conn.execute(
            "DELETE FROM file_slices WHERE recorded_by = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
        )?;
        conn.execute(
            "DELETE FROM file_slice_guard_blocks WHERE peer_id = ?1 AND event_id = ?2",
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
        let deleted_file_mapping: bool = conn.query_row(
            "SELECT COUNT(*) > 0
             FROM deleted_files
             WHERE recorded_by = ?1 AND file_id = ?2 AND message_id = ?3",
            params![recorded_by, file_id, root_message_event_id],
            |row| row.get(0),
        )?;
        if !deleted_file_mapping {
            return Err(format!(
                "purge left no deleted_files mapping for file_id {}",
                file_id
            )
            .into());
        }

        let slices_left: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM file_slices WHERE recorded_by = ?1 AND file_id = ?2",
            params![recorded_by, file_id],
            |row| row.get(0),
        )?;
        if slices_left {
            return Err(format!("purge left file_slices for file_id {}", file_id).into());
        }

        let guard_left: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM file_slice_guard_blocks WHERE peer_id = ?1 AND file_id = ?2",
            params![recorded_by, file_id],
            |row| row.get(0),
        )?;
        if guard_left {
            return Err(format!("purge left file_slice_guard_blocks for {}", file_id).into());
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

    let mut stmt = conn.prepare(
        "SELECT re.event_id, e.blob
         FROM recorded_events re
         JOIN events e ON e.event_id = re.event_id
         WHERE re.peer_id = ?1",
    )?;
    let rows = stmt.query_map(params![recorded_by], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (event_id, blob) = row?;
        let Some(parsed) = inspect_relevant_event(conn, recorded_by, &blob)? else {
            continue;
        };
        match parsed {
            ParsedEvent::Reaction(rxn)
                if event_id_to_base64(&rxn.target_event_id) == root_message_event_id =>
            {
                return Err(format!(
                    "purge left dependent reaction event {} targeting {}",
                    event_id, root_message_event_id
                )
                .into());
            }
            ParsedEvent::File(file)
                if event_id_to_base64(&file.message_id) == root_message_event_id =>
            {
                return Err(format!(
                    "purge left dependent file event {} targeting {}",
                    event_id, root_message_event_id
                )
                .into());
            }
            ParsedEvent::FileSlice(file_slice)
                if manifest
                    .file_ids
                    .contains(&event_id_to_base64(&file_slice.file_id)) =>
            {
                return Err(format!("purge left dependent file_slice event {}", event_id).into());
            }
            _ => {}
        }
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
    test_checkpoint("after_manifest_build")?;
    persist_deleted_file_mappings(conn, recorded_by, root_message_event_id, &manifest)?;
    test_checkpoint("after_deleted_file_mapping")?;
    delete_tenant_scoped_rows(conn, recorded_by, &manifest)?;
    test_checkpoint("after_tenant_scoped_delete")?;
    let orphaned_event_ids = delete_global_rows(conn, &manifest)?;
    test_checkpoint("after_global_delete")?;
    verify_purge(
        conn,
        recorded_by,
        root_message_event_id,
        &manifest,
        &orphaned_event_ids,
    )?;
    Ok(())
}
