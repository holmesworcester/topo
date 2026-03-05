//! CRUD queries for local subscriptions, feed, and state.

use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use super::types::*;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Create a new subscription and initialize its state row.
pub fn create_subscription(
    conn: &Connection,
    recorded_by: &str,
    name: &str,
    event_type: &str,
    delivery_mode: DeliveryMode,
    spec: &SubscriptionSpec,
) -> Result<SubscriptionDef, String> {
    let subscription_id = uuid_v4();
    let spec_json =
        serde_json::to_string(spec).map_err(|e| format!("spec serialization: {}", e))?;
    let now = now_ms();

    conn.execute(
        "INSERT INTO local_subscriptions
            (recorded_by, subscription_id, name, enabled, event_type, delivery_mode, spec_json, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            recorded_by,
            &subscription_id,
            name,
            event_type,
            delivery_mode.as_str(),
            &spec_json,
            now,
            now,
        ],
    )
    .map_err(|e| format!("insert subscription: {}", e))?;

    // Initialize state row.
    conn.execute(
        "INSERT INTO local_subscription_state
            (recorded_by, subscription_id, next_seq, pending_count, dirty, latest_event_id, latest_created_at_ms, updated_at_ms)
         VALUES (?1, ?2, 1, 0, 0, '', 0, ?3)",
        rusqlite::params![recorded_by, &subscription_id, now],
    )
    .map_err(|e| format!("insert subscription state: {}", e))?;

    Ok(SubscriptionDef {
        recorded_by: recorded_by.to_string(),
        subscription_id,
        name: name.to_string(),
        enabled: true,
        event_type: event_type.to_string(),
        delivery_mode,
        spec: spec.clone(),
        created_at_ms: now,
        updated_at_ms: now,
    })
}

/// List all subscriptions for a peer.
pub fn list_subscriptions(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Vec<SubscriptionDef>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT subscription_id, name, enabled, event_type, delivery_mode, spec_json, created_at_ms, updated_at_ms
             FROM local_subscriptions WHERE recorded_by = ?1 ORDER BY created_at_ms ASC",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            let spec_json: String = row.get(5)?;
            let delivery_str: String = row.get(4)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, String>(3)?,
                delivery_str,
                spec_json,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    for row in rows {
        let (sub_id, name, enabled, event_type, delivery_str, spec_json, created, updated) =
            row.map_err(|e| e.to_string())?;
        let delivery_mode = DeliveryMode::from_str(&delivery_str).unwrap_or(DeliveryMode::Full);
        let spec: SubscriptionSpec = serde_json::from_str(&spec_json).map_err(|e| e.to_string())?;
        result.push(SubscriptionDef {
            recorded_by: recorded_by.to_string(),
            subscription_id: sub_id,
            name,
            enabled,
            event_type,
            delivery_mode,
            spec,
            created_at_ms: created,
            updated_at_ms: updated,
        });
    }
    Ok(result)
}

/// Load enabled subscriptions for a specific event type (used by projection hook).
pub fn load_active_subscriptions_for_type(
    conn: &Connection,
    recorded_by: &str,
    event_type: &str,
) -> Result<Vec<SubscriptionDef>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT subscription_id, name, delivery_mode, spec_json, created_at_ms, updated_at_ms
             FROM local_subscriptions
             WHERE recorded_by = ?1 AND enabled = 1 AND event_type = ?2",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map(rusqlite::params![recorded_by, event_type], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    for row in rows {
        let (sub_id, name, delivery_str, spec_json, created, updated) =
            row.map_err(|e| e.to_string())?;
        let delivery_mode = DeliveryMode::from_str(&delivery_str).unwrap_or(DeliveryMode::Full);
        let spec: SubscriptionSpec = serde_json::from_str(&spec_json).map_err(|e| e.to_string())?;
        result.push(SubscriptionDef {
            recorded_by: recorded_by.to_string(),
            subscription_id: sub_id,
            name,
            enabled: true,
            event_type: event_type.to_string(),
            delivery_mode,
            spec,
            created_at_ms: created,
            updated_at_ms: updated,
        });
    }
    Ok(result)
}

/// Enable or disable a subscription.
pub fn set_enabled(
    conn: &Connection,
    recorded_by: &str,
    subscription_id: &str,
    enabled: bool,
) -> Result<(), String> {
    let rows = conn
        .execute(
            "UPDATE local_subscriptions SET enabled = ?3, updated_at_ms = ?4
             WHERE recorded_by = ?1 AND subscription_id = ?2",
            rusqlite::params![recorded_by, subscription_id, enabled, now_ms()],
        )
        .map_err(|e| e.to_string())?;
    if rows == 0 {
        return Err(format!("subscription {} not found", subscription_id));
    }
    Ok(())
}

/// Append a feed item and update state. Returns the assigned seq number.
///
/// Wraps the INSERT + state UPDATE in `BEGIN IMMEDIATE` / `COMMIT` when
/// not already inside a transaction. `BEGIN IMMEDIATE` acquires the write
/// lock before reading, so concurrent connections serialize here — preventing
/// two writers from reading the same `next_seq`. When already inside a
/// transaction, the outer transaction's lock provides the same guarantee.
pub fn append_feed_item(
    conn: &Connection,
    recorded_by: &str,
    subscription_id: &str,
    event_type: &str,
    event_id: &str,
    created_at_ms: i64,
    payload: &serde_json::Value,
) -> Result<i64, String> {
    let now = now_ms();
    let payload_json =
        serde_json::to_string(payload).map_err(|e| format!("payload serialization: {}", e))?;

    // Check if we're already inside a transaction (autocommit == false means
    // a transaction is active). If so, use SAVEPOINT to avoid nested BEGIN.
    let in_transaction = !conn.is_autocommit();

    if in_transaction {
        conn.execute_batch("SAVEPOINT sub_feed_append")
            .map_err(|e| format!("savepoint: {}", e))?;
    } else {
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| format!("begin immediate: {}", e))?;
    }

    let result = (|| -> Result<i64, String> {
        // Idempotency guard: skip if this event is already in the feed for this
        // subscription (can happen if projection retries after a partial failure).
        let already_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM local_subscription_feed
                 WHERE recorded_by = ?1 AND subscription_id = ?2 AND event_id = ?3",
                rusqlite::params![recorded_by, subscription_id, event_id],
                |row| row.get(0),
            )
            .map_err(|e| format!("dedup check: {}", e))?;
        if already_exists {
            // Return the existing seq for logging purposes.
            let existing_seq: i64 = conn
                .query_row(
                    "SELECT seq FROM local_subscription_feed
                     WHERE recorded_by = ?1 AND subscription_id = ?2 AND event_id = ?3",
                    rusqlite::params![recorded_by, subscription_id, event_id],
                    |row| row.get(0),
                )
                .map_err(|e| format!("dedup seq: {}", e))?;
            return Ok(existing_seq);
        }

        // Read next_seq under the write lock.
        let next_seq: i64 = conn
            .query_row(
                "SELECT next_seq FROM local_subscription_state
                 WHERE recorded_by = ?1 AND subscription_id = ?2",
                rusqlite::params![recorded_by, subscription_id],
                |row| row.get(0),
            )
            .map_err(|e| format!("read state: {}", e))?;

        // Insert feed row.
        conn.execute(
            "INSERT INTO local_subscription_feed
                (recorded_by, subscription_id, seq, event_type, event_id, created_at_ms, payload_json, emitted_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                recorded_by,
                subscription_id,
                next_seq,
                event_type,
                event_id,
                created_at_ms,
                &payload_json,
                now,
            ],
        )
        .map_err(|e| format!("insert feed: {}", e))?;

        // Update state.
        conn.execute(
            "UPDATE local_subscription_state
             SET next_seq = ?3, pending_count = pending_count + 1, dirty = 1,
                 latest_event_id = ?4, latest_created_at_ms = ?5, updated_at_ms = ?6
             WHERE recorded_by = ?1 AND subscription_id = ?2",
            rusqlite::params![
                recorded_by,
                subscription_id,
                next_seq + 1,
                event_id,
                created_at_ms,
                now,
            ],
        )
        .map_err(|e| format!("update state: {}", e))?;

        Ok(next_seq)
    })();

    if in_transaction {
        match &result {
            Ok(_) => {
                conn.execute_batch("RELEASE sub_feed_append")
                    .map_err(|e| format!("release: {}", e))?;
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK TO sub_feed_append");
                let _ = conn.execute_batch("RELEASE sub_feed_append");
            }
        }
    } else {
        match &result {
            Ok(_) => {
                conn.execute_batch("COMMIT")
                    .map_err(|e| format!("commit: {}", e))?;
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK");
            }
        }
    }

    result
}

/// Mark has_changed for a subscription (no feed row, just bump state).
pub fn mark_changed(
    conn: &Connection,
    recorded_by: &str,
    subscription_id: &str,
    event_id: &str,
    created_at_ms: i64,
) -> Result<i64, String> {
    let now = now_ms();

    conn.execute(
        "UPDATE local_subscription_state
         SET pending_count = pending_count + 1, dirty = 1,
             latest_event_id = ?3, latest_created_at_ms = ?4, updated_at_ms = ?5
         WHERE recorded_by = ?1 AND subscription_id = ?2",
        rusqlite::params![recorded_by, subscription_id, event_id, created_at_ms, now],
    )
    .map_err(|e| format!("mark changed: {}", e))?;

    // Return pending count.
    let pending: i64 = conn
        .query_row(
            "SELECT pending_count FROM local_subscription_state
             WHERE recorded_by = ?1 AND subscription_id = ?2",
            rusqlite::params![recorded_by, subscription_id],
            |row| row.get(0),
        )
        .map_err(|e| format!("read pending: {}", e))?;

    Ok(pending)
}

/// Poll feed items after a given seq (exclusive). Returns items up to limit.
/// Returns an error if the subscription does not exist.
pub fn poll_feed(
    conn: &Connection,
    recorded_by: &str,
    subscription_id: &str,
    after_seq: i64,
    limit: usize,
) -> Result<Vec<FeedItem>, String> {
    // Verify subscription exists so typos/stale IDs don't silently return empty.
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM local_subscriptions
             WHERE recorded_by = ?1 AND subscription_id = ?2",
            rusqlite::params![recorded_by, subscription_id],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !exists {
        return Err(format!("subscription {} not found", subscription_id));
    }

    let mut stmt = conn
        .prepare(
            "SELECT seq, event_type, event_id, created_at_ms, payload_json, emitted_at_ms
             FROM local_subscription_feed
             WHERE recorded_by = ?1 AND subscription_id = ?2 AND seq > ?3
             ORDER BY seq ASC LIMIT ?4",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map(
            rusqlite::params![recorded_by, subscription_id, after_seq, limit as i64],
            |row| {
                let payload_json: String = row.get(4)?;
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    payload_json,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    for row in rows {
        let (seq, event_type, event_id, created_at_ms, payload_json, emitted_at_ms) =
            row.map_err(|e| e.to_string())?;
        let payload: serde_json::Value =
            serde_json::from_str(&payload_json).unwrap_or(serde_json::Value::Null);
        result.push(FeedItem {
            subscription_id: subscription_id.to_string(),
            seq,
            event_type,
            event_id,
            created_at_ms,
            payload,
            emitted_at_ms,
        });
    }
    Ok(result)
}

/// Acknowledge feed items through a given seq. Decrements pending_count and
/// clears dirty if pending reaches zero.
///
/// For `has_changed` subscriptions (which have no feed rows), this resets
/// pending_count to 0 and clears dirty.
pub fn ack_feed(
    conn: &Connection,
    recorded_by: &str,
    subscription_id: &str,
    through_seq: i64,
) -> Result<(), String> {
    // Check delivery mode to handle has_changed separately.
    let delivery_str: String = conn
        .query_row(
            "SELECT delivery_mode FROM local_subscriptions
             WHERE recorded_by = ?1 AND subscription_id = ?2",
            rusqlite::params![recorded_by, subscription_id],
            |row| row.get(0),
        )
        .map_err(|e| format!("subscription not found: {}", e))?;

    let now = now_ms();

    if delivery_str == "has_changed" {
        // has_changed mode: no feed rows to delete, just reset state.
        conn.execute(
            "UPDATE local_subscription_state
             SET pending_count = 0, dirty = 0, updated_at_ms = ?3
             WHERE recorded_by = ?1 AND subscription_id = ?2",
            rusqlite::params![recorded_by, subscription_id, now],
        )
        .map_err(|e| e.to_string())?;
        return Ok(());
    }

    // full/id mode: count and delete feed rows, then update state.
    // Wrapped in a transaction to prevent concurrent ACKs from double-
    // subtracting pending_count.
    let in_transaction = !conn.is_autocommit();
    if in_transaction {
        conn.execute_batch("SAVEPOINT sub_ack")
            .map_err(|e| format!("savepoint: {}", e))?;
    } else {
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| format!("begin immediate: {}", e))?;
    }

    let result = (|| -> Result<(), String> {
        let acked: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM local_subscription_feed
                 WHERE recorded_by = ?1 AND subscription_id = ?2 AND seq <= ?3",
                rusqlite::params![recorded_by, subscription_id, through_seq],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;

        conn.execute(
            "DELETE FROM local_subscription_feed
             WHERE recorded_by = ?1 AND subscription_id = ?2 AND seq <= ?3",
            rusqlite::params![recorded_by, subscription_id, through_seq],
        )
        .map_err(|e| e.to_string())?;

        conn.execute(
            "UPDATE local_subscription_state
             SET pending_count = MAX(0, pending_count - ?3),
                 dirty = CASE WHEN MAX(0, pending_count - ?3) = 0 THEN 0 ELSE dirty END,
                 updated_at_ms = ?4
             WHERE recorded_by = ?1 AND subscription_id = ?2",
            rusqlite::params![recorded_by, subscription_id, acked, now],
        )
        .map_err(|e| e.to_string())?;

        Ok(())
    })();

    if in_transaction {
        match &result {
            Ok(_) => {
                conn.execute_batch("RELEASE sub_ack")
                    .map_err(|e| format!("release: {}", e))?;
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK TO sub_ack");
                let _ = conn.execute_batch("RELEASE sub_ack");
            }
        }
    } else {
        match &result {
            Ok(_) => {
                conn.execute_batch("COMMIT")
                    .map_err(|e| format!("commit: {}", e))?;
            }
            Err(_) => {
                let _ = conn.execute_batch("ROLLBACK");
            }
        }
    }

    result
}

/// Get subscription state.
pub fn get_state(
    conn: &Connection,
    recorded_by: &str,
    subscription_id: &str,
) -> Result<SubscriptionState, String> {
    conn.query_row(
        "SELECT next_seq, pending_count, dirty, latest_event_id, latest_created_at_ms, updated_at_ms
         FROM local_subscription_state
         WHERE recorded_by = ?1 AND subscription_id = ?2",
        rusqlite::params![recorded_by, subscription_id],
        |row| {
            Ok(SubscriptionState {
                subscription_id: subscription_id.to_string(),
                next_seq: row.get(0)?,
                pending_count: row.get(1)?,
                dirty: row.get::<_, i64>(2)? != 0,
                latest_event_id: row.get(3)?,
                latest_created_at_ms: row.get(4)?,
                updated_at_ms: row.get(5)?,
            })
        },
    )
    .map_err(|e| format!("subscription state not found: {}", e))
}

/// Resolve an event's created_at_ms from its base64 event_id by parsing the
/// stored blob. Used to backfill since cursors when only event_id is provided.
///
/// Note: for encrypted events this returns the outer wrapper's timestamp, which
/// may differ slightly from the decrypted inner event's timestamp. The matcher
/// excludes events strictly before the cursor timestamp and uses event_id
/// tie-breaking at equal timestamps, so a small timestamp discrepancy may
/// allow a re-delivery of the cursor event's inner content (harmless since
/// consumers should be idempotent).
pub fn resolve_event_created_at(conn: &Connection, event_id_b64: &str) -> Result<u64, String> {
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT blob FROM events WHERE event_id = ?1",
            rusqlite::params![event_id_b64],
            |row| row.get(0),
        )
        .map_err(|e| format!("event not found: {}", e))?;

    let parsed =
        crate::event_modules::parse_event(&blob).map_err(|e| format!("parse error: {}", e))?;

    Ok(parsed.created_at_ms())
}

/// Delete a subscription and its state/feed rows.
pub fn delete_subscription(
    conn: &Connection,
    recorded_by: &str,
    subscription_id: &str,
) -> Result<(), String> {
    conn.execute(
        "DELETE FROM local_subscription_feed WHERE recorded_by = ?1 AND subscription_id = ?2",
        rusqlite::params![recorded_by, subscription_id],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM local_subscription_state WHERE recorded_by = ?1 AND subscription_id = ?2",
        rusqlite::params![recorded_by, subscription_id],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM local_subscriptions WHERE recorded_by = ?1 AND subscription_id = ?2",
        rusqlite::params![recorded_by, subscription_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Simple UUID v4 generator (no external dep).
fn uuid_v4() -> String {
    let bytes: [u8; 16] = rand::random();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        (bytes[6] & 0x0f) | 0x40, bytes[7],
        (bytes[8] & 0x3f) | 0x80, bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    fn setup_db() -> rusqlite::Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        super::super::schema::ensure_schema(&conn).unwrap();
        conn
    }

    const PEER: &str = "test_peer";

    fn make_spec() -> SubscriptionSpec {
        SubscriptionSpec {
            event_type: "message".to_string(),
            since: None,
            filters: vec![],
        }
    }

    // ── create + list ──

    #[test]
    fn test_create_and_list_subscription() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "inbox",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();
        assert_eq!(sub.name, "inbox");
        assert_eq!(sub.event_type, "message");
        assert!(sub.enabled);
        assert_eq!(sub.delivery_mode, DeliveryMode::Full);

        let subs = list_subscriptions(&conn, PEER).unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].subscription_id, sub.subscription_id);
    }

    #[test]
    fn test_list_returns_empty_for_unknown_peer() {
        let conn = setup_db();
        let subs = list_subscriptions(&conn, "nobody").unwrap();
        assert!(subs.is_empty());
    }

    // ── enable/disable ──

    #[test]
    fn test_enable_disable() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();

        set_enabled(&conn, PEER, &sub.subscription_id, false).unwrap();
        let subs = list_subscriptions(&conn, PEER).unwrap();
        assert!(!subs[0].enabled);

        set_enabled(&conn, PEER, &sub.subscription_id, true).unwrap();
        let subs = list_subscriptions(&conn, PEER).unwrap();
        assert!(subs[0].enabled);
    }

    #[test]
    fn test_disable_hides_from_active_query() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();
        set_enabled(&conn, PEER, &sub.subscription_id, false).unwrap();

        let active = load_active_subscriptions_for_type(&conn, PEER, "message").unwrap();
        assert!(active.is_empty());
    }

    #[test]
    fn test_set_enabled_unknown_sub_errors() {
        let conn = setup_db();
        let err = set_enabled(&conn, PEER, "nonexistent", true).unwrap_err();
        assert!(err.contains("not found"));
    }

    // ── append_feed_item + state ──

    #[test]
    fn test_append_feed_item_and_state() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();

        let seq = append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_1",
            1000,
            &serde_json::json!({"content": "hi"}),
        )
        .unwrap();
        assert_eq!(seq, 1);

        let state = get_state(&conn, PEER, &sub.subscription_id).unwrap();
        assert_eq!(state.next_seq, 2);
        assert_eq!(state.pending_count, 1);
        assert!(state.dirty);
        assert_eq!(state.latest_event_id, "eid_1");
    }

    #[test]
    fn test_append_feed_item_sequential_seqs() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();

        let s1 = append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_1",
            1000,
            &serde_json::json!({}),
        )
        .unwrap();
        let s2 = append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_2",
            2000,
            &serde_json::json!({}),
        )
        .unwrap();
        let s3 = append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_3",
            3000,
            &serde_json::json!({}),
        )
        .unwrap();
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);

        let state = get_state(&conn, PEER, &sub.subscription_id).unwrap();
        assert_eq!(state.pending_count, 3);
        assert_eq!(state.next_seq, 4);
    }

    // ── idempotency guard ──

    #[test]
    fn test_append_feed_item_idempotent() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();

        let s1 = append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_1",
            1000,
            &serde_json::json!({}),
        )
        .unwrap();
        // Same event_id again — should return existing seq, not create a new row
        let s1_dup = append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_1",
            1000,
            &serde_json::json!({}),
        )
        .unwrap();
        assert_eq!(s1, s1_dup);

        // pending_count should still be 1, not 2
        let state = get_state(&conn, PEER, &sub.subscription_id).unwrap();
        assert_eq!(state.pending_count, 1);
    }

    // ── poll_feed ──

    #[test]
    fn test_poll_feed_returns_items_after_seq() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();

        append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_1",
            1000,
            &serde_json::json!({"a":1}),
        )
        .unwrap();
        append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_2",
            2000,
            &serde_json::json!({"a":2}),
        )
        .unwrap();
        append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_3",
            3000,
            &serde_json::json!({"a":3}),
        )
        .unwrap();

        // Poll from beginning
        let items = poll_feed(&conn, PEER, &sub.subscription_id, 0, 100).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].seq, 1);
        assert_eq!(items[2].seq, 3);

        // Poll after seq 1
        let items = poll_feed(&conn, PEER, &sub.subscription_id, 1, 100).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].seq, 2);

        // Poll with limit
        let items = poll_feed(&conn, PEER, &sub.subscription_id, 0, 2).unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn test_poll_feed_unknown_sub_errors() {
        let conn = setup_db();
        let err = poll_feed(&conn, PEER, "nonexistent", 0, 10).unwrap_err();
        assert!(err.contains("not found"));
    }

    // ── ack_feed ──

    #[test]
    fn test_ack_feed_decrements_pending() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();

        append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_1",
            1000,
            &serde_json::json!({}),
        )
        .unwrap();
        append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_2",
            2000,
            &serde_json::json!({}),
        )
        .unwrap();
        append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_3",
            3000,
            &serde_json::json!({}),
        )
        .unwrap();

        // Ack through seq 2
        ack_feed(&conn, PEER, &sub.subscription_id, 2).unwrap();

        let state = get_state(&conn, PEER, &sub.subscription_id).unwrap();
        assert_eq!(state.pending_count, 1);

        // Feed should only have seq 3
        let items = poll_feed(&conn, PEER, &sub.subscription_id, 0, 100).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].seq, 3);
    }

    #[test]
    fn test_ack_all_clears_dirty() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();

        append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_1",
            1000,
            &serde_json::json!({}),
        )
        .unwrap();
        ack_feed(&conn, PEER, &sub.subscription_id, 1).unwrap();

        let state = get_state(&conn, PEER, &sub.subscription_id).unwrap();
        assert_eq!(state.pending_count, 0);
        assert!(!state.dirty);
    }

    // ── mark_changed (has_changed mode) ──

    #[test]
    fn test_mark_changed_increments_pending() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::HasChanged,
            &make_spec(),
        )
        .unwrap();

        let p1 = mark_changed(&conn, PEER, &sub.subscription_id, "eid_1", 1000).unwrap();
        assert_eq!(p1, 1);
        let p2 = mark_changed(&conn, PEER, &sub.subscription_id, "eid_2", 2000).unwrap();
        assert_eq!(p2, 2);

        let state = get_state(&conn, PEER, &sub.subscription_id).unwrap();
        assert!(state.dirty);
        assert_eq!(state.pending_count, 2);
        assert_eq!(state.latest_event_id, "eid_2");
    }

    #[test]
    fn test_ack_has_changed_resets_state() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::HasChanged,
            &make_spec(),
        )
        .unwrap();

        mark_changed(&conn, PEER, &sub.subscription_id, "eid_1", 1000).unwrap();
        mark_changed(&conn, PEER, &sub.subscription_id, "eid_2", 2000).unwrap();

        ack_feed(&conn, PEER, &sub.subscription_id, 0).unwrap();

        let state = get_state(&conn, PEER, &sub.subscription_id).unwrap();
        assert_eq!(state.pending_count, 0);
        assert!(!state.dirty);
    }

    // ── delete subscription ──

    #[test]
    fn test_delete_subscription() {
        let conn = setup_db();
        let sub = create_subscription(
            &conn,
            PEER,
            "test",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();
        append_feed_item(
            &conn,
            PEER,
            &sub.subscription_id,
            "message",
            "eid_1",
            1000,
            &serde_json::json!({}),
        )
        .unwrap();

        delete_subscription(&conn, PEER, &sub.subscription_id).unwrap();

        let subs = list_subscriptions(&conn, PEER).unwrap();
        assert!(subs.is_empty());
    }

    // ── tenant isolation ──

    #[test]
    fn test_subscriptions_isolated_by_peer() {
        let conn = setup_db();
        create_subscription(
            &conn,
            "alice",
            "inbox",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();
        create_subscription(
            &conn,
            "bob",
            "inbox",
            "message",
            DeliveryMode::Full,
            &make_spec(),
        )
        .unwrap();

        let alice_subs = list_subscriptions(&conn, "alice").unwrap();
        let bob_subs = list_subscriptions(&conn, "bob").unwrap();
        assert_eq!(alice_subs.len(), 1);
        assert_eq!(bob_subs.len(), 1);
        assert_ne!(alice_subs[0].subscription_id, bob_subs[0].subscription_id);
    }
}
