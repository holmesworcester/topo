//! Schema for local subscription tables (non-replicated).

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS local_subscriptions (
            recorded_by TEXT NOT NULL,
            subscription_id TEXT NOT NULL,
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            event_type TEXT NOT NULL,
            delivery_mode TEXT NOT NULL,
            spec_json TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, subscription_id)
        );

        CREATE INDEX IF NOT EXISTS idx_local_subscriptions_active
            ON local_subscriptions(recorded_by, enabled, event_type);

        CREATE TABLE IF NOT EXISTS local_subscription_feed (
            recorded_by TEXT NOT NULL,
            subscription_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            event_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            emitted_at_ms INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, subscription_id, seq)
        );

        CREATE INDEX IF NOT EXISTS idx_local_subscription_feed_event
            ON local_subscription_feed(recorded_by, subscription_id, event_id);

        CREATE TABLE IF NOT EXISTS local_subscription_state (
            recorded_by TEXT NOT NULL,
            subscription_id TEXT NOT NULL,
            next_seq INTEGER NOT NULL DEFAULT 1,
            pending_count INTEGER NOT NULL DEFAULT 0,
            dirty INTEGER NOT NULL DEFAULT 0,
            latest_event_id TEXT NOT NULL DEFAULT '',
            latest_created_at_ms INTEGER NOT NULL DEFAULT 0,
            updated_at_ms INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, subscription_id)
        );
        ",
    )?;
    Ok(())
}
