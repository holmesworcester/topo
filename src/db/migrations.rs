use rusqlite::{Connection, Result as SqliteResult};
use std::time::{SystemTime, UNIX_EPOCH};

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "add_events_and_reactions",
        sql: "
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                blob BLOB NOT NULL,
                share_scope TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                inserted_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS valid_events (
                peer_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (peer_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS rejected_events (
                peer_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                rejected_at INTEGER NOT NULL,
                PRIMARY KEY (peer_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS peer_endpoint_observations (
                recorded_by TEXT NOT NULL,
                via_peer_id TEXT NOT NULL,
                origin_ip TEXT NOT NULL,
                origin_port INTEGER NOT NULL,
                observed_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (recorded_by, via_peer_id, origin_ip, origin_port, observed_at)
            );

            CREATE TABLE IF NOT EXISTS reactions (
                event_id TEXT NOT NULL,
                target_event_id TEXT NOT NULL,
                author_id TEXT NOT NULL,
                emoji TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                recorded_by TEXT NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_reactions_target ON reactions(recorded_by, target_event_id);
        ",
    },
    Migration {
        version: 2,
        name: "add_blocked_event_deps",
        sql: "
            CREATE TABLE IF NOT EXISTS blocked_event_deps (
                peer_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                blocker_event_id TEXT NOT NULL,
                PRIMARY KEY (peer_id, event_id, blocker_event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_blocked_by_dep
                ON blocked_event_deps(peer_id, blocker_event_id);
        ",
    },
    Migration {
        version: 3,
        name: "add_signed_memos",
        sql: "
            CREATE TABLE IF NOT EXISTS signed_memos (
                event_id TEXT NOT NULL,
                signed_by TEXT NOT NULL,
                signer_type INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                recorded_by TEXT NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );
        ",
    },
    Migration {
        version: 4,
        name: "add_secret_keys",
        sql: "
            CREATE TABLE IF NOT EXISTS secret_keys (
                event_id TEXT NOT NULL,
                key_bytes BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                recorded_by TEXT NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );
        ",
    },
    Migration {
        version: 5,
        name: "add_queue_tables",
        sql: "
            CREATE TABLE IF NOT EXISTS project_queue (
                peer_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                available_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                lease_until INTEGER,
                PRIMARY KEY (peer_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS egress_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id TEXT NOT NULL,
                frame_type TEXT NOT NULL DEFAULT 'event',
                event_id BLOB,
                payload BLOB,
                enqueued_at INTEGER NOT NULL,
                available_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                lease_until INTEGER,
                sent_at INTEGER,
                dedupe_key TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_pending_event
                ON egress_queue(connection_id, event_id)
                WHERE frame_type = 'event' AND sent_at IS NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_dedupe
                ON egress_queue(dedupe_key)
                WHERE dedupe_key IS NOT NULL AND sent_at IS NULL;

            CREATE TABLE IF NOT EXISTS ingress_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id TEXT NOT NULL,
                from_addr TEXT,
                received_at INTEGER NOT NULL,
                frame BLOB NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_ingress_unprocessed
                ON ingress_queue(processed, received_at);
        ",
    },
    Migration {
        version: 6,
        name: "add_deleted_messages",
        sql: "
            CREATE TABLE IF NOT EXISTS deleted_messages (
                recorded_by TEXT NOT NULL,
                message_id TEXT NOT NULL,
                deletion_event_id TEXT NOT NULL,
                author_id TEXT NOT NULL,
                deleted_at INTEGER NOT NULL,
                PRIMARY KEY (recorded_by, message_id)
            );
        ",
    },
    Migration {
        version: 7,
        name: "add_peer_endpoint_indexes",
        sql: "
            CREATE INDEX IF NOT EXISTS idx_peer_endpoint_expires
                ON peer_endpoint_observations(recorded_by, via_peer_id, expires_at);
            CREATE INDEX IF NOT EXISTS idx_peer_endpoint_lookup
                ON peer_endpoint_observations(recorded_by, via_peer_id, origin_ip, origin_port);
        ",
    },
    Migration {
        version: 8,
        name: "add_identity_tables",
        sql: "
            CREATE TABLE IF NOT EXISTS trust_anchors (
                peer_id TEXT NOT NULL PRIMARY KEY,
                workspace_id TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workspaces (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );

            CREATE TABLE IF NOT EXISTS invite_accepted (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                invite_event_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );

            CREATE TABLE IF NOT EXISTS user_invites (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );

            CREATE TABLE IF NOT EXISTS device_invites (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );

            CREATE TABLE IF NOT EXISTS users (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );

            CREATE TABLE IF NOT EXISTS peers_shared (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );

            CREATE TABLE IF NOT EXISTS admins (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );

            CREATE TABLE IF NOT EXISTS removed_entities (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                target_event_id TEXT NOT NULL,
                removal_type TEXT NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );

            CREATE TABLE IF NOT EXISTS secret_shared (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                key_event_id TEXT NOT NULL,
                recipient_event_id TEXT NOT NULL,
                wrapped_key BLOB NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );
        ",
    },
    Migration {
        version: 9,
        name: "add_peer_transport_bindings",
        sql: "
            CREATE TABLE IF NOT EXISTS peer_transport_bindings (
                recorded_by TEXT NOT NULL,
                peer_id TEXT NOT NULL,
                spki_fingerprint BLOB NOT NULL,
                bound_at INTEGER NOT NULL,
                PRIMARY KEY (recorded_by, peer_id)
            );
            CREATE INDEX IF NOT EXISTS idx_transport_bindings_spki
                ON peer_transport_bindings(recorded_by, spki_fingerprint);
        ",
    },
    Migration {
        version: 10,
        name: "add_transport_keys",
        sql: "
            CREATE TABLE IF NOT EXISTS transport_keys (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                spki_fingerprint BLOB NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_transport_keys_spki
                ON transport_keys(recorded_by, spki_fingerprint);
        ",
    },
    Migration {
        version: 11,
        name: "enforce_single_workspace_per_peer",
        sql: "
            DELETE FROM workspaces
             WHERE rowid NOT IN (
                 SELECT MIN(rowid)
                 FROM workspaces
                 GROUP BY recorded_by, workspace_id
             );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_single_per_peer
                ON workspaces (recorded_by, workspace_id);
        ",
    },
    Migration {
        version: 12,
        name: "retire_invite_workspace_bindings",
        sql: "SELECT 1;",
    },
    Migration {
        version: 13,
        name: "add_file_attachment_tables",
        sql: "
            CREATE TABLE IF NOT EXISTS message_attachments (
                recorded_by TEXT NOT NULL,
                event_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                blob_bytes INTEGER NOT NULL,
                total_slices INTEGER NOT NULL,
                slice_bytes INTEGER NOT NULL,
                root_hash BLOB NOT NULL,
                key_event_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_msg_att_message ON message_attachments(recorded_by, message_id);
            CREATE INDEX IF NOT EXISTS idx_msg_att_file ON message_attachments(recorded_by, file_id);

            CREATE TABLE IF NOT EXISTS file_slices (
                recorded_by TEXT NOT NULL,
                file_id TEXT NOT NULL,
                slice_number INTEGER NOT NULL,
                event_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (recorded_by, file_id, slice_number)
            );
            CREATE INDEX IF NOT EXISTS idx_file_slices_event ON file_slices(recorded_by, event_id);
        ",
    },
    Migration {
        version: 14,
        name: "add_signer_event_id_to_message_attachments",
        sql: "
            ALTER TABLE message_attachments ADD COLUMN signer_event_id TEXT NOT NULL DEFAULT '';
        ",
    },
    Migration {
        version: 15,
        name: "file_slice_guard_queue_and_descriptor_link",
        sql: "
            ALTER TABLE file_slices ADD COLUMN descriptor_event_id TEXT NOT NULL DEFAULT '';
            CREATE INDEX IF NOT EXISTS idx_file_slices_descriptor
                ON file_slices(recorded_by, descriptor_event_id);

            CREATE TABLE IF NOT EXISTS file_slice_guard_blocks (
                peer_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (peer_id, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_file_slice_guard_blocks_file
                ON file_slice_guard_blocks(peer_id, file_id);
        ",
    },
    Migration {
        version: 16,
        name: "add_intro_attempts",
        sql: "
            CREATE TABLE IF NOT EXISTS intro_attempts (
                recorded_by TEXT NOT NULL,
                intro_id BLOB NOT NULL,
                introduced_by_peer_id TEXT NOT NULL,
                other_peer_id TEXT NOT NULL,
                origin_ip TEXT NOT NULL,
                origin_port INTEGER NOT NULL,
                observed_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                error TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (recorded_by, intro_id)
            );
        ",
    },
    Migration {
        version: 17,
        name: "add_covering_index_blocked_deps",
        sql: "
            CREATE INDEX IF NOT EXISTS idx_blocked_by_dep_covering
                ON blocked_event_deps(peer_id, blocker_event_id, event_id);
            DROP INDEX IF EXISTS idx_blocked_by_dep;
        ",
    },
    Migration {
        version: 18,
        name: "add_invite_bootstrap_trust",
        sql: "
            CREATE TABLE IF NOT EXISTS invite_bootstrap_trust (
                recorded_by TEXT NOT NULL,
                invite_accepted_event_id TEXT NOT NULL,
                invite_event_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                bootstrap_addr TEXT NOT NULL,
                bootstrap_spki_fingerprint BLOB NOT NULL,
                accepted_at INTEGER NOT NULL,
                PRIMARY KEY (recorded_by, invite_accepted_event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_invite_bootstrap_spki
                ON invite_bootstrap_trust(recorded_by, bootstrap_spki_fingerprint);
        ",
    },
    Migration {
        version: 19,
        name: "add_pending_invite_bootstrap_trust",
        sql: "
            CREATE TABLE IF NOT EXISTS pending_invite_bootstrap_trust (
                recorded_by TEXT NOT NULL,
                invite_event_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                expected_bootstrap_spki_fingerprint BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed_at INTEGER,
                PRIMARY KEY (recorded_by, invite_event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_pending_invite_bootstrap_spki
                ON pending_invite_bootstrap_trust(recorded_by, expected_bootstrap_spki_fingerprint);
            CREATE INDEX IF NOT EXISTS idx_pending_invite_bootstrap_live
                ON pending_invite_bootstrap_trust(recorded_by, consumed_at, expires_at);
        ",
    },
    Migration {
        version: 20,
        name: "add_intro_attempts_index",
        sql: "
            CREATE INDEX IF NOT EXISTS idx_intro_attempts_peer
                ON intro_attempts(recorded_by, other_peer_id, created_at DESC);
        ",
    },
    Migration {
        version: 21,
        name: "bound_invite_bootstrap_trust_lifecycle",
        sql: "
            ALTER TABLE invite_bootstrap_trust ADD COLUMN expires_at INTEGER;
            ALTER TABLE invite_bootstrap_trust ADD COLUMN consumed_at INTEGER;
            UPDATE invite_bootstrap_trust
               SET expires_at = accepted_at + 86400000
             WHERE expires_at IS NULL;
            CREATE INDEX IF NOT EXISTS idx_invite_bootstrap_live
                ON invite_bootstrap_trust(recorded_by, consumed_at, expires_at);
        ",
    },
    Migration {
        version: 22,
        name: "rename_consumed_to_superseded",
        sql: "
            ALTER TABLE pending_invite_bootstrap_trust
                RENAME COLUMN consumed_at TO superseded_at;
            ALTER TABLE invite_bootstrap_trust
                RENAME COLUMN consumed_at TO superseded_at;
            DROP INDEX IF EXISTS idx_pending_invite_bootstrap_live;
            CREATE INDEX IF NOT EXISTS idx_pending_invite_bootstrap_live
                ON pending_invite_bootstrap_trust(recorded_by, superseded_at, expires_at);
            DROP INDEX IF EXISTS idx_invite_bootstrap_live;
            CREATE INDEX IF NOT EXISTS idx_invite_bootstrap_live
                ON invite_bootstrap_trust(recorded_by, superseded_at, expires_at);
        ",
    },
    Migration {
        version: 23,
        name: "drop_retired_tables",
        sql: "
            DROP TABLE IF EXISTS shareable_events;
            DROP TABLE IF EXISTS invite_workspace_bindings;
            DROP TABLE IF EXISTS local_signing_keys;
        ",
    },
    Migration {
        version: 24,
        name: "drop_unused_store_table",
        sql: "
            DROP TABLE IF EXISTS store;
        ",
    },
    Migration {
        version: 25,
        name: "add_blocked_events_header",
        sql: "
            CREATE TABLE IF NOT EXISTS blocked_events (
                peer_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                deps_remaining INTEGER NOT NULL,
                PRIMARY KEY (peer_id, event_id)
            );
        ",
    },
    Migration {
        version: 26,
        name: "add_local_transport_creds",
        sql: "
            CREATE TABLE IF NOT EXISTS local_transport_creds (
                peer_id TEXT PRIMARY KEY,
                cert_der BLOB NOT NULL,
                key_der BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
        ",
    },
    Migration {
        version: 27,
        name: "add_workspace_id_to_neg_items",
        sql: "
            -- Recreate neg_items with workspace_id column.
            -- Data loss is acceptable: neg_items is a reconciliation cache
            -- that gets repopulated from events on the next sync.
            DROP TABLE IF EXISTS neg_items;
            CREATE TABLE IF NOT EXISTS neg_items (
                workspace_id TEXT NOT NULL DEFAULT '',
                ts INTEGER NOT NULL,
                id BLOB NOT NULL,
                PRIMARY KEY (workspace_id, ts, id)
            ) WITHOUT ROWID;
        ",
    },
    Migration {
        version: 28,
        name: "drop_unused_ingress_queue",
        sql: "
            DROP TABLE IF EXISTS ingress_queue;
        ",
    },
];

fn ensure_schema_migrations(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        );",
    )
}

pub fn run_migrations(conn: &Connection) -> SqliteResult<()> {
    ensure_schema_migrations(conn)?;

    for migration in MIGRATIONS {
        let already_applied: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM schema_migrations WHERE version = ?1",
            [migration.version],
            |row| row.get(0),
        )?;

        if !already_applied {
            conn.execute_batch(migration.sql)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![migration.version, migration.name, now],
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;

    #[test]
    fn test_migration_runner() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(tables.contains(&"events".to_string()));
        assert!(tables.contains(&"valid_events".to_string()));
        assert!(tables.contains(&"rejected_events".to_string()));
        assert!(tables.contains(&"peer_endpoint_observations".to_string()));
        assert!(tables.contains(&"intro_attempts".to_string()));
        assert!(tables.contains(&"reactions".to_string()));
        assert!(tables.contains(&"invite_bootstrap_trust".to_string()));
        assert!(tables.contains(&"pending_invite_bootstrap_trust".to_string()));
        assert!(tables.contains(&"schema_migrations".to_string()));
    }

    #[test]
    fn test_migration_2_blocked_event_deps() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Table exists
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(tables.contains(&"blocked_event_deps".to_string()));

        // Can insert and query
        conn.execute(
            "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id) VALUES ('p1', 'e1', 'b1')",
            [],
        ).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = 'p1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // Idempotent — running migrations again doesn't fail
        run_migrations(&conn).unwrap();
        let count2: i64 = conn
            .query_row("SELECT COUNT(*) FROM blocked_event_deps", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count2, 1);

        // Migration version recorded
        let versions: Vec<i64> = conn
            .prepare("SELECT version FROM schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(versions.contains(&2));
    }

    #[test]
    fn test_migration_23_drops_retired_tables() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS shareable_events (
                id TEXT PRIMARY KEY,
                stored_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS invite_workspace_bindings (
                peer_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS local_signing_keys (
                event_id TEXT PRIMARY KEY,
                signing_key BLOB NOT NULL
            );
            ",
        )
        .unwrap();
        conn.execute("DELETE FROM schema_migrations WHERE version = 23", [])
            .unwrap();

        run_migrations(&conn).unwrap();

        let has_shareable_events: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='shareable_events'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_invite_workspace_bindings: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='invite_workspace_bindings'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let has_local_signing_keys: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='local_signing_keys'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(!has_shareable_events);
        assert!(!has_invite_workspace_bindings);
        assert!(!has_local_signing_keys);
    }

    #[test]
    fn test_migration_24_drops_store_table() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS store (
                id TEXT PRIMARY KEY,
                blob BLOB NOT NULL,
                stored_at INTEGER NOT NULL
            );
            ",
        )
        .unwrap();
        conn.execute("DELETE FROM schema_migrations WHERE version = 24", [])
            .unwrap();

        run_migrations(&conn).unwrap();

        let has_store: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='store'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!has_store);
    }

    #[test]
    fn test_migration_idempotent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        // Run again — should not fail
        run_migrations(&conn).unwrap();

        let max_version: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(max_version, 28);
    }
}
