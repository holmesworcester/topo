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
        name: "add_peer_keys_and_signed_memos",
        sql: "
            CREATE TABLE IF NOT EXISTS peer_keys (
                event_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                recorded_by TEXT NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );

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

            CREATE TABLE IF NOT EXISTS invite_workspace_bindings (
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
        sql: "
            -- invite_workspace_bindings is no longer used by runtime logic.
            -- Trust anchor binding now derives directly from invite_accepted event fields.
            -- Table is retained for backward compatibility; no runtime code reads or writes it.
            -- No destructive cleanup: existing rows are harmless and preserved for forensics.
            SELECT 1;
        ",
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
        name: "rename_channel_id_to_network_event_id",
        // Handled specially in run_migrations: renames channel_id→network_event_id
        // only if the old column exists (pre-existing DBs). Fresh DBs already have
        // the correct column name from CREATE TABLE in schema.rs.
        sql: "SELECT 1;",
    },
    Migration {
        version: 15,
        name: "rename_network_event_id_to_workspace_event_id",
        // Handled specially in run_migrations: renames network_event_id→workspace_event_id
        // only if the old column exists (pre-existing DBs). Fresh DBs already have
        // the correct column name from CREATE TABLE in schema.rs.
        sql: "SELECT 1;",
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
                status TEXT NOT NULL DEFAULT 'received',
                error TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (recorded_by, intro_id)
            );
            CREATE INDEX IF NOT EXISTS idx_intro_attempts_status
                ON intro_attempts(recorded_by, status);
            CREATE INDEX IF NOT EXISTS idx_intro_attempts_peer
                ON intro_attempts(recorded_by, other_peer_id);
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
            // Migration 14: conditionally rename channel_id → network_event_id
            if migration.version == 14 {
                let has_channel_id: bool = conn.query_row(
                    "SELECT COUNT(*) > 0 FROM pragma_table_info('messages') WHERE name='channel_id'",
                    [],
                    |row| row.get(0),
                )?;
                if has_channel_id {
                    conn.execute_batch(
                        "ALTER TABLE messages RENAME COLUMN channel_id TO network_event_id;
                         DROP INDEX IF EXISTS idx_messages_channel;
                         CREATE INDEX IF NOT EXISTS idx_messages_network ON messages(network_event_id, created_at DESC);"
                    )?;
                }
            } else if migration.version == 15 {
                // Migration 15: conditionally rename network_event_id → workspace_event_id
                let has_network_event_id: bool = conn.query_row(
                    "SELECT COUNT(*) > 0 FROM pragma_table_info('messages') WHERE name='network_event_id'",
                    [],
                    |row| row.get(0),
                )?;
                if has_network_event_id {
                    conn.execute_batch(
                        "ALTER TABLE messages RENAME COLUMN network_event_id TO workspace_event_id;
                         DROP INDEX IF EXISTS idx_messages_network;
                         CREATE INDEX IF NOT EXISTS idx_messages_workspace ON messages(workspace_event_id, created_at DESC);"
                    )?;
                }
            } else {
                conn.execute_batch(migration.sql)?;
            }
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
        assert!(tables.contains(&"reactions".to_string()));
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
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = 'p1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        // Idempotent — running migrations again doesn't fail
        run_migrations(&conn).unwrap();
        let count2: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blocked_event_deps", [], |row| row.get(0),
        ).unwrap();
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
    fn test_migration_idempotent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        // Run again — should not fail
        run_migrations(&conn).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 16);
    }
}
