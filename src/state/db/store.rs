use std::collections::HashMap;

use rusqlite::{params, Connection, Result as SqliteResult};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::event_modules::ShareScope;

pub const SQL_INSERT_EVENT: &str =
    "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
pub const SQL_INSERT_NEG_ITEM: &str =
    "INSERT OR IGNORE INTO neg_items (workspace_id, ts, id) VALUES (?1, ?2, ?3)";
pub const SQL_INSERT_RECORDED_EVENT: &str =
    "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
     VALUES (?1, ?2, ?3, ?4)";

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            blob BLOB NOT NULL,
            share_scope TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            inserted_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recorded_events (
            id INTEGER PRIMARY KEY,
            peer_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            recorded_at INTEGER NOT NULL,
            source TEXT NOT NULL,
            UNIQUE(peer_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_recorded_peer_order ON recorded_events(peer_id, id);

        CREATE TABLE IF NOT EXISTS neg_items (
            workspace_id TEXT NOT NULL DEFAULT '',
            ts INTEGER NOT NULL,
            id BLOB NOT NULL,
            PRIMARY KEY (workspace_id, ts, id)
        ) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS neg_blocks (
            block_idx INTEGER PRIMARY KEY,
            ts INTEGER NOT NULL,
            id BLOB NOT NULL,
            count INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS neg_meta (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

pub fn parse_share_scope(scope: &str) -> Option<ShareScope> {
    match scope {
        "shared" => Some(ShareScope::Shared),
        "local" => Some(ShareScope::Local),
        _ => None,
    }
}

pub fn insert_event(
    conn: &Connection,
    event_id: &EventId,
    event_type: &str,
    blob: &[u8],
    share_scope: ShareScope,
    created_at_ms: i64,
    inserted_at_ms: i64,
) -> SqliteResult<()> {
    let event_id_b64 = event_id_to_base64(event_id);
    conn.execute(
        SQL_INSERT_EVENT,
        params![
            &event_id_b64,
            event_type,
            blob,
            share_scope.as_str(),
            created_at_ms,
            inserted_at_ms
        ],
    )?;
    Ok(())
}

pub fn insert_neg_item_if_shared(
    conn: &Connection,
    share_scope: ShareScope,
    created_at_ms: i64,
    event_id: &EventId,
    workspace_id: &str,
) -> SqliteResult<()> {
    if share_scope == ShareScope::Shared {
        conn.execute(
            SQL_INSERT_NEG_ITEM,
            params![workspace_id, created_at_ms, event_id.as_slice()],
        )?;
    }
    Ok(())
}

/// Look up the workspace_id (base64 event_id of the Workspace event)
/// for a given peer_id from invites_accepted projection rows.
/// Returns None if no accepted workspace binding exists yet.
/// Panics on unexpected DB errors (schema/IO) to avoid masking failures.
pub fn lookup_workspace_id(conn: &Connection, peer_id: &str) -> Option<String> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT workspace_id
         FROM invites_accepted
         WHERE recorded_by = ?1
         ORDER BY created_at ASC, event_id ASC
         LIMIT 1",
        params![peer_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .expect("lookup_workspace_id: unexpected DB error querying invites_accepted")
}

pub fn insert_recorded_event(
    conn: &Connection,
    peer_id: &str,
    event_id: &EventId,
    recorded_at_ms: i64,
    source: &str,
) -> SqliteResult<()> {
    let event_id_b64 = event_id_to_base64(event_id);
    conn.execute(
        SQL_INSERT_RECORDED_EVENT,
        params![peer_id, &event_id_b64, recorded_at_ms, source],
    )?;
    Ok(())
}

/// Like `insert_recorded_event` but returns whether a new row was inserted.
/// `INSERT OR IGNORE` returns rows_changed=0 when the row already exists.
pub fn insert_recorded_event_checked(
    conn: &Connection,
    peer_id: &str,
    event_id: &EventId,
    recorded_at_ms: i64,
    source: &str,
) -> SqliteResult<bool> {
    let event_id_b64 = event_id_to_base64(event_id);
    Ok(conn.execute(
        SQL_INSERT_RECORDED_EVENT,
        params![peer_id, &event_id_b64, recorded_at_ms, source],
    )? > 0)
}

/// Content-addressed blob storage backed by the `events` table.
pub struct Store<'a> {
    conn: &'a Connection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedEventSummary {
    pub event_id: EventId,
    pub semantic_type_code: u8,
    pub encoded_size_bytes: u32,
    pub created_at_ms: i64,
}

impl<'a> Store<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Get a blob by its event ID (reads from `events` table).
    pub fn get(&self, id: &EventId) -> SqliteResult<Option<Vec<u8>>> {
        let id_str = event_id_to_base64(id);

        let result = self.conn.query_row(
            "SELECT blob FROM events WHERE event_id = ?1",
            params![id_str],
            |row| row.get(0),
        );

        match result {
            Ok(blob) => Ok(Some(blob)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get a blob only if its share_scope is 'shared'. Defense-in-depth gate
    /// preventing local-only events (e.g. secret keys) from being sent to peers.
    pub fn get_shared(&self, id: &EventId) -> SqliteResult<Option<Vec<u8>>> {
        let id_str = event_id_to_base64(id);

        let result = self.conn.query_row(
            "SELECT blob FROM events WHERE event_id = ?1 AND share_scope = 'shared'",
            params![id_str],
            |row| row.get(0),
        );

        match result {
            Ok(blob) => Ok(Some(blob)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Fetch blobs for multiple event IDs in a single query.  Only returns rows
    /// whose `share_scope = 'shared'` (same guard as `get_shared`).  Missing or
    /// non-shared IDs are simply absent from the returned map.
    pub fn get_shared_batch(&self, ids: &[EventId]) -> SqliteResult<HashMap<EventId, Vec<u8>>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT event_id, blob FROM events WHERE event_id IN ({}) AND share_scope = 'shared'",
            placeholders
        );
        let id_strs: Vec<String> = ids.iter().map(event_id_to_base64).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let mut map = HashMap::with_capacity(ids.len());
        let mut rows = stmt.query(rusqlite::params_from_iter(id_strs.iter()))?;
        while let Some(row) = rows.next()? {
            let id_str: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            if let Some(event_id) = event_id_from_base64(&id_str) {
                map.insert(event_id, blob);
            }
        }
        Ok(map)
    }

    /// Get lightweight discovery metadata for a shared event without exposing
    /// local-only rows.
    pub fn get_shared_summary(&self, id: &EventId) -> SqliteResult<Option<SharedEventSummary>> {
        let id_str = event_id_to_base64(id);
        let result = self.conn.query_row(
            "SELECT blob, created_at
             FROM events
             WHERE event_id = ?1 AND share_scope = 'shared'",
            params![id_str],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        );
        let (blob, created_at_ms) = match result {
            Ok(row) => row,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(err) => return Err(err),
        };
        let Some(semantic_type_code) = crate::event_modules::outer_semantic_type_code(&blob) else {
            return Ok(None);
        };
        let encoded_size_bytes = u32::try_from(blob.len()).unwrap_or(u32::MAX);
        Ok(Some(SharedEventSummary {
            event_id: *id,
            semantic_type_code,
            encoded_size_bytes,
            created_at_ms,
        }))
    }

    /// Check if we have a blob
    #[cfg(test)]
    pub fn exists(&self, id: &EventId) -> SqliteResult<bool> {
        let id_str = event_id_to_base64(id);

        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE event_id = ?1",
            params![id_str],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{open_in_memory, schema::create_tables};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_get_via_events_table() {
        let conn = setup();
        let store = Store::new(&conn);

        let blob = b"hello world";
        let id = hash_event(blob);
        let id_str = event_id_to_base64(&id);
        let now = now_ms();

        // Insert directly into events table
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id_str, "message", &blob[..], "shared", now, now],
        ).unwrap();

        let retrieved = store.get(&id).unwrap().unwrap();
        assert_eq!(retrieved, blob);
    }

    #[test]
    fn test_get_nonexistent() {
        let conn = setup();
        let store = Store::new(&conn);

        let id = [0u8; 32];
        assert!(store.get(&id).unwrap().is_none());
    }

    #[test]
    fn test_exists() {
        let conn = setup();
        let store = Store::new(&conn);

        let blob = b"test";
        let id = hash_event(blob);
        let id_str = event_id_to_base64(&id);
        let now = now_ms();

        assert!(!store.exists(&id).unwrap());

        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id_str, "message", &blob[..], "shared", now, now],
        ).unwrap();

        assert!(store.exists(&id).unwrap());
    }

    #[test]
    fn test_get_shared_summary_uses_outer_semantic_type_and_encoded_size() {
        let conn = setup();
        let store = Store::new(&conn);

        let blob = vec![crate::event_modules::EVENT_TYPE_MESSAGE, b's', b'u', b'm'];
        let id = hash_event(&blob);
        let id_str = event_id_to_base64(&id);
        let now = now_ms();
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id_str, "message", &blob[..], "shared", now, now],
        )
        .unwrap();

        let summary = store.get_shared_summary(&id).unwrap().unwrap();
        assert_eq!(summary.event_id, id);
        assert_eq!(
            summary.semantic_type_code,
            crate::event_modules::EVENT_TYPE_MESSAGE
        );
        assert_eq!(summary.encoded_size_bytes, blob.len() as u32);
        assert_eq!(summary.created_at_ms, now);
    }
}
