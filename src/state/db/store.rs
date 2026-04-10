use std::collections::HashMap;

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use super::sql_types::{get_blob, get_text};
use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::event_modules::{self as events, ParsedEvent, ShareScope};

const SHARED_BATCH_QUERY_CHUNK_SIZE: usize = 512;

pub const SQL_INSERT_EVENT: &str =
    "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
pub const SQL_INSERT_SHARED_EVENT_INDEX_ENTRY: &str =
    "INSERT OR IGNORE INTO shared_event_index (workspace_id, ts, id) VALUES (?1, ?2, ?3)";
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

        CREATE TABLE IF NOT EXISTS recorded_event_owners (
            peer_id TEXT NOT NULL,
            owner_event_id BLOB NOT NULL,
            event_id TEXT NOT NULL,
            PRIMARY KEY (peer_id, owner_event_id, event_id)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS idx_recorded_event_owners_event
            ON recorded_event_owners(peer_id, event_id);

        CREATE TRIGGER IF NOT EXISTS trg_recorded_events_owner_index_insert
        AFTER INSERT ON recorded_events
        BEGIN
            INSERT OR IGNORE INTO recorded_event_owners (peer_id, owner_event_id, event_id)
            SELECT NEW.peer_id, substr(e.blob, 42, 32), NEW.event_id
            FROM events e
            WHERE e.event_id = NEW.event_id
              AND e.event_type = 'encrypted'
              AND length(e.blob) >= 73
              AND substr(e.blob, 42, 32) != zeroblob(32);
        END;

        CREATE TRIGGER IF NOT EXISTS trg_recorded_events_owner_index_delete
        AFTER DELETE ON recorded_events
        BEGIN
            DELETE FROM recorded_event_owners
            WHERE peer_id = OLD.peer_id
              AND event_id = OLD.event_id;
        END;

        CREATE TABLE IF NOT EXISTS shared_event_index (
            workspace_id TEXT NOT NULL,
            ts INTEGER NOT NULL,
            id BLOB NOT NULL,
            PRIMARY KEY (workspace_id, ts, id)
        ) WITHOUT ROWID;
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

pub fn insert_shared_event_index_entry_if_shared(
    conn: &Connection,
    share_scope: ShareScope,
    created_at_ms: i64,
    event_id: &EventId,
    workspace_id: &str,
    _blob: &[u8],
) -> SqliteResult<()> {
    if share_scope == ShareScope::Shared {
        conn.execute(
            SQL_INSERT_SHARED_EVENT_INDEX_ENTRY,
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
        |row| get_text(row, 0),
    )
    .optional()
    .expect("lookup_workspace_id: unexpected DB error querying invites_accepted")
}

fn recorded_owner_event_id(conn: &Connection, event_id_b64: &str) -> SqliteResult<Option<EventId>> {
    let blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT blob
             FROM events
             WHERE event_id = ?1",
            params![event_id_b64],
            |row| get_blob(row, 0),
        )
        .optional()?;
    let Some(blob) = blob else {
        return Ok(None);
    };

    let mut parsed = match events::parse_event(&blob) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(None),
    };
    loop {
        match parsed {
            ParsedEvent::Signed(signed) => {
                parsed = match events::parse_event(&signed.payload) {
                    Ok(inner) => inner,
                    Err(_) => return Ok(None),
                };
            }
            ParsedEvent::Encrypted(enc) => {
                if enc.owner_event_id == crate::event_modules::encrypted::NO_OWNER_EVENT_ID {
                    return Ok(None);
                }
                return Ok(Some(enc.owner_event_id));
            }
            _ => return Ok(None),
        }
    }
}

fn index_recorded_event_owner(
    conn: &Connection,
    peer_id: &str,
    event_id_b64: &str,
) -> SqliteResult<()> {
    let Some(owner_event_id) = recorded_owner_event_id(conn, event_id_b64)? else {
        return Ok(());
    };
    conn.execute(
        "INSERT OR IGNORE INTO recorded_event_owners (peer_id, owner_event_id, event_id)
         VALUES (?1, ?2, ?3)",
        params![peer_id, owner_event_id.as_slice(), event_id_b64],
    )?;
    Ok(())
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
    index_recorded_event_owner(conn, peer_id, &event_id_b64)?;
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
    let inserted = conn.execute(
        SQL_INSERT_RECORDED_EVENT,
        params![peer_id, &event_id_b64, recorded_at_ms, source],
    )? > 0;
    if inserted {
        index_recorded_event_owner(conn, peer_id, &event_id_b64)?;
    }
    Ok(inserted)
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
            |row| get_blob(row, 0),
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
            |row| get_blob(row, 0),
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
        let mut map = HashMap::with_capacity(ids.len());
        for chunk in ids.chunks(SHARED_BATCH_QUERY_CHUNK_SIZE) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let sql = format!(
                "SELECT event_id, blob FROM events WHERE event_id IN ({}) AND share_scope = 'shared'",
                placeholders
            );
            let id_strs: Vec<String> = chunk.iter().map(event_id_to_base64).collect();
            let mut stmt = self.conn.prepare(&sql)?;
            let mut rows = stmt.query(rusqlite::params_from_iter(id_strs.iter()))?;
            while let Some(row) = rows.next()? {
                let id_str = get_text(row, 0)?;
                let blob = get_blob(row, 1)?;
                if let Some(event_id) = event_id_from_base64(&id_str) {
                    map.insert(event_id, blob);
                }
            }
        }
        Ok(map)
    }

    pub fn get_shared_created_at_batch(
        &self,
        ids: &[EventId],
    ) -> SqliteResult<HashMap<EventId, i64>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let mut map = HashMap::with_capacity(ids.len());
        for chunk in ids.chunks(SHARED_BATCH_QUERY_CHUNK_SIZE) {
            let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let sql = format!(
                "SELECT event_id, created_at
                 FROM events
                 WHERE event_id IN ({})
                   AND share_scope = 'shared'",
                placeholders
            );
            let id_strs: Vec<String> = chunk.iter().map(event_id_to_base64).collect();
            let mut stmt = self.conn.prepare(&sql)?;
            let mut rows = stmt.query(rusqlite::params_from_iter(id_strs.iter()))?;
            while let Some(row) = rows.next()? {
                let id_str = get_text(row, 0)?;
                let created_at: i64 = row.get(1)?;
                if let Some(event_id) = event_id_from_base64(&id_str) {
                    map.insert(event_id, created_at);
                }
            }
        }
        Ok(map)
    }

    /// Get lightweight discovery metadata for a shared event without exposing
    /// local-only rows.
    pub fn get_shared_summary(&self, id: &EventId) -> SqliteResult<Option<SharedEventSummary>> {
        let id_str = event_id_to_base64(id);
        let row: Option<(Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT blob, created_at
                 FROM events
                 WHERE event_id = ?1
                   AND share_scope = 'shared'",
                params![id_str],
                |row| Ok((get_blob(row, 0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((blob, created_at_ms)) = row else {
            return Ok(None);
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
    }

    #[test]
    fn test_get_shared_created_at_batch_chunks_large_queries() {
        let conn = setup();
        let store = Store::new(&conn);
        let now = now_ms();
        let mut ids = Vec::new();

        for idx in 0..(SHARED_BATCH_QUERY_CHUNK_SIZE * 3 + 17) {
            let blob = format!("shared-{idx}").into_bytes();
            let id = hash_event(&blob);
            let id_str = event_id_to_base64(&id);
            conn.execute(
                "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id_str, "message", &blob[..], "shared", now + idx as i64, now + idx as i64],
            )
            .unwrap();
            ids.push(id);
        }

        let created_at = store.get_shared_created_at_batch(&ids).unwrap();
        assert_eq!(created_at.len(), ids.len());
        assert_eq!(created_at.get(&ids[0]).copied(), Some(now));
        assert_eq!(
            created_at.get(ids.last().unwrap()).copied(),
            Some(now + ids.len() as i64 - 1)
        );
    }
}
