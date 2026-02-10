use rusqlite::{Connection, Result as SqliteResult, params};

use crate::crypto::{event_id_to_base64, EventId};

pub struct TenantDb<'a> {
    conn: &'a Connection,
    peer_id: &'a str,
}

impl<'a> TenantDb<'a> {
    pub fn new(conn: &'a Connection, peer_id: &'a str) -> Self {
        Self { conn, peer_id }
    }

    pub fn peer_id(&self) -> &str {
        self.peer_id
    }

    pub fn conn(&self) -> &Connection {
        self.conn
    }

    pub fn scoped_message_count(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            params![self.peer_id],
            |row| row.get(0),
        )
    }

    pub fn scoped_recorded_events_count(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            params![self.peer_id],
            |row| row.get(0),
        )
    }

    pub fn insert_recorded_event(&self, event_id: &str, recorded_at: i64, source: &str) -> SqliteResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, ?4)",
            params![self.peer_id, event_id, recorded_at, source],
        )?;
        Ok(())
    }

    pub fn insert_message(
        &self,
        message_id: &str,
        workspace_event_id: &str,
        author_id: &str,
        content: &str,
        created_at: i64,
    ) -> SqliteResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (message_id, workspace_event_id, author_id, content, created_at, recorded_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![message_id, workspace_event_id, author_id, content, created_at, self.peer_id],
        )?;
        Ok(())
    }

    pub fn insert_reaction(
        &self,
        event_id: &str,
        target_event_id: &str,
        author_id: &str,
        emoji: &str,
        created_at: i64,
    ) -> SqliteResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO reactions (event_id, target_event_id, author_id, emoji, created_at, recorded_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![event_id, target_event_id, author_id, emoji, created_at, self.peer_id],
        )?;
        Ok(())
    }

    pub fn insert_event(
        &self,
        event_id: &EventId,
        event_type: &str,
        blob: &[u8],
        share_scope: &str,
        created_at: i64,
        inserted_at: i64,
    ) -> SqliteResult<()> {
        let event_id_b64 = event_id_to_base64(event_id);
        self.conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![event_id_b64, event_type, blob, share_scope, created_at, inserted_at],
        )?;
        Ok(())
    }

    pub fn scoped_reaction_count(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            params![self.peer_id],
            |row| row.get(0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{open_in_memory, schema::create_tables};

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_tenant_scoped_insert_and_query() {
        let conn = setup();
        let tenant_a = TenantDb::new(&conn, "peer_a");
        let tenant_b = TenantDb::new(&conn, "peer_b");

        // Insert messages for both tenants
        tenant_a
            .insert_message("msg1", "chan1", "auth1", "hello", 100)
            .unwrap();
        tenant_a
            .insert_message("msg2", "chan1", "auth1", "world", 200)
            .unwrap();
        tenant_b
            .insert_message("msg3", "chan1", "auth2", "hi", 300)
            .unwrap();

        assert_eq!(tenant_a.scoped_message_count().unwrap(), 2);
        assert_eq!(tenant_b.scoped_message_count().unwrap(), 1);

        // Insert reactions
        tenant_a
            .insert_reaction("rxn1", "msg3", "auth1", "\u{1f44d}", 400)
            .unwrap();
        assert_eq!(tenant_a.scoped_reaction_count().unwrap(), 1);
        assert_eq!(tenant_b.scoped_reaction_count().unwrap(), 0);

        // Insert recorded_events
        tenant_a.insert_recorded_event("msg1", 100, "local_create").unwrap();
        tenant_a.insert_recorded_event("msg2", 200, "local_create").unwrap();
        tenant_b.insert_recorded_event("msg3", 300, "local_create").unwrap();
        assert_eq!(tenant_a.scoped_recorded_events_count().unwrap(), 2);
        assert_eq!(tenant_b.scoped_recorded_events_count().unwrap(), 1);

        // Insert event
        let blob = b"test-blob";
        let eid = hash_event(blob);
        tenant_a.insert_event(&eid, "message", blob, "shared", 100, 100).unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);
    }
}
