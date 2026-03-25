use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonIdentityRow {
    pub peer_id: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS daemon_transport_identity (
            singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
            peer_id TEXT NOT NULL,
            cert_der BLOB NOT NULL,
            key_der BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

pub fn load(
    conn: &Connection,
) -> Result<Option<DaemonIdentityRow>, Box<dyn std::error::Error + Send + Sync>> {
    let row = conn
        .query_row(
            "SELECT peer_id, cert_der, key_der
             FROM daemon_transport_identity
             WHERE singleton_id = 1",
            [],
            |row| {
                Ok(DaemonIdentityRow {
                    peer_id: row.get(0)?,
                    cert_der: row.get(1)?,
                    key_der: row.get(2)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

pub fn store(
    conn: &Connection,
    peer_id: &str,
    cert_der: &[u8],
    key_der: &[u8],
) -> SqliteResult<()> {
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    conn.execute(
        "INSERT OR REPLACE INTO daemon_transport_identity (
             singleton_id,
             peer_id,
             cert_der,
             key_der,
             created_at
         ) VALUES (1, ?1, ?2, ?3, ?4)",
        params![peer_id, cert_der, key_der, created_at],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn load_returns_none_when_empty() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        assert!(load(&conn).unwrap().is_none());
    }

    #[test]
    fn store_and_load_roundtrip() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        store(&conn, "daemon-peer", b"cert", b"key").unwrap();
        let row = load(&conn).unwrap().expect("daemon identity row");
        assert_eq!(row.peer_id, "daemon-peer");
        assert_eq!(row.cert_der, b"cert");
        assert_eq!(row.key_der, b"key");
    }
}
