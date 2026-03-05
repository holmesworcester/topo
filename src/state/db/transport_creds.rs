use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CRED_SOURCE_UNKNOWN: &str = "unknown";
pub const CRED_SOURCE_RANDOM: &str = "random";
pub const CRED_SOURCE_BOOTSTRAP: &str = "bootstrap";
pub const CRED_SOURCE_PEER_SHARED: &str = "peershared";

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS local_transport_creds (
            peer_id TEXT PRIMARY KEY,
            cert_der BLOB NOT NULL,
            key_der BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            source TEXT NOT NULL DEFAULT 'unknown'
        );
        ",
    )?;
    // Schema epoch is fixed for this POC, but allow additive column convergence so
    // existing DBs in this epoch continue to open.
    let has_source = {
        let mut stmt = conn.prepare("PRAGMA table_info(local_transport_creds)")?;
        let mut rows = stmt.query([])?;
        let mut found = false;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == "source" {
                found = true;
                break;
            }
        }
        found
    };
    if !has_source {
        conn.execute(
            "ALTER TABLE local_transport_creds ADD COLUMN source TEXT NOT NULL DEFAULT 'unknown'",
            [],
        )?;
    }
    Ok(())
}

/// Store TLS cert/key DER blobs for a local peer identity.
pub fn store_local_creds(
    conn: &Connection,
    peer_id: &str,
    cert_der: &[u8],
    key_der: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store_local_creds_with_source(conn, peer_id, cert_der, key_der, CRED_SOURCE_UNKNOWN)
}

/// Store TLS cert/key DER blobs for a local peer identity with explicit source.
pub fn store_local_creds_with_source(
    conn: &Connection,
    peer_id: &str,
    cert_der: &[u8],
    key_der: &[u8],
    source: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    conn.execute(
        "INSERT OR REPLACE INTO local_transport_creds (peer_id, cert_der, key_der, created_at, source) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![peer_id, cert_der, key_der, now, source],
    )?;
    Ok(())
}

/// Return true if any local credential row has the given source marker.
pub fn has_creds_with_source(
    conn: &Connection,
    source: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_transport_creds WHERE source = ?1 LIMIT 1)",
        rusqlite::params![source],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}

/// Load cert/key DER blobs for a specific peer identity.
pub fn load_local_creds(
    conn: &Connection,
    peer_id: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
    match conn.query_row(
        "SELECT cert_der, key_der FROM local_transport_creds WHERE peer_id = ?1",
        rusqlite::params![peer_id],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
    ) {
        Ok(pair) => Ok(Some(pair)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Load the sole local transport credentials.
/// Returns (peer_id, cert_der, key_der) if exactly one exists.
/// Returns None if no credentials exist.
/// Errors if multiple credentials exist (ambiguous — multi-tenant is handled automatically by run_node).
pub fn load_sole_local_creds(
    conn: &Connection,
) -> Result<Option<(String, Vec<u8>, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM local_transport_creds", [], |row| {
        row.get(0)
    })?;
    if count == 0 {
        return Ok(None);
    }
    if count > 1 {
        return Err(format!(
            "Multiple local identities found ({}). Multi-tenant is handled automatically.",
            count
        )
        .into());
    }
    match conn.query_row(
        "SELECT peer_id, cert_der, key_der FROM local_transport_creds LIMIT 1",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        },
    ) {
        Ok(triple) => Ok(Some(triple)),
        Err(e) => Err(e.into()),
    }
}

/// List all peer_ids that have stored transport credentials.
pub fn list_local_peers(
    conn: &Connection,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare("SELECT peer_id FROM local_transport_creds ORDER BY created_at")?;
    let peers = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(peers)
}

/// Tenant discovery: join invites_accepted with local_transport_creds to find
/// all local identities that have both a workspace binding and TLS material.
pub struct TenantInfo {
    pub peer_id: String,
    pub workspace_id: String,
    pub transport_peer_id: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

pub fn discover_local_tenants(
    conn: &Connection,
) -> Result<Vec<TenantInfo>, Box<dyn std::error::Error + Send + Sync>> {
    // Normal case: accepted-workspace binding and transport identity converged.
    let mut stmt = conn.prepare(
        "SELECT DISTINCT i.recorded_by, i.workspace_id, c.peer_id, c.cert_der, c.key_der
         FROM invites_accepted i
         JOIN local_transport_creds c ON i.recorded_by = c.peer_id",
    )?;
    let mut tenants = stmt
        .query_map([], |row| {
            Ok(TenantInfo {
                peer_id: row.get(0)?,
                workspace_id: row.get(1)?,
                transport_peer_id: row.get(2)?,
                cert_der: row.get(3)?,
                key_der: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if !tenants.is_empty() {
        return Ok(tenants);
    }

    // Transitional bootstrap fallback:
    // invite acceptance pre-derives tenant peer_id before bootstrap sync, while
    // the local transport cert may still be invite-derived until projection
    // installs the PeerShared-derived cert.
    let accepted_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM invites_accepted", [], |row| row.get(0))?;
    let creds_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM local_transport_creds", [], |row| {
            row.get(0)
        })?;
    if accepted_count == 1 && creds_count == 1 {
        let (tenant_peer_id, workspace_id): (String, String) = conn.query_row(
            "SELECT recorded_by, workspace_id
             FROM invites_accepted
             ORDER BY created_at ASC, event_id ASC
             LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (transport_peer_id, cert_der, key_der): (String, Vec<u8>, Vec<u8>) = conn.query_row(
            "SELECT peer_id, cert_der, key_der FROM local_transport_creds LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        tenants.push(TenantInfo {
            peer_id: tenant_peer_id,
            workspace_id,
            transport_peer_id,
            cert_der,
            key_der,
        });
    }

    Ok(tenants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;

    #[test]
    fn test_store_and_load_creds() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let peer_id = "abc123";
        let cert = b"cert_data";
        let key = b"key_data";
        store_local_creds(&conn, peer_id, cert, key).unwrap();

        let loaded = load_local_creds(&conn, peer_id).unwrap();
        assert!(loaded.is_some());
        let (c, k) = loaded.unwrap();
        assert_eq!(c, cert);
        assert_eq!(k, key);
    }

    #[test]
    fn test_load_missing_returns_none() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        assert!(load_local_creds(&conn, "nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_load_sole_local_creds() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        assert!(load_sole_local_creds(&conn).unwrap().is_none());

        store_local_creds(&conn, "peer1", b"c1", b"k1").unwrap();
        let result = load_sole_local_creds(&conn).unwrap().unwrap();
        assert_eq!(result.0, "peer1");
    }

    #[test]
    fn test_load_sole_local_creds_rejects_multiple() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        store_local_creds(&conn, "peer1", b"c1", b"k1").unwrap();
        store_local_creds(&conn, "peer2", b"c2", b"k2").unwrap();

        let err = load_sole_local_creds(&conn).unwrap_err();
        assert!(
            err.to_string().contains("Multiple local identities"),
            "should reject ambiguous multi-tenant DB, got: {}",
            err
        );
    }

    #[test]
    fn test_list_local_peers() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        store_local_creds(&conn, "peer_a", b"c1", b"k1").unwrap();
        store_local_creds(&conn, "peer_b", b"c2", b"k2").unwrap();

        let peers = list_local_peers(&conn).unwrap();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&"peer_a".to_string()));
        assert!(peers.contains(&"peer_b".to_string()));
    }

    #[test]
    fn test_store_replaces_existing() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        store_local_creds(&conn, "peer1", b"old_cert", b"old_key").unwrap();
        store_local_creds(&conn, "peer1", b"new_cert", b"new_key").unwrap();

        let (c, k) = load_local_creds(&conn, "peer1").unwrap().unwrap();
        assert_eq!(c, b"new_cert");
        assert_eq!(k, b"new_key");

        assert_eq!(list_local_peers(&conn).unwrap().len(), 1);
    }

    #[test]
    fn test_discover_local_tenants() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // No tenants yet
        assert!(discover_local_tenants(&conn).unwrap().is_empty());

        // Add an accepted-workspace binding and matching creds
        conn.execute(
            "INSERT INTO invites_accepted (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES ('peer1', 'ia1', 't1', 'inv1', 'ws1', 1)",
            [],
        )
        .unwrap();
        store_local_creds(&conn, "peer1", b"cert1", b"key1").unwrap();

        let tenants = discover_local_tenants(&conn).unwrap();
        assert_eq!(tenants.len(), 1);
        assert_eq!(tenants[0].peer_id, "peer1");
        assert_eq!(tenants[0].workspace_id, "ws1");
        assert_eq!(tenants[0].transport_peer_id, "peer1");

        // Accepted binding without creds should not appear
        conn.execute(
            "INSERT INTO invites_accepted (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES ('peer2', 'ia2', 't2', 'inv2', 'ws2', 2)",
            [],
        )
        .unwrap();
        assert_eq!(discover_local_tenants(&conn).unwrap().len(), 1);

        // Add creds for peer2
        store_local_creds(&conn, "peer2", b"cert2", b"key2").unwrap();
        assert_eq!(discover_local_tenants(&conn).unwrap().len(), 2);
    }

    #[test]
    fn test_discover_local_tenants_transitional_fallback() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO invites_accepted (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES ('derived_peer', 'ia3', 't3', 'inv3', 'ws1', 3)",
            [],
        )
        .unwrap();
        store_local_creds(&conn, "invite_peer", b"cert1", b"key1").unwrap();

        let tenants = discover_local_tenants(&conn).unwrap();
        assert_eq!(tenants.len(), 1);
        assert_eq!(tenants[0].peer_id, "derived_peer");
        assert_eq!(tenants[0].transport_peer_id, "invite_peer");
        assert_eq!(tenants[0].workspace_id, "ws1");
    }

    #[test]
    fn test_has_creds_with_source() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        store_local_creds_with_source(&conn, "peer1", b"cert1", b"key1", CRED_SOURCE_BOOTSTRAP)
            .unwrap();

        assert!(has_creds_with_source(&conn, CRED_SOURCE_BOOTSTRAP).unwrap());
        assert!(!has_creds_with_source(&conn, CRED_SOURCE_PEER_SHARED).unwrap());
    }

    #[test]
    fn test_ensure_schema_adds_source_column_for_legacy_table_shape() {
        let conn = open_in_memory().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE local_transport_creds (
                peer_id TEXT PRIMARY KEY,
                cert_der BLOB NOT NULL,
                key_der BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            ",
        )
        .unwrap();

        ensure_schema(&conn).unwrap();

        let mut stmt = conn
            .prepare("PRAGMA table_info(local_transport_creds)")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        let mut has_source = false;
        while let Some(row) = rows.next().unwrap() {
            let name: String = row.get(1).unwrap();
            if name == "source" {
                has_source = true;
                break;
            }
        }
        assert!(has_source, "ensure_schema should add source column");
    }
}
