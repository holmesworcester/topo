use rusqlite::{Connection, OptionalExtension};
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
        CREATE TABLE IF NOT EXISTS local_transport_targets (
            tenant_id TEXT PRIMARY KEY,
            transport_peer_id TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_local_transport_targets_transport_peer_id
            ON local_transport_targets(transport_peer_id);
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
    let target_table_sql: Option<String> = conn
        .query_row(
            "SELECT sql
             FROM sqlite_master
             WHERE type = 'table'
               AND name = 'local_transport_targets'
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if target_table_sql
        .as_deref()
        .map(|sql| !sql.contains("transport_peer_id TEXT NOT NULL UNIQUE"))
        .unwrap_or(false)
    {
        conn.execute_batch(
            "
            ALTER TABLE local_transport_targets RENAME TO local_transport_targets_old;
            CREATE TABLE local_transport_targets (
                tenant_id TEXT PRIMARY KEY,
                transport_peer_id TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO local_transport_targets (tenant_id, transport_peer_id, source, created_at)
            SELECT tenant_id, transport_peer_id, source, created_at
            FROM local_transport_targets_old
            ORDER BY CASE source
                         WHEN 'peershared' THEN 0
                         WHEN 'bootstrap' THEN 1
                         ELSE 2
                     END,
                     created_at ASC,
                     tenant_id ASC;
            DROP TABLE local_transport_targets_old;
            CREATE INDEX IF NOT EXISTS idx_local_transport_targets_transport_peer_id
                ON local_transport_targets(transport_peer_id);
            ",
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTransportTarget {
    pub tenant_id: String,
    pub transport_peer_id: String,
    pub source: String,
}

/// Record the tenant's current local transport target.
///
/// This is replay-derived local routing state, not an independent authority
/// source: projection emits transport identity intents, the adapter applies
/// them, and this table records which local transport fingerprint is now active
/// for that tenant.
pub fn set_local_transport_target(
    conn: &Connection,
    tenant_id: &str,
    transport_peer_id: &str,
    source: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    if let Err(err) = conn.execute(
        "INSERT INTO local_transport_targets (tenant_id, transport_peer_id, source, created_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(tenant_id) DO UPDATE SET
             transport_peer_id = excluded.transport_peer_id,
             source = excluded.source,
             created_at = excluded.created_at",
        rusqlite::params![tenant_id, transport_peer_id, source, now],
    ) {
        let existing: Option<(String, String)> = conn
            .query_row(
                "SELECT tenant_id, source
                 FROM local_transport_targets
                 WHERE transport_peer_id = ?1
                 LIMIT 1",
                rusqlite::params![transport_peer_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_tenant_id, existing_source)) = existing {
            return Err(format!(
                "failed to set local transport target tenant={} transport_peer_id={} source={}: already owned by tenant={} source={}: {}",
                tenant_id,
                transport_peer_id,
                source,
                existing_tenant_id,
                existing_source,
                err
            )
            .into());
        }
        return Err(format!(
            "failed to set local transport target tenant={} transport_peer_id={} source={}: {}",
            tenant_id, transport_peer_id, source, err
        )
        .into());
    }
    Ok(())
}

pub fn resolve_local_transport_target(
    conn: &Connection,
    transport_peer_id: &str,
) -> Result<Option<LocalTransportTarget>, Box<dyn std::error::Error + Send + Sync>> {
    let target = conn
        .query_row(
            "SELECT tenant_id, transport_peer_id, source
             FROM local_transport_targets
             WHERE transport_peer_id = ?1
             LIMIT 1",
            rusqlite::params![transport_peer_id],
            |row| {
                Ok(LocalTransportTarget {
                    tenant_id: row.get(0)?,
                    transport_peer_id: row.get(1)?,
                    source: row.get(2)?,
                })
            },
        )
        .optional()?;
    Ok(target)
}

pub fn resolve_tenant_transport_target(
    conn: &Connection,
    tenant_id: &str,
) -> Result<Option<LocalTransportTarget>, Box<dyn std::error::Error + Send + Sync>> {
    let target = conn
        .query_row(
            "SELECT tenant_id, transport_peer_id, source
             FROM local_transport_targets
             WHERE tenant_id = ?1
             LIMIT 1",
            rusqlite::params![tenant_id],
            |row| {
                Ok(LocalTransportTarget {
                    tenant_id: row.get(0)?,
                    transport_peer_id: row.get(1)?,
                    source: row.get(2)?,
                })
            },
        )
        .optional()?;
    Ok(target)
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

/// Return true if a specific peer_id has a local credential row with `source`.
pub fn peer_has_creds_with_source(
    conn: &Connection,
    peer_id: &str,
    source: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM local_transport_creds
             WHERE peer_id = ?1
               AND source = ?2
             LIMIT 1
         )",
        rusqlite::params![peer_id, source],
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

/// List all local transport keys with their source (e.g. "random", "peershared", "bootstrap").
pub fn list_local_peers_with_source(
    conn: &Connection,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt =
        conn.prepare("SELECT peer_id, source FROM local_transport_creds ORDER BY created_at")?;
    let keys = stmt
        .query_map([], |row| {
            Ok(serde_json::json!({
                "peer_id": row.get::<_, String>(0)?,
                "source": row.get::<_, String>(1)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(keys)
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
    let mut tenants = Vec::new();
    let mut seen_tenants = std::collections::HashSet::new();
    let mut direct_transport_peer_ids = std::collections::HashSet::new();

    // Preferred case: accepted-workspace binding and transport identity converged
    // directly on the tenant peer id. This should win over transitional bootstrap
    // mappings as soon as the final PeerShared transport identity exists.
    let mut direct_stmt = conn.prepare(
        "SELECT i.recorded_by, i.workspace_id, c.peer_id, c.cert_der, c.key_der
         FROM invites_accepted i
         JOIN local_transport_creds c ON i.recorded_by = c.peer_id
         ORDER BY i.created_at ASC, i.event_id ASC",
    )?;
    let direct_rows = direct_stmt.query_map([], |row| {
        Ok(TenantInfo {
            peer_id: row.get(0)?,
            workspace_id: row.get(1)?,
            transport_peer_id: row.get(2)?,
            cert_der: row.get(3)?,
            key_der: row.get(4)?,
        })
    })?;
    for row in direct_rows {
        let tenant = row?;
        if seen_tenants.insert(tenant.peer_id.clone()) {
            direct_transport_peer_ids.insert(tenant.transport_peer_id.clone());
            tenants.push(tenant);
        }
    }

    // Stable routing state recorded by the identity adapter. This covers
    // explicit bootstrap targets and post-bootstrap transport aliases for
    // tenants that do not yet have direct peer-id creds.
    let mut mapped_stmt = conn.prepare(
        "SELECT
             t.tenant_id,
             i.workspace_id,
             t.transport_peer_id,
             c.cert_der,
             c.key_der
         FROM local_transport_targets t
         JOIN local_transport_creds c
           ON c.peer_id = t.transport_peer_id
         JOIN invites_accepted i
           ON i.recorded_by = t.tenant_id
          AND i.event_id = (
              SELECT i2.event_id
              FROM invites_accepted i2
              WHERE i2.recorded_by = t.tenant_id
              ORDER BY i2.created_at DESC, i2.event_id DESC
              LIMIT 1
          )
         ORDER BY i.created_at ASC, i.event_id ASC",
    )?;
    let mapped_rows = mapped_stmt.query_map([], |row| {
        Ok(TenantInfo {
            peer_id: row.get(0)?,
            workspace_id: row.get(1)?,
            transport_peer_id: row.get(2)?,
            cert_der: row.get(3)?,
            key_der: row.get(4)?,
        })
    })?;
    for row in mapped_rows {
        let tenant = row?;
        if seen_tenants.insert(tenant.peer_id.clone()) {
            direct_transport_peer_ids.insert(tenant.transport_peer_id.clone());
            tenants.push(tenant);
        }
    }

    // Transitional bootstrap fallback (generalized):
    // For each accepted tenant without direct peer_id transport creds,
    // try resolving bootstrap transport identity from invite_secrets.
    let mut accepted_stmt = conn.prepare(
        "SELECT recorded_by, workspace_id, invite_event_id
         FROM invites_accepted
         ORDER BY created_at DESC, event_id DESC",
    )?;
    let accepted_rows = accepted_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let unresolved_accept_count = accepted_rows
        .iter()
        .filter(|(tenant_peer_id, _, _)| !seen_tenants.contains(tenant_peer_id))
        .count();
    let sole_transitional_creds = if unresolved_accept_count == 1 {
        let mut stmt = conn.prepare(
            "SELECT peer_id, cert_der, key_der
               FROM local_transport_creds
              ORDER BY created_at DESC, peer_id DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.len() == 1 {
            let row = rows.into_iter().next().expect("sole transport row");
            if direct_transport_peer_ids.contains(&row.0) {
                None
            } else {
                Some(row)
            }
        } else {
            None
        }
    } else {
        None
    };
    for (tenant_peer_id, workspace_id, invite_event_id) in accepted_rows {
        if !seen_tenants.insert(tenant_peer_id.clone()) {
            continue;
        }

        let invite_key_bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT private_key
                 FROM invite_secrets
                 WHERE recorded_by = ?1
                   AND invite_event_id = ?2
                 ORDER BY created_at DESC, event_id DESC
                 LIMIT 1",
                rusqlite::params![&tenant_peer_id, &invite_event_id],
                |row| row.get(0),
            )
            .ok();
        let Some(invite_key_bytes) = invite_key_bytes else {
            if let Some((bootstrap_peer_id, cert_der, key_der)) = sole_transitional_creds.as_ref() {
                tenants.push(TenantInfo {
                    peer_id: tenant_peer_id,
                    workspace_id,
                    transport_peer_id: bootstrap_peer_id.clone(),
                    cert_der: cert_der.clone(),
                    key_der: key_der.clone(),
                });
            }
            continue;
        };
        if invite_key_bytes.len() != 32 {
            continue;
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&invite_key_bytes);
        let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let bootstrap_peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
            &sk.verifying_key().to_bytes(),
        ));
        let maybe_creds: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT cert_der, key_der
                 FROM local_transport_creds
                 WHERE peer_id = ?1
                 LIMIT 1",
                rusqlite::params![&bootstrap_peer_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();
        if let Some((cert_der, key_der)) = maybe_creds {
            tenants.push(TenantInfo {
                peer_id: tenant_peer_id,
                workspace_id,
                transport_peer_id: bootstrap_peer_id,
                cert_der,
                key_der,
            });
        } else if let Some((bootstrap_peer_id, cert_der, key_der)) =
            sole_transitional_creds.as_ref()
        {
            tenants.push(TenantInfo {
                peer_id: tenant_peer_id,
                workspace_id,
                transport_peer_id: bootstrap_peer_id.clone(),
                cert_der: cert_der.clone(),
                key_der: key_der.clone(),
            });
        }
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

        // Add an accepted-workspace binding, matching creds, and target mapping.
        conn.execute(
            "INSERT INTO invites_accepted (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES ('peer1', 'ia1', 't1', 'inv1', 'ws1', 1)",
            [],
        )
        .unwrap();
        store_local_creds(&conn, "peer1", b"cert1", b"key1").unwrap();
        set_local_transport_target(&conn, "peer1", "peer1", CRED_SOURCE_PEER_SHARED).unwrap();

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

        // Add creds and a target mapping for peer2.
        store_local_creds(&conn, "peer2", b"cert2", b"key2").unwrap();
        set_local_transport_target(&conn, "peer2", "peer2", CRED_SOURCE_PEER_SHARED).unwrap();
        assert_eq!(discover_local_tenants(&conn).unwrap().len(), 2);
    }

    #[test]
    fn test_resolve_local_transport_target() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        assert!(resolve_local_transport_target(&conn, "peer1")
            .unwrap()
            .is_none());

        set_local_transport_target(&conn, "tenant_a", "peer1", CRED_SOURCE_BOOTSTRAP).unwrap();

        assert_eq!(
            resolve_local_transport_target(&conn, "peer1").unwrap(),
            Some(LocalTransportTarget {
                tenant_id: "tenant_a".to_string(),
                transport_peer_id: "peer1".to_string(),
                source: CRED_SOURCE_BOOTSTRAP.to_string(),
            })
        );
    }

    #[test]
    fn test_resolve_tenant_transport_target() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        assert!(resolve_tenant_transport_target(&conn, "tenant_a")
            .unwrap()
            .is_none());

        set_local_transport_target(&conn, "tenant_a", "peer1", CRED_SOURCE_BOOTSTRAP).unwrap();

        assert_eq!(
            resolve_tenant_transport_target(&conn, "tenant_a").unwrap(),
            Some(LocalTransportTarget {
                tenant_id: "tenant_a".to_string(),
                transport_peer_id: "peer1".to_string(),
                source: CRED_SOURCE_BOOTSTRAP.to_string(),
            })
        );
    }

    #[test]
    fn test_transport_target_stays_unique_across_tenants() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        set_local_transport_target(&conn, "tenant_a", "bootstrap_peer", CRED_SOURCE_BOOTSTRAP)
            .unwrap();
        let err =
            set_local_transport_target(&conn, "tenant_b", "bootstrap_peer", CRED_SOURCE_BOOTSTRAP)
                .unwrap_err();
        assert!(
            err.to_string().contains("UNIQUE constraint failed"),
            "unexpected error: {err}"
        );
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
    fn test_peer_has_creds_with_source() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        store_local_creds_with_source(&conn, "peer1", b"cert1", b"key1", CRED_SOURCE_BOOTSTRAP)
            .unwrap();
        store_local_creds_with_source(&conn, "peer2", b"cert2", b"key2", CRED_SOURCE_PEER_SHARED)
            .unwrap();

        assert!(peer_has_creds_with_source(&conn, "peer1", CRED_SOURCE_BOOTSTRAP).unwrap());
        assert!(!peer_has_creds_with_source(&conn, "peer1", CRED_SOURCE_PEER_SHARED).unwrap());
        assert!(peer_has_creds_with_source(&conn, "peer2", CRED_SOURCE_PEER_SHARED).unwrap());
    }

    #[test]
    fn test_discover_local_tenants_uses_explicit_target_mapping() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Tenant A is fully converged.
        conn.execute(
            "INSERT INTO invites_accepted (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES ('tenant_a', 'ia_a', 't_a', 'inv_a', 'ws_a', 1)",
            [],
        )
        .unwrap();
        store_local_creds_with_source(
            &conn,
            "tenant_a",
            b"cert_a",
            b"key_a",
            CRED_SOURCE_PEER_SHARED,
        )
        .unwrap();
        set_local_transport_target(&conn, "tenant_a", "tenant_a", CRED_SOURCE_PEER_SHARED).unwrap();

        // Tenant B is transitional: accepted invite + bootstrap creds + explicit target mapping.
        conn.execute(
            "INSERT INTO invites_accepted (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES ('tenant_b', 'ia_b', 't_b', 'inv_b', 'ws_b', 2)",
            [],
        )
        .unwrap();
        let bootstrap_peer_id = "bootstrap_peer_id".to_string();
        store_local_creds_with_source(
            &conn,
            &bootstrap_peer_id,
            b"cert_b",
            b"key_b",
            CRED_SOURCE_BOOTSTRAP,
        )
        .unwrap();
        set_local_transport_target(&conn, "tenant_b", &bootstrap_peer_id, CRED_SOURCE_BOOTSTRAP)
            .unwrap();

        let tenants = discover_local_tenants(&conn).unwrap();
        assert_eq!(tenants.len(), 2);
        let a = tenants
            .iter()
            .find(|t| t.peer_id == "tenant_a")
            .expect("tenant_a");
        assert_eq!(a.transport_peer_id, "tenant_a");
        let b = tenants
            .iter()
            .find(|t| t.peer_id == "tenant_b")
            .expect("tenant_b");
        assert_eq!(b.transport_peer_id, bootstrap_peer_id);
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
