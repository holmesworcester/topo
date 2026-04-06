//! Sync control policy persistence: per-tenant sync policy storage in SQLite.

use rusqlite::{Connection, Result as SqliteResult};

use crate::shared::sync_control::{SyncPolicyMode, TenantSyncPolicy};

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sync_control_policies (
            tenant_id TEXT PRIMARY KEY,
            requests TEXT NOT NULL DEFAULT 'auto',
            responses TEXT NOT NULL DEFAULT 'auto'
        );",
    )
}

pub fn load_policy(conn: &Connection, tenant_id: &str) -> SqliteResult<TenantSyncPolicy> {
    let mut stmt = conn.prepare_cached(
        "SELECT requests, responses
         FROM sync_control_policies
         WHERE tenant_id = ?1",
    )?;
    let result = stmt.query_row([tenant_id], |row| {
        let requests: String = row.get(0)?;
        let responses: String = row.get(1)?;
        Ok(TenantSyncPolicy {
            requests: requests.parse().unwrap_or(SyncPolicyMode::Auto),
            responses: responses.parse().unwrap_or(SyncPolicyMode::Auto),
        })
    });
    match result {
        Ok(policy) => Ok(policy),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(TenantSyncPolicy::default()),
        Err(e) => Err(e),
    }
}

pub fn save_policy(
    conn: &Connection,
    tenant_id: &str,
    policy: &TenantSyncPolicy,
) -> SqliteResult<TenantSyncPolicy> {
    conn.execute(
        "INSERT INTO sync_control_policies (tenant_id, requests, responses)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(tenant_id) DO UPDATE SET
             requests = excluded.requests,
             responses = excluded.responses",
        rusqlite::params![
            tenant_id,
            policy.requests.as_str(),
            policy.responses.as_str(),
        ],
    )?;
    Ok(*policy)
}

pub fn update_policy(
    conn: &Connection,
    tenant_id: &str,
    requests: Option<SyncPolicyMode>,
    responses: Option<SyncPolicyMode>,
) -> SqliteResult<TenantSyncPolicy> {
    let mut policy = load_policy(conn, tenant_id)?;
    if let Some(r) = requests {
        policy.requests = r;
    }
    if let Some(r) = responses {
        policy.responses = r;
    }
    save_policy(conn, tenant_id, &policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn default_policy_is_auto() {
        let conn = setup();
        let policy = load_policy(&conn, "tenant_a").unwrap();
        assert_eq!(policy, TenantSyncPolicy::default());
        assert_eq!(policy.requests, SyncPolicyMode::Auto);
        assert_eq!(policy.responses, SyncPolicyMode::Auto);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let conn = setup();
        let policy = TenantSyncPolicy {
            requests: SyncPolicyMode::Manual,
            responses: SyncPolicyMode::Disabled,
        };
        save_policy(&conn, "tenant_b", &policy).unwrap();
        let loaded = load_policy(&conn, "tenant_b").unwrap();
        assert_eq!(loaded, policy);
    }

    #[test]
    fn update_policy_is_tenant_scoped() {
        let conn = setup();
        update_policy(&conn, "tenant_x", Some(SyncPolicyMode::Manual), None).unwrap();
        update_policy(&conn, "tenant_y", None, Some(SyncPolicyMode::Disabled)).unwrap();

        let x = load_policy(&conn, "tenant_x").unwrap();
        assert_eq!(x.requests, SyncPolicyMode::Manual);
        assert_eq!(x.responses, SyncPolicyMode::Auto);

        let y = load_policy(&conn, "tenant_y").unwrap();
        assert_eq!(y.requests, SyncPolicyMode::Auto);
        assert_eq!(y.responses, SyncPolicyMode::Disabled);
    }
}
