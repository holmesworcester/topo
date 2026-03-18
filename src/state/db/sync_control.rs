use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use crate::shared::sync_control::{SyncPolicyMode, TenantSyncPolicy};

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS sync_control_policies (
            tenant_id TEXT PRIMARY KEY,
            requests_mode TEXT NOT NULL DEFAULT 'auto',
            responses_mode TEXT NOT NULL DEFAULT 'auto',
            forward_on_have_mode TEXT NOT NULL DEFAULT 'auto',
            updated_at_ms INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

pub fn load_policy(conn: &Connection, tenant_id: &str) -> SqliteResult<TenantSyncPolicy> {
    let row = conn
        .query_row(
            "SELECT requests_mode, responses_mode, forward_on_have_mode
             FROM sync_control_policies
             WHERE tenant_id = ?1",
            params![tenant_id],
            |row| {
                Ok(TenantSyncPolicy {
                    requests: parse_mode(row.get::<_, String>(0)?),
                    responses: parse_mode(row.get::<_, String>(1)?),
                    forward_on_have: parse_mode(row.get::<_, String>(2)?),
                })
            },
        )
        .optional()?;

    Ok(row.unwrap_or_default())
}

pub fn save_policy(
    conn: &Connection,
    tenant_id: &str,
    policy: TenantSyncPolicy,
) -> SqliteResult<TenantSyncPolicy> {
    conn.execute(
        "INSERT INTO sync_control_policies
         (tenant_id, requests_mode, responses_mode, forward_on_have_mode, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(tenant_id) DO UPDATE SET
             requests_mode = excluded.requests_mode,
             responses_mode = excluded.responses_mode,
             forward_on_have_mode = excluded.forward_on_have_mode,
             updated_at_ms = excluded.updated_at_ms",
        params![
            tenant_id,
            policy.requests.as_str(),
            policy.responses.as_str(),
            policy.forward_on_have.as_str(),
            now_ms(),
        ],
    )?;
    Ok(policy)
}

pub fn update_policy(
    conn: &Connection,
    tenant_id: &str,
    requests: Option<SyncPolicyMode>,
    responses: Option<SyncPolicyMode>,
    forward_on_have: Option<SyncPolicyMode>,
) -> SqliteResult<TenantSyncPolicy> {
    let mut policy = load_policy(conn, tenant_id)?;
    if let Some(mode) = requests {
        policy.requests = mode;
    }
    if let Some(mode) = responses {
        policy.responses = mode;
    }
    if let Some(mode) = forward_on_have {
        policy.forward_on_have = mode;
    }
    save_policy(conn, tenant_id, policy)
}

fn parse_mode(raw: String) -> SyncPolicyMode {
    raw.parse().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::shared::sync_control::SyncPolicyMode;

    #[test]
    fn default_policy_is_auto() {
        let conn = open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        assert_eq!(load_policy(&conn, "tenant-a").unwrap(), TenantSyncPolicy::default());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let conn = open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let policy = TenantSyncPolicy {
            requests: SyncPolicyMode::Manual,
            responses: SyncPolicyMode::Disabled,
            forward_on_have: SyncPolicyMode::Auto,
        };
        save_policy(&conn, "tenant-a", policy).unwrap();
        assert_eq!(load_policy(&conn, "tenant-a").unwrap(), policy);
    }

    #[test]
    fn update_policy_is_tenant_scoped() {
        let conn = open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        update_policy(
            &conn,
            "tenant-a",
            Some(SyncPolicyMode::Manual),
            None,
            Some(SyncPolicyMode::Disabled),
        )
        .unwrap();
        assert_eq!(
            load_policy(&conn, "tenant-a").unwrap(),
            TenantSyncPolicy {
                requests: SyncPolicyMode::Manual,
                responses: SyncPolicyMode::Auto,
                forward_on_have: SyncPolicyMode::Disabled,
            }
        );
        assert_eq!(load_policy(&conn, "tenant-b").unwrap(), TenantSyncPolicy::default());
    }
}
