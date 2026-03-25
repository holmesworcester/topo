//! Tests for sync control: policy storage (SC1) and registry behavior (SC4).

use std::sync::Arc;
use std::time::Duration;

use topo::db::{open_connection, sync_control};
use topo::runtime::sync_control::{
    ManualSyncRequestResult, SessionCommand, SessionRole, SyncControlRegistry,
};
use topo::shared::sync_control::{SyncPolicyMode, TenantSyncPolicy};

fn temp_db_path() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db").to_string_lossy().to_string();
    let conn = open_connection(&path).unwrap();
    sync_control::ensure_schema(&conn).unwrap();
    drop(conn);
    (dir, path)
}

// -----------------------------------------------------------------------
// SC1: Policy storage
// -----------------------------------------------------------------------

#[test]
fn default_policy_is_all_auto() {
    let (_dir, path) = temp_db_path();
    let conn = open_connection(&path).unwrap();
    let policy = sync_control::load_policy(&conn, "tenant_new").unwrap();
    assert_eq!(policy, TenantSyncPolicy::default());
    assert_eq!(policy.requests, SyncPolicyMode::Auto);
    assert_eq!(policy.responses, SyncPolicyMode::Auto);
}

#[test]
fn save_and_load_roundtrip() {
    let (_dir, path) = temp_db_path();
    let conn = open_connection(&path).unwrap();
    let policy = TenantSyncPolicy {
        requests: SyncPolicyMode::Manual,
        responses: SyncPolicyMode::Disabled,
    };
    sync_control::save_policy(&conn, "tenant_a", &policy).unwrap();
    let loaded = sync_control::load_policy(&conn, "tenant_a").unwrap();
    assert_eq!(loaded, policy);
}

#[test]
fn update_policy_merges_fields() {
    let (_dir, path) = temp_db_path();
    let conn = open_connection(&path).unwrap();
    sync_control::update_policy(&conn, "tenant_b", Some(SyncPolicyMode::Manual), None).unwrap();
    let p1 = sync_control::load_policy(&conn, "tenant_b").unwrap();
    assert_eq!(p1.requests, SyncPolicyMode::Manual);
    assert_eq!(p1.responses, SyncPolicyMode::Auto);

    sync_control::update_policy(&conn, "tenant_b", None, Some(SyncPolicyMode::Disabled)).unwrap();
    let p2 = sync_control::load_policy(&conn, "tenant_b").unwrap();
    assert_eq!(p2.requests, SyncPolicyMode::Manual);
    assert_eq!(p2.responses, SyncPolicyMode::Disabled);
}

#[test]
fn update_policy_is_tenant_scoped() {
    let (_dir, path) = temp_db_path();
    let conn = open_connection(&path).unwrap();
    sync_control::update_policy(&conn, "tenant_x", Some(SyncPolicyMode::Disabled), None).unwrap();
    sync_control::update_policy(&conn, "tenant_y", None, Some(SyncPolicyMode::Manual)).unwrap();

    let x = sync_control::load_policy(&conn, "tenant_x").unwrap();
    assert_eq!(x.requests, SyncPolicyMode::Disabled);
    assert_eq!(x.responses, SyncPolicyMode::Auto);

    let y = sync_control::load_policy(&conn, "tenant_y").unwrap();
    assert_eq!(y.requests, SyncPolicyMode::Auto);
    assert_eq!(y.responses, SyncPolicyMode::Manual);
}

#[test]
fn serde_roundtrip() {
    let policy = TenantSyncPolicy {
        requests: SyncPolicyMode::Manual,
        responses: SyncPolicyMode::Disabled,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let parsed: TenantSyncPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, parsed);
}

// -----------------------------------------------------------------------
// SC4: Registry behavior
// -----------------------------------------------------------------------

#[test]
fn registry_policy_load_returns_default() {
    let (_dir, path) = temp_db_path();
    let registry = SyncControlRegistry::new(path);
    let policy = registry.load_policy("tenant_new").unwrap();
    assert_eq!(policy, TenantSyncPolicy::default());
}

#[test]
fn registry_update_policy_roundtrip() {
    let (_dir, path) = temp_db_path();
    let registry = SyncControlRegistry::new(path);
    let p = registry
        .update_policy("tenant_a", Some(SyncPolicyMode::Manual), None)
        .unwrap();
    assert_eq!(p.requests, SyncPolicyMode::Manual);
    assert_eq!(p.responses, SyncPolicyMode::Auto);

    let loaded = registry.load_policy("tenant_a").unwrap();
    assert_eq!(loaded, p);
}

#[tokio::test]
async fn registry_session_receives_command() {
    let (_dir, path) = temp_db_path();
    let registry = Arc::new(SyncControlRegistry::new(path));

    let mut session = registry.register_session("tenant1", "abcd1234peer", SessionRole::Initiator);

    // Spawn a thread to simulate session loop receiving the command
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            match session.command_rx.recv().await {
                Some(SessionCommand::ForceRequest { reply }) => {
                    let _ = reply.send(Ok(ManualSyncRequestResult {
                        peer_id: "abcd1234peer".to_string(),
                        requested_ids: vec!["abc123".to_string()],
                        reason: None,
                    }));
                }
                _ => panic!("expected ForceRequest"),
            }
        });
        session
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let result = registry
        .trigger_request_for_peer("tenant1", "abcd")
        .unwrap();
    assert_eq!(result.peer_id, "abcd1234peer");
    assert_eq!(result.requested_ids, vec!["abc123"]);
    assert!(result.reason.is_none());

    let _session = handle.join().unwrap();
}

#[tokio::test]
async fn registry_session_deregisters_on_drop() {
    let (_dir, path) = temp_db_path();
    let registry = Arc::new(SyncControlRegistry::new(path));

    {
        let _session = registry.register_session("tenant1", "abcd1234peer", SessionRole::Initiator);
        // While session is alive, wrong prefix should fail
        let result = registry.trigger_round_for_peer("tenant1", "zzzz");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no live session"));
    }
    // After drop, correct prefix should also fail (session was deregistered)
    let result = registry.trigger_round_for_peer("tenant1", "abcd");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("no live session"));
}
