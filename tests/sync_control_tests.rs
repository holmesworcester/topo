//! Tests for manual sync controls: policy storage, CLI surface, and runtime behavior.

use topo::db::{open_connection, schema::create_tables};
use topo::shared::sync_control::{SyncPolicyMode, TenantSyncPolicy};
use topo::state::db::sync_control as sync_control_db;

fn setup_db() -> (rusqlite::Connection, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let conn = open_connection(&db_path).unwrap();
    create_tables(&conn).unwrap();
    sync_control_db::ensure_schema(&conn).unwrap();
    (conn, dir)
}

// --- SC1: Policy storage tests ---

#[test]
fn default_policy_is_all_auto() {
    let (conn, _dir) = setup_db();
    let policy = sync_control_db::load_policy(&conn, "tenant-a").unwrap();
    assert_eq!(policy.requests, SyncPolicyMode::Auto);
    assert_eq!(policy.responses, SyncPolicyMode::Auto);
    assert_eq!(policy.forward_on_have, SyncPolicyMode::Auto);
}

#[test]
fn save_and_load_roundtrip() {
    let (conn, _dir) = setup_db();
    let policy = TenantSyncPolicy {
        requests: SyncPolicyMode::Manual,
        responses: SyncPolicyMode::Disabled,
        forward_on_have: SyncPolicyMode::Auto,
    };
    sync_control_db::save_policy(&conn, "tenant-a", policy).unwrap();
    let loaded = sync_control_db::load_policy(&conn, "tenant-a").unwrap();
    assert_eq!(loaded, policy);
}

#[test]
fn update_policy_partial() {
    let (conn, _dir) = setup_db();
    sync_control_db::update_policy(
        &conn,
        "tenant-a",
        Some(SyncPolicyMode::Manual),
        None,
        None,
    )
    .unwrap();
    let loaded = sync_control_db::load_policy(&conn, "tenant-a").unwrap();
    assert_eq!(loaded.requests, SyncPolicyMode::Manual);
    assert_eq!(loaded.responses, SyncPolicyMode::Auto); // unchanged
    assert_eq!(loaded.forward_on_have, SyncPolicyMode::Auto); // unchanged
}

#[test]
fn policy_is_tenant_scoped() {
    let (conn, _dir) = setup_db();
    sync_control_db::save_policy(
        &conn,
        "tenant-a",
        TenantSyncPolicy {
            requests: SyncPolicyMode::Manual,
            responses: SyncPolicyMode::Disabled,
            forward_on_have: SyncPolicyMode::Disabled,
        },
    )
    .unwrap();

    // tenant-b should still have defaults
    let policy_b = sync_control_db::load_policy(&conn, "tenant-b").unwrap();
    assert_eq!(policy_b, TenantSyncPolicy::default());

    // tenant-a should have the custom policy
    let policy_a = sync_control_db::load_policy(&conn, "tenant-a").unwrap();
    assert_eq!(policy_a.requests, SyncPolicyMode::Manual);
}

#[test]
fn policy_mode_display_and_parse() {
    assert_eq!(SyncPolicyMode::Auto.to_string(), "auto");
    assert_eq!(SyncPolicyMode::Manual.to_string(), "manual");
    assert_eq!(SyncPolicyMode::Disabled.to_string(), "disabled");

    assert_eq!("auto".parse::<SyncPolicyMode>().unwrap(), SyncPolicyMode::Auto);
    assert_eq!("manual".parse::<SyncPolicyMode>().unwrap(), SyncPolicyMode::Manual);
    assert_eq!("disabled".parse::<SyncPolicyMode>().unwrap(), SyncPolicyMode::Disabled);
    assert_eq!("AUTO".parse::<SyncPolicyMode>().unwrap(), SyncPolicyMode::Auto);
    assert!("invalid".parse::<SyncPolicyMode>().is_err());
}

// --- SC4: Policy affects request behavior ---

#[test]
fn registry_request_disabled_returns_reason() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let conn = open_connection(&db_path).unwrap();
    create_tables(&conn).unwrap();
    sync_control_db::ensure_schema(&conn).unwrap();

    // Set policy to disabled
    sync_control_db::save_policy(
        &conn,
        "tenant-x",
        TenantSyncPolicy {
            requests: SyncPolicyMode::Disabled,
            responses: SyncPolicyMode::Auto,
            forward_on_have: SyncPolicyMode::Auto,
        },
    )
    .unwrap();
    drop(conn);

    let registry = std::sync::Arc::new(
        topo::runtime::sync_control::SyncControlRegistry::new(db_path.to_string_lossy().to_string()),
    );

    // Register a fake session
    let _session = registry
        .register_session(
            "tenant-x".to_string(),
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            "initiator".to_string(),
        )
        .unwrap();

    // Trigger request - should report disabled
    let result = registry
        .trigger_request_for_peer("tenant-x", "abcdef")
        .unwrap();
    assert!(result.reason.is_some());
    assert!(result.reason.unwrap().contains("disabled"));
    assert!(result.requested_ids.is_empty());
}

#[test]
fn registry_request_manual_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let conn = open_connection(&db_path).unwrap();
    create_tables(&conn).unwrap();
    sync_control_db::ensure_schema(&conn).unwrap();

    sync_control_db::save_policy(
        &conn,
        "tenant-y",
        TenantSyncPolicy {
            requests: SyncPolicyMode::Manual,
            responses: SyncPolicyMode::Auto,
            forward_on_have: SyncPolicyMode::Auto,
        },
    )
    .unwrap();
    drop(conn);

    let registry = std::sync::Arc::new(
        topo::runtime::sync_control::SyncControlRegistry::new(db_path.to_string_lossy().to_string()),
    );

    let _session = registry
        .register_session(
            "tenant-y".to_string(),
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            "initiator".to_string(),
        )
        .unwrap();

    // Manual mode should allow requests (no reason = allowed)
    let result = registry
        .trigger_request_for_peer("tenant-y", "12345678")
        .unwrap();
    assert!(result.reason.is_none());
}

#[test]
fn registry_round_no_session_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let conn = open_connection(&db_path).unwrap();
    create_tables(&conn).unwrap();
    drop(conn);

    let registry = topo::runtime::sync_control::SyncControlRegistry::new(
        db_path.to_string_lossy().to_string(),
    );

    let result = registry.trigger_round_for_peer("tenant-z", "abcd");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("no live"));
}

#[test]
fn registry_session_deregisters_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let conn = open_connection(&db_path).unwrap();
    create_tables(&conn).unwrap();
    drop(conn);

    let registry = std::sync::Arc::new(
        topo::runtime::sync_control::SyncControlRegistry::new(db_path.to_string_lossy().to_string()),
    );

    {
        let _session = registry
            .register_session(
                "tenant-drop".to_string(),
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                "initiator".to_string(),
            )
            .unwrap();

        // Session is live
        assert!(registry.trigger_round_for_peer("tenant-drop", "deadbeef").is_ok());
    }
    // After drop, session is gone
    assert!(registry.trigger_round_for_peer("tenant-drop", "deadbeef").is_err());
}
