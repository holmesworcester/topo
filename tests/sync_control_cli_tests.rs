//! CLI-level sync control tests.
//!
//! These test the RPC protocol types and sync control policy serialization
//! without requiring a running daemon.

use topo::rpc::protocol::RpcMethod;
use topo::shared::sync_control::{SyncPolicyMode, TenantSyncPolicy};

#[test]
fn sync_policy_show_rpc_method_serializes() {
    let method = RpcMethod::SyncPolicyShow;
    let json = serde_json::to_string(&method).unwrap();
    assert!(json.contains("SyncPolicyShow"));
}

#[test]
fn sync_policy_set_rpc_method_serializes() {
    let method = RpcMethod::SyncPolicySet {
        requests: Some("manual".to_string()),
        responses: None,
        forward_on_have: Some("disabled".to_string()),
    };
    let json = serde_json::to_string(&method).unwrap();
    assert!(json.contains("SyncPolicySet"));
    assert!(json.contains("manual"));
    assert!(json.contains("disabled"));
}

#[test]
fn policy_default_serialization() {
    let policy = TenantSyncPolicy::default();
    let json = serde_json::to_string_pretty(&policy).unwrap();
    assert!(json.contains("auto"));
    let parsed: TenantSyncPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, policy);
}

#[test]
fn sync_round_and_request_rpc_methods_serialize() {
    let round_peer = RpcMethod::SyncRoundPeer {
        peer: "abc123".to_string(),
    };
    let round_all = RpcMethod::SyncRoundAll;
    let request_peer = RpcMethod::SyncRequestPeer {
        peer: "def456".to_string(),
    };
    let request_all = RpcMethod::SyncRequestAll;

    for method in [round_peer, round_all, request_peer, request_all] {
        let json = serde_json::to_string(&method).unwrap();
        let parsed: RpcMethod = serde_json::from_str(&json).unwrap();
        // Just verify round-trip doesn't panic
        let _ = serde_json::to_string(&parsed).unwrap();
    }
}

#[test]
fn sync_policy_mode_from_str() {
    assert_eq!(
        "auto".parse::<SyncPolicyMode>().unwrap(),
        SyncPolicyMode::Auto
    );
    assert_eq!(
        "manual".parse::<SyncPolicyMode>().unwrap(),
        SyncPolicyMode::Manual
    );
    assert_eq!(
        "disabled".parse::<SyncPolicyMode>().unwrap(),
        SyncPolicyMode::Disabled
    );
    assert!("bogus".parse::<SyncPolicyMode>().is_err());
}
