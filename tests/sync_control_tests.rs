//! Tests for sync control registry behavior.

use std::sync::Arc;
use topo::runtime::sync_control::{SessionRole, SyncControlRegistry};

#[tokio::test]
async fn registry_session_deregisters_on_drop() {
    let registry = Arc::new(SyncControlRegistry::new());

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
