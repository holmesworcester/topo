use std::time::Duration;
use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::testutil::{assert_eventually, start_peers_pinned, Peer, ScenarioHarness, SharedDbNode};
use topo::transport::extract_spki_fingerprint;

#[tokio::test]
async fn test_shared_db_two_tenants_different_workspaces() {
    let node = SharedDbNode::new(2);
    let harness = ScenarioHarness::new();
    harness.track_node(&node);
    let t0 = &node.tenants[0];
    let t1 = &node.tenants[1];

    // Each tenant has its own workspace
    assert_ne!(
        t0.workspace_id, t1.workspace_id,
        "tenants should have distinct workspaces"
    );
    assert_ne!(
        t0.identity, t1.identity,
        "tenants should have distinct identities"
    );

    // Create messages per tenant
    t0.batch_create_messages(3);
    t1.batch_create_messages(2);

    // Verify each tenant's scoped message count
    assert_eq!(
        t0.scoped_message_count(),
        3,
        "tenant 0 should have 3 projected messages"
    );
    assert_eq!(
        t1.scoped_message_count(),
        2,
        "tenant 1 should have 2 projected messages"
    );

    // Verify per-tenant projection invariants + no cross-tenant leakage
    harness.finish();
}

/// SharedDbNode tenant discovery: verify discover_local_tenants returns all tenants.
#[tokio::test]
async fn test_shared_db_tenant_discovery() {
    let node = SharedDbNode::new(3);
    let harness = ScenarioHarness::new();
    harness.track_node(&node);

    let db = open_connection(&node.db_path).unwrap();
    let tenants = topo::db::transport_creds::discover_local_tenants(&db).unwrap();

    assert_eq!(tenants.len(), 3, "should discover all 3 tenants");

    // Verify each discovered tenant has matching cert data
    for tenant_info in &tenants {
        let fp = extract_spki_fingerprint(&tenant_info.cert_der).unwrap();
        let expected_id = hex::encode(fp);
        assert_eq!(
            expected_id, tenant_info.peer_id,
            "SPKI fingerprint should match peer_id"
        );
    }

    // Verify all tenant IDs are unique
    let ids: Vec<&str> = tenants.iter().map(|t| t.peer_id.as_str()).collect();
    let unique: std::collections::HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len(), "all tenant IDs should be unique");

    harness.finish();
}

/// No cross-tenant leakage: events created by one tenant should not have
/// recorded_events rows with another tenant's peer_id.
#[tokio::test]
async fn test_shared_db_no_cross_tenant_leakage() {
    let node = SharedDbNode::new(2);
    let harness = ScenarioHarness::new();
    harness.track_node(&node);
    let t0 = &node.tenants[0];
    let t1 = &node.tenants[1];

    t0.batch_create_messages(5);
    t1.batch_create_messages(5);

    let db = open_connection(&node.db_path).unwrap();

    // Get event_ids recorded by t0
    let t0_events: Vec<String> = {
        let mut stmt = db
            .prepare("SELECT event_id FROM recorded_events WHERE peer_id = ?1")
            .unwrap();
        stmt.query_map([&t0.identity], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };

    // Get event_ids recorded by t1
    let t1_events: Vec<String> = {
        let mut stmt = db
            .prepare("SELECT event_id FROM recorded_events WHERE peer_id = ?1")
            .unwrap();
        stmt.query_map([&t1.identity], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };

    // Verify no overlap — each tenant's recorded events are entirely its own.
    // Events blobs are shared in the events table, but recorded_events and
    // valid_events are scoped by peer_id.
    let t0_set: std::collections::HashSet<&str> = t0_events.iter().map(|s| s.as_str()).collect();
    let t1_set: std::collections::HashSet<&str> = t1_events.iter().map(|s| s.as_str()).collect();
    let overlap: Vec<&&str> = t0_set.intersection(&t1_set).collect();
    assert!(
        overlap.is_empty(),
        "recorded_events should have zero overlap between tenants, but found {}: {:?}",
        overlap.len(),
        overlap
    );

    // Verify valid_events are also isolated
    let t0_valid: Vec<String> = {
        let mut stmt = db
            .prepare("SELECT event_id FROM valid_events WHERE peer_id = ?1")
            .unwrap();
        stmt.query_map([&t0.identity], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let t1_valid: Vec<String> = {
        let mut stmt = db
            .prepare("SELECT event_id FROM valid_events WHERE peer_id = ?1")
            .unwrap();
        stmt.query_map([&t1.identity], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let t0_valid_set: std::collections::HashSet<&str> =
        t0_valid.iter().map(|s| s.as_str()).collect();
    let t1_valid_set: std::collections::HashSet<&str> =
        t1_valid.iter().map(|s| s.as_str()).collect();
    let valid_overlap: Vec<&&str> = t0_valid_set.intersection(&t1_valid_set).collect();
    assert!(
        valid_overlap.is_empty(),
        "valid_events should have zero overlap between tenants, but found {}: {:?}",
        valid_overlap.len(),
        valid_overlap
    );

    // Also verify via the comprehensive helper
    harness.finish();
}

/// Node + external peer: a SharedDbNode tenant syncs with a standalone Peer.
#[tokio::test]
async fn test_shared_db_sync_with_external_peer() {
    let node = SharedDbNode::new(1);
    let external = Peer::new_with_identity("external");
    let harness = ScenarioHarness::new();
    harness.track_node(&node);
    harness.track(&external);
    let tenant = &node.tenants[0];

    // Create messages on both sides
    tenant.batch_create_messages(2);
    external.batch_create_messages(3);

    // Create marker messages for convergence tracking
    let tenant_marker = tenant.create_message("tenant-sync-marker");
    let tenant_marker_b64 = event_id_to_base64(&tenant_marker);
    let ext_marker = external.create_message("external-sync-marker");
    let ext_marker_b64 = event_id_to_base64(&ext_marker);

    // Start sync between tenant and external peer.
    // The tenant uses the shared db_path, external uses its own.
    let _sync = start_peers_pinned(tenant, &external);

    assert_eventually(
        || external.has_event(&tenant_marker_b64) && tenant.has_event(&ext_marker_b64),
        Duration::from_secs(15),
        "tenant and external should exchange marker events",
    )
    .await;

    harness.finish();
}

/// svc_node_status returns the correct tenant list.
#[tokio::test]
async fn test_svc_node_status() {
    let node = SharedDbNode::new(2);
    let harness = ScenarioHarness::new();
    harness.track_node(&node);

    let status = topo::service::svc_node_status(&node.db_path).unwrap();
    assert_eq!(status.len(), 2, "should report 2 tenants");

    let ids: Vec<&str> = status.iter().map(|t| t.peer_id.as_str()).collect();
    assert!(ids.contains(&node.tenants[0].identity.as_str()));
    assert!(ids.contains(&node.tenants[1].identity.as_str()));

    harness.finish();
}

/// Two tenants in the same workspace on the same node: verify that canonical
/// events overlap across peer_ids (both tenants see the shared workspace event)
/// while projection invariants still hold.
#[tokio::test]
async fn test_shared_db_same_workspace_two_tenants() {
    let mut node = SharedDbNode::new(1);
    let creator_workspace = node.tenants[0].workspace_id;

    // Second tenant joins the first tenant's workspace
    node.add_tenant_in_workspace("tenant-1-same-ws", 0);

    let harness = ScenarioHarness::new();
    harness.track_node(&node);

    let t0 = &node.tenants[0];
    let t1 = &node.tenants[1];

    assert_eq!(
        t0.workspace_id, t1.workspace_id,
        "both tenants should share the same workspace"
    );
    assert_ne!(
        t0.identity, t1.identity,
        "tenants should have distinct identities"
    );

    // Both tenants create messages
    t0.batch_create_messages(2);
    t1.batch_create_messages(3);

    let db = open_connection(&node.db_path).unwrap();

    // Both tenants should have recorded the shared Workspace event
    let t0_has_ws: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![
                &t0.identity,
                &topo::crypto::event_id_to_base64(&creator_workspace)
            ],
            |row| row.get(0),
        )
        .unwrap();
    let t1_has_ws: bool = db
        .query_row(
            "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![
                &t1.identity,
                &topo::crypto::event_id_to_base64(&creator_workspace)
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        t0_has_ws,
        "tenant 0 should have recorded the workspace event"
    );
    assert!(
        t1_has_ws,
        "tenant 1 should have recorded the workspace event"
    );

    // The workspace event_id should appear in both tenants' recorded_events —
    // this is the legitimate overlap that the workspace-aware leakage check allows.
    let ws_b64 = topo::crypto::event_id_to_base64(&creator_workspace);
    let tenants_with_ws: i64 = db
        .query_row(
            "SELECT COUNT(DISTINCT peer_id) FROM recorded_events WHERE event_id = ?1",
            rusqlite::params![&ws_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        tenants_with_ws, 2,
        "workspace event should be recorded by both tenants"
    );

    // Projection invariants should hold — verify_all_invariants uses the
    // workspace-aware check that allows overlap for same-workspace tenants.
    harness.finish();
}

/// Matrix case: two initial tenants (different workspaces), each invites one
/// more tenant, resulting in two overlapping groups.
#[tokio::test]
async fn test_shared_db_overlapping_workspace_groups_matrix() {
    let mut node = SharedDbNode::new(2);
    node.add_tenant_in_workspace("tenant-2-join-ws0", 0);
    node.add_tenant_in_workspace("tenant-3-join-ws1", 1);
    let harness = ScenarioHarness::new();
    harness.track_node(&node);

    assert_eq!(node.tenants.len(), 4, "expected 4 tenants total");

    let ws0 = node.tenants[0].workspace_id;
    let ws1 = node.tenants[1].workspace_id;
    assert_ne!(ws0, ws1, "base workspaces should differ");
    assert_eq!(
        node.tenants[2].workspace_id, ws0,
        "tenant 2 should join workspace 0"
    );
    assert_eq!(
        node.tenants[3].workspace_id, ws1,
        "tenant 3 should join workspace 1"
    );

    for (idx, tenant) in node.tenants.iter().enumerate() {
        tenant.create_message(&format!("matrix-overlap-marker-{}", idx));
    }

    let db = open_connection(&node.db_path).unwrap();
    let ws0_b64 = event_id_to_base64(&ws0);
    let ws1_b64 = event_id_to_base64(&ws1);
    let ws0_tenants: i64 = db
        .query_row(
            "SELECT COUNT(DISTINCT peer_id) FROM recorded_events WHERE event_id = ?1",
            rusqlite::params![&ws0_b64],
            |row| row.get(0),
        )
        .unwrap();
    let ws1_tenants: i64 = db
        .query_row(
            "SELECT COUNT(DISTINCT peer_id) FROM recorded_events WHERE event_id = ?1",
            rusqlite::params![&ws1_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ws0_tenants, 2, "workspace 0 should be scoped to two tenants");
    assert_eq!(ws1_tenants, 2, "workspace 1 should be scoped to two tenants");

    harness.finish();
}

/// Matrix case: one workspace fanout where multiple tenants join the same
/// workspace on the same shared DB node.
#[tokio::test]
async fn test_shared_db_three_tenants_same_workspace_matrix() {
    let mut node = SharedDbNode::new(1);
    let workspace = node.tenants[0].workspace_id;
    node.add_tenant_in_workspace("tenant-1-join-same", 0);
    node.add_tenant_in_workspace("tenant-2-join-same", 0);
    let harness = ScenarioHarness::new();
    harness.track_node(&node);

    assert_eq!(node.tenants.len(), 3, "expected 3 tenants");
    for tenant in &node.tenants {
        assert_eq!(
            tenant.workspace_id, workspace,
            "all tenants should share one workspace"
        );
    }
    let ids: std::collections::HashSet<&str> =
        node.tenants.iter().map(|t| t.identity.as_str()).collect();
    assert_eq!(ids.len(), 3, "tenant identities must be unique");

    for (idx, tenant) in node.tenants.iter().enumerate() {
        tenant.create_message(&format!("matrix-same-ws-marker-{}", idx));
    }

    let db = open_connection(&node.db_path).unwrap();
    let ws_b64 = event_id_to_base64(&workspace);
    let tenants_with_ws: i64 = db
        .query_row(
            "SELECT COUNT(DISTINCT peer_id) FROM recorded_events WHERE event_id = ?1",
            rusqlite::params![&ws_b64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        tenants_with_ws, 3,
        "shared workspace event should be present for all tenants"
    );

    harness.finish();
}
