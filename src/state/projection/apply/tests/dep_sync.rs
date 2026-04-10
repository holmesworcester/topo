use super::*;
use crate::sync::session::windowing::{SyncWindow, SyncWindowKind};

#[test]
fn projecting_signed_encrypted_message_indexes_shared_dep_edges() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "tenant-dep-sync";

    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);
    let author_id = user_for_signer(&signer_eid);
    conn.execute("DELETE FROM hot_week_dep_index", []).unwrap();

    let (_event, blob) = make_message_signed(&signing_key, &signer_eid, "dep sync");
    let message_eid = insert_event_raw(&conn, recorded_by, &blob);

    assert_eq!(
        project_one(&conn, recorded_by, &message_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let workspace_id =
        crate::db::store::lookup_workspace_id(&conn, recorded_by).expect("workspace binding");
    let dep_ids =
        crate::db::dep_index::list_shared_event_deps(&conn, &workspace_id, &message_eid).unwrap();
    let mut expected = vec![author_id, signer_eid];
    expected.sort_by_key(crate::crypto::event_id_to_base64);

    assert_eq!(dep_ids, expected);

    let root_created_at_ms: i64 = conn
        .query_row(
            "SELECT root_created_at_ms
             FROM hot_week_dep_index
             WHERE workspace_id = ?1
             LIMIT 1",
            rusqlite::params![&workspace_id],
            |row| row.get(0),
        )
        .unwrap();
    let hot_week_dep_ids = crate::db::hot_week_deps::list_hot_week_dep_entries(
        &conn,
        &workspace_id,
        SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(root_created_at_ms),
            ts_max_exclusive_ms: Some(root_created_at_ms + 1),
        },
    )
    .unwrap();
    for dep_id in expected {
        assert!(
            hot_week_dep_ids
                .iter()
                .any(|(_, event_id)| *event_id == dep_id),
            "hot week dep index should include direct dep {}",
            crate::crypto::event_id_to_base64(&dep_id)
        );
    }
}
