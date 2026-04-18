use super::*;
use negentropy::DepReconcileRangeStorage;

use crate::crypto::event_id_to_base64;
use crate::db::dep_index::list_shared_event_deps;
use crate::sync::session::depsync::build_range_dep_storage;
use crate::sync::session::windowing::{SyncWindow, SyncWindowKind};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

fn reindex_shared_event_at(
    conn: &rusqlite::Connection,
    workspace_id: &str,
    event_id: crate::crypto::EventId,
    created_at_ms: i64,
) {
    let event_id_b64 = event_id_to_base64(&event_id);
    conn.execute(
        "UPDATE events
         SET created_at = ?1
         WHERE event_id = ?2",
        rusqlite::params![created_at_ms, event_id_b64],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM shared_event_index
         WHERE workspace_id = ?1
           AND id = ?2",
        rusqlite::params![workspace_id, event_id.as_slice()],
    )
    .unwrap();
    crate::db::store::insert_shared_event_index_entry_if_shared(
        conn,
        crate::event_modules::registry::ShareScope::Shared,
        created_at_ms,
        &event_id,
        workspace_id,
        &[],
    )
    .unwrap();
}

fn age_all_workspace_shared_events(
    conn: &rusqlite::Connection,
    workspace_id: &str,
    created_at_ms: i64,
) {
    let mut stmt = conn
        .prepare(
            "SELECT id
             FROM shared_event_index
             WHERE workspace_id = ?1",
        )
        .unwrap();
    let rows = stmt
        .query_map(rusqlite::params![workspace_id], |row| {
            let id_blob = crate::db::sql_types::get_blob(row, 0)?;
            Ok(id_blob)
        })
        .unwrap();
    let mut event_ids = Vec::new();
    for row in rows {
        let id_blob = row.unwrap();
        if id_blob.len() != 32 {
            continue;
        }
        let mut event_id = [0u8; 32];
        event_id.copy_from_slice(&id_blob);
        event_ids.push(event_id);
    }
    drop(stmt);

    for event_id in event_ids {
        reindex_shared_event_at(conn, workspace_id, event_id, created_at_ms);
    }
}

fn insert_projected_bench_dep(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    workspace_id: &str,
    dep_ids: Vec<crate::crypto::EventId>,
    created_at_ms: i64,
    payload_seed: u8,
) -> crate::crypto::EventId {
    let bench = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: created_at_ms.max(0) as u64,
        dep_ids,
        payload: [payload_seed; 16],
    });
    let blob = events::encode_event(&bench).unwrap();
    let event_id = insert_event_raw(conn, recorded_by, &blob);
    assert_eq!(
        project_one(conn, recorded_by, &event_id).unwrap(),
        ProjectionDecision::Valid
    );
    reindex_shared_event_at(conn, workspace_id, event_id, created_at_ms);
    event_id
}

fn insert_bench_dep_chain(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    workspace_id: &str,
    len: usize,
    created_at_ms: i64,
    tail_dep: Option<crate::crypto::EventId>,
    payload_seed: u8,
) -> Vec<crate::crypto::EventId> {
    let mut chain = Vec::with_capacity(len);
    let mut prev = tail_dep;
    for offset in 0..len {
        let dep_ids = prev.into_iter().collect::<Vec<_>>();
        let event_id = insert_projected_bench_dep(
            conn,
            recorded_by,
            workspace_id,
            dep_ids,
            created_at_ms,
            payload_seed.wrapping_add(offset as u8),
        );
        chain.push(event_id);
        prev = Some(event_id);
    }
    chain
}

fn transitive_dep_ids(
    conn: &rusqlite::Connection,
    workspace_id: &str,
    event_id: crate::crypto::EventId,
) -> Vec<crate::crypto::EventId> {
    let mut out = std::collections::BTreeSet::new();
    let mut stack = vec![event_id];
    while let Some(next) = stack.pop() {
        for dep_id in list_shared_event_deps(conn, workspace_id, &next).unwrap() {
            if out.insert(dep_id) {
                stack.push(dep_id);
            }
        }
    }
    out.into_iter().collect()
}

#[test]
fn today_message_dep_range_storage_includes_old_projection_dependencies() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "tenant-dep-sync";

    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);
    let author_id = user_for_signer(&signer_eid);
    let (_event, blob) = make_message_signed(&signing_key, &signer_eid, "dep sync");
    let message_eid = insert_event_raw(&conn, recorded_by, &blob);

    assert_eq!(
        project_one(&conn, recorded_by, &message_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let workspace_id =
        crate::db::store::lookup_workspace_id(&conn, recorded_by).expect("workspace binding");
    let expected_dep_ids = transitive_dep_ids(&conn, &workspace_id, message_eid);
    assert!(
        expected_dep_ids.contains(&author_id),
        "message dep closure should include author"
    );
    assert!(
        expected_dep_ids.contains(&signer_eid),
        "message dep closure should include signer"
    );

    let now_ms = crate::db::queue::current_timestamp_ms();
    let old_dep_ts = now_ms - (8 * DAY_MS);
    let hot_message_ts = now_ms - 1_000;

    for event_id in expected_dep_ids.iter().copied() {
        let event_id_b64 = event_id_to_base64(&event_id);
        conn.execute(
            "UPDATE events
             SET created_at = ?1
             WHERE event_id = ?2",
            rusqlite::params![old_dep_ts, event_id_b64],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM shared_event_index
             WHERE workspace_id = ?1
               AND id = ?2",
            rusqlite::params![workspace_id, event_id.as_slice()],
        )
        .unwrap();
        crate::db::store::insert_shared_event_index_entry_if_shared(
            &conn,
            crate::event_modules::registry::ShareScope::Shared,
            old_dep_ts,
            &event_id,
            &workspace_id,
            &[],
        )
        .unwrap();
    }
    conn.execute(
        "UPDATE events
         SET created_at = ?1
         WHERE event_id = ?2",
        rusqlite::params![hot_message_ts, event_id_to_base64(&message_eid)],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM shared_event_index
         WHERE workspace_id = ?1
           AND id = ?2",
        rusqlite::params![workspace_id, message_eid.as_slice()],
    )
    .unwrap();
    crate::db::store::insert_shared_event_index_entry_if_shared(
        &conn,
        crate::event_modules::registry::ShareScope::Shared,
        hot_message_ts,
        &message_eid,
        &workspace_id,
        &[],
    )
    .unwrap();

    let storage = build_range_dep_storage(
        &conn,
        "/tmp/dep-range-storage-proof.db",
        &workspace_id,
        SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(now_ms - DAY_MS),
            ts_max_exclusive_ms: Some(now_ms),
        },
    )
    .unwrap();

    assert_eq!(storage.root_size().unwrap(), 1);

    let root_ids = storage
        .root_ids(0, 1)
        .unwrap()
        .into_iter()
        .map(|id| id.to_bytes())
        .collect::<Vec<_>>();
    assert_eq!(root_ids, vec![message_eid]);
    assert!(!root_ids.contains(&author_id));
    assert!(!root_ids.contains(&signer_eid));

    let mut dep_ids = storage
        .dep_ids(0, 1)
        .unwrap()
        .into_iter()
        .map(|id| id.to_bytes())
        .collect::<Vec<_>>();
    dep_ids.sort();
    let mut expected = expected_dep_ids;
    expected.sort();

    assert_eq!(dep_ids, expected);
}

#[test]
fn today_bench_dep_range_storage_includes_long_old_dependency_chain() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "tenant-dep-sync-long-chain";

    let _ = make_identity_chain(&conn, recorded_by);
    let workspace_id =
        crate::db::store::lookup_workspace_id(&conn, recorded_by).expect("workspace binding");

    let now_ms = crate::db::queue::current_timestamp_ms();
    let old_dep_ts = now_ms - (30 * DAY_MS);
    let hot_root_ts = now_ms - 1_000;
    age_all_workspace_shared_events(&conn, &workspace_id, old_dep_ts);

    let chain = insert_bench_dep_chain(
        &conn,
        recorded_by,
        &workspace_id,
        512,
        old_dep_ts,
        None,
        0x41,
    );
    let chain_head = *chain.last().expect("bench dep chain head");
    let hot_root = insert_projected_bench_dep(
        &conn,
        recorded_by,
        &workspace_id,
        vec![chain_head],
        hot_root_ts,
        0xF1,
    );

    let storage = build_range_dep_storage(
        &conn,
        "/tmp/dep-range-storage-long-chain.db",
        &workspace_id,
        SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(now_ms - DAY_MS),
            ts_max_exclusive_ms: Some(now_ms),
        },
    )
    .unwrap();

    assert_eq!(storage.root_size().unwrap(), 1);
    let root_ids = storage
        .root_ids(0, 1)
        .unwrap()
        .into_iter()
        .map(|id| id.to_bytes())
        .collect::<Vec<_>>();
    assert_eq!(root_ids, vec![hot_root]);

    let mut dep_ids = storage
        .dep_ids(0, 1)
        .unwrap()
        .into_iter()
        .map(|id| id.to_bytes())
        .collect::<Vec<_>>();
    dep_ids.sort();

    let mut expected = chain;
    expected.sort();
    assert_eq!(dep_ids, expected);
}

#[test]
fn today_bench_dep_range_storage_dedupes_shared_long_tail_across_many_hot_roots() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "tenant-dep-sync-many-roots";

    let _ = make_identity_chain(&conn, recorded_by);
    let workspace_id =
        crate::db::store::lookup_workspace_id(&conn, recorded_by).expect("workspace binding");

    let now_ms = crate::db::queue::current_timestamp_ms();
    let old_dep_ts = now_ms - (45 * DAY_MS);
    let hot_root_ts = now_ms - 5_000;
    age_all_workspace_shared_events(&conn, &workspace_id, old_dep_ts);

    let shared_tail = insert_bench_dep_chain(
        &conn,
        recorded_by,
        &workspace_id,
        256,
        old_dep_ts,
        None,
        0x55,
    );
    let shared_tail_head = *shared_tail.last().expect("shared tail head");

    let mut expected_dep_ids = std::collections::BTreeSet::new();
    expected_dep_ids.extend(shared_tail.iter().copied());

    let hot_root_count = 48usize;
    let unique_len = 12usize;
    let mut hot_roots = Vec::with_capacity(hot_root_count);
    for idx in 0..hot_root_count {
        let unique_chain = insert_bench_dep_chain(
            &conn,
            recorded_by,
            &workspace_id,
            unique_len,
            old_dep_ts,
            Some(shared_tail_head),
            0x80u8.wrapping_add(idx as u8),
        );
        expected_dep_ids.extend(unique_chain.iter().copied());
        let unique_head = *unique_chain.last().expect("unique chain head");
        let hot_root = insert_projected_bench_dep(
            &conn,
            recorded_by,
            &workspace_id,
            vec![unique_head],
            hot_root_ts + idx as i64,
            0xC0u8.wrapping_add(idx as u8),
        );
        hot_roots.push(hot_root);
    }

    let storage = build_range_dep_storage(
        &conn,
        "/tmp/dep-range-storage-many-hot-roots.db",
        &workspace_id,
        SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(now_ms - DAY_MS),
            ts_max_exclusive_ms: Some(now_ms),
        },
    )
    .unwrap();

    assert_eq!(storage.root_size().unwrap(), hot_root_count);

    let mut actual_root_ids = storage
        .root_ids(0, hot_root_count)
        .unwrap()
        .into_iter()
        .map(|id| id.to_bytes())
        .collect::<Vec<_>>();
    actual_root_ids.sort();
    hot_roots.sort();
    assert_eq!(actual_root_ids, hot_roots);

    let mut dep_ids = storage
        .dep_ids(0, hot_root_count)
        .unwrap()
        .into_iter()
        .map(|id| id.to_bytes())
        .collect::<Vec<_>>();
    dep_ids.sort();

    let expected = expected_dep_ids.into_iter().collect::<Vec<_>>();
    assert_eq!(dep_ids, expected);
}

#[test]
fn blocked_shared_root_persists_missing_dep_edges_for_dep_sync() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "tenant-blocked-dep-sync";

    let _ = make_identity_chain(&conn, recorded_by);
    let workspace_id =
        crate::db::store::lookup_workspace_id(&conn, recorded_by).expect("workspace binding");
    let now_ms = crate::db::queue::current_timestamp_ms();
    let missing_dep = [0x77; 32];

    let blob = events::encode_event(&ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: now_ms.max(0) as u64,
        dep_ids: vec![missing_dep],
        payload: [0x44; 16],
    }))
    .unwrap();
    let blocked_root = insert_event_raw(&conn, recorded_by, &blob);

    match project_one(&conn, recorded_by, &blocked_root).unwrap() {
        ProjectionDecision::BlockOnMissingDeps { missing } => assert_eq!(missing, vec![missing_dep]),
        other => panic!("expected blocked projection, got {:?}", other),
    }
    reindex_shared_event_at(&conn, &workspace_id, blocked_root, now_ms);

    let blocked_workspace_id: String = conn
        .query_row(
            "SELECT workspace_id
             FROM blocked_events
             WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_to_base64(&blocked_root)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(blocked_workspace_id, workspace_id);

    assert_eq!(
        list_shared_event_deps(&conn, &workspace_id, &blocked_root).unwrap(),
        vec![missing_dep],
        "blocked shared roots should retain their missing dep edges for phase2 dep sync"
    );

    let storage = build_range_dep_storage(
        &conn,
        "/tmp/blocked-shared-root-dep-sync.db",
        &workspace_id,
        SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(now_ms - DAY_MS),
            ts_max_exclusive_ms: Some(now_ms + DAY_MS),
        },
    )
    .unwrap();

    assert_eq!(
        storage.dep_candidate_ids_for_roots(&[blocked_root]),
        vec![missing_dep],
        "phase2 should surface missing deps for blocked shared roots already present in shared_event_index"
    );
}

#[test]
fn blocked_shared_root_uses_indexed_workspace_when_invite_binding_is_missing() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "tenant-blocked-indexed-workspace";

    let _ = make_identity_chain(&conn, recorded_by);
    let workspace_id =
        crate::db::store::lookup_workspace_id(&conn, recorded_by).expect("workspace binding");
    let now_ms = crate::db::queue::current_timestamp_ms();
    let missing_dep = [0x88; 32];

    let blob = events::encode_event(&ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: now_ms.max(0) as u64,
        dep_ids: vec![missing_dep],
        payload: [0x55; 16],
    }))
    .unwrap();
    let blocked_root = insert_event_raw(&conn, recorded_by, &blob);
    reindex_shared_event_at(&conn, &workspace_id, blocked_root, now_ms);
    conn.execute(
        "DELETE FROM invites_accepted WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
    )
    .unwrap();

    match project_one(&conn, recorded_by, &blocked_root).unwrap() {
        ProjectionDecision::BlockOnMissingDeps { missing } => assert_eq!(missing, vec![missing_dep]),
        other => panic!("expected blocked projection, got {:?}", other),
    }

    let blocked_workspace_id: String = conn
        .query_row(
            "SELECT workspace_id
             FROM blocked_events
             WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_to_base64(&blocked_root)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(blocked_workspace_id, workspace_id);

    assert_eq!(
        list_shared_event_deps(&conn, &workspace_id, &blocked_root).unwrap(),
        vec![missing_dep],
        "blocked shared roots should resolve workspace from shared_event_index when invites_accepted is not ready"
    );
}

#[test]
fn old_range_storage_disables_dep_expansion() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "tenant-dep-sync-old-window";

    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);
    let author_id = user_for_signer(&signer_eid);
    let (_event, blob) = make_message_signed(&signing_key, &signer_eid, "old dep sync");
    let message_eid = insert_event_raw(&conn, recorded_by, &blob);
    assert_eq!(
        project_one(&conn, recorded_by, &message_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let workspace_id =
        crate::db::store::lookup_workspace_id(&conn, recorded_by).expect("workspace binding");
    let now_ms = crate::db::queue::current_timestamp_ms();
    let old_ts = now_ms - (120 * DAY_MS);
    let old_window = SyncWindow {
        kind: SyncWindowKind::Old,
        ts_min_inclusive_ms: Some(0),
        ts_max_exclusive_ms: Some(now_ms - (13 * 7 * DAY_MS)),
    };

    for event_id in [author_id, signer_eid, message_eid] {
        reindex_shared_event_at(&conn, &workspace_id, event_id, old_ts);
    }

    let storage = build_range_dep_storage(
        &conn,
        "/tmp/dep-range-storage-old-window.db",
        &workspace_id,
        old_window,
    )
    .unwrap();

    assert!(
        storage.root_size().unwrap() >= 3,
        "old window should still include the old roots themselves"
    );
    assert!(
        storage
            .dep_ids(0, storage.root_size().unwrap())
            .unwrap()
            .is_empty(),
        "old-window dep expansion should be disabled"
    );
    assert!(
        storage
            .dep_candidate_ids_for_roots(&[message_eid])
            .is_empty(),
        "old-window phase2 candidates should be empty"
    );
}

#[test]
fn range_dep_storage_reuses_cached_snapshot_until_durable_change() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "tenant-dep-sync-cache";
    let cache_db_path = "/tmp/dep-range-storage-cache-proof.db";

    let (signer_eid, signing_key) = make_identity_chain(&conn, recorded_by);
    let (_event, first_blob) = make_message_signed(&signing_key, &signer_eid, "cache one");
    let first_eid = insert_event_raw(&conn, recorded_by, &first_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &first_eid).unwrap(),
        ProjectionDecision::Valid
    );

    let workspace_id =
        crate::db::store::lookup_workspace_id(&conn, recorded_by).expect("workspace binding");
    let now_ms = crate::db::queue::current_timestamp_ms();
    let range = SyncWindow {
        kind: SyncWindowKind::LastDay,
        ts_min_inclusive_ms: Some(now_ms - DAY_MS),
        ts_max_exclusive_ms: Some(now_ms + DAY_MS),
    };

    let first = build_range_dep_storage(&conn, cache_db_path, &workspace_id, range).unwrap();
    let second = build_range_dep_storage(&conn, cache_db_path, &workspace_id, range).unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&first, &second),
        "unchanged durable window should reuse cached snapshot"
    );

    let (_event, second_blob) = make_message_signed(&signing_key, &signer_eid, "cache two");
    let second_eid = insert_event_raw(&conn, recorded_by, &second_blob);
    assert_eq!(
        project_one(&conn, recorded_by, &second_eid).unwrap(),
        ProjectionDecision::Valid
    );
    reindex_shared_event_at(
        &conn,
        &workspace_id,
        second_eid,
        crate::db::queue::current_timestamp_ms(),
    );

    let third = build_range_dep_storage(&conn, cache_db_path, &workspace_id, range).unwrap();
    assert!(
        !std::sync::Arc::ptr_eq(&second, &third),
        "durable shared_event_index change should invalidate cached snapshot"
    );
    assert_eq!(third.root_size().unwrap(), first.root_size().unwrap() + 1);
}
