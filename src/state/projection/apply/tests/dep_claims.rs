use super::*;
use crate::db::dep_claims::{upsert_hard_claims, upsert_soft_claims, utc_day_start_ms};
use crate::db::store::{
    insert_event, insert_recorded_event, insert_shared_event_index_entry_if_shared,
};
use crate::event_modules::registry::ShareScope;

fn bind_workspace(conn: &Connection, recorded_by: &str, workspace_id: &str) {
    conn.execute(
        "INSERT INTO invites_accepted
         (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            recorded_by,
            "ia-1",
            "tenant-1",
            "invite-1",
            workspace_id,
            0i64
        ],
    )
    .unwrap();
}

fn insert_shared_bench_dep(
    conn: &Connection,
    recorded_by: &str,
    workspace_id: &str,
    created_at_ms: u64,
    dep_ids: Vec<EventId>,
    marker: u8,
) -> EventId {
    let parsed = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms,
        dep_ids,
        payload: [marker; 16],
    });
    let blob = crate::event_modules::encode_event(&parsed).unwrap();
    let event_id = hash_event(&blob);
    insert_event(
        conn,
        &event_id,
        "bench_dep_perf_testing",
        &blob,
        ShareScope::Shared,
        created_at_ms as i64,
        created_at_ms as i64,
    )
    .unwrap();
    insert_shared_event_index_entry_if_shared(
        conn,
        ShareScope::Shared,
        created_at_ms as i64,
        &event_id,
        workspace_id,
    )
    .unwrap();
    insert_recorded_event(conn, recorded_by, &event_id, created_at_ms as i64, "test").unwrap();
    event_id
}

fn claim_count(
    conn: &Connection,
    workspace_id: &str,
    shard_start_ms: i64,
    event_id: &EventId,
) -> i64 {
    conn.query_row(
        "SELECT COUNT(*)
         FROM dep_claims
         WHERE workspace_id = ?1 AND shard_start_ms = ?2 AND event_id = ?3",
        rusqlite::params![workspace_id, shard_start_ms, event_id_to_base64(event_id)],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn hard_claims_recurse_into_the_claiming_shard_after_projection() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "tenant-a";
    let workspace_id = "workspace-1";
    bind_workspace(&conn, recorded_by, workspace_id);

    let today_shard = utc_day_start_ms(10 * 24 * 60 * 60 * 1000);
    let prior_day_start = today_shard - (24 * 60 * 60 * 1000);
    let dep = insert_shared_bench_dep(
        &conn,
        recorded_by,
        workspace_id,
        (prior_day_start + 1_000) as u64,
        vec![],
        1,
    );
    assert_eq!(
        project_one(&conn, recorded_by, &dep).unwrap(),
        ProjectionDecision::Valid
    );

    let claimed = insert_shared_bench_dep(
        &conn,
        recorded_by,
        workspace_id,
        (prior_day_start + 2_000) as u64,
        vec![dep],
        2,
    );
    upsert_hard_claims(&conn, workspace_id, today_shard, &[claimed], 123).unwrap();

    assert_eq!(
        project_one(&conn, recorded_by, &claimed).unwrap(),
        ProjectionDecision::Valid
    );
    assert_eq!(claim_count(&conn, workspace_id, today_shard, &dep), 1);
    assert_eq!(claim_count(&conn, workspace_id, prior_day_start, &dep), 1);
}

#[test]
fn soft_claims_do_not_durably_recurse_into_the_claiming_shard() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();
    let recorded_by = "tenant-a";
    let workspace_id = "workspace-1";
    bind_workspace(&conn, recorded_by, workspace_id);

    let today_shard = utc_day_start_ms(10 * 24 * 60 * 60 * 1000);
    let prior_day_start = today_shard - (24 * 60 * 60 * 1000);
    let dep = insert_shared_bench_dep(
        &conn,
        recorded_by,
        workspace_id,
        (prior_day_start + 1_000) as u64,
        vec![],
        1,
    );
    assert_eq!(
        project_one(&conn, recorded_by, &dep).unwrap(),
        ProjectionDecision::Valid
    );

    let claimed = insert_shared_bench_dep(
        &conn,
        recorded_by,
        workspace_id,
        (prior_day_start + 2_000) as u64,
        vec![dep],
        2,
    );
    upsert_soft_claims(
        &conn,
        workspace_id,
        today_shard,
        &[claimed],
        Some("peer-z"),
        123,
        1_000_000,
    )
    .unwrap();

    assert_eq!(
        project_one(&conn, recorded_by, &claimed).unwrap(),
        ProjectionDecision::Valid
    );
    assert_eq!(claim_count(&conn, workspace_id, today_shard, &dep), 0);
    assert_eq!(claim_count(&conn, workspace_id, prior_day_start, &dep), 1);
}
