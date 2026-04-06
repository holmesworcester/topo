use super::*;
use crate::db::dep_claims::{upsert_hard_claims, upsert_soft_claims, utc_day_start_ms};
use crate::db::store::{
    insert_event, insert_recorded_event, insert_shared_event_index_entry_if_shared,
};
use crate::event_modules::registry::ShareScope;
use ed25519_dalek::SigningKey;

fn peer_id_for_signing_key(key: &SigningKey) -> String {
    hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &key.verifying_key().to_bytes(),
    ))
}

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
fn hot_root_claims_expand_through_already_projected_old_chain() {
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
    assert_eq!(
        project_one(&conn, recorded_by, &claimed).unwrap(),
        ProjectionDecision::Valid
    );

    let hot_root = insert_shared_bench_dep(
        &conn,
        recorded_by,
        workspace_id,
        (today_shard + 1_000) as u64,
        vec![claimed],
        3,
    );
    assert_eq!(
        project_one(&conn, recorded_by, &hot_root).unwrap(),
        ProjectionDecision::Valid
    );

    assert_eq!(claim_count(&conn, workspace_id, today_shard, &claimed), 1);
    assert_eq!(claim_count(&conn, workspace_id, today_shard, &dep), 1);
}

#[test]
fn encrypted_shared_projection_claims_outer_key_event_and_existing_key_delivery() {
    let conn = open_in_memory().unwrap();
    create_tables(&conn).unwrap();

    let workspace = crate::event_modules::workspace::commands::create_workspace(
        &conn,
        "bootstrap",
        "ws",
        "alice",
        "laptop",
    )
    .unwrap();
    let recorded_by = peer_id_for_signing_key(&workspace.peer_shared_key);
    let creator_admin_eid: EventId = conn
        .query_row(
            "SELECT event_id FROM admins WHERE recorded_by = ?1 ORDER BY event_id ASC LIMIT 1",
            rusqlite::params![&recorded_by],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
        .expect("creator admin event");
    let key_event_id = crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
        &conn,
        &recorded_by,
    )
    .unwrap();
    crate::event_modules::workspace::commands::create_user_invite_raw(
        &conn,
        &recorded_by,
        &workspace.peer_shared_key,
        &workspace.peer_shared_event_id,
        &creator_admin_eid,
        &workspace.workspace_id,
    )
    .unwrap();
    let key_shared_event_id: EventId = conn
        .query_row(
            "SELECT event_id
             FROM key_shared
             WHERE recorded_by = ?1
               AND key_event_id = ?2
             ORDER BY event_id ASC
             LIMIT 1",
            rusqlite::params![&recorded_by, event_id_to_base64(&key_event_id)],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
        .expect("key_shared for current content key");

    let ctx =
        crate::event_modules::workspace::load_local_authoring_context(&conn, &recorded_by).unwrap();
    let created_at_ms = 25_u64 * 24 * 60 * 60 * 1000;
    let shard_start_ms = utc_day_start_ms(created_at_ms as i64);
    let workspace_id = event_id_to_base64(&ctx.workspace_id);

    crate::event_modules::message::commands::send(
        &conn,
        &recorded_by,
        &ctx.signer_event_id,
        &ctx.signing_key,
        created_at_ms,
        ctx.workspace_id,
        ctx.author_id,
        "hello",
    )
    .unwrap();

    assert_eq!(
        claim_count(&conn, &workspace_id, shard_start_ms, &key_event_id),
        1
    );
    assert_eq!(
        claim_count(&conn, &workspace_id, shard_start_ms, &key_shared_event_id),
        1
    );
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
