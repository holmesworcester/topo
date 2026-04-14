mod cli_harness;

use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cli_harness::{
    accept_invite_with_identity_on_running_daemon, active_tenant_peer_id,
    create_invite_with_public_addr, create_workspace_with_seeded_history, daemon_listen_addr,
    ensure_active_peer, get_messages, message_count_sql, send_message, start_daemon_with_options,
    sync_round_all, wait_for_active_tenant_ready, wait_for_live_sync_session, DaemonOptions,
};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

struct AuthoringDepTiming {
    user_created_at_ms: i64,
    peer_shared_created_at_ms: i64,
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as i64
}

fn authoring_dep_timing_sql(db: &str) -> AuthoringDepTiming {
    let conn = topo::db::open_connection(db).expect("open db for authoring_dep_timing");
    let peer_id = cli_harness::active_tenant_peer_id(db).expect("active tenant peer id");
    conn.query_row(
        "SELECT COALESCE((
                    SELECT MIN(e.created_at)
                    FROM users u
                    JOIN events e ON e.event_id = u.event_id
                    WHERE u.recorded_by = ?1
                ), 0),
                COALESCE((
                    SELECT MIN(e.created_at)
                    FROM peers_shared ps
                    JOIN events e ON e.event_id = ps.event_id
                    WHERE ps.recorded_by = ?1
                ), 0)",
        rusqlite::params![peer_id],
        |row| {
            Ok(AuthoringDepTiming {
                user_created_at_ms: row.get(0)?,
                peer_shared_created_at_ms: row.get(1)?,
            })
        },
    )
    .expect("query authoring_dep_timing")
}

fn wait_for_message_visible(db: &str, expected_content: &str, timeout: Duration) {
    let start = std::time::Instant::now();
    loop {
        if get_messages(db)
            .into_iter()
            .any(|content| content.contains(expected_content))
        {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "message `{expected_content}` did not become visible within {:?} on db={}",
            timeout,
            db
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_message_count(db: &str, expected: i64, timeout: Duration) {
    let start = std::time::Instant::now();
    loop {
        if message_count_sql(db) >= expected {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "message_count did not reach {} within {:?} on db={} (current={})",
            expected,
            timeout,
            db,
            message_count_sql(db)
        );
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn last_day_only_sync_projects_fresh_message_with_old_authoring_deps() {
    let tmpdir = tempfile::tempdir().expect("create tempdir");
    let alice_db = tmpdir.path().join("alice.db").to_string_lossy().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_string_lossy().to_string();

    create_workspace_with_seeded_history(&alice_db, "workspace", "alice", "desktop", 0, Some("3y"));

    let daemon_opts = DaemonOptions {
        disable_discovery: true,
        last_day_only_sync: true,
        ..Default::default()
    };
    let _alice_daemon = start_daemon_with_options(&alice_db, &daemon_opts);
    ensure_active_peer(&alice_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&alice_db, Duration::from_secs(60));

    let day_cutoff_ms = current_timestamp_ms() - DAY_MS;
    let authoring_dep_timing = authoring_dep_timing_sql(&alice_db);
    assert!(
        authoring_dep_timing.user_created_at_ms < day_cutoff_ms,
        "creator user event should be older than the last-day window: user_created_at_ms={} day_cutoff_ms={}",
        authoring_dep_timing.user_created_at_ms,
        day_cutoff_ms
    );
    assert!(
        authoring_dep_timing.peer_shared_created_at_ms < day_cutoff_ms,
        "creator peer_shared event should be older than the last-day window: peer_shared_created_at_ms={} day_cutoff_ms={}",
        authoring_dep_timing.peer_shared_created_at_ms,
        day_cutoff_ms
    );

    let invite = create_invite_with_public_addr(&alice_db, &daemon_listen_addr(&alice_db));
    let _bob_daemon = start_daemon_with_options(&bob_db, &daemon_opts);
    accept_invite_with_identity_on_running_daemon(
        &bob_db,
        &invite,
        "bob",
        "phone",
        Duration::from_secs(20),
    );

    ensure_active_peer(&bob_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
    wait_for_live_sync_session(&alice_db, Duration::from_secs(60));
    wait_for_live_sync_session(&bob_db, Duration::from_secs(60));
    sync_round_all(&alice_db, Duration::from_secs(60));
    sync_round_all(&bob_db, Duration::from_secs(60));

    assert_eq!(
        message_count_sql(&bob_db),
        0,
        "receiver should start with no messages before the fresh send"
    );

    let content = "depsync last-day proof";
    send_message(&alice_db, content);
    sync_round_all(&alice_db, Duration::from_secs(60));
    sync_round_all(&bob_db, Duration::from_secs(60));

    wait_for_message_visible(&bob_db, content, Duration::from_secs(60));

    assert_eq!(message_count_sql(&alice_db), 1);
    assert_eq!(message_count_sql(&bob_db), 1);
}

#[test]
fn last_day_only_sync_projects_generated_hot_messages_with_old_authoring_deps() {
    let tmpdir = tempfile::tempdir().expect("create tempdir");
    let alice_db = tmpdir.path().join("alice.db").to_string_lossy().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_string_lossy().to_string();

    create_workspace_with_seeded_history(&alice_db, "workspace", "alice", "desktop", 0, Some("3y"));

    let daemon_opts = DaemonOptions {
        disable_discovery: true,
        last_day_only_sync: true,
        ..Default::default()
    };
    let _alice_daemon = start_daemon_with_options(&alice_db, &daemon_opts);
    ensure_active_peer(&alice_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&alice_db, Duration::from_secs(60));

    let day_cutoff_ms = current_timestamp_ms() - DAY_MS;
    let authoring_dep_timing = authoring_dep_timing_sql(&alice_db);
    assert!(
        authoring_dep_timing.user_created_at_ms < day_cutoff_ms,
        "creator user event should be older than the last-day window: user_created_at_ms={} day_cutoff_ms={}",
        authoring_dep_timing.user_created_at_ms,
        day_cutoff_ms
    );
    assert!(
        authoring_dep_timing.peer_shared_created_at_ms < day_cutoff_ms,
        "creator peer_shared event should be older than the last-day window: peer_shared_created_at_ms={} day_cutoff_ms={}",
        authoring_dep_timing.peer_shared_created_at_ms,
        day_cutoff_ms
    );

    let invite = create_invite_with_public_addr(&alice_db, &daemon_listen_addr(&alice_db));
    let _bob_daemon = start_daemon_with_options(&bob_db, &daemon_opts);
    accept_invite_with_identity_on_running_daemon(
        &bob_db,
        &invite,
        "bob",
        "phone",
        Duration::from_secs(20),
    );

    ensure_active_peer(&bob_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
    wait_for_live_sync_session(&alice_db, Duration::from_secs(60));
    wait_for_live_sync_session(&bob_db, Duration::from_secs(60));
    sync_round_all(&alice_db, Duration::from_secs(60));
    sync_round_all(&bob_db, Duration::from_secs(60));

    assert_eq!(
        message_count_sql(&bob_db),
        0,
        "receiver should start with no messages before generated hot traffic"
    );

    let generated_count = 200usize;
    let alice_peer_id = active_tenant_peer_id(&alice_db).expect("alice active tenant peer id");
    topo::event_modules::message::commands::generate_for_peer(
        &alice_db,
        &alice_peer_id,
        generated_count,
        Some("6h"),
    )
    .expect("generate hot last-day messages");

    sync_round_all(&alice_db, Duration::from_secs(120));
    sync_round_all(&bob_db, Duration::from_secs(120));
    wait_for_message_count(&alice_db, generated_count as i64, Duration::from_secs(120));
    wait_for_message_count(&bob_db, generated_count as i64, Duration::from_secs(120));

    assert_eq!(message_count_sql(&alice_db), generated_count as i64);
    assert_eq!(message_count_sql(&bob_db), generated_count as i64);
}
