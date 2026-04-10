mod cli_harness;

use cli_harness::*;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn test_cli_live_message_during_large_file_sync() {
    hold_network_test_lock_for_binary();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir
        .path()
        .join("alice_live_file.db")
        .to_str()
        .unwrap()
        .to_string();
    let bob_db = tmpdir
        .path()
        .join("bob_live_file.db")
        .to_str()
        .unwrap()
        .to_string();
    let source_path = tmpdir.path().join("large-payload.bin");
    let mut source_file = std::fs::File::create(&source_path).unwrap();
    let mut chunk = vec![0u8; 1024 * 1024];
    for (i, b) in chunk.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    for _ in 0..4 {
        source_file.write_all(&chunk).unwrap();
    }
    source_file.flush().unwrap();

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    let invite_link = create_invite_with_public_addr(&alice_db, &daemon_listen_addr(&alice_db));
    accept_invite(&bob_db, &invite_link);
    let mut bob = start_daemon(&bob_db);

    // Readiness gate: confirm the restarted daemons have an active sync path
    // before starting the large transfer. Without this, the "mid-flight"
    // assertion can spend its entire timeout budget waiting for the initial
    // session to come up under full-suite load.
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
    wait_for_live_sync_session(&alice_db, Duration::from_secs(60));
    wait_for_live_sync_session(&bob_db, Duration::from_secs(60));
    let gate_content = "pre-live-file-gate";
    let gate_eid = send_message(&alice_db, gate_content);
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", gate_eid.trim()),
        60_000,
    );

    stop_daemon(&bob_db, &mut bob);

    let send_out = Command::new(bin())
        .args([
            "--db",
            &alice_db,
            "send-file",
            "large binary payload",
            "--file",
            source_path.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run send-file");
    assert!(
        send_out.status.success(),
        "send-file failed: {}",
        String::from_utf8_lossy(&send_out.stderr)
    );
    let send_stdout = String::from_utf8_lossy(&send_out.stdout);
    assert!(
        send_stdout
            .lines()
            .any(|line| line.starts_with("event_id:")),
        "send-file output missing event_id: {}",
        send_stdout.trim()
    );

    let live_contents = ["live message during file download"];
    let live_send_start = Instant::now();
    let live_event_ids: Vec<String> = live_contents
        .iter()
        .map(|content| send_message(&alice_db, content).trim().to_string())
        .collect();

    let _bob = start_daemon(&bob_db);
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
    wait_for_live_sync_session(&alice_db, Duration::from_secs(60));
    wait_for_live_sync_session(&bob_db, Duration::from_secs(60));

    #[derive(Debug)]
    struct LiveArrivalSnapshot {
        messages_stdout: String,
        live_recorded: i64,
        earliest_live_observation_id: Option<i64>,
        last_file_slice_observation_id: Option<i64>,
        file_slice_count: i64,
        elapsed: Duration,
    }

    let load_snapshot = || {
        let messages_stdout = get_messages_raw(&bob_db);
        let observability = ingest_observability_json(&bob_db, &live_event_ids);
        let live_events = observability["events"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let live_recorded = live_events
            .iter()
            .filter(|event| event["observed"].as_bool().unwrap_or(false))
            .count() as i64;
        let earliest_live_observation_id = live_events
            .iter()
            .filter_map(|event| event["observation_id"].as_i64())
            .min();
        let last_file_slice_observation_id =
            observability["last_file_slice_observation_id"].as_i64();
        let file_slice_count = observability["file_slice_count"].as_i64().unwrap_or(0);
        LiveArrivalSnapshot {
            messages_stdout,
            live_recorded,
            earliest_live_observation_id,
            last_file_slice_observation_id,
            file_slice_count,
            elapsed: live_send_start.elapsed(),
        }
    };

    let live_visible_snapshot = assert_value_eventually(
        Duration::from_secs(30),
        Duration::from_millis(100),
        "live messages become visible and are observed before at least one later file slice",
        &load_snapshot,
        |snapshot| {
            snapshot.file_slice_count > 0
                && live_contents
                    .iter()
                    .all(|content| snapshot.messages_stdout.contains(content))
                && matches!(
                    (
                        snapshot.earliest_live_observation_id,
                        snapshot.last_file_slice_observation_id
                    ),
                    (Some(earliest_live_observation_id), Some(last_file_slice_observation_id))
                        if earliest_live_observation_id < last_file_slice_observation_id
                )
        },
    );

    assert!(
        live_visible_snapshot.elapsed <= Duration::from_secs(30),
        "live message burst was not delivered quickly during the file transfer (live_recorded={}, file_slice_count={}, elapsed={:?}):\n{}",
        live_visible_snapshot.live_recorded,
        live_visible_snapshot.file_slice_count,
        live_visible_snapshot.elapsed,
        get_files_raw(&bob_db)
    );
    assert!(
        matches!(
            (
                live_visible_snapshot.earliest_live_observation_id,
                live_visible_snapshot.last_file_slice_observation_id
            ),
            (Some(earliest_live_observation_id), Some(last_file_slice_observation_id))
                if earliest_live_observation_id < last_file_slice_observation_id
        ),
        "at least one live message in the burst should be observed before a later file slice on Bob, got earliest_live_observation_id={:?}, last_file_slice_observation_id={:?}, file_slice_count={}",
        live_visible_snapshot.earliest_live_observation_id,
        live_visible_snapshot.last_file_slice_observation_id,
        live_visible_snapshot.file_slice_count
    );
}
