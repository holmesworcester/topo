mod cli_harness;

use cli_harness::*;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use topo::crypto::{event_id_from_hex, event_id_to_base64};
use topo::db::open_connection;

fn cli_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    hold_network_test_lock_for_binary();
    let guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cleanup_test_daemons();
    guard
}

#[test]
fn test_cli_live_message_during_large_file_sync() {
    let _guard = cli_test_lock();
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
    for _ in 0..128 {
        source_file.write_all(&chunk).unwrap();
    }
    source_file.flush().unwrap();

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));
    accept_invite(&bob_db, &invite_link);
    let _bob = start_daemon(&bob_db);

    let expected_total_file_slices = std::fs::metadata(&source_path)
        .unwrap()
        .len()
        .div_ceil(topo::event_modules::file_slice::FILE_SLICE_CIPHERTEXT_BYTES as u64)
        as i64;
    let send_file_child = Command::new(bin())
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
        .spawn()
        .expect("spawn send-file");
    let bob_recorded_by = {
        let conn = open_connection(&bob_db).expect("open bob db");
        conn.query_row(
            "SELECT recorded_by
             FROM invites_accepted
             ORDER BY created_at DESC, event_id DESC
             LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("bob recorded_by")
    };
    assert_value_eventually(
        Duration::from_secs(20),
        Duration::from_millis(100),
        "file transfer reaches a mid-flight slice count",
        || {
            let conn = open_connection(&bob_db).expect("open bob db");
            topo::event_modules::file_slice::file_slice_event_count(&conn, &bob_recorded_by)
        },
        |raw_file_slice_count| {
            *raw_file_slice_count > 0 && *raw_file_slice_count < expected_total_file_slices
        },
    );

    let live_contents = [
        "live message during file download #1",
        "live message during file download #2",
        "live message during file download #3",
    ];
    let live_send_start = Instant::now();
    let live_event_id_b64s: Vec<String> = live_contents
        .iter()
        .map(|content| {
            let live_eid = send_message(&alice_db, content);
            let live_event_id =
                event_id_from_hex(live_eid.trim()).expect("live message event id should be hex");
            event_id_to_base64(&live_event_id)
        })
        .collect();

    #[derive(Debug)]
    struct LiveArrivalSnapshot {
        messages_stdout: String,
        live_recorded: i64,
        earliest_live_recorded_rowid: Option<i64>,
        last_file_slice_recorded_rowid: Option<i64>,
        raw_file_slice_count: i64,
        elapsed: Duration,
    }

    let load_snapshot = || {
        let messages_stdout = get_messages_raw(&bob_db);
        let conn = open_connection(&bob_db).expect("open bob db");
        let live_recorded = live_event_id_b64s
            .iter()
            .map(|event_id_b64| {
                conn.query_row(
                    "SELECT COUNT(*) FROM recorded_events WHERE event_id = ?1",
                    rusqlite::params![event_id_b64],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
            })
            .sum();
        let earliest_live_recorded_rowid = live_event_id_b64s
            .iter()
            .filter_map(|event_id_b64| {
                conn.query_row(
                    "SELECT MAX(id) FROM recorded_events WHERE event_id = ?1",
                    rusqlite::params![event_id_b64],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .unwrap()
            })
            .min();
        let mut slice_stmt = conn
            .prepare(
                "SELECT re.id, e.blob
                 FROM recorded_events re
                 JOIN events e ON e.event_id = re.event_id
                 WHERE re.peer_id = ?1",
            )
            .expect("prepare raw file-slice scan");
        let slice_rows = slice_stmt
            .query_map(rusqlite::params![&bob_recorded_by], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .expect("query raw file-slice scan");
        let mut last_file_slice_recorded_rowid = None;
        for row in slice_rows {
            let (recorded_rowid, blob) = row.expect("raw file-slice row");
            if topo::event_modules::outer_semantic_type_code(&blob)
                == Some(topo::event_modules::EVENT_TYPE_FILE_SLICE)
            {
                last_file_slice_recorded_rowid = Some(
                    last_file_slice_recorded_rowid
                        .map_or(recorded_rowid, |current: i64| current.max(recorded_rowid)),
                );
            }
        }
        let raw_file_slice_count =
            topo::event_modules::file_slice::file_slice_event_count(&conn, &bob_recorded_by);
        LiveArrivalSnapshot {
            messages_stdout,
            live_recorded,
            earliest_live_recorded_rowid,
            last_file_slice_recorded_rowid,
            raw_file_slice_count,
            elapsed: live_send_start.elapsed(),
        }
    };

    let live_visible_snapshot = assert_value_eventually(
        Duration::from_secs(10),
        Duration::from_millis(100),
        "live messages become visible before the file transfer completes",
        &load_snapshot,
        |snapshot| {
            snapshot.raw_file_slice_count > 0
                && snapshot.raw_file_slice_count < expected_total_file_slices
                && live_contents
                    .iter()
                    .all(|content| snapshot.messages_stdout.contains(content))
        },
    );
    let file_slice_count_when_live_visible = live_visible_snapshot.raw_file_slice_count;
    let final_snapshot = assert_value_eventually(
        Duration::from_secs(20),
        Duration::from_millis(100),
        "later file slices arrive after the live messages",
        &load_snapshot,
        |snapshot| {
            snapshot.raw_file_slice_count > file_slice_count_when_live_visible
                && matches!(
                    (
                        snapshot.earliest_live_recorded_rowid,
                        snapshot.last_file_slice_recorded_rowid
                    ),
                    (Some(earliest_live_recorded_rowid), Some(last_file_slice_recorded_rowid))
                        if earliest_live_recorded_rowid < last_file_slice_recorded_rowid
                )
        },
    );
    let send_out = send_file_child.wait_with_output().expect("wait send-file");
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

    assert!(
        live_visible_snapshot.elapsed <= Duration::from_secs(5),
        "live message burst was not delivered quickly while the file transfer remained incomplete (live_recorded={}, raw_file_slice_count={}, elapsed={:?}):\n{}",
        live_visible_snapshot.live_recorded,
        live_visible_snapshot.raw_file_slice_count,
        live_visible_snapshot.elapsed,
        get_files_raw(&bob_db)
    );
    assert!(
        matches!(
            (
                final_snapshot.earliest_live_recorded_rowid,
                final_snapshot.last_file_slice_recorded_rowid
            ),
            (Some(earliest_live_recorded_rowid), Some(last_file_slice_recorded_rowid))
                if earliest_live_recorded_rowid < last_file_slice_recorded_rowid
        ),
        "at least one live message in the burst should be recorded before a later file slice on Bob, got earliest_live_recorded_rowid={:?}, last_file_slice_recorded_rowid={:?}, raw_file_slice_count={}",
        final_snapshot.earliest_live_recorded_rowid,
        final_snapshot.last_file_slice_recorded_rowid,
        final_snapshot.raw_file_slice_count
    );
}
