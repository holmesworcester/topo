mod cli_harness;

use cli_harness::*;
use std::io::{Seek, SeekFrom, Write};
use std::time::Duration;

const ONE_GIB: u64 = 1024 * 1024 * 1024;
const MAX_DAEMON_RSS_DELTA_MIB: f64 = 192.0;

#[test]
#[ignore = "large 1 GiB local-send RSS regression"]
fn rss_1gib_send_stays_bounded_single_peer() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("single-peer-1gib.db");
    let db = db.to_str().unwrap().to_string();
    let source_path = tmpdir.path().join("large-sparse.bin");

    let mut source = std::fs::File::create(&source_path).unwrap();
    source.set_len(ONE_GIB).unwrap();
    source.seek(SeekFrom::Start(0)).unwrap();
    source.write_all(b"topo").unwrap();
    source.seek(SeekFrom::Start(ONE_GIB - 4)).unwrap();
    source.write_all(b"tail").unwrap();
    source.flush().unwrap();

    create_workspace(&db);
    let mut daemon = start_daemon(&db);
    wait_for_daemon_ready(&db, Duration::from_secs(15));
    wait_for_active_tenant_ready(&db, Duration::from_secs(15));

    let daemon_pid = daemon.child().id();
    let rss_before =
        peak_rss_mib_for_pid(daemon_pid).expect("daemon VmHWM unavailable before send");

    let file_eid = send_file(&db, "large sparse payload", source_path.to_str().unwrap());
    assert!(
        !file_eid.trim().is_empty(),
        "send-file should return an event id"
    );

    let files_raw = assert_value_eventually(
        Duration::from_secs(30),
        Duration::from_millis(250),
        "single-peer files list shows completed large attachment",
        || get_files_raw(&db),
        |raw| raw.contains("large-sparse.bin") && raw.contains("\u{2714}"),
    );
    assert!(
        files_raw.contains("large-sparse.bin"),
        "files output missing large attachment:\n{}",
        files_raw
    );

    let rss_after = peak_rss_mib_for_pid(daemon_pid).expect("daemon VmHWM unavailable after send");
    let rss_delta = rss_after - rss_before;
    assert!(
        rss_delta <= MAX_DAEMON_RSS_DELTA_MIB,
        "1 GiB send should not spike daemon RSS: before={rss_before:.1} MiB after={rss_after:.1} MiB delta={rss_delta:.1} MiB"
    );
}
