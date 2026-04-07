mod cli_harness;

use std::io::BufRead;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn network_lock_helper_succeeds_when_lock_is_free() {
    let temp = tempfile::tempdir().expect("tempdir");
    let lock_path = temp.path().join("free.lock");
    cli_harness::acquire_network_test_lock_for_test(&lock_path, Duration::from_millis(200))
        .expect("free lock should be acquired");
}

#[test]
fn network_lock_helper_times_out_with_holder_diagnostics() {
    let temp = tempfile::tempdir().expect("tempdir");
    let lock_path = temp.path().join("held.lock");
    let script = r#"
import fcntl
import sys
import time
path = sys.argv[1]
f = open(path, 'w')
fcntl.flock(f, fcntl.LOCK_EX)
print('ready', flush=True)
time.sleep(5)
"#;
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(&lock_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn lock holder");

    let stdout = child.stdout.take().expect("holder stdout");
    let mut reader = std::io::BufReader::new(stdout);
    let mut ready = String::new();
    reader
        .read_line(&mut ready)
        .expect("read holder ready line");
    assert_eq!(ready.trim(), "ready", "holder failed to acquire lock");

    let err =
        cli_harness::acquire_network_test_lock_for_test(&lock_path, Duration::from_millis(300))
            .expect_err("held lock should time out");
    assert!(err.contains("timed out waiting"), "unexpected error: {err}");
    assert!(
        err.contains(&lock_path.display().to_string()),
        "error should mention lock path: {err}"
    );
    assert!(
        err.contains("pid="),
        "error should mention holder pid: {err}"
    );

    let _ = child.kill();
    let _ = child.wait();
}
