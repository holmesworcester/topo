mod cli_harness;

use cli_harness::*;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn peer_id_for_username(db_path: &str, username: &str) -> String {
    let conn = topo::db::open_connection(db_path).expect("open db");
    let active_peer_id = topo_cmd(db_path, &["tenant", "active"]);
    let active_peer_id = if active_peer_id.status.success() {
        String::from_utf8_lossy(&active_peer_id.stdout)
            .trim()
            .to_string()
    } else {
        String::new()
    };
    topo::event_modules::workspace::queries::list_tenants_for_display(&conn, &active_peer_id)
        .expect("list tenants")
        .into_iter()
        .find(|tenant| tenant.username == username)
        .map(|tenant| tenant.peer_id)
        .expect("username should map to a tenant")
}

fn repeated_warning_count(log_text: &str, needle: &str) -> usize {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for line in log_text.lines().filter(|line| line.contains(needle)) {
        let normalized = match line.find(needle) {
            Some(idx) => line[idx..].to_string(),
            None => line.to_string(),
        };
        *counts.entry(normalized).or_insert(0) += 1;
    }
    counts
        .values()
        .map(|count| count.saturating_sub(1))
        .sum::<usize>()
}

fn local_transport_cred_source_exists(db_path: &str, peer_id: &str, source: &str) -> bool {
    let conn = topo::db::open_connection(db_path).expect("open db");
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM local_transport_creds
             WHERE peer_id = ?1
               AND source = ?2
             LIMIT 1
         )",
        rusqlite::params![peer_id, source],
        |row| row.get::<_, i64>(0),
    )
    .map(|exists| exists != 0)
    .unwrap_or(false)
}

fn wait_for_transport_cred_source(db_path: &str, peer_id: &str, source: &str, timeout_ms: u64) {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    loop {
        if local_transport_cred_source_exists(db_path, peer_id, source) {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "transport credential source {:?} for peer {} did not appear within {}ms (db={})",
            source,
            peer_id,
            timeout_ms,
            db_path
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn dial_peer_for_tenant(
    db_path: &str,
    tenant_id: &str,
    remote: SocketAddr,
    remote_peer_id: &str,
) -> Result<String, String> {
    let client_config = topo::transport::build_tenant_client_config_from_db(db_path, tenant_id)
        .map_err(|e| e.to_string())?;
    let sni = topo::transport::multi_workspace::transport_sni(remote_peer_id);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("dial runtime");
    runtime.block_on(async {
        let endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).map_err(|e| e.to_string())?;
        topo::transport::dial_peer(&endpoint, remote, &sni, Some(&client_config))
            .await
            .map(|connected| {
                let peer_id = connected.peer_id.clone();
                connected.connection.close(0u32.into(), b"test done");
                endpoint.close(0u32.into(), b"test done");
                peer_id
            })
            .map_err(|e| e.to_string())
    })
}

fn wait_for_direct_trust_dial(
    db_path: &str,
    tenant_id: &str,
    remote: SocketAddr,
    remote_peer_id: &str,
    expected_peer_id: &str,
    timeout_ms: u64,
) {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let last_error = loop {
        match dial_peer_for_tenant(db_path, tenant_id, remote, remote_peer_id) {
            Ok(peer_id) => {
                assert_eq!(
                    peer_id, expected_peer_id,
                    "unexpected transport fingerprint"
                );
                return;
            }
            Err(err) => {
                if start.elapsed() >= timeout {
                    break err;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    panic!(
        "direct dial to {} as tenant {} did not converge to {} within {}ms: {}",
        remote, tenant_id, expected_peer_id, timeout_ms, last_error
    );
}

fn assert_event_visible_on_all(db_paths: &[&str], event_id: &str, timeout_ms: u64) {
    for db_path in db_paths {
        assert_eventually(db_path, &format!("has_event:{} >= 1", event_id), timeout_ms);
    }
}

#[test]
fn test_cli_reused_invite_live_daemon_reloads_bootstrap_transport_identity() {
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 90000;

    let alice_db = tmpdir
        .path()
        .join("alice-reload.db")
        .to_str()
        .unwrap()
        .to_string();
    let bob_db = tmpdir
        .path()
        .join("bob-reload.db")
        .to_str()
        .unwrap()
        .to_string();
    let carol_db = tmpdir
        .path()
        .join("carol-reload.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace_with_details(&alice_db, "reuse-live-reload", "alice", "alice-root");
    let alice_stdout = tmpdir.path().join("alice-reload.stdout.log");
    let alice_stderr = tmpdir.path().join("alice-reload.stderr.log");
    let bob_stdout = tmpdir.path().join("bob-reload.stdout.log");
    let bob_stderr = tmpdir.path().join("bob-reload.stderr.log");
    let carol_stdout = tmpdir.path().join("carol-reload.stdout.log");
    let carol_stderr = tmpdir.path().join("carol-reload.stderr.log");

    let mut alice_daemon = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            bind_port: Some(random_port()),
            stdout_file: Some(alice_stdout.clone()),
            stderr_file: Some(alice_stderr.clone()),
            ..Default::default()
        },
    );

    let reused_invite = create_invite(&alice_db, &daemon_listen_addr(&alice_db));
    let bootstrap_peer_id = {
        let parsed = topo::event_modules::workspace::invite_link::parse_invite_link(&reused_invite)
            .expect("parse invite link");
        let invite_key = parsed.invite_signing_key();
        hex::encode(topo::crypto::spki_fingerprint_from_ed25519_pubkey(
            &invite_key.verifying_key().to_bytes(),
        ))
    };

    let alice_eid = send_message(&alice_db, "reuse-live/alice-base");
    assert_event_visible_on_all(&[&alice_db], &alice_eid, timeout_ms);

    accept_invite_with_identity(&bob_db, &reused_invite, "bob", "bob-box");
    let mut bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            bind_port: Some(random_port()),
            stdout_file: Some(bob_stdout.clone()),
            stderr_file: Some(bob_stderr.clone()),
            ..Default::default()
        },
    );
    assert_event_visible_on_all(&[&alice_db, &bob_db], &alice_eid, timeout_ms);

    let carol_join = topo::event_modules::workspace::commands::accept_invite(
        &carol_db,
        &reused_invite,
        "carol",
        "carol-box",
    )
    .expect("accept reused invite without sync");
    wait_for_transport_cred_source(
        &carol_db,
        &bootstrap_peer_id,
        topo::db::transport_creds::CRED_SOURCE_BOOTSTRAP,
        5000,
    );
    assert!(
        !local_transport_cred_source_exists(
            &carol_db,
            &carol_join.peer_id,
            topo::db::transport_creds::CRED_SOURCE_PEER_SHARED,
        ),
        "partial join should not have final transport credentials before bootstrap sync"
    );

    let mut carol_daemon = start_daemon_with_options(
        &carol_db,
        &DaemonOptions {
            bind_port: Some(random_port()),
            stdout_file: Some(carol_stdout.clone()),
            stderr_file: Some(carol_stderr.clone()),
            ..Default::default()
        },
    );

    let bob_peer_id = peer_id_for_username(&bob_db, "bob");
    let carol_addr: SocketAddr = daemon_listen_addr(&carol_db)
        .parse()
        .expect("carol listen addr");
    wait_for_transport_cred_source(
        &carol_db,
        &carol_join.peer_id,
        topo::db::transport_creds::CRED_SOURCE_PEER_SHARED,
        timeout_ms,
    );
    wait_for_direct_trust_dial(
        &bob_db,
        &bob_peer_id,
        carol_addr,
        &carol_join.peer_id,
        &carol_join.peer_id,
        timeout_ms,
    );

    let carol_eid = send_message(&carol_db, "reuse-live/carol-final");
    assert_event_visible_on_all(&[&alice_db, &bob_db, &carol_db], &carol_eid, timeout_ms);

    stop_daemon(&alice_db, &mut alice_daemon);
    stop_daemon(&bob_db, &mut bob_daemon);
    stop_daemon(&carol_db, &mut carol_daemon);
    wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
    wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));
    wait_for_daemon_stopped(&carol_db, Duration::from_secs(10));

    let bob_log_text = format!(
        "{}{}",
        std::fs::read_to_string(&bob_stdout).unwrap_or_default(),
        std::fs::read_to_string(&bob_stderr).unwrap_or_default()
    );
    let carol_log_text = format!(
        "{}{}",
        std::fs::read_to_string(&carol_stdout).unwrap_or_default(),
        std::fs::read_to_string(&carol_stderr).unwrap_or_default()
    );
    assert!(
        repeated_warning_count(&bob_log_text, "Certificate mismatch connecting to") == 0,
        "bob daemon log should suppress repeated outbound trust mismatch warnings:\n{}",
        bob_log_text
    );
    assert!(
        repeated_warning_count(&bob_log_text, "Rejected incoming connection:") == 0,
        "bob daemon log should suppress repeated inbound trust mismatch warnings:\n{}",
        bob_log_text
    );
    assert!(
        repeated_warning_count(&carol_log_text, "Certificate mismatch connecting to") == 0,
        "carol daemon log should suppress repeated outbound trust mismatch warnings:\n{}",
        carol_log_text
    );
    assert!(
        repeated_warning_count(&carol_log_text, "Rejected incoming connection:") == 0,
        "carol daemon log should suppress repeated inbound trust mismatch warnings:\n{}",
        carol_log_text
    );
}
