//! CLI black-box integration tests.
//!
//! Tests the `topo` binary end-to-end: multi-peer sync flows via invite,
//! CLI command output formatting (event-tree, event-list, reactions, files,
//! completions), and workspace management (workspaces, db registry).
//!
//! **Boundary**: tests that exercise the CLI binary's user-facing behavior —
//! command output, multi-peer sync scenarios, and trust policy enforcement.
//! For RPC protocol mechanics and daemon lifecycle state transitions, see
//! `rpc_test.rs`. For invite-only autodial realism, see
//! `cheat_proof_realism_test.rs`. For real multi-process QUIC sync, see
//! `two_process_test.rs`.

mod cli_harness;

use cli_harness::*;
use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use topo::crypto::event_id_from_base64;
use topo::db::open_connection;
use topo::event_modules::workspace::commands::{
    accept_invite as accept_invite_without_sync, create_user_invite_raw,
};
use topo::event_modules::workspace::invite_link::{
    create_invite_link, parse_bootstrap_address, parse_invite_link, rewrite_bootstrap_addrs,
};
use topo::testutil::{DaemonGuard, Peer};

fn cli_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn create_user_invite_link_for_test_peer(creator: &Peer, bootstrap_addr: &str) -> String {
    let creator_db = open_connection(&creator.db_path).expect("open creator db");
    let creator_peer_key = creator
        .peer_shared_signing_key
        .as_ref()
        .expect("creator must have a peer_shared signer");
    let creator_peer_eid = creator
        .peer_shared_event_id
        .expect("creator must have a peer_shared event");
    let creator_admin_eid = creator_db
        .query_row(
            "SELECT event_id
             FROM admins
             WHERE recorded_by = ?1
             ORDER BY event_id ASC
             LIMIT 1",
            rusqlite::params![&creator.identity],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|b64| event_id_from_base64(&b64))
        .expect("creator must have an admin event");

    let invite = create_user_invite_raw(
        &creator_db,
        &creator.identity,
        creator_peer_key,
        &creator_peer_eid,
        &creator_admin_eid,
        &creator.workspace_id,
    )
    .expect("create user invite");
    let bootstrap_addr =
        parse_bootstrap_address(bootstrap_addr).expect("parse bootstrap address for invite link");
    create_invite_link(&invite, &[bootstrap_addr], &creator.spki_fingerprint())
        .expect("create invite link")
}

fn tenant_index_for_peer_id(db_path: &str, peer_id: &str) -> usize {
    expected_tenant_display_rows(db_path)
        .iter()
        .position(|row| row.peer_id == peer_id)
        .map(|idx| idx + 1)
        .expect("peer id should appear in tenant scopes")
}

fn wait_for_bootstrap_supersession_and_endpoint_observation(
    db_path: &str,
    remote_peer_id: &str,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_millis() as i64;
        let conn = open_connection(db_path).expect("open db");
        let bootstrap_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM invite_bootstrap_trust", [], |row| {
                row.get(0)
            })
            .expect("count invite_bootstrap_trust");
        let pending_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_invite_bootstrap_trust",
                [],
                |row| row.get(0),
            )
            .expect("count pending_invite_bootstrap_trust");
        let observed_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*)
                 FROM peer_endpoint_observations
                 WHERE via_peer_id = ?1
                   AND expires_at > ?2",
                rusqlite::params![remote_peer_id, now_ms],
                |row| row.get(0),
            )
            .expect("count peer_endpoint_observations");
        drop(conn);

        if bootstrap_rows == 0 && pending_rows == 0 && observed_rows > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "bootstrap trust did not supersede into observed-endpoint state for db={} remote={} within {:?} (bootstrap_rows={}, pending_rows={}, observed_rows={})",
            db_path,
            remote_peer_id,
            timeout,
            bootstrap_rows,
            pending_rows,
            observed_rows
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct StartedCliPeer {
    db: String,
    username: String,
    device_name: String,
    _daemon: DaemonGuard,
}

impl StartedCliPeer {
    fn tenant_label(&self) -> String {
        format!("{}/{}", self.username, self.device_name)
    }
}

fn short_cli_id(id: &str) -> &str {
    &id[..id.len().min(8)]
}

fn local_username_for_tenant(conn: &rusqlite::Connection, peer_id: &str) -> String {
    use rusqlite::OptionalExtension;

    if let Some(username) = conn
        .query_row(
            "SELECT COALESCE(u.username, '')
             FROM peers_shared ps
             JOIN local_transport_creds c
               ON c.peer_id = lower(hex(ps.transport_fingerprint))
             LEFT JOIN users u
               ON ps.user_event_id = u.event_id
              AND ps.recorded_by = u.recorded_by
             WHERE ps.recorded_by = ?1
             ORDER BY ps.event_id ASC
             LIMIT 1",
            rusqlite::params![peer_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .expect("query local tenant username")
    {
        return username;
    }

    conn.query_row(
        "SELECT COALESCE(username, '')
         FROM users
         WHERE recorded_by = ?1
         ORDER BY event_id ASC
         LIMIT 1",
        rusqlite::params![peer_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .expect("fallback tenant username")
    .unwrap_or_default()
}

fn workspace_name_for_tenant(
    conn: &rusqlite::Connection,
    peer_id: &str,
    workspace_id: &str,
) -> String {
    use rusqlite::OptionalExtension;

    conn.query_row(
        "SELECT COALESCE(name, '')
         FROM workspaces
         WHERE recorded_by = ?1
           AND workspace_id = ?2
         LIMIT 1",
        rusqlite::params![peer_id, workspace_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .expect("query tenant workspace name")
    .unwrap_or_default()
}

#[derive(Debug)]
struct ExpectedTenantDisplayRow {
    peer_id: String,
    tenant_event_id: String,
    workspace_id: String,
    username: String,
    workspace_name: String,
    active: bool,
}

fn active_tenant_peer_id(db_path: &str) -> Option<String> {
    let output = topo_cmd(db_path, &["tenant", "active"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() && stderr.contains("daemon is not running") {
        return None;
    }
    assert!(
        output.status.success(),
        "tenant active failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        stderr
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() || trimmed == "(no active tenant)" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn expected_tenant_display_rows(db_path: &str) -> Vec<ExpectedTenantDisplayRow> {
    let conn = open_connection(db_path).expect("open db");
    let active_peer_id = active_tenant_peer_id(db_path);
    let mut stmt = conn
        .prepare(
            "SELECT recorded_by, tenant_event_id, workspace_id
             FROM invites_accepted
             ORDER BY recorded_by, created_at ASC, event_id ASC",
        )
        .expect("prepare tenant labels query");
    let mut rows = stmt.query([]).expect("query tenant labels");
    let mut seen = std::collections::HashSet::new();
    let mut labels = Vec::new();

    while let Some(row) = rows.next().expect("read tenant label row") {
        let peer_id: String = row.get(0).expect("tenant peer id");
        if !seen.insert(peer_id.clone()) {
            continue;
        }
        let tenant_event_id: String = row.get(1).expect("tenant event id");
        let workspace_id: String = row.get(2).expect("tenant workspace id");
        let username = local_username_for_tenant(&conn, &peer_id);
        let workspace_name = workspace_name_for_tenant(&conn, &peer_id, &workspace_id);
        labels.push(ExpectedTenantDisplayRow {
            active: active_peer_id.as_deref() == Some(peer_id.as_str()),
            peer_id,
            tenant_event_id,
            workspace_id,
            username,
            workspace_name,
        });
    }

    labels.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then_with(|| a.workspace_name.cmp(&b.workspace_name))
            .then_with(|| a.username.cmp(&b.username))
            .then_with(|| a.tenant_event_id.cmp(&b.tenant_event_id))
    });

    labels
}

fn expected_view_tenant_labels(db_path: &str) -> Vec<(String, String)> {
    expected_tenant_display_rows(db_path)
        .into_iter()
        .map(|row| {
            let user_display = if row.username.is_empty() {
                short_cli_id(&row.peer_id).to_string()
            } else {
                row.username
            };
            let workspace_display = if row.workspace_name.is_empty() {
                short_cli_id(&row.workspace_id).to_string()
            } else {
                row.workspace_name
            };
            (
                short_cli_id(&row.tenant_event_id).to_string(),
                format!("{}@{}", user_display, workspace_display),
            )
        })
        .collect()
}

fn view_tenant_section_lines(output: &str) -> Vec<&str> {
    let mut in_tenants = false;
    let mut lines = Vec::new();
    for line in output.lines() {
        if !in_tenants {
            if line.trim() == "TENANTS:" {
                in_tenants = true;
            }
            continue;
        }
        if line.trim().is_empty() {
            break;
        }
        lines.push(line);
    }
    lines
}

fn numbered_tenant_section_count(output: &str) -> usize {
    view_tenant_section_lines(output)
        .into_iter()
        .filter(|line| {
            let trimmed = line.trim_start();
            let Some(dot_pos) = trimmed.find('.') else {
                return false;
            };
            trimmed[..dot_pos].chars().all(|c| c.is_ascii_digit())
        })
        .count()
}

fn numbered_item_count(output: &str) -> usize {
    output
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            let Some(dot_pos) = trimmed.find('.') else {
                return false;
            };
            trimmed[..dot_pos].chars().all(|c| c.is_ascii_digit())
        })
        .count()
}

fn status_projected_count(output: &str, label: &str) -> usize {
    let prefix = format!("{}:", label);
    output
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix(&prefix)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|num| num.parse::<usize>().ok())
        })
        .unwrap_or_else(|| panic!("missing status count for {} in:\n{}", label, output))
}

fn tenant_index_for_username(db_path: &str, username: &str) -> usize {
    let peer_id = peer_id_for_username(db_path, username);
    tenant_index_for_peer_id(db_path, &peer_id)
}

fn peer_id_for_username(db_path: &str, username: &str) -> String {
    let conn = open_connection(db_path).expect("open db");
    conn.query_row(
        "SELECT recorded_by
         FROM users
         WHERE username = ?1
         LIMIT 1",
        rusqlite::params![username],
        |row| row.get(0),
    )
    .expect("username should map to a tenant")
}

fn wait_for_username_peer_id(db_path: &str, username: &str, timeout_ms: u64) -> String {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    loop {
        let conn = open_connection(db_path).expect("open db");
        let found = conn
            .query_row(
                "SELECT recorded_by
                 FROM users
                 WHERE username = ?1
                 LIMIT 1",
                rusqlite::params![username],
                |row| row.get::<_, String>(0),
            )
            .ok();
        if let Some(peer_id) = found {
            return peer_id;
        }
        if start.elapsed() >= timeout {
            panic!(
                "username {} did not materialize within {}ms in {}",
                username, timeout_ms, db_path
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn use_tenant_for_username(db_path: &str, username: &str) {
    let idx = tenant_index_for_username(db_path, username);
    use_tenant(db_path, &idx.to_string());
}

fn rewrite_invite_addrs(invite_link: &str, addrs: &[&str]) -> String {
    let parsed = addrs
        .iter()
        .map(|addr| parse_bootstrap_address(addr).expect("parse bootstrap address"))
        .collect::<Vec<_>>();
    rewrite_bootstrap_addrs(invite_link, &parsed).expect("rewrite invite bootstrap addrs")
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

fn invite_bootstrap_peer_id(invite_link: &str) -> String {
    let parsed = parse_invite_link(invite_link).expect("parse invite link");
    let invite_key = parsed.invite_signing_key();
    hex::encode(topo::crypto::spki_fingerprint_from_ed25519_pubkey(
        &invite_key.verifying_key().to_bytes(),
    ))
}

fn local_transport_cred_source_exists(db_path: &str, peer_id: &str, source: &str) -> bool {
    let conn = open_connection(db_path).expect("open db");
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
        if start.elapsed() >= timeout {
            panic!(
                "transport credential source {:?} for peer {} did not appear within {}ms (db={})",
                source, peer_id, timeout_ms, db_path
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn projected_transport_peer_exists(db_path: &str, recorded_by: &str, peer_id: &str) -> bool {
    let Ok(transport_fingerprint) = hex::decode(peer_id) else {
        return false;
    };
    if transport_fingerprint.len() != 32 {
        return false;
    }

    let conn = open_connection(db_path).expect("open db");
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM peers_shared
             WHERE recorded_by = ?1
               AND transport_fingerprint = ?2
             LIMIT 1
         )",
        rusqlite::params![recorded_by, transport_fingerprint],
        |row| row.get::<_, i64>(0),
    )
    .map(|exists| exists != 0)
    .unwrap_or(false)
}

fn wait_for_projected_transport_peer(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    timeout_ms: u64,
) {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    loop {
        if projected_transport_peer_exists(db_path, recorded_by, peer_id) {
            return;
        }
        if start.elapsed() >= timeout {
            panic!(
                "projected transport peer {} did not appear within {}ms for tenant {} (db={})",
                peer_id, timeout_ms, recorded_by, db_path
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn dial_peer_for_tenant(
    db_path: &str,
    tenant_id: &str,
    remote: SocketAddr,
    expected_remote_transport_fingerprint: &str,
) -> Result<String, String> {
    let client_config = topo::transport::build_tenant_client_config_from_db(db_path, tenant_id)
        .map_err(|e| e.to_string())?;
    let sni =
        topo::transport::multi_workspace::transport_sni(expected_remote_transport_fingerprint);

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
    expected_peer_id: &str,
    timeout_ms: u64,
) {
    wait_for_projected_transport_peer(db_path, tenant_id, expected_peer_id, timeout_ms);

    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let last_error = loop {
        match dial_peer_for_tenant(db_path, tenant_id, remote, expected_peer_id) {
            Ok(peer_id) => {
                assert_eq!(
                    peer_id, expected_peer_id,
                    "direct dial presented unexpected transport fingerprint"
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

fn assert_direct_dial_never_succeeds(
    db_path: &str,
    tenant_id: &str,
    remote: SocketAddr,
    expected_remote_transport_fingerprint: &str,
    timeout_ms: u64,
) {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    while start.elapsed() < timeout {
        if let Ok(peer_id) = dial_peer_for_tenant(
            db_path,
            tenant_id,
            remote,
            expected_remote_transport_fingerprint,
        ) {
            panic!(
                "direct dial to {} as tenant {} unexpectedly succeeded with peer {}",
                remote, tenant_id, peer_id
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn start_joined_cli_peer(
    tmpdir: &tempfile::TempDir,
    db_name: &str,
    invite_link: &str,
    username: &str,
    device_name: &str,
) -> StartedCliPeer {
    let db = tmpdir.path().join(db_name).to_str().unwrap().to_string();
    accept_invite_with_identity(&db, invite_link, username, device_name);
    let daemon = start_daemon(&db);
    StartedCliPeer {
        db,
        username: username.to_string(),
        device_name: device_name.to_string(),
        _daemon: daemon,
    }
}

fn start_linked_cli_peer(
    tmpdir: &tempfile::TempDir,
    db_name: &str,
    invite_link: &str,
    username: &str,
    device_name: &str,
) -> StartedCliPeer {
    let db = tmpdir.path().join(db_name).to_str().unwrap().to_string();
    accept_device_link_with_name(&db, invite_link, device_name);
    let daemon = start_daemon(&db);
    StartedCliPeer {
        db,
        username: username.to_string(),
        device_name: device_name.to_string(),
        _daemon: daemon,
    }
}

fn send_message_as_username(db_path: &str, username: &str, content: &str) -> String {
    use_tenant_for_username(db_path, username);
    send_message(db_path, content)
}

fn assert_cli_state(
    db_path: &str,
    expected_workspace_names: &[&str],
    expected_view_workspace_name: &str,
    expected_tenant_count: usize,
    expected_user_count: usize,
    expected_users: &[&str],
    expected_tenants: &[&str],
    expected_messages: &[&str],
) {
    let active = topo_cmd(db_path, &["tenant", "active"]);
    assert!(
        active.status.success(),
        "tenant active failed: {}",
        String::from_utf8_lossy(&active.stderr)
    );
    let active_stdout = String::from_utf8_lossy(&active.stdout);
    assert!(
        !active_stdout.trim().is_empty() && active_stdout.trim() != "(no active tenant)",
        "active tenant should be selected: {}",
        active_stdout
    );

    assert_eventually(
        db_path,
        &format!("message_count >= {}", expected_messages.len()),
        30_000,
    );

    let status = get_status_raw(db_path);
    assert!(
        status.contains("Runtime:   Active"),
        "status should show active runtime:\n{}",
        status
    );
    assert_eq!(
        status_projected_count(&status, "Messages"),
        expected_messages.len(),
        "status should report the expected projected message count:\n{}",
        status
    );

    let workspaces = get_workspaces_raw(db_path);
    assert!(
        workspaces.contains("WORKSPACES"),
        "workspaces should include the header:\n{}",
        workspaces
    );
    assert_eq!(
        numbered_item_count(&workspaces),
        expected_workspace_names.len(),
        "workspaces should have the expected count:\n{}",
        workspaces
    );

    let tenants = get_tenants_raw(db_path);
    assert_eq!(
        numbered_item_count(&tenants),
        expected_tenant_count,
        "tenants should have the expected count:\n{}",
        tenants
    );
    for workspace_name in expected_workspace_names {
        assert!(
            tenants.contains(workspace_name),
            "tenant list should include workspace name {:?}:\n{}",
            workspace_name,
            tenants
        );
    }

    let users = get_users_raw(db_path);
    assert_eq!(
        numbered_item_count(&users),
        expected_user_count,
        "users should have the expected count:\n{}",
        users
    );
    for username in expected_users {
        assert!(
            users.contains(username),
            "users should contain {:?}:\n{}",
            username,
            users
        );
    }

    let view = get_view_raw(db_path);
    assert!(
        view.contains(expected_view_workspace_name),
        "view should show workspace {:?}:\n{}",
        expected_view_workspace_name,
        view
    );
    assert!(
        view.contains("USERS:"),
        "view should include USERS:\n{}",
        view
    );
    assert!(
        view.contains("TENANTS:"),
        "view should include TENANTS:\n{}",
        view
    );
    assert_eq!(
        numbered_tenant_section_count(&view),
        expected_tenant_count,
        "view tenant section should number each tenant:\n{}",
        view
    );
    let tenant_lines = view_tenant_section_lines(&view);
    for (idx, (tenant_event_id, tenant_label)) in
        expected_view_tenant_labels(db_path).into_iter().enumerate()
    {
        assert!(
            view.contains(&tenant_event_id),
            "view should contain tenant event id {:?}:\n{}",
            tenant_event_id,
            view
        );
        assert!(
            view.contains(&tenant_label),
            "view should contain top-level tenant label {:?}:\n{}",
            tenant_label,
            view
        );
        let expected_prefix = format!("{}.", idx + 1);
        assert!(
            tenant_lines.iter().any(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with(&expected_prefix)
                    && line.contains(&tenant_event_id)
                    && line.contains(&tenant_label)
            }),
            "view tenant line should be numbered consistently for {:?}:\n{}",
            tenant_label,
            view
        );
    }
    for username in expected_users {
        assert!(
            view.contains(username),
            "view should contain user {:?}:\n{}",
            username,
            view
        );
    }
    for tenant in expected_tenants {
        assert!(
            view.contains(tenant),
            "view should contain workspace user/device {:?}:\n{}",
            tenant,
            view
        );
    }
    for message in expected_messages {
        assert!(
            view.contains(message),
            "view should contain message {:?}:\n{}",
            message,
            view
        );
    }

    let messages = get_messages_raw(db_path);
    for message in expected_messages {
        assert!(
            messages.contains(message),
            "messages should contain {:?}:\n{}",
            message,
            messages
        );
    }

    let identity = topo_cmd(db_path, &["identity"]);
    assert!(
        identity.status.success(),
        "identity failed: {}",
        String::from_utf8_lossy(&identity.stderr)
    );
    let identity_stdout = String::from_utf8_lossy(&identity.stdout);
    assert!(
        identity_stdout.contains("Transport:"),
        "identity should include transport fingerprint:\n{}",
        identity_stdout
    );
    assert!(
        !identity_stdout.contains("User:      (none)"),
        "identity should have a materialized user:\n{}",
        identity_stdout
    );
    assert!(
        !identity_stdout.contains("Peer:      (none)"),
        "identity should have a materialized peer:\n{}",
        identity_stdout
    );
}

fn assert_event_visible_on_all(db_paths: &[&str], event_id: &str, timeout_ms: u64) {
    for db_path in db_paths {
        assert_eventually(db_path, &format!("has_event:{} >= 1", event_id), timeout_ms);
    }
}

fn assert_event_visible_for_username(
    db_path: &str,
    username: &str,
    event_id: &str,
    timeout_ms: u64,
) {
    use_tenant_for_username(db_path, username);
    assert_eventually(db_path, &format!("has_event:{} >= 1", event_id), timeout_ms);
}

fn assert_identity_eventually_materialized(db_path: &str, timeout_ms: u64) {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    loop {
        let identity = topo_cmd(db_path, &["identity"]);
        let stdout = String::from_utf8_lossy(&identity.stdout);
        if identity.status.success()
            && stdout.contains("Transport:")
            && !stdout.contains("User:      (none)")
            && !stdout.contains("Peer:      (none)")
        {
            return;
        }
        if start.elapsed() >= timeout {
            panic!(
                "identity did not materialize within {}ms for {}:\nstdout:\n{}\nstderr:\n{}",
                timeout_ms,
                db_path,
                stdout,
                String::from_utf8_lossy(&identity.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn assert_eventually_users_include(db_path: &str, expected_users: &[&str], timeout_ms: u64) {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    loop {
        let users = get_users_raw(db_path);
        if expected_users
            .iter()
            .all(|username| users.contains(username))
        {
            return;
        }
        if start.elapsed() >= timeout {
            panic!(
                "users did not converge within {}ms for {}: expected {:?}, got:\n{}",
                timeout_ms, db_path, expected_users, users
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn assert_peers_eventually_include(
    db_path: &str,
    username: &str,
    expected_fragments: &[&str],
    timeout_ms: u64,
) {
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    loop {
        use_tenant_for_username(db_path, username);
        let peers = get_peers_raw(db_path);
        if expected_fragments
            .iter()
            .all(|fragment| peers.contains(fragment))
        {
            return;
        }
        if start.elapsed() >= timeout {
            panic!(
                "peers output did not converge within {}ms for {} as {}: expected {:?}, got:\n{}",
                timeout_ms, db_path, username, expected_fragments, peers
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn assert_peers_do_not_include(db_path: &str, username: &str, forbidden_fragments: &[&str]) {
    use_tenant_for_username(db_path, username);
    let peers = get_peers_raw(db_path);
    for fragment in forbidden_fragments {
        assert!(
            !peers.contains(fragment),
            "peers output for {} as {} should not contain {:?}:\n{}",
            db_path,
            username,
            fragment,
            peers
        );
    }
}

fn assert_cli_state_for_username(
    db_path: &str,
    username: &str,
    expected_workspace_names: &[&str],
    expected_view_workspace_name: &str,
    expected_tenant_count: usize,
    expected_user_count: usize,
    expected_users: &[&str],
    expected_tenants: &[&str],
    expected_messages: &[&str],
) {
    use_tenant_for_username(db_path, username);
    let expected_peer_id = {
        let conn = open_connection(db_path).expect("open db");
        conn.query_row(
            "SELECT recorded_by
             FROM users
             WHERE username = ?1
             LIMIT 1",
            rusqlite::params![username],
            |row| row.get::<_, String>(0),
        )
        .expect("username should map to a tenant")
    };
    let active = topo_cmd(db_path, &["tenant", "active"]);
    assert!(
        active.status.success(),
        "tenant active failed after tenant use: {}",
        String::from_utf8_lossy(&active.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&active.stdout).trim(),
        expected_peer_id,
        "active tenant should match username {:?}",
        username
    );
    assert_cli_state(
        db_path,
        expected_workspace_names,
        expected_view_workspace_name,
        expected_tenant_count,
        expected_user_count,
        expected_users,
        expected_tenants,
        expected_messages,
    );
}

/// Functional sync test using invite-based shared workspace flow.
/// Alice bootstraps identity, creates invite, starts daemon.
/// Bob accepts invite (bootstrap sync), starts daemon with invite-seeded autodial.
/// Both send messages in the shared workspace.
#[test]
fn test_cli_bidirectional_sync() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;

    // Alice creates workspace (identity chain)
    create_workspace(&alice_db);

    // Alice starts daemon (auto-selects single peer)
    let _alice = start_daemon(&alice_db);

    // Alice sends messages via daemon RPC
    send_message(&alice_db, "Hello from Alice");
    let alice_eid = send_message(&alice_db, "How are you?");

    // Alice creates invite (via daemon RPC)
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite (bootstrap sync from Alice)
    accept_invite(&bob_db, &invite_link);

    // Bob starts daemon; invite-seeded autodial reaches Alice.
    let _bob = start_daemon(&bob_db);
    std::thread::sleep(Duration::from_secs(1));

    // Bob sends a message in the shared workspace
    let bob_eid = send_message(&bob_db, "Hey Alice!");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_eid),
        timeout_ms,
    );
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", alice_eid),
        timeout_ms,
    );

    // Verify specific message content arrived on both sides
    let alice_msgs = get_messages(&alice_db);
    assert!(
        alice_msgs.len() >= 3,
        "Alice should see at least 3 messages, got {}",
        alice_msgs.len()
    );
    assert!(alice_msgs.contains(&"Hello from Alice".to_string()));
    assert!(alice_msgs.contains(&"How are you?".to_string()));
    assert!(alice_msgs.contains(&"Hey Alice!".to_string()));

    let bob_msgs = get_messages(&bob_db);
    assert!(
        bob_msgs.len() >= 3,
        "Bob should see at least 3 messages, got {}",
        bob_msgs.len()
    );
    assert!(bob_msgs.contains(&"Hello from Alice".to_string()));
    assert!(bob_msgs.contains(&"How are you?".to_string()));
    assert!(bob_msgs.contains(&"Hey Alice!".to_string()));
}

/// Functional sync test using invite-based flow.
/// Verifies sync picks up new messages over time (ongoing sync).
#[test]
fn test_cli_ongoing_sync() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    // Alice sends bootstrap message
    let _bootstrap_eid = send_message(&alice_db, "bootstrap");
    assert_now(&alice_db, "message_count >= 1");

    // Alice creates invite
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite and starts daemon
    accept_invite(&bob_db, &invite_link);
    let _bob = start_daemon(&bob_db);
    // Explicit bootstrap readiness gate: avoid racing ongoing-sync assertions
    // before the invite/bootstrap prerequisite sync has converged.
    assert_eventually(&bob_db, "message_count >= 1", timeout_ms);

    // Both send messages over time
    send_message(&alice_db, "Round 1");
    send_message(&bob_db, "Round 2");
    send_message(&alice_db, "Round 3a");
    let bob_last_eid = send_message(&bob_db, "Round 3b");
    std::thread::sleep(Duration::from_secs(1));
    let alice_last_eid = send_message(&alice_db, "Round 4");

    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_last_eid),
        timeout_ms,
    );
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", alice_last_eid),
        timeout_ms,
    );
}

#[test]
fn test_cli_reconnects_after_bootstrap_supersession_using_observed_endpoint() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;
    let alice_port = random_port();

    create_workspace(&alice_db);
    let mut alice_daemon = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            bind_port: Some(alice_port),
            disable_discovery: true,
            ..Default::default()
        },
    );
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));

    accept_invite(&bob_db, &invite_link);
    let mut bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    );

    let steady_state_eid = send_message(&alice_db, "steady-state before reconnect");
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", steady_state_eid),
        timeout_ms,
    );

    let alice_transport_peer_id = daemon_transport_fingerprint(&alice_db);
    wait_for_bootstrap_supersession_and_endpoint_observation(
        &bob_db,
        &alice_transport_peer_id,
        Duration::from_secs(15),
    );

    stop_daemon(&bob_db, &mut bob_daemon);

    let after_restart_eid = send_message(&alice_db, "delta after bob restart");
    bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    );

    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", after_restart_eid),
        timeout_ms,
    );

    stop_daemon(&bob_db, &mut bob_daemon);
    stop_daemon(&alice_db, &mut alice_daemon);
}

#[test]
fn test_cli_lowmem_receiver_restart_catches_offline_delta_and_resumes_sync() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;
    let alice_port = random_port();

    create_workspace(&alice_db);
    let mut alice_daemon = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            bind_port: Some(alice_port),
            disable_discovery: true,
            ..Default::default()
        },
    );
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));

    accept_invite(&bob_db, &invite_link);
    let mut bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    );

    generate_messages(&alice_db, 2_000);
    assert_eventually(&bob_db, "message_count >= 2000", timeout_ms);

    let alice_transport_peer_id = daemon_transport_fingerprint(&alice_db);
    wait_for_bootstrap_supersession_and_endpoint_observation(
        &bob_db,
        &alice_transport_peer_id,
        Duration::from_secs(15),
    );

    stop_daemon(&bob_db, &mut bob_daemon);

    generate_messages(&alice_db, 200);
    let offline_delta_eid = send_message(&alice_db, "delta after bob lowmem restart");

    bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            disable_discovery: true,
            extra_env: vec![
                ("LOW_MEM_IOS".to_string(), "1".to_string()),
                ("LOW_MEM_WAL_CAP_MIB".to_string(), "12".to_string()),
            ],
            ..Default::default()
        },
    );

    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", offline_delta_eid),
        timeout_ms,
    );
    assert_eventually(&bob_db, "message_count >= 2201", timeout_ms);

    let steady_state_eid = send_message(&bob_db, "steady after bob lowmem catch-up");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", steady_state_eid),
        timeout_ms,
    );

    stop_daemon(&bob_db, &mut bob_daemon);
    stop_daemon(&alice_db, &mut alice_daemon);
}

/// Two separate local daemons should discover and sync on the same machine
/// even when the invite carries no bootstrap addresses.
#[test]
#[cfg(feature = "discovery")]
fn test_cli_local_mdns_discovery_without_bootstrap_addresses() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    let _bootstrap_eid = send_message(&alice_db, "bootstrap");
    assert_now(&alice_db, "message_count >= 1");

    // Alice creates invite while daemon is running, then rewrites it to carry
    // no bootstrap endpoints so Bob must recover via mDNS.
    let invite_link = rewrite_invite_addrs(
        &create_invite(&alice_db, &daemon_listen_addr(&alice_db)),
        &[],
    );
    assert!(
        parse_invite_link(&invite_link)
            .expect("parse empty-address invite")
            .bootstrap_addrs
            .is_empty(),
        "invite should carry no bootstrap addresses"
    );

    // Bob accepts invite and starts daemon normally. With no bootstrap
    // addresses persisted, runtime recovery must come from mDNS only.
    accept_invite(&bob_db, &invite_link);
    let _bob = start_daemon(&bob_db);
    assert_eventually(&bob_db, "message_count >= 1", timeout_ms);
    assert_identity_eventually_materialized(&bob_db, timeout_ms);

    // Validate bidirectional convergence using messages created after both
    // daemons are running (avoids counting accept-time artifacts).
    let alice_live_eid = send_message(&alice_db, "alice-via-mdns-empty-bootstrap");
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", alice_live_eid),
        timeout_ms,
    );

    let bob_msg_eid = send_message(&bob_db, "bob-via-mdns-empty-bootstrap");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_msg_eid),
        timeout_ms,
    );
}

/// A rewritten invite with only wrong bootstrap addresses should still recover
/// via mDNS once both daemons are running.
#[test]
#[cfg(feature = "discovery")]
fn test_cli_local_mdns_discovery_with_wrong_bootstrap_address_only() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);
    let _bootstrap_eid = send_message(&alice_db, "bootstrap");
    assert_now(&alice_db, "message_count >= 1");

    let wrong_addr = format!("127.0.0.1:{}", random_port());
    let invite_link = rewrite_invite_addrs(
        &create_invite(&alice_db, &daemon_listen_addr(&alice_db)),
        &[&wrong_addr],
    );
    assert_eq!(
        parse_invite_link(&invite_link)
            .expect("parse wrong-address invite")
            .bootstrap_addr_strings(),
        vec![wrong_addr.clone()],
        "invite should carry only the wrong bootstrap address"
    );

    accept_invite_with_identity_and_timeout(
        &bob_db,
        &invite_link,
        "bob",
        "bob-box",
        Duration::from_secs(2),
    );
    let _bob = start_daemon(&bob_db);
    assert_eventually(&bob_db, "message_count >= 1", timeout_ms);
    assert_identity_eventually_materialized(&bob_db, timeout_ms);

    let alice_live_eid = send_message(&alice_db, "alice-via-mdns-wrong-bootstrap");
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", alice_live_eid),
        timeout_ms,
    );

    let bob_live_eid = send_message(&bob_db, "bob-via-mdns-wrong-bootstrap");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_live_eid),
        timeout_ms,
    );
}

#[test]
fn test_cli_send_and_messages() {
    let _guard = cli_test_lock();
    // Basic test: create workspace, start daemon, send/messages work
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("test.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let _first_eid = send_message(&db, "First message");
    let second_eid = send_message(&db, "Second message");

    assert_now(&db, "message_count == 2");
    assert_now(&db, &format!("has_event:{} >= 1", second_eid));

    let messages = get_messages(&db);
    assert_eq!(messages.len(), 2);
    assert!(messages.contains(&"First message".to_string()));
    assert!(messages.contains(&"Second message".to_string()));
}

#[test]
fn test_cli_selected_partial_join_tenant_reports_initial_sync_errors() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    create_workspace(&bob_db);

    let alice = Peer::new_with_identity("alice-partial-source");
    let unreachable_bootstrap = format!("127.0.0.1:{}", random_port());
    let invite_link = create_user_invite_link_for_test_peer(&alice, &unreachable_bootstrap);
    let partial_join = accept_invite_without_sync(&bob_db, &invite_link, "bob-join", "pending")
        .expect("accept invite without bootstrap sync");
    let partial_tenant_index = tenant_index_for_peer_id(&bob_db, &partial_join.peer_id);

    let _daemon = start_daemon(&bob_db);

    let select = topo_cmd(
        &bob_db,
        &["tenant", "use", &partial_tenant_index.to_string()],
    );
    assert!(
        select.status.success(),
        "tenant use failed: stdout={} stderr={}",
        String::from_utf8_lossy(&select.stdout),
        String::from_utf8_lossy(&select.stderr)
    );

    let active = topo_cmd(&bob_db, &["tenant", "active"]);
    assert!(active.status.success(), "tenant active failed");
    assert_eq!(
        String::from_utf8_lossy(&active.stdout).trim(),
        partial_join.peer_id,
        "active tenant should match the selected partial-join peer"
    );

    let identity = topo_cmd(&bob_db, &["identity"]);
    assert!(
        identity.status.success(),
        "identity should still succeed on a partial join tenant: stdout={} stderr={}",
        String::from_utf8_lossy(&identity.stdout),
        String::from_utf8_lossy(&identity.stderr)
    );
    let identity_stdout = String::from_utf8_lossy(&identity.stdout);
    assert!(
        identity_stdout.contains("Transport:"),
        "identity output should include transport fingerprint: {}",
        identity_stdout
    );
    assert!(
        identity_stdout.contains("User:      (none)"),
        "identity should show that user identity is not projected yet: {}",
        identity_stdout
    );

    let send = topo_cmd(&bob_db, &["send", "still-waiting"]);
    assert!(
        !send.status.success(),
        "send should fail for a tenant whose initial sync has not completed"
    );
    let send_stderr = String::from_utf8_lossy(&send.stderr);
    assert!(
        send_stderr.contains("workspace has not completed initial sync yet"),
        "send should explain the partial-join state: {}",
        send_stderr
    );

    let invite = topo_cmd(
        &bob_db,
        &["invite", "--public-addr", &unreachable_bootstrap],
    );
    assert!(
        !invite.status.success(),
        "invite should fail for a tenant whose initial sync has not completed"
    );
    let invite_stderr = String::from_utf8_lossy(&invite.stderr);
    assert!(
        invite_stderr.contains("workspace has not completed initial sync yet"),
        "invite should explain the partial-join state: {}",
        invite_stderr
    );

    let link = topo_cmd(&bob_db, &["link", "--public-addr", &unreachable_bootstrap]);
    assert!(
        !link.status.success(),
        "device-link invite should fail for a tenant whose initial sync has not completed"
    );
    let link_stderr = String::from_utf8_lossy(&link.stderr);
    assert!(
        link_stderr.contains("workspace has not completed initial sync yet"),
        "device-link invite should explain the partial-join state: {}",
        link_stderr
    );
}

/// TRUST POLICY TEST: untrusted peer is rejected.
/// Alice bootstraps identity (PeerShared self-trust makes has_any_trusted_peer true).
/// Bob has independent identity (not in Alice's workspace). Alice should reject Bob.
#[test]
fn test_cli_untrusted_peer_rejected() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    // Alice sends a message
    send_message(&alice_db, "alice bootstrap");

    // Bob creates independent workspace (not in Alice's workspace)
    create_workspace(&bob_db);
    let _bob = start_daemon(&bob_db);

    // Bob sends a message
    let bob_eid = send_message(&bob_db, "Should not arrive");
    // Give some time for sync to try
    std::thread::sleep(Duration::from_secs(3));

    assert_now(&alice_db, &format!("has_event:{} == 0", bob_eid));
}

/// E2E file sync test: Alice sends a file, Bob receives all slices, saves to disk.
#[test]
fn test_cli_file_upload_sync_and_save() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;

    // Create a test file with known content
    let test_file = tmpdir.path().join("testfile.txt");
    let test_content = "Hello from the file system! This is a test file for e2e sync.\n";
    std::fs::write(&test_file, test_content).unwrap();

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    // Alice sends the file
    let file_eid = send_file(
        &alice_db,
        "Check out this file",
        test_file.to_str().unwrap(),
    );
    assert!(!file_eid.is_empty(), "send-file should return event_id");

    // Alice creates invite
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite and starts daemon
    accept_invite(&bob_db, &invite_link);
    let _bob = start_daemon(&bob_db);

    let sync_log_cfg = topo_cmd(&bob_db, &["sync-log", "config"]);
    assert!(
        sync_log_cfg.status.success(),
        "sync-log config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&sync_log_cfg.stdout),
        String::from_utf8_lossy(&sync_log_cfg.stderr)
    );
    assert!(
        String::from_utf8_lossy(&sync_log_cfg.stdout).contains("enabled=false"),
        "sync-log should remain disabled by default, got: {}",
        String::from_utf8_lossy(&sync_log_cfg.stdout)
    );

    // Wait for Bob to receive Alice's message event
    assert_eventually(&bob_db, &format!("has_event:{} >= 1", file_eid), timeout_ms);

    // Wait for message projection and attachment completion
    assert_eventually(&bob_db, "message_count >= 1", timeout_ms);

    // Poll until Bob shows the attachment with checkmark (all slices projected)
    let start = std::time::Instant::now();
    loop {
        let raw = get_messages_raw(&bob_db);
        if raw.contains("\u{2714}") {
            break;
        }
        if start.elapsed().as_secs() >= 30 {
            panic!(
                "Bob's file attachment never completed (no checkmark in messages output):\n{}",
                raw
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    // Save the file to disk
    let saved_path = tmpdir.path().join("received_file.txt");
    let out = save_file(&bob_db, "1", saved_path.to_str().unwrap());
    assert!(
        out.status.success(),
        "save-file failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("saved") && stdout.contains("bytes"),
        "save-file output should confirm bytes written, got: {}",
        stdout
    );

    // Verify saved content matches original
    let saved_content = std::fs::read_to_string(&saved_path).unwrap();
    assert_eq!(
        saved_content, test_content,
        "saved file content should match original"
    );
}

/// Daemon start on an empty DB should keep control plane up in IdleNoTenants state.
#[test]
fn test_cli_start_without_trust_starts_idle_runtime() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("no_trust.db")
        .to_str()
        .unwrap()
        .to_string();
    let socket = socket_path_for_db(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .arg("start")
            .arg("--bind")
            .arg(format!("127.0.0.1:{}", random_port()))
            .arg("--db")
            .arg(&db)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to run start"),
    );

    let start = Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(socket.exists(), "daemon socket did not appear");

    let status = Command::new(bin())
        .args(["--db", &db, "status"])
        .output()
        .expect("status command");
    assert!(
        status.status.success(),
        "status should succeed on empty-db daemon: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("Runtime:   IdleNoTenants"),
        "status should show idle runtime state, got: {}",
        stdout
    );

    let stop = Command::new(bin())
        .args(["--db", &db, "stop"])
        .output()
        .expect("stop command");
    assert!(stop.status.success(), "stop should succeed");
}

/// Bootstrap trust test using production invite / accept CLI flow.
/// No direct SQL trust seeding — trust is materialized through CLI commands.
///
/// Projection-first flow: accept creates identity chain (events may
/// block pending prerequisites). The daemon's ongoing peering loop delivers
/// the required events from Alice via bootstrap autodial, cascading the
/// identity chain to completion.
#[test]
fn test_cli_sync_bootstrap_from_accepted_invite_data() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir
        .path()
        .join("alice_bootstrap.db")
        .to_str()
        .unwrap()
        .to_string();
    let bob_db = tmpdir
        .path()
        .join("bob_bootstrap.db")
        .to_str()
        .unwrap()
        .to_string();
    let timeout_ms = 15000;

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    // Alice sends bootstrap message
    send_message(&alice_db, "bootstrap");

    // Alice creates invite (via daemon RPC)
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Alice should have emitted content key wrapping during invite creation
    assert!(
        count_rows(&alice_db, "key_shared") >= 1,
        "inviter should emit at least one key_shared key-wrap during invite creation"
    );

    // Bob accepts invite: installs deterministic cert, creates identity chain
    // (events may block pending sync of prerequisite events from Alice).
    accept_invite(&bob_db, &invite_link);

    // Bob starts daemon; invite bootstrap trust seeds daemon autodial.
    // Autodial connects to Alice, syncs prerequisite events, identity chain
    // cascades to completion, and messages project.
    let _bob = start_daemon(&bob_db);

    // Wait for Bob's identity chain to complete (message_count >= 1 means
    // Alice's "bootstrap" message has been fully projected on Bob's side,
    // which requires the full identity chain cascade).
    assert_eventually(&bob_db, "message_count >= 1", timeout_ms);

    // After sync, Bob should have Alice's key_shared event (content key ciphertext).
    // Note: deferred content key unwrapping (key_shared → key_secrets) is a
    // follow-up feature for the projection-first flow. The old inline bootstrap
    // sync performed this unwrap immediately, but the daemon-driven cascade
    // doesn't yet trigger it automatically.
    assert!(
        count_rows(&bob_db, "key_shared") >= 1,
        "invitee should have inviter's key_shared event after sync"
    );

    let bob_eid = send_message(&bob_db, "bootstrap trust from invite data");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_eid),
        timeout_ms,
    );
}

/// Induction-style CLI test for a single multi-use user invite.
/// Base case: Alice alone is healthy. Step case: if N peers are converged,
/// reusing the same invite for the N+1th peer should preserve healthy CLI
/// state for everyone.
#[test]
fn test_cli_multi_use_user_invite_reuse_induction_n_to_n_plus_one() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 30000;
    let workspace_name = "reuse-user-induction";

    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    create_workspace_with_details(&alice_db, workspace_name, "alice", "alice-root");
    let alice = StartedCliPeer {
        db: alice_db,
        username: "alice".to_string(),
        device_name: "alice-root".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("alice.db")
                .to_str()
                .expect("alice db path"),
        ),
    };
    let alice_tenant = alice.tenant_label();

    let reused_invite = create_invite(&alice.db, &daemon_listen_addr(&alice.db));
    let alice_base = "reuse-user/alice-step-1";
    let alice_base_eid = send_message(&alice.db, alice_base);
    assert_event_visible_on_all(&[&alice.db], &alice_base_eid, timeout_ms);
    assert_cli_state(
        &alice.db,
        &[workspace_name],
        workspace_name,
        1,
        1,
        &["alice"],
        &[&alice_tenant],
        &[alice_base],
    );

    let bob = start_joined_cli_peer(&tmpdir, "bob.db", &reused_invite, "bob", "bob-box");
    let bob_tenant = bob.tenant_label();
    assert_eventually(&bob.db, "message_count >= 1", timeout_ms);
    let bob_msg = "reuse-user/bob-step-2";
    let bob_eid = send_message(&bob.db, bob_msg);
    assert_event_visible_on_all(&[&alice.db, &bob.db], &bob_eid, timeout_ms);
    for db in [&alice.db, &bob.db] {
        assert_cli_state(
            db,
            &[workspace_name],
            workspace_name,
            1,
            2,
            &["alice", "bob"],
            &[&alice_tenant, &bob_tenant],
            &[alice_base, bob_msg],
        );
    }

    let carol = start_joined_cli_peer(&tmpdir, "carol.db", &reused_invite, "carol", "carol-box");
    let carol_tenant = carol.tenant_label();
    assert_eventually(&carol.db, "message_count >= 2", timeout_ms);
    let carol_msg = "reuse-user/carol-step-3";
    let carol_eid = send_message(&carol.db, carol_msg);
    assert_event_visible_on_all(&[&alice.db, &bob.db, &carol.db], &carol_eid, timeout_ms);
    for db in [&alice.db, &bob.db, &carol.db] {
        assert_cli_state(
            db,
            &[workspace_name],
            workspace_name,
            1,
            3,
            &["alice", "bob", "carol"],
            &[&alice_tenant, &bob_tenant, &carol_tenant],
            &[alice_base, bob_msg, carol_msg],
        );
    }

    let dave = start_joined_cli_peer(&tmpdir, "dave.db", &reused_invite, "dave", "dave-box");
    let dave_tenant = dave.tenant_label();
    assert_eventually(&dave.db, "message_count >= 3", timeout_ms);
    let dave_msg = "reuse-user/dave-step-4";
    let dave_eid = send_message(&dave.db, dave_msg);
    assert_event_visible_on_all(
        &[&alice.db, &bob.db, &carol.db, &dave.db],
        &dave_eid,
        timeout_ms,
    );
    for db in [&alice.db, &bob.db, &carol.db, &dave.db] {
        assert_cli_state(
            db,
            &[workspace_name],
            workspace_name,
            1,
            4,
            &["alice", "bob", "carol", "dave"],
            &[&alice_tenant, &bob_tenant, &carol_tenant, &dave_tenant],
            &[alice_base, bob_msg, carol_msg, dave_msg],
        );
    }
}

/// Live-daemon regression: a reused invite joiner can start on the invite-derived
/// bootstrap transport identity and must transition to the final PeerShared
/// transport identity without requiring a manual `topo stop` / `topo start`.
#[test]
fn test_cli_reused_invite_live_daemon_reloads_bootstrap_transport_identity() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 45000;
    let workspace_name = "reuse-live-reload";

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

    create_workspace_with_details(&alice_db, workspace_name, "alice", "alice-root");
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
    let bootstrap_peer_id = invite_bootstrap_peer_id(&reused_invite);

    let alice_msg = "reuse-live/alice-base";
    let alice_eid = send_message(&alice_db, alice_msg);
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

    let bob_tenant = "bob/bob-box".to_string();
    let alice_tenant = "alice/alice-root".to_string();

    let carol_join = accept_invite_without_sync(&carol_db, &reused_invite, "carol", "carol-box")
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

    wait_for_transport_cred_source(
        &carol_db,
        &carol_join.peer_id,
        topo::db::transport_creds::CRED_SOURCE_PEER_SHARED,
        timeout_ms,
    );

    let bob_peer_id = peer_id_for_username(&bob_db, "bob");
    let carol_addr: SocketAddr = daemon_listen_addr(&carol_db)
        .parse()
        .expect("carol listen addr");
    wait_for_direct_trust_dial(
        &bob_db,
        &bob_peer_id,
        carol_addr,
        &carol_join.peer_id,
        timeout_ms,
    );

    let carol_msg = "reuse-live/carol-final";
    let carol_eid = send_message(&carol_db, carol_msg);
    assert_event_visible_on_all(&[&alice_db, &bob_db, &carol_db], &carol_eid, timeout_ms);

    for db in [&alice_db, &bob_db, &carol_db] {
        assert_cli_state(
            db,
            &[workspace_name],
            workspace_name,
            1,
            3,
            &["alice", "bob", "carol"],
            &[&alice_tenant, &bob_tenant, "carol/carol-box"],
            &[alice_msg, carol_msg],
        );
    }

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
        count_occurrences(&bob_log_text, "Certificate mismatch connecting to") <= 1,
        "bob daemon log should suppress repeated outbound trust mismatch warnings:\n{}",
        bob_log_text
    );
    assert!(
        count_occurrences(&bob_log_text, "Rejected incoming connection:") <= 1,
        "bob daemon log should suppress repeated inbound trust mismatch warnings:\n{}",
        bob_log_text
    );
    assert!(
        count_occurrences(&carol_log_text, "Certificate mismatch connecting to") <= 1,
        "carol daemon log should suppress repeated outbound trust mismatch warnings:\n{}",
        carol_log_text
    );
    assert!(
        count_occurrences(&carol_log_text, "Rejected incoming connection:") <= 1,
        "carol daemon log should suppress repeated inbound trust mismatch warnings:\n{}",
        carol_log_text
    );
}

/// Mixed old-invite reuse and fresh invite creation for users.
/// The old invite keeps working as the workspace grows and new invites are issued.
#[test]
fn test_cli_multi_use_user_invites_mix_reuse_and_new_creation() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 30000;
    let workspace_name = "mixed-user-invites";

    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    create_workspace_with_details(&alice_db, workspace_name, "alice", "alice-mac");
    let alice = StartedCliPeer {
        db: alice_db,
        username: "alice".to_string(),
        device_name: "alice-mac".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("alice.db")
                .to_str()
                .expect("alice db path"),
        ),
    };
    let alice_tenant = alice.tenant_label();

    let old_invite = create_invite(&alice.db, &daemon_listen_addr(&alice.db));
    let alice_base = "mixed-user/alice-step-1";
    let alice_base_eid = send_message(&alice.db, alice_base);
    assert_event_visible_on_all(&[&alice.db], &alice_base_eid, timeout_ms);

    let bob = start_joined_cli_peer(&tmpdir, "bob.db", &old_invite, "bob", "bob-linux");
    let bob_tenant = bob.tenant_label();
    assert_eventually(&bob.db, "message_count >= 1", timeout_ms);
    let bob_msg = "mixed-user/bob-step-2";
    let bob_eid = send_message(&bob.db, bob_msg);
    assert_event_visible_on_all(&[&alice.db, &bob.db], &bob_eid, timeout_ms);

    let fresh_invite = create_invite(&alice.db, &daemon_listen_addr(&alice.db));
    let carol = start_joined_cli_peer(&tmpdir, "carol.db", &fresh_invite, "carol", "carol-linux");
    let carol_tenant = carol.tenant_label();
    assert_eventually(&carol.db, "message_count >= 2", timeout_ms);
    let carol_msg = "mixed-user/carol-step-3";
    let carol_eid = send_message(&carol.db, carol_msg);
    assert_event_visible_on_all(&[&alice.db, &bob.db, &carol.db], &carol_eid, timeout_ms);

    let dave = start_joined_cli_peer(&tmpdir, "dave.db", &old_invite, "dave", "dave-linux");
    let dave_tenant = dave.tenant_label();
    assert_eventually(&dave.db, "message_count >= 3", timeout_ms);
    let dave_msg = "mixed-user/dave-step-4";
    let dave_eid = send_message(&dave.db, dave_msg);
    assert_event_visible_on_all(
        &[&alice.db, &bob.db, &carol.db, &dave.db],
        &dave_eid,
        timeout_ms,
    );

    for db in [&alice.db, &bob.db, &carol.db, &dave.db] {
        assert_cli_state(
            db,
            &[workspace_name],
            workspace_name,
            1,
            4,
            &["alice", "bob", "carol", "dave"],
            &[&alice_tenant, &bob_tenant, &carol_tenant, &dave_tenant],
            &[alice_base, bob_msg, carol_msg, dave_msg],
        );
    }
}

/// Device-link induction with both fresh link creation and old-link reuse.
/// A linked device issues the fresh link, and the original link still works
/// later for another device.
#[test]
fn test_cli_multi_use_device_links_mix_reuse_and_new_creation() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 45000;
    let workspace_name = "device-link-induction";

    let phone_db = tmpdir.path().join("phone.db").to_str().unwrap().to_string();
    create_workspace_with_details(&phone_db, workspace_name, "alice", "phone");
    let phone = StartedCliPeer {
        db: phone_db,
        username: "alice".to_string(),
        device_name: "phone".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("phone.db")
                .to_str()
                .expect("phone db path"),
        ),
    };
    let phone_tenant = phone.tenant_label();

    let link_a = create_device_link(&phone.db, &daemon_listen_addr(&phone.db));
    let phone_base = "device-link/phone-step-1";
    let phone_base_eid = send_message(&phone.db, phone_base);
    assert_event_visible_on_all(&[&phone.db], &phone_base_eid, timeout_ms);

    let laptop = start_linked_cli_peer(&tmpdir, "laptop.db", &link_a, "alice", "laptop");
    let laptop_tenant = laptop.tenant_label();
    assert_eventually(&laptop.db, "message_count >= 1", timeout_ms);
    let laptop_msg = "device-link/laptop-step-2";
    let laptop_eid = send_message(&laptop.db, laptop_msg);
    assert_event_visible_on_all(&[&phone.db, &laptop.db], &laptop_eid, timeout_ms);

    let link_b = create_device_link(&laptop.db, &daemon_listen_addr(&laptop.db));
    let tablet = start_linked_cli_peer(&tmpdir, "tablet.db", &link_b, "alice", "tablet");
    let tablet_tenant = tablet.tenant_label();
    assert_eventually(&tablet.db, "message_count >= 2", timeout_ms);
    let tablet_msg = "device-link/tablet-step-3";
    let tablet_eid = send_message(&tablet.db, tablet_msg);
    assert_event_visible_on_all(
        &[&phone.db, &laptop.db, &tablet.db],
        &tablet_eid,
        timeout_ms,
    );

    let desktop = start_linked_cli_peer(&tmpdir, "desktop.db", &link_a, "alice", "desktop");
    let desktop_tenant = desktop.tenant_label();
    assert_eventually(&desktop.db, "message_count >= 3", timeout_ms);
    let desktop_msg = "device-link/desktop-step-4";
    let desktop_eid = send_message(&desktop.db, desktop_msg);
    assert_event_visible_on_all(
        &[&phone.db, &laptop.db, &tablet.db, &desktop.db],
        &desktop_eid,
        timeout_ms,
    );

    for db in [&phone.db, &laptop.db, &tablet.db, &desktop.db] {
        assert_cli_state(
            db,
            &[workspace_name],
            workspace_name,
            1,
            1,
            &["alice"],
            &[
                &phone_tenant,
                &laptop_tenant,
                &tablet_tenant,
                &desktop_tenant,
            ],
            &[phone_base, laptop_msg, tablet_msg, desktop_msg],
        );
    }
}

/// Device-link flow should tolerate mixed topology bootstraps:
/// one link with no addresses (mDNS only), one explicit dead-first/live-second
/// endpoint list, and one link with only wrong addresses.
#[test]
#[cfg(feature = "discovery")]
fn test_cli_device_link_mixed_topology_empty_explicit_and_wrong_only() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 45000;
    let workspace_name = "device-link-mixed-topology";

    let phone_db = tmpdir.path().join("phone.db").to_str().unwrap().to_string();
    create_workspace_with_details(&phone_db, workspace_name, "alice", "phone");
    let phone = StartedCliPeer {
        db: phone_db,
        username: "alice".to_string(),
        device_name: "phone".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("phone.db")
                .to_str()
                .expect("phone db path"),
        ),
    };
    let phone_tenant = phone.tenant_label();
    let phone_base = "device-link-mixed/phone-step-1";
    let phone_base_eid = send_message(&phone.db, phone_base);
    assert_event_visible_on_all(&[&phone.db], &phone_base_eid, timeout_ms);

    let empty_link = rewrite_invite_addrs(
        &create_device_link(&phone.db, &daemon_listen_addr(&phone.db)),
        &[],
    );
    assert!(
        parse_invite_link(&empty_link)
            .expect("parse empty device-link invite")
            .bootstrap_addrs
            .is_empty(),
        "empty device link should carry no bootstrap addresses"
    );

    let laptop_db = tmpdir
        .path()
        .join("laptop.db")
        .to_str()
        .unwrap()
        .to_string();
    accept_device_link_with_name_and_timeout(
        &laptop_db,
        &empty_link,
        "laptop",
        Duration::from_secs(2),
    );
    let laptop = StartedCliPeer {
        db: laptop_db,
        username: "alice".to_string(),
        device_name: "laptop".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("laptop.db")
                .to_str()
                .expect("laptop db path"),
        ),
    };
    let laptop_tenant = laptop.tenant_label();
    assert_eventually(&laptop.db, "message_count >= 1", timeout_ms);
    assert_identity_eventually_materialized(&laptop.db, timeout_ms);
    let laptop_msg = "device-link-mixed/laptop-step-2";
    let laptop_eid = send_message(&laptop.db, laptop_msg);
    assert_event_visible_on_all(&[&phone.db, &laptop.db], &laptop_eid, timeout_ms);

    let laptop_live_addr = daemon_listen_addr(&laptop.db);
    let laptop_live_port = laptop_live_addr
        .rsplit_once(':')
        .expect("laptop listen addr should contain port")
        .1
        .to_string();
    let explicit_link = rewrite_invite_addrs(
        &create_device_link(&laptop.db, &laptop_live_addr),
        &[
            &format!("127.0.0.1:{}", random_port()),
            &format!("localhost:{}", laptop_live_port),
        ],
    );

    let tablet = start_linked_cli_peer(&tmpdir, "tablet.db", &explicit_link, "alice", "tablet");
    let tablet_tenant = tablet.tenant_label();
    assert_eventually(&tablet.db, "message_count >= 2", timeout_ms);
    assert_identity_eventually_materialized(&tablet.db, timeout_ms);
    let tablet_msg = "device-link-mixed/tablet-step-3";
    let tablet_eid = send_message(&tablet.db, tablet_msg);
    assert_event_visible_on_all(
        &[&phone.db, &laptop.db, &tablet.db],
        &tablet_eid,
        timeout_ms,
    );

    let wrong_link = rewrite_invite_addrs(
        &create_device_link(&phone.db, &daemon_listen_addr(&phone.db)),
        &[&format!("127.0.0.1:{}", random_port())],
    );
    let desktop_db = tmpdir
        .path()
        .join("desktop.db")
        .to_str()
        .unwrap()
        .to_string();
    accept_device_link_with_name_and_timeout(
        &desktop_db,
        &wrong_link,
        "desktop",
        Duration::from_secs(2),
    );
    let desktop = StartedCliPeer {
        db: desktop_db,
        username: "alice".to_string(),
        device_name: "desktop".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("desktop.db")
                .to_str()
                .expect("desktop db path"),
        ),
    };
    let desktop_tenant = desktop.tenant_label();
    assert_eventually(&desktop.db, "message_count >= 3", timeout_ms);
    assert_identity_eventually_materialized(&desktop.db, timeout_ms);
    let desktop_msg = "device-link-mixed/desktop-step-4";
    let desktop_eid = send_message(&desktop.db, desktop_msg);
    assert_event_visible_on_all(
        &[&phone.db, &laptop.db, &tablet.db, &desktop.db],
        &desktop_eid,
        timeout_ms,
    );

    for db in [&phone.db, &laptop.db, &tablet.db, &desktop.db] {
        assert_cli_state(
            db,
            &[workspace_name],
            workspace_name,
            1,
            1,
            &["alice"],
            &[
                &phone_tenant,
                &laptop_tenant,
                &tablet_tenant,
                &desktop_tenant,
            ],
            &[phone_base, laptop_msg, tablet_msg, desktop_msg],
        );
    }
}

/// A rewritten invite with a dead first address and a live second address
/// should still converge to the correct CLI-visible state.
#[test]
fn test_cli_invite_with_dead_first_and_live_second_address() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 30000;
    let workspace_name = "dead-first-live-second";

    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    create_workspace_with_details(&alice_db, workspace_name, "alice", "edge-host");
    let alice = StartedCliPeer {
        db: alice_db,
        username: "alice".to_string(),
        device_name: "edge-host".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("alice.db")
                .to_str()
                .expect("alice db path"),
        ),
    };
    let alice_tenant = alice.tenant_label();

    let live_addr = daemon_listen_addr(&alice.db);
    let live_port = live_addr
        .rsplit_once(':')
        .expect("listen addr should contain port")
        .1
        .to_string();
    let rewritten_invite = rewrite_invite_addrs(
        &create_invite(&alice.db, &live_addr),
        &[
            &format!("127.0.0.1:{}", random_port()),
            &format!("localhost:{}", live_port),
        ],
    );

    let alice_base = "dead-first/alice-step-1";
    let alice_base_eid = send_message(&alice.db, alice_base);
    assert_event_visible_on_all(&[&alice.db], &alice_base_eid, timeout_ms);

    let bob = start_joined_cli_peer(&tmpdir, "bob.db", &rewritten_invite, "bob", "fallback-box");
    let bob_tenant = bob.tenant_label();
    assert_eventually(&bob.db, "message_count >= 1", timeout_ms);
    let bob_msg = "dead-first/bob-step-2";
    let bob_eid = send_message(&bob.db, bob_msg);
    assert_event_visible_on_all(&[&alice.db, &bob.db], &bob_eid, timeout_ms);

    for db in [&alice.db, &bob.db] {
        assert_cli_state(
            db,
            &[workspace_name],
            workspace_name,
            1,
            2,
            &["alice", "bob"],
            &[&alice_tenant, &bob_tenant],
            &[alice_base, bob_msg],
        );
    }
}

/// Multitenant + multiworkspace progression:
/// 1. one tenant in one workspace,
/// 2. then one tenant in each of two workspaces,
/// 3. then a reused old invite adds one more tenant to the first workspace.
#[test]
fn test_cli_multitenant_multiworkspace_induction_with_reuse() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 30000;

    let alpha_db = tmpdir.path().join("alpha.db").to_str().unwrap().to_string();
    let zeta_db = tmpdir.path().join("zeta.db").to_str().unwrap().to_string();
    let shared_db = tmpdir
        .path()
        .join("shared.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace_with_details(&alpha_db, "alpha-space", "alpha", "alpha-root");
    let alpha = StartedCliPeer {
        db: alpha_db,
        username: "alpha".to_string(),
        device_name: "alpha-root".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("alpha.db")
                .to_str()
                .expect("alpha db path"),
        ),
    };
    let alpha_tenant = alpha.tenant_label();
    let alpha_invite_reused = create_invite(&alpha.db, &daemon_listen_addr(&alpha.db));
    let alpha_base = "alpha-space/alpha-step-1";
    let alpha_base_eid = send_message(&alpha.db, alpha_base);
    assert_event_visible_on_all(&[&alpha.db], &alpha_base_eid, timeout_ms);

    create_workspace_with_details(&zeta_db, "zeta-space", "zeta", "zeta-root");
    let zeta = StartedCliPeer {
        db: zeta_db,
        username: "zeta".to_string(),
        device_name: "zeta-root".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("zeta.db")
                .to_str()
                .expect("zeta db path"),
        ),
    };
    let zeta_tenant = zeta.tenant_label();
    let zeta_invite_fresh = create_invite(&zeta.db, &daemon_listen_addr(&zeta.db));
    let zeta_base = "zeta-space/zeta-step-1";
    let zeta_base_eid = send_message(&zeta.db, zeta_base);
    assert_event_visible_on_all(&[&zeta.db], &zeta_base_eid, timeout_ms);

    accept_invite_with_identity(
        &shared_db,
        &alpha_invite_reused,
        "bob-alpha",
        "bob-terminal",
    );
    accept_invite_with_identity(&shared_db, &zeta_invite_fresh, "yuki-zeta", "yuki-terminal");
    accept_invite_with_identity(
        &shared_db,
        &alpha_invite_reused,
        "carol-alpha",
        "carol-terminal",
    );

    let _shared_daemon = start_daemon(&shared_db);
    assert_eventually_users_include(
        &alpha.db,
        &["alpha", "bob-alpha", "carol-alpha"],
        timeout_ms,
    );
    assert_eventually_users_include(&zeta.db, &["zeta", "yuki-zeta"], timeout_ms);
    let bob_alpha_tenant = "bob-alpha/bob-terminal";
    let bob_alpha_msg = send_message_as_username(&shared_db, "bob-alpha", "alpha-space/bob-step-2");
    let yuki_zeta_tenant = "yuki-zeta/yuki-terminal";
    let yuki_zeta_msg = send_message_as_username(&shared_db, "yuki-zeta", "zeta-space/yuki-step-2");
    let carol_alpha_tenant = "carol-alpha/carol-terminal";
    let carol_alpha_msg =
        send_message_as_username(&shared_db, "carol-alpha", "alpha-space/carol-step-3");
    assert_event_visible_on_all(&[&alpha.db], &bob_alpha_msg, timeout_ms);
    assert_event_visible_on_all(&[&zeta.db], &yuki_zeta_msg, timeout_ms);
    assert_event_visible_on_all(&[&alpha.db], &carol_alpha_msg, timeout_ms);

    assert_cli_state(
        &alpha.db,
        &["alpha-space"],
        "alpha-space",
        1,
        3,
        &["alpha", "bob-alpha", "carol-alpha"],
        &[&alpha_tenant, bob_alpha_tenant, carol_alpha_tenant],
        &[
            alpha_base,
            "alpha-space/bob-step-2",
            "alpha-space/carol-step-3",
        ],
    );
    assert_cli_state(
        &zeta.db,
        &["zeta-space"],
        "zeta-space",
        1,
        2,
        &["zeta", "yuki-zeta"],
        &[&zeta_tenant, yuki_zeta_tenant],
        &[zeta_base, "zeta-space/yuki-step-2"],
    );
    assert_cli_state_for_username(
        &shared_db,
        "bob-alpha",
        &["alpha-space", "zeta-space"],
        "alpha-space",
        3,
        3,
        &["alpha", "bob-alpha", "carol-alpha"],
        &[&alpha_tenant, bob_alpha_tenant, carol_alpha_tenant],
        &[
            alpha_base,
            "alpha-space/bob-step-2",
            "alpha-space/carol-step-3",
        ],
    );
    assert_cli_state_for_username(
        &shared_db,
        "yuki-zeta",
        &["alpha-space", "zeta-space"],
        "zeta-space",
        3,
        2,
        &["zeta", "yuki-zeta"],
        &[&zeta_tenant, yuki_zeta_tenant],
        &[zeta_base, "zeta-space/yuki-step-2"],
    );
    assert_cli_state_for_username(
        &shared_db,
        "carol-alpha",
        &["alpha-space", "zeta-space"],
        "alpha-space",
        3,
        3,
        &["alpha", "bob-alpha", "carol-alpha"],
        &[&alpha_tenant, bob_alpha_tenant, carol_alpha_tenant],
        &[
            alpha_base,
            "alpha-space/bob-step-2",
            "alpha-space/carol-step-3",
        ],
    );

    use_tenant_for_username(&shared_db, "yuki-zeta");
    let yuki_view = get_view_raw(&shared_db);
    assert!(
        !yuki_view.contains("alpha-space/bob-step-2")
            && !yuki_view.contains("alpha-space/carol-step-3"),
        "zeta tenant view should not leak alpha workspace messages:\n{}",
        yuki_view
    );
}

/// Live-daemon multitenant regression: accepting a second workspace on a
/// running daemon with an existing tenant must switch the active tenant to the
/// newly joined workspace so immediate sends land in the correct workspace.
#[test]
fn test_cli_live_daemon_accept_second_workspace_switches_active_tenant() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 30000;

    let home_db = tmpdir.path().join("home.db").to_str().unwrap().to_string();
    let zeta_db = tmpdir.path().join("zeta.db").to_str().unwrap().to_string();

    create_workspace_with_details(&home_db, "home-space", "home", "home-root");
    let mut home_daemon = start_daemon(&home_db);
    let home_tenant = "home/home-root".to_string();

    create_workspace_with_details(&zeta_db, "zeta-space", "zeta", "zeta-root");
    let mut zeta_daemon = start_daemon(&zeta_db);
    let zeta_tenant = "zeta/zeta-root".to_string();

    let zeta_bootstrap = "zeta-space/bootstrap";
    let zeta_bootstrap_eid = send_message(&zeta_db, zeta_bootstrap);
    assert_event_visible_on_all(&[&zeta_db], &zeta_bootstrap_eid, timeout_ms);

    let zeta_invite = create_invite(&zeta_db, &daemon_listen_addr(&zeta_db));
    let accept = Command::new(bin())
        .args([
            "accept",
            "--db",
            &home_db,
            &zeta_invite,
            "--username",
            "yuki-zeta",
            "--devicename",
            "yuki-terminal",
        ])
        .output()
        .unwrap();
    assert!(
        accept.status.success(),
        "accept failed: stdout={} stderr={}",
        String::from_utf8_lossy(&accept.stdout),
        String::from_utf8_lossy(&accept.stderr)
    );

    let yuki_peer_id = {
        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        loop {
            let conn = open_connection(&home_db).expect("open home db");
            let found = conn
                .query_row(
                    "SELECT recorded_by
                     FROM users
                     WHERE username = ?1
                     LIMIT 1",
                    rusqlite::params!["yuki-zeta"],
                    |row| row.get::<_, String>(0),
                )
                .ok();
            if let Some(peer_id) = found {
                break peer_id;
            }
            if start.elapsed() >= timeout {
                panic!(
                    "accepted tenant did not materialize within {}ms",
                    timeout_ms
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    };

    let active = topo_cmd(&home_db, &["tenant", "active"]);
    assert!(
        active.status.success(),
        "tenant active failed after accept: {}",
        String::from_utf8_lossy(&active.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&active.stdout).trim(),
        yuki_peer_id,
        "accepting a second workspace on a running daemon should switch the active tenant"
    );

    assert_event_visible_for_username(&home_db, "yuki-zeta", &zeta_bootstrap_eid, timeout_ms);

    let yuki_msg = "zeta-space/yuki-live";
    let yuki_eid = send_message(&home_db, yuki_msg);
    assert_event_visible_on_all(&[&zeta_db], &yuki_eid, timeout_ms);

    assert_cli_state_for_username(
        &home_db,
        "home",
        &["home-space", "zeta-space"],
        "home-space",
        2,
        1,
        &["home"],
        &[home_tenant.as_str()],
        &[],
    );
    assert_cli_state_for_username(
        &home_db,
        "yuki-zeta",
        &["home-space", "zeta-space"],
        "zeta-space",
        2,
        2,
        &["zeta", "yuki-zeta"],
        &[zeta_tenant.as_str(), "yuki-zeta/yuki-terminal"],
        &[zeta_bootstrap, yuki_msg],
    );
    assert_cli_state(
        &zeta_db,
        &["zeta-space"],
        "zeta-space",
        1,
        2,
        &["zeta", "yuki-zeta"],
        &[&zeta_tenant, "yuki-zeta/yuki-terminal"],
        &[zeta_bootstrap, yuki_msg],
    );

    stop_daemon(&home_db, &mut home_daemon);
    stop_daemon(&zeta_db, &mut zeta_daemon);
}

/// Live-daemon multitenant regression: creating a second workspace on a
/// running daemon must switch the active tenant to the new workspace so
/// follow-up sends do not stay pinned to the original tenant.
#[test]
fn test_cli_live_daemon_create_second_workspace_switches_active_tenant() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 30000;

    let db = tmpdir.path().join("multi.db").to_str().unwrap().to_string();
    create_workspace_with_details(&db, "home-space", "home", "home-root");
    let mut daemon = start_daemon(&db);

    let home_tenant = "home/home-root".to_string();
    let home_bootstrap = "home-space/bootstrap";
    let home_bootstrap_eid = send_message(&db, home_bootstrap);
    assert_event_visible_on_all(&[&db], &home_bootstrap_eid, timeout_ms);

    let create = Command::new(bin())
        .args([
            "create-workspace",
            "--db",
            &db,
            "--workspace-name",
            "zeta-space",
            "--username",
            "zeta",
            "--device-name",
            "zeta-root",
        ])
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "create-workspace failed: stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let zeta_peer_id = {
        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        loop {
            let conn = open_connection(&db).expect("open multi db");
            let found = conn
                .query_row(
                    "SELECT recorded_by
                     FROM users
                     WHERE username = ?1
                     LIMIT 1",
                    rusqlite::params!["zeta"],
                    |row| row.get::<_, String>(0),
                )
                .ok();
            if let Some(peer_id) = found {
                break peer_id;
            }
            if start.elapsed() >= timeout {
                panic!(
                    "new workspace tenant did not materialize within {}ms",
                    timeout_ms
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    };

    let active = topo_cmd(&db, &["tenant", "active"]);
    assert!(
        active.status.success(),
        "tenant active failed after create-workspace: {}",
        String::from_utf8_lossy(&active.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&active.stdout).trim(),
        zeta_peer_id,
        "creating a second workspace on a running daemon should switch the active tenant"
    );

    let zeta_tenant = "zeta/zeta-root".to_string();
    let zeta_msg = "zeta-space/live-create";
    let zeta_eid = send_message(&db, zeta_msg);
    assert_event_visible_for_username(&db, "zeta", &zeta_eid, timeout_ms);

    assert_cli_state_for_username(
        &db,
        "home",
        &["home-space", "zeta-space"],
        "home-space",
        2,
        1,
        &["home"],
        &[home_tenant.as_str()],
        &[home_bootstrap],
    );
    assert_cli_state_for_username(
        &db,
        "zeta",
        &["home-space", "zeta-space"],
        "zeta-space",
        2,
        1,
        &["zeta"],
        &[zeta_tenant.as_str()],
        &[zeta_msg],
    );

    stop_daemon(&db, &mut daemon);
}

/// Live-daemon multitenant regression mirroring the reported user flow:
/// after creating a second workspace on a running daemon, inviting a new peer
/// into that workspace must support bidirectional ongoing sync in the second
/// workspace without leaking into the first workspace's view.
#[test]
fn test_cli_live_daemon_second_workspace_invite_syncs_bidirectionally() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 30000;

    let owner_db = tmpdir.path().join("owner.db").to_str().unwrap().to_string();
    let guest_db = tmpdir.path().join("guest.db").to_str().unwrap().to_string();

    create_workspace_with_details(&owner_db, "alpha-space", "alpha", "alpha-root");
    let mut owner_daemon = start_daemon(&owner_db);
    let alpha_tenant = "alpha/alpha-root".to_string();

    let create = Command::new(bin())
        .args([
            "create-workspace",
            "--db",
            &owner_db,
            "--workspace-name",
            "beta-space",
            "--username",
            "beta-owner",
            "--device-name",
            "beta-root",
        ])
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "create-workspace failed: stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let beta_tenant = "beta-owner/beta-root".to_string();
    let beta_bootstrap = "beta-space/bootstrap";
    let beta_bootstrap_eid = send_message(&owner_db, beta_bootstrap);
    let beta_invite = create_invite(&owner_db, &daemon_listen_addr(&owner_db));

    accept_invite_with_identity(&guest_db, &beta_invite, "guest-beta", "guest-laptop");
    let mut guest_daemon = start_daemon(&guest_db);

    assert_event_visible_on_all(&[&guest_db], &beta_bootstrap_eid, timeout_ms);

    let guest_msg = "beta-space/guest-reply";
    let guest_eid = send_message(&guest_db, guest_msg);
    assert_event_visible_for_username(&owner_db, "beta-owner", &guest_eid, timeout_ms);

    assert_cli_state_for_username(
        &owner_db,
        "alpha",
        &["alpha-space", "beta-space"],
        "alpha-space",
        2,
        1,
        &["alpha"],
        &[alpha_tenant.as_str()],
        &[],
    );
    assert_cli_state_for_username(
        &owner_db,
        "beta-owner",
        &["alpha-space", "beta-space"],
        "beta-space",
        2,
        2,
        &["beta-owner", "guest-beta"],
        &[beta_tenant.as_str(), "guest-beta/guest-laptop"],
        &[beta_bootstrap, guest_msg],
    );
    assert_cli_state(
        &guest_db,
        &["beta-space"],
        "beta-space",
        1,
        2,
        &["beta-owner", "guest-beta"],
        &[&beta_tenant, "guest-beta/guest-laptop"],
        &[beta_bootstrap, guest_msg],
    );

    use_tenant_for_username(&owner_db, "alpha");
    let alpha_view = get_view_raw(&owner_db);
    assert!(
        !alpha_view.contains(beta_bootstrap) && !alpha_view.contains(guest_msg),
        "first workspace view should not leak second-workspace messages:\n{}",
        alpha_view
    );

    stop_daemon(&owner_db, &mut owner_daemon);
    stop_daemon(&guest_db, &mut guest_daemon);
}

/// Live-daemon multitenant regression: after accepting a second workspace on a
/// running daemon, switching back to the original tenant must route sends back
/// to the original workspace instead of leaving them pinned to the newly
/// accepted tenant.
#[test]
fn test_cli_live_daemon_accept_second_workspace_can_switch_back_and_sync_original_tenant() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 30000;

    let owner_db = tmpdir.path().join("owner.db").to_str().unwrap().to_string();
    let zeta_db = tmpdir.path().join("zeta.db").to_str().unwrap().to_string();

    create_workspace_with_details(&owner_db, "home-space", "home", "home-root");
    let mut owner_daemon = start_daemon(&owner_db);
    let home_tenant = "home/home-root".to_string();

    let home_bootstrap = "home-space/bootstrap";
    let home_bootstrap_eid = send_message(&owner_db, home_bootstrap);
    let home_invite = create_invite(&owner_db, &daemon_listen_addr(&owner_db));
    let home_guest = start_joined_cli_peer(
        &tmpdir,
        "home-guest.db",
        &home_invite,
        "home-guest",
        "guest-laptop",
    );
    assert_event_visible_on_all(&[&home_guest.db], &home_bootstrap_eid, timeout_ms);

    create_workspace_with_details(&zeta_db, "zeta-space", "zeta", "zeta-root");
    let mut zeta_daemon = start_daemon(&zeta_db);
    let zeta_tenant = "zeta/zeta-root".to_string();

    let zeta_bootstrap = "zeta-space/bootstrap";
    let zeta_bootstrap_eid = send_message(&zeta_db, zeta_bootstrap);
    let zeta_invite = create_invite(&zeta_db, &daemon_listen_addr(&zeta_db));

    let accept = Command::new(bin())
        .args([
            "accept",
            "--db",
            &owner_db,
            &zeta_invite,
            "--username",
            "yuki-zeta",
            "--devicename",
            "yuki-terminal",
        ])
        .output()
        .unwrap();
    assert!(
        accept.status.success(),
        "accept failed: stdout={} stderr={}",
        String::from_utf8_lossy(&accept.stdout),
        String::from_utf8_lossy(&accept.stderr)
    );

    wait_for_username_peer_id(&owner_db, "yuki-zeta", timeout_ms);
    assert_event_visible_for_username(&owner_db, "yuki-zeta", &zeta_bootstrap_eid, timeout_ms);

    let zeta_msg = "zeta-space/yuki-live";
    let zeta_eid = send_message_as_username(&owner_db, "yuki-zeta", zeta_msg);
    assert_event_visible_on_all(&[&zeta_db], &zeta_eid, timeout_ms);

    let home_msg = "home-space/home-followup";
    let home_eid = send_message_as_username(&owner_db, "home", home_msg);
    assert_event_visible_on_all(&[&home_guest.db], &home_eid, timeout_ms);

    let home_guest_view = get_view_raw(&home_guest.db);
    assert!(
        !home_guest_view.contains(zeta_msg),
        "original workspace peer should not see second-workspace messages:\n{}",
        home_guest_view
    );
    let zeta_view = get_view_raw(&zeta_db);
    assert!(
        !zeta_view.contains(home_msg),
        "second workspace peer should not see original-workspace messages:\n{}",
        zeta_view
    );

    assert_cli_state_for_username(
        &owner_db,
        "home",
        &["home-space", "zeta-space"],
        "home-space",
        2,
        2,
        &["home", "home-guest"],
        &[home_tenant.as_str(), "home-guest/guest-laptop"],
        &[home_bootstrap, home_msg],
    );
    assert_cli_state_for_username(
        &owner_db,
        "yuki-zeta",
        &["home-space", "zeta-space"],
        "zeta-space",
        2,
        2,
        &["zeta", "yuki-zeta"],
        &[zeta_tenant.as_str(), "yuki-zeta/yuki-terminal"],
        &[zeta_bootstrap, zeta_msg],
    );

    stop_daemon(&owner_db, &mut owner_daemon);
    stop_daemon(&zeta_db, &mut zeta_daemon);
}

/// Live-daemon multitenant regression: after creating a second workspace on a
/// running daemon, explicit tenant switches must keep routing sends to the
/// selected workspace even after follow-up sync is active in both tenants.
#[test]
fn test_cli_live_daemon_create_second_workspace_can_switch_between_tenants_and_sync_both() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 30000;

    let owner_db = tmpdir.path().join("owner.db").to_str().unwrap().to_string();
    create_workspace_with_details(&owner_db, "alpha-space", "alpha", "alpha-root");
    let mut owner_daemon = start_daemon(&owner_db);
    let alpha_tenant = "alpha/alpha-root".to_string();

    let alpha_bootstrap = "alpha-space/bootstrap";
    let alpha_bootstrap_eid = send_message(&owner_db, alpha_bootstrap);
    let alpha_invite = create_invite(&owner_db, &daemon_listen_addr(&owner_db));
    let alpha_guest = start_joined_cli_peer(
        &tmpdir,
        "alpha-guest.db",
        &alpha_invite,
        "alpha-guest",
        "guest-alpha",
    );
    assert_event_visible_on_all(&[&alpha_guest.db], &alpha_bootstrap_eid, timeout_ms);

    let create = Command::new(bin())
        .args([
            "create-workspace",
            "--db",
            &owner_db,
            "--workspace-name",
            "beta-space",
            "--username",
            "beta-owner",
            "--device-name",
            "beta-root",
        ])
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "create-workspace failed: stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    wait_for_username_peer_id(&owner_db, "beta-owner", timeout_ms);
    let beta_tenant = "beta-owner/beta-root".to_string();
    let beta_bootstrap = "beta-space/bootstrap";
    let beta_bootstrap_eid = send_message(&owner_db, beta_bootstrap);
    let beta_invite = create_invite(&owner_db, &daemon_listen_addr(&owner_db));
    let beta_guest = start_joined_cli_peer(
        &tmpdir,
        "beta-guest.db",
        &beta_invite,
        "beta-guest",
        "guest-beta",
    );
    assert_event_visible_on_all(&[&beta_guest.db], &beta_bootstrap_eid, timeout_ms);

    let beta_reply = "beta-space/guest-reply";
    let beta_reply_eid = send_message(&beta_guest.db, beta_reply);
    assert_event_visible_for_username(&owner_db, "beta-owner", &beta_reply_eid, timeout_ms);

    let alpha_followup = "alpha-space/owner-followup";
    let alpha_followup_eid = send_message_as_username(&owner_db, "alpha", alpha_followup);
    assert_event_visible_on_all(&[&alpha_guest.db], &alpha_followup_eid, timeout_ms);

    let beta_followup = "beta-space/owner-second";
    let beta_followup_eid = send_message_as_username(&owner_db, "beta-owner", beta_followup);
    assert_event_visible_on_all(&[&beta_guest.db], &beta_followup_eid, timeout_ms);

    let alpha_view = get_view_raw(&alpha_guest.db);
    assert!(
        !alpha_view.contains(beta_bootstrap)
            && !alpha_view.contains(beta_reply)
            && !alpha_view.contains(beta_followup),
        "alpha tenant peer should not see beta-space messages:\n{}",
        alpha_view
    );
    let beta_view = get_view_raw(&beta_guest.db);
    assert!(
        !beta_view.contains(alpha_bootstrap) && !beta_view.contains(alpha_followup),
        "beta tenant peer should not see alpha-space messages:\n{}",
        beta_view
    );

    assert_cli_state_for_username(
        &owner_db,
        "alpha",
        &["alpha-space", "beta-space"],
        "alpha-space",
        2,
        2,
        &["alpha", "alpha-guest"],
        &[alpha_tenant.as_str(), "alpha-guest/guest-alpha"],
        &[alpha_bootstrap, alpha_followup],
    );
    assert_cli_state_for_username(
        &owner_db,
        "beta-owner",
        &["alpha-space", "beta-space"],
        "beta-space",
        2,
        2,
        &["beta-owner", "beta-guest"],
        &[beta_tenant.as_str(), "beta-guest/guest-beta"],
        &[beta_bootstrap, beta_reply, beta_followup],
    );

    stop_daemon(&owner_db, &mut owner_daemon);
}

/// Live-daemon multitenant regression: creating an additional workspace on a
/// hot daemon must not disrupt ongoing sync in an already-active second
/// workspace, and the newly created workspace must remain isolated.
#[test]
fn test_cli_live_daemon_creating_third_workspace_preserves_existing_second_workspace_sync() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 30000;

    let owner_db = tmpdir.path().join("owner.db").to_str().unwrap().to_string();
    create_workspace_with_details(&owner_db, "alpha-space", "alpha", "alpha-root");
    let mut owner_daemon = start_daemon(&owner_db);

    let create_beta = Command::new(bin())
        .args([
            "create-workspace",
            "--db",
            &owner_db,
            "--workspace-name",
            "beta-space",
            "--username",
            "beta-owner",
            "--device-name",
            "beta-root",
        ])
        .output()
        .unwrap();
    assert!(
        create_beta.status.success(),
        "create-workspace beta failed: stdout={} stderr={}",
        String::from_utf8_lossy(&create_beta.stdout),
        String::from_utf8_lossy(&create_beta.stderr)
    );
    wait_for_username_peer_id(&owner_db, "beta-owner", timeout_ms);

    let beta_tenant = "beta-owner/beta-root".to_string();
    let beta_bootstrap = "beta-space/bootstrap";
    let beta_bootstrap_eid = send_message(&owner_db, beta_bootstrap);
    let beta_invite = create_invite(&owner_db, &daemon_listen_addr(&owner_db));
    let beta_guest = start_joined_cli_peer(
        &tmpdir,
        "beta-guest.db",
        &beta_invite,
        "beta-guest",
        "guest-beta",
    );
    assert_event_visible_on_all(&[&beta_guest.db], &beta_bootstrap_eid, timeout_ms);

    let beta_first = "beta-space/guest-first";
    let beta_first_eid = send_message(&beta_guest.db, beta_first);
    assert_event_visible_for_username(&owner_db, "beta-owner", &beta_first_eid, timeout_ms);

    let create_gamma = Command::new(bin())
        .args([
            "create-workspace",
            "--db",
            &owner_db,
            "--workspace-name",
            "gamma-space",
            "--username",
            "gamma-owner",
            "--device-name",
            "gamma-root",
        ])
        .output()
        .unwrap();
    assert!(
        create_gamma.status.success(),
        "create-workspace gamma failed: stdout={} stderr={}",
        String::from_utf8_lossy(&create_gamma.stdout),
        String::from_utf8_lossy(&create_gamma.stderr)
    );
    wait_for_username_peer_id(&owner_db, "gamma-owner", timeout_ms);

    let gamma_tenant = "gamma-owner/gamma-root".to_string();
    let gamma_msg = "gamma-space/local-only";
    let gamma_eid = send_message(&owner_db, gamma_msg);
    assert_event_visible_for_username(&owner_db, "gamma-owner", &gamma_eid, timeout_ms);

    let beta_second = "beta-space/guest-second";
    let beta_second_eid = send_message(&beta_guest.db, beta_second);
    assert_event_visible_for_username(&owner_db, "beta-owner", &beta_second_eid, timeout_ms);

    let beta_owner_reply = "beta-space/owner-reply";
    let beta_owner_reply_eid = send_message_as_username(&owner_db, "beta-owner", beta_owner_reply);
    assert_event_visible_on_all(&[&beta_guest.db], &beta_owner_reply_eid, timeout_ms);

    let beta_view = get_view_raw(&beta_guest.db);
    assert!(
        !beta_view.contains(gamma_msg),
        "existing second workspace peer should not see third-workspace messages:\n{}",
        beta_view
    );

    assert_cli_state_for_username(
        &owner_db,
        "beta-owner",
        &["alpha-space", "beta-space", "gamma-space"],
        "beta-space",
        3,
        2,
        &["beta-owner", "beta-guest"],
        &[beta_tenant.as_str(), "beta-guest/guest-beta"],
        &[beta_bootstrap, beta_first, beta_second, beta_owner_reply],
    );
    assert_cli_state_for_username(
        &owner_db,
        "gamma-owner",
        &["alpha-space", "beta-space", "gamma-space"],
        "gamma-space",
        3,
        1,
        &["gamma-owner"],
        &[gamma_tenant.as_str()],
        &[gamma_msg],
    );

    stop_daemon(&owner_db, &mut owner_daemon);
}

/// Mixed realistic topology:
/// 1. a shared DB accepts empty-address invites into two workspaces and must
///    recover via mDNS,
/// 2. one additional alpha peer joins with explicit endpoint addresses
///    (dead-first, live-second),
/// 3. CLI state remains workspace-scoped with overlapping but non-identical
///    membership across clients.
#[test]
#[cfg(feature = "discovery")]
fn test_cli_shared_db_multiworkspace_mixes_empty_bootstrap_mdns_and_explicit_endpoints() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 45000;

    let alpha_db = tmpdir.path().join("alpha.db").to_str().unwrap().to_string();
    let zeta_db = tmpdir.path().join("zeta.db").to_str().unwrap().to_string();
    let shared_db = tmpdir
        .path()
        .join("shared.db")
        .to_str()
        .unwrap()
        .to_string();
    let dave_db = tmpdir.path().join("dave.db").to_str().unwrap().to_string();

    create_workspace_with_details(&alpha_db, "alpha-space", "alpha", "alpha-root");
    let alpha = StartedCliPeer {
        db: alpha_db,
        username: "alpha".to_string(),
        device_name: "alpha-root".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("alpha.db")
                .to_str()
                .expect("alpha db path"),
        ),
    };
    let alpha_tenant = alpha.tenant_label();
    let alpha_empty_invite = rewrite_invite_addrs(
        &create_invite(&alpha.db, &daemon_listen_addr(&alpha.db)),
        &[],
    );
    assert!(
        parse_invite_link(&alpha_empty_invite)
            .expect("parse alpha empty-address invite")
            .bootstrap_addrs
            .is_empty(),
        "alpha invite should carry no bootstrap addresses"
    );

    create_workspace_with_details(&zeta_db, "zeta-space", "zeta", "zeta-root");
    let zeta = StartedCliPeer {
        db: zeta_db,
        username: "zeta".to_string(),
        device_name: "zeta-root".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("zeta.db")
                .to_str()
                .expect("zeta db path"),
        ),
    };
    let zeta_tenant = zeta.tenant_label();
    let zeta_empty_invite =
        rewrite_invite_addrs(&create_invite(&zeta.db, &daemon_listen_addr(&zeta.db)), &[]);
    assert!(
        parse_invite_link(&zeta_empty_invite)
            .expect("parse zeta empty-address invite")
            .bootstrap_addrs
            .is_empty(),
        "zeta invite should carry no bootstrap addresses"
    );

    accept_invite_with_identity(&shared_db, &alpha_empty_invite, "bob-alpha", "bob-terminal");
    accept_invite_with_identity(&shared_db, &zeta_empty_invite, "yuki-zeta", "yuki-terminal");
    accept_invite_with_identity(
        &shared_db,
        &alpha_empty_invite,
        "carol-alpha",
        "carol-terminal",
    );
    let _shared_daemon = start_daemon(&shared_db);

    assert_eventually_users_include(
        &alpha.db,
        &["alpha", "bob-alpha", "carol-alpha"],
        timeout_ms,
    );
    assert_eventually_users_include(&zeta.db, &["zeta", "yuki-zeta"], timeout_ms);

    let alpha_live_addr = daemon_listen_addr(&alpha.db);
    let alpha_live_port = alpha_live_addr
        .rsplit_once(':')
        .expect("alpha listen addr should contain port")
        .1
        .to_string();
    let alpha_explicit_invite = rewrite_invite_addrs(
        &create_invite(&alpha.db, &alpha_live_addr),
        &[
            &format!("127.0.0.1:{}", random_port()),
            &format!("localhost:{}", alpha_live_port),
        ],
    );
    let dave = {
        accept_invite_with_identity(
            &dave_db,
            &alpha_explicit_invite,
            "dave-alpha",
            "dave-laptop",
        );
        StartedCliPeer {
            db: dave_db,
            username: "dave-alpha".to_string(),
            device_name: "dave-laptop".to_string(),
            _daemon: start_daemon(
                tmpdir
                    .path()
                    .join("dave.db")
                    .to_str()
                    .expect("dave db path"),
            ),
        }
    };
    let dave_tenant = dave.tenant_label();

    assert_eventually_users_include(
        &alpha.db,
        &["alpha", "bob-alpha", "carol-alpha", "dave-alpha"],
        timeout_ms,
    );

    let alpha_live_msg = "alpha-space/alpha-via-empty-bootstrap-mdns";
    let alpha_live_eid = send_message(&alpha.db, alpha_live_msg);
    assert_event_visible_for_username(&shared_db, "bob-alpha", &alpha_live_eid, timeout_ms);
    assert_event_visible_for_username(&shared_db, "carol-alpha", &alpha_live_eid, timeout_ms);
    assert_event_visible_on_all(&[&dave.db], &alpha_live_eid, timeout_ms);

    let zeta_live_msg = "zeta-space/zeta-via-empty-bootstrap-mdns";
    let zeta_live_eid = send_message(&zeta.db, zeta_live_msg);
    assert_event_visible_for_username(&shared_db, "yuki-zeta", &zeta_live_eid, timeout_ms);

    let dave_live_msg = "alpha-space/dave-via-explicit-endpoints";
    let dave_live_eid = send_message(&dave.db, dave_live_msg);
    assert_event_visible_on_all(&[&alpha.db], &dave_live_eid, timeout_ms);
    assert_event_visible_for_username(&shared_db, "bob-alpha", &dave_live_eid, timeout_ms);
    assert_event_visible_for_username(&shared_db, "carol-alpha", &dave_live_eid, timeout_ms);

    let carol_peer_id = peer_id_for_username(&shared_db, "carol-alpha");
    let dave_peer_id = peer_id_for_username(&dave.db, "dave-alpha");
    let dave_addr: SocketAddr = daemon_listen_addr(&dave.db)
        .parse()
        .expect("dave listen addr");
    wait_for_direct_trust_dial(
        &shared_db,
        &carol_peer_id,
        dave_addr,
        &dave_peer_id,
        timeout_ms,
    );

    let bob_live_msg = "alpha-space/bob-from-shared-db";
    let bob_live_eid = send_message_as_username(&shared_db, "bob-alpha", bob_live_msg);
    assert_event_visible_on_all(&[&alpha.db, &dave.db], &bob_live_eid, timeout_ms);
    assert_event_visible_for_username(&shared_db, "carol-alpha", &bob_live_eid, timeout_ms);

    let yuki_live_msg = "zeta-space/yuki-from-shared-db";
    let yuki_live_eid = send_message_as_username(&shared_db, "yuki-zeta", yuki_live_msg);
    assert_event_visible_on_all(&[&zeta.db], &yuki_live_eid, timeout_ms);

    let bob_alpha_tenant = "bob-alpha/bob-terminal";
    let carol_alpha_tenant = "carol-alpha/carol-terminal";
    let yuki_zeta_tenant = "yuki-zeta/yuki-terminal";

    assert_eventually_users_include(
        &dave.db,
        &["alpha", "bob-alpha", "carol-alpha", "dave-alpha"],
        timeout_ms,
    );

    assert_cli_state(
        &alpha.db,
        &["alpha-space"],
        "alpha-space",
        1,
        4,
        &["alpha", "bob-alpha", "carol-alpha", "dave-alpha"],
        &[
            alpha_tenant.as_str(),
            bob_alpha_tenant,
            carol_alpha_tenant,
            dave_tenant.as_str(),
        ],
        &[alpha_live_msg, dave_live_msg, bob_live_msg],
    );
    assert_cli_state(
        &zeta.db,
        &["zeta-space"],
        "zeta-space",
        1,
        2,
        &["zeta", "yuki-zeta"],
        &[zeta_tenant.as_str(), yuki_zeta_tenant],
        &[zeta_live_msg, yuki_live_msg],
    );
    assert_cli_state(
        &dave.db,
        &["alpha-space"],
        "alpha-space",
        1,
        4,
        &["alpha", "bob-alpha", "carol-alpha", "dave-alpha"],
        &[
            alpha_tenant.as_str(),
            bob_alpha_tenant,
            carol_alpha_tenant,
            dave_tenant.as_str(),
        ],
        &[alpha_live_msg, dave_live_msg, bob_live_msg],
    );
    assert_cli_state_for_username(
        &shared_db,
        "bob-alpha",
        &["alpha-space", "zeta-space"],
        "alpha-space",
        3,
        4,
        &["alpha", "bob-alpha", "carol-alpha", "dave-alpha"],
        &[
            alpha_tenant.as_str(),
            bob_alpha_tenant,
            carol_alpha_tenant,
            dave_tenant.as_str(),
        ],
        &[alpha_live_msg, dave_live_msg, bob_live_msg],
    );
    assert_cli_state_for_username(
        &shared_db,
        "carol-alpha",
        &["alpha-space", "zeta-space"],
        "alpha-space",
        3,
        4,
        &["alpha", "bob-alpha", "carol-alpha", "dave-alpha"],
        &[
            alpha_tenant.as_str(),
            bob_alpha_tenant,
            carol_alpha_tenant,
            dave_tenant.as_str(),
        ],
        &[alpha_live_msg, dave_live_msg, bob_live_msg],
    );
    assert_cli_state_for_username(
        &shared_db,
        "yuki-zeta",
        &["alpha-space", "zeta-space"],
        "zeta-space",
        3,
        2,
        &["zeta", "yuki-zeta"],
        &[zeta_tenant.as_str(), yuki_zeta_tenant],
        &[zeta_live_msg, yuki_live_msg],
    );

    use_tenant_for_username(&shared_db, "yuki-zeta");
    let yuki_view = get_view_raw(&shared_db);
    assert!(
        !yuki_view.contains(alpha_live_msg)
            && !yuki_view.contains(dave_live_msg)
            && !yuki_view.contains(bob_live_msg),
        "zeta tenant view should not leak alpha workspace messages:\n{}",
        yuki_view
    );

    use_tenant_for_username(&shared_db, "bob-alpha");
    let bob_view = get_view_raw(&shared_db);
    assert!(
        !bob_view.contains(zeta_live_msg) && !bob_view.contains(yuki_live_msg),
        "alpha tenant view should not leak zeta workspace messages:\n{}",
        bob_view
    );
}

/// Black-box lift of the shared-db multitenant discovery/isolation cases:
/// two tenants on one shared DB advertise via one daemon, two external peers
/// recover via mDNS-only invites, and each workspace stays isolated in users,
/// peers, views, and direct trust dials.
#[test]
#[cfg(feature = "discovery")]
fn test_cli_shared_db_multitenant_mdns_self_filtering_and_cross_workspace_isolation() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 45000;

    let alpha_db = tmpdir.path().join("alpha.db").to_str().unwrap().to_string();
    let zeta_db = tmpdir.path().join("zeta.db").to_str().unwrap().to_string();
    let shared_db = tmpdir
        .path()
        .join("shared.db")
        .to_str()
        .unwrap()
        .to_string();
    let dave_db = tmpdir.path().join("dave.db").to_str().unwrap().to_string();
    let emma_db = tmpdir.path().join("emma.db").to_str().unwrap().to_string();

    create_workspace_with_details(&alpha_db, "alpha-space", "alpha", "alpha-root");
    let alpha = StartedCliPeer {
        db: alpha_db,
        username: "alpha".to_string(),
        device_name: "alpha-root".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("alpha.db")
                .to_str()
                .expect("alpha db path"),
        ),
    };
    let alpha_tenant = alpha.tenant_label();
    let alpha_bootstrap = send_message(&alpha.db, "alpha-space/bootstrap");
    assert_event_visible_on_all(&[&alpha.db], &alpha_bootstrap, timeout_ms);
    let alpha_empty_invite = rewrite_invite_addrs(
        &create_invite(&alpha.db, &daemon_listen_addr(&alpha.db)),
        &[],
    );

    create_workspace_with_details(&zeta_db, "zeta-space", "zeta", "zeta-root");
    let zeta = StartedCliPeer {
        db: zeta_db,
        username: "zeta".to_string(),
        device_name: "zeta-root".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("zeta.db")
                .to_str()
                .expect("zeta db path"),
        ),
    };
    let zeta_tenant = zeta.tenant_label();
    let zeta_bootstrap = send_message(&zeta.db, "zeta-space/bootstrap");
    assert_event_visible_on_all(&[&zeta.db], &zeta_bootstrap, timeout_ms);
    let zeta_empty_invite =
        rewrite_invite_addrs(&create_invite(&zeta.db, &daemon_listen_addr(&zeta.db)), &[]);

    accept_invite_with_identity(&shared_db, &alpha_empty_invite, "bob-alpha", "bob-terminal");
    accept_invite_with_identity(&shared_db, &zeta_empty_invite, "yuki-zeta", "yuki-terminal");
    let _shared_daemon = start_daemon(&shared_db);

    let dave_alpha_invite = rewrite_invite_addrs(
        &create_invite(&alpha.db, &daemon_listen_addr(&alpha.db)),
        &[],
    );
    let emma_zeta_invite =
        rewrite_invite_addrs(&create_invite(&zeta.db, &daemon_listen_addr(&zeta.db)), &[]);

    accept_invite_with_identity(&dave_db, &dave_alpha_invite, "dave-alpha", "dave-laptop");
    let dave = StartedCliPeer {
        db: dave_db,
        username: "dave-alpha".to_string(),
        device_name: "dave-laptop".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("dave.db")
                .to_str()
                .expect("dave db path"),
        ),
    };
    let dave_tenant = dave.tenant_label();
    assert_eventually(&dave.db, "message_count >= 1", timeout_ms);
    assert_identity_eventually_materialized(&dave.db, timeout_ms);

    accept_invite_with_identity(&emma_db, &emma_zeta_invite, "emma-zeta", "emma-laptop");
    let emma = StartedCliPeer {
        db: emma_db,
        username: "emma-zeta".to_string(),
        device_name: "emma-laptop".to_string(),
        _daemon: start_daemon(
            tmpdir
                .path()
                .join("emma.db")
                .to_str()
                .expect("emma db path"),
        ),
    };
    let emma_tenant = emma.tenant_label();
    assert_eventually(&emma.db, "message_count >= 1", timeout_ms);
    assert_identity_eventually_materialized(&emma.db, timeout_ms);

    assert_eventually_users_include(&alpha.db, &["alpha", "bob-alpha", "dave-alpha"], timeout_ms);
    assert_eventually_users_include(&zeta.db, &["zeta", "yuki-zeta", "emma-zeta"], timeout_ms);

    let dave_alpha_msg = "alpha-space/dave-external";
    let dave_alpha_eid = send_message(&dave.db, dave_alpha_msg);
    assert_event_visible_on_all(&[&alpha.db], &dave_alpha_eid, timeout_ms);
    assert_event_visible_for_username(&shared_db, "bob-alpha", &dave_alpha_eid, timeout_ms);

    let emma_zeta_msg = "zeta-space/emma-external";
    let emma_zeta_eid = send_message(&emma.db, emma_zeta_msg);
    assert_event_visible_on_all(&[&zeta.db], &emma_zeta_eid, timeout_ms);
    assert_event_visible_for_username(&shared_db, "yuki-zeta", &emma_zeta_eid, timeout_ms);

    let bob_alpha_msg = "alpha-space/bob-shared";
    let bob_alpha_eid = send_message_as_username(&shared_db, "bob-alpha", bob_alpha_msg);
    assert_event_visible_on_all(&[&alpha.db, &dave.db], &bob_alpha_eid, timeout_ms);

    let yuki_zeta_msg = "zeta-space/yuki-shared";
    let yuki_zeta_eid = send_message_as_username(&shared_db, "yuki-zeta", yuki_zeta_msg);
    assert_event_visible_on_all(&[&zeta.db, &emma.db], &yuki_zeta_eid, timeout_ms);

    let bob_peer_id = peer_id_for_username(&shared_db, "bob-alpha");
    let yuki_peer_id = peer_id_for_username(&shared_db, "yuki-zeta");
    let dave_peer_id = peer_id_for_username(&dave.db, "dave-alpha");
    let emma_peer_id = peer_id_for_username(&emma.db, "emma-zeta");
    let dave_addr: SocketAddr = daemon_listen_addr(&dave.db)
        .parse()
        .expect("dave listen addr");
    let emma_addr: SocketAddr = daemon_listen_addr(&emma.db)
        .parse()
        .expect("emma listen addr");

    wait_for_direct_trust_dial(
        &shared_db,
        &bob_peer_id,
        dave_addr,
        &dave_peer_id,
        timeout_ms,
    );
    wait_for_direct_trust_dial(
        &shared_db,
        &yuki_peer_id,
        emma_addr,
        &emma_peer_id,
        timeout_ms,
    );
    assert_direct_dial_never_succeeds(&shared_db, &bob_peer_id, emma_addr, &emma_peer_id, 5000);
    assert_direct_dial_never_succeeds(&shared_db, &yuki_peer_id, dave_addr, &dave_peer_id, 5000);

    assert_peers_eventually_include(
        &shared_db,
        "bob-alpha",
        &["alpha", "dave-alpha@dave-laptop"],
        timeout_ms,
    );
    assert_peers_do_not_include(&shared_db, "bob-alpha", &["yuki-zeta", "emma-zeta"]);
    assert_peers_eventually_include(
        &shared_db,
        "yuki-zeta",
        &["zeta", "emma-zeta@emma-laptop"],
        timeout_ms,
    );
    assert_peers_do_not_include(&shared_db, "yuki-zeta", &["bob-alpha", "dave-alpha"]);

    assert_cli_state(
        &alpha.db,
        &["alpha-space"],
        "alpha-space",
        1,
        3,
        &["alpha", "bob-alpha", "dave-alpha"],
        &[
            alpha_tenant.as_str(),
            "bob-alpha/bob-terminal",
            dave_tenant.as_str(),
        ],
        &["alpha-space/bootstrap", dave_alpha_msg, bob_alpha_msg],
    );
    assert_cli_state(
        &zeta.db,
        &["zeta-space"],
        "zeta-space",
        1,
        3,
        &["zeta", "yuki-zeta", "emma-zeta"],
        &[
            zeta_tenant.as_str(),
            "yuki-zeta/yuki-terminal",
            emma_tenant.as_str(),
        ],
        &["zeta-space/bootstrap", emma_zeta_msg, yuki_zeta_msg],
    );
    assert_cli_state_for_username(
        &shared_db,
        "bob-alpha",
        &["alpha-space", "zeta-space"],
        "alpha-space",
        2,
        3,
        &["alpha", "bob-alpha", "dave-alpha"],
        &[
            alpha_tenant.as_str(),
            "bob-alpha/bob-terminal",
            dave_tenant.as_str(),
        ],
        &["alpha-space/bootstrap", dave_alpha_msg, bob_alpha_msg],
    );
    assert_cli_state_for_username(
        &shared_db,
        "yuki-zeta",
        &["alpha-space", "zeta-space"],
        "zeta-space",
        2,
        3,
        &["zeta", "yuki-zeta", "emma-zeta"],
        &[
            zeta_tenant.as_str(),
            "yuki-zeta/yuki-terminal",
            emma_tenant.as_str(),
        ],
        &["zeta-space/bootstrap", emma_zeta_msg, yuki_zeta_msg],
    );

    use_tenant_for_username(&shared_db, "bob-alpha");
    let bob_view = get_view_raw(&shared_db);
    assert!(
        !bob_view.contains(emma_zeta_msg) && !bob_view.contains(yuki_zeta_msg),
        "alpha tenant view should not leak zeta workspace messages:\n{}",
        bob_view
    );

    use_tenant_for_username(&shared_db, "yuki-zeta");
    let yuki_view = get_view_raw(&shared_db);
    assert!(
        !yuki_view.contains(dave_alpha_msg) && !yuki_view.contains(bob_alpha_msg),
        "zeta tenant view should not leak alpha workspace messages:\n{}",
        yuki_view
    );
}

// ---------------------------------------------------------------------------
// CLI command output tests
// ---------------------------------------------------------------------------

#[test]
fn test_cli_completions_bash() {
    let _guard = cli_test_lock();
    let output = Command::new(bin())
        .args(["completions", "bash"])
        .output()
        .expect("failed to run completions");
    assert!(output.status.success(), "completions bash failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "bash completions should produce output");
    assert!(
        stdout.contains("topo"),
        "bash completions should reference 'topo'"
    );
}

#[test]
fn test_cli_completions_zsh() {
    let _guard = cli_test_lock();
    let output = Command::new(bin())
        .args(["completions", "zsh"])
        .output()
        .expect("failed to run completions");
    assert!(output.status.success(), "completions zsh failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "zsh completions should produce output");
}

#[test]
fn test_cli_workspaces() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("wsalias.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "workspaces"])
        .output()
        .expect("workspaces command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("WORKSPACES"),
        "workspaces should show WORKSPACES header"
    );
}

#[test]
fn test_cli_react_by_message_number() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("msgnum.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // Send two messages.
    send_message(&db, "first msg");
    send_message(&db, "second msg");

    // React to message #1 by number.
    let out = Command::new(bin())
        .args(["--db", &db, "react", "thumbsup", "1"])
        .output()
        .expect("react by number");
    assert!(
        out.status.success(),
        "react by number failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Reacted"),
        "expected Reacted output, got: {}",
        stdout
    );

    // React to message #2 with # prefix.
    let out = Command::new(bin())
        .args(["--db", &db, "react", "heart", "#2"])
        .output()
        .expect("react by #N");
    assert!(
        out.status.success(),
        "react by #N failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Delete message #1 by number.
    let out = Command::new(bin())
        .args(["--db", &db, "delete-message", "1"])
        .output()
        .expect("delete by number");
    assert!(
        out.status.success(),
        "delete by number failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Deleted"),
        "expected Deleted output, got: {}",
        stdout
    );

    // Invalid message number should error.
    let out = Command::new(bin())
        .args(["--db", &db, "react", "sad", "99"])
        .output()
        .expect("react invalid number");
    assert!(
        !out.status.success(),
        "should fail for invalid message number"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid message number"),
        "expected error message, got: {}",
        stderr
    );
}

#[test]
fn test_cli_messages_include_reactions() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("enrich.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // Send a message and react to it.
    send_message(&db, "hello world");
    let out = Command::new(bin())
        .args(["--db", &db, "react", "thumbsup", "1"])
        .output()
        .expect("react");
    assert!(
        out.status.success(),
        "react failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Add a second different reaction to the same message.
    let out = Command::new(bin())
        .args(["--db", &db, "react", "fire", "1"])
        .output()
        .expect("react fire");
    assert!(
        out.status.success(),
        "react fire failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `topo messages` output should contain both reactions as real emoji.
    let raw = get_messages_raw(&db);
    assert!(
        raw.contains("\u{1f44d}"),
        "expected thumbsup emoji in messages output, got:\n{}",
        raw
    );
    assert!(
        raw.contains("\u{1f525}"),
        "expected fire emoji in messages output, got:\n{}",
        raw
    );
    // Should NOT contain the text shortcode — only real emoji.
    assert!(
        !raw.contains("thumbsup"),
        "should render emoji glyph, not shortcode name, got:\n{}",
        raw
    );
}

#[test]
fn test_cli_sub_commands_accept_name_selector_and_nested_shape() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("subs.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let create_out = Command::new(bin())
        .args([
            "--db",
            &db,
            "sub",
            "create",
            "--name",
            "new-messages",
            "--event-type",
            "message",
        ])
        .output()
        .expect("sub create");
    assert!(
        create_out.status.success(),
        "sub create failed: {}",
        String::from_utf8_lossy(&create_out.stderr)
    );

    let list_out = Command::new(bin())
        .args(["--db", &db, "subs", "list"])
        .output()
        .expect("subs list");
    assert!(
        list_out.status.success(),
        "subs list failed: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(
        list_stdout.contains("new-messages"),
        "subs list should include subscription name, got: {}",
        list_stdout
    );

    send_message(&db, "hello subscriptions");
    let poll_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let poll_out = Command::new(bin())
            .args(["--db", &db, "sub", "poll", "new-messages"])
            .output()
            .expect("sub poll by name");
        assert!(
            poll_out.status.success(),
            "sub poll by name failed: {}",
            String::from_utf8_lossy(&poll_out.stderr)
        );
        let poll_stdout = String::from_utf8_lossy(&poll_out.stdout).to_string();
        if poll_stdout.contains("hello subscriptions") {
            break;
        }
        if Instant::now() >= poll_deadline {
            panic!(
                "timed out waiting for subscription item by name selector:\n{}",
                poll_stdout
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let state_out = Command::new(bin())
        .args(["--db", &db, "sub", "state"])
        .output()
        .expect("sub state default selector");
    assert!(
        state_out.status.success(),
        "sub state default selector failed: {}",
        String::from_utf8_lossy(&state_out.stderr)
    );
    let state_stdout = String::from_utf8_lossy(&state_out.stdout);
    assert!(
        state_stdout.contains("pending="),
        "sub state should print summary, got: {}",
        state_stdout
    );

    let disable_out = Command::new(bin())
        .args(["--db", &db, "sub", "disable", "--sub", "new-messages"])
        .output()
        .expect("sub disable --sub");
    assert!(
        disable_out.status.success(),
        "sub disable --sub failed: {}",
        String::from_utf8_lossy(&disable_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&disable_out.stderr).contains("deprecated"),
        "sub disable --sub should emit deprecation warning, got: {}",
        String::from_utf8_lossy(&disable_out.stderr)
    );
}

#[test]
fn test_cli_send_file_and_messages_display() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("sendfile.db")
        .to_str()
        .unwrap()
        .to_string();

    // Create a temp file to attach.
    let file_path = tmpdir.path().join("notes.txt");
    std::fs::write(&file_path, "These are my notes.\n").unwrap();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // send-file with content + attachment
    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "send-file",
            "Check out my notes",
            "--file",
            file_path.to_str().unwrap(),
        ])
        .output()
        .expect("send-file");
    assert!(
        out.status.success(),
        "send-file failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("notes.txt"),
        "send-file output should show filename, got: {}",
        stdout
    );

    // `topo messages` should show the message and the attachment.
    let raw = get_messages_raw(&db);
    assert!(
        raw.contains("Check out my notes"),
        "messages should contain message content, got:\n{}",
        raw
    );
    assert!(
        raw.contains("notes.txt"),
        "messages should contain filename, got:\n{}",
        raw
    );
    // Local files should be complete (all slices present) → ✔
    assert!(
        raw.contains("\u{2714}"),
        "local attachment should show checkmark (complete), got:\n{}",
        raw
    );
    assert!(
        !raw.contains("MiB/s"),
        "local attachment should not show a sync-derived rate, got:\n{}",
        raw
    );

    let files_raw = get_files_raw(&db);
    assert!(
        files_raw.contains("notes.txt"),
        "files should contain filename, got:\n{}",
        files_raw
    );
    assert!(
        !files_raw.contains("MiB/s"),
        "local files list should not show a sync-derived rate, got:\n{}",
        files_raw
    );
}

#[test]
fn test_cli_send_file_accepts_path_from_stdin_when_flag_omitted() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("sendfile_stdin.db")
        .to_str()
        .unwrap()
        .to_string();

    let file_path = tmpdir.path().join("stdin-notes.txt");
    std::fs::write(&file_path, "attachment via stdin path\n").unwrap();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let mut child = Command::new(bin())
        .args(["--db", &db, "send-file", "stdin attachment"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn send-file");
    child
        .stdin
        .as_mut()
        .expect("send-file stdin should be piped")
        .write_all(format!("{}\n", file_path.display()).as_bytes())
        .expect("write file path to send-file stdin");

    let out = child.wait_with_output().expect("wait for send-file");
    assert!(
        out.status.success(),
        "send-file failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("stdin-notes.txt"),
        "send-file output should show filename, got: {}",
        stdout
    );
}

#[test]
fn test_cli_send_file_without_path_uses_placeholder_and_save_file_defaults_target() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("sendfile_placeholder.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let send_out = Command::new(bin())
        .args(["--db", &db, "send-file", "missing path"])
        .stdin(Stdio::null())
        .output()
        .expect("send-file");
    assert!(
        send_out.status.success(),
        "send-file should fall back to placeholder when no file path is provided: {}",
        String::from_utf8_lossy(&send_out.stderr)
    );
    let send_stdout = String::from_utf8_lossy(&send_out.stdout);
    assert!(
        send_stdout.contains("topo-placeholder.txt"),
        "send-file should report placeholder filename, got: {}",
        send_stdout
    );

    let positional_out = tmpdir.path().join("placeholder-positional.txt");
    let save_positional = Command::new(bin())
        .args([
            "--db",
            &db,
            "save-file",
            "1",
            "--out",
            positional_out.to_str().unwrap(),
        ])
        .output()
        .expect("save-file positional target");
    assert!(
        save_positional.status.success(),
        "save-file with positional target failed: {}",
        String::from_utf8_lossy(&save_positional.stderr)
    );

    let long_flag_out = tmpdir.path().join("placeholder-long-flag.txt");
    let save_long_flag = Command::new(bin())
        .args([
            "--db",
            &db,
            "save-file",
            "--target",
            "1",
            "--out",
            long_flag_out.to_str().unwrap(),
        ])
        .output()
        .expect("save-file --target");
    assert!(
        save_long_flag.status.success(),
        "save-file --target failed: {}",
        String::from_utf8_lossy(&save_long_flag.stderr)
    );
    assert!(
        String::from_utf8_lossy(&save_long_flag.stderr).contains("deprecated"),
        "save-file --target should emit deprecation warning, got: {}",
        String::from_utf8_lossy(&save_long_flag.stderr)
    );

    let default_out = tmpdir.path().join("placeholder-default.txt");
    let save_default = Command::new(bin())
        .args([
            "--db",
            &db,
            "save-file",
            "--out",
            default_out.to_str().unwrap(),
        ])
        .output()
        .expect("save-file default target");
    assert!(
        save_default.status.success(),
        "save-file default target failed: {}",
        String::from_utf8_lossy(&save_default.stderr)
    );

    let positional_content = std::fs::read_to_string(&positional_out).unwrap();
    let long_flag_content = std::fs::read_to_string(&long_flag_out).unwrap();
    let default_content = std::fs::read_to_string(&default_out).unwrap();
    assert_eq!(positional_content, "placeholder file\n");
    assert_eq!(long_flag_content, "placeholder file\n");
    assert_eq!(default_content, "placeholder file\n");
}

#[test]
fn test_cli_files_and_save_file_roundtrip_after_sync() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir
        .path()
        .join("alice_files.db")
        .to_str()
        .unwrap()
        .to_string();
    let bob_db = tmpdir
        .path()
        .join("bob_files.db")
        .to_str()
        .unwrap()
        .to_string();
    let timeout_ms = 30000;

    let source_path = tmpdir.path().join("payload.bin");
    let mut expected = vec![0u8; 300_123];
    for (i, b) in expected.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    std::fs::write(&source_path, &expected).unwrap();

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));
    accept_invite(&bob_db, &invite_link);
    let _bob = start_daemon(&bob_db);

    let send_out = Command::new(bin())
        .args([
            "--db",
            &alice_db,
            "send-file",
            "binary payload",
            "--file",
            source_path.to_str().unwrap(),
        ])
        .output()
        .expect("send-file");
    assert!(
        send_out.status.success(),
        "send-file failed: {}",
        String::from_utf8_lossy(&send_out.stderr)
    );
    let send_stdout = String::from_utf8_lossy(&send_out.stdout);
    let msg_eid = send_stdout
        .lines()
        .find_map(|line| line.strip_prefix("event_id:").map(|s| s.trim().to_string()))
        .expect("send-file output missing event_id");

    assert_eventually(&bob_db, &format!("has_event:{} >= 1", msg_eid), timeout_ms);

    let files_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let files_stdout = get_files_raw(&bob_db);
        if files_stdout.contains("payload.bin")
            && files_stdout.contains("1.")
            && files_stdout.contains("MiB/s")
        {
            break;
        }
        if Instant::now() >= files_deadline {
            panic!(
                "timed out waiting for bob files list to show payload.bin with MiB/s:\n{}",
                files_stdout
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let messages_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let messages_stdout = get_messages_raw(&bob_db);
        if messages_stdout.contains("payload.bin") && messages_stdout.contains("MiB/s") {
            break;
        }
        if Instant::now() >= messages_deadline {
            panic!(
                "timed out waiting for bob messages to show payload.bin with MiB/s:\n{}",
                messages_stdout
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let restored_path = tmpdir.path().join("restored.bin");
    let save_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let save_out = Command::new(bin())
            .args([
                "--db",
                &bob_db,
                "save-file",
                "1",
                "--out",
                restored_path.to_str().unwrap(),
            ])
            .output()
            .expect("save-file command");
        if save_out.status.success() {
            break;
        }
        let last_stderr = String::from_utf8_lossy(&save_out.stderr).to_string();
        let retryable =
            last_stderr.contains("file incomplete") || last_stderr.contains("invalid file number");
        if !retryable {
            panic!("save-file failed unexpectedly: {}", last_stderr);
        }
        if Instant::now() >= save_deadline {
            panic!(
                "timed out waiting for save-file success; last err={}",
                last_stderr
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let restored = std::fs::read(&restored_path).unwrap();
    assert_eq!(restored, expected, "saved file bytes should match source");
}

#[test]
fn test_cli_generate_files_messages_display() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("genfiles.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // generate-files creates synthetic message + attachment
    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "generate-files",
            "--count",
            "1",
            "--size-mib",
            "1",
        ])
        .output()
        .expect("generate-files");
    assert!(
        out.status.success(),
        "generate-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `topo messages` should show the attachment with filename and checkmark.
    let raw = get_messages_raw(&db);
    assert!(
        raw.contains("file-0.bin"),
        "messages should contain synthetic filename, got:\n{}",
        raw
    );
    assert!(
        raw.contains("\u{2714}"),
        "local attachment should show checkmark (complete), got:\n{}",
        raw
    );
}

#[test]
fn test_cli_event_tree_shows_structure() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("event_tree.db")
        .to_str()
        .unwrap()
        .to_string();

    // create-workspace populates the db with identity chain events.
    create_workspace(&db);

    // event-tree is served via daemon RPC.
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event", "tree"])
        .output()
        .expect("event tree command");
    assert!(
        out.status.success(),
        "event-tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Should contain the root workspace event.
    assert!(
        stdout.contains("workspace"),
        "event-tree should show workspace event, got:\n{}",
        stdout
    );
    // Should contain tree connectors (proves hierarchy is rendered).
    assert!(
        stdout.contains("├──") || stdout.contains("└──"),
        "event-tree should show tree connectors, got:\n{}",
        stdout
    );
    // Should contain the root marker.
    assert!(
        stdout.contains("root"),
        "event-tree should mark root events, got:\n{}",
        stdout
    );
    // Should show event count footer.
    assert!(
        stdout.contains("events."),
        "event-tree should show event count, got:\n{}",
        stdout
    );
    // Parenthesized short IDs.
    assert!(
        stdout.contains("("),
        "event-tree should show parenthesized IDs, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_list_shows_all_events() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("event_list.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event", "list"])
        .output()
        .expect("event list command");
    assert!(
        out.status.success(),
        "event-list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Should show the event-list footer.
    assert!(
        stdout.contains("events. Sorted by insertion order."),
        "event-list should show event count footer, got:\n{}",
        stdout
    );
    // Should contain workspace event type.
    assert!(
        stdout.contains("workspace"),
        "event-list should show workspace event, got:\n{}",
        stdout
    );
    // Should show dep references with parenthesized IDs.
    assert!(
        stdout.contains("signed_by:"),
        "event-list should show dep fields, got:\n{}",
        stdout
    );
    // Should show event count footer.
    assert!(
        stdout.contains("events."),
        "event-list should show event count, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_tree_empty_db() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("empty.db").to_str().unwrap().to_string();

    // event-tree is served via daemon RPC (even for an empty db).
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event", "tree"])
        .output()
        .expect("event tree command");
    assert!(
        out.status.success(),
        "event-tree on empty db failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("no events"),
        "event-tree on empty db should say no events, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_list_empty_db() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("empty_list.db")
        .to_str()
        .unwrap()
        .to_string();

    // event-list is served via daemon RPC (even for an empty db).
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event", "list"])
        .output()
        .expect("event list command");
    assert!(
        out.status.success(),
        "event-list on empty db failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("no events"),
        "event-list on empty db should say no events, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_tree_cross_refs_shown() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("cross_ref.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event", "tree"])
        .output()
        .expect("event tree command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);

    // peer_shared has two deps (user_event_id + signed_by);
    // the tree parent is user_event_id, so signed_by should appear as a cross-ref.
    let has_cross_ref = stdout.lines().any(|line| {
        line.contains("peer_shared") && line.contains("[") && line.contains("signed_by:")
    });
    assert!(
        has_cross_ref,
        "event-tree should show cross-ref annotation on peer_shared, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_commands_require_daemon() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("no_daemon.db")
        .to_str()
        .unwrap()
        .to_string();

    let event_list = Command::new(bin())
        .args(["--db", &db, "event", "list"])
        .output()
        .expect("event list command");
    assert!(
        !event_list.status.success(),
        "event-list should fail without daemon"
    );
    let list_stderr = String::from_utf8_lossy(&event_list.stderr);
    assert!(
        list_stderr.contains("daemon is not running"),
        "event-list should report daemon requirement, got:\n{}",
        list_stderr
    );

    let event_tree = Command::new(bin())
        .args(["--db", &db, "event", "tree"])
        .output()
        .expect("event tree command");
    assert!(
        !event_tree.status.success(),
        "event-tree should fail without daemon"
    );
    let tree_stderr = String::from_utf8_lossy(&event_tree.stderr);
    assert!(
        tree_stderr.contains("daemon is not running"),
        "event-tree should report daemon requirement, got:\n{}",
        tree_stderr
    );
}

// ---------------------------------------------------------------------------
// Error-message quality tests
// ---------------------------------------------------------------------------

/// When a second daemon tries to bind the same port, it should exit with a
/// clear error about the port being in use, not silently retry forever.
#[test]
fn test_cli_port_already_in_use_error() {
    let _guard = cli_test_lock();
    let (_tmpdir_a, db_a) = temp_db();
    let (_tmpdir_b, db_b) = temp_db();

    // Daemon A binds a specific port.
    let port = random_port();
    create_workspace(&db_a);
    let _daemon_a = start_daemon_on_port(&db_a, port);

    // Daemon B tries the same port — should fail with an informative error.
    create_workspace(&db_b);
    let output = Command::new(bin())
        .arg("--db")
        .arg(&db_b)
        .arg("start")
        .arg("--bind")
        .arg(format!("127.0.0.1:{}", port))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run second daemon");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "second daemon on same port should exit with error"
    );
    assert!(
        stderr.contains("already in use") || stderr.contains("address already in use"),
        "error should mention port already in use, got:\n{}",
        stderr
    );
}

/// Connecting to an address where nothing is listening should produce a
/// human-readable diagnostic (timeout or connection refused), not raw errors.
#[test]
fn test_cli_connect_to_dead_address_error() {
    let _guard = cli_test_lock();
    let (_tmpdir_a, db_a) = temp_db();
    let (_tmpdir_b, db_b) = temp_db();

    // Alice creates workspace and generates an invite with a dead address.
    create_workspace(&db_a);
    let _daemon_a = start_daemon(&db_a);
    let dead_port = random_port();
    let invite = create_invite(&db_a, &format!("127.0.0.1:{}", dead_port));
    drop(_daemon_a); // Kill Alice's daemon so the address is dead.

    // Bob accepts the invite — daemon will try to connect to the dead address.
    // Redirect daemon output to file so we can inspect logs after shutdown.
    let log_dir = std::path::Path::new(&db_b).parent().unwrap();
    let stdout_path = log_dir.join("daemon_stdout.log");
    let stderr_path = log_dir.join("daemon_stderr.log");

    let _daemon_b = start_daemon_with_options(
        &db_b,
        &DaemonOptions {
            stdout_file: Some(stdout_path.clone()),
            stderr_file: Some(stderr_path.clone()),
            ..Default::default()
        },
    );

    // Accept invite (this triggers bootstrap connect attempts to the dead address).
    let accept_out = Command::new(bin())
        .args(["--db", &db_b, "accept", &invite])
        .output()
        .expect("accept command");
    assert!(
        accept_out.status.success(),
        "accept should succeed: {}",
        String::from_utf8_lossy(&accept_out.stderr)
    );

    // QUIC (UDP) has no TCP-style "connection refused" — dead addresses time out
    // after ~30s. Wait long enough for at least one timeout.
    std::thread::sleep(Duration::from_secs(35));

    // Stop daemon.
    let _ = Command::new(bin()).args(["--db", &db_b, "stop"]).output();
    std::thread::sleep(Duration::from_millis(500));
    drop(_daemon_b);

    let output = format!(
        "{}{}",
        std::fs::read_to_string(&stdout_path).unwrap_or_default(),
        std::fs::read_to_string(&stderr_path).unwrap_or_default()
    );

    assert!(
        output.contains("timed out")
            || output.contains("connection refused")
            || output.contains("nothing is listening")
            || output.contains("unreachable"),
        "connect-to-dead-address should produce a human-readable diagnostic \
         (timed out / connection refused / unreachable), got:\n{}",
        output
    );
    // Verify it includes our diagnostic text, not just raw error.
    assert!(
        output.contains("the peer may be offline")
            || output.contains("nothing is listening")
            || output.contains("unreachable"),
        "error should include actionable guidance, got:\n{}",
        output
    );
}

/// When peers present untrusted certificates, the error should explain it's a
/// certificate mismatch, not dump raw TLS internals.
#[test]
fn test_cli_untrusted_peer_certificate_error() {
    let _guard = cli_test_lock();
    let (_tmpdir_a, db_a) = temp_db();
    let (_tmpdir_b, db_b) = temp_db();

    // Alice creates workspace and runs daemon.
    create_workspace(&db_a);
    let port_a = random_port();
    let _daemon_a = start_daemon_on_port(&db_a, port_a);

    // Create an invite from Alice with a BOGUS SPKI fingerprint.
    // Bob will connect to Alice's real address but his client-side TLS
    // verifier will reject because Alice's real cert doesn't match the
    // bogus fingerprint in the invite.
    let bogus_spki = "aa".repeat(32); // 64 hex chars = 32 bytes of 0xaa
    let invite =
        create_invite_with_spki(&db_a, &format!("127.0.0.1:{}", port_a), Some(&bogus_spki));

    // Bob's daemon — redirect stdout to file for log inspection.
    create_workspace(&db_b);
    let log_dir_b = std::path::Path::new(&db_b).parent().unwrap();
    let bob_stdout = log_dir_b.join("daemon_stdout.log");
    let bob_stderr = log_dir_b.join("daemon_stderr.log");

    let _daemon_b = start_daemon_with_options(
        &db_b,
        &DaemonOptions {
            stdout_file: Some(bob_stdout.clone()),
            stderr_file: Some(bob_stderr.clone()),
            ..Default::default()
        },
    );

    // Accept the invite — triggers bootstrap connect attempts.
    // Bob will connect to Alice but reject her cert (wrong SPKI).
    let accept_out = Command::new(bin())
        .args(["--db", &db_b, "accept", &invite])
        .output()
        .expect("accept command");
    assert!(
        accept_out.status.success(),
        "accept should succeed: {}",
        String::from_utf8_lossy(&accept_out.stderr)
    );

    // Give time for runtime restart + TLS handshake attempts.
    std::thread::sleep(Duration::from_secs(8));

    // Stop daemons and read logs.
    let _ = Command::new(bin()).args(["--db", &db_b, "stop"]).output();
    std::thread::sleep(Duration::from_millis(500));
    drop(_daemon_b);

    let bob_log = format!(
        "{}{}",
        std::fs::read_to_string(&bob_stdout).unwrap_or_default(),
        std::fs::read_to_string(&bob_stderr).unwrap_or_default()
    );

    // Bob should see our improved error about certificate mismatch
    // (his client-side TLS verifier rejects Alice's cert because the
    // SPKI in the invite doesn't match Alice's real cert).
    assert!(
        bob_log.contains("Certificate mismatch")
            || bob_log.contains("not trusted")
            || bob_log.contains("trust_rejected"),
        "untrusted peer error should mention certificate mismatch or \
         trust rejection, got:\n{}",
        bob_log
    );
    // Should include human-readable explanation.
    assert!(
        bob_log.contains("transport identity")
            || bob_log.contains("not trusted by this workspace")
            || bob_log.contains("Certificate mismatch"),
        "error should include human-readable explanation, got:\n{}",
        bob_log
    );
    assert!(
        count_occurrences(&bob_log, "Certificate mismatch connecting to") <= 1,
        "default logging should suppress repeated identical outbound certificate mismatch warnings, got:\n{}",
        bob_log
    );
    assert!(
        count_occurrences(&bob_log, "Rejected incoming connection:") <= 1,
        "default logging should suppress repeated identical inbound certificate mismatch warnings, got:\n{}",
        bob_log
    );
}

// ---------------------------------------------------------------------------
// Subscription watch tests
// ---------------------------------------------------------------------------

/// Helper: create a subscription via CLI, return subscription id.
fn create_subscription(db: &str, name: &str, delivery: &str) -> String {
    let out = Command::new(bin())
        .args([
            "--db",
            db,
            "sub",
            "create",
            "--name",
            name,
            "--event-type",
            "message",
            "--delivery",
            delivery,
        ])
        .output()
        .expect("sub create");
    assert!(
        out.status.success(),
        "sub create failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Parse subscription id from: Created subscription "name" (id: <uuid>)
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .split("id: ")
        .nth(1)
        .and_then(|s| s.split(')').next())
        .expect("sub create should return id")
        .trim()
        .to_string()
}

/// Helper: poll a subscription by name and return stdout.
fn poll_subscription(db: &str, name: &str) -> String {
    let out = Command::new(bin())
        .args(["--db", db, "sub", "poll", name])
        .output()
        .expect("sub poll");
    assert!(
        out.status.success(),
        "sub poll failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Helper: get subscription state by name, return stdout.
fn sub_state(db: &str, name: &str) -> String {
    let out = Command::new(bin())
        .args(["--db", db, "sub", "state", name])
        .output()
        .expect("sub state");
    assert!(
        out.status.success(),
        "sub state failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Helper: wait for subscription feed to contain at least `min_count` items
/// matching `pattern`, with a timeout.
fn wait_for_sub_items(db: &str, name: &str, pattern: &str, min_count: usize, timeout: Duration) {
    let start = Instant::now();
    loop {
        let stdout = poll_subscription(db, name);
        let matches = stdout.matches(pattern).count();
        if matches >= min_count {
            return;
        }
        if start.elapsed() >= timeout {
            panic!(
                "timed out waiting for {} items matching {:?} in sub {:?}, got {}:\n{}",
                min_count, pattern, name, matches, stdout
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn test_cli_sub_watch_streams_events_to_stdout() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("watch.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    create_subscription(&db, "inbox", "full");

    // Send initial messages so watch has something to catch up on
    send_message(&db, "before-watch");
    wait_for_sub_items(&db, "inbox", "before-watch", 1, Duration::from_secs(5));

    // Ack existing items so watch starts clean
    let _ = Command::new(bin())
        .args(["--db", &db, "sub", "ack", "inbox", "--through-seq", "100"])
        .output();

    // Start watch as a child process
    let mut watch = Command::new(bin())
        .args(["--db", &db, "sub", "watch", "inbox", "--interval-ms", "100"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sub watch");

    std::thread::sleep(Duration::from_millis(300));

    // Send messages while watch is running
    send_message(&db, "live-alpha");
    send_message(&db, "live-beta");
    send_message(&db, "live-gamma");

    // Wait for watch to pick them up
    std::thread::sleep(Duration::from_secs(2));

    // Kill watch and read stdout
    let _ = watch.kill();
    let output = watch.wait_with_output().expect("wait for watch");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    assert!(
        stdout.contains("live-alpha"),
        "watch stdout should contain 'live-alpha', got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("live-beta"),
        "watch stdout should contain 'live-beta', got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("live-gamma"),
        "watch stdout should contain 'live-gamma', got:\n{}",
        stdout
    );

    // Verify output format: [seq=N] message event=... ts=... author=... | content
    assert!(
        stdout.contains("[seq="),
        "watch output should use [seq=N] format, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_sub_watch_json_output() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("watchjson.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    create_subscription(&db, "json-feed", "full");

    let mut watch = Command::new(bin())
        .args([
            "--db",
            &db,
            "sub",
            "watch",
            "json-feed",
            "--interval-ms",
            "100",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sub watch --json");

    std::thread::sleep(Duration::from_millis(300));

    send_message(&db, "json-test-msg");

    std::thread::sleep(Duration::from_secs(2));

    let _ = watch.kill();
    let output = watch.wait_with_output().expect("wait for watch");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Each non-empty line should be valid JSON
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "watch --json should produce at least one line of output"
    );

    for line in &lines {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "each watch --json line should be valid JSON, got: {}",
            line
        );
        let val = parsed.unwrap();
        assert!(
            val.get("seq").is_some(),
            "JSON output should have 'seq' field: {}",
            line
        );
        assert!(
            val.get("event_type").is_some(),
            "JSON output should have 'event_type' field: {}",
            line
        );
    }

    assert!(
        stdout.contains("json-test-msg"),
        "watch --json output should contain message content, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_sub_watch_ack_clears_pending() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("watchack.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    create_subscription(&db, "ack-feed", "full");

    let mut watch = Command::new(bin())
        .args([
            "--db",
            &db,
            "sub",
            "watch",
            "ack-feed",
            "--interval-ms",
            "100",
            "--ack",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sub watch --ack");

    std::thread::sleep(Duration::from_millis(300));

    send_message(&db, "ack-msg-1");
    send_message(&db, "ack-msg-2");

    std::thread::sleep(Duration::from_secs(2));

    let _ = watch.kill();
    let output = watch.wait_with_output().expect("wait for watch");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    assert!(
        stdout.contains("ack-msg-1"),
        "watch should have printed ack-msg-1: {}",
        stdout
    );

    // After watch with --ack exits, pending should be 0
    let state = sub_state(&db, "ack-feed");
    assert!(
        state.contains("pending=0"),
        "watch --ack should clear pending items, got: {}",
        state
    );
}

#[test]
fn test_cli_sub_multiple_delivery_modes() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("modes.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    create_subscription(&db, "full-sub", "full");
    create_subscription(&db, "id-sub", "id");
    create_subscription(&db, "changed-sub", "has_changed");

    send_message(&db, "delivery-mode-test");
    wait_for_sub_items(
        &db,
        "full-sub",
        "delivery-mode-test",
        1,
        Duration::from_secs(5),
    );

    // Full mode: should contain content
    let full_poll = Command::new(bin())
        .args(["--db", &db, "sub", "poll", "full-sub", "--json"])
        .output()
        .expect("poll full-sub");
    let full_stdout = String::from_utf8_lossy(&full_poll.stdout);
    assert!(
        full_stdout.contains("\"content\""),
        "full delivery should include content: {}",
        full_stdout
    );

    // Id mode: should have event_id but no content
    let id_poll = Command::new(bin())
        .args(["--db", &db, "sub", "poll", "id-sub", "--json"])
        .output()
        .expect("poll id-sub");
    let id_stdout = String::from_utf8_lossy(&id_poll.stdout);
    assert!(
        id_stdout.contains("\"event_id\""),
        "id delivery should include event_id: {}",
        id_stdout
    );

    // has_changed mode: state should show dirty
    let hc_state = sub_state(&db, "changed-sub");
    assert!(
        hc_state.contains("dirty=true"),
        "has_changed should show dirty=true: {}",
        hc_state
    );
}

#[test]
fn test_cli_sub_disable_enable() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("disena.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    create_subscription(&db, "toggle-sub", "full");

    // Disable
    let disable = Command::new(bin())
        .args(["--db", &db, "sub", "disable", "toggle-sub"])
        .output()
        .expect("sub disable");
    assert!(disable.status.success());

    // Send while disabled
    send_message(&db, "while-disabled");
    std::thread::sleep(Duration::from_millis(500));

    let poll = poll_subscription(&db, "toggle-sub");
    assert!(
        poll.contains("no new items"),
        "disabled sub should have no items: {}",
        poll
    );

    // Re-enable
    let enable = Command::new(bin())
        .args(["--db", &db, "sub", "enable", "toggle-sub"])
        .output()
        .expect("sub enable");
    assert!(enable.status.success());

    // Send after re-enable
    send_message(&db, "after-reenable");
    wait_for_sub_items(
        &db,
        "toggle-sub",
        "after-reenable",
        1,
        Duration::from_secs(5),
    );
}

#[test]
fn test_cli_sub_multi_tenant_isolation() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("mt.db").to_str().unwrap().to_string();
    let timeout = Duration::from_secs(10);

    // Create first workspace and start daemon
    create_workspace_with_details(&db, "alpha-space", "alice", "laptop");
    let _daemon = start_daemon(&db);

    // Create subscription for tenant 1
    create_subscription(&db, "alice-inbox", "full");

    // Send a message as tenant 1
    send_message(&db, "alice-only-msg");
    wait_for_sub_items(&db, "alice-inbox", "alice-only-msg", 1, timeout);

    // Create second workspace on the live daemon
    let create = Command::new(bin())
        .args([
            "create-workspace",
            "--db",
            &db,
            "--workspace-name",
            "beta-space",
            "--username",
            "charlie",
            "--device-name",
            "tablet",
        ])
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "create second workspace failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );

    // Wait for new tenant to become available
    let start = Instant::now();
    loop {
        let tenants = Command::new(bin())
            .args(["--db", &db, "tenant", "list"])
            .output()
            .expect("tenant list");
        let stdout = String::from_utf8_lossy(&tenants.stdout);
        if stdout.contains("alice") && stdout.contains("charlie") {
            break;
        }
        if start.elapsed() >= timeout {
            panic!("second tenant did not appear: {}", stdout);
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Daemon auto-switched to tenant 2 after create; create subscription there
    create_subscription(&db, "charlie-inbox", "full");

    // Send a message as tenant 2
    send_message(&db, "charlie-only-msg");
    wait_for_sub_items(&db, "charlie-inbox", "charlie-only-msg", 1, timeout);

    // Verify tenant 2's sub has charlie's msg
    let t2_poll = poll_subscription(&db, "charlie-inbox");
    assert!(
        t2_poll.contains("charlie-only-msg"),
        "tenant 2 should see its own message: {}",
        t2_poll
    );

    // Switch back to alice's tenant by finding its number in the list
    let list_out = Command::new(bin())
        .args(["--db", &db, "tenant", "list"])
        .output()
        .expect("tenant list");
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    let alice_index: u64 = list_stdout
        .lines()
        .find(|line| line.contains("alpha-space"))
        .and_then(|line| {
            let trimmed = line.trim_start();
            trimmed.split('.').next()?.trim().parse().ok()
        })
        .expect("alpha-space tenant should appear in list with index");
    let switch = Command::new(bin())
        .args(["--db", &db, "tenant", "use", &alice_index.to_string()])
        .output()
        .expect("tenant use alice");
    assert!(
        switch.status.success(),
        "tenant use {} failed: {}",
        alice_index,
        String::from_utf8_lossy(&switch.stderr)
    );

    // Tenant 1's sub should NOT have tenant 2's message
    let t1_poll = Command::new(bin())
        .args(["--db", &db, "sub", "poll", "alice-inbox", "--json"])
        .output()
        .expect("poll alice-inbox json");
    let t1_stdout = String::from_utf8_lossy(&t1_poll.stdout);
    assert!(
        !t1_stdout.contains("charlie-only-msg"),
        "tenant 1 should NOT see tenant 2's message: {}",
        t1_stdout
    );
    assert!(
        t1_stdout.contains("alice-only-msg"),
        "tenant 1 should still see its own message: {}",
        t1_stdout
    );
}

#[test]
fn test_cli_sub_watch_multi_tenant() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("mtwat.db").to_str().unwrap().to_string();
    let timeout = Duration::from_secs(10);

    create_workspace_with_details(&db, "alpha-space", "alice", "laptop");
    let _daemon = start_daemon(&db);

    // Create second workspace on live daemon
    let create = Command::new(bin())
        .args([
            "create-workspace",
            "--db",
            &db,
            "--workspace-name",
            "beta-space",
            "--username",
            "charlie",
            "--device-name",
            "tablet",
        ])
        .output()
        .unwrap();
    assert!(create.status.success());

    // Wait for both tenants
    let start = Instant::now();
    loop {
        let tenants = Command::new(bin())
            .args(["--db", &db, "tenant", "list"])
            .output()
            .expect("tenant list");
        let stdout = String::from_utf8_lossy(&tenants.stdout);
        if stdout.contains("alice") && stdout.contains("charlie") {
            break;
        }
        if start.elapsed() >= timeout {
            panic!("tenants did not appear");
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Active tenant is now charlie (auto-switched). Create sub and start watch.
    create_subscription(&db, "charlie-watch", "full");

    let mut watch = Command::new(bin())
        .args([
            "--db",
            &db,
            "sub",
            "watch",
            "charlie-watch",
            "--interval-ms",
            "100",
            "--ack",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn watch for charlie");

    std::thread::sleep(Duration::from_millis(300));

    send_message(&db, "charlie-watched-msg");

    std::thread::sleep(Duration::from_secs(2));

    let _ = watch.kill();
    let output = watch.wait_with_output().expect("wait for watch");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    assert!(
        stdout.contains("charlie-watched-msg"),
        "multi-tenant watch should capture message: {}",
        stdout
    );

    // After watch with --ack, pending should be 0
    let state = sub_state(&db, "charlie-watch");
    assert!(
        state.contains("pending=0"),
        "watch --ack should clear pending: {}",
        state
    );
}

#[test]
fn test_cli_sub_watch_rejects_has_changed_mode() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("hcwatch.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    create_subscription(&db, "hc-sub", "has_changed");

    let output = Command::new(bin())
        .args([
            "--db",
            &db,
            "sub",
            "watch",
            "hc-sub",
            "--interval-ms",
            "100",
        ])
        .output()
        .expect("sub watch has_changed");

    // Should fail with a clear error
    assert!(
        !output.status.success(),
        "watch on has_changed subscription should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("has_changed") && stderr.contains("no feed items"),
        "error should explain has_changed produces no feed items: {}",
        stderr
    );
}

#[test]
fn test_cli_sub_watch_exits_on_tenant_switch() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("tswitch.db")
        .to_str()
        .unwrap()
        .to_string();
    let timeout = Duration::from_secs(10);

    create_workspace_with_details(&db, "alpha-space", "alice", "laptop");
    let _daemon = start_daemon(&db);

    create_subscription(&db, "alice-watch", "full");

    // Create second workspace (auto-switches to tenant 2)
    let create = Command::new(bin())
        .args([
            "create-workspace",
            "--db",
            &db,
            "--workspace-name",
            "beta-space",
            "--username",
            "charlie",
            "--device-name",
            "tablet",
        ])
        .output()
        .unwrap();
    assert!(create.status.success());

    // Wait for both tenants
    let start = Instant::now();
    loop {
        let tenants = Command::new(bin())
            .args(["--db", &db, "tenant", "list"])
            .output()
            .expect("tenant list");
        let stdout = String::from_utf8_lossy(&tenants.stdout);
        if stdout.contains("alice") && stdout.contains("charlie") {
            break;
        }
        if start.elapsed() >= timeout {
            panic!("tenants did not appear");
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Switch back to alice's tenant and start watch
    let list_out = Command::new(bin())
        .args(["--db", &db, "tenant", "list"])
        .output()
        .expect("tenant list");
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    let alice_idx: u64 = list_stdout
        .lines()
        .find(|line| line.contains("alpha-space"))
        .and_then(|line| line.trim_start().split('.').next()?.trim().parse().ok())
        .expect("alice tenant index");
    let _ = Command::new(bin())
        .args(["--db", &db, "tenant", "use", &alice_idx.to_string()])
        .output();

    let mut watch = Command::new(bin())
        .args([
            "--db",
            &db,
            "sub",
            "watch",
            "alice-watch",
            "--interval-ms",
            "100",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn watch");

    std::thread::sleep(Duration::from_millis(500));

    // Re-parse tenant list now that alice is active (sort order may have changed)
    let list_out2 = Command::new(bin())
        .args(["--db", &db, "tenant", "list"])
        .output()
        .expect("tenant list");
    let list_stdout2 = String::from_utf8_lossy(&list_out2.stdout);
    let charlie_idx: u64 = list_stdout2
        .lines()
        .find(|line| line.contains("beta-space"))
        .and_then(|line| line.trim_start().split('.').next()?.trim().parse().ok())
        .expect("charlie tenant index");

    // Switch to charlie's tenant from another "terminal"
    let _ = Command::new(bin())
        .args(["--db", &db, "tenant", "use", &charlie_idx.to_string()])
        .output();

    // Watch should exit within a few seconds after repeated "not found" errors
    let start = Instant::now();
    loop {
        match watch.try_wait() {
            Ok(Some(status)) => {
                // Watch exited — verify it's a non-zero exit (error)
                assert!(
                    !status.success(),
                    "watch should exit with error after tenant switch"
                );
                let output = watch.wait_with_output().unwrap_or_else(|_| {
                    // Already consumed, build from what we have
                    std::process::Output {
                        status,
                        stdout: vec![],
                        stderr: vec![],
                    }
                });
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stderr.contains("no longer accessible") || stderr.contains("tenant"),
                    "error should mention tenant switch: {}",
                    stderr
                );
                return;
            }
            Ok(None) => {
                if start.elapsed() >= Duration::from_secs(5) {
                    let _ = watch.kill();
                    panic!("watch did not exit after tenant switch within 5s");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => panic!("try_wait failed: {}", e),
        }
    }
}

#[test]
fn test_cli_sub_watch_drains_backlog_on_startup() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("backlog.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    create_subscription(&db, "backlog-feed", "full");

    // Send messages BEFORE starting watch — these form the backlog
    send_message(&db, "backlog-one");
    send_message(&db, "backlog-two");
    send_message(&db, "backlog-three");
    wait_for_sub_items(&db, "backlog-feed", "backlog-", 3, Duration::from_secs(5));

    // Start watch — it should drain the backlog (cursor starts at 0)
    let mut watch = Command::new(bin())
        .args([
            "--db",
            &db,
            "sub",
            "watch",
            "backlog-feed",
            "--interval-ms",
            "100",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sub watch");

    // Give watch time to drain backlog
    std::thread::sleep(Duration::from_secs(2));

    let _ = watch.kill();
    let output = watch.wait_with_output().expect("wait for watch");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // All three backlog messages must appear in output
    assert!(
        stdout.contains("backlog-one"),
        "watch should drain backlog item 'backlog-one', got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("backlog-two"),
        "watch should drain backlog item 'backlog-two', got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("backlog-three"),
        "watch should drain backlog item 'backlog-three', got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_sub_watch_exits_on_daemon_stop() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("daemonstop.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let daemon = start_daemon(&db);

    create_subscription(&db, "ephemeral", "full");

    // Start watch
    let mut watch = Command::new(bin())
        .args([
            "--db",
            &db,
            "sub",
            "watch",
            "ephemeral",
            "--interval-ms",
            "100",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn watch");

    std::thread::sleep(Duration::from_millis(500));

    // Stop the daemon
    drop(daemon);
    wait_for_daemon_stopped(&db, Duration::from_secs(5));

    // Watch should exit on its own (non-zero) within a few seconds
    let start = Instant::now();
    loop {
        match watch.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    !status.success(),
                    "watch should exit with error when daemon stops"
                );
                let output = watch
                    .wait_with_output()
                    .unwrap_or_else(|_| std::process::Output {
                        status,
                        stdout: vec![],
                        stderr: vec![],
                    });
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stderr.contains("daemon stopped") || stderr.contains("daemon is not running"),
                    "error should mention daemon stopped: {}",
                    stderr
                );
                return;
            }
            Ok(None) => {
                if start.elapsed() >= Duration::from_secs(5) {
                    let _ = watch.kill();
                    panic!("watch did not exit after daemon stop within 5s");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => panic!("try_wait failed: {}", e),
        }
    }
}

#[test]
fn test_cli_sub_watch_escapes_multiline_content() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("multiline.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    create_subscription(&db, "ml-feed", "full");

    // Start watch
    let mut watch = Command::new(bin())
        .args([
            "--db",
            &db,
            "sub",
            "watch",
            "ml-feed",
            "--interval-ms",
            "100",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn watch");

    std::thread::sleep(Duration::from_millis(300));

    // Send a message containing a newline
    send_message(&db, "line1\nline2");

    std::thread::sleep(Duration::from_secs(2));

    let _ = watch.kill();
    let output = watch.wait_with_output().expect("wait for watch");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // The output should have the newline escaped, so "line1\nline2" appears literally
    // and the event is on a single line
    let event_lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with("[seq=")).collect();
    assert!(
        !event_lines.is_empty(),
        "watch should produce at least one event line, got:\n{}",
        stdout
    );
    // Each event line should be self-contained (the newline in content is escaped)
    for line in &event_lines {
        assert!(
            line.contains("line1\\nline2"),
            "multiline content should be escaped as 'line1\\nline2', got: {}",
            line
        );
    }
}

// ---------------------------------------------------------------------------
// Event display enhancements
// ---------------------------------------------------------------------------

#[test]
fn test_cli_event_display_default_is_tree() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("display_default.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);

    // event display (no args) reads directly from DB — no daemon needed.
    let out = Command::new(bin())
        .args(["--db", &db, "event", "display"])
        .output()
        .expect("event display command");
    assert!(
        out.status.success(),
        "event display failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tree"),
        "default display mode should be 'tree', got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_display_set_and_get() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("display_set.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);

    // Set to list
    let set_list = Command::new(bin())
        .args(["--db", &db, "event", "display", "list"])
        .output()
        .expect("event display list");
    assert!(set_list.status.success());
    let stdout = String::from_utf8_lossy(&set_list.stdout);
    assert!(
        stdout.contains("list"),
        "should confirm 'list', got:\n{}",
        stdout
    );

    // Get should now return list
    let get = Command::new(bin())
        .args(["--db", &db, "event", "display"])
        .output()
        .expect("event display get");
    assert!(get.status.success());
    let stdout = String::from_utf8_lossy(&get.stdout);
    assert!(
        stdout.contains("list"),
        "should return 'list', got:\n{}",
        stdout
    );

    // Set to off
    let set_off = Command::new(bin())
        .args(["--db", &db, "event", "display", "off"])
        .output()
        .expect("event display off");
    assert!(set_off.status.success());

    // Set back to tree
    let set_tree = Command::new(bin())
        .args(["--db", &db, "event", "display", "tree"])
        .output()
        .expect("event display tree");
    assert!(set_tree.status.success());
    let stdout = String::from_utf8_lossy(&set_tree.stdout);
    assert!(
        stdout.contains("tree"),
        "should confirm 'tree', got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_show_by_prefix() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("event_show.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // Get event list to find a prefix
    let list_out = Command::new(bin())
        .args(["--db", &db, "event", "list"])
        .output()
        .expect("event list");
    assert!(list_out.status.success());
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);

    // Extract a short ID from the first event line: "(XXXXXXXX) type ..."
    let first_id = list_stdout
        .lines()
        .find_map(|line| {
            let start = line.find('(')?;
            let end = line.find(')')?;
            Some(line[start + 1..end].to_string())
        })
        .expect("should have at least one event in list output");

    // Use first 4 chars as prefix
    let prefix = &first_id[..4.min(first_id.len())];
    let show_out = Command::new(bin())
        .args(["--db", &db, "event", "show", prefix])
        .output()
        .expect("event show command");
    assert!(
        show_out.status.success(),
        "event show failed: {}",
        String::from_utf8_lossy(&show_out.stderr)
    );
    let show_stdout = String::from_utf8_lossy(&show_out.stdout);
    assert!(
        show_stdout.contains(prefix),
        "event show output should contain the prefix '{}', got:\n{}",
        prefix,
        show_stdout
    );
}

#[test]
fn test_cli_event_show_no_match() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("event_show_none.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event", "show", "ZZZZZZZ_no_match"])
        .output()
        .expect("event show command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No events matching"),
        "event show should report no match, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_deps_shows_reverse_tree() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("event_deps.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // Get event list to find a peer_shared event (has deps)
    let list_out = Command::new(bin())
        .args(["--db", &db, "event", "list"])
        .output()
        .expect("event list");
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);

    // Find a peer_shared event and its ID
    let peer_shared_id = list_stdout
        .lines()
        .find_map(|line| {
            if line.contains("peer_shared") && line.contains("(") {
                let start = line.find('(')?;
                let end = line.find(')')?;
                Some(line[start + 1..end].to_string())
            } else {
                None
            }
        })
        .expect("should have a peer_shared event");

    let deps_out = Command::new(bin())
        .args(["--db", &db, "event", "deps", &peer_shared_id])
        .output()
        .expect("event deps command");
    assert!(
        deps_out.status.success(),
        "event deps failed: {}",
        String::from_utf8_lossy(&deps_out.stderr)
    );
    let deps_stdout = String::from_utf8_lossy(&deps_out.stdout);

    // Should contain the root event type
    assert!(
        deps_stdout.contains("peer_shared"),
        "deps output should contain peer_shared, got:\n{}",
        deps_stdout
    );
    // Should show dependency relationships
    assert!(
        deps_stdout.contains("├──") || deps_stdout.contains("└──"),
        "deps output should show tree connectors, got:\n{}",
        deps_stdout
    );
    // Should contain 'root' markers for root events
    assert!(
        deps_stdout.contains("root"),
        "deps output should mark root events, got:\n{}",
        deps_stdout
    );
    // Should show unique events footer
    assert!(
        deps_stdout.contains("unique events"),
        "deps output should show unique events count, got:\n{}",
        deps_stdout
    );
}

#[test]
fn test_cli_event_deps_depth_limit() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("event_deps_depth.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // Find a peer_shared event
    let list_out = Command::new(bin())
        .args(["--db", &db, "event", "list"])
        .output()
        .expect("event list");
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);

    let peer_shared_id = list_stdout
        .lines()
        .find_map(|line| {
            if line.contains("peer_shared") && line.contains("(") {
                let start = line.find('(')?;
                let end = line.find(')')?;
                Some(line[start + 1..end].to_string())
            } else {
                None
            }
        })
        .expect("should have a peer_shared event");

    // depth=1 should truncate
    let d1 = Command::new(bin())
        .args([
            "--db",
            &db,
            "event",
            "deps",
            &peer_shared_id,
            "--depth",
            "1",
        ])
        .output()
        .expect("event deps --depth 1");
    assert!(d1.status.success());
    let d1_stdout = String::from_utf8_lossy(&d1.stdout);

    // depth=5 should show more
    let d5 = Command::new(bin())
        .args([
            "--db",
            &db,
            "event",
            "deps",
            &peer_shared_id,
            "--depth",
            "5",
        ])
        .output()
        .expect("event deps --depth 5");
    assert!(d5.status.success());
    let d5_stdout = String::from_utf8_lossy(&d5.stdout);

    // depth=5 output should be at least as long as depth=1
    assert!(
        d5_stdout.lines().count() >= d1_stdout.lines().count(),
        "depth=5 ({} lines) should be >= depth=1 ({} lines)",
        d5_stdout.lines().count(),
        d1_stdout.lines().count()
    );
}

#[test]
fn test_cli_send_shows_created_events_with_display_tree() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("send_display.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    ensure_active_peer(&db, Duration::from_secs(10));

    // Ensure display mode is tree (default)
    let _ = Command::new(bin())
        .args(["--db", &db, "event", "display", "tree"])
        .output();

    let send_out = Command::new(bin())
        .args(["--db", &db, "send", "display-test-msg"])
        .output()
        .expect("send command");
    assert!(
        send_out.status.success(),
        "send failed: {}",
        String::from_utf8_lossy(&send_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&send_out.stdout);

    // Should contain the standard "Sent:" line
    assert!(
        stdout.contains("Sent:"),
        "should show Sent:, got:\n{}",
        stdout
    );
    // Should show the event_id line
    assert!(
        stdout.contains("event_id:"),
        "should show event_id:, got:\n{}",
        stdout
    );
    // Should show the created event with decrypted content
    assert!(
        stdout.contains("encrypted") || stdout.contains("display-test-msg"),
        "should show created event tree or message content, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_send_suppressed_with_display_off() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("send_display_off.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    ensure_active_peer(&db, Duration::from_secs(10));

    // Set display mode to off
    let _ = Command::new(bin())
        .args(["--db", &db, "event", "display", "off"])
        .output();

    let send_out = Command::new(bin())
        .args(["--db", &db, "send", "quiet-msg"])
        .output()
        .expect("send command");
    assert!(send_out.status.success());
    let stdout = String::from_utf8_lossy(&send_out.stdout);

    // Should contain the standard output
    assert!(
        stdout.contains("Sent:"),
        "should show Sent:, got:\n{}",
        stdout
    );
    // Should NOT contain tree connectors or event count footer
    assert!(
        !stdout.contains("events."),
        "display=off should suppress event display, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_tree_shows_annotations() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("annotations.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event", "tree"])
        .output()
        .expect("event tree command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Check that annotations (em-dash phrases) are present
    assert!(
        stdout.contains("creates the workspace"),
        "should show workspace annotation, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("registers the user"),
        "should show user annotation, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("registers a device"),
        "should show peer_shared annotation, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("grants admin rights"),
        "should show admin annotation, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("stores a local signing key"),
        "should show peer_secret annotation, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_create_workspace_shows_created_events() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("cw_display.db")
        .to_str()
        .unwrap()
        .to_string();

    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "create-workspace",
            "--workspace-name",
            "test",
            "--username",
            "alice",
            "--device-name",
            "dev",
        ])
        .output()
        .expect("create-workspace command");
    assert!(
        out.status.success(),
        "create-workspace failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Should show the standard output
    assert!(
        stdout.contains("peer_id:"),
        "should show peer_id, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("workspace_id:"),
        "should show workspace_id, got:\n{}",
        stdout
    );
    // Should show created events tree with annotations
    assert!(
        stdout.contains("creates the workspace"),
        "should show workspace event annotation, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("events."),
        "should show event count footer, got:\n{}",
        stdout
    );
}
