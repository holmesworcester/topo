mod cli_harness;

use cli_harness::*;
use std::sync::{Mutex, OnceLock};
use topo::event_modules::workspace::invite_link::{
    parse_bootstrap_address, parse_invite_link, rewrite_bootstrap_addrs,
};
use topo::testutil::DaemonGuard;

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

fn reserve_wrong_bootstrap_addr() -> (std::net::UdpSocket, String) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind reserved wrong udp port");
    let addr = socket
        .local_addr()
        .expect("read reserved wrong udp port")
        .to_string();
    (socket, addr)
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

fn rewrite_invite_addrs(invite_link: &str, addrs: &[&str]) -> String {
    let parsed = addrs
        .iter()
        .map(|addr| parse_bootstrap_address(addr).expect("parse bootstrap address"))
        .collect::<Vec<_>>();
    rewrite_bootstrap_addrs(invite_link, &parsed).expect("rewrite invite bootstrap addrs")
}

fn start_linked_cli_peer(
    tmpdir: &tempfile::TempDir,
    db_name: &str,
    invite_link: &str,
    username: &str,
    device_name: &str,
) -> StartedCliPeer {
    let db = tmpdir.path().join(db_name).to_str().unwrap().to_string();
    let empty_bootstrap = matches!(
        parse_invite_link(invite_link),
        Ok(invite) if invite.bootstrap_addrs.is_empty()
    );
    let daemon = if empty_bootstrap {
        accept_device_link_with_name_and_timeout(
            &db,
            invite_link,
            device_name,
            std::time::Duration::from_secs(20),
        );
        start_discovery_daemon(&db)
    } else {
        let daemon = start_daemon(&db);
        accept_device_link_with_name_on_running_daemon(
            &db,
            invite_link,
            device_name,
            std::time::Duration::from_secs(10),
        );
        daemon
    };
    wait_for_active_tenant_ready(&db, std::time::Duration::from_secs(120));
    StartedCliPeer {
        db,
        username: username.to_string(),
        device_name: device_name.to_string(),
        _daemon: daemon,
    }
}

fn start_linked_cli_peer_via_discovery(
    tmpdir: &tempfile::TempDir,
    db_name: &str,
    invite_link: &str,
    username: &str,
    device_name: &str,
) -> StartedCliPeer {
    let db = tmpdir.path().join(db_name).to_str().unwrap().to_string();
    accept_device_link_with_name_and_timeout(
        &db,
        invite_link,
        device_name,
        std::time::Duration::from_secs(20),
    );
    let daemon = start_discovery_daemon(&db);
    wait_for_active_tenant_ready(&db, std::time::Duration::from_secs(120));
    StartedCliPeer {
        db,
        username: username.to_string(),
        device_name: device_name.to_string(),
        _daemon: daemon,
    }
}

fn assert_event_visible_on_all(db_paths: &[&str], event_id: &str, timeout_ms: u64) {
    for db_path in db_paths {
        assert_eventually(db_path, &format!("has_event:{} >= 1", event_id), timeout_ms);
    }
}

#[test]
#[cfg(feature = "discovery")]
fn test_cli_device_link_mixed_topology_empty_explicit_and_wrong_only() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let timeout_ms = 180_000;
    let workspace_name = "device-link-mixed-topology";

    let phone_db = tmpdir.path().join("phone.db").to_str().unwrap().to_string();
    create_workspace_with_details(&phone_db, workspace_name, "alice", "phone");
    let phone = StartedCliPeer {
        db: phone_db,
        username: "alice".to_string(),
        device_name: "phone".to_string(),
        _daemon: start_discovery_daemon(
            tmpdir
                .path()
                .join("phone.db")
                .to_str()
                .expect("phone db path"),
        ),
    };
    let _phone_tenant = phone.tenant_label();
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

    let laptop = start_linked_cli_peer(&tmpdir, "laptop.db", &empty_link, "alice", "laptop");
    let _laptop_tenant = laptop.tenant_label();
    assert_event_visible_on_all(&[&laptop.db], &phone_base_eid, timeout_ms);
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
            &format!("127.0.0.1:{}", laptop_live_port),
        ],
    );

    let tablet = start_linked_cli_peer(&tmpdir, "tablet.db", &explicit_link, "alice", "tablet");
    let _tablet_tenant = tablet.tenant_label();
    assert_event_visible_on_all(&[&tablet.db], &phone_base_eid, timeout_ms);
    assert_event_visible_on_all(&[&tablet.db], &laptop_eid, timeout_ms);
    let tablet_msg = "device-link-mixed/tablet-step-3";
    let tablet_eid = send_message(&tablet.db, tablet_msg);
    assert_event_visible_on_all(
        &[&phone.db, &laptop.db, &tablet.db],
        &tablet_eid,
        timeout_ms,
    );

    let (_wrong_addr_guard, wrong_addr) = reserve_wrong_bootstrap_addr();
    let wrong_link = rewrite_invite_addrs(
        &create_device_link(&phone.db, &daemon_listen_addr(&phone.db)),
        &[&wrong_addr],
    );
    let desktop =
        start_linked_cli_peer_via_discovery(&tmpdir, "desktop.db", &wrong_link, "alice", "desktop");
    let _desktop_tenant = desktop.tenant_label();
    assert_event_visible_on_all(&[&desktop.db], &phone_base_eid, timeout_ms);
    assert_event_visible_on_all(&[&desktop.db], &laptop_eid, timeout_ms);
    assert_event_visible_on_all(&[&desktop.db], &tablet_eid, timeout_ms);
    let desktop_msg = "device-link-mixed/desktop-step-4";
    let desktop_eid = send_message(&desktop.db, desktop_msg);
    assert_event_visible_on_all(
        &[&phone.db, &laptop.db, &tablet.db, &desktop.db],
        &desktop_eid,
        timeout_ms,
    );

    for db in [&phone.db, &laptop.db, &tablet.db, &desktop.db] {
        assert_eventually(db, "message_count >= 4", timeout_ms);
    }
}
