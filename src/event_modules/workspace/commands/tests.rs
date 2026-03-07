use super::*;
use crate::crypto::{event_id_to_base64, EventId};
use crate::db::{open_in_memory, schema::create_tables};
use ed25519_dalek::SigningKey;

fn peer_id_for_signing_key(key: &SigningKey) -> String {
    hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &key.verifying_key().to_bytes(),
    ))
}

#[test]
fn create_user_invite_materializes_pending_bootstrap_trust_via_projection() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");

    let workspace =
        create_workspace(&conn, "bootstrap", "ws", "alice", "laptop").expect("create workspace");
    let recorded_by = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &workspace.peer_shared_key.verifying_key().to_bytes(),
    ));

    // Use a bootstrap SPKI that is not already present in peers_shared so
    // pending bootstrap trust is materialized by projection.
    let bootstrap_spki = [0xAB; 32];
    let admin_event_id: EventId = conn
        .query_row(
            "SELECT event_id FROM admins WHERE recorded_by = ?1 ORDER BY event_id ASC LIMIT 1",
            rusqlite::params![&recorded_by],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
        .expect("workspace bootstrap must create an admin event");

    let bootstrap_addrs = vec![super::super::invite_link::BootstrapAddress::Ipv4 {
        ip: "127.0.0.1".parse().unwrap(),
        port: 4433,
    }];
    let invite = create_user_invite(
        &conn,
        &recorded_by,
        &workspace.peer_shared_key,
        &workspace.peer_shared_event_id,
        &admin_event_id,
        &workspace.workspace_id,
        &bootstrap_addrs,
        &bootstrap_spki,
    )
    .expect("create user invite");

    let invite_event_b64 = event_id_to_base64(&invite.invite_event_id);
    let pending_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
                 WHERE recorded_by = ?1 AND invite_event_id = ?2",
            rusqlite::params![recorded_by, invite_event_b64],
            |row| row.get(0),
        )
        .expect("query pending rows");
    assert_eq!(
        pending_rows, 1,
        "pending trust row should be materialized by projection path"
    );
}

#[test]
fn create_workspace_rejects_unscoped_recorded_by_when_creds_exist() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");

    // Seed an existing tenant identity.
    let (cert, key) = crate::transport::generate_self_signed_cert().expect("generate cert");
    let fp = crate::transport::extract_spki_fingerprint(cert.as_ref()).expect("extract spki");
    let tenant_peer_id = hex::encode(fp);
    crate::db::transport_creds::store_local_creds(
        &conn,
        &tenant_peer_id,
        cert.as_ref(),
        key.secret_pkcs8_der(),
    )
    .expect("store transport creds");

    let err = match create_workspace(&conn, "bootstrap", "ws", "alice", "laptop") {
        Ok(_) => panic!("unscoped recorded_by should be rejected when creds exist"),
        Err(e) => e,
    };
    assert!(
        err.to_string()
            .contains("create_workspace requires scoped tenant identity"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn create_workspace_for_db_scopes_to_existing_transport_identity_when_workspace_missing() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let db_path = dir.path().join("db.sqlite");
    let db_path = db_path.to_string_lossy().to_string();
    let conn = crate::db::open_connection(&db_path).expect("open db");
    create_tables(&conn).expect("create tables");

    // Seed only local transport creds (no workspace/trust anchor rows yet).
    let (cert, key) = crate::transport::generate_self_signed_cert().expect("generate cert");
    let fp = crate::transport::extract_spki_fingerprint(cert.as_ref()).expect("extract spki");
    let seeded_peer_id = hex::encode(fp);
    crate::db::transport_creds::store_local_creds(
        &conn,
        &seeded_peer_id,
        cert.as_ref(),
        key.secret_pkcs8_der(),
    )
    .expect("store transport creds");
    drop(conn);

    let resp = create_workspace_for_db(&db_path, "ws", "alice", "laptop")
        .expect("create workspace should succeed with existing scoped transport identity");
    assert!(
        !resp.workspace_id.is_empty(),
        "workspace id should be populated"
    );
    assert!(!resp.peer_id.is_empty(), "peer id should be populated");

    // Resulting tenant scope should resolve to the created peer identity even
    // when multiple local transport creds exist.
    let conn2 = crate::db::open_connection(&db_path).expect("re-open db");
    let tenants =
        crate::db::transport_creds::discover_local_tenants(&conn2).expect("discover tenants");
    assert_eq!(tenants.len(), 1, "exactly one tenant scope should resolve");
    assert_eq!(tenants[0].peer_id, resp.peer_id);
}

#[test]
fn join_workspace_replays_existing_same_workspace_shared_events_for_new_tenant() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");

    let workspace =
        create_workspace(&conn, "bootstrap", "ws", "alice", "laptop").expect("create workspace");
    let creator_peer_id = peer_id_for_signing_key(&workspace.peer_shared_key);
    let creator_admin_eid: EventId = conn
        .query_row(
            "SELECT event_id FROM admins WHERE recorded_by = ?1 ORDER BY event_id ASC LIMIT 1",
            rusqlite::params![&creator_peer_id],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
        .expect("creator admin event");

    let invite = create_user_invite_raw(
        &conn,
        &creator_peer_id,
        &workspace.peer_shared_key,
        &workspace.peer_shared_event_id,
        &creator_admin_eid,
        &workspace.workspace_id,
    )
    .expect("create invite");

    let bob_key = SigningKey::from_bytes(&[7u8; 32]);
    let bob_peer_id = peer_id_for_signing_key(&bob_key);
    let join = join_workspace_as_new_user(
        &conn,
        &bob_peer_id,
        &invite.invite_key,
        &invite.invite_event_id,
        workspace.workspace_id,
        "bob",
        "tablet",
        bob_key,
    )
    .expect("join workspace");
    persist_join_peer_secret(&conn, &bob_peer_id, &join).expect("persist peer secret");

    let bob_usernames: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT username FROM users WHERE recorded_by = ?1 ORDER BY username")
            .expect("prepare users query");
        stmt.query_map(rusqlite::params![&bob_peer_id], |row| {
            row.get::<_, String>(0)
        })
        .expect("query users")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect users")
    };
    assert_eq!(bob_usernames, vec!["alice".to_string(), "bob".to_string()]);

    let invite_valid: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&bob_peer_id, event_id_to_base64(&invite.invite_event_id)],
            |row| row.get(0),
        )
        .expect("query valid invite");
    assert!(
        invite_valid,
        "existing invite event should be projected for the new tenant"
    );

    let signer = load_local_peer_signer(&conn, &bob_peer_id)
        .expect("load peer signer")
        .expect("peer signer should materialize without network");
    assert_eq!(signer.0, join.peer_shared_event_id);

    let blocked_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
            rusqlite::params![&bob_peer_id],
            |row| row.get(0),
        )
        .expect("query blocked events");
    assert_eq!(
        blocked_count, 0,
        "join should not leave blocked local events"
    );
}

#[test]
fn add_device_replays_existing_same_workspace_shared_events_for_new_device() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");

    let workspace =
        create_workspace(&conn, "bootstrap", "ws", "alice", "laptop").expect("create workspace");
    let creator_peer_id = peer_id_for_signing_key(&workspace.peer_shared_key);
    let creator_admin_eid: EventId = conn
        .query_row(
            "SELECT event_id FROM admins WHERE recorded_by = ?1 ORDER BY event_id ASC LIMIT 1",
            rusqlite::params![&creator_peer_id],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
        .expect("creator admin event");
    let creator_user_eid: EventId = conn
        .query_row(
            "SELECT event_id FROM users WHERE recorded_by = ?1 ORDER BY event_id ASC LIMIT 1",
            rusqlite::params![&creator_peer_id],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
        .expect("creator user event");

    let invite = create_device_link_invite_raw(
        &conn,
        &creator_peer_id,
        &workspace.peer_shared_key,
        &workspace.peer_shared_event_id,
        &creator_admin_eid,
        &creator_user_eid,
        &workspace.workspace_id,
    )
    .expect("create device-link invite");

    let phone_key = SigningKey::from_bytes(&[8u8; 32]);
    let phone_peer_id = peer_id_for_signing_key(&phone_key);
    let link = add_device_to_workspace(
        &conn,
        &phone_peer_id,
        &invite.invite_key,
        &invite.invite_event_id,
        workspace.workspace_id,
        creator_user_eid,
        "phone",
        phone_key,
    )
    .expect("add device to workspace");
    persist_link_peer_secret(&conn, &phone_peer_id, &link).expect("persist link peer secret");

    let signer = load_local_peer_signer(&conn, &phone_peer_id)
        .expect("load peer signer")
        .expect("linked device signer should materialize without network");
    assert_eq!(signer.0, link.peer_shared_event_id);

    let account_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
            rusqlite::params![&phone_peer_id],
            |row| row.get(0),
        )
        .expect("query peers_shared");
    assert_eq!(
        account_count, 2,
        "linked device should project both the existing account and its own peer_shared row"
    );

    let blocked_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
            rusqlite::params![&phone_peer_id],
            |row| row.get(0),
        )
        .expect("query blocked events");
    assert_eq!(
        blocked_count, 0,
        "device link should not leave blocked local events"
    );
}
