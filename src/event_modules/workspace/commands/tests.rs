use super::*;
use crate::crypto::{event_id_to_base64, EventId};
use crate::db::{open_in_memory, schema::create_tables};
use crate::event_modules::workspace::command_plans;
use crate::event_modules::{parse_event, ParsedEvent, RemovalEvent};
use crate::projection::create::create_signed_event;
use ed25519_dalek::SigningKey;

fn peer_id_for_signing_key(key: &SigningKey) -> String {
    hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &key.verifying_key().to_bytes(),
    ))
}

fn materialize_local_daemon_identity(conn: &rusqlite::Connection) {
    crate::transport::materialize_daemon_identity(conn).expect("materialize daemon identity");
}

fn record_invite_link_workspace(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    invite_event_id: &EventId,
    workspace_id: EventId,
) {
    crate::db::transport_trust::append_bootstrap_context(
        conn,
        recorded_by,
        &event_id_to_base64(invite_event_id),
        &event_id_to_base64(&workspace_id),
        "",
        &[0xAB; 32],
    )
    .expect("record invite-link workspace binding");
}

fn create_local_removal(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    signing_key: &SigningKey,
    removed_member_ref: EventId,
    parent_refs: &[EventId],
) -> EventId {
    let slots = crate::event_modules::removal::canonicalize_frontier_refs(parent_refs)
        .expect("canonical removal frontier refs");
    assert!(
        slots.len() <= crate::event_modules::removal::MAX_REMOVAL_FRONTIER_REFS,
        "test frontier should fit in event slots"
    );
    let mut parent_slots = [[0u8; 32]; crate::event_modules::removal::MAX_REMOVAL_FRONTIER_REFS];
    for (slot, event_id) in parent_slots.iter_mut().zip(slots.iter()) {
        *slot = *event_id;
    }
    let removal = ParsedEvent::Removal(RemovalEvent {
        created_at_ms: 9_000,
        removed_member_ref,
        parent_count: slots.len() as u8,
        parent_1: parent_slots[0],
        parent_2: parent_slots[1],
        parent_3: parent_slots[2],
        parent_4: parent_slots[3],
        frontier_hash: crate::event_modules::removal::frontier_hash_from_refs(&slots),
        removed_by: *signer_event_id,
    });
    create_signed_event(conn, recorded_by, signer_event_id, &removal, signing_key)
        .expect("create signed removal")
}

fn encrypted_wrapper_key_event_id(
    conn: &rusqlite::Connection,
    wrapper_event_id: &EventId,
) -> EventId {
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT blob FROM events WHERE event_id = ?1",
            rusqlite::params![event_id_to_base64(wrapper_event_id)],
            |row| crate::db::sql_types::get_blob(row, 0),
        )
        .expect("load encrypted wrapper blob");
    let raw_key_event_id = match parse_event(&blob).expect("parse encrypted wrapper") {
        ParsedEvent::Encrypted(enc) => enc.key_event_id,
        ParsedEvent::Signed(signed) => {
            match parse_event(&signed.payload).expect("parse signed wrapper payload") {
                ParsedEvent::Encrypted(enc) => enc.key_event_id,
                other => panic!("expected signed encrypted wrapper, got {:?}", other),
            }
        }
        other => panic!("expected encrypted wrapper, got {:?}", other),
    };
    // Option C: the Encrypted.key_event_id points at a per-message
    // `message_key` event, not the rotation/content-key event itself.
    // Walk one hop into the message_key to recover the underlying
    // `k_bundle_local_event_id` (which equals the rotation event id
    // under the send-time helper
    // `create_encrypted_event_with_message_key_via_rotation`). Return
    // that so existing assertions comparing wrapper ↔ content-key
    // reuse continue to match.
    let key_blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT blob FROM events WHERE event_id = ?1",
            rusqlite::params![event_id_to_base64(&raw_key_event_id)],
            |row| crate::db::sql_types::get_blob(row, 0),
        )
        .ok();
    if let Some(key_blob) = key_blob {
        if let Ok(ParsedEvent::MessageKey(mk)) = parse_event(&key_blob) {
            return mk.k_bundle_local_event_id;
        }
    }
    raw_key_event_id
}

#[test]
fn create_workspace_with_seeded_history_ages_auth_chain_and_messages() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");
    materialize_local_daemon_identity(&conn);

    let end_at_ms = 90_u64 * 24 * 60 * 60 * 1000;
    let network_age_ms = 30_u64 * 24 * 60 * 60 * 1000;
    let workspace = create_workspace_with_options(
        &conn,
        "bootstrap",
        "ws",
        "alice",
        "laptop",
        CreateWorkspaceOptions {
            message_count: 4,
            network_age_ms: Some(network_age_ms),
            end_at_ms: Some(end_at_ms),
        },
    )
    .expect("create workspace with seeded history");
    let peer_id = peer_id_for_signing_key(&workspace.peer_shared_key);
    let network_start_ms = end_at_ms.saturating_sub(network_age_ms) as i64;

    let message_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&peer_id],
            |row| row.get(0),
        )
        .expect("count seeded messages");
    assert_eq!(message_count, 4);

    let user_event_id: String = conn
        .query_row(
            "SELECT u.event_id
             FROM users u
             JOIN events e ON e.event_id = u.event_id
             WHERE u.recorded_by = ?1
             ORDER BY e.created_at ASC, u.event_id ASC
             LIMIT 1",
            rusqlite::params![&peer_id],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .expect("load creator user event");
    let user_created_at_ms: i64 = conn
        .query_row(
            "SELECT MIN(e.created_at)
             FROM users u
             JOIN events e ON e.event_id = u.event_id
             WHERE u.recorded_by = ?1",
            rusqlite::params![&peer_id],
            |row| row.get(0),
        )
        .expect("load creator user timestamp");
    let peer_shared_created_at_ms: i64 = conn
        .query_row(
            "SELECT MIN(e.created_at)
             FROM peers_shared ps
             JOIN events e ON e.event_id = ps.event_id
             WHERE ps.recorded_by = ?1",
            rusqlite::params![&peer_id],
            |row| row.get(0),
        )
        .expect("load creator peer_shared timestamp");
    let newest_message_author_id: String = conn
        .query_row(
            "SELECT author_id FROM messages WHERE recorded_by = ?1 ORDER BY created_at DESC, message_id DESC LIMIT 1",
            rusqlite::params![&peer_id],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .expect("load newest message author");
    let newest_message_created_at_ms: i64 = conn
        .query_row(
            "SELECT MAX(created_at) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&peer_id],
            |row| row.get(0),
        )
        .expect("load newest message timestamp");

    assert_eq!(newest_message_author_id, user_event_id);
    assert_eq!(newest_message_created_at_ms, end_at_ms as i64);
    assert!(
        user_created_at_ms >= network_start_ms && user_created_at_ms < network_start_ms + 16,
        "user event should be near network start: user_created_at_ms={} network_start_ms={}",
        user_created_at_ms,
        network_start_ms
    );
    assert!(
        peer_shared_created_at_ms >= network_start_ms
            && peer_shared_created_at_ms < network_start_ms + 16,
        "peer_shared event should be near network start: peer_shared_created_at_ms={} network_start_ms={}",
        peer_shared_created_at_ms,
        network_start_ms
    );
}

#[test]
fn create_user_invite_materializes_pending_bootstrap_trust_via_projection() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");
    materialize_local_daemon_identity(&conn);

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
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .ok()
        .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
        .expect("workspace bootstrap must create an admin event");

    let bootstrap_addrs = Vec::new();
    let invite = create_user_invite(
        &conn,
        &recorded_by,
        &workspace.peer_shared_key,
        &workspace.peer_shared_event_id,
        &admin_event_id,
        &workspace.workspace_id,
        &bootstrap_addrs,
        &bootstrap_spki,
        None,
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

    let origin_project_queue_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&recorded_by, &invite_event_b64],
            |row| row.get(0),
        )
        .expect("query origin project_queue rows");
    assert_eq!(
        origin_project_queue_rows, 0,
        "bootstrap-context local create should not rely on origin project_queue recovery rows"
    );

    let pending_fanout_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_shared_fanouts
             WHERE origin_peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&recorded_by, invite.invite_event_id.as_slice()],
            |row| row.get(0),
        )
        .expect("query pending fanout rows");
    assert_eq!(
        pending_fanout_rows, 0,
        "bootstrap-context local create should not leave create-side pending fanout recovery rows"
    );
}

#[test]
fn create_device_link_materializes_pending_bootstrap_trust_via_projection() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");
    materialize_local_daemon_identity(&conn);

    let workspace =
        create_workspace(&conn, "bootstrap", "ws", "alice", "laptop").expect("create workspace");
    let recorded_by = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &workspace.peer_shared_key.verifying_key().to_bytes(),
    ));

    let user_event_id: EventId = conn
        .query_row(
            "SELECT event_id FROM users WHERE recorded_by = ?1 ORDER BY event_id ASC LIMIT 1",
            rusqlite::params![&recorded_by],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .ok()
        .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
        .expect("workspace bootstrap must create a user event");

    let bootstrap_spki = [0xCD; 32];
    let bootstrap_addrs = Vec::new();
    let invite = create_device_link_invite(
        &conn,
        &recorded_by,
        &workspace.peer_shared_key,
        &workspace.peer_shared_event_id,
        &user_event_id,
        &workspace.workspace_id,
        &bootstrap_addrs,
        &bootstrap_spki,
        None,
    )
    .expect("create device link");

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
        "device-link projection should materialize pending bootstrap trust"
    );
}

#[test]
fn create_workspace_allows_unscoped_recorded_by_when_creds_exist_and_creates_new_tenant() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");
    materialize_local_daemon_identity(&conn);
    let daemon_peer_id = crate::transport::load_local_daemon_endpoint_id(&conn)
        .expect("load daemon endpoint id")
        .expect("daemon endpoint id");

    let created = create_workspace(&conn, "bootstrap", "ws", "alice", "laptop")
        .expect("unscoped bootstrap should still create a new workspace tenant");
    let created_peer_id = peer_id_for_signing_key(&created.peer_shared_key);
    assert_ne!(
        created_peer_id, daemon_peer_id,
        "create_workspace should mint a tenant identity instead of reusing the daemon endpoint identity"
    );

    let tenants =
        crate::db::transport_creds::discover_local_tenants(&conn).expect("discover tenants");
    assert_eq!(
        tenants.len(),
        1,
        "only the created workspace should resolve as a tenant"
    );
    assert_eq!(tenants[0].peer_id, created_peer_id);
}

#[test]
fn create_workspace_for_db_creates_new_tenant_when_workspace_missing() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let db_path = dir.path().join("db.sqlite");
    let db_path = db_path.to_string_lossy().to_string();
    let conn = crate::db::open_connection(&db_path).expect("open db");
    create_tables(&conn).expect("create tables");
    drop(conn);
    let seeded_peer_id = crate::transport::materialize_daemon_identity_from_db(&db_path)
        .expect("materialize daemon identity")
        .0;

    let resp = create_workspace_for_db(&db_path, "ws", "alice", "laptop")
        .expect("create workspace should succeed with materialized daemon identity");
    assert!(
        !resp.workspace_id.is_empty(),
        "workspace id should be populated"
    );
    assert!(!resp.peer_id.is_empty(), "peer id should be populated");
    assert_ne!(
        resp.peer_id, seeded_peer_id,
        "create_workspace_for_db should mint a new tenant instead of reusing the preexisting transport identity"
    );

    // Resulting tenant scope should resolve to the created peer identity even
    // when multiple local transport creds exist.
    let conn2 = crate::db::open_connection(&db_path).expect("re-open db");
    let tenants =
        crate::db::transport_creds::discover_local_tenants(&conn2).expect("discover tenants");
    assert_eq!(tenants.len(), 1, "exactly one tenant scope should resolve");
    assert_eq!(tenants[0].peer_id, resp.peer_id);
}

#[test]
fn create_workspace_requires_materialized_daemon_identity() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");

    let err = match create_workspace(&conn, "bootstrap", "ws", "alice", "laptop") {
        Ok(_) => panic!("create_workspace should fail without daemon identity"),
        Err(err) => err,
    };
    assert_eq!(
        err.to_string(),
        command_plans::MISSING_LOCAL_DAEMON_ENDPOINT_SHARED_ERROR
    );
}

#[test]
fn join_workspace_replays_existing_same_workspace_shared_events_for_new_tenant() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");
    materialize_local_daemon_identity(&conn);

    let workspace =
        create_workspace(&conn, "bootstrap", "ws", "alice", "laptop").expect("create workspace");
    let creator_peer_id = peer_id_for_signing_key(&workspace.peer_shared_key);
    let creator_admin_eid: EventId = conn
        .query_row(
            "SELECT event_id FROM admins WHERE recorded_by = ?1 ORDER BY event_id ASC LIMIT 1",
            rusqlite::params![&creator_peer_id],
            |row| crate::db::sql_types::get_text(row, 0),
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
    record_invite_link_workspace(
        &conn,
        &bob_peer_id,
        &invite.invite_event_id,
        workspace.workspace_id,
    );
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
            crate::db::sql_types::get_text(row, 0)
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
    materialize_local_daemon_identity(&conn);

    let workspace =
        create_workspace(&conn, "bootstrap", "ws", "alice", "laptop").expect("create workspace");
    let creator_peer_id = peer_id_for_signing_key(&workspace.peer_shared_key);
    let creator_user_eid: EventId = conn
        .query_row(
            "SELECT event_id FROM users WHERE recorded_by = ?1 ORDER BY event_id ASC LIMIT 1",
            rusqlite::params![&creator_peer_id],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .ok()
        .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
        .expect("creator user event");
    let content_key_event_id =
        crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
            &conn,
            &creator_peer_id,
        )
        .expect("content key for creator");
    let seeded_message_id = crate::event_modules::message::commands::create(
        &conn,
        &creator_peer_id,
        &workspace.peer_shared_event_id,
        &workspace.peer_shared_key,
        42,
        crate::event_modules::message::commands::CreateMessageCmd {
            workspace_id: workspace.workspace_id,
            author_id: creator_user_eid,
            content: "seeded-before-link".to_string(),
        },
    )
    .expect("create seeded encrypted message");

    let invite = create_device_link_invite_raw(
        &conn,
        &creator_peer_id,
        &workspace.peer_shared_key,
        &workspace.peer_shared_event_id,
        &creator_user_eid,
        &workspace.workspace_id,
    )
    .expect("create device-link invite");

    let phone_key = SigningKey::from_bytes(&[8u8; 32]);
    let phone_peer_id = peer_id_for_signing_key(&phone_key);
    record_invite_link_workspace(
        &conn,
        &phone_peer_id,
        &invite.invite_event_id,
        workspace.workspace_id,
    );
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

    let linked_key_present: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![&phone_peer_id, event_id_to_base64(&content_key_event_id)],
            |row| row.get(0),
        )
        .expect("query linked device content key");
    assert!(
        linked_key_present,
        "device link should replay/wrap the workspace content key for the new device"
    );

    let seeded_message_visible: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![&phone_peer_id, event_id_to_base64(&seeded_message_id)],
            |row| row.get(0),
        )
        .expect("query seeded message on linked device");
    assert!(
        seeded_message_visible,
        "linked device should decrypt and project preexisting encrypted messages"
    );

    let tenant_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
            rusqlite::params![&phone_peer_id],
            |row| row.get(0),
        )
        .expect("query peers_shared");
    assert_eq!(
        tenant_count, 2,
        "linked device should project both the existing tenant and its own peer_shared row"
    );

    let blocked_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
            rusqlite::params![&phone_peer_id],
            |row| row.get(0),
        )
        .expect("query blocked events");
    let blocked_details: Vec<(String, String)> = {
        let mut stmt = conn
            .prepare(
                "SELECT e.blob, be.event_id
                 FROM blocked_events be
                 JOIN events e ON e.event_id = be.event_id
                 WHERE be.peer_id = ?1
                 ORDER BY be.event_id ASC",
            )
            .expect("prepare blocked detail query");
        stmt.query_map(rusqlite::params![&phone_peer_id], |row| {
            let blob = crate::db::sql_types::get_blob(row, 0)?;
            let event_id = crate::db::sql_types::get_text(row, 1)?;
            let event_name = |parsed: &crate::event_modules::ParsedEvent| {
                crate::event_modules::registry()
                    .lookup(parsed.event_type_code())
                    .map(|meta| meta.type_name.to_string())
                    .unwrap_or_else(|| format!("type-{}", parsed.event_type_code()))
            };
            let event_type = match crate::event_modules::parse_event(&blob) {
                Ok(crate::event_modules::ParsedEvent::Signed(signed)) => {
                    match crate::event_modules::parse_event(&signed.payload) {
                        Ok(inner) => format!("signed({})", event_name(&inner)),
                        Err(_) => "signed(parse-error)".to_string(),
                    }
                }
                Ok(parsed) => event_name(&parsed),
                Err(_) => "parse-error".to_string(),
            };
            Ok((event_type, event_id))
        })
        .expect("query blocked detail rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect blocked detail rows")
    };
    assert_eq!(
        blocked_count, 0,
        "device link should not leave blocked local events: {:?}",
        blocked_details
    );
}

#[test]
fn send_rotates_on_new_local_removal_frontier_and_reuses_frontier_key() {
    let conn = open_in_memory().expect("open in-memory db");
    create_tables(&conn).expect("create tables");
    materialize_local_daemon_identity(&conn);

    let workspace =
        create_workspace(&conn, "bootstrap", "ws", "alice", "laptop").expect("create workspace");
    let recorded_by = peer_id_for_signing_key(&workspace.peer_shared_key);
    let author_id: EventId = conn
        .query_row(
            "SELECT event_id FROM users WHERE recorded_by = ?1 ORDER BY event_id ASC LIMIT 1",
            rusqlite::params![&recorded_by],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .ok()
        .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
        .expect("creator user event");

    let root_key = crate::event_modules::workspace::identity_ops::ensure_content_key_for_peer(
        &conn,
        &recorded_by,
    )
    .expect("root content key");
    let root_wrapper = crate::event_modules::message::commands::create(
        &conn,
        &recorded_by,
        &workspace.peer_shared_event_id,
        &workspace.peer_shared_key,
        10_000,
        crate::event_modules::message::commands::CreateMessageCmd {
            workspace_id: workspace.workspace_id,
            author_id,
            content: "before-removal".to_string(),
        },
    )
    .expect("create message before removal");
    assert_eq!(
        encrypted_wrapper_key_event_id(&conn, &root_wrapper),
        root_key,
        "message before removal should use the existing root-frontier key"
    );

    let removal_event_id = create_local_removal(
        &conn,
        &recorded_by,
        &workspace.peer_shared_event_id,
        &workspace.peer_shared_key,
        [0x55; 32],
        &[],
    );

    let first_post_removal_wrapper = crate::event_modules::message::commands::create(
        &conn,
        &recorded_by,
        &workspace.peer_shared_event_id,
        &workspace.peer_shared_key,
        11_000,
        crate::event_modules::message::commands::CreateMessageCmd {
            workspace_id: workspace.workspace_id,
            author_id,
            content: "after-removal-1".to_string(),
        },
    )
    .expect("create first post-removal message");
    let frontier_key = encrypted_wrapper_key_event_id(&conn, &first_post_removal_wrapper);
    assert_ne!(
        frontier_key, root_key,
        "message send must rotate to a new key once the local removal frontier advances"
    );

    let expected_frontier_hash =
        event_id_to_base64(&crate::event_modules::removal::frontier_hash_from_refs(&[
            removal_event_id,
        ]));
    let stored_frontier_hash: String = conn
        .query_row(
            "SELECT frontier_hash
             FROM key_rotations
             WHERE recorded_by = ?1 AND key_event_id = ?2
             ORDER BY rowid DESC
             LIMIT 1",
            rusqlite::params![&recorded_by, event_id_to_base64(&frontier_key)],
            |row| crate::db::sql_types::get_text(row, 0),
        )
        .expect("query post-removal key frontier");
    assert_eq!(
        stored_frontier_hash, expected_frontier_hash,
        "rotated key must be stamped with the sender's current removal frontier"
    );

    let second_post_removal_wrapper = crate::event_modules::message::commands::create(
        &conn,
        &recorded_by,
        &workspace.peer_shared_event_id,
        &workspace.peer_shared_key,
        12_000,
        crate::event_modules::message::commands::CreateMessageCmd {
            workspace_id: workspace.workspace_id,
            author_id,
            content: "after-removal-2".to_string(),
        },
    )
    .expect("create second post-removal message");
    assert_eq!(
        encrypted_wrapper_key_event_id(&conn, &second_post_removal_wrapper),
        frontier_key,
        "once a key exists for the current frontier, later sends should reuse it"
    );
}
