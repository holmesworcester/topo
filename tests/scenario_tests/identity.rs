use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::testutil::{Peer, ScenarioHarness};

/// No pre-projection blob capture influence: manually inserting a malformed
/// invite-like blob into events should not alter trust binding state.
#[test]
fn test_no_blob_capture_trust_influence() {
    let harness =
        ScenarioHarness::skip("raw blob insertion without project_one; no projection to replay");
    let alice = Peer::new("alice");
    let db = open_connection(&alice.db_path).unwrap();

    // Manually craft a blob that looks like a UserInvite (type 10) with a specific
    // workspace_id, and insert it directly into the events table (simulating raw ingress).
    let fake_workspace_id: [u8; 32] = [0xAA; 32];
    let mut fake_blob = vec![10u8]; // type code for UserInvite
    fake_blob.extend_from_slice(&[0u8; 40]); // created_at_ms(8) + public_key(32)
    fake_blob.extend_from_slice(&fake_workspace_id); // workspace_id at [41..73]
    fake_blob.extend_from_slice(&[0u8; 97]); // rest of the 170B blob

    let fake_eid = topo::crypto::hash_event(&fake_blob);
    let fake_b64 = event_id_to_base64(&fake_eid);

    db.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, 'user_invite_shared', ?2, 'shared', 0, 0)",
        rusqlite::params![&fake_b64, &fake_blob],
    ).unwrap();
    db.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, 0, 'test')",
        rusqlite::params![&alice.identity, &fake_b64],
    )
    .unwrap();

    // Trust anchor should be unset
    let anchor_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM invites_accepted WHERE recorded_by = ?1",
            rusqlite::params![&alice.identity],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        anchor_count, 0,
        "trust anchor should not be set by raw blob presence"
    );

    harness.finish();
}
