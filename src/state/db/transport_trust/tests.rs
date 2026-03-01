    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn test_binding_alone_not_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let peer_id = "bbbb";
        let spki: [u8; 32] = [42u8; 32];

        // Record a transport binding (observation telemetry)
        record_transport_binding(&conn, recorded_by, peer_id, &spki).unwrap();

        // Binding alone must NOT appear in allowed peers
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(!allowed.contains(&spki));

        // Idempotent insert still works
        record_transport_binding(&conn, recorded_by, peer_id, &spki).unwrap();
    }

    /// Helper: insert a PeerShared row and return its SPKI fingerprint.
    fn insert_peer_shared(
        conn: &Connection,
        recorded_by: &str,
        event_id: &str,
        pubkey: &[u8; 32],
    ) -> [u8; 32] {
        let transport_fingerprint = spki_fingerprint_from_ed25519_pubkey(pubkey);
        conn.execute(
            "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                recorded_by,
                event_id,
                pubkey.as_slice(),
                transport_fingerprint.as_slice(),
            ],
        )
        .unwrap();
        transport_fingerprint
    }

    /// Helper: insert a PeerShared row with user_event_id and return its SPKI fingerprint.
    fn insert_peer_shared_with_user(
        conn: &Connection,
        recorded_by: &str,
        event_id: &str,
        pubkey: &[u8; 32],
        user_event_id: &str,
    ) -> [u8; 32] {
        let transport_fingerprint = spki_fingerprint_from_ed25519_pubkey(pubkey);
        conn.execute(
            "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint, user_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                recorded_by,
                event_id,
                pubkey.as_slice(),
                transport_fingerprint.as_slice(),
                user_event_id,
            ],
        )
        .unwrap();
        transport_fingerprint
    }

    #[test]
    fn test_peer_shared_derived_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [42u8; 32];
        let spki = insert_peer_shared(&conn, recorded_by, "ps1", &pubkey);

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));
    }

    #[test]
    fn test_invite_bootstrap_trust_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [11u8; 32];
        record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia1",
            "invite1",
            "workspace1",
            "127.0.0.1:4433",
            &spki,
        )
        .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));
    }

    #[test]
    fn test_invite_bootstrap_superseded_when_peer_shared_exists() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [14u8; 32];
        let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);
        record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia-supersede",
            "invite-supersede",
            "workspace-supersede",
            "127.0.0.1:4433",
            &spki,
        )
        .unwrap();

        // Add PeerShared entry whose derived SPKI matches the bootstrap SPKI
        insert_peer_shared(&conn, recorded_by, "ps-supersede", &pubkey);

        // Supersession now happens at projection time, not on read
        consume_bootstrap_for_peer_shared(&conn, recorded_by, &pubkey).unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));

        let remaining_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM invite_bootstrap_trust
                  WHERE recorded_by = ?1 AND invite_accepted_event_id = ?2",
                rusqlite::params![recorded_by, "ia-supersede"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining_rows, 0);
    }

    #[test]
    fn test_expired_invite_bootstrap_not_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [15u8; 32];
        let now = now_ms_i64();
        conn.execute(
            "INSERT INTO invite_bootstrap_trust
             (recorded_by, invite_accepted_event_id, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, accepted_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                recorded_by,
                "ia-expired",
                "invite-expired",
                "workspace-expired",
                "127.0.0.1:4433",
                spki.as_slice(),
                now - 1000,
                now - 1,
            ],
        )
        .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(!allowed.contains(&spki));
    }

    #[test]
    fn test_pending_invite_bootstrap_trust_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let invite_eid = "invite-bootstrap";
        let workspace_id = "workspace-bootstrap";
        let spki: [u8; 32] = [55u8; 32];
        record_pending_invite_bootstrap_trust(&conn, recorded_by, invite_eid, workspace_id, &spki)
            .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));
    }

    #[test]
    fn test_pending_invite_bootstrap_superseded_when_peer_shared_exists() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [12u8; 32];
        let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);
        record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite1", "workspace1", &spki)
            .unwrap();

        // Add PeerShared entry whose derived SPKI matches the pending SPKI
        insert_peer_shared(&conn, recorded_by, "ps1", &pubkey);

        // Supersession now happens at projection time, not on read
        consume_bootstrap_for_peer_shared(&conn, recorded_by, &pubkey).unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&spki));

        let remaining_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
                  WHERE recorded_by = ?1 AND invite_event_id = ?2",
                rusqlite::params![recorded_by, "invite1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining_rows, 0);
    }

    #[test]
    fn test_expired_pending_invite_bootstrap_not_in_allowlist() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [13u8; 32];
        let now = now_ms_i64();
        conn.execute(
            "INSERT INTO pending_invite_bootstrap_trust
             (recorded_by, invite_event_id, workspace_id, expected_bootstrap_spki_fingerprint, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                "invite-expired",
                "workspace-expired",
                spki.as_slice(),
                now - 1000,
                now - 1,
            ],
        )
        .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(!allowed.contains(&spki));
    }

    #[test]
    fn test_is_peer_allowed_checks_all_sources() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey: [u8; 32] = [2u8; 32];
        let peer_shared_spki = insert_peer_shared(&conn, recorded_by, "ps_db", &pubkey);
        let pending_only: [u8; 32] = [3u8; 32];
        let denied: [u8; 32] = [4u8; 32];

        record_pending_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "invite-pending",
            "workspace",
            &pending_only,
        )
        .unwrap();

        assert!(is_peer_allowed(&conn, recorded_by, &peer_shared_spki).unwrap());
        assert!(is_peer_allowed(&conn, recorded_by, &pending_only).unwrap());
        assert!(!is_peer_allowed(&conn, recorded_by, &denied).unwrap());
    }

    #[test]
    fn test_mutual_trust_requires_both_sides() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let alice = "alice";
        let bob = "bob";
        let alice_spki: [u8; 32] = [0xA1; 32];
        let bob_spki: [u8; 32] = [0xB2; 32];

        record_pending_invite_bootstrap_trust(&conn, alice, "invite-a", "ws", &bob_spki).unwrap();
        record_pending_invite_bootstrap_trust(&conn, bob, "invite-b", "ws", &alice_spki).unwrap();

        assert!(
            is_peer_allowed(&conn, alice, &bob_spki).unwrap(),
            "alice should trust bob once bob is in alice's trust rows"
        );
        assert!(
            is_peer_allowed(&conn, bob, &alice_spki).unwrap(),
            "bob should trust alice once alice is in bob's trust rows"
        );

        // One-sided trust is not mutual auth.
        let carol = "carol";
        assert!(
            !is_peer_allowed(&conn, carol, &alice_spki).unwrap(),
            "carol has no trust rows and must not trust alice"
        );
    }

    #[test]
    fn test_import_cli_pins_to_sql() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pin1: [u8; 32] = [0xAA; 32];
        let pin2: [u8; 32] = [0xBB; 32];
        let not_pinned: [u8; 32] = [0xCC; 32];

        let cli_pins = AllowedPeers::from_fingerprints(vec![pin1, pin2]);
        let imported = import_cli_pins_to_sql(&conn, recorded_by, &cli_pins).unwrap();
        assert_eq!(imported, 2);

        // Both should be visible via allowed_peers_from_db
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&pin1));
        assert!(allowed.contains(&pin2));
        assert!(!allowed.contains(&not_pinned));

        // And via is_peer_allowed
        assert!(is_peer_allowed(&conn, recorded_by, &pin1).unwrap());
        assert!(is_peer_allowed(&conn, recorded_by, &pin2).unwrap());
        assert!(!is_peer_allowed(&conn, recorded_by, &not_pinned).unwrap());
    }

    #[test]
    fn test_cli_pin_superseded_by_peer_shared() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        // Choose a pubkey whose derived SPKI we'll use as the CLI pin
        let pubkey: [u8; 32] = [0xDD; 32];
        let pin_fp = spki_fingerprint_from_ed25519_pubkey(&pubkey);

        // Import a CLI pin
        let cli_pins = AllowedPeers::from_fingerprints(vec![pin_fp]);
        import_cli_pins_to_sql(&conn, recorded_by, &cli_pins).unwrap();

        // Verify it's trusted
        assert!(is_peer_allowed(&conn, recorded_by, &pin_fp).unwrap());

        // Simulate arrival of a PeerShared entry for the same SPKI
        insert_peer_shared(&conn, recorded_by, "ps-steady", &pubkey);

        // Supersession now happens at projection time, not on read
        consume_bootstrap_for_peer_shared(&conn, recorded_by, &pubkey).unwrap();

        // Still trusted (via PeerShared now)
        assert!(is_peer_allowed(&conn, recorded_by, &pin_fp).unwrap());

        // Bootstrap row should be consumed by the PeerShared projection path.
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&pin_fp));

        let invite_event_id = cli_pin_invite_event_id(&pin_fp);
        let remaining_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
                  WHERE recorded_by = ?1 AND invite_event_id = ?2",
                rusqlite::params![recorded_by, &invite_event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining_rows, 0, "CLI pin bootstrap row should be consumed");
    }

    #[test]
    fn test_cli_pin_not_silently_trusted_without_import() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let raw_fp: [u8; 32] = [0xEE; 32];

        // Without importing, a raw fingerprint should NOT be trusted
        assert!(!is_peer_allowed(&conn, recorded_by, &raw_fp).unwrap());
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(!allowed.contains(&raw_fp));
    }

    #[test]
    fn test_cli_pin_import_no_collision_on_shared_prefix() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        // Two fingerprints that share the same first 8 bytes but differ after
        let mut fp_a: [u8; 32] = [0xAB; 32];
        let mut fp_b: [u8; 32] = [0xAB; 32];
        fp_a[8] = 0x01;
        fp_b[8] = 0x02;

        let pins = AllowedPeers::from_fingerprints(vec![fp_a, fp_b]);
        let count = import_cli_pins_to_sql(&conn, recorded_by, &pins).unwrap();
        assert_eq!(count, 2);

        // Both must remain trusted — no silent overwrite
        assert!(
            is_peer_allowed(&conn, recorded_by, &fp_a).unwrap(),
            "fp_a should be trusted after import"
        );
        assert!(
            is_peer_allowed(&conn, recorded_by, &fp_b).unwrap(),
            "fp_b should be trusted after import"
        );

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&fp_a), "fp_a should be in allowed set");
        assert!(allowed.contains(&fp_b), "fp_b should be in allowed set");
    }

    #[test]
    fn test_invite_bootstrap_trust_insert_idempotent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [20u8; 32];

        // First insert
        record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia1",
            "invite1",
            "workspace1",
            "127.0.0.1:4433",
            &spki,
        )
        .unwrap();

        // Second insert with same PK but different values — should be ignored
        let spki2: [u8; 32] = [21u8; 32];
        record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia1",
            "invite2",
            "workspace2",
            "10.0.0.1:4434",
            &spki2,
        )
        .unwrap();

        // Should be exactly 1 row
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_accepted_event_id = ?2",
                rusqlite::params![recorded_by, "ia1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "INSERT OR IGNORE should not create duplicate");

        // Original values preserved (second insert ignored)
        let (addr, ws): (String, String) = conn
            .query_row(
                "SELECT bootstrap_addr, workspace_id FROM invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_accepted_event_id = ?2",
                rusqlite::params![recorded_by, "ia1"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(addr, "127.0.0.1:4433", "original value preserved");
        assert_eq!(ws, "workspace1", "original value preserved");
    }

    #[test]
    fn test_pending_invite_bootstrap_trust_insert_idempotent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let spki: [u8; 32] = [30u8; 32];

        // First insert
        record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite1", "workspace1", &spki)
            .unwrap();

        // Second insert with same PK but different values — should be ignored
        let spki2: [u8; 32] = [31u8; 32];
        record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite1", "workspace2", &spki2)
            .unwrap();

        // Should be exactly 1 row
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
                rusqlite::params![recorded_by, "invite1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "INSERT OR IGNORE should not create duplicate");

        // Original values preserved (second insert ignored)
        let ws: String = conn
            .query_row(
                "SELECT workspace_id FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
                rusqlite::params![recorded_by, "invite1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ws, "workspace1", "original value preserved");

        // Original SPKI preserved
        let fp_blob: Vec<u8> = conn
            .query_row(
                "SELECT expected_bootstrap_spki_fingerprint FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
                rusqlite::params![recorded_by, "invite1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fp_blob, spki.to_vec(), "original SPKI preserved");
    }

    #[test]
    fn test_different_recorded_by_isolation() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let pubkey: [u8; 32] = [42u8; 32];
        let spki = insert_peer_shared(&conn, "peer_a", "ps1", &pubkey);

        let allowed_a = allowed_peers_from_db(&conn, "peer_a").unwrap();
        assert!(allowed_a.contains(&spki));

        let allowed_b = allowed_peers_from_db(&conn, "peer_b").unwrap();
        assert!(!allowed_b.contains(&spki));
    }

    #[test]
    fn test_malformed_peer_shared_pubkey_skipped() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let good_pubkey: [u8; 32] = [42u8; 32];
        let good_spki = insert_peer_shared(&conn, recorded_by, "ps1", &good_pubkey);

        // Insert a malformed peers_shared row (wrong length public_key)
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "ps_bad", &[0u8; 16][..]],
        )
        .unwrap();

        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(allowed.contains(&good_spki));
        // Malformed entry should be skipped — only 1 valid entry
        let zero_fp: [u8; 32] = [0u8; 32];
        assert!(!allowed.contains(&zero_fp));
    }

    #[test]
    fn test_allowed_peers_count() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let pubkey_ps: [u8; 32] = [1u8; 32];
        let spki_bootstrap: [u8; 32] = [2u8; 32];
        let spki_pending: [u8; 32] = [3u8; 32];

        // Empty → count should be 0
        assert_eq!(allowed_peers_from_db(&conn, recorded_by).unwrap().len(), 0);

        // Add PeerShared row
        insert_peer_shared(&conn, recorded_by, "ps1", &pubkey_ps);
        assert_eq!(allowed_peers_from_db(&conn, recorded_by).unwrap().len(), 1);

        // Add accepted invite bootstrap trust
        record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia1",
            "invite1",
            "ws1",
            "127.0.0.1:4433",
            &spki_bootstrap,
        )
        .unwrap();
        assert_eq!(allowed_peers_from_db(&conn, recorded_by).unwrap().len(), 2);

        // Add pending invite bootstrap trust
        record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite2", "ws2", &spki_pending)
            .unwrap();
        assert_eq!(allowed_peers_from_db(&conn, recorded_by).unwrap().len(), 3);

        // Cross-tenant isolation: different recorded_by sees 0
        assert_eq!(allowed_peers_from_db(&conn, "other_peer").unwrap().len(), 0);
    }

    #[test]
    fn test_allowed_peers_count_dedupes_overlap_across_sources() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "count_dedupe";
        let pubkey: [u8; 32] = [0x42; 32];
        let spki = insert_peer_shared(&conn, recorded_by, "ps-overlap", &pubkey);

        record_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "ia-overlap",
            "invite-overlap",
            "ws-overlap",
            "127.0.0.1:4433",
            &spki,
        )
        .unwrap();
        record_pending_invite_bootstrap_trust(
            &conn,
            recorded_by,
            "invite-overlap-pending",
            "ws-overlap",
            &spki,
        )
        .unwrap();

        assert_eq!(
            allowed_peers_from_db(&conn, recorded_by).unwrap().len(),
            1,
            "same fingerprint in peers_shared + bootstrap rows should count once"
        );
    }

    #[test]
    fn test_has_any_trusted_peer() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";

        // Empty → false
        assert!(!has_any_trusted_peer(&conn, recorded_by).unwrap());

        // PeerShared only → true
        let pubkey_ps: [u8; 32] = [10u8; 32];
        insert_peer_shared(&conn, recorded_by, "ps_only", &pubkey_ps);
        assert!(has_any_trusted_peer(&conn, recorded_by).unwrap());

        // Start fresh for bootstrap-only test
        let rb_boot = "boot_only";
        assert!(!has_any_trusted_peer(&conn, rb_boot).unwrap());
        let spki_boot: [u8; 32] = [20u8; 32];
        record_invite_bootstrap_trust(
            &conn,
            rb_boot,
            "ia_boot",
            "inv_boot",
            "ws_boot",
            "127.0.0.1:4433",
            &spki_boot,
        )
        .unwrap();
        assert!(has_any_trusted_peer(&conn, rb_boot).unwrap());

        // Pending-only test
        let rb_pend = "pending_only";
        assert!(!has_any_trusted_peer(&conn, rb_pend).unwrap());
        let spki_pend: [u8; 32] = [30u8; 32];
        record_pending_invite_bootstrap_trust(&conn, rb_pend, "inv_pend", "ws_pend", &spki_pend)
            .unwrap();
        assert!(has_any_trusted_peer(&conn, rb_pend).unwrap());
    }

    #[test]
    fn test_allowed_peers_count_ignores_malformed_rows() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "malformed_count";

        // Malformed PeerShared public key (wrong length)
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, "ps_short", &[9u8; 16][..]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO invite_bootstrap_trust
             (recorded_by, invite_accepted_event_id, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, accepted_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                recorded_by,
                "ia_short",
                "invite_short",
                "ws",
                "127.0.0.1:4433",
                &[7u8; 31][..],
                now_ms_i64(),
                now_ms_i64() + 60_000,
            ],
        ).unwrap();
        conn.execute(
            "INSERT INTO pending_invite_bootstrap_trust
             (recorded_by, invite_event_id, workspace_id, expected_bootstrap_spki_fingerprint, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                "invite_short_pending",
                "ws",
                &[8u8; 8][..],
                now_ms_i64(),
                now_ms_i64() + 60_000,
            ],
        ).unwrap();

        assert_eq!(allowed_peers_from_db(&conn, recorded_by).unwrap().len(), 0);
        assert!(!has_any_trusted_peer(&conn, recorded_by).unwrap());
    }

    #[test]
    fn test_removed_peer_excluded_from_trust() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let peer_pubkey: [u8; 32] = [0x42; 32];
        let peer_event_id = "peer_shared_evt1";

        // Insert a peers_shared row
        let spki = spki_fingerprint_from_ed25519_pubkey(&peer_pubkey);
        conn.execute(
            "INSERT INTO peers_shared (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                recorded_by,
                peer_event_id,
                peer_pubkey.as_slice(),
                spki.as_slice()
            ],
        )
        .unwrap();

        // Before removal: peer should be trusted
        assert!(
            is_peer_allowed(&conn, recorded_by, &spki).unwrap(),
            "peer should be trusted before removal"
        );
        assert!(
            has_any_trusted_peer(&conn, recorded_by).unwrap(),
            "should have trusted peers before removal"
        );
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(
            allowed.contains(&spki),
            "allowed set should contain peer before removal"
        );

        // Insert removal targeting this peer
        conn.execute(
            "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type)
             VALUES (?1, 'removal_evt1', ?2, 'peer_removed')",
            rusqlite::params![recorded_by, peer_event_id],
        )
        .unwrap();

        // After removal: peer should NOT be trusted
        assert!(
            !is_peer_allowed(&conn, recorded_by, &spki).unwrap(),
            "removed peer should not be trusted"
        );
        assert!(
            !has_any_trusted_peer(&conn, recorded_by).unwrap(),
            "should have no trusted peers after only peer removed"
        );
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(
            !allowed.contains(&spki),
            "allowed set should not contain removed peer"
        );
    }

    #[test]
    fn test_user_removed_denies_linked_peer_trust() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "aaaa";
        let peer_pubkey: [u8; 32] = [0x55; 32];
        let user_event_id = "user_evt1";

        // Insert a peers_shared row with user_event_id
        let spki = insert_peer_shared_with_user(
            &conn,
            recorded_by,
            "peer_shared_evt1",
            &peer_pubkey,
            user_event_id,
        );

        // Before removal: peer should be trusted
        assert!(
            is_peer_allowed(&conn, recorded_by, &spki).unwrap(),
            "peer should be trusted before user removal"
        );
        assert!(
            has_any_trusted_peer(&conn, recorded_by).unwrap(),
            "should have trusted peers before user removal"
        );
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(
            allowed.contains(&spki),
            "allowed set should contain peer before user removal"
        );

        // Insert user removal targeting the user_event_id
        conn.execute(
            "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type)
             VALUES (?1, 'user_removal_evt1', ?2, 'user')",
            rusqlite::params![recorded_by, user_event_id],
        )
        .unwrap();

        // After user removal: peer should NOT be trusted (transitive denial)
        assert!(
            !is_peer_allowed(&conn, recorded_by, &spki).unwrap(),
            "peer linked to removed user should not be trusted"
        );
        assert!(
            !has_any_trusted_peer(&conn, recorded_by).unwrap(),
            "should have no trusted peers after user removed"
        );
        let allowed = allowed_peers_from_db(&conn, recorded_by).unwrap();
        assert!(
            !allowed.contains(&spki),
            "allowed set should not contain peer linked to removed user"
        );
    }

    // ---------------------------------------------------------------
    // Characterization tests: behavioral contracts that must survive
    // the trust-projection-eventization refactor (phases 1–5).
    // ---------------------------------------------------------------

    /// Characterization: inviter pre-accept pending trust allows first dial.
    ///
    /// When an inviter creates an invite, it records pending bootstrap trust
    /// with the expected SPKI derived from the invite key. This MUST allow
    /// the invitee's first TLS connection (using an invite-key-derived cert)
    /// to pass strict mTLS, even though no InviteAccepted or PeerShared
    /// events exist yet.
    ///
    /// After eventization: this row must still be produced (by projection
    /// from the locally-created invite event + bootstrap context), and
    /// is_peer_allowed must still return true for the expected SPKI.
    #[test]
    fn characterization_inviter_pending_trust_allows_first_dial() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let inviter_id = "inviter_peer_aaaa";
        let invite_event_id = "invite_evt_1";
        let workspace_id = "workspace_1";
        // This SPKI would be derived from the invite key in production
        let expected_invitee_spki: [u8; 32] = [0x77; 32];

        // --- Inviter creates invite: pending trust recorded ---
        record_pending_invite_bootstrap_trust(
            &conn,
            inviter_id,
            invite_event_id,
            workspace_id,
            &expected_invitee_spki,
        )
        .unwrap();

        // Invitee's first dial: transport layer checks is_peer_allowed
        assert!(
            is_peer_allowed(&conn, inviter_id, &expected_invitee_spki).unwrap(),
            "INVARIANT: inviter must allow invitee's invite-derived SPKI before accept"
        );

        // Unknown SPKI must still be denied
        let unknown: [u8; 32] = [0x99; 32];
        assert!(
            !is_peer_allowed(&conn, inviter_id, &unknown).unwrap(),
            "INVARIANT: unknown SPKI must be denied even when pending trust exists"
        );
    }

    /// Characterization: joiner accepted trust allows bootstrap sync.
    ///
    /// After the invitee accepts an invite, accepted bootstrap trust is
    /// recorded with the inviter's bootstrap SPKI. This MUST allow the
    /// joiner to continue syncing with the inviter's bootstrap address
    /// until PeerShared-derived trust supersedes it.
    ///
    /// After eventization: this row must be produced by the InviteAccepted
    /// projector (using bootstrap_context), not by the service layer.
    #[test]
    fn characterization_joiner_accepted_trust_allows_bootstrap_sync() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let joiner_id = "joiner_peer_bbbb";
        let invite_accepted_eid = "ia_evt_1";
        let invite_event_id = "invite_evt_1";
        let workspace_id = "workspace_1";
        let bootstrap_addr = "192.168.1.10:4433";
        let inviter_spki: [u8; 32] = [0x88; 32];

        // --- Joiner accepts invite: accepted trust recorded ---
        record_invite_bootstrap_trust(
            &conn,
            joiner_id,
            invite_accepted_eid,
            invite_event_id,
            workspace_id,
            bootstrap_addr,
            &inviter_spki,
        )
        .unwrap();

        // Joiner's transport layer checks the inviter's SPKI
        assert!(
            is_peer_allowed(&conn, joiner_id, &inviter_spki).unwrap(),
            "INVARIANT: joiner must allow inviter's bootstrap SPKI after accept"
        );

        // Bootstrap address should be listed for autodial
        let addrs = list_active_invite_bootstrap_addrs(&conn, joiner_id).unwrap();
        assert!(
            addrs.contains(&bootstrap_addr.to_string()),
            "INVARIANT: accepted bootstrap addr must be available for autodial"
        );
    }

    /// Characterization: full trust lifecycle — pending → accepted → superseded.
    ///
    /// Covers the complete lifecycle:
    /// 1. Inviter records pending trust (allows invitee first dial)
    /// 2. Joiner records accepted trust (allows bootstrap sync)
    /// 3. PeerShared event arrives → both types of bootstrap trust are superseded
    /// 4. Steady-state PeerShared-derived SPKI is the sole trust source
    ///
    /// After eventization: the lifecycle must produce identical trust decisions
    /// at each stage, even though the writes come from projections.
    #[test]
    fn characterization_full_trust_lifecycle() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let inviter = "inviter_cccc";
        let joiner = "joiner_dddd";
        let invite_eid = "invite_lifecycle_1";
        let workspace_id = "ws_lifecycle_1";
        let invitee_spki: [u8; 32] = [0xAA; 32];
        let inviter_spki: [u8; 32] = [0xBB; 32];

        // --- Stage 1: Inviter creates invite, records pending trust ---
        record_pending_invite_bootstrap_trust(
            &conn,
            inviter,
            invite_eid,
            workspace_id,
            &invitee_spki,
        )
        .unwrap();
        assert!(
            is_peer_allowed(&conn, inviter, &invitee_spki).unwrap(),
            "Stage 1: inviter allows invitee SPKI via pending trust"
        );

        // --- Stage 2: Joiner accepts, records accepted trust ---
        record_invite_bootstrap_trust(
            &conn,
            joiner,
            "ia_lifecycle_1",
            invite_eid,
            workspace_id,
            "10.0.0.1:4433",
            &inviter_spki,
        )
        .unwrap();
        assert!(
            is_peer_allowed(&conn, joiner, &inviter_spki).unwrap(),
            "Stage 2: joiner allows inviter SPKI via accepted trust"
        );

        // --- Stage 3: PeerShared arrives for the invitee SPKI on inviter side ---
        // The invitee's PeerShared public key must derive to the same SPKI
        // as the pending trust. For this test we use a known pubkey→SPKI mapping.
        let invitee_pubkey: [u8; 32] = [0xCC; 32];
        let invitee_derived_spki =
            insert_peer_shared(&conn, inviter, "ps_invitee", &invitee_pubkey);

        // After PeerShared, the derived SPKI is trusted via steady state
        assert!(
            is_peer_allowed(&conn, inviter, &invitee_derived_spki).unwrap(),
            "Stage 3: inviter allows invitee via PeerShared-derived SPKI"
        );

        // If the PeerShared SPKI matches the pending trust SPKI, pending is superseded.
        // (In this test they differ, so pending trust is NOT superseded — both paths remain.)
        // When they match, only one trust source remains:
        let matching_pubkey: [u8; 32] = {
            // We need a pubkey whose SPKI matches invitee_spki — but that's hard to
            // reverse. Instead, test supersession explicitly with matching values.
            let test_pubkey: [u8; 32] = [0xDD; 32];
            test_pubkey
        };
        let matching_spki = spki_fingerprint_from_ed25519_pubkey(&matching_pubkey);
        // Set up: pending trust with matching_spki, then PeerShared whose derived SPKI matches
        record_pending_invite_bootstrap_trust(
            &conn,
            inviter,
            "invite_match",
            workspace_id,
            &matching_spki,
        )
        .unwrap();
        assert!(
            is_peer_allowed(&conn, inviter, &matching_spki).unwrap(),
            "Stage 3b: pending trust allows matching SPKI before PeerShared"
        );

        insert_peer_shared(&conn, inviter, "ps_match", &matching_pubkey);
        // Supersession now happens at projection time via PeerShared writes
        consume_bootstrap_for_peer_shared(&conn, inviter, &matching_pubkey).unwrap();
        assert!(
            is_peer_allowed(&conn, inviter, &matching_spki).unwrap(),
            "Stage 3b: SPKI still allowed after PeerShared (via PeerShared path)"
        );
        // Pending trust should now be consumed (PeerShared SPKI matches).
        let remaining_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
                rusqlite::params![inviter, "invite_match"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining_rows, 0);
        // But the SPKI is still allowed (via PeerShared path)
        assert!(
            is_peer_allowed(&conn, inviter, &matching_spki).unwrap(),
            "Stage 3b: SPKI still allowed via PeerShared after supersession"
        );
    }

    /// Characterization: removal denies trust regardless of source.
    ///
    /// Even if PeerShared-derived trust exists, a PeerRemoved or UserRemoved
    /// event targeting that peer MUST deny transport trust. Bootstrap trust
    /// (pending/accepted) is independent of removal — removal only affects
    /// PeerShared-derived trust.
    ///
    /// After eventization: removal semantics must remain identical.
    #[test]
    fn characterization_removal_denies_all_peer_shared_trust() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "removal_test_peer";
        let peer_pubkey: [u8; 32] = [0xEE; 32];
        let peer_event_id = "ps_removal_target";
        let user_event_id = "user_removal_target";

        // --- PeerRemoved denies direct peer trust ---
        let spki = insert_peer_shared(&conn, recorded_by, peer_event_id, &peer_pubkey);
        assert!(
            is_peer_allowed(&conn, recorded_by, &spki).unwrap(),
            "peer trusted before removal"
        );

        conn.execute(
            "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type)
             VALUES (?1, 'pr_evt_1', ?2, 'peer_removed')",
            rusqlite::params![recorded_by, peer_event_id],
        )
        .unwrap();
        assert!(
            !is_peer_allowed(&conn, recorded_by, &spki).unwrap(),
            "INVARIANT: PeerRemoved must deny trust for that peer's SPKI"
        );

        // --- UserRemoved denies all linked peers (transitive) ---
        let other_rb = "user_removal_test";
        let other_pubkey: [u8; 32] = [0xFF; 32];
        let other_spki = insert_peer_shared_with_user(
            &conn,
            other_rb,
            "ps_linked",
            &other_pubkey,
            user_event_id,
        );
        assert!(
            is_peer_allowed(&conn, other_rb, &other_spki).unwrap(),
            "linked peer trusted before user removal"
        );

        conn.execute(
            "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type)
             VALUES (?1, 'ur_evt_1', ?2, 'user')",
            rusqlite::params![other_rb, user_event_id],
        )
        .unwrap();
        assert!(
            !is_peer_allowed(&conn, other_rb, &other_spki).unwrap(),
            "INVARIANT: UserRemoved must transitively deny linked peer trust"
        );

        // --- Bootstrap trust is NOT affected by PeerRemoved/UserRemoved ---
        // (Bootstrap trust exists independently; it has its own SPKI not tied to removal)
        let bootstrap_only_rb = "bootstrap_removal_test";
        let bootstrap_spki: [u8; 32] = [0x11; 32];
        record_invite_bootstrap_trust(
            &conn,
            bootstrap_only_rb,
            "ia_not_removed",
            "invite_not_removed",
            "ws_1",
            "127.0.0.1:4433",
            &bootstrap_spki,
        )
        .unwrap();
        // Even if a PeerRemoved exists for some unrelated peer, bootstrap trust remains
        assert!(
            is_peer_allowed(&conn, bootstrap_only_rb, &bootstrap_spki).unwrap(),
            "bootstrap trust unaffected by removal (independent trust source)"
        );
    }

    /// Characterization: trust check reads are pure (no side effects).
    ///
    /// After eventization (Phase 5), is_peer_allowed and allowed_peers_from_db
    /// are pure read-only queries. Supersession is handled at projection time
    /// by PeerShared projection writes.
    /// This test verifies that reads do NOT mutate the database.
    #[test]
    fn characterization_trust_check_reads_are_pure() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "pure_read_test";
        let pubkey: [u8; 32] = [0x44; 32];
        let spki = spki_fingerprint_from_ed25519_pubkey(&pubkey);

        // Record pending trust, then add matching PeerShared
        record_pending_invite_bootstrap_trust(&conn, recorded_by, "invite_se", "ws_se", &spki)
            .unwrap();
        insert_peer_shared(&conn, recorded_by, "ps_se", &pubkey);

        // Trust checks should NOT trigger supersession as a side effect
        let _ = is_peer_allowed(&conn, recorded_by, &spki).unwrap();
        let _ = allowed_peers_from_db(&conn, recorded_by).unwrap();

        let before_consume_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
                rusqlite::params![recorded_by, "invite_se"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(before_consume_rows, 1);

        // Explicit projection-time consumption works.
        consume_bootstrap_for_peer_shared(&conn, recorded_by, &pubkey).unwrap();
        let after_consume_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1 AND invite_event_id = ?2",
                rusqlite::params![recorded_by, "invite_se"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after_consume_rows, 0);
    }

    // ---------------------------------------------------------------
    // bootstrap_context tests
    // ---------------------------------------------------------------

    #[test]
    fn test_bootstrap_context_append_and_read() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "ctx_peer_1";
        let invite_eid = "invite_ctx_1";
        let workspace_id = "ws_ctx_1";
        let addr = "192.168.1.10:4433";
        let spki: [u8; 32] = [0xAA; 32];

        // No context yet
        let ctx = read_bootstrap_context(&conn, recorded_by, invite_eid).unwrap();
        assert!(ctx.is_none());

        // Append
        append_bootstrap_context(&conn, recorded_by, invite_eid, workspace_id, addr, &spki)
            .unwrap();

        let ctx = read_bootstrap_context(&conn, recorded_by, invite_eid)
            .unwrap()
            .unwrap();
        assert_eq!(ctx.bootstrap_addr, addr);
        assert_eq!(ctx.bootstrap_spki_fingerprint, spki);
        assert_eq!(ctx.workspace_id, workspace_id);
    }

    #[test]
    fn test_bootstrap_context_latest_wins() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "ctx_peer_2";
        let invite_eid = "invite_ctx_2";
        let spki: [u8; 32] = [0xBB; 32];

        // Insert two rows — manual observed_at to control ordering
        conn.execute(
            "INSERT INTO bootstrap_context
             (recorded_by, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![recorded_by, invite_eid, "ws1", "10.0.0.1:4433", spki.as_slice(), 1000],
        ).unwrap();
        conn.execute(
            "INSERT INTO bootstrap_context
             (recorded_by, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![recorded_by, invite_eid, "ws1", "10.0.0.2:4433", spki.as_slice(), 2000],
        ).unwrap();

        let ctx = read_bootstrap_context(&conn, recorded_by, invite_eid)
            .unwrap()
            .unwrap();
        assert_eq!(
            ctx.bootstrap_addr, "10.0.0.2:4433",
            "latest observed_at should win"
        );
    }

    #[test]
    fn test_bootstrap_context_tenant_isolation() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let spki: [u8; 32] = [0xCC; 32];
        append_bootstrap_context(&conn, "peer_a", "invite_1", "ws_1", "1.1.1.1:4433", &spki)
            .unwrap();

        assert!(read_bootstrap_context(&conn, "peer_a", "invite_1")
            .unwrap()
            .is_some());
        assert!(read_bootstrap_context(&conn, "peer_b", "invite_1")
            .unwrap()
            .is_none());
    }
