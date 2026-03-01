    use super::*;
    use crate::crypto::event_id_to_base64;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn create_user_invite_materializes_pending_bootstrap_trust_via_projection() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        let workspace = create_workspace(&conn, "bootstrap", "ws", "alice", "laptop")
            .expect("create workspace");
        let recorded_by = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
            &workspace.peer_shared_key.verifying_key().to_bytes(),
        ));
        let (_workspace_signer_eid, workspace_key) =
            load_workspace_signing_key(&conn, &recorded_by)
                .expect("load workspace key")
                .expect("workspace key must exist");

        // Use a bootstrap SPKI that is not already present in peers_shared so
        // pending bootstrap trust is materialized by projection.
        let bootstrap_spki = [0xAB; 32];

        let invite = create_user_invite(
            &conn,
            &recorded_by,
            &workspace_key,
            &workspace.workspace_id,
            &workspace.peer_shared_key,
            &workspace.peer_shared_event_id,
            "127.0.0.1:4433",
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

        // Resulting transport identity should be the active local identity after create.
        let conn2 = crate::db::open_connection(&db_path).expect("re-open db");
        let loaded_peer_id =
            crate::transport::identity::load_transport_peer_id(&conn2).expect("load peer id");
        assert_eq!(loaded_peer_id, resp.peer_id);
    }
