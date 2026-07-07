use rusqlite::Connection;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::generate_self_signed_cert_from_signing_key;
use crate::projection::create::create_event;

pub const MISSING_DAEMON_IDENTITY_ERROR: &str = "daemon identity not found; start the daemon first";
pub const INCONSISTENT_DAEMON_IDENTITY_ERROR: &str =
    "daemon identity is inconsistent: endpoint_shared exists without endpoint_secret";

use topo_verus_proofs::runtime::transport::daemon_identity::{
    decide_daemon_identity_materialization_plan, DaemonIdentityMaterializationDecisionContext,
    DaemonIdentityMaterializationPlan,
};

fn sqlite_other(msg: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(msg.into())))
}

fn load_endpoint_secret_row(
    conn: &Connection,
) -> Result<
    Option<crate::event_modules::endpoint_secret::EndpointSecretRow>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    crate::event_modules::endpoint_secret::load_local_endpoint_secret(conn)
}

fn load_endpoint_shared_row(
    conn: &Connection,
) -> Result<
    Option<crate::event_modules::endpoint_shared::EndpointSharedRow>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    crate::event_modules::endpoint_shared::load_local_endpoint_shared(conn)
}

fn raw_endpoint_secret_present(
    conn: &Connection,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let present = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM endpoint_secrets LIMIT 1)",
        [],
        |row| row.get(0),
    )?;
    Ok(present)
}

fn raw_endpoint_shared_present(
    conn: &Connection,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let present = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM endpoints_shared LIMIT 1)",
        [],
        |row| row.get(0),
    )?;
    Ok(present)
}

fn load_daemon_identity_materialization_decision_context(
    conn: &Connection,
) -> Result<DaemonIdentityMaterializationDecisionContext, Box<dyn std::error::Error + Send + Sync>>
{
    Ok(DaemonIdentityMaterializationDecisionContext {
        endpoint_secret_present: raw_endpoint_secret_present(conn)?,
        endpoint_shared_present: raw_endpoint_shared_present(conn)?,
    })
}
fn ensure_endpoint_secret_row(
    conn: &Connection,
) -> Result<
    crate::event_modules::endpoint_secret::EndpointSecretRow,
    Box<dyn std::error::Error + Send + Sync>,
> {
    if let Some(row) = load_endpoint_secret_row(conn)? {
        return Ok(row);
    }

    let row = crate::state::db::queue::with_immediate_tx(conn, || {
        if let Some(row) = crate::event_modules::endpoint_secret::load_local_endpoint_secret(conn)
            .map_err(|e| sqlite_other(e.to_string()))?
        {
            return Ok(row);
        }

        let private_key_bytes =
            ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).to_bytes();
        let endpoint_id = crate::event_modules::endpoint_secret::endpoint_id_from_private_key_bytes(
            &private_key_bytes,
        );
        let event = crate::event_modules::endpoint_secret::deterministic_endpoint_secret_event(
            private_key_bytes,
        );

        create_event(conn, &endpoint_id, &event).map_err(|e| sqlite_other(e.to_string()))?;

        crate::event_modules::endpoint_secret::load_local_endpoint_secret(conn)
            .map_err(|e| sqlite_other(e.to_string()))?
            .ok_or_else(|| sqlite_other("endpoint_secret projection missing after create"))
    })?;

    Ok(row)
}

fn ensure_endpoint_shared_row(
    conn: &Connection,
    secret_row: &crate::event_modules::endpoint_secret::EndpointSecretRow,
) -> Result<
    crate::event_modules::endpoint_shared::EndpointSharedRow,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let expected_public_key = ed25519_dalek::SigningKey::from_bytes(&secret_row.private_key_bytes)
        .verifying_key()
        .to_bytes();
    let expected_event_id =
        crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event_id(
            &secret_row.private_key_bytes,
        );
    let expected_event_id_b64 = crate::crypto::event_id_to_base64(&expected_event_id);
    let expected_created_at =
        crate::event_modules::endpoint_shared::deterministic_endpoint_shared_created_at_ms(
            &expected_public_key,
        );

    let row = crate::state::db::queue::with_immediate_tx(conn, || {
        let event_present: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE event_id = ?1)",
                rusqlite::params![&expected_event_id_b64],
                |row| row.get(0),
            )
            .map_err(|e| sqlite_other(e.to_string()))?;
        if !event_present {
            let event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
                secret_row.private_key_bytes,
            );
            create_event(conn, &secret_row.endpoint_id, &event)
                .map_err(|e| sqlite_other(e.to_string()))?;
        }

        conn.execute(
            "DELETE FROM endpoints_shared WHERE endpoint_id = ?1 AND event_id <> ?2",
            rusqlite::params![&secret_row.endpoint_id, &expected_event_id_b64],
        )
        .map_err(|e| sqlite_other(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO endpoints_shared
             (recorded_by, event_id, endpoint_id, public_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                &secret_row.endpoint_id,
                &expected_event_id_b64,
                &secret_row.endpoint_id,
                expected_public_key.as_slice(),
                expected_created_at as i64,
            ],
        )
        .map_err(|e| sqlite_other(e.to_string()))?;

        crate::event_modules::endpoint_shared::load_local_endpoint_shared(conn)
            .map_err(|e| sqlite_other(e.to_string()))?
            .ok_or_else(|| sqlite_other("endpoint_shared projection missing after create"))
    })?;

    Ok(row)
}

pub fn materialize_daemon_identity(
    conn: &Connection,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let context = load_daemon_identity_materialization_decision_context(conn)?;
    let plan = decide_daemon_identity_materialization_plan(&context);
    let row = match plan {
        DaemonIdentityMaterializationPlan::AlreadyMaterialized
        | DaemonIdentityMaterializationPlan::CreateSharedFromExistingSecret => {
            let row = load_endpoint_secret_row(conn)?.ok_or(MISSING_DAEMON_IDENTITY_ERROR)?;
            let _ = ensure_endpoint_shared_row(conn, &row)?;
            row
        }
        DaemonIdentityMaterializationPlan::CreateSecretAndShared => {
            let row = ensure_endpoint_secret_row(conn)?;
            let _ = ensure_endpoint_shared_row(conn, &row)?;
            row
        }
        DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret => {
            return Err(INCONSISTENT_DAEMON_IDENTITY_ERROR.into());
        }
    };
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&row.private_key_bytes);
    let (cert_der, key_der) = generate_self_signed_cert_from_signing_key(&signing_key)?;
    Ok((row.endpoint_id, cert_der, key_der))
}

pub fn load_daemon_identity(
    conn: &Connection,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let row = load_endpoint_secret_row(conn)?.ok_or(MISSING_DAEMON_IDENTITY_ERROR)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&row.private_key_bytes);
    let (cert_der, key_der) = generate_self_signed_cert_from_signing_key(&signing_key)?;
    Ok((row.endpoint_id, cert_der, key_der))
}

pub fn ensure_daemon_identity(
    conn: &Connection,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let (endpoint_id, cert_der, key_der) = materialize_daemon_identity(conn)?;
    crate::db::daemon_identity::store(
        conn,
        &endpoint_id,
        cert_der.as_ref(),
        key_der.secret_pkcs8_der(),
    )
    .map_err(|e| sqlite_other(e.to_string()))?;
    Ok((endpoint_id, cert_der, key_der))
}

pub fn load_daemon_signing_key(
    conn: &Connection,
) -> Result<ed25519_dalek::SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let row = load_endpoint_secret_row(conn)?.ok_or(MISSING_DAEMON_IDENTITY_ERROR)?;
    Ok(ed25519_dalek::SigningKey::from_bytes(
        &row.private_key_bytes,
    ))
}

pub fn load_local_daemon_endpoint_id(
    conn: &Connection,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(row) = load_endpoint_secret_row(conn)? {
        return Ok(Some(row.endpoint_id));
    }
    if let Some(row) = load_endpoint_shared_row(conn)? {
        return Ok(Some(row.endpoint_id));
    }
    Ok(None)
}

#[cfg(feature = "iroh-transport")]
pub fn load_daemon_iroh_secret_key(
    conn: &Connection,
) -> Result<iroh::SecretKey, Box<dyn std::error::Error + Send + Sync>> {
    let row = load_endpoint_secret_row(conn)?.ok_or(MISSING_DAEMON_IDENTITY_ERROR)?;
    Ok(iroh::SecretKey::from_bytes(&row.private_key_bytes))
}

pub fn materialize_daemon_identity_from_db(
    db_path: &str,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    materialize_daemon_identity(&conn)
}

pub fn load_daemon_identity_from_db(
    db_path: &str,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    load_daemon_identity(&conn)
}

pub fn ensure_daemon_identity_from_db(
    db_path: &str,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    ensure_daemon_identity(&conn)
}

pub fn load_daemon_signing_key_from_db(
    db_path: &str,
) -> Result<ed25519_dalek::SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    load_daemon_signing_key(&conn)
}

#[cfg(feature = "iroh-transport")]
pub fn load_daemon_iroh_secret_key_from_db(
    db_path: &str,
) -> Result<iroh::SecretKey, Box<dyn std::error::Error + Send + Sync>> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
    let _ = ensure_daemon_identity(&conn)?;
    load_daemon_iroh_secret_key(&conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn materialize_daemon_identity_generates_and_persists_endpoint_events() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let first = materialize_daemon_identity(&conn).unwrap();
        let second = materialize_daemon_identity(&conn).unwrap();

        assert_eq!(first.0, second.0);
        assert_eq!(first.0.len(), 64);
        let endpoint_secret =
            crate::event_modules::endpoint_secret::load_local_endpoint_secret(&conn)
                .unwrap()
                .expect("endpoint secret row");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&endpoint_secret.private_key_bytes);
        assert_eq!(hex::encode(signing_key.verifying_key().to_bytes()), first.0);
        #[cfg(feature = "iroh-transport")]
        assert_eq!(
            load_daemon_iroh_secret_key(&conn)
                .unwrap()
                .public()
                .to_string(),
            first.0
        );
        assert_eq!(endpoint_secret.endpoint_id, first.0);
        let endpoint_shared =
            crate::event_modules::endpoint_shared::load_local_endpoint_shared(&conn)
                .unwrap()
                .expect("endpoint shared row");
        assert_eq!(endpoint_shared.endpoint_id, first.0);
        assert!(
            crate::db::daemon_identity::load(&conn).unwrap().is_none(),
            "daemon identity should be derived from endpoint events, not persisted in a cache table"
        );
    }

    #[test]
    fn materialize_daemon_identity_repairs_missing_endpoint_shared() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let secret = ensure_endpoint_secret_row(&conn).unwrap();
        assert!(load_endpoint_shared_row(&conn).unwrap().is_none());

        let materialized = materialize_daemon_identity(&conn).unwrap();
        assert_eq!(materialized.0, secret.endpoint_id);
        assert!(load_endpoint_shared_row(&conn).unwrap().is_some());
    }

    #[test]
    fn materialize_daemon_identity_rejects_shared_without_secret() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO endpoints_shared (recorded_by, event_id, endpoint_id, public_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "ghost-endpoint",
                crate::crypto::event_id_to_base64(&[0x55; 32]),
                hex::encode([0x11; 32]),
                vec![0x22_u8; 32],
                1_i64
            ],
        )
        .unwrap();

        let err = materialize_daemon_identity(&conn).unwrap_err();
        assert_eq!(err.to_string(), INCONSISTENT_DAEMON_IDENTITY_ERROR);
    }

    #[test]
    fn ensure_daemon_identity_repairs_stale_endpoint_shared_projection() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let first = ensure_daemon_identity(&conn).unwrap();
        let endpoint_shared =
            crate::event_modules::endpoint_shared::load_local_endpoint_shared(&conn)
                .unwrap()
                .expect("endpoint shared row");

        let bogus_event_id = crate::crypto::event_id_to_base64(
            &crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event_id(
                &[0x77; 32],
            ),
        );
        conn.execute(
            "UPDATE endpoints_shared SET event_id = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![&bogus_event_id, &endpoint_shared.endpoint_id],
        )
        .unwrap();

        let repaired = ensure_daemon_identity(&conn).unwrap();
        let repaired_shared =
            crate::event_modules::endpoint_shared::load_local_endpoint_shared(&conn)
                .unwrap()
                .expect("repaired endpoint shared row");
        let repaired_event_present: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                rusqlite::params![&repaired_shared.event_id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(repaired.0, first.0);
        assert_eq!(repaired_shared.endpoint_id, endpoint_shared.endpoint_id);
        assert_eq!(repaired_shared.event_id, endpoint_shared.event_id);
        assert!(repaired_event_present);
    }

    #[test]
    fn load_daemon_identity_fails_when_missing() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let err = load_daemon_identity(&conn).unwrap_err();
        assert_eq!(err.to_string(), MISSING_DAEMON_IDENTITY_ERROR);
    }

    #[test]
    fn load_local_daemon_endpoint_id_prefers_endpoint_secret() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let secret = ensure_endpoint_secret_row(&conn).unwrap();
        assert_eq!(
            load_local_daemon_endpoint_id(&conn).unwrap(),
            Some(secret.endpoint_id)
        );
    }
}
