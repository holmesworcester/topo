use rusqlite::Connection;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::generate_self_signed_cert_from_signing_key;
use crate::projection::create::create_event_synchronous;

pub const MISSING_DAEMON_IDENTITY_ERROR: &str = "daemon identity not found; start the daemon first";
pub const INCONSISTENT_DAEMON_IDENTITY_ERROR: &str =
    "daemon identity is inconsistent: endpoint_shared exists without endpoint_secret";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonIdentityMaterializationDecisionContext {
    endpoint_secret_present: bool,
    endpoint_shared_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonIdentityMaterializationPlan {
    AlreadyMaterialized,
    CreateSecretAndShared,
    CreateSharedFromExistingSecret,
    RejectSharedWithoutSecret,
}

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

fn decide_daemon_identity_materialization_plan(
    context: &DaemonIdentityMaterializationDecisionContext,
) -> DaemonIdentityMaterializationPlan {
    match (
        context.endpoint_secret_present,
        context.endpoint_shared_present,
    ) {
        (true, true) => DaemonIdentityMaterializationPlan::AlreadyMaterialized,
        (false, false) => DaemonIdentityMaterializationPlan::CreateSecretAndShared,
        (true, false) => DaemonIdentityMaterializationPlan::CreateSharedFromExistingSecret,
        (false, true) => DaemonIdentityMaterializationPlan::RejectSharedWithoutSecret,
    }
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

        let secret_key = iroh::SecretKey::from_bytes(&rand::random());
        let private_key_bytes = secret_key.to_bytes();
        let endpoint_id = crate::event_modules::endpoint_secret::endpoint_id_from_private_key_bytes(
            &private_key_bytes,
        );
        let event = crate::event_modules::endpoint_secret::deterministic_endpoint_secret_event(
            private_key_bytes,
        );

        create_event_synchronous(conn, &endpoint_id, &event)
            .map_err(|e| sqlite_other(e.to_string()))?;

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
    if let Some(row) = load_endpoint_shared_row(conn)? {
        return Ok(row);
    }

    let row = crate::state::db::queue::with_immediate_tx(conn, || {
        if let Some(row) = crate::event_modules::endpoint_shared::load_local_endpoint_shared(conn)
            .map_err(|e| sqlite_other(e.to_string()))?
        {
            return Ok(row);
        }

        let event = crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event(
            secret_row.private_key_bytes,
        );
        create_event_synchronous(conn, &secret_row.endpoint_id, &event)
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
            if matches!(
                plan,
                DaemonIdentityMaterializationPlan::CreateSharedFromExistingSecret
            ) {
                let _ = ensure_endpoint_shared_row(conn, &row)?;
            }
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

pub fn load_daemon_iroh_secret_key_from_db(
    db_path: &str,
) -> Result<iroh::SecretKey, Box<dyn std::error::Error + Send + Sync>> {
    let conn = crate::db::open_connection(db_path)?;
    crate::db::schema::create_tables(&conn)?;
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
        assert_eq!(
            load_daemon_iroh_secret_key(&conn)
                .unwrap()
                .public()
                .to_string(),
            first.0
        );
        let endpoint_secret =
            crate::event_modules::endpoint_secret::load_local_endpoint_secret(&conn)
                .unwrap()
                .expect("endpoint secret row");
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
