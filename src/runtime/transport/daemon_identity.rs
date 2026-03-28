use rusqlite::Connection;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::generate_self_signed_cert_from_signing_key;
use crate::projection::create::create_event_synchronous;

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

pub fn ensure_daemon_identity(
    conn: &Connection,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let row = ensure_endpoint_secret_row(conn)?;
    let _ = ensure_endpoint_shared_row(conn, &row)?;
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
    let row = load_endpoint_secret_row(conn)?
        .ok_or("endpoint identity not found; start the daemon, create a workspace, or accept an invite first")?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&row.private_key_bytes);
    let (cert_der, key_der) = generate_self_signed_cert_from_signing_key(&signing_key)?;
    Ok((row.endpoint_id, cert_der, key_der))
}

pub fn load_daemon_iroh_secret_key(
    conn: &Connection,
) -> Result<iroh::SecretKey, Box<dyn std::error::Error + Send + Sync>> {
    let row = load_endpoint_secret_row(conn)?
        .ok_or("endpoint identity not found; start the daemon, create a workspace, or accept an invite first")?;
    Ok(iroh::SecretKey::from_bytes(&row.private_key_bytes))
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
    fn ensure_daemon_identity_generates_and_persists_endpoint_secret() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let first = ensure_daemon_identity(&conn).unwrap();
        let second = ensure_daemon_identity(&conn).unwrap();

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
    }

    #[test]
    fn load_daemon_identity_fails_when_missing() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        assert!(load_daemon_identity(&conn).is_err());
    }
}
