use rusqlite::Connection;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::{extract_spki_fingerprint, generate_self_signed_cert};

pub fn ensure_daemon_identity(
    conn: &Connection,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    if let Some(row) = crate::db::daemon_identity::load(conn)? {
        return Ok((
            row.peer_id,
            CertificateDer::from(row.cert_der),
            PrivatePkcs8KeyDer::from(row.key_der),
        ));
    }

    let (cert_der, key_der) = generate_self_signed_cert()?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    let peer_id = hex::encode(fp);
    crate::db::daemon_identity::store(
        conn,
        &peer_id,
        cert_der.as_ref(),
        key_der.secret_pkcs8_der().as_ref(),
    )?;
    Ok((peer_id, cert_der, key_der))
}

pub fn load_daemon_identity(
    conn: &Connection,
) -> Result<
    (String, CertificateDer<'static>, PrivatePkcs8KeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let row = crate::db::daemon_identity::load(conn)?
        .ok_or("daemon transport identity not found; start the daemon or create an invite first")?;
    Ok((
        row.peer_id,
        CertificateDer::from(row.cert_der),
        PrivatePkcs8KeyDer::from(row.key_der),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn ensure_daemon_identity_generates_and_persists() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let first = ensure_daemon_identity(&conn).unwrap();
        let second = ensure_daemon_identity(&conn).unwrap();

        assert_eq!(first.0, second.0);
        assert_eq!(first.0.len(), 64);
    }

    #[test]
    fn load_daemon_identity_fails_when_missing() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        assert!(load_daemon_identity(&conn).is_err());
    }
}
