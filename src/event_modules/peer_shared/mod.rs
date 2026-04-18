//! `peer_shared` event (type 16): publicly-visible binding of a user to a transport
//! endpoint. Conceptually today's "account_shared"; the wire `type_name` is preserved for
//! durable on-the-wire compatibility. See the canonical-naming note in DESIGN.md.

pub mod projector;
pub mod queries;
pub mod wire;

pub use projector::project_pure;
pub use queries::{
    count, first_event_id, identity, list_event_ids, list_peers, list_tenant_items, list_tenants,
    load_local_peer_signer, load_local_peer_signer_required,
    resolve_event_id_by_transport_fingerprint, resolve_user_event_id, IdentityResponse, PeerItem,
    TenantItem, TenantRow,
};
pub use wire::{
    encode_peer_shared, parse_peer_shared, PeerSharedEvent, PEER_SHARED_META, PEER_SHARED_WIRE_SIZE,
};

use rusqlite::Connection;

fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name = crate::db::sql_types::get_text(row, 1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS peers_shared (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            transport_fingerprint BLOB,
            endpoint_shared_event_id TEXT,
            endpoint_id TEXT,
            user_event_id TEXT,
            device_name TEXT,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    if !column_exists(conn, "peers_shared", "transport_fingerprint")? {
        conn.execute(
            "ALTER TABLE peers_shared ADD COLUMN transport_fingerprint BLOB",
            [],
        )?;
    }
    if !column_exists(conn, "peers_shared", "endpoint_shared_event_id")? {
        conn.execute(
            "ALTER TABLE peers_shared ADD COLUMN endpoint_shared_event_id TEXT",
            [],
        )?;
    }
    if !column_exists(conn, "peers_shared", "endpoint_id")? {
        conn.execute("ALTER TABLE peers_shared ADD COLUMN endpoint_id TEXT", [])?;
    }
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_peers_shared_transport_fingerprint
            ON peers_shared(recorded_by, transport_fingerprint);
        CREATE INDEX IF NOT EXISTS idx_peers_shared_endpoint_id
            ON peers_shared(recorded_by, endpoint_id);
        ",
    )?;
    Ok(())
}
