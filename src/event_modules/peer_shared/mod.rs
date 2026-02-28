pub mod wire;
pub mod projector;
pub mod queries;

// Re-export stable public API so callers import from `event_modules::peer_shared`.
pub use wire::{
    PeerSharedFirstEvent, PeerSharedOngoingEvent,
    parse_peer_shared_first, encode_peer_shared_first,
    parse_peer_shared_ongoing, encode_peer_shared_ongoing,
    PEER_SHARED_WIRE_SIZE,
    PEER_SHARED_FIRST_META, PEER_SHARED_ONGOING_META,
};
pub use queries::{
    count, list_event_ids, first_event_id, AccountRow, list_accounts,
    load_local_peer_signer, load_local_peer_signer_required, resolve_user_event_id,
    resolve_event_id_by_transport_fingerprint,
    load_local_user_key,
    AccountItem, list_account_items, IdentityResponse, identity,
};
pub use projector::project_pure;

use rusqlite::Connection;

fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
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
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_peers_shared_transport_fingerprint
            ON peers_shared(recorded_by, transport_fingerprint);
        ",
    )?;
    Ok(())
}
