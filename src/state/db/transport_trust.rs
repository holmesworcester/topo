use rusqlite::Connection;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::crypto::{spki_fingerprint_from_ed25519_pubkey, AllowedPeers};

/// Pending bootstrap trust from locally-created invites is temporary.
/// If a peer never joins, this entry should not authorize transport forever.
pub(crate) const PENDING_INVITE_BOOTSTRAP_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// Accepted bootstrap trust is also temporary until steady-state transport key
/// trust converges for that same SPKI.
pub(crate) const ACCEPTED_INVITE_BOOTSTRAP_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Workspace sentinel for CLI-pin-imported bootstrap trust rows.
const CLI_PIN_WORKSPACE: &str = "cli-bootstrap";

/// Build the deterministic `invite_event_id` for a CLI-pin import.
/// Uses the full 32-byte hex fingerprint so distinct pins never collide.
fn cli_pin_invite_event_id(spki_fingerprint: &[u8; 32]) -> String {
    format!("cli-pin-{}", hex::encode(spki_fingerprint))
}

fn now_ms_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn decode_32_byte_blob(blob: Vec<u8>) -> Option<[u8; 32]> {
    if blob.len() != 32 {
        return None;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&blob);
    Some(fp)
}

pub fn ensure_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS peer_transport_bindings (
            recorded_by TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            spki_fingerprint BLOB NOT NULL,
            bound_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, peer_id)
        );
        CREATE INDEX IF NOT EXISTS idx_transport_bindings_spki
            ON peer_transport_bindings(recorded_by, spki_fingerprint);

        CREATE TABLE IF NOT EXISTS invite_bootstrap_trust (
            recorded_by TEXT NOT NULL,
            invite_accepted_event_id TEXT NOT NULL,
            invite_event_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            bootstrap_addr TEXT NOT NULL,
            bootstrap_spki_fingerprint BLOB NOT NULL,
            accepted_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, invite_accepted_event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_invite_bootstrap_spki
            ON invite_bootstrap_trust(recorded_by, bootstrap_spki_fingerprint);
        CREATE INDEX IF NOT EXISTS idx_invite_bootstrap_live
            ON invite_bootstrap_trust(recorded_by, expires_at);

        CREATE TABLE IF NOT EXISTS pending_invite_bootstrap_trust (
            recorded_by TEXT NOT NULL,
            invite_event_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            expected_bootstrap_spki_fingerprint BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, invite_event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_pending_invite_bootstrap_spki
            ON pending_invite_bootstrap_trust(recorded_by, expected_bootstrap_spki_fingerprint);
        CREATE INDEX IF NOT EXISTS idx_pending_invite_bootstrap_live
            ON pending_invite_bootstrap_trust(recorded_by, expires_at);

        CREATE TABLE IF NOT EXISTS bootstrap_context (
            recorded_by TEXT NOT NULL,
            invite_event_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            bootstrap_addr TEXT NOT NULL,
            bootstrap_spki_fingerprint BLOB NOT NULL,
            observed_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bootstrap_context_lookup
            ON bootstrap_context(recorded_by, invite_event_id, observed_at DESC);
        ",
    )?;
    Ok(())
}

/// Append a bootstrap context observation — local durable context used as
/// projection input when materializing trust rows from events.
///
/// Rows are append-only (no UPDATE). The reader picks the latest observation
/// by `observed_at DESC`. Service/bootstrap code appends context rows
/// (bootstrap_addr + bootstrap_spki observed during invite creation or
/// acceptance). Projectors read the winning row to produce trust table
/// entries without the service layer writing trust rows directly.
pub fn append_bootstrap_context(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: &str,
    workspace_id: &str,
    bootstrap_addr: &str,
    bootstrap_spki_fingerprint: &[u8; 32],
) -> Result<(), rusqlite::Error> {
    let now = now_ms_i64();
    conn.execute(
        "INSERT INTO bootstrap_context (
             recorded_by,
             invite_event_id,
             workspace_id,
             bootstrap_addr,
             bootstrap_spki_fingerprint,
             observed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            recorded_by,
            invite_event_id,
            workspace_id,
            bootstrap_addr,
            bootstrap_spki_fingerprint.as_slice(),
            now,
        ],
    )?;
    Ok(())
}

/// Bootstrap context read result.
pub struct BootstrapContext {
    pub workspace_id: String,
    pub bootstrap_addr: String,
    pub bootstrap_spki_fingerprint: [u8; 32],
}

/// Read the latest bootstrap context for a given invite event.
///
/// Picks the winner from append-only rows by `observed_at DESC`.
pub fn read_bootstrap_context(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: &str,
) -> Result<Option<BootstrapContext>, Box<dyn std::error::Error + Send + Sync>> {
    match conn.query_row(
        "SELECT workspace_id, bootstrap_addr, bootstrap_spki_fingerprint
         FROM bootstrap_context
         WHERE recorded_by = ?1 AND invite_event_id = ?2
         ORDER BY observed_at DESC, rowid DESC
         LIMIT 1",
        rusqlite::params![recorded_by, invite_event_id],
        |row| {
            let ws: String = row.get(0)?;
            let addr: String = row.get(1)?;
            let blob: Vec<u8> = row.get(2)?;
            Ok((ws, addr, blob))
        },
    ) {
        Ok((ws, addr, blob)) => {
            let fp =
                decode_32_byte_blob(blob).ok_or("bootstrap_spki_fingerprint is not 32 bytes")?;
            Ok(Some(BootstrapContext {
                workspace_id: ws,
                bootstrap_addr: addr,
                bootstrap_spki_fingerprint: fp,
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Consume bootstrap trust rows whose SPKI matches a PeerShared-derived SPKI.
///
/// Called by the projection pipeline when a PeerShared event is projected,
/// so that trust check reads are pure (no write side-effects).
pub fn consume_bootstrap_for_peer_shared(
    conn: &Connection,
    recorded_by: &str,
    peer_shared_public_key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let spki = spki_fingerprint_from_ed25519_pubkey(peer_shared_public_key);
    consume_bootstrap_for_transport_fingerprint(conn, recorded_by, &spki)
}

/// Consume bootstrap trust rows by transport fingerprint directly.
pub fn consume_bootstrap_for_transport_fingerprint(
    conn: &Connection,
    recorded_by: &str,
    transport_fingerprint: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    conn.execute(
        "DELETE FROM pending_invite_bootstrap_trust
          WHERE recorded_by = ?1
            AND expected_bootstrap_spki_fingerprint = ?2",
        rusqlite::params![recorded_by, transport_fingerprint.as_slice()],
    )?;
    conn.execute(
        "DELETE FROM invite_bootstrap_trust
          WHERE recorded_by = ?1
            AND bootstrap_spki_fingerprint = ?2",
        rusqlite::params![recorded_by, transport_fingerprint.as_slice()],
    )?;
    Ok(())
}

/// Record an observed transport binding (observation telemetry only).
/// peer_id (hex SPKI fingerprint) was seen on a TLS connection with this SPKI
/// fingerprint. Idempotent (INSERT OR IGNORE). NOT used for trust decisions —
/// allowed_peers_from_db queries PeerShared-derived SPKIs and bootstrap trust only.
pub fn record_transport_binding(
    conn: &Connection,
    recorded_by: &str,
    peer_id: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT OR IGNORE INTO peer_transport_bindings (recorded_by, peer_id, spki_fingerprint, bound_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, peer_id, spki_fingerprint.as_slice(), now_ms_i64()],
    )?;
    Ok(())
}

/// Record invite-accepted bootstrap trust metadata.
/// This allows sync bootstrapping from accepted invite links before
/// PeerShared-derived trust appears via identity event sync.
///
/// Uses INSERT OR IGNORE so replays do not refresh TTL.
pub fn record_invite_bootstrap_trust(
    conn: &Connection,
    recorded_by: &str,
    invite_accepted_event_id: &str,
    invite_event_id: &str,
    workspace_id: &str,
    bootstrap_addr: &str,
    bootstrap_spki_fingerprint: &[u8; 32],
) -> Result<(), rusqlite::Error> {
    let now = now_ms_i64();
    conn.execute(
        "INSERT OR IGNORE INTO invite_bootstrap_trust (
             recorded_by,
             invite_accepted_event_id,
             invite_event_id,
             workspace_id,
             bootstrap_addr,
             bootstrap_spki_fingerprint,
             accepted_at,
             expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            recorded_by,
            invite_accepted_event_id,
            invite_event_id,
            workspace_id,
            bootstrap_addr,
            bootstrap_spki_fingerprint.as_slice(),
            now,
            now + ACCEPTED_INVITE_BOOTSTRAP_TTL_MS,
        ],
    )?;
    Ok(())
}

/// Record inviter-side pending bootstrap trust for an invite before the invitee
/// has connected. This lets incoming invitee TLS certs pass strict mTLS checks
/// without CLI pin flags.
///
/// Uses INSERT OR IGNORE so replays do not refresh TTL.
pub fn record_pending_invite_bootstrap_trust(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: &str,
    workspace_id: &str,
    expected_bootstrap_spki_fingerprint: &[u8; 32],
) -> Result<(), rusqlite::Error> {
    let now = now_ms_i64();
    conn.execute(
        "INSERT OR IGNORE INTO pending_invite_bootstrap_trust (
             recorded_by,
             invite_event_id,
             workspace_id,
             expected_bootstrap_spki_fingerprint,
             created_at,
             expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            recorded_by,
            invite_event_id,
            workspace_id,
            expected_bootstrap_spki_fingerprint.as_slice(),
            now,
            now + PENDING_INVITE_BOOTSTRAP_TTL_MS,
        ],
    )?;
    Ok(())
}

/// Import CLI pin hex strings as `pending_invite_bootstrap_trust` rows.
///
/// Each pin is stored with a deterministic `invite_event_id` (via
/// `cli_pin_invite_event_id`) and `workspace_id = CLI_PIN_WORKSPACE`.
/// Reuses the existing table and 24h TTL.
/// Existing consume logic auto-removes these stale rows when PeerShared-derived trust appears.
///
/// This is idempotent: re-importing existing pins is a no-op (INSERT OR IGNORE).
pub fn import_cli_pins_to_sql(
    conn: &Connection,
    recorded_by: &str,
    cli_pins: &AllowedPeers,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let fps = cli_pins.fingerprints();
    let mut imported = 0;
    for fp in &fps {
        let invite_event_id = cli_pin_invite_event_id(fp);
        record_pending_invite_bootstrap_trust(
            conn,
            recorded_by,
            &invite_event_id,
            CLI_PIN_WORKSPACE,
            fp,
        )?;
        imported += 1;
    }
    if imported > 0 {
        info!("Imported {} CLI pin(s) to SQL trust rows", imported);
    }
    Ok(imported)
}

/// Compute SPKI fingerprints for all non-removed PeerShared public keys belonging to a peer.
fn peer_shared_spki_fingerprints(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    let mut out = HashSet::new();

    // Transport trust resolution is projection-backed only.
    let mut stmt = conn.prepare(
        "SELECT p.transport_fingerprint FROM peers_shared p
         WHERE p.recorded_by = ?1
           AND length(p.transport_fingerprint) = 32
           AND NOT EXISTS (
             SELECT 1 FROM removed_entities r
             WHERE r.recorded_by = p.recorded_by
               AND r.target_event_id = p.event_id
           )
           AND NOT EXISTS (
             SELECT 1 FROM removed_entities r
             WHERE r.recorded_by = p.recorded_by
               AND p.user_event_id IS NOT NULL
               AND r.target_event_id = p.user_event_id
               AND r.removal_type = 'user'
           )",
    )?;
    let direct_fps: Vec<[u8; 32]> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(row.get::<_, Vec<u8>>(0)?)
        })?
        .filter_map(|r| r.ok().and_then(decode_32_byte_blob))
        .collect();
    out.extend(direct_fps);

    Ok(out.into_iter().collect())
}

/// Check whether a given SPKI fingerprint matches any PeerShared-derived identity.
fn is_peer_shared_spki(
    conn: &Connection,
    recorded_by: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let matched: bool = conn.query_row(
        "SELECT EXISTS (
            SELECT 1 FROM peers_shared p
            WHERE p.recorded_by = ?1
              AND p.transport_fingerprint = ?2
              AND NOT EXISTS (
                SELECT 1 FROM removed_entities r
                WHERE r.recorded_by = p.recorded_by
                  AND r.target_event_id = p.event_id
              )
              AND NOT EXISTS (
                SELECT 1 FROM removed_entities r
                WHERE r.recorded_by = p.recorded_by
                  AND p.user_event_id IS NOT NULL
                  AND r.target_event_id = p.user_event_id
                  AND r.removal_type = 'user'
              )
        )",
        rusqlite::params![recorded_by, spki_fingerprint.as_slice()],
        |row| row.get(0),
    )?;
    Ok(matched)
}

/// Build AllowedPeers from SQL trust sources only.
/// Trust sources: PeerShared-derived SPKIs (steady-state) ∪ accepted invite
/// bootstrap trust ∪ pending invite bootstrap trust.
/// Observation telemetry (peer_transport_bindings) is NOT consulted for trust.
pub fn allowed_peers_from_db(
    conn: &Connection,
    recorded_by: &str,
) -> Result<AllowedPeers, Box<dyn std::error::Error + Send + Sync>> {
    // Supersession is handled at projection time via PeerShared writes.
    // Trust check reads are pure.
    let now = now_ms_i64();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT bootstrap_spki_fingerprint AS spki_fingerprint
          FROM invite_bootstrap_trust
          WHERE recorded_by = ?1
            AND expires_at > ?2
         UNION
         SELECT DISTINCT expected_bootstrap_spki_fingerprint AS spki_fingerprint
          FROM pending_invite_bootstrap_trust
          WHERE recorded_by = ?1
            AND expires_at > ?2",
    )?;
    let mut fps: Vec<[u8; 32]> = stmt
        .query_map(rusqlite::params![recorded_by, now], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(decode_32_byte_blob(blob))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();

    // Add PeerShared-derived SPKIs (primary steady-state trust source)
    fps.extend(peer_shared_spki_fingerprints(conn, recorded_by)?);

    Ok(AllowedPeers::from_fingerprints(fps))
}

/// Check a single peer fingerprint against SQL trust sources.
/// Trust sources: PeerShared-derived SPKIs ∪ accepted bootstrap ∪ pending bootstrap.
pub fn is_peer_allowed(
    conn: &Connection,
    recorded_by: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    // Supersession is handled at projection time via PeerShared writes.
    // Trust check reads are pure.
    // Check PeerShared-derived SPKIs first (primary steady-state trust source)
    if is_peer_shared_spki(conn, recorded_by, spki_fingerprint)? {
        return Ok(true);
    }
    let now = now_ms_i64();
    let allowed: i64 = conn.query_row(
        "SELECT
            EXISTS(
                SELECT 1
                  FROM invite_bootstrap_trust
                 WHERE recorded_by = ?1
                   AND bootstrap_spki_fingerprint = ?2
                   AND expires_at > ?3
            )
            OR EXISTS(
                SELECT 1
                  FROM pending_invite_bootstrap_trust
                 WHERE recorded_by = ?1
                   AND expected_bootstrap_spki_fingerprint = ?2
                   AND expires_at > ?3
            )",
        rusqlite::params![recorded_by, spki_fingerprint.as_slice(), now],
        |row| row.get(0),
    )?;
    Ok(allowed != 0)
}

/// Check whether any trusted peer fingerprints exist in SQL trust sources
/// without materializing the full set. Uses EXISTS for early exit.
pub fn has_any_trusted_peer(
    conn: &Connection,
    recorded_by: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    // Supersession is handled at projection time via PeerShared writes.
    // Trust check reads are pure.
    let now = now_ms_i64();
    let has_any: i64 = conn.query_row(
        "SELECT
            EXISTS(
                SELECT 1 FROM invite_bootstrap_trust
                WHERE recorded_by = ?1
                  AND length(bootstrap_spki_fingerprint) = 32
                  AND expires_at > ?2
            )
            OR EXISTS(
                SELECT 1 FROM pending_invite_bootstrap_trust
                WHERE recorded_by = ?1
                  AND length(expected_bootstrap_spki_fingerprint) = 32
                  AND expires_at > ?2
            )
            OR EXISTS(
                SELECT 1 FROM peers_shared
                WHERE recorded_by = ?1
                  AND length(transport_fingerprint) = 32
                  AND NOT EXISTS (
                    SELECT 1 FROM removed_entities r
                    WHERE r.recorded_by = peers_shared.recorded_by
                      AND r.target_event_id = peers_shared.event_id
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM removed_entities r
                    WHERE r.recorded_by = peers_shared.recorded_by
                      AND peers_shared.user_event_id IS NOT NULL
                      AND r.target_event_id = peers_shared.user_event_id
                      AND r.removal_type = 'user'
                  )
            )",
        rusqlite::params![recorded_by, now],
        |row| row.get(0),
    )?;
    Ok(has_any != 0)
}

/// List active invite bootstrap addresses for a tenant.
///
/// This is intentionally transport-only metadata used by startup autodial.
/// It does not authorize trust decisions on its own.
pub fn list_active_invite_bootstrap_addrs(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    // Supersession is now handled at projection time.
    let now = now_ms_i64();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT bootstrap_addr
           FROM invite_bootstrap_trust
          WHERE recorded_by = ?1
            AND expires_at > ?2",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by, now], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests;
