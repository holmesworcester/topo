use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::queue::current_timestamp_ms;
use crate::crypto::spki_fingerprint_from_ed25519_pubkey;

/// Pending bootstrap trust from locally-created invites is temporary.
/// If a peer never joins, this entry should not authorize transport forever.
pub(crate) const PENDING_INVITE_BOOTSTRAP_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// Accepted bootstrap trust is also temporary until steady-state transport key
/// trust converges for that same SPKI.
pub(crate) const ACCEPTED_INVITE_BOOTSTRAP_TTL_MS: i64 = 24 * 60 * 60 * 1000;

// Canonical tenant-scoped transport authorization over projected trust rows.
//
// Authoritative sources:
// - peers_shared.transport_fingerprint (steady-state)
// - invite_bootstrap_trust.bootstrap_spki_fingerprint (accepted bootstrap)
// - pending_invite_bootstrap_trust.expected_bootstrap_spki_fingerprint (pending bootstrap)
//
// Observation telemetry (peer_transport_bindings) is intentionally excluded.
//
// The CTE body that unions these three sources is shared across multiple
// queries via macros below. Each query composes the shared CTE prefix with
// a variant-specific outer SELECT/WHERE suffix using concat!().

/// Tenant-scoped authorized transport CTE (params: ?1 = recorded_by).
/// Produces rows of (spki_fingerprint BLOB, expires_at INTEGER|NULL).
macro_rules! tenant_authorized_cte {
    () => {
        "
    WITH authorized_transport_rows AS (
        SELECT
            p.transport_fingerprint AS spki_fingerprint,
            NULL AS expires_at
        FROM peers_shared p
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
          )

        UNION

        SELECT
            t.bootstrap_spki_fingerprint AS spki_fingerprint,
            t.expires_at AS expires_at
        FROM invite_bootstrap_trust t
        WHERE t.recorded_by = ?1
          AND length(t.bootstrap_spki_fingerprint) = 32

        UNION

        SELECT
            t.expected_bootstrap_spki_fingerprint AS spki_fingerprint,
            t.expires_at AS expires_at
        FROM pending_invite_bootstrap_trust t
        WHERE t.recorded_by = ?1
          AND length(t.expected_bootstrap_spki_fingerprint) = 32
    )
    "
    };
}

/// Tenant-scoped authorized transport CTE with fingerprint equality filter
/// (params: ?1 = recorded_by, ?2 = spki_fingerprint).
/// Produces rows of (spki_fingerprint BLOB, expires_at INTEGER|NULL).
/// Each UNION branch is narrowed to a single fingerprint for early pruning.
macro_rules! tenant_authorized_cte_for_fingerprint {
    () => {
        "
    WITH authorized_transport_rows AS (
        SELECT
            p.transport_fingerprint AS spki_fingerprint,
            NULL AS expires_at
        FROM peers_shared p
        WHERE p.recorded_by = ?1
          AND length(p.transport_fingerprint) = 32
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

        UNION

        SELECT
            t.bootstrap_spki_fingerprint AS spki_fingerprint,
            t.expires_at AS expires_at
        FROM invite_bootstrap_trust t
        WHERE t.recorded_by = ?1
          AND length(t.bootstrap_spki_fingerprint) = 32
          AND t.bootstrap_spki_fingerprint = ?2

        UNION

        SELECT
            t.expected_bootstrap_spki_fingerprint AS spki_fingerprint,
            t.expires_at AS expires_at
        FROM pending_invite_bootstrap_trust t
        WHERE t.recorded_by = ?1
          AND length(t.expected_bootstrap_spki_fingerprint) = 32
          AND t.expected_bootstrap_spki_fingerprint = ?2
    )
    "
    };
}

/// Node-scoped authorized transport CTE (no tenant filter).
/// Produces rows of (tenant_id TEXT, spki_fingerprint BLOB, expires_at INTEGER|NULL).
macro_rules! node_authorized_cte {
    () => {
        "
    WITH authorized_transport_rows AS (
        SELECT
            p.recorded_by AS tenant_id,
            p.transport_fingerprint AS spki_fingerprint,
            NULL AS expires_at
        FROM peers_shared p
        WHERE length(p.transport_fingerprint) = 32
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

        UNION

        SELECT
            t.recorded_by AS tenant_id,
            t.bootstrap_spki_fingerprint AS spki_fingerprint,
            t.expires_at AS expires_at
        FROM invite_bootstrap_trust t
        WHERE length(t.bootstrap_spki_fingerprint) = 32

        UNION

        SELECT
            t.recorded_by AS tenant_id,
            t.expected_bootstrap_spki_fingerprint AS spki_fingerprint,
            t.expires_at AS expires_at
        FROM pending_invite_bootstrap_trust t
        WHERE length(t.expected_bootstrap_spki_fingerprint) = 32
    )
    "
    };
}

const TENANT_AUTHORIZED_FINGERPRINTS_SQL: &str = concat!(
    tenant_authorized_cte!(),
    "SELECT DISTINCT spki_fingerprint
    FROM authorized_transport_rows
    WHERE expires_at IS NULL OR expires_at > ?2"
);

const TENANT_AUTHORIZATION_EXISTS_SQL: &str = concat!(
    tenant_authorized_cte_for_fingerprint!(),
    "SELECT EXISTS(
        SELECT 1
        FROM authorized_transport_rows
        WHERE expires_at IS NULL OR expires_at > ?3
    )"
);

const TENANT_HAS_ANY_AUTHORIZED_FINGERPRINT_SQL: &str = concat!(
    tenant_authorized_cte!(),
    "SELECT EXISTS(
        SELECT 1
        FROM authorized_transport_rows
        WHERE expires_at IS NULL OR expires_at > ?2
    )"
);

const TENANT_AUTHORIZED_TRANSPORT_ROWS_SQL: &str = "
    WITH authorized_transport_rows AS (
        SELECT DISTINCT
            'peer_shared' AS source,
            lower(hex(p.transport_fingerprint)) AS transport_peer_id,
            p.event_id AS peer_shared_event_id,
            p.user_event_id AS user_event_id,
            p.device_name AS device_name,
            NULL AS invite_event_id,
            NULL AS invite_accepted_event_id,
            NULL AS workspace_id,
            NULL AS expires_at
        FROM peers_shared p
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
          )

        UNION ALL

        SELECT
            'accepted_bootstrap' AS source,
            lower(hex(t.bootstrap_spki_fingerprint)) AS transport_peer_id,
            NULL AS peer_shared_event_id,
            NULL AS user_event_id,
            NULL AS device_name,
            t.invite_event_id AS invite_event_id,
            t.invite_accepted_event_id AS invite_accepted_event_id,
            t.workspace_id AS workspace_id,
            MAX(t.expires_at) AS expires_at
        FROM invite_bootstrap_trust t
        WHERE t.recorded_by = ?1
          AND length(t.bootstrap_spki_fingerprint) = 32
        GROUP BY
            t.bootstrap_spki_fingerprint,
            t.invite_event_id,
            t.invite_accepted_event_id,
            t.workspace_id

        UNION ALL

        SELECT DISTINCT
            'pending_bootstrap' AS source,
            lower(hex(t.expected_bootstrap_spki_fingerprint)) AS transport_peer_id,
            NULL AS peer_shared_event_id,
            NULL AS user_event_id,
            NULL AS device_name,
            t.invite_event_id AS invite_event_id,
            NULL AS invite_accepted_event_id,
            t.workspace_id AS workspace_id,
            t.expires_at AS expires_at
        FROM pending_invite_bootstrap_trust t
        WHERE t.recorded_by = ?1
          AND length(t.expected_bootstrap_spki_fingerprint) = 32
    )
    SELECT
        source,
        transport_peer_id,
        peer_shared_event_id,
        user_event_id,
        device_name,
        invite_event_id,
        invite_accepted_event_id,
        workspace_id,
        expires_at
    FROM authorized_transport_rows
    WHERE expires_at IS NULL OR expires_at > ?2
    ORDER BY
        CASE source
            WHEN 'peer_shared' THEN 0
            WHEN 'accepted_bootstrap' THEN 1
            ELSE 2
        END,
        transport_peer_id ASC,
        COALESCE(peer_shared_event_id, invite_accepted_event_id, invite_event_id, '') ASC
";

const NODE_AUTHORIZATION_EXISTS_SQL: &str = concat!(
    node_authorized_cte!(),
    "SELECT EXISTS(
        SELECT 1
        FROM authorized_transport_rows
        WHERE spki_fingerprint = ?1
          AND (expires_at IS NULL OR expires_at > ?2)
    )"
);

const NODE_AUTHORIZING_TENANT_SQL: &str = concat!(
    node_authorized_cte!(),
    "SELECT tenant_id
    FROM authorized_transport_rows
    WHERE spki_fingerprint = ?1
      AND (expires_at IS NULL OR expires_at > ?2)
    ORDER BY tenant_id ASC
    LIMIT 1"
);

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
            PRIMARY KEY (recorded_by, invite_accepted_event_id, bootstrap_addr)
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

        CREATE TABLE IF NOT EXISTS removed_entities (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            target_event_id TEXT NOT NULL,
            removal_type TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id, target_event_id, removal_type)
        );
        CREATE INDEX IF NOT EXISTS idx_removed_entities_target
            ON removed_entities(recorded_by, target_event_id, removal_type);
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
    let now = current_timestamp_ms();
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

/// Bootstrap context read result — aggregated across all addresses for one invite.
pub struct BootstrapContext {
    pub workspace_id: String,
    pub bootstrap_addrs: Vec<String>,
    pub bootstrap_spki_fingerprint: [u8; 32],
}

/// Read all bootstrap context rows for a given invite event.
///
/// Returns all distinct addresses recorded. The SPKI and workspace_id are
/// taken from the most recent row (by `observed_at DESC`).
pub fn read_bootstrap_context(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: &str,
) -> Result<Option<BootstrapContext>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT workspace_id, bootstrap_addr, bootstrap_spki_fingerprint
         FROM bootstrap_context
         WHERE recorded_by = ?1 AND invite_event_id = ?2
         ORDER BY observed_at DESC, rowid DESC",
    )?;
    let mut rows = stmt.query(rusqlite::params![recorded_by, invite_event_id])?;
    let mut workspace_id: Option<String> = None;
    let mut spki: Option<[u8; 32]> = None;
    let mut addrs = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while let Some(row) = rows.next()? {
        let ws: String = row.get(0)?;
        let addr: String = row.get(1)?;
        let blob: Vec<u8> = row.get(2)?;
        if workspace_id.is_none() {
            workspace_id = Some(ws);
            spki = Some(
                decode_32_byte_blob(blob).ok_or("bootstrap_spki_fingerprint is not 32 bytes")?,
            );
        }
        if seen.insert(addr.clone()) {
            addrs.push(addr);
        }
    }
    match (workspace_id, spki) {
        (Some(ws), Some(fp)) => Ok(Some(BootstrapContext {
            workspace_id: ws,
            bootstrap_addrs: addrs,
            bootstrap_spki_fingerprint: fp,
        })),
        _ => Ok(None),
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
/// authorization queries use projected trust rows only.
pub fn record_transport_binding(
    conn: &Connection,
    recorded_by: &str,
    peer_id: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT OR IGNORE INTO peer_transport_bindings (recorded_by, peer_id, spki_fingerprint, bound_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, peer_id, spki_fingerprint.as_slice(), current_timestamp_ms()],
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
    let now = current_timestamp_ms();
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
/// before steady-state PeerShared trust appears.
///
/// Uses INSERT OR IGNORE so replays do not refresh TTL.
pub fn record_pending_invite_bootstrap_trust(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: &str,
    workspace_id: &str,
    expected_bootstrap_spki_fingerprint: &[u8; 32],
) -> Result<(), rusqlite::Error> {
    let now = current_timestamp_ms();
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

/// Check whether a peer fingerprint is backed by projected PeerShared state for
/// this tenant. Bootstrap trust aliases are intentionally excluded.
pub fn is_peer_shared_transport_fingerprint(
    conn: &Connection,
    recorded_by: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    is_peer_shared_spki(conn, recorded_by, spki_fingerprint)
}

/// Return the tenant's currently authorized remote transport fingerprints.
/// Observation telemetry (peer_transport_bindings) is NOT consulted.
pub fn authorized_fingerprints_from_db(
    conn: &Connection,
    recorded_by: &str,
) -> Result<HashSet<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    let now = current_timestamp_ms();
    let mut stmt = conn.prepare(TENANT_AUTHORIZED_FINGERPRINTS_SQL)?;
    let fps: HashSet<[u8; 32]> = stmt
        .query_map(rusqlite::params![recorded_by, now], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(decode_32_byte_blob(blob))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    Ok(fps)
}

/// Canonical tenant-scoped transport authorization over projected trust rows.
///
/// Returns true iff `spki_fingerprint` is currently authorized for `tenant_id`
/// by any authoritative projected trust source.
pub fn is_authorized_for_tenant(
    conn: &Connection,
    tenant_id: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let now = current_timestamp_ms();
    let allowed: i64 = conn.query_row(
        TENANT_AUTHORIZATION_EXISTS_SQL,
        rusqlite::params![tenant_id, spki_fingerprint.as_slice(), now],
        |row| row.get(0),
    )?;
    Ok(allowed != 0)
}

/// Resolve one tenant that currently authorizes `spki_fingerprint`.
pub fn resolve_authorizing_tenant(
    conn: &Connection,
    spki_fingerprint: &[u8; 32],
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let now = current_timestamp_ms();
    let tenant_id = conn
        .query_row(
            NODE_AUTHORIZING_TENANT_SQL,
            rusqlite::params![spki_fingerprint.as_slice(), now],
            |row| row.get(0),
        )
        .optional()?;
    Ok(tenant_id)
}

/// Canonical node-scoped inbound transport authorization over projected trust rows.
pub fn is_authorized_for_node(
    conn: &Connection,
    spki_fingerprint: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let now = current_timestamp_ms();
    let allowed: i64 = conn.query_row(
        NODE_AUTHORIZATION_EXISTS_SQL,
        rusqlite::params![spki_fingerprint.as_slice(), now],
        |row| row.get(0),
    )?;
    Ok(allowed != 0)
}

/// Check whether any tenant-scoped transport authorization rows are currently
/// live without materializing the full set. Uses EXISTS for early exit.
pub fn has_any_trusted_peer(
    conn: &Connection,
    recorded_by: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let now = current_timestamp_ms();
    let has_any: i64 = conn.query_row(
        TENANT_HAS_ANY_AUTHORIZED_FINGERPRINT_SQL,
        rusqlite::params![recorded_by, now],
        |row| row.get(0),
    )?;
    Ok(has_any != 0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedTransportRow {
    pub source: String,
    pub transport_peer_id: String,
    pub peer_shared_event_id: Option<String>,
    pub user_event_id: Option<String>,
    pub device_name: Option<String>,
    pub invite_event_id: Option<String>,
    pub invite_accepted_event_id: Option<String>,
    pub workspace_id: Option<String>,
    pub expires_at: Option<i64>,
}

/// Return all currently authorized transport fingerprints for one tenant,
/// including their projected provenance rows.
pub fn list_authorized_transport_rows(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Vec<AuthorizedTransportRow>, Box<dyn std::error::Error + Send + Sync>> {
    let now = current_timestamp_ms();
    let mut stmt = conn.prepare(TENANT_AUTHORIZED_TRANSPORT_ROWS_SQL)?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by, now], |row| {
            Ok(AuthorizedTransportRow {
                source: row.get(0)?,
                transport_peer_id: row.get(1)?,
                peer_shared_event_id: row.get(2)?,
                user_event_id: row.get(3)?,
                device_name: row.get(4)?,
                invite_event_id: row.get(5)?,
                invite_accepted_event_id: row.get(6)?,
                workspace_id: row.get(7)?,
                expires_at: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// List active invite bootstrap addresses for a tenant.
///
/// This is intentionally transport-only metadata used by startup autodial.
/// It does not authorize trust decisions on its own.
pub fn list_active_invite_bootstrap_addrs(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for target in list_active_invite_bootstrap_targets(conn, recorded_by)? {
        if seen.insert(target.bootstrap_addr.clone()) {
            out.push(target.bootstrap_addr);
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteBootstrapTarget {
    pub invite_event_id: String,
    pub transport_peer_id: String,
    pub bootstrap_addr: String,
}

/// List active invite bootstrap targets for a tenant, keyed by invite_event_id.
///
/// Returns all non-expired addresses. When multiple invite acceptances exist
/// for the same invite_event_id, only addresses from the newest acceptance win.
pub fn list_active_invite_bootstrap_targets(
    conn: &Connection,
    recorded_by: &str,
) -> Result<Vec<InviteBootstrapTarget>, Box<dyn std::error::Error + Send + Sync>> {
    let now = current_timestamp_ms();
    let mut stmt = conn.prepare(
        "SELECT t.invite_event_id, t.bootstrap_spki_fingerprint, t.bootstrap_addr
           FROM invite_bootstrap_trust t
          WHERE t.recorded_by = ?1
            AND t.expires_at > ?2
            AND t.bootstrap_addr <> ''
            AND t.invite_accepted_event_id = (
                SELECT t2.invite_accepted_event_id
                  FROM invite_bootstrap_trust t2
                 WHERE t2.recorded_by = t.recorded_by
                   AND t2.invite_event_id = t.invite_event_id
                   AND t2.expires_at > ?2
                   AND t2.bootstrap_addr <> ''
                 ORDER BY t2.accepted_at DESC, t2.invite_accepted_event_id DESC
                 LIMIT 1
            )
          ORDER BY t.accepted_at DESC, t.invite_accepted_event_id DESC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by, now], |row| {
            let bootstrap_spki_fingerprint: Vec<u8> = row.get(1)?;
            let transport_peer_id = decode_32_byte_blob(bootstrap_spki_fingerprint)
                .map(hex::encode)
                .ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Blob,
                        "bootstrap_spki_fingerprint is not 32 bytes".into(),
                    )
                })?;
            Ok(InviteBootstrapTarget {
                invite_event_id: row.get(0)?,
                transport_peer_id,
                bootstrap_addr: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Thin alias so that `#[cfg(test)] mod tests` (which uses `super::*`) can
/// continue calling `now_ms_i64()` without modification.
#[cfg(test)]
fn now_ms_i64() -> i64 {
    current_timestamp_ms()
}

#[cfg(test)]
mod tests;
