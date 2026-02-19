use super::super::result::{EmitCommand, SqlVal, WriteOp};
use crate::crypto::event_id_from_base64;
use rusqlite::Connection;
use rusqlite::OptionalExtension;

/// Execute a list of WriteOps against the database.
///
/// Each WriteOp is executed in order. INSERT OR IGNORE and DELETE are the
/// only supported operations. This is the transactional apply stage.
pub(crate) fn execute_write_ops(
    conn: &Connection,
    ops: &[WriteOp],
) -> Result<(), Box<dyn std::error::Error>> {
    for op in ops {
        match op {
            WriteOp::InsertOrIgnore {
                table,
                columns,
                values,
            } => {
                let cols = columns.join(", ");
                let placeholders: Vec<String> =
                    (1..=values.len()).map(|i| format!("?{}", i)).collect();
                let sql = format!(
                    "INSERT OR IGNORE INTO {} ({}) VALUES ({})",
                    table,
                    cols,
                    placeholders.join(", ")
                );
                let params: Vec<Box<dyn rusqlite::types::ToSql>> = values
                    .iter()
                    .map(|v| -> Box<dyn rusqlite::types::ToSql> {
                        match v {
                            SqlVal::Text(s) => Box::new(s.clone()),
                            SqlVal::Int(i) => Box::new(*i),
                            SqlVal::Blob(b) => Box::new(b.clone()),
                        }
                    })
                    .collect();
                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| &**p).collect();
                conn.execute(&sql, param_refs.as_slice())?;
            }
            WriteOp::Delete {
                table,
                where_clause,
            } => {
                let conditions: Vec<String> = where_clause
                    .iter()
                    .enumerate()
                    .map(|(i, (col, _))| format!("{} = ?{}", col, i + 1))
                    .collect();
                let sql = format!("DELETE FROM {} WHERE {}", table, conditions.join(" AND "));
                let params: Vec<Box<dyn rusqlite::types::ToSql>> = where_clause
                    .iter()
                    .map(|(_, v)| -> Box<dyn rusqlite::types::ToSql> {
                        match v {
                            SqlVal::Text(s) => Box::new(s.clone()),
                            SqlVal::Int(i) => Box::new(*i),
                            SqlVal::Blob(b) => Box::new(b.clone()),
                        }
                    })
                    .collect();
                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| &**p).collect();
                conn.execute(&sql, param_refs.as_slice())?;
            }
        }
    }
    Ok(())
}

/// Execute emitted commands after write_ops have been applied.
pub(crate) fn execute_emit_commands(
    conn: &Connection,
    recorded_by: &str,
    commands: &[EmitCommand],
) -> Result<(), Box<dyn std::error::Error>> {
    for cmd in commands {
        match cmd {
            EmitCommand::RetryWorkspaceGuards => {
                // Find workspace events stuck in guard-blocked limbo and re-project them.
                let guard_candidates: Vec<String> = {
                    let mut stmt = conn.prepare(
                        "SELECT re.event_id
                         FROM recorded_events re
                         INNER JOIN events e ON e.event_id = re.event_id
                         WHERE re.peer_id = ?1
                           AND e.event_type = 'workspace'
                           AND re.event_id NOT IN (SELECT event_id FROM valid_events WHERE peer_id = ?1)
                           AND re.event_id NOT IN (SELECT event_id FROM rejected_events WHERE peer_id = ?1)
                           AND re.event_id NOT IN (SELECT DISTINCT event_id FROM blocked_event_deps WHERE peer_id = ?1)",
                    )?;
                    let mut rows = stmt.query(rusqlite::params![recorded_by])?;
                    let mut result = Vec::new();
                    while let Some(row) = rows.next()? {
                        result.push(row.get::<_, String>(0)?);
                    }
                    result
                };
                for eid_b64 in guard_candidates {
                    if let Some(event_id) = event_id_from_base64(&eid_b64) {
                        let _ = super::project_one(conn, recorded_by, &event_id)?;
                    }
                }
            }
            EmitCommand::RetryFileSliceGuards { file_id } => {
                let fs_candidates: Vec<String> = {
                    let mut stmt = conn.prepare(
                        "SELECT event_id FROM file_slice_guard_blocks
                         WHERE peer_id = ?1 AND file_id = ?2",
                    )?;
                    let mut rows = stmt.query(rusqlite::params![recorded_by, file_id])?;
                    let mut result = Vec::new();
                    while let Some(row) = rows.next()? {
                        result.push(row.get::<_, String>(0)?);
                    }
                    result
                };
                for eid_b64 in fs_candidates {
                    conn.execute(
                        "DELETE FROM file_slice_guard_blocks WHERE peer_id = ?1 AND event_id = ?2",
                        rusqlite::params![recorded_by, &eid_b64],
                    )?;
                    // Re-project: may go Valid, dep-blocked, or guard-blocked again.
                    // Stale blocked_event_deps from prior dep-block→guard-block transitions
                    // are cleaned up by cascade_unblocked_inner's bulk orphan cleanup
                    // (DELETE WHERE event_id NOT IN blocked_events). We do NOT delete dep
                    // edges here because project_one may write fresh dep edges if the event
                    // re-enters dep-blocked state.
                    if let Some(event_id) = event_id_from_base64(&eid_b64) {
                        let _ = super::project_one(conn, recorded_by, &event_id)?;
                    }
                }
            }
            EmitCommand::RecordFileSliceGuardBlock { file_id, event_id } => {
                conn.execute(
                    "INSERT OR IGNORE INTO file_slice_guard_blocks (peer_id, file_id, event_id)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![recorded_by, file_id, event_id],
                )?;
            }
            EmitCommand::WritePendingBootstrapTrust {
                invite_event_id,
                workspace_id,
                expected_bootstrap_spki_fingerprint,
            } => {
                crate::db::transport_trust::record_pending_invite_bootstrap_trust(
                    conn,
                    recorded_by,
                    invite_event_id,
                    workspace_id,
                    expected_bootstrap_spki_fingerprint,
                )?;
                // Bidirectional supersession: if PeerShared already projected
                // for this SPKI, supersede the just-written bootstrap row.
                supersede_bootstrap_if_peer_shared_exists(
                    conn,
                    recorded_by,
                    expected_bootstrap_spki_fingerprint,
                )?;
            }
            EmitCommand::WriteAcceptedBootstrapTrust {
                invite_accepted_event_id,
                invite_event_id,
                workspace_id,
                bootstrap_addr,
                bootstrap_spki_fingerprint,
            } => {
                crate::db::transport_trust::record_invite_bootstrap_trust(
                    conn,
                    recorded_by,
                    invite_accepted_event_id,
                    invite_event_id,
                    workspace_id,
                    bootstrap_addr,
                    bootstrap_spki_fingerprint,
                )?;
                // Bidirectional supersession: if PeerShared already projected
                // for this SPKI, supersede the just-written bootstrap row.
                supersede_bootstrap_if_peer_shared_exists(
                    conn,
                    recorded_by,
                    bootstrap_spki_fingerprint,
                )?;
            }
            EmitCommand::SupersedeBootstrapTrust {
                peer_shared_public_key,
            } => {
                crate::db::transport_trust::supersede_bootstrap_for_peer_shared(
                    conn,
                    recorded_by,
                    peer_shared_public_key,
                )
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;
            }
            EmitCommand::RefreshTransportCreds => {
                // Load peer_shared private key from local_signer_material
                let key_bytes: Option<Vec<u8>> = conn
                    .query_row(
                        "SELECT private_key FROM local_signer_material
                         WHERE recorded_by = ?1 AND signer_kind = 3
                         LIMIT 1",
                        rusqlite::params![recorded_by],
                        |row| row.get(0),
                    )
                    .optional()?
                    .flatten();
                if let Some(key_bytes) = key_bytes {
                    if key_bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key_bytes);
                        let signing_key = ed25519_dalek::SigningKey::from_bytes(&arr);
                        let _ = crate::identity::transport::install_peer_key_transport_identity(
                            conn,
                            &signing_key,
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Bidirectional supersession helper: check if any peers_shared row for this
/// recorded_by has an SPKI matching the given fingerprint. If so, supersede
/// bootstrap trust for that peer. This handles the case where PeerShared is
/// already projected when bootstrap trust is written (out-of-order replay).
fn supersede_bootstrap_if_peer_shared_exists(
    conn: &Connection,
    recorded_by: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::transport::cert::spki_fingerprint_from_ed25519_pubkey;

    // Query all peers_shared public keys for this tenant and check SPKI match
    let mut stmt = conn.prepare("SELECT public_key FROM peers_shared WHERE recorded_by = ?1")?;
    let mut rows = stmt.query(rusqlite::params![recorded_by])?;
    while let Some(row) = rows.next()? {
        let pk_blob: Vec<u8> = row.get(0)?;
        if pk_blob.len() == 32 {
            let pk: [u8; 32] = pk_blob.try_into().unwrap();
            let derived = spki_fingerprint_from_ed25519_pubkey(&pk);
            if derived.as_slice() == spki_fingerprint.as_slice() {
                drop(rows);
                crate::db::transport_trust::supersede_bootstrap_for_peer_shared(
                    conn,
                    recorded_by,
                    &pk,
                )
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;
                return Ok(());
            }
        }
    }
    Ok(())
}
