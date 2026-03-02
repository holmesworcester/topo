use super::super::contract::{EmitCommand, SqlVal, WriteOp};
use crate::crypto::event_id_from_base64;
use rusqlite::Connection;

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
            EmitCommand::RetryWorkspaceEvent { workspace_id } => {
                // Re-project the specific workspace event now that a trust anchor exists.
                // The workspace_id IS the event_id for workspace events.
                // Only attempt if the event exists and is not yet in a terminal state
                // (the workspace event may arrive later, in which case it will project
                // normally since the trust anchor is already set).
                let exists: bool = conn
                    .query_row(
                        "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                        rusqlite::params![workspace_id],
                        |row| row.get(0),
                    )
                    .unwrap_or(false);
                if exists {
                    if let Some(event_id) = event_id_from_base64(workspace_id) {
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
            EmitCommand::ApplyTransportIdentityIntent { intent } => {
                use crate::contracts::transport_identity_contract::TransportIdentityAdapter;
                let adapter = crate::transport::identity_adapter::ConcreteTransportIdentityAdapter;
                adapter
                    .apply_intent(conn, intent.clone())
                    .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
            }
        }
    }
    Ok(())
}
