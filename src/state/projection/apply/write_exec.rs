use super::super::projector::{EmitCommand, SqlVal, WriteOp};
use crate::crypto::event_id_from_base64;
use rusqlite::{Connection, OptionalExtension};
use topo_verus_proofs::state::projection::apply::tenant_isolation::{
    check_writes_tenant_isolated, WriteOpTenantView,
};
use topo_verus_proofs::state::projection::apply::writeop_idempotency::{
    is_idempotent_writeop, WriteOpKind,
};

/// Trusted extractor: exhaustive match over runtime `WriteOp` variants into the
/// verus-proofs `WriteOpKind` tag. If a new `WriteOp` variant is ever added, this
/// match goes non-exhaustive at compile time, forcing a new branch and a matching
/// `WriteOpKind` variant in verus-proofs, which in turn forces `is_idempotent_writeop`
/// to explicitly prove (or reject) the new kind.
fn writeop_kind(op: &WriteOp) -> WriteOpKind {
    match op {
        WriteOp::InsertOrIgnore { .. } => WriteOpKind::InsertOrIgnore,
        WriteOp::Delete { .. } => WriteOpKind::Delete,
        WriteOp::InsertKeySecretFromUnwrap(_) => WriteOpKind::InsertKeySecretFromUnwrap,
        WriteOp::InsertKeySecretLocal(_) => WriteOpKind::InsertKeySecretLocal,
    }
}

/// Trusted extractor: build a `WriteOpTenantView` from a `WriteOp` given the executing
/// tenant. Looks for a column (or where-clause key) named `recorded_by`; if present,
/// compares its value to `executing_tenant`. If absent, the view's `has_recorded_by`
/// is `false` and the verified check allows the write through — those writes target
/// tables that do not participate in the tenant-scope dimension (schema metadata, etc).
fn writeop_tenant_view(op: &WriteOp, executing_tenant: &str) -> WriteOpTenantView {
    match op {
        WriteOp::InsertOrIgnore {
            columns, values, ..
        } => {
            for (idx, col) in columns.iter().enumerate() {
                if *col == "recorded_by" {
                    let matches = matches!(values.get(idx), Some(SqlVal::Text(s)) if s == executing_tenant);
                    return WriteOpTenantView {
                        has_recorded_by: true,
                        recorded_by_matches_executing: matches,
                    };
                }
            }
            WriteOpTenantView {
                has_recorded_by: false,
                recorded_by_matches_executing: false,
            }
        }
        WriteOp::Delete { where_clause, .. } => {
            for (col, val) in where_clause {
                if *col == "recorded_by" {
                    let matches = matches!(val, SqlVal::Text(s) if s == executing_tenant);
                    return WriteOpTenantView {
                        has_recorded_by: true,
                        recorded_by_matches_executing: matches,
                    };
                }
            }
            WriteOpTenantView {
                has_recorded_by: false,
                recorded_by_matches_executing: false,
            }
        }
        WriteOp::InsertKeySecretFromUnwrap(row) | WriteOp::InsertKeySecretLocal(row) => {
            WriteOpTenantView {
                has_recorded_by: true,
                recorded_by_matches_executing: row.recorded_by == executing_tenant,
            }
        }
    }
}

/// Enforce tenant isolation on a batch of WriteOps before execution.
/// Panics if the Verus-verified `check_writes_tenant_isolated` rejects the batch —
/// a rejection means a projector emitted cross-tenant writes, which is a hard bug
/// and must not be silently recovered from.
pub(crate) fn assert_writes_tenant_isolated(executing_tenant: &str, ops: &[WriteOp]) {
    let views: Vec<WriteOpTenantView> = ops
        .iter()
        .map(|op| writeop_tenant_view(op, executing_tenant))
        .collect();
    if !check_writes_tenant_isolated(&views) {
        panic!(
            "tenant isolation violation: projector running as {executing_tenant} emitted WriteOp(s) with recorded_by != {executing_tenant}",
        );
    }
}

/// Execute a list of WriteOps against the database.
///
/// Each WriteOp is executed in order. INSERT OR IGNORE and DELETE are the
/// only supported operations. This is the transactional apply stage.
pub(crate) fn execute_write_ops(
    conn: &Connection,
    ops: &[WriteOp],
) -> Result<(), Box<dyn std::error::Error>> {
    for op in ops {
        debug_assert!(
            is_idempotent_writeop(writeop_kind(op)),
            "WriteOp variant is not idempotent; all WriteOps must be replay-safe",
        );
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
            WriteOp::InsertKeySecretFromUnwrap(row) | WriteOp::InsertKeySecretLocal(row) => {
                // Both variants write the same row shape; they differ only
                // in which access-control invariant applies. Canonical
                // columns pinned at the typed-row constructor.
                let sql = format!(
                    "INSERT OR IGNORE INTO {} ({}) VALUES (?1, ?2, ?3, ?4)",
                    crate::event_modules::key_shared::KEY_SECRETS_TABLE,
                    crate::event_modules::key_shared::KEY_SECRETS_COLUMNS.join(", "),
                );
                conn.execute(
                    &sql,
                    rusqlite::params![
                        row.event_id_b64,
                        row.key_bytes.to_vec(),
                        row.created_at_ms,
                        row.recorded_by,
                    ],
                )?;
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
            EmitCommand::HardPurgeMessageGraph { message_event_id } => {
                crate::state::projection::purge::hard_purge_deleted_message_graph(
                    conn,
                    recorded_by,
                    message_event_id,
                )?;
            }
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
            EmitCommand::MaterializeTransportIdentity { spec } => {
                use crate::contracts::transport_identity_contract::{
                    TransportIdentityMaterializer, TransportIdentitySpec,
                };
                let materializer =
                    crate::transport::identity_adapter::ConcreteTransportIdentityMaterializer;
                let peer_id = materializer
                    .materialize(conn, spec.clone())
                    .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
                // Target ownership is projection-pipeline-owned, not materializer-owned.
                let (tenant_id, source) = match &spec {
                    TransportIdentitySpec::InstallBootstrapIdentityFromInviteSecret {
                        recorded_by,
                        ..
                    } => (
                        recorded_by.as_str(),
                        crate::db::transport_creds::CRED_SOURCE_BOOTSTRAP,
                    ),
                    TransportIdentitySpec::InstallPeerSharedIdentityFromSigner {
                        recorded_by,
                        ..
                    } => (
                        recorded_by.as_str(),
                        crate::db::transport_creds::CRED_SOURCE_PEER_SHARED,
                    ),
                };
                crate::db::transport_creds::set_local_transport_target(
                    conn, tenant_id, &peer_id, source,
                )
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;
            }
            EmitCommand::EmitDeterministicBlob { blob } => {
                let _ = crate::projection::create::emit_deterministic_blob(conn, recorded_by, blob)?;
            }
            EmitCommand::IndexEndpointSharedForWorkspace {
                workspace_id,
                endpoint_shared_event_id,
            } => {
                let endpoint_row: Option<(i64, Vec<u8>)> = conn
                    .query_row(
                        "SELECT created_at, blob
                         FROM events
                         WHERE event_id = ?1
                           AND event_type = 'endpoint_shared'
                           AND share_scope = 'shared'
                         LIMIT 1",
                        rusqlite::params![endpoint_shared_event_id],
                        |row| Ok((row.get(0)?, crate::db::sql_types::get_blob(row, 1)?)),
                    )
                    .optional()?;
                let Some((created_at_ms, endpoint_blob)) = endpoint_row else {
                    continue;
                };
                let Some(endpoint_shared_event_id_raw) =
                    event_id_from_base64(endpoint_shared_event_id)
                else {
                    continue;
                };
                crate::db::store::insert_shared_event_index_entry_if_shared(
                    conn,
                    crate::event_modules::ShareScope::Shared,
                    created_at_ms,
                    &endpoint_shared_event_id_raw,
                    workspace_id,
                    &endpoint_blob,
                )?;
                crate::state::shared_workspace_fanout::fanout_shared_event_immediate(
                    conn,
                    recorded_by,
                    workspace_id,
                    &endpoint_shared_event_id_raw,
                )
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;
            }
            EmitCommand::RetryBlockedEncryptedByKey { key_event_id } => {
                let mut stmt = conn.prepare(
                    "SELECT be.event_id, e.blob
                     FROM blocked_events be
                     JOIN events e ON e.event_id = be.event_id
                     WHERE be.peer_id = ?1
                       AND e.event_type IN ('signed', 'encrypted')
                     ORDER BY e.created_at ASC, e.event_id ASC",
                )?;
                let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
                    Ok((
                        crate::db::sql_types::get_text(row, 0)?,
                        crate::db::sql_types::get_blob(row, 1)?,
                    ))
                })?;
                for row in rows {
                    let (event_id_b64, blob) = row?;
                    let parsed = crate::event_modules::parse_event(&blob)?;
                    let semantic = unwrap_signed_for_retry(parsed)?;
                    let crate::event_modules::ParsedEvent::Encrypted(enc) = semantic else {
                        continue;
                    };
                    if crate::crypto::event_id_to_base64(&enc.key_event_id) != *key_event_id {
                        continue;
                    }
                    if let Some(event_id) = event_id_from_base64(&event_id_b64) {
                        let _ = super::project_one(conn, recorded_by, &event_id)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn unwrap_signed_for_retry(
    parsed: crate::event_modules::ParsedEvent,
) -> Result<crate::event_modules::ParsedEvent, Box<dyn std::error::Error>> {
    match parsed {
        crate::event_modules::ParsedEvent::Signed(signed) => {
            let inner = crate::event_modules::parse_event(&signed.payload)?;
            unwrap_signed_for_retry(inner)
        }
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::transport_identity_contract::TransportIdentitySpec;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::{encode_event, endpoint_shared, ShareScope};
    use rusqlite::OptionalExtension;

    fn insert_invite_secret(
        conn: &rusqlite::Connection,
        recorded_by: &str,
        invite_event_id: [u8; 32],
        key: [u8; 32],
    ) {
        let eid_b64 = crate::crypto::event_id_to_base64(&invite_event_id);
        let secret_eid = crate::crypto::event_id_to_base64(&[0xAAu8; 32]);
        conn.execute(
            "INSERT INTO invite_secrets
             (recorded_by, event_id, invite_event_id, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4, 0)",
            rusqlite::params![recorded_by, secret_eid, eid_b64, key.to_vec()],
        )
        .unwrap();
    }

    /// Pipeline-level test: execute_emit_commands with MaterializeTransportIdentity
    /// must record the transport target mapping in local_transport_targets.
    /// This validates that the ownership transfer from materializer → pipeline is wired correctly.
    #[test]
    fn execute_emit_commands_records_transport_target_for_bootstrap_intent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "tenant-pipeline";
        let invite_event_id = [0x42u8; 32];
        insert_invite_secret(&conn, recorded_by, invite_event_id, [0x42u8; 32]);

        let spec = TransportIdentitySpec::InstallBootstrapIdentityFromInviteSecret {
            recorded_by: recorded_by.to_string(),
            invite_event_id,
        };
        let cmd = EmitCommand::MaterializeTransportIdentity { spec };
        execute_emit_commands(&conn, recorded_by, &[cmd]).unwrap();

        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT transport_peer_id, source
                 FROM local_transport_targets WHERE tenant_id = ?1",
                rusqlite::params![recorded_by],
                |row| {
                    Ok((
                        crate::db::sql_types::get_text(row, 0)?,
                        crate::db::sql_types::get_text(row, 1)?,
                    ))
                },
            )
            .optional()
            .unwrap();
        let (peer_id, source) = row.expect("pipeline must write local_transport_targets");
        assert!(!peer_id.is_empty(), "transport_peer_id must be non-empty");
        assert_eq!(source, crate::db::transport_creds::CRED_SOURCE_BOOTSTRAP);
    }

    /// Pipeline-level test: peershared intent also records target mapping via pipeline.
    #[test]
    fn execute_emit_commands_records_transport_target_for_peershared_intent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let recorded_by = "tenant-peershared";
        let signer_event_id = [0x55u8; 32];
        let signer_eid_b64 = crate::crypto::event_id_to_base64(&signer_event_id);
        let key_bytes = [0x55u8; 32];
        conn.execute(
            "INSERT INTO peer_secrets
             (recorded_by, event_id, signer_event_id, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4, 0)",
            rusqlite::params![
                recorded_by,
                signer_eid_b64.clone(),
                signer_eid_b64,
                key_bytes.to_vec()
            ],
        )
        .unwrap();

        let spec = TransportIdentitySpec::InstallPeerSharedIdentityFromSigner {
            recorded_by: recorded_by.to_string(),
            signer_event_id,
        };
        let cmd = EmitCommand::MaterializeTransportIdentity { spec };
        execute_emit_commands(&conn, recorded_by, &[cmd]).unwrap();

        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT transport_peer_id, source
                 FROM local_transport_targets WHERE tenant_id = ?1",
                rusqlite::params![recorded_by],
                |row| {
                    Ok((
                        crate::db::sql_types::get_text(row, 0)?,
                        crate::db::sql_types::get_text(row, 1)?,
                    ))
                },
            )
            .optional()
            .unwrap();
        let (peer_id, source) = row.expect("pipeline must write local_transport_targets");
        assert!(!peer_id.is_empty(), "transport_peer_id must be non-empty");
        assert_eq!(source, crate::db::transport_creds::CRED_SOURCE_PEER_SHARED);
    }

    #[test]
    fn execute_emit_commands_indexes_endpoint_shared_for_workspace() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let workspace_id = crate::crypto::event_id_to_base64(&[0x41; 32]);
        let endpoint_event =
            endpoint_shared::deterministic_endpoint_shared_event([0x55; 32]);
        let endpoint_blob = encode_event(&endpoint_event).unwrap();
        let endpoint_event_id = crate::crypto::hash_event(&endpoint_blob);
        let endpoint_event_id_b64 = crate::crypto::event_id_to_base64(&endpoint_event_id);
        let created_at_ms = crate::event_modules::extract_created_at_ms(&endpoint_blob).unwrap();

        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'endpoint_shared', ?2, ?3, ?4, ?4)",
            rusqlite::params![
                &endpoint_event_id_b64,
                endpoint_blob,
                ShareScope::Shared.as_str(),
                created_at_ms as i64
            ],
        )
        .unwrap();

        execute_emit_commands(
            &conn,
            "tenant-a",
            &[EmitCommand::IndexEndpointSharedForWorkspace {
                workspace_id: workspace_id.clone(),
                endpoint_shared_event_id: endpoint_event_id_b64.clone(),
            }],
        )
        .unwrap();

        let indexed: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1
                     FROM shared_event_index
                     WHERE workspace_id = ?1
                       AND id = ?2
                 )",
                rusqlite::params![workspace_id, endpoint_event_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(indexed, "endpoint_shared should be indexed for the workspace");
    }
}
