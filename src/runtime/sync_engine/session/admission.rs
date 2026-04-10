use rusqlite::Connection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyncAdmissionRawRows {
    pub(crate) workspace_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncAdmissionDecisionContext {
    MissingWorkspaceBinding,
    UniqueWorkspaceBinding { workspace_id: String },
    AmbiguousWorkspaceBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncAdmissionPlan {
    RejectMissingWorkspaceBinding,
    RejectAmbiguousWorkspaceBinding,
    Start { workspace_id: String },
}

pub(crate) fn load_sync_admission_raw_rows(
    conn: &Connection,
    recorded_by: &str,
) -> rusqlite::Result<SyncAdmissionRawRows> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT workspace_id
         FROM invites_accepted
         WHERE recorded_by = ?1
         ORDER BY workspace_id",
    )?;
    let workspace_ids = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SyncAdmissionRawRows { workspace_ids })
}

pub(crate) fn normalize_sync_admission_decision_context(
    raw_rows: &SyncAdmissionRawRows,
) -> SyncAdmissionDecisionContext {
    let mut workspace_ids = raw_rows.workspace_ids.clone();
    workspace_ids.sort();
    workspace_ids.dedup();
    match workspace_ids.as_slice() {
        [] => SyncAdmissionDecisionContext::MissingWorkspaceBinding,
        [workspace_id] => SyncAdmissionDecisionContext::UniqueWorkspaceBinding {
            workspace_id: workspace_id.clone(),
        },
        _ => SyncAdmissionDecisionContext::AmbiguousWorkspaceBinding,
    }
}

pub(crate) fn decide_sync_admission_plan(
    context: &SyncAdmissionDecisionContext,
) -> SyncAdmissionPlan {
    match context {
        SyncAdmissionDecisionContext::MissingWorkspaceBinding => {
            SyncAdmissionPlan::RejectMissingWorkspaceBinding
        }
        SyncAdmissionDecisionContext::UniqueWorkspaceBinding { workspace_id } => {
            SyncAdmissionPlan::Start {
                workspace_id: workspace_id.clone(),
            }
        }
        SyncAdmissionDecisionContext::AmbiguousWorkspaceBinding => {
            SyncAdmissionPlan::RejectAmbiguousWorkspaceBinding
        }
    }
}

pub(crate) fn resolve_sync_admission(
    conn: &Connection,
    recorded_by: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let raw_rows = load_sync_admission_raw_rows(conn, recorded_by)?;
    let decision_context = normalize_sync_admission_decision_context(&raw_rows);
    match decide_sync_admission_plan(&decision_context) {
        SyncAdmissionPlan::Start { workspace_id } => Ok(workspace_id),
        SyncAdmissionPlan::RejectMissingWorkspaceBinding => Err(format!(
            "no accepted workspace binding for peer_id={}, cannot start sync",
            recorded_by
        )
        .into()),
        SyncAdmissionPlan::RejectAmbiguousWorkspaceBinding => Err(format!(
            "ambiguous accepted workspace binding for peer_id={}, cannot start sync",
            recorded_by
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use rusqlite::params;

    #[test]
    fn sync_admission_plan_rejects_missing_workspace() {
        assert_eq!(
            decide_sync_admission_plan(&SyncAdmissionDecisionContext::MissingWorkspaceBinding),
            SyncAdmissionPlan::RejectMissingWorkspaceBinding
        );
    }

    #[test]
    fn sync_admission_raw_rows_load_workspace_binding() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn.execute(
            "INSERT INTO invites_accepted
                 (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "tenant-a",
                "accepted-a",
                "tenant-event-a",
                "invite-a",
                "workspace-a",
                1i64
            ],
        )
        .unwrap();

        let raw_rows = load_sync_admission_raw_rows(&conn, "tenant-a").unwrap();
        assert_eq!(
            raw_rows,
            SyncAdmissionRawRows {
                workspace_ids: vec!["workspace-a".to_string()],
            }
        );
        assert_eq!(
            normalize_sync_admission_decision_context(&raw_rows),
            SyncAdmissionDecisionContext::UniqueWorkspaceBinding {
                workspace_id: "workspace-a".to_string(),
            }
        );
        assert_eq!(
            decide_sync_admission_plan(&normalize_sync_admission_decision_context(&raw_rows)),
            SyncAdmissionPlan::Start {
                workspace_id: "workspace-a".to_string(),
            }
        );
    }

    #[test]
    fn sync_admission_normalizer_dedups_duplicate_workspace_rows() {
        let context = normalize_sync_admission_decision_context(&SyncAdmissionRawRows {
            workspace_ids: vec![
                "workspace-a".to_string(),
                "workspace-a".to_string(),
                "workspace-a".to_string(),
            ],
        });
        assert_eq!(
            context,
            SyncAdmissionDecisionContext::UniqueWorkspaceBinding {
                workspace_id: "workspace-a".to_string(),
            }
        );
        assert_eq!(
            decide_sync_admission_plan(&context),
            SyncAdmissionPlan::Start {
                workspace_id: "workspace-a".to_string(),
            }
        );
    }

    #[test]
    fn sync_admission_plan_rejects_ambiguous_workspace_binding() {
        let context = normalize_sync_admission_decision_context(&SyncAdmissionRawRows {
            workspace_ids: vec!["workspace-a".to_string(), "workspace-b".to_string()],
        });
        assert_eq!(
            context,
            SyncAdmissionDecisionContext::AmbiguousWorkspaceBinding
        );
        assert_eq!(
            decide_sync_admission_plan(&context),
            SyncAdmissionPlan::RejectAmbiguousWorkspaceBinding
        );
    }

    #[test]
    fn resolve_sync_admission_starts_when_distinct_query_collapses_duplicate_workspace_rows() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        for (event_id, created_at) in [("accepted-a", 1i64), ("accepted-b", 2i64)] {
            conn.execute(
                "INSERT INTO invites_accepted
                     (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    "tenant-a",
                    event_id,
                    format!("tenant-event-{event_id}"),
                    format!("invite-{event_id}"),
                    "workspace-a",
                    created_at
                ],
            )
            .unwrap();
        }

        assert_eq!(
            resolve_sync_admission(&conn, "tenant-a").unwrap(),
            "workspace-a"
        );
    }

    #[test]
    fn resolve_sync_admission_rejects_missing_workspace_binding() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let err = resolve_sync_admission(&conn, "tenant-a").unwrap_err();
        assert!(
            err.to_string().contains("no accepted workspace binding"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_sync_admission_rejects_ambiguous_workspace_binding() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        for (event_id, workspace_id, created_at) in [
            ("accepted-a", "workspace-a", 1i64),
            ("accepted-b", "workspace-b", 2i64),
        ] {
            conn.execute(
                "INSERT INTO invites_accepted
                     (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    "tenant-a",
                    event_id,
                    format!("tenant-event-{event_id}"),
                    format!("invite-{event_id}"),
                    workspace_id,
                    created_at
                ],
            )
            .unwrap();
        }

        let err = resolve_sync_admission(&conn, "tenant-a").unwrap_err();
        assert!(
            err.to_string()
                .contains("ambiguous accepted workspace binding"),
            "unexpected error: {err}"
        );
    }
}
