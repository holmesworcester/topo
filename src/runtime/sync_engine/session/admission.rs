use rusqlite::Connection;

use crate::db::store::lookup_workspace_id;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyncAdmissionContext {
    pub(crate) accepted_workspace_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncAdmissionPlan {
    RejectMissingWorkspace,
    Start { workspace_id: String },
}

pub(crate) fn load_sync_admission_context(
    conn: &Connection,
    recorded_by: &str,
) -> SyncAdmissionContext {
    SyncAdmissionContext {
        accepted_workspace_id: lookup_workspace_id(conn, recorded_by),
    }
}

pub(crate) fn decide_sync_admission_plan(context: &SyncAdmissionContext) -> SyncAdmissionPlan {
    match &context.accepted_workspace_id {
        Some(workspace_id) => SyncAdmissionPlan::Start {
            workspace_id: workspace_id.clone(),
        },
        None => SyncAdmissionPlan::RejectMissingWorkspace,
    }
}

pub(crate) fn resolve_sync_admission(
    conn: &Connection,
    recorded_by: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let context = load_sync_admission_context(conn, recorded_by);
    match decide_sync_admission_plan(&context) {
        SyncAdmissionPlan::Start { workspace_id } => Ok(workspace_id),
        SyncAdmissionPlan::RejectMissingWorkspace => Err(format!(
            "no accepted workspace binding for peer_id={}, cannot start sync",
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
            decide_sync_admission_plan(&SyncAdmissionContext {
                accepted_workspace_id: None,
            }),
            SyncAdmissionPlan::RejectMissingWorkspace
        );
    }

    #[test]
    fn sync_admission_context_loads_workspace_binding() {
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

        let context = load_sync_admission_context(&conn, "tenant-a");
        assert_eq!(
            context,
            SyncAdmissionContext {
                accepted_workspace_id: Some("workspace-a".to_string()),
            }
        );
        assert_eq!(
            decide_sync_admission_plan(&context),
            SyncAdmissionPlan::Start {
                workspace_id: "workspace-a".to_string(),
            }
        );
    }
}
