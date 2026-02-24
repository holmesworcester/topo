use super::phases::{PersistPhaseOutput, PostCommitCommand};

pub(super) fn plan_post_commit_commands(
    output: &PersistPhaseOutput,
    batch_size: usize,
) -> Vec<PostCommitCommand> {
    let mut commands =
        Vec::with_capacity(output.persisted_event_ids.len() + (output.tenants_seen.len() * 3));

    for event_id in &output.persisted_event_ids {
        commands.push(PostCommitCommand::RemoveWanted {
            event_id: *event_id,
        });
    }

    // Deterministic order makes post-commit command planning easier to reason about.
    let mut tenants: Vec<String> = output.tenants_seen.iter().cloned().collect();
    tenants.sort();
    for tenant_id in tenants {
        commands.push(PostCommitCommand::DrainProjectQueue {
            tenant_id: tenant_id.clone(),
            batch_size,
        });
        commands.push(PostCommitCommand::LogProjectQueueHealth {
            tenant_id: tenant_id.clone(),
        });
        commands.push(PostCommitCommand::RunPostDrainHooks { tenant_id });
    }

    commands
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn event_id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn event_pipeline_planner_is_deterministic_for_same_inputs() {
        let output = PersistPhaseOutput {
            persisted_event_ids: vec![event_id(9), event_id(1)],
            tenants_seen: HashSet::from(["tenant-z".to_string(), "tenant-a".to_string()]),
        };

        let planned_a = plan_post_commit_commands(&output, 32);
        let planned_b = plan_post_commit_commands(&output, 32);

        assert_eq!(planned_a, planned_b);
        assert_eq!(
            planned_a,
            vec![
                PostCommitCommand::RemoveWanted {
                    event_id: event_id(9)
                },
                PostCommitCommand::RemoveWanted {
                    event_id: event_id(1)
                },
                PostCommitCommand::DrainProjectQueue {
                    tenant_id: "tenant-a".to_string(),
                    batch_size: 32,
                },
                PostCommitCommand::LogProjectQueueHealth {
                    tenant_id: "tenant-a".to_string(),
                },
                PostCommitCommand::RunPostDrainHooks {
                    tenant_id: "tenant-a".to_string(),
                },
                PostCommitCommand::DrainProjectQueue {
                    tenant_id: "tenant-z".to_string(),
                    batch_size: 32,
                },
                PostCommitCommand::LogProjectQueueHealth {
                    tenant_id: "tenant-z".to_string(),
                },
                PostCommitCommand::RunPostDrainHooks {
                    tenant_id: "tenant-z".to_string(),
                },
            ]
        );
    }

    #[test]
    fn event_pipeline_planner_returns_no_commands_when_nothing_persisted() {
        let output = PersistPhaseOutput::default();
        let planned = plan_post_commit_commands(&output, 16);
        assert!(planned.is_empty());
    }

    #[test]
    fn event_pipeline_planner_command_set_matches_persist_output() {
        let output = PersistPhaseOutput {
            persisted_event_ids: vec![event_id(3), event_id(4), event_id(5)],
            tenants_seen: HashSet::from(["tenant-two".to_string(), "tenant-one".to_string()]),
        };
        let planned = plan_post_commit_commands(&output, 7);

        let remove_count = planned
            .iter()
            .filter(|cmd| matches!(cmd, PostCommitCommand::RemoveWanted { .. }))
            .count();
        assert_eq!(remove_count, output.persisted_event_ids.len());

        let tenant_commands = planned
            .iter()
            .filter_map(|cmd| match cmd {
                PostCommitCommand::DrainProjectQueue { tenant_id, .. } => Some(tenant_id.clone()),
                PostCommitCommand::LogProjectQueueHealth { tenant_id } => Some(tenant_id.clone()),
                PostCommitCommand::RunPostDrainHooks { tenant_id } => Some(tenant_id.clone()),
                PostCommitCommand::RemoveWanted { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(tenant_commands.len(), output.tenants_seen.len() * 3);

        for tenant in &output.tenants_seen {
            let occurrences = tenant_commands
                .iter()
                .filter(|name| *name == tenant)
                .count();
            assert_eq!(occurrences, 3);
        }
    }
}
