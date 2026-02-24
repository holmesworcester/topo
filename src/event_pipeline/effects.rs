use crate::db::project_queue::ProjectQueue;
use crate::db::wanted::WantedEvents;

use super::drain::drain_project_queue_on_connection;
use super::phases::PostCommitCommand;

pub(super) trait PostCommitEffectsExecutor {
    fn execute_post_commit_commands(&self, commands: &[PostCommitCommand]);
}

pub(super) fn run_post_commit_effects<E: PostCommitEffectsExecutor>(
    executor: &E,
    commands: &[PostCommitCommand],
) {
    executor.execute_post_commit_commands(commands);
}

pub(super) struct SqlitePostCommitEffectsExecutor<'a> {
    db: &'a rusqlite::Connection,
}

impl<'a> SqlitePostCommitEffectsExecutor<'a> {
    pub(super) fn new(db: &'a rusqlite::Connection) -> Self {
        Self { db }
    }
}

impl PostCommitEffectsExecutor for SqlitePostCommitEffectsExecutor<'_> {
    fn execute_post_commit_commands(&self, commands: &[PostCommitCommand]) {
        let wanted = WantedEvents::new(self.db);
        let pq = ProjectQueue::new(self.db);

        for command in commands {
            match command {
                PostCommitCommand::RemoveWanted { event_id } => {
                    let _ = wanted.remove(event_id);
                }
                PostCommitCommand::DrainProjectQueue {
                    tenant_id,
                    batch_size,
                } => {
                    if let Err(e) =
                        drain_project_queue_on_connection(self.db, tenant_id, *batch_size)
                    {
                        tracing::warn!("project_queue drain error for {}: {}", tenant_id, e);
                    }
                }
                PostCommitCommand::LogProjectQueueHealth { tenant_id } => {
                    if let Ok(h) = pq.health(tenant_id) {
                        if h.pending > 0 || h.max_attempts > 0 {
                            tracing::debug!(
                                tenant = %tenant_id,
                                pending = %h.pending,
                                max_attempts = %h.max_attempts,
                                oldest_age_ms = %h.oldest_age_ms,
                                "project_queue health"
                            );
                        }
                    }
                }
                PostCommitCommand::RunPostDrainHooks { tenant_id } => {
                    match crate::event_modules::post_drain_hooks(self.db, tenant_id) {
                        Ok(count) if count > 0 => {
                            tracing::info!(
                                "post-drain hooks: tenant {} resolved {} item(s)",
                                short_id(tenant_id),
                                count
                            );
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(
                                "post-drain hooks failed for {}: {}",
                                short_id(tenant_id),
                                e
                            )
                        }
                    }
                }
            }
        }
    }
}

fn short_id(value: &str) -> &str {
    &value[..16.min(value.len())]
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;
    use crate::db::schema::create_tables;
    use crate::db::{open_in_memory, wanted::WantedEvents};

    #[test]
    fn event_pipeline_effects_execute_expected_sqlite_side_effects() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let wanted = WantedEvents::new(&conn);
        let wanted_id = [7u8; 32];
        wanted.insert(&wanted_id).unwrap();

        conn.execute(
            "INSERT INTO project_queue (peer_id, event_id, available_at) VALUES (?1, ?2, 0)",
            params!["tenant-a", "not_base64"],
        )
        .unwrap();

        let commands = vec![
            PostCommitCommand::RemoveWanted {
                event_id: wanted_id,
            },
            PostCommitCommand::DrainProjectQueue {
                tenant_id: "tenant-a".to_string(),
                batch_size: 16,
            },
        ];
        let executor = SqlitePostCommitEffectsExecutor::new(&conn);

        run_post_commit_effects(&executor, &commands);

        let wanted_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM wanted_events WHERE id = ?1",
                params![&wanted_id[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(wanted_count, 0, "wanted.remove should clear requested id");

        let queue_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1",
                params!["tenant-a"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            queue_count, 0,
            "drain command should process and remove queued rows"
        );
    }

    #[test]
    fn event_pipeline_effects_failures_are_best_effort_and_do_not_skip_other_commands() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let wanted = WantedEvents::new(&conn);
        let wanted_id = [9u8; 32];
        wanted.insert(&wanted_id).unwrap();

        conn.execute("DROP TABLE project_queue", []).unwrap();

        let commands = vec![
            PostCommitCommand::DrainProjectQueue {
                tenant_id: "tenant-a".to_string(),
                batch_size: 8,
            },
            PostCommitCommand::RemoveWanted {
                event_id: wanted_id,
            },
        ];
        let executor = SqlitePostCommitEffectsExecutor::new(&conn);

        run_post_commit_effects(&executor, &commands);

        let wanted_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM wanted_events WHERE id = ?1",
                params![&wanted_id[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            wanted_count, 0,
            "remove wanted should still run after prior command failure"
        );
    }
}
