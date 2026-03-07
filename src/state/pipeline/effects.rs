use crate::db::project_queue::ProjectQueue;
use crate::db::wanted::WantedEvents;
use crate::state::shared_workspace_fanout::fanout_shared_event_enqueue;

use super::drain::drain_project_queue_on_connection;
use super::phases::PersistPhaseOutput;

pub(super) trait PostCommitEffectsExecutor {
    fn run_post_commit_effects(&self, persist_output: &PersistPhaseOutput, batch_size: usize);
}

pub(super) fn run_post_commit_effects<E: PostCommitEffectsExecutor>(
    executor: &E,
    persist_output: &PersistPhaseOutput,
    batch_size: usize,
) {
    executor.run_post_commit_effects(persist_output, batch_size);
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
    fn run_post_commit_effects(&self, persist_output: &PersistPhaseOutput, batch_size: usize) {
        let wanted = WantedEvents::new(self.db);
        let pq = ProjectQueue::new(self.db);

        for event_id in &persist_output.persisted_event_ids {
            let _ = wanted.remove(event_id);
        }

        let mut tenant_set = persist_output.tenants_seen.clone();
        for fanout in &persist_output.shared_event_fanouts {
            match fanout_shared_event_enqueue(self.db, fanout) {
                Ok(siblings) => {
                    tenant_set.extend(siblings);
                }
                Err(e) => {
                    tracing::warn!(
                        "same-workspace fanout enqueue failed for {}: {}",
                        short_id(&fanout.origin_peer_id),
                        e
                    );
                }
            }
        }

        // Keep tenant ordering deterministic for readability and reproducible logs.
        let mut tenants: Vec<String> = tenant_set.into_iter().collect();
        tenants.sort();

        for tenant_id in tenants {
            if let Err(e) = drain_project_queue_on_connection(self.db, &tenant_id, batch_size) {
                tracing::warn!("project_queue drain error for {}: {}", tenant_id, e);
            }

            if let Ok(h) = pq.health(&tenant_id) {
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

            match crate::event_modules::post_drain_hooks(self.db, &tenant_id) {
                Ok(count) if count > 0 => {
                    tracing::info!(
                        "post-drain hooks: tenant {} resolved {} item(s)",
                        short_id(&tenant_id),
                        count
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        "post-drain hooks failed for {}: {}",
                        short_id(&tenant_id),
                        e
                    )
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

        let persist_output = PersistPhaseOutput {
            persisted_event_ids: vec![wanted_id],
            tenants_seen: std::collections::HashSet::from(["tenant-a".to_string()]),
            shared_event_fanouts: Vec::new(),
        };
        let executor = SqlitePostCommitEffectsExecutor::new(&conn);

        run_post_commit_effects(&executor, &persist_output, 16);

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

        let persist_output = PersistPhaseOutput {
            persisted_event_ids: vec![wanted_id],
            tenants_seen: std::collections::HashSet::from(["tenant-a".to_string()]),
            shared_event_fanouts: Vec::new(),
        };
        let executor = SqlitePostCommitEffectsExecutor::new(&conn);

        run_post_commit_effects(&executor, &persist_output, 8);

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

    #[test]
    fn event_pipeline_effects_fan_out_shared_events_to_same_workspace_siblings_only() {
        use crate::crypto::{event_id_to_base64, hash_event};
        use crate::db::{open_connection, schema::create_tables, store::insert_event};
        use crate::event_modules::{encode_event, MessageEvent, ParsedEvent};
        use crate::projection::signer::sign_event_bytes;
        use crate::testutil::SharedDbNode;

        let mut node = SharedDbNode::new(2);
        node.add_tenant_in_workspace("same-ws", 0);

        let origin = &node.tenants[0];
        let other_workspace = &node.tenants[1];
        let sibling = &node.tenants[2];

        let conn = open_connection(&node.db_path).unwrap();
        create_tables(&conn).unwrap();

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: 42,
            workspace_id: origin.workspace_id,
            author_id: origin.author_id,
            content: "fanout-from-ingest".to_string(),
            signed_by: origin.peer_shared_event_id.unwrap(),
            signer_type: 5,
            signature: [0u8; 64],
        });
        let mut blob = encode_event(&msg).unwrap();
        let sig = sign_event_bytes(
            origin.peer_shared_signing_key.as_ref().unwrap(),
            &blob[..blob.len() - 64],
        );
        let blob_len = blob.len();
        blob[blob_len - 64..].copy_from_slice(&sig);
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);

        insert_event(
            &conn,
            &event_id,
            "message",
            &blob,
            crate::event_modules::ShareScope::Shared,
            42,
            42,
        )
        .unwrap();
        crate::db::store::insert_neg_item_if_shared(
            &conn,
            crate::event_modules::ShareScope::Shared,
            42,
            &event_id,
            &event_id_to_base64(&origin.workspace_id),
        )
        .unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, 42, 'quic_recv:test')",
            params![&origin.identity, &event_id_b64],
        )
        .unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO project_queue (peer_id, event_id, available_at)
             VALUES (?1, ?2, 42)",
            params![&origin.identity, &event_id_b64],
        )
        .unwrap();

        let persist_output = PersistPhaseOutput {
            persisted_event_ids: vec![event_id],
            tenants_seen: std::collections::HashSet::from([origin.identity.clone()]),
            shared_event_fanouts: vec![crate::state::shared_workspace_fanout::SharedEventFanout {
                origin_peer_id: origin.identity.clone(),
                workspace_id: event_id_to_base64(&origin.workspace_id),
                event_id,
            }],
        };
        let executor = SqlitePostCommitEffectsExecutor::new(&conn);

        run_post_commit_effects(&executor, &persist_output, 16);

        let sibling_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                params![&sibling.identity, &event_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            sibling_count, 1,
            "same-workspace sibling should project message"
        );

        let other_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                params![&other_workspace.identity, &event_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            other_count, 0,
            "different-workspace tenant must not receive same-workspace fanout"
        );
    }
}
