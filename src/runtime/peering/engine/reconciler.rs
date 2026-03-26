//! Event-driven connection reconciler.
//!
//! This module replaces the policy-heavy target dispatcher with a reconciler
//! that reads desired state from SQLite and converges actual OS workers toward
//! it. The reconciler owns no policy — it only:
//!
//! 1. Queries projected connection plan state for what should be active
//! 2. Compares against the thin handle map of what IS active
//! 3. Spawns/cancels workers to converge
//! 4. Records outcomes as events
//!
//! All policy decisions (precedence, activation, cadence, stale-dial thresholds)
//! live in event family modules and are already projected into SQLite tables
//! by the time the reconciler reads them.

use std::collections::HashMap;

use tokio_util::sync::CancellationToken;

use crate::event_modules::operational::connection_planned::{
    load_active_connections, load_connections_needing_workers, load_due_effects,
    ConnectionPlanEffect,
};

/// A thin handle to an OS worker. This is the only process-local state
/// the reconciler needs — it holds the cancellation token and join handle
/// for mechanical lifecycle management. No policy state.
pub struct WorkerHandle {
    pub cancel: CancellationToken,
    pub join: std::thread::JoinHandle<()>,
}

/// The reconciler's state: a map from connection_id to worker handle.
/// This map is NOT a source of truth for policy — it's a mechanical
/// bookkeeping structure. The source of truth is `connection_plan_history`
/// in SQLite.
pub struct ConnectionReconciler {
    handles: HashMap<String, WorkerHandle>,
}

impl ConnectionReconciler {
    pub fn new() -> Self {
        Self {
            handles: HashMap::new(),
        }
    }

    /// Reap finished workers — remove handles for workers that completed.
    pub fn reap_finished(&mut self) -> Vec<String> {
        let finished: Vec<String> = self
            .handles
            .iter()
            .filter(|(_, h)| h.join.is_finished())
            .map(|(k, _)| k.clone())
            .collect();
        for key in &finished {
            self.handles.remove(key);
        }
        finished
    }

    /// Cancel a specific worker by connection_id.
    pub fn cancel(&mut self, connection_id: &str) {
        if let Some(handle) = self.handles.get(connection_id) {
            handle.cancel.cancel();
        }
    }

    /// Register a newly spawned worker.
    pub fn register(&mut self, connection_id: String, handle: WorkerHandle) {
        self.handles.insert(connection_id, handle);
    }

    /// Check if a worker exists for a connection_id.
    pub fn has_worker(&self, connection_id: &str) -> bool {
        self.handles.contains_key(connection_id)
    }

    /// Return connection_ids that have handles but shouldn't be active
    /// according to projected state.
    pub fn workers_to_cancel(&self, desired_active: &[String]) -> Vec<String> {
        self.handles
            .keys()
            .filter(|k| !desired_active.contains(k))
            .cloned()
            .collect()
    }

    /// Return due effects that need new workers (not already handled).
    pub fn effects_needing_spawn(&self, effects: &[ConnectionPlanEffect]) -> Vec<ConnectionPlanEffect> {
        effects
            .iter()
            .filter(|e| !self.handles.contains_key(&e.connection_id))
            .cloned()
            .collect()
    }

    /// Cancel all workers (shutdown).
    pub fn cancel_all(&mut self) {
        for (_, handle) in &self.handles {
            handle.cancel.cancel();
        }
    }

    /// Number of active workers.
    pub fn worker_count(&self) -> usize {
        self.handles.len()
    }
}

/// The reconciliation loop pattern:
///
/// ```ignore
/// let mut reconciler = ConnectionReconciler::new();
/// loop {
///     // 1. Reap finished workers
///     reconciler.reap_finished();
///
///     // 2. Query desired state from SQLite
///     let active = load_active_connections(&conn)?;
///     let due = load_due_effects(&conn, 16)?;
///
///     // 3. Cancel workers that shouldn't be running
///     for id in reconciler.workers_to_cancel(&active) {
///         reconciler.cancel(&id);
///     }
///
///     // 4. Spawn workers for due effects not yet handled
///     for effect in reconciler.effects_needing_spawn(&due) {
///         let handle = spawn_connect_worker(...);
///         reconciler.register(effect.connection_id, handle);
///     }
///
///     // 5. Sleep until next due time or wake event
///     tokio::select! { ... }
/// }
/// ```

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_handle() -> WorkerHandle {
        let cancel = CancellationToken::new();
        let join = std::thread::spawn(|| {});
        WorkerHandle { cancel, join }
    }

    #[test]
    fn register_and_has_worker() {
        let mut r = ConnectionReconciler::new();
        assert!(!r.has_worker("conn-1"));
        r.register("conn-1".to_string(), dummy_handle());
        assert!(r.has_worker("conn-1"));
    }

    #[test]
    fn reap_finished_removes_completed_workers() {
        let mut r = ConnectionReconciler::new();
        r.register("conn-1".to_string(), dummy_handle());
        // The dummy thread finishes immediately
        std::thread::sleep(std::time::Duration::from_millis(10));
        let finished = r.reap_finished();
        assert_eq!(finished, vec!["conn-1".to_string()]);
        assert!(!r.has_worker("conn-1"));
    }

    #[test]
    fn workers_to_cancel_finds_excess() {
        let mut r = ConnectionReconciler::new();
        r.register("conn-1".to_string(), dummy_handle());
        r.register("conn-2".to_string(), dummy_handle());
        let desired = vec!["conn-1".to_string()];
        let excess = r.workers_to_cancel(&desired);
        assert_eq!(excess, vec!["conn-2".to_string()]);
    }

    #[test]
    fn effects_needing_spawn_filters_existing() {
        let mut r = ConnectionReconciler::new();
        r.register("conn-1".to_string(), dummy_handle());
        let effects = vec![
            ConnectionPlanEffect {
                connection_id: "conn-1".to_string(),
                tenant_id: "t".to_string(),
                available_at_ms: 0,
            },
            ConnectionPlanEffect {
                connection_id: "conn-2".to_string(),
                tenant_id: "t".to_string(),
                available_at_ms: 0,
            },
        ];
        let need_spawn = r.effects_needing_spawn(&effects);
        assert_eq!(need_spawn.len(), 1);
        assert_eq!(need_spawn[0].connection_id, "conn-2");
    }
}
