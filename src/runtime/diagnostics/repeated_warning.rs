use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DEFAULT_MAX_TRACKED_WARNINGS: usize = 1024;
const GLOBAL_MAX_TRACKED_WARNINGS: usize = 4096;
const GLOBAL_WARNING_WINDOW: Duration = Duration::from_secs(300);

static GLOBAL_WARNING_GATE: OnceLock<Mutex<RepeatedWarningGate>> = OnceLock::new();

/// Suppress identical warning messages while the same condition persists.
///
/// The first occurrence is emitted immediately. Repeats with the same key are
/// suppressed until the key has been absent for `hold_for`.
#[derive(Debug)]
pub(crate) struct RepeatedWarningGate {
    hold_for: Duration,
    max_entries: usize,
    last_seen: HashMap<String, Instant>,
}

impl RepeatedWarningGate {
    pub(crate) fn new(hold_for: Duration) -> Self {
        Self::with_capacity(hold_for, DEFAULT_MAX_TRACKED_WARNINGS)
    }

    pub(crate) fn with_capacity(hold_for: Duration, max_entries: usize) -> Self {
        Self {
            hold_for,
            max_entries,
            last_seen: HashMap::new(),
        }
    }

    pub(crate) fn should_emit<S: Into<String>>(&mut self, key: S) -> bool {
        self.should_emit_at(key.into(), Instant::now())
    }

    pub(crate) fn clear(&mut self) {
        self.last_seen.clear();
    }

    fn should_emit_at(&mut self, key: String, now: Instant) -> bool {
        self.prune(now);
        if let Some(last_seen) = self.last_seen.get_mut(&key) {
            *last_seen = now;
            return false;
        }
        if self.last_seen.len() >= self.max_entries {
            return false;
        }
        self.last_seen.insert(key, now);
        true
    }

    fn prune(&mut self, now: Instant) {
        self.last_seen
            .retain(|_, last_seen| now.saturating_duration_since(*last_seen) < self.hold_for);
    }
}

pub(crate) fn should_emit_globally<S: Into<String>>(key: S) -> bool {
    let gate = GLOBAL_WARNING_GATE.get_or_init(|| {
        Mutex::new(RepeatedWarningGate::with_capacity(
            GLOBAL_WARNING_WINDOW,
            GLOBAL_MAX_TRACKED_WARNINGS,
        ))
    });
    gate.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .should_emit(key)
}

#[cfg(test)]
mod tests {
    use super::RepeatedWarningGate;
    use std::time::{Duration, Instant};

    #[test]
    fn repeated_warning_gate_emits_first_occurrence_only() {
        let start = Instant::now();
        let mut gate = RepeatedWarningGate::with_capacity(Duration::from_secs(5), 8);

        assert!(gate.should_emit_at("same warning".to_string(), start));
        assert!(!gate.should_emit_at("same warning".to_string(), start));
        assert!(!gate.should_emit_at("same warning".to_string(), start + Duration::from_secs(4),));
    }

    #[test]
    fn repeated_warning_gate_reemits_after_quiet_window() {
        let start = Instant::now();
        let mut gate = RepeatedWarningGate::with_capacity(Duration::from_secs(5), 8);

        assert!(gate.should_emit_at("warning".to_string(), start));
        assert!(!gate.should_emit_at("warning".to_string(), start + Duration::from_secs(3),));
        assert!(gate.should_emit_at("warning".to_string(), start + Duration::from_secs(9),));
    }

    #[test]
    fn repeated_warning_gate_tracks_distinct_keys_independently() {
        let start = Instant::now();
        let mut gate = RepeatedWarningGate::with_capacity(Duration::from_secs(5), 8);

        assert!(gate.should_emit_at("warning-a".to_string(), start));
        assert!(gate.should_emit_at("warning-b".to_string(), start));
        assert!(!gate.should_emit_at("warning-a".to_string(), start + Duration::from_secs(1),));
        assert!(!gate.should_emit_at("warning-b".to_string(), start + Duration::from_secs(1),));
    }

    #[test]
    fn repeated_warning_gate_clear_resets_state() {
        let start = Instant::now();
        let mut gate = RepeatedWarningGate::with_capacity(Duration::from_secs(5), 8);

        assert!(gate.should_emit_at("warning".to_string(), start));
        assert!(!gate.should_emit_at("warning".to_string(), start + Duration::from_secs(1),));
        gate.clear();
        assert!(gate.should_emit_at("warning".to_string(), start + Duration::from_secs(1),));
    }
}
