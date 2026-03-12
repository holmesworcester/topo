use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const RECENT_BUILD_MISMATCH_WINDOW: Duration = Duration::from_secs(300);

static RECENT_BUILD_MISMATCHES: OnceLock<Mutex<HashMap<String, BuildMismatchRecord>>> =
    OnceLock::new();

#[derive(Clone)]
struct BuildMismatchRecord {
    reason: String,
    last_seen: Instant,
}

fn registry() -> &'static Mutex<HashMap<String, BuildMismatchRecord>> {
    RECENT_BUILD_MISMATCHES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn prune(entries: &mut HashMap<String, BuildMismatchRecord>, now: Instant) {
    entries.retain(|_, record| {
        now.saturating_duration_since(record.last_seen) < RECENT_BUILD_MISMATCH_WINDOW
    });
}

pub(crate) fn note_build_mismatch(peer_id: &str, reason: &str) {
    let now = Instant::now();
    let mut entries = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    prune(&mut entries, now);
    entries.insert(
        peer_id.to_string(),
        BuildMismatchRecord {
            reason: reason.to_string(),
            last_seen: now,
        },
    );
}

pub(crate) fn recent_build_mismatch_reason(peer_id: &str) -> Option<String> {
    let now = Instant::now();
    let mut entries = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    prune(&mut entries, now);
    entries.get_mut(peer_id).map(|record| {
        record.last_seen = now;
        record.reason.clone()
    })
}
