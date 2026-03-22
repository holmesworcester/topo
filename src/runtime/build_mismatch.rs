use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const RECENT_BUILD_MISMATCH_WINDOW: Duration = Duration::from_secs(300);

static RECENT_BUILD_MISMATCHES: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, Instant>> {
    RECENT_BUILD_MISMATCHES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn prune(entries: &mut HashMap<String, Instant>, now: Instant) {
    entries.retain(|_, last_seen| {
        now.saturating_duration_since(*last_seen) < RECENT_BUILD_MISMATCH_WINDOW
    });
}

pub(crate) fn note_build_mismatch(peer_id: &str, _reason: &str) {
    let now = Instant::now();
    let mut entries = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    prune(&mut entries, now);
    entries.insert(peer_id.to_string(), now);
}
