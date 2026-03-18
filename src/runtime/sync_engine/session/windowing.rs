use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncWindowKind {
    Full = 0,
    Hot = 1,
    Cold = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncWindow {
    pub kind: SyncWindowKind,
    pub cutoff_ms: i64,
}

const WINDOW_MAGIC: &[u8; 4] = b"P7SW";
const WINDOW_VERSION: u8 = 1;
const HOT_WINDOW_MS: i64 = 30_000;
const _COLD_SESSION_INTERVAL_MS: i64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlannerState {
    _NeedFull,
    Established { last_cold_ms: i64 },
}

fn planner_state() -> &'static Mutex<HashMap<String, PlannerState>> {
    static STATE: OnceLock<Mutex<HashMap<String, PlannerState>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn reset_outbound_window_state(db_path: &str, peer_id: &str) {
    let key = format!("{db_path}|{peer_id}");
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.remove(&key);
}

pub fn select_outbound_window(_db_path: &str, _peer_id: &str, now_ms: i64) -> SyncWindow {
    // Always use Full window.  The previous Hot/Cold split assumed a fast round
    // cadence (100 ms) where Cold could sweep old events on a slower cadence.
    // With the production round gap at 5 s, the Cold condition fired every round,
    // making all rounds Cold (ts < now-30s) and hiding freshly created events for
    // 30+ seconds.  A single Full window avoids that bug and keeps the protocol
    // simple: one negentropy snapshot per round, covering the entire event set.
    let cutoff_ms = now_ms - HOT_WINDOW_MS;
    SyncWindow {
        kind: SyncWindowKind::Full,
        cutoff_ms,
    }
}

pub fn mark_outbound_full_completed(db_path: &str, peer_id: &str, now_ms: i64) {
    let key = format!("{db_path}|{peer_id}");
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.insert(
        key,
        PlannerState::Established {
            last_cold_ms: now_ms,
        },
    );
}

impl SyncWindow {
    pub fn ts_min(self) -> Option<i64> {
        match self.kind {
            SyncWindowKind::Hot => Some(self.cutoff_ms),
            _ => None,
        }
    }

    pub fn ts_max_exclusive(self) -> Option<i64> {
        match self.kind {
            SyncWindowKind::Cold => Some(self.cutoff_ms),
            _ => None,
        }
    }
}

pub fn encode_initial_neg_open(window: SyncWindow, inner: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 1 + 8 + inner.len());
    out.extend_from_slice(WINDOW_MAGIC);
    out.push(WINDOW_VERSION);
    out.push(window.kind as u8);
    out.extend_from_slice(&window.cutoff_ms.to_le_bytes());
    out.extend_from_slice(&inner);
    out
}

pub fn decode_initial_neg_open(msg: &[u8]) -> Result<(SyncWindow, &[u8]), String> {
    if msg.len() < 14 || &msg[..4] != WINDOW_MAGIC {
        return Ok((
            SyncWindow {
                kind: SyncWindowKind::Full,
                cutoff_ms: 0,
            },
            msg,
        ));
    }

    let version = msg[4];
    if version != WINDOW_VERSION {
        return Err(format!("unsupported sync window version {}", version));
    }
    let kind = match msg[5] {
        0 => SyncWindowKind::Full,
        1 => SyncWindowKind::Hot,
        2 => SyncWindowKind::Cold,
        other => return Err(format!("unsupported sync window kind {}", other)),
    };
    let cutoff_ms = i64::from_le_bytes(
        msg[6..14]
            .try_into()
            .map_err(|_| "sync window header truncated".to_string())?,
    );
    Ok((SyncWindow { kind, cutoff_ms }, &msg[14..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_stay_full_until_first_full_completes() {
        let db_path = "/tmp/window-test-a";
        let peer_id = "peer-a";
        reset_outbound_window_state(db_path, peer_id);
        let first = select_outbound_window(db_path, peer_id, 100_000);
        let second = select_outbound_window(db_path, peer_id, 101_000);

        assert_eq!(first.kind, SyncWindowKind::Full);
        assert_eq!(second.kind, SyncWindowKind::Full);
    }

    #[test]
    fn completed_full_stays_full_after_completion() {
        let db_path = "/tmp/window-test-b";
        let peer_id = "peer-b";
        reset_outbound_window_state(db_path, peer_id);
        mark_outbound_full_completed(db_path, peer_id, 100_000);

        // With always-Full windowing, post-completion rounds are also Full.
        let next = select_outbound_window(db_path, peer_id, 101_000);
        let later = select_outbound_window(db_path, peer_id, 106_500);

        assert_eq!(next.kind, SyncWindowKind::Full);
        assert_eq!(later.kind, SyncWindowKind::Full);
    }

    #[test]
    fn reset_returns_planner_to_full_baseline() {
        let db_path = "/tmp/window-test-c";
        let peer_id = "peer-c";
        reset_outbound_window_state(db_path, peer_id);
        mark_outbound_full_completed(db_path, peer_id, 100_000);
        reset_outbound_window_state(db_path, peer_id);

        let window = select_outbound_window(db_path, peer_id, 101_000);
        assert_eq!(window.kind, SyncWindowKind::Full);
    }

    #[test]
    fn initial_neg_open_roundtrips_window_header() {
        let window = SyncWindow {
            kind: SyncWindowKind::Hot,
            cutoff_ms: 123_456,
        };
        let payload = vec![1, 2, 3, 4];
        let encoded = encode_initial_neg_open(window, payload.clone());
        let (decoded_window, inner) = decode_initial_neg_open(&encoded).unwrap();

        assert_eq!(decoded_window, window);
        assert_eq!(inner, payload.as_slice());
    }

    #[test]
    fn decode_initial_neg_open_accepts_legacy_raw_payload() {
        let payload = vec![9, 8, 7];
        let (window, inner) = decode_initial_neg_open(&payload).unwrap();

        assert_eq!(window.kind, SyncWindowKind::Full);
        assert_eq!(inner, payload.as_slice());
    }
}
