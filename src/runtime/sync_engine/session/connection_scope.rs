use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::crypto::EventId;
use crate::tuning::request_inflight_ttl_ms;

#[derive(Debug, Clone, Default)]
pub struct RequestWindowSnapshot {
    pub remote_credit_bytes: usize,
    pub last_credit_received_at: Option<i64>,
    pub inflight_requested: HashMap<EventId, i64>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RequestWindowStats {
    pub remote_credit_bytes: usize,
    pub inflight_len: usize,
}

#[derive(Debug, Default)]
struct ConnectionRequestInner {
    remote_credit_bytes: usize,
    last_credit_received_at: Option<i64>,
    inflight_requested: HashMap<EventId, i64>,
}

#[derive(Debug, Default)]
pub struct ConnectionRequestState {
    inner: Mutex<ConnectionRequestInner>,
}

impl ConnectionRequestState {
    pub fn add_credit_bytes(&self, bytes: usize, now_ms: i64) {
        let mut inner = self.inner.lock().expect("request state mutex poisoned");
        inner.remote_credit_bytes = inner.remote_credit_bytes.saturating_add(bytes);
        inner.last_credit_received_at = Some(now_ms);
    }

    pub fn snapshot(&self, now_ms: i64) -> RequestWindowSnapshot {
        let mut inner = self.inner.lock().expect("request state mutex poisoned");
        inner.expire_stale(now_ms);
        RequestWindowSnapshot {
            remote_credit_bytes: inner.remote_credit_bytes,
            last_credit_received_at: inner.last_credit_received_at,
            inflight_requested: inner.inflight_requested.clone(),
        }
    }

    pub fn note_requested(&self, ids: &[EventId], reserved_bytes: usize, now_ms: i64) {
        let mut inner = self.inner.lock().expect("request state mutex poisoned");
        inner.expire_stale(now_ms);
        for event_id in ids {
            inner.inflight_requested.insert(*event_id, now_ms);
        }
        inner.remote_credit_bytes = inner.remote_credit_bytes.saturating_sub(reserved_bytes);
    }

    pub fn stats(&self, now_ms: i64) -> RequestWindowStats {
        let mut inner = self.inner.lock().expect("request state mutex poisoned");
        inner.expire_stale(now_ms);
        RequestWindowStats {
            remote_credit_bytes: inner.remote_credit_bytes,
            inflight_len: inner.inflight_requested.len(),
        }
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("request state mutex poisoned");
        inner.remote_credit_bytes = 0;
        inner.last_credit_received_at = None;
        inner.inflight_requested.clear();
    }
}

impl ConnectionRequestInner {
    fn expire_stale(&mut self, now_ms: i64) {
        let ttl_ms = request_inflight_ttl_ms();
        self.inflight_requested
            .retain(|_, requested_at| now_ms.saturating_sub(*requested_at) < ttl_ms);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ResponseQueueStats {
    pub pending_len: usize,
    pub pending_bytes: usize,
    pub available_credit_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueuedResponse {
    pub event_id: EventId,
    pub encoded_size_bytes: usize,
}

#[derive(Debug, Default)]
struct ConnectionResponseInner {
    pending: VecDeque<QueuedResponse>,
    pending_bytes: usize,
    available_credit_bytes: usize,
}

#[derive(Debug, Default)]
pub struct ConnectionResponseState {
    inner: Mutex<ConnectionResponseInner>,
}

impl ConnectionResponseState {
    pub fn consume_requests(&self, responses: &[QueuedResponse]) -> usize {
        let mut inner = self.inner.lock().expect("response state mutex poisoned");
        let reserved_bytes: usize = responses.iter().map(|response| response.encoded_size_bytes).sum();
        inner.available_credit_bytes = inner.available_credit_bytes.saturating_sub(reserved_bytes);
        inner.pending_bytes = inner.pending_bytes.saturating_add(reserved_bytes);
        inner.pending.extend(responses.iter().copied());
        responses.len()
    }

    pub fn desired_credit_grant_bytes(&self, high: usize, low: usize) -> usize {
        let inner = self.inner.lock().expect("response state mutex poisoned");
        let outstanding_or_reserved = inner
            .pending_bytes
            .saturating_add(inner.available_credit_bytes);
        if outstanding_or_reserved > low {
            return 0;
        }
        high.saturating_sub(outstanding_or_reserved)
    }

    pub fn note_granted_bytes(&self, grant: usize) {
        let mut inner = self.inner.lock().expect("response state mutex poisoned");
        inner.available_credit_bytes = inner.available_credit_bytes.saturating_add(grant);
    }

    pub fn pop_next_response(&self) -> Option<QueuedResponse> {
        let mut inner = self.inner.lock().expect("response state mutex poisoned");
        let next = inner.pending.pop_front()?;
        inner.pending_bytes = inner.pending_bytes.saturating_sub(next.encoded_size_bytes);
        Some(next)
    }

    /// Peek at up to `n` event IDs from the front of the queue without removing them.
    /// Used to batch-read blobs before the send loop pops IDs one at a time.
    pub fn peek_front_n(&self, n: usize) -> Vec<EventId> {
        let inner = self.inner.lock().expect("response state mutex poisoned");
        inner.pending.iter().take(n).map(|q| q.event_id).collect()
    }

    pub fn requeue_front(&self, response: QueuedResponse) {
        let mut inner = self.inner.lock().expect("response state mutex poisoned");
        inner.pending.push_front(response);
        inner.pending_bytes = inner.pending_bytes.saturating_add(response.encoded_size_bytes);
    }

    pub fn stats(&self) -> ResponseQueueStats {
        let inner = self.inner.lock().expect("response state mutex poisoned");
        ResponseQueueStats {
            pending_len: inner.pending.len(),
            pending_bytes: inner.pending_bytes,
            available_credit_bytes: inner.available_credit_bytes,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.stats().pending_len == 0
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("response state mutex poisoned");
        inner.pending.clear();
        inner.pending_bytes = 0;
        inner.available_credit_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event_id(byte: u8) -> EventId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[test]
    fn request_state_expires_stale_inflight_but_keeps_credit() {
        let state = ConnectionRequestState::default();
        state.add_credit_bytes(300, 17);
        state.note_requested(&[make_event_id(1)], 100, 0);

        let stats = state.stats(request_inflight_ttl_ms() + 1);
        assert_eq!(stats.remote_credit_bytes, 200);
        assert_eq!(stats.inflight_len, 0);

        let snapshot = state.snapshot(request_inflight_ttl_ms() + 1);
        assert_eq!(snapshot.last_credit_received_at, Some(17));
    }

    #[test]
    fn response_state_requeues_and_tracks_credit() {
        let state = ConnectionResponseState::default();
        state.note_granted_bytes(320);
        assert_eq!(state.stats().available_credit_bytes, 320);

        state.consume_requests(&[
            QueuedResponse {
                event_id: make_event_id(1),
                encoded_size_bytes: 120,
            },
            QueuedResponse {
                event_id: make_event_id(2),
                encoded_size_bytes: 140,
            },
        ]);
        let stats = state.stats();
        assert_eq!(stats.available_credit_bytes, 60);
        assert_eq!(stats.pending_len, 2);
        assert_eq!(stats.pending_bytes, 260);

        let first = state.pop_next_response().unwrap();
        let second = state.pop_next_response().unwrap();
        state.requeue_front(first);
        let replay = state.pop_next_response().unwrap();
        assert_eq!(replay, first);
        assert_eq!(second.event_id, make_event_id(2));
    }
}
