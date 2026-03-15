use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::crypto::EventId;
use crate::tuning::request_inflight_ttl_ms;

#[derive(Debug, Clone, Default)]
pub struct RequestWindowSnapshot {
    pub remote_credit: usize,
    pub inflight_requested: HashMap<EventId, i64>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RequestWindowStats {
    pub remote_credit: usize,
    pub inflight_len: usize,
}

#[derive(Debug, Default)]
struct ConnectionRequestInner {
    remote_credit: usize,
    inflight_requested: HashMap<EventId, i64>,
}

#[derive(Debug, Default)]
pub struct ConnectionRequestState {
    inner: Mutex<ConnectionRequestInner>,
}

impl ConnectionRequestState {
    pub fn add_credit(&self, credits: usize) {
        let mut inner = self.inner.lock().expect("request state mutex poisoned");
        inner.remote_credit = inner.remote_credit.saturating_add(credits);
    }

    pub fn snapshot(&self, now_ms: i64) -> RequestWindowSnapshot {
        let mut inner = self.inner.lock().expect("request state mutex poisoned");
        inner.expire_stale(now_ms);
        RequestWindowSnapshot {
            remote_credit: inner.remote_credit,
            inflight_requested: inner.inflight_requested.clone(),
        }
    }

    pub fn note_requested(&self, ids: &[EventId], now_ms: i64) {
        let mut inner = self.inner.lock().expect("request state mutex poisoned");
        inner.expire_stale(now_ms);
        for event_id in ids {
            inner.inflight_requested.insert(*event_id, now_ms);
        }
        inner.remote_credit = inner.remote_credit.saturating_sub(ids.len());
    }

    pub fn stats(&self, now_ms: i64) -> RequestWindowStats {
        let mut inner = self.inner.lock().expect("request state mutex poisoned");
        inner.expire_stale(now_ms);
        RequestWindowStats {
            remote_credit: inner.remote_credit,
            inflight_len: inner.inflight_requested.len(),
        }
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("request state mutex poisoned");
        inner.remote_credit = 0;
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
    pub available_credit: usize,
}

#[derive(Debug, Default)]
struct ConnectionResponseInner {
    pending_ids: VecDeque<EventId>,
    available_credit: usize,
}

#[derive(Debug, Default)]
pub struct ConnectionResponseState {
    inner: Mutex<ConnectionResponseInner>,
}

impl ConnectionResponseState {
    pub fn consume_requests(&self, ids: &[EventId]) -> usize {
        let mut inner = self.inner.lock().expect("response state mutex poisoned");
        inner.available_credit = inner.available_credit.saturating_sub(ids.len());
        inner.pending_ids.extend(ids.iter().copied());
        ids.len()
    }

    pub fn desired_credit_grant(&self, high: usize, low: usize) -> usize {
        let inner = self.inner.lock().expect("response state mutex poisoned");
        let outstanding_or_reserved = inner
            .pending_ids
            .len()
            .saturating_add(inner.available_credit);
        if outstanding_or_reserved > low {
            return 0;
        }
        high.saturating_sub(outstanding_or_reserved)
    }

    pub fn note_granted(&self, grant: usize) {
        let mut inner = self.inner.lock().expect("response state mutex poisoned");
        inner.available_credit = inner.available_credit.saturating_add(grant);
    }

    pub fn pop_next_response(&self) -> Option<EventId> {
        let mut inner = self.inner.lock().expect("response state mutex poisoned");
        inner.pending_ids.pop_front()
    }

    pub fn requeue_front(&self, event_id: EventId) {
        let mut inner = self.inner.lock().expect("response state mutex poisoned");
        inner.pending_ids.push_front(event_id);
    }

    pub fn stats(&self) -> ResponseQueueStats {
        let inner = self.inner.lock().expect("response state mutex poisoned");
        ResponseQueueStats {
            pending_len: inner.pending_ids.len(),
            available_credit: inner.available_credit,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.stats().pending_len == 0
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("response state mutex poisoned");
        inner.pending_ids.clear();
        inner.available_credit = 0;
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
        state.add_credit(3);
        state.note_requested(&[make_event_id(1)], 0);

        let stats = state.stats(request_inflight_ttl_ms() + 1);
        assert_eq!(stats.remote_credit, 2);
        assert_eq!(stats.inflight_len, 0);
    }

    #[test]
    fn response_state_requeues_and_tracks_credit() {
        let state = ConnectionResponseState::default();
        state.note_granted(2);
        assert_eq!(state.stats().available_credit, 2);

        state.consume_requests(&[make_event_id(1), make_event_id(2)]);
        let stats = state.stats();
        assert_eq!(stats.available_credit, 0);
        assert_eq!(stats.pending_len, 2);

        let first = state.pop_next_response().unwrap();
        let second = state.pop_next_response().unwrap();
        state.requeue_front(first);
        let replay = state.pop_next_response().unwrap();
        assert_eq!(replay, first);
        assert_eq!(second, make_event_id(2));
    }
}
