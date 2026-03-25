use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::contracts::peering_contract::SessionDirection;

pub fn peer_fingerprint_from_hex(peer_id: &str) -> Option<[u8; 32]> {
    let peer_fp_bytes = hex::decode(peer_id).ok()?;
    if peer_fp_bytes.len() != 32 {
        return None;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&peer_fp_bytes);
    Some(fp)
}

pub fn preferred_connection_direction(
    local_peer_id: &str,
    remote_peer_id: &str,
) -> Option<SessionDirection> {
    let local = peer_fingerprint_from_hex(local_peer_id)?;
    let remote = peer_fingerprint_from_hex(remote_peer_id)?;
    Some(match local.cmp(&remote) {
        std::cmp::Ordering::Less | std::cmp::Ordering::Equal => SessionDirection::Outbound,
        std::cmp::Ordering::Greater => SessionDirection::Inbound,
    })
}

fn connection_direction_rank(
    local_peer_id: &str,
    remote_peer_id: &str,
    direction: SessionDirection,
) -> u8 {
    match preferred_connection_direction(local_peer_id, remote_peer_id) {
        Some(preferred) if preferred == direction => 2,
        Some(_) => 0,
        None => 1,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct LiveConnectionKey {
    db_path: String,
    recorded_by: String,
    peer_id: String,
}

struct LiveConnectionSlot {
    claim_id: u64,
    direction: SessionDirection,
    direction_rank: u8,
    connection: crate::transport::TransportConnection,
    released: Arc<tokio::sync::Notify>,
}

fn live_connection_slots() -> &'static Mutex<HashMap<LiveConnectionKey, LiveConnectionSlot>> {
    static LIVE_CONNECTION_SLOTS: OnceLock<Mutex<HashMap<LiveConnectionKey, LiveConnectionSlot>>> =
        OnceLock::new();
    LIVE_CONNECTION_SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_live_connection_claim_id() -> u64 {
    static NEXT_CLAIM_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_CLAIM_ID.fetch_add(1, Ordering::Relaxed)
}

pub struct LiveConnectionLease {
    key: LiveConnectionKey,
    claim_id: u64,
}

impl Drop for LiveConnectionLease {
    fn drop(&mut self) {
        let released = {
            let mut slots = live_connection_slots()
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            match slots.get(&self.key) {
                Some(slot) if slot.claim_id == self.claim_id => {
                    let slot = slots
                        .remove(&self.key)
                        .expect("live connection slot missing");
                    Some(slot.released)
                }
                _ => None,
            }
        };
        if let Some(released) = released {
            released.notify_waiters();
        }
    }
}

pub struct LiveConnectionOccupied {
    pub preferred_direction: Option<SessionDirection>,
    pub active_direction: SessionDirection,
    pub released: Arc<tokio::sync::Notify>,
}

pub enum LiveConnectionClaim {
    Acquired(LiveConnectionLease),
    Occupied(LiveConnectionOccupied),
}

pub fn claim_live_connection_slot(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    direction: SessionDirection,
    connection: crate::transport::TransportConnection,
) -> LiveConnectionClaim {
    let key = LiveConnectionKey {
        db_path: db_path.to_string(),
        recorded_by: recorded_by.to_string(),
        peer_id: peer_id.to_string(),
    };
    let direction_rank = connection_direction_rank(recorded_by, peer_id, direction);
    let preferred_direction = preferred_connection_direction(recorded_by, peer_id);
    let claim_id = next_live_connection_claim_id();

    let mut replaced: Option<(
        crate::transport::TransportConnection,
        Arc<tokio::sync::Notify>,
    )> = None;
    let claim = {
        let mut slots = live_connection_slots()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match slots.get_mut(&key) {
            None => {
                let released = Arc::new(tokio::sync::Notify::new());
                slots.insert(
                    key.clone(),
                    LiveConnectionSlot {
                        claim_id,
                        direction,
                        direction_rank,
                        connection,
                        released,
                    },
                );
                LiveConnectionClaim::Acquired(LiveConnectionLease { key, claim_id })
            }
            Some(existing) if direction_rank > existing.direction_rank => {
                let released = Arc::new(tokio::sync::Notify::new());
                replaced = Some((existing.connection.clone(), existing.released.clone()));
                *existing = LiveConnectionSlot {
                    claim_id,
                    direction,
                    direction_rank,
                    connection,
                    released,
                };
                LiveConnectionClaim::Acquired(LiveConnectionLease { key, claim_id })
            }
            Some(existing) => LiveConnectionClaim::Occupied(LiveConnectionOccupied {
                preferred_direction,
                active_direction: existing.direction,
                released: existing.released.clone(),
            }),
        }
    };

    if let Some((existing_connection, released)) = replaced {
        existing_connection.close(0u32.into(), b"replaced by preferred peer connection");
        released.notify_waiters();
    }

    claim
}

pub fn live_connection_peer_ids(db_path: &str, recorded_by: &str) -> Vec<String> {
    let slots = live_connection_slots()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let mut peer_ids: Vec<String> = slots
        .keys()
        .filter(|key| key.db_path == db_path && key.recorded_by == recorded_by)
        .map(|key| key.peer_id.clone())
        .collect();
    peer_ids.sort();
    peer_ids.dedup();
    peer_ids
}

/// Derive a bilateral connection episode ID that both sides compute identically.
/// sorted(peer_a, peer_b) + stable_id → deterministic hash.
pub fn bilateral_connection_episode_id(
    local_peer_id: &str,
    remote_peer_id: &str,
    connection_stable_id: usize,
) -> String {
    let (first, second) = if local_peer_id <= remote_peer_id {
        (local_peer_id, remote_peer_id)
    } else {
        (remote_peer_id, local_peer_id)
    };
    let input = format!("conn:{first}:{second}:{connection_stable_id}");
    let hash = crate::crypto::hash_event(input.as_bytes());
    crate::crypto::event_id_to_base64(&hash)
}

/// Derive a bilateral sync round episode ID from shared context.
pub fn bilateral_sync_round_episode_id(
    connection_episode_id: &str,
    session_id: u64,
) -> String {
    let input = format!("round:{connection_episode_id}:{session_id}");
    let hash = crate::crypto::hash_event(input.as_bytes());
    crate::crypto::event_id_to_base64(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_connection_direction_is_symmetric() {
        let lower = format!("{:064x}", 1);
        let higher = format!("{:064x}", 2);
        assert_eq!(
            preferred_connection_direction(&lower, &higher),
            Some(SessionDirection::Outbound)
        );
        assert_eq!(
            preferred_connection_direction(&higher, &lower),
            Some(SessionDirection::Inbound)
        );
    }

    #[test]
    fn preferred_connection_direction_defaults_to_outbound_for_equal_ids() {
        let peer = format!("{:064x}", 9);
        assert_eq!(
            preferred_connection_direction(&peer, &peer),
            Some(SessionDirection::Outbound)
        );
    }

    #[test]
    fn preferred_connection_direction_returns_none_for_invalid_peer_ids() {
        assert_eq!(preferred_connection_direction("not-hex", "also-bad"), None);
    }

    #[test]
    fn bilateral_connection_id_is_symmetric() {
        let a = format!("{:064x}", 1);
        let b = format!("{:064x}", 2);
        assert_eq!(
            bilateral_connection_episode_id(&a, &b, 42),
            bilateral_connection_episode_id(&b, &a, 42)
        );
    }

    #[test]
    fn bilateral_connection_id_differs_by_stable_id() {
        let a = format!("{:064x}", 1);
        let b = format!("{:064x}", 2);
        assert_ne!(
            bilateral_connection_episode_id(&a, &b, 1),
            bilateral_connection_episode_id(&a, &b, 2)
        );
    }

    #[test]
    fn bilateral_round_id_differs_by_session() {
        let ep = bilateral_connection_episode_id("a", "b", 1);
        assert_ne!(
            bilateral_sync_round_episode_id(&ep, 1),
            bilateral_sync_round_episode_id(&ep, 2)
        );
    }

    #[test]
    fn two_client_exchange_paired_by_episode_ids() {
        let (alice, bob, stable, sess) = ("alice", "bob", 7usize, 3u64);
        let a_conn = bilateral_connection_episode_id(alice, bob, stable);
        let b_conn = bilateral_connection_episode_id(bob, alice, stable);
        assert_eq!(a_conn, b_conn);
        assert_eq!(
            bilateral_sync_round_episode_id(&a_conn, sess),
            bilateral_sync_round_episode_id(&b_conn, sess)
        );
    }
}
