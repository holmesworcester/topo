//! Connection-level orchestration: accept, connect, and download loops.
//!
//! These functions manage the lifecycle of individual QUIC connections and
//! the sync sessions running on them. Session execution is delegated to
//! `SessionHandler` -- no protocol logic lives here.
//!
//! The transport↔peering seam is [`run_session`]: both accept and connect
//! loops call it to wire QUIC streams into session handler invocations,
//! centralizing DualConnection / SessionMeta / QuicTransportSessionIo
//! construction (R4/SC4 of the peering readability plan).
//!
//! Sub-modules:
//!  - `accept`   -- accept_loop, accept_loop_until_cancel, resolve_inbound_auth_context
//!  - `connect`  -- connect_loop, ConnectLoopConfig
//!  - `supervisor` -- shared preflight + session lifecycle supervision

mod accept;
mod connect;
mod supervisor;

// Re-export public API so callers can still `use crate::peering::loops::*`.
pub use accept::{accept_loop, accept_loop_until_cancel};
pub(crate) use connect::STALE_DIAL_TARGET_MARKER;
pub use connect::{connect_loop, ConnectLoopConfig};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::contracts::peering_contract::{
    PeerFingerprint, SessionDirection, SessionHandler, SessionMeta, TenantId, TransportSessionIo,
};
use crate::runtime::repeated_warning::should_emit_globally;
use crate::sync::SyncConnectionHandler;
use crate::transport::session_factory::extract_build_mismatch_reason;
use crate::transport::DaemonConnection;

// ---------------------------------------------------------------------------
// Tuning constants (orchestration-level only; session constants live in
// sync::session)
// ---------------------------------------------------------------------------

/// Endpoint observation TTL: 24 hours in milliseconds.
pub(super) const ENDPOINT_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Activity timeout for sync data transfer (seconds).
///
/// Used as the idle timeout between data chunks in the receive task.  If no
/// data arrives for this long, the receive side treats the transfer as stalled.
/// This is NOT a total session timeout — sessions run until completion as long
/// as data keeps flowing.
pub const SYNC_SESSION_TIMEOUT_SECS: u64 = 60;

/// Sleep after a failed QUIC connection attempt before retrying.
pub(super) const CONNECT_RETRY_DELAY: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) use crate::db::queue::current_timestamp_ms;

pub(crate) fn short_peer_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
}

pub(crate) fn peer_fingerprint_from_hex(peer_id: &str) -> Option<[u8; 32]> {
    let peer_fp_bytes = hex::decode(peer_id).ok()?;
    if peer_fp_bytes.len() != 32 {
        return None;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&peer_fp_bytes);
    Some(fp)
}

pub(crate) fn preferred_connection_direction(
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct LiveDaemonConnectionKey {
    db_path: String,
    remote_daemon_peer_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct LiveSessionPeerKey {
    db_path: String,
    tenant_id: String,
    remote_session_peer_id: String,
}

struct LiveDaemonConnectionSlot {
    claim_id: u64,
    direction: SessionDirection,
    daemon_connection: DaemonConnection,
    released: Arc<tokio::sync::Notify>,
}

fn live_daemon_connection_slots(
) -> &'static Mutex<HashMap<LiveDaemonConnectionKey, LiveDaemonConnectionSlot>> {
    static LIVE_DAEMON_CONNECTION_SLOTS: OnceLock<
        Mutex<HashMap<LiveDaemonConnectionKey, LiveDaemonConnectionSlot>>,
    > = OnceLock::new();
    LIVE_DAEMON_CONNECTION_SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_live_daemon_connection_claim_id() -> u64 {
    static NEXT_CLAIM_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_CLAIM_ID.fetch_add(1, Ordering::Relaxed)
}

fn live_daemon_connection_key(
    db_path: &str,
    remote_daemon_peer_id: &str,
) -> LiveDaemonConnectionKey {
    LiveDaemonConnectionKey {
        db_path: db_path.to_string(),
        remote_daemon_peer_id: remote_daemon_peer_id.to_string(),
    }
}

fn live_session_peer_counts() -> &'static Mutex<HashMap<LiveSessionPeerKey, usize>> {
    static LIVE_SESSION_PEER_COUNTS: OnceLock<Mutex<HashMap<LiveSessionPeerKey, usize>>> =
        OnceLock::new();
    LIVE_SESSION_PEER_COUNTS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) struct LiveDaemonConnectionLease {
    key: LiveDaemonConnectionKey,
    claim_id: u64,
}

pub(crate) struct LiveSessionPeerLease {
    key: LiveSessionPeerKey,
}

impl Drop for LiveDaemonConnectionLease {
    fn drop(&mut self) {
        let released = {
            let mut slots = live_daemon_connection_slots()
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

impl Drop for LiveSessionPeerLease {
    fn drop(&mut self) {
        let mut counts = live_session_peer_counts()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let remove = match counts.get_mut(&self.key) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            Some(_) => true,
            None => false,
        };
        if remove {
            counts.remove(&self.key);
        }
    }
}

pub(crate) struct LiveDaemonConnectionOccupied {
    pub preferred_direction: Option<SessionDirection>,
    pub active_direction: SessionDirection,
    pub daemon_connection: DaemonConnection,
}

pub(crate) enum LiveDaemonConnectionClaim {
    Acquired(LiveDaemonConnectionLease),
    Occupied(LiveDaemonConnectionOccupied),
}

pub(crate) fn claim_live_daemon_connection_slot(
    db_path: &str,
    local_daemon_peer_id: &str,
    remote_daemon_peer_id: &str,
    direction: SessionDirection,
    daemon_connection: DaemonConnection,
) -> LiveDaemonConnectionClaim {
    let key = live_daemon_connection_key(db_path, remote_daemon_peer_id);
    let preferred_direction =
        preferred_connection_direction(local_daemon_peer_id, remote_daemon_peer_id);
    let claim_id = next_live_daemon_connection_claim_id();

    let mut replaced: Option<(DaemonConnection, Arc<tokio::sync::Notify>)> = None;
    let claim = {
        let mut slots = live_daemon_connection_slots()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match slots.get_mut(&key) {
            None => {
                let released = Arc::new(tokio::sync::Notify::new());
                slots.insert(
                    key.clone(),
                    LiveDaemonConnectionSlot {
                        claim_id,
                        direction,
                        daemon_connection,
                        released,
                    },
                );
                LiveDaemonConnectionClaim::Acquired(LiveDaemonConnectionLease { key, claim_id })
            }
            Some(existing)
                if existing
                    .daemon_connection
                    .connection()
                    .close_reason()
                    .is_some()
                    || existing.daemon_connection.remote_addr()
                        != daemon_connection.remote_addr() =>
            {
                let released = Arc::new(tokio::sync::Notify::new());
                replaced = Some((
                    existing.daemon_connection.clone(),
                    existing.released.clone(),
                ));
                *existing = LiveDaemonConnectionSlot {
                    claim_id,
                    direction,
                    daemon_connection,
                    released,
                };
                LiveDaemonConnectionClaim::Acquired(LiveDaemonConnectionLease { key, claim_id })
            }
            Some(existing) => LiveDaemonConnectionClaim::Occupied(LiveDaemonConnectionOccupied {
                preferred_direction,
                active_direction: existing.direction,
                daemon_connection: existing.daemon_connection.clone(),
            }),
        }
    };

    if let Some((existing_connection, released)) = replaced {
        existing_connection
            .connection()
            .close(0u32.into(), b"replaced by preferred daemon connection");
        released.notify_waiters();
    }

    claim
}

pub(crate) fn live_daemon_connection(
    db_path: &str,
    remote_daemon_peer_id: &str,
) -> Option<DaemonConnection> {
    let key = live_daemon_connection_key(db_path, remote_daemon_peer_id);
    let (connection, released) = {
        let mut slots = live_daemon_connection_slots()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let should_remove = slots
            .get(&key)
            .map(|slot| slot.daemon_connection.connection().close_reason().is_some())
            .unwrap_or(false);
        if should_remove {
            (None, slots.remove(&key).map(|slot| slot.released))
        } else {
            (
                slots.get(&key).map(|slot| slot.daemon_connection.clone()),
                None,
            )
        }
    };
    if let Some(released) = released {
        released.notify_waiters();
    }
    connection
}

pub(crate) fn evict_live_daemon_connection(
    db_path: &str,
    remote_daemon_peer_id: &str,
    stable_id: usize,
) {
    let key = live_daemon_connection_key(db_path, remote_daemon_peer_id);
    let released = {
        let mut slots = live_daemon_connection_slots()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let should_remove = slots
            .get(&key)
            .map(|slot| slot.daemon_connection.connection().stable_id() == stable_id)
            .unwrap_or(false);
        if should_remove {
            slots.remove(&key).map(|slot| slot.released)
        } else {
            None
        }
    };
    if let Some(released) = released {
        released.notify_waiters();
    }
}

pub(crate) fn claim_live_session_peer(
    db_path: &str,
    tenant_id: &str,
    remote_session_peer_id: &str,
) -> LiveSessionPeerLease {
    let key = LiveSessionPeerKey {
        db_path: db_path.to_string(),
        tenant_id: tenant_id.to_string(),
        remote_session_peer_id: remote_session_peer_id.to_string(),
    };
    let mut counts = live_session_peer_counts()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    *counts.entry(key.clone()).or_insert(0) += 1;
    LiveSessionPeerLease { key }
}

pub(crate) fn live_session_peer_ids(db_path: &str, tenant_id: &str) -> Vec<String> {
    let counts = live_session_peer_counts()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let mut remote_session_peer_ids: Vec<String> = counts
        .keys()
        .filter(|key| key.db_path == db_path && key.tenant_id == tenant_id)
        .map(|key| key.remote_session_peer_id.clone())
        .collect();
    remote_session_peer_ids.sort();
    remote_session_peer_ids.dedup();
    remote_session_peer_ids
}

// ---------------------------------------------------------------------------
// Transport↔peering session seam
// ---------------------------------------------------------------------------

/// Run a single sync session using a pre-built `TransportSessionIo`.
///
/// This is the peering orchestration seam: it wires session metadata,
/// cancellation, and the session handler together. Transport
/// details (stream opening, `DualConnection`, `QuicTransportSessionIo`)
/// are handled by `transport::session_factory` before this is called.
pub(super) async fn run_session(
    handler: &SyncConnectionHandler,
    session_id: u64,
    io: Box<dyn TransportSessionIo>,
    tenant_id: &str,
    peer_fp: [u8; 32],
    remote_addr: SocketAddr,
    direction: SessionDirection,
    _db_path: &str,
) -> bool {
    let meta = SessionMeta {
        session_id,
        tenant: TenantId(tenant_id.to_string()),
        peer: PeerFingerprint(peer_fp),
        remote_addr,
        direction,
    };
    let cancel = CancellationToken::new();

    if let Err(e) = handler.on_session(meta, io, cancel.clone()).await {
        let label = match direction {
            SessionDirection::Outbound => "Initiator",
            SessionDirection::Inbound => "Responder",
        };
        if let Some(reason) = extract_build_mismatch_reason(&e) {
            let peer_id = hex::encode(peer_fp);
            let key = format!("session-build-mismatch:{label}:{peer_id}:{direction:?}");
            if should_emit_globally(key) {
                warn!(
                    "{} session rejected by peer {}: {}",
                    label,
                    &peer_id[..16.min(peer_id.len())],
                    reason
                );
            }
        } else {
            warn!("{} session error: {}", label, e);
        }
        cancel.cancel();
        return false;
    }
    cancel.cancel();
    true
}

pub(super) use crate::tuning::drain_batch_size;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        claim_live_daemon_connection_slot, claim_live_session_peer, live_daemon_connection,
        live_session_peer_ids, preferred_connection_direction, LiveDaemonConnectionClaim,
        SessionDirection,
    };
    use crate::db::schema::create_tables;
    use crate::transport::{
        accept_daemon_connection, create_runtime_endpoint_for_tenants, dial_daemon_connection,
        load_daemon_identity_from_db, multi_workspace::transport_sni,
    };

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
    fn live_session_peers_are_tracked_by_tenant_and_deduped() {
        let db_path = "/tmp/live-session-peer-tracking.db";
        let tenant_a = format!("{:064x}", 1);
        let tenant_b = format!("{:064x}", 2);
        let peer = format!("{:064x}", 3);

        assert!(live_session_peer_ids(db_path, &tenant_a).is_empty());

        let lease_a1 = claim_live_session_peer(db_path, &tenant_a, &peer);
        let lease_a2 = claim_live_session_peer(db_path, &tenant_a, &peer);
        let _lease_b = claim_live_session_peer(db_path, &tenant_b, &peer);

        assert_eq!(
            live_session_peer_ids(db_path, &tenant_a),
            vec![peer.clone()]
        );
        assert_eq!(
            live_session_peer_ids(db_path, &tenant_b),
            vec![peer.clone()]
        );

        drop(lease_a1);
        assert_eq!(
            live_session_peer_ids(db_path, &tenant_a),
            vec![peer.clone()]
        );

        drop(lease_a2);
        assert!(live_session_peer_ids(db_path, &tenant_a).is_empty());
        assert_eq!(live_session_peer_ids(db_path, &tenant_b), vec![peer]);
    }

    #[tokio::test]
    async fn inbound_reconnect_from_new_remote_addr_replaces_stale_slot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let server_db = temp.path().join("server.sqlite3");
        let client_db = temp.path().join("client.sqlite3");
        let server_ep = create_runtime_endpoint_for_tenants(
            "127.0.0.1:0".parse().unwrap(),
            server_db.to_str().unwrap(),
        )
        .await
        .expect("server endpoint");
        let client_ep_a = create_runtime_endpoint_for_tenants(
            "127.0.0.1:0".parse().unwrap(),
            client_db.to_str().unwrap(),
        )
        .await
        .expect("client endpoint a");
        let client_ep_b = create_runtime_endpoint_for_tenants(
            "127.0.0.1:0".parse().unwrap(),
            client_db.to_str().unwrap(),
        )
        .await
        .expect("client endpoint b");
        let server_peer_id = load_daemon_identity_from_db(server_db.to_str().unwrap())
            .expect("server daemon identity")
            .0;
        let client_peer_id = load_daemon_identity_from_db(client_db.to_str().unwrap())
            .expect("client daemon identity")
            .0;

        let server_addr = server_ep.local_addr().expect("server addr");
        let server_sni = transport_sni(&server_peer_id);
        let db_path = temp.path().join("live-daemon-slot.db");
        let db_str = db_path.to_str().expect("db path");

        let (accepted_a, _) = tokio::join!(
            accept_daemon_connection(&server_ep),
            dial_daemon_connection(&client_ep_a, server_addr, &server_sni),
        );
        let accepted_a = accepted_a
            .expect("accept a")
            .expect("accepted daemon connection a");
        let lease_a = match claim_live_daemon_connection_slot(
            db_str,
            &server_peer_id,
            &client_peer_id,
            SessionDirection::Inbound,
            accepted_a.clone(),
        ) {
            LiveDaemonConnectionClaim::Acquired(lease) => lease,
            LiveDaemonConnectionClaim::Occupied(_) => {
                panic!("first inbound connection should acquire slot")
            }
        };

        let first_remote_addr = accepted_a.remote_addr();

        let (accepted_b, _) = tokio::join!(
            accept_daemon_connection(&server_ep),
            dial_daemon_connection(&client_ep_b, server_addr, &server_sni),
        );
        let accepted_b = accepted_b
            .expect("accept b")
            .expect("accepted daemon connection b");
        let second_remote_addr = accepted_b.remote_addr();
        assert_ne!(
            first_remote_addr, second_remote_addr,
            "test requires reconnect to arrive from a fresh remote address"
        );

        let lease_b = match claim_live_daemon_connection_slot(
            db_str,
            &server_peer_id,
            &client_peer_id,
            SessionDirection::Inbound,
            accepted_b.clone(),
        ) {
            LiveDaemonConnectionClaim::Acquired(lease) => lease,
            LiveDaemonConnectionClaim::Occupied(_) => {
                panic!("fresh inbound reconnect should replace stale slot")
            }
        };

        let live = live_daemon_connection(db_str, &client_peer_id).expect("live slot");
        assert_eq!(live.remote_addr(), second_remote_addr);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if accepted_a.connection().close_reason().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("replaced connection closed");

        drop(lease_a);
        drop(lease_b);
        client_ep_a.close(0u32.into(), b"test close");
        client_ep_b.close(0u32.into(), b"test close");
        server_ep.close(0u32.into(), b"test close");
    }

    #[tokio::test]
    async fn pending_bootstrap_aliases_share_live_daemon_slot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let server_db = temp.path().join("server.sqlite3");
        let client_db = temp.path().join("client.sqlite3");
        let server_ep = create_runtime_endpoint_for_tenants(
            "127.0.0.1:0".parse().unwrap(),
            server_db.to_str().unwrap(),
        )
        .await
        .expect("server endpoint");
        let client_ep_a = create_runtime_endpoint_for_tenants(
            "127.0.0.1:0".parse().unwrap(),
            client_db.to_str().unwrap(),
        )
        .await
        .expect("client endpoint a");
        let client_ep_b = create_runtime_endpoint_for_tenants(
            "127.0.0.1:0".parse().unwrap(),
            client_db.to_str().unwrap(),
        )
        .await
        .expect("client endpoint b");
        let server_peer_id = load_daemon_identity_from_db(server_db.to_str().unwrap())
            .expect("server daemon identity")
            .0;
        let client_peer_id = load_daemon_identity_from_db(client_db.to_str().unwrap())
            .expect("client daemon identity")
            .0;

        let server_addr = server_ep.local_addr().expect("server addr");
        let server_sni = transport_sni(&server_peer_id);
        let db_path = temp.path().join("bootstrap-alias-slot.db");
        let db_str = db_path.to_str().expect("db path");
        let db = crate::db::open_connection(db_str).expect("open db");
        create_tables(&db).expect("create tables");
        drop(db);

        let (accepted_a, dialed_a) = tokio::join!(
            accept_daemon_connection(&server_ep),
            dial_daemon_connection(&client_ep_a, server_addr, &server_sni),
        );
        let accepted_a = accepted_a
            .expect("accept a")
            .expect("accepted daemon connection a");
        let dialed_a = dialed_a.expect("dial a");
        let first_remote_addr = accepted_a.remote_addr();
        let lease_a = match claim_live_daemon_connection_slot(
            db_str,
            &server_peer_id,
            &client_peer_id,
            SessionDirection::Inbound,
            accepted_a.clone(),
        ) {
            LiveDaemonConnectionClaim::Acquired(lease) => lease,
            LiveDaemonConnectionClaim::Occupied(_) => {
                panic!("first daemon connection should acquire slot")
            }
        };

        let (accepted_b, dialed_b) = tokio::join!(
            accept_daemon_connection(&server_ep),
            dial_daemon_connection(&client_ep_b, server_addr, &server_sni),
        );
        let accepted_b = accepted_b
            .expect("accept b")
            .expect("accepted daemon connection b");
        let dialed_b = dialed_b.expect("dial b");
        let second_remote_addr = accepted_b.remote_addr();
        assert_ne!(
            first_remote_addr, second_remote_addr,
            "test requires a distinct remote address for the second inbound connection",
        );

        let lease_b = match claim_live_daemon_connection_slot(
            db_str,
            &server_peer_id,
            &client_peer_id,
            SessionDirection::Inbound,
            accepted_b.clone(),
        ) {
            LiveDaemonConnectionClaim::Acquired(lease) => lease,
            LiveDaemonConnectionClaim::Occupied(_) => {
                panic!("fresh inbound reconnect should replace the old live daemon slot")
            }
        };

        let live = live_daemon_connection(db_str, &client_peer_id).expect("second live slot");
        assert_eq!(live.remote_addr(), second_remote_addr);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if accepted_a.connection().close_reason().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("replaced connection closed");

        drop(lease_a);
        drop(lease_b);
        drop(dialed_a);
        drop(dialed_b);
        client_ep_a.close(0u32.into(), b"test close");
        client_ep_b.close(0u32.into(), b"test close");
        server_ep.close(0u32.into(), b"test close");
    }
}
