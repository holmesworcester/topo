//! Tests the rateless spray session ordering when TOPO_SYNC_MODE=rateless-spray.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{SessionDirection, SessionHandler};
use topo::protocol::Frame;
use topo::sync::session::rateless::{decode_rateless_open, encode_rateless_open, RatelessSyncOpen};
use topo::sync::session::windowing::{
    encode_sync_window_kind, prime_outbound_window_kind, reset_outbound_window_state, SyncWindow,
    SyncWindowKind,
};
use topo::sync::session_handler::SyncConnectionHandler;

use crate::fake_session_io::{create_test_db, fake_session_io_pair, run_local, test_session_meta};

struct EnvGuard {
    prev_sync_mode: Option<String>,
}

impl EnvGuard {
    fn enable_rateless_sync() -> Self {
        let prev_sync_mode = std::env::var("TOPO_SYNC_MODE").ok();
        std::env::set_var("TOPO_SYNC_MODE", "rateless-spray");
        Self { prev_sync_mode }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev_sync_mode {
            Some(value) => std::env::set_var("TOPO_SYNC_MODE", value),
            None => std::env::remove_var("TOPO_SYNC_MODE"),
        }
    }
}

#[tokio::test]
async fn initiator_starts_with_rateless_open_and_sends_header_on_data_lane() {
    run_local(async {
        let _env = EnvGuard::enable_rateless_sync();
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::outbound(db_path, 30);
        let meta = test_session_meta(SessionDirection::Outbound);
        let session_id = meta.session_id;
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);
        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move { handler.on_session(meta, Box::new(fake_io), cancel).await }
        });

        let first = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected initial rateless open");
        assert!(
            matches!(first, Frame::RatelessOpen { .. }),
            "expected RatelessOpen as the first control frame, got {first:?}"
        );
        let Frame::RatelessOpen { msg } = first else {
            unreachable!("assert above guarantees RatelessOpen");
        };
        match decode_rateless_open(&msg).unwrap() {
            RatelessSyncOpen::SteadyState {
                workspace_id,
                requested_range,
            } => {
                assert_eq!(workspace_id, "ws-test-tenant");
                if let (Some(ts_min), Some(ts_max)) = (
                    requested_range.ts_min_inclusive_ms,
                    requested_range.ts_max_exclusive_ms,
                ) {
                    assert!(
                        ts_min < ts_max,
                        "expected initiator window bounds to be ordered, got {requested_range:?}"
                    );
                }
            }
            other => panic!("expected steady-state rateless open, got {other:?}"),
        }

        let first_data = peer
            .recv_data_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected rateless header on data stream");
        assert_eq!(
            first_data,
            Frame::RatelessHeader {
                chunk_size: topo::tuning::rateless_chunk_bytes() as u32,
                source_symbols: 0,
                symbols_sent: 0,
                total_bytes: 0,
                total_events: 0,
                seed: *blake3::hash(&session_id.to_le_bytes()).as_bytes(),
            }
        );

        cancel.cancel();
        peer.force_close();
        handler_task.abort();
        let _ = handler_task.await;
    })
    .await;
}

#[tokio::test]
async fn responder_accepts_rateless_open_and_sends_header_on_data_lane() {
    run_local(async {
        let _env = EnvGuard::enable_rateless_sync();
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::responder(db_path, 30);
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);
        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move { handler.on_session(meta, Box::new(fake_io), cancel).await }
        });

        peer.send_control_msg(&Frame::RatelessOpen {
            msg: encode_rateless_open(&RatelessSyncOpen::SteadyState {
                workspace_id: "ws-test-tenant".to_string(),
                requested_range: SyncWindow {
                    kind: SyncWindowKind::LastDay,
                    ts_min_inclusive_ms: Some(0),
                    ts_max_exclusive_ms: None,
                },
            })
            .expect("encode rateless open"),
        })
        .await;

        let unexpected_control = peer.recv_control_msg_timeout(Duration::from_millis(250)).await;
        assert!(
            unexpected_control.is_none(),
            "expected no control reply for accepted rateless session, got {unexpected_control:?}"
        );

        let first_data = peer
            .recv_data_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected rateless header on responder data stream");
        assert!(matches!(
            first_data,
            Frame::RatelessHeader {
                source_symbols: 0,
                symbols_sent: 0,
                total_bytes: 0,
                total_events: 0,
                ..
            }
        ));

        cancel.cancel();
        peer.force_close();
        handler_task.abort();
        let _ = handler_task.await;
    })
    .await;
}

#[tokio::test]
async fn initiator_clamps_future_rateless_windows_after_explicit_last_week_policy_reject() {
    run_local(async {
        let _env = EnvGuard::enable_rateless_sync();
        std::env::remove_var("LOW_MEM_IOS");

        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::outbound(db_path.clone(), 30);
        let meta = test_session_meta(SessionDirection::Outbound);
        let peer_id = hex::encode(meta.peer.0);
        let cancel = CancellationToken::new();

        reset_outbound_window_state(&db_path, "test-tenant", &peer_id);
        prime_outbound_window_kind(
            &db_path,
            "test-tenant",
            &peer_id,
            SyncWindowKind::LastTwelveWeeks,
        );

        let (fake_io_1, mut peer_1) = fake_session_io_pair(meta.session_id);
        let handler_task_1 = tokio::task::spawn_local({
            let handler = handler.clone();
            let cancel = cancel.clone();
            let meta = meta.clone();
            async move { handler.on_session(meta, Box::new(fake_io_1), cancel).await }
        });

        let first_open = peer_1
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected first rateless open");
        let Frame::RatelessOpen { msg } = first_open else {
            panic!("expected RatelessOpen frame");
        };
        let first_requested_range = match decode_rateless_open(&msg).expect("decode rateless open")
        {
            RatelessSyncOpen::SteadyState {
                requested_range, ..
            }
            | RatelessSyncOpen::Bootstrap {
                requested_range, ..
            } => requested_range,
        };
        assert_eq!(first_requested_range.kind, SyncWindowKind::LastTwelveWeeks);

        peer_1
            .send_control_msg(&Frame::RangePolicyReject {
                rejected_window_kind: encode_sync_window_kind(SyncWindowKind::LastTwelveWeeks),
                oldest_allowed_window_kind: encode_sync_window_kind(SyncWindowKind::LastWeek),
            })
            .await;

        let first_result = tokio::time::timeout(Duration::from_secs(5), handler_task_1)
            .await
            .expect("rateless initiator timed out on explicit range policy reject")
            .expect("rateless initiator task panicked");
        assert!(
            first_result.is_ok(),
            "rateless initiator should treat the explicit last-week policy reject as a clean adaptation: {first_result:?}"
        );

        let meta_2 = test_session_meta(SessionDirection::Outbound);
        let (fake_io_2, mut peer_2) = fake_session_io_pair(meta_2.session_id);
        let handler_task_2 = tokio::task::spawn_local({
            let handler = handler.clone();
            let cancel = cancel.clone();
            async move { handler.on_session(meta_2, Box::new(fake_io_2), cancel).await }
        });

        let second_open = peer_2
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected second rateless open");
        let Frame::RatelessOpen { msg } = second_open else {
            panic!("expected RatelessOpen frame");
        };
        let second_requested_range =
            match decode_rateless_open(&msg).expect("decode second rateless open") {
                RatelessSyncOpen::SteadyState {
                    requested_range, ..
                }
                | RatelessSyncOpen::Bootstrap {
                    requested_range, ..
                } => requested_range,
            };
        assert!(
            matches!(
                second_requested_range.kind,
                SyncWindowKind::LastDay | SyncWindowKind::LastWeek
            ),
            "after explicit last-week policy reject, rateless initiator should only request day/week windows, got {:?}",
            second_requested_range.kind
        );

        cancel.cancel();
        peer_1.force_close();
        peer_2.force_close();
        handler_task_2.abort();
        let _ = handler_task_2.await;
    })
    .await;
}
