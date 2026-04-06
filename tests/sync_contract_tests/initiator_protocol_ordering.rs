//! Tests the current one-range-per-session initiator control ordering.

use std::time::Duration;
use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{SessionDirection, SessionHandler};
use topo::protocol::Frame;
use topo::sync::session::windowing::{
    decode_initial_neg_open, encode_sync_window_kind, prime_outbound_window_kind,
    reset_outbound_window_state, SyncWindowKind,
};
use topo::sync::session_handler::SyncConnectionHandler;

use crate::fake_session_io::{
    create_test_db, empty_negentropy_storage, fake_session_io_pair, run_local, test_session_meta,
};

fn empty_negentropy_response(neg_open: Frame) -> Vec<u8> {
    let Frame::NegOpen { msg } = neg_open else {
        panic!("expected NegOpen frame");
    };
    let (_window, msg) = decode_initial_neg_open(&msg).expect("decode NegOpen header");
    let storage = empty_negentropy_storage();
    let mut neg = negentropy::Negentropy::new(negentropy::Storage::Borrowed(&storage), 0).unwrap();
    neg.reconcile(msg).unwrap()
}

#[tokio::test]
async fn initiator_outbound_starts_with_negopen_then_ends_control_phase() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::outbound(db_path, 30);
        let meta = test_session_meta(SessionDirection::Outbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move { handler.on_session(meta, Box::new(fake_io), cancel).await }
        });

        let neg_open_1 = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected initial NegOpen");
        assert!(matches!(neg_open_1, Frame::NegOpen { .. }));
        peer.send_control_msg(&Frame::NegMsg {
            msg: empty_negentropy_response(neg_open_1),
        })
        .await;

        // No per-round completion markers should appear on the data stream.
        let unexpected = peer.recv_data_msg_timeout(Duration::from_millis(250)).await;
        assert!(
            unexpected.is_none(),
            "expected no unsolicited per-round data marker, got {:?}",
            unexpected
        );

        // The simplified range session ends the control phase with an empty
        // NegMsg instead of starting another round on the same session.
        let frame = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected control terminator");
        assert_eq!(frame, Frame::NegMsg { msg: Vec::new() });

        let no_second_round = peer
            .recv_control_msg_timeout(Duration::from_millis(250))
            .await;
        assert!(
            no_second_round.is_none(),
            "expected no second NegOpen on the same session, got {:?}",
            no_second_round
        );

        cancel.cancel();
        peer.force_close();
        handler_task.abort();
        let _ = handler_task.await;
    })
    .await;
}

#[tokio::test]
async fn anticheat_first_control_frame_is_negopen() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::outbound(db_path, 30);
        let meta = test_session_meta(SessionDirection::Outbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move {
                let _ = handler.on_session(meta, Box::new(fake_io), cancel).await;
            }
        });

        let first = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected first control message");
        assert!(
            matches!(first, Frame::NegOpen { .. }),
            "ANTI-CHEAT: first control message must be NegOpen, not a fake startup marker"
        );

        let unexpected_data = peer.recv_data_msg_timeout(Duration::from_millis(250)).await;
        assert!(
            unexpected_data.is_none(),
            "ANTI-CHEAT: data stream must not carry startup markers or unsolicited data"
        );

        cancel.cancel();
        peer.force_close();
    })
    .await;
}

#[tokio::test]
async fn initiator_rejects_inbound_direction() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::outbound(db_path, 30);
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let (fake_io, _peer) = fake_session_io_pair(meta.session_id);

        let result = handler.on_session(meta, Box::new(fake_io), cancel).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("initiator handler cannot run inbound sessions"),
            "expected role/direction mismatch error"
        );
    })
    .await;
}

#[tokio::test]
async fn initiator_clamps_future_windows_after_explicit_last_week_policy_reject() {
    // Ensure LOW_MEM_IOS is unset so the planner allows Full for
    // priming. Another concurrent test may have set it via EnvGuard.
    std::env::remove_var("LOW_MEM_IOS");
    run_local(async {
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
            SyncWindowKind::Full,
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
            .expect("expected first outbound NegOpen");
        let (first_phase, _msg) = decode_initial_neg_open(match &first_open {
            Frame::NegOpen { msg } => msg,
            other => panic!("expected NegOpen frame, got {other:?}"),
        })
        .expect("decode first NegOpen header");
        let topo::sync::session::windowing::SyncNegPhase::ObjectsRange { window: first_window } =
            first_phase
        else {
            panic!("expected object-range phase");
        };
        assert_eq!(first_window.kind, SyncWindowKind::Full);
        peer_1
            .send_control_msg(&Frame::RangePolicyReject {
                rejected_window_kind: encode_sync_window_kind(SyncWindowKind::Full),
                oldest_allowed_window_kind: encode_sync_window_kind(SyncWindowKind::LastWeek),
            })
            .await;

        let first_result = tokio::time::timeout(Duration::from_secs(5), handler_task_1)
            .await
            .expect("initiator timed out on explicit range policy reject")
            .expect("initiator task panicked");
        assert!(
            first_result.is_ok(),
            "initiator should treat the explicit last-week policy reject as a clean adaptation: {first_result:?}"
        );

        let meta_2 = test_session_meta(SessionDirection::Outbound);
        let (fake_io_2, mut peer_2) = fake_session_io_pair(meta_2.session_id);
        let handler_task_2 = tokio::task::spawn_local({
            let handler = handler.clone();
            let cancel = cancel.clone();
            async move { handler.on_session(meta_2, Box::new(fake_io_2), cancel).await }
        });

        let second_window = loop {
            let second_open = peer_2
                .recv_control_msg_timeout(Duration::from_secs(5))
                .await
                .expect("expected second outbound NegOpen or claim shard");
            let second_phase = decode_initial_neg_open(match &second_open {
                Frame::NegOpen { msg } => msg,
                other => panic!("expected NegOpen frame, got {other:?}"),
            })
            .expect("decode second NegOpen header")
            .0;
            match second_phase {
                topo::sync::session::windowing::SyncNegPhase::ClaimsWeekShard { .. } => {
                    peer_2
                        .send_control_msg(&Frame::NegMsg {
                            msg: empty_negentropy_response(second_open),
                        })
                        .await;
                    let terminator = peer_2
                        .recv_control_msg_timeout(Duration::from_secs(5))
                        .await
                        .expect("expected claim-phase terminator");
                    assert_eq!(terminator, Frame::NegMsg { msg: Vec::new() });
                }
                topo::sync::session::windowing::SyncNegPhase::ObjectsRange { window } => {
                    break window;
                }
            }
        };
        assert!(
            matches!(
                second_window.kind,
                SyncWindowKind::Today
                    | SyncWindowKind::Yesterday
                    | SyncWindowKind::ThisWeek
                    | SyncWindowKind::LastWeek
            ),
            "after explicit last-week policy reject, initiator should only request day/week windows, got {:?}",
            second_window.kind
        );

        cancel.cancel();
        peer_1.force_close();
        peer_2.force_close();
        handler_task_2.abort();
        let _ = handler_task_2.await;
    })
    .await;
}
