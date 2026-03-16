//! Tests that the initiator keeps one long-lived sync session open while
//! repeating discovery rounds on it.

use std::time::Duration;
use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{SessionDirection, SessionHandler};
use topo::protocol::Frame;
use topo::sync::session::windowing::decode_initial_neg_open;
use topo::sync::session_handler::SyncSessionHandler;

use crate::fake_session_io::{
    create_test_db, empty_negentropy_storage, fake_session_io_pair, noop_ingest_tx, run_local,
    test_session_meta,
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
async fn initiator_outbound_sends_markers_then_negopen_then_next_round() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncSessionHandler::outbound(
            db_path,
            30,
            std::sync::Arc::new(topo::sync::CoordinationManager::new()).register_peer(),
            noop_ingest_tx(),
        );
        let meta = test_session_meta(SessionDirection::Outbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move { handler.on_session(meta, Box::new(fake_io), cancel).await }
        });

        let ctrl_marker = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected control marker");
        assert_eq!(ctrl_marker, Frame::HaveList { ids: vec![] });

        let data_marker = peer
            .recv_data_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected data marker");
        assert_eq!(data_marker, Frame::HaveList { ids: vec![] });

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
            "expected no per-round DataDone marker, got {:?}",
            unexpected
        );

        // The same session should later start another discovery round.
        let mut saw_second_round = false;
        for _ in 0..6 {
            let frame = peer
                .recv_control_msg_timeout(Duration::from_secs(5))
                .await
                .expect("expected control frame");
            match frame {
                Frame::RequestCredit { .. } => {}
                neg_open_2 @ Frame::NegOpen { .. } => {
                    saw_second_round = true;
                    peer.send_control_msg(&Frame::NegMsg {
                        msg: empty_negentropy_response(neg_open_2),
                    })
                    .await;
                    break;
                }
                other => panic!("unexpected control frame after round 1: {:?}", other),
            }
        }
        assert!(
            saw_second_round,
            "expected a second NegOpen on the same session"
        );

        cancel.cancel();
        peer.force_close();
        handler_task.abort();
        let _ = handler_task.await;
    })
    .await;
}

#[tokio::test]
async fn anticheat_markers_precede_negopen() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncSessionHandler::outbound(
            db_path,
            30,
            std::sync::Arc::new(topo::sync::CoordinationManager::new()).register_peer(),
            noop_ingest_tx(),
        );
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
        assert_eq!(
            first,
            Frame::HaveList { ids: vec![] },
            "ANTI-CHEAT: first control message must be the stream-open marker"
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
        let handler = SyncSessionHandler::outbound(
            db_path,
            30,
            std::sync::Arc::new(topo::sync::CoordinationManager::new()).register_peer(),
            noop_ingest_tx(),
        );
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
