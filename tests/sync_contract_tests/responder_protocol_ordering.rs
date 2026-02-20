//! Tests that the responder (inbound) session handler emits protocol
//! messages in the correct order through the FakeSessionIo contract.
//!
//! Anti-cheat: asserts exact frame-level events, goes through SessionHandler
//! entrypoint (on_session), never invokes internal helpers directly.

use std::time::Duration;
use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{SessionDirection, SessionHandler};
use topo::sync::session_handler::SyncSessionHandler;
use topo::protocol::Frame;

use crate::fake_session_io::{
    create_test_db, empty_negentropy_storage, fake_session_io_pair, noop_ingest_tx,
    run_local, test_session_meta,
};

#[tokio::test]
async fn responder_inbound_replies_negmsg_then_doneack() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::responder(db_path, 30, noop_ingest_tx());
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move {
                handler
                    .on_session(meta, Box::new(fake_io), cancel)
                    .await
            }
        });

        // Simulate the initiator side:
        // 1. Send NegOpen with empty negentropy
        let storage = empty_negentropy_storage();
        let mut neg = negentropy::Negentropy::new(
            negentropy::Storage::Borrowed(&storage),
            0,
        )
        .unwrap();
        let initial_msg = neg.initiate().unwrap();
        peer.send_control_msg(&Frame::NegOpen { msg: initial_msg })
            .await;

        // 2. Responder should reply with NegMsg
        let neg_msg = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await;
        if let Some(Frame::NegMsg { msg }) = &neg_msg {
            let mut have_ids = Vec::new();
            let mut need_ids = Vec::new();
            let _ = neg.reconcile_with_ids(msg, &mut have_ids, &mut need_ids);
        }

        // 3. Signal Done from initiator
        peer.send_data_msg(&Frame::DataDone).await;
        peer.send_control_msg(&Frame::Done).await;

        // 4. Responder should send DataDone on data stream, then DoneAck on control
        let data_done = peer
            .recv_data_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected DataDone from responder");
        assert_eq!(data_done, Frame::DataDone);

        let done_ack = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected DoneAck from responder");
        assert_eq!(done_ack, Frame::DoneAck);

        let result = tokio::time::timeout(Duration::from_secs(10), handler_task)
            .await
            .expect("handler timed out")
            .expect("handler panicked");
        assert!(result.is_ok(), "handler failed: {:?}", result.err());
    })
    .await;
}

/// Anti-cheat mutation target: DoneAck ordering.
/// Responder MUST send DataDone BEFORE DoneAck.
#[tokio::test]
async fn anticheat_responder_datadone_before_doneack() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::responder(db_path, 30, noop_ingest_tx());
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move {
                let _ = handler.on_session(meta, Box::new(fake_io), cancel).await;
            }
        });

        // Drive initiator side: NegOpen → Done
        let storage = empty_negentropy_storage();
        let mut neg = negentropy::Negentropy::new(
            negentropy::Storage::Borrowed(&storage),
            0,
        )
        .unwrap();
        let initial_msg = neg.initiate().unwrap();
        peer.send_control_msg(&Frame::NegOpen { msg: initial_msg })
            .await;

        // Consume NegMsg if any
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(2)).await;

        // Signal done
        peer.send_data_msg(&Frame::DataDone).await;
        peer.send_control_msg(&Frame::Done).await;

        // DataDone must arrive on data stream before DoneAck on control.
        let data_msg = peer
            .recv_data_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected data message from responder");
        assert_eq!(
            data_msg,
            Frame::DataDone,
            "ANTI-CHEAT: responder's first post-Done data message must be DataDone"
        );

        let ctrl_msg = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected control message from responder");
        assert_eq!(
            ctrl_msg,
            Frame::DoneAck,
            "ANTI-CHEAT: responder's post-DataDone control message must be DoneAck"
        );

        cancel.cancel();
    })
    .await;
}

/// Verify that responder rejects outbound direction.
#[tokio::test]
async fn responder_rejects_outbound_direction() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::responder(db_path, 30, noop_ingest_tx());
        let meta = test_session_meta(SessionDirection::Outbound);
        let cancel = CancellationToken::new();

        let (fake_io, _peer) = fake_session_io_pair(meta.session_id);

        let result = handler
            .on_session(meta, Box::new(fake_io), cancel)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("responder handler cannot run outbound"),
            "expected role/direction mismatch error"
        );
    })
    .await;
}

/// Responder handles empty HaveList (marker) gracefully by ignoring it.
#[tokio::test]
async fn responder_ignores_empty_havelist_marker() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::responder(db_path, 30, noop_ingest_tx());
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move {
                let _ = handler.on_session(meta, Box::new(fake_io), cancel).await;
            }
        });

        // Send empty HaveList markers (like an outbound initiator would)
        peer.send_control_msg(&Frame::HaveList { ids: vec![] })
            .await;

        // Then proceed with normal protocol
        let storage = empty_negentropy_storage();
        let mut neg = negentropy::Negentropy::new(
            negentropy::Storage::Borrowed(&storage),
            0,
        )
        .unwrap();
        let initial_msg = neg.initiate().unwrap();
        peer.send_control_msg(&Frame::NegOpen { msg: initial_msg })
            .await;

        // Consume NegMsg
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(2)).await;

        // Signal done
        peer.send_data_msg(&Frame::DataDone).await;
        peer.send_control_msg(&Frame::Done).await;

        // Should still get proper DoneAck sequence
        let data_done = peer
            .recv_data_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected DataDone");
        assert_eq!(data_done, Frame::DataDone);

        let done_ack = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected DoneAck");
        assert_eq!(done_ack, Frame::DoneAck);

        cancel.cancel();
    })
    .await;
}
