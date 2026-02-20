//! Tests that the initiator (outbound) session handler emits protocol
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
    create_test_db, empty_negentropy_storage, fake_session_io_pair, noop_batch_writer,
    run_local, test_session_meta, FakePeerSide,
};

/// Drive the responder side of an empty-DB sync from the test harness.
async fn drive_empty_responder(peer: &mut FakePeerSide) {
    // 1. Initiator sends stream materialization markers (outbound only).
    let ctrl_marker = peer
        .recv_control_msg_timeout(Duration::from_secs(5))
        .await
        .expect("expected control marker");
    assert_eq!(
        ctrl_marker,
        Frame::HaveList { ids: vec![] },
        "first control message should be empty HaveList marker"
    );

    let data_marker = peer
        .recv_data_msg_timeout(Duration::from_secs(5))
        .await
        .expect("expected data marker");
    assert_eq!(
        data_marker,
        Frame::HaveList { ids: vec![] },
        "first data message should be empty HaveList marker"
    );

    // 2. Initiator sends NegOpen
    let neg_open = peer
        .recv_control_msg_timeout(Duration::from_secs(5))
        .await
        .expect("expected NegOpen");
    assert!(
        matches!(neg_open, Frame::NegOpen { .. }),
        "expected NegOpen, got {:?}",
        neg_open
    );

    // 3. Respond with NegMsg to complete reconciliation.
    if let Frame::NegOpen { msg } = neg_open {
        let storage = empty_negentropy_storage();
        let mut neg = negentropy::Negentropy::new(
            negentropy::Storage::Borrowed(&storage),
            0,
        )
        .unwrap();
        let response = neg.reconcile(&msg).unwrap();
        peer.send_control_msg(&Frame::NegMsg { msg: response })
            .await;
    }

    // 4. Initiator should send DataDone on data stream, then Done on control.
    let data_done = peer
        .recv_data_msg_timeout(Duration::from_secs(5))
        .await
        .expect("expected DataDone");
    assert_eq!(data_done, Frame::DataDone, "expected DataDone");

    let done = peer
        .recv_control_msg_timeout(Duration::from_secs(5))
        .await
        .expect("expected Done");
    assert_eq!(done, Frame::Done, "expected Done");

    // 5. Send DataDone + DoneAck back to let initiator complete.
    peer.send_data_msg(&Frame::DataDone).await;
    peer.send_control_msg(&Frame::DoneAck).await;
}

#[tokio::test]
async fn initiator_outbound_sends_markers_then_negopen_then_done_sequence() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::initiator(db_path, 30, noop_batch_writer);
        let meta = test_session_meta(SessionDirection::Outbound);
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

        drive_empty_responder(&mut peer).await;

        let result = tokio::time::timeout(Duration::from_secs(10), handler_task)
            .await
            .expect("handler timed out")
            .expect("handler panicked");
        assert!(result.is_ok(), "handler failed: {:?}", result.err());
    })
    .await;
}

/// Anti-cheat mutation target: markers must be sent before NegOpen.
/// If the marker send code is disabled, the first control message from the
/// handler would be NegOpen instead of an empty HaveList.
#[tokio::test]
async fn anticheat_markers_precede_negopen() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::initiator(db_path, 30, noop_batch_writer);
        let meta = test_session_meta(SessionDirection::Outbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move {
                let _ = handler.on_session(meta, Box::new(fake_io), cancel).await;
            }
        });

        // The very first control frame MUST be the empty HaveList marker.
        let first = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected first control message");

        assert_eq!(
            first,
            Frame::HaveList { ids: vec![] },
            "ANTI-CHEAT: first control message must be marker HaveList, not {:?}. \
             If this fails, the stream materialization marker code was disabled.",
            first
        );

        cancel.cancel();
    })
    .await;
}

/// Anti-cheat mutation target: Done must be preceded by DataDone on data stream.
#[tokio::test]
async fn anticheat_datadone_before_done() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::initiator(db_path, 30, noop_batch_writer);
        let meta = test_session_meta(SessionDirection::Outbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move {
                let _ = handler.on_session(meta, Box::new(fake_io), cancel).await;
            }
        });

        // Consume markers
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(5)).await;
        let _ = peer.recv_data_msg_timeout(Duration::from_secs(5)).await;

        // Consume NegOpen and respond
        let neg_open = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .unwrap();
        if let Frame::NegOpen { msg } = neg_open {
            let storage = empty_negentropy_storage();
            let mut neg = negentropy::Negentropy::new(
                negentropy::Storage::Borrowed(&storage),
                0,
            )
            .unwrap();
            let response = neg.reconcile(&msg).unwrap();
            peer.send_control_msg(&Frame::NegMsg { msg: response })
                .await;
        }

        // DataDone on data stream must come first
        let data_done = peer
            .recv_data_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected DataDone on data stream");
        assert_eq!(
            data_done,
            Frame::DataDone,
            "ANTI-CHEAT: DataDone must appear on data stream before Done on control"
        );

        // Then Done on control stream
        let done = peer
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected Done on control stream");
        assert_eq!(
            done,
            Frame::Done,
            "ANTI-CHEAT: Done must follow DataDone"
        );

        // Send completion
        peer.send_data_msg(&Frame::DataDone).await;
        peer.send_control_msg(&Frame::DoneAck).await;
        cancel.cancel();
    })
    .await;
}

/// Verify that initiator rejects inbound direction.
#[tokio::test]
async fn initiator_rejects_inbound_direction() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::initiator(db_path, 30, noop_batch_writer);
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let (fake_io, _peer) = fake_session_io_pair(meta.session_id);

        let result = handler
            .on_session(meta, Box::new(fake_io), cancel)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("initiator handler cannot run inbound"),
            "expected role/direction mismatch error"
        );
    })
    .await;
}
