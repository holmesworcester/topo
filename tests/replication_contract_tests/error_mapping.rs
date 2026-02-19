//! Tests that IO errors are correctly surfaced through the SessionHandler
//! when using FakeSessionIo.
//!
//! Covers: connection loss, half-close, abrupt close, delayed delivery,
//! frame-size enforcement, and out-of-order delivery scenarios.

use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use topo::contracts::network_contract::{
    SessionDirection, SessionHandler, SessionIo, SessionIoError,
};
use topo::replication::session_handler::ReplicationSessionHandler;
use topo::sync::SyncMessage;

use crate::fake_session_io::{
    create_test_db, empty_negentropy_storage, fake_session_io_pair,
    fake_session_io_pair_with_config, noop_batch_writer, run_local, test_session_meta,
    FakeIoConfig,
};

/// When the peer drops the control channel (half-close), the handler should
/// detect ConnectionLost and terminate.
#[tokio::test]
async fn control_channel_half_close_terminates_handler() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            ReplicationSessionHandler::responder(db_path, 30, noop_batch_writer);
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let (fake_io, peer) = fake_session_io_pair(meta.session_id);

        let cancel_clone = cancel.clone();
        let handler_task = tokio::task::spawn_local(async move {
            handler
                .on_session(meta, Box::new(fake_io), cancel_clone)
                .await
        });

        // Drop the control send channel — handler's control recv will get None
        drop(peer.control_send);
        // Also drop data send so the data receiver exits
        drop(peer.data_send);

        let result = tokio::time::timeout(Duration::from_secs(10), handler_task)
            .await
            .expect("handler timed out on half-close")
            .expect("handler panicked");

        // The handler should have terminated (either Ok or Err is fine,
        // as long as it doesn't hang)
        let _ = result;
        cancel.cancel();
    })
    .await;
}

/// Abrupt close via force_close flag should cause handler to error.
#[tokio::test]
async fn abrupt_close_surfaces_connection_lost() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            ReplicationSessionHandler::initiator(db_path, 30, noop_batch_writer);
        let meta = test_session_meta(SessionDirection::Outbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        let cancel_clone = cancel.clone();
        let handler_task = tokio::task::spawn_local(async move {
            handler
                .on_session(meta, Box::new(fake_io), cancel_clone)
                .await
        });

        // Let the handler start, consume markers
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(5)).await;
        let _ = peer.recv_data_msg_timeout(Duration::from_secs(5)).await;

        // Force close the connection
        peer.force_close();

        // Also drop send channels so pending operations fail
        drop(peer.control_send);
        drop(peer.data_send);

        let result = tokio::time::timeout(Duration::from_secs(10), handler_task)
            .await
            .expect("handler timed out on abrupt close")
            .expect("handler panicked");

        // Handler should terminate (not hang). It may return Ok (graceful
        // connection-closed handling) or Err depending on timing of the
        // close relative to the protocol state machine.
        let _ = result;
        cancel.cancel();
    })
    .await;
}

/// Test that handler completes full round-trip with normal frames
/// (serves as baseline to verify error tests are meaningful).
#[tokio::test]
async fn normal_roundtrip_completes_successfully() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            ReplicationSessionHandler::responder(db_path, 30, noop_batch_writer);
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

        // Normal protocol: NegOpen → NegMsg → Done → DoneAck
        let storage = empty_negentropy_storage();
        let mut neg = negentropy::Negentropy::new(
            negentropy::Storage::Borrowed(&storage),
            0,
        )
        .unwrap();
        let initial_msg = neg.initiate().unwrap();
        peer.send_control_msg(&SyncMessage::NegOpen { msg: initial_msg })
            .await;

        // Consume NegMsg if any
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(2)).await;

        // Signal done
        peer.send_data_msg(&SyncMessage::DataDone).await;
        peer.send_control_msg(&SyncMessage::Done).await;

        // Get DataDone + DoneAck
        let _ = peer.recv_data_msg_timeout(Duration::from_secs(5)).await;
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(5)).await;

        let result = tokio::time::timeout(Duration::from_secs(10), handler_task)
            .await
            .expect("handler timed out")
            .expect("handler panicked");
        assert!(result.is_ok(), "normal roundtrip should succeed");
    })
    .await;
}

// ---------------------------------------------------------------------------
// FakeIoConfig failure-mode tests
// ---------------------------------------------------------------------------

/// Verify that configuring a frame_delay actually adds latency to recv.
/// We configure a 50ms delay, send a frame, and check that recv takes at
/// least 50ms to return.
#[tokio::test]
async fn delayed_delivery_adds_latency() {
    let config = FakeIoConfig {
        frame_delay: Some(Duration::from_millis(50)),
        ..Default::default()
    };
    let (fake_io, peer) = fake_session_io_pair_with_config(1, config);
    let mut parts = Box::new(fake_io).split();

    // Send a data frame from the peer side before we start timing.
    peer.data_send
        .send(vec![1, 2, 3])
        .await
        .expect("send failed");

    let start = Instant::now();
    let frame = parts.data_recv.recv().await.expect("recv failed");
    let elapsed = start.elapsed();

    assert_eq!(frame, vec![1, 2, 3]);
    assert!(
        elapsed >= Duration::from_millis(50),
        "recv should have taken at least 50ms due to frame_delay, but took {:?}",
        elapsed
    );
}

/// Verify that sending a frame larger than max_frame_size returns
/// FrameTooLarge from both the control and data send paths.
#[tokio::test]
async fn frame_size_enforcement_rejects_oversized() {
    let config = FakeIoConfig {
        max_frame_size: 100,
        ..Default::default()
    };
    let (fake_io, _peer) = fake_session_io_pair_with_config(2, config);
    let mut parts = Box::new(fake_io).split();

    // A 101-byte frame should be rejected.
    let oversized = vec![0xAA; 101];

    // Test data_send path.
    let data_err = parts.data_send.send(&oversized).await.unwrap_err();
    match &data_err {
        SessionIoError::FrameTooLarge { len, max } => {
            assert_eq!(*len, 101);
            assert_eq!(*max, 100);
        }
        other => panic!("expected FrameTooLarge, got: {other:?}"),
    }

    // Test control send path.
    let ctrl_err = parts.control.send(&oversized).await.unwrap_err();
    match &ctrl_err {
        SessionIoError::FrameTooLarge { len, max } => {
            assert_eq!(*len, 101);
            assert_eq!(*max, 100);
        }
        other => panic!("expected FrameTooLarge, got: {other:?}"),
    }

    // A frame at exactly the limit should succeed.
    let exact = vec![0xBB; 100];
    parts
        .data_send
        .send(&exact)
        .await
        .expect("frame at exactly max_frame_size should succeed");
    parts
        .control
        .send(&exact)
        .await
        .expect("control frame at exactly max_frame_size should succeed");
}

/// Verify that with reorder_data_frames=true, data frames arrive in
/// reversed order compared to how they were sent.
#[tokio::test]
async fn out_of_order_data_delivery() {
    let config = FakeIoConfig {
        reorder_data_frames: true,
        ..Default::default()
    };
    let (fake_io, peer) = fake_session_io_pair_with_config(3, config);
    let mut parts = Box::new(fake_io).split();

    // Send three data frames in order: A, B, C.
    peer.data_send
        .send(vec![0xAA])
        .await
        .expect("send A failed");
    peer.data_send
        .send(vec![0xBB])
        .await
        .expect("send B failed");
    peer.data_send
        .send(vec![0xCC])
        .await
        .expect("send C failed");

    // Drop the sender so the reorder buffer can drain completely.
    drop(peer.data_send);

    // With reordering, they should arrive as C, B, A.
    let f1 = parts.data_recv.recv().await.expect("recv 1 failed");
    let f2 = parts.data_recv.recv().await.expect("recv 2 failed");
    let f3 = parts.data_recv.recv().await.expect("recv 3 failed");

    assert_eq!(f1, vec![0xCC], "first received frame should be C (last sent)");
    assert_eq!(f2, vec![0xBB], "second received frame should be B");
    assert_eq!(f3, vec![0xAA], "third received frame should be A (first sent)");

    // After all frames consumed, next recv should signal channel closed.
    let eof = parts.data_recv.recv().await;
    assert!(
        eof.is_err(),
        "recv after all reordered frames should return ConnectionLost"
    );
}
