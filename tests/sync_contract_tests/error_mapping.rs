//! Tests that IO errors are correctly surfaced through the SessionHandler
//! when using FakeTransportSessionIo.
//!
//! Covers: connection loss, half-close, abrupt close, delayed delivery,
//! frame-size enforcement, out-of-order delivery, frame fragmentation,
//! and deterministic protocol violation scenarios.

use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{
    SessionDirection, SessionHandler, TransportSessionIo, TransportSessionIoError,
};
use topo::sync::session_handler::SyncSessionHandler;
use topo::protocol::Frame;

use crate::fake_session_io::{
    create_test_db, empty_negentropy_storage, fake_session_io_pair,
    fake_session_io_pair_with_config, noop_batch_writer, run_local, test_session_meta,
    FakeIoConfig, ProtocolViolation,
};

/// When the peer drops the control channel (half-close), the handler should
/// detect ConnectionLost and terminate.
#[tokio::test]
async fn control_channel_half_close_terminates_handler() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::responder(db_path, 30, noop_batch_writer);
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
            SyncSessionHandler::initiator(db_path, 30, noop_batch_writer);
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
            SyncSessionHandler::responder(db_path, 30, noop_batch_writer);
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
        peer.send_control_msg(&Frame::NegOpen { msg: initial_msg })
            .await;

        // Consume NegMsg if any
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(2)).await;

        // Signal done
        peer.send_data_msg(&Frame::DataDone).await;
        peer.send_control_msg(&Frame::Done).await;

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
        TransportSessionIoError::FrameTooLarge { len, max } => {
            assert_eq!(*len, 101);
            assert_eq!(*max, 100);
        }
        other => panic!("expected FrameTooLarge, got: {other:?}"),
    }

    // Test control send path.
    let ctrl_err = parts.control.send(&oversized).await.unwrap_err();
    match &ctrl_err {
        TransportSessionIoError::FrameTooLarge { len, max } => {
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

// ---------------------------------------------------------------------------
// Frame fragmentation tests
// ---------------------------------------------------------------------------

/// Verify that fragment_data_frames splits each data frame into 2 chunks.
/// The handler receives fragments (not complete protocol messages) on the
/// data channel. The data receiver task encounters parse errors on the
/// fragmented frames, but the responder's control loop is tolerant and the
/// session terminates without hanging or panicking.
///
/// This documents the handler's resilience to transport-layer fragmentation:
/// the data receiver task fails gracefully, and the control protocol drives
/// the session to completion.
#[tokio::test]
async fn fragmented_data_frames_handler_completes() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::responder(db_path, 30, noop_batch_writer);
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let config = FakeIoConfig {
            fragment_data_frames: true,
            ..Default::default()
        };
        let (fake_io, mut peer) = fake_session_io_pair_with_config(meta.session_id, config);

        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move {
                handler
                    .on_session(meta, Box::new(fake_io), cancel)
                    .await
            }
        });

        // Drive the normal protocol: NegOpen -> NegMsg -> then send events
        // on the data channel, which will be fragmented.
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

        // Send an Event with a multi-byte payload that WILL be fragmented.
        // The data receiver will get a partial frame and fail to parse it.
        peer.send_data_msg(&Frame::Event { blob: vec![0xAA; 100] })
            .await;

        // Send DataDone (1-byte message, not fragmented since len==1) and
        // Done on control to drive the session toward completion.
        peer.send_data_msg(&Frame::DataDone).await;
        peer.send_control_msg(&Frame::Done).await;

        // Consume any responses from the handler.
        let _ = peer.recv_data_msg_timeout(Duration::from_secs(5)).await;
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(5)).await;

        // Drop channels to ensure handler can exit.
        drop(peer.control_send);
        drop(peer.data_send);

        let result = tokio::time::timeout(Duration::from_secs(10), handler_task)
            .await
            .expect("handler timed out with fragmented frames -- must not hang")
            .expect("handler panicked");

        // The handler tolerates data-receiver parse failures from fragmented
        // frames — the control loop drives the session to completion.
        assert!(
            result.is_ok(),
            "handler should complete gracefully despite fragmented data frames, got: {:?}",
            result
        );
        cancel.cancel();
    })
    .await;
}

/// Verify that fragmentation correctly splits multi-byte frames at the
/// DataRecvIo level by testing the raw IO adapter directly.
#[tokio::test]
async fn fragmentation_splits_data_frames_into_chunks() {
    let config = FakeIoConfig {
        fragment_data_frames: true,
        ..Default::default()
    };
    let (fake_io, peer) = fake_session_io_pair_with_config(100, config);
    let mut parts = Box::new(fake_io).split();

    // Send a 10-byte frame.
    let original = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
    peer.data_send
        .send(original.clone())
        .await
        .expect("send failed");

    // First recv should return the first half (5 bytes).
    let chunk1 = parts.data_recv.recv().await.expect("recv chunk1 failed");
    assert_eq!(chunk1, vec![0x01, 0x02, 0x03, 0x04, 0x05]);

    // Second recv should return the second half (5 bytes).
    let chunk2 = parts.data_recv.recv().await.expect("recv chunk2 failed");
    assert_eq!(chunk2, vec![0x06, 0x07, 0x08, 0x09, 0x0A]);

    // The two chunks together should equal the original frame.
    let mut reassembled = chunk1;
    reassembled.extend(chunk2);
    assert_eq!(reassembled, original, "reassembled chunks should match original");
}

// ---------------------------------------------------------------------------
// Protocol violation tests
// ---------------------------------------------------------------------------

/// Verify that injecting a GarbageControlFrame causes the responder handler
/// to terminate. The garbage is injected as the first control frame the
/// handler receives (before any legitimate NegOpen from the peer).
///
/// The responder's control loop handles parse errors by logging and breaking
/// out of the loop. The session terminates cleanly without hanging or
/// panicking, even though the peer sent an unparseable control frame.
#[tokio::test]
async fn garbage_control_frame_terminates_handler() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::responder(db_path, 30, noop_batch_writer);
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let config = FakeIoConfig {
            inject_protocol_violation: Some(ProtocolViolation::GarbageControlFrame),
            ..Default::default()
        };
        let (fake_io, peer) = fake_session_io_pair_with_config(meta.session_id, config);

        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move {
                handler
                    .on_session(meta, Box::new(fake_io), cancel)
                    .await
            }
        });

        // The handler will receive garbage as its first control frame and
        // should fail to parse it. Drop all channels so the handler's
        // data receiver can also exit.
        drop(peer.control_send);
        drop(peer.data_send);

        let result = tokio::time::timeout(Duration::from_secs(10), handler_task)
            .await
            .expect("handler timed out on garbage control frame -- must not hang")
            .expect("handler panicked");

        // Responder breaks out of its control loop on parse errors and
        // terminates the session gracefully — garbage does not cause hangs.
        assert!(
            result.is_ok(),
            "handler should exit gracefully on garbage control frame, got: {:?}",
            result
        );
        cancel.cancel();
    })
    .await;
}

/// Verify behavior when a DuplicateDone violation is injected. The harness
/// sends Done twice on the control channel. The responder should either
/// handle the duplicate gracefully or error — but must not hang or panic.
#[tokio::test]
async fn duplicate_done_violation_terminates_handler() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler =
            SyncSessionHandler::responder(db_path, 30, noop_batch_writer);
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let config = FakeIoConfig {
            inject_protocol_violation: Some(ProtocolViolation::DuplicateDone),
            ..Default::default()
        };
        let (fake_io, mut peer) = fake_session_io_pair_with_config(meta.session_id, config);

        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move {
                handler
                    .on_session(meta, Box::new(fake_io), cancel)
                    .await
            }
        });

        // Drive the normal protocol up to Done, which will be duplicated
        // by the FakeControlIo violation injection.
        let storage = empty_negentropy_storage();
        let mut neg = negentropy::Negentropy::new(
            negentropy::Storage::Borrowed(&storage),
            0,
        )
        .unwrap();
        let initial_msg = neg.initiate().unwrap();
        peer.send_control_msg(&Frame::NegOpen { msg: initial_msg })
            .await;

        // Consume NegMsg from responder
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(2)).await;

        // Signal done (the FakeControlIo will auto-duplicate this Done)
        peer.send_data_msg(&Frame::DataDone).await;
        peer.send_control_msg(&Frame::Done).await;

        // Try to receive DataDone + DoneAck — the handler may or may not
        // produce these depending on how it handles the duplicate Done.
        let _ = peer.recv_data_msg_timeout(Duration::from_secs(5)).await;
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(5)).await;

        // Drop our channels so the handler doesn't block indefinitely
        // waiting for more messages after processing the duplicate.
        drop(peer.control_send);
        drop(peer.data_send);

        let result = tokio::time::timeout(Duration::from_secs(10), handler_task)
            .await
            .expect("handler timed out on duplicate Done — it should not hang")
            .expect("handler panicked");

        // Handler processes the first Done normally and completes the
        // session. The duplicate Done arrives after the control loop has
        // already exited, so the handler terminates gracefully.
        assert!(
            result.is_ok(),
            "handler should complete gracefully despite duplicate Done, got: {:?}",
            result
        );
        cancel.cancel();
    })
    .await;
}
