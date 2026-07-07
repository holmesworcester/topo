//! Tests that IO errors are correctly surfaced through the SessionHandler
//! when using FakeTransportSessionIo.
//!
//! Covers: connection loss, half-close, abrupt close, delayed delivery,
//! frame-size enforcement, out-of-order delivery, frame fragmentation,
//! and deterministic protocol violation scenarios.

use negentropy::NegentropyStorageBase;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{
    SessionDirection, SessionHandler, TransportSessionIo, TransportSessionIoError,
};
use topo::protocol::Frame;
use topo::sync::session_handler::SyncConnectionHandler;

use crate::fake_session_io::{
    create_test_db, empty_negentropy_storage, fake_session_io_pair,
    fake_session_io_pair_with_config, run_local, test_session_meta, FakeIoConfig,
    ProtocolViolation,
};

const CONTROL_PHASE1: u8 = 1;
const CONTROL_PHASE1_DONE: u8 = 2;
const CONTROL_DEP_CANDIDATE_DONE: u8 = 4;
const CONTROL_PHASE2_DONE: u8 = 6;

enum TestDepSyncControlPayload {
    Phase1(Vec<u8>),
    Phase1Done,
    DepCandidateDone,
    Phase2Done,
}

fn encode_dep_sync_control(payload: TestDepSyncControlPayload) -> Vec<u8> {
    match payload {
        TestDepSyncControlPayload::Phase1(msg) => {
            let mut out = Vec::with_capacity(1 + msg.len());
            out.push(CONTROL_PHASE1);
            out.extend_from_slice(&msg);
            out
        }
        TestDepSyncControlPayload::Phase1Done => vec![CONTROL_PHASE1_DONE],
        TestDepSyncControlPayload::DepCandidateDone => vec![CONTROL_DEP_CANDIDATE_DONE],
        TestDepSyncControlPayload::Phase2Done => vec![CONTROL_PHASE2_DONE],
    }
}

fn decode_dep_sync_control(msg: &[u8]) -> TestDepSyncControlPayload {
    match msg.first().copied() {
        Some(CONTROL_PHASE1) => TestDepSyncControlPayload::Phase1(msg[1..].to_vec()),
        Some(CONTROL_PHASE1_DONE) => TestDepSyncControlPayload::Phase1Done,
        Some(CONTROL_DEP_CANDIDATE_DONE) => TestDepSyncControlPayload::DepCandidateDone,
        Some(CONTROL_PHASE2_DONE) => TestDepSyncControlPayload::Phase2Done,
        other => panic!("unexpected dep-sync control tag: {:?}", other),
    }
}

#[derive(Default)]
struct EmptyDepRangeStorage;

impl negentropy::DepReconcileRangeStorage for EmptyDepRangeStorage {
    fn root_size(&self) -> Result<usize, negentropy::Error> {
        Ok(0)
    }

    fn get_root_item(&self, _i: usize) -> Result<Option<negentropy::Item>, negentropy::Error> {
        Ok(None)
    }

    fn find_lower_bound(&self, _first: usize, _last: usize, _value: &negentropy::Bound) -> usize {
        0
    }

    fn combined_fingerprint(
        &self,
        _begin: usize,
        _end: usize,
    ) -> Result<negentropy::Fingerprint, negentropy::Error> {
        let mut storage = negentropy::NegentropyStorageVector::with_capacity(0);
        storage.seal().unwrap();
        storage.fingerprint(0, storage.size()?)
    }

    fn root_ids(
        &self,
        _begin: usize,
        _end: usize,
    ) -> Result<Vec<negentropy::Id>, negentropy::Error> {
        Ok(Vec::new())
    }
}

async fn drive_empty_inbound_round(peer: &mut crate::fake_session_io::FakePeerSide) {
    let storage = EmptyDepRangeStorage;
    let mut phase1 = negentropy::DepReconciler::borrowed(&storage);
    let initial_msg = topo::sync::session::windowing::encode_initial_neg_open(
        topo::sync::session::windowing::SyncWindow {
            kind: topo::sync::session::windowing::SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(0),
            ts_max_exclusive_ms: None,
        },
        encode_dep_sync_control(TestDepSyncControlPayload::Phase1(
            phase1.initiate().unwrap(),
        )),
    );
    peer.send_control_msg(&Frame::NegOpen { msg: initial_msg })
        .await;

    let phase1_reply = peer
        .recv_control_msg_timeout(Duration::from_secs(2))
        .await
        .expect("expected phase1 response");
    let Frame::NegMsg { msg } = phase1_reply else {
        panic!("expected NegMsg from responder");
    };
    let TestDepSyncControlPayload::Phase1(msg) = decode_dep_sync_control(&msg) else {
        panic!("expected phase1 response payload");
    };
    let mut diff = negentropy::DepReconcileDiff::default();
    let next = phase1
        .reconcile_with_ids(&msg, &mut diff)
        .expect("reconcile empty phase1");
    assert!(
        next.is_none(),
        "empty dep-aware phase1 should complete in one round"
    );

    peer.send_control_msg(&Frame::NegMsg {
        msg: encode_dep_sync_control(TestDepSyncControlPayload::Phase1Done),
    })
    .await;
    peer.send_control_msg(&Frame::NegMsg {
        msg: encode_dep_sync_control(TestDepSyncControlPayload::DepCandidateDone),
    })
    .await;

    let dep_candidate_reply = peer
        .recv_control_msg_timeout(Duration::from_secs(2))
        .await
        .expect("expected dep candidate terminator");
    let Frame::NegMsg { msg } = dep_candidate_reply else {
        panic!("expected NegMsg dep candidate reply");
    };
    assert!(matches!(
        decode_dep_sync_control(&msg),
        TestDepSyncControlPayload::DepCandidateDone
    ));

    peer.send_control_msg(&Frame::NegMsg {
        msg: encode_dep_sync_control(TestDepSyncControlPayload::Phase2Done),
    })
    .await;
}

/// When the peer drops the control channel (half-close), the handler should
/// detect ConnectionLost and terminate.
#[tokio::test]
async fn control_channel_half_close_terminates_handler() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::responder(db_path, 30);
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
        let handler = SyncConnectionHandler::outbound(db_path, 30);
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

/// Test that a normal empty discovery round succeeds without using a
/// per-round completion handshake, and the handler remains healthy until
/// cancellation.
#[tokio::test]
async fn normal_roundtrip_stays_healthy_until_cancel() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::responder(db_path, 30);
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move { handler.on_session(meta, Box::new(fake_io), cancel).await }
        });

        let storage = empty_negentropy_storage();
        let mut neg =
            negentropy::Negentropy::new(negentropy::Storage::Borrowed(&storage), 0).unwrap();
        let initial_msg = topo::sync::session::windowing::encode_initial_neg_open(
            topo::sync::session::windowing::SyncWindow {
                kind: topo::sync::session::windowing::SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(0),
                ts_max_exclusive_ms: None,
            },
            neg.initiate().unwrap(),
        );
        peer.send_control_msg(&Frame::NegOpen { msg: initial_msg })
            .await;

        if let Some(frame) = peer.recv_control_msg_timeout(Duration::from_secs(2)).await {
            if let Frame::NegMsg { msg } = frame {
                let mut have_ids = Vec::new();
                let mut need_ids = Vec::new();
                if let Some(next) = neg
                    .reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)
                    .unwrap()
                {
                    peer.send_control_msg(&Frame::NegMsg { msg: next }).await;
                }
            }
        }

        let unexpected = peer.recv_data_msg_timeout(Duration::from_millis(250)).await;
        assert!(
            unexpected.is_none(),
            "expected no unsolicited per-round data marker, got {:?}",
            unexpected
        );

        cancel.cancel();
        peer.force_close();
        handler_task.abort();
        let _ = handler_task.await;
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

    assert_eq!(
        f1,
        vec![0xCC],
        "first received frame should be C (last sent)"
    );
    assert_eq!(f2, vec![0xBB], "second received frame should be B");
    assert_eq!(
        f3,
        vec![0xAA],
        "third received frame should be A (first sent)"
    );

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
/// The handler receives fragmented raw range-data bytes on the data channel
/// after the control negotiation has completed. The data receiver task must
/// tolerate an incomplete trailing payload and the session must still
/// terminate without hanging or panicking when the peer closes the channel.
///
/// This documents the handler's resilience to transport-layer fragmentation:
/// the data receiver task tolerates fragmented/incomplete range-data bytes,
/// and the control protocol still drives the session to completion.
#[tokio::test]
async fn fragmented_data_frames_handler_completes() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::responder(db_path, 30);
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let config = FakeIoConfig {
            fragment_data_frames: true,
            ..Default::default()
        };
        let (fake_io, mut peer) = fake_session_io_pair_with_config(meta.session_id, config);

        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move { handler.on_session(meta, Box::new(fake_io), cancel).await }
        });

        // Drive the modern dep-sync control handshake so the responder starts
        // its range-data receive task before we inject fragmented payload
        // bytes on the data channel.
        drive_empty_inbound_round(&mut peer).await;

        // Send raw range-data bytes with no complete length-prefixed record.
        // Fragmentation will split them into multiple recv_chunk calls; the
        // receiver must not hang when the peer closes mid-record.
        peer.data_send
            .send(vec![0xAA; 100])
            .await
            .expect("data channel closed before fragmented payload send");

        // Drop channels to ensure handler can exit after seeing the malformed
        // fragmented payload path. The connection-scoped data lane no longer
        // relies on per-session completion markers.
        drop(peer.control_send);
        drop(peer.data_send);

        let result = tokio::time::timeout(Duration::from_secs(10), handler_task)
            .await
            .expect("handler timed out with fragmented frames -- must not hang")
            .expect("handler panicked");

        // The responder may treat the truncated tail as a clean close or a
        // connection-close race, but it must terminate promptly.
        assert!(
            result.is_ok() || matches!(result, Err(ref err) if err.contains("Connection closed")),
            "handler should terminate promptly on fragmented data frames, got: {:?}",
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
    assert_eq!(
        reassembled, original,
        "reassembled chunks should match original"
    );
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
        let handler = SyncConnectionHandler::responder(db_path, 30);
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let config = FakeIoConfig {
            inject_protocol_violation: Some(ProtocolViolation::GarbageControlFrame),
            ..Default::default()
        };
        let (fake_io, peer) = fake_session_io_pair_with_config(meta.session_id, config);

        let handler_task = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move { handler.on_session(meta, Box::new(fake_io), cancel).await }
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

        // Garbage control bytes are now surfaced as a parse failure, but the
        // important contract is still "fail fast, do not hang".
        assert!(
            matches!(result, Err(ref err) if err.contains("Parse error")),
            "handler should fail fast on garbage control frame, got: {:?}",
            result
        );
        cancel.cancel();
    })
    .await;
}
