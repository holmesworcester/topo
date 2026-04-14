//! Tests that the responder answers repeated discovery rounds on one
//! long-lived session without emitting per-round completion markers.

use std::time::Duration;
use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{SessionDirection, SessionHandler};
use topo::protocol::Frame;
use topo::sync::session::windowing::{
    encode_initial_neg_open, encode_sync_window_kind, SyncWindow, SyncWindowKind,
};
use topo::sync::session_handler::SyncConnectionHandler;

use crate::fake_session_io::{
    create_test_db, empty_negentropy_storage, fake_session_io_pair, run_local, test_session_meta,
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

struct EnvGuard {
    prev_low_mem_ios: Option<String>,
}

impl EnvGuard {
    fn enable_low_mem_ios() -> Self {
        let prev_low_mem_ios = std::env::var("LOW_MEM_IOS").ok();
        std::env::set_var("LOW_MEM_IOS", "1");
        Self { prev_low_mem_ios }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev_low_mem_ios {
            Some(v) => std::env::set_var("LOW_MEM_IOS", v),
            None => std::env::remove_var("LOW_MEM_IOS"),
        }
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
        empty_fingerprint()
    }

    fn root_ids(
        &self,
        _begin: usize,
        _end: usize,
    ) -> Result<Vec<negentropy::Id>, negentropy::Error> {
        Ok(Vec::new())
    }
}

fn empty_fingerprint() -> Result<negentropy::Fingerprint, negentropy::Error> {
    use negentropy::NegentropyStorageBase;

    let mut storage = negentropy::NegentropyStorageVector::with_capacity(0);
    storage.seal().unwrap();
    storage.fingerprint(0, storage.size()?)
}

fn decode_control_payload(frame: Frame) -> TestDepSyncControlPayload {
    let Frame::NegMsg { msg } = frame else {
        panic!("expected NegMsg from responder");
    };
    decode_dep_sync_control(&msg)
}

async fn drive_empty_inbound_round(peer: &mut crate::fake_session_io::FakePeerSide) {
    let storage = EmptyDepRangeStorage;
    let mut phase1 = negentropy::DepReconciler::borrowed(&storage);
    // Use a LastDay window header so this works even when LOW_MEM_IOS=1 leaks
    // from a concurrent test (low-mem responders reject Old/LastTwelveWeeks).
    let initial_msg = encode_initial_neg_open(
        SyncWindow {
            kind: SyncWindowKind::LastDay,
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
    let TestDepSyncControlPayload::Phase1(msg) = decode_control_payload(phase1_reply) else {
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
    assert!(matches!(
        decode_control_payload(dep_candidate_reply),
        TestDepSyncControlPayload::DepCandidateDone
    ));

    peer.send_control_msg(&Frame::NegMsg {
        msg: encode_dep_sync_control(TestDepSyncControlPayload::Phase2Done),
    })
    .await;
}

#[tokio::test]
async fn lowmem_responder_rejects_ranges_beyond_last_week() {
    run_local(async {
        let _env = EnvGuard::enable_low_mem_ios();
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
        let initial_msg = encode_initial_neg_open(
            SyncWindow {
                kind: SyncWindowKind::LastTwelveWeeks,
                ts_min_inclusive_ms: Some(0),
                ts_max_exclusive_ms: Some(1_000_000),
            },
            neg.initiate().unwrap(),
        );
        peer.send_control_msg(&Frame::NegOpen { msg: initial_msg })
            .await;

        let reply = peer
            .recv_control_msg_timeout(Duration::from_secs(2))
            .await
            .expect("lowmem responder should emit an explicit rejection marker");
        assert_eq!(
            reply,
            Frame::RangePolicyReject {
                rejected_window_kind: encode_sync_window_kind(SyncWindowKind::LastTwelveWeeks),
                oldest_allowed_window_kind: encode_sync_window_kind(SyncWindowKind::LastWeek),
            }
        );

        let result = tokio::time::timeout(Duration::from_secs(5), handler_task)
            .await
            .expect("handler timed out on lowmem range rejection")
            .expect("handler panicked");
        assert!(
            result.is_ok(),
            "lowmem responder should end the rejected range session cleanly: {result:?}"
        );
        assert!(
            peer.recv_data_msg_timeout(Duration::from_millis(250))
                .await
                .is_none(),
            "rejected session should not send data"
        );
    })
    .await;
}

#[tokio::test]
async fn responder_inbound_replies_negmsg_and_finishes_one_round_cleanly() {
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

        drive_empty_inbound_round(&mut peer).await;

        let unexpected = peer.recv_data_msg_timeout(Duration::from_millis(250)).await;
        assert!(
            unexpected.is_none(),
            "expected no unsolicited data marker from responder, got {:?}",
            unexpected
        );

        let closed = peer
            .recv_control_msg_timeout(Duration::from_millis(250))
            .await;
        assert!(
            closed.is_none(),
            "expected no extra control frames after responder finished the round, got {:?}",
            closed
        );

        cancel.cancel();
        peer.force_close();
        handler_task.abort();
        let _ = handler_task.await;
    })
    .await;
}

#[tokio::test]
async fn responder_rejects_outbound_direction() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::responder(db_path, 30);
        let meta = test_session_meta(SessionDirection::Outbound);
        let cancel = CancellationToken::new();

        let (fake_io, _peer) = fake_session_io_pair(meta.session_id);

        let result = handler.on_session(meta, Box::new(fake_io), cancel).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("responder handler cannot run outbound sessions"),
            "expected role/direction mismatch error"
        );
    })
    .await;
}
