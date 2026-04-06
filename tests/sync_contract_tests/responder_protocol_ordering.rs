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

async fn drive_empty_inbound_round(peer: &mut crate::fake_session_io::FakePeerSide) {
    let storage = empty_negentropy_storage();
    let mut neg = negentropy::Negentropy::new(negentropy::Storage::Borrowed(&storage), 0).unwrap();
    // Use a LastDay window header so this works even when LOW_MEM_IOS=1 leaks
    // from a concurrent test (low-mem responders reject Full/LastTwelveWeeks).
    let initial_msg = encode_initial_neg_open(
        SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(0),
            ts_max_exclusive_ms: None,
        },
        neg.initiate().unwrap(),
    );
    peer.send_control_msg(&Frame::NegOpen { msg: initial_msg })
        .await;

    loop {
        let Some(frame) = peer
            .recv_control_msg_timeout(Duration::from_millis(300))
            .await
        else {
            break;
        };
        let Frame::NegMsg { msg } = frame else {
            panic!("expected NegMsg from responder");
        };
        let mut have_ids = Vec::new();
        let mut need_ids = Vec::new();
        if let Some(next) = neg
            .reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)
            .unwrap()
        {
            peer.send_control_msg(&Frame::NegMsg { msg: next }).await;
        }
        break;
    }
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
async fn responder_inbound_replies_negmsg_and_stays_open_for_next_round() {
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

        // A second round on the same session should also be answered.
        drive_empty_inbound_round(&mut peer).await;

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
