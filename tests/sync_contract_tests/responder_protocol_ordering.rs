//! Tests that the responder answers repeated discovery rounds on one
//! long-lived session without emitting per-round completion markers.

use std::time::Duration;
use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{SessionDirection, SessionHandler};
use topo::protocol::Frame;
use topo::sync::session_handler::SyncConnectionHandler;

use crate::fake_session_io::{
    create_test_db, empty_negentropy_storage, fake_session_io_pair, noop_ingest_tx, run_local,
    test_session_meta,
};

async fn drive_empty_inbound_round(peer: &mut crate::fake_session_io::FakePeerSide) {
    let storage = empty_negentropy_storage();
    let mut neg = negentropy::Negentropy::new(negentropy::Storage::Borrowed(&storage), 0).unwrap();
    peer.send_control_msg(&Frame::NegOpen {
        msg: neg.initiate().unwrap(),
    })
    .await;

    loop {
        let Some(frame) = peer
            .recv_control_msg_timeout(Duration::from_millis(300))
            .await
        else {
            break;
        };
        if matches!(frame, Frame::ResponseCredit { .. }) {
            continue;
        }
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
async fn responder_inbound_replies_negmsg_and_stays_open_for_next_round() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::responder(
            db_path,
            30,
            std::sync::Arc::new(topo::sync::CoordinationManager::new()).register_peer(),
            noop_ingest_tx(),
        );
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
        let handler = SyncConnectionHandler::responder(
            db_path,
            30,
            std::sync::Arc::new(topo::sync::CoordinationManager::new()).register_peer(),
            noop_ingest_tx(),
        );
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

#[tokio::test]
async fn responder_ignores_empty_request_ids_marker() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncConnectionHandler::responder(
            db_path,
            30,
            std::sync::Arc::new(topo::sync::CoordinationManager::new()).register_peer(),
            noop_ingest_tx(),
        );
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move {
                let _ = handler.on_session(meta, Box::new(fake_io), cancel).await;
            }
        });

        peer.send_control_msg(&Frame::RequestIds { ids: vec![] })
            .await;

        drive_empty_inbound_round(&mut peer).await;

        cancel.cancel();
        peer.force_close();
    })
    .await;
}
