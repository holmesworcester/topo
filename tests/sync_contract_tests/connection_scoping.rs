use std::time::Duration;

use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{SessionDirection, SessionHandler};
use topo::db::{open_connection, timeline::EventTimeline, wanted::WantedEvents};
use topo::protocol::Frame;
use topo::sync::session::windowing::decode_initial_neg_open;
use topo::sync::session_handler::SyncSessionHandler;

use crate::fake_session_io::{
    create_test_db, empty_negentropy_storage, fake_session_io_pair, noop_ingest_tx, run_local,
    test_session_meta, FakePeerSide,
};

async fn recv_outbound_negopen(peer: &mut FakePeerSide) -> Frame {
    peer.recv_control_msg_timeout(Duration::from_secs(5))
        .await
        .expect("expected NegOpen")
}

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
async fn initiator_reuses_connection_scoped_credit_across_repeated_rounds() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let peer_hex = hex::encode([0xABu8; 32]);
        let mut requested_event = [0u8; 32];
        requested_event[0] = 7;

        let handler = SyncSessionHandler::outbound(
            db_path.clone(),
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

        // First round: grant credit, but there is no wanted work yet.
        let neg_open1 = recv_outbound_negopen(&mut peer).await;
        peer.send_control_msg(&Frame::RequestCredit { credits: 1 })
            .await;
        peer.send_control_msg(&Frame::NegMsg {
            msg: empty_negentropy_response(neg_open1),
        })
        .await;

        let unexpected_data = peer.recv_data_msg_timeout(Duration::from_millis(250)).await;
        assert!(
            unexpected_data.is_none(),
            "no unsolicited per-round data marker should be emitted, got {:?}",
            unexpected_data
        );

        // Teach the sink about a wanted event from the same peer after round 1.
        let conn = open_connection(&db_path).expect("open test db");
        let wanted = WantedEvents::new(&conn);
        let timeline = EventTimeline::new(&conn);
        assert_eq!(
            wanted
                .observe_many_for_peer(
                    "test-tenant",
                    &peer_hex,
                    &[requested_event],
                    1_000,
                    &timeline
                )
                .expect("observe wanted"),
            1
        );
        drop(conn);

        // On the same long-lived session:
        // - existing request credit should be reused to emit HaveList
        // - a later discovery round should still start with another NegOpen
        let mut saw_request = false;
        let mut saw_second_round = false;
        for _ in 0..8 {
            let frame = peer
                .recv_control_msg_timeout(Duration::from_secs(5))
                .await
                .expect("expected control frame on long-lived session");
            match frame {
                Frame::RequestCredit { .. } => {}
                Frame::HaveList { ids } => {
                    assert_eq!(ids, vec![requested_event]);
                    saw_request = true;
                }
                neg_open @ Frame::NegOpen { .. } => {
                    saw_second_round = true;
                    peer.send_control_msg(&Frame::NegMsg {
                        msg: empty_negentropy_response(neg_open),
                    })
                    .await;
                }
                other => panic!("unexpected control frame: {:?}", other),
            }
            if saw_request && saw_second_round {
                break;
            }
        }

        assert!(saw_request, "expected HaveList to reuse connection credit");
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
