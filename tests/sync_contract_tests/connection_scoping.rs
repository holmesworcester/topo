use std::rc::Rc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{SessionDirection, SessionHandler};
use topo::db::{open_connection, wanted::WantedEvents};
use topo::protocol::Frame;
use topo::sync::session::windowing::decode_initial_neg_open;
use topo::sync::session_handler::SyncSessionHandler;

use crate::fake_session_io::{
    create_test_db, empty_negentropy_storage, fake_session_io_pair, noop_ingest_tx, run_local,
    test_session_meta, FakePeerSide,
};

async fn recv_outbound_markers_and_negopen(peer: &mut FakePeerSide) -> Frame {
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
async fn initiator_reuses_connection_scoped_credit_across_rounds() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let peer_hex = hex::encode([0xABu8; 32]);
        let mut requested_event = [0u8; 32];
        requested_event[0] = 7;

        let coordination =
            std::sync::Arc::new(topo::sync::CoordinationManager::new()).register_peer();
        let handler = Rc::new(SyncSessionHandler::outbound(
            db_path.clone(),
            30,
            coordination,
            noop_ingest_tx(),
        ));

        // Round 1: remote grants request credit, but there is nothing wanted yet.
        let meta1 = test_session_meta(SessionDirection::Outbound);
        let cancel1 = CancellationToken::new();
        let (fake_io1, mut peer1) = fake_session_io_pair(meta1.session_id);
        let handler1 = handler.clone();
        let round1 = tokio::task::spawn_local({
            let cancel = cancel1.clone();
            async move { handler1.on_session(meta1, Box::new(fake_io1), cancel).await }
        });

        let neg_open1 = recv_outbound_markers_and_negopen(&mut peer1).await;
        peer1
            .send_control_msg(&Frame::RequestCredit { credits: 1 })
            .await;
        peer1
            .send_control_msg(&Frame::NegMsg {
                msg: empty_negentropy_response(neg_open1),
            })
            .await;

        let data_done = peer1
            .recv_data_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected DataDone in round 1");
        assert_eq!(data_done, Frame::DataDone);
        let done = peer1
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected Done in round 1");
        assert_eq!(done, Frame::Done);
        peer1.send_data_msg(&Frame::DataDone).await;
        peer1.send_control_msg(&Frame::DoneAck).await;

        let result1 = tokio::time::timeout(Duration::from_secs(10), round1)
            .await
            .expect("round 1 timed out")
            .expect("round 1 panicked");
        assert!(result1.is_ok(), "round 1 failed: {:?}", result1.err());

        // After round 1, the sink now learns about a wanted event from the same peer.
        let conn = open_connection(&db_path).expect("open test db");
        let wanted = WantedEvents::new(&conn);
        assert_eq!(
            wanted
                .observe_many_for_peer(&peer_hex, &[requested_event])
                .expect("observe wanted"),
            1
        );
        drop(conn);

        // Round 2: without any new RequestCredit frame, the initiator should
        // immediately reuse the connection-scoped credit and emit HaveList.
        let meta2 = test_session_meta(SessionDirection::Outbound);
        let cancel2 = CancellationToken::new();
        let (fake_io2, mut peer2) = fake_session_io_pair(meta2.session_id);
        let handler2 = handler.clone();
        let round2 = tokio::task::spawn_local({
            let cancel = cancel2.clone();
            async move { handler2.on_session(meta2, Box::new(fake_io2), cancel).await }
        });

        let _neg_open2 = recv_outbound_markers_and_negopen(&mut peer2).await;
        let request = peer2
            .recv_control_msg_timeout(Duration::from_secs(5))
            .await
            .expect("expected connection-scoped HaveList request");
        match request {
            Frame::HaveList { ids } => assert_eq!(ids, vec![requested_event]),
            other => panic!("expected HaveList request, got {:?}", other),
        }

        cancel2.cancel();
        let result2 = tokio::time::timeout(Duration::from_secs(10), round2)
            .await
            .expect("round 2 timed out")
            .expect("round 2 panicked");
        assert!(
            result2.is_err(),
            "round 2 should exit via cancellation after the assertion"
        );
    })
    .await;
}
