//! Tests that cancellation tokens correctly abort sessions via SessionHandler.
//!
//! Anti-cheat mutation target: if the cancellation `select!` is removed from
//! the session handler, these tests will hang or fail.

use std::time::Duration;
use tokio_util::sync::CancellationToken;

use topo::contracts::peering_contract::{SessionDirection, SessionHandler};
use topo::sync::session_handler::SyncSessionHandler;

use crate::fake_session_io::{
    create_test_db, fake_session_io_pair, noop_ingest_tx, run_local, test_session_meta,
};

/// Session cancelled BEFORE on_session starts should return error immediately.
#[tokio::test]
async fn pre_cancelled_session_returns_error() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncSessionHandler::outbound(
            db_path,
            30,
            std::sync::Arc::new(topo::sync::CoordinationManager::new()),
            noop_ingest_tx(),
        );
        let meta = test_session_meta(SessionDirection::Outbound);
        let cancel = CancellationToken::new();
        cancel.cancel(); // pre-cancel

        let (fake_io, _peer) = fake_session_io_pair(meta.session_id);

        let result = handler.on_session(meta, Box::new(fake_io), cancel).await;
        assert!(result.is_err(), "pre-cancelled session should fail");
        let err = result.unwrap_err();
        assert!(
            err.contains("cancelled"),
            "error should mention cancellation, got: {}",
            err
        );
    })
    .await;
}

/// Session cancelled during protocol should terminate within timeout.
/// Anti-cheat: if the cancellation watch `select!` is removed, this test
/// will time out because the handler will block waiting for NegMsg forever.
#[tokio::test]
async fn mid_session_cancellation_terminates_handler() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncSessionHandler::outbound(
            db_path,
            30,
            std::sync::Arc::new(topo::sync::CoordinationManager::new()),
            noop_ingest_tx(),
        );
        let meta = test_session_meta(SessionDirection::Outbound);
        let cancel = CancellationToken::new();

        let (fake_io, mut peer) = fake_session_io_pair(meta.session_id);

        let cancel_clone = cancel.clone();
        let handler_task = tokio::task::spawn_local(async move {
            handler
                .on_session(meta, Box::new(fake_io), cancel_clone)
                .await
        });

        // Consume the stream materialization markers so the handler proceeds
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(5)).await;
        let _ = peer.recv_data_msg_timeout(Duration::from_secs(5)).await;

        // Consume NegOpen
        let _ = peer.recv_control_msg_timeout(Duration::from_secs(5)).await;

        // Don't reply — instead cancel the token
        cancel.cancel();

        // Handler should exit quickly
        let result = tokio::time::timeout(Duration::from_secs(5), handler_task)
            .await
            .expect(
                "ANTI-CHEAT: handler did not terminate after cancellation — \
                 the cancellation select! may have been removed",
            )
            .expect("handler panicked");

        assert!(result.is_err(), "cancelled session should return error");
        assert!(
            result.unwrap_err().contains("cancelled"),
            "error should mention cancellation"
        );
    })
    .await;
}

/// Responder also respects cancellation.
#[tokio::test]
async fn responder_cancellation_terminates_handler() {
    run_local(async {
        let (db_path, _tmpdir) = create_test_db("test-tenant");
        let handler = SyncSessionHandler::responder(db_path, 30, noop_ingest_tx());
        let meta = test_session_meta(SessionDirection::Inbound);
        let cancel = CancellationToken::new();

        let (fake_io, _peer) = fake_session_io_pair(meta.session_id);

        let cancel_clone = cancel.clone();
        let handler_task = tokio::task::spawn_local(async move {
            handler
                .on_session(meta, Box::new(fake_io), cancel_clone)
                .await
        });

        // Cancel immediately — responder is waiting for first control message
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();

        let result = tokio::time::timeout(Duration::from_secs(5), handler_task)
            .await
            .expect("handler did not terminate after cancellation")
            .expect("handler panicked");

        assert!(
            result.is_err(),
            "cancelled responder session should return error"
        );
    })
    .await;
}
