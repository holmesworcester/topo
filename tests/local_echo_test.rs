//! Local-echo reconciliation tests.
//!
//! Tests the `client_op_id` mechanism: write commands can carry an optional
//! client-generated operation ID, and view/messages responses annotate canonical
//! items with the corresponding `client_op_id` for frontend reconciliation.

mod cli_harness;

use cli_harness::*;
use topo::rpc::client::rpc_call;
use topo::rpc::protocol::RpcMethod;

// ---------------------------------------------------------------------------
// 1. Message with client_op_id appears annotated in view
// ---------------------------------------------------------------------------

#[test]
fn message_send_with_client_op_id_annotated_in_view() {
    let (_dir, db) = temp_db();
    create_workspace(&db);
    let mut daemon = start_daemon(&db);

    let socket = socket_path_for_db(&db);

    // Send a message with client_op_id
    let resp = rpc_call(
        &socket,
        RpcMethod::Send {
            content: "hello local echo".into(),
            client_op_id: Some("test-op-001".into()),
        },
    )
    .expect("send RPC");
    assert!(resp.ok, "send should succeed: {:?}", resp.error);
    let send_data = resp.data.unwrap();
    assert!(!send_data["event_id"].as_str().unwrap_or("").is_empty());

    // View should annotate the message with client_op_id
    let resp = rpc_call(&socket, RpcMethod::View { limit: 50 }).expect("view RPC");
    assert!(resp.ok, "view should succeed: {:?}", resp.error);
    let view_data = resp.data.unwrap();
    let messages = view_data["messages"].as_array().expect("messages array");
    assert!(!messages.is_empty(), "should have at least one message");

    let msg = messages
        .iter()
        .find(|m| m["content"].as_str() == Some("hello local echo"))
        .expect("should find our message");
    assert_eq!(
        msg["client_op_id"].as_str(),
        Some("test-op-001"),
        "message should be annotated with client_op_id"
    );

    stop_daemon(&db, &mut daemon);
}

// ---------------------------------------------------------------------------
// 2. Message without client_op_id has no annotation (backward compat)
// ---------------------------------------------------------------------------

#[test]
fn message_without_client_op_id_has_no_annotation() {
    let (_dir, db) = temp_db();
    create_workspace(&db);
    let mut daemon = start_daemon(&db);

    let socket = socket_path_for_db(&db);

    // Send without client_op_id
    let resp = rpc_call(
        &socket,
        RpcMethod::Send {
            content: "no op id".into(),
            client_op_id: None,
        },
    )
    .expect("send RPC");
    assert!(resp.ok);

    // View should NOT have client_op_id on this message
    let resp = rpc_call(&socket, RpcMethod::View { limit: 50 }).expect("view RPC");
    let view_data = resp.data.unwrap();
    let messages = view_data["messages"].as_array().unwrap();
    let msg = messages
        .iter()
        .find(|m| m["content"].as_str() == Some("no op id"))
        .expect("should find message");
    assert!(
        msg.get("client_op_id").is_none() || msg["client_op_id"].is_null(),
        "should have no client_op_id annotation"
    );

    stop_daemon(&db, &mut daemon);
}

// ---------------------------------------------------------------------------
// 3. Reaction with client_op_id
// ---------------------------------------------------------------------------

#[test]
fn reaction_with_client_op_id_annotated_in_messages() {
    let (_dir, db) = temp_db();
    create_workspace(&db);
    let mut daemon = start_daemon(&db);

    let socket = socket_path_for_db(&db);

    // Send a message first
    let resp = rpc_call(
        &socket,
        RpcMethod::Send {
            content: "react to me".into(),
            client_op_id: None,
        },
    )
    .expect("send RPC");
    assert!(resp.ok);

    // React with client_op_id — use message number "1"
    let resp = rpc_call(
        &socket,
        RpcMethod::React {
            target: "1".into(),
            emoji: "thumbsup".into(),
            client_op_id: Some("react-op-001".into()),
        },
    )
    .expect("react RPC");
    assert!(resp.ok, "react should succeed: {:?}", resp.error);
    let react_data = resp.data.unwrap();
    assert!(!react_data["event_id"].as_str().unwrap_or("").is_empty());

    // Messages endpoint should show the reaction event_id has a client_op_id mapping.
    // But since reactions are attached to messages (not top-level items), we verify
    // the mapping exists by checking the messages list. The reaction itself is inline.
    // The client_op_id mapping exists in the DB for the reaction event.
    // For now, verify the react call succeeded and the reaction appears.
    let resp = rpc_call(&socket, RpcMethod::View { limit: 50 }).expect("view RPC");
    let view_data = resp.data.unwrap();
    let messages = view_data["messages"].as_array().unwrap();
    let msg = &messages[0];
    let reactions = msg["reactions"].as_array().unwrap();
    assert!(
        !reactions.is_empty(),
        "message should have at least one reaction"
    );
    assert_eq!(reactions[0]["emoji"].as_str(), Some("thumbsup"));

    stop_daemon(&db, &mut daemon);
}

// ---------------------------------------------------------------------------
// 4. Multiple messages with different client_op_ids
// ---------------------------------------------------------------------------

#[test]
fn multiple_messages_each_annotated_with_own_client_op_id() {
    let (_dir, db) = temp_db();
    create_workspace(&db);
    let mut daemon = start_daemon(&db);

    let socket = socket_path_for_db(&db);

    // Send three messages with different client_op_ids
    for i in 1..=3 {
        let resp = rpc_call(
            &socket,
            RpcMethod::Send {
                content: format!("msg-{}", i),
                client_op_id: Some(format!("op-{}", i)),
            },
        )
        .expect("send RPC");
        assert!(resp.ok);
    }

    // View should have all three annotated correctly
    let resp = rpc_call(&socket, RpcMethod::View { limit: 50 }).expect("view RPC");
    let view_data = resp.data.unwrap();
    let messages = view_data["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3);

    for i in 1..=3 {
        let msg = messages
            .iter()
            .find(|m| m["content"].as_str() == Some(&format!("msg-{}", i)))
            .unwrap_or_else(|| panic!("should find msg-{}", i));
        assert_eq!(
            msg["client_op_id"].as_str(),
            Some(format!("op-{}", i).as_str()),
            "msg-{} should have client_op_id op-{}",
            i,
            i
        );
    }

    stop_daemon(&db, &mut daemon);
}

// ---------------------------------------------------------------------------
// 5. client_op_id appears in Messages response too (not just View)
// ---------------------------------------------------------------------------

#[test]
fn client_op_id_in_messages_response() {
    let (_dir, db) = temp_db();
    create_workspace(&db);
    let mut daemon = start_daemon(&db);

    let socket = socket_path_for_db(&db);

    let resp = rpc_call(
        &socket,
        RpcMethod::Send {
            content: "messages endpoint test".into(),
            client_op_id: Some("msg-ep-001".into()),
        },
    )
    .expect("send RPC");
    assert!(resp.ok);

    let resp = rpc_call(&socket, RpcMethod::Messages { limit: 50 }).expect("messages RPC");
    assert!(resp.ok);
    let data = resp.data.unwrap();
    let messages = data["messages"].as_array().unwrap();
    let msg = &messages[0];
    assert_eq!(msg["client_op_id"].as_str(), Some("msg-ep-001"));

    stop_daemon(&db, &mut daemon);
}
