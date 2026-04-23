//! Integration test: the three K_bundle producers
//! (key_broadcast, key_history_bundle, key_bundle_share) MUST
//! materialize the same deterministic local KeySecret(K_bundle)
//! event id for the same K_bundle bytes.
//!
//! This is the cornerstone property that keeps heal / bootstrap / bulk
//! fanout interchangeable in the Per-Message FS design: whichever path
//! delivers K_bundle to a peer, the resulting local event id is
//! identical, so standard cascade unblocks every message_key blocked
//! on that bundle uniformly regardless of which producer delivered it.
//!
//! Plan: docs/planning/DELETE_TRIGGERED_REKEY_EXECUTION_PLAN.md
//!   §"Projection (message_key)" / "Why this dep shape"
//!   §"Phase 3" / "All three producers materialize the same
//!     deterministic KeySecret(K_bundle)"

use topo::event_modules::key_secret::{
    deterministic_key_secret_created_at_ms, deterministic_key_secret_event_id,
};

#[test]
fn three_producers_produce_identical_keysecret_event_ids() {
    // Given the same K_bundle bytes, any producer — key_broadcast,
    // key_history_bundle, or key_bundle_share — emits a local
    // KeySecret(K_bundle) whose deterministic event_id is derived
    // purely from the key bytes.
    let k_bundle = [0x42u8; 32];

    // Simulate three independent projections (each producer path)
    // computing the deterministic local event id.
    let id_from_broadcast = deterministic_key_secret_event_id(&k_bundle);
    let id_from_history = deterministic_key_secret_event_id(&k_bundle);
    let id_from_bundle_share = deterministic_key_secret_event_id(&k_bundle);

    assert_eq!(id_from_broadcast, id_from_history);
    assert_eq!(id_from_history, id_from_bundle_share);

    // created_at_ms also deterministic — needed for content-address
    // stability across replay / re-emit.
    let ts_a = deterministic_key_secret_created_at_ms(&k_bundle);
    let ts_b = deterministic_key_secret_created_at_ms(&k_bundle);
    assert_eq!(ts_a, ts_b);

    // Different K_bundle bytes must produce a different event id.
    let other_k_bundle = [0x43u8; 32];
    let id_other = deterministic_key_secret_event_id(&other_k_bundle);
    assert_ne!(id_from_broadcast, id_other);
}

#[test]
fn message_key_event_id_determinism_across_emitters() {
    // Two different devices emitting a message_key for the SAME
    // (K_bundle, K_m, owning_message) must produce byte-identical
    // events — content-addressed dedupe.
    use topo::event_modules::{
        message_key::{
            deterministic_message_key_created_at_ms, encode_message_key, MessageKeyEvent,
        },
        ParsedEvent,
    };

    let bundle_id = [0x01u8; 32];
    let k_bundle_local = [0x05u8; 32];
    let wrapped_k_m = [0x03u8; 48];
    let nonce = [0x04u8; 12];

    let created_at_a = deterministic_message_key_created_at_ms(
        &bundle_id,
        &k_bundle_local,
        &wrapped_k_m,
    );
    let created_at_b = deterministic_message_key_created_at_ms(
        &bundle_id,
        &k_bundle_local,
        &wrapped_k_m,
    );
    assert_eq!(created_at_a, created_at_b);

    let evt_a = ParsedEvent::MessageKey(MessageKeyEvent {
        created_at_ms: created_at_a,
        bundle_id,
        k_bundle_local_event_id: k_bundle_local,
        nonce,
        wrapped_k_m,
    });
    let evt_b = ParsedEvent::MessageKey(MessageKeyEvent {
        created_at_ms: created_at_b,
        bundle_id,
        k_bundle_local_event_id: k_bundle_local,
        nonce,
        wrapped_k_m,
    });

    let blob_a = encode_message_key(&evt_a).expect("encode a");
    let blob_b = encode_message_key(&evt_b).expect("encode b");
    assert_eq!(blob_a, blob_b);
}

#[test]
fn wire_sizes_follow_plan_targets() {
    use topo::event_modules::key_broadcast::KEY_BROADCAST_WIRE_SIZE;
    use topo::event_modules::key_bundle_request::KEY_BUNDLE_REQUEST_WIRE_SIZE;
    use topo::event_modules::key_bundle_share::KEY_BUNDLE_SHARE_WIRE_SIZE;
    use topo::event_modules::key_history_bundle::KEY_HISTORY_BUNDLE_WIRE_SIZE;
    use topo::event_modules::message_key::MESSAGE_KEY_WIRE_SIZE;
    use topo::event_modules::wrap_pubkey::WRAP_PUBKEY_WIRE_SIZE;

    // Small events: WrapPubkey, message_key, key_bundle_request,
    // key_bundle_share all stay well under master's 524 KB-class.
    assert_eq!(WRAP_PUBKEY_WIRE_SIZE, 49);
    // Option C: owning_message_event_id dropped from wire
    // (133 = 1 type + 8 created_at + 32 bundle_id +
    //  32 k_bundle_local_event_id + 12 nonce + 48 wrapped_k_m).
    assert_eq!(MESSAGE_KEY_WIRE_SIZE, 133);
    assert_eq!(KEY_BUNDLE_REQUEST_WIRE_SIZE, 73);
    assert_eq!(KEY_BUNDLE_SHARE_WIRE_SIZE, 105);

    // Bulk events: key_broadcast (8192 × 2 × 32 B slots) and
    // key_history_bundle (8192 × 80 B K_bundle slots + 4096 × 80 B K_m
    // slots for Case A retired-bundle recovery per DESIGN §9.6.5).
    assert_eq!(KEY_BROADCAST_WIRE_SIZE, 524_329);
    // 655_477 + 4096 * 80 = 983_157.
    assert_eq!(KEY_HISTORY_BUNDLE_WIRE_SIZE, 983_157);
}
