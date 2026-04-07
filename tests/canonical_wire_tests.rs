//! Golden-byte, negative parse, and idempotent encode/decode tests
//! for all canonical event types with fixed wire layouts.

use topo::event_modules::file::file_offsets;
use topo::event_modules::key_request::delivery_target_id;
use topo::event_modules::layout::common::{
    encrypted_inner_wire_size, encrypted_wire_size, ENCRYPTED_HEADER_BYTES,
};
use topo::event_modules::layout::field_spec::field_offset;
use topo::event_modules::message::layout::offsets as message_offsets;
use topo::event_modules::reaction::wire::REACTION_FIELDS;
use topo::event_modules::{
    self as events, BenchDepEvent, EncryptedEvent, EventError, FileEvent, FileSliceEvent,
    KeyRequestEvent, KeySharedEvent, MessageEvent, ParsedEvent, ReactionEvent, SignedEvent,
};

// ─── Golden-byte tests ───
//
// Each test constructs a known ParsedEvent, encodes it, and verifies specific
// byte positions against expected values. This catches accidental offset drift.

fn wrap_signed(inner: ParsedEvent, signer_event_id: [u8; 32], signature: [u8; 64]) -> ParsedEvent {
    let payload = events::encode_event(&inner).unwrap();
    ParsedEvent::Signed(SignedEvent {
        signer_event_id,
        inner_type_code: inner.event_type_code(),
        inner_created_at_ms: inner.created_at_ms(),
        payload,
        signature,
    })
}

#[test]
fn golden_bytes_message() {
    let inner = ParsedEvent::Message(MessageEvent {
        created_at_ms: 0x0102030405060708,
        workspace_id: [0xAA; 32],
        author_id: [0xBB; 32],
        content: "Hi".to_string(),
    });
    let blob = events::encode_event(&wrap_signed(inner.clone(), [0xCC; 32], [0xDD; 64])).unwrap();
    let inner_blob = events::encode_event(&inner).unwrap();
    assert_eq!(
        blob.len(),
        1 + 32 + inner_blob.len() + 64,
        "outer Signed envelope size"
    );

    assert_eq!(blob[0], events::EVENT_TYPE_SIGNED);
    assert_eq!(&blob[1..33], &[0xCC; 32]);
    assert_eq!(
        &blob[33..33 + inner_blob.len()],
        &inner_blob,
        "inner payload should be embedded canonically"
    );
    let inner_start = 33;
    // Type code
    assert_eq!(blob[inner_start], 1);
    // created_at_ms LE
    assert_eq!(
        &blob[inner_start + 1..inner_start + 9],
        &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    );
    // workspace_id
    assert_eq!(&blob[inner_start + 9..inner_start + 41], &[0xAA; 32]);
    // author_id
    assert_eq!(&blob[inner_start + 41..inner_start + 73], &[0xBB; 32]);
    // content: "Hi" + zero padding
    assert_eq!(&blob[inner_start + 73..inner_start + 75], b"Hi");
    assert!(blob[inner_start + 75..inner_start + 73 + 1024]
        .iter()
        .all(|&b| b == 0));
    assert_eq!(&blob[blob.len() - 64..], &[0xDD; 64]);
}

#[test]
fn golden_bytes_reaction() {
    let inner = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 1000,
        target_event_id: [0x11; 32],
        author_id: [0x22; 32],
        emoji: "\u{1f44d}".to_string(), // 👍 = 4 UTF-8 bytes
    });
    let blob = events::encode_event(&wrap_signed(inner.clone(), [0x33; 32], [0x44; 64])).unwrap();
    let inner_blob = events::encode_event(&inner).unwrap();
    assert_eq!(blob[0], events::EVENT_TYPE_SIGNED);
    assert_eq!(&blob[33..33 + inner_blob.len()], &inner_blob);
    let inner_start = 33;
    assert_eq!(blob[inner_start], 2);
    assert_eq!(&blob[inner_start + 9..inner_start + 41], &[0x11; 32]);
    assert_eq!(&blob[inner_start + 41..inner_start + 73], &[0x22; 32]);
    // emoji: 4 bytes of 👍 then zeros
    assert_eq!(
        &blob[inner_start + 73..inner_start + 77],
        "\u{1f44d}".as_bytes()
    );
    assert!(blob[inner_start + 77..inner_start + 73 + 64]
        .iter()
        .all(|&b| b == 0));
    assert_eq!(&blob[blob.len() - 64..], &[0x44; 64]);
}

#[test]
fn golden_bytes_encrypted() {
    let ct_size = encrypted_inner_wire_size(2).unwrap(); // reaction = 234
    let enc = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: 3000,
        key_event_id: [0x77; 32],
        owner_event_id: [0x66; 32],
        inner_type_code: 2,
        nonce: [0x88; 12],
        ciphertext: vec![0x99; ct_size],
        auth_tag: [0xAA; 16],
    });
    let blob = events::encode_event(&enc).unwrap();
    let expected_size = encrypted_wire_size(ct_size);
    assert_eq!(blob.len(), expected_size);
    assert_eq!(blob[0], 5);
    assert_eq!(&blob[9..41], &[0x77; 32]);
    assert_eq!(&blob[41..73], &[0x66; 32]);
    assert_eq!(blob[73], 2); // inner_type_code
    assert_eq!(&blob[74..86], &[0x88; 12]); // nonce
    assert_eq!(&blob[86..86 + ct_size], &vec![0x99; ct_size]); // ciphertext
    let tag_start = 86 + ct_size;
    assert_eq!(&blob[tag_start..tag_start + 16], &[0xAA; 16]); // auth_tag
}

#[test]
fn golden_bytes_file() {
    let inner = ParsedEvent::File(FileEvent {
        created_at_ms: 4000,
        message_id: [0x01; 32],
        file_id: [0x02; 32],
        blob_bytes: 1024,
        total_slices: 1,
        slice_bytes: 1024,
        root_hash: [0x03; 32],
        key_event_id: [0x04; 32],
        filename: "test.bin".to_string(),
        mime_type: "application/octet-stream".to_string(),
    });
    let blob = events::encode_event(&wrap_signed(inner.clone(), [0x05; 32], [0x06; 64])).unwrap();
    let inner_blob = events::encode_event(&inner).unwrap();
    assert_eq!(blob[0], events::EVENT_TYPE_SIGNED);
    assert_eq!(&blob[33..33 + inner_blob.len()], &inner_blob);
    let inner_start = 33;
    assert_eq!(blob[inner_start], 24);
    // filename at offset 153
    assert_eq!(&blob[inner_start + 153..inner_start + 161], b"test.bin");
    assert!(blob[inner_start + 161..inner_start + 153 + 255]
        .iter()
        .all(|&b| b == 0));
    // mime_type at offset 408
    let mime = b"application/octet-stream";
    assert_eq!(
        &blob[inner_start + 408..inner_start + 408 + mime.len()],
        mime
    );
    assert!(
        blob[inner_start + 408 + mime.len()..inner_start + 408 + 128]
            .iter()
            .all(|&b| b == 0)
    );
    assert_eq!(&blob[blob.len() - 64..], &[0x06; 64]);
}

#[test]
fn golden_bytes_bench_dep() {
    let bd = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: 6000,
        dep_ids: vec![[0xAA; 32], [0xBB; 32]],
        payload: [0xCC; 16],
    });
    let blob = events::encode_event(&bd).unwrap();
    assert_eq!(blob.len(), events::bench_dep::BENCH_DEP_WIRE_SIZE);
    assert_eq!(blob[0], 26);
    // First dep slot at offset 9
    assert_eq!(&blob[9..41], &[0xAA; 32]);
    // Second dep slot
    assert_eq!(&blob[41..73], &[0xBB; 32]);
    // Remaining 8 slots are zero
    assert!(blob[73..9 + 320].iter().all(|&b| b == 0));
    // Payload at offset 329
    assert_eq!(&blob[329..345], &[0xCC; 16]);
}

#[test]
fn golden_bytes_key_request() {
    let frontier_hash = [0x23; 32];
    let inner = ParsedEvent::KeyRequest(KeyRequestEvent {
        created_at_ms: 7000,
        blocked_event_id: [0x11; 32],
        key_event_id: [0x22; 32],
        frontier_hash,
        delivery_target_id: delivery_target_id(
            &[0x22; 32],
            &frontier_hash,
            &[0x33; 32],
            &[0x44; 32],
        ),
        recipient_event_id: [0x33; 32],
        unwrap_key_event_id: [0x44; 32],
    });
    let blob = events::encode_event(&wrap_signed(inner.clone(), [0x55; 32], [0x66; 64])).unwrap();
    let inner_blob = events::encode_event(&inner).unwrap();
    assert_eq!(blob[0], events::EVENT_TYPE_SIGNED);
    assert_eq!(&blob[33..33 + inner_blob.len()], &inner_blob);
    let inner_start = 33;
    assert_eq!(blob[inner_start], 30);
    assert_eq!(&blob[inner_start + 9..inner_start + 41], &[0x11; 32]);
    assert_eq!(&blob[inner_start + 41..inner_start + 73], &[0x22; 32]);
    assert_eq!(&blob[inner_start + 73..inner_start + 105], &frontier_hash);
    assert_eq!(
        &blob[inner_start + 105..inner_start + 137],
        &delivery_target_id(&[0x22; 32], &frontier_hash, &[0x33; 32], &[0x44; 32])
    );
    assert_eq!(&blob[inner_start + 137..inner_start + 169], &[0x33; 32]);
    assert_eq!(&blob[inner_start + 169..inner_start + 201], &[0x44; 32]);
    assert_eq!(&blob[blob.len() - 64..], &[0x66; 64]);
}

#[test]
fn golden_bytes_key_shared() {
    let frontier_hash = topo::event_modules::removal::frontier_hash_from_refs(&[]);
    let inner = ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms: 6000,
        key_event_id: [0x21; 32],
        frontier_count: 0,
        frontier_ref_1: [0u8; 32],
        frontier_ref_2: [0u8; 32],
        frontier_ref_3: [0u8; 32],
        frontier_ref_4: [0u8; 32],
        frontier_hash,
        delivery_target_id: delivery_target_id(
            &[0x21; 32],
            &frontier_hash,
            &[0x31; 32],
            &[0x41; 32],
        ),
        recipient_event_id: [0x31; 32],
        unwrap_key_event_id: [0x41; 32],
        wrapped_key: [0x51; 32],
    });
    let blob = events::encode_event(&wrap_signed(inner.clone(), [0x61; 32], [0x71; 64])).unwrap();
    let inner_blob = events::encode_event(&inner).unwrap();
    assert_eq!(blob[0], events::EVENT_TYPE_SIGNED);
    assert_eq!(&blob[33..33 + inner_blob.len()], &inner_blob);
    let inner_start = 33;
    assert_eq!(blob[inner_start], 22);
    assert_eq!(&blob[inner_start + 9..inner_start + 41], &[0x21; 32]);
    assert_eq!(blob[inner_start + 41], 0);
    assert!(blob[inner_start + 42..inner_start + 170]
        .iter()
        .all(|&b| b == 0));
    assert_eq!(&blob[inner_start + 170..inner_start + 202], &frontier_hash);
    assert_eq!(
        &blob[inner_start + 202..inner_start + 234],
        &delivery_target_id(&[0x21; 32], &frontier_hash, &[0x31; 32], &[0x41; 32])
    );
    assert_eq!(&blob[inner_start + 234..inner_start + 266], &[0x31; 32]);
    assert_eq!(&blob[inner_start + 266..inner_start + 298], &[0x41; 32]);
    assert_eq!(&blob[inner_start + 298..inner_start + 330], &[0x51; 32]);
    assert_eq!(&blob[blob.len() - 64..], &[0x71; 64]);
}

// ─── Negative parse tests: truncation ───

#[test]
fn truncation_message() {
    let inner = ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "".to_string(),
    });
    let blob = events::encode_event(&inner).unwrap();
    // Truncate by 1 byte
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

#[test]
fn truncation_reaction() {
    let inner = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 100,
        target_event_id: [0u8; 32],
        author_id: [0u8; 32],
        emoji: "x".to_string(),
    });
    let blob = events::encode_event(&inner).unwrap();
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

#[test]
fn truncation_encrypted() {
    let ct_size = encrypted_inner_wire_size(1).unwrap();
    let enc = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: 100,
        key_event_id: [0u8; 32],
        owner_event_id: [0u8; 32],
        inner_type_code: 1,
        nonce: [0u8; 12],
        ciphertext: vec![0u8; ct_size],
        auth_tag: [0u8; 16],
    });
    let blob = events::encode_event(&enc).unwrap();
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

#[test]
fn truncation_bench_dep() {
    let bd = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: 100,
        dep_ids: vec![],
        payload: [0u8; 16],
    });
    let blob = events::encode_event(&bd).unwrap();
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

#[test]
fn truncation_key_request() {
    let frontier_hash = [4u8; 32];
    let inner = ParsedEvent::KeyRequest(KeyRequestEvent {
        created_at_ms: 100,
        blocked_event_id: [0u8; 32],
        key_event_id: [1u8; 32],
        frontier_hash,
        delivery_target_id: delivery_target_id(&[1u8; 32], &frontier_hash, &[2u8; 32], &[3u8; 32]),
        recipient_event_id: [2u8; 32],
        unwrap_key_event_id: [3u8; 32],
    });
    let blob = events::encode_event(&inner).unwrap();
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

#[test]
fn truncation_key_shared() {
    let frontier_hash = topo::event_modules::removal::frontier_hash_from_refs(&[]);
    let inner = ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms: 100,
        key_event_id: [1u8; 32],
        frontier_count: 0,
        frontier_ref_1: [0u8; 32],
        frontier_ref_2: [0u8; 32],
        frontier_ref_3: [0u8; 32],
        frontier_ref_4: [0u8; 32],
        frontier_hash,
        delivery_target_id: delivery_target_id(&[1u8; 32], &frontier_hash, &[2u8; 32], &[3u8; 32]),
        recipient_event_id: [2u8; 32],
        unwrap_key_event_id: [3u8; 32],
        wrapped_key: [4u8; 32],
    });
    let blob = events::encode_event(&inner).unwrap();
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

#[test]
fn truncation_file() {
    let inner = ParsedEvent::File(FileEvent {
        created_at_ms: 100,
        message_id: [0u8; 32],
        file_id: [0u8; 32],
        blob_bytes: 0,
        total_slices: 0,
        slice_bytes: 0,
        root_hash: [0u8; 32],
        key_event_id: [0u8; 32],
        filename: "".to_string(),
        mime_type: "".to_string(),
    });
    let blob = events::encode_event(&inner).unwrap();
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

// ─── Negative parse tests: non-zero padding in text slots ───

#[test]
fn nonzero_padding_message_content() {
    let inner = ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "a".to_string(),
    });
    let mut blob = events::encode_event(&inner).unwrap();
    // Inject non-zero byte after NUL in content slot
    let content_start = message_offsets::CONTENT;
    blob[content_start + 2] = 0xFF; // byte after "a\0" should be 0
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

#[test]
fn nonzero_padding_reaction_emoji() {
    let inner = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 100,
        target_event_id: [0u8; 32],
        author_id: [0u8; 32],
        emoji: "x".to_string(),
    });
    let mut blob = events::encode_event(&inner).unwrap();
    let emoji_start = field_offset(REACTION_FIELDS, 3); // emoji field
    blob[emoji_start + 2] = 0xFF; // after "x\0"
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

#[test]
fn nonzero_padding_attachment_filename() {
    let inner = ParsedEvent::File(FileEvent {
        created_at_ms: 100,
        message_id: [0u8; 32],
        file_id: [0u8; 32],
        blob_bytes: 0,
        total_slices: 0,
        slice_bytes: 0,
        root_hash: [0u8; 32],
        key_event_id: [0u8; 32],
        filename: "a".to_string(),
        mime_type: "".to_string(),
    });
    let mut blob = events::encode_event(&inner).unwrap();
    let fn_start = file_offsets::FILENAME;
    blob[fn_start + 2] = 0xFF;
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

#[test]
fn nonzero_padding_attachment_mime() {
    let inner = ParsedEvent::File(FileEvent {
        created_at_ms: 100,
        message_id: [0u8; 32],
        file_id: [0u8; 32],
        blob_bytes: 0,
        total_slices: 0,
        slice_bytes: 0,
        root_hash: [0u8; 32],
        key_event_id: [0u8; 32],
        filename: "".to_string(),
        mime_type: "x".to_string(),
    });
    let mut blob = events::encode_event(&inner).unwrap();
    let mime_start = file_offsets::MIME_TYPE;
    blob[mime_start + 2] = 0xFF;
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

// ─── Negative parse tests: malformed UTF-8 in text slots ───

#[test]
fn malformed_utf8_message_content() {
    let inner = ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "".to_string(),
    });
    let mut blob = events::encode_event(&inner).unwrap();
    let content_start = message_offsets::CONTENT;
    blob[content_start] = 0xFF; // invalid UTF-8 lead byte
    blob[content_start + 1] = 0xFE;
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

#[test]
fn malformed_utf8_reaction_emoji() {
    let inner = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 100,
        target_event_id: [0u8; 32],
        author_id: [0u8; 32],
        emoji: "".to_string(),
    });
    let mut blob = events::encode_event(&inner).unwrap();
    let emoji_start = field_offset(REACTION_FIELDS, 3); // emoji field
    blob[emoji_start] = 0xFF;
    blob[emoji_start + 1] = 0xFE;
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

// ─── Negative parse tests: wrong type code ───

#[test]
fn wrong_type_code_message() {
    let inner = ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "".to_string(),
    });
    let mut blob = events::encode_event(&wrap_signed(inner, [0u8; 32], [0u8; 64])).unwrap();
    blob[0] = 99; // wrong type
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::UnknownType(99)));
}

// ─── Negative parse tests: encrypted with unknown inner type ───

#[test]
fn encrypted_unknown_inner_type_code() {
    // Build raw blob with inner_type_code=200 (unknown)
    let header_size = ENCRYPTED_HEADER_BYTES;
    // Minimal: just enough for the parser to read the header and reject
    let mut buf = vec![0u8; header_size + 1]; // +1 so TooShort isn't the error
    buf[0] = 5; // EVENT_TYPE_ENCRYPTED
    buf[73] = 200; // unknown inner_type_code
    let err = events::parse_event(&buf).unwrap_err();
    assert!(matches!(err, EventError::InvalidEncryptedInnerType(200)));
}

// ─── Negative parse tests: forbidden dep slot shapes (bench_dep) ───

#[test]
fn bench_dep_too_many_deps_rejected_by_encoder() {
    let bd = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: 100,
        dep_ids: vec![[1u8; 32]; 11], // 11 > max 10
        payload: [0u8; 16],
    });
    let err = events::encode_event(&bd).unwrap_err();
    assert!(matches!(err, EventError::ContentTooLong(11)));
}

#[test]
fn bench_dep_max_deps_accepted() {
    let bd = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: 100,
        dep_ids: vec![[1u8; 32]; 10], // exactly max
        payload: [0u8; 16],
    });
    let blob = events::encode_event(&bd).unwrap();
    let parsed = events::parse_event(&blob).unwrap();
    if let ParsedEvent::BenchDep(b) = parsed {
        assert_eq!(b.dep_ids.len(), 10);
    } else {
        panic!("expected BenchDep");
    }
}

// ─── Negative parse tests: file slice wrong ciphertext size ───

#[test]
fn file_slice_wrong_ciphertext_size_rejected() {
    let fs = ParsedEvent::FileSlice(FileSliceEvent {
        created_at_ms: 100,
        file_id: [0u8; 32],
        slice_number: 0,
        ciphertext: vec![0u8; 1024], // not the canonical fixed payload size
    });
    assert!(events::encode_event(&fs).is_err());
}

// ─── Negative parse tests: content too long for text slots ───

#[test]
fn message_content_too_long() {
    let inner = ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "x".repeat(1025), // 1025 > 1024
    });
    assert!(events::encode_event(&inner).is_err());
}

#[test]
fn reaction_emoji_too_long() {
    let inner = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 100,
        target_event_id: [0u8; 32],
        author_id: [0u8; 32],
        emoji: "x".repeat(65), // 65 > 64
    });
    assert!(events::encode_event(&inner).is_err());
}

#[test]
fn attachment_filename_too_long() {
    let inner = ParsedEvent::File(FileEvent {
        created_at_ms: 100,
        message_id: [0u8; 32],
        file_id: [0u8; 32],
        blob_bytes: 0,
        total_slices: 0,
        slice_bytes: 0,
        root_hash: [0u8; 32],
        key_event_id: [0u8; 32],
        filename: "x".repeat(256), // 256 > 255
        mime_type: "".to_string(),
    });
    assert!(events::encode_event(&inner).is_err());
}

#[test]
fn attachment_mime_too_long() {
    let inner = ParsedEvent::File(FileEvent {
        created_at_ms: 100,
        message_id: [0u8; 32],
        file_id: [0u8; 32],
        blob_bytes: 0,
        total_slices: 0,
        slice_bytes: 0,
        root_hash: [0u8; 32],
        key_event_id: [0u8; 32],
        filename: "".to_string(),
        mime_type: "x".repeat(129), // 129 > 128
    });
    assert!(events::encode_event(&inner).is_err());
}

// ─── Idempotent encode/decode canonicalization tests ───
//
// Verify that encode(decode(encode(event))) == encode(event) — the canonical
// byte representation is unique and stable through roundtrips.

fn assert_idempotent(event: &ParsedEvent) {
    let blob1 = events::encode_event(event).unwrap();
    let parsed1 = events::parse_event(&blob1).unwrap();
    let blob2 = events::encode_event(&parsed1).unwrap();
    assert_eq!(blob1, blob2, "encode/decode is not idempotent");
    let parsed2 = events::parse_event(&blob2).unwrap();
    assert_eq!(parsed1, parsed2, "second parse differs from first");
}

#[test]
fn idempotent_message() {
    assert_idempotent(&wrap_signed(
        ParsedEvent::Message(MessageEvent {
            created_at_ms: 1234567890123,
            workspace_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "Hello, world!".to_string(),
        }),
        [3u8; 32],
        [4u8; 64],
    ));
}

#[test]
fn idempotent_message_empty_content() {
    assert_idempotent(&wrap_signed(
        ParsedEvent::Message(MessageEvent {
            created_at_ms: 100,
            workspace_id: [0u8; 32],
            author_id: [0u8; 32],
            content: "".to_string(),
        }),
        [0u8; 32],
        [0u8; 64],
    ));
}

#[test]
fn idempotent_message_max_content() {
    assert_idempotent(&wrap_signed(
        ParsedEvent::Message(MessageEvent {
            created_at_ms: 100,
            workspace_id: [0u8; 32],
            author_id: [0u8; 32],
            content: "x".repeat(1024),
        }),
        [0u8; 32],
        [0u8; 64],
    ));
}

#[test]
fn idempotent_reaction() {
    assert_idempotent(&wrap_signed(
        ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: 200,
            target_event_id: [5u8; 32],
            author_id: [6u8; 32],
            emoji: "\u{1f44d}".to_string(),
        }),
        [7u8; 32],
        [8u8; 64],
    ));
}

#[test]
fn idempotent_encrypted() {
    let ct_size = encrypted_inner_wire_size(1).unwrap();
    assert_idempotent(&ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: 400,
        key_event_id: [11u8; 32],
        owner_event_id: [10u8; 32],
        inner_type_code: 1,
        nonce: [12u8; 12],
        ciphertext: vec![13u8; ct_size],
        auth_tag: [14u8; 16],
    }));
}

#[test]
fn idempotent_file() {
    assert_idempotent(&wrap_signed(
        ParsedEvent::File(FileEvent {
            created_at_ms: 500,
            message_id: [15u8; 32],
            file_id: [16u8; 32],
            blob_bytes: 65536,
            total_slices: 1,
            slice_bytes: 65536,
            root_hash: [17u8; 32],
            key_event_id: [18u8; 32],
            filename: "photo.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
        }),
        [19u8; 32],
        [20u8; 64],
    ));
}

#[test]
fn idempotent_file_slice() {
    assert_idempotent(&ParsedEvent::FileSlice(FileSliceEvent {
        created_at_ms: 600,
        file_id: [21u8; 32],
        slice_number: 42,
        ciphertext: vec![22u8; events::file_slice::FILE_SLICE_CIPHERTEXT_BYTES],
    }));
}

#[test]
fn idempotent_bench_dep() {
    assert_idempotent(&ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: 700,
        dep_ids: vec![[25u8; 32], [26u8; 32], [27u8; 32]],
        payload: [28u8; 16],
    }));
}

#[test]
fn idempotent_bench_dep_empty() {
    assert_idempotent(&ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: 800,
        dep_ids: vec![],
        payload: [0u8; 16],
    }));
}

#[test]
fn idempotent_bench_dep_full() {
    assert_idempotent(&ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: 900,
        dep_ids: vec![[0xFF; 32]; 10],
        payload: [0xEE; 16],
    }));
}

#[test]
fn idempotent_key_request() {
    let frontier_hash = [33u8; 32];
    assert_idempotent(&wrap_signed(
        ParsedEvent::KeyRequest(KeyRequestEvent {
            created_at_ms: 1_234,
            blocked_event_id: [29u8; 32],
            key_event_id: [30u8; 32],
            frontier_hash,
            delivery_target_id: delivery_target_id(
                &[30u8; 32],
                &frontier_hash,
                &[31u8; 32],
                &[32u8; 32],
            ),
            recipient_event_id: [31u8; 32],
            unwrap_key_event_id: [32u8; 32],
        }),
        [33u8; 32],
        [34u8; 64],
    ));
}

#[test]
fn idempotent_key_shared() {
    let frontier_hash = topo::event_modules::removal::frontier_hash_from_refs(&[]);
    assert_idempotent(&wrap_signed(
        ParsedEvent::KeyShared(KeySharedEvent {
            created_at_ms: 1_235,
            key_event_id: [36u8; 32],
            frontier_count: 0,
            frontier_ref_1: [0u8; 32],
            frontier_ref_2: [0u8; 32],
            frontier_ref_3: [0u8; 32],
            frontier_ref_4: [0u8; 32],
            frontier_hash,
            delivery_target_id: delivery_target_id(
                &[36u8; 32],
                &frontier_hash,
                &[37u8; 32],
                &[38u8; 32],
            ),
            recipient_event_id: [37u8; 32],
            unwrap_key_event_id: [38u8; 32],
            wrapped_key: [39u8; 32],
        }),
        [40u8; 32],
        [41u8; 64],
    ));
}
