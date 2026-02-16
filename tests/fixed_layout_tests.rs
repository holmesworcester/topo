//! Phase 5 test expansion: golden-byte, negative parse, and idempotent
//! encode/decode tests for all fixed-layout canonical event types.

use poc_7::events::{
    self, fixed_layout, EventError, ParsedEvent,
    MessageEvent, ReactionEvent, SignedMemoEvent, EncryptedEvent,
    FileSliceEvent, MessageAttachmentEvent, BenchDepEvent,
};

// ─── Golden-byte tests ───
//
// Each test constructs a known ParsedEvent, encodes it, and verifies specific
// byte positions against expected values. This catches accidental offset drift.

#[test]
fn golden_bytes_message() {
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: 0x0102030405060708,
        workspace_id: [0xAA; 32],
        author_id: [0xBB; 32],
        content: "Hi".to_string(),
        signed_by: [0xCC; 32],
        signer_type: 5,
        signature: [0xDD; 64],
    });
    let blob = events::encode_event(&msg).unwrap();
    assert_eq!(blob.len(), fixed_layout::MESSAGE_WIRE_SIZE);

    // Type code
    assert_eq!(blob[0], 1);
    // created_at_ms LE
    assert_eq!(&blob[1..9], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    // workspace_id
    assert_eq!(&blob[9..41], &[0xAA; 32]);
    // author_id
    assert_eq!(&blob[41..73], &[0xBB; 32]);
    // content: "Hi" + zero padding
    assert_eq!(&blob[73..75], b"Hi");
    assert!(blob[75..73 + 1024].iter().all(|&b| b == 0));
    // signed_by
    let sb_start = fixed_layout::message_offsets::SIGNED_BY;
    assert_eq!(&blob[sb_start..sb_start + 32], &[0xCC; 32]);
    // signer_type
    assert_eq!(blob[fixed_layout::message_offsets::SIGNER_TYPE], 5);
    // signature
    let sig_start = fixed_layout::message_offsets::SIGNATURE;
    assert_eq!(&blob[sig_start..sig_start + 64], &[0xDD; 64]);
}

#[test]
fn golden_bytes_reaction() {
    let rxn = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 1000,
        target_event_id: [0x11; 32],
        author_id: [0x22; 32],
        emoji: "\u{1f44d}".to_string(), // 👍 = 4 UTF-8 bytes
        signed_by: [0x33; 32],
        signer_type: 5,
        signature: [0x44; 64],
    });
    let blob = events::encode_event(&rxn).unwrap();
    assert_eq!(blob.len(), fixed_layout::REACTION_WIRE_SIZE);
    assert_eq!(blob[0], 2);
    assert_eq!(&blob[9..41], &[0x11; 32]);
    assert_eq!(&blob[41..73], &[0x22; 32]);
    // emoji: 4 bytes of 👍 then zeros
    assert_eq!(&blob[73..77], "\u{1f44d}".as_bytes());
    assert!(blob[77..73 + 64].iter().all(|&b| b == 0));
}

#[test]
fn golden_bytes_signed_memo() {
    let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
        created_at_ms: 2000,
        signed_by: [0x55; 32],
        signer_type: 5,
        content: "memo".to_string(),
        signature: [0x66; 64],
    });
    let blob = events::encode_event(&memo).unwrap();
    assert_eq!(blob.len(), fixed_layout::SIGNED_MEMO_WIRE_SIZE);
    assert_eq!(blob[0], 4);
    assert_eq!(&blob[9..41], &[0x55; 32]);
    assert_eq!(blob[41], 5);
    assert_eq!(&blob[42..46], b"memo");
    assert!(blob[46..42 + 1024].iter().all(|&b| b == 0));
    let sig_off = fixed_layout::signed_memo_offsets::SIGNATURE;
    assert_eq!(&blob[sig_off..sig_off + 64], &[0x66; 64]);
}

#[test]
fn golden_bytes_encrypted() {
    let ct_size = fixed_layout::encrypted_inner_wire_size(2).unwrap(); // reaction = 234
    let enc = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: 3000,
        key_event_id: [0x77; 32],
        inner_type_code: 2,
        nonce: [0x88; 12],
        ciphertext: vec![0x99; ct_size],
        auth_tag: [0xAA; 16],
    });
    let blob = events::encode_event(&enc).unwrap();
    let expected_size = fixed_layout::encrypted_wire_size(ct_size);
    assert_eq!(blob.len(), expected_size);
    assert_eq!(blob[0], 5);
    assert_eq!(&blob[9..41], &[0x77; 32]);
    assert_eq!(blob[41], 2); // inner_type_code
    assert_eq!(&blob[42..54], &[0x88; 12]); // nonce
    assert_eq!(&blob[54..54 + ct_size], &vec![0x99; ct_size]); // ciphertext
    let tag_start = 54 + ct_size;
    assert_eq!(&blob[tag_start..tag_start + 16], &[0xAA; 16]); // auth_tag
}

#[test]
fn golden_bytes_message_attachment() {
    let att = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
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
        signed_by: [0x05; 32],
        signer_type: 5,
        signature: [0x06; 64],
    });
    let blob = events::encode_event(&att).unwrap();
    assert_eq!(blob.len(), fixed_layout::MESSAGE_ATTACHMENT_WIRE_SIZE);
    assert_eq!(blob[0], 24);
    // filename at offset 153
    assert_eq!(&blob[153..161], b"test.bin");
    assert!(blob[161..153 + 255].iter().all(|&b| b == 0));
    // mime_type at offset 408
    let mime = b"application/octet-stream";
    assert_eq!(&blob[408..408 + mime.len()], mime);
    assert!(blob[408 + mime.len()..408 + 128].iter().all(|&b| b == 0));
}

#[test]
fn golden_bytes_bench_dep() {
    let bd = ParsedEvent::BenchDep(BenchDepEvent {
        created_at_ms: 6000,
        dep_ids: vec![[0xAA; 32], [0xBB; 32]],
        payload: [0xCC; 16],
    });
    let blob = events::encode_event(&bd).unwrap();
    assert_eq!(blob.len(), fixed_layout::BENCH_DEP_WIRE_SIZE);
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

// ─── Negative parse tests: truncation ───

#[test]
fn truncation_message() {
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "".to_string(),
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let blob = events::encode_event(&msg).unwrap();
    // Truncate by 1 byte
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

#[test]
fn truncation_reaction() {
    let rxn = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 100,
        target_event_id: [0u8; 32],
        author_id: [0u8; 32],
        emoji: "x".to_string(),
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let blob = events::encode_event(&rxn).unwrap();
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

#[test]
fn truncation_signed_memo() {
    let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
        created_at_ms: 100,
        signed_by: [0u8; 32],
        signer_type: 5,
        content: "x".to_string(),
        signature: [0u8; 64],
    });
    let blob = events::encode_event(&memo).unwrap();
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

#[test]
fn truncation_encrypted() {
    let ct_size = fixed_layout::encrypted_inner_wire_size(1).unwrap();
    let enc = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: 100,
        key_event_id: [0u8; 32],
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
fn truncation_message_attachment() {
    let att = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
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
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let blob = events::encode_event(&att).unwrap();
    let err = events::parse_event(&blob[..blob.len() - 1]).unwrap_err();
    assert!(matches!(err, EventError::TooShort { .. }));
}

// ─── Negative parse tests: non-zero padding in text slots ───

#[test]
fn nonzero_padding_message_content() {
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "a".to_string(),
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut blob = events::encode_event(&msg).unwrap();
    // Inject non-zero byte after NUL in content slot
    let content_start = fixed_layout::message_offsets::CONTENT;
    blob[content_start + 2] = 0xFF; // byte after "a\0" should be 0
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

#[test]
fn nonzero_padding_reaction_emoji() {
    let rxn = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 100,
        target_event_id: [0u8; 32],
        author_id: [0u8; 32],
        emoji: "x".to_string(),
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut blob = events::encode_event(&rxn).unwrap();
    let emoji_start = fixed_layout::reaction_offsets::EMOJI;
    blob[emoji_start + 2] = 0xFF; // after "x\0"
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

#[test]
fn nonzero_padding_signed_memo_content() {
    let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
        created_at_ms: 100,
        signed_by: [0u8; 32],
        signer_type: 5,
        content: "b".to_string(),
        signature: [0u8; 64],
    });
    let mut blob = events::encode_event(&memo).unwrap();
    let content_start = fixed_layout::signed_memo_offsets::CONTENT;
    blob[content_start + 2] = 0xFF;
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

#[test]
fn nonzero_padding_attachment_filename() {
    let att = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
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
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut blob = events::encode_event(&att).unwrap();
    let fn_start = fixed_layout::attachment_offsets::FILENAME;
    blob[fn_start + 2] = 0xFF;
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

#[test]
fn nonzero_padding_attachment_mime() {
    let att = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
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
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut blob = events::encode_event(&att).unwrap();
    let mime_start = fixed_layout::attachment_offsets::MIME_TYPE;
    blob[mime_start + 2] = 0xFF;
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

// ─── Negative parse tests: malformed UTF-8 in text slots ───

#[test]
fn malformed_utf8_message_content() {
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "".to_string(),
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut blob = events::encode_event(&msg).unwrap();
    let content_start = fixed_layout::message_offsets::CONTENT;
    blob[content_start] = 0xFF; // invalid UTF-8 lead byte
    blob[content_start + 1] = 0xFE;
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

#[test]
fn malformed_utf8_reaction_emoji() {
    let rxn = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 100,
        target_event_id: [0u8; 32],
        author_id: [0u8; 32],
        emoji: "".to_string(),
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut blob = events::encode_event(&rxn).unwrap();
    let emoji_start = fixed_layout::reaction_offsets::EMOJI;
    blob[emoji_start] = 0xFF;
    blob[emoji_start + 1] = 0xFE;
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::TextSlot(_)));
}

// ─── Negative parse tests: wrong type code ───

#[test]
fn wrong_type_code_message() {
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "".to_string(),
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    let mut blob = events::encode_event(&msg).unwrap();
    blob[0] = 99; // wrong type
    let err = events::parse_event(&blob).unwrap_err();
    assert!(matches!(err, EventError::UnknownType(99)));
}

// ─── Negative parse tests: encrypted with unknown inner type ───

#[test]
fn encrypted_unknown_inner_type_code() {
    // Build raw blob with inner_type_code=200 (unknown)
    let header_size = fixed_layout::ENCRYPTED_HEADER_BYTES;
    // Minimal: just enough for the parser to read the header and reject
    let mut buf = vec![0u8; header_size + 1]; // +1 so TooShort isn't the error
    buf[0] = 5; // EVENT_TYPE_ENCRYPTED
    buf[41] = 200; // unknown inner_type_code
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
        ciphertext: vec![0u8; 1024], // not canonical 262144
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    assert!(events::encode_event(&fs).is_err());
}

// ─── Negative parse tests: content too long for text slots ───

#[test]
fn message_content_too_long() {
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "x".repeat(1025), // 1025 > 1024
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    assert!(events::encode_event(&msg).is_err());
}

#[test]
fn reaction_emoji_too_long() {
    let rxn = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 100,
        target_event_id: [0u8; 32],
        author_id: [0u8; 32],
        emoji: "x".repeat(65), // 65 > 64
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    assert!(events::encode_event(&rxn).is_err());
}

#[test]
fn attachment_filename_too_long() {
    let att = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
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
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    assert!(events::encode_event(&att).is_err());
}

#[test]
fn attachment_mime_too_long() {
    let att = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
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
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    });
    assert!(events::encode_event(&att).is_err());
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
    assert_idempotent(&ParsedEvent::Message(MessageEvent {
        created_at_ms: 1234567890123,
        workspace_id: [1u8; 32],
        author_id: [2u8; 32],
        content: "Hello, world!".to_string(),
        signed_by: [3u8; 32],
        signer_type: 5,
        signature: [4u8; 64],
    }));
}

#[test]
fn idempotent_message_empty_content() {
    assert_idempotent(&ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "".to_string(),
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    }));
}

#[test]
fn idempotent_message_max_content() {
    assert_idempotent(&ParsedEvent::Message(MessageEvent {
        created_at_ms: 100,
        workspace_id: [0u8; 32],
        author_id: [0u8; 32],
        content: "x".repeat(1024),
        signed_by: [0u8; 32],
        signer_type: 5,
        signature: [0u8; 64],
    }));
}

#[test]
fn idempotent_reaction() {
    assert_idempotent(&ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: 200,
        target_event_id: [5u8; 32],
        author_id: [6u8; 32],
        emoji: "\u{1f44d}".to_string(),
        signed_by: [7u8; 32],
        signer_type: 5,
        signature: [8u8; 64],
    }));
}

#[test]
fn idempotent_signed_memo() {
    assert_idempotent(&ParsedEvent::SignedMemo(SignedMemoEvent {
        created_at_ms: 300,
        signed_by: [9u8; 32],
        signer_type: 5,
        content: "memo content".to_string(),
        signature: [10u8; 64],
    }));
}

#[test]
fn idempotent_encrypted() {
    let ct_size = fixed_layout::encrypted_inner_wire_size(1).unwrap();
    assert_idempotent(&ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: 400,
        key_event_id: [11u8; 32],
        inner_type_code: 1,
        nonce: [12u8; 12],
        ciphertext: vec![13u8; ct_size],
        auth_tag: [14u8; 16],
    }));
}

#[test]
fn idempotent_message_attachment() {
    assert_idempotent(&ParsedEvent::MessageAttachment(MessageAttachmentEvent {
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
        signed_by: [19u8; 32],
        signer_type: 5,
        signature: [20u8; 64],
    }));
}

#[test]
fn idempotent_file_slice() {
    assert_idempotent(&ParsedEvent::FileSlice(FileSliceEvent {
        created_at_ms: 600,
        file_id: [21u8; 32],
        slice_number: 42,
        ciphertext: vec![22u8; fixed_layout::FILE_SLICE_CIPHERTEXT_BYTES],
        signed_by: [23u8; 32],
        signer_type: 5,
        signature: [24u8; 64],
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
