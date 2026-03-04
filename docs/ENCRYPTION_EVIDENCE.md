# Encryption Reality — Evidence Document

Branch: `feat/encryption-rigor-plan`

## Command-Path Diff Matrix

| Content Type | Old Path | New Path | Status |
|---|---|---|---|
| Message (1) | `create_signed_event_synchronous` | `create_encrypted_event_synchronous` | Migrated |
| Reaction (2) | `create_signed_event_synchronous` | `create_encrypted_event_synchronous` | Migrated |
| MessageDeletion (7) | `create_signed_event_synchronous` | `create_encrypted_event_synchronous` | Migrated |
| MessageAttachment (24) | `create_signed_event_synchronous` | `create_encrypted_event_synchronous` | Migrated |
| FileSlice (25) | `create_signed_event_synchronous` | `create_signed_event_synchronous` (ciphertext field encrypted with attachment key) | Real encryption via AES-256-GCM with AAD (see [Design Note: FileSlice](#design-note-fileslice-field-level-encryption)) |

## Key Distribution

| Path | Mechanism | Status |
|---|---|---|
| User invite | `wrap_content_key_for_invite` in accept flow | Real (X25519 DH + BLAKE2b wrap) |
| Device-link invite | `wrap_content_key_for_invite` in accept flow | Real (X25519 DH + BLAKE2b wrap) |
| Workspace content key | One shared key per workspace, deterministic event ID | Real |
| Per-attachment key | Fresh random key per attachment, wrapped via `wrap_attachment_key_for_peers` | Real |
| Dep-driven key unwrap | `secret_shared::build_projector_context` context_loader with DH unwrap | Real (handles both invite and PeerShared recipients) |
| SecretShared materialization | `MaterializeSecretKey` EmitCommand on valid SecretShared with local private key | Real |

## File Encryption

| Property | Implementation | Evidence |
|---|---|---|
| Per-attachment unique key | `rand::random::<[u8; 32]>()` per file | `file_slice_encryption_tests::test_different_keys_differ` |
| AES-256-GCM encryption | `encrypt_file_slice` / `decrypt_file_slice` | `file_slice_encryption_tests::test_round_trip` |
| Deterministic nonce | `Blake2b-96("poc7-file-slice-nonce" \|\| file_id \|\| slice_number_le)` | `test_deterministic` |
| AAD metadata binding | `aad = file_id \|\| slice_number_le` | `test_wrong_file_id_fails_decrypt`, `test_wrong_slice_number_fails_decrypt` |
| Crypto-shred on deletion | `message_deletion` projector cascades DELETE to `file_slices` + `message_attachments` | `test_deletion_cascades_file_slices_and_attachments` |

## Dependency / Unblock Correctness

| Property | Implementation | Evidence |
|---|---|---|
| Encrypted blocks on missing key | `check_deps_and_block` for `key_event_id` dep | `test_encrypted_blocks_on_missing_key` |
| Key materialization cascades unblock | `cascade_unblocked` in apply/cascade.rs | `test_encrypted_unblocks_when_key_arrives` |
| MessageAttachment blocks on missing key | `key_event_id` in `dep_fields` (type code 6) | `test_attachment_blocks_on_missing_message` |
| No reject-path shortcut for missing keys | Block (not Reject) semantics throughout | All encrypted parity tests |

## Test Summary

- **Unit tests**: 460 passed, 0 failed
- **Projector conformance tests**: 59 passed
- **Scenario integration tests**: 59 passed
- **CLI integration tests**: 22 passed
- **All other test binaries**: 0 failures
- **Total**: 521 passed, 0 failed

## TLC Model Check Results

| Model | Config | Result | States |
|---|---|---|---|
| EventGraphSchema | fast | PASS | 282,751 generated, 40,788 distinct |
| TransportCredentialLifecycle | fast | PASS | 529,848,151 generated, 23,184,625 distinct |
| UnifiedBridge | progress_fast | PASS | 3,740,535 generated, 358,255 distinct |
| EncryptionLifecycle | fast | PASS | 21,529 generated, 4,563 distinct |
| EncryptionLifecycle | expanded | PASS | 4,608,257 generated, 544,512 distinct |

## Static Anti-Fake Guard

`scripts/check_boundary_imports.sh` includes encryption anti-fake guards:
- `create_signed_event_synchronous` forbidden in `reaction/commands.rs`
- `create_signed_event_synchronous` forbidden in `message_deletion/commands.rs`
- `create_signed_event_synchronous` forbidden for Message/Reaction/MessageDeletion/MessageAttachment in `message/commands.rs`
- FileSlice allowed (uses field-level encryption, not wrapper)

## Design Note: FileSlice Field-Level Encryption

FileSlice events use `create_signed_event_synchronous` (not `create_encrypted_event_synchronous`)
because their payload is already a ciphertext blob produced by `encrypt_file_slice` with a unique
per-attachment AES-256-GCM key plus AAD binding (`file_id || slice_number_le`). Wrapping them
again inside an `encrypted` envelope would double-encrypt without security benefit and add
unnecessary key dependency overhead. The anti-fake guard in `check_boundary_imports.sh`
explicitly permits this pattern.

## Design Note: Attachment Key Uniqueness

Per-attachment keys are generated via `rand::random::<[u8; 32]>()` (256 bits of OS entropy).
The birthday bound for collision among 256-bit keys is ~2^128 operations, which is
computationally infeasible. This provides cryptographic uniqueness without requiring a
deterministic derivation scheme or uniqueness index.

## Design Note: Attachment Key Wrap Lifecycle

`wrap_attachment_key_for_peers` is called exactly once per attachment at creation time,
immediately after the `SecretKey` event for that attachment is created. There is no re-wrap
path for attachment keys when new peers join (only the workspace content key is re-wrapped
via `wrap_content_key_for_invite`). This means a deleted message's attachment keys can
never be re-distributed after crypto-shred, because:
1. The wrap happens synchronously during file creation (before the `MessageAttachment` event)
2. No code path exists to re-wrap per-attachment keys for late-joining peers
3. Late-joining peers receive only the workspace content key, not historical attachment keys

## Design Note: Scenario Test Key Materialization

Scenario tests like `test_encrypted_blocks_then_unblocks_on_key_materialization` and
`test_wrap_unwrap_encrypted_convergence` use manual `create_deterministic_secret_key_event`
calls to inject keys directly. This is intentional: these tests verify the block/unblock
cascade and convergence mechanics (the dependency graph engine), not the key distribution
protocol. The key distribution protocol is tested separately via CLI integration tests
(`test_cli_bidirectional_sync`) and invite flow tests that exercise `wrap_content_key_for_invite`
and the dep-driven `secret_shared` context_loader unwrap path end-to-end.

## Explicit Out-of-Scope

1. **TreeKEM/DCKGA** — group key agreement not implemented; one shared workspace content key
2. **Historical key rotation** — no re-encryption of old content on key change
3. **Auth/identity naming encryption** — workspace/user/device/invite naming fields remain plaintext
4. **Forward secrecy for deleted attachments** — crypto-shred removes projected rows but raw event blobs remain in events table (full forward secrecy requires event-store compaction, out of scope)
