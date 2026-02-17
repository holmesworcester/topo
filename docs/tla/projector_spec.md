# Projector Spec — TLA+ to Rust Mapping (Frozen)

Changes to this document require TLA+ model re-verification.

## Event Type Registry

| Code | Rust Type | TLA+ Name | Wire Size | Share Scope | Encryptable | Signer Required | Sig Len | Signer Type |
|------|-----------|-----------|-----------|-------------|-------------|-----------------|---------|-------------|
| 1 | Message | Message | 1194B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 2 | Reaction | MessageReaction | 234B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 3 | Retired (code reserved) | Peer (legacy) | — | — | — | — | — | — |
| 4 | SignedMemo | — | 1130B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 5 | Encrypted | Encrypted | 70+inner_size | Shared | No | No | 0 | — |
| 6 | SecretKey | SecretKey | 41B | Local | Yes | No | 0 | — |
| 7 | MessageDeletion | MessageDeletion | 170B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 8 | Workspace | Workspace | 73B | Shared | No | No | 0 | — |
| 9 | InviteAccepted | InviteAccepted | 73B | Local | No | No | 0 | — |
| 10 | UserInviteBoot | UserInviteBoot | 170B | Shared | No | Yes | 64 | 1 (workspace) |
| 11 | UserInviteOngoing | UserInviteOngoing | 170B | Shared | No | Yes | 64 | 5 (peer_shared) |
| 12 | DeviceInviteFirst | DeviceInviteFirst | 138B | Shared | No | Yes | 64 | 4 (user) |
| 13 | DeviceInviteOngoing | DeviceInviteOngoing | 138B | Shared | No | Yes | 64 | 5 (peer_shared) |
| 14 | UserBoot | UserBoot | 138B | Shared | No | Yes | 64 | 2 (user_invite) |
| 15 | UserOngoing | UserOngoing | 138B | Shared | No | Yes | 64 | 2 (user_invite) |
| 16 | PeerSharedFirst | PeerSharedFirst | 138B | Shared | No | Yes | 64 | 3 (device_invite) |
| 17 | PeerSharedOngoing | PeerSharedOngoing | 138B | Shared | No | Yes | 64 | 3 (device_invite) |
| 18 | AdminBoot | AdminBoot | 170B | Shared | No | Yes | 64 | 1 (workspace) |
| 19 | AdminOngoing | AdminOngoing | 170B | Shared | No | Yes | 64 | 5 (peer_shared) |
| 20 | UserRemoved | UserRemoved | 138B | Shared | No | Yes | 64 | 5 (peer_shared) |
| 21 | PeerRemoved | PeerRemoved | 138B | Shared | No | Yes | 64 | 5 (peer_shared) |
| 22 | SecretShared | SecretShared | 202B | Shared | No | Yes | 64 | 5 (peer_shared) |
| 23 | TransportKey | — | 138B | Shared | No | Yes | 64 | runtime (1..5) |
| 24 | MessageAttachment | — | 633B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 25 | FileSlice | — | 262286B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 26 | BenchDep | — | 345B | Shared | No | No | 0 | — |

## Signer Type Resolution

| signer_type | Resolves From | Valid Event Type Codes | Key Extraction |
|-------------|--------------|------------------------|----------------|
| 1 | Workspace | 8 | public_key at [9..41] |
| 2 | UserInvite (Boot/Ongoing) | 10, 11 | public_key at [9..41] |
| 3 | DeviceInvite (First/Ongoing) | 12, 13 | public_key at [9..41] |
| 4 | User (Boot/Ongoing) | 14, 15 | public_key at [9..41] |
| 5 | PeerShared (First/Ongoing) | 16, 17 | public_key at [9..41] |

## Dependencies (TLA+ RawDeps → Rust dep_field_values)

| Code | TLA+ RawDeps | Rust dep_fields |
|------|-------------|-----------------|
| 1 | {signed_by} | [signed_by] |
| 2 | {target_event_id, signed_by} | [target_event_id, signed_by] |
| 3 | {} | [] |
| 4 | {signed_by} | [signed_by] |
| 5 | {key_event_id} | [key_event_id] |
| 6 | {} | [] |
| 7 | {target_event_id, signed_by} | [target_event_id, signed_by] |
| 8 | {} | [] |
| 9 | {} | [] |
| 10 | {signed_by} | [signed_by] (workspace_id is reference, not dep) |
| 11 | {admin_event_id, signed_by} | [admin_event_id, signed_by] |
| 12 | {signed_by} | [signed_by] |
| 13 | {signed_by} | [signed_by] |
| 14 | {signed_by} | [signed_by] |
| 15 | {signed_by} | [signed_by] |
| 16 | {signed_by} | [signed_by] |
| 17 | {signed_by} | [signed_by] |
| 18 | {user_event_id, signed_by} | [user_event_id, signed_by] |
| 19 | {admin_boot_event_id, signed_by} | [admin_boot_event_id, signed_by] |
| 20 | {target_event_id, signed_by} | [target_event_id, signed_by] |
| 21 | {target_event_id, signed_by} | [target_event_id, signed_by] |
| 22 | {key_event_id, recipient_event_id, signed_by} | [key_event_id, recipient_event_id, signed_by] |
| 23 | {signed_by} | [signed_by] |
| 24 | {message_id, key_event_id, signed_by} | [message_id, key_event_id, signed_by] |
| 25 | {signed_by} | [signed_by] |
| 26 | {dep_id × 10 slots} | [dep_id × non-zero slots] |

## Guards (TLA+ Guard → Rust pipeline check)

| Guard | TLA+ Definition | Rust Check | Applies To |
|-------|----------------|------------|------------|
| TrustAnchorMatch | trustAnchor[p] = WorkspaceEventId(e) | trust_anchors.workspace_id = event.workspace_id; Block if no anchor | type 8 (Workspace) |

## Projection Tables

| Code | Projector Function | Projection Table | Special Logic |
|------|-------------------|------------------|---------------|
| 1 | project_message | messages | — |
| 2 | project_reaction | reactions | skip if target deleted |
| 3 | retired (peer_key) | — | rejected as unknown type |
| 4 | project_signed_memo | signed_memos | — |
| 5 | project_encrypted | (dispatches inner) | decrypt → admissibility check → shared dep/signer/dispatch stages |
| 6 | project_secret_key | secret_keys | — |
| 7 | project_message_deletion | deleted_messages | author auth + cascade |
| 8 | project_workspace | workspaces | TrustAnchorMatch guard |
| 9 | project_invite_accepted | invite_accepted | writes trust_anchors (first-write-wins immutable) |
| 10 | project_user_invite | user_invites | — |
| 11 | project_user_invite | user_invites | — |
| 12 | project_device_invite | device_invites | — |
| 13 | project_device_invite | device_invites | — |
| 14 | project_user | users | — |
| 15 | project_user | users | — |
| 16 | project_peer_shared | peers_shared | — |
| 17 | project_peer_shared | peers_shared | — |
| 18 | project_admin | admins | — |
| 19 | project_admin | admins | — |
| 20 | project_user_removed | removed_entities | — |
| 21 | project_peer_removed | removed_entities | — |
| 22 | project_secret_shared | secret_shared | — |
| 23 | project_transport_key | transport_keys | — |
| 24 | project_message_attachment | message_attachments | — |
| 25 | project_file_slice | file_slices | signature verification |
| 26 | (none) | valid_events | dependency benchmark event; no projection table side effects |

## Shared Pipeline Stages

One staged dependency/signer/dispatch engine is reused for both cleartext
outer events and decrypted inner events from encrypted wrappers.

### Shared stages (pipeline.rs)

| Stage | Function | Description |
|-------|----------|-------------|
| Dep presence | `check_deps_and_block` | Check deps against `valid_events`; write `blocked_event_deps` + `blocked_events` rows keyed to caller-provided `event_id_b64` if missing |
| Dep type check | `check_dep_types` | Verify each dep's type code matches registry expectations (cleartext path only; skipped for encrypted inner events whose dep targets may be encrypted wrappers) |
| Signer verify + dispatch | `apply_projection` | Resolve signer key, verify Ed25519 signature, dispatch to per-event projector |
| Rejection recording | `record_rejection` | Write durable rejection to `rejected_events` |

### Cleartext event path (project_one_step)

1. Terminal check (already valid/rejected?)
2. Load blob + parse
3. Dep presence → `check_deps_and_block`
4. Dep type check → `check_dep_types`
5. Signer verify + dispatch → `apply_projection`
6. Write `valid_events`

### Encrypted inner event path (project_encrypted)

Wrapper-specific logic (steps 1-6 below), then shared stages (step 7-8):

1. Secret-key resolve from `secret_keys` table
2. AES-256-GCM decrypt
3. Parse inner event
4. Verify `inner_type_code` consistency
5. Reject nested encryption (inner type = 5)
6. Reject disallowed inner families (identity events, bench_dep)
7. Inner dep presence → `check_deps_and_block` (block rows keyed to **outer** encrypted `event_id`)
8. Inner signer verify + dispatch → `apply_projection` (signing bytes = decrypted plaintext)

Block/reject/valid state is always anchored to the outer encrypted event_id.

## Wire Formats

### 73B fixed (Workspace, InviteAccepted)
```
Workspace (8):       type_code(1) | created_at_ms(8) | public_key(32) | workspace_id(32)  = 73B
InviteAccepted (9):  type_code(1) | created_at_ms(8) | invite_event_id(32) | workspace_id(32)  = 73B
```

### 138B signed (DeviceInvite, User, PeerShared, Removal)
```
type_code(1) | created_at_ms(8) | public_key_or_target(32) | signed_by(32) | signer_type(1) | signature(64)  = 138B
```
- Types 12-17: field at [9..41] is public_key
- Types 20-21: field at [9..41] is target_event_id

### 170B signed (UserInvite, Admin)
```
type_code(1) | created_at_ms(8) | public_key(32) | extra_dep_id(32) | signed_by(32) | signer_type(1) | signature(64)  = 170B
```
- Type 10: extra_dep_id = workspace_id (reference, not a dep)
- Type 11: extra_dep_id = admin_event_id (dep)
- Type 18: extra_dep_id = user_event_id (dep)
- Type 19: extra_dep_id = admin_boot_event_id (dep)

### 202B signed (SecretShared)
```
type_code(1) | created_at_ms(8) | key_event_id(32) | recipient_event_id(32) | wrapped_key(32) | signed_by(32) | signer_type(1) | signature(64)  = 202B
```

### 1194B fixed signed (Message)
```
Message (1): type_code(1) | created_at_ms(8) | workspace_id(32) | author_id(32) | content(1024) | signed_by(32) | signer_type(1) | signature(64) = 1194B
```
- content: fixed 1024-byte UTF-8 slot, zero-padded after text

### 234B fixed signed (Reaction)
```
Reaction (2): type_code(1) | created_at_ms(8) | target_event_id(32) | author_id(32) | emoji(64) | signed_by(32) | signer_type(1) | signature(64) = 234B
```
- emoji: fixed 64-byte UTF-8 slot, zero-padded after text

### 1130B fixed signed (SignedMemo)
```
SignedMemo (4): type_code(1) | created_at_ms(8) | signed_by(32) | signer_type(1) | content(1024) | signature(64) = 1130B
```
- content: fixed 1024-byte UTF-8 slot, zero-padded after text

### 70+inner_size fixed unsigned (Encrypted)
```
Encrypted (5): type_code(1) | created_at_ms(8) | key_event_id(32) | inner_type_code(1) | nonce(12) | ciphertext(inner_wire_size) | auth_tag(16) = 70 + inner_wire_size
```
- ciphertext size is deterministic: equals the fixed wire size of `inner_type_code`
- no `ciphertext_len` field; parser derives size from `inner_type_code` lookup

### 633B fixed signed (MessageAttachment)
```
MessageAttachment (24): type_code(1) | created_at_ms(8) | message_id(32) | file_id(32) | blob_bytes(8) | total_slices(4) | slice_bytes(4) | root_hash(32) | key_event_id(32) | filename(255) | mime_type(128) | signed_by(32) | signer_type(1) | signature(64) = 633B
```
- filename: fixed 255-byte UTF-8 slot, zero-padded after text
- mime_type: fixed 128-byte UTF-8 slot, zero-padded after text

### 262286B fixed signed (FileSlice)
```
FileSlice (25): type_code(1) | created_at_ms(8) | file_id(32) | slice_number(4) | ciphertext(262144) | signed_by(32) | signer_type(1) | signature(64) = 262286B
```
- ciphertext: canonical fixed 262144-byte (256 KiB) slot
- final plaintext chunk is zero-padded before encryption; receiver uses `blob_bytes` from MessageAttachment for truncation

### 345B fixed unsigned (BenchDep)
```
BenchDep (26): type_code(1) | created_at_ms(8) | dep_slots(10 × 32 = 320) | payload(16) = 345B
```
- 10 fixed dep slots; unused slots are all-zeros
- no `dep_count` field; application counts non-zero slots

### Canonical text slot rules
1. UTF-8 required (reject invalid UTF-8 sequences)
2. Zero-padding required: all bytes after the last content byte must be 0x00
3. No non-zero bytes may appear after the first 0x00 byte in a text slot (NUL-terminated, then zero-padded)
4. Encodings are unique: one valid byte representation per logical text content

### Parser canonicalization boundary (TLA+ non-modeled)
The TLA+ models cover event-graph semantics (dependencies, guards, trust transitions).
The following parser-level canonicalization guarantees are enforced in Rust but not modeled in TLA+:
1. Fixed wire sizes per event type (no length-field-controlled boundaries)
2. Zero-padding enforcement on text and dep slots
3. UTF-8 validity for text slots
4. Deterministic ciphertext sizing for encrypted events by `inner_type_code`

## TLA+ Invariants → Rust Test Assertions

| TLA+ Invariant | Rust Test |
|----------------|-----------|
| InvDeps | verify_projection_invariants: all valid events have deps valid |
| InvSigner | Signer verification in apply_projection |
| InvWorkspaceAnchor | test_foreign_workspace_excluded: foreign workspace blocked |
| InvSingleWorkspace | At most one workspace row per peer in workspaces table |
| InvTrustAnchorImmutable | test_bootstrap_sequence: trust anchor is immutable once set; mismatch rejected |
| InvTrustAnchorSource | invite_accepted must be valid for trust anchor to be set |
| InvInviteAcceptedRecorded | invite_accepted can become valid only when invite material is recorded in the same peer scope |
| InvBootstrapTrustSource | bootstrap transport trust (`invite_bootstrap_trust`) is derived only from valid `invite_accepted` |
| InvBootstrapTrustMatchesCarried | bootstrap trust identity matches invite-carried bootstrap identity fields |
| InvBootstrapTrustConsumedByPeerShared | bootstrap trust is consumed when equivalent PeerShared-derived trust appears |
| InvPendingBootstrapTrustSource | pending bootstrap trust (`pending_invite_bootstrap_trust`) is derived only from recorded invite events |
| InvPendingBootstrapTrustMatchesCarried | pending bootstrap trust identity matches invite-carried pending peer identity fields |
| InvTransportKeyTrustSource | (legacy) transport-key trust (`transport_keys`) is derived only from valid `transport_key` events; non-authoritative |
| InvTransportKeyTrustMatchesCarried | (legacy) transport-key trust identity matches transport-key carried identity fields; non-authoritative |
| InvTrustedPeerSetMembers | `TrustedPeerSet` members come only from PeerShared-derived SPKIs, bootstrap trust, or pending bootstrap trust |
| InvUserInviteChain | test_bootstrap_sequence: UserBoot requires UserInviteBoot valid |
| InvDeviceInviteChain | test_bootstrap_sequence: PeerSharedFirst requires DeviceInviteFirst valid |
| InvAdminChain | test_bootstrap_sequence: AdminOngoing requires AdminBoot valid |
| InvForeignWorkspaceExcluded | test_foreign_workspace_excluded |
| InvRemovalAdmin | test_removal_enforcement: removal requires admin context |
| InvAllValidRequireWorkspace | test_bootstrap_sequence: non-local events require workspace valid |
| InvMessageWorkspace | Message projection requires workspace (workspace_event_id dep) |
| InvEncryptedKey | Encrypted content requires valid secret_key dependency |
| InvSecretSharedKey | SecretShared requires valid secret_key dependency |
| InvFileSliceAuth | FileSlice and MessageAttachment for the same file must share the same signer |
| InvRemovalExclusion | project_secret_shared: reject if recipient removed |

## Transport Credential Lifecycle (TransportCredentialLifecycle.tla)

Standalone module modeling runtime SPKI credential and trust-store state transitions.
Not an extension of EventGraphSchema — trust-source inputs are nondeterministic,
abstracting over the event graph.

| TLA+ Invariant | Rust Check |
|----------------|------------|
| InvActiveCredInHistory | load_or_generate_cert: generated cert SPKI tracked in local identity |
| InvRevokedSubsetHistory | Revocation only applies to previously held credentials |
| InvActiveCredNotRevoked | Active cert is never in revoked set |
| InvSPKIUniqueness | BLAKE2b-256 collision resistance: no two peers share an SPKI |
| InvActiveCredGloballyUnique | Each active cert fingerprint is distinct (extract_spki_fingerprint) |
| InvBootstrapConsumedByPeerShared | supersede_accepted_bootstrap_if_steady_trust_exists: bootstrap ∩ PeerShared_SPKIs = {} |
| InvPendingConsumedByPeerShared | supersede_pending_bootstrap_if_steady_trust_exists: pending ∩ PeerShared_SPKIs = {} |
| InvTrustSetIsExactUnion | allowed_peers_from_db: UNION of PeerShared_SPKIs, invite_bootstrap_trust, pending_invite_bootstrap_trust |
| InvTrustSourcesWellFormed | All trust table rows contain valid 32-byte SPKI fingerprints |
| InvRevokedNotInBootstrapTrust | Revoked credentials not trusted via bootstrap paths |
| InvMutualAuthSymmetry | Mutual CanAuthenticate requires both peers have active credentials |

### Multi-tenant trust scoping (collapse-single-tenant, 2026-02-17)

The TLA+ `CanAuthenticate(p, q)` models per-tenant trust: peer `p` admits peer `q`
only if `q`'s active credential is in `TrustedSPKIs(p)`. The Rust implementation
now realizes two distinct trust scopes on the same QUIC endpoint:

- **Inbound (server-side)**: Union trust — accept if ANY local tenant trusts the
  remote. Post-handshake routing determines the correct `recorded_by` tenant.
  (`run_node`: `dynamic_allow` closure iterates all tenant_peer_ids.)

- **Outbound (client-side)**: Per-tenant trust — each `connect_loop` uses a
  `workspace_client_config` that presents only that tenant's cert and verifies
  the remote against only that tenant's `is_peer_allowed`.

The TLA+ model captures the per-tenant semantic (CanAuthenticate is per-peer).
The union inbound gate is a routing optimization that does not weaken the model
invariant: once routed, each sync session operates within a single tenant's trust
boundary. No TLA+ model changes required.

## TLA Verification Notes

### Trust source supersession model drift (2026-02-17)

The TLA+ models (`EventGraphSchema.tla`, `TransportCredentialLifecycle.tla`) still
use `...ConsumedByTransportKey` invariant names and include `TransportKeyTrustSet`
in the `TrustedPeerSet` definition. The Rust implementation and this mapping document
use `...ConsumedByPeerShared` semantics (bootstrap trust is consumed when PeerShared-derived
SPKI trust appears, not transport_key trust). The TLA+ models need updating once the
transport identity architecture is finalized (TODO 11). Until then, the mapping rows
in this document reflect the target/implemented semantics, not the current TLA+ model text.

### collapse-encrypted-inner refactor (2026-02-16)

This refactor collapses duplicated dep/signer/dispatch logic from `encrypted.rs`
into shared pipeline stages without changing event semantics or projection outcomes.
No TLA+ model changes were required because:

1. The TLA+ model (`EventGraphSchema`) specifies *what* projections and guards hold,
   not *how* the Rust pipeline is structured internally.
2. Admissibility, dep checking, signer verification, and dispatch behavior are
   unchanged — only the code path was unified.
3. The `encryptable` metadata field on `EventTypeMeta` centralizes the admissible
   inner type set previously hard-coded in `encrypted.rs`.

TLC status (run on 2026-02-17):

1. `cd docs/tla && ./tlc event_graph_schema_fast.cfg`:
   - fails `InvAllValidRequireWorkspace`.
   - counterexample path includes `transport_key` becoming valid without `workspace` in one-step traces from bootstrap-carried states.
   - trace file emitted under `docs/tla/EventGraphSchema_TTrace_*.tla`.
2. `cd docs/tla && ./tlc TransportCredentialLifecycle transport_credential_lifecycle_fast.cfg`:
   - passes (no invariant violations).

### collapse-single-tenant per-tenant outbound trust (2026-02-17)

`run_node` now builds per-tenant `workspace_client_config` for outbound connections,
scoping trust to each tenant's `is_peer_allowed`. The TLA+ `CanAuthenticate(p, q)`
already models per-tenant trust, so no model changes are needed. A Rust comment was
added to the `CanAuthenticate` operator documenting the dual trust model
(union inbound, per-tenant outbound). See the table note above for details.
