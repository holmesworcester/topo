# Projector Spec — TLA+ to Rust Mapping (Frozen)

Changes to this document require TLA+ model re-verification.

## Event Type Registry

| Code | Rust Type | TLA+ Name | Wire Size | Share Scope | Encryptable | Signer Required | Sig Len | Signer Type |
|------|-----------|-----------|-----------|-------------|-------------|-----------------|---------|-------------|
| 1 | Message | Message | variable | Shared | Yes | No | 0 | — |
| 2 | Reaction | MessageReaction | variable | Shared | Yes | No | 0 | — |
| 3 | PeerKey | Peer | 41B | Shared | — | No | 0 | — |
| 4 | SignedMemo | — | variable | Shared | Yes | Yes | 64 | 0 (peer) |
| 5 | Encrypted | Encrypted | variable | Shared | No | No | 0 | — |
| 6 | SecretKey | SecretKey | 41B | Local | Yes | No | 0 | — |
| 7 | MessageDeletion | MessageDeletion | 73B | Shared | Yes | No | 0 | — |
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
| 23 | TransportKey | — | 41B | Shared | No | No | 0 | — |
| 24 | MessageAttachment | — | variable | Shared | Yes | No | 0 | — |
| 25 | FileSlice | — | variable | Shared | Yes | Yes | 64 | 5 (peer_shared) |

## Signer Type Resolution

| signer_type | Resolves From | Valid Event Type Codes | Key Extraction |
|-------------|--------------|------------------------|----------------|
| 0 | PeerKey | 3 | public_key at [9..41] |
| 1 | Workspace | 8 | public_key at [9..41] |
| 2 | UserInvite (Boot/Ongoing) | 10, 11 | public_key at [9..41] |
| 3 | DeviceInvite (First/Ongoing) | 12, 13 | public_key at [9..41] |
| 4 | User (Boot/Ongoing) | 14, 15 | public_key at [9..41] |
| 5 | PeerShared (First/Ongoing) | 16, 17 | public_key at [9..41] |

## Dependencies (TLA+ RawDeps → Rust dep_field_values)

| Code | TLA+ RawDeps | Rust dep_fields |
|------|-------------|-----------------|
| 1 | {Workspace} | [workspace_event_id] |
| 2 | {target_event_id} | [target_event_id] |
| 3 | {} | [] |
| 4 | {signed_by} | [signed_by] |
| 5 | {key_event_id} | [key_event_id] |
| 6 | {} | [] |
| 7 | {target_event_id} | [target_event_id] |
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
| 23 | {} | [] |
| 24 | {message_id, key_event_id} | [message_id, key_event_id] |
| 25 | {signed_by} | [signed_by] |

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

### Cleartext event path (project_one_core)

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
| InvBootstrapTrustConsumedByTransportKey | bootstrap trust is consumed when equivalent transport-key trust appears |
| InvPendingBootstrapTrustSource | pending bootstrap trust (`pending_invite_bootstrap_trust`) is derived only from recorded invite events |
| InvPendingBootstrapTrustMatchesCarried | pending bootstrap trust identity matches invite-carried pending peer identity fields |
| InvTransportKeyTrustSource | transport-key trust (`transport_keys`) is derived only from valid `transport_key` events |
| InvTransportKeyTrustMatchesCarried | transport-key trust identity matches transport-key carried identity fields |
| InvTrustedPeerSetMembers | `TrustedPeerSet` members come only from bootstrap trust, pending bootstrap trust, or transport-key trust |
| InvUserInviteChain | test_bootstrap_sequence: UserBoot requires UserInviteBoot valid |
| InvDeviceInviteChain | test_bootstrap_sequence: PeerSharedFirst requires DeviceInviteFirst valid |
| InvAdminChain | test_bootstrap_sequence: AdminOngoing requires AdminBoot valid |
| InvForeignWorkspaceExcluded | test_foreign_workspace_excluded |
| InvRemovalAdmin | test_removal_enforcement: removal requires admin context |
| InvAllValidRequireWorkspace | test_bootstrap_sequence: non-local events require workspace valid |
| InvMessageWorkspace | Message projection requires workspace (workspace_event_id dep) |
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
| InvBootstrapConsumedByTransportKey | supersede_accepted_bootstrap_if_steady_trust_exists: bootstrap ∩ transport_keys = {} |
| InvPendingConsumedByTransportKey | supersede_pending_bootstrap_if_steady_trust_exists: pending ∩ transport_keys = {} |
| InvTrustSetIsExactUnion | allowed_peers_from_db: UNION of transport_keys, invite_bootstrap_trust, pending_invite_bootstrap_trust |
| InvTrustSourcesWellFormed | All trust table rows contain valid 32-byte SPKI fingerprints |
| InvRevokedNotInBootstrapTrust | Revoked credentials not trusted via bootstrap paths |
| InvMutualAuthSymmetry | Mutual CanAuthenticate requires both peers have active credentials |

## TLA Verification Notes

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

TLC model check was not run because `tla2tools.jar` is not present in this worktree.
When the JAR is restored, verify with:
```
cd docs/tla && ./tlc event_graph_schema_fast.cfg
cd docs/tla && ./tlc transport_credential_lifecycle_fast.cfg
```
