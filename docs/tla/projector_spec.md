# Projector Spec — TLA+ to Rust Mapping (Frozen)

Changes to this document require TLA+ model re-verification.

## Event Type Registry

| Code | Rust Type | TLA+ Name | Wire Size | Share Scope | Encryptable | Signer Required | Sig Len | Signer Type |
|------|-----------|-----------|-----------|-------------|-------------|-----------------|---------|-------------|
| 1 | Message | Message | 1194B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 2 | Reaction | MessageReaction | 234B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 3 | Retired (code reserved) | Peer (legacy) | — | — | — | — | — | — |
| 4 | Retired (code reserved) | — | — | — | — | — | — | — |
| 5 | Encrypted | Encrypted | 70+inner_size | Shared | No | No | 0 | — |
| 6 | Secret | Secret | 41B | Local | Yes | No | 0 | — |
| 7 | MessageDeletion | MessageDeletion | 170B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 8 | Workspace | Workspace | 105B | Shared | No | No | 0 | — |
| 9 | InviteAccepted | InviteAccepted | 105B | Local | No | No | 0 | — |
| 10 | UserInvite | UserInvite | 202B | Shared | No | Yes | 64 | 1 (workspace) or 5 (peer_shared) |
| 11 | Retired (code reserved) | — | — | — | — | — | — | — |
| 12 | DeviceInvite | DeviceInvite | 170B | Shared | No | Yes | 64 | 4 (user) or 5 (peer_shared) |
| 13 | Retired (code reserved) | — | — | — | — | — | — | — |
| 14 | User | User | 202B | Shared | No | Yes | 64 | 2 (user_invite_shared) |
| 15 | Retired (code reserved) | — | — | — | — | — | — | — |
| 16 | PeerShared | PeerShared | 234B | Shared | No | Yes | 64 | 3 (peer_invite_shared) |
| 17 | Retired (code reserved) | — | — | — | — | — | — | — |
| 18 | Admin | Admin | 170B | Shared | No | Yes | 64 | 1 (workspace) |
| 19 | Retired (code reserved) | — | — | — | — | — | — | — |
| 20 | UserRemoved | UserRemoved | 138B | Shared | No | Yes | 64 | 5 (peer_shared) |
| 21 | PeerRemoved | PeerRemoved | 138B | Shared | No | Yes | 64 | 5 (peer_shared) |
| 22 | SecretShared | SecretShared | 234B | Shared | No | Yes | 64 | 5 (peer_shared) |
| 23 | Peer | Peer | 73B | Local | No | No | 0 | — |
| 24 | MessageAttachment | — | 633B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 25 | FileSlice | — | 262286B | Shared | Yes | Yes | 64 | runtime (1..5) |
| 26 | BenchDep | — | 345B | Shared | No | No | 0 | — |
| 27 | LocalSignerSecret | PeerPrivkey | 74B | Local | No | No | 0 | — |
| 28 | InvitePrivkey | InvitePrivkey | 73B | Local | No | No | 0 | — |
| 29 | Tenant | Tenant | 41B | Local | No | No | 0 | — |

## Signer Type Resolution

| signer_type | Resolves From | Valid Event Type Codes | Key Extraction |
|-------------|--------------|------------------------|----------------|
| 1 | Workspace | 8 | public_key at [9..41] |
| 2 | UserInvite | 10 | public_key at [9..41] |
| 3 | DeviceInvite | 12 | public_key at [9..41] |
| 4 | User | 14 | public_key at [9..41] |
| 5 | PeerShared | 16 | public_key at [9..41] |

## Dependencies (TLA+ RawDeps → Rust dep_field_values)

| Code | TLA+ RawDeps | Rust dep_fields |
|------|-------------|-----------------|
| 1 | {signed_by} | [signed_by] |
| 2 | {target_event_id, signed_by} | [target_event_id, signed_by] |
| 3 | retired (code reserved) | [] |
| 4 | retired (code reserved) | [] |
| 5 | {key_event_id} | [key_event_id] |
| 6 | {} | [] |
| 7 | {target_event_id, signed_by} | [target_event_id, signed_by] |
| 8 | {} | [] |
| 9 | {tenant_event_id} | [tenant_event_id] |
| 10 | {authority_event_id, signed_by} | [authority_event_id, signed_by] |
| 11 | retired (code reserved) | [] |
| 12 | {authority_event_id, signed_by} | [authority_event_id, signed_by] |
| 13 | retired (code reserved) | [] |
| 14 | {signed_by} | [signed_by] |
| 15 | retired (code reserved) | [] |
| 16 | {user_event_id, signed_by} | [user_event_id, signed_by] |
| 17 | retired (code reserved) | [] |
| 18 | {user_event_id, signed_by} | [user_event_id, signed_by] |
| 19 | retired (code reserved) | [] |
| 20 | {target_event_id, signed_by} | [target_event_id, signed_by] |
| 21 | {target_event_id, signed_by} | [target_event_id, signed_by] |
| 22 | {recipient_event_id, unwrap_key_event_id, signed_by} | [recipient_event_id, unwrap_key_event_id, signed_by] (`key_event_id` is integrity-checked at unwrap materialization) |
| 23 | {tenant_event_id} | [tenant_event_id] |
| 24 | {message_id, key_event_id, signed_by} | [message_id, key_event_id, signed_by] |
| 25 | {signed_by} | [signed_by] |
| 26 | {dep_id × 10 slots} | [dep_id × non-zero slots] |
| 27 | {} | [] (local-first signer material; no hard dep) |
| 28 | {invite_event_id} | [invite_event_id] |
| 29 | {} | [] |

## Guards (TLA+ Guard → Rust pipeline check)

| Guard | TLA+ Definition | Rust Check | Applies To |
|-------|----------------|------------|------------|
| TrustAnchorMatch | trustAnchor[p] = WorkspaceEventId(e) | winner(`invites_accepted`) = event.workspace_id; Block if no accepted binding | type 8 (Workspace) |

## Projection Tables

| Code | Projector Function | Projection Table | Special Logic |
|------|-------------------|------------------|---------------|
| 1 | project_message | messages | — |
| 2 | project_reaction | reactions | skip if target deleted |
| 3 | retired (peer_key) | — | rejected as unknown type |
| 4 | retired (type4_legacy) | — | rejected as unknown type |
| 5 | project_encrypted | (dispatches inner) | decrypt → admissibility check → shared dep/signer/dispatch stages |
| 6 | project_secret | secret_keys | — |
| 7 | project_message_deletion | deleted_messages | author auth + cascade |
| 8 | project_workspace | workspaces | TrustAnchorMatch guard |
| 9 | project_invite_accepted | invites_accepted | writes accepted-binding row; emits RetryWorkspaceEvent + WriteAcceptedBootstrapTrust |
| 10 | project_user_invite | user_invites | enforces authority/signer invariants; emits WritePendingBootstrapTrust (gated by is_local_create) |
| 11 | retired (code reserved) | — | rejected as unknown type |
| 12 | project_device_invite | device_invites | enforces authority/signer invariants; emits WritePendingBootstrapTrust (gated by is_local_create) |
| 13 | retired (code reserved) | — | rejected as unknown type |
| 14 | project_user | users | — |
| 15 | retired (code reserved) | — | rejected as unknown type |
| 16 | project_peer_shared | peers_shared | emits SupersedeBootstrapTrust |
| 17 | retired (code reserved) | — | rejected as unknown type |
| 18 | project_admin | admins | — |
| 19 | retired (code reserved) | — | rejected as unknown type |
| 20 | project_user_removed | removed_entities | — |
| 21 | project_peer_removed | removed_entities | — |
| 22 | project_secret_shared | secret_shared | wraps to invite recipient; emits deterministic local `key_secret` on successful unwrap |
| 23 | project_peer | peers_local | local tenant-bound peer identity |
| 24 | project_message_attachment | message_attachments | — |
| 25 | project_file_slice | file_slices | signature verification |
| 26 | (none) | valid_events | dependency benchmark event; no projection table side effects |
| 27 | project_local_signer_secret | local_signer_material | UPSERT by signer_event_id; emits ApplyTransportIdentityIntent for peer_shared signer kind |
| 28 | project_invite_privkey | invite_privkeys | deterministic local invite unwrap key material |
| 29 | project_tenant | tenants | local tenant root identity |

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

### 105B fixed (Workspace, InviteAccepted)
```
Workspace (8):       type_code(1) | created_at_ms(8) | public_key(32) | name(64) = 105B
InviteAccepted (9):  type_code(1) | created_at_ms(8) | tenant_event_id(32) | invite_event_id(32) | workspace_id(32) = 105B
```

### 138B signed (Removal)
```
type_code(1) | created_at_ms(8) | public_key_or_target(32) | signed_by(32) | signer_type(1) | signature(64)  = 138B
```
- Types 20-21: field at [9..41] is target_event_id

### 170B signed (DeviceInvite, Admin)
```
type_code(1) | created_at_ms(8) | public_key(32) | authority_or_user_event_id(32) | signed_by(32) | signer_type(1) | signature(64)  = 170B
```
- Type 12: authority_or_user_event_id = authority_event_id
- Type 18: authority_or_user_event_id = user_event_id (dep)

### 202B signed (UserInvite, User)
```
UserInvite (10): type_code(1) | created_at_ms(8) | public_key(32) | workspace_id(32) | authority_event_id(32) | signed_by(32) | signer_type(1) | signature(64) = 202B
User (14):       type_code(1) | created_at_ms(8) | public_key(32) | username(64) | signed_by(32) | signer_type(1) | signature(64) = 202B
```

### 234B signed (PeerShared, SecretShared)
```
PeerShared (16): type_code(1) | created_at_ms(8) | public_key(32) | user_event_id(32) | device_name(64) | signed_by(32) | signer_type(1) | signature(64) = 234B
SecretShared (22): type_code(1) | created_at_ms(8) | key_event_id(32) | recipient_event_id(32) | unwrap_key_event_id(32) | wrapped_key(32) | signed_by(32) | signer_type(1) | signature(64) = 234B
```
- `SecretShared.key_event_id` is a carried claimed key id; unwrap materialization verifies deterministic local `key_secret` event id equality.
- Recipients unwrap and materialize local `key_secret` events with deterministic event IDs (BLAKE2b of key bytes -> `created_at_ms`), ensuring both parties derive identical `key_event_id` values.

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

### 74B fixed unsigned (LocalSignerSecret)
```
LocalSignerSecret (27): type_code(1) | created_at_ms(8) | signer_event_id(32) | signer_kind(1) | private_key_bytes(32) = 74B
```
- signer_kind: 1=workspace, 2=user, 3=peer_shared
- Dep: none (local-first materialization; transporter install waits for peer_shared projection)
- ShareScope: Local (never shared across peers)
- Projector: UPSERT into local_signer_material (Delete + InsertOrIgnore)
- EmitCommand: ApplyTransportIdentityIntent when signer_kind == 3 (peer_shared)

### Key-wrap dependency model

`key_shared.key_event_id` is a carried claimed key id, not a hard dependency. The key_event_id
field is carried in the wire format but excluded from dep_fields. Validation occurs
at materialization time: when a recipient unwraps the content key, the deterministic
`key_secret` event ID is computed from the plaintext key bytes and compared against
`key_event_id`. Mismatch causes projection rejection for that `key_shared` event.

This means:
- `encrypted` events hard-dep on `key_secret` (key_event_id in dep_fields)
- `key_shared` hard-deps on `recipient_event_id` and `unwrap_key_event_id`
- `key_shared` does NOT hard-dep on `key_secret` (to avoid a self-materialization cycle)
- Out-of-order arrival is handled: key_shared can project before the local
  key_secret exists; encrypted blocks until key_secret is projected

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
| InvTrustAnchorImmutable | test_trust_anchor_immutability: accepted-workspace winner remains earliest `(created_at,event_id)` |
| InvTrustAnchorSource | invite_accepted must be valid for accepted-binding rows to be set |
| InvBootstrapTrustSource | bootstrap transport trust (`invite_bootstrap_trust`) is derived only from valid `invite_accepted` |
| InvBootstrapTrustMatchesCarried | bootstrap trust identity matches invite-carried bootstrap identity fields |
| InvBootstrapTrustConsumedByPeerShared | bootstrap trust is consumed when equivalent PeerShared-derived trust appears |
| InvPendingBootstrapTrustSource | pending bootstrap trust (`pending_invite_bootstrap_trust`) is derived only from recorded invite events |
| InvPendingBootstrapTrustMatchesCarried | pending bootstrap trust identity matches invite-carried pending peer identity fields |
| InvPeerSharedTrustSource | PeerShared-derived trust (`peerSharedTrustPeer`) is set only when a PeerShared event is valid |
| InvPeerSharedTrustMatchesCarried | PeerShared-derived trust identity matches event-derived peer identity |
| InvPendingBootstrapTrustConsumedByPeerShared | pending bootstrap trust is consumed when equivalent PeerShared-derived trust appears |
| InvTrustedPeerSetMembers | `TrustedPeerSet` members come only from PeerShared-derived SPKIs, bootstrap trust, or pending bootstrap trust |
| InvUserInviteChain | test_bootstrap_sequence: User requires UserInvite valid |
| InvDeviceInviteChain | test_bootstrap_sequence: PeerShared requires DeviceInvite valid |
| InvAdminChain | test_bootstrap_sequence: Admin requires User valid |
| InvForeignWorkspaceExcluded | test_foreign_workspace_excluded |
| InvRemovalAdmin | test_removal_enforcement: removal requires admin context |
| InvAllValidRequireWorkspace | test_bootstrap_sequence: non-local events require workspace valid |
| InvMessageWorkspace | Message projection requires workspace (workspace_event_id dep) |
| InvEncryptedKey | Encrypted content requires valid secret dependency |
| InvSecretSharedKey | SecretShared key_event_id must match deterministic unwrapped key_secret event id |
| InvFileSliceAuth | FileSlice and MessageAttachment for the same file must share the same signer |
| InvRemovalExclusion | project_secret_shared: reject if recipient removed |
| InvUserRemovalTransitiveDeny | user_removed transitively denies all peers linked via peers_shared.user_event_id |

### Bootstrap key materialization

When a joiner accepts an invite, the acceptance path unwraps bootstrap content-key material (from the invite link) and materializes local `key_secret` events with deterministic event IDs. The deterministic ID derivation (BLAKE2b of key bytes -> `created_at_ms`) ensures that both inviter and joiner produce matching `key_event_id` values without out-of-band coordination. This enables encrypted events referencing those keys to unblock via normal cascade after key materialization.

The TLA model does not distinguish bootstrap vs runtime SecretShared structurally — both use the same event type with identical dependency semantics (`recipient_event_id` + `unwrap_key_event_id` raw deps, plus `peer_shared` signer). The `key_event_id` field is a non-dependency integrity claim validated at materialization time. The bootstrap/runtime distinction is a key-source detail below the model's abstraction boundary.

## Transport Credential Lifecycle (TransportCredentialLifecycle.tla)

Standalone module modeling runtime SPKI credential and trust-store state transitions.
Current flow is two-step: invite acceptance may install an invite-derived bootstrap
credential first, then projection installs the PeerShared-derived credential.
Arbitrary rotation/revocation is out of scope. Trust sources: PeerShared-derived
SPKIs (steady-state) ∪ invite_bootstrap_trust ∪ pending_invite_bootstrap_trust.
Not an extension of EventGraphSchema — trust-source inputs are nondeterministic,
abstracting over the event graph.

| TLA+ Invariant | Rust Check |
|----------------|------------|
| InvSPKIUniqueness | BLAKE2b-256 collision resistance: no two peers share an SPKI |
| InvBootstrapConsumedByPeerShared | supersede_bootstrap_for_peer_shared (projection-time): bootstrap ∩ PeerShared_SPKIs = {} |
| InvPendingConsumedByPeerShared | supersede_bootstrap_for_peer_shared (projection-time): pending ∩ PeerShared_SPKIs = {} |
| InvTrustSetIsExactUnion | allowed_peers_from_db: UNION of PeerShared_SPKIs, invite_bootstrap_trust, pending_invite_bootstrap_trust |
| InvTrustSourcesWellFormed | All trust table rows contain valid 32-byte SPKI fingerprints |
| InvMutualAuthSymmetry | Mutual CanAuthenticate requires both peers have active credentials |
| InvPendingTrustOnlyOnInviter | is_local_create gate: pending bootstrap trust exists only on invite creator's trust store |
| InvCredentialSourceConsistency | local credential presence/source consistency during bootstrap→PeerShared transition |

## Unified bridge model (UnifiedBridge.tla)

`UnifiedBridge.tla` is the cross-layer integration model binding:
1. event facts (`EF_*`),
2. projection write-intents (`PW_*`),
3. runtime trust/connection outcomes (`RT_*`, `CtxMode`).

The bridge covers trust-source coherence, security invariants, and product-goal
progress properties over bootstrap/upgrade/fallback behavior.

| UnifiedBridge invariant/property | Runtime check / implementation owner |
|----------------------------------|--------------------------------------|
| BrInv_RowToMaterializedExactness | CHK_BRIDGE_ROW_TO_RUNTIME_TRUST (projection/trust_store + runtime/transport) |
| BrInv_PendingOnlyOnInviter | CHK_BRIDGE_PENDING_LOCAL_CREATE (user_invite_shared + peer_invite_shared projectors) |
| BrInv_AllowedPeerMatchesAuthDecision | CHK_BRIDGE_ALLOWED_PEER_AUTH (runtime/transport/authz) |
| BrInv_OngoingPreferred | CHK_BRIDGE_ONGOING_PREFERENCE (runtime/transport/bootstrap_dial_context + connect loop) |
| BrInv_BootstrapFallbackOnlyWhenNeeded | CHK_BRIDGE_BOOTSTRAP_FALLBACK (runtime/transport/bootstrap_dial_context + connect loop) |
| BrInv_BootstrapContextDeterministic | CHK_BRIDGE_BOOTSTRAP_CTX_DETERMINISM (runtime/transport/bootstrap_dial_context + connect loop) |
| BrSec_ConnectionRequiresAuthorization | CHK_BRIDGE_SEC_CONN_AUTHZ |
| BrSec_NoTrustWithoutProvenance | CHK_BRIDGE_SEC_TRUST_PROVENANCE |
| BrSec_NoPendingTrustOnJoiner | CHK_BRIDGE_SEC_PENDING_INVITER_ONLY |
| BrSec_SourceBindingConsistency | CHK_BRIDGE_SEC_SOURCE_BINDING |
| BrSec_RemovalDeniesConnectivity | CHK_BRIDGE_SEC_REMOVAL_DENY |
| BrSec_NoIdentityCollisionInAuthPath | CHK_BRIDGE_SEC_IDENTITY_COLLISION |
| BrLive_BootstrapConnectEventually | CHK_BRIDGE_BOOTSTRAP_PROGRESS |
| BrLive_PeerUpgradeEventually | CHK_BRIDGE_UPGRADE_PROGRESS |
| BrLive_BootstrapCompletionSyncEventually | CHK_BRIDGE_SYNC_COMPLETION_PROGRESS |

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

TLC status (run on 2026-02-17, post-transport-identity-unification):

1. `cd docs/tla && ./tlc event_graph_schema_fast.cfg`:
   - passes (no invariant violations).
   - model aligned with PeerShared-derived trust: `transportKeyCarriedPeer`/`transportKeyTrustPeer`
     renamed to `peerSharedDerivedPeer`/`peerSharedTrustPeer`; invariants renamed accordingly.
2. `cd docs/tla && ./tlc TransportCredentialLifecycle transport_credential_lifecycle_fast.cfg`:
   - passes (no invariant violations).
   - model simplified: rotation/revocation removed (POC single-credential-per-peer),
     `transportKeyTrust` renamed to `peerSharedTrust`.

### collapse-single-tenant per-tenant outbound trust (2026-02-17)

`run_node` now builds per-tenant `workspace_client_config` for outbound connections,
scoping trust to each tenant's `is_peer_allowed`. The TLA+ `CanAuthenticate(p, q)`
already models per-tenant trust, so no model changes are needed. A Rust comment was
added to the `CanAuthenticate` operator documenting the dual trust model
(union inbound, per-tenant outbound). See the table note above for details.

### trust-projection-eventization invite ownership (2026-02-19)

Extended `TransportCredentialLifecycle.tla` with invite ownership tracking to catch
the joiner-side pending trust emission bug. Changes:
- Added `inviteCreator` variable (function from SPKIs to Peers ∪ {None})
- Added `CreateInvite(p, s)` action establishing invite SPKI ownership
- Added `inviteCreator[s] = p` guard on `AddPendingBootstrapTrust`
- Added `InvPendingTrustOnlyOnInviter` invariant

TLC status: correct model passes (11.5M states, 771K distinct, 2 peers / 3 SPKIs).
Buggy model (guard weakened to `inviteCreator[s] # None`) violates invariant in 5 steps:
counterexample shows Bob (joiner) materializing pending trust for Alice's (inviter's) SPKI.

Rust mapping: `is_local_create` field in `ContextSnapshot` (populated from
`recorded_events.source`) gates `WritePendingBootstrapTrust` emission in
UserInvite and DeviceInvite projectors.

### UnifiedBridge integration checks (2026-02-28)

1. `cd docs/tla && ./tlc UnifiedBridge unified_bridge_bug_repro.cfg`
   - fails as expected on `BrInv_LocalInviteProjectsPending`.
2. `cd docs/tla && ./tlc UnifiedBridge unified_bridge_fix_repro.cfg`
   - passes (bridge safety + security invariants).
3. `cd docs/tla && ./tlc UnifiedBridge unified_bridge_progress_fast.cfg`
   - passes (safety + temporal progress properties).
4. `cd docs/tla && ./tlc UnifiedBridge unified_bridge_progress_deep.cfg`
   - passes (expanded deep domain; 10.3M generated / 1.06M distinct / depth 20).
