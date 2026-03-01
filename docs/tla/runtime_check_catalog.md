# Runtime Check Catalog

Machine-readable catalog of runtime validation checks, their source locations,
and TLA+ guard mappings. Every check_id must map to a tla_guard_id or carry
an explicit `NON_MODELED::<reason>` waiver.

## Projector-Local Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_WS_TRUST_ANCHOR_BLOCK | event_modules/workspace::project_pure | InvWorkspaceAnchor | projector_local |
| CHK_WS_TRUST_ANCHOR_MISMATCH | event_modules/workspace::project_pure | InvForeignWorkspaceExcluded | projector_local |
| CHK_WS_INSERT | event_modules/workspace::project_pure | InvSingleWorkspace | projector_local |
| CHK_IA_TRUST_ANCHOR_WRITE | event_modules/invite_accepted::project_pure | InvTrustAnchorImmutable | projector_local |
| CHK_IA_TRUST_ANCHOR_CONFLICT | event_modules/invite_accepted::project_pure | InvTrustAnchorImmutable | projector_local |
| CHK_IA_RETRY_GUARDS | event_modules/invite_accepted::project_pure | InvWorkspaceAnchor | projector_local |
| CHK_IA_BOOTSTRAP_TRUST | event_modules/invite_accepted::project_pure | InvBootstrapTrustSource | projector_local |
| CHK_MSG_SIGNER_USER_MISMATCH | event_modules/message::project_pure | InvSigner | projector_local |
| CHK_MSG_DELETE_BEFORE_CREATE | event_modules/message::project_pure | NON_MODELED::convergence_optimization | projector_local |
| CHK_MSG_INSERT | event_modules/message::project_pure | InvMessageWorkspace | projector_local |
| CHK_RXN_SIGNER_USER_MISMATCH | event_modules/reaction::project_pure | InvSigner | projector_local |
| CHK_RXN_SKIP_DELETED | event_modules/reaction::project_pure | NON_MODELED::post_tombstone_skip | projector_local |
| CHK_RXN_INSERT | event_modules/reaction::project_pure | InvDeps | projector_local |
| CHK_DEL_SIGNER_USER_MISMATCH | event_modules/message_deletion::project_pure | InvSigner | projector_local |
| CHK_DEL_NON_MESSAGE | event_modules/message_deletion::project_pure | NON_MODELED::type_constraint | projector_local |
| CHK_DEL_WRONG_AUTHOR | event_modules/message_deletion::project_pure | InvRemovalAdmin | projector_local |
| CHK_DEL_INTENT | event_modules/message_deletion::project_pure | NON_MODELED::convergence_intent | projector_local |
| CHK_DEL_TOMBSTONE | event_modules/message_deletion::project_pure | NON_MODELED::convergence_tombstone | projector_local |
| CHK_DEL_IDEMPOTENT | event_modules/message_deletion::project_pure | NON_MODELED::idempotent_replay | projector_local |
| CHK_SS_RECIPIENT_REMOVED | event_modules/secret_shared::project_pure | InvRemovalExclusion | projector_local |
| CHK_SS_INSERT | event_modules/secret_shared::project_pure | InvSecretSharedKey | projector_local |
| CHK_FS_GUARD_BLOCK | event_modules/file_slice::project_pure | InvFileSliceAuth | projector_local |
| CHK_FS_SIGNER_MISMATCH | event_modules/file_slice::project_pure | InvFileSliceAuth | projector_local |
| CHK_FS_SLOT_CONFLICT | event_modules/file_slice::project_pure | NON_MODELED::slot_uniqueness | projector_local |
| CHK_FS_IDEMPOTENT | event_modules/file_slice::project_pure | NON_MODELED::idempotent_replay | projector_local |
| CHK_FS_INSERT | event_modules/file_slice::project_pure | InvFileSliceAuth | projector_local |
| CHK_MA_INSERT | event_modules/message_attachment::project_pure | InvDeps | projector_local |
| CHK_MA_RETRY_GUARD | event_modules/message_attachment::project_pure | InvFileSliceAuth | projector_local |
| CHK_UI_INSERT | event_modules/user_invite::project_pure | InvUserInviteChain | projector_local |
| CHK_UI_PENDING_TRUST | event_modules/user_invite::project_pure | InvPendingTrustOnlyOnInviter | projector_local |
| CHK_UI_PENDING_BOOTSTRAP_SRC | event_modules/user_invite::project_pure | InvPendingBootstrapTrustSource | projector_local |
| CHK_DI_INSERT | event_modules/device_invite::project_pure | InvDeviceInviteChain | projector_local |
| CHK_DI_PENDING_TRUST | event_modules/device_invite::project_pure | InvPendingTrustOnlyOnInviter | projector_local |
| CHK_DI_PENDING_BOOTSTRAP_SRC | event_modules/device_invite::project_pure | InvPendingBootstrapTrustSource | projector_local |
| CHK_USR_INSERT | event_modules/user::project_pure | InvDeps | projector_local |
| CHK_PS_INSERT | event_modules/peer_shared::project_pure | InvPeerSharedTrustSource | projector_local |
| CHK_PS_SUPERSEDE | event_modules/peer_shared::project_pure | InvBootstrapConsumedByPeerShared | projector_local |
| CHK_ADM_INSERT | event_modules/admin::project_pure | InvAdminChain | projector_local |
| CHK_UR_INSERT | event_modules/user_removed::project_pure | InvRemovalAdmin | projector_local |
| CHK_PR_INSERT | event_modules/peer_removed::project_pure | InvRemovalAdmin | projector_local |
| CHK_SK_INSERT | event_modules/secret_key::project_pure | InvEncryptedKey | projector_local |
| CHK_TK_INSERT | event_modules/transport_key::project_pure | InvPeerSharedTrustMatchesCarried | projector_local |
| CHK_SM_INSERT | event_modules/signed_memo::project_pure | InvDeps | projector_local |
| CHK_BD_NOOP | event_modules/bench_dep::project_pure | NON_MODELED::benchmark_only | projector_local |
| CHK_IA_INVITE_RECORDED | event_modules/invite_accepted::project_pure | NON_MODELED::no_prior_invite_required | projector_local |
| CHK_IA_ANCHOR_SOURCE | event_modules/invite_accepted::project_pure | InvTrustAnchorSource | projector_local |
| CHK_PS_BOOTSTRAP_TRUST_CONSUME | event_modules/peer_shared::project_pure | InvBootstrapTrustConsumedByPeerShared | projector_local |
| CHK_PS_PENDING_CONSUME | event_modules/peer_shared::project_pure | InvPendingConsumedByPeerShared | projector_local |
| CHK_PS_PENDING_BOOTSTRAP_CONSUME | event_modules/peer_shared::project_pure | InvPendingBootstrapTrustConsumedByPeerShared | projector_local |
| CHK_UI_PENDING_SOURCE | event_modules/user_invite::project_pure | InvPendingBootstrapTrustSource | projector_local |
| CHK_SS_TRANSITIVE_DENY | event_modules/secret_shared::project_pure | InvUserRemovalTransitiveDeny | projector_local |

## Pipeline-Shared Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_DEP_PRESENCE | projection/apply/stages::check_deps_and_block | InvDeps | pipeline_shared |
| CHK_DEP_TYPE | projection/apply/stages::check_dep_types | InvDeps | pipeline_shared |
| CHK_SIGNER_RESOLVE | projection/signer::resolve_signer_key | InvSigner | pipeline_shared |
| CHK_SIGNER_VERIFY | projection/apply/stages::apply_projection | InvSigner | pipeline_shared |
| CHK_REJECTION_RECORD | projection/apply/stages::record_rejection | NON_MODELED::durable_rejection | pipeline_shared |
| CHK_ENCRYPTED_KEY_RESOLVE | projection/encrypted::project_encrypted | InvEncryptedKey | pipeline_shared |
| CHK_ENCRYPTED_DECRYPT | projection/encrypted::project_encrypted | InvEncryptedKey | pipeline_shared |
| CHK_ENCRYPTED_TYPE_MATCH | projection/encrypted::project_encrypted | NON_MODELED::wire_integrity | pipeline_shared |
| CHK_ENCRYPTED_NESTED | projection/encrypted::project_encrypted | NON_MODELED::structural_prohibition | pipeline_shared |
| CHK_ENCRYPTED_ADMISSIBLE | projection/encrypted::project_encrypted | NON_MODELED::admissibility_gate | pipeline_shared |
| CHK_ENCRYPTED_DEP_OUTER_KEY | projection/encrypted::project_encrypted | InvEncryptedKey | pipeline_shared |
| CHK_CASCADE_UNBLOCK | projection/apply/cascade::cascade_unblocked | InvDeps | pipeline_shared |
| CHK_DISPATCH_UNKNOWN_TYPE | projection/apply/dispatch::dispatch_pure_projector | NON_MODELED::registry_safety | pipeline_shared |
| CHK_WS_DEP_REQUIRED | projection/apply/stages::check_deps_and_block | InvAllValidRequireWorkspace | pipeline_shared |

## Transport Credential Lifecycle Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_TCL_SPKI_UNIQUE | projection/trust_store | InvSPKIUniqueness | transport_credential |
| CHK_TCL_TRUST_UNION | projection/trust_store | InvTrustSetIsExactUnion | transport_credential |
| CHK_TCL_SOURCES_FORMED | projection/trust_store | InvTrustSourcesWellFormed | transport_credential |
| CHK_TCL_MUTUAL_AUTH | projection/trust_store | InvMutualAuthSymmetry | transport_credential |
| CHK_TCL_TRUSTED_MEMBERS | projection/trust_store | InvTrustedPeerSetMembers | transport_credential |
| CHK_TCL_BOOTSTRAP_MATCH | projection/trust_store | InvBootstrapTrustMatchesCarried | transport_credential |
| CHK_TCL_PENDING_MATCH | projection/trust_store | InvPendingBootstrapTrustMatchesCarried | transport_credential |
| CHK_TCL_CRED_SOURCE_CONSISTENCY | transport/identity_adapter + transport_creds | InvCredentialSourceConsistency | transport_credential |

## Unified Bridge Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_BRIDGE_ROW_TO_RUNTIME_TRUST | projection/trust_store + runtime/transport | BrInv_RowToMaterializedExactness | unified_bridge |
| CHK_BRIDGE_PENDING_LOCAL_CREATE | event_modules/user_invite + event_modules/device_invite | BrInv_PendingOnlyOnInviter | unified_bridge |
| CHK_BRIDGE_ALLOWED_PEER_AUTH | runtime/transport/authz | BrInv_AllowedPeerMatchesAuthDecision | unified_bridge |
| CHK_BRIDGE_ONGOING_PREFERENCE | runtime/transport/bootstrap_dial_context + runtime/peering/loops/connect | BrInv_OngoingPreferred | unified_bridge |
| CHK_BRIDGE_BOOTSTRAP_FALLBACK | runtime/transport/bootstrap_dial_context + runtime/peering/loops/connect | BrInv_BootstrapFallbackOnlyWhenNeeded | unified_bridge |
| CHK_BRIDGE_BOOTSTRAP_CTX_DETERMINISM | runtime/transport/bootstrap_dial_context + runtime/peering/loops/connect | BrInv_BootstrapContextDeterministic | unified_bridge |
| CHK_BRIDGE_BOOTSTRAP_PROGRESS | runtime/peering/bootstrap + sync loops | BrLive_BootstrapConnectEventually | unified_bridge |
| CHK_BRIDGE_UPGRADE_PROGRESS | runtime/peering/loops/connect | BrLive_PeerUpgradeEventually | unified_bridge |
| CHK_BRIDGE_SYNC_COMPLETION_PROGRESS | runtime/sync + projection/apply | BrLive_BootstrapCompletionSyncEventually | unified_bridge |
| CHK_BRIDGE_SEC_CONN_AUTHZ | runtime/transport/authz | BrSec_ConnectionRequiresAuthorization | unified_bridge |
| CHK_BRIDGE_SEC_TRUST_PROVENANCE | projection/trust_store | BrSec_NoTrustWithoutProvenance | unified_bridge |
| CHK_BRIDGE_SEC_PENDING_INVITER_ONLY | event_modules/user_invite + event_modules/device_invite | BrSec_NoPendingTrustOnJoiner | unified_bridge |
| CHK_BRIDGE_SEC_SOURCE_BINDING | runtime/transport + projection/trust_store | BrSec_SourceBindingConsistency | unified_bridge |
| CHK_BRIDGE_SEC_REMOVAL_DENY | event_modules/peer_removed + runtime/transport/authz | BrSec_RemovalDeniesConnectivity | unified_bridge |
| CHK_BRIDGE_SEC_IDENTITY_COLLISION | transport/identity_adapter + transport_creds | BrSec_NoIdentityCollisionInAuthPath | unified_bridge |

## Replay/Order Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_REPLAY_CONVERGENCE | tests/scenario_test + projection/apply/tests | InvDeps | replay_order |
| CHK_REPLAY_IDEMPOTENT | projection/apply/tests | NON_MODELED::idempotent_invariant | replay_order |
| CHK_REPLAY_TERMINAL | projection/apply/tests | NON_MODELED::terminal_stability | replay_order |
| CHK_DEL_TWO_STAGE_CONVERGENCE | projection/apply/tests | NON_MODELED::deletion_convergence | replay_order |
