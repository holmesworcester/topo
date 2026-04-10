# Runtime Check Catalog

Machine-readable catalog of runtime validation checks, their source locations,
and TLA+ guard mappings. Every check_id must map to a tla_guard_id or carry
an explicit `NON_MODELED::<reason>` waiver.

## Projector-Local Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_WS_TRUST_ANCHOR_BLOCK | state/projection/queries::decide_workspace_context_plan | InvWorkspaceAnchor | projector_context |
| CHK_WS_TRUST_ANCHOR_MISMATCH | state/projection/queries::decide_workspace_context_plan | InvForeignWorkspaceExcluded | projector_context |
| CHK_WS_TRUST_ANCHOR_AMBIGUOUS | state/projection/queries::normalize_workspace_acceptance | InvForeignWorkspaceExcluded | projection_read_model |
| CHK_WS_INSERT | event_modules/workspace::project_pure | InvSingleWorkspace | projector_local |
| CHK_IA_TRUST_ANCHOR_WRITE | event_modules/invite_accepted::project_pure | InvTrustAnchorImmutable | projector_local |
| CHK_IA_TRUST_ANCHOR_CONFLICT | state/db/store::lookup_workspace_id | InvTrustAnchorImmutable | projection_read_model |
| CHK_IA_WINNER_ORDER | state/db/store::lookup_workspace_id | InvTrustAnchorImmutable | projection_read_model |
| CHK_IA_RETRY_GUARDS | event_modules/invite_accepted::project_pure | InvWorkspaceAnchor | projector_local |
| CHK_IA_BOOTSTRAP_TRUST | event_modules/invite_accepted::project_pure | InvBootstrapTrustSource | projector_local |
| CHK_MSG_SIGNER_USER_MISMATCH | state/projection/queries::decide_content_authority_plan + event_modules/message::build_projector_context | InvSigner | projector_context |
| CHK_MSG_OUTER_OWNER_ABSENT | event_modules/message::project_pure | NON_MODELED::encrypted_owner_wrapper | projector_local |
| CHK_MSG_DELETE_BEFORE_CREATE | event_modules/message::project_pure | InvDeleteIntentNoLiveMessage | projector_local |
| CHK_MSG_HARD_PURGE | event_modules/message::project_pure | InvDeletePurgeAtomic | projector_local |
| CHK_MSG_INSERT | event_modules/message::project_pure | InvMessageWorkspace | projector_local |
| CHK_FILE_HARD_PURGE | projection/apply/stages::load_context_with_prereqs + apply_projection_frame | InvDeletedMessagePurgesLiveGraph | pipeline_shared |
| CHK_FILE_OWNER_MATCH | event_modules/file::project_pure | NON_MODELED::encrypted_owner_wrapper | projector_local |
| CHK_RXN_SIGNER_USER_MISMATCH | state/projection/queries::decide_content_authority_plan + event_modules/reaction::build_projector_context | InvSigner | projector_context |
| CHK_RXN_SKIP_DELETED | projection/apply/stages::load_context_with_prereqs + apply_projection_frame | InvDeletedMessagePurgesLiveGraph | pipeline_shared |
| CHK_RXN_HARD_PURGE | projection/apply/stages::load_context_with_prereqs + apply_projection_frame | InvDeletedMessagePurgesLiveGraph | pipeline_shared |
| CHK_RXN_OWNER_MATCH | event_modules/reaction::project_pure | NON_MODELED::encrypted_owner_wrapper | projector_local |
| CHK_RXN_INSERT | event_modules/reaction::project_pure | InvDeps | projector_local |
| CHK_DEL_SIGNER_AUTH | state/projection/queries::decide_deletion_signer_plan + event_modules/message_deletion::build_projector_context | InvSigner | projector_context |
| CHK_DEL_OUTER_OWNER_ABSENT | event_modules/message_deletion::project_pure | NON_MODELED::encrypted_owner_wrapper | projector_local |
| CHK_DEL_NON_MESSAGE | event_modules/message_deletion::project_pure | NON_MODELED::type_constraint | projector_local |
| CHK_DEL_WRONG_AUTHOR | event_modules/message_deletion::project_pure | NON_MODELED::author_constraint | projector_local |
| CHK_DEL_INTENT | event_modules/message_deletion::project_pure | InvDeleteIntentSource | projector_local |
| CHK_DEL_TOMBSTONE | event_modules/message_deletion::project_pure | InvDeletedMessageSource | projector_local |
| CHK_DEL_IDEMPOTENT | event_modules/message_deletion::project_pure | NON_MODELED::idempotent_replay | projector_local |
| CHK_DEL_HARD_PURGE | event_modules/message_deletion::project_pure | InvDeletePurgeAtomic | projector_local |
| CHK_SS_INSERT | event_modules/secret_shared::project_pure | InvSecretSharedKey | projector_local |
| CHK_KR_INSERT | event_modules/key_request::project_pure | NON_MODELED::repair_request_primitive | projector_local |
| CHK_KR_TARGET_BINDING | event_modules/key_request::project_pure | NON_MODELED::repair_target_binding | projector_local |
| CHK_KS_TARGET_BINDING | event_modules/key_shared::project_pure | NON_MODELED::repair_target_binding | projector_local |
| CHK_KS_FRONTIER_HASH | event_modules/key_shared::project_pure | NON_MODELED::repair_response_frontier_hash | projector_local |
| CHK_KS_FRONTIER_ORDER | event_modules/key_shared::project_pure | NON_MODELED::repair_response_frontier_canonical_order | projector_local |
| CHK_RM_SIGNER_BINDING | event_modules/removal::project_pure | NON_MODELED::remover_self_binding | projector_local |
| CHK_RM_FRONTIER_HASH | event_modules/removal::project_pure | NON_MODELED::removal_frontier_hash | projector_local |
| CHK_RM_FRONTIER_ORDER | event_modules/removal::project_pure | NON_MODELED::removal_frontier_canonical_order | projector_local |
| CHK_KROT_SIGNER_BINDING | event_modules/key_rotation::project_pure | NON_MODELED::rotation_self_binding | projector_local |
| CHK_KROT_FRONTIER_HASH | event_modules/key_rotation::project_pure | NON_MODELED::rotation_frontier_hash | projector_local |
| CHK_KROT_FRONTIER_ORDER | event_modules/key_rotation::project_pure | NON_MODELED::rotation_frontier_canonical_order | projector_local |
| CHK_FS_DEP_BLOCK | event_modules/file_slice::project_pure | InvFileSliceAuth | projector_local |
| CHK_FS_HARD_PURGE | event_modules/file_slice::build_projector_context | InvDeletedFilePurgesLiveSlice | projector_local |
| CHK_FS_OWNER_MATCH | event_modules/file_slice::project_pure | NON_MODELED::encrypted_owner_wrapper | projector_local |
| CHK_FS_SIGNER_MISMATCH | event_modules/file_slice::project_pure | InvFileSliceAuth | projector_local |
| CHK_FS_SLOT_CONFLICT | event_modules/file_slice::project_pure | NON_MODELED::slot_uniqueness | projector_local |
| CHK_FS_IDEMPOTENT | event_modules/file_slice::project_pure | NON_MODELED::idempotent_replay | projector_local |
| CHK_FS_INSERT | event_modules/file_slice::project_pure | InvFileSliceAuth | projector_local |
| CHK_MA_INSERT | event_modules/file::project_pure | InvDeps | projector_local |
| CHK_UI_INSERT | event_modules/user_invite::project_pure | InvUserInviteChain | projector_local |
| CHK_UI_AUTHORITY | event_modules/user_invite::project_pure + build_projector_context | InvUserInviteChain | projector_local |
| CHK_UI_PENDING_TRUST | event_modules/user_invite::project_pure | InvPendingTrustOnlyOnInviter | projector_local |
| CHK_UI_PENDING_BOOTSTRAP_SRC | event_modules/user_invite::project_pure | InvPendingBootstrapTrustSource | projector_local |
| CHK_DI_INSERT | event_modules/device_invite::project_pure | InvDeviceInviteChain | projector_local |
| CHK_DI_AUTHORITY | event_modules/device_invite::project_pure + build_projector_context | InvDeviceInviteChain | projector_local |
| CHK_DI_PENDING_TRUST | event_modules/device_invite::project_pure | InvPendingTrustOnlyOnInviter | projector_local |
| CHK_DI_PENDING_BOOTSTRAP_SRC | event_modules/device_invite::project_pure | InvPendingBootstrapTrustSource | projector_local |
| CHK_USR_INSERT | event_modules/user::project_pure | InvDeps | projector_local |
| CHK_PS_INSERT | event_modules/peer_shared::project_pure | InvPeerSharedTrustSource | projector_local |
| CHK_PS_AUTHORIZED_USER | event_modules/peer_shared::build_projector_context | InvDeviceInviteChain | projector_local |
| CHK_PS_MATCH_CARRIED | event_modules/peer_shared::project_pure | InvPeerSharedTrustMatchesCarried | projector_local |
| CHK_PS_SUPERSEDE | state/db/transport_trust::consume_bootstrap_for_peer_shared | InvBootstrapConsumedByPeerShared | transport_credential |
| CHK_ADM_INSERT | event_modules/admin::project_pure | InvAdminChain | projector_local |
| CHK_ADM_MATCH_USER_KEY | state/projection/queries::decide_admin_authority_plan + event_modules/admin::build_projector_context | InvAdminChain | projector_context |
| CHK_SK_INSERT | event_modules/secret_key::project_pure | InvEncryptedKey | projector_local |
| CHK_BD_NOOP | event_modules/bench_dep::project_pure | NON_MODELED::benchmark_only | projector_local |
| CHK_IA_ANCHOR_SOURCE | event_modules/invite_accepted::project_pure | InvTrustAnchorSource | projector_local |
| CHK_IA_LINK_WORKSPACE_MATCH | event_modules/invite_accepted::build_projector_context | InvInviteAcceptedLinkWorkspace | projector_local |
| CHK_PS_BOOTSTRAP_TRUST_CONSUME | state/db/transport_trust::consume_bootstrap_for_peer_shared | InvBootstrapTrustConsumedByPeerShared | transport_credential |
| CHK_PS_PENDING_CONSUME | state/db/transport_trust::consume_bootstrap_for_peer_shared | InvPendingConsumedByPeerShared | transport_credential |
| CHK_PS_PENDING_BOOTSTRAP_CONSUME | state/db/transport_trust::consume_bootstrap_for_peer_shared | InvPendingBootstrapTrustConsumedByPeerShared | transport_credential |
| CHK_UI_PENDING_SOURCE | event_modules/user_invite::project_pure | InvPendingBootstrapTrustSource | projector_local |
| CHK_ES_INSERT | event_modules/endpoint_secret::project_pure | NON_MODELED::local_endpoint_root | projector_local |
| CHK_ES_SCOPE_MATCH | event_modules/endpoint_secret::project_pure | NON_MODELED::endpoint_scope_match | projector_local |
| CHK_EPS_INSERT | event_modules/endpoint_shared::project_pure | NON_MODELED::shared_endpoint_projection | projector_local |
| CHK_EPS_SCOPE_MATCH | event_modules/endpoint_shared::project_pure | NON_MODELED::endpoint_shared_scope_match | projector_local |
| CHK_EPS_SELF_SIG | event_modules/endpoint_shared::project_pure | NON_MODELED::endpoint_shared_self_auth | projector_local |

## Wire Validation Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_UI_SIGNER_FAMILY | event_modules/user_invite::build_projector_context | InvUserInviteChain | projector_local |
| CHK_DI_SIGNER_FAMILY | event_modules/device_invite::build_projector_context | InvDeviceInviteChain | projector_local |
| CHK_PS_SIGNER_FAMILY | event_modules/peer_shared::build_projector_context | InvDeviceInviteChain | projector_local |
| CHK_ADM_SIGNER_FAMILY | state/projection/queries::decide_admin_authority_plan + event_modules/admin::build_projector_context | InvAdminChain | projector_context |

## Pipeline-Shared Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_DEP_PRESENCE | projection/apply/stages::check_deps_and_block | InvDeps | pipeline_shared |
| CHK_DEP_TYPE | state/projection/queries::decide_semantic_type_plan + projection/apply/stages::load_context_with_prereqs | InvDeps | projector_context |
| CHK_FILE_TOMBSTONE_DEP_OK | projection/apply/stages::load_context_with_prereqs + apply_projection_frame | InvAttachmentTombstoneBypass | pipeline_shared |
| CHK_RXN_TOMBSTONE_DEP_OK | projection/apply/stages::load_context_with_prereqs + apply_projection_frame | InvReactionTombstoneBypass | pipeline_shared |
| CHK_SIGNER_RESOLVE | projection/signer::resolve_signer_key | InvSigner | pipeline_shared |
| CHK_SIGNER_VERIFY | projection/apply/stages::apply_projection | InvSigner | pipeline_shared |
| CHK_REJECTION_RECORD | projection/apply/stages::record_rejection | NON_MODELED::durable_rejection | pipeline_shared |
| CHK_PROJECTION_TX_ATOMIC | projection/apply/project_one::project_one | InvDeletePurgeAtomic | pipeline_shared |
| CHK_ENCRYPTED_KEY_RESOLVE | projection/encrypted::project_encrypted | InvEncryptedKey | pipeline_shared |
| CHK_ENCRYPTED_DECRYPT | projection/encrypted::project_encrypted | InvEncryptedKey | pipeline_shared |
| CHK_ENCRYPTED_TYPE_MATCH | projection/encrypted::project_encrypted | NON_MODELED::wire_integrity | pipeline_shared |
| CHK_ENCRYPTED_NESTED | projection/encrypted::project_encrypted | NON_MODELED::structural_prohibition | pipeline_shared |
| CHK_ENCRYPTED_ADMISSIBLE | projection/encrypted::project_encrypted | NON_MODELED::admissibility_gate | pipeline_shared |
| CHK_ENCRYPTED_DEP_OUTER_KEY | projection/apply/stages::load_context_with_prereqs | InvEncryptedKey | pipeline_shared |
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
| CHK_BRIDGE_ONGOING_PREFERENCE | runtime/peering/engine/target_dispatch | BrInv_OngoingPreferred | unified_bridge |
| CHK_BRIDGE_BOOTSTRAP_FALLBACK | runtime/peering/engine/bootstrap_auth + runtime/peering/engine/target_dispatch | BrInv_BootstrapFallbackOnlyWhenNeeded | unified_bridge |
| CHK_BRIDGE_BOOTSTRAP_CTX_DETERMINISM | runtime/peering/engine/bootstrap_auth | BrInv_BootstrapContextDeterministic | unified_bridge |
| CHK_BRIDGE_BOOTSTRAP_PROGRESS | runtime/peering/bootstrap + sync loops | BrLive_BootstrapConnectEventually | unified_bridge |
| CHK_BRIDGE_UPGRADE_PROGRESS | runtime/peering/loops/connect | BrLive_PeerUpgradeEventually | unified_bridge |
| CHK_BRIDGE_SYNC_COMPLETION_PROGRESS | runtime/sync + projection/apply | BrLive_BootstrapCompletionSyncEventually | unified_bridge |
| CHK_BRIDGE_SEC_CONN_AUTHZ | runtime/transport/authz | BrSec_ConnectionRequiresAuthorization | unified_bridge |
| CHK_BRIDGE_SEC_TRUST_PROVENANCE | projection/trust_store | BrSec_NoTrustWithoutProvenance | unified_bridge |
| CHK_BRIDGE_SEC_PENDING_INVITER_ONLY | event_modules/user_invite + event_modules/device_invite | BrSec_NoPendingTrustOnJoiner | unified_bridge |
| CHK_BRIDGE_SEC_SOURCE_BINDING | runtime/transport + projection/trust_store | BrSec_SourceBindingConsistency | unified_bridge |
| CHK_BRIDGE_SEC_IDENTITY_COLLISION | transport/identity_adapter + transport_creds | BrSec_NoIdentityCollisionInAuthPath | unified_bridge |

## Endpoint Bootstrap Route Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_ENDPOINT_BOOTSTRAP_PROOF_SCOPE | runtime/transport/session_auth | InvBootstrapAdmissionProofScoped | endpoint_bootstrap_route |

## Exact Transport Targeting Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_ETT_INBOUND_EXACT_TARGET | runtime/transport/session_auth + runtime/peering/loops/accept | InvInboundAdmittedAuthorized | exact_transport_targeting |
| CHK_ETT_NO_CROSS_TENANT_FALLBACK | runtime/transport/session_auth + runtime/peering/loops/accept | InvNoCrossTenantFallback | exact_transport_targeting |
| CHK_ETT_OUTBOUND_EXACT_REMOTE | runtime/transport/connection_lifecycle | InvOutboundConnectedAuthorized | exact_transport_targeting |

## Replay/Order Checks

| check_id | owner | tla_guard_id | category |
|----------|-------|-------------|----------|
| CHK_REPLAY_CONVERGENCE | tests/scenario_test + projection/apply/tests | InvDeps | replay_order |
| CHK_REPLAY_IDEMPOTENT | projection/apply/tests | NON_MODELED::idempotent_invariant | replay_order |
| CHK_REPLAY_TERMINAL | projection/apply/tests | NON_MODELED::terminal_stability | replay_order |
| CHK_DEL_TWO_STAGE_CONVERGENCE | projection/apply/tests | NON_MODELED::deletion_convergence | replay_order |
