# Projector TLA Conformance Matrix

Machine-readable mapping from TLA+ spec requirements to runtime checks and tests.
Every `spec_id` must have at least one linked test. Guard-level spec_ids require
both `pass` and `break` polarity unless waived.

## EventGraphSchema Invariants

| spec_id | source | check_id | layer | test_id | polarity |
|---------|--------|----------|-------|---------|----------|
| SPEC_DEPS_01 | InvDeps | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_project_message_valid | pass |
| SPEC_DEPS_01 | InvDeps | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_project_reaction_blocked | break |
| SPEC_DEPS_01 | InvDeps | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_multi_dep_event_projects_only_when_all_resolve | break |
| SPEC_DEPS_02 | InvDeps | CHK_DEP_TYPE | pipeline_integration | apply::tests::test_dep_type_mismatch_rejects | break |
| SPEC_DEPS_02 | InvDeps | CHK_DEP_TYPE | pipeline_integration | apply::tests::test_project_signed_memo_valid | pass |
| SPEC_DEPS_03 | InvDeps (cascade) | CHK_CASCADE_UNBLOCK | pipeline_integration | apply::tests::test_project_unblock_cascade | pass |
| SPEC_DEPS_03 | InvDeps (cascade) | CHK_CASCADE_UNBLOCK | pipeline_integration | apply::tests::test_project_reaction_blocked | break |
| SPEC_SIGNER_01 | InvSigner | CHK_SIGNER_RESOLVE | pipeline_integration | apply::tests::test_signed_memo_blocks_on_missing_signer | break |
| SPEC_SIGNER_01 | InvSigner | CHK_SIGNER_RESOLVE | pipeline_integration | apply::tests::test_signed_memo_unblocks_when_signer_arrives | pass |
| SPEC_SIGNER_02 | InvSigner | CHK_SIGNER_VERIFY | pipeline_integration | apply::tests::test_signed_memo_invalid_signature_rejects | break |
| SPEC_SIGNER_02 | InvSigner | CHK_SIGNER_VERIFY | pipeline_integration | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_SIGNER_03 | InvSigner | CHK_SIGNER_RESOLVE | pipeline_integration | apply::tests::test_unsupported_signer_type_rejects | break |
| SPEC_SIGNER_03 | InvSigner | CHK_SIGNER_RESOLVE | pipeline_integration | apply::tests::test_signed_memo_unblocks_when_signer_arrives | pass |
| SPEC_WS_ANCHOR_01 | InvWorkspaceAnchor | CHK_WS_TRUST_ANCHOR_BLOCK | projector_unit | workspace_projector_tests::tests::test_workspace_blocks_without_trust_anchor | break |
| SPEC_WS_ANCHOR_01 | InvWorkspaceAnchor | CHK_WS_TRUST_ANCHOR_BLOCK | projector_unit | workspace_projector_tests::tests::test_workspace_valid_with_matching_anchor | pass |
| SPEC_WS_ANCHOR_02 | InvForeignWorkspaceExcluded | CHK_WS_TRUST_ANCHOR_MISMATCH | projector_unit | workspace_projector_tests::tests::test_workspace_rejects_anchor_mismatch | break |
| SPEC_WS_ANCHOR_02 | InvForeignWorkspaceExcluded | CHK_WS_TRUST_ANCHOR_MISMATCH | pipeline_integration | apply::tests::test_invite_accepted_guard_retry_on_workspace | pass |
| SPEC_WS_SINGLE_01 | InvSingleWorkspace | CHK_WS_INSERT | projector_unit | workspace_projector_tests::tests::test_workspace_insert_or_ignore | pass |
| SPEC_WS_SINGLE_01 | InvSingleWorkspace | CHK_WS_INSERT | projector_unit | workspace_projector_tests::tests::test_workspace_rejects_anchor_mismatch | break |
| SPEC_ANCHOR_IMMUTABLE_01 | InvTrustAnchorImmutable | CHK_IA_TRUST_ANCHOR_WRITE | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_trust_anchor | pass |
| SPEC_ANCHOR_IMMUTABLE_01 | InvTrustAnchorImmutable | CHK_IA_TRUST_ANCHOR_CONFLICT | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_rejects_anchor_conflict | break |
| SPEC_ANCHOR_SOURCE_01 | InvTrustAnchorSource | CHK_IA_TRUST_ANCHOR_WRITE | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_trust_anchor | pass |
| SPEC_ANCHOR_SOURCE_01 | InvTrustAnchorSource | CHK_WS_TRUST_ANCHOR_BLOCK | projector_unit | workspace_projector_tests::tests::test_workspace_blocks_without_trust_anchor | break |
| SPEC_BOOTSTRAP_TRUST_01 | InvBootstrapTrustSource | CHK_IA_BOOTSTRAP_TRUST | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_emits_bootstrap_trust | pass |
| SPEC_BOOTSTRAP_TRUST_01 | InvBootstrapTrustSource | CHK_IA_BOOTSTRAP_TRUST | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_no_bootstrap_without_context | break |
| SPEC_BOOTSTRAP_CONSUMED_01 | InvBootstrapTrustConsumedByPeerShared | CHK_PS_SUPERSEDE | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_emits_supersede | pass |
| SPEC_BOOTSTRAP_CONSUMED_01 | InvBootstrapTrustConsumedByPeerShared | CHK_PS_SUPERSEDE | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_ongoing_also_emits_supersede | break |
| SPEC_PENDING_TRUST_01 | InvPendingBootstrapTrustSource | CHK_UI_PENDING_BOOTSTRAP_SRC | projector_unit | user_invite_projector_tests::tests::test_user_invite_boot_emits_pending_trust | pass |
| SPEC_PENDING_TRUST_01 | InvPendingBootstrapTrustSource | CHK_UI_PENDING_BOOTSTRAP_SRC | projector_unit | user_invite_projector_tests::tests::test_user_invite_ongoing_no_pending_trust | break |
| SPEC_PENDING_TRUST_02 | InvPendingBootstrapTrustSource | CHK_DI_PENDING_BOOTSTRAP_SRC | projector_unit | device_invite_projector_tests::tests::test_device_invite_first_emits_pending_trust | pass |
| SPEC_PENDING_TRUST_02 | InvPendingBootstrapTrustSource | CHK_DI_PENDING_BOOTSTRAP_SRC | projector_unit | device_invite_projector_tests::tests::test_device_invite_ongoing_no_pending_trust | break |
| SPEC_PENDING_INVITER_01 | InvPendingTrustOnlyOnInviter | CHK_UI_PENDING_TRUST | projector_unit | user_invite_projector_tests::tests::test_user_invite_no_pending_when_not_local | break |
| SPEC_PENDING_INVITER_01 | InvPendingTrustOnlyOnInviter | CHK_UI_PENDING_TRUST | projector_unit | user_invite_projector_tests::tests::test_user_invite_boot_emits_pending_trust | pass |
| SPEC_PENDING_INVITER_02 | InvPendingTrustOnlyOnInviter | CHK_DI_PENDING_TRUST | projector_unit | device_invite_projector_tests::tests::test_device_invite_no_pending_when_not_local | break |
| SPEC_PENDING_INVITER_02 | InvPendingTrustOnlyOnInviter | CHK_DI_PENDING_TRUST | projector_unit | device_invite_projector_tests::tests::test_device_invite_first_emits_pending_trust | pass |
| SPEC_PEER_SHARED_TRUST_01 | InvPeerSharedTrustSource | CHK_PS_INSERT | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_writes_row | pass |
| SPEC_PEER_SHARED_TRUST_01 | InvPeerSharedTrustSource | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_project_reaction_blocked | break |
| SPEC_PEER_SHARED_TRUST_02 | InvPeerSharedTrustMatchesCarried | CHK_PS_INSERT | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_writes_correct_fields | pass |
| SPEC_PEER_SHARED_TRUST_02 | InvPeerSharedTrustMatchesCarried | CHK_PS_INSERT | projector_unit | — | waiver:structural_copy |
| SPEC_PENDING_CONSUMED_01 | InvPendingBootstrapTrustConsumedByPeerShared | CHK_PS_SUPERSEDE | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_emits_supersede | pass |
| SPEC_PENDING_CONSUMED_01 | InvPendingBootstrapTrustConsumedByPeerShared | CHK_PS_SUPERSEDE | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_ongoing_also_emits_supersede | break |
| SPEC_INVITE_CHAIN_01 | InvUserInviteChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_INVITE_CHAIN_01 | InvUserInviteChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_signed_memo_blocks_on_missing_signer | break |
| SPEC_DEVICE_CHAIN_01 | InvDeviceInviteChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_DEVICE_CHAIN_01 | InvDeviceInviteChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_signed_memo_blocks_on_missing_signer | break |
| SPEC_ADMIN_CHAIN_01 | InvAdminChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_ADMIN_CHAIN_01 | InvAdminChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_signed_memo_blocks_on_missing_signer | break |
| SPEC_REMOVAL_ADMIN_01 | InvRemovalAdmin | CHK_UR_INSERT | projector_unit | simple_projector_tests::tests::test_user_removed_writes_row | pass |
| SPEC_REMOVAL_ADMIN_01 | InvRemovalAdmin | CHK_PR_INSERT | projector_unit | simple_projector_tests::tests::test_peer_removed_writes_row | pass |
| SPEC_REMOVAL_ADMIN_01 | InvRemovalAdmin | CHK_SIGNER_VERIFY | pipeline_integration | apply::tests::test_signed_memo_invalid_signature_rejects | break |
| SPEC_REMOVAL_EXCLUSION_01 | InvRemovalExclusion | CHK_SS_RECIPIENT_REMOVED | projector_unit | secret_shared_projector_tests::tests::test_secret_shared_rejects_removed_recipient | break |
| SPEC_REMOVAL_EXCLUSION_01 | InvRemovalExclusion | CHK_SS_RECIPIENT_REMOVED | projector_unit | secret_shared_projector_tests::tests::test_secret_shared_valid | pass |
| SPEC_MSG_WORKSPACE_01 | InvMessageWorkspace | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_project_message_valid | pass |
| SPEC_MSG_WORKSPACE_01 | InvMessageWorkspace | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::test_project_reaction_blocked | break |
| SPEC_MSG_SIGNER_01 | InvSigner (message) | CHK_MSG_SIGNER_USER_MISMATCH | projector_unit | message_projector_tests::tests::test_message_rejects_signer_user_mismatch | break |
| SPEC_MSG_SIGNER_01 | InvSigner (message) | CHK_MSG_SIGNER_USER_MISMATCH | projector_unit | message_projector_tests::tests::test_message_valid | pass |
| SPEC_ENCRYPTED_KEY_01 | InvEncryptedKey | CHK_ENCRYPTED_KEY_RESOLVE | pipeline_integration | apply::tests::test_encrypted_blocks_on_missing_key | break |
| SPEC_ENCRYPTED_KEY_01 | InvEncryptedKey | CHK_ENCRYPTED_KEY_RESOLVE | pipeline_integration | apply::tests::test_encrypted_message_valid | pass |
| SPEC_ENCRYPTED_DECRYPT_01 | InvEncryptedKey | CHK_ENCRYPTED_DECRYPT | pipeline_integration | apply::tests::test_encrypted_wrong_key_rejects | break |
| SPEC_ENCRYPTED_DECRYPT_01 | InvEncryptedKey | CHK_ENCRYPTED_DECRYPT | pipeline_integration | apply::tests::test_encrypted_message_valid | pass |
| SPEC_ENCRYPTED_TYPE_01 | (wire integrity) | CHK_ENCRYPTED_TYPE_MATCH | pipeline_integration | apply::tests::test_encrypted_inner_type_mismatch_rejects | break |
| SPEC_ENCRYPTED_TYPE_01 | (wire integrity) | CHK_ENCRYPTED_TYPE_MATCH | pipeline_integration | apply::tests::test_encrypted_message_valid | pass |
| SPEC_ENCRYPTED_NESTED_01 | (structural) | CHK_ENCRYPTED_NESTED | pipeline_integration | apply::tests::test_encrypted_nested_rejects | break |
| SPEC_ENCRYPTED_NESTED_01 | (structural) | CHK_ENCRYPTED_NESTED | pipeline_integration | apply::tests::test_encrypted_message_valid | pass |
| SPEC_ENCRYPTED_ADMISSIBLE_01 | (admissibility) | CHK_ENCRYPTED_ADMISSIBLE | pipeline_integration | apply::tests::test_encrypted_identity_event_rejects | break |
| SPEC_ENCRYPTED_ADMISSIBLE_01 | (admissibility) | CHK_ENCRYPTED_ADMISSIBLE | pipeline_integration | apply::tests::test_encrypted_message_valid | pass |
| SPEC_SECRET_SHARED_KEY_01 | InvSecretSharedKey | CHK_SS_INSERT | projector_unit | secret_shared_projector_tests::tests::test_secret_shared_valid | pass |
| SPEC_SECRET_SHARED_KEY_01 | InvSecretSharedKey | CHK_SS_RECIPIENT_REMOVED | projector_unit | secret_shared_projector_tests::tests::test_secret_shared_rejects_removed_recipient | break |
| SPEC_FILE_AUTH_01 | InvFileSliceAuth | CHK_FS_GUARD_BLOCK | projector_unit | file_slice_projector_tests::tests::test_file_slice_blocks_no_descriptor | break |
| SPEC_FILE_AUTH_01 | InvFileSliceAuth | CHK_FS_INSERT | projector_unit | file_slice_projector_tests::tests::test_file_slice_valid | pass |
| SPEC_FILE_AUTH_02 | InvFileSliceAuth | CHK_FS_SIGNER_MISMATCH | projector_unit | file_slice_projector_tests::tests::test_file_slice_rejects_signer_mismatch | break |
| SPEC_FILE_AUTH_02 | InvFileSliceAuth | CHK_FS_INSERT | projector_unit | file_slice_projector_tests::tests::test_file_slice_valid | pass |
| SPEC_DEL_AUTHOR_01 | InvRemovalAdmin (deletion) | CHK_DEL_WRONG_AUTHOR | projector_unit | message_deletion_projector_tests::tests::test_deletion_rejects_wrong_author | break |
| SPEC_DEL_AUTHOR_01 | InvRemovalAdmin (deletion) | CHK_DEL_TOMBSTONE | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | pass |
| SPEC_RXN_SIGNER_01 | InvSigner (reaction) | CHK_RXN_SIGNER_USER_MISMATCH | projector_unit | reaction_projector_tests::tests::test_reaction_rejects_signer_user_mismatch | break |
| SPEC_RXN_SIGNER_01 | InvSigner (reaction) | CHK_RXN_INSERT | projector_unit | reaction_projector_tests::tests::test_reaction_valid | pass |
| SPEC_RXN_SKIP_DEL_01 | (post-tombstone) | CHK_RXN_SKIP_DELETED | projector_unit | reaction_projector_tests::tests::test_reaction_skips_when_target_deleted | pass |
| SPEC_RXN_SKIP_DEL_01 | (post-tombstone) | CHK_RXN_SKIP_DELETED | projector_unit | reaction_projector_tests::tests::test_reaction_valid | break |
| SPEC_MSG_INSERT_01 | InvMessageWorkspace | CHK_MSG_INSERT | projector_unit | message_projector_tests::tests::test_message_valid | pass |
| SPEC_MSG_INSERT_01 | InvMessageWorkspace | CHK_MSG_INSERT | projector_unit | message_projector_tests::tests::test_message_rejects_signer_user_mismatch | break |
| SPEC_MSG_DEL_BEFORE_01 | (convergence) | CHK_MSG_DELETE_BEFORE_CREATE | projector_unit | message_projector_tests::tests::test_message_tombstoned_by_deletion_intent | pass |
| SPEC_MSG_DEL_BEFORE_01 | (convergence) | CHK_MSG_DELETE_BEFORE_CREATE | projector_unit | message_projector_tests::tests::test_message_valid | break |
| SPEC_DEL_SIGNER_01 | InvSigner (deletion) | CHK_DEL_SIGNER_USER_MISMATCH | projector_unit | message_deletion_projector_tests::tests::test_deletion_rejects_signer_user_mismatch | break |
| SPEC_DEL_SIGNER_01 | InvSigner (deletion) | CHK_DEL_SIGNER_USER_MISMATCH | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | pass |
| SPEC_DEL_NON_MSG_01 | (type constraint) | CHK_DEL_NON_MESSAGE | projector_unit | message_deletion_projector_tests::tests::test_deletion_rejects_non_message_target | break |
| SPEC_DEL_NON_MSG_01 | (type constraint) | CHK_DEL_NON_MESSAGE | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | pass |
| SPEC_DEL_INTENT_01 | (convergence) | CHK_DEL_INTENT | projector_unit | message_deletion_projector_tests::tests::test_deletion_intent_only_when_no_target | pass |
| SPEC_DEL_INTENT_01 | (convergence) | CHK_DEL_INTENT | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | break |
| SPEC_DEL_IDEMPOTENT_01 | (idempotent) | CHK_DEL_IDEMPOTENT | projector_unit | message_deletion_projector_tests::tests::test_deletion_idempotent_when_tombstoned | pass |
| SPEC_DEL_IDEMPOTENT_01 | (idempotent) | CHK_DEL_IDEMPOTENT | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | break |
| SPEC_FS_IDEMPOTENT_01 | (idempotent) | CHK_FS_IDEMPOTENT | projector_unit | file_slice_projector_tests::tests::test_file_slice_idempotent_replay | pass |
| SPEC_FS_IDEMPOTENT_01 | (idempotent) | CHK_FS_IDEMPOTENT | projector_unit | file_slice_projector_tests::tests::test_file_slice_valid | break |
| SPEC_FS_SLOT_01 | (slot uniqueness) | CHK_FS_SLOT_CONFLICT | projector_unit | file_slice_projector_tests::tests::test_file_slice_rejects_slot_conflict | break |
| SPEC_FS_SLOT_01 | (slot uniqueness) | CHK_FS_SLOT_CONFLICT | projector_unit | file_slice_projector_tests::tests::test_file_slice_valid | pass |
| SPEC_ADM_INSERT_01 | InvAdminChain | CHK_ADM_INSERT | projector_unit | simple_projector_tests::tests::test_admin_boot_valid | pass |
| SPEC_ADM_INSERT_01 | InvAdminChain | CHK_ADM_INSERT | projector_unit | — | waiver:insert_or_ignore_no_break |
| SPEC_DI_INSERT_01 | InvDeviceInviteChain | CHK_DI_INSERT | projector_unit | device_invite_projector_tests::tests::test_device_invite_first_emits_pending_trust | pass |
| SPEC_DI_INSERT_01 | InvDeviceInviteChain | CHK_DI_INSERT | projector_unit | — | waiver:insert_or_ignore_no_break |
| SPEC_UI_INSERT_01 | InvUserInviteChain | CHK_UI_INSERT | projector_unit | user_invite_projector_tests::tests::test_user_invite_boot_basic_valid | pass |
| SPEC_UI_INSERT_01 | InvUserInviteChain | CHK_UI_INSERT | projector_unit | — | waiver:insert_or_ignore_no_break |
| SPEC_USR_INSERT_01 | InvDeps | CHK_USR_INSERT | projector_unit | simple_projector_tests::tests::test_user_boot_valid | pass |
| SPEC_USR_INSERT_01 | InvDeps | CHK_USR_INSERT | projector_unit | — | waiver:insert_or_ignore_no_break |
| SPEC_SK_INSERT_01 | InvEncryptedKey | CHK_SK_INSERT | projector_unit | simple_projector_tests::tests::test_secret_key_valid | pass |
| SPEC_SK_INSERT_01 | InvEncryptedKey | CHK_SK_INSERT | projector_unit | — | waiver:insert_or_ignore_no_break |
| SPEC_SM_INSERT_01 | InvDeps | CHK_SM_INSERT | projector_unit | simple_projector_tests::tests::test_signed_memo_valid | pass |
| SPEC_SM_INSERT_01 | InvDeps | CHK_SM_INSERT | projector_unit | — | waiver:insert_or_ignore_no_break |
| SPEC_MA_INSERT_01 | InvDeps | CHK_MA_INSERT | projector_unit | simple_projector_tests::tests::test_message_attachment_valid | pass |
| SPEC_MA_INSERT_01 | InvDeps | CHK_MA_INSERT | projector_unit | — | waiver:insert_or_ignore_no_break |
| SPEC_MA_RETRY_01 | InvFileSliceAuth | CHK_MA_RETRY_GUARD | projector_unit | simple_projector_tests::tests::test_message_attachment_valid | pass |
| SPEC_MA_RETRY_01 | InvFileSliceAuth | CHK_MA_RETRY_GUARD | projector_unit | — | waiver:insert_or_ignore_no_break |
| SPEC_BD_NOOP_01 | (benchmark) | CHK_BD_NOOP | projector_unit | simple_projector_tests::tests::test_bench_dep_noop | pass |
| SPEC_BD_NOOP_01 | (benchmark) | CHK_BD_NOOP | projector_unit | — | waiver:insert_or_ignore_no_break |
| SPEC_IA_RETRY_01 | InvWorkspaceAnchor | CHK_IA_RETRY_GUARDS | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_trust_anchor | pass |
| SPEC_IA_RETRY_01 | InvWorkspaceAnchor | CHK_IA_RETRY_GUARDS | pipeline_integration | apply::tests::test_invite_accepted_guard_retry_on_workspace | break |
| SPEC_ENCRYPTED_DEP_01 | InvEncryptedKey | CHK_ENCRYPTED_DEP_OUTER_KEY | pipeline_integration | apply::tests::test_encrypted_message_valid | pass |
| SPEC_ENCRYPTED_DEP_01 | InvEncryptedKey | CHK_ENCRYPTED_DEP_OUTER_KEY | pipeline_integration | apply::tests::test_encrypted_blocks_on_missing_key | break |
| SPEC_DISPATCH_01 | (registry) | CHK_DISPATCH_UNKNOWN_TYPE | pipeline_integration | apply::tests::test_project_message_valid | pass |
| SPEC_DISPATCH_01 | (registry) | CHK_DISPATCH_UNKNOWN_TYPE | pipeline_integration | apply::tests::test_retired_type3_peer_key_blob_rejected | break |
| SPEC_REJECTION_01 | (durable rejection) | CHK_REJECTION_RECORD | pipeline_integration | apply::tests::test_signed_memo_invalid_signature_rejects | pass |
| SPEC_REJECTION_01 | (durable rejection) | CHK_REJECTION_RECORD | pipeline_integration | apply::tests::test_project_message_valid | break |
| SPEC_INVITE_RECORDED_01 | InvInviteAcceptedRecorded | CHK_IA_INVITE_RECORDED | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_trust_anchor | pass |
| SPEC_INVITE_RECORDED_01 | InvInviteAcceptedRecorded | CHK_IA_INVITE_RECORDED | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_rejects_anchor_conflict | break |
| SPEC_ANCHOR_SOURCE_02 | InvTrustAnchorSource | CHK_IA_ANCHOR_SOURCE | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_trust_anchor | pass |
| SPEC_ANCHOR_SOURCE_02 | InvTrustAnchorSource | CHK_IA_ANCHOR_SOURCE | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_rejects_anchor_conflict | break |
| SPEC_BOOTSTRAP_TRUST_CONSUME_01 | InvBootstrapTrustConsumedByPeerShared | CHK_PS_BOOTSTRAP_TRUST_CONSUME | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_emits_supersede | pass |
| SPEC_BOOTSTRAP_TRUST_CONSUME_01 | InvBootstrapTrustConsumedByPeerShared | CHK_PS_BOOTSTRAP_TRUST_CONSUME | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_ongoing_also_emits_supersede | break |
| SPEC_PENDING_CONSUME_02 | InvPendingConsumedByPeerShared | CHK_PS_PENDING_CONSUME | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_emits_supersede | pass |
| SPEC_PENDING_CONSUME_02 | InvPendingConsumedByPeerShared | CHK_PS_PENDING_CONSUME | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_ongoing_also_emits_supersede | break |
| SPEC_PENDING_BOOTSTRAP_CONSUME_01 | InvPendingBootstrapTrustConsumedByPeerShared | CHK_PS_PENDING_BOOTSTRAP_CONSUME | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_emits_supersede | pass |
| SPEC_PENDING_BOOTSTRAP_CONSUME_01 | InvPendingBootstrapTrustConsumedByPeerShared | CHK_PS_PENDING_BOOTSTRAP_CONSUME | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_ongoing_also_emits_supersede | break |
| SPEC_PENDING_SOURCE_01 | InvPendingBootstrapTrustSource | CHK_UI_PENDING_SOURCE | projector_unit | user_invite_projector_tests::tests::test_user_invite_boot_emits_pending_trust | pass |
| SPEC_PENDING_SOURCE_01 | InvPendingBootstrapTrustSource | CHK_UI_PENDING_SOURCE | projector_unit | user_invite_projector_tests::tests::test_user_invite_ongoing_no_pending_trust | break |
| SPEC_TRANSITIVE_DENY_01 | InvUserRemovalTransitiveDeny | CHK_SS_TRANSITIVE_DENY | projector_unit | secret_shared_projector_tests::tests::test_secret_shared_rejects_removed_recipient | pass |
| SPEC_TRANSITIVE_DENY_01 | InvUserRemovalTransitiveDeny | CHK_SS_TRANSITIVE_DENY | projector_unit | secret_shared_projector_tests::tests::test_secret_shared_valid | break |
| SPEC_WS_DEP_01 | InvAllValidRequireWorkspace | CHK_WS_DEP_REQUIRED | pipeline_integration | apply::tests::test_project_message_valid | pass |
| SPEC_WS_DEP_01 | InvAllValidRequireWorkspace | CHK_WS_DEP_REQUIRED | pipeline_integration | apply::tests::test_project_reaction_blocked | break |

## TransportCredentialLifecycle Invariants

| spec_id | source | check_id | layer | test_id | polarity |
|---------|--------|----------|-------|---------|----------|
| SPEC_BOOTSTRAP_CONSUMED_TCL_01 | InvBootstrapConsumedByPeerShared | CHK_PS_SUPERSEDE | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_emits_supersede | pass |
| SPEC_BOOTSTRAP_CONSUMED_TCL_01 | InvBootstrapConsumedByPeerShared | CHK_PS_SUPERSEDE | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_ongoing_also_emits_supersede | break |
| SPEC_PENDING_CONSUMED_TCL_01 | InvPendingConsumedByPeerShared | CHK_PS_SUPERSEDE | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_emits_supersede | pass |
| SPEC_PENDING_CONSUMED_TCL_01 | InvPendingConsumedByPeerShared | CHK_PS_SUPERSEDE | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_ongoing_also_emits_supersede | break |
| SPEC_PENDING_INVITER_TCL_01 | InvPendingTrustOnlyOnInviter | CHK_UI_PENDING_TRUST | projector_unit | user_invite_projector_tests::tests::test_user_invite_no_pending_when_not_local | break |
| SPEC_PENDING_INVITER_TCL_01 | InvPendingTrustOnlyOnInviter | CHK_UI_PENDING_TRUST | projector_unit | user_invite_projector_tests::tests::test_user_invite_boot_emits_pending_trust | pass |
| SPEC_PENDING_INVITER_TCL_02 | InvPendingTrustOnlyOnInviter | CHK_DI_PENDING_TRUST | projector_unit | device_invite_projector_tests::tests::test_device_invite_no_pending_when_not_local | break |
| SPEC_PENDING_INVITER_TCL_02 | InvPendingTrustOnlyOnInviter | CHK_DI_PENDING_TRUST | projector_unit | device_invite_projector_tests::tests::test_device_invite_first_emits_pending_trust | pass |
| SPEC_TCL_SPKI_01 | InvSPKIUniqueness | CHK_TCL_SPKI_UNIQUE | transport_credential | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_SPKI_01 | InvSPKIUniqueness | CHK_TCL_SPKI_UNIQUE | transport_credential | — | waiver:integration_effect_only |
| SPEC_TCL_TRUST_UNION_01 | InvTrustSetIsExactUnion | CHK_TCL_TRUST_UNION | transport_credential | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_TRUST_UNION_01 | InvTrustSetIsExactUnion | CHK_TCL_TRUST_UNION | transport_credential | — | waiver:integration_effect_only |
| SPEC_TCL_SOURCES_01 | InvTrustSourcesWellFormed | CHK_TCL_SOURCES_FORMED | transport_credential | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_SOURCES_01 | InvTrustSourcesWellFormed | CHK_TCL_SOURCES_FORMED | transport_credential | — | waiver:integration_effect_only |
| SPEC_TCL_MUTUAL_01 | InvMutualAuthSymmetry | CHK_TCL_MUTUAL_AUTH | transport_credential | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_MUTUAL_01 | InvMutualAuthSymmetry | CHK_TCL_MUTUAL_AUTH | transport_credential | — | waiver:integration_effect_only |
| SPEC_TCL_MEMBERS_01 | InvTrustedPeerSetMembers | CHK_TCL_TRUSTED_MEMBERS | transport_credential | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_MEMBERS_01 | InvTrustedPeerSetMembers | CHK_TCL_TRUSTED_MEMBERS | transport_credential | — | waiver:integration_effect_only |
| SPEC_TCL_BOOTSTRAP_MATCH_01 | InvBootstrapTrustMatchesCarried | CHK_TCL_BOOTSTRAP_MATCH | transport_credential | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_BOOTSTRAP_MATCH_01 | InvBootstrapTrustMatchesCarried | CHK_TCL_BOOTSTRAP_MATCH | transport_credential | — | waiver:integration_effect_only |
| SPEC_TCL_PENDING_MATCH_01 | InvPendingBootstrapTrustMatchesCarried | CHK_TCL_PENDING_MATCH | transport_credential | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_PENDING_MATCH_01 | InvPendingBootstrapTrustMatchesCarried | CHK_TCL_PENDING_MATCH | transport_credential | — | waiver:integration_effect_only |
| SPEC_TCL_CRED_SOURCE_01 | InvCredentialSourceConsistency | CHK_TCL_CRED_SOURCE_CONSISTENCY | transport_credential | apply::tests::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_CRED_SOURCE_01 | InvCredentialSourceConsistency | CHK_TCL_CRED_SOURCE_CONSISTENCY | transport_credential | — | waiver:integration_effect_only |

## Replay/Order Conformance

| spec_id | source | check_id | layer | test_id | polarity |
|---------|--------|----------|-------|---------|----------|
| SPEC_REPLAY_CONVERGE_01 | InvDeps (convergence) | CHK_REPLAY_CONVERGENCE | replay_integration | apply::tests::test_source_isomorphism_message_reaction_chain | pass |
| SPEC_REPLAY_CONVERGE_01 | InvDeps (convergence) | CHK_REPLAY_CONVERGENCE | replay_integration | apply::tests::test_source_isomorphism_reverse_order_replay | pass |
| SPEC_REPLAY_CONVERGE_02 | InvDeps (convergence) | CHK_REPLAY_CONVERGENCE | replay_integration | apply::tests::test_source_isomorphism_encrypted_message | pass |
| SPEC_REPLAY_IDEMPOTENT_01 | (idempotent) | CHK_REPLAY_IDEMPOTENT | replay_integration | apply::tests::test_already_processed | pass |
| SPEC_REPLAY_IDEMPOTENT_01 | (idempotent) | CHK_REPLAY_IDEMPOTENT | replay_integration | apply::tests::test_source_isomorphism_idempotent_double_projection | pass |
| SPEC_DEL_CONVERGENCE_01 | (deletion convergence) | CHK_DEL_TWO_STAGE_CONVERGENCE | replay_integration | apply::tests::test_deletion_convergence | pass |
| SPEC_DEL_CONVERGENCE_01 | (deletion convergence) | CHK_DEL_TWO_STAGE_CONVERGENCE | replay_integration | apply::tests::test_deletion_intent_then_target_arrives | pass |
| SPEC_DEL_CONVERGENCE_02 | (deletion convergence) | CHK_DEL_TWO_STAGE_CONVERGENCE | replay_integration | apply::tests::test_source_isomorphism_deletion_cascade | pass |
| SPEC_CASCADE_CONVERGE_01 | InvDeps (cascade) | CHK_CASCADE_UNBLOCK | replay_integration | apply::tests::test_source_isomorphism_multi_event_deep_cascade | pass |
| SPEC_CASCADE_CONVERGE_01 | InvDeps (cascade) | CHK_CASCADE_UNBLOCK | replay_integration | apply::tests::test_cascade_and_direct_produce_same_state | pass |
| SPEC_REPLAY_TERMINAL_01 | (terminal stability) | CHK_REPLAY_TERMINAL | replay_integration | apply::tests::test_already_processed | pass |
| SPEC_REPLAY_TERMINAL_01 | (terminal stability) | CHK_REPLAY_TERMINAL | replay_integration | apply::tests::test_source_isomorphism_message_reaction_chain | break |
