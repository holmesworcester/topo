# Projector TLA Conformance Matrix

Machine-readable mapping from TLA+ spec requirements to runtime checks and tests.
Every `spec_id` must have at least one linked test. Guard-level spec_ids require
both `pass` and `break` polarity unless waived.

## EventGraphSchema Invariants

| spec_id | source | check_id | layer | test_id | polarity |
|---------|--------|----------|-------|---------|----------|
| SPEC_DEPS_01 | InvDeps | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::core_projection::test_project_message_valid | pass |
| SPEC_DEPS_01 | InvDeps | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::core_projection::test_project_reaction_blocked | break |
| SPEC_DEPS_01 | InvDeps | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::cascade::test_multi_dep_event_projects_only_when_all_resolve | break |
| SPEC_DEPS_02 | InvDeps | CHK_DEP_TYPE | pipeline_integration | apply::tests::invite::test_dep_type_mismatch_rejects | break |
| SPEC_DEPS_02 | InvDeps | CHK_DEP_TYPE | pipeline_integration | apply::tests::core_projection::test_project_message_valid | pass |
| SPEC_DEPS_03 | InvDeps (cascade) | CHK_CASCADE_UNBLOCK | pipeline_integration | apply::tests::core_projection::test_project_unblock_cascade | pass |
| SPEC_DEPS_03 | InvDeps (cascade) | CHK_CASCADE_UNBLOCK | pipeline_integration | apply::tests::core_projection::test_project_reaction_blocked | break |
| SPEC_SIGNER_01 | InvSigner | CHK_SIGNER_RESOLVE | pipeline_integration | apply::tests::file_slice::test_file_slice_blocks_on_missing_signer | break |
| SPEC_SIGNER_01 | InvSigner | CHK_SIGNER_RESOLVE | pipeline_integration | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_SIGNER_02 | InvSigner | CHK_SIGNER_VERIFY | pipeline_integration | apply::tests::file_slice::test_file_slice_invalid_signature_rejects | break |
| SPEC_SIGNER_02 | InvSigner | CHK_SIGNER_VERIFY | pipeline_integration | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_SIGNER_03 | InvSigner | CHK_SIGNER_RESOLVE | pipeline_integration | apply::tests::identity::test_unsupported_signer_type_rejects | break |
| SPEC_SIGNER_03 | InvSigner | CHK_SIGNER_RESOLVE | pipeline_integration | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_WS_ANCHOR_01 | InvWorkspaceAnchor | CHK_WS_TRUST_ANCHOR_BLOCK | projector_unit | workspace_projector_tests::tests::test_workspace_blocks_without_trust_anchor | break |
| SPEC_WS_ANCHOR_01 | InvWorkspaceAnchor | CHK_WS_TRUST_ANCHOR_BLOCK | projector_unit | workspace_projector_tests::tests::test_workspace_valid_with_matching_anchor | pass |
| SPEC_WS_ANCHOR_02 | InvForeignWorkspaceExcluded | CHK_WS_TRUST_ANCHOR_MISMATCH | projector_unit | workspace_projector_tests::tests::test_workspace_rejects_anchor_mismatch | break |
| SPEC_WS_ANCHOR_02 | InvForeignWorkspaceExcluded | CHK_WS_TRUST_ANCHOR_MISMATCH | pipeline_integration | apply::tests::cascade::test_invite_accepted_guard_retry_on_workspace | pass |
| SPEC_WS_SINGLE_01 | InvSingleWorkspace | CHK_WS_INSERT | projector_unit | workspace_projector_tests::tests::test_workspace_insert_or_ignore | pass |
| SPEC_WS_SINGLE_01 | InvSingleWorkspace | CHK_WS_INSERT | projector_unit | workspace_projector_tests::tests::test_workspace_rejects_anchor_mismatch | break |
| SPEC_ANCHOR_IMMUTABLE_01 | InvTrustAnchorImmutable | CHK_IA_TRUST_ANCHOR_WRITE | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_workspace_binding | pass |
| SPEC_ANCHOR_IMMUTABLE_01 | InvTrustAnchorImmutable | CHK_IA_TRUST_ANCHOR_CONFLICT | scenario_integration | cli_observability_test::test_trust_anchor_second_workspace_does_not_project | break |
| SPEC_ANCHOR_IMMUTABLE_01 | InvTrustAnchorImmutable | CHK_IA_WINNER_ORDER | scenario_integration | cli_observability_test::test_trust_anchor_second_workspace_does_not_project | break |
| SPEC_ANCHOR_SOURCE_01 | InvTrustAnchorSource | CHK_IA_TRUST_ANCHOR_WRITE | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_workspace_binding | pass |
| SPEC_ANCHOR_SOURCE_01 | InvTrustAnchorSource | CHK_IA_ANCHOR_SOURCE | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_workspace_binding | pass |
| SPEC_ANCHOR_SOURCE_01 | InvTrustAnchorSource | CHK_WS_TRUST_ANCHOR_BLOCK | projector_unit | workspace_projector_tests::tests::test_workspace_blocks_without_trust_anchor | break |
| SPEC_BOOTSTRAP_TRUST_01 | InvBootstrapTrustSource | CHK_IA_BOOTSTRAP_TRUST | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_bootstrap_trust | pass |
| SPEC_BOOTSTRAP_TRUST_01 | InvBootstrapTrustSource | CHK_IA_BOOTSTRAP_TRUST | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_no_bootstrap_without_context | break |
| SPEC_IA_LINK_WORKSPACE_01 | InvInviteAcceptedLinkWorkspace | CHK_IA_LINK_WORKSPACE_MATCH | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_workspace_binding | pass |
| SPEC_IA_LINK_WORKSPACE_01 | InvInviteAcceptedLinkWorkspace | CHK_IA_LINK_WORKSPACE_MATCH | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_allows_self_accept_without_bootstrap_context | pass |
| SPEC_IA_LINK_WORKSPACE_01 | InvInviteAcceptedLinkWorkspace | CHK_IA_LINK_WORKSPACE_MATCH | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_rejects_missing_local_link_workspace_binding | break |
| SPEC_IA_LINK_WORKSPACE_01 | InvInviteAcceptedLinkWorkspace | CHK_IA_LINK_WORKSPACE_MATCH | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_rejects_local_link_workspace_mismatch | break |
| SPEC_IA_LINK_WORKSPACE_01 | InvInviteAcceptedLinkWorkspace | CHK_IA_LINK_WORKSPACE_MATCH | pipeline_integration | apply::tests::invite::test_invite_accepted_requires_tenant_not_workspace | pass |
| SPEC_IA_LINK_WORKSPACE_01 | InvInviteAcceptedLinkWorkspace | CHK_IA_LINK_WORKSPACE_MATCH | pipeline_integration | apply::tests::invite::test_invite_accepted_rejects_missing_local_link_workspace_binding | break |
| SPEC_IA_LINK_WORKSPACE_01 | InvInviteAcceptedLinkWorkspace | CHK_IA_LINK_WORKSPACE_MATCH | pipeline_integration | apply::tests::invite::test_invite_accepted_rejects_local_link_workspace_mismatch | break |
| SPEC_BOOTSTRAP_CONSUMED_01 | InvBootstrapTrustConsumedByPeerShared | CHK_PS_BOOTSTRAP_TRUST_CONSUME | transport_credential | state::db::transport_trust::tests::test_invite_bootstrap_superseded_when_peer_shared_exists | pass |
| SPEC_BOOTSTRAP_CONSUMED_01 | InvBootstrapTrustConsumedByPeerShared | CHK_PS_BOOTSTRAP_TRUST_CONSUME | transport_credential | state::db::transport_trust::tests::test_invite_bootstrap_trust_in_authorized_fingerprints | break |
| SPEC_PENDING_TRUST_01 | InvPendingBootstrapTrustSource | CHK_UI_PENDING_BOOTSTRAP_SRC | projector_unit | user_invite_projector_tests::tests::test_user_invite_writes_pending_trust | pass |
| SPEC_PENDING_TRUST_01 | InvPendingBootstrapTrustSource | CHK_UI_PENDING_BOOTSTRAP_SRC | projector_unit | user_invite_projector_tests::tests::test_user_invite_no_pending_when_not_local | break |
| SPEC_PENDING_TRUST_02 | InvPendingBootstrapTrustSource | CHK_DI_PENDING_BOOTSTRAP_SRC | projector_unit | device_invite_projector_tests::tests::test_device_invite_writes_pending_trust | pass |
| SPEC_PENDING_TRUST_02 | InvPendingBootstrapTrustSource | CHK_DI_PENDING_BOOTSTRAP_SRC | projector_unit | device_invite_projector_tests::tests::test_device_invite_no_pending_when_not_local | break |
| SPEC_ENDPOINT_SECRET_01 | NON_MODELED::local_endpoint_root | CHK_ES_INSERT | pipeline_integration | apply::tests::identity::test_endpoint_secret_projects_under_endpoint_scope | waiver:local_root_only |
| SPEC_ENDPOINT_SECRET_02 | NON_MODELED::endpoint_scope_match | CHK_ES_SCOPE_MATCH | pipeline_integration | apply::tests::identity::test_endpoint_secret_rejects_mismatched_scope | waiver:scope_guard_only |
| SPEC_ENDPOINT_SHARED_01 | NON_MODELED::shared_endpoint_projection | CHK_EPS_INSERT | pipeline_integration | apply::tests::identity::test_endpoint_shared_projects_under_endpoint_scope | pass |
| SPEC_ENDPOINT_SHARED_01 | NON_MODELED::shared_endpoint_projection | CHK_EPS_INSERT | pipeline_integration | apply::tests::identity::test_endpoint_shared_rejects_invalid_signature | break |
| SPEC_ENDPOINT_SHARED_02 | NON_MODELED::endpoint_shared_scope_match | CHK_EPS_SCOPE_MATCH | pipeline_integration | apply::tests::identity::test_endpoint_shared_projects_under_endpoint_scope | pass |
| SPEC_ENDPOINT_SHARED_02 | NON_MODELED::endpoint_shared_scope_match | CHK_EPS_SCOPE_MATCH | pipeline_integration | apply::tests::identity::test_endpoint_shared_rejects_mismatched_scope | break |
| SPEC_ENDPOINT_SHARED_03 | NON_MODELED::endpoint_shared_self_auth | CHK_EPS_SELF_SIG | pipeline_integration | apply::tests::identity::test_endpoint_shared_projects_under_endpoint_scope | pass |
| SPEC_ENDPOINT_SHARED_03 | NON_MODELED::endpoint_shared_self_auth | CHK_EPS_SELF_SIG | pipeline_integration | apply::tests::identity::test_endpoint_shared_rejects_invalid_signature | break |
| SPEC_PENDING_INVITER_01 | InvPendingTrustOnlyOnInviter | CHK_UI_PENDING_TRUST | projector_unit | user_invite_projector_tests::tests::test_user_invite_no_pending_when_not_local | break |
| SPEC_PENDING_INVITER_01 | InvPendingTrustOnlyOnInviter | CHK_UI_PENDING_TRUST | projector_unit | user_invite_projector_tests::tests::test_user_invite_writes_pending_trust | pass |
| SPEC_PENDING_INVITER_02 | InvPendingTrustOnlyOnInviter | CHK_DI_PENDING_TRUST | projector_unit | device_invite_projector_tests::tests::test_device_invite_no_pending_when_not_local | break |
| SPEC_PENDING_INVITER_02 | InvPendingTrustOnlyOnInviter | CHK_DI_PENDING_TRUST | projector_unit | device_invite_projector_tests::tests::test_device_invite_writes_pending_trust | pass |
| SPEC_PEER_SHARED_TRUST_01 | InvPeerSharedTrustSource | CHK_PS_INSERT | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_writes_row | pass |
| SPEC_PEER_SHARED_TRUST_01 | InvPeerSharedTrustSource | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::core_projection::test_project_reaction_blocked | break |
| SPEC_PEER_SHARED_TRUST_02 | InvPeerSharedTrustMatchesCarried | CHK_PS_MATCH_CARRIED | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_writes_correct_fields | pass |
| SPEC_PEER_SHARED_TRUST_02 | InvPeerSharedTrustMatchesCarried | CHK_PS_MATCH_CARRIED | projector_unit | peer_shared_projector_tests::tests::test_peer_shared_rejects_non_peer_shared_event | break |
| SPEC_PENDING_CONSUMED_01 | InvPendingBootstrapTrustConsumedByPeerShared | CHK_PS_PENDING_BOOTSTRAP_CONSUME | transport_credential | state::db::transport_trust::tests::test_pending_invite_bootstrap_superseded_when_peer_shared_exists | pass |
| SPEC_PENDING_CONSUMED_01 | InvPendingBootstrapTrustConsumedByPeerShared | CHK_PS_PENDING_BOOTSTRAP_CONSUME | transport_credential | state::db::transport_trust::tests::test_pending_invite_bootstrap_trust_in_authorized_fingerprints | break |
| SPEC_UI_SIGNER_01 | InvUserInviteChain | CHK_UI_SIGNER_FAMILY | pipeline_integration | apply::tests::identity::test_user_invite_projects_with_workspace_signer_family | pass |
| SPEC_UI_SIGNER_01 | InvUserInviteChain | CHK_UI_SIGNER_FAMILY | pipeline_integration | apply::tests::identity::test_user_invite_projects_with_peer_signed_admin_authority | pass |
| SPEC_UI_SIGNER_01 | InvUserInviteChain | CHK_UI_SIGNER_FAMILY | pipeline_integration | apply::tests::identity::test_user_invite_rejects_wrong_signer_family_at_projection | break |
| SPEC_UI_AUTH_01 | InvUserInviteChain | CHK_UI_AUTHORITY | projector_unit | event_modules::user_invite_shared::projector::user_invite_projector_tests::test_user_invite_basic_valid | pass |
| SPEC_UI_AUTH_01 | InvUserInviteChain | CHK_UI_AUTHORITY | projector_unit | event_modules::user_invite_shared::projector::user_invite_projector_tests::test_user_invite_rejects_bootstrap_signer_mismatch | break |
| SPEC_UI_AUTH_01 | InvUserInviteChain | CHK_UI_AUTHORITY | projector_unit | event_modules::user_invite_shared::projector::user_invite_projector_tests::test_user_invite_rejects_bootstrap_authority_mismatch | break |
| SPEC_UI_AUTH_01 | InvUserInviteChain | CHK_UI_AUTHORITY | projector_unit | event_modules::user_invite_shared::projector::user_invite_projector_tests::test_user_invite_rejects_peer_signed_authority_mismatch | break |
| SPEC_UI_AUTH_01 | InvUserInviteChain | CHK_UI_AUTHORITY | pipeline_integration | apply::tests::identity::test_user_invite_projects_with_peer_signed_admin_authority | pass |
| SPEC_UI_AUTH_01 | InvUserInviteChain | CHK_UI_AUTHORITY | pipeline_integration | apply::tests::identity::test_user_invite_rejects_bootstrap_authority_mismatch_at_projection | break |
| SPEC_UI_AUTH_01 | InvUserInviteChain | CHK_UI_AUTHORITY | pipeline_integration | apply::tests::identity::test_user_invite_rejects_peer_signed_authority_mismatch_at_projection | break |
| SPEC_INVITE_CHAIN_01 | InvUserInviteChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_INVITE_CHAIN_01 | InvUserInviteChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::core_projection::test_project_reaction_blocked | break |
| SPEC_DI_SIGNER_01 | InvDeviceInviteChain | CHK_DI_SIGNER_FAMILY | pipeline_integration | apply::tests::identity::test_device_invite_projects_with_user_signer_family | pass |
| SPEC_DI_SIGNER_01 | InvDeviceInviteChain | CHK_DI_SIGNER_FAMILY | pipeline_integration | apply::tests::identity::test_device_invite_projects_with_peer_signed_admin_authority | pass |
| SPEC_DI_SIGNER_01 | InvDeviceInviteChain | CHK_DI_SIGNER_FAMILY | pipeline_integration | apply::tests::identity::test_device_invite_rejects_wrong_signer_family_at_projection | break |
| SPEC_DI_AUTH_01 | InvDeviceInviteChain | CHK_DI_AUTHORITY | projector_unit | event_modules::peer_invite_shared::projector::device_invite_projector_tests::test_device_invite_writes_pending_trust | pass |
| SPEC_DI_AUTH_01 | InvDeviceInviteChain | CHK_DI_AUTHORITY | projector_unit | event_modules::peer_invite_shared::projector::device_invite_projector_tests::test_device_invite_rejects_bootstrap_authority_mismatch | break |
| SPEC_DI_AUTH_01 | InvDeviceInviteChain | CHK_DI_AUTHORITY | projector_unit | event_modules::peer_invite_shared::projector::device_invite_projector_tests::test_device_invite_rejects_peer_signed_authority_mismatch | break |
| SPEC_DI_AUTH_01 | InvDeviceInviteChain | CHK_DI_AUTHORITY | pipeline_integration | apply::tests::identity::test_device_invite_projects_with_peer_signed_admin_authority | pass |
| SPEC_DI_AUTH_01 | InvDeviceInviteChain | CHK_DI_AUTHORITY | pipeline_integration | apply::tests::identity::test_device_invite_rejects_bootstrap_authority_mismatch_at_projection | break |
| SPEC_DI_AUTH_01 | InvDeviceInviteChain | CHK_DI_AUTHORITY | pipeline_integration | apply::tests::identity::test_device_invite_rejects_peer_signed_authority_mismatch_at_projection | break |
| SPEC_DEVICE_CHAIN_01 | InvDeviceInviteChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_DEVICE_CHAIN_01 | InvDeviceInviteChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::core_projection::test_project_reaction_blocked | break |
| SPEC_DEVICE_CHAIN_01 | InvDeviceInviteChain | CHK_PS_SIGNER_FAMILY | pipeline_integration | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_DEVICE_CHAIN_01 | InvDeviceInviteChain | CHK_PS_SIGNER_FAMILY | pipeline_integration | apply::tests::identity::test_peer_shared_rejects_wrong_signer_family_at_projection | break |
| SPEC_DEVICE_CHAIN_01 | InvDeviceInviteChain | CHK_PS_AUTHORIZED_USER | pipeline_integration | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_DEVICE_CHAIN_01 | InvDeviceInviteChain | CHK_PS_AUTHORIZED_USER | pipeline_integration | apply::tests::identity::test_peer_shared_rejects_bootstrap_user_mismatch | break |
| SPEC_DEVICE_CHAIN_01 | InvDeviceInviteChain | CHK_PS_AUTHORIZED_USER | pipeline_integration | apply::tests::identity::test_peer_shared_rejects_peer_signed_device_link_user_mismatch | break |
| SPEC_ADMIN_CHAIN_01 | InvAdminChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_ADMIN_CHAIN_01 | InvAdminChain | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::core_projection::test_project_reaction_blocked | break |
| SPEC_ADMIN_CHAIN_01 | InvAdminChain | CHK_ADM_SIGNER_FAMILY | pipeline_integration | apply::tests::identity::test_admin_projects_with_workspace_signer_family | pass |
| SPEC_ADMIN_CHAIN_01 | InvAdminChain | CHK_ADM_SIGNER_FAMILY | pipeline_integration | apply::tests::identity::test_admin_rejects_wrong_signer_family_at_projection | break |
| SPEC_ADMIN_CHAIN_01 | InvAdminChain | CHK_ADM_MATCH_USER_KEY | projector_unit | event_modules::admin::projector::projector_tests::test_admin_valid_with_matching_user_binding | pass |
| SPEC_ADMIN_CHAIN_01 | InvAdminChain | CHK_ADM_MATCH_USER_KEY | pipeline_integration | apply::tests::identity::test_admin_rejects_public_key_that_does_not_match_user | break |
| SPEC_MSG_WORKSPACE_01 | InvMessageWorkspace | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::core_projection::test_project_message_valid | pass |
| SPEC_MSG_WORKSPACE_01 | InvMessageWorkspace | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::core_projection::test_project_reaction_blocked | break |
| SPEC_MSG_SIGNER_01 | InvSigner (message) | CHK_MSG_SIGNER_USER_MISMATCH | projector_unit | message_projector_tests::tests::test_message_rejects_signer_user_mismatch | break |
| SPEC_MSG_SIGNER_01 | InvSigner (message) | CHK_MSG_SIGNER_USER_MISMATCH | projector_unit | message_projector_tests::tests::test_message_valid | pass |
| SPEC_ENCRYPTED_KEY_01 | InvEncryptedKey | CHK_ENCRYPTED_KEY_RESOLVE | pipeline_integration | apply::tests::encryption::test_encrypted_blocks_on_missing_key | break |
| SPEC_ENCRYPTED_KEY_01 | InvEncryptedKey | CHK_ENCRYPTED_KEY_RESOLVE | pipeline_integration | apply::tests::encryption::test_encrypted_message_valid | pass |
| SPEC_ENCRYPTED_DECRYPT_01 | InvEncryptedKey | CHK_ENCRYPTED_DECRYPT | pipeline_integration | apply::tests::encryption::test_encrypted_wrong_key_rejects | break |
| SPEC_ENCRYPTED_DECRYPT_01 | InvEncryptedKey | CHK_ENCRYPTED_DECRYPT | pipeline_integration | apply::tests::encryption::test_encrypted_message_valid | pass |
| SPEC_ENCRYPTED_TYPE_01 | (wire integrity) | CHK_ENCRYPTED_TYPE_MATCH | pipeline_integration | apply::tests::encryption::test_encrypted_inner_type_mismatch_rejects | break |
| SPEC_ENCRYPTED_TYPE_01 | (wire integrity) | CHK_ENCRYPTED_TYPE_MATCH | pipeline_integration | apply::tests::encryption::test_encrypted_message_valid | pass |
| SPEC_ENCRYPTED_NESTED_01 | (structural) | CHK_ENCRYPTED_NESTED | pipeline_integration | apply::tests::encryption::test_encrypted_nested_rejects | break |
| SPEC_ENCRYPTED_NESTED_01 | (structural) | CHK_ENCRYPTED_NESTED | pipeline_integration | apply::tests::encryption::test_encrypted_message_valid | pass |
| SPEC_ENCRYPTED_ADMISSIBLE_01 | (admissibility) | CHK_ENCRYPTED_ADMISSIBLE | pipeline_integration | apply::tests::encryption::test_encrypted_identity_event_rejects | break |
| SPEC_ENCRYPTED_ADMISSIBLE_01 | (admissibility) | CHK_ENCRYPTED_ADMISSIBLE | pipeline_integration | apply::tests::encryption::test_encrypted_message_valid | pass |
| SPEC_SECRET_SHARED_KEY_01 | InvSecretSharedKey | CHK_SS_INSERT | projector_unit | key_shared_projector_tests::tests::test_key_shared_valid | pass |
| SPEC_SECRET_SHARED_KEY_01 | InvSecretSharedKey | CHK_SS_INSERT | projector_unit | key_shared_projector_tests::tests::test_key_shared_rejects_key_event_id_mismatch | break |
| SPEC_KS_TARGET_01 | NON_MODELED::repair_target_binding | CHK_KS_TARGET_BINDING | projector_unit | key_shared_projector_tests::tests::test_key_shared_valid | pass |
| SPEC_KS_TARGET_01 | NON_MODELED::repair_target_binding | CHK_KS_TARGET_BINDING | projector_unit | key_shared_projector_tests::tests::test_key_shared_rejects_delivery_target_mismatch | break |
| SPEC_KS_TARGET_01 | NON_MODELED::repair_target_binding | CHK_KS_TARGET_BINDING | pipeline_integration | apply::tests::core_projection::key_shared_does_not_block_non_recipient_observers_on_local_invite_secret | pass |
| SPEC_KS_TARGET_01 | NON_MODELED::repair_target_binding | CHK_KS_TARGET_BINDING | pipeline_integration | apply::tests::core_projection::test_key_shared_rejects_delivery_target_mismatch_at_projection | break |
| SPEC_KS_FRONTIER_01 | NON_MODELED::repair_response_frontier_hash | CHK_KS_FRONTIER_HASH | projector_unit | key_shared_projector_tests::tests::test_key_shared_valid | pass |
| SPEC_KS_FRONTIER_01 | NON_MODELED::repair_response_frontier_hash | CHK_KS_FRONTIER_HASH | projector_unit | key_shared_projector_tests::tests::test_key_shared_rejects_frontier_hash_mismatch | break |
| SPEC_KS_FRONTIER_ORDER_01 | NON_MODELED::repair_response_frontier_canonical_order | CHK_KS_FRONTIER_ORDER | projector_unit | key_shared_projector_tests::tests::test_key_shared_valid_multi_parent_frontier | pass |
| SPEC_KS_FRONTIER_ORDER_01 | NON_MODELED::repair_response_frontier_canonical_order | CHK_KS_FRONTIER_ORDER | projector_unit | key_shared_projector_tests::tests::test_key_shared_rejects_unsorted_multi_parent_frontier_refs | break |
| SPEC_KS_FRONTIER_ORDER_01 | NON_MODELED::repair_response_frontier_canonical_order | CHK_KS_FRONTIER_ORDER | pipeline_integration | apply::tests::core_projection::key_shared_rejects_unsorted_multi_parent_frontier_even_when_all_frontier_deps_exist | break |
| SPEC_KS_DEP_01 | InvDeps | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::core_projection::key_shared_blocks_on_missing_frontier_then_projects | break |
| SPEC_KS_DEP_01 | InvDeps | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::core_projection::key_shared_blocks_on_missing_frontier_then_projects | pass |
| SPEC_KR_INSERT_01 | NON_MODELED::repair_request_primitive | CHK_KR_INSERT | projector_unit | key_request_projector_tests::tests::test_key_request_valid | pass |
| SPEC_KR_INSERT_01 | NON_MODELED::repair_request_primitive | CHK_KR_INSERT | projector_unit | key_request_projector_tests::tests::test_key_request_rejects_non_key_request_event | break |
| SPEC_KR_TARGET_01 | NON_MODELED::repair_target_binding | CHK_KR_TARGET_BINDING | projector_unit | key_request_projector_tests::tests::test_key_request_valid | pass |
| SPEC_KR_TARGET_01 | NON_MODELED::repair_target_binding | CHK_KR_TARGET_BINDING | projector_unit | key_request_projector_tests::tests::test_key_request_rejects_delivery_target_mismatch | break |
| SPEC_KR_TARGET_01 | NON_MODELED::repair_target_binding | CHK_KR_TARGET_BINDING | pipeline_integration | apply::tests::core_projection::test_project_key_request_valid_with_delivery_target_binding | pass |
| SPEC_KR_TARGET_01 | NON_MODELED::repair_target_binding | CHK_KR_TARGET_BINDING | pipeline_integration | apply::tests::core_projection::test_project_key_request_rejects_delivery_target_mismatch | break |
| SPEC_RM_SIGNER_01 | NON_MODELED::remover_self_binding | CHK_RM_SIGNER_BINDING | projector_unit | removal_projector_tests::tests::test_removal_valid | pass |
| SPEC_RM_SIGNER_01 | NON_MODELED::remover_self_binding | CHK_RM_SIGNER_BINDING | projector_unit | removal_projector_tests::tests::test_removal_rejects_removed_by_signer_mismatch | break |
| SPEC_RM_FRONTIER_01 | NON_MODELED::removal_frontier_hash | CHK_RM_FRONTIER_HASH | projector_unit | removal_projector_tests::tests::test_removal_valid | pass |
| SPEC_RM_FRONTIER_01 | NON_MODELED::removal_frontier_hash | CHK_RM_FRONTIER_HASH | projector_unit | removal_projector_tests::tests::test_removal_rejects_frontier_hash_mismatch | break |
| SPEC_RM_FRONTIER_01 | NON_MODELED::removal_frontier_hash | CHK_RM_FRONTIER_HASH | pipeline_integration | apply::tests::removal_rotation::test_removal_projects_and_rejects_bad_frontier_hash | pass |
| SPEC_RM_FRONTIER_01 | NON_MODELED::removal_frontier_hash | CHK_RM_FRONTIER_HASH | pipeline_integration | apply::tests::removal_rotation::test_removal_projects_and_rejects_bad_frontier_hash | break |
| SPEC_RM_FRONTIER_ORDER_01 | NON_MODELED::removal_frontier_canonical_order | CHK_RM_FRONTIER_ORDER | projector_unit | removal_projector_tests::tests::test_removal_valid_multi_parent_frontier | pass |
| SPEC_RM_FRONTIER_ORDER_01 | NON_MODELED::removal_frontier_canonical_order | CHK_RM_FRONTIER_ORDER | projector_unit | removal_projector_tests::tests::test_removal_rejects_unsorted_multi_parent_frontier_refs | break |
| SPEC_RM_FRONTIER_ORDER_01 | NON_MODELED::removal_frontier_canonical_order | CHK_RM_FRONTIER_ORDER | pipeline_integration | apply::tests::removal_rotation::test_concurrent_multi_parent_frontier_hash_converges_despite_parent_order | pass |
| SPEC_KROT_SIGNER_01 | NON_MODELED::rotation_self_binding | CHK_KROT_SIGNER_BINDING | projector_unit | key_rotation_projector_tests::tests::test_key_rotation_valid_root_frontier | pass |
| SPEC_KROT_SIGNER_01 | NON_MODELED::rotation_self_binding | CHK_KROT_SIGNER_BINDING | projector_unit | key_rotation_projector_tests::tests::test_key_rotation_rejects_rotated_by_signer_mismatch | break |
| SPEC_KROT_FRONTIER_01 | NON_MODELED::rotation_frontier_hash | CHK_KROT_FRONTIER_HASH | projector_unit | key_rotation_projector_tests::tests::test_key_rotation_valid_root_frontier | pass |
| SPEC_KROT_FRONTIER_01 | NON_MODELED::rotation_frontier_hash | CHK_KROT_FRONTIER_HASH | projector_unit | key_rotation_projector_tests::tests::test_key_rotation_rejects_frontier_hash_mismatch | break |
| SPEC_KROT_FRONTIER_01 | NON_MODELED::rotation_frontier_hash | CHK_KROT_FRONTIER_HASH | pipeline_integration | apply::tests::removal_rotation::test_key_rotation_projects_root_frontier_and_rejects_bad_hash | pass |
| SPEC_KROT_FRONTIER_01 | NON_MODELED::rotation_frontier_hash | CHK_KROT_FRONTIER_HASH | pipeline_integration | apply::tests::removal_rotation::test_key_rotation_blocks_on_missing_frontier_then_projects_and_rejects_bad_hash | break |
| SPEC_KROT_FRONTIER_ORDER_01 | NON_MODELED::rotation_frontier_canonical_order | CHK_KROT_FRONTIER_ORDER | projector_unit | key_rotation_projector_tests::tests::test_key_rotation_valid_multi_parent_frontier | pass |
| SPEC_KROT_FRONTIER_ORDER_01 | NON_MODELED::rotation_frontier_canonical_order | CHK_KROT_FRONTIER_ORDER | projector_unit | key_rotation_projector_tests::tests::test_key_rotation_rejects_unsorted_multi_parent_frontier_refs | break |
| SPEC_KROT_FRONTIER_ORDER_01 | NON_MODELED::rotation_frontier_canonical_order | CHK_KROT_FRONTIER_ORDER | pipeline_integration | apply::tests::removal_rotation::test_key_rotation_rejects_unsorted_multi_parent_frontier_even_when_hash_matches | break |
| SPEC_KROT_FRONTIER_ORDER_01 | NON_MODELED::rotation_frontier_canonical_order | CHK_KROT_FRONTIER_ORDER | pipeline_integration | apply::tests::removal_rotation::test_key_rotation_multi_parent_frontier_blocks_until_all_frontier_deps_arrive | pass |
| SPEC_KROT_DEP_01 | InvDeps | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::removal_rotation::test_key_rotation_blocks_on_missing_frontier_then_projects_and_rejects_bad_hash | pass |
| SPEC_KROT_DEP_01 | InvDeps | CHK_DEP_PRESENCE | pipeline_integration | apply::tests::removal_rotation::test_key_rotation_blocks_on_missing_frontier_then_projects_and_rejects_bad_hash | break |
| SPEC_FILE_AUTH_01 | InvFileSliceAuth | CHK_FS_DEP_BLOCK | projector_unit | file_slice_projector_tests::tests::test_file_slice_blocks_no_descriptor | break |
| SPEC_FILE_AUTH_01 | InvFileSliceAuth | CHK_FS_INSERT | projector_unit | file_slice_projector_tests::tests::test_file_slice_valid | pass |
| SPEC_FILE_AUTH_02 | InvFileSliceAuth | CHK_FS_SIGNER_MISMATCH | projector_unit | file_slice_projector_tests::tests::test_file_slice_rejects_signer_mismatch | break |
| SPEC_FILE_AUTH_02 | InvFileSliceAuth | CHK_FS_INSERT | projector_unit | file_slice_projector_tests::tests::test_file_slice_valid | pass |
| SPEC_DEL_AUTHOR_01 | NON_MODELED::author_constraint | CHK_DEL_WRONG_AUTHOR | projector_unit | message_deletion_projector_tests::tests::test_deletion_rejects_wrong_author | break |
| SPEC_DEL_AUTHOR_01 | InvDeletedMessageSource | CHK_DEL_TOMBSTONE | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | pass |
| SPEC_RXN_SIGNER_01 | InvSigner (reaction) | CHK_RXN_SIGNER_USER_MISMATCH | projector_unit | reaction_projector_tests::tests::test_reaction_rejects_signer_user_mismatch | break |
| SPEC_RXN_SIGNER_01 | InvSigner (reaction) | CHK_RXN_INSERT | projector_unit | reaction_projector_tests::tests::test_reaction_valid | pass |
| SPEC_RXN_SKIP_DEL_01 | InvDeletedMessagePurgesLiveGraph | CHK_RXN_SKIP_DELETED | projector_unit | reaction_projector_tests::tests::test_reaction_skips_when_target_deleted | pass |
| SPEC_RXN_SKIP_DEL_01 | InvDeletedMessagePurgesLiveGraph | CHK_RXN_SKIP_DELETED | projector_unit | reaction_projector_tests::tests::test_reaction_valid | break |
| SPEC_RXN_SKIP_DEL_01 | InvDeletedMessagePurgesLiveGraph | CHK_RXN_HARD_PURGE | projector_unit | reaction_projector_tests::tests::test_reaction_skips_when_target_deleted | pass |
| SPEC_RXN_SKIP_DEL_01 | InvDeletedMessagePurgesLiveGraph | CHK_RXN_HARD_PURGE | projector_unit | reaction_projector_tests::tests::test_reaction_valid | break |
| SPEC_RXN_OWNER_01 | (owner wrapper) | CHK_RXN_OWNER_MATCH | projector_unit | reaction_projector_tests::tests::test_reaction_valid | pass |
| SPEC_RXN_OWNER_01 | (owner wrapper) | CHK_RXN_OWNER_MATCH | projector_unit | reaction_projector_tests::tests::test_reaction_rejects_owner_mismatch | break |
| SPEC_MSG_INSERT_01 | InvMessageWorkspace | CHK_MSG_INSERT | projector_unit | message_projector_tests::tests::test_message_valid | pass |
| SPEC_MSG_INSERT_01 | InvMessageWorkspace | CHK_MSG_INSERT | projector_unit | message_projector_tests::tests::test_message_rejects_signer_user_mismatch | break |
| SPEC_MSG_OWNER_01 | (owner wrapper) | CHK_MSG_OUTER_OWNER_ABSENT | projector_unit | message_projector_tests::tests::test_message_valid | pass |
| SPEC_MSG_OWNER_01 | (owner wrapper) | CHK_MSG_OUTER_OWNER_ABSENT | projector_unit | message_projector_tests::tests::test_message_rejects_outer_owner_event_id | break |
| SPEC_MSG_DEL_BEFORE_01 | InvDeleteIntentNoLiveMessage | CHK_MSG_DELETE_BEFORE_CREATE | projector_unit | message_projector_tests::tests::test_message_tombstoned_by_deletion_intent | pass |
| SPEC_MSG_DEL_BEFORE_01 | InvDeleteIntentNoLiveMessage | CHK_MSG_DELETE_BEFORE_CREATE | projector_unit | message_projector_tests::tests::test_message_valid | break |
| SPEC_MSG_DEL_BEFORE_01 | InvDeletePurgeAtomic | CHK_MSG_HARD_PURGE | projector_unit | message_projector_tests::tests::test_message_tombstoned_by_deletion_intent | pass |
| SPEC_MSG_DEL_BEFORE_01 | InvDeletePurgeAtomic | CHK_MSG_HARD_PURGE | projector_unit | message_projector_tests::tests::test_message_valid | break |
| SPEC_MA_SKIP_DEL_01 | InvDeletedMessagePurgesLiveGraph | CHK_FILE_HARD_PURGE | projector_unit | simple_projector_tests::tests::test_file_skips_when_target_message_deleted | pass |
| SPEC_MA_SKIP_DEL_01 | InvDeletedMessagePurgesLiveGraph | CHK_FILE_HARD_PURGE | projector_unit | simple_projector_tests::tests::test_file_valid | break |
| SPEC_FILE_OWNER_01 | (owner wrapper) | CHK_FILE_OWNER_MATCH | projector_unit | simple_projector_tests::tests::test_file_valid | pass |
| SPEC_FILE_OWNER_01 | (owner wrapper) | CHK_FILE_OWNER_MATCH | projector_unit | simple_projector_tests::tests::test_file_rejects_owner_mismatch | break |
| SPEC_DEL_SIGNER_01 | InvSigner (deletion) | CHK_DEL_SIGNER_AUTH | projector_unit | message_deletion_projector_tests::tests::test_deletion_rejects_invalid_signer_auth | break |
| SPEC_DEL_SIGNER_01 | InvSigner (deletion) | CHK_DEL_SIGNER_AUTH | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid_for_admin_signer | pass |
| SPEC_DEL_OWNER_01 | (owner wrapper) | CHK_DEL_OUTER_OWNER_ABSENT | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | pass |
| SPEC_DEL_OWNER_01 | (owner wrapper) | CHK_DEL_OUTER_OWNER_ABSENT | projector_unit | message_deletion_projector_tests::tests::test_deletion_rejects_outer_owner_event_id | break |
| SPEC_DEL_NON_MSG_01 | (type constraint) | CHK_DEL_NON_MESSAGE | projector_unit | message_deletion_projector_tests::tests::test_deletion_rejects_non_message_target | break |
| SPEC_DEL_NON_MSG_01 | (type constraint) | CHK_DEL_NON_MESSAGE | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | pass |
| SPEC_DEL_INTENT_01 | InvDeleteIntentSource | CHK_DEL_INTENT | projector_unit | message_deletion_projector_tests::tests::test_deletion_intent_only_when_no_target | pass |
| SPEC_DEL_INTENT_01 | InvDeleteIntentSource | CHK_DEL_INTENT | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | break |
| SPEC_DEL_IDEMPOTENT_01 | (idempotent) | CHK_DEL_IDEMPOTENT | projector_unit | message_deletion_projector_tests::tests::test_deletion_idempotent_when_tombstoned | pass |
| SPEC_DEL_IDEMPOTENT_01 | (idempotent) | CHK_DEL_IDEMPOTENT | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | break |
| SPEC_DEL_AUTHOR_01 | InvDeletePurgeAtomic | CHK_DEL_HARD_PURGE | projector_unit | message_deletion_projector_tests::tests::test_deletion_valid | pass |
| SPEC_DEL_AUTHOR_01 | InvDeletePurgeAtomic | CHK_DEL_HARD_PURGE | projector_unit | message_deletion_projector_tests::tests::test_deletion_intent_only_when_no_target | break |
| SPEC_DEL_IDEMPOTENT_01 | InvDeletePurgeAtomic | CHK_DEL_HARD_PURGE | projector_unit | message_deletion_projector_tests::tests::test_deletion_idempotent_when_tombstoned | pass |
| SPEC_DEL_IDEMPOTENT_01 | InvDeletePurgeAtomic | CHK_DEL_HARD_PURGE | projector_unit | message_deletion_projector_tests::tests::test_deletion_intent_only_when_no_target | break |
| SPEC_FS_IDEMPOTENT_01 | (idempotent) | CHK_FS_IDEMPOTENT | projector_unit | file_slice_projector_tests::tests::test_file_slice_idempotent_replay | pass |
| SPEC_FS_IDEMPOTENT_01 | (idempotent) | CHK_FS_IDEMPOTENT | projector_unit | file_slice_projector_tests::tests::test_file_slice_valid | break |
| SPEC_FS_SKIP_DEL_01 | InvDeletedFilePurgesLiveSlice | CHK_FS_HARD_PURGE | projector_unit | file_slice_projector_tests::tests::test_file_slice_skips_when_owner_message_deleted | pass |
| SPEC_FS_SKIP_DEL_01 | InvDeletedFilePurgesLiveSlice | CHK_FS_HARD_PURGE | projector_unit | file_slice_projector_tests::tests::test_file_slice_blocks_no_descriptor | break |
| SPEC_FS_OWNER_01 | (owner wrapper) | CHK_FS_OWNER_MATCH | projector_unit | file_slice_projector_tests::tests::test_file_slice_valid | pass |
| SPEC_FS_OWNER_01 | (owner wrapper) | CHK_FS_OWNER_MATCH | projector_unit | file_slice_projector_tests::tests::test_file_slice_rejects_owner_mismatch | break |
| SPEC_FS_SLOT_01 | (slot uniqueness) | CHK_FS_SLOT_CONFLICT | projector_unit | file_slice_projector_tests::tests::test_file_slice_rejects_slot_conflict | break |
| SPEC_FS_SLOT_01 | (slot uniqueness) | CHK_FS_SLOT_CONFLICT | projector_unit | file_slice_projector_tests::tests::test_file_slice_valid | pass |
| SPEC_ADM_INSERT_01 | InvAdminChain | CHK_ADM_INSERT | projector_unit | simple_projector_tests::tests::test_admin_valid | pass |
| SPEC_ADM_INSERT_01 | InvAdminChain | CHK_ADM_INSERT | projector_unit | simple_projector_tests::tests::test_admin_rejects_non_admin_event | break |
| SPEC_DI_INSERT_01 | InvDeviceInviteChain | CHK_DI_INSERT | projector_unit | device_invite_projector_tests::tests::test_device_invite_writes_pending_trust | pass |
| SPEC_DI_INSERT_01 | InvDeviceInviteChain | CHK_DI_INSERT | projector_unit | device_invite_projector_tests::tests::test_device_invite_rejects_non_device_invite_event | break |
| SPEC_UI_INSERT_01 | InvUserInviteChain | CHK_UI_INSERT | projector_unit | user_invite_projector_tests::tests::test_user_invite_basic_valid | pass |
| SPEC_UI_INSERT_01 | InvUserInviteChain | CHK_UI_INSERT | projector_unit | user_invite_projector_tests::tests::test_user_invite_rejects_non_user_invite_event | break |
| SPEC_USR_INSERT_01 | InvDeps | CHK_USR_INSERT | projector_unit | simple_projector_tests::tests::test_user_valid | pass |
| SPEC_USR_INSERT_01 | InvDeps | CHK_USR_INSERT | projector_unit | simple_projector_tests::tests::test_user_rejects_non_user_event | break |
| SPEC_SK_INSERT_01 | InvEncryptedKey | CHK_SK_INSERT | projector_unit | simple_projector_tests::tests::test_key_secret_valid | pass |
| SPEC_SK_INSERT_01 | InvEncryptedKey | CHK_SK_INSERT | projector_unit | simple_projector_tests::tests::test_key_secret_rejects_non_key_secret_event | break |
| SPEC_MA_INSERT_01 | InvDeps | CHK_MA_INSERT | projector_unit | simple_projector_tests::tests::test_file_valid | pass |
| SPEC_MA_INSERT_01 | InvDeps | CHK_MA_INSERT | projector_unit | simple_projector_tests::tests::test_file_rejects_non_attachment_event | break |
| SPEC_BD_NOOP_01 | (benchmark) | CHK_BD_NOOP | projector_unit | simple_projector_tests::tests::test_bench_dep_noop | pass |
| SPEC_BD_NOOP_01 | (benchmark) | CHK_BD_NOOP | projector_unit | simple_projector_tests::tests::test_bench_dep_rejects_non_bench_dep_event | break |
| SPEC_IA_RETRY_01 | InvWorkspaceAnchor | CHK_IA_RETRY_GUARDS | projector_unit | invite_accepted_projector_tests::tests::test_invite_accepted_writes_workspace_binding | pass |
| SPEC_IA_RETRY_01 | InvWorkspaceAnchor | CHK_IA_RETRY_GUARDS | pipeline_integration | apply::tests::cascade::test_invite_accepted_guard_retry_on_workspace | break |
| SPEC_ENCRYPTED_DEP_01 | InvEncryptedKey | CHK_ENCRYPTED_DEP_OUTER_KEY | pipeline_integration | apply::tests::encryption::test_encrypted_message_valid | pass |
| SPEC_ENCRYPTED_DEP_01 | InvEncryptedKey | CHK_ENCRYPTED_DEP_OUTER_KEY | pipeline_integration | apply::tests::encryption::test_encrypted_blocks_on_missing_key | break |
| SPEC_DISPATCH_01 | (registry) | CHK_DISPATCH_UNKNOWN_TYPE | pipeline_integration | apply::tests::core_projection::test_project_message_valid | pass |
| SPEC_DISPATCH_01 | (registry) | CHK_DISPATCH_UNKNOWN_TYPE | pipeline_integration | apply::tests::core_projection::test_retired_type3_peer_key_blob_rejected | break |
| SPEC_REJECTION_01 | (durable rejection) | CHK_REJECTION_RECORD | pipeline_integration | apply::tests::file_slice::test_file_slice_invalid_signature_rejects | pass |
| SPEC_REJECTION_01 | (durable rejection) | CHK_REJECTION_RECORD | pipeline_integration | apply::tests::core_projection::test_project_message_valid | break |
| SPEC_MA_SKIP_DEL_01 | InvAttachmentTombstoneBypass | CHK_FILE_TOMBSTONE_DEP_OK | pipeline_integration | apply::tests::deletion::test_file_arriving_after_tombstone_is_hard_purged | pass |
| SPEC_MA_SKIP_DEL_01 | InvAttachmentTombstoneBypass | CHK_FILE_TOMBSTONE_DEP_OK | pipeline_integration | apply::tests::file_slice::test_attachment_blocks_on_missing_message | break |
| SPEC_MA_SKIP_DEL_01 | InvDeletedMessagePurgesLiveGraph | CHK_FILE_HARD_PURGE | pipeline_integration | apply::tests::deletion::test_file_arriving_after_tombstone_is_hard_purged | pass |
| SPEC_MA_SKIP_DEL_01 | InvDeletedMessagePurgesLiveGraph | CHK_FILE_HARD_PURGE | pipeline_integration | apply::tests::file_slice::test_project_attachment_valid | break |
| SPEC_RXN_SKIP_DEL_01 | InvReactionTombstoneBypass | CHK_RXN_TOMBSTONE_DEP_OK | pipeline_integration | apply::tests::encryption::test_encrypted_deleted_owner_fast_purges_without_key_resolution | pass |
| SPEC_RXN_SKIP_DEL_01 | InvReactionTombstoneBypass | CHK_RXN_TOMBSTONE_DEP_OK | pipeline_integration | apply::tests::deletion::test_reaction_arriving_after_tombstone_is_hard_purged | pass |
| SPEC_RXN_SKIP_DEL_01 | InvReactionTombstoneBypass | CHK_RXN_TOMBSTONE_DEP_OK | pipeline_integration | apply::tests::core_projection::test_project_reaction_blocked | break |
| SPEC_FS_SKIP_DEL_01 | InvDeletedFilePurgesLiveSlice | CHK_FS_HARD_PURGE | pipeline_integration | apply::tests::deletion::test_file_slice_dependents_of_deleted_message_are_hard_purged_by_owner | pass |
| SPEC_FS_SKIP_DEL_01 | InvDeletedFilePurgesLiveSlice | CHK_FS_HARD_PURGE | pipeline_integration | apply::tests::file_slice::test_file_slice_valid | break |
| SPEC_PROJECTION_TX_01 | InvDeletePurgeAtomic | CHK_PROJECTION_TX_ATOMIC | pipeline_integration | apply::tests::deletion::test_hard_purge_failure_rolls_back_and_retries_from_project_queue | pass |
| SPEC_PROJECTION_TX_01 | InvDeletePurgeAtomic | CHK_PROJECTION_TX_ATOMIC | pipeline_integration | apply::tests::deletion::test_hard_purge_failure_rolls_back_and_retries_from_project_queue | break |
| SPEC_DEL_INTENT_01 | InvDeleteIntentSource | CHK_DEL_INTENT | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_DEL_AUTHOR_01 | InvDeletedMessageSource | CHK_DEL_TOMBSTONE | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_DEL_AUTHOR_01 | InvDeletePurgeAtomic | CHK_DEL_HARD_PURGE | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_MSG_DEL_BEFORE_01 | InvDeleteIntentNoLiveMessage | CHK_MSG_DELETE_BEFORE_CREATE | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_MSG_DEL_BEFORE_01 | InvDeletePurgeAtomic | CHK_MSG_HARD_PURGE | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_MA_SKIP_DEL_01 | InvAttachmentTombstoneBypass | CHK_FILE_TOMBSTONE_DEP_OK | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_MA_SKIP_DEL_01 | InvDeletedMessagePurgesLiveGraph | CHK_FILE_HARD_PURGE | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_RXN_SKIP_DEL_01 | InvReactionTombstoneBypass | CHK_RXN_TOMBSTONE_DEP_OK | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_RXN_SKIP_DEL_01 | InvDeletedMessagePurgesLiveGraph | CHK_RXN_HARD_PURGE | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_FS_SKIP_DEL_01 | InvDeletedFilePurgesLiveSlice | CHK_FS_HARD_PURGE | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_PROJECTION_TX_01 | InvDeletePurgeAtomic | CHK_PROJECTION_TX_ATOMIC | tla_safety | tlc::EventGraphSchema::event_graph_schema_delete_fast.cfg | pass |
| SPEC_BOOTSTRAP_TRUST_CONSUME_01 | InvBootstrapTrustConsumedByPeerShared | CHK_PS_BOOTSTRAP_TRUST_CONSUME | transport_credential | state::db::transport_trust::tests::test_invite_bootstrap_superseded_when_peer_shared_exists | pass |
| SPEC_BOOTSTRAP_TRUST_CONSUME_01 | InvBootstrapTrustConsumedByPeerShared | CHK_PS_BOOTSTRAP_TRUST_CONSUME | transport_credential | state::db::transport_trust::tests::test_invite_bootstrap_trust_in_authorized_fingerprints | break |
| SPEC_PENDING_CONSUME_02 | InvPendingConsumedByPeerShared | CHK_PS_PENDING_CONSUME | transport_credential | state::db::transport_trust::tests::test_pending_invite_bootstrap_superseded_when_peer_shared_exists | pass |
| SPEC_PENDING_CONSUME_02 | InvPendingConsumedByPeerShared | CHK_PS_PENDING_CONSUME | transport_credential | state::db::transport_trust::tests::test_pending_invite_bootstrap_trust_in_authorized_fingerprints | break |
| SPEC_PENDING_BOOTSTRAP_CONSUME_01 | InvPendingBootstrapTrustConsumedByPeerShared | CHK_PS_PENDING_BOOTSTRAP_CONSUME | transport_credential | state::db::transport_trust::tests::test_pending_invite_bootstrap_superseded_when_peer_shared_exists | pass |
| SPEC_PENDING_BOOTSTRAP_CONSUME_01 | InvPendingBootstrapTrustConsumedByPeerShared | CHK_PS_PENDING_BOOTSTRAP_CONSUME | transport_credential | state::db::transport_trust::tests::test_pending_invite_bootstrap_trust_in_authorized_fingerprints | break |
| SPEC_PENDING_SOURCE_01 | InvPendingBootstrapTrustSource | CHK_UI_PENDING_SOURCE | projector_unit | user_invite_projector_tests::tests::test_user_invite_writes_pending_trust | pass |
| SPEC_PENDING_SOURCE_01 | InvPendingBootstrapTrustSource | CHK_UI_PENDING_SOURCE | projector_unit | user_invite_projector_tests::tests::test_user_invite_no_pending_when_not_local | break |
| SPEC_WS_DEP_01 | InvAllValidRequireWorkspace | CHK_WS_DEP_REQUIRED | pipeline_integration | apply::tests::core_projection::test_project_message_valid | pass |
| SPEC_WS_DEP_01 | InvAllValidRequireWorkspace | CHK_WS_DEP_REQUIRED | pipeline_integration | apply::tests::core_projection::test_project_reaction_blocked | break |

## TransportCredentialLifecycle Invariants

| spec_id | source | check_id | layer | test_id | polarity |
|---------|--------|----------|-------|---------|----------|
| SPEC_BOOTSTRAP_CONSUMED_TCL_01 | InvBootstrapConsumedByPeerShared | CHK_PS_SUPERSEDE | transport_credential | state::db::transport_trust::tests::test_invite_bootstrap_superseded_when_peer_shared_exists | pass |
| SPEC_BOOTSTRAP_CONSUMED_TCL_01 | InvBootstrapConsumedByPeerShared | CHK_PS_SUPERSEDE | transport_credential | state::db::transport_trust::tests::test_invite_bootstrap_trust_in_authorized_fingerprints | break |
| SPEC_PENDING_CONSUMED_TCL_01 | InvPendingConsumedByPeerShared | CHK_PS_PENDING_CONSUME | transport_credential | state::db::transport_trust::tests::test_pending_invite_bootstrap_superseded_when_peer_shared_exists | pass |
| SPEC_PENDING_CONSUMED_TCL_01 | InvPendingConsumedByPeerShared | CHK_PS_PENDING_CONSUME | transport_credential | state::db::transport_trust::tests::test_pending_invite_bootstrap_trust_in_authorized_fingerprints | break |
| SPEC_PENDING_INVITER_TCL_01 | InvPendingTrustOnlyOnInviter | CHK_UI_PENDING_TRUST | projector_unit | user_invite_projector_tests::tests::test_user_invite_no_pending_when_not_local | break |
| SPEC_PENDING_INVITER_TCL_01 | InvPendingTrustOnlyOnInviter | CHK_UI_PENDING_TRUST | projector_unit | user_invite_projector_tests::tests::test_user_invite_writes_pending_trust | pass |
| SPEC_PENDING_INVITER_TCL_02 | InvPendingTrustOnlyOnInviter | CHK_DI_PENDING_TRUST | projector_unit | device_invite_projector_tests::tests::test_device_invite_no_pending_when_not_local | break |
| SPEC_PENDING_INVITER_TCL_02 | InvPendingTrustOnlyOnInviter | CHK_DI_PENDING_TRUST | projector_unit | device_invite_projector_tests::tests::test_device_invite_writes_pending_trust | pass |
| SPEC_TCL_SPKI_01 | InvSPKIUniqueness | CHK_TCL_SPKI_UNIQUE | transport_credential | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_SPKI_01 | InvSPKIUniqueness | CHK_TCL_SPKI_UNIQUE | runtime_unit | runtime::transport::cert::tests::test_validate_cert_key_match_detects_mismatch | break |
| SPEC_TCL_TRUST_UNION_01 | InvTrustSetIsExactUnion | CHK_TCL_TRUST_UNION | transport_credential | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_TRUST_UNION_01 | InvTrustSetIsExactUnion | CHK_TCL_TRUST_UNION | runtime_unit | state::db::transport_trust::tests::test_is_authorized_for_tenant_checks_all_sources | break |
| SPEC_TCL_SOURCES_01 | InvTrustSourcesWellFormed | CHK_TCL_SOURCES_FORMED | transport_credential | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_SOURCES_01 | InvTrustSourcesWellFormed | CHK_TCL_SOURCES_FORMED | runtime_unit | state::db::transport_trust::tests::test_allowed_peers_count_ignores_malformed_rows | break |
| SPEC_TCL_MUTUAL_01 | InvMutualAuthSymmetry | CHK_TCL_MUTUAL_AUTH | transport_credential | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_MUTUAL_01 | InvMutualAuthSymmetry | CHK_TCL_MUTUAL_AUTH | runtime_unit | state::db::transport_trust::tests::test_mutual_trust_requires_both_sides | break |
| SPEC_TCL_MEMBERS_01 | InvTrustedPeerSetMembers | CHK_TCL_TRUSTED_MEMBERS | transport_credential | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_MEMBERS_01 | InvTrustedPeerSetMembers | CHK_TCL_TRUSTED_MEMBERS | runtime_unit | state::db::transport_trust::tests::test_binding_alone_not_in_authorized_fingerprints | break |
| SPEC_TCL_BOOTSTRAP_MATCH_01 | InvBootstrapTrustMatchesCarried | CHK_TCL_BOOTSTRAP_MATCH | transport_credential | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_BOOTSTRAP_MATCH_01 | InvBootstrapTrustMatchesCarried | CHK_TCL_BOOTSTRAP_MATCH | runtime_unit | state::db::transport_trust::tests::test_expired_invite_bootstrap_not_in_authorized_fingerprints | break |
| SPEC_TCL_PENDING_MATCH_01 | InvPendingBootstrapTrustMatchesCarried | CHK_TCL_PENDING_MATCH | transport_credential | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_PENDING_MATCH_01 | InvPendingBootstrapTrustMatchesCarried | CHK_TCL_PENDING_MATCH | runtime_unit | state::db::transport_trust::tests::test_expired_pending_invite_bootstrap_not_in_authorized_fingerprints | break |
| SPEC_TCL_CRED_SOURCE_01 | InvCredentialSourceConsistency | CHK_TCL_CRED_SOURCE_CONSISTENCY | transport_credential | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_TCL_CRED_SOURCE_01 | InvCredentialSourceConsistency | CHK_TCL_CRED_SOURCE_CONSISTENCY | runtime_unit | runtime::transport::identity_adapter::tests::bootstrap_install_rejected_after_peershared_for_same_peer | break |

## Exact Transport Targeting Invariants

| spec_id | source | check_id | layer | test_id | polarity |
|---------|--------|----------|-------|---------|----------|
| SPEC_ETT_INBOUND_01 | InvInboundAdmittedAuthorized | CHK_ETT_INBOUND_EXACT_TARGET | runtime_unit | runtime::transport::session_auth::tests::open_session_route_accepts_known_daemon_binding_without_local_signer | pass |
| SPEC_ETT_INBOUND_01 | InvInboundAdmittedAuthorized | CHK_ETT_INBOUND_EXACT_TARGET | runtime_unit | runtime::transport::session_auth::tests::open_session_route_rejects_when_only_other_tenant_authorizes_remote_peer | break |
| SPEC_ETT_CROSS_TENANT_01 | InvNoCrossTenantFallback | CHK_ETT_NO_CROSS_TENANT_FALLBACK | runtime_unit | runtime::transport::session_auth::tests::open_session_route_accepts_known_daemon_binding_without_local_signer | pass |
| SPEC_ETT_CROSS_TENANT_01 | InvNoCrossTenantFallback | CHK_ETT_NO_CROSS_TENANT_FALLBACK | runtime_unit | runtime::transport::session_auth::tests::open_session_route_rejects_when_only_other_tenant_authorizes_remote_peer | break |
| SPEC_ETT_OUTBOUND_01 | InvOutboundConnectedAuthorized | CHK_ETT_OUTBOUND_EXACT_REMOTE | runtime_unit | connection_lifecycle::tests::dial_and_accept_extract_expected_peer_ids | pass |
| SPEC_ETT_OUTBOUND_01 | InvOutboundConnectedAuthorized | CHK_ETT_OUTBOUND_EXACT_REMOTE | runtime_unit | connection_lifecycle::tests::dial_daemon_rejects_invalid_remote_daemon_id | break |

## UnifiedBridge Invariants

| spec_id | source | check_id | layer | test_id | polarity |
|---------|--------|----------|-------|---------|----------|
| SPEC_BR_ROW_RUNTIME_01 | BrInv_RowToMaterializedExactness | CHK_BRIDGE_ROW_TO_RUNTIME_TRUST | bridge_integration | apply::tests::tenant::test_signed_content_events_project_with_identity_chain | pass |
| SPEC_BR_ROW_RUNTIME_01 | BrInv_RowToMaterializedExactness | CHK_BRIDGE_ROW_TO_RUNTIME_TRUST | bridge_integration | state::db::transport_trust::tests::test_binding_alone_not_in_authorized_fingerprints | break |
| SPEC_BR_PENDING_LOCAL_01 | BrInv_PendingOnlyOnInviter | CHK_BRIDGE_PENDING_LOCAL_CREATE | projector_unit | user_invite_projector_tests::tests::test_user_invite_writes_pending_trust | pass |
| SPEC_BR_PENDING_LOCAL_01 | BrInv_PendingOnlyOnInviter | CHK_BRIDGE_PENDING_LOCAL_CREATE | projector_unit | user_invite_projector_tests::tests::test_user_invite_no_pending_when_not_local | break |
| SPEC_BR_PENDING_LOCAL_02 | BrInv_PendingOnlyOnInviter | CHK_BRIDGE_PENDING_LOCAL_CREATE | projector_unit | device_invite_projector_tests::tests::test_device_invite_writes_pending_trust | pass |
| SPEC_BR_PENDING_LOCAL_02 | BrInv_PendingOnlyOnInviter | CHK_BRIDGE_PENDING_LOCAL_CREATE | projector_unit | device_invite_projector_tests::tests::test_device_invite_no_pending_when_not_local | break |
| SPEC_BR_ALLOWED_AUTH_01 | BrInv_AllowedPeerMatchesAuthDecision | CHK_BRIDGE_ALLOWED_PEER_AUTH | bridge_integration | tlc::UnifiedBridge::unified_bridge_fix_repro.cfg | pass |
| SPEC_BR_ALLOWED_AUTH_01 | BrInv_AllowedPeerMatchesAuthDecision | CHK_BRIDGE_ALLOWED_PEER_AUTH | runtime_unit | state::db::transport_trust::tests::test_is_authorized_for_tenant_checks_all_sources | pass |
| SPEC_BR_ALLOWED_AUTH_01 | BrInv_AllowedPeerMatchesAuthDecision | CHK_BRIDGE_ALLOWED_PEER_AUTH | runtime_unit | state::db::transport_trust::tests::test_is_authorized_for_tenant_checks_all_sources | break |
| SPEC_BR_ONGOING_PREF_01 | BrInv_OngoingPreferred | CHK_BRIDGE_ONGOING_PREFERENCE | runtime_unit | target_dispatch::tests::known_peer_targets_follow_preferred_side_gate | pass |
| SPEC_BR_ONGOING_PREF_01 | BrInv_OngoingPreferred | CHK_BRIDGE_ONGOING_PREFERENCE | runtime_unit | target_dispatch::tests::known_peer_targets_follow_preferred_side_gate | break |
| SPEC_BR_FALLBACK_01 | BrInv_BootstrapFallbackOnlyWhenNeeded | CHK_BRIDGE_BOOTSTRAP_FALLBACK | runtime_unit | bootstrap_auth::tests::known_peer_uses_bootstrap_fallback_when_available | pass |
| SPEC_BR_FALLBACK_01 | BrInv_BootstrapFallbackOnlyWhenNeeded | CHK_BRIDGE_BOOTSTRAP_FALLBACK | runtime_unit | bootstrap_auth::tests::known_peer_without_bootstrap_fallback_keeps_preferred_side_gate | break |
| SPEC_BR_CTX_DET_01 | BrInv_BootstrapContextDeterministic | CHK_BRIDGE_BOOTSTRAP_CTX_DETERMINISM | runtime_unit | bootstrap_auth::tests::bootstrap_session_fallback_is_deterministic_for_single_row | pass |
| SPEC_BR_CTX_DET_01 | BrInv_BootstrapContextDeterministic | CHK_BRIDGE_BOOTSTRAP_CTX_DETERMINISM | runtime_unit | bootstrap_auth::tests::bootstrap_session_fallback_returns_none_when_ambiguous | break |
| SPEC_BR_SEC_CONN_01 | BrSec_ConnectionRequiresAuthorization | CHK_BRIDGE_SEC_CONN_AUTHZ | bridge_integration | tlc::UnifiedBridge::unified_bridge_fix_repro.cfg | pass |
| SPEC_BR_SEC_CONN_01 | BrSec_ConnectionRequiresAuthorization | CHK_BRIDGE_SEC_CONN_AUTHZ | runtime_unit | runtime::transport::session_auth::tests::invite_bootstrap_auth_accepts_accepted_bootstrap_trust_without_pending_row | pass |
| SPEC_BR_SEC_CONN_01 | BrSec_ConnectionRequiresAuthorization | CHK_BRIDGE_SEC_CONN_AUTHZ | runtime_unit | runtime::transport::session_auth::tests::invite_bootstrap_auth_rejects_when_bootstrap_trust_targets_other_daemon | break |
| SPEC_BR_SEC_PROV_01 | BrSec_NoTrustWithoutProvenance | CHK_BRIDGE_SEC_TRUST_PROVENANCE | bridge_integration | tlc::UnifiedBridge::unified_bridge_fix_repro.cfg | pass |
| SPEC_BR_SEC_PROV_01 | BrSec_NoTrustWithoutProvenance | CHK_BRIDGE_SEC_TRUST_PROVENANCE | runtime_unit | state::db::transport_trust::tests::test_invite_bootstrap_trust_in_authorized_fingerprints | pass |
| SPEC_BR_SEC_PROV_01 | BrSec_NoTrustWithoutProvenance | CHK_BRIDGE_SEC_TRUST_PROVENANCE | runtime_unit | state::db::transport_trust::tests::test_binding_alone_not_in_authorized_fingerprints | break |
| SPEC_BR_SEC_PENDING_01 | BrSec_NoPendingTrustOnJoiner | CHK_BRIDGE_SEC_PENDING_INVITER_ONLY | projector_unit | user_invite_projector_tests::tests::test_user_invite_no_pending_when_not_local | break |
| SPEC_BR_SEC_PENDING_01 | BrSec_NoPendingTrustOnJoiner | CHK_BRIDGE_SEC_PENDING_INVITER_ONLY | projector_unit | user_invite_projector_tests::tests::test_user_invite_writes_pending_trust | pass |
| SPEC_BR_SEC_BIND_01 | BrSec_SourceBindingConsistency | CHK_BRIDGE_SEC_SOURCE_BINDING | bridge_integration | tlc::UnifiedBridge::unified_bridge_fix_repro.cfg | pass |
| SPEC_BR_SEC_BIND_01 | BrSec_SourceBindingConsistency | CHK_BRIDGE_SEC_SOURCE_BINDING | runtime_unit | state::db::transport_trust::tests::test_peer_shared_derived_in_authorized_fingerprints | pass |
| SPEC_BR_SEC_BIND_01 | BrSec_SourceBindingConsistency | CHK_BRIDGE_SEC_SOURCE_BINDING | runtime_unit | state::db::transport_trust::tests::test_malformed_peer_shared_pubkey_skipped | break |
| SPEC_BR_SEC_COLLIDE_01 | BrSec_NoIdentityCollisionInAuthPath | CHK_BRIDGE_SEC_IDENTITY_COLLISION | bridge_integration | tlc::UnifiedBridge::unified_bridge_fix_repro.cfg | pass |
| SPEC_BR_SEC_COLLIDE_01 | BrSec_NoIdentityCollisionInAuthPath | CHK_BRIDGE_SEC_IDENTITY_COLLISION | runtime_unit | runtime::transport::cert::tests::test_spki_fingerprint_different_certs | pass |
| SPEC_BR_SEC_COLLIDE_01 | BrSec_NoIdentityCollisionInAuthPath | CHK_BRIDGE_SEC_IDENTITY_COLLISION | runtime_unit | runtime::transport::cert::tests::test_validate_cert_key_match_detects_mismatch | break |
| SPEC_BR_LIVE_BOOTSTRAP_01 | BrLive_BootstrapConnectEventually | CHK_BRIDGE_BOOTSTRAP_PROGRESS | tla_liveness | tlc::UnifiedBridge::unified_bridge_progress_fast.cfg | pass |
| SPEC_BR_LIVE_BOOTSTRAP_01 | BrLive_BootstrapConnectEventually | CHK_BRIDGE_BOOTSTRAP_PROGRESS | tla_liveness | — | waiver:liveness_counterexamples_tracked_in_bug_cfg |
| SPEC_BR_LIVE_UPGRADE_01 | BrLive_PeerUpgradeEventually | CHK_BRIDGE_UPGRADE_PROGRESS | tla_liveness | tlc::UnifiedBridge::unified_bridge_progress_fast.cfg | pass |
| SPEC_BR_LIVE_UPGRADE_01 | BrLive_PeerUpgradeEventually | CHK_BRIDGE_UPGRADE_PROGRESS | tla_liveness | — | waiver:liveness_counterexamples_tracked_in_bug_cfg |
| SPEC_BR_LIVE_SYNC_01 | BrLive_BootstrapCompletionSyncEventually | CHK_BRIDGE_SYNC_COMPLETION_PROGRESS | tla_liveness | tlc::UnifiedBridge::unified_bridge_progress_fast.cfg | pass |
| SPEC_BR_LIVE_SYNC_01 | BrLive_BootstrapCompletionSyncEventually | CHK_BRIDGE_SYNC_COMPLETION_PROGRESS | tla_liveness | — | waiver:liveness_counterexamples_tracked_in_bug_cfg |

## EndpointBootstrapRoute Invariants

| spec_id | source | check_id | layer | test_id | polarity |
|---------|--------|----------|-------|---------|----------|
| SPEC_EP_BOOTSTRAP_SCOPE_01 | InvBootstrapAdmissionProofScoped | CHK_ENDPOINT_BOOTSTRAP_PROOF_SCOPE | runtime_unit | runtime::transport::session_auth::tests::invite_bootstrap_auth_accepts_accepted_bootstrap_trust_without_pending_row | pass |
| SPEC_EP_BOOTSTRAP_SCOPE_01 | InvBootstrapAdmissionProofScoped | CHK_ENDPOINT_BOOTSTRAP_PROOF_SCOPE | runtime_unit | runtime::transport::session_auth::tests::invite_bootstrap_auth_rejects_when_bootstrap_trust_targets_other_daemon | break |

## Replay/Order Conformance

| spec_id | source | check_id | layer | test_id | polarity |
|---------|--------|----------|-------|---------|----------|
| SPEC_REPLAY_CONVERGE_01 | InvDeps (convergence) | CHK_REPLAY_CONVERGENCE | replay_integration | apply::tests::cascade::test_source_isomorphism_message_reaction_chain | pass |
| SPEC_REPLAY_CONVERGE_01 | InvDeps (convergence) | CHK_REPLAY_CONVERGENCE | replay_integration | apply::tests::cascade::test_source_isomorphism_reverse_order_replay | pass |
| SPEC_REPLAY_CONVERGE_02 | InvDeps (convergence) | CHK_REPLAY_CONVERGENCE | replay_integration | apply::tests::cascade::test_source_isomorphism_encrypted_message | pass |
| SPEC_REPLAY_IDEMPOTENT_01 | (idempotent) | CHK_REPLAY_IDEMPOTENT | replay_integration | apply::tests::core_projection::test_already_processed | pass |
| SPEC_REPLAY_IDEMPOTENT_01 | (idempotent) | CHK_REPLAY_IDEMPOTENT | replay_integration | apply::tests::cascade::test_source_isomorphism_idempotent_double_projection | pass |
| SPEC_DEL_CONVERGENCE_01 | (deletion convergence) | CHK_DEL_TWO_STAGE_CONVERGENCE | replay_integration | apply::tests::deletion::test_deletion_convergence | pass |
| SPEC_DEL_CONVERGENCE_01 | (deletion convergence) | CHK_DEL_TWO_STAGE_CONVERGENCE | replay_integration | apply::tests::deletion::test_deletion_intent_then_target_arrives | pass |
| SPEC_DEL_CONVERGENCE_02 | (deletion convergence) | CHK_DEL_TWO_STAGE_CONVERGENCE | replay_integration | apply::tests::cascade::test_source_isomorphism_deletion_cascade | pass |
| SPEC_CASCADE_CONVERGE_01 | InvDeps (cascade) | CHK_CASCADE_UNBLOCK | replay_integration | apply::tests::cascade::test_source_isomorphism_multi_event_deep_cascade | pass |
| SPEC_CASCADE_CONVERGE_01 | InvDeps (cascade) | CHK_CASCADE_UNBLOCK | replay_integration | apply::tests::cascade::test_cascade_and_direct_produce_same_state | pass |
| SPEC_REPLAY_TERMINAL_01 | (terminal stability) | CHK_REPLAY_TERMINAL | replay_integration | apply::tests::core_projection::test_already_processed | pass |
| SPEC_REPLAY_TERMINAL_01 | (terminal stability) | CHK_REPLAY_TERMINAL | replay_integration | apply::tests::cascade::test_source_isomorphism_message_reaction_chain | break |
