//! Formal verification of inbound route/bootstrap admission planning.

use vstd::prelude::*;

verus! {

pub struct BootstrapSessionTenantRawRows {
    pub row_count: nat,
    pub all_tenant_ids_equal: bool,
}

pub enum BootstrapSessionTenantDecisionContext {
    MissingTenantBinding,
    UniqueTenantBinding,
    AmbiguousTenantBinding,
}

pub enum BootstrapSessionTenantPlan {
    RejectMissingTenantBinding,
    Accept,
    RejectAmbiguousTenantBinding,
}

pub enum InboundRouteAuthDecision {
    RejectUnauthorized,
    Accept,
}

pub enum InboundBootstrapAuthDecision {
    RejectInvalidAuth,
    AcceptResolvedTenant,
    AcceptCachedTenant,
    RejectTenantResolution,
}

pub open spec fn normalize_bootstrap_session_tenant_decision_context(
    raw_rows: BootstrapSessionTenantRawRows,
) -> BootstrapSessionTenantDecisionContext {
    if raw_rows.row_count == 0 {
        BootstrapSessionTenantDecisionContext::MissingTenantBinding
    } else if raw_rows.all_tenant_ids_equal {
        BootstrapSessionTenantDecisionContext::UniqueTenantBinding
    } else {
        BootstrapSessionTenantDecisionContext::AmbiguousTenantBinding
    }
}

pub open spec fn decide_bootstrap_session_tenant_plan(
    context: BootstrapSessionTenantDecisionContext,
) -> BootstrapSessionTenantPlan {
    match context {
        BootstrapSessionTenantDecisionContext::MissingTenantBinding => {
            BootstrapSessionTenantPlan::RejectMissingTenantBinding
        }
        BootstrapSessionTenantDecisionContext::UniqueTenantBinding => {
            BootstrapSessionTenantPlan::Accept
        }
        BootstrapSessionTenantDecisionContext::AmbiguousTenantBinding => {
            BootstrapSessionTenantPlan::RejectAmbiguousTenantBinding
        }
    }
}

pub open spec fn decide_inbound_route_auth(route_authorized: bool) -> InboundRouteAuthDecision {
    if route_authorized {
        InboundRouteAuthDecision::Accept
    } else {
        InboundRouteAuthDecision::RejectUnauthorized
    }
}

pub open spec fn decide_inbound_bootstrap_auth(
    tenant_resolution: BootstrapSessionTenantDecisionContext,
    has_cached_tenant: bool,
    expiry_valid: bool,
    daemon_binding_valid: bool,
    claimed_peer_matches_key: bool,
    invite_signature_valid: bool,
) -> InboundBootstrapAuthDecision {
    if !expiry_valid || !daemon_binding_valid || !claimed_peer_matches_key || !invite_signature_valid
    {
        InboundBootstrapAuthDecision::RejectInvalidAuth
    } else {
        match tenant_resolution {
            BootstrapSessionTenantDecisionContext::UniqueTenantBinding => {
                InboundBootstrapAuthDecision::AcceptResolvedTenant
            }
            BootstrapSessionTenantDecisionContext::MissingTenantBinding
            | BootstrapSessionTenantDecisionContext::AmbiguousTenantBinding => {
                if has_cached_tenant {
                    InboundBootstrapAuthDecision::AcceptCachedTenant
                } else {
                    InboundBootstrapAuthDecision::RejectTenantResolution
                }
            }
        }
    }
}

proof fn inbound_route_rejects_unauthorized()
    ensures decide_inbound_route_auth(false) == InboundRouteAuthDecision::RejectUnauthorized,
{
}

proof fn inbound_route_accepts_authorized()
    ensures decide_inbound_route_auth(true) == InboundRouteAuthDecision::Accept,
{
}

proof fn bootstrap_session_tenant_normalizes_empty_to_missing()
    ensures
        normalize_bootstrap_session_tenant_decision_context(BootstrapSessionTenantRawRows {
            row_count: 0,
            all_tenant_ids_equal: true,
        }) == BootstrapSessionTenantDecisionContext::MissingTenantBinding,
{
}

proof fn bootstrap_session_tenant_normalizes_equal_rows_to_unique(row_count: nat)
    requires row_count > 0
    ensures
        normalize_bootstrap_session_tenant_decision_context(BootstrapSessionTenantRawRows {
            row_count,
            all_tenant_ids_equal: true,
        }) == BootstrapSessionTenantDecisionContext::UniqueTenantBinding,
        decide_bootstrap_session_tenant_plan(
            normalize_bootstrap_session_tenant_decision_context(BootstrapSessionTenantRawRows {
                row_count,
                all_tenant_ids_equal: true,
            })
        ) == BootstrapSessionTenantPlan::Accept,
{
}

proof fn bootstrap_session_tenant_normalizes_mixed_rows_to_ambiguous(row_count: nat)
    requires row_count > 0
    ensures
        normalize_bootstrap_session_tenant_decision_context(BootstrapSessionTenantRawRows {
            row_count,
            all_tenant_ids_equal: false,
        }) == BootstrapSessionTenantDecisionContext::AmbiguousTenantBinding,
        decide_bootstrap_session_tenant_plan(
            normalize_bootstrap_session_tenant_decision_context(BootstrapSessionTenantRawRows {
                row_count,
                all_tenant_ids_equal: false,
            })
        ) == BootstrapSessionTenantPlan::RejectAmbiguousTenantBinding,
{
}

proof fn inbound_bootstrap_rejects_invalid_auth_even_with_cached_tenant()
    ensures
        decide_inbound_bootstrap_auth(
            BootstrapSessionTenantDecisionContext::MissingTenantBinding,
            true,
            false,
            true,
            true,
            true,
        ) == InboundBootstrapAuthDecision::RejectInvalidAuth,
{
}

proof fn inbound_bootstrap_accepts_cached_tenant_after_resolution_loss()
    ensures
        decide_inbound_bootstrap_auth(
            BootstrapSessionTenantDecisionContext::MissingTenantBinding,
            true,
            true,
            true,
            true,
            true,
        ) == InboundBootstrapAuthDecision::AcceptCachedTenant,
{
}

proof fn inbound_bootstrap_accepts_resolved_tenant_without_cache()
    ensures
        decide_inbound_bootstrap_auth(
            BootstrapSessionTenantDecisionContext::UniqueTenantBinding,
            false,
            true,
            true,
            true,
            true,
        ) == InboundBootstrapAuthDecision::AcceptResolvedTenant,
{
}

} // verus!
