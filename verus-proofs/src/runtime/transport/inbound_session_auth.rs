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

pub struct InboundRouteAuthRawRows {
    pub route_authorized: bool,
}

pub struct InboundRouteAuthDecisionContext {
    pub route_authorized: bool,
}

pub enum InboundRouteAuthDecision {
    RejectUnauthorized,
    Accept,
}

pub struct InboundBootstrapAuthRawRows {
    pub tenant_resolution: BootstrapSessionTenantDecisionContext,
    pub has_cached_tenant: bool,
    pub expiry_valid: bool,
    pub daemon_binding_valid: bool,
    pub claimed_peer_matches_key: bool,
    pub invite_signature_valid: bool,
}

pub struct InboundBootstrapAuthDecisionContext {
    pub tenant_resolution: BootstrapSessionTenantDecisionContext,
    pub has_cached_tenant: bool,
    pub expiry_valid: bool,
    pub daemon_binding_valid: bool,
    pub claimed_peer_matches_key: bool,
    pub invite_signature_valid: bool,
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

pub open spec fn normalize_inbound_route_auth_decision_context(
    raw_rows: InboundRouteAuthRawRows,
) -> InboundRouteAuthDecisionContext {
    InboundRouteAuthDecisionContext {
        route_authorized: raw_rows.route_authorized,
    }
}

pub open spec fn decide_inbound_route_auth(
    context: &InboundRouteAuthDecisionContext,
) -> InboundRouteAuthDecision {
    if context.route_authorized {
        InboundRouteAuthDecision::Accept
    } else {
        InboundRouteAuthDecision::RejectUnauthorized
    }
}

pub open spec fn normalize_inbound_bootstrap_auth_decision_context(
    raw_rows: InboundBootstrapAuthRawRows,
) -> InboundBootstrapAuthDecisionContext {
    InboundBootstrapAuthDecisionContext {
        tenant_resolution: raw_rows.tenant_resolution,
        has_cached_tenant: raw_rows.has_cached_tenant,
        expiry_valid: raw_rows.expiry_valid,
        daemon_binding_valid: raw_rows.daemon_binding_valid,
        claimed_peer_matches_key: raw_rows.claimed_peer_matches_key,
        invite_signature_valid: raw_rows.invite_signature_valid,
    }
}

pub open spec fn decide_inbound_bootstrap_auth(
    context: &InboundBootstrapAuthDecisionContext,
) -> InboundBootstrapAuthDecision {
    if !context.expiry_valid
        || !context.daemon_binding_valid
        || !context.claimed_peer_matches_key
        || !context.invite_signature_valid
    {
        InboundBootstrapAuthDecision::RejectInvalidAuth
    } else {
        match context.tenant_resolution {
            BootstrapSessionTenantDecisionContext::UniqueTenantBinding => {
                InboundBootstrapAuthDecision::AcceptResolvedTenant
            }
            BootstrapSessionTenantDecisionContext::MissingTenantBinding
            | BootstrapSessionTenantDecisionContext::AmbiguousTenantBinding => {
                if context.has_cached_tenant {
                    InboundBootstrapAuthDecision::AcceptCachedTenant
                } else {
                    InboundBootstrapAuthDecision::RejectTenantResolution
                }
            }
        }
    }
}

proof fn inbound_route_rejects_unauthorized()
    ensures
        decide_inbound_route_auth(&InboundRouteAuthDecisionContext {
            route_authorized: false,
        }) == InboundRouteAuthDecision::RejectUnauthorized,
{
}

proof fn inbound_route_accepts_authorized()
    ensures
        decide_inbound_route_auth(&InboundRouteAuthDecisionContext {
            route_authorized: true,
        }) == InboundRouteAuthDecision::Accept,
{
}

proof fn inbound_route_auth_normalizer_preserves_query_facts(route_authorized: bool)
    ensures
        normalize_inbound_route_auth_decision_context(InboundRouteAuthRawRows {
            route_authorized,
        }) == (InboundRouteAuthDecisionContext {
            route_authorized,
        }),
{
}

proof fn inbound_bootstrap_auth_normalizer_preserves_query_facts(
    tenant_resolution: BootstrapSessionTenantDecisionContext,
    has_cached_tenant: bool,
    expiry_valid: bool,
    daemon_binding_valid: bool,
    claimed_peer_matches_key: bool,
    invite_signature_valid: bool,
)
    ensures
        normalize_inbound_bootstrap_auth_decision_context(InboundBootstrapAuthRawRows {
            tenant_resolution,
            has_cached_tenant,
            expiry_valid,
            daemon_binding_valid,
            claimed_peer_matches_key,
            invite_signature_valid,
        }) == (InboundBootstrapAuthDecisionContext {
            tenant_resolution,
            has_cached_tenant,
            expiry_valid,
            daemon_binding_valid,
            claimed_peer_matches_key,
            invite_signature_valid,
        }),
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

proof fn bootstrap_session_tenant_duplicate_row_count_is_noninterfering(
    row_count_a: nat,
    row_count_b: nat,
)
    requires
        row_count_a > 0,
        row_count_b > 0,
    ensures
        decide_bootstrap_session_tenant_plan(
            normalize_bootstrap_session_tenant_decision_context(BootstrapSessionTenantRawRows {
                row_count: row_count_a,
                all_tenant_ids_equal: true,
            })
        ) == decide_bootstrap_session_tenant_plan(
            normalize_bootstrap_session_tenant_decision_context(BootstrapSessionTenantRawRows {
                row_count: row_count_b,
                all_tenant_ids_equal: true,
            })
        ),
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
        decide_inbound_bootstrap_auth(&InboundBootstrapAuthDecisionContext {
            tenant_resolution: BootstrapSessionTenantDecisionContext::MissingTenantBinding,
            has_cached_tenant: true,
            expiry_valid: false,
            daemon_binding_valid: true,
            claimed_peer_matches_key: true,
            invite_signature_valid: true,
        }) == InboundBootstrapAuthDecision::RejectInvalidAuth,
{
}

proof fn inbound_bootstrap_accepts_cached_tenant_after_resolution_loss()
    ensures
        decide_inbound_bootstrap_auth(&InboundBootstrapAuthDecisionContext {
            tenant_resolution: BootstrapSessionTenantDecisionContext::MissingTenantBinding,
            has_cached_tenant: true,
            expiry_valid: true,
            daemon_binding_valid: true,
            claimed_peer_matches_key: true,
            invite_signature_valid: true,
        }) == InboundBootstrapAuthDecision::AcceptCachedTenant,
{
}

proof fn inbound_bootstrap_accepts_resolved_tenant_without_cache()
    ensures
        decide_inbound_bootstrap_auth(&InboundBootstrapAuthDecisionContext {
            tenant_resolution: BootstrapSessionTenantDecisionContext::UniqueTenantBinding,
            has_cached_tenant: false,
            expiry_valid: true,
            daemon_binding_valid: true,
            claimed_peer_matches_key: true,
            invite_signature_valid: true,
        }) == InboundBootstrapAuthDecision::AcceptResolvedTenant,
{
}

} // verus!
