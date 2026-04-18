//! Formal verification of inbound route/bootstrap admission planning.
//!
//! Every `pub fn` below is executable Rust consumed by
//! `src/runtime/transport/session_auth.rs`. Postconditions (`ensures`) are
//! SMT-checked against the function body by `cargo-verus verify`.

use vstd::prelude::*;

verus! {

/// Primitive core of the bootstrap-session-tenant raw rows — carries only a
/// row count and an equality flag. The runtime aggregates its
/// `Vec<String>` of tenant ids into this core before calling the verified
/// planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapSessionTenantRawRows {
    pub row_count: u32,
    pub all_tenant_ids_equal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapSessionTenantDecisionContext {
    MissingTenantBinding,
    UniqueTenantBinding,
    AmbiguousTenantBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapSessionTenantPlan {
    RejectMissingTenantBinding,
    Accept,
    RejectAmbiguousTenantBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRouteAuthRawRows {
    pub route_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRouteAuthDecisionContext {
    pub route_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundRouteAuthDecision {
    RejectUnauthorized,
    Accept,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundBootstrapAuthRawRows {
    pub tenant_resolution: BootstrapSessionTenantDecisionContext,
    pub has_cached_tenant: bool,
    pub expiry_valid: bool,
    pub daemon_binding_valid: bool,
    pub claimed_peer_matches_key: bool,
    pub invite_signature_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundBootstrapAuthDecisionContext {
    pub tenant_resolution: BootstrapSessionTenantDecisionContext,
    pub has_cached_tenant: bool,
    pub expiry_valid: bool,
    pub daemon_binding_valid: bool,
    pub claimed_peer_matches_key: bool,
    pub invite_signature_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundBootstrapAuthDecision {
    RejectInvalidAuth,
    AcceptResolvedTenant,
    AcceptCachedTenant,
    RejectTenantResolution,
}

pub fn normalize_bootstrap_session_tenant_decision_context(
    raw_rows: BootstrapSessionTenantRawRows,
) -> (context: BootstrapSessionTenantDecisionContext)
    ensures
        raw_rows.row_count == 0
            ==> context == BootstrapSessionTenantDecisionContext::MissingTenantBinding,
        (raw_rows.row_count > 0 && raw_rows.all_tenant_ids_equal)
            ==> context == BootstrapSessionTenantDecisionContext::UniqueTenantBinding,
        (raw_rows.row_count > 0 && !raw_rows.all_tenant_ids_equal)
            ==> context == BootstrapSessionTenantDecisionContext::AmbiguousTenantBinding,
{
    if raw_rows.row_count == 0 {
        BootstrapSessionTenantDecisionContext::MissingTenantBinding
    } else if raw_rows.all_tenant_ids_equal {
        BootstrapSessionTenantDecisionContext::UniqueTenantBinding
    } else {
        BootstrapSessionTenantDecisionContext::AmbiguousTenantBinding
    }
}

pub fn decide_bootstrap_session_tenant_plan(
    context: &BootstrapSessionTenantDecisionContext,
) -> (plan: BootstrapSessionTenantPlan)
    ensures
        *context == BootstrapSessionTenantDecisionContext::MissingTenantBinding
            ==> plan == BootstrapSessionTenantPlan::RejectMissingTenantBinding,
        *context == BootstrapSessionTenantDecisionContext::UniqueTenantBinding
            ==> plan == BootstrapSessionTenantPlan::Accept,
        *context == BootstrapSessionTenantDecisionContext::AmbiguousTenantBinding
            ==> plan == BootstrapSessionTenantPlan::RejectAmbiguousTenantBinding,
{
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

pub fn normalize_inbound_route_auth_decision_context(
    raw_rows: InboundRouteAuthRawRows,
) -> (context: InboundRouteAuthDecisionContext)
    ensures context.route_authorized == raw_rows.route_authorized,
{
    InboundRouteAuthDecisionContext {
        route_authorized: raw_rows.route_authorized,
    }
}

pub fn decide_inbound_route_auth(
    context: &InboundRouteAuthDecisionContext,
) -> (decision: InboundRouteAuthDecision)
    ensures
        context.route_authorized ==> decision == InboundRouteAuthDecision::Accept,
        !context.route_authorized ==> decision == InboundRouteAuthDecision::RejectUnauthorized,
{
    if context.route_authorized {
        InboundRouteAuthDecision::Accept
    } else {
        InboundRouteAuthDecision::RejectUnauthorized
    }
}

pub fn normalize_inbound_bootstrap_auth_decision_context(
    raw_rows: InboundBootstrapAuthRawRows,
) -> (context: InboundBootstrapAuthDecisionContext)
    ensures
        context.tenant_resolution == raw_rows.tenant_resolution,
        context.has_cached_tenant == raw_rows.has_cached_tenant,
        context.expiry_valid == raw_rows.expiry_valid,
        context.daemon_binding_valid == raw_rows.daemon_binding_valid,
        context.claimed_peer_matches_key == raw_rows.claimed_peer_matches_key,
        context.invite_signature_valid == raw_rows.invite_signature_valid,
{
    InboundBootstrapAuthDecisionContext {
        tenant_resolution: raw_rows.tenant_resolution,
        has_cached_tenant: raw_rows.has_cached_tenant,
        expiry_valid: raw_rows.expiry_valid,
        daemon_binding_valid: raw_rows.daemon_binding_valid,
        claimed_peer_matches_key: raw_rows.claimed_peer_matches_key,
        invite_signature_valid: raw_rows.invite_signature_valid,
    }
}

pub fn decide_inbound_bootstrap_auth(
    context: &InboundBootstrapAuthDecisionContext,
) -> (decision: InboundBootstrapAuthDecision)
    ensures
        // Any failing primitive auth check rejects before tenant resolution.
        (!context.expiry_valid
            || !context.daemon_binding_valid
            || !context.claimed_peer_matches_key
            || !context.invite_signature_valid)
            ==> decision == InboundBootstrapAuthDecision::RejectInvalidAuth,
        // Unique tenant binding (with all auth checks valid) accepts the resolved tenant.
        (context.expiry_valid
            && context.daemon_binding_valid
            && context.claimed_peer_matches_key
            && context.invite_signature_valid
            && context.tenant_resolution == BootstrapSessionTenantDecisionContext::UniqueTenantBinding)
            ==> decision == InboundBootstrapAuthDecision::AcceptResolvedTenant,
        // Missing or ambiguous tenant resolution with a cached tenant accepts the cache.
        (context.expiry_valid
            && context.daemon_binding_valid
            && context.claimed_peer_matches_key
            && context.invite_signature_valid
            && context.tenant_resolution != BootstrapSessionTenantDecisionContext::UniqueTenantBinding
            && context.has_cached_tenant)
            ==> decision == InboundBootstrapAuthDecision::AcceptCachedTenant,
        // Missing or ambiguous tenant resolution with no cached tenant rejects.
        (context.expiry_valid
            && context.daemon_binding_valid
            && context.claimed_peer_matches_key
            && context.invite_signature_valid
            && context.tenant_resolution != BootstrapSessionTenantDecisionContext::UniqueTenantBinding
            && !context.has_cached_tenant)
            ==> decision == InboundBootstrapAuthDecision::RejectTenantResolution,
{
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

} // verus!
