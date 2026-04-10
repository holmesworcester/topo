//! Formal verification of inbound route/bootstrap admission planning.

use vstd::prelude::*;

verus! {

pub enum BootstrapSessionTenantDecision {
    RejectMissing,
    Accept,
    RejectAmbiguous,
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

pub open spec fn decide_inbound_route_auth(route_authorized: bool) -> InboundRouteAuthDecision {
    if route_authorized {
        InboundRouteAuthDecision::Accept
    } else {
        InboundRouteAuthDecision::RejectUnauthorized
    }
}

pub open spec fn decide_inbound_bootstrap_auth(
    tenant_resolution: BootstrapSessionTenantDecision,
    has_cached_tenant: bool,
    expiry_valid: bool,
    daemon_binding_valid: bool,
    claimed_peer_matches_key: bool,
    invite_signature_valid: bool,
) -> InboundBootstrapAuthDecision {
    if !expiry_valid || !daemon_binding_valid || !claimed_peer_matches_key || !invite_signature_valid {
        InboundBootstrapAuthDecision::RejectInvalidAuth
    } else {
        match tenant_resolution {
            BootstrapSessionTenantDecision::Accept => {
                InboundBootstrapAuthDecision::AcceptResolvedTenant
            }
            BootstrapSessionTenantDecision::RejectMissing
            | BootstrapSessionTenantDecision::RejectAmbiguous => {
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

proof fn inbound_bootstrap_rejects_invalid_auth_even_with_cached_tenant()
    ensures
        decide_inbound_bootstrap_auth(
            BootstrapSessionTenantDecision::RejectMissing,
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
            BootstrapSessionTenantDecision::RejectMissing,
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
            BootstrapSessionTenantDecision::Accept,
            false,
            true,
            true,
            true,
            true,
        ) == InboundBootstrapAuthDecision::AcceptResolvedTenant,
{
}

} // verus!
