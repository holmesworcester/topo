//! Formal verification of target-dispatch precedence and spawn policy.

use vstd::prelude::*;

verus! {

pub enum TargetSourceKind {
    Bootstrap,
    KnownPeer,
}

pub enum DispatchAction {
    Skip,
    Connect,
    Reconnect,
}

pub enum TargetDispatchPlan {
    Skip,
    Spawn { cancel_existing_dispatch_key: bool, cancel_bootstrap_prefix: bool },
}

pub open spec fn decide_target_dispatch_plan(
    incoming_source: TargetSourceKind,
    should_initiate_connect: bool,
    bootstrap_phase: bool,
    has_active_higher_precedence_worker: bool,
    dispatch_action: DispatchAction,
) -> TargetDispatchPlan {
    if !should_initiate_connect {
        TargetDispatchPlan::Skip
    } else if matches!(incoming_source, TargetSourceKind::Bootstrap)
        && has_active_higher_precedence_worker
        && !bootstrap_phase
    {
        TargetDispatchPlan::Skip
    } else {
        match dispatch_action {
            DispatchAction::Skip => TargetDispatchPlan::Skip,
            DispatchAction::Connect => TargetDispatchPlan::Spawn {
                cancel_existing_dispatch_key: false,
                cancel_bootstrap_prefix: matches!(incoming_source, TargetSourceKind::KnownPeer)
                    && !bootstrap_phase,
            },
            DispatchAction::Reconnect => TargetDispatchPlan::Spawn {
                cancel_existing_dispatch_key: true,
                cancel_bootstrap_prefix: matches!(incoming_source, TargetSourceKind::KnownPeer)
                    && !bootstrap_phase,
            },
        }
    }
}

proof fn bootstrap_is_suppressed_by_active_known_peer_outside_bootstrap_phase(
    dispatch_action: DispatchAction,
)
    requires !matches!(dispatch_action, DispatchAction::Skip)
    ensures matches!(
        decide_target_dispatch_plan(
            TargetSourceKind::Bootstrap,
            true,
            false,
            true,
            dispatch_action,
        ),
        TargetDispatchPlan::Skip
    ),
{
}

proof fn bootstrap_phase_keeps_bootstrap_dispatch_available(dispatch_action: DispatchAction)
    requires !matches!(dispatch_action, DispatchAction::Skip)
    ensures !matches!(
        decide_target_dispatch_plan(
            TargetSourceKind::Bootstrap,
            true,
            true,
            true,
            dispatch_action,
        ),
        TargetDispatchPlan::Skip
    ),
{
}

proof fn dispatcher_skip_produces_no_spawn(
    incoming_source: TargetSourceKind,
    bootstrap_phase: bool,
    has_active_higher_precedence_worker: bool,
)
    requires
        !(matches!(incoming_source, TargetSourceKind::Bootstrap)
            && has_active_higher_precedence_worker
            && !bootstrap_phase)
    ensures matches!(
        decide_target_dispatch_plan(
            incoming_source,
            true,
            bootstrap_phase,
            has_active_higher_precedence_worker,
            DispatchAction::Skip,
        ),
        TargetDispatchPlan::Skip
    ),
{
}

proof fn known_peer_outside_bootstrap_phase_cancels_bootstrap_prefix(
    cancel_existing_dispatch_key: bool,
)
    ensures
        decide_target_dispatch_plan(
            TargetSourceKind::KnownPeer,
            true,
            false,
            false,
            if cancel_existing_dispatch_key {
                DispatchAction::Reconnect
            } else {
                DispatchAction::Connect
            },
        ) == (TargetDispatchPlan::Spawn {
            cancel_existing_dispatch_key,
            cancel_bootstrap_prefix: true,
        }),
{
}

proof fn known_peer_during_bootstrap_phase_keeps_bootstrap_prefix(
    cancel_existing_dispatch_key: bool,
)
    ensures
        decide_target_dispatch_plan(
            TargetSourceKind::KnownPeer,
            true,
            true,
            false,
            if cancel_existing_dispatch_key {
                DispatchAction::Reconnect
            } else {
                DispatchAction::Connect
            },
        ) == (TargetDispatchPlan::Spawn {
            cancel_existing_dispatch_key,
            cancel_bootstrap_prefix: false,
        }),
{
}

} // verus!
