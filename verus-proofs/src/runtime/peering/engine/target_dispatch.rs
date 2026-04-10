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

pub struct TargetDispatchDecisionContext {
    pub incoming_source: TargetSourceKind,
    pub should_initiate_connect: bool,
    pub bootstrap_phase: bool,
    pub has_active_higher_precedence_worker: bool,
    pub dispatch_action: DispatchAction,
}

pub enum TargetDispatchPlan {
    Skip,
    Spawn { cancel_existing_dispatch_key: bool, cancel_bootstrap_prefix: bool },
}

pub open spec fn decide_target_dispatch_plan(
    context: &TargetDispatchDecisionContext,
) -> TargetDispatchPlan {
    if !context.should_initiate_connect {
        TargetDispatchPlan::Skip
    } else if matches!(context.incoming_source, TargetSourceKind::Bootstrap)
        && context.has_active_higher_precedence_worker
        && !context.bootstrap_phase
    {
        TargetDispatchPlan::Skip
    } else {
        match context.dispatch_action {
            DispatchAction::Skip => TargetDispatchPlan::Skip,
            DispatchAction::Connect => TargetDispatchPlan::Spawn {
                cancel_existing_dispatch_key: false,
                cancel_bootstrap_prefix: matches!(context.incoming_source, TargetSourceKind::KnownPeer)
                    && !context.bootstrap_phase,
            },
            DispatchAction::Reconnect => TargetDispatchPlan::Spawn {
                cancel_existing_dispatch_key: true,
                cancel_bootstrap_prefix: matches!(context.incoming_source, TargetSourceKind::KnownPeer)
                    && !context.bootstrap_phase,
            },
        }
    }
}

proof fn bootstrap_is_suppressed_by_active_known_peer_outside_bootstrap_phase(
    dispatch_action: DispatchAction,
)
    requires !matches!(dispatch_action, DispatchAction::Skip)
    ensures matches!(
        decide_target_dispatch_plan(&TargetDispatchDecisionContext {
            incoming_source: TargetSourceKind::Bootstrap,
            should_initiate_connect: true,
            bootstrap_phase: false,
            has_active_higher_precedence_worker: true,
            dispatch_action,
        }),
        TargetDispatchPlan::Skip
    ),
{
}

proof fn bootstrap_phase_keeps_bootstrap_dispatch_available(dispatch_action: DispatchAction)
    requires !matches!(dispatch_action, DispatchAction::Skip)
    ensures !matches!(
        decide_target_dispatch_plan(&TargetDispatchDecisionContext {
            incoming_source: TargetSourceKind::Bootstrap,
            should_initiate_connect: true,
            bootstrap_phase: true,
            has_active_higher_precedence_worker: true,
            dispatch_action,
        }),
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
        decide_target_dispatch_plan(&TargetDispatchDecisionContext {
            incoming_source,
            should_initiate_connect: true,
            bootstrap_phase,
            has_active_higher_precedence_worker,
            dispatch_action: DispatchAction::Skip,
        }),
        TargetDispatchPlan::Skip
    ),
{
}

proof fn known_peer_outside_bootstrap_phase_cancels_bootstrap_prefix(
    cancel_existing_dispatch_key: bool,
)
    ensures
        decide_target_dispatch_plan(&TargetDispatchDecisionContext {
            incoming_source: TargetSourceKind::KnownPeer,
            should_initiate_connect: true,
            bootstrap_phase: false,
            has_active_higher_precedence_worker: false,
            dispatch_action: if cancel_existing_dispatch_key {
                DispatchAction::Reconnect
            } else {
                DispatchAction::Connect
            },
        }) == (TargetDispatchPlan::Spawn {
            cancel_existing_dispatch_key,
            cancel_bootstrap_prefix: true,
        }),
{
}

proof fn known_peer_during_bootstrap_phase_keeps_bootstrap_prefix(
    cancel_existing_dispatch_key: bool,
)
    ensures
        decide_target_dispatch_plan(&TargetDispatchDecisionContext {
            incoming_source: TargetSourceKind::KnownPeer,
            should_initiate_connect: true,
            bootstrap_phase: true,
            has_active_higher_precedence_worker: false,
            dispatch_action: if cancel_existing_dispatch_key {
                DispatchAction::Reconnect
            } else {
                DispatchAction::Connect
            },
        }) == (TargetDispatchPlan::Spawn {
            cancel_existing_dispatch_key,
            cancel_bootstrap_prefix: false,
        }),
{
}

} // verus!
