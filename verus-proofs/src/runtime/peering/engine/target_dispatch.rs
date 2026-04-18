//! Target-dispatch precedence and spawn policy — verified core.
//!
//! The runtime's `TargetDispatchPlan` carries skip-reason and ingress-source payloads that
//! can't cross into verus-proofs without cyclic deps. We expose a verified *core* plan that
//! classifies only the abstract decision (Skip/Spawn with two booleans), and the runtime
//! wraps this with a thin adapter that re-attaches the concrete skip reason.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSourceKind {
    Bootstrap,
    KnownPeer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreDispatchAction {
    Skip,
    Connect,
    Reconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetDispatchCoreRawRows {
    pub incoming_source: TargetSourceKind,
    pub should_initiate_connect: bool,
    pub bootstrap_phase: bool,
    pub has_active_higher_precedence_worker: bool,
    pub dispatch_action: CoreDispatchAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetDispatchCoreContext {
    pub incoming_source: TargetSourceKind,
    pub should_initiate_connect: bool,
    pub bootstrap_phase: bool,
    pub has_active_higher_precedence_worker: bool,
    pub dispatch_action: CoreDispatchAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetDispatchCoreSkipReason {
    SourceNotInitiated,
    LowerPrecedenceThanActiveWorker,
    DispatcherNoop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetDispatchCoreSpawnPlan {
    pub cancel_existing_dispatch_key: bool,
    pub cancel_bootstrap_prefix: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetDispatchCorePlan {
    Skip(TargetDispatchCoreSkipReason),
    Spawn(TargetDispatchCoreSpawnPlan),
}

pub fn normalize_target_dispatch_core_context(
    raw_rows: TargetDispatchCoreRawRows,
) -> (context: TargetDispatchCoreContext)
    ensures
        context.incoming_source == raw_rows.incoming_source,
        context.should_initiate_connect == raw_rows.should_initiate_connect,
        context.bootstrap_phase == raw_rows.bootstrap_phase,
        context.has_active_higher_precedence_worker == raw_rows.has_active_higher_precedence_worker,
        context.dispatch_action == raw_rows.dispatch_action,
{
    TargetDispatchCoreContext {
        incoming_source: raw_rows.incoming_source,
        should_initiate_connect: raw_rows.should_initiate_connect,
        bootstrap_phase: raw_rows.bootstrap_phase,
        has_active_higher_precedence_worker: raw_rows.has_active_higher_precedence_worker,
        dispatch_action: raw_rows.dispatch_action,
    }
}

pub fn decide_target_dispatch_core_plan(
    context: &TargetDispatchCoreContext,
) -> (plan: TargetDispatchCorePlan)
    ensures
        // Source not initiated → always Skip(SourceNotInitiated).
        !context.should_initiate_connect
            ==> plan == TargetDispatchCorePlan::Skip(TargetDispatchCoreSkipReason::SourceNotInitiated),
        // Bootstrap source suppressed by a known-peer worker outside bootstrap phase.
        (context.should_initiate_connect
            && context.incoming_source == TargetSourceKind::Bootstrap
            && context.has_active_higher_precedence_worker
            && !context.bootstrap_phase)
            ==> plan == TargetDispatchCorePlan::Skip(TargetDispatchCoreSkipReason::LowerPrecedenceThanActiveWorker),
        // DispatcherAction::Skip propagates to DispatcherNoop.
        (context.should_initiate_connect
            && !(context.incoming_source == TargetSourceKind::Bootstrap
                && context.has_active_higher_precedence_worker
                && !context.bootstrap_phase)
            && context.dispatch_action == CoreDispatchAction::Skip)
            ==> plan == TargetDispatchCorePlan::Skip(TargetDispatchCoreSkipReason::DispatcherNoop),
        // Any Spawn implies connect is initiated and dispatch_action isn't Skip.
        (match plan {
            TargetDispatchCorePlan::Spawn(_) => true,
            _ => false,
        }) ==> context.should_initiate_connect
            && context.dispatch_action != CoreDispatchAction::Skip
            && !(context.incoming_source == TargetSourceKind::Bootstrap
                && context.has_active_higher_precedence_worker
                && !context.bootstrap_phase),
        // Known-peer spawn outside bootstrap phase cancels bootstrap prefix.
        (match plan {
            TargetDispatchCorePlan::Spawn(p) =>
                context.incoming_source == TargetSourceKind::KnownPeer && !context.bootstrap_phase
                    ==> p.cancel_bootstrap_prefix,
            _ => true,
        }),
        // Reconnect → cancel_existing_dispatch_key = true.
        (match plan {
            TargetDispatchCorePlan::Spawn(p) =>
                context.dispatch_action == CoreDispatchAction::Reconnect ==> p.cancel_existing_dispatch_key,
            _ => true,
        }),
        // Connect → cancel_existing_dispatch_key = false.
        (match plan {
            TargetDispatchCorePlan::Spawn(p) =>
                context.dispatch_action == CoreDispatchAction::Connect ==> !p.cancel_existing_dispatch_key,
            _ => true,
        }),
{
    if !context.should_initiate_connect {
        return TargetDispatchCorePlan::Skip(TargetDispatchCoreSkipReason::SourceNotInitiated);
    }
    let suppressed_bootstrap = matches!(context.incoming_source, TargetSourceKind::Bootstrap)
        && context.has_active_higher_precedence_worker
        && !context.bootstrap_phase;
    if suppressed_bootstrap {
        return TargetDispatchCorePlan::Skip(TargetDispatchCoreSkipReason::LowerPrecedenceThanActiveWorker);
    }
    let cancel_bootstrap_prefix = matches!(context.incoming_source, TargetSourceKind::KnownPeer)
        && !context.bootstrap_phase;
    match context.dispatch_action {
        CoreDispatchAction::Skip =>
            TargetDispatchCorePlan::Skip(TargetDispatchCoreSkipReason::DispatcherNoop),
        CoreDispatchAction::Connect =>
            TargetDispatchCorePlan::Spawn(TargetDispatchCoreSpawnPlan {
                cancel_existing_dispatch_key: false,
                cancel_bootstrap_prefix,
            }),
        CoreDispatchAction::Reconnect =>
            TargetDispatchCorePlan::Spawn(TargetDispatchCoreSpawnPlan {
                cancel_existing_dispatch_key: true,
                cancel_bootstrap_prefix,
            }),
    }
}

} // verus!
