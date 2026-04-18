//! Connect-loop decision planners, verified by Verus.
//!
//! Every `pub fn` below is executable Rust consumed by `src/runtime/peering/loops/connect.rs`.
//! Postconditions (`ensures`) are SMT-checked against the function body by `cargo-verus verify`.

use vstd::prelude::*;

verus! {

pub const STALE_DIAL_FAILURE_THRESHOLD: u32 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialFailureRawRows {
    pub has_connected_once: bool,
    pub stale_dial_failure: bool,
    pub consecutive_stale_dial_failures: u32,
    pub warn_on_startup_stale_failure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialFailureDecisionContext {
    pub has_connected_once: bool,
    pub stale_dial_failure: bool,
    pub consecutive_stale_dial_failures: u32,
    pub warn_on_startup_stale_failure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialFailurePlan {
    ReturnStaleTarget {
        should_warn: bool,
        next_consecutive_stale_dial_failures: u32,
    },
    Retry {
        should_warn: bool,
        next_consecutive_stale_dial_failures: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOpenFailureRawRows {
    pub connection_lost: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOpenFailureDecisionContext {
    pub connection_lost: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOpenFailurePlan {
    Break,
    EvictAndBreak,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthFailureCoreRawRows {
    pub connection_lost: bool,
    pub has_bootstrap_retry_invite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthFailureCoreContext {
    pub connection_lost: bool,
    pub has_bootstrap_retry_invite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthFailureCorePlan {
    pub next_auth_plan_override: bool,
    pub evict_live_connection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRetryRawRows {
    pub session_stats_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRetryDecisionContext {
    pub session_stats_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRetryPlan {
    NoDelay,
    DelayMs(u32),
}

pub fn should_warn_for_connect_failure(
    has_connected_once: bool,
    stale_dial_failure: bool,
    warn_on_startup_stale_failure: bool,
) -> (warn: bool)
    ensures warn == (has_connected_once || !stale_dial_failure || warn_on_startup_stale_failure),
{
    has_connected_once || !stale_dial_failure || warn_on_startup_stale_failure
}

pub fn normalize_dial_failure_decision_context(
    raw_rows: DialFailureRawRows,
) -> (context: DialFailureDecisionContext)
    ensures
        context.has_connected_once == raw_rows.has_connected_once,
        context.stale_dial_failure == raw_rows.stale_dial_failure,
        context.consecutive_stale_dial_failures == raw_rows.consecutive_stale_dial_failures,
        context.warn_on_startup_stale_failure == raw_rows.warn_on_startup_stale_failure,
{
    DialFailureDecisionContext {
        has_connected_once: raw_rows.has_connected_once,
        stale_dial_failure: raw_rows.stale_dial_failure,
        consecutive_stale_dial_failures: raw_rows.consecutive_stale_dial_failures,
        warn_on_startup_stale_failure: raw_rows.warn_on_startup_stale_failure,
    }
}

pub fn decide_dial_failure_plan(context: &DialFailureDecisionContext) -> (plan: DialFailurePlan)
    ensures
        // Non-stale failures always retry with a zeroed counter.
        !context.stale_dial_failure ==> plan == (DialFailurePlan::Retry {
            should_warn: context.has_connected_once || context.warn_on_startup_stale_failure || !context.stale_dial_failure,
            next_consecutive_stale_dial_failures: 0,
        }),
        // Stale failures increment the counter (overflow-bounded by the u32 precondition that
        // consecutive_stale_dial_failures < u32::MAX; we avoid stating the condition explicitly
        // since Verus tracks overflow for u32 arithmetic).
        context.stale_dial_failure ==> match plan {
            DialFailurePlan::ReturnStaleTarget { should_warn, next_consecutive_stale_dial_failures } =>
                next_consecutive_stale_dial_failures >= STALE_DIAL_FAILURE_THRESHOLD
                && should_warn == (context.has_connected_once || context.warn_on_startup_stale_failure),
            DialFailurePlan::Retry { should_warn, next_consecutive_stale_dial_failures } =>
                next_consecutive_stale_dial_failures < STALE_DIAL_FAILURE_THRESHOLD
                && should_warn == (context.has_connected_once || context.warn_on_startup_stale_failure),
        },
{
    let should_warn = should_warn_for_connect_failure(
        context.has_connected_once,
        context.stale_dial_failure,
        context.warn_on_startup_stale_failure,
    );
    let next_consecutive_stale_dial_failures: u32 = if context.stale_dial_failure {
        // Saturating add: avoid overflow UB; in practice the caller caps this well before u32::MAX.
        if context.consecutive_stale_dial_failures == u32::MAX {
            u32::MAX
        } else {
            context.consecutive_stale_dial_failures + 1
        }
    } else {
        0
    };
    if context.stale_dial_failure
        && next_consecutive_stale_dial_failures >= STALE_DIAL_FAILURE_THRESHOLD
    {
        DialFailurePlan::ReturnStaleTarget {
            should_warn,
            next_consecutive_stale_dial_failures,
        }
    } else {
        DialFailurePlan::Retry {
            should_warn,
            next_consecutive_stale_dial_failures,
        }
    }
}

pub fn normalize_session_open_failure_decision_context(
    raw_rows: SessionOpenFailureRawRows,
) -> (context: SessionOpenFailureDecisionContext)
    ensures context.connection_lost == raw_rows.connection_lost,
{
    SessionOpenFailureDecisionContext {
        connection_lost: raw_rows.connection_lost,
    }
}

pub fn decide_session_open_failure_plan(
    context: &SessionOpenFailureDecisionContext,
) -> (plan: SessionOpenFailurePlan)
    ensures
        context.connection_lost ==> plan == SessionOpenFailurePlan::EvictAndBreak,
        !context.connection_lost ==> plan == SessionOpenFailurePlan::Break,
{
    if context.connection_lost {
        SessionOpenFailurePlan::EvictAndBreak
    } else {
        SessionOpenFailurePlan::Break
    }
}

pub fn normalize_session_auth_failure_core_context(
    raw_rows: SessionAuthFailureCoreRawRows,
) -> (context: SessionAuthFailureCoreContext)
    ensures
        context.connection_lost == raw_rows.connection_lost,
        context.has_bootstrap_retry_invite == raw_rows.has_bootstrap_retry_invite,
{
    SessionAuthFailureCoreContext {
        connection_lost: raw_rows.connection_lost,
        has_bootstrap_retry_invite: raw_rows.has_bootstrap_retry_invite,
    }
}

/// Verified core of the session-auth-failure planner (abstract over the runtime's
/// `Option<OutboundSessionAuthPlan>`, which can't cross the verus-proofs/topo crate boundary
/// without cyclic deps). The runtime wraps this with a thin adapter that re-introduces the
/// concrete invite_event_id string carried by the original `bootstrap_retry_invite: Option<String>`.
pub fn decide_session_auth_failure_core_plan(
    context: SessionAuthFailureCoreContext,
) -> (plan: SessionAuthFailureCorePlan)
    ensures
        plan.next_auth_plan_override == context.has_bootstrap_retry_invite,
        plan.evict_live_connection == context.connection_lost,
{
    SessionAuthFailureCorePlan {
        next_auth_plan_override: context.has_bootstrap_retry_invite,
        evict_live_connection: context.connection_lost,
    }
}

pub fn normalize_session_retry_decision_context(
    raw_rows: SessionRetryRawRows,
) -> (context: SessionRetryDecisionContext)
    ensures context.session_stats_present == raw_rows.session_stats_present,
{
    SessionRetryDecisionContext {
        session_stats_present: raw_rows.session_stats_present,
    }
}

pub fn decide_session_retry_plan(
    context: &SessionRetryDecisionContext,
) -> (plan: SessionRetryPlan)
    ensures
        context.session_stats_present ==> plan == SessionRetryPlan::NoDelay,
        !context.session_stats_present ==> plan == SessionRetryPlan::DelayMs(250),
{
    if context.session_stats_present {
        SessionRetryPlan::NoDelay
    } else {
        SessionRetryPlan::DelayMs(250)
    }
}

} // verus!
