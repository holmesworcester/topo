//! Formal verification of connect-loop decision contexts.

use vstd::prelude::*;

verus! {

pub spec const STALE_DIAL_FAILURE_THRESHOLD: nat = 8;

pub struct DialFailureDecisionContext {
    pub has_connected_once: bool,
    pub stale_dial_failure: bool,
    pub consecutive_stale_dial_failures: nat,
    pub warn_on_startup_stale_failure: bool,
}

pub enum DialFailurePlan {
    ReturnStaleTarget {
        should_warn: bool,
        next_consecutive_stale_dial_failures: nat,
    },
    Retry {
        should_warn: bool,
        next_consecutive_stale_dial_failures: nat,
    },
}

pub struct SessionOpenFailureDecisionContext {
    pub connection_lost: bool,
}

pub enum SessionOpenFailurePlan {
    Break,
    EvictAndBreak,
}

pub struct SessionAuthFailureDecisionContext {
    pub connection_lost: bool,
    pub has_bootstrap_retry_invite: bool,
}

pub struct SessionAuthFailurePlan {
    pub next_auth_plan_override: bool,
    pub evict_live_connection: bool,
}

pub struct SessionRetryDecisionContext {
    pub session_stats_present: bool,
}

pub enum SessionRetryPlan {
    NoDelay,
    Delay250Ms,
}

pub open spec fn should_warn_for_connect_failure(
    has_connected_once: bool,
    stale_dial_failure: bool,
    warn_on_startup_stale_failure: bool,
) -> bool {
    has_connected_once || !stale_dial_failure || warn_on_startup_stale_failure
}

pub open spec fn decide_dial_failure_plan(
    context: &DialFailureDecisionContext,
) -> DialFailurePlan {
    let should_warn = should_warn_for_connect_failure(
        context.has_connected_once,
        context.stale_dial_failure,
        context.warn_on_startup_stale_failure,
    );
    let next_consecutive_stale_dial_failures = if context.stale_dial_failure {
        context.consecutive_stale_dial_failures + 1
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

pub open spec fn decide_session_open_failure_plan(
    context: &SessionOpenFailureDecisionContext,
) -> SessionOpenFailurePlan {
    if context.connection_lost {
        SessionOpenFailurePlan::EvictAndBreak
    } else {
        SessionOpenFailurePlan::Break
    }
}

pub open spec fn decide_session_auth_failure_plan(
    context: SessionAuthFailureDecisionContext,
) -> SessionAuthFailurePlan {
    SessionAuthFailurePlan {
        next_auth_plan_override: context.has_bootstrap_retry_invite,
        evict_live_connection: context.connection_lost,
    }
}

pub open spec fn decide_session_retry_plan(
    context: &SessionRetryDecisionContext,
) -> SessionRetryPlan {
    if context.session_stats_present {
        SessionRetryPlan::NoDelay
    } else {
        SessionRetryPlan::Delay250Ms
    }
}

proof fn stale_dial_failure_returns_stale_target_at_threshold()
    ensures
        decide_dial_failure_plan(&DialFailureDecisionContext {
            has_connected_once: false,
            stale_dial_failure: true,
            consecutive_stale_dial_failures: 7,
            warn_on_startup_stale_failure: false,
        }) == (DialFailurePlan::ReturnStaleTarget {
            should_warn: false,
            next_consecutive_stale_dial_failures: STALE_DIAL_FAILURE_THRESHOLD,
        }),
{
}

proof fn nonstale_dial_failure_resets_stale_counter(consecutive_stale_dial_failures: nat)
    ensures
        decide_dial_failure_plan(&DialFailureDecisionContext {
            has_connected_once: true,
            stale_dial_failure: false,
            consecutive_stale_dial_failures,
            warn_on_startup_stale_failure: false,
        }) == (DialFailurePlan::Retry {
            should_warn: true,
            next_consecutive_stale_dial_failures: 0,
        }),
{
}

proof fn session_open_failure_evicts_only_on_lost_connection()
    ensures
        decide_session_open_failure_plan(&SessionOpenFailureDecisionContext {
            connection_lost: true,
        }) == SessionOpenFailurePlan::EvictAndBreak,
        decide_session_open_failure_plan(&SessionOpenFailureDecisionContext {
            connection_lost: false,
        }) == SessionOpenFailurePlan::Break,
{
}

proof fn session_auth_failure_preserves_bootstrap_retry_and_evicts_lost_connection()
    ensures
        decide_session_auth_failure_plan(SessionAuthFailureDecisionContext {
            connection_lost: true,
            has_bootstrap_retry_invite: true,
        }) == (SessionAuthFailurePlan {
            next_auth_plan_override: true,
            evict_live_connection: true,
        }),
        decide_session_auth_failure_plan(SessionAuthFailureDecisionContext {
            connection_lost: false,
            has_bootstrap_retry_invite: true,
        }) == (SessionAuthFailurePlan {
            next_auth_plan_override: true,
            evict_live_connection: false,
        }),
{
}

proof fn session_retry_plan_does_not_back_off_after_completed_session()
    ensures
        decide_session_retry_plan(&SessionRetryDecisionContext {
            session_stats_present: true,
        }) == SessionRetryPlan::NoDelay,
        decide_session_retry_plan(&SessionRetryDecisionContext {
            session_stats_present: false,
        }) == SessionRetryPlan::Delay250Ms,
{
}

} // verus!
