//! Cross-seam composition invariants for proof-bearing planners.
//!
//! These are abstract system-level obligations that individual mirrored seam
//! proofs instantiate with their own `DecisionContext` and `Plan` types.

use vstd::prelude::*;

verus! {

pub struct CompositionDecisionContext {
    pub has_unique_current_authority: bool,
    pub authority_ambiguous: bool,
    pub authority_malformed: bool,
    pub workspace_already_local: bool,
    pub bootstrap_link_present: bool,
    pub workspace_binding_matches: bool,
}

pub struct RuntimeEffectPlan {
    pub authorize_runtime_action: bool,
    pub allow_local_replay_or_fanout: bool,
    pub allow_bootstrap_dial: bool,
    pub allow_bootstrap_auth: bool,
    pub allow_bootstrap_trust_write: bool,
    pub allow_bootstrap_started_sync: bool,
}

pub struct ExecutorEffects {
    pub runtime_action_started: bool,
    pub local_replay_or_fanout_performed: bool,
    pub bootstrap_dial_performed: bool,
    pub bootstrap_auth_performed: bool,
    pub bootstrap_trust_written: bool,
    pub bootstrap_started_sync: bool,
}

pub open spec fn empty_runtime_effect_plan() -> RuntimeEffectPlan {
    RuntimeEffectPlan {
        authorize_runtime_action: false,
        allow_local_replay_or_fanout: false,
        allow_bootstrap_dial: false,
        allow_bootstrap_auth: false,
        allow_bootstrap_trust_write: false,
        allow_bootstrap_started_sync: false,
    }
}

pub open spec fn decide_composed_runtime_effect_plan(
    context: &CompositionDecisionContext,
) -> RuntimeEffectPlan {
    if context.authority_ambiguous
        || context.authority_malformed
        || !context.has_unique_current_authority
        || !context.workspace_binding_matches
    {
        empty_runtime_effect_plan()
    } else if context.workspace_already_local {
        RuntimeEffectPlan {
            authorize_runtime_action: true,
            allow_local_replay_or_fanout: true,
            allow_bootstrap_dial: false,
            allow_bootstrap_auth: false,
            allow_bootstrap_trust_write: false,
            allow_bootstrap_started_sync: false,
        }
    } else {
        RuntimeEffectPlan {
            authorize_runtime_action: true,
            allow_local_replay_or_fanout: false,
            allow_bootstrap_dial: context.bootstrap_link_present,
            allow_bootstrap_auth: context.bootstrap_link_present,
            allow_bootstrap_trust_write: context.bootstrap_link_present,
            allow_bootstrap_started_sync: context.bootstrap_link_present,
        }
    }
}

pub open spec fn executor_effects_are_within_plan(
    plan: &RuntimeEffectPlan,
    effects: &ExecutorEffects,
) -> bool {
    (!effects.runtime_action_started || plan.authorize_runtime_action)
    && (!effects.local_replay_or_fanout_performed || plan.allow_local_replay_or_fanout)
    && (!effects.bootstrap_dial_performed || plan.allow_bootstrap_dial)
    && (!effects.bootstrap_auth_performed || plan.allow_bootstrap_auth)
    && (!effects.bootstrap_trust_written || plan.allow_bootstrap_trust_write)
    && (!effects.bootstrap_started_sync || plan.allow_bootstrap_started_sync)
}

proof fn ambiguous_authority_rejects_all_effects(context: CompositionDecisionContext)
    requires context.authority_ambiguous
    ensures
        decide_composed_runtime_effect_plan(&context) == empty_runtime_effect_plan(),
{
}

proof fn malformed_authority_rejects_all_effects(context: CompositionDecisionContext)
    requires context.authority_malformed
    ensures
        decide_composed_runtime_effect_plan(&context) == empty_runtime_effect_plan(),
{
}

proof fn missing_unique_authority_rejects_all_effects(context: CompositionDecisionContext)
    requires !context.has_unique_current_authority
    ensures
        decide_composed_runtime_effect_plan(&context) == empty_runtime_effect_plan(),
{
}

proof fn workspace_mismatch_rejects_all_effects(context: CompositionDecisionContext)
    requires
        !context.authority_ambiguous,
        !context.authority_malformed,
        context.has_unique_current_authority,
        !context.workspace_binding_matches,
    ensures
        decide_composed_runtime_effect_plan(&context) == empty_runtime_effect_plan(),
{
}

proof fn already_local_workspace_suppresses_all_bootstrap_effects(context: CompositionDecisionContext)
    requires
        !context.authority_ambiguous,
        !context.authority_malformed,
        context.has_unique_current_authority,
        context.workspace_binding_matches,
        context.workspace_already_local,
    ensures
        ({
            let plan = decide_composed_runtime_effect_plan(&context);
            !plan.allow_bootstrap_dial
            && !plan.allow_bootstrap_auth
            && !plan.allow_bootstrap_trust_write
            && !plan.allow_bootstrap_started_sync
            && plan.allow_local_replay_or_fanout
        }),
{
}

proof fn nonlocal_bootstrap_link_may_authorize_bootstrap_effects(context: CompositionDecisionContext)
    requires
        !context.authority_ambiguous,
        !context.authority_malformed,
        context.has_unique_current_authority,
        context.workspace_binding_matches,
        !context.workspace_already_local,
        context.bootstrap_link_present,
    ensures
        ({
            let plan = decide_composed_runtime_effect_plan(&context);
            plan.allow_bootstrap_dial
            && plan.allow_bootstrap_auth
            && plan.allow_bootstrap_trust_write
            && plan.allow_bootstrap_started_sync
        }),
{
}

proof fn no_bootstrap_link_no_bootstrap_effects(context: CompositionDecisionContext)
    requires
        !context.authority_ambiguous,
        !context.authority_malformed,
        context.has_unique_current_authority,
        context.workspace_binding_matches,
        !context.workspace_already_local,
        !context.bootstrap_link_present,
    ensures
        ({
            let plan = decide_composed_runtime_effect_plan(&context);
            !plan.allow_bootstrap_dial
            && !plan.allow_bootstrap_auth
            && !plan.allow_bootstrap_trust_write
            && !plan.allow_bootstrap_started_sync
        }),
{
}

proof fn executor_conformance_blocks_unplanned_bootstrap_effects(
    plan: RuntimeEffectPlan,
    effects: ExecutorEffects,
)
    requires executor_effects_are_within_plan(&plan, &effects)
    ensures
        (!plan.allow_bootstrap_dial ==> !effects.bootstrap_dial_performed),
        (!plan.allow_bootstrap_auth ==> !effects.bootstrap_auth_performed),
        (!plan.allow_bootstrap_trust_write ==> !effects.bootstrap_trust_written),
        (!plan.allow_bootstrap_started_sync ==> !effects.bootstrap_started_sync),
{
}

} // verus!
