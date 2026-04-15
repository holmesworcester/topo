//! Abstract contracts for runtime control command helpers.
//!
//! These proofs focus on selector resolution rules that CLI command entrypoints
//! must preserve when parsing positional, deprecated, and default target
//! selectors before touching the runtime.

use vstd::prelude::*;

verus! {

pub struct TargetSelectorInputs {
    pub has_positional: bool,
    pub has_deprecated_flag: bool,
    pub has_default: bool,
}

pub enum TargetSelectorPlan {
    RejectConflict,
    UsePositional,
    UseDeprecated,
    UseDefault,
    RejectMissing,
}

pub open spec fn decide_target_selector_plan(i: TargetSelectorInputs) -> TargetSelectorPlan {
    if i.has_positional && i.has_deprecated_flag {
        TargetSelectorPlan::RejectConflict
    } else if i.has_positional {
        TargetSelectorPlan::UsePositional
    } else if i.has_deprecated_flag {
        TargetSelectorPlan::UseDeprecated
    } else if i.has_default {
        TargetSelectorPlan::UseDefault
    } else {
        TargetSelectorPlan::RejectMissing
    }
}

proof fn conflicting_selectors_reject(has_default: bool)
    ensures
        decide_target_selector_plan(TargetSelectorInputs {
            has_positional: true,
            has_deprecated_flag: true,
            has_default,
        }) == TargetSelectorPlan::RejectConflict,
{
}

proof fn positional_selector_wins_over_default(has_default: bool)
    ensures
        decide_target_selector_plan(TargetSelectorInputs {
            has_positional: true,
            has_deprecated_flag: false,
            has_default,
        }) == TargetSelectorPlan::UsePositional,
{
}

proof fn deprecated_selector_only_applies_when_positional_is_absent(has_default: bool)
    ensures
        decide_target_selector_plan(TargetSelectorInputs {
            has_positional: false,
            has_deprecated_flag: true,
            has_default,
        }) == TargetSelectorPlan::UseDeprecated,
{
}

proof fn default_selector_only_applies_when_no_selector_is_supplied()
    ensures
        decide_target_selector_plan(TargetSelectorInputs {
            has_positional: false,
            has_deprecated_flag: false,
            has_default: true,
        }) == TargetSelectorPlan::UseDefault,
        decide_target_selector_plan(TargetSelectorInputs {
            has_positional: false,
            has_deprecated_flag: false,
            has_default: false,
        }) == TargetSelectorPlan::RejectMissing,
{
}

} // verus!
