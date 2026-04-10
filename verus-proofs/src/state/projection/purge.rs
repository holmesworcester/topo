//! Formal verification of tombstone-gated hard-purge planning.

use vstd::prelude::*;

verus! {

pub struct HardPurgeDecisionContext {
    pub tombstoned: bool,
    pub manifest_event_count: nat,
    pub manifest_file_count: nat,
}

pub enum HardPurgePlan {
    RejectMissingTombstone,
    ExecuteManifest { event_count: nat, file_count: nat },
}

pub open spec fn decide_hard_purge_plan(
    context: &HardPurgeDecisionContext,
) -> HardPurgePlan {
    if context.tombstoned {
        HardPurgePlan::ExecuteManifest {
            event_count: context.manifest_event_count,
            file_count: context.manifest_file_count,
        }
    } else {
        HardPurgePlan::RejectMissingTombstone
    }
}

proof fn hard_purge_requires_tombstone(event_count: nat, file_count: nat)
    ensures
        decide_hard_purge_plan(&HardPurgeDecisionContext {
            tombstoned: false,
            manifest_event_count: event_count,
            manifest_file_count: file_count,
        }) == HardPurgePlan::RejectMissingTombstone,
{
}

proof fn hard_purge_executes_exact_manifest_counts(event_count: nat, file_count: nat)
    ensures
        decide_hard_purge_plan(&HardPurgeDecisionContext {
            tombstoned: true,
            manifest_event_count: event_count,
            manifest_file_count: file_count,
        }) == (HardPurgePlan::ExecuteManifest {
            event_count,
            file_count,
        }),
{
}

} // verus!
