//! Formal verification of tombstone-gated hard-purge planning.

use vstd::prelude::*;

verus! {

pub struct HardPurgeRawRows {
    pub tombstoned: bool,
    pub manifest_event_count: nat,
    pub manifest_file_count: nat,
}

pub struct HardPurgeDecisionContext {
    pub tombstoned: bool,
    pub manifest_event_count: nat,
    pub manifest_file_count: nat,
}

pub enum HardPurgePlan {
    RejectMissingTombstone,
    ExecuteManifest { event_count: nat, file_count: nat },
}

pub open spec fn normalize_hard_purge_context(
    raw_rows: HardPurgeRawRows,
) -> HardPurgeDecisionContext {
    HardPurgeDecisionContext {
        tombstoned: raw_rows.tombstoned,
        manifest_event_count: raw_rows.manifest_event_count,
        manifest_file_count: raw_rows.manifest_file_count,
    }
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

proof fn hard_purge_normalizer_preserves_query_facts(
    tombstoned: bool,
    event_count: nat,
    file_count: nat,
)
    ensures
        normalize_hard_purge_context(HardPurgeRawRows {
            tombstoned,
            manifest_event_count: event_count,
            manifest_file_count: file_count,
        }) == (HardPurgeDecisionContext {
            tombstoned,
            manifest_event_count: event_count,
            manifest_file_count: file_count,
        }),
{
}

proof fn hard_purge_requires_tombstone(event_count: nat, file_count: nat)
    ensures
        decide_hard_purge_plan(&normalize_hard_purge_context(HardPurgeRawRows {
            tombstoned: false,
            manifest_event_count: event_count,
            manifest_file_count: file_count,
        })) == HardPurgePlan::RejectMissingTombstone,
{
}

proof fn hard_purge_executes_exact_manifest_counts(event_count: nat, file_count: nat)
    ensures
        decide_hard_purge_plan(&normalize_hard_purge_context(HardPurgeRawRows {
            tombstoned: true,
            manifest_event_count: event_count,
            manifest_file_count: file_count,
        })) == (HardPurgePlan::ExecuteManifest {
            event_count,
            file_count,
        }),
{
}

} // verus!
