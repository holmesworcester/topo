//! Formal verification of tombstone-gated hard-purge planning.
//!
//! Every `pub fn` below is executable Rust consumed by `src/state/projection/purge.rs`.
//! Postconditions (`ensures`) are SMT-checked against the function body by `cargo-verus verify`.
//!
//! The runtime carries rich `BTreeSet<String>` manifests. This Verus core reduces the
//! planning decision to primitive counts (event/file count) since the tombstone-gated
//! dispatch depends only on whether the tombstone row is present. The runtime wraps
//! this core via an adapter that passes `manifest.event_ids.len()` / `manifest.file_ids.len()`.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardPurgeRawRowsCore {
    pub tombstoned: bool,
    pub manifest_event_count: u64,
    pub manifest_file_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardPurgeDecisionContextCore {
    pub tombstoned: bool,
    pub manifest_event_count: u64,
    pub manifest_file_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardPurgePlanCore {
    RejectMissingTombstone,
    ExecuteManifest { event_count: u64, file_count: u64 },
}

pub fn normalize_hard_purge_context_core(
    raw_rows: HardPurgeRawRowsCore,
) -> (context: HardPurgeDecisionContextCore)
    ensures
        context.tombstoned == raw_rows.tombstoned,
        context.manifest_event_count == raw_rows.manifest_event_count,
        context.manifest_file_count == raw_rows.manifest_file_count,
{
    HardPurgeDecisionContextCore {
        tombstoned: raw_rows.tombstoned,
        manifest_event_count: raw_rows.manifest_event_count,
        manifest_file_count: raw_rows.manifest_file_count,
    }
}

pub fn decide_hard_purge_plan_core(
    context: &HardPurgeDecisionContextCore,
) -> (plan: HardPurgePlanCore)
    ensures
        !context.tombstoned ==> plan == HardPurgePlanCore::RejectMissingTombstone,
        context.tombstoned ==> plan == (HardPurgePlanCore::ExecuteManifest {
            event_count: context.manifest_event_count,
            file_count: context.manifest_file_count,
        }),
{
    if context.tombstoned {
        HardPurgePlanCore::ExecuteManifest {
            event_count: context.manifest_event_count,
            file_count: context.manifest_file_count,
        }
    } else {
        HardPurgePlanCore::RejectMissingTombstone
    }
}

} // verus!
