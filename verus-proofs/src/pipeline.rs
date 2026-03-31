//! Formal verification of pipeline batch processing and commit semantics.

use vstd::prelude::*;

verus! {

/// Event type codes.
pub spec const EVENT_TYPE_FILE_SLICE: u8 = 25;

/// Model of an ingest item.
pub struct IngestItem {
    pub type_code: u8,
    pub index: nat,
}

pub open spec fn is_bulk(item: &IngestItem) -> bool {
    item.type_code == EVENT_TYPE_FILE_SLICE
}

pub open spec fn is_foreground(item: &IngestItem) -> bool {
    !is_bulk(item)
}

/// Filter to foreground items.
pub open spec fn filter_foreground(items: Seq<IngestItem>) -> Seq<IngestItem>
    decreases items.len(),
{
    if items.len() == 0 {
        Seq::empty()
    } else {
        let rest = filter_foreground(items.drop_last());
        if is_foreground(&items.last()) {
            rest.push(items.last())
        } else {
            rest
        }
    }
}

/// Filter to bulk items.
pub open spec fn filter_bulk(items: Seq<IngestItem>) -> Seq<IngestItem>
    decreases items.len(),
{
    if items.len() == 0 {
        Seq::empty()
    } else {
        let rest = filter_bulk(items.drop_last());
        if is_bulk(&items.last()) {
            rest.push(items.last())
        } else {
            rest
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Batch sorting proofs
// ═══════════════════════════════════════════════════════════════════

/// Proof: filters preserve total count.
proof fn proof_filter_lengths_sum(items: Seq<IngestItem>)
    ensures filter_foreground(items).len() + filter_bulk(items).len() == items.len(),
    decreases items.len(),
{
    if items.len() == 0 {
    } else {
        proof_filter_lengths_sum(items.drop_last());
    }
}

/// Proof: all items in filter_foreground are foreground.
proof fn proof_filter_foreground_all_foreground(items: Seq<IngestItem>)
    ensures forall|i: int| #![trigger filter_foreground(items)[i]]
        0 <= i < filter_foreground(items).len() as int ==> is_foreground(&filter_foreground(items)[i]),
    decreases items.len(),
{
    if items.len() == 0 {
    } else {
        proof_filter_foreground_all_foreground(items.drop_last());
        let rest = filter_foreground(items.drop_last());
        if is_foreground(&items.last()) {
            // filter_foreground(items) == rest.push(items.last())
            // Items 0..rest.len()-1 come from rest (inductive hypothesis)
            // Item rest.len() is items.last() which is foreground
            assert forall|i: int| #![trigger filter_foreground(items)[i]]
                0 <= i < filter_foreground(items).len() as int
                implies is_foreground(&filter_foreground(items)[i])
            by {
                if i < rest.len() as int {
                    assert(filter_foreground(items)[i] == rest[i]);
                } else {
                    assert(filter_foreground(items)[i] == items.last());
                }
            }
        } else {
            // filter_foreground(items) == rest, inductive hypothesis suffices
        }
    }
}

/// Proof: all items in filter_bulk are bulk.
proof fn proof_filter_bulk_all_bulk(items: Seq<IngestItem>)
    ensures forall|i: int| #![trigger filter_bulk(items)[i]]
        0 <= i < filter_bulk(items).len() as int ==> is_bulk(&filter_bulk(items)[i]),
    decreases items.len(),
{
    if items.len() == 0 {
    } else {
        proof_filter_bulk_all_bulk(items.drop_last());
        let rest = filter_bulk(items.drop_last());
        if is_bulk(&items.last()) {
            assert forall|i: int| #![trigger filter_bulk(items)[i]]
                0 <= i < filter_bulk(items).len() as int
                implies is_bulk(&filter_bulk(items)[i])
            by {
                if i < rest.len() as int {
                    assert(filter_bulk(items)[i] == rest[i]);
                } else {
                    assert(filter_bulk(items)[i] == items.last());
                }
            }
        } else {
            // filter_bulk(items) == rest, inductive hypothesis suffices
        }
    }
}

/// Proof: the concatenation fg ++ bulk has all foreground first, then all bulk.
proof fn proof_concat_has_fg_then_bulk(items: Seq<IngestItem>)
    ensures
        ({
            let fg = filter_foreground(items);
            let bk = filter_bulk(items);
            let sorted = fg.add(bk);
            &&& sorted.len() == items.len()
            &&& (forall|i: int| #![trigger sorted[i]] 0 <= i < fg.len() as int ==> is_foreground(&sorted[i]))
            &&& (forall|i: int| #![trigger sorted[i]] fg.len() as int <= i < sorted.len() as int ==> is_bulk(&sorted[i]))
        }),
{
    proof_filter_lengths_sum(items);
    proof_filter_foreground_all_foreground(items);
    proof_filter_bulk_all_bulk(items);

    let fg = filter_foreground(items);
    let bk = filter_bulk(items);
    let sorted = fg.add(bk);

    // The first fg.len() elements come from fg (all foreground)
    assert forall|i: int| #![trigger sorted[i]] 0 <= i < fg.len() as int implies is_foreground(&sorted[i]) by {
        assert(sorted[i] == fg[i]);
    }
    // The remaining elements come from bk (all bulk)
    assert forall|i: int| #![trigger sorted[i]] fg.len() as int <= i < sorted.len() as int implies is_bulk(&sorted[i]) by {
        assert(sorted[i] == bk[i - fg.len() as int]);
    }
}

/// Proof: an all-foreground batch is unchanged.
proof fn proof_all_foreground_unchanged(items: Seq<IngestItem>)
    requires forall|i: int| #![trigger items[i]] 0 <= i < items.len() as int ==> is_foreground(&items[i])
    ensures filter_foreground(items) =~= items && filter_bulk(items).len() == 0,
    decreases items.len(),
{
    if items.len() == 0 {
    } else {
        assert(is_foreground(&items.last()));
        proof_all_foreground_unchanged(items.drop_last());
    }
}

/// Proof: an all-bulk batch is unchanged.
proof fn proof_all_bulk_unchanged(items: Seq<IngestItem>)
    requires forall|i: int| #![trigger items[i]] 0 <= i < items.len() as int ==> is_bulk(&items[i])
    ensures filter_bulk(items) =~= items && filter_foreground(items).len() == 0,
    decreases items.len(),
{
    if items.len() == 0 {
    } else {
        assert(is_bulk(&items.last()));
        proof_all_bulk_unchanged(items.drop_last());
    }
}

// ═══════════════════════════════════════════════════════════════════
// Commit atomicity proofs
// ═══════════════════════════════════════════════════════════════════

pub open spec fn commit_and_effects_model(
    commit_succeeds: bool,
    effects_count: nat,
) -> (bool, nat) {
    if commit_succeeds {
        (true, effects_count)
    } else {
        (false, 0)
    }
}

proof fn proof_commit_failure_no_effects(effects_count: nat)
    ensures
        ({
            let (success, executed) = commit_and_effects_model(false, effects_count);
            !success && executed == 0
        }),
{
}

proof fn proof_commit_success_runs_all_effects(effects_count: nat)
    ensures
        ({
            let (success, executed) = commit_and_effects_model(true, effects_count);
            success && executed == effects_count
        }),
{
}

pub open spec fn post_commit_tail_model(
    _wal_cap_ok: bool,
    effects_count: nat,
) -> nat {
    effects_count
}

proof fn proof_wal_cap_failure_does_not_skip_effects(effects_count: nat)
    ensures
        post_commit_tail_model(true, effects_count) == effects_count,
        post_commit_tail_model(false, effects_count) == effects_count,
{
}

// ═══════════════════════════════════════════════════════════════════
// Drain semantics
// ═══════════════════════════════════════════════════════════════════

pub open spec fn drain_model(
    queue_size: nat,
    batch_limit: nat,
    items_projectable: nat,
) -> nat {
    let to_process = if queue_size < batch_limit { queue_size } else { batch_limit };
    if items_projectable < to_process { items_projectable } else { to_process }
}

proof fn proof_drain_respects_limit(queue_size: nat, batch_limit: nat, items_projectable: nat)
    ensures drain_model(queue_size, batch_limit, items_projectable) <= batch_limit,
{
}

proof fn proof_drain_respects_queue_size(queue_size: nat, batch_limit: nat, items_projectable: nat)
    ensures drain_model(queue_size, batch_limit, items_projectable) <= queue_size,
{
}

// ═══════════════════════════════════════════════════════════════════
// Batch cap
// ═══════════════════════════════════════════════════════════════════

pub open spec fn batch_cap_model(first_is_bulk: bool, write_cap: nat, bulk_cap: nat) -> nat {
    if first_is_bulk { bulk_cap } else { write_cap }
}

proof fn proof_bulk_first_gets_bulk_cap(write_cap: nat, bulk_cap: nat)
    requires bulk_cap >= write_cap
    ensures batch_cap_model(true, write_cap, bulk_cap) >= write_cap,
{
}

} // verus!
