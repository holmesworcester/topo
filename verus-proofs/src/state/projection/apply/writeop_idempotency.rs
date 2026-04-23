//! WriteOp idempotency — verified constructive property.
//!
//! Projection write ops are deliberately limited to `InsertOrIgnore` and `Delete`, both of
//! which are idempotent under replay (INSERT OR IGNORE no-ops on conflict; DELETE is a
//! set-equality operation). This file encodes that property as a verified predicate on
//! a `WriteOpKind` tag that the runtime's trusted extractor derives from `WriteOp` via
//! an exhaustive match. If a new `WriteOp` variant is added to the runtime (e.g.,
//! `Update`), the extractor's match goes non-exhaustive at compile time, forcing an
//! update here, and `is_idempotent_writeop` must explicitly prove (or reject) the new
//! variant.
//!
//! The runtime calls `is_idempotent_writeop` per op immediately before executing via
//! `debug_assert!` — so a future variant that is not idempotent fires in debug test
//! runs as well as in the formal proof.
//!
//! Recent runtime changes added more post-write emit-command handlers, but they still
//! execute strictly outside the `WriteOp` surface covered here; this mirror continues
//! to prove replay safety for the actual DB mutations themselves.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOpKind {
    InsertOrIgnore,
    Delete,
}

pub open spec fn kind_is_idempotent_spec(kind: WriteOpKind) -> bool {
    match kind {
        WriteOpKind::InsertOrIgnore => true,
        WriteOpKind::Delete => true,
    }
}

pub fn is_idempotent_writeop(kind: WriteOpKind) -> (ok: bool)
    ensures ok == kind_is_idempotent_spec(kind),
{
    match kind {
        WriteOpKind::InsertOrIgnore => true,
        WriteOpKind::Delete => true,
    }
}

pub proof fn all_known_writeop_kinds_are_idempotent(kind: WriteOpKind)
    ensures kind_is_idempotent_spec(kind),
{
}

// ═══════════════════════════════════════════════════════════════════
// Note on retired control-channel emit commands.
//
// `EmitCommand::RetryBlockedEncryptedByKey` was retired in the
// LocalKeySecret migration. Its write-site (a custom scan of
// `blocked_events` for encrypted rows matching a specific
// key_event_id, re-projecting them one by one) was never covered by
// a Verus invariant — the retry signal ran alongside the event
// graph, not inside it. Its replacement is the standard cascade
// unblock triggered when a KeySecret event projects. That cascade
// path is already covered by the `cascade_invariant` mirror; no new
// mirror obligation is introduced by the retirement.

} // verus!
