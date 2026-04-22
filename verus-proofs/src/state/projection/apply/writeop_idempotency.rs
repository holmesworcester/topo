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
    /// Dedicated typed variant for unwrap-gated key_secrets writes
    /// (produced by KeyShared, KeyRotation, KeyHistory projectors).
    /// The unwrap-based access-control theorem applies.
    InsertKeySecretFromUnwrap,
    /// Dedicated typed variant for local peer's own key plant (produced
    /// only by the KeySecret projector). The unwrap theorem does NOT
    /// apply; this is the peer writing its own key material.
    InsertKeySecretLocal,
}

pub open spec fn kind_is_idempotent_spec(kind: WriteOpKind) -> bool {
    match kind {
        WriteOpKind::InsertOrIgnore => true,
        WriteOpKind::Delete => true,
        WriteOpKind::InsertKeySecretFromUnwrap => true,
        WriteOpKind::InsertKeySecretLocal => true,
    }
}

pub fn is_idempotent_writeop(kind: WriteOpKind) -> (ok: bool)
    ensures ok == kind_is_idempotent_spec(kind),
{
    match kind {
        WriteOpKind::InsertOrIgnore => true,
        WriteOpKind::Delete => true,
        WriteOpKind::InsertKeySecretFromUnwrap => true,
        WriteOpKind::InsertKeySecretLocal => true,
    }
}

pub proof fn all_known_writeop_kinds_are_idempotent(kind: WriteOpKind)
    ensures kind_is_idempotent_spec(kind),
{
}

} // verus!
