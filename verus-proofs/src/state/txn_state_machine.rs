//! Transaction state machine — verified.
//!
//! A `TxnGuard` has three terminal states after `begin`: `Active`, `Committed`, or
//! `RolledBack`. Valid transitions:
//! - `Active → Committed` (explicit commit)
//! - `Active → RolledBack` (explicit rollback OR Drop)
//! - `Committed → Committed` (Drop is a no-op after commit)
//! - `RolledBack → RolledBack` (Drop is a no-op after rollback)
//!
//! Invalid transitions (caught by the verified predicates):
//! - Commit from Committed (double commit)
//! - Commit from RolledBack
//! - Rollback from Committed
//! - Any transition back to Active
//!
//! The runtime `TxnGuard` carries a `state: DbTxnState` field and asserts the
//! transition predicate on every operation. Rust's ownership system does the heavy
//! lifting (non-Clone prevents double-use, Drop guarantees rollback); this file
//! expresses the invariant Verus can check.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbTxnState {
    Active,
    Committed,
    RolledBack,
}

/// True iff `begin` producing `after` from fresh is valid.
/// Fresh = the caller has no prior txn for this connection.
pub fn begin_transition_valid(after: DbTxnState) -> (ok: bool)
    ensures ok == (after == DbTxnState::Active),
{
    matches!(after, DbTxnState::Active)
}

/// True iff `commit` transitioning `before` to `after` is valid.
pub fn commit_transition_valid(before: DbTxnState, after: DbTxnState) -> (ok: bool)
    ensures
        ok == (before == DbTxnState::Active && after == DbTxnState::Committed),
{
    matches!(before, DbTxnState::Active) && matches!(after, DbTxnState::Committed)
}

/// True iff `rollback` transitioning `before` to `after` is valid.
pub fn rollback_transition_valid(before: DbTxnState, after: DbTxnState) -> (ok: bool)
    ensures
        ok == (before == DbTxnState::Active && after == DbTxnState::RolledBack),
{
    matches!(before, DbTxnState::Active) && matches!(after, DbTxnState::RolledBack)
}

/// True iff `drop_is_noop(state)` — drop should do nothing for terminal states.
pub fn drop_is_noop(state: DbTxnState) -> (ok: bool)
    ensures
        ok == (state == DbTxnState::Committed || state == DbTxnState::RolledBack),
{
    matches!(state, DbTxnState::Committed | DbTxnState::RolledBack)
}

/// True iff `drop_should_rollback(state)` — drop should issue ROLLBACK if active.
pub fn drop_should_rollback(state: DbTxnState) -> (ok: bool)
    ensures ok == (state == DbTxnState::Active),
{
    matches!(state, DbTxnState::Active)
}

} // verus!
