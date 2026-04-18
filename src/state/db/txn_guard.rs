//! Linear-typed transaction guard.
//!
//! `TxnGuard<'c>` wraps a `&'c Connection` and tracks the transaction's lifecycle
//! in the Rust type system:
//!
//! - **`begin`** executes `BEGIN IMMEDIATE` (or no-op if the connection is already
//!   in a non-autocommit state — a nested-txn compatibility path).
//! - **`commit(self)`** consumes the guard and executes `COMMIT`.
//! - **`Drop`** executes `ROLLBACK` if the guard is still `Active`. A commit'd
//!   guard has already been consumed, so Drop cannot fire for committed guards.
//!
//! The type is deliberately **non-Clone, non-Send, non-Sync** via `PhantomData<*const ()>`.
//! That means you cannot:
//! - duplicate the guard (would commit or rollback twice),
//! - move it across threads (would race against the owning connection),
//! - leak it across an `.await` point without keeping the whole future non-Send.
//!
//! The state machine (`Active → Committed` / `Active → RolledBack`, never backwards)
//! is mirrored in `topo_verus_proofs::state::txn_state_machine` and asserted at every
//! operation via the verified transition predicates.

use rusqlite::Connection;
use std::marker::PhantomData;
use topo_verus_proofs::state::db::txn_guard::{
    begin_transition_valid, commit_transition_valid, drop_is_noop, drop_should_rollback,
    rollback_transition_valid, DbTxnState,
};

/// Linear-typed active database transaction. See module docs.
pub struct TxnGuard<'c> {
    conn: &'c Connection,
    state: DbTxnState,
    /// If true, the connection was already non-autocommit when this guard was
    /// constructed — we are participating in an outer transaction and must not
    /// issue our own COMMIT/ROLLBACK (the outer scope owns the lifecycle).
    nested: bool,
    /// Non-Send, non-Sync: raw pointer type has those negative auto traits.
    /// Also non-Clone by default because `PhantomData<*const ()>` isn't Clone
    /// without a derive — which we intentionally don't provide.
    _phantom: PhantomData<*const ()>,
}

impl<'c> TxnGuard<'c> {
    /// Begin an immediate transaction. If the connection is already mid-txn
    /// (nested case), returns a passthrough guard that does nothing on commit/drop.
    /// The busy-retry loop lives here to match the old `with_sqlite_busy_retry`.
    pub fn begin(conn: &'c Connection) -> rusqlite::Result<Self> {
        if !conn.is_autocommit() {
            let guard = Self {
                conn,
                state: DbTxnState::Active,
                nested: true,
                _phantom: PhantomData,
            };
            debug_assert!(begin_transition_valid(guard.state));
            return Ok(guard);
        }

        super::queue::begin_immediate_with_retry(conn)?;
        let guard = Self {
            conn,
            state: DbTxnState::Active,
            nested: false,
            _phantom: PhantomData,
        };
        debug_assert!(begin_transition_valid(guard.state));
        Ok(guard)
    }

    /// Commit the transaction. Consumes the guard; Drop will not fire afterward.
    /// If the guard is nested, the COMMIT is deferred to the outer scope.
    pub fn commit(mut self) -> rusqlite::Result<()> {
        let prior = self.state;
        let target = DbTxnState::Committed;
        debug_assert!(
            commit_transition_valid(prior, target),
            "invalid commit transition: {prior:?} -> {target:?}"
        );
        if !self.nested {
            self.conn.execute("COMMIT", [])?;
        }
        self.state = DbTxnState::Committed;
        // Drop will run but is a no-op for Committed state.
        Ok(())
    }

    /// Explicit rollback. Consumes the guard.
    pub fn rollback(mut self) -> rusqlite::Result<()> {
        let prior = self.state;
        let target = DbTxnState::RolledBack;
        debug_assert!(
            rollback_transition_valid(prior, target),
            "invalid rollback transition: {prior:?} -> {target:?}"
        );
        if !self.nested {
            self.conn.execute("ROLLBACK", [])?;
        }
        self.state = DbTxnState::RolledBack;
        Ok(())
    }

    /// Borrow the underlying connection for read-only or same-txn write usage.
    /// Writes performed through this reference participate in the guarded txn.
    pub fn conn(&self) -> &Connection {
        self.conn
    }
}

impl Drop for TxnGuard<'_> {
    fn drop(&mut self) {
        if drop_is_noop(self.state) {
            return;
        }
        if self.nested {
            // Outer scope owns the lifecycle; don't touch it.
            return;
        }
        debug_assert!(
            drop_should_rollback(self.state),
            "drop on unexpected state {:?}",
            self.state
        );
        // Best-effort rollback — we can't return the error from Drop.
        let _ = self.conn.execute("ROLLBACK", []);
    }
}

/// Closure-based helper — drop-in replacement for the old `with_immediate_tx`.
/// Uses `TxnGuard` under the hood so early returns, panics, and `?` all roll back.
pub fn with_immediate_tx<T, F>(conn: &Connection, op: F) -> rusqlite::Result<T>
where
    F: FnOnce(&TxnGuard<'_>) -> rusqlite::Result<T>,
{
    let guard = TxnGuard::begin(conn)?;
    let value = op(&guard)?;
    guard.commit()?;
    Ok(value)
}

/// Closure-based helper — drop-in replacement for `with_immediate_tx_result`.
pub fn with_immediate_tx_result<T, E, F>(conn: &Connection, op: F) -> Result<T, E>
where
    F: FnOnce(&TxnGuard<'_>) -> Result<T, E>,
    E: From<rusqlite::Error>,
{
    let guard = TxnGuard::begin(conn).map_err(E::from)?;
    let value = op(&guard)?;
    guard.commit().map_err(E::from)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE t (x INTEGER)", []).unwrap();
        conn
    }

    #[test]
    fn commit_persists_writes() {
        let conn = setup();
        let guard = TxnGuard::begin(&conn).unwrap();
        conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
        guard.commit().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn drop_rolls_back_writes() {
        let conn = setup();
        {
            let _guard = TxnGuard::begin(&conn).unwrap();
            conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
            // no commit; Drop fires
        }
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "dropped guard must roll back uncommitted writes");
    }

    #[test]
    fn explicit_rollback_rolls_back() {
        let conn = setup();
        let guard = TxnGuard::begin(&conn).unwrap();
        conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
        guard.rollback().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn with_immediate_tx_commits_on_ok() {
        let conn = setup();
        with_immediate_tx(&conn, |g| {
            g.conn().execute("INSERT INTO t VALUES (1)", [])?;
            Ok(())
        })
        .unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn with_immediate_tx_rolls_back_on_err() {
        let conn = setup();
        let _ = with_immediate_tx(&conn, |g| {
            g.conn().execute("INSERT INTO t VALUES (1)", [])?;
            Err::<(), _>(rusqlite::Error::ExecuteReturnedResults)
        });
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn nested_guard_is_passthrough() {
        let conn = setup();
        let outer = TxnGuard::begin(&conn).unwrap();
        {
            // Inner begin sees non-autocommit, acts as passthrough.
            let inner = TxnGuard::begin(&conn).unwrap();
            conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
            inner.commit().unwrap();
            // Outer is still active — the inner's commit did NOT actually commit.
        }
        // Roll back outer.
        drop(outer);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "outer rollback must also discard inner writes");
    }
}
