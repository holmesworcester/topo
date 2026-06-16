//! Phase 3: SQL-mapping spec for typed WriteOp variants.
//!
//! Pins the SQL template and parameter count that the apply executor
//! emits for `WriteOp::InsertKeySecretFromUnwrap` and `InsertKeySecretLocal`.
//! The runtime imports `key_secrets_insert_sql_template` and uses it as the
//! SQL argument to `conn.execute`; drift between the runtime string and this
//! Verus-pinned constant requires updating both simultaneously.
//!
//! Scope: currently covers only the two typed key_secrets variants, which
//! are the access-control-critical writes. Generic `InsertOrIgnore` and
//! `Delete` variants have runtime-supplied table/columns so their SQL is
//! not statically pinnable; their correctness is enforced via the
//! write-site CI gate + the typed-row constructors.

use vstd::prelude::*;
use super::writeop_idempotency::WriteOpKind;

verus! {

/// Canonical SQL template for both `InsertKeySecretFromUnwrap` and
/// `InsertKeySecretLocal`. The two variants share the same SQL — they
/// differ only in which access-control invariant applies. The runtime
/// `conn.execute(..)` call is bound to this exact string.
pub const KEY_SECRETS_INSERT_SQL: &'static str =
    "INSERT OR IGNORE INTO key_secrets (event_id, key_bytes, created_at, recorded_by) VALUES (?1, ?2, ?3, ?4)";

/// Exec-side accessor. Returns a reference to the canonical template.
/// `ensures` pins the return value so Rust refactors cannot drift the
/// template without failing `cargo-verus verify`.
pub fn key_secrets_insert_sql_template() -> (out: &'static str)
    ensures out == KEY_SECRETS_INSERT_SQL,
{
    KEY_SECRETS_INSERT_SQL
}

/// Placeholder count for the key_secrets insert SQL. Must match the
/// number of `?N` markers in the template and the number of fields in
/// `KeySecretsRow` (event_id_b64, key_bytes, created_at_ms, recorded_by).
pub fn key_secrets_insert_placeholder_count() -> (n: u8)
    ensures n == 4,
{
    4
}

/// Which table does each WriteOp variant target? For variants with a
/// statically-pinned SQL, this must match the table name in the template.
/// For variants whose table is runtime-supplied, returns None.
pub open spec fn writeop_target_table_spec(kind: WriteOpKind) -> Option<Seq<char>> {
    match kind {
        WriteOpKind::InsertKeySecretFromUnwrap
        | WriteOpKind::InsertKeySecretLocal => Some("key_secrets"@),
        WriteOpKind::InsertOrIgnore
        | WriteOpKind::Delete => Option::None,
    }
}

/// THE VARIANT-TABLE DISCIPLINE THEOREM.
///
/// Both key_secrets-typed variants write to the `key_secrets` table,
/// and never to any other table. A future refactor that re-routed one of
/// these variants to a different table would require updating this proof
/// fn (and thereby `writeop_target_table_spec`) in lockstep with the
/// executor's match arm.
pub proof fn typed_variants_target_key_secrets(kind: WriteOpKind)
    ensures
        (kind == WriteOpKind::InsertKeySecretFromUnwrap
         || kind == WriteOpKind::InsertKeySecretLocal)
            ==> writeop_target_table_spec(kind) == Some::<Seq<char>>("key_secrets"@),
{
}

/// Generic variants have no pinned table: their target is supplied at
/// construction time via the `table: &'static str` field. The CI gate
/// covers their write-site discipline; this proof records that the
/// Verus SQL-mapping layer explicitly does NOT bind them.
pub proof fn generic_variants_target_is_runtime_supplied(kind: WriteOpKind)
    ensures
        (kind == WriteOpKind::InsertOrIgnore || kind == WriteOpKind::Delete)
            ==> writeop_target_table_spec(kind) is None,
{
}

} // verus!
