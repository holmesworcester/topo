# Review Feedback (current status)

## Findings
1. Perf risk: `find_lower_bound` now scans without a `LIMIT`, which can turn a block-sized scan into a full tail scan on larger tables. This is likely a performance regression vs the previous `LIMIT (BLOCK_SIZE + 1)` behavior, especially under heavy reconciliation. Consider restoring a bounded scan now that the infinity/overflow guard is in place, or at least cap by `(last - block_start_count)`.
   - File: `src/sync/negentropy_sqlite.rs`

2. Test suite weight/noise: A large number of new tests were added with `println!` and 5k-item loops. These are great for diagnosis but will slow unit tests and add noise in CI. Consider marking the heavier, diagnostic tests as `#[ignore]` or gating prints behind an env flag.
   - File: `src/sync/negentropy_sqlite.rs`

3. Lockfile drift: `Cargo.lock` now adds `rustls-webpki` without a visible `Cargo.toml` change. If this isn’t intentional, confirm dependency changes.
   - File: `Cargo.lock`

## Notes
- The infinity guard (`timestamp >= i64::MAX`) makes sense given `ts` is stored as `INTEGER` (i64) in SQLite. That should fix the responder overflow case.
- I didn’t run tests.
