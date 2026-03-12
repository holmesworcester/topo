CLI integration coverage is still too dependent on one giant `tests/cli_test.rs`
binary.

Current state:
- Exact per-test runs are much more reliable than running the full `cli_test`
  binary end-to-end.
- We added repo-scoped cross-binary locking and in-process daemon cleanup, but
  some join/link/bootstrap scenarios still behave differently when dozens of
  daemon-heavy tests share one test process.

What to do next:
- Split `tests/cli_test.rs` into smaller binaries grouped by concern:
  workspace management, user invites, device links, files, subscriptions.
- Alternatively, add an official deterministic runner that enumerates the
  `cli_test` cases and runs each in its own process.
- Keep daemon lifecycle cleanup in the harness even after the split; it is still
  useful protection against leaked children after panics.

Why this matters:
- The product behavior under test is stateful and networked.
- Rust integration-test binaries share process globals across all tests in the
  file, which is the wrong isolation boundary for these scenarios.
- We want `cargo test` results to reflect product regressions, not test-process
  ordering artifacts.
