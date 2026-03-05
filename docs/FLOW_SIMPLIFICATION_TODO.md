# Flow Simplification TODO

- [x] Drop `egress_queue` retry/recovery complexity that duplicates negentropy retries across rounds/sessions.
  - Simplify `egress_queue` usage to ephemeral per-session send buffering semantics.
  - Remove unused/low-value retry machinery (`attempts` backoff paths, explicit recovery handling) where safe.
  - Preserve correctness via existing negentropy re-diff/re-request behavior in subsequent rounds/sessions.
  - Validate with sync/session + perf tests to confirm no regression in convergence.

- [x] Extract and centralize queue tuning + low-memory configuration.
  - Consolidate duplicated `low_mem` toggles and queue-cap/batch-size constants across ingest/sync/peering/db modules.
  - Define one canonical config surface for queue capacities, claim sizes, and batch caps.
  - Keep existing defaults and low-memory behavior equivalent while reducing drift risk.

- [x] Remove unused trait-based ingest/store abstraction.
  - Remove unused `IngestSink` / `ReplicationStore` traits and `sqlite_adapters` if they remain unwired in production paths.
  - Keep runtime composition rooted in the active production ingest model (shared writer + queue-backed sync flow).
  - Ensure tests and docs no longer reference retired abstraction paths.
