Here's my review:

## Top 3 Remaining Risks

1. **Phase 1 scope creep / analysis paralysis.** Freezing all contracts upfront before any extraction is a big-bang design commitment. If the contracts turn out wrong once you hit real extraction in phases 2-3, you'll either live with a bad boundary or do a costly contract revision that ripples across adapters and tests. The plan says "no throwaway adapters" but that's aspirational — you won't know until you extract.

2. **Tier 3/4 test infrastructure as a blocking dependency.** Multi-process conformance tests and netns/netem CI require significant infra work (privileged CI runners, test harness for process orchestration). If this isn't ready by phase 5, the adversity suite becomes a permanent "TODO" and the anti-bypass guarantees are paper-only. There's no fallback if your CI environment can't support privileged netns.

3. **Adapter performance and semantic drift.** The thin adapters in phase 1 wrap existing APIs, but the contracts assume clean async boundaries (`poll_send_ready`, typed errors) that the current code may not naturally support. Shimming these semantics into adapters risks subtle behavioral differences (e.g., backpressure that didn't exist before, error variants that get mapped lossy). The baseline trace comparison helps but won't catch all edge cases.

## One Contract Improvement

`SessionIo` should have a `session_id` or carry a reference to `SessionMeta` so that logging/diagnostics inside trait implementations can correlate without out-of-band plumbing. More importantly, `recv_control` and `recv_data` return `Vec<u8>` — consider returning a `Bytes` type (or a bounded buffer type that enforces `max_frame_size` at the type level) so the frame size invariant is structural rather than relying on every implementor to check and return `FrameTooLarge` correctly. Push the invariant into the contract, not the implementation.

## One Test Gap

There's no test coverage specified for **concurrent session interleaving** — multiple peers replicating simultaneously with the same tenant, competing for the same outbound queue (`claim_outbound`). The conformance matrix covers single-session integrity and crash recovery, but doesn't address whether two concurrent sessions can corrupt shared queue state, double-claim events, or deadlock on the `ReplicationStore`. Add a tier 2 test that runs N parallel sessions against a shared store and asserts no duplicate delivery and no lost events.
