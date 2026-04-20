# Command And Projector Formal Coverage

This file indexes repo command-entry files and the projector-family gate.

Rules:

1. Every repo command-entry file (`src/**/commands.rs` and
   `src/**/commands_api.rs`) must be listed here with a Verus mirror and
   concrete targeted checks.
2. Registered event projectors must remain covered by the projector-family gate
   in `src/event_modules/mod.rs`.
3. Primary merge-readiness must run this coverage check, the projector-family
   gate, and strict Verus verification.
4. If a covered runtime command or projector path changes, the same diff must
   also touch one of its mapped Verus mirrors.

## Covered Command Categories

| Area | Runtime Module | Verus Mirror | Role | Targeted Checks |
| --- | --- | --- | --- | --- |
| Content-event command APIs | `src/event_modules/message/commands.rs`; `src/event_modules/reaction/commands.rs`; `src/event_modules/message_deletion/commands.rs` | `verus-proofs/src/event_modules/roundtrip.rs`; `verus-proofs/src/event_modules/registry.rs` | Message send, reaction, and message-deletion command APIs produce events whose encoder round-trip and event-type/projector-family bijection are SMT-verified in the Verus mirrors. Command-level invariants beyond framing are covered by the listed runtime tests. | `cargo test -j1 --lib parse_history_span_supports_human_units -- --nocapture`; `cargo test -j1 --lib send_file_rolls_back_all_rows_on_mid_send_failure -- --nocapture`; `cargo test -j1 --lib react_returns_response_for_created_message_target -- --nocapture`; `cargo test -j1 --lib delete_message_returns_target_hex_for_created_message -- --nocapture`; `cargo-verus verify` |
| Workspace workflow command APIs | `src/event_modules/workspace/commands.rs`; `src/event_modules/workspace/commands_api.rs` | `verus-proofs/src/event_modules/workspace/command_plans.rs`; `verus-proofs/src/event_modules/roundtrip.rs` | Workspace create/invite/join/device-link commands resolve explicit bootstrap endpoints via the verified `command_plans` planners (AMF/ECP on missing identity); admin-only `admin add`, `ban`, and `unlink` funnel through mirrored grant/remove planners for non-admin, already-admin, self-target, and already-removed gating, and emitted events still round-trip through the verified encoders. | `cargo test -j1 --lib create_workspace_with_seeded_history_ages_auth_chain_and_messages -- --nocapture`; `cargo test -j1 --lib create_user_invite_materializes_pending_bootstrap_trust_via_projection -- --nocapture`; `cargo test -j1 --lib resolve_invite_bootstrap_endpoint_id_uses_daemon_identity_by_default -- --nocapture`; `cargo test -j1 --lib create_invite_for_peer_leaves_bootstrap_addresses_empty_by_default -- --nocapture`; `cargo test -j1 --lib grant_admin_plan_rejects_non_admin_before_already_admin -- --nocapture`; `cargo test -j1 --lib remove_member_plan_rejects_non_admin_before_other_checks -- --nocapture`; `cargo test -j1 --test cli_admin_commands_test -- --nocapture`; `cargo test -j1 --test cli_remove_member_commands_test -- --nocapture`; `cargo-verus verify` |
| Runtime control command APIs | `src/runtime/control/commands.rs` | `verus-proofs/src/event_modules/registry.rs` | CLI command helpers reject conflicting target selectors, accept the positional selector when present, accept the deprecated selector only when positional input is absent, and use defaults only when no selector was supplied. Events produced by the CLI funnel through the verified event-type-code registry. | `cargo test -j1 --bin topo resolve_target_selector_ -- --nocapture`; `cargo-verus verify` |
| Registered projector families | `src/event_modules/mod.rs` | `verus-proofs/src/event_modules/registry.rs` | Every registered projector must remain assigned to a Verus-covered projector family (via exhaustive match in registry.rs) and the TLA/runtime projector mappings must stay current. | `cargo test -j1 --lib registry_formal_projector_coverage -- --nocapture`; `cargo test -j1 --test projectors -- --nocapture`; `python3 scripts/check_projector_tla_conformance.py`; `python3 scripts/check_projector_tla_bijection.py`; `cargo-verus verify` |
