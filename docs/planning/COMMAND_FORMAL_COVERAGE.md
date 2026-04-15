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
| Content-event command APIs | `src/event_modules/message/commands.rs`; `src/event_modules/reaction/commands.rs`; `src/event_modules/message_deletion/commands.rs` | `verus-proofs/src/event_modules/content_commands.rs` | Message send, reaction, and message-deletion command APIs must preserve resolved authoring inputs, require the needed content-key/target-owner context, and fail closed when that context is absent. | `cargo test -j1 --lib parse_history_span_supports_human_units -- --nocapture`; `cargo test -j1 --lib send_file_rolls_back_all_rows_on_mid_send_failure -- --nocapture`; `cargo test -j1 --lib react_returns_response_for_created_message_target -- --nocapture`; `cargo test -j1 --lib delete_message_returns_target_hex_for_created_message -- --nocapture`; `cargo-verus verify` |
| Workspace workflow command APIs | `src/event_modules/workspace/commands.rs`; `src/event_modules/workspace/commands_api.rs` | `verus-proofs/src/event_modules/workspace_commands.rs` | Workspace create/invite/join/device-link command APIs must keep already-local joins local-only, preserve explicit local replay/bootstrap split, and fail closed on malformed bootstrap scope. | `cargo test -j1 --lib create_workspace_with_seeded_history_ages_auth_chain_and_messages -- --nocapture`; `cargo test -j1 --lib create_user_invite_materializes_pending_bootstrap_trust_via_projection -- --nocapture`; `cargo test -j1 --lib resolve_invite_bootstrap_endpoint_id_uses_daemon_identity_by_default -- --nocapture`; `cargo test -j1 --lib create_invite_for_peer_leaves_bootstrap_addresses_empty_by_default -- --nocapture`; `cargo-verus verify` |
| Runtime control command APIs | `src/runtime/control/commands.rs` | `verus-proofs/src/runtime/control/commands.rs` | CLI command helpers must reject conflicting target selectors, accept the positional selector when present, accept the deprecated selector only when positional input is absent, and use defaults only when no selector was supplied. | `cargo test -j1 --bin topo resolve_target_selector_ -- --nocapture`; `cargo-verus verify` |
| Registered projector families | `src/event_modules/mod.rs` | `verus-proofs/src/pipeline/projectors.rs`; `verus-proofs/src/pipeline/file_projectors.rs`; `verus-proofs/src/pipeline/event_projectors.rs` | Every registered projector must remain assigned to a Verus-covered projector family and the TLA/runtime projector mappings must stay current. | `cargo test -j1 --lib registry_formal_projector_coverage -- --nocapture`; `cargo test -j1 --test projectors -- --nocapture`; `python3 scripts/check_projector_tla_conformance.py`; `python3 scripts/check_projector_tla_bijection.py`; `cargo-verus verify` |
