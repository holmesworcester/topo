# Encryption Coverage Matrix

## Content Write Paths (must produce `encrypted` wrappers)

| Write Path | Location | Pre-Fix Status | Post-Fix Status |
|---|---|---|---|
| `message::commands::create()` | `src/event_modules/message/commands.rs:38` | FAKE (raw signed) | REAL (encrypted) |
| `message::commands::send()` | `src/event_modules/message/commands.rs:60` | FAKE (calls create) | REAL (via create) |
| `message::commands::send_for_peer()` | `src/event_modules/message/commands.rs:173` | FAKE (calls send) | REAL (via send) |
| `message::commands::generate_for_peer()` | `src/event_modules/message/commands.rs:227` | FAKE (calls create) | REAL (via create) |
| `message::commands::create_deletion()` | `src/event_modules/message/commands.rs:99` | FAKE (raw signed) | REAL (encrypted) |
| `message::commands::delete_message()` | `src/event_modules/message/commands.rs:120` | FAKE (calls create_deletion) | REAL (via create_deletion) |
| `message::commands::delete_message_for_peer()` | `src/event_modules/message/commands.rs:199` | FAKE (calls delete_message) | REAL (via delete_message) |
| `message::commands::generate_files_for_peer()` | `src/event_modules/message/commands.rs:269` | FAKE (raw msg+attachment+slices) | REAL (encrypted wrappers) |
| `message::commands::send_file_for_peer()` | `src/event_modules/message/commands.rs:420` | FAKE (raw msg+attachment+slices) | REAL (encrypted wrappers) |
| `reaction::commands::create()` | `src/event_modules/reaction/commands.rs:28` | FAKE (raw signed) | REAL (encrypted) |
| `reaction::commands::react()` | `src/event_modules/reaction/commands.rs:56` | FAKE (calls create) | REAL (via create) |
| `reaction::commands::react_for_peer()` | `src/event_modules/reaction/commands.rs:91` | FAKE (calls react) | REAL (via react) |
| `message_deletion::commands::create()` | `src/event_modules/message_deletion/commands.rs:14` | FAKE (raw signed, unused) | REAL (encrypted) |
| `message_deletion::commands::delete_message()` | `src/event_modules/message_deletion/commands.rs:35` | FAKE (calls create, unused) | REAL (via create) |

## Key Distribution Paths (must use real wrap/unwrap)

| Path | Location | Status |
|---|---|---|
| Workspace create → content key | `workspace/commands.rs:244` | REAL |
| User invite → wrap content key | `workspace/identity_ops.rs:160` | REAL |
| User invite accept → unwrap content key | `workspace/identity_ops.rs:207` | REAL |
| Device-link invite → wrap content key | `workspace/commands.rs:515` | GAP (no wrap) |
| Device-link accept → unwrap content key | `workspace/commands.rs:399` | GAP (no unwrap) |
| Pending invite retry | `workspace/commands.rs:553` | REAL |

## Test Patterns (fake vs real)

| Test | Location | Pre-Fix Status |
|---|---|---|
| `test_encrypted_event_sync` | `tests/scenario_test.rs:~810` | MIXED (real crypto, PSK distribution) |
| `test_encrypted_out_of_order_sync` | `tests/scenario_test.rs:~860` | MIXED (real crypto, PSK distribution) |
| `test_encrypted_replay_invariants` | `tests/scenario_test.rs:~930` | MIXED (raw + encrypted) |
| `Peer::create_message()` | `src/testutil/mod.rs:401` | FAKE (raw signed, no encrypt) |
| `Peer::create_reaction()` | `src/testutil/mod.rs:418` | FAKE (raw signed, no encrypt) |
| `Peer::create_message_deletion()` | `src/testutil/mod.rs:496` | FAKE (raw signed, no encrypt) |
| `Peer::create_encrypted_message()` | `src/testutil/mod.rs:462` | REAL (encrypted) |
| `Peer::create_encrypted_deletion()` | `src/testutil/mod.rs:512` | REAL (encrypted) |
| `Peer::create_secret_key_deterministic()` | `src/testutil/mod.rs:447` | PSK (manual both-sides) |

## Explicit Out-of-Scope

1. TreeKEM/DCKGA or advanced group key agreement
2. Historical key rotation and history re-encryption
3. Encrypting auth/identity naming fields
