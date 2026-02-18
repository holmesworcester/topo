# Plan: Collapse single-tenant mode into node mode

## Context

Two sync entry points exist: `svc_sync` (single-tenant, `service.rs:1078`) and `run_node` (multi-tenant, `node.rs:82`). They duplicate endpoint creation, trust setup, batch_writer spawning, and accept_loop orchestration. With transport identity unification complete, a single-tenant peer is just a node with one tenant. The `--node` flag in the daemon and the dual code paths add complexity with no functional benefit.

Goal: make `run_node` the single sync entry point. Remove `svc_sync` and all single-tenant-only code paths it depended on.

## Step 1: Extend `run_node` signature

**File**: `src/node.rs`

Change `run_node(db_path: &str, bind_ip: IpAddr)` to:

```rust
pub async fn run_node(
    db_path: &str,
    bind: SocketAddr,
    connect: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
```

Currently `run_node` does `SocketAddr::new(bind_ip, 0)` (auto-assign port). Change to use the caller-provided `bind` directly, so callers can specify an exact port (needed by CLI tests and `topo start --bind`).

Remove the `use std::net::IpAddr` import (no longer needed), add `use std::net::SocketAddr`.

## Step 2: Add explicit `--connect` support to `run_node`

**File**: `src/node.rs`

**Important**: `endpoint` is moved into the accept thread at line 302. We must clone it *before* the move for connect_loop use. Restructure the accept_loop block to clone first:

```rust
// Clone endpoint before moving into accept thread
let connect_endpoint = endpoint.clone();

let accept_handle = std::thread::spawn(move || {
    // ... existing accept_loop_with_ingest using endpoint (moved) ...
});

// After accept_loop spawn, add connect_loop if --connect provided
if let Some(remote) = connect {
    for tenant in &tenants {
        let ep = connect_endpoint.clone();
        let db = db_path.to_string();
        let tid = tenant.peer_id.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = crate::sync::engine::connect_loop(&db, &tid, ep, remote).await {
                    tracing::warn!("connect_loop for {} exited: {}", &tid[..16], e);
                }
            });
        });
    }
}
```

**Note on per-tenant client cert**: `create_single_port_endpoint` sets the default client config to the first tenant's cert. For single-tenant (the common case after collapse), this is correct — there's only one cert. For true multi-tenant `--connect`, all outbound connections present the same cert. This is acceptable because:
- `connect_loop` uses SNI (`workspace_sni`) to identify the workspace
- The remote server resolves the tenant via SPKI fingerprint post-handshake
- Multi-tenant `--connect` is a rare edge case (mDNS discovery handles it)

If needed later, per-tenant `connect_with()` configs can be added.

## Step 3: Remove `svc_sync` from service.rs

**File**: `src/service.rs`

Delete `svc_sync` (lines 1074-1174) and its section comment. Keep:
- `create_dual_endpoint_dynamic` import (line 24) — still used by `svc_intro` (line 1198)
- All other service functions unchanged

## Step 4: Update `src/main.rs` Sync command

**File**: `src/main.rs`

Change:
```rust
Commands::Sync { bind, connect, db } => {
    service::svc_sync(bind, connect.clone(), &db).await?;
}
```
To:
```rust
Commands::Sync { bind, connect, db } => {
    poc_7::node::run_node(&db, bind, connect).await?;
}
```

The `use poc_7::service` import stays (used by many other commands).

## Step 5: Update `src/main.rs` (formerly `src/bin/p7d.rs`)

**File**: `src/main.rs`

Remove:
- `--node` flag from `Args` struct (line 43-44)
- The if/else branch that switches between `run_node` and `svc_sync`

**Keep** `use poc_7::service;` — still needed for `service::socket_path_for_db` (line 66).

Replace the sync dispatch with unconditional:
```rust
poc_7::node::run_node(&args.db, args.bind, args.connect).await?;
```

The RPC server setup stays unchanged (still runs alongside).

## Step 6: Keep `accept_loop` in engine.rs

**File**: `src/sync/engine.rs`

`accept_loop` (lines 1087-1105) is a thin wrapper around `accept_loop_with_ingest` that creates its own batch_writer. After removing `svc_sync`, its only callers are `testutil.rs` test helpers. **Keep it as-is** — it's a useful convenience for single-tenant test scenarios.

## Step 7: Update error messages and test assertions

**File**: `src/node.rs`, `tests/cli_test.rs`

`run_node` currently errors with "No local identities found" when `discover_local_tenants` returns empty. `svc_sync` errored with "No trusted peers". The test `test_cli_sync_without_trust_fails` (cli_test.rs:333) checks for `"No trusted peers" || "invite"`.

Fix: update the test assertion to also accept the new message:

```rust
assert!(
    stderr.contains("No trusted peers")
    || stderr.contains("invite")
    || stderr.contains("No local identities"),
    "error should mention trust or identities, got: {}",
    stderr
);
```

## Step 8: Verify discovery feature behavior

`discovery` is a default feature (`Cargo.toml:36`). After collapse, mDNS advertise/browse runs for all sync users, not just `--node` users. This is acceptable:
- mDNS discovery is no-op when there are no other mDNS peers on the network
- It enables automatic peer discovery for all users
- Can still be disabled with `--no-default-features` if unwanted

No code change needed, but worth noting as a behavior change.

## Step 9: Clean up dead code, stale references, and docs

- Remove `svc_sync` section comment block in service.rs
- Update `src/db/transport_creds.rs:41,55` — `load_sole_local_creds` error message references `--node mode` which no longer exists. Change to generic message: `"Multiple local identities found ({count}). This is handled automatically."`
- Update `docs/DESIGN.md` if it mentions `--node` flag or node mode as separate from normal mode
- Update `docs/PLAN.md` references if any mention the dual-mode architecture

## Files modified

1. `src/node.rs` — extend signature (`SocketAddr` + `Option<SocketAddr>`), clone endpoint before accept thread, add connect_loop support
2. `src/service.rs` — delete `svc_sync` function (~100 lines)
3. `src/main.rs` — change Sync handler to call `run_node`
4. `src/main.rs` — remove `--node` flag, always call `run_node`, keep service import
5. `tests/cli_test.rs` — update `test_cli_sync_without_trust_fails` error assertion

## Files NOT modified

- `src/sync/engine.rs` — `accept_loop` kept for test use
- `src/transport/mod.rs` — `create_dual_endpoint_dynamic` kept for `svc_intro` and tests
- `src/testutil.rs` — uses `accept_loop` and `create_dual_endpoint_dynamic` directly, unchanged

## Verification

1. `cargo build --bin topo` — compiles
2. `cargo test -q --test cli_test` — all 6 CLI tests pass
3. `cargo test -q --test rpc_test` — all 13 RPC tests pass
4. `cargo test -q --test holepunch_test` — all 4 holepunch tests pass
5. `cargo test -q` — full suite green (expect same 2 pre-existing scenario failures)

## Codex Review Findings (addressed)

1. **Endpoint move** (High): Fixed in Step 2 — clone endpoint before accept thread spawn
2. **Per-tenant client cert** (High): Acknowledged — single default cert is correct for 1-tenant case; SNI+SPKI handles multi-tenant adequately
3. **has_any_trusted_peer vs discover_local_tenants** (Medium): The semantics differ but both correctly gate on "has a bootstrapped identity". `discover_local_tenants` is actually stricter (requires both trust_anchors and transport creds), which is correct behavior
4. **service import in main** (Low): Fixed in Step 5 — keep the import for `socket_path_for_db`
5. **Discovery feature** (Low): Documented in Step 8 — acceptable behavior change
