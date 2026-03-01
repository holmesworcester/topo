# DESIGN.md Omission Audit And Remediation Plan (2026-02-24)

## Scope

Audit target: `docs/DESIGN.md` versus current `src/` implementation in `poc-7`.

This audit checks for **omissions** (missing significant behavior), not factual inaccuracies in existing text.

## Conclusion

`docs/DESIGN.md` is **not complete** relative to implemented code. Core architecture is well-covered, but several significant implemented surfaces are not documented.

## Plan Update

Remediation plan (updated):

1. Capture and patch all six original omissions from this audit.
2. Re-scan `src/` vs `DESIGN.md` for additional significant omissions.
3. Patch newly discovered omissions.
4. Keep this audit document as a status ledger (issues + fix state + evidence).

Status:

- [x] Step 1 complete (`f1de373`).
- [x] Step 2 complete (second-pass sweep run on `master`).
- [x] Step 3 complete (additional omissions patched in `docs/DESIGN.md`).
- [x] Step 4 complete (this update).

## Significant omissions

1. **UPnP/IGD NAT mapping flow is undocumented**
   - Code implements first-class UPnP mapping status/reporting and double-NAT detection: `src/peering/nat/upnp.rs` (`UpnpMappingReport`, `attempt_udp_port_mapping`) [upnp.rs](/home/holmes/poc-7/src/peering/nat/upnp.rs:13), [upnp.rs](/home/holmes/poc-7/src/peering/nat/upnp.rs:159).
   - Exposed as daemon RPC + CLI command: `RpcMethod::Upnp` and `topo upnp` [protocol.rs](/home/holmes/poc-7/src/rpc/protocol.rs:109), [server.rs](/home/holmes/poc-7/src/rpc/server.rs:597), [main.rs](/home/holmes/poc-7/src/main.rs:1023).
   - `DESIGN.md` NAT section covers hole punch/intro only; no UPnP behavior or contract [DESIGN.md](/home/holmes/poc-7/docs/DESIGN.md:168).

2. **RPC wire/API contract is underspecified**
   - Implementation has explicit versioned RPC envelope and length-prefixed JSON framing [protocol.rs](/home/holmes/poc-7/src/rpc/protocol.rs:6), [protocol.rs](/home/holmes/poc-7/src/rpc/protocol.rs:158).
   - Server enforces connection caps and owns daemon-state behavior (`active_peer`, invite refs, channel aliases) [server.rs](/home/holmes/poc-7/src/rpc/server.rs:22), [server.rs](/home/holmes/poc-7/src/rpc/server.rs:40).
   - `DESIGN.md` CLI/daemon section only states "local RPC control socket" and broad routing shape; method-level and framing contract are omitted [DESIGN.md](/home/holmes/poc-7/docs/DESIGN.md:856).

3. **Identity finalization/rebinding path is missing**
   - Code performs transactional identity rebinding (`recorded_by`/`peer_id`) after bootstrap identity transitions, including queue/blocker reconciliation [db/mod.rs](/home/holmes/poc-7/src/db/mod.rs:64), [db/mod.rs](/home/holmes/poc-7/src/db/mod.rs:159).
   - Called in workspace bootstrap and invite/device-link accept flows [commands.rs](/home/holmes/poc-7/src/event_modules/workspace/commands.rs:726), [commands.rs](/home/holmes/poc-7/src/event_modules/workspace/commands.rs:912), [commands.rs](/home/holmes/poc-7/src/event_modules/workspace/commands.rs:1005).
   - `DESIGN.md` describes bootstrap operation ordering and transport identity intent, but not this rebinding/finalization stage [DESIGN.md](/home/holmes/poc-7/docs/DESIGN.md:237).

4. **Control/data stream completion protocol details are missing**
   - Wire protocol defines explicit `Done`, `DoneAck`, and `DataDone` frames [protocol.rs](/home/holmes/poc-7/src/protocol.rs:15), [protocol.rs](/home/holmes/poc-7/src/protocol.rs:37).
   - Initiator/responder logic depends on strict ordering for session completion and drain guarantees [initiator.rs](/home/holmes/poc-7/src/sync/session/initiator.rs:213), [responder.rs](/home/holmes/poc-7/src/sync/session/responder.rs:147).
   - `DESIGN.md` discusses queue/coordination and frame delimiting, but not this end-of-session control protocol [DESIGN.md](/home/holmes/poc-7/docs/DESIGN.md:84), [DESIGN.md](/home/holmes/poc-7/docs/DESIGN.md:769).

5. **Database registry behavior is undocumented**
   - CLI supports a persistent DB alias/default registry (`topo db add/list/remove/rename/default`) [main.rs](/home/holmes/poc-7/src/main.rs:980).
   - Backed by `~/.topo/db_registry.json` with selector-resolution semantics [db_registry.rs](/home/holmes/poc-7/src/db_registry.rs:1), [db_registry.rs](/home/holmes/poc-7/src/db_registry.rs:123).
   - `DESIGN.md` does not document this operational contract in section 8 [DESIGN.md](/home/holmes/poc-7/docs/DESIGN.md:854).

6. **Retired event type 4 status was omitted from design narrative**
   - Canonical event type 4 existed historically in earlier parser/projector stacks.
   - `DESIGN.md` now documents event type 4 as retired/unknown-type rejected in the current epoch.

## Additional omissions found in second sweep

7. **`bench_dep` event type (type 26) not documented**
   - Code defines canonical fixed-size benchmark dependency event (`bench_dep_perf_testing`) in the event registry [mod.rs](/home/holmes/poc-7/src/event_modules/mod.rs:74), [bench_dep.rs](/home/holmes/poc-7/src/event_modules/bench_dep.rs:127).
   - This event type was not explicitly covered in `DESIGN.md`.

8. **`transport_session_io` ownership not explicit**
   - `src/transport/transport_session_io.rs` owns frame validation and adapter-layer error mapping for `TransportSessionIo` [transport_session_io.rs](/home/holmes/poc-7/src/transport/transport_session_io.rs:1).
   - Module-ownership section previously documented `connection_lifecycle` and `session_factory` but not this adapter seam.

9. **Low-memory tuning control surface underdocumented**
   - Runtime low-memory mode is controlled by `LOW_MEM_IOS` / `LOW_MEM` and centralized in `src/tuning.rs` [tuning.rs](/home/holmes/poc-7/src/tuning.rs:1).
   - `DESIGN.md` described goals (`low_mem_ios`) but not the runtime toggle and centralized tuning surface.

## Remediation status

- Omissions 1-6: fixed in `docs/DESIGN.md` (`f1de373`).
- Omissions 7-9: fixed in `docs/DESIGN.md` in the follow-up sweep (current branch `master`, post-merge patch).

## Overall verdict

After both remediation passes, previously identified omissions are addressed. Additional omissions found in the second sweep are also addressed.
