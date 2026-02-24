# DESIGN.md Omission Audit (2026-02-24)

## Scope

Audit target: `docs/DESIGN.md` versus current `src/` implementation in `poc-7`.

This audit checks for **omissions** (missing significant behavior), not factual inaccuracies in existing text.

## Conclusion

`docs/DESIGN.md` is **not complete** relative to implemented code. Core architecture is well-covered, but several significant implemented surfaces are not documented.

## Significant omissions

1. **UPnP/IGD NAT mapping flow is undocumented**
   - Code implements first-class UPnP mapping status/reporting and double-NAT detection: `src/peering/nat/upnp.rs` (`UpnpMappingReport`, `attempt_udp_port_mapping`) [upnp.rs](/home/holmes/poc-7-design-omissions-audit/src/peering/nat/upnp.rs:13), [upnp.rs](/home/holmes/poc-7-design-omissions-audit/src/peering/nat/upnp.rs:159).
   - Exposed as daemon RPC + CLI command: `RpcMethod::Upnp` and `topo upnp` [protocol.rs](/home/holmes/poc-7-design-omissions-audit/src/rpc/protocol.rs:109), [server.rs](/home/holmes/poc-7-design-omissions-audit/src/rpc/server.rs:597), [main.rs](/home/holmes/poc-7-design-omissions-audit/src/main.rs:1023).
   - `DESIGN.md` NAT section covers hole punch/intro only; no UPnP behavior or contract [DESIGN.md](/home/holmes/poc-7-design-omissions-audit/docs/DESIGN.md:168).

2. **RPC wire/API contract is underspecified**
   - Implementation has explicit versioned RPC envelope and length-prefixed JSON framing [protocol.rs](/home/holmes/poc-7-design-omissions-audit/src/rpc/protocol.rs:6), [protocol.rs](/home/holmes/poc-7-design-omissions-audit/src/rpc/protocol.rs:158).
   - Server enforces connection caps and owns daemon-state behavior (`active_peer`, invite refs, channel aliases) [server.rs](/home/holmes/poc-7-design-omissions-audit/src/rpc/server.rs:22), [server.rs](/home/holmes/poc-7-design-omissions-audit/src/rpc/server.rs:40).
   - `DESIGN.md` CLI/daemon section only states "local RPC control socket" and broad routing shape; method-level and framing contract are omitted [DESIGN.md](/home/holmes/poc-7-design-omissions-audit/docs/DESIGN.md:856).

3. **Identity finalization/rebinding path is missing**
   - Code performs transactional identity rebinding (`recorded_by`/`peer_id`) after bootstrap identity transitions, including queue/blocker reconciliation [db/mod.rs](/home/holmes/poc-7-design-omissions-audit/src/db/mod.rs:64), [db/mod.rs](/home/holmes/poc-7-design-omissions-audit/src/db/mod.rs:159).
   - Called in workspace bootstrap and invite/device-link accept flows [commands.rs](/home/holmes/poc-7-design-omissions-audit/src/event_modules/workspace/commands.rs:726), [commands.rs](/home/holmes/poc-7-design-omissions-audit/src/event_modules/workspace/commands.rs:912), [commands.rs](/home/holmes/poc-7-design-omissions-audit/src/event_modules/workspace/commands.rs:1005).
   - `DESIGN.md` describes bootstrap operation ordering and transport identity intent, but not this rebinding/finalization stage [DESIGN.md](/home/holmes/poc-7-design-omissions-audit/docs/DESIGN.md:237).

4. **Control/data stream completion protocol details are missing**
   - Wire protocol defines explicit `Done`, `DoneAck`, and `DataDone` frames [protocol.rs](/home/holmes/poc-7-design-omissions-audit/src/protocol.rs:15), [protocol.rs](/home/holmes/poc-7-design-omissions-audit/src/protocol.rs:37).
   - Initiator/responder logic depends on strict ordering for session completion and drain guarantees [initiator.rs](/home/holmes/poc-7-design-omissions-audit/src/sync/session/initiator.rs:213), [responder.rs](/home/holmes/poc-7-design-omissions-audit/src/sync/session/responder.rs:147).
   - `DESIGN.md` discusses queue/coordination and frame delimiting, but not this end-of-session control protocol [DESIGN.md](/home/holmes/poc-7-design-omissions-audit/docs/DESIGN.md:84), [DESIGN.md](/home/holmes/poc-7-design-omissions-audit/docs/DESIGN.md:769).

5. **Database registry behavior is undocumented**
   - CLI supports a persistent DB alias/default registry (`topo db add/list/remove/rename/default`) [main.rs](/home/holmes/poc-7-design-omissions-audit/src/main.rs:980).
   - Backed by `~/.topo/db_registry.json` with selector-resolution semantics [db_registry.rs](/home/holmes/poc-7-design-omissions-audit/src/db_registry.rs:1), [db_registry.rs](/home/holmes/poc-7-design-omissions-audit/src/db_registry.rs:123).
   - `DESIGN.md` does not document this operational contract in section 8 [DESIGN.md](/home/holmes/poc-7-design-omissions-audit/docs/DESIGN.md:854).

6. **SignedMemo event type is omitted from design narrative**
   - Canonical event type 4 is present in registry and parser/projector stack [mod.rs](/home/holmes/poc-7-design-omissions-audit/src/event_modules/mod.rs:52), [signed_memo.rs](/home/holmes/poc-7-design-omissions-audit/src/event_modules/signed_memo.rs:143).
   - `DESIGN.md` explicitly references several specific non-identity event types (message/reaction/deletion/attachment/file_slice), but not `signed_memo` [DESIGN.md](/home/holmes/poc-7-design-omissions-audit/docs/DESIGN.md:1051).

## Overall verdict

`DESIGN.md` captures most core protocol architecture but does **not** completely capture implemented behavior. The missing areas above are substantial enough that the answer to "does DESIGN.md completely capture all code?" is **no**.
