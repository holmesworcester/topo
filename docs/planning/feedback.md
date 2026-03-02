# Perf Tail Profile + Tuning Review Feedback

## Review 1 — Codex CLI (gpt-5.3-codex, 2026-03-01)

### Finding: [P2] Preserve low-mem WAL checkpoints during queue drain

**Severity**: Medium
**File**: `src/state/pipeline/drain.rs:34`
**Description**: `PRAGMA wal_autocheckpoint = 0` was set unconditionally for every projection drain, including `LOW_MEM/LOW_MEM_IOS` runs where `open_connection` configures checkpoint and journal limits to bound WAL size. On constrained-storage devices with a large project_queue backlog, this could let WAL grow until `SQLITE_FULL` before any checkpoint occurs.

**Resolution**: Gated the deferred checkpoint optimization with `!low_mem_mode()`. In low_mem mode, the drain runs with the default `wal_autocheckpoint = 1000` set by `open_connection`, preserving bounded WAL growth. Updated PLAN.md, DESIGN.md, and evidence file to document the guard.

**Status**: Fixed.

---

### Overall Status: All findings resolved.
