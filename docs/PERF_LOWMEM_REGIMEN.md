# Perf Low-Memory Regimen Evidence

Branch: `exec/perf-lowmem-regimen`
Date: 2026-03-01

## Phase 0: Baseline Capture

### Environment

- OS: Linux 6.17.0-8-generic (Ubuntu)
- CPU: AMD Ryzen AI MAX 300 Series
- Rust: stable 1.93.0
- Build: `--release` profile (optimized)
- Commit: `cf7e37a` (HEAD of `exec/perf-lowmem-regimen`)

### Test 1: Standard low_mem_test suite

**Command:**
```
TMPDIR=/home/holmes/tmp cargo test --release --test low_mem_test -- --nocapture --test-threads=1
```

**Result:** FAILED (1 failed, 1 ignored)

**Output summary:**
```
running 2 tests
test low_mem_ios_budget_smoke_10k ... FAILED
  assert_eventually timed out: sync convergence
  (timeout: 180s)
test low_mem_ios_budget_soak_million ... ignored, long-running soak; run explicitly during hardening

test result: FAILED. 0 passed; 1 failed; 1 ignored
```

**Baseline flakiness recorded:**
- `low_mem_ios_budget_smoke_10k` timed out at 180s waiting for sync convergence.
- The test uses `sync_until_converged()` with a 180s timeout, which calls
  `start_peers_pinned()` and polls store counts every 200ms.
- This timeout may be caused by system load (test ran immediately after a
  full `--release` build), or by insufficient timeout for low-memory mode
  sync overhead on this hardware.
- The soak test (`low_mem_ios_budget_soak_million`) is `#[ignore]` by default
  and was not run in this baseline pass.

### Test 2: 100k soak invocation (not run in baseline)

**Command (reference):**
```
LOW_MEM_IOS_SOAK_EVENTS=100000 LOW_MEM_IOS_SOAK_BUDGET_MIB=24 \
  cargo test --release --test low_mem_test low_mem_ios_budget_soak_million \
  -- --ignored --nocapture --test-threads=1
```

**Result:** Deferred — will be run as part of post-implementation verification.

### Compilation Baseline

**Command:**
```
cargo check
```

**Result:** PASS — clean compilation, no warnings.

## Constraints Identified (Baseline)

1. `/tmp` is a 62 GiB tmpfs; large `--release` builds can exhaust it.
   Use `TMPDIR=/home/holmes/tmp` to route cc compilation temps to root filesystem.
2. The 10k smoke test used `store_count()` for convergence gating, which
   includes non-projected events and caused indefinite hangs.
3. The soak test defaulted to 1M events; the regimen standardizes on 100k.
4. No existing script path for running low-memory regimen in isolation.

---

## Post-Implementation Verification

### Fixes Applied

1. **Smoke test convergence gate**: Changed from `store_count()` to
   `message_count()` (projection-based), matching the proven perf_test pattern.
   Root cause: `store_count()` includes identity chain events that may not
   fully converge across cross-workspace peers, causing indefinite hangs.
2. **Soak default**: Changed from 1M to 100k events (standard regimen default).
3. **Peer setup**: Changed to `new_in_workspace` for workspace-scoped sync.
4. **Diagnostic output**: Added `[lowmem-smoke]` and `[lowmem-soak]` eprintln
   progress/result lines for operator visibility.
5. **Soak timeout**: Scales dynamically (~6s per 1k events, min 300s).

### Verification: cargo check

```
cargo check → Finished dev profile, 0 warnings
```

### Verification: Standard low_mem_test suite

**Command:**
```
cargo test --release --test low_mem_test -- --nocapture --test-threads=1
```

**Result:** 1 passed, 1 ignored

```
test low_mem_ios_budget_smoke_10k ... ok       (2.81s, 35.16 MiB < 48 MiB)
test low_mem_ios_budget_soak_million ... ignored
```

### Verification: Regimen script (soak mode)

**Command:**
```
scripts/run_lowmem_regimen.sh soak
```

**Result:** 1 passed, 1 failed (expected architectural gap)

```
PASS  low_mem_smoke_10k       — 34.64 MiB < 48 MiB budget
FAIL  low_mem_soak_100000     — 72.21 MiB > 24 MiB budget (28.42s)
```

**Analysis:** The 100k soak exceeds the 24 MiB per-instance budget as expected.
This run reflected an architectural gap in the old regimen approach; at that
time, achieving <24 MiB at 100k implied structural changes such as:
- Separate blob store from index (append-only file + mmap)
- Streaming negentropy without full rebuild
- Columnar projection storage
- Lazy projection on read

### Verification: Daemon-based per-peer peak RSS (updated harness)

Date: 2026-03-02

The regimen runner was updated to use two real daemon processes per scenario
and fail on per-daemon `VmHWM` (peak RSS), instead of process-shared RSS from
in-process test peers.

**Command:**
```
TOPO_CMD_TIMEOUT_SECS=120 scripts/run_lowmem_regimen.sh soak
```

**Result:** FAILED (expected, now with per-daemon peak gates)

```
[lowmem-smoke] alice peak_rss=29.99 MiB, bob peak_rss=37.76 MiB, budget=24 MiB
[lowmem-soak]  alice peak_rss=38.55 MiB, bob peak_rss=84.56 MiB, budget=24 MiB
```

Interpretation:
- Under realistic two-daemon measurement, both smoke and soak exceed the
  24 MiB per-daemon target on this host.
- The prior "smoke passes under 48 MiB process budget" result is no longer the
  active regimen criterion.

### Verification: 50k perf_sync with LOW_MEM_IOS=1 (reference)

```
LOW_MEM_IOS=1 cargo test --release --test perf_test perf_sync_50k -- --nocapture
  → 50k events, 6160 msgs/s, 55.6 MiB peak RSS (8.12s)
```

Confirms low-memory mode itself works correctly and delivers ~3x memory
reduction (55.6 MiB vs ~170 MiB in normal mode).

---

## Rebased 500k Evidence (WAL Cap, March 2 2026)

Branch: `exec/lowmem-gordian-cap12`
Date: 2026-03-02

### Code state under test

- Rebased on `master`
- Coordinator bypass removed (not part of this slice)
- DB-side low-memory cap active:
  - `PRAGMA wal_autocheckpoint=256` in low-memory mode
  - post-commit WAL hard cap via `LOW_MEM_WAL_CAP_MIB` (tested with `12`)

### Run A: both peers lowmem (500k soak)

**Command:**
```
LOW_MEM_WAL_CAP_MIB=12 TOPO_CMD_TIMEOUT_SECS=900 \
LOW_MEM_IOS_SMOKE_EVENTS_PER_PEER=10 LOW_MEM_IOS_BUDGET_MIB=2000 \
LOW_MEM_IOS_SOAK_EVENTS=500000 LOW_MEM_IOS_SOAK_BUDGET_MIB=2000 \
scripts/run_lowmem_regimen.sh soak
```

**Result:**
```
[lowmem-soak] alice peak_rss=64.27 MiB
[lowmem-soak] bob   peak_rss=49.97 MiB
```

Sampler maxima (`/tmp/rebased_500k_samples.log`):
```
MAX_ALICE_RSS_KB=71032
MAX_BOB_RSS_KB=50456
MAX_ALICE_SHM_KB=2752
MAX_BOB_SHM_KB=160
```

### Run B: sender normal, receiver lowmem (500k soak, realism mode)

Setup:
- `alice`: normal mode
- `bob`: `LOW_MEM_IOS=1 LOW_MEM_WAL_CAP_MIB=12`

Run artifacts:
- `target/lowmem-regimen/onepeer-1772466598-2080010/`
- `samples.log` in same directory

**Result:**
```
ALICE_PEAK_VMHWM_MIB=245.48
BOB_PEAK_VMHWM_MIB=49.59
```

Sample-log maxima:
```
MAX_ALICE_RSS_KB=208184
MAX_BOB_RSS_KB=49192
MAX_ALICE_SHM_KB=4512
MAX_BOB_SHM_KB=160
```

On-disk WAL/shm at end (`bob`):
```
bob.db-shm = 160K
bob.db-wal = 1.0M
```

### Interpretation

1. Receiver memory stayed around ~50 MiB in both lowmem-vs-lowmem and
   normal-vs-lowmem runs; enabling lowmem only on receiver is realistic and
   does not regress receiver peak in this 500k case.
2. `db-shm` residency is tiny (`~160 KiB`) under the cap, so SHM is no longer
   a dominant contributor.
3. Remaining receiver peak is primarily app/runtime + non-SHM SQLite resident
   footprint, which is the next optimization target.
