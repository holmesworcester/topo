---
marp: true
paginate: true
size: 16:9
title: Topo demo presentation
description: How Topo addresses major pain points in p2p stacks
style: |
  section {
    background: #0f1115;
    color: #f2efe5;
    font-family: "Aptos", "Segoe UI", "Helvetica Neue", sans-serif;
    padding: 56px 64px;
  }

  section.lead {
    justify-content: center;
    text-align: center;
  }

  h1,
  h2,
  h3 {
    color: #8ec07c;
  }

  section.lead h1 {
    font-size: 2.2em;
    margin-bottom: 0.25em;
  }

  section.lead p {
    font-size: 1.05em;
  }

  ul {
    font-size: 1.05em;
    line-height: 1.35;
  }

  strong {
    color: #8ec07c;
  }

  pre {
    background: #161b22;
    border: 1px solid #2a2f3a;
    border-radius: 10px;
    padding: 18px 20px;
    box-shadow: none;
  }

  code {
    background: transparent;
    color: #f2efe5;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.72em;
    color: #f2efe5;
    background: #161b22;
    border: 1px solid #2a2f3a;
  }

  th,
  td {
    border: 1px solid #2a2f3a;
    padding: 8px 10px;
  }

  th {
    background: #1f2630;
    color: #8ec07c;
    font-weight: 700;
  }

  td {
    background: #11161d;
  }

  tr:nth-child(even) td {
    background: #151b24;
  }
---

<!-- _class: lead -->

# Topo 🐭

## Can building p2p collaboration tools be made easier? 🥹

---

# Why does this matter? 🤔

<!-- pt:incremental_lists: true -->

- A FOSS p2p Slack or Discord would be awesome
- It would provide safety🛡 and resiliency🛟 to orgs we care about 
- We've spent years building one (**Quiet - tryquiet.org**)
- This has been a real slog

---

# This question haunts our team 👻 

Is p2p just intrinsically #$%@ing hard? Or is all this slog totally avoidable and pointless?

---

# Why has this been such a slog? 😡

<!-- pt:incremental_lists: true -->

- Many problems to solve: p2p, e2ee, sync, files, push etc.
- Solutions aren't generic; must fit product needs
- Concurrency is a minefield 💥, time bomb 💣, quagmire 🐊, rat's nest 🐀, death march 💀 — choose your favorite metaphor!

---

# Can't we build on existing work? 😥

<!-- pt:incremental_lists: true -->

* There's BitTorrent, Git, libp2p, IPFS, SSB, Briar, Nostr, Signal, Tor...*Somebody* must have figured this stuff out! 
* Right?
* ...right?
* ... 

---

# Our experience with existing p2p tools has been meh 🫤

<!-- pt:incremental_lists: true -->

- They cover *some* of our needed stack
- But what they *do* cover is costly to adapt to product goals
- And *uncovered* areas sprout concurrency problems, heisenbugs

<span style="color: #fb4934">Result: easy features are super hard, hard features are out of reach.</span>

---

# Specific gripes with existing p2p tools 😡

<!-- pt:incremental_lists: true -->

- **Arbitrary dependency linkages** - these are the opposite of what you want: they block content when you *don't* need that and not when you do 
- **No iOS support** - especially for push & the iOS NSE memory limit 🐼
- **No multi-tenant/account support** - so you'll need to roll a lot of your own infra to support mobile devices and notifications 🐼
- **No simple API for frontends** - you must build a complex middle layer to cover all the queries your frontend 🐼

(**p2panda** is a lot better than others, but all gripes marked 🐼 apply to it too)

---

# Topo 🐭 is maybe a better way

Instead of providing lots of features for *parts* of the problem, it focuses on covering

<!-- pt:incremental_lists: true -->

- **All layers**: everything from networking to the local app API.
- **Most contexts**: everything from iOS notification fetching to multi-tenant servers. (Soon the web, too.)

...in a principled solution to the hard problem, **concurrency**.

---

#  Topo 🐭 makes backends simple

<!-- pt:incremental_lists: true -->

- No separate backend for iOS (uses SQLite to stay memory-bounded)
- No separate backend for cloud: one endpoint can host many tenants
- Dependencies can match product needs
- End-to-end testing is cheap and easy
- You get a flexible, concurrency-safe way to do encryption and auth

---

# Topo 🐭 makes frontends simple

<!-- pt:incremental_lists: true -->

- Projected SQLite tables give the data the shape it actually wants.
- The API can answer complex queries like "give me a paginated message list with usernames, reactions, attachments, and download progress".
- Optimistic UI just appends a local `client_op_id`; no need for a custom sync state machine.
- Frontends can poll or get subscription feeds of what changed.

---

# How Topo 🐭 manages concurrency

<!-- pt:incremental_lists: true -->

- **Data** including files, who to connect to, is represented as a set of events
- **State and auth** is derived deterministically from the event set (think: Redux but with dependencies)
- **Peer connection** is an ongoing behaviors determined by this set
- **Sync** is a process that ensures all peers converge on the same event set
- **Event pipeline** decrypts, validates, and writes events into SQLite tables that can queried however frontends need
- **Key material** is stored, sealed, and unsealed as events and, just like any other dependency, block dependents until it arrives.

---

# Runtime Loop

```text
CLI / RPC Control
   |\
   | +--> Local create/query ------> Projection / DB State
   |
   +--> Daemon startup --> Runtime supervisor --> Transport <--> Sync sessions
                                                         |
                                                         v
                                                   Event pipeline
                                                         |
                                                         v
                                                  Projection / DB State
                                                         |
                                                         +--> trust / tenant SQL --> Transport
```
---

# Result: easy stuff gets easy again. 

And hard stuff stays possible.

Next, a demo 🐭

<!-- Scraps

# TL;DR:

**Most p2p stacks** offer lots of features that aren't what you need; you're on your own in a hard battle with concurrency.

**Topo 🐭** covers the concurrency problem; features are up to you.


# An observation 💡

Given that:

<!-- pt:incremental_lists: true 

* data, auth, syncing, and peering must be tailored to product needs
* all p2p libraries (except perhaps libp2p) are at very early stages of maturity
* this stuff is hard

...Maybe p2p library features are ~useless?

Instead, maybe what you need is a **concurrency approach** covering the whole problem.

-->

---

<!-- _class: lead -->

# Appendix: Performance Benchmarks

AMD Ryzen AI MAX+ 395 (16c/32t) · 122 GiB RAM · SQLite WAL · Rust `--release`

---

# Core Sync Throughput

Peer-to-peer QUIC sync over localhost with negentropy reconciliation.

| Test | Events | Wall Time | Msgs/s | MiB/s | Peak RSS |
|------|-------:|----------:|-------:|------:|--------:|
| 10k bidirectional (5k each) | 10,000 | 1.02s | 9,783 | 11.14 | 134.8 MiB |
| 50k one-way | 50,000 | 6.73s | 7,431 | 8.46 | 230.4 MiB |
| 500k one-way | 500,000 | 116s | 4,300 | 4.90 | 488.5 MiB |
| 10k continuous inject | 10,000 | 3.60s | 2,775 | 3.16 | 176.3 MiB |

- 500k tail-phase slowdown gated by receiver-side SQLite insert rate
- Continuous inject: events injected in 100-event batches while sync is running

---

# Negentropy Frame Size Tuning

500k one-way sync — per-round reconciliation cost is super-linear in frame size.

| Frame Size | Rounds | Reconcile | Wall Time | Msgs/s | MiB/s |
|:----------:|-------:|----------:|----------:|-------:|------:|
| 64 KB | 245 | 295s | 303s | 1,648 | 1.88 |
| 128 KB | 123 | 152s | 162s | 3,087 | 3.52 |
| **256 KB** | **62** | **131s** | **141s** | **3,555** | **4.05** |
| 512 KB | 31 | 105s | 117s | 4,267 | 4.86 |
| 1 MB | 16 | 543s | killed | - | - |

- **256 KB** is the sweet spot; 1 MB is catastrophic (34s/round)

---

# File Attachment Throughput

Local encode + store + project for 256 KiB ciphertext slices (no sync).

| Size | Slices | Wall Time | MB/s | MiB/s | Slices/s |
|-----:|-------:|----------:|-----:|------:|---------:|
| 256 KiB | 1 | 0.003s | 83.7 | 79.8 | 335 |
| 10 MB | 40 | 0.057s | 175.1 | 167.0 | 701 |
| 100 MB | 400 | 0.531s | 188.4 | 179.7 | 754 |
| 1 GB | 4,096 | 5.167s | 198.2 | 189.0 | 793 |

- Throughput scales to ~200 MB/s; CPU-bound on encryption + SQLite writes

---

# Topo Cascade (Projector Stress)

Worst-case dependency cascade: each event depends on up to 10 prior events, inserted in reverse order to maximize block/unblock depth.

| Scale | Blocking | Cascade | Cascade Rate | Total | Peak RSS |
|------:|---------:|--------:|-------------:|------:|---------:|
| 10k | 2.22s | 1.44s | 6,930 ev/s | 3.73s | 59.2 MiB |
| 50k | 10.31s | 6.51s | 7,678 ev/s | 17.23s | 106.1 MiB |
| 500k | 91.16s | 69.78s | 7,165 ev/s | 165.60s | 399.6 MiB |

- Cascade rate ~7k ev/s across all scales (linear scaling)
- Memory grows sub-linearly: 50x events = ~7x RSS

---

# Sync Graph: 10-Hop Chain

Events injected at P0, propagate through P0 → P1 → ... → P9.

| Scale | Tail Converge | Events/s | MiB/s | Hop P50 | Hop P95 | Peak RSS |
|------:|--------------:|---------:|------:|--------:|--------:|---------:|
| 10k | 7,127 ms | 1,403 | 1.60 | 1,021 ms | 6,329 ms | 1,363 MiB |
| 50k | 3,668 ms | 13,631 | 15.52 | 2,929 ms | 7,777 ms | 1,755 MiB |

- 50k appears faster due to amortized fixed setup/connection costs
- Chain results show topology behavior (hop delay + memory), not raw throughput

---

# Sync Graph: Multi-Source Catchup

Sink-driven catchup from pre-seeded identical source datasets (100k events at sink).

| Sources | Wall | Events/s | MiB/s | Peak RSS |
|--------:|-----:|---------:|------:|---------:|
| 4 | 6,083 ms | 16,439 | 1.56 | 689 MiB |
| 8 | 9,604 ms | 10,412 | 0.99 | 1,370 MiB |

Large-file catchup (256 KiB slices per file):

| Case | Wall | Events/s | MB/s | Peak RSS |
|------|-----:|---------:|-----:|---------:|
| 4x400 slices | 416 ms | 962 | 240.5 | 1,111 MiB |
| 4x1024 slices | 630 ms | 1,625 | 406.6 | 1,111 MiB |
| 8x1024 slices | 833 ms | 1,229 | 307.5 | 1,363 MiB |

---

# Low-Memory: iOS NSE Target (24 MiB)

Constrained-runtime gate for iOS background push (24 MiB target, 22 MiB enforced via cgroup v2).

| Case | Synced | Peak KB | 24 MiB? | 22 MiB cgroup? |
|------|--------|--------:|:-------:|:--------------:|
| 500k+10k messages | all 10k msgs | 18,764 | PASS | PASS |
| 500k+100x1MiB files | all 400 slices | 14,088 | PASS | PASS |

- SQLite cache ~1 MiB, `temp_store=FILE`, `mmap_size=0`
- Ingest channel capacity reduced to 1000
- Peak RSS flat across baselines; memory shape dominated by `wanted` watermark + DB-backed `need_queue`

---

<!-- _class: lead -->

# Appendix: Code Walkthrough

Follow one message from CLI command to sync, projection, and query output.

---

# Walkthrough: Repo Layout

```text
src/runtime/control/      CLI entrypoint + daemon RPC
src/runtime/peering/      runtime worker graph
src/runtime/transport/    QUIC + trust boundary
src/runtime/sync_engine/  reconciliation + session loops
src/event_modules/        commands / projectors / queries
src/state/projection/     create + apply pipeline
tests/                    projector, sync, CLI/e2e checks
```

- Read order for this walkthrough: `runtime/control` -> `event_modules` -> `state/projection` -> `runtime/sync_engine`
- `docs/DESIGN_DIAGRAMS.md` mirrors the same boundaries at a higher level

---

# Walkthrough: Local Send Path

- `src/runtime/control/main.rs`: `topo send` turns into `RpcMethod::Send`
- `src/runtime/control/rpc/server.rs`: daemon dispatch calls `message::send_for_peer`
- `src/event_modules/message/commands.rs`: resolve signer/workspace/author, build `ParsedEvent::Message`
- `src/state/projection/create.rs`: encode, sign, store, and immediately project the event

```text
topo send "hello"
  -> rpc_require_daemon(...)
  -> RpcMethod::Send
  -> message::send_for_peer(...)
  -> create_signed_event_synchronous(...)
```

- The important design choice: local writes go through the same event + projection machinery as synced writes

---

# Walkthrough: Projection + Query Path

- `src/state/projection/apply/project_one.rs`: single canonical projection entrypoint
- `src/event_modules/registry.rs`: lookup parser, projector, share scope, and context loader by event type
- `src/event_modules/message/projector.rs`: pure projector writes `messages` or `deleted_messages`
- `src/event_modules/message/queries.rs`: join projected rows into the UI/RPC shape

```text
events blob
  -> parse via registry
  -> dependency + signer checks
  -> module projector
  -> valid_events + subscription hook
  -> query response with users / reactions / files
```

- This is where Topo gets its "SQLite is the app API" property: frontend-friendly reads come from projected tables, not ad hoc sync state

---

# Walkthrough: Runtime + Sync Path

- `src/runtime/peering/engine/supervisor.rs`: owns accept loop, target dispatcher, and shared ingest writer
- `src/runtime/transport/peering_boundary.rs`: transport boundary around QUIC sessions and trust checks
- `src/runtime/sync_engine/session/*`: reconciliation plus control/data streams
- Wire-received events land in the same ingest/projection pipeline used by local creates

```text
peer session
  -> sync control/data frames
  -> shared ingest channel
  -> batch_writer / project_queue
  -> project_one(...)
  -> SQLite rows visible to queries
```

- Best proof points to open alongside the code:
- `tests/projectors/message_projector_tests.rs`
- `tests/cli_test.rs`
- `tests/two_process_test.rs`
