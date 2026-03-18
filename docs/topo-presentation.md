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

# Why is building useful p2p apps so hard?

<!-- pt:incremental_lists: true -->

- Many problems to solve: p2p, e2ee, sync, files, push etc.
- Solutions aren't generic; must fit product needs
- Concurrency is a minefield 💥, time bomb 💣, quagmire 🐊, rat's nest 🐀, death march 💀 — choose your favorite metaphor, it is *the* hard part!

---

# Can't we just use existing approaches? 😥

<!-- pt:incremental_lists: true -->

* There's BitTorrent, Git, libp2p, IPFS, SSB, Briar, Nostr, Signal, Tor...*Somebody* must have figured this stuff out! 
* Right?
* ...right?
* ... 

---

# Our experience with existing p2p tools: 🫤

<!-- pt:incremental_lists: true -->

- They cover *some* of our needed stack
- But what they *do* cover is costly to adapt to product goals
- And *uncovered* areas sprout concurrency problems, heisenbugs

<span style="color: #fb4934">Result: easy features are super hard, hard features are out of reach.</span>

---

# Specific gripes with existing p2p tools 😡

<!-- pt:incremental_lists: true -->

- **Arbitrary dependencies in data** - these are the opposite of what you want: they block content when you *don't* need that and not when you do 
- **No iOS support** - especially for push & the iOS NSE memory limit 🐼
- **No multi-tenant/account support** - so you'll need to roll a lot of your own infra to support mobile devices and notifications 🐼
- **No simple API for frontends** - you must build a complex middle layer to cover all the queries your frontend needs 🐼

(**p2panda** is a lot better than others, but all gripes marked 🐼 apply to it too)

---

# Topo 🐭 proposes a better way

Instead of providing lots of features for *parts* of the problem, it focuses on covering

<!-- pt:incremental_lists: true -->

- **All layers**: everything from networking to the local app API.
- **Most contexts**: everything from iOS notification fetching to multi-tenant servers. (Soon the web, too.)

...in a principled solution to the hard problem, **concurrency**.

---

#  Topo 🐭 makes your backend simpler

<!-- pt:incremental_lists: true -->

- Uses SQLite to stay memory-bounded so **no separate backend for iOS**
- One endpoint can host many tenants so **no separate infra for cloud** 
- SQLite contains all state including files; **no OS filesystem quirks**
- Dependencies can match product needs
- End-to-end testing is cheap and easy
- You get a flexible, concurrency-safe way to do encryption and auth

You have to model causal order as dependency graphs, but this is inevitable in a p2p world (unless you have a really fast blockchain?) so we embrace it!

---

# Topo 🐭 makes your frontend simpler

<!-- pt:incremental_lists: true -->

- Events turn into SQLite tables so **data can have whatever shape it wants**
- The API can answer complex queries like "give me a paginated message list with usernames, reactions, attachments, and download progress" so **you don't need a middle layer**
- A local `client_op_id` can return with eventually-updated events, so **you don't need a custom sync state machine for optimistic updates**
- Frontends can get subscription feeds of changes and poll for the latest state, so **frontend state management is easy.**

This makes P2P frontend development *easier* than centralized apps (less frontend state)

---

# Topo 🐭 tames concurrency

<!-- pt:incremental_lists: true -->

- **Data** including files, who to connect to, is represented as a set of events with dependencies
- **Peer connection** is ongoing behavior determined by this set
- **Sync** is a process that ensures all peers converge on the same event set
- **Event pipeline** decrypts, validates, and writes events into easily-queried tables
- **Topo sort** blocks action on events until their dependencies arrive
- **State and auth** is derived deterministically from the event set (think: Redux but with dependencies)
- **Secrets** are stored as events and block dependent encrypted events until known

This way, devs can think about dependency & converging sets, **not concurrency**.

---

# Runtime Loop

```text
CLI / RPC Control
  |\
  | +--> Local create/query --> Projection / DB
  |
  +--> Daemon --> Supervisor --> Transport <--> Sync
                                    |
                                    v
                              Event pipeline
                                    |
                                    v
                             Projection / DB
                                    |
                              trust/tenant SQL
                                    |
                                    v
                                Transport
```

---

# Result: easy stuff gets easy again. 

And hard stuff stays possible.

Next, a demo 🐭

---

# Demo

* Create, invite, message, react, attach a file
* Link a device
* Event and sync logs
* Multitenancy in action

**Won't demo:** subscriptions, holepunching, mDNS discovery, multi-source sync.



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

# Performance Benchmarks

(All scores are from a fast desktop: AMD Ryzen AI MAX+ 395 (16c/32t) · 122 GiB RAM · SQLite WAL · Rust `--release`)

---

# Event Sync Throughput

Peer-to-peer QUIC sync over localhost with negentropy reconciliation (daemon-based, warm start).

| Test | Events | Wall Time | Msgs/s | Peak VmHWM |
|------|-------:|----------:|-------:|-----------:|
| 10k bidirectional (5k each) | 10,000 | 2.37s | 4,211 | 70.4 MiB |
| 50k one-way | 50,000 | 16.13s | 3,100 | 131.2 MiB |
| 10k continuous inject | 10,000 | 1.85s | 5,412 | 66.6 MiB |


* *continuous inject* means events injected while sync is running
* Maybe not network-bound on a fast network and slow device, but fast enough

---

# Realistic Network Sync (2k bidirectional)

Same QUIC sync, but through a UDP traffic shaper modelling real-world link conditions (bandwidth cap, latency, jitter, packet loss).

| Profile | Bandwidth | RTT | Loss | Wall Time | Msgs/s | Peak VmHWM |
|---------|----------:|----:|-----:|----------:|-------:|-----------:|
| Cable | 35 Mbps | 24ms | 0.2% | 1.32s | 1,514 | 25.6 MiB |
| DSL | 3 Mbps | 44ms | 0.3% | 7.13s | 281 | 25.2 MiB |
| Mobile | 15 Mbps | 80ms | 0.8% | 7.03s | 285 | 24.3 MiB |
| Slow Mobile | 2 Mbps | 140ms | 1.5% | 20.47s | 98 | 26.5 MiB |
| Starlink | 15 Mbps | 70ms | 0.5% | 6.33s | 316 | 23.3 MiB |

- All profiles complete successfully, including degraded conditions (slow mobile: 2 Mbps, 140ms RTT, 1.5% loss)
- Memory stays flat ~24 MiB across all profiles — no protocol-driven memory blowup
- Throughput scales with link quality as expected; not artificially bottlenecked

---

# File Attachment Throughput

Local encode + store + project for 256 KiB ciphertext slices (no sync).

| Size | Slices | Wall Time | MB/s | Slices/s |
|-----:|-------:|----------:|-----:|---------:|
| 256 KiB | 1 | 0.001s | 185.6 | 742 |
| 10 MB | 40 | 0.049s | 206.0 | 824 |
| 100 MB | 400 | 0.489s | 204.6 | 818 |
| 1 GB | 4,096 | 4.995s | 205.0 | 820 |

- Seems network-bound, even on a slow device.
- Easy optimization: make slice sizes bigger for bigger files. 

---

# Topo-sort Cascade

What happens when each event depends on a max (10) prior events and they are processed in reverse order to maximize block/unblock workload?

| Scale | Blocking | Cascade | Cascade Rate | Total | Peak RSS |
|------:|---------:|--------:|-------------:|------:|---------:|
| 10k | 1.614s | 1.168s | 8,555 ev/s | 2.850s | 59.0 MiB |
| 50k | 10.633s | 6.786s | 7,366 ev/s | 17.797s | 106.0 MiB |
| 500k | 92.460s | 71.961s | 6,948 ev/s | 169.185s | 399.6 MiB |

- Cascade rate ~7-8.5k ev/s across all scales (linear scaling)
- Memory grows sub-linearly: 50x events = ~7x RSS

---

# Low-Memory Performance

iOS background fetch is under a 24Mb memory limit, so we have a `lowmem` mode and tests for that.
For these runs, `lowmem` uses a 256 KiB SQLite cache, `temp_store=FILE`, `mmap_size=0`, and a smaller ingest channel.

---

# Low-Memory Topo-sort Cascade (10k)

Same worst-case cascade as above, but with `lowmem` enabled.

| Scale | Blocking | Cascade | Cascade Rate | Total | Peak RSS |
|------:|---------:|--------:|-------------:|------:|---------:|
| 10k | 1.36s | 1.30s | 7,710 ev/s | 2.75s | 9.6 MiB |

- Same throughput as normal mode (~7-8k ev/s) — cascade is CPU-bound, not cache-bound
- Peak RSS 9.6 MiB — well under the 24 MiB iOS NSE budget

---

# Low-Memory Sync

Constrained-runtime gate for iOS background push: 24 MiB target, with the stricter 22 MiB check enforced via cgroup v2.
Per-daemon VmHWM is measured via the lowmem delta harness.

| Case | Synced | Peak KB | 24 MiB? | 22 MiB cgroup? |
|------|--------|--------:|:-------:|:--------------:|
| 50k+10k messages | all 10k msgs | 7,364 | PASS | PASS |
| 500k+10k messages | all 10k msgs | 17,768 | PASS | not run |
| 50k+20x1MiB files | all 80 slices | 7,016 | PASS | PASS |


- Memory increase varies with number of new events synced and (to a lesser extent) total number of events. 
- Files pass easily because the number of events is small
- Full sync of 100k+ events is not possible in background, but expecting background-fetched diffs to be <10k events seems reasonable.

---

<!-- _class: lead -->

# Code Walkthrough

---

# Repo Layout

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

# Local Send Path

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

# Projection + Query Path

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

# Runtime + Sync Path

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
