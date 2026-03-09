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
---

<!-- _class: lead -->

# Introducing Topo 🐭  
## A proposal to make peer-to-peer apps practical & painless

(Or, at least, to provoke better ideas.)

---

# Why make p2p apps practical and painless? 🤔

<!-- pt:incremental_lists: true -->

- A FOSS p2p Slack or Discord would be awesome
- It would provide safety and resiliency to orgs we care about
- We've spent years building one (**tryquiet.org**)
- It has been a real slog

---

# The question that haunts us 👻 

Could this slog be much easier, or not a slog at all? Or is p2p just really #$%@ing hard?

---

# What makes p2p so #$%@ing hard? 😡

<!-- pt:incremental_lists: true -->

- Big laundry list of problems to solve (p2p, e2ee, sync, files, push etc.)
- Solutions aren't generic; must fit product needs
- Concurrency is hard to reason through

---

# Can't we just build on existing work? 😥

<!-- pt:incremental_lists: true -->

* There's BitTorrent, Git, libp2p, IPFS, SSB, Briar, Nostr, Signal, Tor...*Somebody* must have figured this stuff out! 
* Right?
* ...right?
* ...
* 

---

# Our experience with existing p2p tools 🫤

<!-- pt:incremental_lists: true -->

- They cover *some* of our laundry list / stack
- But what they *do* cover is costly to adapt to product goals
- And *uncovered* areas sprout concurrency problems, heisenbugs

<span style="color: #fb4934">Result: easy features are super hard, hard features are out of reach.</span>

---

# Some concrete gripes with existing tools 😡

<!-- pt:incremental_lists: true -->

- Arbitrary dependencies block when you don't want to, not when you do
- Mobile push notifications (e.g. the iOS NSE memory limit) not considered
- Multi-tenant cloud and multi-account clients are usually not covered by the model
- You must build a middle layer to cover all the queries your frontend needs want
- Lots of state duplication (another concurrency problem)

---

# An observation 💡

Given that:

<!-- pt:incremental_lists: true -->

* data, auth, syncing, and peering must be tailored to product needs
* all p2p libraries (except perhaps libp2p) are at very early stages of maturity
* this stuff is hard

...Maybe p2p library features are ~useless?

Instead, maybe what you need is a **concurrency approach** covering the whole problem.

---

# This is Topo 🐭

Topo covers:

<!-- pt:incremental_lists: true -->

- **All layers**: everything from networking to the local app API.
- **Most contexts**: everything from iOS notification fetching to multi-tenant servers. (Soon the web, too.)

---

# How Topo 🐭 manages concurrency

<!-- pt:incremental_lists: true -->

- All data (including files, who to connect to) is events
- All state derived from the set of events
- Minimal state duplication (one event set, one DB file)
- Peer connection is an ongoig process controlled by the event set.
- Event set controls auth too
- Events sync efficiently, get decrypted, validated, and turned into SQLite rows.
- These can be queried in complex ways.
- Keys are stored as events and work just like any other dependency, blocking decryption until they arrive.

---

#  How Topo 🐭 makes backends simpler 

<!-- pt:incremental_lists: true -->

- No separate backend for iOS (uses SQLite to stay memory-bounded)
- No separate backend for cloud: one endpoint can host many tenants
- Dependencies can match product needs
* End-to-end testing is cheap and easy
* Gives you a flexible, concurrency-safe way to do encryption and auth

---

# How Topo 🐭 makes frontends simpler

<!-- pt:incremental_lists: true -->

- Projected SQLite tables give the data the shape it actually wants.
- The API can answer complex queries like "give me a paginated message list with usernames, reactions, attachments, and download progress".
- Optimistic UI just append a local `client_op_id`; no need for a custom sync state machine.
- Frontends can poll or get subscription feeds of what changed.

---

# Result: easy stuff gets easy again. 

And hard stuff stays possible.

Now, the demo 🐭

<!-- Scraps

# TL;DR:

**Most p2p stacks** offer lots of features that aren't what you need; you're your own in a hard battle with concurrency.

**Topo 🐭** covers the concurrency problem; features are up to you.
 
-->
