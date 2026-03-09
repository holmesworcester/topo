---
marp: true
theme: default
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

  .drawback {
    color: #fb4934;
    font-weight: 700;
  }

  .answer {
    color: #83a598;
    font-weight: 700;
  }

  .muted {
    color: #b8c0cc;
  }
---

<!-- _class: lead -->

# Introducing Topo 🐭  
## A proposal to make peer-to-peer apps practical & painless

(Or, at least, to provoke better ideas.)

---

# Why make p2p apps practical and painless? 🤔

- A FOSS p2p Slack would be awesome
- It would provide safety and resiliency to orgs we care about
- We've spent years building one (**tryquiet.org**)
- It has been a real slog; could it have been much easier?

---

# These questions haunt us 👻 

If there was a way all this slog could be much easier, and we aren't pursuing it, that would be really dumb. Or is the slog unavoidable?

---

# So what makes p2p so #$%@ing hard? 😡

- Big laundry list of problems to solve (p2p, e2ee, sync, files, push etc.)
- Solutions aren't generic; must fit product needs
- Concurrency is hard to reason through

---

# Can't we just build on existing work? 😥

* There's BitTorrent, Git, libp2p, IPFS, SSB, Briar, Nostr, Signal, Tor...*Somebody* must have figured this stuff out! 
* Right?
* ...right?
* ...

---

# Our experience with existing p2p tools  

- They cover *some* of our laundry list / stack
- But what they *do* cover is costly to adapt to product goals
- And *uncovered* areas sprout concurrency problems, heisenbugs

<span class="drawback">Result: easy features are super hard, hard features are out of reach.</span>

---

# Some concrete gripes with existing tools 😡

- Arbitrary dependencies (last sent/seen) block when you don't want to, not when you do
- Dependencies are often used for deciding what to fetch
- Nobody considers mobile push notifications (e.g. the iOS NSE memory limit)
- Multi-tenant cloud and multi-account clients are usually not covered by the model
- You must build a middle layer to cover all the queries your frontend needs want
- Identity and app state gets duplicated across layers

---

# An idea 💡

Given that:

* data, auth, syncing, and peering must be tailored to product needs
* all p2p libraries (except perhaps libp2p) are at very early stages of maturity
* this stuff is hard

...Maybe you don't *want* to trust some library?

Maybe what you need is more like **a plan for battling concurrency and... winning!** ⚔

---

# This is the Topo 🐭 philosophy 

Don't provide features covering *parts* of the problem.

Provide a **concurrency solution** across the *whole* problem.

Then devs can safely build the features *their users need* without getting devoured by the concurrency beast!

---

# Topo 🐭 covers the whole problem

- **All layers**: everything from networking to the local app API.
- **Most contexts**: everything from iOS notification fetching to multi-tenant servers. 

(The current POC omits the web context, but this is tractable too.)

---

# Topo 🐭 solves the hard (concurrency) parts

- Expressing all data (including files, who to connect to) as events
- Minimizing state duplication (one event set, one DB file)
- Connecting to and authenticating peers 
- Syncing all events (including files) efficiently
- Decrypting and validating them in the correct order
- Converging on the correct state
- Managing deletion
- Providing a useful API for frontends

It also provides a basic sketch for multi-device syncing and group key agreement 

--- 

# ...Then it lets devs build what their users want 🌈

- API will do whatever a modern frontend needs it to
- Sync is never blocked by missing events
- Events can block on prior events or not, as you wish
- Modify encryption, auth to match product needs 

---


#  Why backend dev is easier 

- SQLite-backed reconciliation stays memory-bounded for e.g. iOS NSE.
- One instance and one QUIC port can host many tenants, for cloud.
- Easy to define dependencies to match product needs
- Framework for reasoning about concurrency/causality makes advanced crypto, forward secrecy, TreeKEM-style designs easier to build.
* End-to-end testing is cheap and easy. 

---

# Why frontend dev is easier:

- Projected SQLite tables give the data the shape it actually wants.
- The API can answer complex queries like "give me a paginated message list with usernames, reactions, attachments, and download progress".
- Optimistic UI just append a local `client_op_id`; no need for a custom sync state machine.
- Frontends can poll or get subscription feeds of what changed.

<span class="answer">Easy stuff gets easy again. Hard stuff stays possible.</span>

---

# TL;DR:

**Most p2p stacks** offer lots of features that aren't what you need; you're your own in a hard battle with concurrency.

**Topo 🐭** covers the concurrency problem; features are up to you.
 