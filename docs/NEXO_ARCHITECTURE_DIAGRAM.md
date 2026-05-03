# NEXO Architecture Diagram

## Purpose

This document is a short, visual map of NEXO as a **union of parts with role-bounded responsibilities**.
It is centered on the repository’s confirmed, verifiable backbone and shows how supporting surfaces relate to it.

## High-Level Architecture

```mermaid
flowchart LR
  %% Verified backbone (center)
  Client[Client / operator tooling] -->|signed request| API[API intake (/evaluate)]
  API -->|fail-closed checks| Sec[Auth + replay + timestamp + rate-limit]
  Sec --> Engine[Deterministic evaluate (Rust trust core)]
  Engine --> Decision[final_decision + ordered trace]
  Decision --> Store[AuditStore append (JSONL)]
  Store --> Artifact[audit artifact (JSONL)]
  Artifact -->|offline verification| Zig[Zig verifier (nexo-audit)]

  %% Role-bounded surfaces (supporting)
  Ruby[Ruby UI (operator surface)] -->|reads response + state| API
  Julia[Julia observer (secondary, non-authoritative)] -->|reads /api/state and summaries| API

  Docs[Docs / Evidence Pack\n(scope + reproducible review)] -.-> Reviewer[Reviewer / operator]
  Reviewer -.-> Ruby
  Reviewer -.-> Artifact
  Reviewer -.-> Zig

  %% Experimental / research tracks (not the product center)
  subgraph Experimental["Research / experimental tracks (not the current product center)"]
    Mesh[mesh / P2P / relay]
    Witness[Witness Layer]
    Bitcoin[Bitcoin logistics experiment]
  end
  Experimental -.-> Docs
```

## Verified Backbone

The current verified backbone is:

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification`

This backbone organizes the system: it makes the core decision evidence reproducible and independently checkable.
It does not make other parts irrelevant; it makes their roles and trust boundaries legible.

## Role-Bounded Surfaces

- **Rust (trust core):** validates signed input fail-closed, evaluates deterministic rules, emits `final_decision` + ordered `trace`, persists audit artifacts.
- **Zig (offline verifier):** independently verifies persisted artifacts offline (schema + trace/decision/hash contract checks).
- **Ruby (operator surface):** presents the core evidence path for a human (core-first, edges-visible).
- **Julia (observer):** reads and summarizes without authority; it does not decide or redefine the product center.
- **Docs / Evidence Pack:** protects scope and makes review reproducible; it is part of how NEXO stays honest over time.
- **Experimental tracks:** Bitcoin, mesh/P2P, and Witness work can be important, but they are bounded as research/experimental tracks unless explicitly promoted by contract.

## What The Diagram Does Not Claim

This diagram does not claim that NEXO is:

- a global truth system, a consensus protocol, or a blockchain
- a CRDT runtime or a full sync runtime
- an AI judge
- a Bitcoin mining/profitability/PoW shortcut/ASIC-competitiveness system
- a universal compliance platform

It also must not be read as a promise of complete offline validation of `record_hash` / `prev_record_hash` chain semantics (not asserted here).
Secondary surfaces (Ruby UI, Julia observer, Witness/mesh/Bitcoin tracks) must not be treated as authorities over the core Rust decision evidence.

