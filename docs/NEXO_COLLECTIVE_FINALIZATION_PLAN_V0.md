# NEXO Collective Finalization Plan V0

## Status and intent

This document records the current collective finalization plan for NEXO.

It is intentionally conservative.

It does **not** redefine NEXO as a finished distributed platform.
It does **not** promote mesh/P2P, Witness Layer, or the experimental `decision_cycle` path to the center of the product before their contracts are mature enough.

Its purpose is smaller and stricter:

- define the current product center;
- define the surrounding layers that must remain alive;
- define what can mature in parallel without taking the center;
- define objective gates for later promotion;
- define what "NEXO ready V0" means without overclaim.

The working formulation is:

> **closed center, live edges, gradual promotion by semantic merit.**

## 1. Current product center

The current center of NEXO is the deterministic decision path:

- signed `POST /evaluate`
- deterministic Rust evaluation
- `final_decision`
- ordered `trace`
- persisted audit trail
- offline Zig verification

This is the narrowest path that already forms one complete, reviewable, operator-relevant flow.

It should be closed first because it already has:

- a canonical request/response contract;
- deterministic runtime behavior;
- reproducible audit artifacts;
- independent offline verification;
- a release posture that can be explained publicly without inflating semantics.

## 2. System layers

### Layer A — Product center

The primary operator surface:

- evaluate
- final decision
- trace
- audit metadata
- offline verification path

This is the only layer that should define the V0 interface center.

### Layer B — Secondary semantic surfaces

Read-only layers that enrich the system but do not define its center yet:

- Witness Layer
- comparability
- freshness
- actionability
- local diagnostics and truth-surface projections

These are valuable and real, but should remain secondary until their operator-facing surface is simpler and more stable.

### Layer C — Independent observation and verification

Support layers that keep the system legible and auditable:

- Julia as observer/analyst
- Zig as independent offline verifier

These layers must remain clearly subordinate to the Rust trust core.

### Layer D — Silent operational infrastructure

Real infrastructure that supports future evolution, but should not be promoted to the center yet:

- mesh/P2P
- relay bridge
- local persistence and transport plumbing

This layer stays useful even when it is not the primary product surface.

### Layer E — Experimental tracks

Laboratory paths that test future logic without becoming product claims:

- `decision_cycle` V0
- evidence-guided logistics and economics harnesses

These tracks must stay canonical and maintained, but must remain explicitly experimental until they pass stronger gates.

## 3. What must mature in parallel without taking the center

The following parts must not become orphaned while the center is being finalized:

### Witness Layer and diagnostics

They should continue to mature as read-only semantic surfaces, especially around:

- proof / non-proof wording;
- comparability;
- freshness;
- actionability;
- operator-safe language.

### Julia

Julia should continue maturing as the observation and analysis layer:

- readable summaries;
- conservative interpretation;
- compact operator artifacts;
- no runtime authority.

### Zig

Zig should continue as independent verification:

- audit artifact integrity;
- semantic recomputation where contracts are already stable;
- no expansion into sync/runtime authority without explicit need.

### mesh/P2P

mesh/P2P should continue hardening as infrastructure:

- contract clarity;
- replay/dedup/ordering boundaries;
- relay passivity;
- local-first operational limits.

It must not be abandoned, but it also must not be promoted prematurely.

### `decision_cycle`

The experimental V0 path should continue as:

- canonical experiment artifact;
- policy comparison harness;
- laboratory for Evidence-Guided Work;
- explicitly non-authoritative surface.

## 4. What remains experimental or silent

The following should remain non-central in V0:

- mesh/P2P as a primary product claim;
- witnesses as the main UI narrative;
- `decision_cycle` as a product surface;
- anything implying sync runtime, convergence authority, or global truth.

The following should remain mostly silent infrastructure unless a later phase explicitly promotes them:

- relay details;
- transport internals;
- experimental economics harnesses;
- broad distributed topology language.

## 5. Promotion gates for secondary parts

A secondary part should only move closer to the main experience when at least these conditions hold.

### Witness Layer promotion gates

- stable operator-facing terminology;
- clear proof / non-proof contract;
- no hidden runtime authority;
- actual operator value without requiring repository-level knowledge.

### `decision_cycle` promotion gates

- stable schema and stable decision taxonomy;
- repeatable experimental usefulness;
- explicit separation from runtime authority;
- value beyond internal experimentation.

### mesh/P2P promotion gates

- stronger node/sync contract clarity;
- stronger restore/replay/pull semantics;
- operator-facing use case that does not depend on overclaim;
- no need to imply consensus, global truth, or full sync runtime.

### Zig promotion gates

- stable artifact worth verifying independently;
- clear gain from second implementation;
- no duplication of Julia or Rust roles.

## 6. What NEXO ready V0 means in this collective view

NEXO ready V0 does **not** mean "the whole platform is finished".

It means a narrower and more honest condition:

- there is one clear primary operator surface;
- the operator can use the central flow without reading the entire repository;
- the system can show what it proves and what it does not prove;
- the audit path is reproducible and independently verifiable;
- secondary parts remain live and correctly positioned.

In practical terms, ready V0 means:

- the deterministic decision path is the product center;
- witnesses/diagnostics are available as secondary read-only surfaces when appropriate;
- Julia supports observation and interpretation;
- Zig supports independent offline verification;
- mesh/P2P and experiments remain available but non-central.

## 7. What is explicitly outside V0

The following are outside V0 and must remain outside V0 claims:

- consensus;
- global truth;
- CRDT runtime;
- full sync runtime;
- broad distributed-platform positioning;
- treating relay or received artifacts as semantic authority;
- treating `decision_cycle` as product authority.

## 8. Collective finalization phases

### Phase 1 — Close the center

Finish the narrow product center:

- evaluate flow
- final decision
- trace
- audit trail
- Zig verification path
- operator-facing V0 interface
- explicit non-claims

### Phase 2 — Keep the edges alive

While the center is closing, continue to harden and clarify:

- Witness Layer wording and diagnostics;
- Julia observation artifacts;
- mesh/P2P contracts and silent operational quality;
- `decision_cycle` as an experimental harness.

These parts do not move to the center yet, but they remain live, coherent, and ready for future promotion.

### Phase 3 — Promote by semantic merit

Allow a secondary part to gain more visibility only when:

- its contract is stable;
- its non-claims are explicit;
- its operator value is real;
- its semantics do not inflate the system.

### Phase 4 — Expand carefully

After V0 is stable, broaden the system gradually:

- deeper witness/operator views;
- stronger Julia-assisted observability;
- carefully introduced mesh/P2P use cases;
- selective experimental graduation where deserved.

## 9. Role of the operator

The operator remains central in V0.

NEXO still depends on:

- local evidence;
- conservative diagnosis;
- explicit contract before action.

So the system must continue to assume a human operator or explicitly contracted runtime behavior, not hidden autonomy.

## 10. Finalization rule of thumb

When deciding whether a part belongs in the center, ask:

1. Is the contract already stable?
2. Can the operator understand it without reading the whole repository?
3. Can the interface show what it proves and what it does not prove?
4. Does it stay useful without inflated semantics?
5. Is it ready to be seen, not just interesting to developers?

If the answer is no, the part should remain secondary, silent, or experimental for now.

---

Short version:

- close the deterministic audit path first;
- keep the other layers alive and maturing;
- promote nothing by enthusiasm alone;
- let semantic merit decide what rises next.
