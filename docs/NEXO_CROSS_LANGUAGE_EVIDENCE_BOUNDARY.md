# NEXO Cross-Language Evidence Boundary

## Purpose

This document defines a **canonical evidence boundary contract** across NEXO surfaces.
It is reviewer-facing: it explains what each language/surface may treat as authoritative, and what it must not reinterpret as authority.

Verified core path:

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> record chain -> offline Zig verification`

## Rust: What Is Authoritative

Rust is the trust core. It is authoritative for:

- deterministic evaluation rules for valid input
- `final_decision` semantics (`Approved` / `Flagged` / `Blocked`)
- ordered trace semantics (stable ordering is part of the evidence contract)
- audit artifact generation and persistence (JSONL)
- `audit_hash` derivation from semantic trace framing
- `record_hash` derivation from `audit_record_v2` framing
- `prev_record_hash` semantics in the persisted record chain
- fail-closed append behavior when extending an existing persisted audit log

Rust is the only place where **the decision is made**.

## Zig: What Is Authoritative

Zig is an independent offline verifier. It is authoritative for:

- offline verification of a persisted artifact, without trusting the Rust runtime process
- checking schema validity and the trace/hash/decision consistency contract
- detecting semantic tampering against `audit_hash`
- validating `record_hash` when present (integrity of persisted record fields)
- validating in-file chain continuity when `--require-chain` is enabled
- reporting verifier outcomes as:
  - `schema_invalid`: the artifact does not match the expected contract
  - `tampering`: the artifact claims hashes that do not match recomputation

Zig does not decide; it verifies evidence produced by Rust.

## Ruby: What Is Allowed

Ruby is an operator/reviewer presentation surface. Ruby may:

- present artifacts produced by Rust and verified by Zig
- display verifier status and `schema_invalid` / `tampering` outcomes clearly
- display operator-facing warnings and fail-closed states

Ruby must not:

- recompute `final_decision` as a source of truth
- reinterpret verifier failure as “still acceptable”
- override or normalize away `schema_invalid` / `tampering`

## Julia: What Is Allowed

Julia is an observer/analysis surface. Julia may:

- read verified artifacts (or verified summaries) and compute metrics
- generate charts, reports, and anomaly signals
- flag patterns for human review

Julia must not:

- decide or override Rust `final_decision`
- treat observations as authority over Rust+artifact+Zig
- rewrite evidence semantics (ordering, hashing, or decision meaning)

## Mesh/P2P/Witness: What Is Allowed

Mesh/P2P and Witness layers are **transport and continuity surfaces**. They may:

- transport, mirror, witness, or replicate artifacts and supporting metadata
- preserve evidence and enable reviewers/operators to obtain it

They must not:

- transform invalid evidence into valid evidence
- act as stronger authority than **Rust decision + persisted artifact + Zig verification**
- “fix up” artifacts after verification (mutation after verification is not evidence)

## Bitcoin Logistics (Experimental): What Is Allowed

Bitcoin logistics, if used later, is an experimental/research track. It may:

- provide experimental anchoring or external continuity references
- help compare “what was seen when” across operators, environments, or exports

It must not:

- prove decision correctness
- replace local artifact verification
- be presented as profitability, a consensus shortcut, a PoW shortcut, or an ASIC advantage

## Forbidden Interpretations

Future layers must not:

- recompute `final_decision` as a source of truth
- alter trace ordering or trace semantics
- explain away verifier failure
- accept unverified artifacts as valid
- treat unsafe deserialization, heuristics, or “best effort parsing” as authority
- mutate artifacts after verification and still present them as verified evidence
- treat Mesh/P2P/Witness/Bitcoin as stronger than Rust+artifact+Zig
- present observation (Ruby/Julia) as decision authority

## Safe Synchronization Model

The intended safe model for integrations is:

- Rust generates canonical decision evidence and persists canonical artifacts.
- Zig verifies canonical artifacts offline (and can optionally require chain continuity).
- Ruby displays verified evidence and verifier outcomes.
- Julia analyzes verified evidence without authority.
- Mesh/P2P/Witness may transport or mirror evidence, but never upgrade its authority.
- Bitcoin logistics may only anchor or experiment externally; it does not replace local verification.
- Verification failure remains failure everywhere.

