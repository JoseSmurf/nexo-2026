# NEXO Comparison and Positioning

## Purpose

This document positions NEXO relative to adjacent system ideas without hype or overclaim.
It is meant to help reviewers and operators understand what NEXO is trying to be (and not be) based on the current repository center.

## Positioning In One Sentence

NEXO is a local-first system that turns signed requests into deterministic decision evidence that can be inspected and independently verified offline.

## What NEXO Is Similar To

NEXO is adjacent to multiple well-known categories:

- deterministic rule engines and policy evaluation
- policy-as-code (OPA-style evaluation), at the level of “explicit rules produce explicit outcomes”
- audit logging and forensic recordkeeping
- append-only evidence and hash-based integrity framing
- HMAC request signing, replay protection, and fail-closed API intake
- observability systems (in the limited sense of producing operator-readable evidence)
- compliance tooling (in the limited sense of producing reviewable decisions and trails)

## Where NEXO Is Different

NEXO’s current differentiator is the *combination* of a narrow, reproducible center:

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification`

And the separation of roles:

- Rust decides deterministically (trust core).
- Zig verifies offline independently (verifier boundary).
- Ruby presents operator evidence (operator surface).
- Julia observes/analyzes without authority (observer surface).
- Docs protect scope and reviewability (review surface).
- Bitcoin, mesh/P2P, and Witness work are research/experimental tracks (not the current product promise).

## Category Comparison

| Category | Similarity | Difference | NEXO Boundary |
| --- | --- | --- | --- |
| Deterministic rule engines | Explicit rules in fixed order yield explicit outcomes. | NEXO couples rules with trace semantics, persisted artifacts, and offline verification. | Not a universal rule engine platform; center is the verified evidence path. |
| Policy-as-code | Shares the idea of policy evaluation producing an allow/deny-style outcome. | NEXO emphasizes trace evidence and offline verification of persisted artifacts as a first-class reviewer surface. | Does not claim to replace OPA-style systems; positioning is “adjacent, not substitute”. |
| Audit logs | Produces audit records intended for later inspection. | NEXO treats audit artifacts as a verifiable evidence contract (trace + hash framing + offline verifier). | Not a general logging pipeline or SIEM replacement. |
| Append-only / Merkle-style evidence | Uses hash framing and chained fields as integrity/continuity evidence; offline verification is demonstrated primarily for schema/trace/decision/hash checks and semantic tampering vs `audit_hash` (not complete `record_hash` / `prev_record_hash` validation). | NEXO’s most concrete verifier today is focused on trace semantics vs `audit_hash` and schema/consistency checks. | Do not assume complete offline validation of `record_hash` / `prev_record_hash` chain semantics (not asserted here). |
| HMAC signing / replay protection | Uses signed requests, timestamps, and replay controls. | NEXO’s security boundary is explicitly fail-closed to protect deterministic evidence production. | Not a general auth product; scoped to protecting the central decision path. |
| SIEM / observability | Provides operator-visible evidence and summaries. | NEXO’s center is decision evidence verification, not large-scale telemetry aggregation. | Not a SIEM; observers (Julia/UI) are secondary and non-authoritative. |
| Blockchain / consensus | Shares “tamper visibility” goals in some integrity framing. | NEXO is local-first and does not aim for global consensus or global truth. | Not a blockchain, not consensus, not CRDT runtime, not a sync runtime. |
| AI decision systems | Can be used in environments where “AI decisions” are discussed. | NEXO’s trust center is deterministic rules + verifiable artifacts, not AI judgment. | Not an AI judge; no claim that AI outputs are authoritative. |
| Financial compliance tooling | Produces decisions and review trails aligned with compliance workflows. | NEXO emphasizes reproducibility and independent verification over “feature completeness”. | Not a universal compliance platform; scope is intentionally narrow and evidence-driven. |

## What NEXO Should Not Be Compared As

NEXO should not be framed as:

- a blockchain
- a consensus protocol
- a global truth system
- a CRDT runtime or full sync runtime
- an AI judge
- a Bitcoin mining system (profitability, PoW shortcuts, ASIC competitiveness)
- a universal compliance platform
- a replacement for existing policy engines, SIEMs, audit logging stacks, or compliance tooling

## Current Honest Claim

NEXO currently demonstrates deterministic decision evidence, persisted audit artifacts, offline Zig verification, and semantic trace tampering detection against `audit_hash`.
