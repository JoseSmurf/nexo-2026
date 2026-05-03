# NEXO Executive Summary

## What NEXO Is

NEXO is a deterministic, local-first decision and audit system for security-sensitive financial and operational decision workflows.
Its core value is turning sensitive decisions into **reproducible, inspectable, independently verifiable evidence**.

NEXO is a union of parts with deliberately separated roles:

- **Rust (trust core):** validates signed input fail-closed, evaluates deterministic rules, and produces decision evidence.
- **Zig (offline verifier):** independently verifies persisted evidence offline without trusting the Rust runtime process.
- **Ruby UI (operator surface):** presents the core evidence path for human review (core-first, edges-visible).
- **Julia (observer/analysis):** reads and summarizes; it is **secondary and non-authoritative**.
- **Docs / Evidence Pack:** protects scope and makes review reproducible.

## Problem

Many security and compliance systems fail under pressure because decisions drift across environments, logs are hard to trust, or post-hoc narratives replace evidence.
NEXO narrows the problem: it focuses on making **the decision path** and **its evidence** stable, reviewable, and verifiable offline.

## System Shape

NEXO intentionally centers on one verifiable backbone:

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification`

This verifiable backbone organizes the system and keeps roles legible.
It does not make Ruby, Julia, Zig, docs, Witness, mesh, or Bitcoin irrelevant; each adds value when its role is bounded by explicit contract.

## Current Verified Path

At a high level:

1. A client sends a **signed request** with request context (request id, timestamp, signature).
2. The API performs **fail-closed security checks** (auth, replay, timestamp window, rate limiting).
3. Rust runs a **deterministic evaluate** and emits:
   - `final_decision` (Approved / Flagged / Blocked)
   - ordered `trace` (how the decision was reached)
   - `audit_hash` + `hash_algo` (semantic hash over the trace contract)
4. Rust persists an **audit artifact** (JSONL) containing the decision evidence.
5. Zig performs **offline verification** of the artifact (schema + trace/decision/hash contract checks).

## What Is Proven Today

Based on the repository’s Evidence Pack and the runnable demos:

- **Reproducible decision evidence:** the same valid input/profile yields stable `final_decision` and trace semantics.
- **Offline verification:** Zig can verify a persisted artifact without trusting the runtime process.
- **Semantic tampering detection (trace vs `audit_hash`):** a valid artifact is accepted, while a copy with an altered `trace` but unchanged `audit_hash` is rejected as tampering (`bash scripts/demo_tampering_trace.sh`).
- **Role-bounded surfaces:** Ruby UI presents the operator view of the core evidence; Julia observes and summarizes. Experimental tracks remain bounded and do not override the verifiable center.

## What NEXO Does Not Claim

NEXO does not claim:

- global truth, consensus, or a CRDT/runtime sync system
- AI-based judgment or “intelligence” as the trust source
- Bitcoin mining, profitability, PoW shortcuts, or ASIC competitiveness
- that external real-world facts are true (it verifies artifacts and contracts, not reality)
- complete validation of `record_hash` / `prev_record_hash` chain semantics by the offline Zig verifier (not asserted here)

Bitcoin, mesh/P2P, and Witness Layer work remain **experimental/research tracks** and must not be confused with the current product center.

## How To Review Quickly

1. Read the evidence pack (reading map + contracts):
   - `AGENTS.md`
   - `README.md`
   - `docs/NEXO_REVIEWER_START_HERE.md`
   - `docs/NEXO_ARCHITECTURE_EVIDENCE.md`
   - `docs/NEXO_THREAT_MODEL.md`
   - `docs/NEXO_REPRODUCIBILITY_REPORT.md`
   - `docs/NEXO_TEST_MATRIX.md`
2. Run the reproducible core demo:
   - `bash scripts/demo_decision_flow.sh`
3. Run the tampering proof:
   - `bash scripts/demo_tampering_trace.sh`
4. If you are reviewing validation surfaces, run the test/check commands listed in `docs/NEXO_TEST_MATRIX.md`.

## Current Status

NEXO is strongest today when treated as a narrow, verifiable evidence system:
Rust decides deterministically, Zig verifies offline, Ruby presents the core evidence to an operator, and Julia remains an observer.
The repository includes a reviewer-oriented Evidence Pack and reproducible scripts that demonstrate acceptance and tampering rejection of audit artifacts.
