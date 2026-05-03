# NEXO Architecture Evidence

## Purpose

This document records the architectural evidence for the current center of NEXO.
It is intended to help reviewers inspect what the repository actually proves about its main decision and audit path.

## Architecture Center

signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification

## What Each Layer Does

- signed request
  - A client sends a request with signed headers and request context.
- API security checks
  - The API validates HMAC, request id shape, timestamp window, replay constraints, and optional edge or client attestation fail-closed.
- deterministic Rust evaluate
  - Rust applies explicit rules in fixed order and computes the same semantic result for the same valid input.
- final_decision
  - Rust emits the final local decision outcome: approved, flagged, or blocked.
- trace
  - Rust emits the ordered decision trace that explains how the decision was reached.
- audit artifact
  - Rust persists a JSONL audit record with decision evidence and chain fields.
- audit hash / record hash
  - Rust computes a semantic `audit_hash` from the trace and a chained `record_hash` from the persisted record.
- offline Zig verification
  - Zig independently re-checks schema, trace semantics, final decision consistency, and stored hash values.

## Trust Boundaries

- Rust decides.
- Zig verifies offline.
- Ruby presents.
- Julia observes.
- experimental tracks do not redefine the center.

## Evidence Produced

The central flow produces and persists evidence including:

- `request_id`
- `final_decision`
- `trace`
- `audit_hash`
- `hash_algo`
- `prev_record_hash`
- `record_hash`

## What This Proves

- a decision can be reproduced semantically
- the trace/hash contract can be checked
- persisted artifacts can be independently verified
- tampering should be detectable through hash/verifier checks

## What This Does Not Prove

- not global truth
- not consensus
- not a CRDT runtime
- not Bitcoin mining/profitability/PoW/ASIC claim
- not AI-based judgment
- not proof that external real-world facts are true

## Reviewer Path

- read docs
  - `AGENTS.md`
  - `README.md`
  - `docs/NEXO_REVIEWER_START_HERE.md`
  - `docs/OPERATIONAL_FLOW.md`
  - `docs/SECURITY_OPERATIONS.md`
- inspect Rust evaluate
  - `src/engine/evaluate.rs`
- inspect audit hash/record
  - `src/audit/hash.rs`
  - `src/audit/record.rs`
  - `src/audit_store.rs`
- inspect API auth
  - `src/api.rs`
  - `src/api/auth.rs`
- inspect Zig verifier
  - `tools/zig/src/verify.zig`
- run demo / inspect artifact / verify offline
  - `scripts/demo_decision_flow.sh`
  - `scripts/inspect_audit_artifact.sh`
  - `scripts/find_audit_artifact.sh`
  - `cd tools/zig && zig build run -- verify /path/to/audit_records.jsonl`

## Protected Contracts

- final_decision semantics
- trace ordering
- audit hash framing
- audit record schema
- record chain semantics
- HMAC/replay fail-closed behavior
- Zig verifier expectations

## Summary

NEXO is strongest when its central path stays narrow, explicit, and testable.
Rust makes the deterministic decision and emits the evidence.
The trace and hash contracts make that evidence inspectable.
The persisted audit record and record chain make it retainable.
The Zig verifier makes it independently checkable.
This is a local evidence architecture, not a global truth system.
Its core value is not broad intelligence but reproducible, inspectable, independently verifiable decision evidence.
