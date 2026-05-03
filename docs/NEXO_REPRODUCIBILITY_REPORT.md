# NEXO Reproducibility Report

## Purpose

This document shows how to reproduce the central NEXO evidence path locally.
It is intended to help a reviewer run, inspect, and independently verify the current repository center.

## Reproducible Center

signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification

## Required Tools

- Rust/Cargo
- Zig
- Bash-compatible shell
- Julia only for observer/tests, not required for the central verification path unless running Julia tests

## What The Reproduction Should Demonstrate

A reviewer should be able to:

- run a signed decision flow
- inspect the emitted final_decision and trace
- locate the persisted audit artifact
- verify the artifact offline with Zig
- confirm the path is local and deterministic

## Primary Reproduction Path

```bash
bash scripts/demo_decision_flow.sh
```

This path should generate a decision, persist a temporary audit artifact, run Zig verification, and print exact follow-up inspection commands for that artifact.

## Flagged Scenario Reproduction

```bash
bash scripts/demo_decision_flow_flagged.sh
```

This path helps review a non-approved scenario and confirm that the same central artifact and verification flow still applies.

## Trace Tampering Demo (Audit Hash Mismatch)

```bash
bash scripts/demo_tampering_trace.sh
```

This demo proves two outcomes using the same central artifact format:

- the original audit artifact is accepted by the Zig verifier
- a tampered copy (same `audit_hash` / record fields, but an altered `trace`) is rejected as tampering

Expected verifier output includes:

- `verify: total=1 ok=1 schema_invalid=false tampering=false`
- `verify: total=1 ok=0 schema_invalid=false tampering=true`

Important limit: this demo demonstrates semantic `trace` tampering detection against `audit_hash`.
It must not be read as a claim of complete `record_hash` / `prev_record_hash` chain validation.

## Artifact Inspection

```bash
bash scripts/inspect_audit_artifact.sh
```

After temporary demo runs, the reviewer should use the exact inspection command printed by the demo for the temporary audit file, rather than assuming the default path.

## Historical Artifact Lookup

```bash
bash scripts/find_audit_artifact.sh <request_id-or-hash>
```

This searches by `request_id`, `audit_hash`, or `record_hash`.

## Offline Zig Verification

```bash
cd tools/zig
zig build run -- verify /path/to/audit_records.jsonl
```

Zig revalidates schema, trace semantics, final_decision consistency, and stored hash values.

## Expected Evidence Fields

- request_id
- final_decision
- trace
- audit_hash
- hash_algo
- prev_record_hash
- record_hash

## What Counts As Success

- demo completes without error
- audit artifact is produced
- final_decision and trace are visible
- Zig verifier accepts the artifact
- no unsupported global/AI/Bitcoin authority claim is needed

## What Counts As Failure

- demo fails before artifact creation
- artifact cannot be inspected
- Zig verifier rejects the artifact
- final_decision conflicts with trace semantics
- audit_hash or record_hash mismatch
- reviewer must trust runtime claims without artifact verification

## Non-Claims

- This does not prove global truth.
- This does not prove external real-world facts are true.
- This does not prove consensus.
- This does not prove Bitcoin mining/profitability/PoW/ASIC advantage.
- This does not make Julia, Ruby UI, Witness, mesh, or Bitcoin authoritative.

## Summary

NEXO becomes strongest when a reviewer can clone, run, inspect, and independently verify the decision evidence.
The core path is narrow enough to reproduce locally.
The artifact path is concrete enough to inspect directly.
The Zig verifier is independent enough to check the persisted result without trusting the runtime alone.
This is a reproducibility advantage, not a claim of global truth or broad platform authority.
