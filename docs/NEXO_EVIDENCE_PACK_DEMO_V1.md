# NEXO Evidence Pack Demo v1

## Status and Scope

This document records the Evidence Pack Demo v1 guide for NEXO Core.
It consolidates existing demo, artifact inspection, lookup, Zig verification, trace tamper, and record-chain verification workflows.

It does not change scripts, runtime behavior, tests, CI, fixtures, or verifier semantics.

Related documents:

- [Core Validation Gate v1](NEXO_CORE_VALIDATION_GATE_V1.md)
- [Audit Contract Baseline v1](NEXO_AUDIT_CONTRACT_BASELINE_V1.md)
- [Policy/Profile Provenance Contract v1](NEXO_POLICY_PROFILE_PROVENANCE_CONTRACT_V1.md)
- [Reproducibility Report](NEXO_REPRODUCIBILITY_REPORT.md)
- [Operational Flow](OPERATIONAL_FLOW.md)
- [Production Hostile Baseline v1](NEXO_PRODUCTION_HOSTILE_BASELINE_V1.md)

## What Evidence Pack Demo v1 Means

Evidence Pack Demo v1 is a reviewer demo guide, not a production deployment guide.

It demonstrates a local evidence story using existing scripts.
It does not replace CI, hostile-baseline validation, incident runbooks, or production operations.
It shows how evidence is produced, inspected, verified, and tamper-tested.

## Center Path

The current product center is:

```text
signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> record chain -> offline Zig verification
```

## Trust Boundaries

- Rust decides and writes the primary audit artifact.
- Zig verifies persisted artifacts offline.
- Ruby presents.
- Julia observes.
- Mesh/P2P/Witness/Bitcoin are live edges or experiments, not authority.
- Future IA may observe or analyze, but must not decide under this demo.

## Required Local Tools / Assumptions

The current demo path assumes:

- Rust/Cargo are installed.
- Zig is installed and usable from the shell.
- Bash-compatible shell is available.
- `curl` is available.
- `python3` is available for tamper/chain demos.
- Ruby is available for `find_audit_artifact.sh`.
- The default demo API URL `http://127.0.0.1:3000` is free, or `API_URL` is set explicitly.

Demo artifacts are written to temporary paths.
Copy them before closing the terminal if they must be preserved as review evidence.

## Evidence Pack Overview

The demo story is:

1. signed local `/evaluate` request
2. deterministic Rust decision
3. persisted JSONL audit artifact
4. visible `audit_hash`, `record_hash`, and `prev_record_hash`
5. offline Zig verification
6. trace tamper detection
7. record-chain verification
8. explicit claims and non-claims

## Quick Path (5 Commands)

Prerequisites:

- Install `bash`, `rust/cargo`, and `zig` locally, and run from the repository root on a clean clone.
- Use a local environment with free loopback ports and permission to create temporary files under `/tmp` (or system temp dir).

1. Run signed decision demo:

```bash
bash scripts/demo_decision_flow.sh
```

Success criterion: script exits `0`, prints locations for generated outputs (response JSON, audit JSONL, and run/log artifacts), and produces at least one new audit artifact path to inspect.

2. Inspect the generated audit artifact:

```bash
bash scripts/inspect_audit_artifact.sh <artifact.jsonl>
```

Success criterion: output shows parseable record details including `request_id`, `final_decision`, `audit_hash`, `hash_algo`, `profile_name`, `profile_version`, and chain fields (`record_hash`, `prev_record_hash` when present).

3. Verify artifact offline with Zig (base verification):

```bash
cd tools/zig && zig build run -- verify <artifact.jsonl>
```

Success criterion: verifier exits `0` and reports successful integrity/consistency validation for the artifact.

4. Demonstrate trace tamper detection:

```bash
bash scripts/demo_tampering_trace.sh
```

Success criterion: original generated artifact passes verification, tampered copy fails verification, and script exits `0` only if this pass/fail behavior is observed.

5. Verify chain mode (require-chain):

```bash
cd tools/zig && zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl
```

Success criterion: verifier exits `0` in chain-required mode for the fixture chain artifact.

Evidence pack to save:

- Response JSON produced by `demo_decision_flow.sh`.
- Generated audit artifact JSONL (`<artifact.jsonl>` used in steps 2 and 3).
- Output from `inspect_audit_artifact.sh`.
- Zig base verification output (step 3).
- Tamper demo output showing original pass + tampered fail (step 4).
- Zig `--require-chain` output (step 5).
- Key identifiers copied from outputs: `request_id`, `audit_hash`, `record_hash`, `prev_record_hash`, `profile_name`, `profile_version`.

Notes:

- This quick path is a reviewer shortcut; it does not replace CI, hostile baseline gates, or full operational runbooks.
- This path demonstrates evidence generation and verification behavior only; it does not claim global truth, consensus, or full-input replay.

## Step 1 — Run Signed Decision Demo

Run:

```bash
bash scripts/demo_decision_flow.sh
```

This script starts the Rust API with a temporary audit path, sends one signed `/evaluate` request, prints the response and generated artifact, runs Zig base verification, and prints follow-up inspection commands.

Capture from the output:

- response JSON path
- audit JSONL path
- server log path
- request id if printed or visible in the response/artifact
- `audit_hash` if printed or visible in the response/artifact
- `record_hash` if printed or visible in the artifact

Temporary paths can be lost.
Copy the files if they are part of a review packet.

## Step 2 — Capture Evidence Paths

For a complete reviewer packet, collect or copy:

- response JSON
- audit JSONL
- server log
- inspect output
- Zig verification output
- tamper demo output
- chain verification output

Do not treat terminal output alone as the preserved evidence pack if later review is expected.

## Step 3 — Inspect the Audit Artifact

Run the exact command printed by the demo, or pass the artifact path directly:

```bash
bash scripts/inspect_audit_artifact.sh <artifact.jsonl>
```

Identify:

- `request_id`
- `final_decision`
- `audit_hash`
- `hash_algo`
- `profile_name`
- `profile_version`
- `record_hash`
- `prev_record_hash`
- persisted trace shape

This inspection helper prepares a single-record JSONL file and prints a Zig verification command.

## Step 4 — Find Evidence by Identifier

Search by `request_id`, `audit_hash`, or `record_hash`:

```bash
bash scripts/find_audit_artifact.sh <request_id|audit_hash|record_hash> <path-or-dir>
```

This is a reviewer helper.
It is not an authority layer and does not replace offline verification.

## Step 5 — Verify Artifact Offline with Zig

Base verification:

```bash
cd tools/zig && zig build run -- verify <artifact.jsonl>
```

Zig verifies persisted artifact consistency:

- JSON/schema shape
- supported `hash_algo`
- lowercase hash format
- `final_decision` consistency with persisted trace
- recomputed `audit_hash`
- `record_hash` when present and non-null

Zig does not verify:

- HMAC validity
- replay validity
- timestamp freshness
- known profile config correctness
- full original request replay
- never-persisted events

## Step 6 — Run Flagged Decision Demo

Run:

```bash
bash scripts/demo_decision_flow_flagged.sh
```

This demonstrates a non-approved path.
The request is expected to produce `Flagged` because `risk_bps=9500` exceeds the default AML review threshold while the amount remains below the blocking amount threshold.

Collect the same evidence as Step 1.

## Step 7 — Demonstrate Trace Tamper Detection

Run:

```bash
bash scripts/demo_tampering_trace.sh
```

This script runs the flagged demo, verifies the original generated artifact, creates a tampered copy by changing a persisted trace field, and verifies that Zig rejects the tampered copy.

This demonstrates `audit_hash` / trace tamper detection.
The original generated artifact should pass; the tampered copy should fail with tampering evidence.

## Step 8 — Demonstrate Record Chain Verification

Run:

```bash
bash scripts/demo_record_chain_verification.sh
```

This demonstrates:

- valid chained artifact verification
- wrong `prev_record_hash` detection
- record-field tamper detection
- offline Zig `--require-chain` behavior

Important limit: this chain demo is fixture/temp-record driven.
It is not a live two-request `/evaluate` chain demo.

## Step 9 — Optional Fixture Chain Verification

Verify the persistent chained fixture:

```bash
cd tools/zig && zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl
```

This proves that the offline Zig verifier can validate a persistent two-record chained JSONL fixture.
It does not prove deployment storage safety, runtime integrity, or live multi-record generation by itself.

## Evidence to Collect

Collect:

- response JSON
- audit JSONL
- server log
- inspect output
- Zig base verification output
- Zig chain verification output
- tamper demo output
- `request_id`
- `audit_hash`
- `record_hash`
- `prev_record_hash`
- `profile_name`
- `profile_version`

## What Each Evidence Item Means

| Evidence item | Meaning |
| --- | --- |
| response JSON | Runtime response returned after successful audit append. |
| audit JSONL | Persisted decision evidence artifact. |
| server log | Local runtime context for the demo process. |
| inspect output | Extracted artifact fields for reviewer readability. |
| Zig base verification output | Offline consistency check for persisted artifact schema, trace, decision, and hashes. |
| Zig chain verification output | Offline continuity check for `record_hash` / `prev_record_hash` chain mode. |
| tamper demo output | Evidence that modified persisted trace data is detected. |
| `request_id` | Request/evidence lookup identifier; also replay nonce in runtime semantics. |
| `audit_hash` | Semantic hash of persisted trace. |
| `record_hash` | Record-level hash over selected persisted fields. |
| `prev_record_hash` | Link to the previous persisted record hash. |
| `profile_name` / `profile_version` | Selected profile metadata binding, not full policy/config binding. |

## What Evidence Pack Demo v1 Can Claim

Evidence Pack Demo v1 can claim:

- reviewer can run a signed local `/evaluate`
- Rust computes deterministic decision and trace
- JSONL audit artifact is persisted
- artifact exposes `audit_hash`, `hash_algo`, and current audit record fields
- current append artifacts include `record_hash` and `prev_record_hash`
- Zig can verify persisted artifacts offline
- Zig `--require-chain` can verify chained artifacts
- trace tampering is detected
- record-chain continuity and record-field tampering are demonstrated
- Ruby, Julia, Mesh/P2P, Witness, Bitcoin, and IA are not required for the core evidence demo

## What Evidence Pack Demo v1 Cannot Claim

Evidence Pack Demo v1 cannot claim:

- global truth
- consensus
- full-input replay
- HMAC validity proven by Zig
- replay validity proven by Zig
- timestamp freshness proven by Zig
- full profile/config binding
- never-persisted event detection
- live multi-record chain generation unless a new script is added
- every failure mode or production deployment condition
- public exposure safety
- runtime process was never compromised before persistence

## Known Limits

- The demo story currently uses multiple scripts, not one orchestrator.
- Generated trace tamper demo and fixture-driven chain demo are separate.
- Fixture-driven chain demo does not prove live multi-record append generation.
- There is no dedicated live blocked-path demo script.
- Demo paths are temporary and should be copied if evidence must be preserved.
- Local port conflicts can affect demo clarity.
- Older docs may understate current `record_hash` / `--require-chain` coverage and may need cleanup later.

## vNext / Open Decisions

- Add one-command evidence pack script.
- Add live two-record chain generation using `/evaluate` twice.
- Add live blocked-path demo.
- Add generated-artifact record-hash tamper demo.
- Add evidence output directory convention.
- Add JSON summary output for reviewer packs.
- Add optional replay/fail-closed demo.
- Decide whether Evidence Pack Demo becomes part of release/checkpoint gate.
- Clean up older docs that understate chain verification coverage.

## Reviewer Checklist

- Run `bash scripts/demo_decision_flow.sh`.
- Preserve response JSON, audit JSONL, and server log paths.
- Inspect the artifact with `scripts/inspect_audit_artifact.sh`.
- Verify the artifact with Zig base verification.
- Run `bash scripts/demo_decision_flow_flagged.sh`.
- Run `bash scripts/demo_tampering_trace.sh`.
- Run `bash scripts/demo_record_chain_verification.sh`.
- Verify `fixtures/audit_chain_sample.jsonl` with `--require-chain`.
- Record what passed, what failed, and which commands were actually run.
- Keep the non-claims visible in any review summary.

## Operator Checklist

- Confirm required local tools are available before the demo.
- Ensure `127.0.0.1:3000` is free or set `API_URL`.
- Copy temporary evidence files before ending the session.
- Keep evidence files in a review-safe directory if they must be retained.
- Do not edit audit JSONL manually.
- Do not treat demo success as production readiness.
- Use production/hostile-baseline gates separately when deployment readiness is under review.
