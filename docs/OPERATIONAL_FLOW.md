# Operational Flow Guide

This guide describes the day-to-day operational path of the current NEXO system:

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> inspection -> offline Zig verification`

It is intentionally focused on the current production-shaped path already present in the repository.

## 1. Operational flow

### 1.1 Request intake

- A client sends a signed `POST /evaluate` request.
- The API validates HMAC, timestamp window, replay constraints, and other fail-closed security checks.
- Rate limiting uses the socket peer IP by default. Forwarded proxy identity headers are ignored unless explicitly enabled via `NEXO_TRUST_PROXY_HEADERS=true` behind a sanitizing reverse proxy boundary.
- Replay protection is in-memory by default (local/dev posture) and does not survive process restart. Production-like hostile deployments should require a persistent replay backend via `NEXO_REQUIRE_PERSISTENT_REPLAY=true` (see `docs/SECURITY_OPERATIONS.md`).
- `request_id` is a one-time signed nonce consumed at the security/replay gate and is not an idempotent retry key.

### 1.2 Deterministic decision

- The Rust engine evaluates the request deterministically.
- The response includes:
  - `final_decision`
  - `trace`
  - `audit_hash`
  - `hash_algo`

### 1.3 Audit artifact persistence

- The API appends an `AuditRecord` to the configured audit file.
- Default path:
  - `logs/audit_records.jsonl`
- Override path:
  - `NEXO_AUDIT_PATH=/path/to/audit_records.jsonl`

Each persisted record contains the fields needed for later inspection and offline verification, including:

- `request_id`
- `final_decision`
- `trace`
- `audit_hash`
- `hash_algo`
- `prev_record_hash`
- `record_hash`

Acceptance boundary:

- `/evaluate` is accepted only when it returns `200` after audit append succeeds.
- If audit append fails, `/evaluate` returns an error and withholds the decision payload.
- A retry with the same `request_id` is expected to be rejected as replay conflict; incident recovery requires operator review and, when appropriate, a new signed request with a new `request_id`.
- Zig verifies persisted artifacts only; it cannot prove events that were never persisted.

Durability incident note:

- If audit append returns a storage/durability error, stop accepting new decisions, preserve the current audit file and any remaining `*.jsonl.tmp`, run offline verification, and quarantine the affected artifact path before resuming writes.
- Keep exactly one writer process per `NEXO_AUDIT_PATH`; do not run multiple replicas writing the same audit file path unless external single-writer coordination is in place.
- If `<audit_path>.lock` already exists, treat it as an incident signal (possible active writer or stale lock after interruption), not as a cleanup-only task.
- If append fails at lock release after a completed durable write, treat it as an incident where the record may already be persisted; do not blindly retry the same request or blindly delete the lock before process/timestamp checks and offline verification.

## 2. Where artifacts are stored

The current storage model is JSONL append-only persistence via the Rust audit store.

Default location:

```bash
logs/audit_records.jsonl
```

Configured location:

```bash
echo "${NEXO_AUDIT_PATH:-logs/audit_records.jsonl}"
```

Operational note:

- The lowest-risk retrieval path is the persisted JSONL file itself.
- An admin-gated read-only endpoint (`GET /audit/recent`) also exists, but the local file remains the simplest and most direct operational source.

## 3. Retention guidance

Minimal safe posture for the current system:

- Treat the audit file as append-only operational evidence.
- Restrict write access to the service account only.
- Restrict read access to operators who need audit access.
- Retain the full JSONL file, not only extracted hashes.
- Preserve ordering and exact contents when copying or archiving.
- Keep `prev_record_hash` and `record_hash` intact when retaining records.
- Rotate by copying closed files to protected storage rather than rewriting active artifacts in place.

This repository does not yet add a separate archival subsystem. Current safe practice is disciplined file retention around `NEXO_AUDIT_PATH`.

Recommended minimal convention:

- active file:
  - `logs/audit_records.jsonl`
- archived closed files:
  - `logs/audit_archive/YYYY-MM-DD/audit_records-*.jsonl`

The system does not require this exact layout, but using a stable archive directory makes later lookup and recovery easier.

## 4. Inspecting recent decisions

To inspect the latest persisted artifact:

```bash
bash scripts/inspect_audit_artifact.sh
```

To inspect a specific audit file:

```bash
bash scripts/inspect_audit_artifact.sh /path/to/audit_records.jsonl
```

To locate a past artifact by `request_id`, `audit_hash`, or `record_hash`:

```bash
bash scripts/find_audit_artifact.sh <request_id-or-hash>
```

To search only one archive file or one archive directory:

```bash
bash scripts/find_audit_artifact.sh <request_id-or-hash> /path/to/audit_records.jsonl
bash scripts/find_audit_artifact.sh <request_id-or-hash> /path/to/audit_archive/
```

Important:

- `scripts/demo_decision_flow.sh` and `scripts/demo_decision_flow_flagged.sh` write to a temporary audit file.
- After either demo, use the exact inspection command printed by the demo for that artifact.
- The no-argument form of `scripts/inspect_audit_artifact.sh` reads `NEXO_AUDIT_PATH` or `logs/audit_records.jsonl`; it does not automatically reopen the demo's temporary file after the demo exits.

The helper will:

1. locate the audit file
2. extract the latest non-empty artifact
3. print the main fields
4. write a single-artifact `.jsonl`
5. print the exact Zig verification command

For a quick read-only health signal from the running API, inspect `/api/state` and check:

- `audit_chain_status`
- `audit_chain_checked_records`
- `audit_chain_last_record_hash`
- `audit_chain_error`

Operational meaning:

- `ok`: the recent persisted `record_hash` chain window is internally consistent
- `broken`: the recent persisted chain window has a continuity problem and should be inspected immediately
- `empty`: no persisted audit records are currently available in the checked window

This signal is intentionally compact. Use `scripts/inspect_audit_artifact.sh` and the Zig verifier for deeper investigation.

## 5. Verifying past decisions

For a generated or retained artifact:

```bash
cd tools/zig
zig build run -- verify /path/to/audit_records.jsonl
```

If the record is no longer in the active audit file:

1. locate it with `scripts/find_audit_artifact.sh`
2. verify the prepared single-artifact `.jsonl`
3. if needed, recover the original archived JSONL file from protected storage and verify that file directly

For a quick local walkthrough:

```bash
bash scripts/demo_decision_flow.sh
```

Then run the exact `bash scripts/inspect_audit_artifact.sh ...` command printed by the demo for the generated temporary artifact.

For a non-approved scenario:

```bash
bash scripts/demo_decision_flow_flagged.sh
```

Then run the exact `bash scripts/inspect_audit_artifact.sh ...` command printed by the flagged demo for its generated temporary artifact.

## 6. Suggested operator workflow

A minimal operator loop for the current system is:

1. run or receive an evaluation request
2. inspect the latest artifact
3. confirm `final_decision`, `trace`, `audit_hash`, and `hash_algo`
4. verify the artifact with Zig
5. retain the JSONL artifact in protected storage

For historical recovery:

1. search active and archived files with `scripts/find_audit_artifact.sh`
2. confirm the matched `request_id`, `audit_hash`, and `record_hash`
3. verify the prepared artifact with Zig
4. restore the archived JSONL file only if deeper historical review is required

## 7. Related repository paths

- `scripts/demo_decision_flow.sh`
- `scripts/demo_decision_flow_flagged.sh`
- `scripts/inspect_audit_artifact.sh`
- `scripts/find_audit_artifact.sh`
- `examples/basic_decision_flow.md`
- `examples/flagged_decision_flow.md`
- `examples/audit_inspection_flow.md`
- `docs/SECURITY_OPERATIONS.md`
