# Operational Flow Guide

This guide describes the day-to-day operational path of the current NEXO system:

`request -> decision -> audit artifact -> inspection -> verification`

It is intentionally focused on the current production-shaped path already present in the repository.

## 1. Operational flow

### 1.1 Request intake

- A client sends a signed `POST /evaluate` request.
- The API validates HMAC, timestamp window, replay constraints, and other fail-closed security checks.

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

## 4. Inspecting recent decisions

To inspect the latest persisted artifact:

```bash
bash scripts/inspect_audit_artifact.sh
```

To inspect a specific audit file:

```bash
bash scripts/inspect_audit_artifact.sh /path/to/audit_records.jsonl
```

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

For a quick local walkthrough:

```bash
bash scripts/demo_decision_flow.sh
bash scripts/inspect_audit_artifact.sh
```

For a non-approved scenario:

```bash
bash scripts/demo_decision_flow_flagged.sh
bash scripts/inspect_audit_artifact.sh
```

## 6. Suggested operator workflow

A minimal operator loop for the current system is:

1. run or receive an evaluation request
2. inspect the latest artifact
3. confirm `final_decision`, `trace`, `audit_hash`, and `hash_algo`
4. verify the artifact with Zig
5. retain the JSONL artifact in protected storage

## 7. Related repository paths

- `scripts/demo_decision_flow.sh`
- `scripts/demo_decision_flow_flagged.sh`
- `scripts/inspect_audit_artifact.sh`
- `examples/basic_decision_flow.md`
- `examples/flagged_decision_flow.md`
- `examples/audit_inspection_flow.md`
- `docs/SECURITY_OPERATIONS.md`
