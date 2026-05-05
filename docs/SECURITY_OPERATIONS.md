# Security Operations Guide (Phase 3)

This document defines the deployment hardening and incident response baseline for `nexo-2026` in production.

## 1. Deployment Hardening Checklist

### 1.1 Edge/Gateway

- Put an API gateway or reverse proxy in front of the service.
- Enforce HTTPS at the edge.
- Limit request body size at edge and app.
- Restrict allowed methods and paths.
- Enable IP reputation and WAF rules when available.

Proxy identity headers trust boundary:

- By default, NEXO does **not** trust `X-Forwarded-For` / `X-Real-IP` for rate-limit identity.
- If you must run behind a reverse proxy and want forwarded identity, enable explicitly:
  - `NEXO_TRUST_PROXY_HEADERS=true`
- This is safe only when the deployment guarantees:
  - direct access to the service is blocked (proxy is the only ingress)
  - the proxy strips/sanitizes any incoming forwarded headers from clients
  - only the trusted proxy injects the forwarded identity headers

Recommended baseline:
- `POST /evaluate` only from trusted networks/clients.
- `GET /security/status` and `GET /metrics` restricted to internal/admin access.

### 1.2 TLS and mTLS

- Use TLS 1.2+ minimum.
- Prefer TLS 1.3 with modern ciphers.
- For internal service-to-service traffic, prefer mTLS.
- Rotate certificates with automation and short validity windows.
- Optional app-level attestation mode can enforce edge mTLS proof via headers:
  - `NEXO_MTLS_REQUIRED=true`
  - `NEXO_MTLS_VERIFIED_HEADER` / `NEXO_MTLS_VERIFIED_VALUE`
  - `NEXO_MTLS_CLIENT_ID_HEADER` / `NEXO_MTLS_ALLOWED_CLIENT_IDS`

### 1.3 Secrets Management

- Store `NEXO_HMAC_SECRET` in a secret manager (not plaintext files).
- Optionally enable managed secret providers with `NEXO_SECRET_PROVIDER=vault|azure|gcp|aws`.
- Prefer mounted secret files for runtime injection:
  - `NEXO_HMAC_SECRET_FILE`
  - `NEXO_HMAC_SECRET_PREV_FILE`
  - `NEXO_HMAC_KEY_ID_FILE`
  - `NEXO_HMAC_KEY_ID_PREV_FILE`
- Keep active and previous key IDs distinct.
- Rotate keys with overlap window (`active_plus_previous`) and then remove previous.
- Never log key values or HMAC material.

Vault runtime variables:
- `NEXO_VAULT_ADDR`
- `NEXO_VAULT_TOKEN`
- `NEXO_VAULT_PATH`
- `NEXO_VAULT_MOUNT` (default `secret`)
- `NEXO_VAULT_TIMEOUT_MS` (default `2000`)

Azure runtime variables:
- `NEXO_AZURE_VAULT_URL`
- `NEXO_AZURE_ACCESS_TOKEN` or `NEXO_AZURE_ACCESS_TOKEN_FILE`
- `NEXO_AZURE_USE_MANAGED_IDENTITY=true` (optional)

GCP runtime variables:
- `NEXO_GCP_PROJECT_ID`
- `NEXO_GCP_ACCESS_TOKEN` or `NEXO_GCP_ACCESS_TOKEN_FILE`
- `NEXO_GCP_USE_METADATA_TOKEN=true` (optional)

AWS runtime variables:
- `NEXO_AWS_REGION`
- `NEXO_AWS_SECRET_ID`

Client asymmetric signature mode (optional):
- `NEXO_CLIENT_SIG_REQUIRED=true`
- `NEXO_CLIENT_PUBKEYS_JSON` or `NEXO_CLIENT_PUBKEYS_FILE`

### 1.3.1 Replay Protection Posture

- Local/dev mode: in-memory replay protection is allowed, but it does **not** survive process restart.
- Production-like hostile environments: require a persistent replay backend (Redis) and fail closed if it is not configured:
  - `NEXO_REQUIRE_PERSISTENT_REPLAY=true`
  - `NEXO_REDIS_URL=...`
- If Redis replay is configured, backend unavailability should remain fail-closed (requests guarded by replay must be rejected).
- `request_id` is a one-time signed nonce consumed at the security/replay gate, before audit persistence.
- `request_id` is not a retry/idempotency key.
- A request is accepted only when `/evaluate` returns `200` after audit append success.
- If audit append fails, `/evaluate` fails closed, returns an error, and withholds the decision payload.
- Retrying the same `request_id` after audit append failure is expected to return replay conflict; after incident review/recovery, use a new signed request with a new `request_id`.
- Two-phase replay reservation/commit is a future architecture option and is not the current behavior.

### 1.3.2 Audit Persistence Durability Contract

- On append, NEXO writes full JSONL replacement content into a same-directory temp file (`*.jsonl.tmp`), flushes/syncs that temp file, renames it into the final audit path, and then syncs the parent directory when supported by the platform.
- If temp write/sync fails before rename, the previous audit file remains authoritative.
- If rename fails, the previous audit file remains authoritative and the temp file may remain for operator inspection/removal.
- If parent-directory sync fails after rename, treat it as a storage durability incident; visible file state may already have changed.
- This durable replace sequence improves crash/power-loss resilience, but it is not a universal crash-proof guarantee across every filesystem, mount option, storage device, or platform.
- This durability contract does not replace offline Zig verification, and does not prove full historical chain validity by itself.

### 1.3.3 Single-Writer Audit Path Contract

- One audit artifact path must have exactly one writer process.
- `AuditStore::append` uses a same-directory lock file (`<audit_path>.lock`) as a fail-closed process-level guard.
- If the lock file already exists, append fails closed and should be treated as an operator incident (another writer may be active, or a stale lock may remain after an interrupted append).
- If lock release fails after a completed durable append sequence, treat it as an operator incident: the record may already be persisted even if the caller receives an error.
- Do not run multiple replicas writing to the same `NEXO_AUDIT_PATH`.
- Shared filesystems/NFS/container replicas require external single-writer coordination or separate audit paths per writer.
- The lock file guard is not a distributed lock system.
- A stale lock file must not be blindly deleted without checking whether an append was interrupted and whether the artifact needs verification/quarantine.
- On post-append lock-release failure, do not blindly retry the same request and do not blindly delete the lock; preserve current audit/lock state, inspect process/timestamp context, and run offline verification before recovery decisions.
- Zig verification can detect visible chain/tampering issues in persisted artifacts, but it cannot prove that no accepted event was lost before persistence.

### 1.4 Runtime Isolation

- Run as non-root user.
- Read-only filesystem where possible.
- Minimal container/base image.
- Network policy denying egress by default.

### 1.5 Access Control

- Restrict who can read:
  - `logs/audit_records.jsonl`
  - `/security/status`
  - `/metrics`
- Enforce RBAC on deployment platform.

## 2. Observability Baseline

Track from `/metrics` and `/security/status`:

- `requests_total`
- `requests_error`
- `avg_latency_ns`
- `p95_latency_ns`
- `p99_latency_ns`
- `unauthorized_total` (401)
- `request_timeout_total` (408)
- `conflict_total` (409)
- `too_many_requests_total` (429)
- `rate_limit_hits`
- `rotation_mode`

## 3. Alert Thresholds (Starting Point)

Tune per environment, but start with:

- Critical: `p99_latency_ns` sustained > 2x baseline for 5m.
- Warning: `unauthorized_total` growth > normal baseline (possible auth probing).
- Warning: `conflict_total` spike (possible replay attempts).
- Warning: `too_many_requests_total` spike (burst/abuse/client bug).
- Critical: `rotation_mode` unexpected change during deploy window.

## 4. Incident Runbook

### 4.1 401 Spike (Unauthorized)

1. Check `NEXO_HMAC_KEY_ID` and client `X-Key-Id`.
2. Verify key rotation status (`rotation_mode`).
3. Validate client signing path and timestamp generation.
4. If active key leaked, rotate immediately and revoke previous.

### 4.2 408 Spike (Request Timeout / timestamp window)

1. Check clock drift between clients and server.
2. Confirm NTP sync on all nodes.
3. Validate `NEXO_AUTH_WINDOW_MS` against real network latency.

### 4.3 409 Spike (Replay Detected)

1. Check for client request-id reuse bugs.
2. Verify load balancer retry policy (must not replay same signed request blindly).
3. Inspect potential attack source IPs and apply edge blocks.

### 4.4 429 Spike (Rate Limit Exceeded)

1. Identify offender by IP/user patterns.
2. Decide if it is abuse or legitimate traffic growth.
3. Adjust edge and app limits only after root-cause analysis.

### 4.5 High Latency (p95/p99)

1. Check CPU, memory, lock contention, I/O.
2. Compare with deploy/change timeline.
3. Roll back if SLO is breached and cause is unknown.

### 4.6 Audit Incident Recovery & Quarantine Checklist

This checklist is for audit persistence incidents (append failures, lock incidents, malformed audit content, or chain-integrity concerns).

Immediate posture (fail closed):

1. Stop accepting new `POST /evaluate` traffic while audit persistence is failing (disable ingress/drain or stop the API process).
2. Preserve the current audit file, lock file, and temp artifacts before any mutation.
3. Do not delete/truncate/overwrite/edit audit JSONL files manually.
4. Do not blindly retry the same `request_id`.
5. Do not treat `/api/state`, `/audit/recent`, or `/security/status` as authoritative proof of audit integrity.

Evidence preservation order (command-level):

1. Capture incident context:
   - `UTC_TS="$(date -u +%Y%m%dT%H%M%SZ)"`
   - `AUDIT_PATH="${NEXO_AUDIT_PATH:-logs/audit_records.jsonl}"`
   - `LOCK_PATH="${AUDIT_PATH}.lock"`
   - `AUDIT_DIR="$(dirname "${AUDIT_PATH}")"`
   - `AUDIT_BASE="$(basename "${AUDIT_PATH}")"`
   - `AUDIT_STEM="${AUDIT_BASE%.*}"; [ "${AUDIT_STEM}" = "${AUDIT_BASE}" ] && AUDIT_STEM="${AUDIT_BASE}"`
   - `TMP_PATH="${AUDIT_DIR}/${AUDIT_STEM}.jsonl.tmp"`
2. Record current build/revision:
   - `git rev-parse HEAD`
3. Record whether lock/temp exists:
   - `test -f "${LOCK_PATH}" && echo "lock:present" || echo "lock:absent"`
   - `test -f "${TMP_PATH}" && echo "tmp:present" || echo "tmp:absent"`
4. Preserve evidence before recovery actions:
   - `mkdir -p "quarantine/audit/${UTC_TS}"`
   - `cp -a "${AUDIT_PATH}" "quarantine/audit/${UTC_TS}/"`
   - `test -f "${LOCK_PATH}" && cp -a "${LOCK_PATH}" "quarantine/audit/${UTC_TS}/"`
   - `test -f "${TMP_PATH}" && cp -a "${TMP_PATH}" "quarantine/audit/${UTC_TS}/"`
5. Preserve logs and operator notes for the incident window:
   - save API/runtime logs around the failure window
   - save request metadata needed for forensics without leaking secrets

Quarantine convention:

- Use `quarantine/audit/<UTC_TIMESTAMP>/` (for example `quarantine/audit/20260505T120000Z/`).
- Include:
  - copied audit JSONL
  - copied `.lock` file (if present)
  - copied `.jsonl.tmp` file (if present)
  - operator notes (timeline, actions, assumptions)
  - offline verification output
  - relevant runtime logs
- Do not mutate original evidence files before quarantine copy + verification.

Offline verification (authoritative for persisted artifacts):

- `cd tools/zig && zig build run -- verify --require-chain <artifact.jsonl>`
- `bash scripts/inspect_audit_artifact.sh <artifact.jsonl>`
- `bash scripts/find_audit_artifact.sh <request_id|audit_hash|record_hash> <path-or-dir>`

Interpretation:

- Zig is authoritative for persisted artifact schema/hash/chain checks.
- Zig cannot prove that a never-persisted event existed.

Persistence-outcome decision table:

| Scenario | Operator interpretation | Retry same `request_id`? | New signed request/new `request_id`? | Resume service? | Required actions |
| --- | --- | --- | --- | --- | --- |
| Definitely not persisted | Failure occurred before any durable replace success evidence | No | Only after incident review | Not yet | Preserve evidence, quarantine, run offline verification on current artifact, document incident |
| Possibly persisted | Error surface is ambiguous (for example post-rename/post-append incident) | No | Only after review confirms safe continuation | Not yet | Treat as high-risk ambiguity, preserve/quarantine, verify persisted artifact, record operator decision |
| Persisted but caller received error | Append likely persisted but caller saw failure (for example lock release failure after durable append) | No | Yes, but only for a new business attempt, never by reusing old nonce | Only after checks below | Preserve/quarantine, verify artifact, ensure one-writer topology, document incident and caller impact |
| Visible chain break | Persisted file fails chain continuity/hash checks | No | Only after quarantine and continuity decision | Not until resolved | Quarantine current path, verify with Zig, investigate source, do not overwrite evidence |
| Never-persisted event risk | Some accepted intent may not exist in persisted artifact history | No | Only after explicit review and new signed request | Not by default | Preserve logs + metadata, do not overclaim, document limitation explicitly |
| Stale lock vs active writer uncertainty | Existing lock may indicate live writer or stale incident artifact | No | Only after lock investigation and review | Not until resolved | Confirm process ownership, preserve lock before removal, verify artifact before resuming |

Lock investigation procedure:

1. Assume lock may be valid until proven otherwise.
2. Check for active writer process using deployment-native process inspection.
3. Preserve lock file into quarantine before any removal attempt.
4. If active writer is confirmed, do not remove lock manually; resolve writer topology first.
5. If stale lock is concluded, remove only after evidence capture, process check, and offline verification.
6. Deleting a stale lock is a recovery action, not proof of chain integrity.

Resume criteria:

Resume `POST /evaluate` traffic only when all are true:

1. Incident evidence was preserved/quarantined.
2. Offline verification was completed on active/recovered artifact.
3. No unresolved active-writer or lock ambiguity remains.
4. Deployment topology enforces one writer per audit path.
5. Incident record includes persistence-outcome interpretation and recovery decision.
6. If chain is broken or persistence outcome remains ambiguous, resume only under explicit operator incident procedure.
7. Do not resume solely because `/api/state` or `/security/status` appears healthy.

MUST NOT actions during incident response:

- MUST NOT manually edit audit JSONL.
- MUST NOT truncate audit files.
- MUST NOT overwrite malformed tails.
- MUST NOT delete lock files before evidence capture.
- MUST NOT retry the same `request_id` after audit persistence failure.
- MUST NOT treat Zig pass as proof that no request was ever lost before persistence.
- MUST NOT treat Ruby/Julia/Mesh/Witness/Bitcoin outputs as authority over unverified evidence.

Informational vs authoritative:

- Informational only: `/api/state`, `/audit/recent`, `/security/status`.
- Authoritative for persisted audit evidence: offline artifact verification and preserved incident artifacts.
- Informational endpoints are useful for triage, not substitutes for forensic verification.

## 5. Key Rotation Procedure

1. Set new `NEXO_HMAC_SECRET_FILE` and keep old as `NEXO_HMAC_SECRET_PREV_FILE` (or env equivalents).
2. Set/verify `NEXO_HMAC_KEY_ID[_FILE]` and `NEXO_HMAC_KEY_ID_PREV[_FILE]`.
3. Deploy server.
4. Migrate clients to new key id.
5. Monitor 401/408/409 during migration.
6. Remove previous key after stabilization.

## 6. Compliance and Audit Integrity

- Keep `audit_hash` and `hash_algo` unchanged unless a planned contract version bump occurs.
- Any change in `trace` ordering or hashing contract must be treated as a breaking forensic change.
- Verify samples offline with Zig verifier as part of release validation.
