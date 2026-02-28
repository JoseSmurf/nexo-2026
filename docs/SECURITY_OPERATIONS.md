# Security Operations Guide (Phase 3)

This document defines the deployment hardening and incident response baseline for `nexo-2026` in production.

## 1. Deployment Hardening Checklist

### 1.1 Edge/Gateway

- Put an API gateway or reverse proxy in front of the service.
- Enforce HTTPS at the edge.
- Limit request body size at edge and app.
- Restrict allowed methods and paths.
- Enable IP reputation and WAF rules when available.

Recommended baseline:
- `POST /evaluate` only from trusted networks/clients.
- `GET /security/status` and `GET /metrics` restricted to internal/admin access.

### 1.2 TLS and mTLS

- Use TLS 1.2+ minimum.
- Prefer TLS 1.3 with modern ciphers.
- For internal service-to-service traffic, prefer mTLS.
- Rotate certificates with automation and short validity windows.

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
