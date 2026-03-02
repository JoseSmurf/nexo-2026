# NEXO 2026

NEXO is a deterministic decision engine designed for security-critical financial workflows where reproducibility, auditability, and fail-closed behavior are mandatory. It receives signed requests, applies explicit rules, returns a reproducible trace, and writes a cryptographically verifiable audit record.

This project is focused on applied security engineering for deterministic systems.

## Table of Contents

- [What problem it solves](#what-problem-it-solves)
- [Core guarantees](#core-guarantees)
- [Architecture overview](#architecture-overview)
- [Quickstart (60s)](#quickstart-60s)
- [Security model](#security-model)
- [Audit and hashing](#audit-and-hashing)
  - [Basic](#basic)
  - [Deep Dive](#deep-dive)
- [Zig verifier](#zig-verifier)
- [Configuration reference](#configuration-reference)
- [Performance](#performance)
- [Advanced deployment (optional)](#advanced-deployment-optional)
- [Roadmap](#roadmap)
- [Current status](#current-status)
- [License](#license)

## What problem it solves

- Prevents hidden decision drift between environments by enforcing deterministic rules and stable trace order.
- Enables third-party forensic validation without trusting the Rust runtime process.
- Eliminates probabilistic ambiguity in compliance decisions with fail-closed request security controls.

## Core guarantees

- Deterministic decisions: same valid input and profile -> same `final_decision` + trace semantics.
- Deterministic audit hashing over ordered trace (`trace_v4` framing contract).
- Reproducible forensic verification with Zig verifier.
- Fail-closed request validation (invalid/missing auth context is rejected).
- Anti-replay protection with timestamp window + request-id uniqueness checks.
- Security backends fail closed (Redis timeout/error paths reject guarded requests).
- Backward-compatible audit contract with explicit `hash_algo`.
- Legacy hash support is opt-in and isolated (no runtime SHA3 policy emission).

## Architecture overview

```text
Client (signed request)
        |
        v
  Axum API (/evaluate)
        |
        |-- security checks
        |   (HMAC, timestamp, replay, rate-limit, optional edge/mTLS/client-sig)
        v
  Deterministic Engine (rules + profile)
        |
        v
  AuditStore (JSONL append, retention)
        |
        +--> API response (final_decision, trace, audit_hash, hash_algo)
        |
        +--> Zig Verifier (offline forensic validation)

Optional distributed guards: Redis (replay/rate-limit coordination)
```

## Quickstart (60s)

Requirements: `rustup/cargo`, `julia` (for bridge/tests), `zig` (offline verifier optional in local dev).

```bash
git clone https://github.com/JoseSmurf/nexo-2026
cd nexo-2026
cp .env.example .env
export NEXO_HMAC_SECRET='dev-secret-active'
export NEXO_HMAC_KEY_ID='active'
export NEXO_PROFILE='br_default_v1'
cargo run --bin syntax-engine
```

```bash
REQ_ID="$(cat /proc/sys/kernel/random/uuid)"; TS="$(date +%s%3N)"
BODY="$(printf '{"user_id":"quickstart_user","amount_cents":150000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":%s,"risk_bps":1200,"ui_hash_valid":true,"request_id":"%s"}' "$TS" "$REQ_ID")"
SIG="$(cargo run --quiet --bin sign_request -- "$NEXO_HMAC_SECRET" "$NEXO_HMAC_KEY_ID" "$REQ_ID" "$TS" "$BODY")"
curl -sS -X POST 'http://127.0.0.1:3000/evaluate' -H 'content-type: application/json' -H "x-signature: $SIG" -H "x-request-id: $REQ_ID" -H "x-timestamp: $TS" -H "x-key-id: $NEXO_HMAC_KEY_ID" --data "$BODY"
```

## Security model

- Request signing: HMAC-BLAKE3 over canonical request context (`x-key-id`, `x-request-id`, `x-timestamp`, body).
- Anti-replay: timestamp window + replay key tracking (in-memory; Redis optional for distributed mode).
- Rate-limit: per IP and per `user_id`.
- Duplicate critical header rejection: rejects ambiguous multi-header auth/replay fields.
- Admin gate (default off): `/audit/recent`, `/security/status`, `/metrics` require `NEXO_ADMIN_API_ENABLED=true` and valid `Authorization: Bearer <token>`.
- Redis guard operations have short timeout and fail-closed behavior.

## Audit and hashing

### Basic

- Every decision writes `audit_hash` + `hash_algo`.
- Runtime hash algorithms emitted by contract:
  - `blake3`
  - `shake256-256`
  - `shake256-384`
  - `shake256-512`
  - `shake256-512+blake3-256`
- Deterministic policy:
  - `NEXO_SECURITY_LEVEL=INCIDENT` -> `shake256-512+blake3-256`
  - `NORMAL`/`ELEVATED` -> `shake256-*` only when `risk_bps >= 8000` or `amount_cents >= NEXO_AUDIT_HIGH_THRESHOLD_CENTS`; otherwise `blake3`
- `sha3-256` is legacy-only for historical offline verification and not emitted by runtime policy.

### Deep Dive

`audit_hash` is computed from trace semantics using fixed domain/tag framing (`trace_v4`), preserving sequence order.

Framing:
- `hash_field("schema", "trace_v4")`
- For each trace item in order:
- `Approved` -> `hash_field("D:A", "")`
- `FlaggedForReview` -> `hash_field("D:F", rule_id)`, `hash_field("R", reason)`, `severity_rank(u8)`, `measured(u64 LE)`, `threshold(u64 LE)`
- `Blocked` -> `hash_field("D:B", rule_id)`, `hash_field("R", reason)`, `severity_rank(u8)`, `measured(u64 LE)`, `threshold(u64 LE)`

`hash_field(tag, data)` byte layout:
- `u32_le(tag_len) || tag || u32_le(data_len) || data`

Severity rank:
- `Baixa=0`, `Alta=1`, `Grave=2`, `Critica=3`

Hybrid format:
- `shake256-512+blake3-256` means raw bytes concatenation in this exact order:
- `SHAKE256(64 bytes)` then `BLAKE3(32 bytes)`
- hex output length = `192` chars

Record-level fields:
- `sha3_shadow` is a legacy field name for shadow hashing.
- If present, `shadow_hash_algo` declares the real shadow algorithm used.

## Zig verifier

Run locally:

```bash
cd tools/zig
zig build test
zig build run -- verify ../../logs/audit_records.jsonl
```

What it validates:
- Required record schema and supported `hash_algo`.
- Recomputed hash equals stored `audit_hash`.
- `final_decision` is consistent with trace semantics.
- If `trace_bytes` exists, verifier recomputes both structured-trace hash and trace-bytes hash and requires equivalence (rejects mismatch).

Legacy behavior:
- `sha3-256` is rejected by default.
- For legacy archive validation only:

```bash
NEXO_ZIG_LEGACY_SHA3_256=1 zig build run -- verify ../../logs/audit_records.jsonl
```

## Configuration reference

### Security

| Env var | Default | Purpose | Safe notes |
|---|---|---|---|
| `NEXO_HMAC_SECRET` | none | Active HMAC secret | Required unless provider/file supplies it |
| `NEXO_HMAC_SECRET_FILE` | unset | Active secret file path | Prefer in staging/prod |
| `NEXO_HMAC_KEY_ID` | `active` | Active key identifier | Must be non-empty |
| `NEXO_HMAC_SECRET_PREV` | unset | Previous secret for rotation | Optional dual-key rotation |
| `NEXO_HMAC_KEY_ID_PREV` | unset | Previous key id | Must differ from active key id |
| `NEXO_AUTH_WINDOW_MS` | `60000` | Timestamp tolerance window | Tighten only with synchronized clocks |
| `NEXO_REPLAY_TTL_MS` | `120000` | Replay key TTL | Keep > auth window |
| `NEXO_REPLAY_MAX_KEYS` | `100000` | In-memory replay map cap | Prevents unbounded growth |
| `NEXO_RATE_LIMIT_WINDOW_MS` | `60000` | Rate-limit window | Tune per expected traffic |
| `NEXO_RATE_LIMIT_IP` | `600` | Per-IP request budget | Lower in public exposure |
| `NEXO_RATE_LIMIT_USER` | `300` | Per-user request budget | Protects user-level abuse |
| `NEXO_EDGE_REQUIRED` | `false` | Require edge shared-secret header | Optional hardening layer |
| `NEXO_MTLS_REQUIRED` | `false` | Require upstream mTLS attestation headers | Enable behind trusted proxy only |
| `NEXO_CLIENT_SIG_REQUIRED` | `false` | Require client Ed25519 signature | Requires key registry env/file |

### Admin

| Env var | Default | Purpose | Safe notes |
|---|---|---|---|
| `NEXO_ADMIN_API_ENABLED` | `false` | Enable admin endpoints (`/audit/recent`, `/security/status`, `/metrics`) | Keep false on public surfaces |
| `NEXO_ADMIN_API_TOKEN` | none | Bearer token for admin endpoints | Required when admin API is enabled |

### Audit/Hash

| Env var | Default | Purpose | Safe notes |
|---|---|---|---|
| `NEXO_SECURITY_LEVEL` | `NORMAL` | Hash policy mode (`NORMAL`, `ELEVATED`, `INCIDENT`) | `INCIDENT` enforces hybrid hashing |
| `NEXO_AUDIT_HIGH_THRESHOLD_CENTS` | `5000000` | Amount threshold for adaptive switch | Keep aligned with risk policy |
| `NEXO_AUDIT_SHAKE_BITS` | `512` | SHAKE output bits (`256`/`384`/`512`) | Affects only shake paths |
| `NEXO_SHA3_SHADOW_ENABLED` | `false` | Emits legacy-named `sha3_shadow` field | For migration/compat only |
| `NEXO_AUDIT_PATH` | `logs/audit_records.jsonl` | Audit file path | Secure write access required |
| `NEXO_AUDIT_RETENTION` | `5000` | In-memory recent-audit retention | Not archival storage |

### Redis

| Env var | Default | Purpose | Safe notes |
|---|---|---|---|
| `NEXO_REDIS_URL` | unset | Redis endpoint for distributed guards | If set, Redis path becomes authoritative |
| `NEXO_REDIS_PREFIX` | `nexo` | Key prefix namespace | Set per environment |
| `NEXO_REDIS_OP_TIMEOUT_MS` | `100` | Per-op timeout for Redis guard calls | Timeout/error fails closed |

### Observability / Performance

| Env var | Default | Purpose | Safe notes |
|---|---|---|---|
| `NEXO_ENGINE_BUDGET_NS` | tool default | Perf budget for engine benchmark binary | CI fail gate |
| `NEXO_HTTP_BUDGET_US` | tool default | Perf budget for HTTP benchmark binary | CI fail gate |
| `NEXO_LOAD_REQUESTS` | `2000` | Load test request count | Tune for CI cost |
| `NEXO_LOAD_CONCURRENCY` | `200` | Load test concurrency | Keep realistic for runner size |
| `NEXO_LOAD_MAX_P95_US` | unset | p95 threshold for load_test | Optional fail gate |
| `NEXO_LOAD_MAX_P99_US` | unset | p99 threshold for load_test | Optional fail gate |
| `NEXO_ALERT_MAX_ERROR_RATE_PCT` | unset | Max allowed error ratio in load_test | Fail-closed threshold |
| `NEXO_ALERT_MAX_401` | unset | Max unauthorized count in load_test | Fail-closed threshold |
| `NEXO_ALERT_MAX_408` | unset | Max expired timestamp count in load_test | Fail-closed threshold |
| `NEXO_ALERT_MAX_409` | unset | Max replay conflict count in load_test | Fail-closed threshold |
| `NEXO_ALERT_MAX_429` | unset | Max rate-limit count in load_test | Fail-closed threshold |

## Performance

What is measured:
- Engine path latency budget (`perf_budget` binary).
- HTTP/load path percentiles and security error counters (`load_test` binary).

How to run:

```bash
cargo run --release --bin perf_budget
cargo run --release --bin load_test
cargo bench
```

## Advanced deployment (optional)

Optional secret providers for runtime key loading:
- `vault`
- `azure`
- `gcp`
- `aws`

Selector:
- `NEXO_SECRET_PROVIDER=none|vault|azure|gcp|aws`

Use `.env.example` provider sections as the canonical reference for required variables. Keep this optional for local dev; enforce in staging/prod.

## Roadmap

- Staging parity checks for provider-backed secrets and distributed guards.
- Alerting dashboards from CI/runtime SLO metrics (latency + 401/408/409/429 + 503).
- Audit storage hardening for long-term retention and integrity controls.
- Expanded verifier fixtures across profiles and incident modes.
- Operational runbooks for key rotation and incident-level hash policy transitions.

## Current status

- API endpoints:
  - `POST /evaluate`
  - `GET /healthz`
  - `GET /readyz`
  - `GET /metrics` (admin-gated)
  - `GET /audit/recent?limit=50` (admin-gated)
  - `GET /security/status` (admin-gated)
- Rule profiles include 9 jurisdictions/currencies/regulators.
- Rust tests: 127
- Julia tests: 124
- Zig tests: 20
- Total tests: 271
- Tech stack:
  - Rust (core engine + API)
  - BLAKE3 + SHAKE256 (audit hash, with deterministic hybrid mode in INCIDENT)
  - Axum + Tokio (HTTP)
  - serde/serde_json (contracts)
  - Julia bridge (precision PLCA scoring)
  - Zig offline verifier (forensic audit hash check)

## License

MIT

NEXO is not a probabilistic AI compliance engine. It is a deterministic, auditable decision system designed for environments where reproducibility matters more than heuristics.
