# NEXO 2026

NEXO is a deterministic decision engine designed for security-critical financial workflows where reproducibility, auditability, and fail-closed behavior are mandatory. It receives signed requests, applies explicit rules, returns a reproducible trace, and writes a cryptographically verifiable audit record.

This project is focused on applied security engineering for deterministic systems.

## Table of Contents

- [What problem it solves](#what-problem-it-solves)
- [Core guarantees](#core-guarantees)
- [Architecture overview](#architecture-overview)
- [Quick Demo](#quick-demo)
- [Audit Inspection](#audit-inspection)
- [Operational Guide](#operational-guide)
- [Quickstart (60s)](#quickstart-60s)
- [Quick demo (2 terminals)](#quick-demo-2-terminals)
- [Relay bridge (global mode)](#relay-bridge-global-mode)
- [Hybrid demo](#hybrid-demo)
- [P2P Protocol & Operations](#p2p-protocol--operations)
- [Testing commands](#testing-commands)
- [Security model](#security-model)
- [Audit and hashing](#audit-and-hashing)
  - [Basic](#basic)
  - [Deep Dive](#deep-dive)
- [Zig verifier](#zig-verifier)
- [Configuration reference](#configuration-reference)
- [Performance](#performance)
- [Advanced deployment (optional)](#advanced-deployment-optional)
- [Roadmap](#roadmap)
- [Troubleshooting](#troubleshooting)
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

## Quick Demo

For the fastest end-to-end walkthrough, run:

```bash
bash scripts/demo_decision_flow.sh
```

This demo executes the current verifiable path in one command:

`API -> engine decision -> trace -> audit record -> Zig verification`

Related docs:
- [`scripts/demo_decision_flow.sh`](scripts/demo_decision_flow.sh)
- [`scripts/demo_decision_flow_flagged.sh`](scripts/demo_decision_flow_flagged.sh)
- [`examples/basic_decision_flow.md`](examples/basic_decision_flow.md)
- [`examples/flagged_decision_flow.md`](examples/flagged_decision_flow.md)
- [`RELEASE_PLAN_v0.2.0.md`](RELEASE_PLAN_v0.2.0.md)

## Audit Inspection

To inspect the latest persisted audit artifact after a request or demo run:

```bash
bash scripts/inspect_audit_artifact.sh
```

This reads the latest record from `NEXO_AUDIT_PATH` or `logs/audit_records.jsonl`, prints the main audit fields, writes a single-artifact temporary `.jsonl`, and shows the exact Zig verification command for that artifact.

To find a past artifact by `request_id`, `audit_hash`, or `record_hash` across the active file and `logs/audit_archive/`:

```bash
bash scripts/find_audit_artifact.sh <request_id-or-hash>
```

For a compact runtime signal, `/api/state` also exposes the recent audit-chain status via:
- `audit_chain_status`
- `audit_chain_checked_records`
- `audit_chain_last_record_hash`
- `audit_chain_error`

## Operational Guide

For day-to-day operation of the current verification path, see:

- [`docs/OPERATIONAL_FLOW.md`](docs/OPERATIONAL_FLOW.md)
- [`docs/SECURITY_OPERATIONS.md`](docs/SECURITY_OPERATIONS.md)

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

## Quick demo (2 terminals)

Terminal A:

```bash
cargo run --features network --bin nexo_p2p -- chat --bind 127.0.0.1:9001 --peer 127.0.0.1:9002 --sender node_a --db /tmp/nexo_a.db
```

Terminal B:

```bash
cargo run --features network --bin nexo_p2p -- chat --bind 127.0.0.1:9002 --peer 127.0.0.1:9001 --sender node_b --db /tmp/nexo_b.db
```

Example session:
- Type `hello` on terminal A: terminal B prints `[node_a] hello`.
- Type `hello` again (same sender + nonce always changes): another event is inserted normally.
- Type `/last 5` to show recent persisted messages from local SQLite.
- Type `/id` to print current sender id and bind address.
- Type `/quit` to exit.

Dedup behavior:
- Received events are deduplicated by `event_hash`.
- Replayed packet with the same `event_hash` is treated as duplicate and not inserted twice.

Demo script (automated):

```bash
bash scripts/demo_p2p.sh
```

## Relay bridge (global mode)

Start relay:

```bash
cargo run --features network --bin nexo_relay -- --bind 127.0.0.1:9100 --db /tmp/nexo_relay.db
```

Relay API:
- `POST /push` with body `{"items":[SyncItem...]}` validates signature envelope and dedups by persisted `event_hash`.
- `GET /pull?since_ms=0&limit=200` returns items ordered by `timestamp_ms ASC` (deterministic).

Minimal calls:

```bash
curl -sS -X POST 'http://127.0.0.1:9100/push' \
  -H 'content-type: application/json' \
  --data '{"items":[]}'
curl -sS 'http://127.0.0.1:9100/pull?since_ms=0&limit=200'
```

Bridge mode (manual flow):
- Node A/B continues using `nexo_p2p` locally.
- Export signed events from one side and push to relay.
- Pull from relay on the other side and ingest through existing sync/event path.
- Dedup remains persistent by `event_hash` in both relay and local SQLite.
- Pull cursor is persisted in SQLite (`relay_state.last_relay_pull_since_ms`) to survive restarts.
- Relay HTTP errors use deterministic per-relay backoff (`1s -> 2s -> 4s ...` capped at `30s`, reset on success).
- `known_peers` received from relay are not trusted immediately: they enter a candidate queue and are promoted only after valid UDP observation.

## Hybrid demo

Run end-to-end local bridge (relay + two chat nodes):

```bash
bash scripts/demo_hybrid.sh
```

What it does:
- Starts `nexo_relay` on `127.0.0.1:19100`.
- Starts `node_a` and `node_b` in `chat --daemon` with `--relay`.
- Sends one `hello` message from a short `node_a` chat session.
- Validates node B pulled at least one event from relay (`relay_pull count>0`).

## P2P Protocol & Operations

### Supported CLI commands

- `listen` starts a UDP node and prints accepted events.
  - Use `--bind` to choose local UDP endpoint and `--db` for persistence.
  - Typical command:
    - `cargo run --features network --bin nexo_p2p -- listen --bind 127.0.0.1:9001 --db /tmp/nexo_a.db --sender node_a`
- `send` sends one signed event to a peer.
  - Example:
    - `cargo run --features network --bin nexo_p2p -- send --bind 127.0.0.1:9002 --peer 127.0.0.1:9001 --sender node_b --db /tmp/nexo_b.db --msg "hello"`
- `sync` pulls/pushes offline history using `SyncItem` frames.
  - Typical command:
    - `cargo run --features network --bin nexo_p2p -- sync --bind 127.0.0.1:9003 --peer 127.0.0.1:9001 --db /tmp/nexo_sync.db --since-ms 0`
- `discover` runs UDP peer discovery handshake.
  - Example:
    - `cargo run --features network --bin nexo_p2p -- discover --bind 0.0.0.0:9001 --broadcast 255.255.255.255:9001 --timeout-ms 800`
- `ai` stores deterministic AI-channel prompts and responses for deterministic analysis.
  - Example:
    - `cargo run --features network --bin nexo_p2p -- ai --sender node_a --db /tmp/nexo_a.db --msg "como reduzir risco de fraude"`

### SignedEvent contract

- `sender_id` (`String`): sender identifier.
- `timestamp_utc_ms` (`u64`): millisecond timestamp.
- `nonce` (`u64`): monotonic counter per sender persisted in SQLite.
- `content` (`String`): human payload for transport.
- `content_hash` (`String`): BLAKE3 digest of canonical bytes.
- `content_len` (`u8`): byte-size bound for validation.
- `event_hash` (`String`): canonical frame hash used for dedup and forwarding decisions.
- `sender_pubkey` (`Vec<u8, 32>`): Ed25519 public key identity.
- `signature` (`Vec<u8, 64>`): Ed25519 signature over framed bytes.
- `hops_remaining` (`u8`): forwarding hop budget, decremented on each relay-forward.
- `origin_event_hash` (`String`): immutable hash of the original origin event.
- `known_peers` (`Vec<String>`): up to bounded peers carried on forward.
- `content_encrypted` (`Option<Vec<u8>>`): optional encrypted payload when crypto is enabled.
- `crypto_nonce` (`Option<[u8; 24]>`): optional AEAD nonce separate from `nonce` (never reused).

Frame-level rules:
- Sequence is fixed and deterministic and is never reordered.
- ACK/retry:
  - Sender keeps the socket open with bounded retries.
- Replay and anti-loop:
  - Event is only accepted once by `event_hash`.
  - Forwarding stops when `hops_remaining == 0`.
  - Forwarded hashes are persisted and checked before any re-forward.

### ACK/retry, dedup and anti-loop

- ACK is required for successful send completion.
- Retry is deterministic and bounded by feature path.
- Replay dedup is enforced by persisted `seen_hashes`.
- Anti-loop is enforced by:
  - persisted `forwarded_hashes` table
  - `origin_event_hash` carrying origin
  - `hops_remaining` budget
  - candidate-peer promotion before trust elevation
- A valid event must pass verification before it is ever persisted or forwarded.

### SQLite persistence and guarantees

Core tables used by the P2P layer:

| Table | Role | Guarantee |
|---|---|---|
| `messages` | persisted event timeline | durable local store for global/ai flows; supports history queries |
| `seen_hashes` | `event_hash` replay index | duplicate replay rejection across process restarts |
| `forwarded_hashes` | anti-loop marker | prevents repeated forward cycles and loops |
| `relay_state` | relay cursor metadata | persists `last_relay_pull_since_ms` per DB and survives restart |
| `sender_counters` | monotonic nonce state | guarantees per-sender monotonic `nonce` |
| `node_identity` | Ed25519 keypair | persistent local identity, required for signature verification |

Operationally, listener paths must:
- consult `seen_hashes` before insert,
- persist via `INSERT OR IGNORE` and mark as seen only when accepted,
- write successful messages to `messages` and forwarding decisions to `forwarded_hashes` under success criteria.

### P2P security model

- All forwarded user payloads are fail-closed on verification:
  - `invalid_sig` is rejected and not persisted.
  - `decrypt_failed` (when crypto is enabled) is rejected and not persisted.
- Signature and optional decryption are evaluated before persistence and before forwarding.
- Relay candidate promotion:
  - peers observed from relay are put in a candidate queue first,
  - they are promoted to local known peers only after a valid UDP event/ACK evidence.
- Replay protection and anti-loop are enforced before business handling, so malformed or duplicate frames cannot be injected by timing.

### Operational limits and runtime behavior

- Human input hard limit is **32 bytes** (`UTF-8` bytes). Failures are explicit and fail-closed.
- Relay pull cursor is persisted.
  - On restart, chat continues from persisted `last_relay_pull_since_ms`.
  - Cursor updates only after verified, deduplicated inserts.
- Relay backoff is deterministic and bounded:
  - start `1000ms`, then `2000ms`, `4000ms`, doubling to max `30000ms`, reset on success.
- Network hardening defaults:
  - bounded peer list (deterministic ordering),
  - bounded peer count,
  - bounded known relay count.

## Testing commands

```bash
cargo test -q
cargo test --features network -q
julia --project=./julia julia/test/runtests.jl
cd tools/zig && zig build test
```

## Security model

- Request signing: HMAC-BLAKE3 over canonical request context (`x-key-id`, `x-request-id`, `x-timestamp`, body).
- Anti-replay: timestamp window + replay key tracking (in-memory; Redis optional for distributed mode).
- Rate-limit: per IP and per `user_id`.
- Duplicate critical header rejection: rejects ambiguous multi-header auth/replay fields.
- Admin gate (default off): `/audit/recent`, `/security/status`, `/metrics` require `NEXO_ADMIN_API_ENABLED=true` and valid `Authorization: Bearer <token>`.
- Redis guard operations have short timeout and fail-closed behavior.

### Chat mutation surface

- `POST /api/chat/send` is intended for the local dashboard UI only.
- The Rust endpoint is loopback-only at the API boundary.
- The Sinatra UI route is also loopback-only before it forwards to the core.
- The core only enables chat mutation when its P2P/network storage path is available.
- Remote clients cannot use this endpoint as a general chat API.
- The UI does not guess send capability; it reads the core signal from `/api/state`.

### Chat capability fields

`/api/state` exposes the chat mutation capability explicitly:

- `chat_send_available`: whether the core currently allows chat mutation.
- `chat_send_mode`: operational mode for chat send, e.g. `core` or `core_unavailable`.
- `chat_send_reason`: stable reason string when send is blocked or restricted.

These fields let the UI reflect the core truth directly instead of inferring capability from surrounding state.

### Julia observability layer

- Julia now also serves as a deterministic numerical observer over `/api/state`.
- The observer reads live Rust state, measures recent flow mix and intensity, and produces compact explainable summaries.
- Julia does not replace Rust decisions and does not participate in the write path.
- The observer can also emit a compact JSON artifact for UI consumers, analysis pipelines, and future distributed node observers.
- Observation artifacts can be persisted as historical windows and compared over time for simple regime hints.
- The Sinatra UI can read the latest Julia artifact if present and render a compact observation line in the existing Integrity surface.
- Example: `julia --project=./julia julia/observe_state.jl http://127.0.0.1:3000/api/state`
- Continuous loop: `julia --project=./julia julia/observe_loop.jl http://127.0.0.1:3000/api/state ./observations`
- Role split remains explicit: Rust decides, Julia observes, Ruby presents.

## UI modes

- `connected to core`
  - The dashboard is reading live state from Rust.
  - Chat send can succeed only if the core also reports chat capability as available.
- `offline local state`
  - The dashboard is reading local file/SQLite state without a writable core path.
  - Chat send is read-only in this mode.
- `offline mode`
  - The dashboard could not reach a real source and is showing fallback state.
  - This is not a writable core-backed mode.
- `demo mode`
  - Manual simulation is active in the UI layer.
  - Actions update demo state only and do not mutate the core.

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

## Troubleshooting

- `cargo run` reports multiple binaries:
  - Use explicit binary, e.g. `cargo run --bin syntax-engine` or `cargo run --features network --bin nexo_p2p -- chat ...`.
- API startup panic about missing HMAC secret:
  - Set `NEXO_HMAC_SECRET` (or `NEXO_HMAC_SECRET_FILE`) before running `syntax-engine`.

## Current status

- API endpoints:
  - `POST /evaluate`
  - `GET /healthz`
  - `GET /readyz`
  - `GET /metrics` (admin-gated)
  - `GET /audit/recent?limit=50` (admin-gated)
  - `GET /security/status` (admin-gated)
- Rule profiles include 9 jurisdictions/currencies/regulators.
- Rust tests: 213
- Julia tests: 126
- Zig tests: 21
- Total tests: 360
- Tech stack:
  - Rust (core engine + API)
  - BLAKE3 + SHAKE256 (audit hash, with deterministic hybrid mode in INCIDENT)
  - Axum + Tokio (HTTP)
  - serde/serde_json (contracts)
  - Julia bridge (precision PLCA scoring + flow observability)
  - Zig offline verifier (forensic audit hash check)

## License

MIT

NEXO is not a probabilistic AI compliance engine. It is a deterministic, auditable decision system designed for environments where reproducibility matters more than heuristics.
