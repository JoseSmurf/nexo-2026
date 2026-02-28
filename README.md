# NEXO 2026

> Deterministic compliance engine for financial and high-risk systems.

NEXO 2026 is a decision engine where every result is **explainable, reproducible, and cryptographically verifiable** — not probabilistic.

Built in Rust. Designed for regulated environments.

---

## Why this exists

Modern AI systems rely on probabilities. In regulated environments — finance, AML, KYC, LGPD — probability is not enough.

A compliance decision must be:
- **Deterministic** — same input always produces the same output
- **Auditable** — every decision has a cryptographic proof
- **Explainable** — every block or flag has a human-readable reason

NEXO 2026 enforces this by design.

---

## How it works

1. Input validation (anti-replay + integrity)
2. Rule engine (UI + Night limit + AML/KYC/PEP)
3. Decision trace generation
4. BLAKE3 cryptographic audit hash
5. Output (FinalDecision + hash)

---

## Rules implemented

| Rule | Reference | Action |
|------|-----------|--------|
| UI integrity failure | Internal | Blocked (Critica) |
| Night transaction > profile limit | BCB / FinCEN / EBA-AMLD | Blocked (Grave) |
| PEP without active KYC | FATF / BCB | Blocked (Grave) |
| High risk + high amount | AML/FATF | Blocked (Critica) |
| High risk OR high amount | AML/FATF | Flagged (Alta) |

---

## Example

```rust
let tx = TransactionIntent::new(
    "user_pep",
    150_000,   // R$ 1.500,00
    true,      // is_pep
    false,     // has_active_kyc (missing!)
    timestamp,
    server_time,
    4_500,     // 45% risk
    true,
).unwrap();

let (decision, trace, hash) = evaluate(&tx);
// Final decision: Blocked
// rule_id: "KYC-PEP-002"
// reason: "PEP without active KYC."
```

## Quickstart em 60s

```bash
git clone https://github.com/JoseSmurf/nexo-2026
cd nexo-2026

# Required env for signed /evaluate requests
export NEXO_HMAC_SECRET='dev-secret'
export NEXO_HMAC_KEY_ID='active'

# Profile examples
export NEXO_PROFILE='jp_default_v1'
# export NEXO_PROFILE='gb_default_v1'

# Terminal 1: run API
cargo run --bin syntax-engine
```

```bash
# Terminal 2: run tests
cd nexo-2026
cargo test -q
```

```bash
# Terminal 2: real signed call to /evaluate with curl
cd nexo-2026
REQ_ID="$(cat /proc/sys/kernel/random/uuid)"
TS="$(date +%s%3N)"
BODY="$(printf '{"user_id":"quickstart_user","amount_cents":150000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":%s,"risk_bps":1200,"ui_hash_valid":true,"request_id":"%s"}' "$TS" "$REQ_ID")"
SIG="$(cargo run --quiet --bin sign_request -- "$NEXO_HMAC_SECRET" "$NEXO_HMAC_KEY_ID" "$REQ_ID" "$TS" "$BODY")"

curl -sS -X POST 'http://127.0.0.1:3000/evaluate' \
  -H 'content-type: application/json' \
  -H "x-signature: $SIG" \
  -H "x-request-id: $REQ_ID" \
  -H "x-timestamp: $TS" \
  -H "x-key-id: $NEXO_HMAC_KEY_ID" \
  --data "$BODY"
```

## Tech stack

- Rust (core engine + API)
- BLAKE3 (audit + signatures)
- Axum + Tokio (HTTP)
- serde/serde_json (contracts)
- Julia bridge (precision PLCA scoring)
- Zig offline verifier (forensic audit hash check)

## Status

- Core engine: stable
- Rules: BCB + AML/FATF + KYC/PEP
- API layer: implemented and active (`POST /evaluate`, health, metrics, audit, security)
- Security layer: HMAC-BLAKE3, anti-replay, key rotation, rate limit
- Offline verification: Zig verifier in CI
- Rust tests: 81
- Julia tests: 118
- Zig tests: 10
- Total tests: 209
- Jurisdictions covered: 9
- Currencies covered: 9
- Regulators covered: 9

## License

MIT

## API Endpoints

- `POST /evaluate`
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /audit/recent?limit=50`
- `GET /security/status`

## Audit Contract (Fixed Schema)

`logs/audit_records.jsonl` uses one JSON object per line with this exact schema:

```json
{
  "request_id": "uuid-v4",
  "calc_version": "string|null",
  "profile_name": "string",
  "profile_version": "string",
  "timestamp_utc_ms": 1771845406862,
  "user_id": "string",
  "amount_cents": 150000,
  "risk_bps": 9999,
  "final_decision": "Approved|Flagged|Blocked",
  "trace": [
    "Approved",
    {
      "FlaggedForReview": {
        "rule_id": "string",
        "reason": "string",
        "severity": "Baixa|Alta|Grave|Critica",
        "measured": 150000,
        "threshold": 5000000
      }
    },
    {
      "Blocked": {
        "rule_id": "string",
        "reason": "string",
        "severity": "Baixa|Alta|Grave|Critica",
        "measured": 1,
        "threshold": 0
      }
    }
  ],
  "audit_hash": "64-char-lowercase-hex-blake3",
  "hash_algo": "blake3"
}
```

`audit_hash` is computed from `trace` only, with fixed domain tag `schema=trace_v4`:

1. `hash_field("schema", "trace_v4")`
2. For each trace entry:
3. `"Approved"` => `hash_field("D:A", "")`
4. `"FlaggedForReview"` => `hash_field("D:F", rule_id)`, `hash_field("R", reason)`, `severity_rank (u8)`, `measured (u64 LE)`, `threshold (u64 LE)`
5. `"Blocked"` => `hash_field("D:B", rule_id)`, `hash_field("R", reason)`, `severity_rank (u8)`, `measured (u64 LE)`, `threshold (u64 LE)`

`hash_field(tag, data)` format:

- `u32_le(tag_len)` + `tag_bytes`
- `u32_le(data_len)` + `data_bytes`

Severity rank mapping:

- `Baixa=0`, `Alta=1`, `Grave=2`, `Critica=3`

Rule profiles (versioned, via env):

| Profile | Country | Currency | Regulator | Timezone | Night Window | Night Limit |
|---|---|---|---|---|---|---|
| br_default_v1 | Brazil | BRL | BCB | UTC-3 | 20h-6h | R$ 1.000,00 |
| us_default_v1 | USA | USD | FinCEN | UTC-5 | 23h-5h | R$ 5.000,00 |
| eu_default_v1 | Europe | EUR | EBA | UTC+1 | 22h-6h | R$ 3.000,00 |
| cn_default_v1 | China | CNY | PBOC | UTC+8 | 23h-5h | R$ 4.000,00 |
| ae_default_v1 | UAE | AED | CBUAE | UTC+4 | 22h-6h | R$ 3.000,00 |
| in_default_v1 | India | INR | RBI | UTC+5:30 | 22h-6h | R$ 2.000,00 |
| jp_default_v1 | Japan | JPY | FSA | UTC+9 | 23h-5h | R$ 4.500,00 |
| gb_default_v1 | UK | GBP | FCA | UTC+0 | 22h-6h | R$ 3.500,00 |
| kr_default_v1 | South Korea | KRW | FSC | UTC+9 | 23h-5h | R$ 3.800,00 |

## Security (Formal HMAC-BLAKE3 + Anti-Replay + Rotation + Rate Limit)

`POST /evaluate` now requires signed headers:

- `X-Signature`
- `X-Request-Id` (UUID v4)
- `X-Timestamp` (unix ms)
- `X-Key-Id`

Server validation order:

1. Strict `X-Key-Id` check (must match active or previous id)
2. Formal HMAC-BLAKE3 verification (timing-safe compare)
3. Timestamp window check (default 60s)
4. Replay check in-memory (DashMap TTL cache, default 120s)
5. Rate limit check (per IP and per `user_id`)

Status codes:

- `401` invalid/missing signature
- `408` expired timestamp window
- `409` replayed `X-Request-Id`
- `429` rate limit exceeded

Required environment:

- `NEXO_HMAC_SECRET` (required, startup panic if missing)
- `NEXO_HMAC_SECRET_PREV` (optional rotation window)
- `NEXO_HMAC_KEY_ID` (optional, default `active`)
- `NEXO_HMAC_KEY_ID_PREV` (optional, default `previous`)
- `NEXO_AUDIT_PATH` (optional, default `logs/audit_records.jsonl`)
- `NEXO_AUDIT_RETENTION` (optional, default `5000`)
- `NEXO_AUTH_WINDOW_MS` (optional, default `60000`)
- `NEXO_REPLAY_TTL_MS` (optional, default `120000`)
- `NEXO_REPLAY_MAX_KEYS` (optional, default `100000`)
- `NEXO_RATE_LIMIT_WINDOW_MS` (optional, default `60000`)
- `NEXO_RATE_LIMIT_IP` (optional, default `600`)
- `NEXO_RATE_LIMIT_USER` (optional, default `300`)

Rotation flow:

1. Deploy new active key in `NEXO_HMAC_SECRET`
2. Move previous active to `NEXO_HMAC_SECRET_PREV`
3. Update Julia `X-Key-Id` to the active key id
4. Remove previous key after clients are migrated

Response authenticity:

- `X-Response-Signature`
- `X-Response-Key-Id`

## Latency & Load

Run endpoint benchmarks:

```bash
cargo bench --bench engine_bench --bench http_bench --bench security_bench
```

Run concurrent load test with p50/p95/p99:

```bash
cargo run --release --bin load_test
```

CI load gate example:

```bash
NEXO_LOAD_REQUESTS=600 \
NEXO_LOAD_CONCURRENCY=60 \
NEXO_LOAD_MAX_P95_US=400 \
NEXO_LOAD_MAX_P99_US=1200 \
cargo run --release --bin load_test
```

Enforce performance budget (also in CI):

```bash
cargo run --release --bin perf_budget
```

## Offline Audit Verification (Zig)

Offline verifier (no Rust runtime, no HTTP, no hot path dependency):

```bash
# Build and run Zig verifier tests
cd tools/zig
zig build test

# Verify full runtime file (returns non-zero on failure)
zig build run -- verify ../../logs/audit_records.jsonl

# Verify pinned fixture used in CI
zig build run -- verify ../../fixtures/audit_sample.jsonl
```

Expected output includes:

- `verify: total=... ok=... schema_invalid=... tampering=...`

CI runs this verifier with Zig pinned to `0.11.0`.

Compatibility note:

- `tools/zig/audit_verify.zig` remains as a wrapper entrypoint for direct `zig run` execution.

## Julia PLCA Bridge

There is a Julia bridge at `julia/plca_bridge.jl` that:
- computes PLCA score with `Rational{Int64}` and `BigFloat`
- converts to deterministic `risk_bps` (`0..9999`)
- signs payload with formal HMAC-BLAKE3 (`Blake3Hash.jl`) and sends authenticated request headers

Quick run:

```bash
julia --project=./julia -e 'using Pkg; Pkg.instantiate()'
NEXO_HMAC_SECRET='change-me' cargo run --bin syntax-engine
NEXO_HMAC_SECRET='change-me' julia --project=./julia julia/plca_bridge.jl
```
