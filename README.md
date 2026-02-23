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
| Night transaction > R$ 1.000 | BCB 150/2021 | Blocked (Grave) |
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
Running
git clone https://github.com/JoseSmurf/nexo-2026
cd nexo-2026
cargo run
cargo test
Tech stack
Rust — memory safe, zero-cost abstractions
BLAKE3 — cryptographic audit hash
serde — JSON serialization
No async in core, no float for money
Status
Core engine: stable
Rules: BCB + AML/FATF + KYC/PEP
API layer (HTTP): active
License
MIT

## API Endpoints

- `POST /evaluate`
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /audit/recent?limit=50`

Rule profiles (versioned, via env):

- `NEXO_PROFILE=br_default_v1` (default)
- `NEXO_PROFILE=us_default_v1`
- `NEXO_PROFILE=eu_default_v1`

## Security (HMAC + Anti-Replay + Key Rotation)

`POST /evaluate` now requires signed headers:

- `X-Signature`
- `X-Request-Id` (UUID v4)
- `X-Timestamp` (unix ms)
- `X-Key-Id`

Server validation order:

1. Signature validation with active key (`NEXO_HMAC_SECRET`)
2. Fallback validation with previous key (`NEXO_HMAC_SECRET_PREV`, optional)
3. Timestamp window check (60s)
4. Replay check in memory cache (DashMap, TTL 120s)

Status codes:

- `401` invalid/missing signature
- `408` expired timestamp window
- `409` replayed `X-Request-Id`

Required environment:

- `NEXO_HMAC_SECRET` (required, startup panic if missing)
- `NEXO_HMAC_SECRET_PREV` (optional rotation window)
- `NEXO_HMAC_KEY_ID` (optional, default `active`)
- `NEXO_HMAC_KEY_ID_PREV` (optional, default `previous`)

Rotation flow:

1. Deploy new active key in `NEXO_HMAC_SECRET`
2. Move previous active to `NEXO_HMAC_SECRET_PREV`
3. Update Julia `X-Key-Id` to the active key id
4. Remove previous key after clients are migrated

## Latency & Load

Run endpoint benchmarks:

```bash
cargo bench --bench engine_bench --bench http_bench
```

Run concurrent load test with p50/p95/p99:

```bash
cargo run --release --bin load_test
```

Enforce performance budget (also in CI):

```bash
cargo run --release --bin perf_budget
```

## Julia PLCA Bridge

There is a Julia bridge at `julia/plca_bridge.jl` that:
- computes PLCA score with `Rational{Int64}` and `BigFloat`
- converts to deterministic `risk_bps` (`0..9999`)
- signs payload with BLAKE3 (`Blake3Hash.jl`) and sends authenticated request headers

Quick run:

```bash
julia --project=./julia -e 'using Pkg; Pkg.instantiate()'
NEXO_HMAC_SECRET='change-me' cargo run
NEXO_HMAC_SECRET='change-me' julia --project=./julia julia/plca_bridge.jl
```
