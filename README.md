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
API layer (HTTP): planned
License
MIT
