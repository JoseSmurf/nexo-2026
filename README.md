NEXO 2026
Deterministic compliance engine for financial and high-risk systems.
NEXO 2026 is a decision engine where every result is explainable, reproducible, and cryptographically verifiable — not probabilistic.
Built in Rust. Designed for regulated environments.
Why this exists
Modern AI systems rely on probabilities. In regulated environments — finance, AML, KYC, LGPD — probability is not enough.
A compliance decision must be:
Deterministic — same input always produces the same output
Auditable — every decision has a cryptographic proof
Explainable — every block or flag has a human-readable reason
NEXO 2026 enforces this by design.
How it works
Input (TransactionIntent)
        ↓
[ Anti-replay validation ]
        ↓
[ Rule Engine ]
  ├─ UI integrity check
  ├─ Night limit (BCB)
  └─ AML / KYC / PEP rules
        ↓
[ Decision Trace ]
        ↓
[ BLAKE3 Audit Hash ]
        ↓
Output (FinalDecision + hash)
Rules implemented
Rule
Reference
Action
UI integrity failure
Internal
Blocked (Critica)
Night transaction limit > R$ 1.000
BCB Resolution 150/2021
Blocked (Grave)
PEP without active KYC
FATF / BCB
Blocked (Grave)
High risk + high amount (> R$ 50k, > 90% risk)
AML/FATF
Blocked (Critica)
High risk OR high amount
AML/FATF
Flagged (Alta)
Example
Input:
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
Output:
Final decision: Blocked
Trace:
  Approved                          ← UI ok
  Approved                          ← night limit ok
  Blocked { rule_id: "KYC-PEP-002", reason: "PEP without active KYC." }
Audit hash: 3f8a1c... (BLAKE3)
Anti-replay protection
Every transaction is validated against a 5-minute server time window.
timestamp too far in future → REJECTED: future timestamp
timestamp too old           → REJECTED: replay detected
Tech stack
Rust — memory safe, zero-cost abstractions
BLAKE3 — cryptographic audit hash
serde — JSON serialization for API layer
No runtime, no async in core, no float for money
Project structure
nexo-2026/
├─ Cargo.toml
├─ README.md
└─ src/
   ├─ lib.rs   ← core engine (deterministic, pure)
   └─ main.rs  ← demo
Running
git clone https://github.com/JoseSmurf/nexo-2026
cd nexo-2026
cargo run
cargo test
Status
Core engine: stable
Rules: BCB + AML/FATF + KYC/PEP
Audit hash: BLAKE3 (trace_v4)
API layer (HTTP): planned
License
MIT
