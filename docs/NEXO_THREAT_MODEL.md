# NEXO Threat Model

## Purpose

This document models threats against the current central path of NEXO:

signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification

It is intentionally narrow and focused on the repository center that reviewers can inspect today.

## Scope

In scope:

- signed request intake
- API auth/security checks
- deterministic Rust decision
- trace and final_decision semantics
- audit artifact persistence
- audit hash and record hash
- offline Zig verification

Out of scope:

- global truth
- consensus
- CRDT/runtime sync
- Bitcoin mining/profitability/PoW/ASIC claims
- AI judgment
- proving that external real-world facts are true

## Trust Boundaries

- client/request boundary
- API security boundary
- Rust deterministic decision boundary
- audit persistence boundary
- offline verifier boundary
- UI/observer boundary
- experimental tracks boundary

## Threats And Controls

| Threat | Risk | Existing Control | Evidence / Files | Remaining Risk |
| --- | --- | --- | --- | --- |
| unsigned or forged request | unauthorized decision request accepted | HMAC validation, key id validation, fail-closed auth path | `src/api/auth.rs`, `src/api.rs` | key compromise or bad secret handling outside the repo |
| duplicate or ambiguous auth headers | header confusion or auth bypass | duplicate auth headers rejected explicitly | `src/api/auth.rs` | proxy/header normalization mistakes outside app boundary |
| spoofed forwarded identity headers | rate-limit evasion or misleading operator attribution | proxy headers not trusted by default; optional trusted-proxy mode gated by `NEXO_TRUST_PROXY_HEADERS` | `src/api.rs`, `docs/SECURITY_OPERATIONS.md` | requires correct ingress posture (service must not be directly reachable; proxy must sanitize forwarded headers) |
| replayed request | repeated execution of old signed request | request id replay cache, optional distributed replay guard | `src/api/auth.rs`, `src/api/replay.rs`, `src/api.rs` | replay window depends on correct deployment and storage posture |
| stale timestamp | delayed request accepted as fresh | bounded timestamp window, request timeout rejection | `src/api/auth.rs`, `src/api.rs` | clock drift between clients and server |
| abusive request volume | service degradation or abuse | rate limiting, optional distributed rate limiting | `src/api/rate_limit.rs`, `src/api.rs` | edge posture and deployment tuning still matter |
| decision drift | same input produces different result | deterministic evaluate path, fixed rule order, tests | `src/engine/evaluate.rs`, `tests/engine_boundaries.rs` | careless future refactors can still break determinism |
| trace reordering | forensic hash mismatch or semantic drift | fixed trace order contract, hash framing tied to ordered semantics | `src/engine/evaluate.rs`, `src/audit/hash.rs`, `tools/zig/src/verify.zig` | any casual reordering is breaking and must be reviewed |
| audit hash tampering | modified trace accepted as original | independent recomputation of `audit_hash` in Zig | `src/audit/hash.rs`, `tools/zig/src/verify.zig` | only detectable if artifacts are actually re-verified |
| audit record tampering | altered persisted record appears valid | `record_hash` recomputation over persisted fields | `src/audit/record.rs`, `src/audit_store.rs` | records outside protected storage can still be edited before review |
| broken record chain | deletion or continuity break in audit log | `prev_record_hash` and `record_hash` chain, state exposure and inspection path | `src/audit_store.rs`, `docs/OPERATIONAL_FLOW.md`, `src/api/state.rs` | partial file loss or archive mishandling remains possible |
| runtime/process compromise after artifact creation | live process untrusted after decision emission | offline verifier checks persisted artifact independently of runtime | `tools/zig/src/verify.zig`, `docs/NEXO_ARCHITECTURE_EVIDENCE.md` | does not prove runtime was never compromised before persistence |
| UI misrepresenting authority | operators trust presentation more than core evidence | Interface V0 keeps core center explicit and labels secondary context | `nexo_ui/views/index.erb`, `docs/NEXO_REVIEWER_START_HERE.md` | UI wording can still drift if not reviewed carefully |
| Julia being treated as decision authority | observer surface mistaken for trust core | Julia documented as secondary and non-authoritative | `docs/NEXO_REVIEWER_START_HERE.md`, `docs/NEXO_ARCHITECTURE_EVIDENCE.md` | humans can still overread observer output |
| Witness being treated as global truth | local evidence mistaken for universal authority | Witness docs explicitly deny global truth semantics | `README.md`, `docs/NEXO_WITNESS_LAYER.md` | documentation drift or superficial reading |
| Bitcoin experiment being treated as product center | research track mistaken for product claim | reviewer/docs non-claims, explicit experimental framing | `docs/NEXO_REVIEWER_START_HERE.md`, `docs/NEXO_ARCHITECTURE_EVIDENCE.md` | narrative confusion if experimental docs are read in isolation |

## Fail-Closed Posture

NEXO should reject instead of guess when it encounters:

- invalid/missing auth context
- replay conflict
- expired/stale timestamp
- rate-limit breach
- unsupported verifier/hash contract
- malformed audit artifact

This posture matters because the repository center is about reproducible evidence, not permissive inference.

## What The Threat Model Proves

- NEXO reduces ambiguity in sensitive decision review.
- NEXO makes decision evidence inspectable.
- NEXO supports independent offline verification.
- NEXO helps detect tampering or contract drift.

## What The Threat Model Does Not Prove

- It does not prove external facts are true.
- It does not prove global consensus.
- It does not prove the runtime was never compromised.
- It does not prove Bitcoin profitability or mining advantage.
- It does not make UI, Julia, Witness, mesh, or Bitcoin authoritative.

## Reviewer Checklist

- inspect auth path
- inspect replay/rate-limit behavior
- inspect deterministic evaluate
- inspect trace/hash contract
- inspect audit record chain
- inspect Zig verifier
- run demo and verify artifact offline

## Summary

NEXO is strongest when threats are modeled around its actual center rather than around imagined platform scope.
Its main control surface is fail-closed request validation plus deterministic decision evidence.
Its main review surface is the trace, the hash contract, and the persisted record chain.
Its strongest independent check is the offline Zig verifier.
This does not create global truth or consensus.
It creates a narrower, more inspectable decision system with better tamper visibility and lower ambiguity in review.
