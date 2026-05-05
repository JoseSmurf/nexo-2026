# NEXO Test Matrix

## 1. Purpose

This document maps **existing** tests and validation checks to the **central NEXO contracts**.
It is a reviewer-oriented matrix: it shows what surfaces exist today, what they protect, and how failures should be interpreted.

It does **not** claim exhaustive coverage. Anything not defensible from the referenced files is marked as **not asserted here**.

## 2. Test Center

signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification

## 3. Test Matrix

| Area | Contract Protected | Evidence / Files | Validation Command | What Failure Means |
| --- | --- | --- | --- | --- |
| Rust deterministic engine | Deterministic evaluation for identical valid input | `src/engine/evaluate.rs` | `cargo test -q evaluate_reproducible_for_identical_input` | Core decision drift risk (same input may not yield same decision/trace). |
| final_decision semantics | Approved vs Flagged vs Blocked classification remains stable | `src/engine/evaluate.rs` | Run individually: `cargo test -q aml_trace_contract_approved` / `..._flagged` / `..._blocked` | Decision semantics changed (operator meaning of outcomes may have drifted). |
| trace ordering | Trace step order/index/rule ids stay stable (forensic relevance) | `src/engine/evaluate.rs` | `cargo test -q decision_trace_contract_is_stable_golden` | Trace contract drift; downstream hashes/verifier expectations may break. |
| Engine boundary hygiene | Engine avoids non-deterministic / forbidden dependencies | `tests/engine_boundaries.rs`, `.github/workflows/rust.yml` (engine_boundaries job) | `cargo test -q engine_modules_do_not_import_or_use_forbidden_dependencies` | Determinism boundary at risk (forbidden imports in `src/engine/`). |
| audit_hash contract | Semantic trace hashing framing (`trace_v4`) is stable | `src/audit/hash.rs` | Run individually: `cargo test -q semantic_trace_hash_is_stable_for_known_blake3_input` / `...equal_semantic_traces_produce_equal_hashes` | Audit hash contract drift; offline verification may reject artifacts. |
| audit record schema | Persisted `AuditRecord` shape and defaults remain compatible | `src/audit_store.rs` | `cargo test -q` (not asserted here: a single named schema test) | JSONL artifacts may become unreadable or incompatible with verifier/inspection tools. |
| record chain semantics | `prev_record_hash` / `record_hash` chaining stays intact | `src/audit_store.rs`, `src/audit/record.rs` | Run individually: `cargo test -q append_adds_chain_fields` / `...compute_record_hash_is_stable_for_known_input` | Tamper/continuity detection weakens; archive integrity assumptions may break. |
| API auth/HMAC | Fail-closed header validation, signature verification, key-id policy | `src/api/auth.rs`, `src/api.rs` | Run individually: `cargo test -q request_without_signature_returns_401` / `...request_with_wrong_signature_returns_401` / `...duplicate_x_signature_header_is_rejected` / `...duplicate_x_request_id_header_is_rejected` | Signed request boundary may accept ambiguous/forged input or lose fail-closed posture. |
| `/evaluate` HTTP body/content-type boundary | `/evaluate` enforces a bounded body and strict JSON content-type gate | `src/api.rs` | Run individually: `cargo test -q oversized_body_is_rejected_before_auth_validation` / `...missing_content_type_returns_415` / `...non_json_content_type_returns_415` / `...duplicate_content_type_returns_415` / `...application_json_with_charset_is_accepted` | Oversized or ambiguous payloads may reach deeper security/decision paths unexpectedly. |
| replay protection | Request-id reuse is rejected (conflict) | `src/api/replay.rs`, `src/api.rs` | `cargo test -q request_id_reused_returns_409` | Same signed request may be replayed; audit trail may include duplicated decisions. |
| timestamp window / freshness gate | Stale timestamps are rejected (timeout) | `src/api/auth.rs`, `src/api.rs` | `cargo test -q request_with_expired_timestamp_returns_408` | Time window enforcement drift; replay/latency assumptions weaken. |
| rate limiting / fail-closed behavior | Rate limiting exists and is intended to fail closed under configured posture | `src/api/rate_limit.rs`, `src/api.rs` | `cargo test` (not asserted here: dedicated 429 test) | Abuse control may be ineffective or drift silently; operational risk increases. |
| offline Zig verifier | Independent offline re-validation of schema + hashes + trace contract | `tools/zig/src/verify.zig`, `tools/zig/src/schema.zig`, `.github/workflows/rust.yml` (build job) | `cd tools/zig && zig build test` and `zig build run -- verify ../../fixtures/audit_sample.jsonl` and `zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl` | Independent verification breaks; reviewers must trust runtime without offline evidence. |
| Ruby Interface V0 surface | UI preserves core-first hierarchy and non-claims; status contract keys exist | `nexo_ui/app.rb`, `nexo_ui/views/index.erb`, `nexo_ui/test/app_surface_test.rb` | `ruby nexo_ui/test/app_surface_test.rb` (not asserted here: CI coverage) | UI may mislead operators about authority/hierarchy; core visibility may regress. |
| Julia observer tests | Observer remains deterministic/secondary; bridge integration checks basic API contract | `julia/test/runtests.jl`, `julia/test_flow_observer.jl`, `julia/test_integration.jl`, `.github/workflows/rust.yml` (build + docs_consistency) | `julia --project=./julia julia/test/runtests.jl` and `julia --project=./julia julia/test_integration.jl` | Observer expectations drift or integration assumptions break; does not imply Rust trust-core drift by itself. |
| README/docs consistency | README test counters and hash-line invariants match repo reality | `scripts/check_readme_consistency.sh`, `.github/workflows/rust.yml` (docs_consistency job) | `bash scripts/check_readme_consistency.sh` | Documentation mismatch or stale counters; reviewer guidance becomes unreliable. |
| CI workflow | The canonical CI validation set is the workflow definition | `.github/workflows/rust.yml` | not asserted here (CI-defined) | CI drift may remove intended guardrails; repo may lose enforced checks. |

Notes:
`cargo test --features network` is also exercised by CI for selected determinism tests (see `.github/workflows/rust.yml`).

## 4. Core Validation Commands

Only commands defensible from the current repository surfaces are listed here.

- `cargo test`
- `cargo test --features network`
- `cargo test -q engine_modules_do_not_import_or_use_forbidden_dependencies`
- Run the CI determinism/trace-contract set (same pattern used in `.github/workflows/rust.yml` engine_boundaries job):<br>`for t in aml_trace_contract_approved aml_trace_contract_flagged aml_trace_contract_blocked decision_trace_contract_is_stable_golden evaluate_reproducible_for_identical_input; do cargo test -q \"$t\"; done`
- Same, with network feature (CI: engine_boundaries job):<br>`for t in aml_trace_contract_approved aml_trace_contract_flagged aml_trace_contract_blocked decision_trace_contract_is_stable_golden evaluate_reproducible_for_identical_input; do cargo test --features network -q \"$t\"; done`
- `cargo fmt --check` (CI: fmt job)
- `cargo clippy --all-targets --all-features -- -D warnings` (CI: clippy job)
- `cargo deny check` (CI: security job)
- `bash scripts/check_readme_consistency.sh` (CI: docs_consistency job)
- `cd tools/zig && zig build test` (CI: build job)
- `cd tools/zig && zig build run -- verify ../../fixtures/audit_sample.jsonl` (CI: build job)
- `julia --project=./julia julia/test/runtests.jl` (CI: build + docs_consistency prerequisites)
- `julia --project=./julia julia/test_integration.jl` (CI: build job)
- `ruby nexo_ui/test/app_surface_test.rb` (not asserted here: CI coverage)
- `ruby nexo_ui/test/core_adapter_test.rb` (not asserted here: CI coverage)
- `ruby nexo_ui/test/app_config_test.rb` (not asserted here: CI coverage)

## 5. What The Matrix Proves

- Deterministic rules have explicit test surfaces (`src/engine/evaluate.rs`, `tests/engine_boundaries.rs`).
- Trace ordering and audit hashing have concrete validation surfaces (Rust tests + Zig verifier).
- Persisted artifacts have an independent offline check path (`tools/zig/src/` + CI Zig verification step).
- UI (Ruby) and observer (Julia) are secondary surfaces: their tests should not be treated as redefining the Rust trust core.
- README/docs consistency has an explicit repo check (`scripts/check_readme_consistency.sh`) and CI enforcement.

## 6. What The Matrix Does Not Prove

- It does not prove global truth.
- It does not prove external real-world facts are true.
- It does not prove consensus.
- It does not prove Bitcoin mining/profitability/PoW/ASIC advantage.
- It does not prove every deployment environment is safe.
- It does not make UI, Julia, Witness, mesh, or Bitcoin authoritative.

## 7. Reviewer Checklist

- Run Rust tests (at minimum: the determinism/trace-contract tests used by CI).
- Run Zig verifier tests and verify a known artifact fixture offline.
- Run README/docs consistency check.
- If reviewing Interface V0: run the Ruby UI tests (secondary surface).
- If reviewing observer surfaces: run Julia tests (observer) and (optionally) the Julia integration test.
- If auditing end-to-end behavior: run the demo flow and verify the emitted artifact offline (see `README.md` and `docs/OPERATIONAL_FLOW.md`). (not asserted here: demo stability across all host environments)

## 8. Gaps / Not Asserted Here

- No claim of exhaustive or formal verification coverage.
- No claim that rate limiting is covered by a dedicated unit test asserting a 429 path.
- No claim that Ruby UI tests are executed in CI.
- No claim that the test suite proves external facts, real-world identity, or correctness of upstream data.
- No claim that experimental tracks (mesh, Witness, Bitcoin experiment, `decision_cycle`) are part of the product center.

## 9. Summary

This matrix is a contract map, not a coverage claim.
The strongest validated surfaces cluster around determinism, trace ordering, and audit hashing.
The independent Zig verifier is the key offline check for persisted decision evidence.
API auth/replay/timestamp gates are part of the central fail-closed posture and have explicit tests.
Secondary surfaces (Ruby UI, Julia observer) have tests but must remain non-authoritative.
Docs consistency is enforced by a repository script and CI.
If a protected contract changes, reviewers should require corresponding validation evidence.
