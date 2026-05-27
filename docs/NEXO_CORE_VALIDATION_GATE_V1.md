# NEXO Core Validation Gate v1

## Status and Scope

This document records the official Core Validation Gate v1 for NEXO Core.
It consolidates current validation posture; it does not change CI, runtime behavior, tests, scripts, or language implementations.

Core Validation Gate v1 applies to the current center path and its validation-adjacent surfaces.
It does not promote Ruby, Julia, relay, Mesh/P2P, Witness, Bitcoin, or future IA surfaces into the trust core.

Related documents:

- [Test Matrix](NEXO_TEST_MATRIX.md)
- [Production Hostile Baseline v1](NEXO_PRODUCTION_HOSTILE_BASELINE_V1.md)
- [Public Exposure Policy v1](NEXO_PUBLIC_EXPOSURE_POLICY_V1.md)
- [Audit Contract Baseline v1](NEXO_AUDIT_CONTRACT_BASELINE_V1.md)
- [Policy/Profile Provenance Contract v1](NEXO_POLICY_PROFILE_PROVENANCE_CONTRACT_V1.md)
- [Reproducibility Report](NEXO_REPRODUCIBILITY_REPORT.md)
- [Security Operations](SECURITY_OPERATIONS.md)

## What Core Validation Gate v1 Means

Core Validation Gate v1 defines the checks a reviewer or operator should use to decide whether the current NEXO Core contracts are still intact.

It is a validation gate, not a formal proof system.
It does not claim universal production readiness, consensus, global truth, full-input replay, or full policy/config cryptographic binding.

## Center Path

The current product center is:

```text
signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> record chain -> offline Zig verification
```

## Trust Boundaries

- Rust decides and writes the primary audit artifact.
- Zig verifies persisted artifacts offline.
- Ruby presents.
- Julia observes.
- Relay/P2P/Mesh/Witness/Bitcoin are live edges or experiments, not authority.
- Future IA may observe or analyze, but must not decide under this gate.

## Gate Levels Overview

| Gate | Purpose | Typical use |
| --- | --- | --- |
| Fast Local Gate | Fast trust-core feedback before review or commit. | Local development and narrow patches. |
| Core CI Gate | Current required CI validation set. | Push/PR validation. |
| Hostile Baseline Gate | Stronger local/reviewer gate for hostile-baseline promotion. | Security/release review. |
| Release / Checkpoint Gate | End-to-end smoke and artifact verification evidence. | Release checkpoint or reviewer demo. |
| Manual / Staging Gate | Deployment-like smoke for edge security controls. | Manual staging workflow. |

## Fast Local Gate

Use this gate for narrow local changes that touch the Rust trust core, docs counters, supply-chain posture, or audit verifier expectations:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -q api
cargo test -q profile
cargo test -q audit_store
cargo test -q audit_chain
cargo test -q replay
bash scripts/check_readme_consistency.sh
bash scripts/check_supply_chain_surface.sh
cd tools/zig && zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl
```

For docs-only changes, run only docs-safe checks unless the change claims or alters validation behavior.
Do not claim code validation that was not actually run.

## Core CI Gate

The current CI gate is defined by `.github/workflows/rust.yml`.
Its effective validation set includes:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --verbose
cargo test --features network --verbose
bash scripts/check_readme_consistency.sh
bash scripts/check_supply_chain_surface.sh
cargo deny check
cd tools/zig && zig build test
cd tools/zig && zig build run -- verify ../../fixtures/audit_sample.jsonl
cd tools/zig && zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl
julia --project=./julia julia/test/runtests.jl
julia --project=./julia julia/test_integration.jl
```

CI also runs engine-boundary checks and selected determinism/trace-contract tests in both normal and `network` feature modes.
CI verifies a Rust-generated audit fixture with Zig.

## Hostile Baseline Gate

Use this gate for hostile-baseline review, security-sensitive changes, or release promotion:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -q
cargo test --features network -q
bash scripts/check_readme_consistency.sh
bash scripts/check_supply_chain_surface.sh
cargo deny check
cd tools/zig && zig build test
cd tools/zig && zig build run -- verify ../../fixtures/audit_sample.jsonl
cd tools/zig && zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl
julia --project=./julia julia/test/runtests.jl
julia --project=./julia julia/test_integration.jl
```

If Ruby/UI surfaces are part of the hostile review or release scope, add:

```bash
ruby nexo_ui/test/app_surface_test.rb
ruby nexo_ui/test/core_adapter_test.rb
ruby nexo_ui/test/app_config_test.rb
```

## Single-Command Local Gate Helpers

When operators want one command that runs the full local release gate sequence:

```bash
bash scripts/run_release_gate.sh
```

On Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_release_gate.ps1
```

These wrappers execute the same required classes of checks (format, lint, tests, docs consistency, supply-chain checks, and offline verifier checks) and are intended to reduce operator drift.

## Release / Checkpoint Gate

Use this gate to produce reviewer-facing smoke evidence and offline artifact verification:

```bash
bash scripts/demo_decision_flow.sh
bash scripts/demo_decision_flow_flagged.sh
bash scripts/demo_record_chain_verification.sh
bash scripts/inspect_audit_artifact.sh <artifact.jsonl>
cd tools/zig && zig build run -- verify --require-chain <artifact.jsonl>
```

These commands are release/checkpoint evidence.
They are not a substitute for the Core CI Gate.

## Manual / Staging Gate

The staging security workflow is manual:

```text
.github/workflows/staging-security.yml via workflow_dispatch
```

It validates a staging mTLS + HMAC + Ed25519 smoke path.
Bench/load checks are push/manual or release evidence, not a universal PR gate.

## Required Commands

Core Validation Gate v1 requires the following classes of checks:

| Check class | Required surface |
| --- | --- |
| Rust format | `cargo fmt --check` |
| Rust lint | `cargo clippy --all-targets --all-features -- -D warnings` |
| Rust tests | full Rust test suite |
| Network-feature Rust tests | `cargo test --features network` |
| README/docs consistency | `bash scripts/check_readme_consistency.sh` |
| Supply-chain surface guard | `bash scripts/check_supply_chain_surface.sh` |
| Dependency policy | `cargo deny check` |
| Zig unit tests | `cd tools/zig && zig build test` |
| Zig base fixture verification | `zig build run -- verify ../../fixtures/audit_sample.jsonl` |
| Zig chain fixture verification | `zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl` |
| Julia unit tests | `julia --project=./julia julia/test/runtests.jl` |
| Julia integration tests | `julia --project=./julia julia/test_integration.jl` |

## Optional / Manual Commands

These commands are optional/manual unless the touched surface or release scope makes them required:

| Command | Classification |
| --- | --- |
| `ruby nexo_ui/test/app_surface_test.rb` | Required when Ruby UI surface is touched; otherwise manual. |
| `ruby nexo_ui/test/core_adapter_test.rb` | Required when Ruby UI adapter behavior is touched; otherwise manual. |
| `ruby nexo_ui/test/app_config_test.rb` | Required when Ruby UI config/bind behavior is touched; otherwise manual. |
| `bash scripts/demo_decision_flow.sh` | Release/checkpoint smoke. |
| `bash scripts/demo_decision_flow_flagged.sh` | Release/checkpoint smoke. |
| `bash scripts/demo_record_chain_verification.sh` | Release/checkpoint chain-verifier demo. |
| `bash scripts/inspect_audit_artifact.sh <artifact.jsonl>` | Reviewer/operator artifact inspection. |
| `bash scripts/find_audit_artifact.sh <request_id\|audit_hash\|record_hash> <path-or-dir>` | Reviewer/operator artifact lookup. |
| `cargo run --release --bin perf_budget` | Push/manual or release performance evidence. |
| `cargo run --release --bin load_test` | Push/manual or release load evidence. |
| `.github/workflows/staging-security.yml` | Manual staging smoke. |

## Touched-Surface Review Rules

- If `src/api*` changes, run API/auth/replay/audit relevant tests.
- If `src/profile.rs` changes, run profile tests and docs consistency.
- If `src/audit*` or `src/audit_store.rs` changes, run `audit_store` / `audit_chain` tests and Zig fixture verification.
- If Zig verifier files change, run Zig build test and fixture verification.
- If Julia files change, run Julia unit and integration tests.
- If Ruby UI files change, run Ruby UI tests.
- If docs test counters change, run README consistency.
- If supply-chain sensitive files change, run the supply-chain script and `cargo deny check`.
- If exposure endpoints change, review [Public Exposure Policy v1](NEXO_PUBLIC_EXPOSURE_POLICY_V1.md) and relevant endpoint tests.

## Existing CI Coverage

`.github/workflows/rust.yml` currently enforces:

- README/docs consistency.
- Rust format.
- Clippy with warnings denied.
- Engine boundary forbidden-token check.
- Determinism and trace-contract tests in normal and `network` feature modes.
- Supply-chain surface guard.
- `cargo deny check`.
- Rust build.
- Full Rust tests.
- Full Rust tests with `network` feature.
- Julia unit and integration tests.
- Zig unit tests.
- Zig base fixture verification.
- Zig chain fixture verification with `--require-chain`.
- Zig verification of a Rust-generated audit fixture.

The bench/load job runs on push or manual dispatch.
It is not a universal pull-request gate.

## Zig Verification Coverage

Zig validation covers:

- verifier unit tests
- base fixture verification
- `--require-chain` fixture verification
- Rust-generated artifact verification in CI

Zig verifies persisted artifacts offline.
It does not prove HMAC validity, replay validity, timestamp freshness, profile config correctness, or never-persisted events.

## Julia Validation Coverage

Julia validation covers observer and bridge behavior:

- `julia --project=./julia julia/test/runtests.jl`
- `julia --project=./julia julia/test_integration.jl`

Julia remains observer/analyst only.
Passing Julia tests does not make Julia authority.

## Ruby UI Validation Coverage

Ruby UI tests exist:

- `ruby nexo_ui/test/app_surface_test.rb`
- `ruby nexo_ui/test/core_adapter_test.rb`
- `ruby nexo_ui/test/app_config_test.rb`

They validate presentation hierarchy, core-adapter behavior, and UI config behavior.
They are not currently CI-enforced.
Ruby remains presentation/operator surface only.

## Supply-Chain Validation Coverage

Supply-chain validation includes:

- `bash scripts/check_supply_chain_surface.sh`
- `cargo deny check`
- lockfile source policy
- advisory/license/source checks
- workflow-level `permissions: contents: read`

Limits:

- duplicate dependency versions are warn-only
- GitHub Actions are tag-pinned, not SHA-pinned
- transitive dependency build scripts and proc macros remain build-time trust surfaces
- the local supply-chain script scans repository-owned sensitive paths, not Cargo registry source

## Operational Demo Coverage

Operational demos provide reviewer-facing evidence:

- `scripts/demo_decision_flow.sh` exercises a signed decision and verifies the emitted artifact with Zig.
- `scripts/demo_decision_flow_flagged.sh` exercises a flagged decision and verifies the emitted artifact with Zig.
- `scripts/demo_record_chain_verification.sh` demonstrates `--require-chain` continuity and record-hash tamper detection.
- `scripts/inspect_audit_artifact.sh` extracts and summarizes persisted artifact fields.
- `scripts/find_audit_artifact.sh` locates artifacts by `request_id`, `audit_hash`, or `record_hash`.

These are smoke/reviewer tools.
They are not formal proofs and may depend on local tools or runtime environment.

## What Core Validation Gate v1 Can Claim

Core Validation Gate v1 can claim:

- Rust trust-core format, lint, and tests pass.
- Network-feature tests pass.
- Deterministic engine boundary checks run.
- Central API/auth/audit/replay tests are included in the Rust suite.
- Zig offline verifier tests and fixture verification pass.
- Zig `--require-chain` is exercised.
- Julia observer tests pass without making Julia authority.
- README counters and docs consistency are enforced.
- Supply-chain source/advisory/license guardrails run.
- CI enforces the main validation set on push/PR.
- Staging security smoke exists as a manual workflow.

## What Core Validation Gate v1 Cannot Claim

Core Validation Gate v1 cannot claim:

- formal verification
- global truth or consensus
- full-input replay
- full policy/config cryptographic binding
- complete Redis failure coverage
- dedicated `429` test coverage
- `/api/state` internal-only policy enforcement in code
- Ruby UI tests are CI-enforced
- CI actions are SHA-pinned
- duplicate dependencies are denied
- complete supply-chain provenance
- staging smoke runs automatically on every PR
- operational demos are stable across every host environment

## Known Gaps

- No dedicated `429` rate-limit test.
- Redis failure integration coverage is limited.
- Redis replay plus audit-append failure direct integration/API coverage is limited.
- `/api/state` internal-only exposure policy is documented but not code-enforced.
- Ruby UI tests are not CI-enforced.
- Staging smoke is manual-only.
- Bench/load is not PR-enforced.
- Duplicate dependency policy is warn-only.
- GitHub Actions are tag-pinned, not SHA-pinned.
- Direct end-to-end `NEXO_REQUIRE_AUDIT_PREFLIGHT=true` startup test is still pending.
- `config_hash`, `policy_hash`, and full replay remain vNext.

## vNext / Open Decisions

- Decide whether Ruby UI tests should become CI-enforced.
- Add a dedicated `429` rate-limit test.
- Add stable Redis failure integration tests.
- Add direct end-to-end startup test for `NEXO_REQUIRE_AUDIT_PREFLIGHT=true`.
- Decide whether staging smoke should run on schedule or protected branch events.
- Decide whether bench/load should gate PRs or remain push/manual.
- SHA-pin GitHub Actions.
- Strengthen duplicate dependency policy beyond warn.
- Add CI drift guard for required workflow jobs if needed.
- Add explicit public exposure policy tests if endpoint exposure becomes code-enforced.

## Operator Checklist

Before claiming Core Validation Gate v1:

- Run the Core CI Gate or confirm current CI passed.
- Run the Hostile Baseline Gate for hostile-baseline promotion.
- Run Ruby UI tests when Ruby/UI surfaces are in scope.
- Run release/checkpoint demos when reviewer-facing evidence is needed.
- Verify retained artifacts offline with Zig.
- Do not claim validation for commands that were not actually run.
- Record any environment-dependent skipped checks.

## Reviewer Checklist

When reviewing validation posture:

- Did Rust fmt, clippy, and full tests run?
- Did network-feature tests run?
- Did Zig unit and fixture verification run?
- Did `--require-chain` verification run?
- Did Julia observer tests run without redefining authority?
- Did README/docs consistency pass?
- Did supply-chain guard and `cargo deny check` pass?
- Were Ruby UI tests run if UI files changed?
- Were demos run only as smoke/reviewer evidence, not overstated as proof?
- Are known gaps and non-claims still accurate?
