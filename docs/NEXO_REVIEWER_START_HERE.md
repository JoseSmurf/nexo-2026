# NEXO Reviewer Start Here

## Purpose

This document is a reading and review map for NEXO.
It helps human reviewers and agents understand the current hierarchy of the repository without confusing the product center with experimental tracks.

It does not replace `AGENTS.md`, `README.md`, `docs/OPERATIONAL_FLOW.md`, or `docs/SECURITY_OPERATIONS.md`.
For agents, `AGENTS.md` remains the primary source of operational rules.

## Read This First

Minimum reading order:

1. `AGENTS.md`
2. `README.md`
3. `docs/OPERATIONAL_FLOW.md`
4. `docs/SECURITY_OPERATIONS.md`

## Confirmed Center Of NEXO

signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification

This is the current confirmed center of the repository.
Do not treat secondary tracks as if they redefine this path.

## Reviewer Evidence Pack

This guide is the reading map. The documents below complement it with concrete reviewer surfaces:

- `docs/NEXO_ARCHITECTURE_EVIDENCE.md` (architecture evidence)
- `docs/NEXO_THREAT_MODEL.md` (threat model)
- `docs/NEXO_REPRODUCIBILITY_REPORT.md` (reproducibility path)
- `docs/NEXO_TEST_MATRIX.md` (validation/test matrix)

The center remains:

signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification

## Project Categories

### Product Center

- Deterministic Rust decision flow
- `final_decision`
- ordered trace
- audit artifact persistence

Primary files:

- `src/lib.rs`
- `src/engine/evaluate.rs`
- `src/engine/trace.rs`

### Security & Audit Boundary

- request signing and fail-closed validation
- replay protection
- rate limiting
- audit hash and record chain integrity

Primary files:

- `src/api.rs`
- `src/api/auth.rs`
- `src/api/replay.rs`
- `src/api/rate_limit.rs`
- `src/audit/hash.rs`
- `src/audit/record.rs`
- `src/audit_store.rs`

### Verification

- independent offline verification of persisted artifacts

Primary files:

- `tools/zig/src/verify.zig`
- `tools/zig/src/schema.zig`
- `tools/zig/src/crypto.zig`

### Operator Interface

- narrow Interface V0 for operator review
- center-aligned surface around decision, trace, audit trail, and offline verification

Primary files:

- `nexo_ui/app.rb`
- `nexo_ui/core_adapter.rb`
- `nexo_ui/views/index.erb`
- `docs/NEXO_INTERFACE_V0_PLAN.md`
- `docs/NEXO_INTERFACE_V0_OPERATOR_GUIDE.md`
- `docs/NEXO_INTERFACE_V0_READINESS_CHECKLIST.md`

### Observability

- read-only summaries and observer artifacts
- no runtime authority

Primary files:

- `julia/flow_observer.jl`
- `julia/observe_state.jl`
- `julia/plca_bridge.jl`

### Experimental Tracks

- mesh/P2P/relay
- Witness Layer
- sync diagnostics
- Bitcoin logistics experiment

Representative files and docs:

- `src/mesh/`
- `src/bin/nexo_p2p.rs`
- `src/bin/nexo_relay.rs`
- `docs/NEXO_WITNESS_LAYER.md`
- `docs/NEXO_WITNESS_DRIVEN_SYNC_V0.md`
- `docs/NEXO_BITCOIN_LOGISTICS_EXPERIMENT_V0.md`
- `docs/NEXO_BITCOIN_LOGISTICS_EXPERIMENT_V0_TECHNICAL_MINIMUM.md`

### Validation Surface

- repository checks
- tests across Rust, Zig, Ruby, and Julia

Representative files:

- `tests/engine_boundaries.rs`
- `tests/network_udp_integration.rs`
- `scripts/check_readme_consistency.sh`
- `nexo_ui/test/`
- `julia/test/`

## What Is Experimental

The following areas are experimental relative to the current product center:

- mesh/P2P/relay
- Witness Layer
- Bitcoin logistics experiment
- `decision_cycle`
- Bitcoin-related Julia analysis

Julia observation that reads `/api/state` is secondary and non-authoritative.
It is not a decision layer and does not redefine the product center.

These areas may be important, but they are not the current center of the product.
They should not be promoted into the main NEXO story without explicit instruction.
The Bitcoin logistics experiment should be read as a research track and experimental case study, not the product center.
It is not a mining, profitability, PoW shortcut, or ASIC-competitiveness claim.

## What Must Not Be Inferred

- Bitcoin is not the product center.
- Bitcoin is not a mining, profitability, PoW shortcut, or ASIC-competitiveness claim.
- Witness is not global truth.
- Julia does not decide.
- Ruby UI is not a broad dashboard.
- mesh/P2P is not the current product center.

## Reviewer Working Rules

- read `AGENTS.md` first
- make small changes
- do not silently change Rust/Zig trust contracts
- do not promote experimental tracks into product center
- do not commit, merge, or push without explicit human instruction
- always report changed files and validation commands

## Fast Review Paths By Goal

### product center

- `AGENTS.md`
- `README.md`
- `docs/OPERATIONAL_FLOW.md`
- `src/lib.rs`
- `src/engine/evaluate.rs`
- `src/api.rs`

### security/audit

- `docs/SECURITY_OPERATIONS.md`
- `src/api/auth.rs`
- `src/api/replay.rs`
- `src/api/rate_limit.rs`
- `src/audit/hash.rs`
- `src/audit/record.rs`
- `src/audit_store.rs`

### offline verification

- `README.md`
- `docs/OPERATIONAL_FLOW.md`
- `tools/zig/src/verify.zig`
- `tools/zig/src/schema.zig`

### Interface V0

- `docs/NEXO_INTERFACE_V0_PLAN.md`
- `docs/NEXO_INTERFACE_V0_OPERATOR_GUIDE.md`
- `docs/NEXO_INTERFACE_V0_READINESS_CHECKLIST.md`
- `nexo_ui/app.rb`
- `nexo_ui/views/index.erb`

### observability

- `julia/flow_observer.jl`
- `julia/observe_state.jl`
- `src/api/state.rs`

### experimental tracks

- `docs/NEXO_WITNESS_LAYER.md`
- `docs/NEXO_WITNESS_DRIVEN_SYNC_V0.md`
- `docs/NEXO_BITCOIN_LOGISTICS_EXPERIMENT_V0.md`
- `docs/NEXO_BITCOIN_LOGISTICS_EXPERIMENT_V0_TECHNICAL_MINIMUM.md`
- `src/mesh/`

### tests/CI

- `tests/engine_boundaries.rs`
- `tests/network_udp_integration.rs`
- `nexo_ui/test/`
- `julia/test/`
- `scripts/check_readme_consistency.sh`

## Protected Surfaces

The following files are sensitive and should not drift casually:

- `src/engine/evaluate.rs`
- `src/audit/hash.rs`
- `src/audit/record.rs`
- `src/audit_store.rs`
- `src/api.rs`
- `src/api/auth.rs`
- `tools/zig/src/verify.zig`

If these files change, reviewers should assume the trust contract may be affected until proven otherwise.
Changes in these files require an explicit task, careful review, and corresponding validation.

## Scope Mistakes To Avoid

- treating Bitcoin as the main product
- treating Witness as authority
- treating Julia as a decision engine
- expanding the UI into a broad dashboard
- promoting mesh/P2P before the core evidence pack is reviewer-ready
- changing trace/hash/artifact semantics casually
