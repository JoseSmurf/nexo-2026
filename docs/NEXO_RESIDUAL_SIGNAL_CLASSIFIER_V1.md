# NEXO Residual Signal Classifier V1

## 1. Purpose

Define the operational contract for the **residual signal classifier** path:

1. Julia generates a deterministic residual artifact.
2. Rust validates the residual contract (fail-closed).
3. Zig independently verifies the Blake3 hash of the generated artifact bytes.

This module is **observer/diagnostic only**. It is not runtime authority, not global truth, and does not change Rust trust-core decision authority.

## 2. Boundary

- Rust trust core remains centered at:
  `signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification`
- Residual classifier is a secondary path for operational analysis and data-quality signals.
- Julia may classify and score signals, but cannot authorize decisions.

## 3. Contract Surfaces

- Julia classifier:
  - `julia/residual_signal_classifier.jl`
  - `julia/generate_residual_signal_artifact.jl`
- Rust contract validator:
  - `src/residual_signal_contract.rs`
  - `src/bin/residual_signal_hash.rs`
- Zig hash verifier:
  - `tools/zig/src/hash_file.zig`

## 4. Artifact Contract (V1)

Expected schema/version constants:

- `schema_version = "nexo_residual_signal_v1"`
- `classifier_version = "julia_residual_signal_classifier_v1"`

Key invariants (fail-closed when broken):

- deterministic `feature_order`
- valid sample ranges (`loss_pct`, `retransmission_pct`, non-negative latency/jitter)
- deterministic sample sorting
- summary totals must match sample list
- `is_runtime_authority == false`
- `is_global_truth == false`

## 5. CI Flow (Cross-Language)

CI job `residual_signal_classifier_contract` executes:

1. Julia generates artifact bytes.
2. Rust validates contract and emits Blake3 hex.
3. Zig recomputes Blake3 over the same file and rejects mismatch.

This proves cross-language agreement for:

- structural contract acceptance (Rust fail-closed validator)
- byte-level hash agreement (Rust vs Zig)

## 6. Local Reproduction

```bash
julia --project=./julia julia/generate_residual_signal_artifact.jl artifacts/residual_signal_classifier/generated_local.json
cargo run --quiet --bin residual_signal_hash -- artifacts/residual_signal_classifier/generated_local.json > /tmp/residual_hash_rust.txt
zig run tools/zig/src/hash_file.zig -- artifacts/residual_signal_classifier/generated_local.json "$(cat /tmp/residual_hash_rust.txt)"
```

Expected outcome:

- Rust command prints one 64-char lowercase Blake3 hex value.
- Zig command exits `0` with `hash_ok: <same_hex>`.

## 7. Non-Claims

- No runtime authority transfer from Rust to Julia.
- No claim of consensus/global truth.
- No extension of this module to mesh/Witness/Bitcoin experimental authority.
