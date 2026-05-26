# ORCHESTRATOR Experiment Gate (V0)

Status: experimental helper path only.

This gate does not promote orchestrator to NEXO trust core.
Rust deterministic evaluate + audit artifact + Zig offline verifier remains the center.

## Goal

Keep `src/orchestrator.rs` verifiable before any broader integration.

## Required checks

1. Fail-closed behavior:
- Empty server input must return error.

2. Deterministic rule behavior:
- Selection must follow the `menor_latencia` rule.
- Tie behavior must remain deterministic (current behavior: first minimum in input order).

3. Artifact contract:
- JSONL append target: `logs/orchestrator_decision.jsonl`.
- Required fields: `timestamp_utc_ms`, `servers`, `choice`, `rule`, `hash`.
- `hash` must be `blake3` over canonical content without the `hash` field.

4. Append behavior:
- Multiple decisions must append multiple JSONL lines.

## Validation command

Run from repository root:

```bash
cargo test -q orchestrator::
```

Or run full Rust suite:

```bash
cargo test -q
```

## Promotion rule

Do not route orchestrator output into central audit acceptance or CI pass/fail policy until this gate is green in the target host environment.
