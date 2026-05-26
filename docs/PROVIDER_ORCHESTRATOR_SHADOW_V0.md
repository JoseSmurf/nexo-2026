# Provider Orchestrator Shadow V0

Status: experimental operator path.

This path does not change the central trust core:

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification`

## Goal

Run deterministic provider-route selection from measured metrics and persist auditable decision artifacts.

## Inputs

- JSON file with provider metrics
- accepted formats:
  - `{ "providers": [ ... ] }`
  - `[ ... ]`

Each provider record uses:

- `id`
- `latency_ms`
- `jitter_ms`
- `loss_bps`
- `cost_microunits`
- `region`
- `healthy`

## Activation

Set:

`NEXO_PROVIDER_ORCH=1`

## Run

```bash
bash scripts/run_provider_orch_shadow.sh
```

Or with explicit file:

```bash
bash scripts/run_provider_orch_shadow.sh fixtures/provider_metrics_sample.json
```

## Output

- stdout prints:
  - primary route id
  - fallback route id (if available)
- artifact append:
  - `logs/provider_orchestrator_decision.jsonl`

## Safety

- fail-closed when no providers are healthy
- deterministic tie-break by provider id
- artifact hash uses `blake3` over content without hash field
