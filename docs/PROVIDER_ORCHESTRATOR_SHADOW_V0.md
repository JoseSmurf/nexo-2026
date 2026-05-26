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

Optional failover inputs (all three required to enable threshold mode):

- `NEXO_PROVIDER_ORCH_PREVIOUS_PRIMARY=<provider-id>`
- `NEXO_PROVIDER_ORCH_MAX_LATENCY_MS=<u32>`
- `NEXO_PROVIDER_ORCH_MAX_JITTER_MS=<u32>`
- `NEXO_PROVIDER_ORCH_MAX_LOSS_BPS=<u16>`

## Run

```bash
bash scripts/run_provider_orch_shadow.sh
```

Or with explicit file:

```bash
bash scripts/run_provider_orch_shadow.sh fixtures/provider_metrics_sample.json
```

## Continuous cycle runner (SLO report)

```bash
bash scripts/run_provider_orch_cycle.sh fixtures/provider_metrics_cycle_sample.json
```

Optional thresholds:

- failover thresholds:
  - `NEXO_PROVIDER_ORCH_MAX_LATENCY_MS`
  - `NEXO_PROVIDER_ORCH_MAX_JITTER_MS`
  - `NEXO_PROVIDER_ORCH_MAX_LOSS_BPS`
- SLO thresholds:
  - `NEXO_PROVIDER_ORCH_SLO_MAX_P95_LATENCY_MS`
  - `NEXO_PROVIDER_ORCH_SLO_MAX_CHURN_PCT`
  - `NEXO_PROVIDER_ORCH_SLO_MAX_INVALID_ARTIFACTS`

Cycle runner outputs:

- artifact JSONL (default): `logs/provider_orchestrator_cycle.jsonl`
- report JSON (default): `logs/provider_orchestrator_cycle_report.json`

## Offline verification

```bash
bash scripts/verify_provider_orch_artifact.sh logs/provider_orchestrator_decision.jsonl
```

Expected output format:

`provider_orch_verify: total=<n> ok=<n> invalid=<n>`

## Output

- stdout prints:
  - primary route id
  - fallback route id (if available)
- artifact append:
  - `logs/provider_orchestrator_decision.jsonl`

## Safety

- fail-closed when no providers are healthy
- fail-closed when threshold mode leaves no healthy provider
- deterministic tie-break by provider id
- artifact hash uses `blake3` over content without hash field
