# NEXO Bitcoin Logistics Experiment v0 Technical Minimum

## Objetivo

Congelar o desenho tecnico minimo para executar o experimento v0 sem abrir implementacao cedo.
Este documento complementa [NEXO_BITCOIN_LOGISTICS_EXPERIMENT_V0.md](./NEXO_BITCOIN_LOGISTICS_EXPERIMENT_V0.md).

## Escopo minimo canonicamente observado

Unidade observada: `decision_cycle`.

Definicao operacional de `decision_cycle`:

- inicio: quando um item de trabalho local e observado;
- fim: quando a politica emite `decision_intent` e o ciclo e fechado em telemetria;
- regra: `decision_intent` e diagnostico experimental, nao acao de runtime.

## Eventos minimos coletados

- `work_item_observed`
- `structural_validation_result`
- `comparability_result`
- `freshness_result`
- `policy_decision_emitted`
- `action_simulated`
- `stale_detected`
- `submission_attempted`
- `submission_abandoned`
- `decision_cycle_closed`

## Estados minimos

- `structural_state`: `StructurallyValid` | `StructuralInvalid`
- `comparability_state`: `Comparable` | `NotComparable` | `NotEvaluated`
- `freshness_state`: `FreshEnough` | `Stale` | `FreshnessNotAssessable` | `NotEvaluated`
- `actionability_state`: `DiagnosticOnly`
- `decision_intent`: `Continue` | `Refresh` | `Rebuild` | `Discard` | `SubmitAttempt` | `Abandon`

Contrato semantico minimo:

- `StructuralInvalid` nao pode ser reclassificado como `NotComparable`;
- `StructuralInvalid` nao pode ser reclassificado como `FreshnessNotAssessable`;
- `FreshnessNotAssessable` so se aplica a caso estruturalmente valido.

## Telemetria minima

- timestamps de ciclo: `observed_at_ts_ms`, `decision_at_ts_ms`, `cycle_closed_at_ts_ms`
- latencias: `decision_overhead_ms`, `refresh_latency_ms` (quando aplicavel)
- contadores por ciclo: `rebuild_count`, `discard_count`, `submit_attempt_count`, `abandon_count`
- flags: `stale_detected`, `structural_error_detected_early`
- razao curta de decisao: `reason_code` estavel

## Contrato de dados minimo

Formato recomendado no v0: JSONL canonico, 1 linha por `decision_cycle`, com `schema_version`.

Campos minimos recomendados:

- `schema_version`
- `run_id`
- `cycle_id`
- `policy_mode` (`blind` | `evidence_guided`)
- `work_item_id`
- `observed_at_ts_ms`
- `structural_state`
- `comparability_state`
- `freshness_state`
- `actionability_state`
- `decision_intent`
- `decision_overhead_ms`
- `stale_detected`
- `reason_code`

Fora de escopo neste contrato:

- campos de rentabilidade financeira;
- inferencias de vantagem economica em mainnet;
- qualquer campo que implique autoridade de runtime.

## Comparacao A/B sem contaminacao

Politica cega:

- usa gatilhos fixos e regras simples;
- nao usa gates semanticos para modulacao fina de decisao.

Politica guiada por evidencia:

- aplica gates na ordem: estrutura -> comparabilidade -> freshness -> actionability;
- mantem `actionability_state=DiagnosticOnly`.

Regra de comparacao:

- as duas politicas avaliam o mesmo stream de entrada;
- cada par A/B compartilha o mesmo `cycle_id` logico;
- comparacao e offline a partir do artefato, sem feedback cruzado durante execucao.

## Artefato primario de saida

Artefato primario: `artifacts/bitcoin_logistics_experiment/decision_cycles.jsonl`.

Artefato derivado opcional:

- resumo tabular comparativo por politica e por cenario (CSV ou markdown).

## Riscos metodologicos que nao podem ser violados

- baseline cego fraco demais, enviesando resultado;
- colapso de erro estrutural em diagnostico valido;
- definicao inconsistente de `stale` entre cenarios;
- mistura de relogios sem contrato temporal claro;
- leitura de `decision_intent` como acao real de runtime;
- extrapolacao indevida de laboratorio para claim economico de mainnet.

## Non-claims experimentais obrigatorios

- nao e otimizacao criptografica de PoW;
- nao e prova de competitividade contra ASIC;
- nao e prova de rentabilidade;
- nao e consenso, verdade global ou convergencia global;
- nao autoriza autoridade de runtime nem sync automatico.
