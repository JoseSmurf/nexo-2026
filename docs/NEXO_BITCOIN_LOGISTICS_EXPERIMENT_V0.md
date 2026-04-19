# NEXO Bitcoin Logistics Experiment v0

## Objetivo

Registrar um plano experimental curto e falsificavel para testar se uma politica guiada por evidencia minima reduz desperdicio operacional ao redor de trabalho de mineracao, sem alterar PoW e sem alegar competitividade contra ASIC.

## 1) Hipotese experimental (1 frase)

Uma politica guiada por evidencia minima pode reduzir desperdicio operacional (stale/rebuild/descartes ruins) em comparacao com uma politica cega, sem alterar o trabalho criptografico inevitavel.

## 2) Escopo exato

- foco em logistica operacional local (refresh/rebuild/descarte/submissao/abandono);
- comparacao A/B entre politica cega e politica guiada por evidencia;
- medicao de custo/beneficio operacional;
- sem promessa de rentabilidade;
- sem afirmacao de convergencia global.

## 3) Ambiente recomendado

Fase 1 (obrigatoria): `regtest` (controle alto, repetibilidade, baixo custo).

Fase 2 (opcional): `testnet` e/ou observacao de templates/jobs para validar robustez fora de laboratorio.

`mainnet` nao e ambiente inicial deste experimento.

## 4) Pipeline do experimento

`template -> validacao estrutural -> comparabilidade -> freshness -> actionability -> refresh/rebuild/descarte -> submissao/abandono (ou simulacao) -> telemetria`

Interpretacao da lente NEXO:

- estrutura: bloquear erro estrutural cedo (fail-closed);
- comparabilidade: comparar apenas contexto compativel;
- freshness: evitar interpretacao forte com contexto velho;
- actionability: manter decisao conservadora e explicita.

## 5) Politica cega vs politica guiada por evidencia

Politica cega:

- refresh em intervalo fixo;
- rebuild por regra simples (ex.: sempre que chega template novo);
- baixa distincao entre mudanca relevante e ruido.

Politica guiada por evidencia:

- erro estrutural -> descarte imediato;
- estrutural valido + comparavel + fresco -> continuar;
- estrutural valido + comparavel + stale -> refresh;
- estrutural valido + nao comparavel -> rebuild;
- freshness nao avaliavel -> estado conservador, sem promocao de acao forte.

## 6) Metricas minimas

- `stale_work_ratio`;
- `unnecessary_rebuild_rate`;
- `refresh_latency_ms`;
- `false_discard_rate`;
- `structural_error_early_detection_rate`;
- `decision_overhead_ms` e `cpu_overhead_pct`.

## 7) Criterios de sucesso

- reducao consistente de stale/rebuild desnecessario versus baseline cego;
- overhead de decisao baixo e controlado;
- sem aumento relevante de falso descarte.

## 8) Criterios de fracasso / falsificadores

- ausencia de melhoria frente a politica cega;
- ganho marginal menor que o overhead de coordenacao;
- aumento material de falso descarte;
- resultados inconsistentes entre execucoes controladas.

## 9) Papel do notebook

- laboratorio local;
- observador/classificador/simulador/coordenador local;
- executor parcial de workload de teste.

Nao e:

- substituto de ASIC;
- prova de vantagem economica em `mainnet`;
- atalho criptografico.

## 10) Non-claims obrigatorios

- nao e equivalencia com mineracao do Bitcoin Core;
- nao ensina "como achar o hash";
- nao muda PoW;
- nao prova rentabilidade;
- nao autoriza afirmar verdade global, consenso, autoridade de runtime ou sync automatico.

## Limite metodologico central

A pergunta e sobre desperdicio operacional evitavel, nao sobre superioridade de hardware nem sobre desempenho criptografico absoluto.
