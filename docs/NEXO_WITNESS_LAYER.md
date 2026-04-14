# NEXO Witness Layer

## Objetivo do documento

Registrar, de forma conservadora, a linha atual de provas locais do NEXO apos os merges de:

- `AcceptedStateWitness`
- `RecoveryWitness`
- `RelayNeutralityProof`

Este documento descreve o que essas provas realmente validam hoje e, principalmente, o que elas ainda nao validam.

## O que e a Witness Layer

A Witness Layer e o conjunto de artefatos deterministas e harnesses de verificacao local que ajudam a reduzir ambiguidade operacional no Mesh v0.

Ela existe para responder perguntas locais com evidencia reproduzivel, sem transformar observabilidade em autoridade semantica.

## Por que ela existe

O NEXO e local-first e precisa evoluir Mesh sem pular direto para integracao de runtime distribuido.

A Witness Layer permite:

- formalizar invariantes pequenos, uma ideia por vez;
- provar comportamentos locais de forma determinista;
- detectar regressao sem introduzir autoridade global;
- preparar contratos para passos futuros com risco controlado.

## Witnesses existentes hoje

## 1) AcceptedStateWitness

Base principal:

- `src/mesh/types.rs` (`AcceptedStateWitness`)
- `src/mesh/adapters.rs` (`build_accepted_state_witness`)

O que prova:

- resumo determinista de uma fatia de historico local aceito;
- `ordering`, `since_ts_ms`, `event_count`, `first_event_hash`, `last_event_hash`;
- `state_digest` com framing explicito e estavel;
- comportamento fail-closed para cursor invalido e hash malformado.

O que nao prova:

- verdade global da malha;
- convergencia completa entre nos;
- causalidade global;
- autoridade de relay.

Leitura correta:

- "este no consegue resumir, de forma determinista, o que ele aceitou localmente".

## 2) RecoveryWitness

Base principal:

- `src/mesh/types.rs` (`RecoveryWitness`, `RecoveryClassification`)
- `src/mesh/adapters.rs` (`build_recovery_witness`)

O que prova:

- classificacao conservadora de continuidade local com evidencia disponivel hoje;
- classes automaticas: `NewNode`, `Intact`, `Ambiguous`, `Invalid`;
- digest determinista de continuidade (`continuity_digest`);
- inspecao read-only (sem criar identidade nova e sem mutar storage).

O que nao prova:

- restore valido automatico;
- decisao de runtime para restore/rejoin;
- identidade global entre dispositivos;
- convergencia da malha.

Observacao importante:

- `RestoredValid` existe no tipo como contrato reservado, mas nao e emitido automaticamente sem evidencia explicita adicional.

## 3) RelayNeutralityProof

Base principal:

- `src/bin/nexo_relay.rs` (harnesses de neutralidade do relay)
- `.github/workflows/rust.yml` (execucao explicita de testes com `--features network`)

O que prova:

- push/pull preserva envelope/evento sem reinterpretacao semantica;
- assinatura invalida e rejeitada;
- duplicata nao vira novo evento semantico;
- ordering de pull e operacional (`timestamp_ms`, `rowid`) e reproduzivel.

O que nao prova:

- convergencia global;
- causalidade global forte;
- autoridade do relay sobre verdade do sistema.

Leitura correta:

- "relay e ponte passiva store-and-forward, nao fonte de verdade semantica".

## O que a Witness Layer nao e

A Witness Layer, no estado atual, nao e:

- verdade global da malha;
- mecanismo de consenso;
- implementacao de CRDT;
- protocolo completo de sync runtime;
- substituto do contrato de identidade/lifecycle;
- substituto do contrato de sync/convergencia.

## Por que isso ainda nao e sync runtime completo

Mesmo com os tres pilares atuais, ainda faltam contratos e validacoes para integracao forte no runtime distribuido, por exemplo:

- fronteira entre evidencias locais e decisoes de runtime;
- contrato de convergencia minima sob replay/restart/rejoin;
- criterios mais fortes para restore valido;
- uso seguro de sinais de relay sem promover autoridade implicita.

## Proximos witnesses possiveis

### OperationalTruthSurface

Objetivo:

- reforcar a separacao entre `core truth` e campos `derived` de diagnostico/operacao.

Estado:

- promissor e seguro para testes/contrato.

Limite:

- nao promover `/api/state` a protocolo de replicacao.

### BandwidthMinimalSyncDigest

Objetivo:

- preparar comparacao economica de estado aceito local antes de payload completo.

Estado:

- util como helper/harness read-only.

Limite:

- qualquer uso em sync real ou wire: precisa de contrato antes.

### SyncConvergenceHarness

Objetivo:

- medir convergencia minima em cenarios controlados (replay, restart, pull repetido).

Estado:

- importante para maturidade de Mesh.

Limite:

- nao afirmar convergencia global forte sem contrato explicito.

## Regras para futuros PRs de witness

1. Uma ideia semantica por PR.
2. Comecar por contrato + helper/harness read-only.
3. Declarar explicitamente "o que prova" e "o que nao prova".
4. Usar framing determinista e comportamento fail-closed.
5. Nao criar autoridade nova por inferencia (relay, UI, observador, API de estado).
6. Nao integrar em runtime/sync real sem contrato previo.
7. Nao usar `/api/state` como protocolo de replicacao.
8. Nao introduzir consenso/CRDT/anchor cedo demais.
9. Cobrir invariantes com testes pequenos e diretos.
10. Garantir que CI exercite os testes relevantes de feature (`network`) quando aplicavel.

## Tese operacional da Witness Layer

No v0, a Witness Layer serve para provar evidencia local com determinismo e humildade semantica: ela reduz risco de regressao e prepara a evolucao do Mesh sem fingir autoridade global antes da hora.
