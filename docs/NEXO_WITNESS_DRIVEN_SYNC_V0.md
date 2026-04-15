# NEXO Witness-driven Sync v0 Path

## Objetivo

Definir, de forma conservadora, como a Witness Layer prepara um caminho de `Sync v0` sem integrar sync runtime completo agora.

O foco aqui e reduzir custo de sincronizacao e ambiguidade operacional com evidencias locais deterministicas.

## Fluxo conceitual

`AcceptedStateWitness` -> `BandwidthMinimalSyncDigest` -> comparacao barata -> pull/delta futuro -> `Sync v0`

Leitura correta do fluxo:

- primeiro o no resume o que aceitou localmente (`AcceptedStateWitness`);
- depois condensa uma janela para comparacao economica (`BandwidthMinimalSyncDigest`);
- com base na comparacao, abre caminho para decidir quando vale pedir delta/pull no futuro;
- `RecoveryWitness` protege continuidade local para evitar leitura otimista apos restart/restore;
- `RelayNeutralityProof` limita o relay ao papel de ponte, sem autoridade semantica.

## Como cada peca entra no caminho

### AcceptedStateWitness

Contribuicao:

- resumo deterministico da fatia aceita local;
- base semantica para derivar digests de baixo custo.

Nao implica:

- verdade global;
- convergencia completa.

### BandwidthMinimalSyncDigest

Contribuicao:

- comparacao barata de janela local (`since`/`until`, `event_count`, `state_digest`);
- preparacao para reciclar conectividade disponivel (Wi-Fi/4G) com menos payload inicial.

Nao implica:

- decisao real de sync runtime;
- protocolo wire novo.

### RecoveryWitness

Contribuicao:

- classificacao conservadora de continuidade local (`NewNode`, `Intact`, `Ambiguous`, `Invalid`);
- reducao de falso positivo de continuidade em rejoin/restart.

Nao implica:

- restore automatico;
- enforcement de runtime.

### RelayNeutralityProof

Contribuicao:

- evidencia de que relay permanece ponte passiva store-and-forward;
- reforco de que ordering do pull e operacional, nao autoridade global.

Nao implica:

- autoridade do relay;
- convergencia global forte.

## O que ja existe hoje

- witness deterministico de estado aceito local;
- witness deterministico de continuidade local;
- harness de neutralidade do relay;
- digest minimo read-only para comparacao economica de janelas.

## O que ainda nao existe

- pull/delta runtime orientado por digest;
- contrato de convergencia minima para sync real;
- API publica nova para sync witness-driven;
- politica de reconciliacao completa entre nos.

## Limites explicitos (nao prometer)

- consenso;
- CRDT;
- verdade global;
- convergencia global forte;
- sync runtime completo;
- API publica nova.

## Proximos PRs possiveis

1. `OperationalTruthSurface`: separar verdade de contrato vs campos derivados de diagnostico.
2. `SyncConvergenceHarness`: cenarios controlados de replay/restart/rejoin sem overclaim global.
3. `Witness-driven Delta Contract (docs only)`: contrato minimo para delta futuro antes de runtime.

## Regra de integracao futura

Qualquer uso desses digests/witnesses para governar sync runtime real deve passar por contrato explicito antes de codigo operacional.
