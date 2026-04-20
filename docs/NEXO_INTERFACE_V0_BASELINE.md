# NEXO Interface V0 Baseline

## 1) Definicao curta da V0

A Interface V0 do NEXO e uma superficie operacional estreita para decisao local auditavel.
Ela foi desenhada para uso humano com centro fechado em avaliacao deterministica e rastreabilidade.

## 2) Fluxo principal da V0

`evaluate -> final_decision -> trace -> audit trail -> verify offline`

Este e o caminho central da interface.
Elementos fora desse fluxo aparecem apenas como contexto secundario.

## 3) O que a V0 prova

- a decisao exibida e legivel no centro da interface;
- existe explicabilidade local via `trace`;
- existe rastreabilidade local via `audit trail`;
- existe caminho de conferencia offline (`verify offline` com Zig).

## 4) O que a V0 nao prova

- nao prova verdade global;
- nao prova convergencia global;
- nao executa sync automatico;
- nao cria nova autoridade de runtime;
- nao representa plataforma completa.

## 5) O que continua fora de escopo

- deployment online e distribuicao APK;
- expansao para dashboard amplo;
- promocao de mesh/P2P, Witness Layer ou decision_cycle ao centro;
- integracao secundaria como criterio principal de decisao;
- claims economicos ou de consenso.

## 6) Como apresentar a V0 de forma honesta

Apresentar a V0 como interface de uso controlado com foco em decisao local auditavel.
Manter o discurso no centro semantico da interface e nos non-claims obrigatorios.
Evitar linguagem de produto/plataforma total antes de escopo e evidencias adicionais.

## 7) Frases permitidas

1. "A V0 prioriza decisao local auditavel com fluxo central claro."
2. "A interface foi desenhada para uso controlado, sem promover sinais secundarios ao centro."
3. "O caminho de verificacao offline existe como conferencia, nao como nova autoridade."

## 8) Frases proibidas (overclaim)

1. "A V0 entrega convergencia global."
2. "A V0 ja e um runtime completo de sync."
3. "A V0 e uma plataforma pronta para todos os casos."
