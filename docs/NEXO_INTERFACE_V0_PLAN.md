# NEXO Interface V0 Plan

## Objetivo

Congelar uma interface V0 estreita, orientada ao operador humano, com centro fechado no fluxo deterministico de avaliacao e auditoria.

## 1) Centro da Interface V0

O centro da Interface V0 e:

- `evaluate` deterministico;
- `final_decision`;
- `trace` explicavel;
- `audit trail` verificavel;
- verificabilidade offline com Zig.

Qualquer elemento fora desse centro entra apenas como contexto secundario.

## 2) Workflow Minimo do Operador

1. Submeter payload para `evaluate`.
2. Ler `final_decision`.
3. Inspecionar `trace` para entender o motivo da decisao.
4. Conferir `audit trail` associado.
5. Validar offline com Zig quando necessario.

## 3) Superficies Principais

### Superficie Principal (Operator Core View)

- entrada de avaliacao (payload);
- `final_decision` em destaque;
- `trace` legivel e navegavel;
- referencia direta ao `audit trail`;
- status de verificabilidade offline (Zig) como capacidade de conferencia, nao como autoridade nova.

### Superficie Secundaria (Edge Context)

- Witness Layer;
- Julia observadora;
- mesh/P2P;
- `decision_cycle` experimental;
- paines amplos de chat/relay/AI/network.

Esses itens permanecem vivos, mas nao organizam a narrativa central da V0.

## 4) Obrigatorio na Tela Principal

- `final_decision` visivel sem ambiguidade;
- `trace` com causalidade local da decisao;
- ponte para `audit trail` da decisao corrente;
- indicacao clara de que a verificacao offline e possivel.

## 5) O que Fica em Superficie Secundaria

- diagnosticos de Witness Layer;
- observabilidade Julia;
- sinais de mesh/P2P;
- artefatos `decision_cycle`;
- telemetria expandida.

Regra: superficie secundaria informa contexto, mas nao redefine a decisao principal.

## 6) Non-claims Obrigatorios

- nao e consenso;
- nao e verdade global;
- nao e sync runtime completo;
- nao transforma diagnostico em autoridade de runtime;
- nao e claim de vantagem economica.

## 7) Fora de Escopo da V0

- automacao de acao operacional baseada em diagnostico;
- integracao de runtime mesh/sync no fluxo principal da interface;
- dashboard unificado amplo para todos os subsistemas;
- qualquer promocao semantica de bordas vivas para centro sem contrato explicito.

## 8) 3 Erros Fatais de UX/Semantica a Evitar

1. Esconder `final_decision` atras de paines secundarios.
2. Tratar sinais de witness/mesh como fonte primaria de autoridade da interface.
3. Apresentar telemetria experimental como prova de comportamento global ou economico.

## Regra de Evolucao

`Closed center, live edges, gradual promotion by semantic merit`:

- o centro fica pequeno e estavel;
- bordas evoluem sem sequestrar a tela principal;
- promocao de borda para centro exige contrato semantico explicito e verificavel.
