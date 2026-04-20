# NEXO Interface V0 Operator Guide

## 1) O que e a Interface V0

A Interface V0 e uma superficie operacional estreita para leitura humana de decisao local auditavel.  
O centro desta interface e:

- `evaluate` deterministico
- `final_decision`
- `trace`
- `audit trail`
- `verify offline` com Zig

Tudo fora desse centro aparece como contexto secundario.

## 2) Fluxo principal do operador

1. Ler `final_decision` como resultado principal da avaliacao local.
2. Conferir `trace` para entender causalidade da decisao.
3. Validar consistencia em `audit trail` (hash, tipo, origem, canal, timestamp).
4. Usar `verify offline (Zig)` quando precisar de conferencia independente.
5. Tratar sinais secundarios apenas como contexto diagnostico.

## 3) Como ler o centro da tela

### `final_decision`

E o ponto central para orientacao do operador na V0.  
Nao deve ser escondido por paineis secundarios.

### `trace`

Mostra o caminho causal local da decisao (`kind`, `summary`, `origin`, `timestamp`).  
Serve para explicabilidade operacional da decisao exibida.

### `audit trail`

Mostra evidencia local rastreavel da decisao corrente (event hash, tipo, origem, canal, timestamp).  
Serve para inspeção e auditoria local, nao para afirmar verdade global.

## 4) O que significa `verify offline (Zig)`

`verify offline (Zig)` e uma capacidade de conferencia independente fora da UI.  
Ela reforca verificabilidade local e auditavel.  
Nao cria nova autoridade de runtime e nao substitui contrato semantico da decisao.

## 5) O que a Interface V0 prova

- a decisao exibida e legivel, rastreavel e auditavel localmente;
- o operador consegue seguir o fluxo central sem depender de paineis amplos;
- existe caminho explicito de verificacao offline.

## 6) O que a Interface V0 nao prova

- nao prova verdade global;
- nao prova convergencia global;
- nao executa sync automatico;
- nao transforma diagnostico em autoridade de runtime;
- nao e consenso nem runtime completo de sync.

## 7) Elementos secundarios (diagnosticos)

Witness/diagnosticos, Julia observadora, decision_cycle experimental e health operacional podem aparecer como contexto.  
Esses elementos sao secundarios e nao devem competir com o centro da decisao.

## 8) Fora de escopo da V0

- dashboard amplo como superficie principal;
- promover mesh/P2P ao centro da experiencia;
- promover decision_cycle experimental a autoridade primaria;
- acao automatica de runtime a partir de sinal diagnostico.

## 9) 3 erros de interpretacao a evitar

1. Tratar contexto secundario como mais importante que `final_decision`.
2. Ler `verify offline (Zig)` como nova fonte de autoridade de runtime.
3. Inferir verdade global, convergencia global ou sync automatico a partir da tela V0.
