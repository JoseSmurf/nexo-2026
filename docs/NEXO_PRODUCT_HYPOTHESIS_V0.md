# NEXO Product Hypothesis v0

## 1. O que o NEXO e

NEXO e um sistema local-first, verificavel e resiliente para fluxos sensiveis, com um nucleo deterministico em Rust que produz evidencias reproduziveis.

No estado atual, o projeto prioriza contratos pequenos e auditaveis (witnesses, guardrails e harnesses) para reduzir ambiguidade operacional antes de qualquer integracao de sync runtime real.

## 2. O que o NEXO nao e

NEXO, no v0 atual, nao e:

- consenso;
- CRDT runtime;
- verdade global da malha;
- protocolo completo de sincronizacao em runtime;
- produto pronto para operacao distribuida irrestrita.

Tambem nao substitui sistemas financeiros globais e nao deve ser descrito como "nova internet".

## 3. O que ja esta consolidado tecnicamente

Base consolidada na `main`:

- Witness Layer:
  - `AcceptedStateWitness`
  - `RecoveryWitness`
  - `RelayNeutralityProof`
- Sync diagnostics read-only:
  - comparability local de slices
  - freshness diagnostica
  - actionability conservadora (`DiagnosticOnly`/`RequiresExplicitRuntimeContract`)
  - replay/dedup/sequencing diagnostics
- Guardrails de contrato:
  - dominio temporal persistivel fail-closed
  - separacao explicita entre evidencia local, sinal operacional e diagnostico derivado
- Two-Snapshot Sync Economics Harness:
  - artefato canonico em Rust
  - leitura/analise Julia com validacao de schema e parsing fail-closed
- Hardening de supply-chain:
  - atualizacoes para advisories criticos e `cargo deny` em verde.

## 4. O que ainda e hipotese

Ainda sao hipoteses (nao entregas de runtime):

- Sync v0 operacional orientado por evidencias locais;
- Contrato robusto para pull/delta com integracao em runtime;
- Politica de convergencia mais forte para cenarios multi-no heterogeneos;
- Evolucao de produto para ambientes reais com restricoes de conectividade e governanca.

## 5. Nicho inicial mais plausivel

Nicho inicial plausivel: fluxos locais e semi-distribuidos que exigem rastreabilidade tecnica e verificacao independente, mas nao dependem de consenso global.

Exemplos:

- operacao local com reconexao intermitente;
- trilhas auditaveis entre poucos nos confiados;
- ambientes que valorizam determinismo e evidencia reproduzivel antes de escala.

## 6. Casos de uso errados

Nao e adequado usar NEXO hoje para:

- prometer convergencia global forte entre muitos dominios sem contrato adicional;
- tratar diagnostico local como decisao automatica de runtime;
- vender sincronizacao plena em tempo real como capacidade ja entregue;
- inferir autoridade semantica do relay;
- tratar observabilidade como protocolo de replicacao.

## 7. Evidence-Guided Work

O metodo de trabalho do NEXO e "evidence-guided":

1. definir um invariante pequeno e testavel;
2. implementar contrato read-only conservador;
3. provar comportamento com testes deterministas;
4. declarar explicitamente o que a evidencia prova e o que nao prova;
5. somente depois discutir integracao de runtime, com contrato explicito.

Esse metodo reduz risco de overclaim e de acoplamento prematuro.

### Lente conceitual: pesquisa sobre Bitcoin Core

Leitura util para o NEXO (sem equivalencia de mineracao):

- a pesquisa nao ensina "como achar o hash";
- ela ajuda a separar trabalho inevitavel de desperdicio operacional evitavel;
- ela reforca contratos entre quem prepara trabalho e quem executa trabalho caro;
- ela reforca exigencia de sinais locais minimos antes de aumentar custo ou interpretacao.

No NEXO, essa lente deve ser aplicada como disciplina operacional de mapa:

- estrutura -> comparabilidade -> freshness -> actionability.

Essa lente NAO autoriza afirmar:

- verdade global;
- consenso;
- autoridade de runtime;
- otimizacao criptografica;
- sync automatico.

## 8. Relacao entre Rust, Julia e a arquitetura

- Rust e a fonte de verdade de contrato e artefato canonico.
- Julia le, valida e analisa artefatos para observabilidade quantitativa.
- A ponte Rust -> Julia existe para analise, nao para governar runtime.

Em resumo: Rust define e mede; Julia interpreta e compara. Nenhuma das duas camadas deve extrapolar para "verdade global" sem contrato adicional.

## 9. Proximos passos

Passos conservadores para a proxima fase:

1. consolidar tese de produto com limites semanticos explicitos;
2. ampliar hardening de bordas (freshness/comparability/consumo diagnostico) sem integrar sync real;
3. evoluir harnesses economicos e cenarios de teste para suportar decisao de produto;
4. definir contrato minimo de runtime apenas quando houver evidencia suficiente.

## 10. Glossario curto (termos sensiveis)

- `LocalEvidence`: evidencia local deterministica; nao e verdade global.
- `ContractTruth`: verdade de contrato limitado (ex.: harness/garantia especifica), nao autoridade global.
- `OperationalSignal`: sinal operacional util para observacao; nao decisao de runtime.
- `DerivedDiagnostic`: diagnostico derivado de artefatos locais; sem autoridade semantica.
- `DiagnosticOnly`: resultado que nao deve acionar runtime automaticamente.
- `RequiresExplicitRuntimeContract`: qualquer uso em runtime depende de contrato explicito previo.
- `EquivalentLocalSlice`: equivalencia local de uma janela comparavel; nao prova convergencia global.
- `NotComparableLocalSlice`: contexto local insuficiente/incompatível para comparacao valida.
- `FreshEnoughLocalDiagnostic`: diagnostico local ainda util na janela de freshness; nao implica acao automatica.

---

Hipotese central v0:

> Se o NEXO evoluir por evidencias locais deterministicas, com limites semanticos explicitos e integracao gradual, ele pode construir um caminho realista para sync economico e resiliente sem prometer autoridade global antes da hora.
