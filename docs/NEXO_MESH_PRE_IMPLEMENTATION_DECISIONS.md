# NEXO Mesh Pre-Implementation Decisions

## Objetivo

Este documento extrai, de forma curta e operacional, as decisões que precisam virar contrato antes de qualquer implementação do NEXO Mesh.

O foco aqui não é desenhar novas features. O foco é reduzir ambiguidade antes de mexer em transporte, sincronização, retenção local e papéis de nós.

Este documento parte do estado real do repositório atual:

- já existe núcleo determinístico em Rust;
- já existe substrato local/P2P sob a feature `network`;
- já existe relay passivo, observabilidade local e verificação externa;
- ainda não existe cliente mobile real;
- ainda não existe `anchor` implementado;
- `/api/state` continua sendo observabilidade operacional local, não protocolo de malha.

## Decisões que precisam virar contrato agora

### 1. Identidade do nó

- O que precisa ser decidido:
  definição de identidade canônica do nó, escopo da chave local, regras de rotação e o que caracteriza “o mesmo nó” após restore ou migração.
- Por que isso importa:
  o nó só consegue participar de uma malha previsível se identidade e continuidade forem inequívocas.
- Qual risco existe se ficar ambíguo:
  clones, reaproveitamento indevido de identidade, perda de confiança no sender e conflitos de continuidade.
- Qual parte do repositório atual toca nesse tema:
  `src/offline_store.rs`, `src/message.rs`
- O que já existe:
  identidade local persistida e `sender_id` no envelope.
- O que precisa ser formalizado:
  lifecycle da identidade.
- O que ainda é futuro:
  política de identidade entre múltiplos dispositivos do mesmo usuário.

### 2. Monotonicidade de nonce

- O que precisa ser decidido:
  garantia operacional de monotonicidade por sender, inclusive após restart, restore, reinstall e rejoin.
- Por que isso importa:
  replay protection e ordering parcial dependem disso.
- Qual risco existe se ficar ambíguo:
  replay aceito, rejeição de eventos válidos ou ambiguidade de ordering.
- Qual parte do repositório atual toca nesse tema:
  `src/offline_store.rs`, `src/message.rs`
- O que já existe:
  contador monotônico persistido por sender.
- O que precisa ser formalizado:
  como o contador sobrevive a recovery e quais eventos invalidam continuidade.
- O que ainda é futuro:
  políticas específicas para dispositivos móveis reinstalados.

### 3. Persistência local mínima

- O que precisa ser decidido:
  quais dados são mínimos e obrigatórios para um nó continuar confiável localmente.
- Por que isso importa:
  sem um núcleo mínimo de persistência, qualquer restore degrada dedup, sync ou identidade.
- Qual risco existe se ficar ambíguo:
  estado parcial, replay, perda de cursores e retenção inconsistente.
- Qual parte do repositório atual toca nesse tema:
  `src/offline_store.rs`, `src/audit_store.rs`
- O que já existe:
  SQLite local para P2P e JSONL local para auditoria.
- O que precisa ser formalizado:
  conjunto mínimo obrigatório para operação e recovery.
- O que ainda é futuro:
  política de retenção diferenciada por classe de nó.

### 4. Restore / reinstall / rejoin

- O que precisa ser decidido:
  diferença formal entre restore válido, reinstall limpo, nó novo e rejoin do mesmo nó.
- Por que isso importa:
  esse é o ponto mais frágil para celulares e para qualquer nó que perca storage local.
- Qual risco existe se ficar ambíguo:
  nós retornando com identidade sem continuidade, nonce incoerente ou estado parcialmente reaproveitado.
- Qual parte do repositório atual toca nesse tema:
  `src/offline_store.rs`, `src/chat.rs`
- O que já existe:
  persistência local e identidade armazenada.
- O que precisa ser formalizado:
  semântica de recuperação e invalidação.
- O que ainda é futuro:
  fluxo operacional para cliente mobile real.

### 5. Papel do relay

- O que precisa ser decidido:
  limites formais do relay como store-and-forward passivo, bridge opcional e retenção intermediária.
- Por que isso importa:
  relay é a borda mais fácil de virar autoridade implícita por acidente.
- Qual risco existe se ficar ambíguo:
  reinterpretação de eventos, concentração indevida de confiança ou ordering informal.
- Qual parte do repositório atual toca nesse tema:
  `src/bin/nexo_relay.rs`, `src/relay_client.rs`
- O que já existe:
  relay HTTP simples com validação e deduplicação.
- O que precisa ser formalizado:
  o que relay pode e não pode fazer.
- O que ainda é futuro:
  qualquer noção de `anchor` como papel separado.

### 6. Semântica de sincronização

- O que precisa ser decidido:
  regras de sync, replay, dedup, anti-loop, cursor e aceitação de itens remotos.
- Por que isso importa:
  transporte sem contrato de sync não garante convergência.
- Qual risco existe se ficar ambíguo:
  malha que troca pacotes mas não converge de forma confiável.
- Qual parte do repositório atual toca nesse tema:
  `src/chat.rs`, `src/network_udp.rs`, `src/offline_store.rs`, `src/relay_client.rs`
- O que já existe:
  sync básico, cursor persistido, dedup e anti-loop.
- O que precisa ser formalizado:
  um contrato único e explícito.
- O que ainda é futuro:
  sync entre nós heterogêneos e móveis com garantias fortes.

### 7. Convergência esperada

- O que precisa ser decidido:
  o que significa “dois nós equivalentes convergiram” e em que condições isso deve acontecer.
- Por que isso importa:
  sem definição de convergência, não existe critério técnico para validar o Mesh.
- Qual risco existe se ficar ambíguo:
  bugs de sync virarem comportamento “aceitável” sem prova de correção.
- Qual parte do repositório atual toca nesse tema:
  `src/chat.rs`, `src/network_udp.rs`, `src/offline_store.rs`
- O que já existe:
  blocos básicos de sync e persistência.
- O que precisa ser formalizado:
  invariantes de convergência após replay, restart e relay pull.
- O que ainda é futuro:
  comparação multi-nó real fora de ambiente controlado.

### 8. Separação entre estado operacional e estado de malha

- O que precisa ser decidido:
  quais campos são apenas observabilidade local e quais poderiam, no futuro, participar de contrato distribuído.
- Por que isso importa:
  confundir UI/state operacional com estado de malha é um erro de arquitetura fácil e perigoso.
- Qual risco existe se ficar ambíguo:
  `/api/state` virar pseudo-protocolo por inferência, levando a decisões baseadas em campos derivados.
- Qual parte do repositório atual toca nesse tema:
  `src/api/state.rs`, `nexo_ui/core_adapter.rb`
- O que já existe:
  projeção operacional local com campos verbatim e derivados.
- O que precisa ser formalizado:
  fronteira semântica entre observabilidade e replicação.
- O que ainda é futuro:
  qualquer state contract de malha entre nós.

### 9. Fronteira entre Rust e outras linguagens

- O que precisa ser decidido:
  quais contratos JSON/artifact podem ser consumidos por Ruby, Julia e Zig sem reinterpretação semântica.
- Por que isso importa:
  o valor arquitetural do projeto depende de Rust permanecer como fonte única de verdade.
- Qual risco existe se ficar ambíguo:
  UI, observação ou tooling começarem a “corrigir” ou preencher lacunas do core.
- Qual parte do repositório atual toca nesse tema:
  `src/api/state.rs`, `src/engine/trace.rs`, `src/audit/hash.rs`, `nexo_ui/core_adapter.rb`, `julia/flow_observer.jl`, `tools/zig/src/verify.zig`
- O que já existe:
  boa separação de papéis entre Rust, Ruby, Julia e Zig.
- O que precisa ser formalizado:
  contratos pequenos, estáveis e conservadores.
- O que ainda é futuro:
  contratos específicos para malha distribuída e observação multi-nó.

### 10. Papel de mobile node vs stable pc node

- O que precisa ser decidido:
  quais responsabilidades operacionais cada classe de nó pode assumir sem alterar o protocolo.
- Por que isso importa:
  celular e PC não têm o mesmo perfil de disponibilidade, retenção e recuperação.
- Qual risco existe se ficar ambíguo:
  depender do celular para retenção/estabilidade ou tratar o PC estável como autoridade semântica.
- Qual parte do repositório atual toca nesse tema:
  `src/chat.rs`, `src/offline_store.rs`, `src/bin/nexo_relay.rs`, `docs/NEXO_MESH_ARCHITECTURE_NOTES.md`
- O que já existe:
  substrato técnico que permite nó local e relay.
- O que precisa ser formalizado:
  papéis operacionais por classe de dispositivo.
- O que ainda é futuro:
  implementação de cliente mobile real e de um futuro papel de `anchor`.

## Decisões que podem esperar

- refinamento completo de versionamento de wire protocol, desde que o contrato de sync seja fechado antes;
- política internet-facing completa para a malha, desde que o v0 permaneça local-first e controlado;
- observação Julia multi-nó, desde que Julia continue fora do write path;
- semântica avançada de chat global distribuído;
- qualquer noção de `anchor` como componente implementado.

## Riscos de implementar antes de fechar os contratos

- solidificar um protocolo de malha em cima de hipóteses operacionais ainda vagas;
- misturar observabilidade local com estado distribuído real;
- aceitar replay, restore inconsistente ou duplicação de identidade como “casos de borda” quando na verdade são falhas de contrato;
- transformar relay em autoridade implícita por falta de limites claros;
- deixar Ruby, Julia ou tooling preencherem sem querer lacunas que deveriam ser resolvidas em Rust.

## Ordem recomendada de fechamento

1. identidade do nó
2. monotonicidade de nonce
3. persistência local mínima
4. restore / reinstall / rejoin
5. papel do relay
6. semântica de sincronização
7. convergência esperada
8. separação entre estado operacional e estado de malha
9. fronteira entre Rust e outras linguagens
10. papel de `mobile node` vs `stable pc node`

## Checklist de prontidão antes de escrever código

- [ ] identidade do nó definida com critérios de continuidade e invalidação
- [ ] monotonicidade de nonce definida para restart, restore e reinstall
- [ ] persistência local mínima definida por classe de nó
- [ ] semântica de restore, reinstall e rejoin documentada
- [ ] papel do relay fechado como passivo
- [ ] contrato de sincronização documentado
- [ ] convergência esperada definida como invariantes testáveis
- [ ] `/api/state` explicitamente tratado como observabilidade local, não como protocolo de malha
- [ ] fronteira entre Rust e outras linguagens explicitamente congelada
- [ ] papel operacional de `mobile node` vs `stable pc node` definido sem transformar PC em autoridade
