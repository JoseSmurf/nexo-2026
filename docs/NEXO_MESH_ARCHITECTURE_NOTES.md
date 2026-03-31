# NEXO Mesh Architecture Notes

## Objetivo do documento

Este documento registra a base arquitetural atual do NEXO e define, de forma técnica e objetiva, quais bordas precisam ser fortalecidas antes de qualquer implementação séria de um futuro Nexo Mesh.

O objetivo aqui não é desenhar um produto imaginário. O objetivo é:

- partir do repositório atual;
- separar claramente o que já existe do que ainda falta;
- congelar decisões provisórias úteis;
- reduzir risco antes de introduzir malha distribuída entre celulares e PCs.

Este documento não altera o núcleo determinístico e não propõe mudanças de runtime neste momento.

## O que o Nexo é hoje

Hoje o NEXO é, concretamente:

- um núcleo de decisão determinística em Rust;
- um contrato explícito de `DecisionTrace`;
- uma trilha de auditoria com `audit_hash`, `record_hash` e `prev_record_hash`;
- uma API HTTP com validação fail-closed;
- um verificador externo em Zig;
- uma superfície de observabilidade e operação;
- um conjunto experimental, mas real, de capacidades P2P/relay/discovery atrás da feature `network`.

Hoje o repositório ainda não contém:

- um cliente mobile real;
- um componente `anchor` implementado;
- um contrato fechado de sincronização de malha entre nós heterogêneos;
- uma topologia distribuída observável de forma confiável via `/api/state`.

O repositório já contém componentes suficientes para provar:

- decisão reproduzível;
- hashing auditável;
- persistência local;
- inspeção operacional;
- verificação externa independente.

O repositório ainda não é uma malha distribuída madura.

## O que pode servir de base para o Nexo Mesh

Os componentes abaixo já existem e podem servir de base real:

- Mensagem canônica com limite explícito de payload em `src/message.rs`
- `content_hash` e `event_hash` determinísticos em `src/message.rs`
- Assinatura de envelope com Ed25519 em `src/message.rs`
- Persistência local em SQLite com:
  - `messages`
  - `seen_hashes`
  - `forwarded_hashes`
  - `relay_state`
  - `sender_counters`
  - `node_identity`
  em `src/offline_store.rs`
- Transporte UDP com ACK, discovery, sync item e sync request em `src/network_udp.rs`
- Relay HTTP com dedup e validação de assinatura em `src/bin/nexo_relay.rs`
- Cliente de relay em `src/relay_client.rs`
- Discovery local e registry de relays em `src/discovery.rs` e `src/relay_registry.rs`
- Projeção de estado operacional em `src/api/state.rs`
- Observação determinística do fluxo em Julia em `julia/flow_observer.jl`
- Verificação offline independente em Zig em `tools/zig/src/verify.zig`

Essa base já sustenta experimentação local e controlada. Ela ainda não fecha, por si só, os contratos necessários para uma malha com nós móveis, retenção séria e sincronização robusta.

Em especial, `src/api/state.rs` deve ser lido como projeção de observabilidade operacional local. Ele não é, hoje, um protocolo de replicação nem um espelho fiel da topologia de uma futura malha.

## Princípios do Nexo Mesh

Os princípios abaixo devem ser mantidos desde o início:

- Rust continua sendo o núcleo de confiança.
- Outras linguagens podem observar, apresentar e verificar, mas não contornam Rust.
- O transporte não decide semântica.
- O relay não decide semântica.
- A IA observa, resume e mede, mas não decide o núcleo.
- O estado distribuído deve ser aceito apenas após validação explícita em Rust.
- Toda borda deve operar em modo fail-closed.
- Identidade, sincronização e persistência devem ser fechadas antes de “chat global distribuído”.
- `/api/state` continua sendo um contrato de observabilidade operacional local, não um contrato de replicação entre nós.
- Campos derivados de UI/estado operacional não devem ser promovidos, por inferência, a verdade de topologia ou sincronização.

## Papéis dos nós

### Mobile node

Estado atual no repositório:

- não existe cliente mobile implementado;
- existe apenas um substrato local/P2P em Rust que pode servir de base futura.

Papel futuro esperado:

- nó móvel com armazenamento local;
- emissor e receptor de mensagens;
- participante de sync;
- consumidor de relay quando necessário.

Restrições operacionais:

- não deve ser assumido como âncora principal;
- sofre com bateria, sono, troca de rede, clock drift e reinstalação;
- precisa de recovery explícito para identidade e nonce.

### Stable PC node

Estado atual no repositório:

- o repositório já suporta um nó local em Rust, relay HTTP simples e superfícies de observação/inspeção;
- isso permite tratar o PC como candidato natural a nó mais estável, mas esse papel ainda não está formalizado como contrato de malha.

Papel futuro esperado:

- nó mais estável operacionalmente;
- retenção local mais confiável;
- melhor ponto para observabilidade e inspeção;
- bom candidato a relay e a um futuro ponto estável de sincronização local.

Restrições:

- não deve virar autoridade de decisão só por ser mais estável;
- disponibilidade operacional não equivale a autoridade semântica.

### Relay

Estado atual no repositório:

- já existe relay HTTP simples com validação de assinatura e deduplicação;
- ele deve ser entendido como store-and-forward passivo, não como autoridade.

Papel esperado:

- store-and-forward passivo;
- deduplicação;
- redistribuição;
- retenção intermediária curta ou média.

Restrições:

- não reescreve evento;
- não decide ordering sem contrato explícito;
- não promove confiança automaticamente;
- não define verdade do sistema.

### Observer

Estado atual no repositório:

- já existe observação determinística em Julia e projeção operacional em Rust/Ruby;
- isso já cumpre o papel de observação local, não de coordenação da malha.

Papel esperado:

- medir fluxo;
- resumir intensidade e regime;
- explicar o estado para operador e UI.

Restrições:

- não altera o núcleo;
- não entra no write path;
- não redefine semântica do state produzido por Rust.

## Matriz das bordas

| borda | papel da borda | estado atual no repositório | lacuna para Nexo Mesh | risco principal | componente guardião em Rust | teste/garantia que deveria existir | prioridade |
|---|---|---|---|---|---|---|---|
| dispositivo | proteger identidade, continuidade e estado operacional do nó | identidade local persistida e nonce monotônico já existem em `src/offline_store.rs`; mensagem canônica já carrega `sender_id`, `nonce` e `timestamp` em `src/message.rs` | falta contrato explícito para reinstalação, recovery, rotação de chave, perda e rejoin do nó | perda de chave, reset de nonce, duplicação de identidade | `src/offline_store.rs`, `src/message.rs` | garantia de recuperação segura de identidade e de monotonicidade de nonce após restore/rejoin | crítica agora |
| armazenamento local | reter histórico e estado local com recuperação previsível | SQLite local existe para P2P em `src/offline_store.rs`; audit trail local JSONL existe em `src/audit_store.rs` | falta política fechada de retenção, backup, restore, migração e separação entre ativo e arquivado | corrupção, replay após restore, perda parcial de histórico | `src/offline_store.rs`, `src/audit_store.rs`, `src/audit/record.rs` | garantia de restore/rehydration sem quebrar dedup, chain e cursores | crítica agora |
| transporte | transformar bytes da rede em frames válidos ou rejeitar | UDP framing, ACK, sync, discovery e envelopes assinados já existem em `src/network_udp.rs` e `src/message.rs` | falta contrato formal de versionamento de protocolo e compatibilidade entre versões de nós | pacote malformado, spoofing, drift de protocolo | `src/network_udp.rs`, `src/message.rs` | garantia de compatibilidade/versionamento e de rejeição total de inputs inválidos | importante em seguida |
| relay | redistribuir e reter envelopes sem virar autoridade | relay HTTP simples já valida assinatura e dedup em `src/bin/nexo_relay.rs`; não existe componente `anchor` separado | falta definição formal do papel do relay como passivo, bridge ou futuro ponto estável de sincronização | relay virar ponto de verdade implícito | `src/bin/nexo_relay.rs`, `src/relay_client.rs` | garantia de neutralidade do relay: sem reinterpretação, sem autoridade semântica | crítica agora |
| sincronização | fazer nós convergirem de forma segura e previsível | já existe sync básico, cursor persistido, anti-loop e dedup em `src/chat.rs`, `src/offline_store.rs`, `src/network_udp.rs`, `src/relay_client.rs` | falta um contrato único e explícito de ordering, replay, convergência, restart e recuperação | troca de mensagens sem convergência confiável | hoje está disperso entre `src/chat.rs`, `src/offline_store.rs`, `src/network_udp.rs`, `src/relay_client.rs` | garantia de convergência sob replay, restart, relay pull e sync repetido | crítica agora |
| IA observadora | observar fluxo sem influenciar o núcleo | Julia observa `/api/state` em `julia/flow_observer.jl`; analyzer determinístico em Rust também existe | falta delimitação formal para observação multi-nó e para apresentação consistente na malha | observação virar “verdade” operacional indevida | `src/api/state.rs` | garantia de não-autoridade: observação nunca altera estado do núcleo | importante em seguida |
| entre linguagens | impedir drift semântico entre Rust, Ruby, Julia e Zig | contratos já estão relativamente claros: Rust produz, Ruby apresenta, Julia observa, Zig verifica; a UI ainda tem fallbacks explícitos e campos derivados | falta endurecer ainda mais contratos de schema entre state, artifacts e futuro protocolo de malha, evitando que observabilidade local pareça semântica distribuída | camadas auxiliares reinterpretarem ou reconstruírem semântica | `src/api/state.rs`, `src/engine/trace.rs`, `src/audit/hash.rs` | testes de contrato preservando campos core-verbatim e artifacts estáveis | crítica agora |
| celular ↔ PC | separar nó móvel e nó estável sem mudar o protocolo | o repositório já suporta nó local, relay e armazenamento local, mas não possui cliente mobile real nem papel formal por classe de dispositivo | falta modelo operacional explícito para `mobile node`, `stable pc node`, `relay` e futuro `anchor` | confiar demais no celular para retenção, estabilidade ou sincronização | base distribuída entre `src/chat.rs`, `src/offline_store.rs`, `src/bin/nexo_relay.rs` | garantia de papel: mesmo protocolo com políticas operacionais diferentes por classe de nó | crítica agora |
| rede local ↔ internet pública | definir o que pode operar localmente e o que pode atravessar a internet com segurança | discovery LAN existe em `src/discovery.rs`; relay/registry HTTP existem em `src/relay_registry.rs` e `src/bin/nexo_relay.rs`; API admin já é fechada por padrão | falta política explícita de exposição pública para a futura malha e separação clara entre confiança local e borda internet-facing | usar mecanismos locais como se fossem solução global ou expor bordas frágeis | `src/api.rs`, `src/discovery.rs`, `src/relay_registry.rs`, `src/bin/nexo_relay.rs` | garantia de postura: discovery LAN não é discovery global confiável | importante em seguida |

### Observações importantes sobre o estado atual

- `src/api/state.rs` projeta observabilidade operacional local. Ele não deve ser tratado como protocolo de replicação entre nós.
- `peers_count` atual não representa topologia real da malha. Hoje ele é derivado de usuários únicos vistos em audit records.
- `relay_status`, `network_mode` e `mesh_status` atuais são fortemente derivados/configurados no runtime. Eles não equivalem, hoje, a medição direta de uma malha distribuída ativa.
- `recent_flow` é uma síntese operacional local de eventos, chat e observação. Ele não é um log causal distribuído.

## As 5 garantias que devem ser fechadas primeiro

### 1. Garantia de identidade do nó

Um nó restaurado, reinstalado ou migrado não pode reaparecer com identidade ambígua.

Isso implica:

- chave persistida com política explícita;
- monotonicidade de nonce;
- diferenciação entre “nó restaurado” e “nó novo”.

### 2. Garantia de convergência de sincronização

Sync repetido, replay, restart e relay pull não podem produzir estados divergentes entre nós equivalentes.

Isso implica:

- ordering explícito;
- replay/dedup consistentes;
- política de convergência documentada.

### 3. Garantia de persistência e recuperação

Backup/restore local não pode quebrar:

- dedup;
- chain de auditoria;
- cursores de relay;
- identidade;
- monotonicidade do sender.

### 4. Garantia de neutralidade do relay

Relay deve ser explicitamente passivo:

- recebe;
- valida o mínimo necessário;
- deduplica;
- redistribui;
- não decide.

### 5. Garantia de fronteira semântica entre linguagens

Rust deve continuar como única fonte de verdade semântica.

Ruby, Julia e Zig:

- consomem contratos;
- não redefinem regras;
- não corrigem o núcleo;
- não mascaram ausência de estado real.

## As 3 bordas que podem esperar no v0

### 1. IA observadora

Ela já está no papel correto e não precisa liderar o v0 da malha.

### 2. Rede local ↔ internet pública

O v0 pode começar local-first e controlado, sem resolver ainda toda a postura internet-facing.

### 3. Refinamento completo de transporte/versionamento

O transporte atual já serve para experimentação controlada. O que não pode esperar é o contrato de sync, não o refinamento final do wire protocol.

## O que não fazer ainda

- Não tratar o experimento P2P atual como protocolo final.
- Não usar `/api/state` como contrato principal de replicação entre nós.
- Não interpretar `peers_count`, `relay_status`, `network_mode` ou `mesh_status` como topologia real da malha.
- Não confiar em discovery LAN como solução global.
- Não transformar relay em autoridade implícita.
- Não usar celular como única âncora de retenção.
- Não misturar decisão determinística com lógica do chat distribuído.
- Não deixar Ruby ou Julia preencherem lacunas de verdade da malha.
- Não adicionar complexidade de consenso antes de fechar sync, identidade e persistência.

## Ordem de trabalho para as próximas 48 horas

### 1. Congelar o vocabulário dos nós

Definir claramente:

- `mobile node`
- `stable pc node`
- `relay`
- `observer`

### 2. Especificar o contrato de identidade

Definir:

- quando um nó é “o mesmo nó”;
- o que acontece em reinstalação;
- o que é restore válido;
- quando uma identidade anterior deve ser invalidada.

### 3. Especificar o contrato de sincronização

Definir:

- ordering esperado;
- replay policy;
- dedup policy;
- anti-loop policy;
- convergência esperada;
- comportamento após restart.

### 4. Especificar o papel do relay e do anchor

Definir:

- relay passivo;
- `anchor` apenas como conceito futuro, não como componente já implementado;
- retenção esperada;
- o que um relay não pode fazer.

### 5. Separar estado operacional de estado de malha

`/api/state` hoje é ótimo para observabilidade local. Antes do Mesh, deve ficar explícito que ele não é automaticamente o contrato de replicação entre nós.

## Decisões provisórias a congelar agora

As decisões abaixo são provisórias, mas já valem como guard rails:

- Rust continua como núcleo de confiança.
- A malha não pode contornar Rust.
- Relay é passivo até prova explícita em contrário.
- Celular é nó móvel, não âncora principal.
- PC pode atuar como nó mais estável, relay e observer já com a base atual; `anchor` continua sendo apenas conceito futuro neste documento.
- `/api/state` é contrato operacional/local de observabilidade, não contrato definitivo de replicação.
- `peers_count` não descreve topologia real da malha.
- `relay_status`, `network_mode` e `mesh_status` atuais são campos operacionais derivados/configurados.
- Julia continua como observador numérico.
- Zig continua como verificador externo.
- Antes de “chat global distribuído”, identidade, sync e persistência devem estar fechados.
