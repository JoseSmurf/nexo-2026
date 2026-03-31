# NEXO Mesh Node and Sync Contract

## Objetivo do documento

Definir, de forma estreita e contratual, o comportamento mínimo de nó e sincronização no v0 do NEXO Mesh.

Este documento não implementa Mesh e não substitui o núcleo determinístico em Rust. Ele organiza o que já existe hoje no repositório e o que ainda precisa virar contrato antes de qualquer evolução distribuída mais séria.

## Escopo

Este documento cobre:

- modelo mínimo do nó no v0;
- persistência local mínima para operação e recuperação;
- aceitação, validação, dedup, anti-loop, persistência e forwarding de eventos;
- papel do relay no v0;
- ordering e convergência esperada de forma conservadora;
- falhas e recuperação no caminho local-first.

Este documento não cobre:

- consenso sofisticado;
- CRDTs;
- contrato completo de cliente mobile;
- componente `anchor` implementado;
- uso de `/api/state` como protocolo de replicação;
- topologia distribuída global.

## O que já existe hoje no repositório

- `src/message.rs` já define `CanonicalMessage` com `sender_id`, `timestamp_utc_ms`, `nonce` e payload limitado.
- `src/message.rs` já define `event_hash` determinístico e assinatura/verificação Ed25519.
- `src/network_udp.rs` já define `SignedEvent`, `UdpFrame`, `SyncRequest` e `SyncItem`.
- `src/offline_store.rs` já persiste:
  - `messages`
  - `seen_hashes`
  - `forwarded_hashes`
  - `relay_state`
  - `sender_counters`
  - `node_identity`
- `src/chat.rs` já executa ingestão local com:
  - validação de evento assinado
  - dedup por `event_hash`
  - anti-loop por `origin_event_hash`
  - forwarding com `hops_remaining`
  - pull/sync local e via relay
- `src/relay_client.rs` já faz `push` e `pull` de `SignedEvent` serializado em JSON.
- `src/bin/nexo_relay.rs` já implementa relay HTTP passivo com validação, dedup e pull ordenado.
- `README.md` já documenta comportamento local-first, relay bridge e persistência de cursor de relay.

## O que precisa virar contrato

- qual é o modelo mínimo de nó no v0;
- quais dados locais são obrigatórios para operação correta;
- em que ordem um evento deve ser tratado no ingresso;
- quando um evento é aceito, rejeitado, duplicado ou não-forwardável;
- qual é o papel exato do relay no v0;
- qual ordering é assumido no v0;
- o que significa convergência suficiente no v0;
- como restore, replay e pull devem se comportar sem violar os invariantes locais.

## Relação deste documento com o contrato de identidade/lifecycle

Este documento assume como pré-condição o contrato definido em `docs/NEXO_MESH_NODE_IDENTITY_AND_LIFECYCLE.md`.

Isso implica:

- a identidade do nó e a monotonicidade de nonce já devem estar tratadas como invariantes prévios;
- restore, reinstall e rejoin não são redefinidos aqui;
- o contrato de sync depende da noção de continuidade do nó já ter sido congelada antes.

Sem essa pré-condição, replay protection, ordering parcial e rejoin ficariam semanticamente ambíguos.

## Modelo mínimo do nó no v0

No v0, um nó deve ser entendido como:

- uma identidade local persistida;
- um storage local persistido;
- um emissor e receptor de `SignedEvent`;
- um participante de sync local-first, opcionalmente com relay;
- um executor de validação, dedup, persistência e forwarding limitados.

Esse modelo não presume:

- cliente mobile real;
- malha global completa;
- autoridade distribuída fora do núcleo Rust.

## Persistência local mínima necessária

No v0, o nó só deve ser tratado como operacionalmente válido se mantiver, no mínimo:

- `node_identity`
- `sender_counters`
- `messages`
- `seen_hashes`
- `forwarded_hashes`
- `relay_state`

Isso já existe hoje em `src/offline_store.rs`.

O que ainda precisa ser formalizado:

- quais desses itens são obrigatórios para restore válido;
- quando perda parcial de um deles invalida continuidade operacional.

## O que é fonte de verdade local

No v0, a fonte de verdade local do nó é o storage persistido em Rust.

Isso significa:

- `messages` é a base local para histórico aceito;
- `seen_hashes` sustenta dedup/replay local;
- `forwarded_hashes` sustenta anti-loop de forwarding;
- `relay_state` sustenta continuidade de pull;
- `sender_counters` sustenta monotonicidade local do sender.

`/api/state` não é fonte de verdade de replicação.

## O que é um evento aceito pelo nó

No v0, um evento aceito pelo nó é um `SignedEvent` que:

- pode ser decodificado corretamente;
- possui `sender_id` válido;
- possui assinatura verificável;
- respeita o framing esperado;
- não viola dedup/replay local;
- não viola anti-loop local;
- pode ser persistido localmente.

Aceitação não implica autoridade global. Ela implica apenas aceitação válida no nó local.

## Ingresso de evento

No v0, o ingresso de evento deve ser entendido como pipeline local:

1. recepção do frame
2. decodificação
3. validação do envelope assinado
4. verificação de dedup/replay local
5. verificação de anti-loop local
6. persistência local
7. ACK ao emissor
8. forwarding opcional e limitado

Essa ordem já aparece de forma operacional em `src/chat.rs`, embora ainda não esteja congelada como contrato documental.

## Validação

No v0, a validação do evento deve incluir no mínimo:

- estrutura válida do frame;
- `sender_id` não vazio;
- `nonce` e `timestamp_utc_ms` presentes;
- assinatura válida do envelope;
- integridade entre campos do envelope e `event_hash` reconstruído.

O relay também já aplica validação mínima equivalente antes de aceitar `push`.

## Dedup

No v0, dedup local deve ser persistente e baseado em `event_hash`.

O que já existe:

- `messages` com `INSERT OR IGNORE`
- `seen_hashes`
- checagem explícita de duplicidade antes de inserir novamente

Consequência contratual:

- o mesmo `event_hash` não deve produzir múltiplas inserções locais;
- replay do mesmo evento deve ser tratado como duplicata, não como novo evento.

## Anti-loop

No v0, anti-loop deve ser tratado como mecanismo local e persistente.

O que já existe:

- `origin_event_hash`
- `hops_remaining`
- `forwarded_hashes`

Consequência contratual:

- um evento já forwardado pelo mesmo nó não deve ser forwardado novamente como se fosse novo;
- `hops_remaining` limita propagação;
- anti-loop não depende de confiança em relay.

## Persistência

Persistência acontece após validação suficiente para aceitação local.

No v0:

- evento aceito deve ser persistido antes de ser considerado parte do histórico local;
- cursor de relay deve ser persistido para sobreviver a restart;
- persistência incompleta não deve ser mascarada como sync bem-sucedido.

## Forwarding

No v0, forwarding é opcional, limitado e subordinado ao estado local.

O que já existe:

- forwarding apenas quando o evento foi realmente inserido;
- decremento de `hops_remaining`;
- compartilhamento limitado de `known_peers`.

Consequência contratual:

- duplicata não gera novo forwarding;
- evento aceito localmente pode ser forwardado somente dentro do orçamento de hops;
- forwarding não transforma o nó em autoridade.

## Pull / restore / replay

No v0:

- `pull` de relay é mecanismo de recuperação operacional simples;
- `since_ms` e `relay_state.last_relay_pull_since_ms` sustentam continuidade local do pull;
- replay continua sendo bloqueado por dedup local;
- restore não redefine o contrato de sync; ele apenas condiciona se o nó continua apto a usar pull sem quebrar invariantes.

O que ainda precisa ser formalizado:

- quando restore é suficientemente íntegro para reutilizar estado de pull;
- em que casos replay após restore invalida continuidade local.

## Papel do relay

No v0, o relay é store-and-forward passivo.

Ele pode existir como apoio operacional de disponibilidade, não como fonte de verdade semântica.

O repositório já implementa isso em `src/bin/nexo_relay.rs`.

## O que o relay pode fazer

- aceitar `push` de `SignedEvent` válido;
- validar estrutura e assinatura do envelope;
- deduplicar por `event_hash`;
- persistir o blob serializado;
- responder `pull` ordenado por `timestamp_ms ASC, rowid ASC`;
- reportar `inserted` e `duplicates`.

## O que o relay não pode fazer

- reescrever evento;
- redefinir semântica do sender;
- promover autoridade de ordering além do contrato simples de pull;
- impor verdade global;
- transformar `/pull` em prova de convergência;
- substituir o contrato de identidade do nó.

## Ordering no v0

No v0, o ordering deve ser tratado de forma simples e operacional.

O que já existe:

- `messages_since` ordena por `timestamp_utc_ms ASC, rowid ASC`
- relay ordena `pull` por `timestamp_ms ASC, rowid ASC`

Leitura contratual conservadora:

- esse ordering é suficiente para operação local-first e recuperação simples;
- ele não deve ser vendido como ordering global forte ou causalidade completa.

## Convergência esperada no v0

No v0, convergência esperada deve ser entendida de forma mínima:

- nós equivalentes, com identidade/lifecycle válidos e acesso ao mesmo conjunto de eventos, devem tender ao mesmo histórico aceito após ciclos suficientes de sync/pull;
- duplicatas e replay não devem multiplicar eventos já aceitos;
- relay pull deve ajudar recuperação, não redefinir verdade.

Isso não implica:

- consenso;
- ordering global forte;
- CRDT sofisticado;
- convergência formal multi-partição.

## Falhas e recuperação

No v0, falhas devem ser tratadas de forma fail-closed e operacionalmente simples.

Exemplos:

- evento inválido => rejeição
- assinatura inválida => rejeição
- duplicata => ACK/ignore conforme caminho local
- perda de estado mínimo => continuidade local questionável
- falha de relay => retry/backoff, sem promoção indevida de confiança

Recuperação continua subordinada ao contrato de identidade/lifecycle.

## Invariantes que o sistema deve preservar

- um evento inválido não pode entrar no histórico aceito como se fosse válido;
- o mesmo `event_hash` não pode produzir múltiplas inserções locais válidas;
- anti-loop local não pode depender de confiança em relay;
- relay não pode virar autoridade semântica;
- ordering simples de v0 não pode ser descrito como causalidade global forte.

## Riscos se o contrato ficar ambíguo

- sync parecer funcional sem garantir convergência mínima;
- replay e restore se misturarem de forma insegura;
- relay passar a concentrar confiança sem contrato explícito;
- UI ou observação local serem confundidas com estado de malha;
- ordering local simples ser tratado como verdade distribuída.

## O que fica fora do escopo por enquanto

- consenso distribuído;
- CRDT pesado;
- cliente mobile real;
- `anchor` como componente implementado;
- qualquer uso de `/api/state` como protocolo de replicação;
- semântica global sofisticada de membership/topologia;
- garantias fortes além do v0 local-first.

## Perguntas ainda abertas

- qual é o conjunto mínimo exato de estado local necessário para restore continuar apto a pull/sync?
- quando um cursor de relay restaurado ainda é semanticamente reutilizável?
- como formalizar melhor o aceite de `sender_id` sem confundir isso com o contrato de identidade canônica do nó?
- quais invariantes de convergência mínima serão exigidos em testes antes de qualquer implementação de Mesh?
- em que momento o ordering simples do v0 deixa de ser suficiente para a evolução da malha?
