# NEXO Mesh Node Identity and Lifecycle

## Objetivo do documento

Definir, de forma estreita e contratual, o que constitui a identidade de um nó no v0 do NEXO Mesh e como essa identidade deve se comportar ao longo do lifecycle local.

Este documento é uma pré-condição para o contrato completo de sincronização. Ele não define sync, convergência de malha nem política completa de transporte.

## Escopo

Este documento cobre:

- identidade local do nó;
- chave local e escopo da identidade;
- nonce e monotonicidade;
- estados do nó ao longo do lifecycle;
- restore, reinstall, rejoin e perda de identidade;
- implicações mínimas para `mobile node` e `stable pc node`.

Este documento não cobre:

- contrato completo de sync;
- topologia de malha;
- política internet-facing;
- cliente mobile implementado;
- qualquer componente `anchor` já existente.

## O que já existe hoje no repositório

- `src/offline_store.rs` já persiste `node_identity` em SQLite.
- `src/offline_store.rs` já persiste `sender_counters` e expõe `next_nonce()` monotônico por sender.
- `src/message.rs` já inclui `sender_id`, `timestamp_utc_ms` e `nonce` no `CanonicalMessage`.
- `src/message.rs` já faz `event_hash` determinístico sobre identidade, tempo, nonce e conteúdo.
- `src/chat.rs` já usa `get_or_create_identity()` e `next_nonce()` no caminho P2P local.
- O repositório ainda não possui cliente mobile real.
- O repositório ainda não possui contrato explícito de restore/reinstall/rejoin.

## O que precisa virar contrato

- o que é a identidade canônica de um nó no v0;
- qual é o escopo da chave local;
- quando um nó continua sendo o mesmo nó após restore;
- quando reinstall implica nó novo;
- como a monotonicidade de nonce deve ser preservada;
- quando perda de identidade invalida continuidade anterior;
- como diferenciar `mobile node` e `stable pc node` sem mudar a semântica do núcleo.

## O que é a identidade canônica de um nó no v0

No v0, a identidade canônica de um nó deve ser tratada como **identidade local da instalação persistida em storage local**, materializada por uma chave local persistida e refletida no `sender_id` usado para emissão de eventos.

Isso implica:

- o contrato é de identidade do nó local, não de identidade do usuário;
- o contrato é de instalação/dispositivo local, não de conta global;
- o nó só continua sendo “o mesmo nó” se preservar material de identidade e continuidade operacional compatível.

O que já existe:

- persistência local de `node_identity`;
- `sender_id` no envelope.

O que precisa ser formalizado:

- relação exata entre chave persistida e `sender_id`;
- regra de continuidade entre instalações.

## Chave local e escopo da identidade

No v0:

- a chave local representa a identidade do nó;
- a chave é local ao storage persistido da instalação;
- a chave não deve ser tratada, por enquanto, como identidade compartilhada entre múltiplos dispositivos do mesmo usuário.

Consequência contratual:

- mesma chave local persistida + continuidade de estado compatível => mesmo nó;
- chave local perdida ou substituída => continuidade anterior não pode ser presumida.

O que já existe:

- `node_identity` persistida em SQLite em `src/offline_store.rs`.

O que ainda é futuro:

- política de identidade multi-dispositivo;
- rotação formal de chave.

## Nonce e monotonicidade

No v0:

- `nonce` é monotônico por sender local;
- o valor deve sobreviver a restart normal;
- restore só é válido se preservar continuidade suficiente para não violar monotonicidade;
- reinstall sem continuidade preservada não deve fingir continuidade anterior.

O que já existe:

- `sender_counters` persistidos;
- `next_nonce()` monotônico por sender.

O que precisa ser formalizado:

- o que conta como continuidade suficiente para manter monotonicidade;
- quando monotonicidade anterior deve ser considerada encerrada.

## Estados possíveis do nó

### Nó novo

- instalação sem identidade anterior confiável;
- inicia identidade local nova;
- não herda continuidade anterior.

### Nó ativo

- identidade local válida;
- storage local coerente;
- monotonicidade de nonce preservada.

### Nó restaurado

- identidade local e estado mínimo foram restaurados de forma compatível;
- pode continuar como o mesmo nó, se invariantes forem preservados.

### Nó reinstalado

- instalação refeita sem continuidade suficientemente comprovada;
- não deve assumir automaticamente identidade anterior.

### Nó inválido

- identidade local corrompida, incompleta, ambígua ou incompatível com continuidade anterior;
- não deve continuar operando como se fosse o mesmo nó.

## Transições válidas

- `nó novo -> nó ativo`
- `nó ativo -> nó restaurado`, se identidade e monotonicidade permanecerem válidas
- `nó restaurado -> nó ativo`, após validação local bem-sucedida
- `nó ativo -> nó inválido`, quando identidade ou estado mínimo ficarem incoerentes
- `nó reinstalado -> nó novo`, quando não houver continuidade válida com a instalação anterior

## Transições inválidas

- `nó reinstalado -> nó ativo` assumindo automaticamente identidade anterior
- `nó inválido -> nó ativo` sem revalidação explícita
- `nó novo -> nó restaurado` sem material de continuidade
- qualquer transição que preserve `sender_id` efetivo sem preservar monotonicidade compatível

## Restore

Restore deve ser tratado como continuação do mesmo nó **somente se**:

- a identidade local persistida for restaurada de forma íntegra;
- o estado mínimo necessário para monotonicidade continuar consistente;
- não houver ambiguidade sobre reaproveitamento parcial do estado.

Se essas condições não forem satisfeitas, restore não deve implicar continuidade automática.

## Reinstall

Reinstall deve ser tratado, por padrão, como criação de novo nó, a menos que haja restauração explícita e íntegra da identidade local e do estado mínimo exigido.

No v0, a postura conservadora deve ser:

- reinstall sem identidade preservada => nó novo
- reinstall com identidade ambígua => nó inválido, não continuidade automática

## Rejoin

Rejoin significa retorno operacional de um nó previamente válido.

No v0, rejoin só deve ser aceito como continuidade do mesmo nó quando:

- identidade local continua válida;
- monotonicidade continua coerente;
- o nó não foi implicitamente “reiniciado” como se fosse novo.

Rejoin não deve ser usado como atalho para esconder reinstall ou perda de identidade.

## Perda de identidade

Perda de identidade local deve ser tratada como quebra de continuidade.

Consequências no v0:

- o nó não deve continuar emitindo como se fosse o mesmo nó anterior;
- a continuidade anterior não deve ser presumida por UI, relay ou observação;
- qualquer retomada deve ser tratada como novo nó ou estado inválido, até prova em contrário.

## Implicações para mobile node

Como ainda não existe cliente mobile real no repositório, esta seção é apenas contratual e preventiva.

No v0:

- `mobile node` deve ser tratado como mais vulnerável a perda de storage, reinstall e quebra de continuidade;
- não deve ser assumido como âncora principal de retenção;
- restore e reinstall precisam ser mais conservadores para esse perfil.

## Implicações para stable pc node

No v0:

- `stable pc node` tende a oferecer storage local mais estável;
- isso favorece continuidade operacional mais confiável;
- isso não transforma o PC em autoridade semântica.

O papel do PC continua sendo operacionalmente mais estável, não semanticamente superior.

## Invariantes que o sistema deve preservar

- a identidade do nó não pode ser assumida sem material local coerente;
- monotonicidade de nonce por sender não pode retroceder silenciosamente;
- reinstall sem continuidade válida não pode fingir ser restore;
- perda de identidade invalida continuidade anterior até nova definição explícita;
- UI, relay e observação não podem “corrigir” ou inferir continuidade fora do contrato Rust.

## Riscos se esse contrato ficar ambíguo

- clones operacionais do mesmo nó;
- replay ou ordering parcial incoerente;
- restore aceito com estado insuficiente;
- reinstall mascarado como continuidade válida;
- divergência entre o que Rust considera identidade válida e o que outras camadas exibem ou inferem.

## O que fica fora do escopo por enquanto

- contrato completo de sync;
- critérios completos de convergência;
- política de rotação formal de chave;
- identidade compartilhada entre múltiplos dispositivos;
- definição de `anchor` como componente implementado;
- qualquer semântica de chat global distribuído.

## Perguntas ainda abertas

- `sender_id` deve ser sempre derivado da chave local, ou apenas consistente com ela?
- qual é o estado mínimo obrigatório para um restore continuar sendo o mesmo nó?
- quando uma restauração parcial deve ser tratada como inválida?
- qual política de invalidação será usada quando a monotonicidade não puder ser comprovada?
- no futuro, como múltiplos dispositivos do mesmo usuário coexistirão sem quebrar a semântica local do nó?
