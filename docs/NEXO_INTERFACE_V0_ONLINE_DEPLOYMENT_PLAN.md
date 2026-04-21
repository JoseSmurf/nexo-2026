# NEXO Interface V0 Online Deployment Plan

## 1) Objetivo do deployment V0

O objetivo do deployment V0 e colocar a Interface V0 online no menor shape honesto de entrega.
Esse deployment existe para disponibilizar o fluxo central da V0 em ambiente controlado:

`evaluate -> final_decision -> trace -> audit trail -> verify offline`

Nao e objetivo deste deployment transformar a V0 em plataforma ampla, dashboard expandido ou runtime completo.

## 2) Menor deployment honesto

O menor deployment honesto da V0 e:

- um unico ambiente controlado;
- um processo do core expondo o estado necessario;
- uma instancia da UI Ruby V0 lendo esse estado;
- acesso restrito ou privado no inicio.

Esse shape preserva a V0 como sistema unico, estreito e controlado.

## 3) Shapes minimos possiveis

### Opcao A: processo direto no mesmo host

- core rodando como processo de aplicacao;
- UI Ruby rodando como processo separado no mesmo host;
- proxy simples na frente, se necessario;
- operacao mais direta para primeira entrega controlada.

### Opcao B: Docker host

- core empacotado em container;
- UI Ruby empacotada separadamente;
- compose ou orquestracao minima no mesmo host.

Essa opcao pode ser valida, mas introduz mais superficie operacional antes de consolidar a entrega estreita.

## 4) Recomendacao principal

Recomendacao inicial: **processo direto no mesmo host, em ambiente privado/controlado**.

Motivo:

- menor atrito operacional;
- menor numero de decisoes simultaneas;
- mais coerente com o estado atual da V0;
- reduz risco de discutir empacotamento antes de validar a entrega estreita.

## 5) Modelo de exposicao inicial

Modelo recomendado: **controlado/privado**, nao publico.

A V0 ja esta pronta para apresentar e para uso controlado.
Isso nao implica exposicao publica ampla.

## 6) Componentes que entram no deployment

- core com o endpoint de estado necessario para a UI;
- UI Ruby V0;
- configuracao minima de rede/processo para ligar UI ao core;
- caminho operacional para verificacao offline com Zig como capacidade de conferencia.

## 7) Componentes que ficam fora

- mesh/P2P como centro da entrega;
- Witness Layer como superficie principal;
- Julia observadora como parte central do deployment;
- decision_cycle experimental;
- dashboard amplo;
- APK;
- qualquer automacao de sync ou runtime authority adicional.

## 8) Variaveis, segredos e configuracao esperada

Em alto nivel, o deployment precisa decidir:

- URL do core lida pela UI (`NEXO_CORE_STATE_URL`);
- bind/porta da UI;
- bind/porta do core;
- caminho de audit trail e perfil operacional, quando aplicavel;
- segredos e chaves ja usados pelo core, sem redefinir seu contrato neste documento.

Este plano nao fecha valores finais; ele fecha o shape minimo que precisara desses parametros.

## 9) Riscos operacionais

- expor a V0 publicamente cedo demais;
- misturar deployment V0 com expansao de produto;
- abrir duas discussoes ao mesmo tempo: deploy e plataforma;
- tratar sinais secundarios como parte central da primeira entrega online;
- adiar decisoes basicas de processo, porta, proxy e acesso controlado.

## 10) O que precisa estar decidido antes de executar o deploy

1. O host inicial sera privado/controlado ou publico.
2. O primeiro shape sera processo direto ou Docker host.
3. Qual endereco do core a UI vai ler.
4. Qual porta/endereco a UI vai expor.
5. Qual nivel de acesso externo sera permitido no inicio.

## Regra de leitura

Este plano existe para escolher o menor caminho de entrega online da V0.
Ele nao autoriza, por si so:

- ampliar o centro do produto;
- promover partes secundarias;
- declarar plataforma completa;
- antecipar deployment publico amplo.
