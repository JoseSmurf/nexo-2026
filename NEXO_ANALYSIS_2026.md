# NEXO 2026 — Análise Profunda e Mapa de Arquitetura

**Data**: 24 de maio de 2026  
**Status**: Análise completa do núcleo de confiança, auditoria e verificação  
**Foco**: Rastreabilidade determinística, reproducibilidade offline, fail-closed  

---

## 1. Identidade & Propósito

NEXO é um sistema **local-first, determinístico, verificável** para fluxos financeiros críticos:

```
signed request → deterministic evaluate → final_decision → trace → audit artifact → offline Zig verification
```

### O que NÃO é NEXO:
- ❌ Oracle global de verdade
- ❌ Protocolo de consenso ou CRDT
- ❌ Sistema de mineração Bitcoin ou PoW
- ❌ Sync runtime completo (P2P/Mesh ainda experimentais)
- ❌ IA judicial ou plataforma universal de compliance

### O que SIM é NEXO:
- ✅ Decisões determinísticas com auditoria completa
- ✅ Artefatos offline verificáveis (Blake3 + Zig)
- ✅ Fail-closed em toda entrada não assinada
- ✅ Prova de integridade de trace e chain (record_hash)

---

## 2. Arquitetura de Confiança

```
┌─────────────────────────────────────────────────────────────┐
│  VERIFIED BACKBONE (Núcleo de Confiança)                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  CLIENT          RUST CORE         AUDIT STORE        ZIG   │
│  ┌──────┐        ┌──────────┐      ┌──────────┐      ┌───┐  │
│  │Signed│──────→ │Evaluate  │─────→│ JSONL    │─────→│Ver│  │
│  │HMAC  │        │Lock-     │      │Append    │      │ify│  │
│  │      │        │Free      │      │Record    │      │   │  │
│  └──────┘        │Hash      │      │Hash      │      └───┘  │
│                  │Trace     │      │Chain     │       Offline
│                  └──────────┘      └──────────┘      Verifier
│
│  TRUST BOUNDARIES:
│  • Rust = decisor determinístico (único source of truth)
│  • Zig = validador offline (sem estado, puro)
│  • Lock-file = proteção contra multi-writer (local/process)
│  • Durable replace = atomicidade de append
│
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  ROLE-BOUNDED SURFACES (não autoridade)                     │
├─────────────────────────────────────────────────────────────┤
│  Ruby (nexo_ui/)         → apresentação SPA                 │
│  Julia (julia/)          → observador de fluxo               │
│  Relay/P2P/Mesh          → pesquisa/experimental             │
│  Witness Layer           → prova local, não verdade global   │
│  Bitcoin Logistics       → experimento (não produto)         │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Motor Determinístico (`src/engine/evaluate.rs`)

### Fluxo de Decisão (Ordem Fixa = Contrato)

```rust
trace.push("UI-FRAUD-001", rule_ui_integrity(intent))         // Bloqueia se hash UI inválido
trace.push("BCB-NIGHT-001", rule_night_limit(intent, config)) // Bloqueia se limite noturno excedido
trace.push(aml_rule_id, rule_aml(intent, config))             // Flagged/Blocked por AML
```

### Estados Finais

| Decision | Trace | Semântica |
|----------|-------|-----------|
| `Approved` | Todas `Approved` | Transação aceita |
| `Flagged` | Qualquer `FlaggedForReview` | Requer revisão AML |
| `Blocked` | Qualquer `Blocked` | Rejeitada (fail-closed) |

### Contrato Imutável

- **Ordem fixa**: mudanças de ordem = breaking change (hashes forensicos mudam)
- **Schema `trace_v4`**: framing de campos com tags (não JSON raw)
- **Semântica de rule_id**: só em Flagged/Blocked (não em Approved)

---

## 4. Auditoria & Hash

### `audit_hash` (Semântico)

```
hash_field(schema) = "trace_v4"
for each decision in trace:
  hash_field("D:A" or "D:F" or "D:B", rule_id)
  hash_field("R", reason)
  push severity.rank(), measured, threshold
finalize() → 64 hex chars (blake3)
```

**Prova**: trace não foi reordenado ou alterado  
**Não prova**: autenticidade de entrada, validade HMAC, replay

### `record_hash` (Nível-Registro)

```
schema = "audit_record_v2"
hash_field: request_id, profile_*, user_id, amount, risk_bps, 
            audit_hash, hash_algo, trace (JSON minified), 
            final_decision, prev_record_hash, timestamp_utc_ms
finalize() → 64 hex chars (blake3)
```

**Prova**: campos do registro persistido não foram alterados  
**Não prova**: integridade de config de policy, full input replay

### `prev_record_hash` (Encadeamento)

```
record[0].prev_record_hash = null
record[1].prev_record_hash = record[0].record_hash
record[2].prev_record_hash = record[1].record_hash
...
```

**Verificação Zig**: `--require-chain` detecta deletions, inserções, reordenação

---

## 5. Persistência & Durabilidade

### Contrato de Append (`AuditStore`)

```rust
1. Adquire lock file (<audit_path>.lock)
   └─ Se já existe → falha fechada (outro writer ativo?)
   
2. Lê audit file atual
   └─ Extrai prev_record_hash do último record

3. Constrói novo record com:
   prev_record_hash = hash anterior
   record_hash = compute_record_hash(self)
   
4. Escreve arquivo temp (<audit_path>.jsonl.tmp)
   └─ flush() + sync_all()
   
5. rename() temp → final path
   └─ sync_parent_directory() (Unix)
   
6. Libera lock file
```

### Limites

- **Single-writer**: um processo por `NEXO_AUDIT_PATH`
- **Local lock**: não é lock distribuído (não replica-safe)
- **Durability**: melhora resilência mas não é crash-proof universal
- **Incident recovery**: guia operacional em `docs/SECURITY_OPERATIONS.md`

### Preflight de Startup

```bash
NEXO_REQUIRE_AUDIT_PREFLIGHT=true
```

Se habilitado, startup falha se:
- `<audit_path>.lock` existe
- `<audit_path>.jsonl.tmp` existe  
- Chain prev_record_hash quebrado
- Malformed JSON tail

---

## 6. Segurança de API

### Headers Assinados

| Header | Propósito | Fail-Closed |
|--------|-----------|-------------|
| `X-Signature` | HMAC-SHA256 body | ❌ → 401 |
| `X-Request-Id` | One-time nonce | ❌ → 409 (replay) |
| `X-Timestamp` | Window de 60s (default) | ❌ → 408 (stale) |
| `X-Key-Id` | Identidade de chave ativa | ❌ → 401 (mismatch) |

### Proteção de Replay

```
request_id consumido em security/replay gate ANTES de /evaluate
├─ Se Redis: verificação distribuída (fail-closed se indisponível)
└─ Se in-memory: local apenas (não survives restart)

Retry com mesmo request_id:
├─ Se append falhou → retorna 409 (replay conflict)
├─ Recovery requer novo request com novo request_id
└─ Operador revisa e toma decisão manual
```

### Rate Limiting

- Por IP (default 600 req/min)
- Por user_id (default 300 req/min)
- Falha fechada com 429 (Too Many Requests)

### `/api/chat/send` (Não-Autoridade)

```
✅ Loopback-only (127.0.0.1)
✅ 4 KiB cap (não toca audit)
✅ Content-Type JSON com rejeição de duplicatas
✅ Não cria audit evidence
```

---

## 7. Verificação Offline (Zig)

### Modo Base (`verify`)

```bash
cd tools/zig && zig build run -- verify ../../fixtures/audit_sample.jsonl
```

Verifica cada linha:
1. Parse JSON
2. Valida schema (fields presentes e tipos corretos)
3. Extrai `hash_algo` (blake3, sha3-256, shake256-*, hybrid)
4. Recomputa `audit_hash` do trace
5. Compara com stored
6. Valida `final_decision` contra trace semantics

Output:
```
verify: total=1 ok=1 schema_invalid=false tampering=false
```

### Modo Chain (`--require-chain`)

```bash
cd tools/zig && zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl
```

Além do base:
1. Record[0]: `prev_record_hash` deve ser null ou vazio
2. Record[i]: `prev_record_hash` deve == Record[i-1].record_hash
3. Recomputa `record_hash` de cada record
4. Detecta: deleção, inserção, reordenação, tampering em field

Output em caso de tampering:
```
verify: total=2 ok=1 schema_invalid=false tampering=true
```

---

## 8. Contratos Imutáveis (Baselines v1)

### Trace Persistida

```json
{
  "trace": [
    "Approved",
    "Approved",
    {
      "FlaggedForReview": {
        "rule_id": "AML-FATF-REVIEW-001",
        "reason": "Transaction requires AML review.",
        "severity": "Alta",
        "measured": 150000,
        "threshold": 5000000
      }
    }
  ]
}
```

**Contrato**:
- Approved = string (sem rule_id)
- FlaggedForReview/Blocked = object com 5 campos
- Ordem determinística (3 regras)
- Severidade: rank() → u8 (Critica > Grave > Alta > Média > Baixa)

### AuditRecord Persistida

| Campo | Persistido | Em audit_hash | Em record_hash | Notas |
|-------|-----------|---|---|---|
| request_id | ✅ | ❌ | ✅ | Nonce único |
| final_decision | ✅ | ❌ | ✅ | Deve match trace semantics |
| trace | ✅ | ✅ (semântico) | ✅ (JSON) | Vec<Decision> |
| audit_hash | ✅ | N/A | ✅ | Recomputa em Zig |
| hash_algo | ✅ | Seleciona algo | ✅ | blake3 / sha3-256 / shake* |
| record_hash | ✅ (append) | ❌ | N/A | Chaining link |
| prev_record_hash | ✅ | ❌ | ✅ | Detecta deleção/inserção |
| timestamp_utc_ms | ✅ | ❌ | ✅ | Auth header (não tx timestamp) |
| user_id | ✅ | ❌ | ✅ | Request body |
| amount_cents | ✅ | ❌ | ✅ | Request body |
| risk_bps | ✅ | ❌ | ✅ | Request body |
| is_pep | ❌ | ❌ | ❌ | Input apenas |
| has_active_kyc | ❌ | ❌ | ❌ | Input apenas |
| ui_hash_valid | ❌ | ❌ | ❌ | Input apenas |

---

## 9. Limites Conhecidos (Baseline v1)

### Não Provado

- ❌ Full input replay (is_pep, has_active_kyc, ui_hash_valid não persistidos)
- ❌ Integridade de config de policy (só profile name/version)
- ❌ Timestamp da transação body separado (timestamp_utc_ms é do auth header)
- ❌ Primeira record `prev_record_hash` semanticamente igual (Zig < Rust preflight)

### Experimental / Pesquisa

- 🔬 Witness Layer: prova de aceitação local, não verdade global
- 🔬 Mesh/P2P: sync protocol ainda em pesquisa
- 🔬 Bitcoin Logistics: experimento, não product center
- 🔬 Julia Observer: análise, não decisão

### Operator-Dependent

- 👤 Incidentes de auditoria: requer triage manual + offline verification
- 👤 Rotação de chaves: overlap window + explicit removal needed
- 👤 Retenção de arquivo: disciplina de cópia/archival fora do código

---

## 10. Matriz de Testes (Core CI Gate)

```bash
# Fast Local Gate (desenvolvimento narrow)
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -q api
cargo test -q profile
cargo test -q audit_store
cargo test -q audit_chain
cargo test -q replay
bash scripts/check_readme_consistency.sh
bash scripts/check_supply_chain_surface.sh

# Core CI Gate (.github/workflows/rust.yml)
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --verbose
cargo test --features network --verbose
bash scripts/check_readme_consistency.sh
bash scripts/check_supply_chain_surface.sh
cargo deny check

# Zig Verification
cd tools/zig
zig build test
zig build run -- verify ../../fixtures/audit_sample.jsonl
zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl

# Julia Observer
julia --project=./julia julia/test/runtests.jl
julia --project=./julia julia/test_integration.jl
```

---

## 11. Fluxo Operacional

### Request → Audit → Verify

```
1. CLIENT
   └─ POST /evaluate
      • Signed: HMAC(body)
      • Headers: X-Request-Id, X-Timestamp, X-Key-Id
      • Body: user_id, amount_cents, is_pep, has_active_kyc, risk_bps, ...

2. RUST CORE (src/api.rs)
   ├─ Validate HMAC, timestamp window, replay
   ├─ Call evaluate(TransactionIntent)
   │  └─ src/engine/evaluate.rs: 3 rules (fixed order)
   ├─ Build AuditRecord
   └─ Append to JSONL

3. AUDIT STORE (src/audit_store.rs)
   ├─ Acquire lock (<audit_path>.lock)
   ├─ Read existing records
   ├─ Compute record_hash (fields + prev_record_hash)
   ├─ Durable replace: tmp → final
   └─ Release lock

4. HTTP RESPONSE
   ├─ 200 only if append succeeded
   └─ Payload: final_decision, trace, audit_hash, hash_algo

5. OFFLINE VERIFICATION (tools/zig/)
   ├─ Read JSONL artifact (files, not runtime)
   ├─ Recompute audit_hash
   ├─ Recompute record_hash
   ├─ Check --require-chain continuity (optional)
   └─ Output: tampering=true/false
```

### Incidente de Auditoria

```
Append fails at lock → 500 error, no payload
└─ Operator review required:
   1. Preserve audit file + *.jsonl.tmp
   2. Run offline Zig verification
   3. Quarantine affected path
   4. New signed request (new request_id)
   5. Resume writes after fix
```

---

## 12. Estrutura de Código

```
nexo-2026/
├── src/
│   ├── main.rs               → HTTP server entry (Tokio + Axum)
│   ├── lib.rs                → Facade: evaluate() + audit_hash()
│   ├── api.rs                → Request handler, rate limit, auth
│   ├── api/
│   │   ├── auth.rs           → HMAC, timestamp, key management
│   │   ├── replay.rs         → request_id nonce guard
│   │   ├── rate_limit.rs     → IP/user rate limiting
│   │   └── state.rs          → Operator expose (non-authoritative)
│   ├── engine/
│   │   ├── evaluate.rs       → 3 rules determinísticas
│   │   └── trace.rs          → DecisionTrace structure
│   ├── audit_store.rs        → JSONL append, lock, durability
│   ├── audit/
│   │   ├── hash.rs           → audit_hash, record_hash computação
│   │   └── record.rs         → record_hash formula
│   ├── profile.rs            → RuleProfile from env
│   ├── telemetry.rs          → Metrics (latency, counts)
│   └── ... (mesh, relay, p2p, etc. — bordas, não core)
│
├── tools/zig/
│   ├── src/
│   │   ├── verify.zig        → Base + --require-chain verification
│   │   ├── schema.zig        → JSON field extraction
│   │   └── crypto.zig        → blake3, sha3, shake hashing
│   └── build.zig
│
├── julia/
│   ├── flow_observer.jl      → Loop de observação
│   ├── test/
│   │   └── runtests.jl       → Teste de bridge
│   └── Project.toml
│
├── nexo_ui/
│   ├── app.rb                → Ruby SPA server
│   ├── views/
│   │   └── index.erb         → UI (não autoridade)
│   └── test/
│
├── docs/
│   ├── OPERATIONAL_FLOW.md   → Dia-a-dia do sistema
│   ├── SECURITY_OPERATIONS.md→ Hardening + incident response
│   ├── NEXO_AUDIT_CONTRACT_BASELINE_V1.md
│   ├── NEXO_CORE_VALIDATION_GATE_V1.md
│   ├── NEXO_TEST_MATRIX.md
│   ├── NEXO_THREAT_MODEL.md
│   └── ... (evidência pack completo)
│
├── fixtures/
│   ├── audit_sample.jsonl         → 1 record (base verification)
│   └── audit_chain_sample.jsonl   → 2 records (--require-chain)
│
├── scripts/
│   ├── demo_decision_flow.sh
│   ├── demo_decision_flow_flagged.sh
│   ├── check_readme_consistency.sh
│   ├── check_supply_chain_surface.sh
│   └── inspect_audit_artifact.sh
│
└── Cargo.toml, Cargo.lock, deny.toml, AGENTS.md
```

---

## 13. Princípios de Design

### Fail-Closed
- ❌ Sem assinatura → 401
- ❌ Replay duplo → 409
- ❌ Append falha → 500 (sem decision payload)
- ❌ Lock pré-existente → 500 (não overwrite)

### Determinístico
- Ordem fixa de regras (indexación forensic hash)
- Semântica de trace reproduzível offline
- Sem estado compartilhado na decisão (puro)

### Verificável
- Artefatos offline (não requer runtime)
- Framing de hash explícito (schema tags)
- Encadeamento via prev_record_hash

### Transparente
- Audit trail completo persistido
- Operador inspeciona com scripts + Zig
- Docs protegem scope (não consenso, não Bitcoin)

---

## 14. Checklist de Revisão

Use quando revisar ou deploy:

- ✅ README evidence pack está atualizado?
- ✅ Core validation gate local passa? (`cargo test -q`, Zig verify)
- ✅ Supply chain guard (`check_supply_chain_surface.sh`)?
- ✅ Dependency audit (`cargo deny check`)?
- ✅ `audit_hash` contrato é stable (trace_v4 framing)?
- ✅ `record_hash` recomputa corretamente?
- ✅ Zig `--require-chain` passa para fixtures?
- ✅ HMAC + timestamp window + replay protection ativo?
- ✅ Lock-file guard presente (single-writer)?
- ✅ Durable replace com sync_all() implementado?
- ✅ `/evaluate` retorna 200 somente pós-append?
- ✅ `NEXO_REQUIRE_AUDIT_PREFLIGHT=true` funciona?
- ✅ Docs são honestos sobre limits (não consenso, não mining)?
- ✅ Operator runbook (`SECURITY_OPERATIONS.md`) está legível?

---

## 15. Onde Explorar Mais

- **Arquitetura**: [docs/NEXO_ARCHITECTURE_DIAGRAM.md](docs/NEXO_ARCHITECTURE_DIAGRAM.md)
- **Ameaças**: [docs/NEXO_THREAT_MODEL.md](docs/NEXO_THREAT_MODEL.md)
- **Operações**: [docs/OPERATIONAL_FLOW.md](docs/OPERATIONAL_FLOW.md)
- **Segurança**: [docs/SECURITY_OPERATIONS.md](docs/SECURITY_OPERATIONS.md)
- **Auditoria**: [docs/NEXO_AUDIT_CONTRACT_BASELINE_V1.md](docs/NEXO_AUDIT_CONTRACT_BASELINE_V1.md)
- **Testes**: [docs/NEXO_TEST_MATRIX.md](docs/NEXO_TEST_MATRIX.md)
- **Reprodutibilidade**: [docs/NEXO_REPRODUCIBILITY_REPORT.md](docs/NEXO_REPRODUCIBILITY_REPORT.md)

---

## 16. Conclusão

NEXO é um **sistema minimalista mas rigoroso** para decisões determinísticas com auditoria:

| Aspecto | Estratégia |
|---------|-----------|
| Confiança | Rust (decisor) + Zig (verificador offline) |
| Auditoria | Blake3 + encadeamento record_hash |
| Durabilidade | Lock-file + durable replace + single-writer |
| Segurança | HMAC + timestamp + replay + rate-limit |
| Verificabilidade | Offline, sem estado, framing explícito |
| Scope | Local-first, não global, não consenso |

Ele **não promete verdade global**, mas **prova integridade local** de forma reproduzível e offline-verificável.

---

*Análise criada 2026-05-24. Pronto para dark mode. 🖤*
