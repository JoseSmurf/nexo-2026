# NEXO 2026 — Guia Operacional Rápido

## 1. Setup & Primeiras Execuções

### Instalar dependências (Windows)

```bash
# Instalar Rust (se não tiver)
rustup default stable
rustup toolchain install stable

# Instalar Zig (para verificador offline)
# Visite https://ziglang.org/download/
# Ou use chocolatey: choco install zig

# Verificar instalações
rustc --version
cargo --version
zig version
```

### Build local

```bash
cd c:\Users\Olá\Documents\nexo-2026

# Compilar (nota: Windows pode precisar Windows SDK)
cargo build --release

# Ou, se erro de linking dbghelp.lib:
# Instale "Windows SDK" via Visual Studio Community
# ou configure CARGO_CFG_DBGHELP_PATH
```

### Rodar testes (quando build funcionar)

```bash
# Core fast gate
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -q api
cargo test -q audit_store
cargo test -q replay

# Full gate
cargo test --verbose
cargo test --features network --verbose

# Supply chain audit
bash scripts/check_supply_chain_surface.sh
cargo deny check
```

---

## 2. Iniciar Servidor

```bash
# Terminal 1: Servidor HTTP
cd c:\Users\Olá\Documents\nexo-2026
cargo run --release

# Output:
# HTTP server running on http://0.0.0.0:3000
# Acessar UI: http://localhost:3000/nexo-ui
```

### Variáveis de ambiente (opcional)

```bash
# Porta HTTP
set NEXO_HTTP_BIND=127.0.0.1:8080

# Auditoria
set NEXO_AUDIT_PATH=C:\temp\audit_records.jsonl
set NEXO_REQUIRE_AUDIT_PREFLIGHT=true

# Autenticação
set NEXO_HMAC_SECRET=seu_secret_aqui
set NEXO_HMAC_KEY_ID=active

# Replay (production)
set NEXO_REQUIRE_PERSISTENT_REPLAY=true
set NEXO_REDIS_URL=redis://localhost:6379

# Rate limit
set NEXO_RATE_LIMIT_IP=600
set NEXO_RATE_LIMIT_USER=300
```

---

## 3. Enviar Requests Assinadas

### Gerar HMAC

```python
#!/usr/bin/env python3
import hmac
import hashlib
import time
import uuid
import json

def compute_hmac(body: str, secret: str) -> str:
    return hmac.new(
        secret.encode(),
        body.encode(),
        hashlib.sha256
    ).hexdigest()

secret = "seu_secret_aqui"
request_id = str(uuid.uuid4())
timestamp_ms = int(time.time() * 1000)

body = json.dumps({
    "user_id": "user_123",
    "amount_cents": 50000,
    "is_pep": False,
    "has_active_kyc": True,
    "timestamp_utc_ms": timestamp_ms,
    "risk_bps": 1000,
    "ui_hash_valid": True,
    "request_id": request_id,
})

signature = compute_hmac(body, secret)
print(f"Body: {body}")
print(f"Signature: {signature}")
print(f"Request-ID: {request_id}")
print(f"Timestamp: {timestamp_ms}")
```

### Enviar com curl

```bash
BODY='{"user_id":"user_123","amount_cents":50000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":1716571324000,"risk_bps":1000,"ui_hash_valid":true,"request_id":"req-001"}'
SECRET="seu_secret_aqui"
TIMESTAMP="1716571324000"
REQUEST_ID="req-001"

SIGNATURE=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | cut -d' ' -f2)

curl -X POST http://localhost:3000/evaluate \
  -H "Content-Type: application/json" \
  -H "X-Signature: $SIGNATURE" \
  -H "X-Request-Id: $REQUEST_ID" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Key-Id: active" \
  -d "$BODY" \
  -w "\nStatus: %{http_code}\n"
```

---

## 4. Inspecionar Auditoria

### Ver último registro

```bash
bash scripts/inspect_audit_artifact.sh

# Saída:
# Found artifact at: logs/audit_records.jsonl
# Request: req-001
# Decision: Approved
# Audit Hash: bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3
# ...
```

### Procurar por request_id

```bash
bash scripts/find_audit_artifact.sh req-001

# Ou procurar por hash
bash scripts/find_audit_artifact.sh bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3
```

### Ler arquivo raw JSONL

```bash
# Windows PowerShell
Get-Content logs/audit_records.jsonl | ConvertFrom-Json | Format-Table request_id, final_decision, audit_hash

# Linux/Mac
cat logs/audit_records.jsonl | jq '.request_id, .final_decision, .audit_hash'
```

---

## 5. Verificação Offline (Zig)

### Build verifier

```bash
cd tools/zig
zig build
```

### Verificar record único

```bash
cd tools/zig
zig build run -- verify ../../fixtures/audit_sample.jsonl

# Saída:
# verify: total=1 ok=1 schema_invalid=false tampering=false
```

### Verificar chain (com require-chain)

```bash
cd tools/zig
zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl

# Saída:
# verify: total=2 ok=2 schema_invalid=false tampering=false
```

### Verificar seu audit_records.jsonl

```bash
cd tools/zig
zig build run -- verify ../../logs/audit_records.jsonl
```

---

## 6. Demonstrações

### Demo 1: Fluxo Normal (Approved)

```bash
bash scripts/demo_decision_flow.sh

# Cria audit artifact temporário com decisão Approved
# Imprime comando Zig para verificar
```

### Demo 2: Fluxo Flagged (AML Review)

```bash
bash scripts/demo_decision_flow_flagged.sh

# Cria audit artifact temporário com decisão Flagged
# Imprime comando Zig para verificar
```

### Demo 3: Record Chain Verification

```bash
bash scripts/demo_record_chain_verification.sh

# Demonstra:
# 1. Chain válido passa
# 2. prev_record_hash quebrado detectado como tampering
# 3. Zig --require-chain funciona
```

---

## 7. Testes de Segurança

### Testar HMAC rejection

```bash
# Sem header
curl -X POST http://localhost:3000/evaluate \
  -H "Content-Type: application/json" \
  -d '{"user_id":"user_123",...}'
# Esperado: 401 Unauthorized

# HMAC inválido
curl -X POST http://localhost:3000/evaluate \
  -H "Content-Type: application/json" \
  -H "X-Signature: invalid_sig" \
  -H "X-Request-Id: req-002" \
  -H "X-Timestamp: $(date +%s)000" \
  -H "X-Key-Id: active" \
  -d '{"user_id":"user_123",...}'
# Esperado: 401 Unauthorized
```

### Testar replay rejection

```bash
# Primeiro request (sucesso)
curl -X POST http://localhost:3000/evaluate \
  -H "..." -H "X-Request-Id: same-id" -d "..."
# Esperado: 200 OK

# Segundo request (mesmo request_id)
curl -X POST http://localhost:3000/evaluate \
  -H "..." -H "X-Request-Id: same-id" -d "..."
# Esperado: 409 Conflict
```

### Testar rate limiting

```bash
# Enviar 600+ requests rápido de mesmo IP
for i in {1..650}; do
  curl -X POST http://localhost:3000/evaluate \
    -H "..." -d "..." &
done
wait

# Esperado: ~50 requests com 429 Too Many Requests
```

---

## 8. Monitoramento & Status

### Health check

```bash
curl http://localhost:3000/health

# Esperado: 200 OK
# {
#   "status": "ok",
#   "timestamp_utc_ms": 1716571324000
# }
```

### Security status (admin endpoint, se habilitado)

```bash
curl http://localhost:3000/security/status

# Esperado: JSON com:
# {
#   "auth_window_ms": 60000,
#   "replay_ttl_ms": 120000,
#   "replay_cache_size": 45,
#   "key_active_id": "active",
#   "rate_limit_ip": 600,
#   "rate_limit_user": 300,
#   "rate_limit_hits": 12,
#   "p95_latency_ns": 1234567890
# }
```

### Audit recent (read-only)

```bash
curl "http://localhost:3000/audit/recent?limit=10"

# Esperado: JSON com array dos últimos 10 records
# {
#   "records": [ ... ]
# }
```

---

## 9. Incident Response

### Auditoria com lock pré-existente

```bash
# Se logs/audit_records.jsonl.lock existe:

# 1. Verificar se processo está rodando
ps aux | grep nexo

# 2. Se não há processo:
rm logs/audit_records.jsonl.lock

# 3. Se há processo:
kill <pid>
rm logs/audit_records.jsonl.lock

# 4. Verificar integridade offline
cd tools/zig
zig build run -- verify --require-chain ../../logs/audit_records.jsonl

# 5. Reiniciar servidor
cargo run --release
```

### Arquivo temp pendente

```bash
# Se logs/audit_records.jsonl.tmp existe:

# 1. Checar se servidor está ativo
ps aux | grep nexo

# 2. Se não há servidor:
# A. Comparar .tmp vs .jsonl
# B. Se .tmp mais novo e válido, deletar .jsonl e renomear
# C. Se .tmp inválido, deletar .tmp

# 3. Se servidor está rodando: aguarde (append em progresso)

# 4. Verificar ambos offline
cd tools/zig
zig build run -- verify ../../logs/audit_records.jsonl
zig build run -- verify ../../logs/audit_records.jsonl.tmp
```

### Chain quebrada (prev_record_hash inconsistent)

```bash
# Se Zig --require-chain falha:

# 1. Extrair records problemáticos
tail -5 logs/audit_records.jsonl | jq '.request_id, .prev_record_hash, .record_hash'

# 2. Recompute offline
cd tools/zig
zig build run -- verify --require-chain ../../logs/audit_records.jsonl

# 3. Identificar linha problemática (output mostra tampering=true)

# 4. Quarantine arquivo e investigar
cp logs/audit_records.jsonl logs/audit_records.jsonl.quarantine
rm logs/audit_records.jsonl

# 5. Reiniciar com novo arquivo vazio
touch logs/audit_records.jsonl
cargo run --release
```

---

## 10. Deployment Checklist

### Pre-Deploy

- [ ] `cargo fmt --check` passou
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passou
- [ ] `cargo test --verbose` passou
- [ ] `cargo deny check` passou
- [ ] `bash scripts/check_supply_chain_surface.sh` passou
- [ ] `bash scripts/check_readme_consistency.sh` passou
- [ ] Zig verifier builds: `cd tools/zig && zig build`
- [ ] Julia tests pass: `julia --project=./julia julia/test/runtests.jl`

### Deploy

- [ ] Configurar HMAC_SECRET em secret manager
- [ ] Configurar NEXO_AUDIT_PATH em storage seguro
- [ ] Habilitar NEXO_REQUIRE_PERSISTENT_REPLAY=true
- [ ] Habilitar NEXO_REQUIRE_AUDIT_PREFLIGHT=true
- [ ] Configurar TLS 1.3 na edge
- [ ] Configurar WAF + rate limit na reverse proxy
- [ ] Testar primeiros requests com curl
- [ ] Backup inicial de logs/audit_records.jsonl vazio

### Post-Deploy

- [ ] Health check retorna 200 OK
- [ ] Primeiro request assinado retorna 200
- [ ] Audit record está em logs/audit_records.jsonl
- [ ] `zig verify logs/audit_records.jsonl` passa
- [ ] Monitorar /metrics para erros de append

---

## 11. Desenvolvimento Local (Windows)

### Estrutura recomendada

```
C:\Users\Olá\Documents\
├── nexo-2026/          ← main repo
│   ├── src/
│   ├── tools/zig/
│   ├── docs/
│   ├── logs/           ← create: mkdir logs
│   └── Cargo.toml
└── nexo-dev-notes/     ← seu workspace pessoal
    ├── test_requests.sh
    ├── quick_demo.sh
    └── incidents.md
```

### Script rápido de demo local

```bash
#!/bin/bash
# quick_demo.sh

set -e
cd "$(dirname "$0")/../nexo-2026"

echo "=== NEXO Demo ==="
echo ""
echo "1. Building..."
cargo build --release 2>/dev/null || echo "⚠️  Build error (Windows SDK may be missing)"

echo ""
echo "2. Running demo decision flow..."
bash scripts/demo_decision_flow.sh

echo ""
echo "3. Verifying artifact offline..."
cd tools/zig
zig build run -- verify ../../fixtures/audit_sample.jsonl

echo ""
echo "✅ Demo complete!"
```

---

## 12. Recursos

| Recurso | Localização |
|---------|------------|
| Documentação principal | [README.md](README.md) |
| Fluxo operacional | [docs/OPERATIONAL_FLOW.md](docs/OPERATIONAL_FLOW.md) |
| Segurança & Hardening | [docs/SECURITY_OPERATIONS.md](docs/SECURITY_OPERATIONS.md) |
| Contrato de auditoria | [docs/NEXO_AUDIT_CONTRACT_BASELINE_V1.md](docs/NEXO_AUDIT_CONTRACT_BASELINE_V1.md) |
| Teste matriz | [docs/NEXO_TEST_MATRIX.md](docs/NEXO_TEST_MATRIX.md) |
| Ameaças & mitigação | [docs/NEXO_THREAT_MODEL.md](docs/NEXO_THREAT_MODEL.md) |
| Reprodutibilidade | [docs/NEXO_REPRODUCIBILITY_REPORT.md](docs/NEXO_REPRODUCIBILITY_REPORT.md) |
| Código Rust core | [src/engine/evaluate.rs](src/engine/evaluate.rs) |
| Código Zig verifier | [tools/zig/src/verify.zig](tools/zig/src/verify.zig) |

---

*Guia operacional. Pronto para copiar/colar em seu terminal. 🖤*
