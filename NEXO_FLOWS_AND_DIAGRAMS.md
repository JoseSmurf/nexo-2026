# NEXO 2026 — Fluxos & Diagramas Visuais

## 1. Fluxo de Request → Audit → Verify

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CLIENT REQUEST                                  │
├─────────────────────────────────────────────────────────────────────────┤
│  POST /evaluate                                                          │
│  ┌─ Header: X-Signature (HMAC-SHA256)                                   │
│  ├─ Header: X-Request-Id (nonce único)                                  │
│  ├─ Header: X-Timestamp (unix_ms)                                       │
│  ├─ Header: X-Key-Id (active/prev)                                      │
│  └─ Body: {user_id, amount_cents, is_pep, has_active_kyc, risk_bps}    │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       RUST API VALIDATION                               │
├─────────────────────────────────────────────────────────────────────────┤
│  1. HMAC verification → 401 if fail                                     │
│  2. Timestamp window (±60s default) → 408 if stale                      │
│  3. Replay check (request_id) → 409 if duplicate                        │
│  4. Rate limit check (IP/user) → 429 if exceeded                        │
│  5. Body size limit (1 MB default)                                      │
│  6. Content-Type: application/json (strict)                             │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼ (all pass)
┌─────────────────────────────────────────────────────────────────────────┐
│                    DETERMINISTIC EVALUATION                             │
│                    (src/engine/evaluate.rs)                             │
├─────────────────────────────────────────────────────────────────────────┤
│  TransactionIntent:                                                      │
│  ┌─ ui_hash_valid: bool                                                 │
│  ├─ amount_cents: u64                                                   │
│  ├─ timestamp_utc_ms: u64                                               │
│  ├─ is_pep: bool                                                        │
│  └─ has_active_kyc: bool                                                │
│                                                                          │
│  Rule 1: UI-FRAUD-001                                                   │
│  ├─ if !ui_hash_valid → Decision::Blocked                               │
│  └─ else → Decision::Approved                                           │
│                                                                          │
│  Rule 2: BCB-NIGHT-001 (Night Limit)                                    │
│  ├─ if is_night && amount > limit → Decision::Blocked                   │
│  └─ else → Decision::Approved                                           │
│                                                                          │
│  Rule 3: AML-FATF-* (High Risk & High Amount)                           │
│  ├─ if pep && !kyc → Decision::Blocked                                  │
│  ├─ if (high_risk && high_amount) → Decision::Blocked                   │
│  ├─ if (high_risk || high_amount) → Decision::FlaggedForReview          │
│  └─ else → Decision::Approved                                           │
│                                                                          │
│  Final Decision:                                                         │
│  ├─ if any Blocked → FinalDecision::Blocked                             │
│  ├─ else if any Flagged → FinalDecision::Flagged                        │
│  └─ else → FinalDecision::Approved                                      │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        AUDIT HASH COMPUTATION                           │
│                     (src/audit/hash.rs, trace_v4)                      │
├─────────────────────────────────────────────────────────────────────────┤
│  hasher = blake3.new()                                                  │
│  hash_field("schema", "trace_v4")                                       │
│                                                                          │
│  for decision in trace:                                                 │
│    if Approved:                                                         │
│      hash_field("D:A", "")                                              │
│    if FlaggedForReview:                                                 │
│      hash_field("D:F", rule_id)                                         │
│      hash_field("R", reason)                                            │
│      update(severity.rank())                                            │
│      update(measured_u64_le)                                            │
│      update(threshold_u64_le)                                           │
│    if Blocked:                                                          │
│      hash_field("D:B", rule_id)                                         │
│      hash_field("R", reason)                                            │
│      update(severity.rank())                                            │
│      update(measured_u64_le)                                            │
│      update(threshold_u64_le)                                           │
│                                                                          │
│  audit_hash = hasher.finalize().to_hex()  → 64 chars                   │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         AUDIT STORE APPEND                              │
│                    (src/audit_store.rs, Durability)                     │
├─────────────────────────────────────────────────────────────────────────┤
│  1. acquire_lock(<audit_path>.lock)                                     │
│     └─ if exists: FAIL CLOSED (500, no payload)                         │
│                                                                          │
│  2. read existing records from <audit_path>                             │
│     └─ extract prev_hash from tail record.record_hash                   │
│                                                                          │
│  3. construct AuditRecord:                                              │
│     {                                                                    │
│       request_id, profile_name, profile_version,                        │
│       timestamp_utc_ms, user_id, amount_cents, risk_bps,                │
│       final_decision, trace (Vec<Decision>),                            │
│       audit_hash, hash_algo,                                            │
│       prev_record_hash: (prev_hash or null),                            │
│       record_hash: null (será preenchido)                               │
│     }                                                                    │
│                                                                          │
│  4. compute_record_hash(AuditRecord)                                    │
│     └─ hasher = blake3.new()                                            │
│        hash_field("schema", "audit_record_v2")                          │
│        hash_field("request_id", ...)                                    │
│        hash_field("profile_name", ...)                                  │
│        ...                                                              │
│        update(timestamp_utc_ms_le)                                      │
│        update(amount_cents_le)                                          │
│        update(risk_bps_le)                                              │
│        finalize() → 64 chars                                            │
│                                                                          │
│  5. write to temp file (<audit_path>.jsonl.tmp)                         │
│     ├─ write all lines + new record                                     │
│     ├─ flush()                                                          │
│     ├─ sync_all() (fsync)                                               │
│     └─ close                                                            │
│                                                                          │
│  6. atomic rename:                                                      │
│     ├─ rename(<audit_path>.jsonl.tmp, <audit_path>)                     │
│     └─ sync_parent_directory() on Unix                                  │
│                                                                          │
│  7. release_lock(<audit_path>.lock)                                     │
│                                                                          │
│  Result: JSONL with record_hash field populated                         │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        HTTP 200 RESPONSE                                │
│              (only returned if append succeeded)                         │
├─────────────────────────────────────────────────────────────────────────┤
│  {                                                                       │
│    "request_id": "...",                                                 │
│    "final_decision": "Approved|Flagged|Blocked",                        │
│    "trace": [                                                           │
│      "Approved",                                                        │
│      "Approved",                                                        │
│      { "FlaggedForReview": { rule_id, reason, severity, ... } }         │
│    ],                                                                    │
│    "audit_hash": "bf5cfda1e218837d2f8a597f8011b4096...",               │
│    "hash_algo": "blake3"                                                │
│  }                                                                       │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   OFFLINE ZIG VERIFICATION                              │
│                  (tools/zig/src/verify.zig)                             │
├─────────────────────────────────────────────────────────────────────────┤
│  FILE: logs/audit_records.jsonl                                         │
│                                                                          │
│  for each line:                                                         │
│    1. parse JSON                                                        │
│    2. extract hash_algo (blake3, sha3-256, shake256-*, hybrid)          │
│    3. recompute audit_hash from trace                                   │
│    4. compare: stored vs. recomputed                                    │
│       └─ TAMPERING if mismatch                                          │
│                                                                          │
│  if --require-chain:                                                    │
│    1. check record[0].prev_record_hash == null                          │
│    2. for i in 1..N:                                                    │
│       └─ record[i].prev_record_hash must == record[i-1].record_hash     │
│    3. recompute all record_hash values                                  │
│    4. compare: stored vs. recomputed                                    │
│       └─ TAMPERING if mismatch OR continuity broken                     │
│                                                                          │
│  OUTPUT:                                                                │
│  verify: total=N ok=X schema_invalid=Y tampering=Z                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Estado de Decisão (Decision Flowchart)

```
                          TransactionIntent
                                 │
                 ┌───────────────┬┴┬──────────────┐
                 │               │  │              │
              ui_hash_valid     │  amount_cents  is_pep
               reason?          │  timestamp     has_kyc
                                │  risk_bps      ...
                                │
                    ┌───────────┴─────────────┐
                    │                         │
             ▼ Rule 1: UI-FRAUD-001  
             If !ui_hash_valid:
                └─ Blocked("UI integrity failed")
             Else:
                └─ Approved
                            │
                    ┌───────┴──────────┐
                    │                  │
             ▼ Rule 2: BCB-NIGHT-001
             Calculate hour from timestamp + tz_offset
             If is_night && amount > night_limit:
                └─ Blocked("Night limit exceeded")
             Else:
                └─ Approved
                            │
                    ┌───────┴──────────┐
                    │                  │
             ▼ Rule 3: AML-FATF-*
             If is_pep && !has_kyc:
                └─ Blocked("PEP without active KYC")
             If (high_risk && high_amount):
                └─ Blocked("High-risk and high-amount")
             If (high_risk || high_amount):
                └─ FlaggedForReview("Transaction requires AML review")
             Else:
                └─ Approved
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
   ▼ Any Blocked?     ▼ Any Flagged?       ▼ All Approved?
   FinalDecision::   FinalDecision::       FinalDecision::
     Blocked          Flagged              Approved
        │                   │                   │
        └───────────────────┴───────────────────┘
                         │
                    TRACE VECTOR
                   [D1, D2, D3]
                         │
                 ▼ audit_hash(trace)
                 → 64 hex chars (blake3)
                         │
            ▼ record_hash(record fields)
            → 64 hex chars (blake3)
                         │
            ▼ persist to JSONL
            {
              request_id, final_decision, trace,
              audit_hash, hash_algo,
              prev_record_hash, record_hash
            }
```

---

## 3. Lock-Free & Durable Append

```
Time Series:

  State before append:
  ┌──────────────────────────┐
  │ logs/audit_records.jsonl │
  │ {record_1}               │
  │ {record_2}               │
  └──────────────────────────┘
    record_hash_2 = "abc123..."
          │
          └─ this becomes prev_record_hash for record_3

  Action: append(record_3)
          │
          ├─ acquire lock
          │  └─ create logs/audit_records.jsonl.lock
          │     (atomic create_new, fail if exists)
          │
          ├─ read existing file
          │  └─ extract prev_record_hash from record_2.record_hash
          │
          ├─ compute record_3.record_hash
          │
          ├─ write to temp:
          │  └─ create logs/audit_records.jsonl.tmp
          │     write: {record_1}\n{record_2}\n{record_3}
          │     flush()
          │     fsync()
          │     close()
          │
          ├─ atomic rename
          │  └─ rename tmp → final (kernel atomic)
          │     sync_parent_dir() [Unix only]
          │
          ├─ release lock
          │  └─ delete logs/audit_records.jsonl.lock
          │
          └─ return success

  State after append:
  ┌──────────────────────────┐
  │ logs/audit_records.jsonl │
  │ {record_1}               │
  │ {record_2}               │
  │ {record_3}               │
  └──────────────────────────┘
    record_1.prev_record_hash = null
    record_1.record_hash = "abc000..."
    record_2.prev_record_hash = "abc000..."
    record_2.record_hash = "abc111..."
    record_3.prev_record_hash = "abc111..."
    record_3.record_hash = "abc222..."

  Invariant Verified:
  record[i].prev_record_hash == record[i-1].record_hash ✓
```

---

## 4. Zig Verification States

```
                    ┌─────────────────┐
                    │  JSONL File     │
                    │ (audit artifact)│
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Parse JSON     │
                    │  & validate     │
                    │  schema         │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Has record_hash │
                    │    field?       │
                    └──┬──────────┬───┘
                   NO  │          │ YES
                       │          └─────────────────┐
                       │                             │
                 ┌─────▼────────┐         ┌──────────▼──────┐
                 │ Base Verify  │         │ Extract both    │
                 │ (audit_hash) │         │ audit_hash &    │
                 │              │         │ record_hash     │
                 └─────┬────────┘         └────────┬────────┘
                       │                           │
            ┌──────────▼────────────┐  ┌──────────▼─────────┐
            │ Recompute audit_hash  │  │ Recompute both:    │
            │ from trace semantics  │  │ 1. audit_hash      │
            │                       │  │ 2. record_hash     │
            └──────────┬────────────┘  └────────┬───────────┘
                       │                        │
            ┌──────────▼─────────────┐ ┌────────▼──────────┐
            │ Compare:               │ │ Compare:          │
            │ stored == computed?    │ │ stored == computed│
            │                        │ │ for both?         │
            └──────────┬─────────────┘ └────────┬──────────┘
                       │                        │
         ┌─────────────┴──────────┐    ┌────────┴──────────┐
         │ MISMATCH?              │    │ MISMATCH?         │
         │                        │    │                   │
     NO  │               YES      │NO  │           YES     │
        ▼                   ▼          ▼                    ▼
      OK               tampering=true  OK              tampering=true

  Output: verify: total=X ok=Y schema_invalid=Z tampering=W


If --require-chain mode:
  └─ Additional check:
     record[0].prev_record_hash == null (or empty)
     record[i].prev_record_hash == record[i-1].record_hash  ∀i>0
```

---

## 5. Hash Field Framing (Deterministic Serialization)

```
hash_field(hasher, tag: &[u8], data: &[u8]) {
  hasher.update(tag.len() as u32 LE)    // 4 bytes: len(tag)
  hasher.update(tag)                     // N bytes: tag itself
  hasher.update(data.len() as u32 LE)   // 4 bytes: len(data)
  hasher.update(data)                    // M bytes: data itself
}

Example for audit_hash:
  hash_field(hasher, "schema", "trace_v4")
  hash_field(hasher, "D:A", "")
  hash_field(hasher, "D:F", "AML-FATF-REVIEW-001")
  hash_field(hasher, "R", "Transaction requires AML review.")
  hasher.update([1])  // severity.rank()
  hasher.update(150000_u64.to_le_bytes())  // measured
  hasher.update(5000000_u64.to_le_bytes()) // threshold

Result: blake3.finalize() → 32 bytes → hex → 64 chars

This exact framing must be identical in:
  - src/audit/hash.rs (Rust compute)
  - tools/zig/src/crypto.zig (Zig verify)

Reordering fields = different hash = breaking change ❌
```

---

## 6. Error Cases & Fail-Closed Responses

```
Request Flow With Error Cases:

  POST /evaluate
         │
         ├─ Missing HMAC header
         │  └─ 401 Unauthorized
         │
         ├─ Invalid HMAC signature
         │  └─ 401 Unauthorized
         │
         ├─ Stale timestamp (> 60s window)
         │  └─ 408 Request Timeout
         │
         ├─ Duplicate request_id (replay)
         │  └─ 409 Conflict
         │
         ├─ Rate limit exceeded
         │  └─ 429 Too Many Requests
         │
         ├─ Request body oversized (> 1 MB)
         │  └─ 413 Payload Too Large
         │
         ├─ Missing Content-Type or non-JSON
         │  └─ 415 Unsupported Media Type
         │
         ├─ Duplicate Content-Type header
         │  └─ 400 Bad Request
         │
         ├─ Malformed JSON body
         │  └─ 400 Bad Request
         │
         ├─ [evaluation succeeds, but...]
         │
         ├─ Audit append lock file exists
         │  └─ 500 Internal Server Error
         │     (decision NOT returned)
         │
         ├─ Audit file write fails
         │  └─ 500 Internal Server Error
         │     (decision NOT returned)
         │
         ├─ Audit file JSON malformed
         │  └─ 500 Internal Server Error
         │     (decision NOT returned)
         │
         └─ [all checks pass]
            └─ 200 OK + payload
```

---

*Diagramas criados em ASCII/Markdown pronto para dark mode. Copiar/colar em VS Code para melhor visualização. 🖤*
