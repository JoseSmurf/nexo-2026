# Release Plan v0.2.0

## Release scope

`v0.2.0` is the next structured public release of NEXO as a deterministic decision engine with a verifiable audit trail.

This release is intentionally narrow:

- Signed `POST /evaluate` API flow
- Deterministic rule evaluation in Rust
- Stable decision trace semantics
- Deterministic audit hashing
- JSONL audit record persistence
- Offline forensic verification with the Zig verifier

The goal of `v0.2.0` is to ship one complete, reviewable path from request intake to offline audit verification, aligned with the current architecture and release posture, without changing engine behavior during release preparation.

## Core capabilities included

- Rust API with fail-closed request validation
- Deterministic engine evaluation with stable rule ordering
- `final_decision` + `trace` response contract
- Audit hash selection contract:
  - `blake3`
  - `shake256-256`
  - `shake256-384`
  - `shake256-512`
  - `shake256-512+blake3-256`
- Audit record append flow in `logs/audit_records.jsonl`
- Audit record chaining fields:
  - `prev_record_hash`
  - `record_hash`
- Offline Zig verification of audit records against stored `audit_hash`
- Local developer flow with `sign_request` for request signing

## Features intentionally deferred

- Broad distributed deployment guidance
- Production secret-provider rollout as a release requirement
- Full Ruby UI release positioning as primary public surface
- P2P chat/relay/network features as part of the `v0.2.0` public contract
- Historical Julia observation artifacts as a release requirement
- Long-term audit archive/backfill tooling
- Public auth model for mutation endpoints beyond the current local/internal posture

## Minimal end-to-end flow

The `v0.2.0` release flow is:

1. Client signs a request for `POST /evaluate`
2. Rust API validates:
   - HMAC
   - timestamp window
   - replay protection
   - rate-limit / security guards
3. Engine evaluates the request deterministically
4. Engine returns:
   - `final_decision`
   - ordered `trace`
5. Audit layer computes `audit_hash` from trace semantics
6. Audit store appends an `AuditRecord` to `logs/audit_records.jsonl`
7. Zig verifier recomputes the trace hash offline and validates:
   - schema shape
   - `final_decision` consistency
   - `audit_hash` integrity

## Local run procedure

### 1. Start the API

```bash
git clone https://github.com/JoseSmurf/nexo-2026
cd nexo-2026
cp .env.example .env
export NEXO_HMAC_SECRET='dev-secret-active'
export NEXO_HMAC_KEY_ID='active'
export NEXO_PROFILE='br_default_v1'
cargo run --bin syntax-engine
```

### 2. Send a signed evaluation request

In a second terminal:

```bash
cd nexo-2026
REQ_ID="$(cat /proc/sys/kernel/random/uuid)"
TS="$(date +%s%3N)"
BODY="$(printf '{"user_id":"release_user","amount_cents":50000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":%s,"risk_bps":1200,"ui_hash_valid":true,"request_id":"%s"}' "$TS" "$REQ_ID")"
SIG="$(cargo run --quiet --bin sign_request -- "$NEXO_HMAC_SECRET" "$NEXO_HMAC_KEY_ID" "$REQ_ID" "$TS" "$BODY")"
curl -sS -X POST 'http://127.0.0.1:3000/evaluate' \
  -H 'content-type: application/json' \
  -H "x-signature: $SIG" \
  -H "x-request-id: $REQ_ID" \
  -H "x-timestamp: $TS" \
  -H "x-key-id: $NEXO_HMAC_KEY_ID" \
  --data "$BODY"
```

### 3. Confirm audit record generation

```bash
tail -n 1 logs/audit_records.jsonl
```

Expected fields include:

- `request_id`
- `final_decision`
- `trace`
- `audit_hash`
- `hash_algo`

### 4. Verify the audit record with Zig

```bash
cd tools/zig
zig build test
zig build run -- verify ../../logs/audit_records.jsonl
```

Expected verifier outcome:

- `ok` when the record is structurally valid and the hash matches the trace semantics
- non-zero exit when schema drift or tampering is detected

### Fast demo path

For a single-command local demo:

```bash
bash scripts/demo_decision_flow.sh
```

This script starts the API, sends one signed request, captures the generated audit artifact in a temporary file, and verifies that artifact with the Zig verifier.

## Release acceptance checklist

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test -q`
- `cargo test --features network -q`
- `julia --project=./julia julia/test/runtests.jl`
- `cd tools/zig && zig build test`
- `cd tools/zig && zig build run -- verify ../../fixtures/audit_sample.jsonl`
- `cd tools/zig && zig build run -- verify ../../logs/audit_records.jsonl`

## Public release posture

`v0.2.0` should be presented as:

- deterministic engine first
- auditability-first release
- offline verification included
- deliberately narrow public scope

It should not be presented as a finished distributed platform release.
