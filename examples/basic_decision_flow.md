# Basic Decision Flow

This example shows one real local flow:

1. start the API
2. send one signed request
3. produce one audit record
4. verify that record with the Zig verifier

## Start the API

```bash
cd nexo-2026
cp .env.example .env
export NEXO_HMAC_SECRET='dev-secret-active'
export NEXO_HMAC_KEY_ID='active'
export NEXO_PROFILE='br_default_v1'
cargo run --bin syntax-engine
```

## Send one evaluation request

Open a second terminal:

```bash
cd nexo-2026
REQ_ID="$(cat /proc/sys/kernel/random/uuid)"
TS="$(date +%s%3N)"
BODY="$(printf '{"user_id":"example_user","amount_cents":150000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":%s,"risk_bps":1200,"ui_hash_valid":true,"request_id":"%s"}' "$TS" "$REQ_ID")"
SIG="$(cargo run --quiet --bin sign_request -- "$NEXO_HMAC_SECRET" "$NEXO_HMAC_KEY_ID" "$REQ_ID" "$TS" "$BODY")"
curl -sS -X POST 'http://127.0.0.1:3000/evaluate' \
  -H 'content-type: application/json' \
  -H "x-signature: $SIG" \
  -H "x-request-id: $REQ_ID" \
  -H "x-timestamp: $TS" \
  -H "x-key-id: $NEXO_HMAC_KEY_ID" \
  --data "$BODY"
```

Expected response shape:

```json
{
  "request_id": "...",
  "profile_name": "br_default_v1",
  "profile_version": "2026.02",
  "auth_key_id": "active",
  "final_decision": "Blocked|Flagged|Approved",
  "trace": ["..."],
  "audit_hash": "...",
  "hash_algo": "blake3|shake256-256|shake256-384|shake256-512|shake256-512+blake3-256"
}
```

## Inspect the generated audit record

```bash
tail -n 1 logs/audit_records.jsonl
```

The stored record is the artifact later checked by the Zig verifier.

## Verify the record offline with Zig

```bash
cd tools/zig
zig build test
zig build run -- verify ../../logs/audit_records.jsonl
```

Expected result:

```text
verify: total=1 ok=1 schema_invalid=false tampering=false
```

## End-to-end contract

The minimal public verification flow is:

`request -> engine evaluation -> decision trace -> audit hash -> audit record -> Zig verification`

This is the smallest complete path NEXO exposes for `v0.2.0`.
