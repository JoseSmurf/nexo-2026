# Flagged Decision Flow

This companion example shows a non-approved outcome while keeping the same verifiable path:

1. start the API
2. send one signed request
3. produce one audit record
4. verify that record with the Zig verifier

Fast path:

```bash
bash scripts/demo_decision_flow_flagged.sh
```

Why this request is expected to be flagged:

- `risk_bps=9500`
- default AML review threshold is `9000`
- `amount_cents=50000` stays below the blocking amount threshold

That combination should produce `Flagged` with an AML review trace step, not `Approved` and not `Blocked`.

## Manual request

```bash
cd nexo-2026
REQ_ID="$(cat /proc/sys/kernel/random/uuid)"
TS="$(date +%s%3N)"
BODY="$(printf '{"user_id":"flagged_example_user","amount_cents":50000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":%s,"risk_bps":9500,"ui_hash_valid":true,"request_id":"%s"}' "$TS" "$REQ_ID")"
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
  "final_decision": "Flagged",
  "trace": [
    "Approved",
    "Approved",
    {
      "FlaggedForReview": {
        "rule_id": "AML-FATF-REVIEW-001"
      }
    }
  ]
}
```

## Verification path

The verification path stays the same:

`API -> engine decision -> trace -> audit record -> Zig verification`
