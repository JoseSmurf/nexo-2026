#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_URL="${API_URL:-http://127.0.0.1:3000}"
AUDIT_FILE="$(mktemp /tmp/nexo-demo-flagged-audit-XXXXXX.jsonl)"
RESPONSE_FILE="$(mktemp /tmp/nexo-demo-flagged-response-XXXXXX.json)"
SERVER_LOG="$(mktemp /tmp/nexo-demo-flagged-server-XXXXXX.log)"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}

trap cleanup EXIT

cd "${ROOT_DIR}"

export NEXO_HMAC_SECRET="${NEXO_HMAC_SECRET:-dev-secret-active}"
export NEXO_HMAC_KEY_ID="${NEXO_HMAC_KEY_ID:-active}"
export NEXO_PROFILE="${NEXO_PROFILE:-br_default_v1}"
export NEXO_AUDIT_PATH="${AUDIT_FILE}"

cargo run --quiet --bin syntax-engine >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 120); do
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "API process exited early. Server log: ${SERVER_LOG}" >&2
    exit 1
  fi
  if curl -fsS "${API_URL}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -fsS "${API_URL}/healthz" >/dev/null 2>&1; then
  echo "API did not become ready. Server log: ${SERVER_LOG}" >&2
  exit 1
fi

REQ_ID="$(cat /proc/sys/kernel/random/uuid)"
TS="$(date +%s%3N)"
BODY="$(printf '{"user_id":"demo_flagged_user","amount_cents":50000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":%s,"risk_bps":9500,"ui_hash_valid":true,"request_id":"%s"}' "${TS}" "${REQ_ID}")"
SIG="$(cargo run --quiet --bin sign_request -- "${NEXO_HMAC_SECRET}" "${NEXO_HMAC_KEY_ID}" "${REQ_ID}" "${TS}" "${BODY}")"

curl -fsS -X POST "${API_URL}/evaluate" \
  -H "content-type: application/json" \
  -H "x-signature: ${SIG}" \
  -H "x-request-id: ${REQ_ID}" \
  -H "x-timestamp: ${TS}" \
  -H "x-key-id: ${NEXO_HMAC_KEY_ID}" \
  --data "${BODY}" \
  >"${RESPONSE_FILE}"

if [[ ! -s "${AUDIT_FILE}" ]]; then
  echo "No audit artifact was written to ${AUDIT_FILE}" >&2
  exit 1
fi

if ! grep -q '"final_decision":"Flagged"' "${RESPONSE_FILE}"; then
  echo "Expected a flagged decision but response differed. Response file: ${RESPONSE_FILE}" >&2
  exit 1
fi

echo "Expected outcome:"
echo "FlaggedForReview due to AML review threshold. This request sets risk_bps=9500, which is above the default AML review threshold (9000), while amount_cents=50000 stays below the blocking amount threshold."
echo
echo "Response:"
cat "${RESPONSE_FILE}"
echo
echo
echo "Audit artifact:"
tail -n 1 "${AUDIT_FILE}"
echo
echo
echo "Zig verification:"
(cd tools/zig && zig build run -- verify "${AUDIT_FILE}")
echo
echo "Flagged demo completed successfully."
echo "Response file: ${RESPONSE_FILE}"
echo "Audit artifact: ${AUDIT_FILE}"
echo "Server log: ${SERVER_LOG}"
