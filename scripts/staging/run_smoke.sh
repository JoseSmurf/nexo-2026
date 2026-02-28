#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SECRETS_DIR="${ROOT_DIR}/staging/secrets"
CERT_DIR="${ROOT_DIR}/staging/certs"

mkdir -p "${SECRETS_DIR}" "${CERT_DIR}" "${ROOT_DIR}/logs"

if [[ ! -f "${CERT_DIR}/ca.crt" || ! -f "${CERT_DIR}/client.crt" || ! -f "${CERT_DIR}/client.key" ]]; then
  echo "Missing certs. Run: ./scripts/staging/gen_certs.sh"
  exit 1
fi

if [[ ! -f "${SECRETS_DIR}/hmac_secret" ]]; then
  echo "dev-secret-active" > "${SECRETS_DIR}/hmac_secret"
fi
if [[ ! -f "${SECRETS_DIR}/hmac_key_id" ]]; then
  echo "active" > "${SECRETS_DIR}/hmac_key_id"
fi

CLIENT_SEED_B64="${CLIENT_SEED_B64:-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=}"
CLIENT_ID="${CLIENT_ID:-client-a}"
HMAC_KEY_ID="$(tr -d '\r\n' < "${SECRETS_DIR}/hmac_key_id")"
HMAC_SECRET="$(tr -d '\r\n' < "${SECRETS_DIR}/hmac_secret")"

CLIENT_PUB_B64="$(cd "${ROOT_DIR}" && cargo run --quiet --bin client_pubkey -- "${CLIENT_SEED_B64}")"
printf '{"%s":"%s"}\n' "${CLIENT_ID}" "${CLIENT_PUB_B64}" > "${SECRETS_DIR}/client_pubkeys.json"

cd "${ROOT_DIR}"
docker compose -f docker-compose.staging.yml up -d --build

REQ_ID="$(cat /proc/sys/kernel/random/uuid)"
TS="$(date +%s%3N)"
BODY="$(printf '{"user_id":"staging_user","amount_cents":120000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":%s,"risk_bps":1200,"ui_hash_valid":true,"request_id":"%s"}' "${TS}" "${REQ_ID}")"
SIG="$(cargo run --quiet --bin sign_request -- "${HMAC_SECRET}" "${HMAC_KEY_ID}" "${REQ_ID}" "${TS}" "${BODY}")"
CLIENT_SIG="$(cargo run --quiet --bin sign_client_request -- "${CLIENT_SEED_B64}" "${CLIENT_ID}" "${HMAC_KEY_ID}" "${REQ_ID}" "${TS}" "${BODY}")"

curl --fail-with-body -sS \
  --cacert "${CERT_DIR}/ca.crt" \
  --cert "${CERT_DIR}/client.crt" \
  --key "${CERT_DIR}/client.key" \
  -X POST "https://localhost:3443/evaluate" \
  -H "content-type: application/json" \
  -H "x-signature: ${SIG}" \
  -H "x-request-id: ${REQ_ID}" \
  -H "x-timestamp: ${TS}" \
  -H "x-key-id: ${HMAC_KEY_ID}" \
  -H "x-client-id: ${CLIENT_ID}" \
  -H "x-client-signature: ${CLIENT_SIG}" \
  --data "${BODY}"

echo
echo "Smoke test passed."
