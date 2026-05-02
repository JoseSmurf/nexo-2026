#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROOF_DIR="$(mktemp -d /tmp/nexo-interface-v0-acceptance-XXXXXX)"
AUDIT_FILE="${PROOF_DIR}/audit_records.jsonl"
RESPONSE_FILE="${PROOF_DIR}/evaluate_response.json"
INSPECT_OUTPUT="${PROOF_DIR}/inspect_output.txt"
FIND_OUTPUT="${PROOF_DIR}/find_output.txt"
ZIG_OUTPUT="${PROOF_DIR}/zig_verify_output.txt"
BOOT_OUTPUT="${PROOF_DIR}/boot_output.txt"

CORE_BIND="${NEXO_HTTP_BIND:-127.0.0.1:3000}"
UI_BIND="${NEXO_UI_BIND:-127.0.0.1}"
UI_PORT="${NEXO_UI_PORT:-4567}"
CORE_PORT="${CORE_BIND##*:}"
CORE_HOST="${CORE_BIND%:*}"
CORE_STATE_URL="http://${CORE_HOST}:${CORE_PORT}/api/state"
UI_URL="http://${UI_BIND}:${UI_PORT}"
CORE_READY_TIMEOUT_SECONDS="${NEXO_ACCEPT_CORE_READY_TIMEOUT_SECONDS:-240}"
UI_READY_TIMEOUT_SECONDS="${NEXO_ACCEPT_UI_READY_TIMEOUT_SECONDS:-30}"

BOOT_PID=""

cleanup() {
  local exit_code=$?

  if [[ -n "${BOOT_PID}" ]] && kill -0 "${BOOT_PID}" 2>/dev/null; then
    kill "${BOOT_PID}" 2>/dev/null || true
    wait "${BOOT_PID}" 2>/dev/null || true
  fi

  exit "${exit_code}"
}

trap cleanup EXIT INT TERM

fail() {
  echo "controlled-host acceptance: failed" >&2
  echo "reason: $*" >&2
  echo "proof dir: ${PROOF_DIR}" >&2
  exit 1
}

require_command() {
  local name="$1"
  command -v "${name}" >/dev/null 2>&1 || fail "missing required command: ${name}"
}

wait_for_url() {
  local url="$1"
  local attempts="${2:-60}"

  while (( attempts > 0 )); do
    if curl --silent --show-error --fail --max-time 1 "${url}" >/dev/null 2>&1; then
      return 0
    fi

    sleep 1
    attempts=$((attempts - 1))
  done

  return 1
}

extract_prepared_artifact() {
  local path
  path="$(awk -F': ' '/^Prepared artifact:/ { value = $2 } END { if (value) print value }' "$1")"

  if [[ -z "${path}" || ! -f "${path}" ]]; then
    fail "could not locate prepared artifact from $1"
  fi

  printf '%s\n' "${path}"
}

uuid_value() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  elif [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  else
    fail "uuidgen is unavailable and /proc/sys/kernel/random/uuid is not readable"
  fi
}

require_command cargo
require_command curl
require_command ruby
require_command zig

cd "${ROOT_DIR}"

if [[ "${CORE_HOST}" != "127.0.0.1" && "${CORE_HOST}" != "localhost" ]]; then
  fail "controlled-host acceptance requires NEXO_HTTP_BIND on loopback; got ${CORE_BIND}"
fi

if [[ "${UI_BIND}" != "127.0.0.1" && "${UI_BIND}" != "localhost" ]]; then
  fail "controlled-host acceptance requires NEXO_UI_BIND on loopback; got ${UI_BIND}"
fi

export NEXO_HMAC_SECRET="${NEXO_HMAC_SECRET:-dev-secret-active}"
export NEXO_HMAC_KEY_ID="${NEXO_HMAC_KEY_ID:-active}"
export NEXO_PROFILE="${NEXO_PROFILE:-br_default_v1}"
export NEXO_AUDIT_PATH="${AUDIT_FILE}"
export NEXO_HTTP_BIND="${CORE_BIND}"
export NEXO_UI_BIND="${UI_BIND}"
export NEXO_UI_PORT="${UI_PORT}"
unset NEXO_CORE_STATE_URL
export NEXO_V0_LOG_DIR="${NEXO_V0_LOG_DIR:-${PROOF_DIR}/interface_v0_online_logs}"

echo "controlled-host acceptance: starting"
echo "repo_commit=$(git rev-parse HEAD)"
echo "host=$(hostname)"
echo "proof_dir=${PROOF_DIR}"
echo "core_state_url=${CORE_STATE_URL}"
echo "ui_url=${UI_URL}"
echo "audit_file=${AUDIT_FILE}"
echo "core_bin=${NEXO_CORE_BIN:-scripts/run_interface_v0_online.sh default}"
echo "core_ready_timeout_seconds=${CORE_READY_TIMEOUT_SECONDS}"

bash scripts/run_interface_v0_online.sh >"${BOOT_OUTPUT}" 2>&1 &
BOOT_PID=$!

if ! wait_for_url "${CORE_STATE_URL}" "${CORE_READY_TIMEOUT_SECONDS}"; then
  fail "core did not become ready at ${CORE_STATE_URL}; boot output: ${BOOT_OUTPUT}"
fi

if ! wait_for_url "${UI_URL}" "${UI_READY_TIMEOUT_SECONDS}"; then
  fail "ui did not become reachable at ${UI_URL}; boot output: ${BOOT_OUTPUT}"
fi

REQ_ID="$(uuid_value)"
TS="$(date +%s%3N)"
BODY="$(printf '{"user_id":"controlled_host_acceptance_user","amount_cents":50000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":%s,"risk_bps":1200,"ui_hash_valid":true,"request_id":"%s"}' "${TS}" "${REQ_ID}")"
SIG="$(cargo run --quiet --bin sign_request -- "${NEXO_HMAC_SECRET}" "${NEXO_HMAC_KEY_ID}" "${REQ_ID}" "${TS}" "${BODY}")"

curl --silent --show-error --fail -X POST "http://127.0.0.1:${CORE_PORT}/evaluate" \
  -H "content-type: application/json" \
  -H "x-signature: ${SIG}" \
  -H "x-request-id: ${REQ_ID}" \
  -H "x-timestamp: ${TS}" \
  -H "x-key-id: ${NEXO_HMAC_KEY_ID}" \
  --data "${BODY}" \
  >"${RESPONSE_FILE}" || fail "evaluate request failed"

ruby -rjson -e '
  path = ARGV.fetch(0)
  obj = JSON.parse(File.read(path))
  required = %w[final_decision trace audit_hash hash_algo]
  missing = required.select { |key| !obj.key?(key) }
  abort("missing response fields: #{missing.join(", ")}") unless missing.empty?
  abort("trace must be an array") unless obj["trace"].is_a?(Array)
' "${RESPONSE_FILE}" || fail "evaluate response shape is invalid"

[[ -s "${AUDIT_FILE}" ]] || fail "audit file was not written: ${AUDIT_FILE}"

bash scripts/inspect_audit_artifact.sh "${NEXO_AUDIT_PATH}" >"${INSPECT_OUTPUT}" || fail "audit inspection failed"
bash scripts/find_audit_artifact.sh "${REQ_ID}" "${NEXO_AUDIT_PATH}" >"${FIND_OUTPUT}" || fail "exact audit artifact lookup failed"

PREPARED_ARTIFACT="$(extract_prepared_artifact "${FIND_OUTPUT}")"
(
  cd tools/zig
  zig build run -- verify "${PREPARED_ARTIFACT}"
) >"${ZIG_OUTPUT}" 2>&1 || fail "offline Zig verification failed"

if ! grep -q "verify: total=1 ok=1 schema_invalid=false tampering=false" "${ZIG_OUTPUT}"; then
  fail "offline Zig verification did not report the expected success line"
fi

echo "request_id=${REQ_ID}"
echo "response_file=${RESPONSE_FILE}"
echo "inspect_output=${INSPECT_OUTPUT}"
echo "find_output=${FIND_OUTPUT}"
echo "prepared_artifact=${PREPARED_ARTIFACT}"
echo "zig_verify_output=${ZIG_OUTPUT}"
echo "boot_output=${BOOT_OUTPUT}"
echo "controlled-host acceptance: ok"
