#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d /tmp/nexo-evidence-pack-v1-XXXXXX)"

require_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "evidence_pack_quick_v1: missing required command: ${name}" >&2
    exit 1
  fi
}

require_cmd bash
require_cmd cargo
require_cmd curl
require_cmd ruby
require_cmd python3
require_cmd zig

cd "${ROOT_DIR}"

export API_URL="${API_URL:-http://127.0.0.1:3000}"

DEMO_LOG="${WORK_DIR}/demo_decision_flow.log"
INSPECT_LOG="${WORK_DIR}/inspect.log"
FIND_LOG="${WORK_DIR}/find.log"
ZIG_VERIFY_LOG="${WORK_DIR}/zig_verify.log"
TAMPER_LOG="${WORK_DIR}/tamper.log"
CHAIN_LOG="${WORK_DIR}/record_chain.log"

echo "evidence_pack_quick_v1: work_dir=${WORK_DIR}"
echo "evidence_pack_quick_v1: running demo_decision_flow..."
bash scripts/demo_decision_flow.sh | tee "${DEMO_LOG}"

AUDIT_PATH="$(awk -F': ' '/^Audit artifact:/ { value = $2 } END { if (value) print value }' "${DEMO_LOG}")"
RESPONSE_PATH="$(awk -F': ' '/^Response file:/ { value = $2 } END { if (value) print value }' "${DEMO_LOG}")"

if [[ -z "${AUDIT_PATH}" || ! -f "${AUDIT_PATH}" ]]; then
  echo "evidence_pack_quick_v1: failed to locate generated audit artifact" >&2
  exit 1
fi

if [[ -z "${RESPONSE_PATH}" || ! -f "${RESPONSE_PATH}" ]]; then
  echo "evidence_pack_quick_v1: failed to locate generated response file" >&2
  exit 1
fi

REQ_ID="$(ruby -rjson -e 'obj = JSON.parse(File.read(ARGV[0])); print(obj["request_id"] || "")' "${RESPONSE_PATH}" 2>/dev/null || true)"
if [[ -z "${REQ_ID}" ]]; then
  REQ_ID="$(ruby -rjson -e 'obj = JSON.parse(File.read(ARGV[0])); print(obj["audit_hash"] || "")' "${RESPONSE_PATH}" 2>/dev/null || true)"
fi

echo "evidence_pack_quick_v1: inspecting artifact..."
bash scripts/inspect_audit_artifact.sh "${AUDIT_PATH}" | tee "${INSPECT_LOG}"

if [[ -n "${REQ_ID}" ]]; then
  echo "evidence_pack_quick_v1: locating artifact by identifier..."
  bash scripts/find_audit_artifact.sh "${REQ_ID}" "${AUDIT_PATH}" | tee "${FIND_LOG}"
else
  echo "evidence_pack_quick_v1: request_id unavailable in response; skipping find_audit_artifact"
fi

echo "evidence_pack_quick_v1: zig offline verification..."
(cd tools/zig && zig build run -- verify "${AUDIT_PATH}") | tee "${ZIG_VERIFY_LOG}"

echo "evidence_pack_quick_v1: tampering proof..."
bash scripts/demo_tampering_trace.sh | tee "${TAMPER_LOG}"

echo "evidence_pack_quick_v1: record-chain proof..."
bash scripts/demo_record_chain_verification.sh | tee "${CHAIN_LOG}"

echo
echo "evidence_pack_quick_v1: ok"
echo "work_dir=${WORK_DIR}"
echo "audit_artifact=${AUDIT_PATH}"
echo "response_file=${RESPONSE_PATH}"
echo "logs:"
echo "  demo=${DEMO_LOG}"
echo "  inspect=${INSPECT_LOG}"
echo "  find=${FIND_LOG}"
echo "  zig_verify=${ZIG_VERIFY_LOG}"
echo "  tamper=${TAMPER_LOG}"
echo "  chain=${CHAIN_LOG}"
