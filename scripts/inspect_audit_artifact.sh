#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDIT_PATH_INPUT="${1:-${NEXO_AUDIT_PATH:-logs/audit_records.jsonl}}"
INSPECT_DIR="${ROOT_DIR}/logs"

if [[ "${AUDIT_PATH_INPUT}" = /* ]]; then
  AUDIT_PATH="${AUDIT_PATH_INPUT}"
else
  AUDIT_PATH="${ROOT_DIR}/${AUDIT_PATH_INPUT}"
fi

if [[ ! -f "${AUDIT_PATH}" ]]; then
  echo "Audit file not found: ${AUDIT_PATH}" >&2
  exit 1
fi

LATEST_LINE="$(awk 'NF { line = $0 } END { if (line) print line; else exit 1 }' "${AUDIT_PATH}")" || {
  echo "No non-empty audit artifacts found in ${AUDIT_PATH}" >&2
  exit 1
}

ARTIFACT_COUNT="$(awk 'NF { count += 1 } END { print count + 0 }' "${AUDIT_PATH}")"
mkdir -p "${INSPECT_DIR}"
LATEST_ARTIFACT="$(mktemp "${INSPECT_DIR}/inspect-audit-artifact-XXXXXX.jsonl")"
printf '%s\n' "${LATEST_LINE}" > "${LATEST_ARTIFACT}"

echo "Audit source: ${AUDIT_PATH}"
echo "Persisted artifacts: ${ARTIFACT_COUNT}"
echo "Latest artifact file: ${LATEST_ARTIFACT}"
echo
echo "Main fields:"

if command -v jq >/dev/null 2>&1; then
  jq '{
    request_id,
    final_decision,
    hash_algo,
    audit_hash,
    timestamp_utc_ms,
    profile_name,
    profile_version,
    user_id,
    amount_cents,
    risk_bps,
    prev_record_hash,
    record_hash,
    trace
  }' "${LATEST_ARTIFACT}"
else
  echo "${LATEST_LINE}"
  echo
  echo "Install jq for structured field inspection."
fi

echo
echo "To verify this artifact with Zig:"
echo "cd ${ROOT_DIR}/tools/zig && zig build run -- verify ${LATEST_ARTIFACT}"
