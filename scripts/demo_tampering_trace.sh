#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

require_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "Missing required command: ${name}" >&2
    exit 1
  fi
}

require_cmd python3
require_cmd zig

DEMO_LOG="$(mktemp /tmp/nexo-demo-tampering-trace-XXXXXX.log)"

echo "Running flagged demo to generate a valid audit artifact..."
bash scripts/demo_decision_flow_flagged.sh | tee "${DEMO_LOG}"

AUDIT_PATH="$(grep -E '^Audit artifact: /' "${DEMO_LOG}" | tail -n 1 | sed 's/^Audit artifact: //')"
if [[ -z "${AUDIT_PATH}" ]]; then
  echo "Failed to locate audit artifact path in demo output. Log: ${DEMO_LOG}" >&2
  exit 1
fi
if [[ ! -s "${AUDIT_PATH}" ]]; then
  echo "Audit artifact does not exist or is empty: ${AUDIT_PATH}" >&2
  exit 1
fi

echo
echo "Building Zig verifier binary (nexo-audit)..."
(cd tools/zig && zig build)
ZIG_AUDIT_BIN="${ROOT_DIR}/tools/zig/zig-out/bin/nexo-audit"
if [[ ! -x "${ZIG_AUDIT_BIN}" ]]; then
  echo "Expected Zig verifier binary not found/executable: ${ZIG_AUDIT_BIN}" >&2
  exit 1
fi

echo
echo "Zig verification (original):"
set +e
ZIG_ORIG_OUT="$( "${ZIG_AUDIT_BIN}" verify "${AUDIT_PATH}" 2>&1 )"
ZIG_ORIG_CODE=$?
set -e
echo "${ZIG_ORIG_OUT}"
if [[ "${ZIG_ORIG_CODE}" -ne 0 ]]; then
  echo "Expected original artifact to verify cleanly, but Zig exited with ${ZIG_ORIG_CODE}." >&2
  exit 1
fi

TAMPERED_PATH="$(mktemp /tmp/nexo-demo-flagged-audit-tampered-XXXXXX.jsonl)"

python3 - "${AUDIT_PATH}" "${TAMPERED_PATH}" <<'PY'
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

changed = 0
out_lines = []

with src.open("r", encoding="utf-8") as f:
    for raw in f:
        line = raw.strip()
        if not line:
            continue
        obj = json.loads(line)
        trace = obj.get("trace")
        if isinstance(trace, list):
            for item in trace:
                if not isinstance(item, dict):
                    continue
                payload = item.get("FlaggedForReview")
                if not isinstance(payload, dict):
                    continue
                measured = payload.get("measured")
                if isinstance(measured, int):
                    payload["measured"] = measured + 1
                    changed += 1
                    break
        out_lines.append(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))

if changed == 0:
    raise SystemExit("No trace[*].FlaggedForReview.measured field found to tamper.")

dst.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
PY

echo
echo "Zig verification (tampered copy, expected tampering):"
set +e
ZIG_TAMPER_OUT="$( "${ZIG_AUDIT_BIN}" verify "${TAMPERED_PATH}" 2>&1 )"
ZIG_TAMPER_CODE=$?
set -e
echo "${ZIG_TAMPER_OUT}"
if [[ "${ZIG_TAMPER_CODE}" -ne 3 ]]; then
  echo "Expected tampered artifact to be rejected as tampering (exit code 3), but got ${ZIG_TAMPER_CODE}." >&2
  exit 1
fi
if ! grep -qE 'tampering=true|line [0-9]+: tampering' <<<"${ZIG_TAMPER_OUT}"; then
  echo "Expected tampering evidence in Zig output, but did not find it." >&2
  exit 1
fi

echo
echo "Tampering demo summary:"
echo "original_artifact: ${AUDIT_PATH}"
echo "tampered_artifact: ${TAMPERED_PATH}"
echo "zig_original_exit: ${ZIG_ORIG_CODE} (expected 0)"
echo "zig_tampered_exit: ${ZIG_TAMPER_CODE} (expected 3)"
echo "conclusion: ok (tampering detected)"
