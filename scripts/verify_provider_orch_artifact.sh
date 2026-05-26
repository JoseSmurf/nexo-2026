#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_PATH="${1:-${ROOT_DIR}/logs/provider_orchestrator_decision.jsonl}"

if [[ ! -f "${ARTIFACT_PATH}" ]]; then
  echo "verify_provider_orch_artifact: artifact file not found: ${ARTIFACT_PATH}" >&2
  exit 2
fi

cd "${ROOT_DIR}"

cargo run --quiet --bin provider_orch_verify -- "${ARTIFACT_PATH}"
