#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT_PATH="${1:-${ROOT_DIR}/fixtures/provider_metrics_cycle_sample.json}"
ARTIFACT_PATH="${2:-${ROOT_DIR}/logs/provider_orchestrator_cycle.jsonl}"
REPORT_PATH="${3:-${ROOT_DIR}/logs/provider_orchestrator_cycle_report.json}"

if [[ ! -f "${INPUT_PATH}" ]]; then
  echo "run_provider_orch_cycle: input file not found: ${INPUT_PATH}" >&2
  exit 2
fi

cd "${ROOT_DIR}"

export NEXO_PROVIDER_ORCH="${NEXO_PROVIDER_ORCH:-1}"

cargo run --quiet --bin provider_orch_cycle -- "${INPUT_PATH}" "${ARTIFACT_PATH}" "${REPORT_PATH}"

echo "run_provider_orch_cycle: report=${REPORT_PATH}"
