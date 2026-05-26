#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT_PATH="${1:-${ROOT_DIR}/fixtures/provider_metrics_sample.json}"

if [[ ! -f "${INPUT_PATH}" ]]; then
  echo "run_provider_orch_shadow: input file not found: ${INPUT_PATH}" >&2
  exit 2
fi

cd "${ROOT_DIR}"

export NEXO_PROVIDER_ORCH="${NEXO_PROVIDER_ORCH:-1}"

cargo run --quiet --bin provider_orch_shadow -- "${INPUT_PATH}"
