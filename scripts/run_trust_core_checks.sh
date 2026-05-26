#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${OS:-}" == "Windows_NT" ]] || uname -s | grep -Eiq "mingw|msys|cygwin"; then
  echo "run_trust_core_checks: use scripts/run_trust_core_checks.ps1 on Windows for MSVC-compatible checks." >&2
  exit 2
fi

first_available_cmd() {
  for candidate in "$@"; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      echo "${candidate}"
      return 0
    fi
  done
  return 1
}

CARGO_CMD="$(first_available_cmd cargo cargo.exe || true)"
JULIA_CMD="$(first_available_cmd julia julia.exe || true)"
ZIG_CMD="$(first_available_cmd zig zig.exe || true)"

if [[ -z "${CARGO_CMD}" ]]; then
  echo "run_trust_core_checks: missing required command: cargo/cargo.exe" >&2
  exit 1
fi
if [[ -z "${JULIA_CMD}" ]]; then
  echo "run_trust_core_checks: missing required command: julia/julia.exe" >&2
  exit 1
fi

cd "${ROOT_DIR}"

echo "run_trust_core_checks: cargo test -q"
"${CARGO_CMD}" test -q

echo "run_trust_core_checks: cargo test --features network -q"
"${CARGO_CMD}" test --features network -q

echo "run_trust_core_checks: julia --project=./julia julia/test/runtests.jl"
"${JULIA_CMD}" --project=./julia julia/test/runtests.jl

if [[ -n "${ZIG_CMD}" ]]; then
  echo "run_trust_core_checks: cd tools/zig && zig build test"
  (cd tools/zig && "${ZIG_CMD}" build test)
else
  if [[ "${NEXO_ALLOW_MISSING_ZIG:-0}" == "1" ]]; then
    echo "run_trust_core_checks: zig not found in PATH, skipping zig build test (NEXO_ALLOW_MISSING_ZIG=1)"
  else
    echo "run_trust_core_checks: zig not found in PATH. Install zig or set NEXO_ALLOW_MISSING_ZIG=1 to skip locally." >&2
    exit 1
  fi
fi

echo "run_trust_core_checks: ok"
