#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${OS:-}" == "Windows_NT" ]] || uname -s | grep -Eiq "mingw|msys|cygwin"; then
  echo "run_release_gate: use scripts/run_release_gate.ps1 on Windows for MSVC-compatible checks." >&2
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
ZIG_CMD="$(first_available_cmd zig zig.exe || true)"

if [[ -z "${CARGO_CMD}" ]]; then
  echo "run_release_gate: missing required command: cargo/cargo.exe" >&2
  exit 1
fi

if ! "${CARGO_CMD}" deny --version >/dev/null 2>&1; then
  echo "run_release_gate: cargo-deny is not installed. Install with: cargo install --locked cargo-deny" >&2
  exit 1
fi

cd "${ROOT_DIR}"

echo "run_release_gate: cargo fmt --check"
"${CARGO_CMD}" fmt --check

echo "run_release_gate: cargo clippy --all-targets --all-features -- -D warnings"
"${CARGO_CMD}" clippy --all-targets --all-features -- -D warnings

echo "run_release_gate: bash scripts/check_readme_consistency.sh"
bash scripts/check_readme_consistency.sh

echo "run_release_gate: bash scripts/check_supply_chain_surface.sh"
bash scripts/check_supply_chain_surface.sh

echo "run_release_gate: cargo deny check"
"${CARGO_CMD}" deny check

echo "run_release_gate: bash scripts/run_trust_core_checks.sh"
bash scripts/run_trust_core_checks.sh

if [[ -n "${ZIG_CMD}" ]]; then
  echo "run_release_gate: cd tools/zig && zig build run -- verify ../../fixtures/audit_sample.jsonl"
  (cd tools/zig && "${ZIG_CMD}" build run -- verify ../../fixtures/audit_sample.jsonl)

  echo "run_release_gate: cd tools/zig && zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl"
  (cd tools/zig && "${ZIG_CMD}" build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl)
elif [[ "${NEXO_ALLOW_MISSING_ZIG:-0}" == "1" ]]; then
  echo "run_release_gate: zig not found in PATH, skipping offline verify steps (NEXO_ALLOW_MISSING_ZIG=1)"
else
  echo "run_release_gate: zig not found in PATH. Install zig or set NEXO_ALLOW_MISSING_ZIG=1 for local-only skip." >&2
  exit 1
fi

echo "run_release_gate: ok"
