#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README_PATH="$ROOT_DIR/README.md"

if [[ ! -f "$README_PATH" ]]; then
  echo "README.md not found at $README_PATH"
  exit 1
fi

readme_rust="$(sed -n 's/^- Rust tests: \([0-9][0-9]*\)$/\1/p' "$README_PATH" | head -n1)"
readme_julia="$(sed -n 's/^- Julia tests: \([0-9][0-9]*\)$/\1/p' "$README_PATH" | head -n1)"
readme_zig="$(sed -n 's/^- Zig tests: \([0-9][0-9]*\)$/\1/p' "$README_PATH" | head -n1)"
readme_total="$(sed -n 's/^- Total tests: \([0-9][0-9]*\)$/\1/p' "$README_PATH" | head -n1)"

if [[ -z "$readme_rust" || -z "$readme_julia" || -z "$readme_zig" || -z "$readme_total" ]]; then
  echo "README test counters not found or malformed."
  exit 1
fi

if ! grep -Eq "^[[:space:]]*-[[:space:]]*BLAKE3 \+ SHAKE256" "$README_PATH"; then
  echo "README tech stack hash line is missing or outdated."
  exit 1
fi

if grep -Eq "^[[:space:]]*-[[:space:]]*BLAKE3 \+ SHA3-256" "$README_PATH"; then
  echo "README still contains deprecated runtime tech stack line with SHA3-256."
  exit 1
fi

actual_rust="$(
  grep -R -E '#\[tokio::test\]|#\[test\]' "$ROOT_DIR/src" --include='*.rs' \
    | wc -l | tr -d ' '
)"
actual_zig="$(
  grep -R -E '^test "' "$ROOT_DIR/tools/zig/src" --include='*.zig' \
    | wc -l | tr -d ' '
)"

if ! command -v julia >/dev/null 2>&1; then
  echo "julia command not found; cannot validate Julia test total."
  exit 1
fi

julia_output="$(
  cd "$ROOT_DIR"
  julia --project=./julia julia/test_plca.jl 2>&1
)"

actual_julia="$(
  printf '%s\n' "$julia_output" \
    | sed -n 's/^PLCA score and risk_bps | *[0-9][0-9]* *\([0-9][0-9]*\).*/\1/p' \
    | tail -n1
)"

if [[ -z "$actual_julia" ]]; then
  echo "Could not parse Julia test total from julia/test_plca.jl output."
  printf '%s\n' "$julia_output"
  exit 1
fi

actual_total=$((actual_rust + actual_julia + actual_zig))

echo "README counters: rust=$readme_rust julia=$readme_julia zig=$readme_zig total=$readme_total"
echo "Actual counters: rust=$actual_rust julia=$actual_julia zig=$actual_zig total=$actual_total"

if [[ "$readme_rust" != "$actual_rust" ]]; then
  echo "Mismatch: README Rust tests=$readme_rust but actual=$actual_rust"
  exit 1
fi
if [[ "$readme_julia" != "$actual_julia" ]]; then
  echo "Mismatch: README Julia tests=$readme_julia but actual=$actual_julia"
  exit 1
fi
if [[ "$readme_zig" != "$actual_zig" ]]; then
  echo "Mismatch: README Zig tests=$readme_zig but actual=$actual_zig"
  exit 1
fi
if [[ "$readme_total" != "$actual_total" ]]; then
  echo "Mismatch: README Total tests=$readme_total but actual=$actual_total"
  exit 1
fi

echo "README consistency check passed."
