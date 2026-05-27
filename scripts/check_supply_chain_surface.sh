#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

status=0
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

fail_with_matches() {
  local check_name="$1"
  local why="$2"
  local matches_file="$3"
  echo "[check_supply_chain_surface] FAIL: ${check_name}" >&2
  echo "  why: ${why}" >&2
  echo "  matches:" >&2
  cat "$matches_file" >&2
  echo "  action: treat as a security review incident; do not merge silently." >&2
  status=1
}

echo "[check_supply_chain_surface] scanning repository-owned supply-chain surface..."

RG_BIN=""
if command -v rg >/dev/null 2>&1; then
  RG_BIN="$(command -v rg)"
elif command -v rg.exe >/dev/null 2>&1; then
  RG_BIN="$(command -v rg.exe)"
elif [[ -x "$HOME/.cargo/bin/rg.exe" ]]; then
  RG_BIN="$HOME/.cargo/bin/rg.exe"
fi

if [[ -z "$RG_BIN" ]]; then
  echo "[check_supply_chain_surface] FAIL: missing required command 'rg' (ripgrep)." >&2
  echo "  action: install ripgrep and ensure it is available in this shell PATH before running the supply-chain gate." >&2
  exit 1
fi

find . -type f -name build.rs \
  -not -path "./target/*" \
  -not -path "./.git/*" \
  -not -path "./.codex/*" \
  -not -path "./vendor/*" \
  -not -path "./.cargo/*" \
  >"$tmp_dir/build_rs.txt"
if [[ -s "$tmp_dir/build_rs.txt" ]]; then
  fail_with_matches \
    "repository-owned build.rs files" \
    "repo build scripts execute during build and can alter trusted build behavior" \
    "$tmp_dir/build_rs.txt"
fi

scan_dirs=()
for dir in src tests benches; do
  if [[ -d "$dir" ]]; then
    scan_dirs+=("$dir")
  fi
done

check_rust_pattern() {
  local pattern="$1"
  local label="$2"
  local why="$3"
  local ignore_regex="${4:-}"
  local out_raw="$tmp_dir/pattern_raw.txt"
  local out_file="$tmp_dir/pattern.txt"
  local rg_status=0

  set +e
  "$RG_BIN" -n --glob '*.rs' "$pattern" "${scan_dirs[@]}" >"$out_raw"
  rg_status=$?
  set -e

  if [[ "$rg_status" -eq 1 ]]; then
    return 0
  fi
  if [[ "$rg_status" -ne 0 ]]; then
    echo "[check_supply_chain_surface] FAIL: ripgrep execution failed for pattern check '$label' (exit=${rg_status})." >&2
    exit 1
  fi

  if [[ -n "$ignore_regex" ]]; then
    grep -Ev "$ignore_regex" "$out_raw" >"$out_file" || true
  else
    cp "$out_raw" "$out_file"
  fi

  if [[ -s "$out_file" ]]; then
    fail_with_matches "$label" "$why" "$out_file"
  fi
}

if [[ "${#scan_dirs[@]}" -gt 0 ]]; then
  check_rust_pattern '\bunsafe\b' "unsafe usage in sensitive Rust paths" "unsafe in trust-adjacent paths requires explicit approval and narrow justification"
  check_rust_pattern 'extern "C"' "FFI boundary in sensitive Rust paths" "FFI expands memory-safety and ABI trust assumptions"
  # Known exceptions:
  # - src/api.rs: test-only Zig verifier helper inside #[cfg(test)] module
  # - src/bin/trust_core_validate.rs: explicit local operator tooling binary
  allowed_process_spawn_files='^src[\\/](api\.rs|bin[\\/]trust_core_validate\.rs):'
  check_rust_pattern 'std::process::Command' "runtime process execution in sensitive Rust paths" "process spawning can expand command-injection and runtime trust surface" "$allowed_process_spawn_files"
  check_rust_pattern 'Command::new\(' "runtime process execution constructor in sensitive Rust paths" "process spawning can expand command-injection and runtime trust surface" "$allowed_process_spawn_files"
  check_rust_pattern 'std::ptr' "raw pointer API usage in sensitive Rust paths" "raw pointer usage can bypass safety guarantees"
  check_rust_pattern 'std::mem::transmute' "transmute usage in sensitive Rust paths" "transmute can silently violate type and memory invariants"
  check_rust_pattern 'MaybeUninit' "MaybeUninit usage in sensitive Rust paths" "manual initialization paths need explicit memory-safety review"
  check_rust_pattern 'libloading' "dynamic library loading in sensitive Rust paths" "runtime dynamic loading expands executable trust boundary"
  check_rust_pattern 'dlopen' "dynamic linker invocation in sensitive Rust paths" "dynamic linker invocation expands executable trust boundary"
  check_rust_pattern 'libc::' "libc boundary usage in sensitive Rust paths" "libc boundary often implies low-level unsafe or platform-specific behavior"
fi

if "$RG_BIN" -n '^source = "git\+' Cargo.lock >"$tmp_dir/git_source.txt"; then
  fail_with_matches \
    "git sources in Cargo.lock" \
    "git sources bypass crates.io registry-only posture and require explicit exception handling" \
    "$tmp_dir/git_source.txt"
fi

if "$RG_BIN" -n '^source = "' Cargo.lock >"$tmp_dir/all_sources.txt"; then
  grep -v 'source = "registry+https://github.com/rust-lang/crates.io-index"' "$tmp_dir/all_sources.txt" >"$tmp_dir/non_cratesio_sources.txt" || true
  if [[ -s "$tmp_dir/non_cratesio_sources.txt" ]]; then
    fail_with_matches \
      "non-crates.io lockfile sources" \
      "unknown source origins weaken dependency provenance guarantees" \
      "$tmp_dir/non_cratesio_sources.txt"
  fi
fi

if [[ "$status" -ne 0 ]]; then
  echo "[check_supply_chain_surface] one or more checks failed." >&2
  exit 1
fi

echo "[check_supply_chain_surface] all checks passed."
