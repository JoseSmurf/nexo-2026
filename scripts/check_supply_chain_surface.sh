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
  local out_file="$tmp_dir/pattern.txt"
  if rg -n --glob '*.rs' "$pattern" "${scan_dirs[@]}" >"$out_file"; then
    fail_with_matches "$label" "$why" "$out_file"
  fi
}

if [[ "${#scan_dirs[@]}" -gt 0 ]]; then
  check_rust_pattern '\bunsafe\b' "unsafe usage in sensitive Rust paths" "unsafe in trust-adjacent paths requires explicit approval and narrow justification"
  check_rust_pattern 'extern "C"' "FFI boundary in sensitive Rust paths" "FFI expands memory-safety and ABI trust assumptions"
  check_rust_pattern 'std::process::Command' "runtime process execution in sensitive Rust paths" "process spawning can expand command-injection and runtime trust surface"
  check_rust_pattern 'Command::new\(' "runtime process execution constructor in sensitive Rust paths" "process spawning can expand command-injection and runtime trust surface"
  check_rust_pattern 'std::ptr' "raw pointer API usage in sensitive Rust paths" "raw pointer usage can bypass safety guarantees"
  check_rust_pattern 'std::mem::transmute' "transmute usage in sensitive Rust paths" "transmute can silently violate type and memory invariants"
  check_rust_pattern 'MaybeUninit' "MaybeUninit usage in sensitive Rust paths" "manual initialization paths need explicit memory-safety review"
  check_rust_pattern 'libloading' "dynamic library loading in sensitive Rust paths" "runtime dynamic loading expands executable trust boundary"
  check_rust_pattern 'dlopen' "dynamic linker invocation in sensitive Rust paths" "dynamic linker invocation expands executable trust boundary"
  check_rust_pattern 'libc::' "libc boundary usage in sensitive Rust paths" "libc boundary often implies low-level unsafe or platform-specific behavior"
fi

if rg -n '^source = "git\+' Cargo.lock >"$tmp_dir/git_source.txt"; then
  fail_with_matches \
    "git sources in Cargo.lock" \
    "git sources bypass crates.io registry-only posture and require explicit exception handling" \
    "$tmp_dir/git_source.txt"
fi

if rg -n '^source = "' Cargo.lock >"$tmp_dir/all_sources.txt"; then
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
