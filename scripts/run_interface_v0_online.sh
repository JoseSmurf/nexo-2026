#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_BIND="${NEXO_HTTP_BIND:-127.0.0.1:3000}"
UI_BIND="${NEXO_UI_BIND:-0.0.0.0}"
UI_PORT="${NEXO_UI_PORT:-4567}"
LOG_DIR="${NEXO_V0_LOG_DIR:-$ROOT_DIR/tmp/interface_v0_online}"
DEFAULT_CORE_BIN="$ROOT_DIR/target/release/syntax-engine"
CORE_BIN="${NEXO_CORE_BIN:-$DEFAULT_CORE_BIN}"

core_port="${CORE_BIND##*:}"
DEFAULT_CORE_STATE_URL="http://127.0.0.1:${core_port}/api/state"
CORE_STATE_URL="${NEXO_CORE_STATE_URL:-$DEFAULT_CORE_STATE_URL}"

mkdir -p "$LOG_DIR"
CORE_LOG="$LOG_DIR/core.log"
UI_LOG="$LOG_DIR/ui.log"
: > "$CORE_LOG"
: > "$UI_LOG"

core_pid=""
ui_pid=""

cleanup() {
  local exit_code=$?

  if [[ -n "$ui_pid" ]] && kill -0 "$ui_pid" 2>/dev/null; then
    kill "$ui_pid" 2>/dev/null || true
  fi

  if [[ -n "$core_pid" ]] && kill -0 "$core_pid" 2>/dev/null; then
    kill "$core_pid" 2>/dev/null || true
  fi

  wait "$ui_pid" 2>/dev/null || true
  wait "$core_pid" 2>/dev/null || true

  exit "$exit_code"
}

trap cleanup EXIT INT TERM

if [[ -z "${NEXO_HMAC_SECRET:-}" && -z "${NEXO_HMAC_SECRET_FILE:-}" ]]; then
  echo "NEXO_HMAC_SECRET or NEXO_HMAC_SECRET_FILE is required for Interface V0 online boot." >&2
  exit 1
fi

needs_build=0

if [[ "$CORE_BIN" == "$DEFAULT_CORE_BIN" ]]; then
  if [[ ! -x "$CORE_BIN" ]]; then
    needs_build=1
  elif find "$ROOT_DIR/src" -type f -newer "$CORE_BIN" -print -quit | grep -q .; then
    needs_build=1
  elif [[ "$ROOT_DIR/Cargo.toml" -nt "$CORE_BIN" || "$ROOT_DIR/Cargo.lock" -nt "$CORE_BIN" ]]; then
    needs_build=1
  fi
elif [[ ! -x "$CORE_BIN" ]]; then
  echo "Configured NEXO_CORE_BIN is not executable: ${CORE_BIN}" >&2
  exit 1
fi

if [[ "$needs_build" -eq 1 ]]; then
  echo "Building syntax-engine release binary..."
  (
    cd "$ROOT_DIR"
    cargo build --release --bin syntax-engine
  )
fi

wait_for_core() {
  local url="$1"
  local attempts=30

  while (( attempts > 0 )); do
    if curl --silent --show-error --fail --max-time 1 "$url" >/dev/null 2>&1; then
      return 0
    fi

    sleep 1
    attempts=$((attempts - 1))
  done

  return 1
}

echo "Starting NEXO core on ${CORE_BIND}"
(
  cd "$ROOT_DIR"
  NEXO_HTTP_BIND="$CORE_BIND" "$CORE_BIN" >>"$CORE_LOG" 2>&1
) &
core_pid=$!

if ! wait_for_core "$CORE_STATE_URL"; then
  echo "Core did not become ready at ${CORE_STATE_URL}" >&2
  echo "See log: ${CORE_LOG}" >&2
  exit 1
fi

echo "Starting NEXO Interface V0 UI on ${UI_BIND}:${UI_PORT}"
(
  cd "$ROOT_DIR"
  NEXO_UI_BIND="$UI_BIND" \
  NEXO_UI_PORT="$UI_PORT" \
  NEXO_CORE_STATE_URL="$CORE_STATE_URL" \
  ruby nexo_ui/app.rb >>"$UI_LOG" 2>&1
) &
ui_pid=$!

echo "NEXO Interface V0 online boot active"
echo "  core state url: ${CORE_STATE_URL}"
echo "  ui url: http://${UI_BIND}:${UI_PORT}"
echo "  core log: ${CORE_LOG}"
echo "  ui log: ${UI_LOG}"

wait -n "$core_pid" "$ui_pid"
