#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_URL="http://127.0.0.1:19100"
RELAY_DB="/tmp/nexo_relay_hybrid_demo.db"
DB_A="/tmp/nexo_hybrid_a.db"
DB_B="/tmp/nexo_hybrid_b.db"
LOG_RELAY="/tmp/nexo_hybrid_relay.log"
LOG_A="/tmp/nexo_hybrid_a.log"
LOG_B="/tmp/nexo_hybrid_b.log"
LOG_SEND="/tmp/nexo_hybrid_send.log"

cleanup() {
  if [[ -n "${PID_A:-}" ]]; then kill "$PID_A" >/dev/null 2>&1 || true; fi
  if [[ -n "${PID_B:-}" ]]; then kill "$PID_B" >/dev/null 2>&1 || true; fi
  if [[ -n "${PID_RELAY:-}" ]]; then kill "$PID_RELAY" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

rm -f "$RELAY_DB" "$DB_A" "$DB_B" "$LOG_RELAY" "$LOG_A" "$LOG_B" "$LOG_SEND"

cd "$ROOT_DIR"

cargo run --features network --bin nexo_relay -- --bind 127.0.0.1:19100 --db "$RELAY_DB" \
  >"$LOG_RELAY" 2>&1 &
PID_RELAY=$!
sleep 1

cargo run --features network --bin nexo_p2p -- chat \
  --bind 127.0.0.1:19001 \
  --relay "$RELAY_URL" \
  --relay-push-interval-ms 200 \
  --relay-pull-interval-ms 200 \
  --sender node_a \
  --db "$DB_A" \
  --daemon \
  >"$LOG_A" 2>&1 &
PID_A=$!

cargo run --features network --bin nexo_p2p -- chat \
  --bind 127.0.0.1:19002 \
  --relay "$RELAY_URL" \
  --relay-push-interval-ms 200 \
  --relay-pull-interval-ms 200 \
  --sender node_b \
  --db "$DB_B" \
  --daemon \
  >"$LOG_B" 2>&1 &
PID_B=$!

sleep 1

printf 'hello\n/quit\n' | cargo run --features network --bin nexo_p2p -- chat \
  --bind 127.0.0.1:19011 \
  --relay "$RELAY_URL" \
  --relay-push-interval-ms 200 \
  --relay-pull-interval-ms 200 \
  --sender node_a \
  --db "$DB_A" \
  >"$LOG_SEND" 2>&1

ok=false
for _ in $(seq 1 40); do
  if grep -Eq 'relay_pull count=[1-9]' "$LOG_B"; then
    ok=true
    break
  fi
  sleep 0.25
done

if [[ "$ok" != "true" ]]; then
  echo "demo_hybrid failed: node_b did not pull any event from relay"
  echo "--- relay log ---"
  tail -n 30 "$LOG_RELAY" || true
  echo "--- node_a log ---"
  tail -n 30 "$LOG_A" || true
  echo "--- node_b log ---"
  tail -n 30 "$LOG_B" || true
  echo "--- sender log ---"
  tail -n 30 "$LOG_SEND" || true
  exit 1
fi

echo "demo_hybrid ok"
echo "logs:"
echo "  relay  $LOG_RELAY"
echo "  node_a $LOG_A"
echo "  node_b $LOG_B"
echo "  send   $LOG_SEND"
