#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LISTENER_DB="/tmp/nexo_a_demo.db"
SENDER_DB="/tmp/nexo_b_demo.db"
LISTENER_LOG="/tmp/nexo_p2p_listener.log"
LISTENER_PID=""
A_PORT=""
B_PORT=""

cleanup() {
  if [[ -n "${LISTENER_PID}" ]] && kill -0 "${LISTENER_PID}" 2>/dev/null; then
    kill "${LISTENER_PID}" 2>/dev/null || true
    wait "${LISTENER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

rm -f "${LISTENER_DB}" "${SENDER_DB}" "${LISTENER_LOG}"

cd "${ROOT_DIR}"

A_PORT="$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

B_PORT="$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

cargo run --features network --quiet --bin nexo_p2p -- \
  listen --bind "127.0.0.1:${A_PORT}" --db "${LISTENER_DB}" >"${LISTENER_LOG}" 2>&1 &
LISTENER_PID="$!"

sleep 1

if ! kill -0 "${LISTENER_PID}" 2>/dev/null; then
  cat "${LISTENER_LOG}" >&2
  echo "listener failed to start" >&2
  exit 1
fi

cargo run --features network --quiet --bin nexo_p2p -- \
  send --bind "127.0.0.1:${B_PORT}" --peer "127.0.0.1:${A_PORT}" --sender node_b --msg "hello" --db "${SENDER_DB}"

python3 - "${A_PORT}" <<'PY'
import sys
import socket
import sqlite3

a_port = int(sys.argv[1])
db = "/tmp/nexo_b_demo.db"
conn = sqlite3.connect(db)
row = conn.execute(
    "SELECT sender_id, timestamp_utc_ms, content_blob FROM messages ORDER BY rowid DESC LIMIT 1"
).fetchone()
if row is None:
    raise SystemExit("missing message row")
sender_id, ts, content = row
nonce_row = conn.execute(
    "SELECT last_nonce FROM sender_counters WHERE sender_id = ?",
    (sender_id,),
).fetchone()
if nonce_row is None:
    raise SystemExit("missing sender nonce row")
nonce = int(nonce_row[0])

sender = sender_id.encode("utf-8")
if len(sender) > 255 or len(content) > 255:
    raise SystemExit("sender/content too large for wire format")

packet = bytearray()
packet.append(1)  # PACKET_EVENT
packet.extend(int(ts).to_bytes(8, "little"))
packet.extend(nonce.to_bytes(8, "little"))
packet.append(len(sender))
packet.extend(sender)
packet.append(len(content))
packet.extend(content)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(packet, ("127.0.0.1", a_port))
sock.close()
PY

sleep 1

cleanup
LISTENER_PID=""

cat "${LISTENER_LOG}"

if ! grep -q "recv inserted" "${LISTENER_LOG}"; then
  echo "missing inserted marker in listener output" >&2
  exit 1
fi

if ! grep -q "recv duplicate" "${LISTENER_LOG}"; then
  echo "missing duplicate marker in listener output" >&2
  exit 1
fi

echo "INSERTED"
echo "DUPLICATE"
