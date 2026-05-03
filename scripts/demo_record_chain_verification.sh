#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# This demo proves the offline Zig "--require-chain" verifier behavior.
# It generates a fixture-driven 2-line JSONL artifact in mktemp.
# It is not an end-to-end Rust AuditStore generation demo.

require_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "Missing required command: ${name}" >&2
    exit 1
  fi
}

require_cmd python3

ZIG_0110="${HOME}/tools/zig/zig-linux-x86_64-0.11.0/zig"
if [[ -x "${ZIG_0110}" ]]; then
  ZIG="${ZIG_0110}"
else
  require_cmd zig
  ZIG="$(command -v zig)"
fi

WORK_DIR="$(mktemp -d /tmp/nexo-demo-record-chain-XXXXXX)"

ZIG_PREFIX="${WORK_DIR}/zig-prefix"
ZIG_CACHE_DIR="${WORK_DIR}/zig-cache"
ZIG_GLOBAL_CACHE_DIR="${WORK_DIR}/zig-global-cache"

ARTIFACT_VALID="${WORK_DIR}/audit_chain_valid.jsonl"
ARTIFACT_WRONG_PREV="${WORK_DIR}/audit_chain_wrong_prev.jsonl"
ARTIFACT_TAMPER_FIELD="${WORK_DIR}/audit_chain_tampered_amount.jsonl"

HASH_HELPER_SRC="${WORK_DIR}/record_hash_v2.zig"
HASH_HELPER_BIN="${WORK_DIR}/record_hash_v2"

echo "Working directory: ${WORK_DIR}"
echo
echo "Building nexo-audit (Zig verifier) without leaving cache in the repo..."
(cd tools/zig && "${ZIG}" build -p "${ZIG_PREFIX}" --cache-dir "${ZIG_CACHE_DIR}" --global-cache-dir "${ZIG_GLOBAL_CACHE_DIR}" --summary all)
ZIG_AUDIT_BIN="${ZIG_PREFIX}/bin/nexo-audit"
if [[ ! -x "${ZIG_AUDIT_BIN}" ]]; then
  echo "Expected nexo-audit binary not found/executable: ${ZIG_AUDIT_BIN}" >&2
  exit 1
fi

cat >"${HASH_HELPER_SRC}" <<'ZIG'
const std = @import("std");
const schema = @import("schema");
const crypto = @import("crypto");

fn toHexLower(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, bytes.len * 2);
    errdefer alloc.free(out);
    _ = std.fmt.bufPrint(out, "{s}", .{std.fmt.fmtSliceHexLower(bytes)}) catch return error.FormatFailed;
    return out;
}

fn stringifyJsonMinifiedAlloc(alloc: std.mem.Allocator, v: std.json.Value) ![]const u8 {
    return std.json.stringifyAlloc(alloc, v, .{ .whitespace = .minified });
}

// Mirrors Rust `src/audit/record.rs::compute_record_hash` framing (schema: audit_record_v2).
fn computeRecordHashV2Hex(alloc: std.mem.Allocator, root_obj: std.json.ObjectMap) ![]u8 {
    var hasher = crypto.Hasher.init(.blake3);

    const request_id = schema.getString(root_obj, "request_id") orelse return error.SchemaInvalid;
    const profile_name = schema.getString(root_obj, "profile_name") orelse return error.SchemaInvalid;
    const profile_version = schema.getString(root_obj, "profile_version") orelse return error.SchemaInvalid;
    const calc_version = schema.getStringOrEmpty(root_obj, "calc_version") orelse return error.SchemaInvalid;
    const user_id = schema.getString(root_obj, "user_id") orelse return error.SchemaInvalid;
    const audit_hash_str = schema.getString(root_obj, "audit_hash") orelse return error.SchemaInvalid;
    const hash_algo_str = schema.getString(root_obj, "hash_algo") orelse return error.SchemaInvalid;
    const sha3_shadow = schema.getStringOrEmpty(root_obj, "sha3_shadow") orelse return error.SchemaInvalid;
    const final_decision = schema.getString(root_obj, "final_decision") orelse return error.SchemaInvalid;
    const prev_record_hash = schema.getStringOrEmpty(root_obj, "prev_record_hash") orelse return error.SchemaInvalid;

    const timestamp_utc_ms = schema.getU64(root_obj, "timestamp_utc_ms") orelse return error.SchemaInvalid;
    const amount_cents = schema.getU64(root_obj, "amount_cents") orelse return error.SchemaInvalid;
    const risk_bps_u64 = schema.getU64(root_obj, "risk_bps") orelse return error.SchemaInvalid;
    const risk_bps = std.math.cast(u16, risk_bps_u64) orelse return error.SchemaInvalid;

    const trace_val = root_obj.get("trace") orelse return error.SchemaInvalid;
    var trace_json_alloc: ?[]const u8 = null;
    const trace_json: []const u8 = blk: {
        const s = stringifyJsonMinifiedAlloc(alloc, trace_val) catch break :blk "[]";
        trace_json_alloc = s;
        break :blk s;
    };
    defer if (trace_json_alloc) |s| alloc.free(s);

    crypto.hashField(&hasher, "schema", "audit_record_v2");
    crypto.hashField(&hasher, "request_id", request_id);
    crypto.hashField(&hasher, "profile_name", profile_name);
    crypto.hashField(&hasher, "profile_version", profile_version);
    crypto.hashField(&hasher, "calc_version", calc_version);
    crypto.hashField(&hasher, "user_id", user_id);
    crypto.hashField(&hasher, "audit_hash", audit_hash_str);
    crypto.hashField(&hasher, "hash_algo", hash_algo_str);
    crypto.hashField(&hasher, "sha3_shadow", sha3_shadow);
    crypto.hashField(&hasher, "final_decision", final_decision);
    crypto.hashField(&hasher, "trace_json", trace_json);
    crypto.hashField(&hasher, "prev_record_hash", prev_record_hash);
    crypto.pushU64Le(&hasher, timestamp_utc_ms);
    crypto.pushU64Le(&hasher, amount_cents);
    crypto.pushU16Le(&hasher, risk_bps);

    const out_bytes = try hasher.finalAlloc(alloc);
    defer alloc.free(out_bytes);
    return try toHexLower(alloc, out_bytes);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const argv = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, argv);
    if (argv.len != 2) {
        std.debug.print("usage: {s} <path/to/record.json>\n", .{argv[0]});
        std.process.exit(2);
    }

    const raw = try std.fs.cwd().readFileAlloc(alloc, argv[1], 1024 * 1024);
    defer alloc.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");

    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, trimmed, .{});
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.SchemaInvalid,
    };

    const hex = try computeRecordHashV2Hex(alloc, obj);
    defer alloc.free(hex);

    try std.io.getStdOut().writer().print("{s}\n", .{hex});
}
ZIG

echo
echo "Building record_hash helper (audit_record_v2 framing) in temp..."
"${ZIG}" build-exe -O ReleaseSafe \
  --cache-dir "${ZIG_CACHE_DIR}" --global-cache-dir "${ZIG_GLOBAL_CACHE_DIR}" \
  --mod schema::tools/zig/src/schema.zig \
  --mod crypto::tools/zig/src/crypto.zig \
  --deps schema,crypto \
  -femit-bin="${HASH_HELPER_BIN}" \
  "${HASH_HELPER_SRC}"

if [[ ! -x "${HASH_HELPER_BIN}" ]]; then
  echo "Expected record_hash helper binary not found/executable: ${HASH_HELPER_BIN}" >&2
  exit 1
fi

echo
echo "Generating a 2-line chained artifact in mktemp..."
python3 - "${HASH_HELPER_BIN}" "${ARTIFACT_VALID}" "${ARTIFACT_WRONG_PREV}" "${ARTIFACT_TAMPER_FIELD}" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

hash_helper = Path(sys.argv[1])
out_valid = Path(sys.argv[2])
out_wrong_prev = Path(sys.argv[3])
out_tamper_field = Path(sys.argv[4])

record_fixture = (
    '{"request_id":"known-request-001","calc_version":"fixture_rust_v1","profile_name":"br_default_v1",'
    '"profile_version":"2026.02","timestamp_utc_ms":1771845406862,"user_id":"rust_fixture_user",'
    '"amount_cents":150000,"risk_bps":9999,"final_decision":"Flagged","trace":["Approved","Approved",'
    '{"FlaggedForReview":{"measured":150000,"reason":"Transaction requires AML review.","rule_id":"AML-FATF-REVIEW-001",'
    '"severity":"Alta","threshold":5000000}}],"audit_hash":"bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3",'
    '"hash_algo":"blake3","sha3_shadow":null,"prev_record_hash":null,"record_hash":null}'
)

def minijson(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

def compute_record_hash(obj) -> str:
    tmp = Path(out_valid.parent) / "tmp_record.json"
    tmp.write_text(minijson(obj) + "\n", encoding="utf-8")
    res = subprocess.run([str(hash_helper), str(tmp)], capture_output=True, text=True)
    if res.returncode != 0:
        raise SystemExit(f"record_hash helper failed: code={res.returncode} stderr={res.stderr.strip()}")
    return res.stdout.strip()

base = json.loads(record_fixture)

# Line 1: record_hash computed, prev_record_hash remains null.
line1 = dict(base)
line1_hash = compute_record_hash(line1)
line1["record_hash"] = line1_hash

# Line 2: chained to line1 via prev_record_hash, and has its own record_hash.
line2 = dict(base)
line2["request_id"] = "known-request-002"
line2["prev_record_hash"] = line1_hash
line2_hash = compute_record_hash(line2)
line2["record_hash"] = line2_hash

out_valid.write_text(minijson(line1) + "\n" + minijson(line2) + "\n", encoding="utf-8")

# Tamper case A: wrong prev_record_hash on second line, but record_hash recomputed for that record.
wrong_prev = dict(line2)
wrong_prev["prev_record_hash"] = "a" * 64
wrong_prev["record_hash"] = compute_record_hash(wrong_prev)
out_wrong_prev.write_text(minijson(line1) + "\n" + minijson(wrong_prev) + "\n", encoding="utf-8")

# Tamper case B: change a non-trace field (amount_cents) but keep old record_hash.
tampered_field = dict(line2)
tampered_field["amount_cents"] = int(tampered_field["amount_cents"]) + 1
out_tamper_field.write_text(minijson(line1) + "\n" + minijson(tampered_field) + "\n", encoding="utf-8")

print("artifact_valid:", out_valid)
print("artifact_wrong_prev:", out_wrong_prev)
print("artifact_tampered_field:", out_tamper_field)
print("line1_record_hash:", line1_hash)
print("line2_record_hash:", line2_hash)
PY

echo
echo "Verify (valid, expected ok):"
set +e
VALID_OUT="$("${ZIG_AUDIT_BIN}" verify --require-chain "${ARTIFACT_VALID}" 2>&1)"
VALID_CODE=$?
set -e
echo "${VALID_OUT}"
if [[ "${VALID_CODE}" -ne 0 ]]; then
  echo "Expected valid chained artifact to verify cleanly, but got exit code ${VALID_CODE}." >&2
  exit 1
fi

echo
echo "Verify (wrong prev_record_hash on 2nd line, expected tampering):"
set +e
WRONG_PREV_OUT="$("${ZIG_AUDIT_BIN}" verify --require-chain "${ARTIFACT_WRONG_PREV}" 2>&1)"
WRONG_PREV_CODE=$?
set -e
echo "${WRONG_PREV_OUT}"
if [[ "${WRONG_PREV_CODE}" -ne 3 ]]; then
  echo "Expected wrong-prev artifact to be rejected as tampering (exit code 3), but got ${WRONG_PREV_CODE}." >&2
  exit 1
fi
if ! grep -qE 'tampering=true|line [0-9]+: tampering' <<<"${WRONG_PREV_OUT}"; then
  echo "Expected tampering evidence in output for wrong-prev case, but did not find it." >&2
  exit 1
fi

echo
echo "Verify (non-trace field changed w/ old record_hash, expected tampering):"
set +e
TAMPER_FIELD_OUT="$("${ZIG_AUDIT_BIN}" verify --require-chain "${ARTIFACT_TAMPER_FIELD}" 2>&1)"
TAMPER_FIELD_CODE=$?
set -e
echo "${TAMPER_FIELD_OUT}"
if [[ "${TAMPER_FIELD_CODE}" -ne 3 ]]; then
  echo "Expected tampered-field artifact to be rejected as tampering (exit code 3), but got ${TAMPER_FIELD_CODE}." >&2
  exit 1
fi
if ! grep -qE 'tampering=true|line [0-9]+: tampering' <<<"${TAMPER_FIELD_OUT}"; then
  echo "Expected tampering evidence in output for tampered-field case, but did not find it." >&2
  exit 1
fi

echo
echo "Record chain demo summary:"
echo "artifact_valid: ${ARTIFACT_VALID}"
echo "artifact_wrong_prev: ${ARTIFACT_WRONG_PREV}"
echo "artifact_tampered_field: ${ARTIFACT_TAMPER_FIELD}"
echo "zig_bin: ${ZIG}"
echo "nexo_audit: ${ZIG_AUDIT_BIN}"
echo "valid_exit: ${VALID_CODE} (expected 0)"
echo "wrong_prev_exit: ${WRONG_PREV_CODE} (expected 3)"
echo "tampered_field_exit: ${TAMPER_FIELD_CODE} (expected 3)"
echo "conclusion: ok (--require-chain detects continuity breaks and record hash tampering)"
