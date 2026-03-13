#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUERY="${1:-}"
SOURCE_INPUT="${2:-}"
INSPECT_DIR="${ROOT_DIR}/logs"
DEFAULT_ACTIVE_INPUT="${NEXO_AUDIT_PATH:-logs/audit_records.jsonl}"
DEFAULT_ARCHIVE_DIR="${ROOT_DIR}/logs/audit_archive"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/find_audit_artifact.sh <request_id|audit_hash|record_hash> [audit-file-or-dir]

Behavior:
  - without a second argument, searches:
      1. NEXO_AUDIT_PATH or logs/audit_records.jsonl
      2. logs/audit_archive/ if it exists
  - with a file path, searches only that file
  - with a directory path, searches *.jsonl files under that directory

This helper writes a single-artifact .jsonl only when exactly one match is found.
EOF
}

resolve_path() {
  local input="$1"
  if [[ "${input}" = /* ]]; then
    printf '%s\n' "${input}"
  else
    printf '%s\n' "${ROOT_DIR}/${input}"
  fi
}

append_target() {
  local candidate="$1"
  if [[ -f "${candidate}" ]]; then
    TARGETS+=("${candidate}")
  fi
}

collect_dir_targets() {
  local dir="$1"
  if [[ -d "${dir}" ]]; then
    while IFS= read -r file; do
      TARGETS+=("${file}")
    done < <(find "${dir}" -type f -name '*.jsonl' | sort)
  fi
}

if [[ -z "${QUERY}" ]]; then
  usage >&2
  exit 1
fi

if ! command -v ruby >/dev/null 2>&1; then
  echo "ruby is required for audit artifact lookup." >&2
  exit 1
fi

declare -a TARGETS=()

if [[ -n "${SOURCE_INPUT}" ]]; then
  RESOLVED_SOURCE="$(resolve_path "${SOURCE_INPUT}")"
  if [[ -f "${RESOLVED_SOURCE}" ]]; then
    append_target "${RESOLVED_SOURCE}"
  elif [[ -d "${RESOLVED_SOURCE}" ]]; then
    collect_dir_targets "${RESOLVED_SOURCE}"
  else
    echo "Audit source not found: ${RESOLVED_SOURCE}" >&2
    exit 1
  fi
else
  append_target "$(resolve_path "${DEFAULT_ACTIVE_INPUT}")"
  collect_dir_targets "${DEFAULT_ARCHIVE_DIR}"
fi

if [[ "${#TARGETS[@]}" -eq 0 ]]; then
  echo "No audit files found for lookup." >&2
  exit 1
fi

MATCHES_FILE="$(mktemp)"
cleanup() {
  rm -f "${MATCHES_FILE}"
}
trap cleanup EXIT

for file in "${TARGETS[@]}"; do
  ruby -rjson -e '
    query = ARGV[0]
    path = ARGV[1]
    File.foreach(path) do |line|
      line = line.strip
      next if line.empty?
      begin
        obj = JSON.parse(line)
      rescue JSON::ParserError
        next
      end
      next unless [obj["request_id"], obj["audit_hash"], obj["record_hash"]].include?(query)
      puts JSON.generate(obj)
    end
  ' "${QUERY}" "${file}" | while IFS= read -r line; do
      printf '%s\t%s\n' "${file}" "${line}" >> "${MATCHES_FILE}"
    done
done

MATCH_COUNT="$(awk 'END { print NR + 0 }' "${MATCHES_FILE}")"

if [[ "${MATCH_COUNT}" -eq 0 ]]; then
  echo "No matching audit artifact found for query: ${QUERY}" >&2
  echo "Searched files:" >&2
  for file in "${TARGETS[@]}"; do
    echo "- ${file}" >&2
  done
  exit 1
fi

echo "Lookup query: ${QUERY}"
echo "Matched artifacts: ${MATCH_COUNT}"
echo

if [[ "${MATCH_COUNT}" -gt 1 ]]; then
  echo "Matches:"
  while IFS=$'\t' read -r source_file json_line; do
    metadata="$(
      printf '%s\n' "${json_line}" | ruby -rjson -e '
        obj = JSON.parse(STDIN.read)
        fields = [
          obj["request_id"],
          obj["final_decision"],
          obj["timestamp_utc_ms"],
          obj["audit_hash"],
          obj["record_hash"] || ""
        ]
        puts fields.map { |value| value.to_s }.join("\t")
      '
    )"
    IFS=$'\t' read -r request_id final_decision timestamp audit_hash record_hash <<< "${metadata}"
    echo "- source=${source_file}"
    echo "  request_id=${request_id}"
    echo "  final_decision=${final_decision}"
    echo "  timestamp_utc_ms=${timestamp}"
    echo "  audit_hash=${audit_hash}"
    echo "  record_hash=${record_hash}"
  done < "${MATCHES_FILE}"
  echo
  echo "Refine the query or pass a specific audit file/directory as the second argument."
  exit 0
fi

mkdir -p "${INSPECT_DIR}"
FOUND_ARTIFACT="$(mktemp "${INSPECT_DIR}/found-audit-artifact-XXXXXX.jsonl")"
IFS=$'\t' read -r SOURCE_FILE JSON_LINE < "${MATCHES_FILE}"
printf '%s\n' "${JSON_LINE}" > "${FOUND_ARTIFACT}"

echo "Matched source: ${SOURCE_FILE}"
echo "Prepared artifact: ${FOUND_ARTIFACT}"
echo
echo "Main fields:"
ruby -rjson -e '
  obj = JSON.parse(File.read(ARGV[0]))
  selected = {
    request_id: obj["request_id"],
    final_decision: obj["final_decision"],
    hash_algo: obj["hash_algo"],
    audit_hash: obj["audit_hash"],
    timestamp_utc_ms: obj["timestamp_utc_ms"],
    profile_name: obj["profile_name"],
    profile_version: obj["profile_version"],
    user_id: obj["user_id"],
    amount_cents: obj["amount_cents"],
    risk_bps: obj["risk_bps"],
    prev_record_hash: obj["prev_record_hash"],
    record_hash: obj["record_hash"],
    trace: obj["trace"]
  }
  puts JSON.pretty_generate(selected)
' "${FOUND_ARTIFACT}"
echo
echo "To verify this artifact with Zig:"
echo "cd ${ROOT_DIR}/tools/zig && zig build run -- verify ${FOUND_ARTIFACT}"
