# NEXO Interface V0 Controlled-Host Acceptance Runbook

## 1. Purpose

This runbook defines the smallest controlled-host acceptance flow for the current Interface V0.

It is limited to the already-confirmed central path on `main`:

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification`

The goal is not new functionality. The goal is to prove that the current center can be started and exercised repeatably on one controlled host without private guidance.

## 2. Scope and non-scope

### In scope

- one controlled host
- one running Rust core
- one running Ruby Interface V0
- one valid signed acceptance request
- one persisted audit artifact
- one offline Zig verification result

### Out of scope

- mesh / P2P
- Witness Layer
- Julia flows
- Bitcoin experiment implementation
- Docker
- Kubernetes
- public exposure
- scaling
- HA / failover
- dashboard expansion
- any new runtime semantics

## 3. Preconditions

The controlled host must have:

- a checkout of this repository at a known commit
- `cargo`
- `ruby`
- `zig`
- `curl`

Useful but optional:

- `jq` for structured artifact inspection output

The operator should run this from the repository root.

## 4. Required environment variables

The current direct-host boot path requires these variables to be set before starting the system:

```bash
export NEXO_HMAC_SECRET='dev-secret-active'
export NEXO_HMAC_KEY_ID='active'
export NEXO_PROFILE='br_default_v1'
```

For a controlled local acceptance run, set explicit bind values. This runbook also sets `NEXO_AUDIT_PATH` explicitly as a repeatability convention so the artifact path is predictable during acceptance. That convention is not a universal product requirement.

```bash
export NEXO_HTTP_BIND='127.0.0.1:3000'
export NEXO_UI_BIND='127.0.0.1'
export NEXO_UI_PORT='4567'
export NEXO_AUDIT_PATH="$PWD/logs/audit_records.jsonl"
```

Optional:

```bash
export NEXO_CORE_BIN="$PWD/target/release/syntax-engine"
```

Use `NEXO_CORE_BIN` only when an explicit binary path is desired. If it is not set, `scripts/run_interface_v0_online.sh` uses the default release binary path and builds it when needed.

## 5. Controlled-host boot steps

From the repository root:

```bash
mkdir -p logs
bash scripts/run_interface_v0_online.sh
```

Expected behavior:

- the script starts the Rust core first
- it waits for the core readiness path
- it starts the Ruby Interface V0 after the core is ready
- it prints:
  - core state URL
  - UI URL
  - core log path
  - UI log path

The process remains attached to the terminal. Keep it running while performing the acceptance checks below.

## 6. Core readiness check

In a second terminal, verify that the core is reachable:

```bash
curl -fsS http://127.0.0.1:3000/api/state
```

Minimum acceptance condition:

- the request returns HTTP 200
- the response is valid JSON

This confirms that the core is reachable on the configured bind and that the Interface V0 can read its state source.

## 7. UI readiness check

Open the UI URL printed by the boot script. For the default controlled-host values above, that is:

```text
http://127.0.0.1:4567
```

Minimum acceptance condition:

- the page loads successfully
- the primary decision surface is manually visible and legible
- the page preserves the intended hierarchy: primary decision center first, secondary/context information visibly subordinate

This is a manual/visual readiness check. It confirms that the operator-facing surface is usable; it is not a backend proof and does not replace `/api/state`, audit inspection, or Zig verification.

At minimum, confirm that the page exposes the decision center, audit/trace context, offline verification guidance, and secondary/context area without making secondary signals compete with the primary decision.

## 8. Single acceptance request flow

In a second terminal, send one valid signed request through the current central path:

```bash
REQ_ID="$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)"
TS="$(date +%s%3N)"
BODY="$(printf '{"user_id":"controlled_host_acceptance_user","amount_cents":50000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":%s,"risk_bps":1200,"ui_hash_valid":true,"request_id":"%s"}' "$TS" "$REQ_ID")"
SIG="$(cargo run --quiet --bin sign_request -- "$NEXO_HMAC_SECRET" "$NEXO_HMAC_KEY_ID" "$REQ_ID" "$TS" "$BODY")"
curl -fsS -X POST 'http://127.0.0.1:3000/evaluate' \
  -H 'content-type: application/json' \
  -H "x-signature: $SIG" \
  -H "x-request-id: $REQ_ID" \
  -H "x-timestamp: $TS" \
  -H "x-key-id: $NEXO_HMAC_KEY_ID" \
  --data "$BODY"
```

Minimum acceptance condition:

- the request returns HTTP 200
- the response contains:
  - `final_decision`
  - `trace`
  - `audit_hash`
  - `hash_algo`

This is the acceptance request for the controlled-host runbook. No additional request scenarios are required here.

## 9. Audit artifact inspection

Inspect the persisted artifact from the running host:

```bash
bash scripts/inspect_audit_artifact.sh "$NEXO_AUDIT_PATH"
```

Minimum acceptance condition:

- the audit file exists
- at least one persisted artifact is found
- the helper prints the main fields
- the helper writes a single-artifact `.jsonl` and prints the exact Zig verification command

If a specific `request_id` must be recovered explicitly, use:

```bash
bash scripts/find_audit_artifact.sh "$REQ_ID" "$NEXO_AUDIT_PATH"
```

## 10. Offline Zig verification

Use the exact verification command printed by `scripts/inspect_audit_artifact.sh`.

The shape is:

```bash
cd tools/zig
zig build run -- verify /path/to/prepared-single-artifact.jsonl
```

Minimum acceptance condition:

```text
verify: total=1 ok=1 schema_invalid=false tampering=false
```

This is the final proof point of the runbook.

## 11. Required proof points to record

Record all of the following:

- repository commit SHA used for the run
- host label or hostname
- `request_id` used for the acceptance request
- exact values used for:
  - `NEXO_HTTP_BIND`
  - `NEXO_UI_BIND`
  - `NEXO_UI_PORT`
  - `NEXO_AUDIT_PATH`
- the successful `/api/state` response capture
- the UI URL used
- the `/evaluate` response containing:
  - `final_decision`
  - `trace`
  - `audit_hash`
  - `hash_algo`
- the persisted audit file path
- the output of `scripts/inspect_audit_artifact.sh`
- the Zig verification result

These proof points are sufficient to declare that the controlled-host acceptance path succeeded.

## 12. Success criteria

The runbook is successful only if all of the following are true:

1. the direct-host boot script starts the core and the UI on the same host
2. `/api/state` responds successfully
3. the Interface V0 loads and keeps the primary center visible
4. one valid signed `/evaluate` request succeeds
5. an audit artifact is persisted
6. the artifact can be inspected with the existing helper
7. the artifact verifies offline with Zig

If any of these fail, the acceptance run is incomplete.

## 13. Failure handling / stop conditions

Stop the run and record the failure if any of the following occurs:

- `scripts/run_interface_v0_online.sh` exits before both processes are up
- the core never becomes ready on `/api/state`
- the UI does not load on the configured bind/port
- the acceptance request fails or returns an invalid response shape
- no audit artifact is written
- `scripts/inspect_audit_artifact.sh` cannot read the expected audit file
- the Zig verifier reports:
  - `schema_invalid=true`
  - `tampering=true`
  - or any non-success result

When stopping, record:

- the failing step
- the relevant command
- the core log path printed by the boot script
- the UI log path printed by the boot script

Do not extend the run during failure handling into unrelated debugging, deployment redesign, or new product work. This runbook is only for controlled-host acceptance of the current center.
