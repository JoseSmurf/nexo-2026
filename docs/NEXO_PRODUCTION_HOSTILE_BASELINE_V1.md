# NEXO Production Hostile Baseline v1

## Status and Scope

This document records the current minimum hostile-production posture for NEXO Core.
It documents current repository behavior and operator requirements; it does not change runtime behavior.

Production Hostile Baseline v1 applies to the current center path only.
It does not promote Ruby, Julia, Mesh/P2P, Witness, Bitcoin, relay, or future IA surfaces into the trust core.

Related documents:

- [Audit Contract Baseline v1](NEXO_AUDIT_CONTRACT_BASELINE_V1.md)
- [Policy/Profile Provenance Contract v1](NEXO_POLICY_PROFILE_PROVENANCE_CONTRACT_V1.md)
- [Security Operations](SECURITY_OPERATIONS.md)
- [Operational Flow](OPERATIONAL_FLOW.md)
- [Threat Model](NEXO_THREAT_MODEL.md)
- [Test Matrix](NEXO_TEST_MATRIX.md)

## What "Production Hostile Baseline v1" Means

Production Hostile Baseline v1 does not mean universal production readiness.
It means the current NEXO Core can be configured, operated, validated, and audited under a stricter hostile baseline with known limits.

The baseline is intentionally narrow:

- signed decision requests are fail-closed
- replay state can be made persistent-required
- existing audit artifacts can be checked before startup
- audit records are chained and verifiable offline
- non-authoritative endpoints remain outside the evidence path
- operational recovery preserves evidence before mutation

## Center Path

The current product center is:

```text
signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> record chain -> offline Zig verification
```

## Trust Boundaries

- Rust decides and writes the primary audit artifact.
- Zig verifies persisted artifacts offline.
- Ruby presents.
- Julia observes.
- Mesh/P2P/Witness/Bitcoin are live edges, not authority.
- Future IA may observe or analyze, but must not decide.

## Required Hostile Configuration

Hostile deployments should set or intentionally confirm:

| Variable | Required posture |
| --- | --- |
| `NEXO_HMAC_SECRET` or `NEXO_HMAC_SECRET_FILE` | Required signing secret. Prefer file or managed secret provider over inline environment values. |
| `NEXO_HMAC_KEY_ID` | Required active key identifier; must be non-empty and match client signing. |
| `NEXO_AUDIT_PATH` | Explicit protected audit JSONL path. Exactly one writer process per path. |
| `NEXO_PROFILE` | Set to a known built-in profile, or intentionally leave unset to use `br_default_v1`. Explicit unknown values fail closed. |
| `NEXO_REQUIRE_PERSISTENT_REPLAY` | Set to `true` for hostile deployments. |
| `NEXO_REDIS_URL` | Required when persistent replay is required. Redis becomes the replay/rate-limit coordination backend. |
| `NEXO_REQUIRE_AUDIT_PREFLIGHT` | Set to `true` so startup fails closed on existing audit artifact, lock, temp, record-hash, or chain-continuity incidents. |

If `NEXO_REQUIRE_PERSISTENT_REPLAY=true` and Redis is not configured, startup fails closed.
If `NEXO_REQUIRE_AUDIT_PREFLIGHT=true` and preflight fails, startup fails closed before serving traffic.

## Recommended Hostile Configuration

- Set `NEXO_HTTP_BIND` to a loopback or internal bind address where appropriate, for example `127.0.0.1:3000` behind a controlled proxy.
- Do not enable `NEXO_TRUST_PROXY_HEADERS=true` unless direct service access is blocked and the proxy strips/sanitizes client-supplied forwarded headers.
- Keep `NEXO_ADMIN_API_ENABLED=false` unless an internal admin boundary and strong `NEXO_ADMIN_API_TOKEN` are configured.
- Consider optional edge controls where the deployment can enforce them correctly:
  - `NEXO_EDGE_REQUIRED=true`
  - `NEXO_MTLS_REQUIRED=true`
  - `NEXO_CLIENT_SIG_REQUIRED=true`
- Keep `NEXO_REDIS_OP_TIMEOUT_MS` short enough that Redis failures fail closed quickly rather than hanging request handling.
- Store audit artifacts on protected storage with restricted read/write access.
- Run only one writer process per `NEXO_AUDIT_PATH`.
- Use external coordination or separate audit paths for replicas/shared filesystems; the local lock file is not a distributed lock.

## Endpoint Exposure Policy

| Endpoint / surface | Baseline exposure posture |
| --- | --- |
| `POST /evaluate` | Central signed decision endpoint. Expose only behind TLS/edge controls and signed-client discipline. |
| `GET /healthz` | Shallow liveness only. Not security readiness, audit readiness, or verifier proof. |
| `GET /readyz` | Runtime readiness only. Not offline verification. With audit preflight enabled, startup should already fail before this endpoint matters. |
| `GET /api/state` | Unauthenticated informational state. Not authority. Hostile deployments should avoid public exposure unless the information disclosure risk is intentionally accepted. |
| `GET /audit/recent` | Admin-gated and disabled by default. Informational, not a replacement for offline verification. |
| `GET /security/status` | Admin-gated and disabled by default. Operational signal only. |
| `GET /metrics` | Admin-gated and disabled by default. Operational signal only. |
| `POST /api/chat/send` | Loopback-only, bounded, JSON-gated, non-authoritative local UI support. Not public-proxy safe. |
| Ruby UI | Presentation surface only. It must not redefine evidence or decision authority. |
| Relay/P2P/Mesh/Witness/Bitcoin | Live edges or experiments. Not authority for this baseline. |
| Future IA | Observer/analyzer only unless a future contract explicitly changes this. |

## Audit Storage and Chain Requirements

- `AuditStore::append` must remain fail-closed.
- The audit path must have one writer process.
- Existing `<audit_path>.lock` is an incident signal, not a cleanup-only condition.
- The append path uses record chaining with `prev_record_hash` and `record_hash`.
- Current append rejects malformed tail JSON, missing tail `record_hash`, and invalid tail `record_hash` format.
- `NEXO_REQUIRE_AUDIT_PREFLIGHT=true` should be enabled in hostile deployments to check existing artifact state before serving traffic.
- Offline Zig verification remains required for persisted artifact review.
- Operators must preserve audit files, lock files, temp files, and logs before recovery actions.

## Replay and Rate-Limit Requirements

- `request_id` is a one-time signed nonce, not an idempotency key.
- Local in-memory replay is acceptable for local/dev only and does not survive restart.
- Hostile deployments should require persistent replay with Redis:
  - `NEXO_REQUIRE_PERSISTENT_REPLAY=true`
  - `NEXO_REDIS_URL=...`
- Redis replay and rate-limit backend errors/timeouts fail closed.
- Rate limiting applies to `/evaluate`; identity uses socket peer by default.
- Forwarded IP headers must remain untrusted unless a trusted proxy boundary is explicitly enforced.
- There is no dedicated local 429 test today; this remains a known test-coverage gap.

## Profile Selection Requirements

- `NEXO_PROFILE` unset defaults to `br_default_v1`.
- Explicit unknown `NEXO_PROFILE` values fail closed at startup/config selection.
- Known built-in profiles select their matching `RuleProfile`.
- Current provenance strength is selected metadata binding:
  - `profile_name` and `profile_version` are persisted
  - both are covered by `record_hash`
  - full `RuleProfile`, full `EngineConfig`, `country`, `config_hash`, and `policy_hash` are not persisted

## Auth / HMAC / Timestamp Requirements

- `/evaluate` requires HMAC-BLAKE3 over canonical request context.
- The auth path rejects duplicate critical headers.
- `X-Request-Id` must be UUID v4.
- `X-Key-Id` must be valid and match active or previous configured key.
- `X-Timestamp` must be inside `NEXO_AUTH_WINDOW_MS`.
- Optional edge/mTLS/client Ed25519 guards are available but must be deployed behind a correctly controlled boundary.
- HMAC secrets and previous rotation secrets must be stored and rotated as operational secrets.

## Offline Verification Requirements

Run Zig verifier checks against retained artifacts:

```bash
cd tools/zig && zig build test
cd tools/zig && zig build run -- verify ../../fixtures/audit_sample.jsonl
cd tools/zig && zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl
```

For operational artifacts:

```bash
cd tools/zig && zig build run -- verify --require-chain <artifact.jsonl>
```

Zig verifies persisted artifact consistency.
It does not verify HMAC validity, replay validity, timestamp freshness, known profile config, or never-persisted events.

## Admin and Observability Surfaces

- `/audit/recent`, `/security/status`, and `/metrics` are disabled by default.
- If enabled, they require `Authorization: Bearer <NEXO_ADMIN_API_TOKEN>`.
- These endpoints are operational signals, not evidence authority.
- `/api/state` is informational and unauthenticated today; hostile deployments should avoid public exposure unless explicitly accepted.
- `/healthz` and `/readyz` are not substitutes for offline artifact verification.

## Supply-Chain and CI Requirements

Required validation surfaces:

- `bash scripts/check_supply_chain_surface.sh`
- `cargo deny check`
- CI security job running both checks
- lockfile source policy denying unknown registries/git sources
- workflow-level `permissions: contents: read`

Known supply-chain limits:

- Dependency build scripts and proc macros remain build-time trust surfaces.
- CI actions are tag-pinned, not full commit-SHA pinned.
- `bans.multiple-versions` is warn-only today.
- The local supply-chain script scans repository-owned sensitive paths, not transitive Cargo registry source.
- These controls are guardrails, not formal artifact provenance proof.

## Operational Validation Gate

Before promoting a hostile-baseline deployment, run the relevant current validation set:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -q
cargo test --features network
bash scripts/check_readme_consistency.sh
bash scripts/check_supply_chain_surface.sh
cargo deny check
cd tools/zig && zig build test
cd tools/zig && zig build run -- verify ../../fixtures/audit_sample.jsonl
cd tools/zig && zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl
julia --project=./julia julia/test/runtests.jl
julia --project=./julia julia/test_integration.jl
```

Also run an operational flow and verify the emitted artifact offline:

```bash
bash scripts/demo_decision_flow.sh
bash scripts/inspect_audit_artifact.sh <artifact.jsonl>
cd tools/zig && zig build run -- verify --require-chain <artifact.jsonl>
```

Use environment-specific judgment for commands that require local Zig, Julia, Redis, or runtime services.
Do not claim validation that was not actually run.

## Incident / Quarantine Expectations

On audit persistence, lock, temp-file, malformed-tail, or chain-integrity incidents:

- stop accepting new `POST /evaluate` traffic
- preserve the active audit file
- preserve `<audit_path>.lock` if present
- preserve deterministic temp files if present
- preserve runtime logs and failed request metadata without leaking secrets
- do not manually edit, truncate, overwrite, or repair audit JSONL
- do not blindly delete lock files
- do not retry the same `request_id`
- quarantine evidence before recovery actions
- run offline verification before resume decisions

Follow `docs/SECURITY_OPERATIONS.md` section `4.6 Audit Incident Recovery & Quarantine Checklist`.

## What This Baseline Can Claim

Production Hostile Baseline v1 can honestly claim:

- documented and tested fail-closed central `/evaluate` request/audit path
- persistent replay can be required
- startup audit preflight can be required
- decision evidence is persisted with record chaining
- offline Zig verification can validate persisted artifacts and chain continuity mode
- unknown explicit profiles fail closed
- profile provenance is selected metadata binding
- `/api/chat/send` is bounded, loopback-only, and non-authoritative
- admin endpoints are disabled by default and bearer-gated when enabled
- supply-chain and docs consistency guardrails exist

## What This Baseline Cannot Claim

Production Hostile Baseline v1 cannot claim:

- universal production readiness
- global truth
- consensus
- full-input replay evidence
- full policy/config cryptographic binding
- Zig proof of HMAC validity
- Zig proof of replay validity
- Zig proof of timestamp freshness
- Zig proof of profile config correctness
- Zig proof that no never-persisted event existed
- continuous runtime audit-chain verification after startup
- distributed lock safety for shared filesystems or multi-replica writers
- public-safe exposure for all endpoints by default
- complete supply-chain provenance
- formal dependency safety proof

## Known Limits

- `NEXO_REQUIRE_AUDIT_PREFLIGHT=true` has helper/unit coverage, but no direct end-to-end `AppState::from_env()` enabled-startup test today.
- Redis unavailability and Redis append-failure replay paths are not fully covered by stable local tests.
- The test matrix notes no dedicated 429/rate-limit test.
- `/api/state` remains unauthenticated and informational.
- Default HTTP bind is `0.0.0.0:3000`; hostile deployments need explicit bind/network/proxy controls.
- Duplicate dependency policy is warn-only.
- GitHub Actions are tag-pinned, not commit-SHA pinned.
- Profile provenance remains selected metadata binding, not config/policy binding.

## vNext / Open Decisions

- Add a direct startup test for `NEXO_REQUIRE_AUDIT_PREFLIGHT=true`.
- Add a dedicated 429/rate-limit test.
- Add stable Redis-backed integration tests if an acceptable non-flaky test environment exists.
- Decide whether `/api/state` should become admin-gated under a hostile profile.
- Recommend or enforce `NEXO_HTTP_BIND=127.0.0.1:...` for hostile deployments.
- SHA-pin GitHub Actions.
- Strengthen duplicate dependency policy beyond warn.
- Add `config_hash`, `policy_hash`, or full profile replay if future provenance work requires it.
- Add continuous audit-chain verification if runtime cost and semantics are acceptable.
- Add a distributed/multi-writer lock model only if shared-path multi-replica writes become a requirement.

## Operator Checklist

- Configure HMAC secret from file or managed provider.
- Set active `NEXO_HMAC_KEY_ID`.
- Set protected `NEXO_AUDIT_PATH`.
- Set known `NEXO_PROFILE`, or intentionally accept unset `br_default_v1`.
- Set `NEXO_REQUIRE_PERSISTENT_REPLAY=true`.
- Set `NEXO_REDIS_URL`.
- Set `NEXO_REQUIRE_AUDIT_PREFLIGHT=true`.
- Bind service to loopback/internal interface or enforce equivalent network controls.
- Keep admin endpoints disabled unless internal access and bearer token are configured.
- Keep `/api/chat/send` private/local-only.
- Run the operational validation gate.
- Verify generated and retained artifacts offline with Zig.
- Preserve/quarantine evidence before incident recovery.

## Reviewer Checklist

- Confirm hostile env values are set or intentionally omitted.
- Confirm only `POST /evaluate` is exposed as the central signed decision endpoint.
- Confirm `/api/state`, `/healthz`, and `/readyz` are not treated as evidence authority.
- Confirm audit path has exactly one writer.
- Confirm persistent replay is required for hostile deployments.
- Confirm audit preflight is required for hostile deployments.
- Confirm unknown explicit `NEXO_PROFILE` fails closed.
- Confirm Zig verification passes for retained artifacts.
- Confirm docs and README consistency checks pass.
- Confirm supply-chain guard and `cargo deny check` pass.
- Confirm all non-claims and known limits are understood before promotion.
