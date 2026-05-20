# NEXO Public Exposure Policy v1

## Status and Scope

This document records the current public exposure policy for NEXO surfaces.
It documents current repository behavior and deployment posture; it does not change runtime behavior.

Public Exposure Policy v1 applies to the current NEXO center path and adjacent operator/UI/network surfaces.
It does not promote Ruby, Julia, relay, Mesh/P2P, Witness, Bitcoin, or future IA surfaces into the trust core.

Related documents:

- [Production Hostile Baseline v1](NEXO_PRODUCTION_HOSTILE_BASELINE_V1.md)
- [Audit Contract Baseline v1](NEXO_AUDIT_CONTRACT_BASELINE_V1.md)
- [Policy/Profile Provenance Contract v1](NEXO_POLICY_PROFILE_PROVENANCE_CONTRACT_V1.md)
- [Security Operations](SECURITY_OPERATIONS.md)
- [Operational Flow](OPERATIONAL_FLOW.md)
- [Threat Model](NEXO_THREAT_MODEL.md)
- [Test Matrix](NEXO_TEST_MATRIX.md)

## Core Principle

Evidence can be public.
Authority and control surfaces must remain bounded.

NEXO should expose verifiable evidence and documentation where appropriate, but it must not expose every operational, control, admin, UI, relay, or experimental surface.

## Center Path

The current product center is:

```text
signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> record chain -> offline Zig verification
```

## Authority Model

- Rust decides and writes the primary audit artifact.
- Zig verifies persisted artifacts offline.
- Ruby presents.
- Julia observes.
- Relay/P2P/Mesh/Witness/Bitcoin are live edges or experiments, not authority.
- Future IA may observe or analyze, but must not decide under this policy.

## Exposure Classification Legend

| Classification | Meaning |
| --- | --- |
| Public-capable with strict controls | May be reachable through a controlled public edge only when the listed controls are enforced. |
| Internal-only | Must stay inside an internal service/network boundary. |
| Admin-only | Must be disabled by default or protected by an explicit admin boundary and token. |
| Loopback-only | Must only be reachable from the same host/process boundary. |
| Local/dev-only | Intended for local development, demos, or operator-only use; not public-safe. |
| Non-authoritative future/experimental surface | May exist in code or docs, but is not part of the authority path and needs separate exposure policy before public use. |
| Do not expose | Should not be exposed beyond local controlled use in its current form. |

## Surface Classification Table

| Surface | Status | Current auth/gating | Authority level | v1 exposure classification | Required controls / notes |
| --- | --- | --- | --- | --- | --- |
| `POST /evaluate` | Code + docs | HMAC/key id/timestamp/request id/replay/rate-limit/audit append | Central signed decision endpoint | Public-capable with strict controls | TLS/edge controls, signed-client discipline, replay posture, rate limit, audit fail-closed behavior. |
| `GET /healthz` | Code + docs | None | Shallow liveness only | Internal-only or load-balancer-only | Not security proof, not audit readiness, not verifier proof. |
| `GET /readyz` | Code + docs | None | Runtime readiness only | Internal-only | Not offline artifact verification. |
| `GET /api/state` | Code + docs | None | Informational/windowed state | Internal-only | Unauthenticated today; not authority or audit proof. |
| `POST /api/chat/send` | Code + docs | Loopback peer check | Non-authoritative local UI support | Loopback-only | JSON-gated, bounded, not signed/replayed like `/evaluate`, not public-proxy safe. |
| `/audit/recent` | Code + docs | Admin API enabled + bearer token | Admin triage signal | Admin-only | Disabled by default; not a replacement for offline verification. |
| `/security/status` | Code + docs | Admin API enabled + bearer token | Admin security signal | Admin-only | Disabled by default; operational signal only. |
| `/metrics` | Code + docs | Admin API enabled + bearer token | Observability signal | Admin-only | Disabled by default; not public-safe. |
| Ruby UI `/` | Code + docs | Deployment boundary | Presentation/demo/operator UI | Internal-only / local operator UI | Ruby presents; it does not decide or verify authority. |
| Ruby UI `/api/status` | Code + docs | Deployment boundary | Presentation/status | Internal-only / local operator UI | May expose operational state; not authority. |
| Ruby UI `/api/health` | Code + docs | Deployment boundary | UI health/status | Internal-only / local operator UI | Not security proof. |
| Ruby UI `/api/simulate` | Code | Demo mutation surface | Demo/local UI state | Local/dev-only or do not expose | Not public-safe; can mutate simulated UI state. |
| Ruby UI `/api/chat/send` | Code | Loopback check in UI path | UI/chat support | Loopback-only / local operator UI | Not evidence and not authority. |
| Relay `/push` | Code behind network feature | Event signature validation, no central admin gate | Passive relay edge | Internal-only / non-authoritative edge | Requires separate relay exposure policy before public use. |
| Relay `/pull` | Code behind network feature | No central admin gate | Passive relay edge | Internal-only / non-authoritative edge | Requires separate relay exposure policy before public use. |
| P2P/Mesh/Witness/Bitcoin/IA surfaces | Code/docs depending on surface | Surface-specific or future | Not authority | Non-authoritative future/experimental surface | Not consensus, not global truth, not part of the central decision trust path. |

## `POST /evaluate`

`POST /evaluate` is the only central signed authoritative decision endpoint in this policy.

It may be exposed only behind strict controls:

- TLS or equivalent edge transport protection.
- HMAC/key id/timestamp/request id validation.
- Replay protection, preferably persistent replay for hostile deployments.
- Rate-limit posture for hostile traffic.
- JSON content-type validation and duplicate content-type rejection.
- Explicit request body cap.
- Audit append success before a successful response.

`POST /evaluate` is still bounded by the audit contract.
It is decision evidence, not global truth, consensus, or full-input replay proof.

## Health and Readiness Endpoints

`GET /healthz` is shallow liveness only.
It does not prove security posture, audit integrity, replay health, profile provenance, or offline verifier success.

`GET /readyz` is runtime readiness only.
It is not a substitute for offline artifact verification.
When audit preflight is required and startup fails closed, the service should fail before readiness becomes relevant.

Both endpoints should be internal-only or load-balancer-only in hostile deployments.

## `/api/state`

`GET /api/state` exists today as unauthenticated informational/windowed state.

It is not:

- authority
- audit proof
- offline verification
- a full-chain verifier
- a substitute for Zig verification

Hostile deployments should not expose `/api/state` publicly by default.
Public Exposure Policy v1 classifies it as internal-only.
In hostile mode (`ELEVATED`/`INCIDENT`), `/api/state` is fail-closed by default and returns `503` unless `NEXO_EXPOSE_API_STATE=true` is explicitly set.

Open decision: a future hostile profile may admin-gate `/api/state`, or the project may keep it internal-only by deployment policy.

## Chat and UI Support Surfaces

`POST /api/chat/send` is local UI support.
It is loopback-only, bounded, JSON-gated, and non-authoritative.

It is not:

- signed/replayed like `/evaluate`
- audit evidence
- verified evidence
- a deterministic decision input
- public-proxy safe

Hostile deployments must not public-proxy `POST /api/chat/send`.

## Admin and Observability Endpoints

`/audit/recent`, `/security/status`, and `/metrics` are disabled by default.
When enabled, they require bearer-token admin access.

These endpoints are operational and observability surfaces only.
They are not public-safe and must be exposed only inside an admin boundary.

They do not replace:

- persisted audit artifacts
- offline Zig verification
- incident/quarantine procedures
- operator review

## Ruby UI and Demo Surfaces

The Ruby UI is a presentation, demo, and operator surface.
Ruby presents; it does not decide.

The UI should remain internal/local unless separately hardened by deployment controls.
Ruby UI routes can expose or mutate demo/operator state and must not be treated as evidence authority.

`/api/simulate` is a demo/local mutation surface.
It should be local/dev-only or not exposed.

## Relay / P2P / Mesh / Witness / Bitcoin / IA Surfaces

Relay, P2P, Mesh, Witness, Bitcoin, and future IA surfaces are not authority under this policy.

They do not provide:

- consensus
- global truth
- runtime authority
- replacement decision authority
- replacement offline verification

Any public deployment of relay/P2P surfaces requires a separate exposure policy and threat model.

## Default Bind and Deployment Boundary

The Rust API default bind is broad unless `NEXO_HTTP_BIND` is set.
Hostile deployments should set an explicit loopback or internal bind where appropriate, for example:

```bash
NEXO_HTTP_BIND=127.0.0.1:3000
```

The Ruby UI default bind may also be broad unless configured.
Treat it as an internal/local operator UI unless separately protected.

Do not trust forwarded IP headers unless direct service access is blocked and the proxy strips or sanitizes client-supplied forwarded headers.

## Existing Test Coverage

Current repository tests cover important exposure boundaries:

- `/evaluate` content-type, body-size, auth, replay, and audit fail-closed behavior.
- `/api/chat/send` content-type, duplicate content-type, body-size, loopback, channel, empty text, and long text behavior.
- Admin endpoints disabled-by-default and bearer-token gating.
- `/healthz` shallow liveness and `/readyz` limited runtime readiness.
- `/api/state` response shape and state-field contract.
- Relay deterministic push/pull, invalid signature rejection, timestamp bounds, and ordering.
- Ruby UI/core adapter presentation and fallback separation.

Known test gaps remain in [NEXO Test Matrix](NEXO_TEST_MATRIX.md), including dedicated rate-limit `429` coverage and stable Redis failure integration coverage.

## What Public Exposure Policy v1 Can Claim

Public Exposure Policy v1 can claim:

- `POST /evaluate` is the only central signed authoritative decision endpoint.
- Evidence verification is centered on persisted audit artifacts and offline Zig verification.
- `/api/state` is informational and internal-only for hostile deployments.
- `/api/chat/send` is loopback-only and non-authoritative.
- Admin endpoints are disabled by default and bearer-gated when enabled.
- Ruby UI presents but does not decide.
- Relay/P2P/Mesh/Witness/Bitcoin/IA surfaces are non-authoritative under this policy.

## What Public Exposure Policy v1 Cannot Claim

This policy does not claim:

- all endpoints are public-safe
- health/readiness proves security or audit integrity
- `/api/state` is authoritative
- chat/UI messages are verified evidence
- metrics/status endpoints are safe public surfaces
- Ruby, Julia, Mesh, P2P, Witness, Bitcoin, relay, or IA can decide
- relay/P2P surfaces provide consensus, global truth, or runtime authority
- deployment networking is correct by default

## Known Limits

- Accidental public exposure of `/api/state` remains a deployment risk.
- Broad default bind behavior requires explicit deployment controls.
- Ruby UI demo routes are not public-safe.
- Relay/P2P exposure needs a separate policy.
- Dedicated `429` rate-limit testing is still pending.
- Stable Redis failure integration coverage remains limited.
- Policy-level enforcement that `/api/state` is internal-only is not yet coded.

## vNext / Open Decisions

- Decide whether `/api/state` should become admin-gated in hostile profile.
- Add dedicated `429` rate-limit tests.
- Add stable Redis failure-mode integration tests if acceptable.
- Decide whether Rust API should default to loopback in hostile deployments.
- Decide whether Ruby UI should gain stronger auth or default local-only posture.
- Define separate relay/P2P exposure policy before public use.
- Consider explicit policy tests for endpoint exposure classification.

## Operator Checklist

Before exposing any NEXO surface:

- Confirm whether the surface is public-capable, internal-only, admin-only, loopback-only, local/dev-only, experimental, or do-not-expose.
- Expose `POST /evaluate` only behind TLS/edge controls and signed-client discipline.
- Keep `/api/state` internal-only unless the information disclosure risk is explicitly accepted.
- Keep `/api/chat/send` loopback-only.
- Keep admin endpoints disabled unless an admin boundary and bearer token are configured.
- Keep Ruby UI internal/local unless separately hardened.
- Do not expose relay/P2P surfaces publicly without a separate policy.
- Verify audit artifacts offline before making evidence claims.

## Reviewer Checklist

When reviewing exposure posture:

- Is the endpoint part of the Rust decision authority path?
- Does the endpoint return evidence, state, control, admin, UI, or experimental data?
- Is the endpoint authenticated or intentionally internal-only?
- Is the endpoint bounded by body-size/content-type controls when it accepts a body?
- Could an operator mistake the surface for verified evidence or authority?
- Does the deployment bind address match the intended exposure classification?
- Are non-authoritative surfaces clearly kept out of the trust core?
