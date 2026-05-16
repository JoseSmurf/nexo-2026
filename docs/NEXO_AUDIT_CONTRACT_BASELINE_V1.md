# NEXO Audit Contract Baseline v1

## Status and Scope

This document records the current authoritative audit/evidence contract for NEXO as it exists in this repository today.
It is a baseline description only: it does not change runtime behavior, verifier behavior, storage behavior, or API semantics.

Baseline v1 is decision-evidence, not full-input-replay evidence.
It lets a reviewer inspect persisted decision artifacts, recompute the current trace hash, check selected record fields, and verify chain continuity when the chain mode is used.
It does not claim that every original request input can be reconstructed or re-executed from the artifact alone.

Related context:

- [AGENTS.md](../AGENTS.md)
- [README.md](../README.md)
- [NEXO Test Matrix](NEXO_TEST_MATRIX.md)
- [Operational Flow](OPERATIONAL_FLOW.md)
- [Security Operations](SECURITY_OPERATIONS.md)
- [Reproducibility Report](NEXO_REPRODUCIBILITY_REPORT.md)
- [Threat Model](NEXO_THREAT_MODEL.md)

## Center Path

Baseline v1 is centered on:

```text
signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> record chain -> offline Zig verification
```

Trust boundaries:

- Rust decides and writes the primary audit artifact.
- Zig verifies persisted artifacts offline.
- Ruby presents only.
- Julia observes only.
- Mesh/P2P/Witness/Bitcoin are live edges and experiments, not authority over the audit contract.

## What Audit Contract Baseline v1 Proves

Baseline v1 can prove, for persisted artifacts:

- Persisted decision evidence integrity for the fields covered by `record_hash`.
- Trace semantic integrity for the persisted `trace` covered by `audit_hash`.
- Record-level integrity for selected persisted `AuditRecord` fields under `audit_record_v2` framing.
- Record chain continuity when checked by Rust preflight or Zig `--require-chain`.
- Alignment between the current Rust artifact shape and the offline Zig verifier for the persisted artifact contract.

## What Baseline v1 Does Not Prove

Baseline v1 does not prove:

- Global truth.
- Consensus.
- Full original request replay.
- That external real-world facts are true.
- HMAC/auth validity by Zig.
- `auth_key_id` provenance in the persisted artifact.
- Full profile configuration or policy source identity.
- That no accepted event was ever lost before persistence.
- That Mesh/P2P/Witness/Bitcoin are authority.
- That Ruby or Julia can redefine the Rust/Zig evidence contract.

## Persisted AuditRecord Fields

| Field | Persisted | Included in `audit_hash` | Included in `record_hash` | Verified by Zig | Notes |
| --- | --- | --- | --- | --- | --- |
| `request_id` | Yes | No | Yes | Required by base Zig verification | Header `X-Request-Id`; body `request_id`, if present, must match before evaluation. |
| `calc_version` | Yes | No | Yes | Only through `record_hash` when enforced | Optional request field. Missing/null hashes as empty string in `record_hash`. |
| `profile_name` | Yes | No | Yes | Only through `record_hash` when enforced | Identifies selected profile name, not full profile config. |
| `profile_version` | Yes | No | Yes | Only through `record_hash` when enforced | Identifies selected profile version, not full profile config. |
| `timestamp_utc_ms` | Yes | No | Yes | Only through `record_hash` when enforced | Auth/header timestamp. It is not persisted separately as the body transaction timestamp used by engine rules. |
| `user_id` | Yes | No | Yes | Only through `record_hash` when enforced | Request body field. |
| `amount_cents` | Yes | No | Yes | Only through `record_hash` when enforced | Request body field. |
| `risk_bps` | Yes | No | Yes | Only through `record_hash` when enforced | Request body field. |
| `final_decision` | Yes | No | Yes | Required and checked against trace semantics | Computed by Rust from the projected trace. |
| `trace` | Yes | Yes | Yes as serialized JSON | Required and semantically verified | Persisted as `Vec<Decision>`, not full `DecisionTrace`. |
| `audit_hash` | Yes | N/A | Yes | Required and recomputed | Hash of persisted trace semantics only. |
| `hash_algo` | Yes | Selects algorithm | Yes | Required and checked as supported | Runtime emits current supported algorithm names; Zig also retains limited legacy compatibility. |
| `sha3_shadow` | Optional | No | Yes when present | Only through `record_hash` when enforced | Zig does not recompute this shadow value today. |
| `prev_record_hash` | Yes | No | Yes | Enforced by Zig only with `--require-chain` | Links to previous record hash. |
| `record_hash` | Yes on current append path | No | N/A | Optional in base mode; required in `--require-chain` | Hash of selected persisted record fields under `audit_record_v2`. |
| `auth_key_id` | No | No | No | No | Response-only today. |
| `shadow_hash_algo` | No | No | No | No | Response-only today. |
| `is_pep` | No | No | No | No | Input to engine, not persisted. |
| `has_active_kyc` | No | No | No | No | Input to engine, not persisted. |
| `ui_hash_valid` | No | No | No | No | Input to engine, not persisted. |
| Body transaction `timestamp_utc_ms` | No as a separate field | No | No | No | Used by `TransactionIntent`; persisted `timestamp_utc_ms` is the auth/header timestamp. |

## Trace Contract v1

The persisted trace contract is `Vec<Decision>`.
It is not the full internal `DecisionTrace`.

Persisted decision variants:

- `Approved` is a unit/string value and does not carry `rule_id`.
- `FlaggedForReview` carries `rule_id`, `reason`, `severity`, `measured`, and `threshold`.
- `Blocked` carries `rule_id`, `reason`, `severity`, `measured`, and `threshold`.

The internal engine trace contains more information:

- trace schema
- trace format version
- step indexes
- rule IDs for approved steps
- `TraceStep { index, rule_id, decision }`

Those internal fields are not persisted in Baseline v1 and are not part of the current `audit_hash`.
This is the current contract, not a statement that the trace contract should never evolve.

## Hash Contract v1

### `audit_hash`

`audit_hash` is the semantic hash of the persisted trace under `trace_v4` framing.
It proves that the persisted trace semantics and ordering match the stored hash.

It does not prove:

- HMAC/auth validity.
- Request replay status.
- Full input replay.
- Profile/config provenance.
- Record-chain continuity.
- Integrity of non-trace record fields.

### `record_hash`

`record_hash` is the record-level hash under `audit_record_v2` framing.
It covers selected persisted fields, including the serialized trace JSON, `audit_hash`, `hash_algo`, `final_decision`, `prev_record_hash`, and selected request/profile metadata.

It does not cover:

- `record_hash` itself.
- `auth_key_id`.
- `shadow_hash_algo`.
- `is_pep`.
- `has_active_kyc`.
- `ui_hash_valid`.
- The body transaction timestamp as a separate field.
- Full profile config.

### `prev_record_hash`

`prev_record_hash` links each record to the previous record's `record_hash`.
It proves continuity only when the chain is checked by Rust preflight or Zig `--require-chain`.

### `hash_algo`

`hash_algo` declares which audit hash algorithm was used.
Current runtime policy can emit:

- `blake3`
- `shake256-256`
- `shake256-384`
- `shake256-512`
- `shake256-512+blake3-256`

`sha3-256` is legacy verifier support only and is not current runtime emission.

### `sha3_shadow`

`sha3_shadow` is optional.
When present, it is persisted and protected by `record_hash` if `record_hash` is enforced.
Baseline v1 does not require Zig to recompute or independently verify `sha3_shadow`.
The response-only `shadow_hash_algo` is not persisted today.

## `/evaluate` Persistence Boundary

Runtime order relevant to the audit contract:

1. HTTP boundary validation runs before the handler.
2. Auth, timestamp, HMAC, and replay checks run before evaluation.
3. `request_id` is consumed as a replay nonce before audit append.
4. Rust constructs `TransactionIntent`.
5. Rust computes `final_decision`, projected `trace`, and `audit_hash`.
6. Rust constructs `AuditRecord`.
7. Rust appends the audit record.
8. Success response is constructed only after append succeeds.

If audit append fails:

- `/evaluate` returns non-`200`.
- The decision payload is withheld.
- `final_decision` is not returned to the caller.
- Retrying the same `request_id` is expected to return replay conflict because the nonce was already consumed.

This is a conservative fail-closed contract, not an idempotent retry contract.

## Policy/Profile Provenance v1

Baseline v1 persists:

- `profile_name`
- `profile_version`

These fields are protected by `record_hash`.

Baseline v1 does not persist:

- full `RuleProfile`
- profile country
- full `EngineConfig`
- profile/config hash
- source file or policy bundle identifier

`EngineConfig` drives decisions.
It is derived from `RuleProfile`, but the artifact stores only profile name/version plus selected request/result fields.
Therefore Baseline v1 does not provide full policy replay from the artifact alone.

## Zig Verifier Contract v1

Zig verifies persisted artifacts offline.
It does not become runtime authority and does not decide requests.

Base Zig verification validates:

- JSON schema shape required by the verifier.
- Supported `hash_algo`.
- `audit_hash` lowercase hex length for the algorithm.
- Non-empty `trace` array.
- Trace item shape and semantics.
- `final_decision` consistency with trace semantics.
- Recomputed `audit_hash`.
- `record_hash` if present and non-null.
- Optional `trace_bytes` consistency if present.

Zig base verification does not validate:

- HMAC signature.
- `auth_key_id`.
- Replay or nonce consumption.
- Timestamp freshness.
- Known profile config.
- Full original input replay.
- Mesh/P2P/Witness/Bitcoin authority.

Zig `--require-chain` additionally:

- requires `record_hash`
- checks `record_hash` format
- checks `prev_record_hash` continuity across records

Fixture roles:

- `fixtures/audit_sample.jsonl` covers the base single-record verifier path.
- `fixtures/audit_chain_sample.jsonl` covers chained `record_hash` / `prev_record_hash` verification with `--require-chain`.

Extra JSON fields may be ignored unless they are explicitly part of the hash/verifier contract.
Adding fields to JSON is not the same as adding them to Baseline v1 evidence semantics.

## Known Limits

- `auth_key_id` is response-only.
- `shadow_hash_algo` is response-only.
- Baseline v1 is not full input replay.
- `Approved` lacks `rule_id` in persisted artifacts.
- Step indexes, trace schema, trace format version, and approved-step rule IDs are internal-only today.
- No profile/config hash exists.
- Full profile config and country are not persisted.
- Body transaction timestamp is not persisted as a separate transaction timestamp.
- Persisted `timestamp_utc_ms` is the auth/header timestamp.
- Redis replay plus audit-append failure behavior follows current code ordering, but lacks a direct API-level test.
- Zig `--require-chain` is more permissive than Rust preflight for the first record's `prev_record_hash`: Zig allows missing/null/string-if-valid on the first record, while Rust preflight requires first `prev_record_hash` to be null.
- Zig cannot prove that a never-persisted event existed.

## vNext / Open Contract Decisions

| Decision | Baseline v1 position | vNext question |
| --- | --- | --- |
| Persist `auth_key_id`? | Not persisted today | Should key provenance be part of audit evidence? |
| Persist full `DecisionTrace`? | Not persisted today | Should artifacts include step indexes, trace schema/version, and approved rule IDs? |
| Add policy/config hash? | Not present today | Should artifacts bind exact policy config, not just profile name/version? |
| Add full input replay artifact? | Not present today | Should artifacts include all original engine inputs needed to recompute decisions? |
| Persist body transaction timestamp separately? | Not present today | Should auth timestamp and transaction timestamp be distinct persisted fields? |
| Persist shadow hash algorithm? | Response-only today | Should `shadow_hash_algo` be persisted and verified? |
| Recompute `sha3_shadow` in Zig? | Not required today | Should Zig independently verify shadow hash values? |
| Redis replay + append failure direct test? | Not directly covered today | Should there be an integration/API test for Redis mode? |
| Align Rust/Zig first `prev_record_hash` semantics? | Not identical today | Should Zig require first `prev_record_hash == null` in chain mode? |

## Non-Authority Boundaries

- Ruby presents; it does not decide.
- Julia observes; it does not decide.
- Mesh/P2P/Witness/Bitcoin are not authority over Baseline v1 audit evidence.
- Zig verifies persisted artifacts offline; it does not become runtime authority.
- Informational endpoints and dashboards do not replace offline artifact verification.

## Reviewer Checklist

Use this checklist when reviewing a Baseline v1 audit artifact:

- Does the artifact contain the expected persisted fields?
- Is the trace a `Vec<Decision>` shape, not full `DecisionTrace`?
- Does `audit_hash` recompute from persisted trace semantics?
- Does `record_hash` recompute over the selected persisted fields?
- Does Zig base verification pass?
- Does Zig `--require-chain` pass for chained JSONL artifacts?
- Is `final_decision` consistent with trace semantics?
- Are response-only fields such as `auth_key_id` and `shadow_hash_algo` understood as not persisted?
- Are Baseline v1 limits understood before making claims about replay, profile provenance, or full input reconstruction?
