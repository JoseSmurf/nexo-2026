# NEXO Policy/Profile Provenance Contract v1

## Status and Scope

This document records the current Policy/Profile Provenance Contract v1.
It describes current repository behavior and does not change runtime behavior.

This contract is a baseline, not a future design.
It documents how NEXO currently selects a policy profile, derives the effective engine configuration, persists profile metadata, protects that metadata with record hashing, and exposes the limits of that provenance.

NEXO Audit Contract Baseline v1 remains the artifact-level baseline: current audit artifacts are decision evidence, not full-input-replay evidence.
See [`docs/NEXO_AUDIT_CONTRACT_BASELINE_V1.md`](NEXO_AUDIT_CONTRACT_BASELINE_V1.md).

## Center Path

Current center:

```text
signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> record chain -> offline Zig verification
```

Trust boundaries:

- Rust decides.
- Zig verifies persisted artifacts offline.
- Ruby presents.
- Julia observes.
- Mesh/P2P/Witness/Bitcoin are live edges, not authority.
- Future IA may observe or analyze, but must not decide.

## Current Provenance Strength

Current provenance strength is **selected metadata binding**.

That means:

- It is stronger than label-only provenance because `profile_name` and `profile_version` are persisted in `AuditRecord` and covered by `record_hash`.
- It is not config binding because full `EngineConfig` and full `RuleProfile` are not persisted or hashed.
- It is not full replay binding because the artifact alone cannot reconstruct the exact policy/config used for evaluation.
- It is not cryptographic policy binding because no `config_hash` or `policy_hash` exists today.

## Runtime Profile Selection v1

Runtime profile selection happens in Rust application state setup:

- `AppState::from_env()` calls `profile_from_env()`.
- `profile_from_env()` reads `NEXO_PROFILE`.
- If `NEXO_PROFILE` is unset, the selected profile defaults to `br_default_v1`.
- If `NEXO_PROFILE` has an unknown value, startup/config selection fails closed.

The unset default is current behavior.
Explicitly unknown profile values are not allowed and should be treated as startup/config incidents.

`/evaluate` uses the selected runtime profile through:

```text
state.profile.engine_config()
```

The response and persisted audit record use:

```text
state.profile.name
state.profile.version
```

## `RuleProfile` Contract v1

`RuleProfile` is the current named profile model.

Current fields:

| Field | Decision-affecting after mapping | Persisted in `AuditRecord` | Notes |
| --- | --- | --- | --- |
| `name` | No | As `profile_name` | Selected profile label. |
| `version` | No | As `profile_version` | Selected profile version label. |
| `country` | No | No | Present in `RuleProfile`, dropped before engine config. |
| `tz_offset_minutes` | Yes | No | Used by night-window policy. |
| `night_start` | Yes | No | Used by night-window policy. |
| `night_end` | Yes | No | Used by night-window policy. |
| `night_limit_cents` | Yes | No | Used by night-limit policy. |
| `aml_amount_cents` | Yes | No | Used by AML amount threshold. |
| `aml_risk_bps` | Yes | No | Used by AML risk threshold. |

Current built-in profile names include:

- `br_default_v1`
- `us_default_v1`
- `eu_default_v1`
- `cn_default_v1`
- `ae_default_v1`
- `in_default_v1`
- `jp_default_v1`
- `gb_default_v1`
- `kr_default_v1`

All inspected built-in profiles currently use version `2026.02`.

## `EngineConfig` Contract v1

`EngineConfig` is the effective policy configuration used by the deterministic engine.

Current fields:

- `tz_offset_minutes`
- `night_start`
- `night_end`
- `night_limit_cents`
- `aml_amount_cents`
- `aml_risk_bps`

`EngineConfig` does not contain:

- `name`
- `version`
- `country`
- `config_hash`
- `policy_hash`
- source file id
- jurisdiction id
- policy bundle id

The engine `evaluate()` function accepts a `RuleProfile` argument, but that parameter is currently named `_profile` and is explicitly unused.
Current rule behavior is driven by `EngineConfig`.

## `RuleProfile` -> `EngineConfig` Mapping

`RuleProfile::engine_config()` copies only these fields into `EngineConfig`:

- `tz_offset_minutes`
- `night_start`
- `night_end`
- `night_limit_cents`
- `aml_amount_cents`
- `aml_risk_bps`

It drops these `RuleProfile` fields:

- `name`
- `version`
- `country`

Therefore, profile labels are persisted for provenance metadata, but they are not the values directly consumed by the rule functions.
The rule functions consume the derived `EngineConfig`.

## Decision-Affecting Policy Fields

Decision-affecting config fields:

- `tz_offset_minutes`
- `night_start`
- `night_end`
- `night_limit_cents`
- `aml_amount_cents`
- `aml_risk_bps`

Decision-affecting request fields:

- `amount_cents`
- `is_pep`
- `has_active_kyc`
- body `timestamp_utc_ms`
- `risk_bps`
- `ui_hash_valid`

Profile metadata fields that do not directly affect rule execution after mapping:

- `profile_name`
- `profile_version`
- `country`

## Persisted Provenance Fields

The only profile/provenance fields persisted in `AuditRecord` today are:

- `profile_name`
- `profile_version`

Not persisted:

- full `RuleProfile`
- full `EngineConfig`
- `country`
- `config_hash`
- `policy_hash`
- source bundle id
- source file id
- policy bundle id
- jurisdiction id

This means a persisted artifact can show which profile label/version the runtime reported, but it cannot reconstruct the complete profile or engine config from the artifact alone.

## Hash Coverage

`record_hash` covers:

- `profile_name`
- `profile_version`

`record_hash` does not cover:

- full `RuleProfile`
- full `EngineConfig`
- `country`
- `config_hash`
- `policy_hash`

Those values are not covered because they are not persisted in the current `AuditRecord`.

`audit_hash` covers trace semantics, not profile labels directly.
It does not directly hash `profile_name`, `profile_version`, `country`, full `RuleProfile`, or full `EngineConfig`.

Trace semantics may indirectly expose some effective policy values when a rule fires.
That indirect exposure is partial and should not be treated as full policy provenance.

## Zig Verifier Coverage

Zig validates persisted artifact consistency.

Zig can verify:

- supported `hash_algo`
- trace schema and semantic shape
- `final_decision` consistency with trace
- recomputed `audit_hash`
- `record_hash` when present and non-null
- `record_hash` and `prev_record_hash` continuity when `--require-chain` is used

For policy/profile provenance, Zig can only protect `profile_name` and `profile_version` through `record_hash` when `record_hash` is enforced.

Zig cannot currently verify:

- that `profile_name` is a known built-in profile
- that `profile_version` maps to a specific profile config
- that a full `RuleProfile` was used
- that a full `EngineConfig` was used
- `country` or jurisdiction provenance
- `config_hash`
- `policy_hash`
- source bundle identity
- original input replay

Zig cannot verify config/policy hash because no such hash exists today.

## Trace Evidence and Its Limits

Persisted trace can provide partial policy evidence.

For fired `Blocked` and `FlaggedForReview` decisions, trace entries can expose:

- `rule_id`
- `reason`
- `severity`
- `measured`
- `threshold`

This can reveal some effective thresholds used by fired rules.

However:

- `Approved` entries do not carry rule ids.
- `Approved` entries do not carry thresholds.
- Trace does not persist the full `DecisionTrace` container.
- Trace does not persist full `RuleProfile`.
- Trace does not persist full `EngineConfig`.

Trace evidence is partial policy evidence, not full config provenance.

## Unknown Profile Fail-Closed Behavior

Current `NEXO_PROFILE` behavior:

| Input | Current selected profile |
| --- | --- |
| unset | `br_default_v1` |
| `br_default_v1` | `br_default_v1` |
| known built-in profile | matching built-in profile |
| unknown value | fail closed at startup/config selection |

Unknown explicit values are fail-closed.
This avoids silently running BR defaults when an operator intended another profile.

The unset default remains `br_default_v1`.

## What Policy/Profile Provenance v1 Proves

Baseline v1 proves:

- The runtime selected profile label is persisted as `profile_name`.
- The runtime selected profile version label is persisted as `profile_version`.
- `profile_name` and `profile_version` are protected by `record_hash` when `record_hash` is enforced.
- The effective decision trace is protected by `audit_hash`.
- Fired blocked/flagged trace entries can expose some rule IDs and thresholds.
- Offline Zig verification can detect tampering with protected persisted fields when the relevant hash checks are enforced.

## What Policy/Profile Provenance v1 Does Not Prove

Baseline v1 does not prove:

- exact policy config used
- full profile replay
- full config replay
- country/jurisdiction verification
- known-profile verification by Zig
- cryptographic policy binding
- full-input replay
- that a `profile_name/profile_version` pair uniquely identifies a historical config
- that future code still maps the same labels to the same thresholds
- that Mesh/P2P/Witness/Bitcoin outputs are authority
- that future IA output is authority

## Known Limits

- Current provenance is selected metadata binding, not full config binding.
- Unknown explicit `NEXO_PROFILE` values fail closed.
- Full `RuleProfile` is not persisted.
- Full `EngineConfig` is not persisted.
- `country` is not persisted.
- No `config_hash` exists.
- No `policy_hash` exists.
- The engine currently ignores the `RuleProfile` argument and uses `EngineConfig`.
- `Approved` trace entries do not persist rule ids or thresholds.
- Existing fixtures inspected use `br_default_v1`; they do not demonstrate multi-profile provenance coverage.
- Existing tests cover many config outcomes, but there is no direct profile-selection contract test for `profile_from_env()` fallback/default behavior.

## Contract Drift Risks

- Built-in profile thresholds could change while keeping the same `profile_name` and `profile_version`.
- A profile label could remain stable while `RuleProfile::engine_config()` mapping changes.
- If future changes weaken unknown-profile fail-closed behavior, deployment mistakes could silently run the wrong profile.
- Docs could overread `profile_name/profile_version` as a cryptographic policy binding.
- Zig could be described as verifying known profile config even though it does not.
- Trace evidence for approved rules could be overread as full policy evidence.
- Future IA, Mesh, P2P, Witness, or Bitcoin surfaces could be incorrectly treated as policy authority.

## vNext / Open Contract Decisions

| Decision | Current v1 state | Open question |
| --- | --- | --- |
| Persist full `EngineConfig`? | Not persisted | Should artifacts carry exact effective config values? |
| Persist full `RuleProfile`? | Not persisted | Should artifacts carry full named profile metadata and thresholds? |
| Persist `country`? | Not persisted | Should jurisdiction/country be part of artifact provenance? |
| Add `config_hash`? | Not present | Should artifacts bind exact effective config with a stable hash? |
| Add `policy_hash`? | Not present | Should artifacts bind policy source/bundle identity? |
| Fail closed on unknown `NEXO_PROFILE`? | Yes | Should this remain a required startup/config invariant? |
| Version/bind policy source code or policy bundle identity? | Not present | Should provenance include code/bundle/source identity? |
| Add rule ids and thresholds for approved trace entries? | Not present | Should approved steps expose rule provenance and thresholds? |
| Teach Zig known profile/config mappings? | Not implemented | Should Zig remain schema/hash-only or verify known policy profiles? |
| Add fixtures for multiple profiles? | Current fixtures are BR-focused | Should verifier fixtures cover all built-in profiles? |
| Add tests for `profile_from_env()` fallback/default behavior? | Not directly asserted | Should fallback/default semantics be locked by tests? |
| Add API tests asserting persisted profile labels? | Not strongly asserted | Should `/evaluate` persistence tests check `profile_name/profile_version` exactly? |

## Non-Authority Boundaries

- Rust decides.
- Zig verifies persisted artifacts offline, but does not become runtime policy authority.
- Ruby presents and must not decide.
- Julia observes and must not decide.
- Mesh/P2P/Witness/Bitcoin are not policy authority.
- Future IA may observe or analyze, but must not decide.

Policy/profile provenance claims must remain tied to the Rust decision path and persisted audit artifact.
Experimental or observer surfaces must not be used to reinterpret unverified evidence as authority.

## Reviewer Checklist

Use this checklist when reviewing policy/profile provenance claims:

- Is the claimed `profile_name` present in the artifact?
- Is the claimed `profile_version` present in the artifact?
- Does `record_hash` recompute over the artifact when enforced?
- Is the reviewer treating `profile_name/profile_version` as selected metadata binding, not full config binding?
- Is anyone claiming `country` was persisted or verified?
- Is anyone claiming Zig verified known profile config?
- Is anyone claiming a `config_hash` or `policy_hash` exists?
- Are fired-rule thresholds being treated as partial trace evidence, not full config provenance?
- Are approved trace entries understood to lack rule ids and thresholds?
- Are unknown `NEXO_PROFILE` fail-closed semantics understood before deployment claims are made?
- Are vNext decisions separated from current v1 behavior?
