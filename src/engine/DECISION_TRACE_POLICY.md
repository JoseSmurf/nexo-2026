# DecisionTrace Contract & Evolution Policy

This document defines the long-lived contract for `DecisionTrace` in `src/engine/`
and how it evolves without breaking forensic reproducibility.

## 1) Purpose

`DecisionTrace` is the deterministic explanation layer of the engine evaluation.

- It records the exact ordered rule execution outcome for a transaction decision.
- It is the bridge between raw decision logic and audit artifacts (`audit_hash`).
- It must remain stable for a given input while a format contract is in force.

## 2) Current contract shape (stable baseline)

As implemented today:

- `DecisionTrace::schema`: fixed text marker for trace schema (`"v1"`).
- `DecisionTrace::format_version`: stable version marker (`"1"` via `TraceFormatVersion::V1`).
- `DecisionTrace::steps`: ordered list of `TraceStep`.
- each `TraceStep` has:
  - `index`: zero-based execution order within the run.
  - `rule_id`: canonical domain identifier for the rule.
  - `decision`: normalized rule result (`Approved` / `FlaggedForReview` / `Blocked`).

The current execution order is fixed by engine implementation:

1. `UI-FRAUD-001`
2. `BCB-NIGHT-001`
3. AML rule step (`KYC-PEP-002`, `AML-FATF-REVIEW-001`, or `AML-FATF-001`)

This ordering is a core contractual guarantee today and is intentionally coupled to
hash reproducibility.

## 3) Deterministic ordering rules

- `index` must always be sequential from `0` and must reflect insertion order.
- `steps` must not be reordered for the same input under the same format version.
- `rule_id` values must be stable canonical identifiers (never replaced for
  compatibility without explicit migration handling).
- The decision set for a single engine input must be replayable exactly when
  `format_version` is unchanged.

## 4) Trace and audit hashing

Runtime hashing uses `trace.into_decisions()` (sequence of `Decision`) from the
`DecisionTrace`.

- For each step, the hash input is built from:
  - decision kind (`Approved` / `Flagged` / `Blocked`)
  - rule metadata (`rule_id`, `reason`, `severity`, `measured`, `threshold`)
  - fixed `schema` tag (`trace_v4`) in hash framing
- Any change in the emitted `Decision` sequence for a given input changes
  deterministic audit hashes.

Current verifier expectations:

- Rust runtime must emit stable traces for signature-equivalent inputs.
- Offline Zig verifier checks trace semantics against `audit_hash` and is expected to
  validate equivalent structured trace content and ordering under current hashes.
- `trace` is persisted as JSON in audit records (`trace_json`); changing interpretation
  without contract handling is a compatibility risk.

## 5) Evolution policy

### 5.1 When to bump `format_version`

Bump the effective trace contract (`format_version`) when any of these happen:

1. **Execution order changes**  
   Any reordering of existing step sequence.
2. **Rule identity changes**  
   Rename/remove/redefine an existing `rule_id` that impacts prior audit
   interpretation.
3. **Step semantics change**  
   Any change that changes what the same rule position and input should mean.
4. **Hash-relevant field behavior change**  
   Any change to decision values / payload used in hash derivation.

### 5.2 Backward compatibility posture

- Prefer additive changes first:
  - adding optional fields in trace representations that do not alter the
    `Decision` sequence used by current hash/evaluation.
- Keep legacy decoding behavior for prior versions when feasible and deterministic.
- Do not remove existing step fields while older versions are still in circulation.
- Do not reinterpret historical data under a newer version without explicit
  migration support.

### 5.3 Field-addition rules

For a given format version:

- Add new fields only when:
  - they are clearly additive;
  - they do not affect existing hash behavior;
  - they are not read by the verifier in a way that changes acceptance.
- If a field change affects hash or decision replay, perform a format bump.

## 6) Proposed version discipline

- `V1` (current): current fields + semantics as implemented now.
- `V2+`: only introduced through explicit contract update with test coverage in:
  - engine deterministic/reproducibility tests
  - trace shape/ordering contract tests
  - audit verification expectations

## 7) Operational compatibility checklist (must remain true)

For any trace changes under current version:

- Same input + same profile + same engine config => same `trace.steps` list.
- Same input + same `format_version` => same audit hash.
- Deterministic test vectors must continue to assert step order and `rule_id`s.

## 8) Governance and review

- Any change to this contract must include:
  - explicit design note in this policy doc,
  - tests showing deterministic outcome for representative inputs,
  - reviewer sign-off that hash and verifier compatibility is preserved or versioned.

