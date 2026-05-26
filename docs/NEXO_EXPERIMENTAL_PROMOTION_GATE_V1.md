# NEXO Experimental Promotion Gate v1

Status: policy guard for experimental tracks.

This gate prevents silent promotion of experimental/runtime-adjacent work into NEXO trust authority.

## Scope

Applies to:

- `orchestrator` experimental path
- `provider_orchestrator` shadow path
- mesh/P2P/Witness/Bitcoin experimental tracks

Does not modify central trust-core semantics.

## Promotion Criteria (all required)

1. Contract explicitness:
- Input/output schema is documented.
- Hash/integrity semantics are documented.
- Failure behavior is fail-closed and explicit.

2. Determinism:
- Same input produces same semantic decision output.
- Tie-break behavior is deterministic and documented.

3. Evidence compatibility:
- Experimental artifacts do not redefine central `audit_hash` semantics.
- Zig verifier expectations for core artifacts remain unchanged.

4. Security posture:
- Threats are mapped to controls and checks.
- Downgrade paths are explicit and rejected by default.

5. Operational legibility:
- One-command operator path exists.
- Failure messages are actionable.
- Rollback/disabling switch exists and is documented.

6. Validation gate:
- Rust tests for touched surface pass.
- Formatter/check gates pass.
- README counters/docs consistency remain accurate.

## Non-promotion triggers (stop and review)

- Any change that alters `final_decision` authority path without explicit approval.
- Any change that mixes experimental artifacts into core audit acceptance.
- Any claim of consensus/global truth/full-sync authority introduced by experimental modules.

## Current state

- `orchestrator`: experimental helper path only.
- `provider_orchestrator`: experimental shadow path only.
- Core authority remains:

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification`

## Related docs

- [NEXO Reviewer Start Here](NEXO_REVIEWER_START_HERE.md)
- [NEXO Cross-Language Evidence Boundary](NEXO_CROSS_LANGUAGE_EVIDENCE_BOUNDARY.md)
- [Orchestrator Experiment Gate V0](ORCHESTRATOR_EXPERIMENT_GATE_V0.md)
- [Provider Orchestrator Shadow V0](PROVIDER_ORCHESTRATOR_SHADOW_V0.md)
