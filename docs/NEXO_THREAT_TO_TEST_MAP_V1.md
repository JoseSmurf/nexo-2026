# NEXO Threat-to-Test Map v1

Status: reviewer/operator mapping document.

This document links central threats to concrete controls and reproducible validation commands.
It is intentionally scoped to the current center path:

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification`

## Threat-to-Test Map

| Threat | Primary control | Reproducible check |
| --- | --- | --- |
| unsigned or forged request accepted | fail-closed HMAC + key-id validation | `cargo test -q request_without_signature_returns_401` and `cargo test -q request_with_wrong_signature_returns_401` |
| replay request accepted | request-id replay protection with conflict response | `cargo test -q request_id_reused_returns_409` and `cargo test -q same_request_id_after_audit_lock_failure_returns_replay_conflict` |
| stale timestamp accepted | timestamp window validation | `cargo test -q request_with_expired_timestamp_returns_408` |
| duplicate auth headers bypass validation | duplicate header rejection | `cargo test -q duplicate_x_signature_header_is_rejected` and `cargo test -q duplicate_x_request_id_header_is_rejected` |
| decision trace drift for same input | deterministic evaluation with stable trace semantics | `cargo test -q evaluate_reproducible_for_identical_input` and `cargo test -q decision_trace_contract_is_stable_golden` |
| final_decision classification drift | explicit Approved/Flagged/Blocked contracts | `cargo test -q aml_trace_contract_approved`, `cargo test -q aml_trace_contract_flagged`, `cargo test -q aml_trace_contract_blocked` |
| persisted artifact tampering undetected | offline Zig verifier recomputes hash and detects mismatch | `bash scripts/demo_tampering_trace.sh` |
| record chain continuity drift | optional `--require-chain` continuity checks | `bash scripts/demo_record_chain_verification.sh` |
| append ambiguity when lock exists | fail-closed append lock behavior | `cargo test -q evaluate_fails_closed_when_audit_lock_preexists_and_does_not_append` |
| malformed persisted tail repaired silently | fail-closed malformed-tail behavior | `cargo test -q evaluate_fails_closed_with_malformed_audit_tail_and_does_not_repair` |

## Operator Notes

- Run checks from repository root.
- Preserve generated artifact paths/logs when collecting reviewer evidence.
- Experimental surfaces (`orchestrator`, `provider_orchestrator`, mesh/P2P tracks) do not redefine central authority contracts.

## Related docs

- [NEXO Threat Model](NEXO_THREAT_MODEL.md)
- [NEXO Test Matrix](NEXO_TEST_MATRIX.md)
- [NEXO Reproducibility Report](NEXO_REPRODUCIBILITY_REPORT.md)
- [NEXO Evidence Pack Demo v1](NEXO_EVIDENCE_PACK_DEMO_V1.md)
