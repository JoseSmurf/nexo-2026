# NEXO Map Gaps v1

Status: orientation map for next engineering cycles.

This document does not change trust semantics.
It helps prioritize what still matters most after current implementation progress.

## Current center (kept intact)

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification`

## What is already strong

- Deterministic Rust decision core with stable trace contracts.
- Offline Zig verification path with tamper detection.
- Threat model, reproducibility report, and test matrix published.
- Experimental orchestrators isolated from central authority path.
- One-command evidence-pack workflow exists.

## Highest-priority remaining gaps

1. Cross-platform operational parity:
- Bash/PowerShell/WSL execution parity is improved, but still operationally fragile under mixed host setups.

2. Experimental artifact lifecycle:
- Provider/orchestrator artifacts need explicit retention/rotation policy and version headers to reduce mixed-schema history ambiguity.

3. Continuous provider evidence:
- Provider orchestration currently supports deterministic selection + offline verification.
- Missing: automated long-window cycle report with fixed SLO thresholds as release evidence.

4. Incident ergonomics:
- Core fail-closed behavior exists.
- Missing: stronger operator-facing “what to do now” summaries auto-generated on failure paths.

5. Governance for promotion:
- Experimental promotion gate exists.
- Missing: strict CI gate that blocks promotion claims unless required evidence artifacts are present.

## Non-goals (must remain explicit)

- Do not reframe NEXO as consensus/global truth/CRDT/full-sync runtime.
- Do not promote experimental network/provider selection into trust authority without explicit approval.
- Do not mix Bitcoin experiment semantics into core audit acceptance.

## Suggested next sequence

1. Add artifact version tags + retention helper for experimental JSONL logs.
2. Add cycle-runner report with SLO pass/fail summary for provider orchestration.
3. Add CI check for experimental docs/runbook consistency.
4. Add operator incident summary templates for common fail-closed outcomes.
