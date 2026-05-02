# AGENTS.md

## Project Context

NEXO is a deterministic, local-first decision and audit system.

Primary center of the repository:
signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification

Current trust boundaries:
- Rust is the trust core
- Zig is an independent offline verifier
- Julia is observer / analyst only, not trust core
- Bitcoin experiment docs are experimental and protocol-first
- mesh / P2P / Witness Layer are live edges, not product center

Do not conflate these roles.

## Current Priority

Current priority is to strengthen and clarify the central path:
- reproducibility of the main operational flow
- operator / reviewer legibility
- alignment between docs, scripts, tests, and actual behavior

Do not open new scope unless explicitly instructed.

## Protected Semantic Boundaries

Do not describe or implement NEXO as:
- consensus
- global truth
- CRDT runtime
- full sync runtime
- mining profitability system
- ASIC competitiveness layer

Do not promote experimental tracks to the center without explicit instruction.

## Repository Guidance

Use the repository docs as the human source of truth.
Especially relevant:
- `README.md`
- `docs/OPERATIONAL_FLOW.md`
- `docs/SECURITY_OPERATIONS.md`

For Bitcoin experimental work, treat these as the canonical starting point:
- `docs/NEXO_BITCOIN_LOGISTICS_EXPERIMENT_V0.md`
- `docs/NEXO_BITCOIN_LOGISTICS_EXPERIMENT_V0_TECHNICAL_MINIMUM.md`

Do not invent new contracts when existing docs already define them.

## Execution Rules

Prefer narrow, explicit tasks over broad refactors.

Before editing:
1. identify the exact surface being touched
2. confirm what is in scope
3. avoid touching unrelated files
4. preserve existing semantic boundaries

After editing:
1. run the relevant validation commands for the touched surface
2. report exactly what changed
3. report any uncertainty or unverified assumptions
4. stop after the requested scope is complete

## Surfaces and Rules

### Rust trust core
This is the center.
Protect:
- deterministic evaluate behavior
- final_decision semantics
- trace stability
- audit artifact behavior
- fail-closed validation paths

For auth, validation, and audit-related paths:
- prefer fail-closed behavior
- do not weaken checks to satisfy a task
- do not silently change security semantics

### Zig verifier
Treat as protected.
Do not modify Zig verifier logic, schema assumptions, or verification semantics unless explicitly instructed.

### Julia
Treat Julia as observer / analyst only.
Do not give Julia runtime authority.
Do not move Julia into the trust core.

### Bitcoin experiment
Treat as experimental and protocol-first.
Do not add implementation that implies runtime authority, profitability claims, mainnet claims, or mining superiority.
Do not mix Bitcoin experimental artifacts with the main compliance/audit path unless explicitly instructed.

### mesh / P2P / Witness Layer
Do not expand these areas unless explicitly instructed.
They are not the current coding priority.

## Contracts That Must Not Drift Silently

### Central audit path
Do not silently change:
- audit artifact structure
- trace ordering assumptions
- audit hash derivation semantics
- verifier expectations

### Experimental Bitcoin path
Do not silently change:
- `decision_cycle` semantics
- experimental JSONL contract
- meaning of `decision_intent`
- non-claims and experimental boundaries

## Interface / Operator Surface

Do not broaden the interface or add large dashboard-style surface unless explicitly instructed.

Narrow, center-aligned operator improvements are allowed only when clearly scoped and tied to:
- reproducibility
- inspection
- verification
- reduction of operator friction

## Tests and Validation

Run the relevant validation commands for the touched surface.

Core commands:
- `cargo test -q`
- `cargo test --features network -q`
- `cd tools/zig && zig build test`
- `julia --project=./julia julia/test/runtests.jl`

Rules:
- do not weaken or bypass tests to make a task pass
- test changes must be explicit and justified
- for trust-core or shared-contract changes, run Rust + Zig + Julia validations where relevant
- for docs-only changes, do not claim code validation unless commands were actually run

## Definition of Done

A task is done when:
- the requested scope is completed without opening lateral scope
- touched surfaces remain semantically consistent
- relevant validations were run and reported
- no protected contract drift occurred without explicit approval
- the diff is reviewable and narrow
- uncertainties are stated clearly instead of hidden

Additional rule:
If the task touches the central audit path, the result must remain compatible with offline verification expectations.

## Explicit Refusals

Refuse or stop and report when a task would:
- broaden mesh / P2P / Witness Layer without explicit instruction
- silently alter protected contracts
- connect experimental `decision_intent` to runtime authority
- inflate the interface beyond the current center
- mix the Bitcoin experiment with the compliance core without explicit approval
- introduce overclaiming language into docs or code comments

## Prompt Handling Preference

Work best from prompts that include:
- Goal
- Context
- Constraints
- Done when

When scope is ambiguous:
- ask for clarification only if necessary
- otherwise choose the narrowest reasonable interpretation
- do not expand the task on your own

## Reporting Format

At the end of each task, report:
1. what was changed
2. what was not changed
3. what validations were run
4. whether any uncertainty remains
