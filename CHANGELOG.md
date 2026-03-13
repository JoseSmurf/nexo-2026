# Changelog

## v0.2.0 - Draft

### Included in first public release
- Deterministic `POST /evaluate` API flow with signed requests.
- Stable Rust decision engine with ordered rule execution and deterministic `trace`.
- Deterministic audit hashing with explicit `hash_algo`.
- Audit record persistence to JSONL with record chaining fields.
- Offline Zig verifier for forensic validation of audit records.
- Release documentation for local end-to-end verification flow.

### Intentionally deferred
- Distributed/P2P features as part of the public release contract.
- Ruby dashboard as the primary release surface.
- Julia historical observation workflow as a release requirement.
- Secret-provider and deployment breadth as part of release acceptance.

## Unreleased

### Hash Contract Migration
- Rust runtime policy keeps emitting: `blake3`, `shake256-256`, `shake256-384`, `shake256-512`, `shake256-512+blake3-256`.
- `hash_algo = "sha3-256"` is treated as legacy (historical records only), not emitted by current API policy.
- Zig verifier now supports optional legacy verification for `sha3-256` behind env flag:
  - `NEXO_ZIG_LEGACY_SHA3_256=1`
  - default behavior remains fail-closed (reject legacy algo).

### Tests
- Added Zig test that confirms `sha3-256` is rejected by default and accepted only when legacy support is explicitly enabled.
