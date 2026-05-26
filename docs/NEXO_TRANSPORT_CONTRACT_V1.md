# NEXO Transport Contract v1

## Purpose

This document defines a minimal transport envelope for multi-platform delivery of NEXO requests.

It is transport-facing only.
It does not replace the central path:

`signed request -> deterministic evaluate -> final_decision -> trace -> audit artifact -> offline Zig verification`

## Scope

This contract is for moving request payloads across different carriers:
- HTTP
- mobile clients
- low-band / delayed links

It does not grant new runtime authority to transport layers.

## Canonical Envelope

Schema id:

`nexo_transport_envelope_v1`

Required fields:
- `schema`: must be `nexo_transport_envelope_v1`
- `request_id`: UUID v4
- `timestamp_utc_ms`: persistable UTC timestamp in milliseconds
- `nonce`: monotonic or unique sender nonce
- `key_id`: active signing key identifier
- `payload_hash`: lowercase hex BLAKE3-256 hash of canonical payload bytes
- `signature`: transport signature string (format is transport-specific, content is deterministic)

## Canonical Payload Hashing

Payload hash is computed over canonical JSON bytes:
- object keys sorted lexicographically at every nesting level
- arrays preserve original order
- numbers, booleans, null, and strings serialized deterministically

Hash algorithm:
- BLAKE3-256
- lowercase hex output with 64 chars

## Deterministic Signing Message

Envelope signing bytes are framed with length-prefixed parts in this order:
1. `schema`
2. `request_id`
3. `timestamp_utc_ms` (decimal string)
4. `nonce` (decimal string)
5. `key_id`
6. `payload_hash`

This preserves deterministic cross-platform signature input.

## Trust Boundary

- Rust trust core remains authoritative for decision and audit artifact generation.
- Zig remains authoritative for offline artifact verification.
- Transport adapters are delivery surfaces, not decision engines.

## Current Implementation Surface

Rust module:
- `src/transport/envelope.rs`

Public capabilities:
- envelope validation (fail-closed)
- canonical payload hashing
- deterministic signing message bytes
- payload verification against stored `payload_hash`

