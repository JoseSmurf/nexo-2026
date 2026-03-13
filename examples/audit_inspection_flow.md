# Audit Inspection Flow

NEXO already persists audit artifacts to JSONL. The lowest-risk inspection path is to read that persisted file directly.

Use:

```bash
bash scripts/inspect_audit_artifact.sh
```

To find an older artifact by `request_id`, `audit_hash`, or `record_hash`, use:

```bash
bash scripts/find_audit_artifact.sh <request_id-or-hash>
```

By default the helper reads:

- `NEXO_AUDIT_PATH` when set
- otherwise `logs/audit_records.jsonl`

What it does:

1. locates the persisted audit file
2. extracts the latest non-empty artifact
3. prints the main fields for inspection
4. writes that single artifact to a temporary `.jsonl`
5. prints the exact Zig command to verify it

Typical flow after running a demo:

```bash
bash scripts/demo_decision_flow.sh
bash scripts/inspect_audit_artifact.sh
```

You can also inspect a specific file path:

```bash
bash scripts/inspect_audit_artifact.sh /tmp/nexo-demo-audit-123456.jsonl
```

And you can restrict historical lookup to one file or archive directory:

```bash
bash scripts/find_audit_artifact.sh <request_id-or-hash> /tmp/nexo-demo-audit-123456.jsonl
bash scripts/find_audit_artifact.sh <request_id-or-hash> /tmp/nexo-audit-archive/
```

The verification step remains:

```bash
cd tools/zig
zig build run -- verify /tmp/nexo-audit-artifact-XXXXXX.jsonl
```

This closes the practical verification loop without changing the audit model or adding new runtime behavior.
