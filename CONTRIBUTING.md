# Contributing

Thanks for contributing to NEXO 2026.

## Branch Policy

- `main` is protected/releasable.
- Open changes in feature branches:
  - `feat/<topic>`
  - `fix/<topic>`
  - `chore/<topic>`
- Keep PRs scoped and small when possible.

## How to Open a PR

1. Sync with latest `main`.
2. Create a branch from `main`.
3. Make changes with clear commit messages.
4. Open PR with:
   - context/problem
   - what changed
   - risk/impact
   - validation evidence (test output, benchmark output, or screenshots)

## Local Validation Before Submit

Run before opening PR:

```bash
cargo fmt
cargo test -q
```

For API/performance/security-related changes, also run:

```bash
cargo run --release --bin perf_budget
cargo run --release --bin load_test
```

For audit verifier changes:

```bash
cd tools/zig
zig build test
zig build run -- verify ../../fixtures/audit_sample.jsonl
```

## Security Notes

- Never commit secrets.
- Use environment variables for keys (`NEXO_HMAC_SECRET`, etc).
- Do not log secret values.
- Preserve deterministic behavior in the core engine.

## Style Expectations

- Keep contracts explicit and documented.
- Prefer deterministic and auditable logic over implicit behavior.
- Add or update tests when behavior changes.
