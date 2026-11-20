# GForge Plan

Current goal: build a minimal installer for secure global Git hooks.

## MVP

1. Create a small command entry point - Done
2. Detect Git, platform, shell, and home directory - Done
3. Create a GForge-owned hooks directory - Done
4. Install initial security hooks - Done
5. Configure global `core.hooksPath` - Done
6. Add `verify`, `update`, and `uninstall` commands - Done
7. Add tests for repeated runs and safe uninstall - Done

## Suggested Commands

Final command names can change during implementation, but the product should support:

```bash
gforge install
gforge verify
gforge update
gforge uninstall
```

## Safety Requirements

- Re-running install must be safe.
- Verify must be read-only.
- Uninstall must remove only GForge-owned files/config.
- Git config changes must be backed up or clearly reversible.
- Hooks must avoid exposing secrets in logs.

## Detection Engine (v0.2)

The pre-commit hook delegates to a self-contained Node scanner (`src/scanner.js`,
installed as `~/.gforge/hooks/gforge-scan.mjs`):

- Provider rules (AWS, GitHub, Google, Slack, Stripe, npm, private keys, JWTs, …).
- Generic credential keyword=value detection (catches `DB_PASS=…`).
- Shannon-entropy detection for unnamed secrets (skips SHAs/UUIDs/lockfiles).
- Secret-file rules (`.env`, `id_rsa`, `*.p12`, keystores, …; templates allowed).
- Approved local secret sources (`~/.gforge/sources.json`): selected keys from
  repo-local JSON/properties files, cross-referenced like `.env` values. Home-only
  approvals, reads confined to the repo's real root, data-only parsing, size/value
  budgets. YAML/TOML deferred until a safe parser is chosen.
- Allowlist via `.gforgeignore` and inline `gforge:allow`.
- Optional gitleaks pass merged in when the binary is present.
- Redacted output (never prints matched values); fails closed on scan errors.

## Next Work

1. Initialize Git for this repository. Done.
2. Choose implementation stack. Done (Node ESM, zero deps).
3. Add packaged installation instructions. Done.
4. Expand hook coverage after the first safe baseline. Done (v0.2 engine above).
5. Prepare release validation. Done (published to npm as `gforge`).
6. Consider: configurable rule packs, per-org shared allowlists, secret history scan.
