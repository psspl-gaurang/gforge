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

## Decision: Server-Side Secret Enforcement (GH-128)

Status: research/design only. Nothing here authorizes building server tooling or
deploying to any Git server. Server-side work is outside the workstation-installer
scope in `AGENTS.md`; changing that needs explicit owner approval.

### Conclusion

- **Go/no-go:** **No-go** on building a GForge server adapter now. **Go** on
  recommending each host's native push protection, or an existing scanner run
  from a pre-receive hook, to orgs that need a remote enforcement boundary.
- Revisit only after #89 and #90 stabilize the benchmark and scanner, and only
  with an approved scope change.
- GForge stays the local, early-feedback layer; the server is the boundary.

### Options compared

| | Integrate existing protection | Minimal GForge pre-receive adapter |
| --- | --- | --- |
| What | Host-native push protection, or gitleaks/trufflehog as a pre-receive hook | Script reading `<old> <new> <ref>` and running GForge rules on new commits |
| Hosts | All major hosts, SaaS included | Only hosts that allow custom pre-receive hooks |
| Build cost | Configuration and docs | New entry point, range scan, server allowlist, packaging |
| Run cost | Vendor or existing tool maintainers | GForge maintainers, per host hook API |
| Detection parity | Different rules than local GForge | Same rules, minus `.env` cross-reference and `~/.gforge/rules.json` |

Integration wins: it covers SaaS hosts an adapter cannot reach and does not
turn GForge into a platform. An adapter only adds rule parity on self-hosted
servers, which does not justify the cost today.

### Supported Git hosts

| Host | Native push protection | Custom pre-receive hook |
| --- | --- | --- |
| github.com | Yes (push protection) | No |
| GitHub Enterprise Server | Yes | Yes (admin-managed) |
| gitlab.com | Yes (secret push protection) | No |
| GitLab self-managed | Yes | Yes (server hooks) |
| Bitbucket Cloud / Data Center | Secret scanning, varies by edition | Data Center only (plugins) |
| Gitea, Forgejo, plain git over SSH | No | Yes |

Feature availability and licensing tiers change; confirm with the vendor before
relying on a row. Any future adapter would target only the "Yes" rows in the
last column.

### Outgoing and reachable-history semantics

For any server check (native or adapter), the contract is:

- Scan only commits the push introduces: per ref,
  `git rev-list <new> --not --all`, evaluated before refs update.
- Ref deletion (`<new>` is all zeros): nothing to scan.
- New ref (`<old>` is all zeros): same rule, so a branch built on existing
  history scans only its new commits.
- Force-push or rebase: rewritten commits not reachable from any existing ref
  are new and get scanned; commits already on the server are not rescanned.
- Merges: scan content first introduced by the merge, matching `history.js`
  (`-m`).
- Annotated tags pointing at existing commits introduce no new content.
- Secrets already in reachable history are not blocked by a push check; that
  is the job of a one-off audit (`gforge history --all`) plus rotation.

### Resource limits

- Wall-clock budget set below the host's own hook timeout, which differs per
  host.
- Per-blob cap of 10 MB, matching `HISTORY_MAX_BLOB_BYTES`.
- Per-push caps on commits and bytes scanned.
- Bounded memory: read blobs in batches as `history.js` does (#134).
- No network calls and no optional unpinned binaries on the server.

### Failure policy

- Fail closed: a scanner error, timeout, or exceeded cap rejects the push with
  a redacted message that names the limit, never the value. This matches
  local behaviour ("never allowed through unscanned").
- Emergency fail-open is a central control only: time-boxed, recorded with
  approver and reason, and followed by a scan of the affected range.
- If a native host feature is unavailable, its own documented behaviour
  applies; record it in the org's runbook.

### Exceptions and response

- Exceptions are centrally approved and stored by the server owner, never in
  the repository. Repo `.gforgeignore`, `gforge:allow`, and `--no-verify` come
  from the pusher and are not trusted server-side.
- Key an exception by repository, commit SHA, path, and rule id. Never store
  the secret value or a hash of it: short or low-entropy secrets can be
  recovered from a hash by brute force.
- Each record holds requester, approver, reason, ticket, creation time, and
  expiry. On native hosts, use the host's recorded bypass flow.
- Response is rotation first: revoke and rotate the credential, record that it
  was rotated (not what it was), then decide whether a history rewrite is
  still worth doing. A rewrite removes the copy, not the exposure.

### Local prevention vs server enforcement

| | Local GForge hook | Server-enforced policy |
| --- | --- | --- |
| When | `pre-commit` (GForge ships no `pre-push` hook) | On push, before refs update |
| Bypass | `--no-verify`, missing or uninstalled hook | Not by the pusher; only via recorded central exception |
| Context | Index, worktree `.env` cross-reference, user rule pack | Pushed objects only; no worktree or user config |
| Exposure | Secret never enters a commit | Secret already in local history; must be rewritten before pushing again |
| Allowlist trust | Repo `.gforgeignore` honoured | Central list only |
| Feedback | Immediate, private | Later, at push time |

Both layers are needed: local hooks prevent most leaks cheaply; only the server
is an enforcement boundary.

### Compatibility

- Local GForge keeps working unchanged alongside any server check.
- Findings can differ because rule sets differ; an org that needs parity
  should align its server scanner's rules rather than expect GForge to
  reproduce them.

### Operational ownership

- The org's platform or security team owns server configuration, exception
  approval, the exception record, and incident response.
- GForge maintainers own only local hooks and this guidance; they operate no
  server and receive no findings.

### Test strategy

- For integration: each org validates on a test repository by pushing a known
  fake credential and confirming rejection, bypass recording, and the
  redacted message.
- If an adapter is ever approved: bare-repository fixture tests that run
  `git push` into a local bare repo with the hook installed, covering new ref,
  deletion, force-push, merge, tag, cap exceeded, timeout, and scanner error
  (fail closed). No real server needed.

### Maintenance cost

- Integration: low; keep this guidance current as host features change.
- Adapter: ongoing; tracking each host's hook API, timeouts, quarantine
  environment, and packaging, plus a second allowlist model. This is the main
  reason for no-go.

### Out of scope

Cloud provisioning, dashboards, general CI/CD orchestration, and deploying
anything to a Git server.
