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

## Credential Verification (GH-127): Decision Record

Question: would optional live verification (asking a provider whether a detected
credential is active) materially improve triage without weakening offline-first
prevention?

### Status

- Decision: **no-go for implementation now; design only.**
- No live credentials, provider requests, or verification code are authorized.
  Transmitting a detected credential to a provider needs explicit maintainer
  approval after the gates below.
- Gates before any implementation issue is opened:
  1. A labelled benchmark exists (none does today) and shows the benefit below.
  2. A private security review of this record is complete.
  3. The maintainer explicitly approves transmission to the named providers.
- No-go remains a valid final outcome.

### Invariants (apply to any future design)

- Offline detection stays the default and the only input to blocking. The
  pre-commit decision (`findings.length > 0 || gitleaks.leaks` in `runPreCommit`)
  must not read verification state.
- A finding is never allowed because verification failed, timed out, was
  unavailable, or reported "inactive". Allowing stays `.gforgeignore` or
  `gforge:allow` only.
- No network call on the commit path. The pre-commit hook never verifies;
  candidate home is an explicit flag on `gforge history`.
- `gforge verify` stays read-only and never verifies credentials.

### Result states and benefit measurement

Every finding gets exactly one state; all still block:

| State | Meaning |
| ----- | ------- |
| `detected` | Offline match; no verification requested (default). |
| `verified-active` | Provider confirmed the credential works. |
| `verified-inactive` | Provider rejected it (revoked, expired, fake). |
| `unverified` | Not attempted: not opted in, rule not eligible, or cap reached. |
| `unknown` | Network error, timeout, rate limit, unexpected response. |

Benchmark requirements: labelled true/false positives per `ruleId`, synthetic
or provider-issued test values only, run offline through `scanStaged` and
`scanHistory`. Benefit = share of findings per eligible provider moved to a
definitive state (`verified-*`) and the triage time saved, weighed against
request count, `unknown` rate, and side effects. Go needs a material gain on
eligible rules; if eligible rules are a small share of real findings, no-go.

### Initial provider set (if ever approved)

Only built-in rules with a documented, read-only identity endpoint on a fixed
public host:

| Rule IDs | Endpoint | Why |
| -------- | -------- | --- |
| `github-pat`, `github-fine-grained-pat` | `GET https://api.github.com/user` | Most common leak; read-only; documented. |
| `gitlab-pat` | `GET https://gitlab.com/api/v4/personal_access_tokens/self` | Read-only self-lookup; gitlab.com only. |
| `slack-token` | `POST https://slack.com/api/auth.test` | Purpose-built token check. |

Excluded:

- AWS keys: the common honeytoken format, and STS calls are logged to the key
  owner's account.
- Stripe and other payment or billing keys: account impact on a live financial
  account.
- Self-hosted hosts (GitLab self-managed, Vault, Grafana, Atlassian, and so on):
  the destination would come from the repository.
- Rules with no provider: `jwt`, `basic-auth-url`, `private-key`, `slack-webhook`
  (verifying would post a message), generic keyword, entropy, secret files,
  custom rules, and gitleaks results.

### Network policy

- Hardcoded HTTPS allowlist of exact hosts and paths in the shipped scanner;
  never read from a repository, `.gforgeignore`, `rules.json`, env, or settings.
- Endpoint validation: the URL is built only from the allowlist; refuse anything
  else before any connection.
- Redirects refused (`redirect: "error"`); a redirect gives `unknown`.
- TLS only, with default certificate validation; registry and proxy overrides
  never apply.
- Timeouts: 5 s per request (AbortController, as in the update check) and a
  30 s overall budget, after which remaining findings are `unverified`.
- Rate limits: at most 1 request per provider per second, 20 per run, no retries,
  and stop at that provider on HTTP 429 or 403. Each distinct value is verified
  once per run.
- Credential sent only in the provider's documented auth header; never in a URL
  or query string.

### Opt-in

- Off by default, per invocation only, for example `gforge history --verify`.
- No persistent setting, env variable, or CI default until separately approved.
- A non-interactive run (no TTY or `CI` set) never verifies implicitly.
- Before the first request, the CLI states which providers will be contacted.

### Output redaction

- Never print, log, cache, or persist the credential, any part of it, or a
  provider response body.
- Output only file, line, `ruleId`, and state. Error messages must not echo
  request headers or URLs that carry data.

### Side effects assessed

- Honeytokens: any request to a canary fires its alert and names the caller's
  IP, which is why AWS is excluded and verification is never automatic.
- Provider audit: requests show up in the token owner's audit or security logs
  and may trigger GitHub or Slack security notifications or automated revocation.
- Account impact: failed attempts can count toward lockout or abuse heuristics,
  hence no retries and per-run caps.
- Privacy and legal: the credential leaves the machine and may belong to someone
  else; using another party's credential can be unauthorized access. This is
  the main reason for the per-run opt-in.
- Air-gapped: every eligible finding becomes `unknown`, blocking is unchanged,
  and no delay beyond the timeout budget.

### Threat model

| Threat | Mitigation |
| ------ | ---------- |
| Malicious repo steers requests to its own host | Hardcoded allowlist; no repo-defined destinations. |
| MITM or DNS spoofing captures the credential | HTTPS with certificate validation; no redirects or proxy overrides. |
| Compromised release turns the verifier into an exfiltration channel | Allowlist in reviewed source; guard test that only approved hosts are fetched; existing update quarantine. |
| Leaks through logs, errors, or timing output | Redaction rules; tests on stdout, stderr, and the update log. |
| User trusts `verified-inactive` and commits anyway | Verification never changes blocking; this is enforced by tests. |
| Slow or hostile endpoint stalls the tool | Per-request timeout and overall budget. |

### Maintenance cost

- Provider endpoints, auth schemes, and response shapes drift, so each provider
  needs fixtures and periodic re-checks.
- Each provider adds per-release review of the allowlist and redaction.
- It widens the network surface of a currently offline, zero-dependency hook
  engine and grows the self-contained scanner file.

### Tests required before implementation

- Every state (including `verified-inactive` and `unknown`) still blocks.
- No opt-in means zero network calls; the pre-commit hook never makes any.
- Non-allowlisted hosts and redirects are refused before connecting.
- A timeout or network error gives `unknown` and the run still blocks.
- The credential value never appears in stdout, stderr, or logs.
- Air-gapped runs give the same findings and exit code as offline runs.
- Rate caps and the stop-on-429 behaviour are honoured, and there are no retries.
- All tests use mocked `fetch`; never live credentials or provider hosts.

### Open questions for the private security review

- Is `gforge history --verify` the only acceptable entry point?
- Should `verified-inactive` be shown at all, given the risk of over-trust?
- Is the GitHub, GitLab.com, and Slack set acceptable under each provider's terms?

## Next Work

1. Initialize Git for this repository. Done.
2. Choose implementation stack. Done (Node ESM, zero deps).
3. Add packaged installation instructions. Done.
4. Expand hook coverage after the first safe baseline. Done (v0.2 engine above).
5. Prepare release validation. Done (published to npm as `gforge`).
6. Consider: configurable rule packs, per-org shared allowlists, secret history scan.
7. Credential verification (GH-127): design only, gated on benchmark, private
   security review, and maintainer approval. See decision record above.
