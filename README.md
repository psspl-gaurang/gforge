# GForge

> **Governance Forge** — an engineering governance platform that helps teams forge
> consistent development standards through Git automation, quality gates, and
> developer tooling.

[![npm version](https://img.shields.io/npm/v/gforge.svg)](https://www.npmjs.com/package/gforge)
[![node](https://img.shields.io/node/v/gforge.svg)](https://nodejs.org)
[![platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-informational)](#cross-platform-support)
[![license](https://img.shields.io/npm/l/gforge.svg)](LICENSE)

GForge brings engineering standards to the one place every change passes through:
the commit. Its first governance capability is a **secret firewall** — a managed
global Git hook that stops credentials from ever entering your history, on every
repository, across your whole team.

---

## Why GForge

A single leaked API key, database password, or private key in a commit can mean a
production incident, a costly rotation, and a permanent entry in Git history.
Per-project hooks drift, get skipped, or are never installed. GForge makes the
guardrail **global, automatic, and uniform** for every developer and every repo —
so the standard is enforced by default, not by discipline.

## Features

- **Install once, protected everywhere.** Configures Git's global `core.hooksPath`,
  so the firewall applies to every repository on the machine.
- **Deep, layered detection**
  - **`.env` cross-reference** — blocks any staged file that hardcodes a real value
    from your git-ignored `.env` files (the classic "pasted a token out of `.env`"),
    including per-package `.env` files in a monorepo, not just the repo root.
  - **Provider rules** — 25+ credential shapes: AWS, Azure (Storage keys and
    Entra ID client secrets), GitHub/GitLab, Google, Slack, Stripe, Twilio,
    Vonage, SendGrid, npm, PyPI, OpenAI/Anthropic, PEM private keys, JWTs,
    database URLs, and more.
  - **Generic secrets** — any credential keyword assigned to a hardcoded value
    (`DB_PASSWORD=…`, `password: "…"`, `api_key = "…"`).
  - **Entropy** — high-entropy strings that carry no recognizable name.
- **Low noise by design.** References like `process.env.DB_PASSWORD`, placeholders,
  and env templates (`.env.example`) are not flagged, so correct code keeps flowing.
- **Never leaks the secret.** Reports only file paths, line numbers, and rule names —
  the matched value is never printed.
- **Encoding-aware.** Handles UTF‑8, UTF‑16, and BOM-prefixed files (e.g. those
  written by PowerShell) so nothing slips through as "binary".
- **Zero-config upkeep.** Self-installing on `npm i -g`, self-upgrading, and
  auto-updating — every workstation stays current on its own.
- **gitleaks turbo (optional).** If [gitleaks](https://github.com/gitleaks/gitleaks)
  is on `PATH`, GForge runs it too and merges the findings.
- **Cross-platform, zero runtime dependencies.**

## Requirements

- **Node.js** 20 or newer
- **Git**

## Installation

```bash
npm install -g gforge
```

That's the whole setup — installing globally configures the hooks for every
repository automatically. From the next commit onward, changes are scanned for
secrets. Confirm anytime with:

```bash
gforge verify
```

### If you install with `--ignore-scripts`

`npm install --ignore-scripts` is a reasonable supply-chain precaution, and many
CI pipelines and lockfile-strict setups enable it globally. It also skips
GForge's `postinstall` step — which is the step that installs the git hooks.

npm gives no indication that it skipped anything, so the result is the failure
mode GForge exists to prevent: the `gforge` command is on your PATH and looks
installed, but **no hook is registered and no commit is ever scanned**.

If you use that flag, run the install step yourself afterwards:

```bash
npm install -g gforge --ignore-scripts
gforge install     # registers the hooks that postinstall would have
```

`gforge verify` reports this state explicitly — it exits non-zero and names
`not-installed` — so it is worth running once after any install, and worth
wiring into CI if your pipeline relies on GForge:

```bash
gforge verify      # exit 0 only when scanning is actually active
```

## Quick start

```bash
# See the current status of your workstation
gforge verify

# Try it — a hardcoded secret is blocked before it can be committed
echo 'DB_PASSWORD=S3cr3t-Value-123' > config.txt
git add config.txt
git commit -m "add config"
# → GForge blocks the commit and names config.txt (the value is never printed)
```

## Commands

```bash
gforge <command> [--force]
```

| Command | Description |
| --- | --- |
| `gforge install` | Upgrade to the latest version (if any) and install the global hooks. |
| `gforge verify` | Read-only health check of the environment, the installed hooks, and (inside a repo) the `.env` files the cross-reference can see. |
| `gforge update` | Upgrade to the latest version (if any) and refresh the hooks. |
| `gforge uninstall` | Remove GForge-owned hooks and restore your previous Git config. |
| `gforge version` | Print the installed version. |
| `gforge help` | Print usage. |

`--force` (with `install`/`update`) reinstalls the latest release even if you are
already on it. GForge never downgrades below your installed version.

## How detection works

The `pre-commit` hook scans only the files staged for the current commit — not the
whole repository — and blocks the commit if any appear to contain a secret. It
reports file paths, line numbers, and rule names, and **never prints the matched
value**. Detection runs several layers in order:

1. **`.env` cross-reference** — the highest-precision signal: values read (in
   memory only) from your git-ignored `.env` files, matched verbatim in staged code.
   Every `.env` in the repository is used, not only the root one, so a monorepo's
   `server/.env` and `client/.env` are covered. Template files are skipped, and
   the search prunes vendored and build directories (`node_modules`, `dist`, …).
   `gforge verify` prints which `.env` files this layer found.
2. **Provider rules** — fixed credential shapes for the major cloud and SaaS providers.
3. **Generic secrets** — credential keywords assigned to a hardcoded value; smart
   enough to ignore `process.env.*`, function calls, `${VAR}` interpolation, and
   obvious placeholders.
4. **Entropy** — unnamed high-entropy strings, tuned to skip Git SHAs, UUIDs,
   lockfiles, and file paths (a path is scored per segment, so a long import path
   is not mistaken for a base64 blob).
5. **Secret files** — `.env` (and `.env.*` unless its final extension marks it a
   template: `.example`, `.sample`, `.template`, `.dist`, `.defaults`, `.tpl`,
   `.test` — so `.env.cron-backfill.example` is treated as a template too),
   `id_rsa`, `*.p12`/`*.pfx`,
   keystores, `.git-credentials`, `.netrc`, and more.

Detection is best-effort and complements — not replaces — good secret hygiene.

### Paths the heuristic layers skip

A credential keyword followed by a colon is the *normal* shape of a translation
entry (`"Password": "Passwort"`) and of a documentation example, so layers 3 and 4
— the two heuristic ones — are skipped by default in:

| Kind | Matched by |
| --- | --- |
| Translations / i18n | a `i18n`, `l10n`, `intl`, `translation(s)`, `locale(s)`, `lang(s)` directory |
| Documentation | a `doc(s)`, `document(s)`, `documentation` directory, or a `.md`/`.mdx`/`.rst`/`.adoc` file |
| Generated output | a `dist`, `build`, `out`, `coverage`, `vendor`, `node_modules`, `target`, `obj`, `.next`, `.nuxt` … directory |
| Lockfiles & bundles | `package-lock.json`, `yarn.lock`, `go.sum`, … and `*.min.js`, `*.min.css`, `*.map` |

**Layers 1, 2 and 5 always run, everywhere.** A real AWS, Stripe, GitHub, or
Google credential, a private key, a `.env` file, or a value copied out of your
`.env` is still blocked inside `dist/`, a README, or a translation catalogue —
only the noisy keyword and entropy heuristics are quietened. Set
`GFORGE_NO_DEFAULT_EXCLUDES=1` to scan every path with every layer.

## Managing false positives

Maximum coverage occasionally flags something safe. Three escape hatches:

- **Inline:** add a `gforge:allow` (or `gitleaks:allow`) comment on the line.
- **Per-repo:** add a path or pattern to a `.gforgeignore` file at the repo root
  (a `.gitleaksignore` is also honored):

  ```gitignore
  # .gforgeignore
  test/fixtures/
  ^docs/sample-config\.md$
  ```

- **One-off:** bypass a single commit with `git commit --no-verify`.

Each non-comment line is treated as a regular expression, falling back to a
plain substring match when it is not valid regex syntax.

Because these files live in the repository, cloning an untrusted repo means
inheriting its allowlist. Two limits apply so that a hostile or simply careless
entry cannot stall your commits: patterns are capped at 200 characters, and
patterns with nested unbounded quantifiers (`(a+)+`, `(a*)*`) are refused —
those backtrack catastrophically and would otherwise hang the hook. A refused
pattern falls back to substring matching, so it loses its allowlisting power
rather than silently hiding files.

## Staying up to date

`gforge update` upgrades the package to the latest published release and refreshes
the hook — no manual `npm install` needed. GForge also keeps itself current on its
own: at most once a day it checks for a new version in a detached background
process (it never delays or blocks a commit), installs it, and prints a one-line
notice on commit:

```
gforge: v1.2.0 is available (you have v1.1.0). Run: gforge update
```

## Configuration

Behavior is controlled through the environment variables below.

GForge keeps its own state under `~/.gforge` — the managed hooks, an install
state file, and an update-check cache. Those are managed for you by
`install` / `update` / `uninstall` and are not meant to be edited by hand, so
there is nothing to set up before the table below applies.

| Variable | Effect |
| --- | --- |
| `GFORGE_AUTO_UPDATE=0` | Notify only; do not auto-install new versions (default: auto-install on). |
| `GFORGE_NO_SELF_UPDATE=1` | Skip the npm self-upgrade in `install`/`update` (CI / air-gapped). |
| `GFORGE_SKIP_POSTINSTALL=1` | Skip automatic hook setup during `npm install`. |
| `GFORGE_NODE=/path/to/node` | Pin the Node.js runtime the hook uses. |
| `GFORGE_NO_DEFAULT_EXCLUDES=1` | Run the heuristic layers on every path, including translations, docs, and build output. |

If a repository, or the system itself, already defines its own `core.hooksPath`
(e.g. Husky or lefthook, or an org policy pushed via `GIT_CONFIG_SYSTEM`), the
automatic `npm install` setup does not override it — global config outranks
system config in git's own precedence, so writing a global value would silently
shadow a system-level one even without touching it directly, and the automatic
setup checks for that too. Run `gforge install` to have GForge take over
explicitly. Automatic setup is skipped in CI (`CI` environment variable).

A **classic, hand-written** `.git/hooks/pre-commit` script (one that predates
GForge and isn't itself managed by a tool like Husky) is a different case: git
only ever consults one `core.hooksPath` location, so once GForge's global path
is active, a script sitting directly in a repository's own `hooks/` directory
goes dormant — there's no config value there for GForge to detect and preserve.
`gforge verify` checks for this and reports a `classic-hook-shadowed` warning
when it finds one, so it doesn't fail silently.

## Cross-platform support

| Platform | Shells |
| --- | --- |
| macOS | Bash, Zsh |
| Linux | Bash |
| Windows | Git Bash, WSL, PowerShell (via Git for Windows) |

The scanner runs on Node.js; the hook is a small POSIX shell shim that locates Node
robustly (including on Git for Windows) and fails closed if it cannot — a commit is
never allowed through unscanned.

## What GForge changes on your machine

GForge is transparent and fully reversible. It touches only your **global** Git
config and a single directory in your home folder:

- `~/.gforge/hooks/` — the managed hook and scanner (`core.hooksPath` points here).
- `~/.gforge/state.json` — records your previous `core.hooksPath` so `uninstall`
  can restore it.

`gforge uninstall` removes GForge-owned files and restores your prior configuration.

## Programmatic use

GForge is primarily a CLI, but the command runner is exposed for scripting:

```js
import { runCli } from "gforge";

const result = await runCli(["verify"], { stdout: process.stdout, stderr: process.stderr });
process.exit(result.exitCode);
```

## Roadmap

The secret firewall is the first governance capability. Planned directions for the
platform include:

- Additional commit-time quality gates (commit message and branch conventions,
  large-file and merge-conflict guards).
- Shareable, versioned org policy packs.
- Reporting and audit for governance coverage across a team.

## Contributing

Issues and pull requests are welcome at the
[GitHub repository](https://github.com/psspl-gaurang/gforge). Please run
`npm test` before submitting, keep changes focused, and preserve the Apache-2.0
license header and `NOTICE`.

```bash
npm test               # run the test suite
npm run package:check  # inspect the publishable package contents
```

## 👥 Contributors

Thanks to the following members who contributing to **GForge**:

<a href="https://github.com/psspl-gaurang/gforge/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=psspl-gaurang/gforge" alt="Contributors List" />
</a>

## Security

To report a vulnerability, follow the process in [SECURITY.md](SECURITY.md). Do not
open a public issue for security reports, and never include real secrets in a report.

## License

Licensed under the [Apache License 2.0](LICENSE). Please preserve the `NOTICE` file
when redistributing.
