# Security Policy

## Supported Versions

GForge is published as `0.x` releases and has not reached 1.0, so there are no
parallel maintenance lines: fixes go to the next release rather than being
backported.

| Version | Supported |
| ------- | --------- |
| Latest published release | Yes |
| Any earlier `0.x` release | No — upgrade with `gforge update` |

Deliberately stated as "latest published release" rather than a pinned number.
A hardcoded version is what made this section wrong in the first place, and it
would go stale again on the next publish.

Most installations upgrade themselves: auto-update is on by default, so in
practice a workstation reaches the latest release without anyone doing anything.
It can be disabled with `GFORGE_AUTO_UPDATE=0`, in which case upgrading is
manual. `gforge verify` flags an installed hook engine that has fallen out of
step with the installed package.

## Reporting a Vulnerability

Report security issues privately by emailing:

```text
Gaurang Joshi <gaurangnil@gmail.com>
```

Do not open a public issue for vulnerabilities.

Include:

- A clear description of the issue.
- Steps to reproduce when safe.
- Affected files, commands, or hook behavior.
- Any known impact.

Do not include real secrets, tokens, passwords, private keys, or customer data in the report.

## Security Scope

GForge manages global Git hook configuration. Security-sensitive areas include:

- Hook installation and update behavior.
- Global Git configuration changes.
- Secret detection logic.
- Logging output.
- Uninstall behavior.

## Response Expectations

The maintainer will review valid reports, ask for clarification if needed, and prioritize fixes based on risk and project maturity.
