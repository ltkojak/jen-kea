# Security Policy

Jen is a solo-maintained, open-source homelab project. There's no
dedicated security team and no paid support — but security issues are
taken seriously, and real vulnerabilities get fixed promptly once
reported.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**
A public issue discloses the problem to everyone, including anyone
running an un-patched copy, before a fix exists.

Instead, report privately via **GitHub's private vulnerability
reporting**: open the repository's **Security** tab → **Report a
vulnerability**. This creates a private advisory visible only to the
maintainer until a fix is ready.

If that's not available or convenient, open a regular GitHub issue with
only a high-level description ("possible auth bypass in X, details sent
privately") and ask for a way to share details privately, rather than
posting exploit details in the clear.

### What to include

- The affected version (or commit/tag)
- Steps to reproduce, or a proof-of-concept
- What you'd expect to happen vs. what actually happens
- Your assessment of impact/severity, if you have one — helpful but not
  required

### What to expect

- **Acknowledgment:** within a few days.
- **Fix timeline:** varies by severity and complexity. Straightforward
  fixes (a missing access check, a misconfigured decorator) typically
  ship within days. Anything requiring a schema change or broader
  refactor takes longer — you'll get a status update either way, not
  silence.
- **Credit:** reporters are credited in the CHANGELOG entry for the fix,
  unless you'd prefer to stay anonymous — say so in your report.
- **Disclosure:** coordinated. The fix ships first; details go in the
  CHANGELOG once a patched release is available, not before.

## Supported versions

Jen doesn't maintain long-term-support branches — there's one active
line, and only the latest released version gets security fixes. If
you're running something older, the fix is to upgrade, not to expect a
backport. Given the project's actual size and maintenance model, this is
the realistic policy rather than an aspirational one.

## Scope

In scope:
- The core Jen application (`jen/`)
- The bundled plugins (`plugins/ipam`, `plugins/network-discovery`)
- The install/update scripts (`install.sh`, self-update flow) and the
  release pipeline (`.github/workflows/`)

Out of scope:
- Vulnerabilities in Kea DHCP, MariaDB, or other third-party software
  Jen depends on or manages — report those to their own maintainers
- Issues that require an attacker to already have superadmin access to
  the box Jen itself runs on (that's already full control)
- Findings from automated scanners without a demonstrated, concrete
  impact — see the note below

## A note on how this project is actually audited

Jen doesn't have a professional external pentest the way a funded
project would. What it does have: periodic deep-dive audits (including
AI-assisted line-by-line code review) that have found and fixed real
issues — privilege-escalation bugs, missing authorization checks, broken
routes, SSRF-adjacent gaps, and more — documented candidly in
`CHANGELOG.md` rather than glossed over. `.github/bandit-baseline.json`
tracks the current set of static-analysis findings that have been
manually reviewed and accepted as safe (with reasoning); new findings
introduced after that baseline will fail CI.

That's a meaningfully lower bar than a project with a paid security team
and a completed third-party audit, and it's worth being honest about
that gap rather than overstating Jen's maturity. If you're evaluating
Jen for anything beyond a personal homelab, factor that in.
