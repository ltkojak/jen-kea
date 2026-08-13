# Jen — Architecture & Threat Model

This document exists because a lot of Jen's security-relevant design
decisions only ever lived in CHANGELOG entries and one very long audit
conversation. Writing them down once means the next person touching this
code — future maintainer, contributor, or another audit session — starts
from the actual reasoning instead of rediscovering it from scratch.

## 1. System overview

Jen is a single Flask application, deployed as one process (`run.py`),
that manages Kea DHCP servers directly:

```
┌─────────────┐         MySQL (jen_db)        ┌──────────────┐
│   Browser    │◄──────────────────────────────│   MariaDB    │
│  (HTMX UI)   │         MySQL (kea_db)         │ (jen + kea)  │
└──────┬───────┘                                └──────────────┘
       │ HTTPS
       ▼
┌─────────────────┐   Kea Control Agent API   ┌───────────────┐
│   Jen (Flask)    │──────────────────────────►│  Kea DHCP4    │
│   run.py         │   SSH (config push,       │  Server(s)    │
│   www-data user   │   restarts, log reads)    │               │
└─────────────────┘◄──────────────────────────┘└───────────────┘
```

Deliberately **not** an agent-based architecture. There's no separate
process running on each Kea server the way Stork's `stork-agent` works —
Jen connects out to each Kea server directly, either via the Kea Control
Agent's HTTP API (for reads/live status) or via SSH (for config file
changes and service restarts). This is a real, considered tradeoff:

- **Why:** a single-process, no-agent design is dramatically simpler to
  deploy and maintain for a solo admin managing a handful of servers. No
  agent to install/update/monitor on each Kea box, no separate
  agent-to-server protocol to secure.
- **The cost:** it doesn't scale to fleets the way an agent architecture
  does, and config changes go through SSH + generated scripts rather
  than Kea's native config-management hooks. See §3.3 below for how
  that's mitigated.

Jen's own data (users, sessions, audit log, alerts, devices, plugin
state) lives in `jen_db`. Kea's own data (leases, reservations, DHCP
options) lives in `kea_db` — a separate MySQL database that Kea itself
owns the schema for. In production these are typically two different
databases (possibly on different hosts); Jen never modifies Kea's schema,
only its data, and only through the same tables Kea's own tooling would.

## 2. Trust model summary

Jen has three tiers of user: `viewer` (read-only), `admin` (day-to-day
management, scoped to assigned subnets when subnet restrictions are
configured), and `superadmin` (full access, including database
export/import, plugin management, and system settings). The permission
matrix is enforced primarily through two decorators —
`@login_required` and `@_admin_required`/`@_superadmin_required` — plus,
for anything subnet-scoped, `current_user.can_access_subnet()` /
`add_subnet_restriction()` checked per-query.

That subnet-restriction layer has been the single most common source of
real bugs found across this project's audit history — not because the
underlying mechanism is flawed, but because it has to be applied
*consistently* by every route and secondary endpoint that touches
subnet-scoped data, and new endpoints have repeatedly been added without
it. If you're adding a new route that touches leases, reservations,
devices, or anything else tied to a subnet: apply subnet restriction
there too, even if it feels obviously admin-only. It's the checklist
item that has actually mattered in practice.

## 3. Deliberate trust boundaries

These are places where Jen makes a conscious security tradeoff rather
than an oversight. Documenting them here so future changes are informed
decisions, not accidental regressions.

### 3.1 The self-update sudoers grant

`jen-sudoers` grants `www-data` (the user Jen runs as) passwordless
`sudo` execution of `/bin/bash /tmp/jen_update_install.sh` — a fixed,
predictable path. The sudoers rule only checks the *path*, not the file's
*content*.

**Why this is safe as designed:** the self-update flow that writes that
file first downloads a release tarball, verifies its checksum against
the pinned `ltkojak/jen-kea` GitHub repo via the GitHub API, and only
then writes and `chmod`s the installer script. The trust boundary is the
pinned repo + checksum verification, not the sudoers rule itself.

**What this means for any future change:** if Jen ever grows *any* other
way for `www-data` to write attacker-influenced content to exactly that
path (a file-upload bug, a path-traversal bug reachable from an HTTP
request), that becomes an instant root exploit, because the sudoers rule
has no way to tell the difference between "content the self-update flow
verified" and "content something else wrote." Any code review touching
file-write paths should ask: could this ever write to
`/tmp/jen_update_install.sh`?

### 3.2 SSH host-key verification (trust-on-first-use)

Every outbound SSH connection Jen makes (`subnets.py`, `ddns.py`,
`servers.py`) uses trust-on-first-use: the first connection to a new
host is accepted automatically and the key is persisted
(`/etc/jen/ssh/known_hosts`), but a *changed* key on a later connection
to a previously-known host is rejected. This is implemented via two
shared helpers in `jen/services/auth.py` — `ssh_cli_opts()` (for plain
`ssh` CLI calls, using `StrictHostKeyChecking=accept-new`) and
`paramiko_load_known_hosts()` (for paramiko-based connections, pairing
`AutoAddPolicy()` with an explicit load + `save_host_keys()` after
connecting).

**Why not strict verification with pre-shared keys:** this would require
an out-of-band step to get each Kea server's host key onto Jen before
first use, which is real setup friction for a homelab tool whose main
value proposition is being easy to stand up. TOFU is the standard,
accepted middle ground (it's what `ssh` itself defaults to for a human
operator).

**What this means:** an attacker positioned to MITM the *very first*
connection to a given Kea server (before Jen has ever talked to it)
could plant a malicious key that then gets trusted permanently. On a
private homelab LAN this is a low-realistic-risk scenario. If Jen is
ever deployed somewhere the network path to Kea servers isn't fully
trusted, that assumption should be revisited.

### 3.3 SSH-based config push instead of native Kea config management

Jen changes subnet/pool configuration by generating a Python script
(with all values safely embedded via `repr()`/`json.dumps()`, not
string-interpolated), base64-encoding it, piping it over SSH, and having
it write the new Kea config, test it with `kea-dhcp4 -t`, and only
replace the live config (after taking a backup) if the test passes.

**Why not Kea's native API-based config management:** Kea's Control
Agent API for live config changes doesn't persist to the on-disk config
file the way editing the file directly does — a live-only API change
would be lost on Kea's next restart unless something also updates the
file. Editing the file directly and testing before committing is more
robust for Jen's actual use case (persistent, restart-safe config), at
the cost of being a workaround rather than integration with an API
designed for this.

**What this means:** this is inherently more fragile to Kea version
changes than a tool built on Kea's own config-management primitives
would be. If Kea's config file format or CLI flags change in a future
version, Jen's script-generation logic needs to be updated to match —
there's no API contract protecting against that the way there would be
with native hook-based integration.

### 3.4 API keys are global-scope by design

Jen's API keys (`api_keys` table) have no subnet-restriction column and
aren't tied to a user's own subnet access — a key can read anything the
`/api/v1/*` endpoints expose, regardless of who created it. This is
intentional: API keys are treated as integration credentials (scripts,
external tooling), not as a way to hand a restricted human user
programmatic access. If per-key subnet scoping is ever needed, it's a
schema change (`api_keys` needs a `subnet_access` column, and every
`/api/v1/*` route needs to check it) — not currently planned.

### 3.5 Floor-pinned (not exact-pinned) Python dependencies

`install.sh` pins dependencies with a floor (`flask>=3.1.3`) rather than
an exact version (`flask==3.1.3`). This is deliberate: it means fresh
installs automatically pick up security patches without a maintainer
re-reviewing and re-pinning every dependency on every release.

**The tradeoff:** it means installs aren't fully reproducible — two
installs done weeks apart could resolve to different exact versions —
and there's no protection against a hypothetically-compromised newest
release of a dependency (a supply-chain risk floor-pinning doesn't
address, only exact-pinning + manual review would). `pip-audit` in CI
(see below) is the compensating control: it checks whatever actually
gets installed against known CVEs on every push, so a newly-disclosed
vulnerability in a floor-pinned dependency gets caught even without a
version bump.

## 4. CI/CD verification

As of the process work following the v4.4.10 audit series:

- **`tests.yml`** (reusable workflow) runs on every push and PR via
  `ci.yml`, and gates every tagged release via `release.yml`:
  - `pytest` against a real MariaDB service container — the full test
    suite, not a subset.
  - `bandit` (static security analysis) against `jen/` and `plugins/`,
    diffed against `.github/bandit-baseline.json` — a snapshot of
    findings that existed as of this writing, each manually traced and
    verified safe (whitelisted table/column names, int()-cast values,
    the TOFU SSH model described above). New findings introduced after
    the baseline fail CI; the existing, reviewed backlog doesn't block
    anything.
  - `pip-audit` against the actual installed dependency set.
- **Dependabot** watches the GitHub Actions used in these workflows and
  opens PRs to bump pinned commit SHAs forward when new releases exist.

None of this replaces a real external security audit. It's the
realistic, zero-budget equivalent: automated checks that catch
regressions and known-CVE dependencies going forward, plus a documented
paper trail for what's already been manually reviewed.

## 5. Known gaps (as of this writing)

Documenting these here rather than letting them go unstated:

- **IPv4 only.** Every Kea-side table Jen queries (`lease4`, `hosts`,
  `dhcp4_options`) is the IPv4 schema. Adding IPv6 support would touch
  nearly every query in the app, not be an additive change.
- **No DNS/BIND9 management.** Jen is DHCP-only.
- **No professional external security audit.** See `SECURITY.md` for
  the honest framing of what level of scrutiny this project has
  actually had.
- **The tarball-based deploy model can't delete files.** Every release
  is deployed via `tar xzf ~/jen-vX.Y.Z.tar.gz --strip-components=1 -C .`
  extracted on top of an existing checkout — which can only add or
  overwrite files, never remove one that's no longer in the current
  tarball but still sitting in the working tree from an earlier release.
  Discovered concretely in the v4.4.14 cleanup: the top-level `jen.py`
  monolith (retired at v2.6.0, moved to `legacy/jen.py`) and four
  `docs/github-release-*.x.md` files (properly relocated to
  `docs/release-history/` at some point since) had been quietly
  persisting in the real repository for releases, invisible to every
  tarball built from a clean working tree that never had them in the
  first place. There's no automatic detection for this — the practical
  mitigation is periodically pulling the actual published GitHub
  archive (`github.com/<repo>/archive/refs/tags/vX.Y.Z.tar.gz`) and
  diffing it against the working tree that built it, which is how this
  specific instance was found.
