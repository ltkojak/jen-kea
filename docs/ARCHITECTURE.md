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
┌─────────────────┐   Kea command HTTP API    ┌───────────────┐
│   Jen (Flask)    │──────────────────────────►│  Kea DHCP4/6  │
│   run.py         │   SSH (config push,       │  Server(s)    │
│   www-data user   │   restarts, log reads)    │               │
└─────────────────┘◄──────────────────────────┘└───────────────┘
```

The command HTTP API is reached one of two ways, chosen by
`[kea] connection_mode` (`jen/services/kea.py`):

- **`ca`** (default) — one `kea-ctrl-agent` endpoint routes commands to
  each daemon by a `"service"` field. Every release before v5.10.0 did
  only this.
- **`direct`** — Jen talks to each daemon's own `http`/`https` control
  socket. ISC deprecated the Control Agent in Kea 3.0 and **removed it in
  3.2**, so `direct` is the only option on current Kea. `kea-dhcp4` and
  `kea-dhcp6` each get their own URL (`[kea] api_url` / `[kea6] api_url`,
  explicit port required), and the `"service"` field is omitted. For an
  `https://` socket Jen can present a client certificate (`[kea]
  api_client_cert` / `api_client_key`) — Kea's per-daemon TLS socket
  defaults `cert-required` to true, so mutual TLS is the norm. The client
  key sits under `/etc/jen/ssl` readable by `www-data`; a compromise of
  the Jen process exposes it exactly the way it already exposes the Kea
  SSH key — one more reason for the planned Kea-host helper (§3.3), not a
  new class of exposure. Each server's v6 endpoint and authored bind
  address are its own; `[kea6]` is the primary's override only.

Deliberately **not** an agent-based architecture. There's no separate
process running on each Kea server the way Stork's `stork-agent` works —
Jen connects out to each Kea server directly, either via the command HTTP
API (for reads/live status) or via SSH (for config file changes and
service restarts). This is a real, considered tradeoff:

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

**Step-up auth (v5.17.0 / Q6).** A live session is not enough for the
routes that manage a user's own MFA (enroll a second factor, regenerate
backup codes, add/remove a trusted device, an admin's MFA reset).
`session["auth_at"]` records when a password (and MFA, if enrolled) was
last verified; `access.recent_auth_required(minutes=10)` sends a stale
session through `GET /auth/reauth` first. `session.clear()` runs before
every `login_user()` so a pre-auth session can't carry anything into the
authenticated one, and `/logout` is POST-only (a GET renders a confirm
page) so a link or prefetch can't end a session. `audit()` and the
rate-limit `clear_*` helpers write synchronously — a security event is
never lost to an unseen background-thread error.

**Kea config history at rest (v5.20.0).** `kea_config_revisions` bodies
are encrypted (the same `crypto.py` Fernet key as MFA secrets and alert
credentials — §3.6) — a database dump alone doesn't hand over Kea DB
passwords, HA peer credentials, or DDNS TSIG keys. Above that, the
config-history and diff pages themselves mask those same secret-shaped
keys for anyone who can see them at all; only a `superadmin` can reach
the real, unmasked body, and only through the same step-up gate as
above (`@_recent_auth_required(minutes=10)`), with every unmasked
download written to the audit log. A viewer or admin sees the same
masked diff a superadmin does — the step-up boundary is specifically
"the real secret values," not "the config history feature."

## 3. Deliberate trust boundaries

These are places where Jen makes a conscious security tradeoff rather
than an oversight. Documenting them here so future changes are informed
decisions, not accidental regressions.

### 3.1 The self-update sudoers grant

`jen-sudoers` grants `www-data` (the user Jen runs as) exactly two
passwordless commands, matched by `sudo` byte-for-byte:

```
/usr/bin/systemctl restart jen
/usr/bin/systemctl start --no-block jen-update.service
```

Neither takes any input from Jen. `jen-update.service` is a root
`oneshot` that runs `/usr/local/sbin/jen-update-root.py` — owned
`root:root`, mode `0700`, **outside** every directory `www-data` can
write — which re-derives "the current latest release" from the pinned
`ltkojak/jen-kea` GitHub repo on its own, verifies the tarball's SHA-256
against the published `SHA256SUMS`, and only then installs (see §6 for
the staged/rollback flow).

**Why this is the boundary:** even a fully-compromised `www-data` can
only trigger "install whatever GitHub currently publishes as latest". It
cannot pass a version, a URL, or file content into the privileged step,
because nothing it controls reaches that script as input.

**History — why it looks this way (v5.2.6):** the previous design had
`www-data` write `/tmp/jen_update_install.sh` and `sudo` it. Since
`/tmp` is world-writable and `www-data` was the exact account allowed to
write that exact path, any code execution as `www-data` was root — the
sudoers rule couldn't tell "content the update flow verified" from
"content something else wrote". Moving the whole pipeline into a
root-owned script that takes no caller input closed that.

**What this means for any future change:** rule 8 in `CLAUDE.md` — a
changed `sudo` command string is a changed sudoers line in the same
commit, and this section is updated with it. Never add a parameter to
either command. `jen-update-root.py` must never read `sys.argv` or any
file `www-data` can write (`tests/test_jen_update_root.py` pins the
first; the second is a review checklist item).

**systemd sandboxing (v5.17.0 / Q6 6E).** `jen.service` runs with
`ProtectSystem=strict` (only `/etc/jen` and `/var/lib/jen` writable —
`/opt/jen` is read-only since v5.13.0), `PrivateTmp`, `PrivateDevices`
and the `Protect*` / `Restrict*` family. It deliberately does **not**
set `NoNewPrivileges`, `CapabilityBoundingSet` or `ProtectProc`: Jen's
only privileged action is `sudo` (the two commands above, and the
banner-warned legacy `python3` path on un-migrated Kea hosts), which
needs the setuid transition. `jen-update.service` — the root updater —
is intentionally left un-sandboxed; it writes `/opt/jen` and
`/usr/local/sbin`. `tests/test_service_hardening.py` pins both.

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

Jen changes Kea configuration over SSH — it edits the on-disk config
file, tests it with `kea-dhcp4 -t`, and only replaces the live file
(after a backup) if the test passes. It does **not** use Kea's Control
Agent API for config changes: a live-only API change is lost on Kea's
next restart unless something also rewrites the file, so editing the
file directly and testing before committing is more robust for Jen's
use case (persistent, restart-safe config). The tradeoff is that this
is more fragile to Kea version changes than native hook-based
integration would be — if Kea's config format or CLI flags change,
Jen's logic has to be updated to match.

**How the push happens (v5.11.0 — `jen-kea-helper`).** Every Kea-side
operation Jen performs — read a config, `kea-dhcpX -t` a candidate,
replace the live file, restart/enable/disable a daemon, tail a log,
install a Kea package — goes through a fixed-function helper on the Kea
host:

- `jen-kea-helper` is a small pure-stdlib script installed at
  `/usr/local/sbin/jen-kea-helper`, owned `root:root` mode `0755`.
  `www-data` cannot read or modify it.
- Jen invokes it as `sudo -n /usr/local/sbin/jen-kea-helper <op>` with
  one JSON object on stdin; it replies with one JSON object on stdout.
  It **never executes anything it is handed** — stdin is data only.
- The **one** Kea-side sudoers line is
  `youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper`. The
  bare command (no argument list) is deliberate: the control is the
  helper's own op allowlist and path walls (config files must sit
  directly in `/etc/kea` or `/usr/local/etc/kea` and match
  `*.conf`; logs must resolve under `/var/log` and end `.log`), not
  sudo's argument matching.
- There is **no `self-update` op**. "Jen writes a file the Kea host then
  runs as root" is exactly the capability being removed; letting the
  helper update itself would put it straight back. Upgrading the helper
  (only when its integer `HELPER_VERSION` changes — rare, called out in
  the release notes) is pressing **Update helper** in Settings → Kea →
  SSH — it re-copies the current file, then asks the freshly-copied
  helper its own version rather than trusting what the copy script
  printed (v5.19.1 fix: it used to trust the echo, and separately used
  to treat any installed version as fully current instead of comparing
  against the version Jen actually wants) — or a manual
  `install -m 0755` by an administrator. Either path still needs the
  legacy `sudo python3` grant present for that one run, same as a fresh
  install.

**Helper protocol v2 (v5.16.0 — optimistic concurrency).** `read-config`
now also returns `"sha256"`, the hex SHA-256 of the raw config-file
bytes (whitespace and key order included — the point is to detect a hand
edit). `apply-config` accepts an optional `"expect_sha256"`: when
present, the helper takes an exclusive `flock` on a sidecar
`<path>.jen_lock` (never on the config itself — `os.replace` swaps the
inode), re-hashes the live file, and refuses with
`{"ok": false, "error": "conflict", "sha256": <current>}` **before**
running `kea-dhcpX -t` if it doesn't match (`""` means "must not
exist"). Success also returns the SHA of the bytes just written. Every
v2 response — protocol errors included — carries `"helper_version"`, so
Jen learns the real number from any op, not just `version`.
`JEN_HELPER_MIN_VERSION` stays 1: a v1 host keeps working, and
`JEN_HELPER_WANT_VERSION = 2` only drives an "upgrade available" hint.

- `jen-config` mutation now happens **in Jen** (`jen/services/kea_config_edit.py`,
  pure functions) rather than inside a generated script. Read → mutate →
  apply is not a single atomic step on the Kea host, but since v5.16.0
  the write is guarded: the v2 helper enforces `expect_sha256` under the
  lock above, and a v1 / legacy host gets a best-effort compare in Jen
  (re-read, canonical-JSON diff against the last recorded revision,
  refuse on mismatch) with a one-per-request "no atomic guard" warning.
  Every config Jen writes — and every out-of-band change it notices on
  the next read — is also recorded in `kea_config_revisions` (jen_db,
  migration 20, extended by migration 21) as a diffable, restorable
  revision; see the admin guide.

**A hash always says what it hashes (v5.20.0 — `hash_kind`).**
`kea_config_revisions.sha256` has always held one of two genuinely
different quantities with no way to tell them apart: the helper's
raw-bytes hash (v2) or `sha256(canonical(cfg))`, a Jen-computed
stand-in (v1 / legacy) — and a v1→v2 upgrade meant the two got compared
against each other, always mismatching, so `config_history_restore`
always conflicted until a fresh Jen write happened to replace the
stored value. Migration 21 adds `hash_kind ∈ {raw, canonical, legacy}`
(`legacy` marking a pre-5.20.0 row of unknown kind); `record()` now
requires it as a keyword on every call. The first contact with a
server/service, and the first read after a `canonical` host's helper
crosses to v2, is recorded as a `baseline` revision rather than
`external` — a crossover is not a hand edit, it's Jen re-establishing
what it can trust to compare against. `config_history_restore` only
passes `expect_sha256` when the latest revision's kind is `raw`;
otherwise it reads the live hash immediately before applying, since a
`canonical`/`legacy` value was never comparable to the helper's raw
hash to begin with.

**The legacy-grant check runs at check time, not just install time
(v5.20.0).** `kea_host.check_helper()` — the one place Jen already
talks to a Kea host to ask its helper version — now also probes whether
`/etc/sudoers.d/jen-kea` (below) is still present and records that
alongside the version, so Health Center can warn about it without
adding an SSH round trip of its own (Health Center's own rule is no SSH
at render time). This closes a gap where a host could have both the
current helper **and** the old root grant, and nothing would say so.

**The legacy fallback.** A host that does not have the helper yet falls
back to the pre-5.11.0 path: Jen generates a Python script, base64s it,
pipes it over SSH into `sudo python3`, and runs it as root. That
requires the old `NOPASSWD: /usr/bin/python3` grant — which **is root,
full stop**: a compromised `www-data` on the Jen host is root on every
such Kea box. Jen shows an admin banner naming every server still on
this path, and flashes a warning on each use. The fallback is kept for
compatibility and **is not removed anywhere in the 5.x line** —
removing it would break a clean upgrade for anyone still relying on it,
which is the MAJOR trigger. `CLAUDE.md` rule 9 still applies: any new
Kea-side capability is a new helper op **and** a documented change to
both sudoers subsections in `docs/admin-guide.md` and
`docs/troubleshooting.md`.

The Jen side of this same "www-data writes a root-run file" problem was
fixed in v5.2.6 (§3.1, §6); v5.11.0 closes the Kea side for hosts that
have adopted the helper.

### 3.4 API key scope

Originally API keys were deliberately global-scope (integration
credentials, not restricted-human access). v5.1.11 (migration 13) added
a per-key `subnet_access` column: `api_keys_create` clamps a key's
scope to what the creating user can themselves see (any "all" or
out-of-access subnet in the submitted form is dropped server-side), and
the `/api/v1/*` routes apply the same subnet restriction as the human
UI. A key with `subnet_access = NULL` is still global — that's the
default for a key created by an unrestricted admin, and remains a valid
"this is a trusted integration credential" choice.

**Client IP behind a proxy (v5.17.0 / Q6 6D).** Rate limiting, the audit
log and MFA trusted-device records all key off `request.remote_addr`.
When `[server] trusted_proxies` is set (a list of proxy IPs / CIDRs),
`TrustedProxyMiddleware` — installed ahead of Flask, and only when that
list is non-empty — rewrites `REMOTE_ADDR` from the rightmost
non-trusted `X-Forwarded-For` hop and `wsgi.url_scheme` from
`X-Forwarded-Proto`, but *only* when the immediate peer is itself in the
trusted list. An untrusted peer's forwarding headers are ignored
entirely. With the setting on, the Secure cookie flag and HSTS turn on
(the proxy is required to serve HTTPS) and gunicorn gets the same list
as `--forwarded-allow-ips`.

### 3.5 Floor-pinned (not exact-pinned) Python dependencies

Runtime dependencies are declared once, in `requirements.txt` at the
repo root (v5.4.1 — before that the same list was duplicated across
`install.sh`, `Dockerfile`, and `.github/workflows/tests.yml`, which had
already drifted). `install.sh`, the Docker build, and both CI jobs all
`pip install -r requirements.txt`; `requirements-dev.txt` adds the
test/lint tooling. `tests/test_dependency_consistency.py` fails CI if
any of those files re-introduces an inline package pin.

Each pin is a floor (`flask>=3.1.3`) rather than an exact version
(`flask==3.1.3`). This is deliberate: fresh installs automatically pick
up security patches without a maintainer re-reviewing and re-pinning
every dependency on every release. A full lockfile was considered and
rejected for this project's size and solo-maintenance model — it would
mean a deliberate re-lock for every security update, which won't happen
reliably, so stale-by-neglect deps would be the real outcome.

**The tradeoff:** installs aren't fully reproducible — two installs done
weeks apart could resolve to different exact versions — and there's no
protection against a hypothetically-compromised *newest* release of a
dependency (only exact-pinning + manual review addresses that).
`pip-audit` in CI (see below) is the compensating control: it checks
whatever actually gets installed against known CVEs on every push, so a
newly-disclosed vulnerability in a floor-pinned dependency gets caught
even without a version bump.

v5.5.0 — the self-updater started running `pip`. v5.8.0 moved that into
a `/opt/jen/venv` and made the update transactional — see §6.

### 3.6 MFA secret encryption at rest (v5.4.0)

`mfa_methods.secret` (the TOTP shared secret) is encrypted with Fernet
before storage — see `jen/services/crypto.py`. Backup codes,
trusted-device tokens, and API keys are one-way sha256 hashes because
Jen only ever needs to *check* them; a TOTP secret has to be recovered
in cleartext every 30 seconds to recompute the current code, so it's
encryption with an external key, not a hash.

**The key** lives at `/etc/jen/mfa_key` (0600), created on first use
with the same load-or-create + `$JEN_ROOT` fallback pattern as the
Flask session key (`_load_secret_key()`). It is deliberately **not** in
the database it protects and **not** in database exports.

**Why this is the boundary:** the threat is read access to the `jen_db`
`mfa_methods` table without corresponding access to the application
host's filesystem — a downloaded export, a read replica, a compromised
DB account, SQL injection, a shared DB host. An attacker who already
has `/etc/jen` has the app itself and this buys nothing; that's an
accepted non-goal, same framing as the sudoers grant in 3.1.

**What this means for future changes:** `verify_totp()` fails **closed**
on a decrypt failure (unreadable row skipped, never trusted) — a DB
restored/migrated without its key leaves users on backup codes / an
admin reset, never bypassed. Migration 17 does the one-time in-place
encryption of pre-existing plaintext rows and aborts startup (rather
than minting an ephemeral key) if the key can't be persisted. Any new
code path that reads `mfa_methods.secret` must go through
`crypto.decrypt_secret()` and must not treat a `SecretDecryptError` as
"authenticated".

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

## 5. IPv6 support (v5.0)

v5.0 added IPv6 (DHCPv6) support alongside Jen's existing IPv4 management —
read-only visibility across every major page, plus write support for
reservations and subnet pool/timer editing. This section describes what's
covered, what's deliberately deferred, and the design decisions that keep
it a genuinely additive change rather than a rewrite.

### 5.1 Off by default, verified off by default

`ipv6_enabled` (a `settings` table key, same pattern as `restart_pending`)
defaults to `false` on every install — new and existing. Every v6 code
path is written to check it first: `SUBNET6_MAP` is never populated for
display, no v6 nav/UI element renders, and no v6 Kea command fires unless
it's explicitly on. This isn't just a design intention — it's the single
most heavily tested property in the v6 test suite (`tests/test_kea6_*.py`,
`test_kea6_config.py::TestZeroBehaviorChange` and equivalents throughout), because a
regression here would mean every v4-only install silently starts doing
extra work or showing broken UI on upgrade. `[kea6]`/`[kea6_db]`/
`[subnets6]` are all optional `jen.config` sections; when absent, every
v6 connection value falls back to its v4 counterpart at config-load time
(`jen/config.py`'s `AppConfig.apply()`) rather than requiring separate
credentials — the common real-world case is one Kea Control Agent
proxying both `kea-dhcp4` and `kea-dhcp6`, and one shared MySQL database.
The one exception (v5.10.0): in `connection_mode = direct` there is **no**
fallback for `[kea6] api_url` — a `kea-dhcp4` daemon can't answer DHCPv6
commands, so v6 needs its own control-socket URL or v6 API calls return
an error dict.

### 5.2 Data model

- **`SUBNET6_MAP`** is a fully independent map keyed by Kea's own v6
  subnet IDs, which do **not** share a numbering space with v4's — the
  same integer can validly appear in both `[subnets]` and `[subnets6]`
  and refer to two unrelated subnets. An optional `paired_subnet4_id`
  field (a third comma-separated value in a `[subnets6]` entry) lets an
  admin explicitly associate a v6 subnet with its v4 counterpart so the
  Subnets page renders them as one card with two detail blocks.
  Deliberately config-driven, not auto-detected by name/VLAN matching —
  guessing wrong and silently merging two unrelated subnets is worse
  than requiring one config line.
- **`hosts` is the same table for v4 and v6** — it gained
  `dhcp6_subnet_id`/`dhcp6_client_classes` columns alongside its existing
  v4 columns (this is Kea's own schema, not something Jen added). One
  `hosts` row (one DUID) can carry both a v4 and a v6 reservation at
  once.
- **`ipv6_reservations`** is a genuine one-to-many junction table off
  `hosts` — a single device can hold both an address (IA_NA) reservation
  and a delegated-prefix (IA_PD) reservation simultaneously. Every v6
  reservation read/write path in Jen represents this directly (a device
  row with a list of reservations), not retrofitted from a
  one-reservation-per-device assumption inherited from the v4 code.
- **`lease6`** columns were confirmed directly against Kea's own
  `dhcpdb_create.mysql` (not assumed from the v4 schema): `address` is
  `VARCHAR(39)`, not the `INET_ATON` integer v4 uses; `duid` is
  `VARBINARY` like `hwaddr`; `hwaddr`/`hwtype`/`hwaddr_source` were added
  in a later Kea schema version so are nullable. MAC display for a v6
  lease prefers Kea's own populated `hwaddr` when present, falling back
  to manual DUID-LL/DUID-LLT parsing (`jen/services/kea6.py`,
  `extract_mac_from_duid()`) only when it isn't — and returns nothing
  (never a guess) for DUID-EN/DUID-UUID, which have no embedded
  link-layer address at all.
- **`lease6_history`** is a separate table from `lease_history`, not
  columns bolted on: v4's single active/dynamic/pool-size-percentage
  model doesn't map onto v6, where IA_NA and IA_PD are different,
  non-comparable quantities and a `/64` pool has no finite "percent
  used" the way a v4 `/24` does. Active-lease counts are tracked
  per-type; there's no pool-size or utilization-ratio column, and none
  of `/metrics`' v6 gauges (`jen_subnet6_*`) attempt one either — this
  is the same reasoning applied consistently at three separate layers
  (schema, metrics, alerts — see 5.4).

### 5.3 The enable/disable toggle reaches real infrastructure

Flipping "Enable IPv6 support" (Settings → Kea, superadmin
only) is two layers, not one: the `ipv6_enabled` display flag above, and
actual SSH-driven service-state orchestration
(`jen/services/kea6.py::set_ipv6_service_state()`) that connects to
every configured Kea server, confirms `kea-dhcp6.conf` genuinely exists
first (Jen never authors one from nothing), and runs
`systemctl enable --now kea-dhcp6-server` (with the same dual-name
fallback to `isc-kea-dhcp6-server` the v4 restart logic already has).
The display flag only flips to enabled if **every** server succeeds;
disabling always flips it off regardless of partial SSH failure, since
"off" is the safe state to fail toward and any server that didn't
actually stop is surfaced as an error rather than silently trusted.

### 5.4 Write-side: reservations and subnet editing

Both go through the same trust boundary already established for v4
(§3.3), not a new one:

- **Reservations** use Kea's own `reservation-add`/`reservation-del`
  commands via the Control Agent API (`host_cmds` hook — the same one
  the v4 add/edit-reservation flow already requires), not direct SQL
  writes to `hosts`/`ipv6_reservations`. This keeps Kea's in-memory host
  cache and the database in sync automatically.
- **Subnet pool/timer editing** reuses the exact SSH config-push pattern
  from §3.3 and the v4.4.24 Preview & Validate work: a generated Python
  script patches `kea-dhcp6.conf`, tests it with `kea-dhcp6 -t` against a
  temp file, and only replaces the live config (after a backup) if the
  test passes. The dry-run preview endpoint never writes to the live
  config under any outcome — this is directly tested
  (`TestEditSubnet6PreviewRoute`) by asserting the SSH session only ever
  sees one command (the test), never a second apply/restart call. What's
  genuinely different from v4: `preferred-lifetime` and `valid-lifetime`
  are distinct fields (v4 only has one), DNS is delivered via the
  `dns-servers` option (code 23, space `dhcp6`) rather than v4's
  `domain-name-servers`, and there's no `routers` field at all — DHCPv6
  has no default-gateway option; that's Router Advertisement's job,
  entirely outside Kea.

### 5.5 What's explicitly deferred, and why

Stated plainly rather than left to be discovered mid-implementation:

- **Cross-protocol device correlation.** Jen does not attempt to link "this
  v6 lease" and "this v4 lease" as the same physical device. Privacy-extension
  IPv6 addresses rotate, and DUID-to-MAC extraction only works for two
  of several DUID types (DUID-LL, DUID-LLT — not DUID-EN or DUID-UUID).
  A wrong automatic correlation is worse than none; v4 and v6 device
  lists are genuinely separate. `jen/services/kea6.py::list_lease6_devices()`
  groups v6 leases by DUID (so one device's IA_NA and IA_PD leases
  collapse into one row) but never cross-references the v4 `devices`
  table.
- **No v6 equivalent of the IP Map page.** Full-address-space
  enumeration doesn't extend to a `/64` — there's nothing meaningful to
  render. If an address-list view is ever wanted for v6, it would need
  to be "reservations + active leases only," a genuinely different page,
  not an extension of the existing one.
- **IPAM Lite and Network Discovery plugins remain IPv4-only.** Both
  document this directly in their own README and show an in-app note
  (gated on `ipv6_enabled`, invisible on v4-only installs) rather than
  silently producing incomplete results. Full-address-space IPAM and
  active network scanning don't have a sane v6 equivalent at homelab
  scale for the same "/64 has no finite space to enumerate" reason as
  the IP Map.
- **Alerting stays mostly v4-shaped.** `kea_down`/`kea_up`/`ha_failover`
  already generalize (they alert on Kea server reachability, not
  protocol-specific data). Utilization/pool-exhaustion alerts are
  deliberately **not** ported to v6 — same "/64 percentage is
  meaningless" reasoning as the schema and metrics decisions above.
  `new_lease`/`new_device`/`stale_reservation` stay v4-only because
  they're built on the `devices` table, which cross-protocol correlation
  concerns (above) keep v4-only. See the comment block above
  `ALERT_TYPE_LABELS` in `jen/services/alerts.py` for the full per-type
  reasoning, including the discovery that `reservation_added`,
  `reservation_deleted`, and `kea_config_changed` aren't actually wired
  to fire from any v4 route today either — there was nothing to
  generalize to v6 for those three.
- **Heavy prefix-delegation topologies.** This covers straightforward
  dual-stack LANs (address reservations, a delegated-prefix reservation
  or two) well. A full PD-relay-chain setup is a different, harder
  problem that would need its own scoping.

## 6. Serving model (v5.5.0)

Through v5.4.x, `run.py` *was* the server — `werkzeug.serving.make_server`
/ `app.run`, i.e. the Flask development server. `threaded=True` (v5.3.3)
stopped one slow request from blocking every other user, but it was
still the dev server: unbounded thread spawning, no request timeouts,
no graceful drain on restart.

v5.5.0 puts **gunicorn** in front. `run.py` is now a launcher, not a
server:

- **No SSL:** `os.execvp` gunicorn bound to the HTTP port. `run.py` is
  replaced by the process; systemd owns gunicorn directly and SIGTERM
  goes straight to it.
- **SSL:** gunicorn runs as a child process (`--certfile/--keyfile`,
  HTTPS port); `run.py` stays as the parent, runs the HTTP→HTTPS 301
  redirect (`jen/httpredirect.py`, stdlib only) on its main thread, and
  forwards SIGTERM/SIGINT to gunicorn. gunicorn can only terminate TLS
  process-wide, so the plain-HTTP redirect genuinely can't share its
  process — hence the split. A `systemctl restart jen` now drains
  in-flight requests (gunicorn `--graceful-timeout 30`,
  `jen.service` `TimeoutStopSec=40`) instead of cutting them.

**Single worker, many threads.** `--workers 1 --threads N` (N =
`[server] threads`, default 8, Settings → System). Jen is
I/O-bound — DB, Kea Control Agent API, SSH — not CPU-bound, so threads
carry the concurrency fine. `-w 1` is also load-bearing for correctness:
the backup scheduler and the `check_alerts` loop are **single-process**
background work. They were started by `create_app()` before v5.5.0 —
which would have run them once per gunicorn worker. Now the factory only
builds the app; `jen/wsgi.py` (imported once by the single worker) calls
`jen.services.background.start_background_workers()`. A multi-worker
gunicorn would reopen the "scheduler runs N times, alerts fire N times"
problem and is deliberately not offered — that's a separate project
needing a dedicated worker process or a distributed lock.

**Werkzeug fallback.** If gunicorn can't be imported or spawned — a
botched dependency install, a non-Linux dev box — `run.py` logs a
CRITICAL and falls back to the old werkzeug path (which then starts the
background workers itself). This is a safety net so the console never
goes dark on a bad update; it is not a supported way to run in
production, and it says so, loudly, in the log on every start.

**venv + transactional self-update (v5.8.0).** Two paired changes to how
Jen's code and dependencies land on bare metal.

*The venv.* Jen's Python dependencies live in a virtualenv, not system
site-packages — no more `pip --break-system-packages`. As of **v5.14.0**
each release gets its **own** venv at `releases/<X.Y.Z>/venv`, built for
exactly that release's `requirements.txt`; `jen.service` runs
`/opt/jen/current/venv/bin/python /opt/jen/current/app/run.py`. `run.py`
still carries a re-exec shim (it prefers `<run.py dir>/../venv`, then the
flat `/opt/jen/venv`) as a safety net for a still-flat box and for
Docker, but on a versioned box the unit already names the right
interpreter. Pre-5.14 the venv was the single flat `/opt/jen/venv` and
the unit ran `/usr/bin/python3 /opt/jen/run.py`.

The venv is **`root:root`** — the `www-data` service account reads and
executes the interpreter and site-packages but never writes them (it's
byte-compiled as root at install time so there's no lazy `.pyc` write).
A writable venv would be a persistence foothold for a compromised
`www-data`: swap a package's code and Jen runs it on every restart. Only
`install.sh` and the root self-updater modify it. Docker doesn't use a
venv at all — the container is the isolation — and reaches the app
through the same `JEN_ROOT` fallback.

*The transactional updater.* `jen-update-root.py` was
*replace-then-try-deps*: overwrite `/opt/jen`, then `pip` non-fatally,
then restart — which silently shipped a half-updated app if a release
genuinely needed a new library. As of **v5.14.0** it builds the whole
release under `releases/<X.Y.Z>.staging-<ts>/` (extract the tarball into
`app/`, build `venv/`, `pip`, compile, import-check) and the install is
`os.rename()` of the staging dir into place plus an `os.replace()` of the
`/opt/jen/current` relative symlink — atomic on POSIX. **Any failure**
flips the symlink back to the previous release (its directory was never
touched, so it is its own rollback — no snapshot/restore of the app tree
at all) and restarts. The out-of-tree files an update replaces
(`jen.service`, `/etc/sudoers.d/jen`, the updater itself,
`jen-update.service`) are still snapshotted and restored, so a bad unit
file can't survive the rollback. The per-release venv finally makes the
rollback a **true point-in-time revert** — the old release's venv is
exactly the dependencies it shipped with.

The first run on a still-flat box ("migration run" — no `current` symlink
yet) keeps `snapshot_install()` / `restore_snapshot()` for exactly that
one case: it snapshots the flat tree, builds the versioned layout, and on
success removes the flat `jen/ run.py templates/ static/ plugins/ venv/`.
`sudo ./install.sh` does the same migration immediately.

Two small deliberate choices worth stating: `/api/v1/health` is
**unauthenticated** (it returns Jen's version, whether Kea is up, Kea's
version string and the subnet count — no leases, MACs or hostnames) and
the updater's post-restart version confirmation depends on it; and the
snapshot copies symlinks *as* symlinks (`copytree(symlinks=True)`) —
v5.8.4, after a stray dangling `templates/templates` link from an old
install made every snapshot raise before the swap.

The venv build (`_build_release_venv()`, pre-5.14 `ensure_venv()`)
requires a venv with a *working `pip`* (a half-built venv from a failed
`python3 -m venv` is wiped and rebuilt), and — running as root already —
`apt-get install`s `python3-venv` (v5.8.3: `apt-get update` + one more
retry on a box with stale indices). Because the venv build now happens
against a brand-new staging path, a failure there aborts the update with
nothing touched. The post-restart health-check timeout is 90s (was 45),
overridable via `[server] update_health_timeout`. The health and version
probes talk to the app's real port — HTTPS directly when certs are
present — and neither follows redirects nor verifies TLS on the loopback
call, so an SSL install with a hostname cert isn't mistaken for a dead
one (v5.8.2 chased `jen/httpredirect.py`'s 301 into a failing TLS
handshake and rolled back healthy HTTPS upgrades).

**The 5.13.0 → 5.14.0 transition.** The updater already deployed on a
5.13.x box is the flat one; it installs the 5.14.0 tarball — the new
`jen.service` included — but has no `current` symlink, so the new unit
can't start. That box fails the health check and **cleanly rolls back to
5.13.0**. Operators take 5.14.0 with `sudo ./install.sh` once (it builds
the versioned layout and removes the flat leftovers); every in-app update
from 5.14.0 onward is the atomic-symlink path.

**Still not offered:** a reverse proxy is not required and not
configured by the installer. Terminating TLS in nginx/caddy and running
gunicorn HTTP-only behind it is a valid deployment, just not the
default — the default keeps the "one `install.sh` and done" story.

### 6.1 On-disk layout (v5.13.0, extended in v5.14.0)

Through v5.12.x the application tree under `/opt/jen` held user-writable
content — custom icons, the uploaded favicon and nav logo, database
backups, registry-installed plugins, the secret-key/MFA-key fallbacks —
so `www-data` needed write access to parts of the tree it also executes.
That is a persistence foothold: anything that can write a `.py` file Jen
imports, and later run it as `www-data` on the next restart, has a way to
stay resident across an update. v5.13.0 split the two apart; v5.14.0
added the versioned release directories.

| Path | Holds | Owner / mode | What an upgrade does |
|------|-------|--------------|----------------------|
| `/opt/jen/releases/<X.Y.Z>/app/` | One release's full tree: `jen/`, `templates/`, `static/`, `plugins/` (bundled `ipam` + `network-discovery`), `run.py`, the shipped external files, `docs/` | `root:root`, `a+rX` — read-and-execute only for `www-data` | Built whole under a `.staging-<ts>` sibling, then `os.rename()`d into place. Byte-compiled as root. The previous release's directory is left untouched. |
| `/opt/jen/releases/<X.Y.Z>/venv/` | That release's virtualenv, built for its own `requirements.txt` | `root:root` | Built fresh per release — the rollback is a true point-in-time revert of dependencies too. |
| `/opt/jen/current` | Relative symlink → `releases/<live>` | symlink | Flipped with `os.replace()` (atomic). A rollback flips it back. |
| `/opt/jen/` (flat, pre-5.14) | `jen/`, `run.py`, `templates/`, `static/`, `plugins/`, `venv/` | `root:root`, `a+rX` | Removed by the migration run / `install.sh` once the versioned layout is live. Docker stays flat. |
| `/etc/jen/` | `jen.config`, its backups, TLS certs (`ssl/`), SSH keys (`ssh/`) | `www-data` | Never touched. |
| `/var/lib/jen/` | User content: `icons/`, `branding/` (`nav_logo.*`, `favicon.ico`), `backups/` (database backups), `plugins/` (registry-installed), `plugins-enabled/` (enable markers), `keys/` (`.secret_key`, `.mfa_key` fallbacks) | `www-data`, `750` | Never touched. Populated once, on the upgrade to 5.13.0, by moving the old locations out of `/opt/jen`. |
| `/tmp` | Scratch only (`PrivateTmp=yes`) | per-service namespace | n/a |

`extensions.JEN_ROOT` reads `/opt/jen/current/app` when it exists, else
the flat `/opt/jen` (the `JEN_ROOT` env var overrides both, for dev and
CI). Because `current` is a symlink flipped atomically, a running worker
that opened a file under it keeps reading the old release until it
restarts — which the updater does anyway.

`extensions.CONTENT_DIR` is the single read surface for the `/var/lib/jen`
row:
`/var/lib/jen` in production, `$JEN_ROOT/var` in a source checkout,
overridable with `JEN_CONTENT_DIR`. The app factory best-effort *copies*
any content still in an old `/opt/jen` location into `CONTENT_DIR` on
every boot (idempotent, never clobbers, never crashes the factory) — a
safety net for a box the root-side move missed, and for the Docker named
volume that used to mount at `/opt/jen/static/icons/custom`. Serving is a
dedicated blueprint (`/content/icons/<name>.svg`,
`/content/branding/<file>`); the old `/static/icons/custom/…` and
`/static/nav_logo.*` URLs are gone.

Bundled and registry-installed plugins can now both exist for the same
id (a box that installed `ipam` from the registry, then upgraded). The
`/var/lib/jen/plugins` copy wins; uninstalling a bundled plugin disables
it rather than deleting release-owned files.

## 7. Known gaps (as of this writing)

Documenting these here rather than letting them go unstated:

- **The Health Center (`/health-center`, v5.12.0) is deliberately
  read-only and does no SSH at render time.** Every check runs against
  the Kea HTTP API, the two databases, local files, or state Jen already
  persisted — never a live SSH command to a Kea host. This is what makes
  it safe for a `viewer` to open and safe to poll. It surfaces problems
  and links to the page that fixes them; it does not fix anything itself.
- **No DNS/BIND9 management.** Jen is DHCP-only.
- **No professional external security audit.** See `SECURITY.md` for
  the honest framing of what level of scrutiny this project has
  actually had.
- **The deployed application tree can no longer accrete stale files
  (v5.14.0).** Each release is a fresh directory built from that
  tarball's contents and switched in with one symlink flip, so a file
  dropped from a later release is simply absent from that release's
  `app/`. The *source repository* can still quietly carry a file that no
  clean-checkout tarball ever had (discovered in the v4.4.14 cleanup:
  the retired `jen.py` monolith and some relocated `docs/` files had
  persisted in the real repo for releases). The mitigation for that is
  still to periodically diff the published GitHub archive
  (`github.com/<repo>/archive/refs/tags/vX.Y.Z.tar.gz`) against the
  working tree that built it.
