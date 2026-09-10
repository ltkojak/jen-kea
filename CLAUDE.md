# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Jen is

A single Flask web application that manages ISC Kea DHCP servers for a homelab-scale
operator. Deployed as one process (`run.py`), no per-server agent — Jen connects
*out* to each Kea box via the Kea Control Agent HTTP API (reads/status) and via SSH
(config file edits, service restarts). Targets Ubuntu 22.04/24.04 + Python 3.10+ +
Kea 3.0+ with a MySQL/MariaDB backend.

**Read `docs/ARCHITECTURE.md` first.** It is the threat model and the record of every
deliberate security tradeoff (the self-update sudoers grant, SSH trust-on-first-use,
SSH-based config push, global-scope API keys, floor-pinned deps). Changes that touch
those areas need to be informed by it, not rediscovered.

## Commands

The app itself only runs on Linux (hardcoded `/opt/jen`, `/etc/jen`, `/tmp` paths;
SSH; systemd). On Windows, work through WSL or a Linux box for anything that executes.

```bash
# Install deps — requirements.txt is the single source of truth (v5.4.1),
# shared by install.sh, Dockerfile, and CI. requirements-dev.txt adds the
# test/lint tooling. Never re-list packages inline anywhere else —
# tests/test_dependency_consistency.py fails CI if you do.
pip install -r requirements-dev.txt

# Tests — needs a running MariaDB/MySQL with a `jen_test` database reachable.
# jen_test serves as BOTH jen_db and kea_db in tests; conftest.py creates the
# Kea-side tables and patches jen/extensions.py globals to point at it.
JEN_DB_HOST=127.0.0.1 JEN_DB_USER=jen JEN_DB_PASS=... python3 -m pytest tests/ -v
python3 -m pytest tests/test_subnets.py -v                 # one file
python3 -m pytest tests/test_subnets.py::TestEditSubnet -v # one class/test

# Lint / format (Ruff, added v5.3.3 — config in ruff.toml, conservative rule set)
ruff check .
ruff format .

# Security checks that gate CI (see .github/workflows/tests.yml)
bandit -r jen/ plugins/ -ll -b .github/bandit-baseline.json
pip-audit

# Run locally (Linux; expects /etc/jen/jen.config or JEN_* env vars — see run.py)
JEN_ROOT=$(pwd) python3 run.py
```

CI (`.github/workflows/ci.yml` → `tests.yml`) runs pytest against a real MariaDB
service container, bandit diffed against the baseline, and pip-audit — on every push/PR
and as a gate on every tagged release (`release.yml`).

### Test environment notes

- `JEN_ROOT` env var (v5.3.3) overrides the `/opt/jen` install root for local/CI use.
  CI still symlinks `/opt/jen/templates` and `/opt/jen/static` and pre-creates
  `/etc/jen/{ssl,ssh}` because `init_jen_db()` and `create_app()` touch those paths.
- `tests/conftest.py`: `client` is function-scoped (fresh cookie jar per test),
  `app`/`test_database` are session-scoped. Use the `logged_in_client` fixture for an
  admin session, `restricted_client()` helper for a subnet-restricted non-superadmin,
  `mock_kea` fixture to stub the Kea API.
- A new schema change is a **new numbered migration**, never an edit to an existing one
  — then add a test in `tests/test_migrations.py`.
- **Probe, redirect and TLS behaviour is tested against real local servers**, not a
  mocked `urlopen`. v5.8.3's SSL health-check bug shipped behind a test that mocked
  `urlopen` *raising* `HTTPError(302)` — a real redirect is followed, never raised. Stand
  up `http.server` / `jen.httpredirect.make_server` / an `ssl`-wrapped server on an
  ephemeral port (see `tests/test_jen_update_root.py::TestServiceHealthy`).

### Local verification (Windows dev box)

The full suite cannot run here: `tests/conftest.py` has a session-scoped **autouse** DB
fixture, so every test errors without a reachable MariaDB. What works locally:

- `py_compile` / `ruff check` / `ruff format --check` / `bash -n install.sh`.
- A standalone harness that `importlib`-loads `jen-update-root.py` (pure stdlib) and
  exercises the function under test against real temp dirs, real venvs, real local
  servers — this is how the updater work has been verified before each push.
- Tests that need no DB can be listed and reasoned about, but still won't *run* here:
  test_dependency_consistency, test_docker_config, test_small_hardening_fixes,
  test_htmx_vendoring, test_pwa_manifest, test_device_identity, test_sudoers_command_matching,
  test_jen_update_root, test_changelog. CI is the arbiter; expect one push per round.

Gotchas learned the hard way:

- **MariaDB puts an implicit `CHECK (json_valid(col))` on every `JSON` column.** A
  non-JSON string (e.g. an encrypted `v1:` blob) fails INSERT with error 4025 and will
  never show up locally. Store it as a JSON string literal: `json.dumps(token)`. MySQL 8
  additionally forbids a literal `DEFAULT` on TEXT/BLOB/JSON columns (error 1101) — use
  `VARCHAR(n)` for defaulted short strings.
- **bandit's exit code is meaningless on Windows** — it reports `jen/routes\settings.py`
  (backslash), which never matches the forward-slash baseline, so everything shows as
  new. Baseline matching is by (test_id, filename, text, severity, confidence), not line
  number.
- When adding a test class to an existing file, put it **after** the class it follows —
  dropping it mid-class silently reparents every method below it.
- After a broad `ruff format` pass, re-check every source-scanning test: line-shape
  regexes (e.g. `set_cookie\("jen_trusted"`) break silently when the formatter
  re-wraps a call.
- A venv's `bin/python` on Linux **realpaths to the system interpreter**. "Am I in this
  venv?" is `sys.prefix == venv_dir`, never a `realpath` comparison.
- Rule 7 in practice: the word "other" in new page prose has broken absence-assertion
  tests. Grep `tests/` for `not in` assertions on the page you're touching.

## Architecture

### Configuration is a single choke point

`jen/config.py` `AppConfig` owns the entire lifecycle of `jen.config` (an INI file at
`/etc/jen/jen.config`). The module-level globals in `jen/extensions.py` are the read
surface for the whole app, but they are assigned **only** by `AppConfig.apply()`. Never
assign an `extensions.*` config global anywhere else. To change config at runtime use
`app_config.write_value()` / `write_values()` / `write_subnets()` / `mutate()` — each
writes to disk *and* re-derives every global atomically, so disk and memory can't diverge.
(The test suite patching these globals directly is the one sanctioned exception.)

### App factory and request pipeline

`jen/__init__.py::create_app()` builds the Flask app: loads config, registers all
blueprints from `jen/routes/`, loads plugins, runs DB migrations, clears the
`restart_pending` flag. It does **not** start background work (v5.5.0) — the
factory is pure so the test suite and every gunicorn worker can import it freely.

Serving (v5.5.0 — see `docs/ARCHITECTURE.md` §6): `run.py` is a *launcher*, not a
server. It loads config then runs **gunicorn** `jen.wsgi:application`
(`--workers 1 --threads N`, N = `[server] threads`): `os.execvp` when there's no
SSL, or gunicorn-as-child + a stdlib HTTP→HTTPS redirect (`jen/httpredirect.py`)
when there is. `jen/wsgi.py` calls `jen.services.background.start_background_workers()`
once (the scheduler + the `check_alerts` loop) — `-w 1` keeps that single-process.
If gunicorn can't load, `run.py` falls back to the old werkzeug server with a loud
CRITICAL — safety net only, never the intended path.

`before_request` middleware, in order: request timing, session-timeout enforcement,
HTTPS redirect (only if SSL configured), forced-password-change gate
(`must_change_password`), and CSRF protection. CSRF is hand-rolled in
`jen/services/csrf.py` (not Flask-WTF) — validated globally for POST/PUT/PATCH/DELETE,
exempt for API-key-authenticated requests and when `WTF_CSRF_ENABLED=False` (tests).

### Layers

- `jen/routes/*.py` — one Blueprint per file. Thin: parse request, check access, call a
  service, render. Modules are imported with `__`-prefixed aliases (`import jen.services.kea as __kea`).
- `jen/services/*.py` — business logic. `kea.py` (Control Agent API), `kea6.py` (IPv6),
  `kea_authoring.py` (generating starter Kea configs), `auth.py` (SSH helpers, search
  sanitizing), `alerts.py`, `plugins.py`, `scheduler.py`, `csrf.py`, `access.py`.
- `jen/models/` — `db.py` (pooled connections), `migrations.py` (schema), `user.py`
  (User model + global settings key/value store in the `settings` table).

### Databases

Two logical databases, possibly on different hosts:

- **`jen_db`** — Jen's own: users, sessions, audit log, alerts, devices, plugin state,
  `schema_migrations`, `settings`. Jen owns this schema entirely (`jen/models/migrations.py`).
- **`kea_db`** — Kea's own: `lease4`/`lease6`, `hosts`, `ipv6_reservations`, DHCP options.
  Jen **never** modifies this schema and writes data only through the same tables/commands
  Kea's own tooling would (mostly via the `host_cmds` hook, not raw SQL).

Access via context managers in `jen/models/db.py`: `jen_db()`, `kea_db()`, `kea6_db()`.
Each yields a pooled connection and auto commit/rollback/return. `kea6_db()` reuses the
`kea_db` pool when v6 targets the same database (the common case).

### Kea hosts (SSH)

**v5.11.0 — every Kea-side operation goes through `jen/services/kea_host.py`**, the one
client. It prefers `jen-kea-helper` (a fixed-function root script on the Kea host, one
sudoers line — see `docs/ARCHITECTURE.md` §3.3) and falls back to the pre-5.11.0
`sudo python3` / dual-name-systemctl / `sudo tail` / apt path per host, flashing a
warning and recording a null status. Config mutation is pure (`jen/services/kea_config_edit.py`);
`jen-kea-helper` is the shipped helper file at the repo root.

- **Adding a Kea-side capability = a new helper op** in `jen-kea-helper` (with its own
  path/arg validation) **+** a matching high-level method on `kea_host.py` (with a legacy
  fallback) **+** a docs change to the "Kea host helper" and "Legacy grant" subsections in
  BOTH `docs/admin-guide.md` and `docs/troubleshooting.md` (rule 9). Do NOT add a new
  `sudo …` string to a route.
- The `| sudo python3` pipe may appear ONLY in `kea_host.py` (the legacy engine) and
  `kea_authoring.py::render_install_helper_script` (deploys the helper once). No route
  shells out to `ssh` (except ddns.py's non-sudo `dig`/`host` lookup). A source-guard
  test in `tests/test_kea_host.py` enforces both.
- Kea's systemd unit is `kea-dhcpX-server` on ISC packages and `isc-kea-dhcpX-server` on
  older Debian/Ubuntu packages — the helper (`_resolve_unit`) and the legacy fallback
  both try both.
- Anything interpolated into a remote command string is validated on save
  (`valid_remote_path()`, `valid_ssh_target()`, `valid_unix_username()` in
  `jen/services/auth.py`) **and** `shlex.quote`d at the call site. Local `subprocess`
  calls are always list-args.

### Access control

Three tiers: `superadmin` > `admin` > `viewer`. Decorators live in
`jen/services/access.py`: `@superadmin_required`, `@admin_required`, `@viewer_or_above`
(plus Flask-Login's `@login_required`). **Subnet-scoped data is separate:** any route
touching leases/reservations/devices/subnets must also apply subnet restriction —
`add_subnet_restriction(where, params, alias, column)` for queries,
`assert_subnet_access(subnet_id)` / `current_user.can_access_subnet()` for single-object
checks. `docs/ARCHITECTURE.md` §2 flags this as the single most common source of real
bugs in this project — new subnet-touching endpoints have repeatedly shipped without it.

### IPv6 (v5.0+)

Off by default and *verified* off by default. Gated on the `ipv6_enabled` key in the
`settings` table (NOT a config value) — checked before any v6 code path runs, UI element
renders, or v6 Kea command fires. `[kea6]`/`[kea6_db]`/`[subnets6]` config sections are
optional and each value falls back to its v4 counterpart. v6 subnet IDs are a separate
numbering space from v4 (`SUBNET6_MAP` vs `SUBNET_MAP`). The v6 suite is
`tests/test_kea6_*.py` (+ `tests/test_kea_authoring.py`), split by feature
area from the old monolithic `test_kea6.py` in v5.6.1;
`test_kea6_config.py::TestZeroBehaviorChange` guards the "nothing changes
for v4-only installs" property.

### Plugins

`jen/services/plugins.py`. A plugin is a directory under `plugins/<id>/` with
`manifest.json` (+ optional `plugin.py` defining `register(app)`). `plugin_id` is
attacker-influenced (URL path segment) — always run it through `valid_plugin_id()`
before building a filesystem path. Plugin schema changes use `db_migrations` in the
manifest, tracked per-plugin in `plugin_schema_migrations`, same append-only discipline
as core migrations. Bundled: `plugins/ipam`, `plugins/network-discovery` (both IPv4-only
by design).

### Frontend

Jinja templates in `templates/` + HTMX (`static/js/htmx.min.js`, vendored — see
`tests/test_htmx_vendoring.py`) + hand-rolled dashboard JS + Chart.js. Templates use
inline `<script>`, `style=`, and `onclick=` throughout, so the CSP deliberately allows
`'unsafe-inline'` for script/style while still blocking external origins. Partial
templates are `_`-prefixed and returned for HTMX swaps.

- A value placed in a **JS context** — inside a `<script>` block or an `on*=` attribute —
  goes through `|tojson`, never bare `{{ }}`. HTML autoescaping is not JS escaping.
- Uploaded SVGs (custom icons, nav logo) are served same-origin from `/static/`, so an
  SVG containing `<script>`/`on*=`/`javascript:` is executable content under this CSP.
  Reject on upload; never sanitize-and-hope.

## Deployment paths and versioning

- `/opt/jen/` — application code (override with `JEN_ROOT`). Reinstalled from the release
  tarball on every upgrade; the tarball deploy **can only add/overwrite, never delete** a
  file (`docs/ARCHITECTURE.md` §6).
- `/etc/jen/` — config, secrets, SSL certs, SSH keys. Never touched by upgrades.
- The version string lives in `jen/__init__.py` (`JEN_VERSION`), `install.sh`
  (`JEN_VERSION`), and the README badges — keep them in sync. Bump for a release along
  with a `CHANGELOG.md` entry.
- `CHANGELOG.md` entries are detailed narrative prose explaining *why*, not terse bullet
  lists; a release commonly bundles several independently-scoped fixes. Commit messages
  for releases are version-prefixed (`v5.3.3: ...`).
- Bandit findings that are reviewed-and-accepted go in `.github/bandit-baseline.json`
  with reasoning; only *new* findings fail CI.

## Versioning

`MAJOR.MINOR.PATCH`. The deciding question is what an operator has to do on upgrade:

- **PATCH** (`5.3.3 → 5.3.4`) — bug fixes, small self-contained security fixes,
  dependency bumps, docs, refactors with no behavior change, test-only changes, lint
  passes. No new user-facing capability. A migration is allowed only if it's a pure
  corrective backfill of an existing feature (e.g. migration 16).
- **MINOR** (`5.3.x → 5.4.0`) — a new user-facing feature or subsystem; a migration that
  adds a capability or changes stored-data format (e.g. encrypting MFA secrets at rest);
  security hardening bigger than a one-line fix; a new **optional / backward-compatible**
  config section. Upgrade stays fully automatic (`sudo ./install.sh`), no manual steps.
- **MAJOR** (`5.x → 6.0.0`) — anything that breaks a clean `install.sh` upgrade: a
  required config-file change, a migration that can't run automatically, dropped
  OS/Kea/Python support, a removed feature or API endpoint, or a changed default an
  operator would notice.

MAJOR is reserved for changes that require the **operator** to do something. An on-disk
layout change under `/opt/jen` (versioned release dirs, user content moving to
`/var/lib/jen`, a root-owned app tree) that `install.sh` and the in-app updater migrate
automatically is MINOR. Removing a fallback that an operator may still depend on (e.g.
the legacy `sudo python3` config-push path once a Kea-host helper exists) is what would
actually be MAJOR — so keep fallbacks, banner them, and don't remove them in 5.x.

Process:

- The version strings move together in the **same commit**: `jen/__init__.py`
  `JEN_VERSION`, `install.sh` `JEN_VERSION`, `Dockerfile` `LABEL version`, the
  `jen-dhcp:` image tag in `docker-compose.yml` and `docker-compose.mysql.yml`,
  the README badge, and the two `jen-vX.Y.Z.tar.gz` examples in the README.
  `tests/test_dependency_consistency.py` enforces this — it will fail on the
  next release until every one is bumped.
- Bump only at release time, bundled with the `CHANGELOG.md` entry — never per-fix on a
  working branch.
- Once a version has been described as deployed it is frozen; see rule 4 below.

## Release & Working Discipline

1. **Never run `git push` or `git tag` without explicitly asking first and getting a
   clear yes** — even when confident the change is correct.
2. **Deploy is always the full six-line git block** — `cd`, tar extract (if applicable),
   `git add`, `git commit`, `git push`, `git tag`, tag push. Never abbreviate or skip a
   step, and always show the exact commands before running them.
3. **Hold tags until CI is confirmed green.** A push to `main` triggers CI only; the
   release workflow triggers on tag push. Never tag before the user confirms CI passed.
4. **Never reuse a version number once it's been described as deployed**, even to fix
   something found immediately afterward — bump to a new version instead.
5. **Batch related work into meaningful releases.** Don't bump the version after every
   small fix. Ask before treating a change as "done" and ready to ship — hold related
   work together first.
6. **Verify claims by actually running things** (tests, syntax checks, direct
   simulation) before saying something works. Don't call a fix correct without checking it.
7. **Watch for word-collision issues in changelog / template prose.** This codebase has
   tests asserting specific words are *absent* from certain pages (the word "other" has
   broken this before). Check new prose against the relevant test assertions before
   finalizing.
8. **Any change to a command invoked via `sudo` requires updating the sudoers file in the
   same change** to match it exactly — `sudo` matches command strings literally, word for
   word, not by meaning. (See `jen-sudoers`, `jen-update-root.py`, and
   `tests/test_sudoers_command_matching.py`.) `docs/ARCHITECTURE.md` §3.1 describes that
   grant — update it in the same change too; it has gone stale before.
9. **The same rule applies on the Kea hosts (v5.11.0).** A new Kea-side capability is a
   new op in `jen-kea-helper` — with its own path/argument validation — plus a matching
   `jen/services/kea_host.py` method (helper call + legacy fallback), plus a docs change
   to the "Kea host helper" and "Legacy grant" subsections in BOTH `docs/admin-guide.md`
   and `docs/troubleshooting.md`, plus the `docs/ARCHITECTURE.md` §3.3 op list. Never add
   a `sudo …` string straight to a route. The helper is behind ONE sudoers line
   (`/usr/local/sbin/jen-kea-helper`, bare command); the legacy `/usr/bin/python3` grant
   is the banner-warned fallback and is never removed in 5.x.
