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
`restart_pending` flag, starts the backup scheduler. `run.py` is the entry point
(werkzeug `make_server`, `threaded=True`, optional TLS, HTTP→HTTPS redirect, and the
background `check_alerts` thread).

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
numbering space from v4 (`SUBNET6_MAP` vs `SUBNET_MAP`). `tests/test_kea6.py`
`TestZeroBehaviorChange` guards the "nothing changes for v4-only installs" property.

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
   `tests/test_sudoers_command_matching.py`.)
