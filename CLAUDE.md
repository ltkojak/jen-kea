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
  Since Q114 it also moves the config and content *defaults* to `$JEN_ROOT/etc` and
  `$JEN_ROOT/var` (`JEN_CONFIG_DIR` / `JEN_DATA_DIR` win over it) — config is NOT read
  from `/etc/jen` once it is set — and `runtime.deployment()` never reads it.
  CI still symlinks `/opt/jen/templates` and `/opt/jen/static` and pre-creates
  `/etc/jen/{ssl,ssh}` because `init_jen_db()` and `create_app()` touch those paths.
- `tests/conftest.py`: `client` is function-scoped (fresh cookie jar per test),
  `app`/`test_database` are session-scoped. Use the `logged_in_client` fixture for an
  admin session, `restricted_client()` helper for a subnet-restricted non-superadmin,
  `mock_kea` fixture to stub the Kea API.
- A new schema change is a **new numbered migration**, never an edit to an existing one
  — then add a test in `tests/test_migrations.py` that interrupts it between its statements
  and re-runs it. Every DDL statement has its own guard (Q151); the only edit to a released
  migration is tightening its guards.
- **Six layers (Q154).** A Q that states a contract ends by naming where it is true in each of: live, persisted, derived, delivered, restored, exported - and
  the test that says so (`docs/ARCHITECTURE.md` §2). The review keeps reading the archive and asking "where else is this true?"; ask it first.
- **A fix to a definition is a fix to every use.** A Q that introduces or changes a definition (what "current lease" means, how a pool's size
  is read, what a threshold alert's state is) carries the repository-wide grep of its uses as a deliverable - the count goes in the report - and
  a source test over the WHOLE tree, never a file list (Q145 pinned `ACTIVE_LEASE4` over three files and twenty-five other queries kept
  `state=0`; Q153 moved them and made the guard whole-tree: `tests/test_active_lease.py`, `jen/services/leases_sql.py`).
- **The audits are tests.** `tests/test_invariant_sweeps.py` (Q151) is the whole-repo audit of
  the invariants that kept being re-found by hand: S1 a secret is never written by a plain
  `open`/redirect/`cp` (private from the first byte, `jen/services/private_files.py`,
  `tools/private_write.py`), S2 a `.prev` is made only by `certs.commit_file_set`, S3 every
  migration statement has its own guard, S4 one identity resolver and no swallowed
  `chown`/`replace`/`fsync` in the helper, S5 the legacy config script never runs for authoring,
  S9 root never copies anything into the app tree from the config or content dirs. A new
  violation fails CI; do not add to a sweep's reviewed allowlist without saying why in the test.
- **The registry and the release audit (Q166).** `docs/SAFETY_INVARIANTS.md` is the version-controlled list of the rules this project has learned - one per entry, with the Q that
  established it, the choke point it is enforced at and the tests that fail when it breaks; `tests/test_safety_invariants.py` parses it with `ast` and fails on a missing test, an unresolved
  reference or a reused id. A new rule gets its entry in the commit that adds its test. `docs/RELEASE_AUDIT.md` is the procedure run on a release candidate's diff BEFORE a tarball goes to a
  reviewer (seven steps and an independent adversarial second pass). Sweep S10 in `tests/test_invariant_sweeps.py` is the fail-closed audit: an `except` on a security or safety path that returns
  an empty value or passes must be on its reviewed list with the reason it fails closed there.
- **The model test.** `tests/test_investigation_model.py` (Q163) is a seeded random walk over EVERY operation and fault of investigation logging, with nine
  invariants (I1 no DEBUG without responsibility ... I9 unavailable is refused) checked after every step against the STORED record, plus a second walk over Explain's
  log evidence (E1). Reviews kept finding SEQUENCES no path test named; this composes them. Any change under `jen/services/investigation_logging.py`,
  `jen/services/explain_context.py` or the Kea settings routes runs it locally before the push
  (`py -m pytest --noconftest tests/test_investigation_model.py -q`; `JEN_MODEL_SEEDS=500` widens it, `JEN_MODEL_SEED=<n>` replays one walk and a failure prints the
  seed and the step log), and a new operation, state or fault in those modules is added to the walk in the SAME commit - the test that lists the service's public
  functions fails until it is. A defect the walk finds is fixed and its sequence pinned by name beside it (`TestWhatTheWalkFound`).
- **Probe, redirect and TLS behavior is tested against real local servers**, not a
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
- Tests that need no DB *do* run here, straight up: `py -m pytest --noconftest
  tests/test_config_doctor.py` (Q41 — `jen/services/config_doctor.py` is pure, no
  DB/Kea/Flask). Others can be listed and reasoned about but still won't *run* without
  `--noconftest` skipping the autouse DB fixture, or will themselves error even with it
  (a DB-backed test class mixed into an otherwise-pure file): test_dependency_consistency,
  test_docker_config, test_small_hardening_fixes, test_htmx_vendoring, test_pwa_manifest,
  test_device_identity, test_sudoers_command_matching, test_jen_update_root,
  test_changelog, test_no_hardcoded_layout_paths (Q114 — pure `ast` analysis, no DB, but
  needs --noconftest the same way test_config_doctor doesn't). test_layout (Q114 — sources
  install.sh's own functions into a real bash process) self-skips its whole module on
  Windows regardless of --noconftest; it and test_jen_update_root's `TestLoadLayout` both
  need real Linux to mean anything, and even there the plain `pytest` CI job runs as a
  non-root user — a test that needs a *trusted* (root-owned) file bypasses just the
  ownership check via a post-source/monkeypatched override rather than skipping outright,
  the same technique test_kea_helper.py already established for jen-kea-helper's own
  analogous `_bin_dir_ok`. CI is the arbiter; expect one push per round.
- `tests/e2e/` (Q40 — Playwright, `pytest.mark.e2e`) needs both a MariaDB **and**
  `playwright install chromium`, so it doesn't run here either — but its collection
  *safety* does: `py -m pytest --collect-only -q` must still exit 0 and collect every
  other test unchanged, because `tests/e2e/conftest.py` opens with
  `pytest.importorskip("playwright")` precisely so the default `pytest`/`pytest tests/`
  run never notices playwright is absent. Verify that property after touching anything
  under `tests/e2e/`. Template changes for the suite's journeys can still be checked the
  usual way: `py -m ruff check`/`format --check`, and a plain Jinja `Environment` with
  `StrictUndefined` rendering the template against a fabricated context catches undefined
  variables without a server. Run it for real with `JEN_DB_HOST=... python -m pytest
  tests/e2e -m e2e -v` once `playwright install chromium` has run — CI's `e2e` job
  (`.github/workflows/tests.yml`) is what actually gates every push and release.
- `tests/kea_compat/` (Q50 — `pytest.mark.kea_compat`) drives Jen's Kea client against
  REAL kea-dhcp4 3.0 / 3.2 / 3.3 from ISC's Cloudsmith images. It belongs to its own
  workflow, `.github/workflows/kea-compat.yml` (weekly + `workflow_dispatch`, NOT called
  from ci.yml/release.yml, so a Kea release can't redden a push or a tag); every test skips
  unless `KEA_COMPAT_URL` is set, so `pytest` here just reports them skipped. Image tags are
  exact patch versions (no floating `3.0`) — bump the matrix when Kea ships a patch; the
  3.3 dev leg is `continue-on-error`. Read-only against Kea (`config-test`, never
  `config-set`). Run it by hand with `gh workflow run kea-compat.yml`; a workflow-only
  change carries no version bump and no release tag.
- `tests/system/` (Q84 — `pytest.mark.system`) breaks ten of Jen's boundaries on purpose
  against REAL processes: a docker compose stack (`tests/system/compose/`) of Jen under
  gunicorn, two Kea hosts (real kea-dhcp4 + sshd + `jen-kea-helper` installed through
  Jen's own `install_helper`), MariaDB, a resolver that goes silent and a Control Agent
  that answers 500. Driven with `docker compose` / `docker exec` only; the scenario
  scripts run INSIDE the Jen container. Every test skips unless `JEN_SYSTEM_TESTS=1`,
  and `tests/system/conftest.py` overrides the unit suite's autouse DB fixtures the way
  `tests/kea_compat/conftest.py` does. It belongs to its own workflow,
  `.github/workflows/system-tests.yml` (weekly, `workflow_dispatch` with an optional `-k`
  selector, any `-rc.` tag, and — the critical subset only, `test_00/01/02/03/11/12/14/16/17/19` — any `-beta.` tag;
  NOT called from ci.yml/release.yml, so a slow boundary
  test can't redden a push or a tag). It has no Docker or WSL here, so a change to it
  is verified by dispatching the workflow (`gh workflow run system-tests.yml`, ~10 min a
  round). The job summary is the per-scenario table (`summarize.py`); a red run is read
  there and does NOT open an issue. A scenario that fails because Jen really has the bug
  it names is marked `known_bug(...)` (xfail, strict) so it reads "known bug" in the
  table and goes red the day the bug is fixed with the marker still on. Stand-ins are
  named in the test that uses them (no systemd in a container; no GitHub for the updater).
  A workflow-only change carries no version bump and no release tag.

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
Every writer holds ONE lock for its whole read-modify-replace: the class-level `RLock` (threads) and an advisory `flock` on `<config>.lock`
(processes - `install.sh --configure` holds the same one, and merges its wizard's answers into the live file through `tools/config_merge.py`).
A writer called from inside a `mutate` callback raises; edit the parser you were given.
Identity-changing writes - which Kea a server is reached on (`api_url`, `ssh_host`, `ssh_user`, `kea_conf`) and the global connection mode - are guarded in `_write_parser`
(`register_identity_guard`; `app_config.preflight_identity_change` asks the same question on a copy for a route that acts on the Kea host first), and writes of the Kea
config FILE in `kea_host.apply_config` (`investigation_writer()` is the only way past it); never add a route-level check for either - `tests/test_identity_guard.py`
walks the whole tree and fails the one that does.

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
- **The Kea host owns the restore of investigation logging (v5.68.0-beta.29, Q165).** `jen-kea-helper` build 15 arms a root-owned systemd timer (`investigation-arm`;
  `--self-restore [--now]`; state in `/var/lib/jen-kea-helper/`) when logging goes on and puts the `kea-dhcp4` logger back at the deadline with Jen stopped, its database down or
  its settings pointed elsewhere. Jen's index, marker, sweep and observation are **display and audit** - a new investigation *state* on Jen's side is display and is held to
  that, and the property to defend is the walk's I10 (`tests/test_investigation_model.py`): a daemon the host was armed for is never at DEBUG 55 past its deadline + 120 s.
  The restore transformation exists twice (`kea_config_edit.clear_investigation_logging`, the helper's `_restore_logger`) and is held identical by
  `tests/vectors/investigation_restore.json`; a change to either runs the other's test.
  **The host's evidence is the daemon's own answer (v5.68.0-beta.31, Q168, helper build 17).** `restored_at` is written in one place (`_restore_state`), only with an `evidence`: the running daemon's `config-get` on
  its control socket shows the logger the FILE has, Kea's completion id read across rotation (only when no socket answered), or a NEW active process after the one restart; a reload-START line is never evidence and
  a state file that exists and cannot be read is `bad-state`, never "no session" (INV-007, INV-009..011; the walk's I11 and `tests/kea_compat/test_log_levels.py::test_the_daemons_own_control_socket_answers_config_get`).
- **Investigation logging on demand is opt-in (v5.68.0-beta.30, Q167).** `investigation_logging_enabled` (default off, superadmin toggle under Settings -> Kea) gates turning logging ON only (the buttons, the route's `on`, `turn_on`); never gate
  `turn_off`, the sweep, `forget`, `acknowledge`, Health or the host's timer - a session that exists is always restored and shown (`tests/test_investigation_host.py::TestInvestigationLoggingIsOptIn` pins who may read the switch).
  The Kea host's record of an unresolved session is authoritative (INV-008): Jen shows a conflict and refuses to arm over it, never overwrites.
- Anything interpolated into a remote command string is validated on save
  (`valid_remote_path()`, `valid_ssh_target()`, `valid_unix_username()` in
  `jen/services/auth.py`) **and** `shlex.quote`d at the call site. Local `subprocess`
  calls are always list-args.
- **Pushing one config edit to every SSH-configured Kea server goes through
  `jen/services/kea_changeset.py::apply_change()`** (v5.28.0) — plan/preflight every
  target before the first write, commit sequentially, revert already-committed targets
  if a later one fails. Do not write a new per-route read/mutate/apply/restart loop;
  every subnet/shared-network/option/class/DDNS/D2 route already goes through it.

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
as core migrations. Bundled: every directory under `plugins/` (`shipped_plugin_ids()`; seven
today: ipam, network-discovery, watchdog, dns-sync, switchport, wol, presence), all IPv4-only
by design. On a systemd host, install/remove is a request/confirm split (v5.28.0):
the route only queues a marker for a root-privileged service to act on, and
`consume_plugin_results()` is what actually applies the DB row/audit/`restart_pending`
state — called from both the page render and the status poller — once that service's
own result file confirms the root side finished.

### Frontend

Jinja templates in `templates/` + HTMX (`static/js/htmx.min.js`, vendored — see
`tests/test_htmx_vendoring.py`) + hand-rolled dashboard JS + Chart.js. Every `<script>`
tag carries a per-request nonce (`jen/services/csp.py`, `csp_nonce` in templates) —
`script-src` has no `'unsafe-inline'` (v5.22.0, Q18). Inline event handlers don't exist
anymore either: everything goes through base.html's `data-confirm`/`data-href`/
`data-submit` dispatcher or a named function bound with `addEventListener` (delegated
for anything inside an htmx-swapped partial). `style-src` still allows `'unsafe-inline'`
deliberately — 1,200+ inline `style=` attributes would need a real redesign to remove.
Partial templates are `_`-prefixed and returned for HTMX swaps; none of the ones actually
route-rendered for a swap may contain a `<script>` tag (`tests/test_csp.py` enforces it).
A row that names a client carries the Investigate action, written ONLY by the `investigate_link`
macro in `templates/_investigate.html` (the dashboard's browser-built widgets use its JS twin);
`tests/test_investigate_links.py` scans every core template that prints a MAC and refuses one
that neither imports the macro nor is on its short list of pages that are part of the investigation.

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
  (`JEN_VERSION`), the Dockerfile and compose files — keep them in sync (never the
  README; see Versioning). Bump for a release along with a `CHANGELOG.md` entry.
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

- The version strings move together in the **same commit** — six spots:
  `jen/__init__.py` `JEN_VERSION`, `install.sh` `JEN_VERSION`, `Dockerfile`
  `LABEL version`, the `jen-dhcp:` image tag in `docker-compose.yml` and
  `docker-compose.mysql.yml`, and the CHANGELOG heading.
  `tests/test_dependency_consistency.py` enforces this — it will fail on the
  next release until every one is bumped. **The README is deliberately NOT a
  version spot** (v5.33.0): its badge is shields.io's `github/v/release`, which
  shows the latest *stable* GitHub release on its own, and its install/upgrade
  commands say `jen-vX.Y.Z.tar.gz` and link the releases page — `main` carries a
  `-beta.N` most of the time and a stranger's first screen must be the stable one.
  A test refuses a hard-coded version badge or a versioned tarball name in it.
- Bump only at release time, bundled with the `CHANGELOG.md` entry — never per-fix on a
  working branch.
- Once a version has been described as deployed it is frozen; see rule 4 below.

### Release channels (from Q38 / v5.32.0 onward)

Two channels, `stable` and `beta`, selected per install under Settings → System →
Updates (`[updates] channel` in jen.config, default `stable`). There is ONE branch,
`main`; channels are tags. The version grammar is `X.Y.Z` or `X.Y.Z-beta.N` (also
`-rc.N`); `jen/version.py::parse_version` is the only parser and the root updater
carries a byte-identical copy (a test enforces it). A beta of `X.Y.Z` satisfies a
plugin's `requires_jen: X.Y.Z`.

Q38 itself (v5.32.0) ships straight to stable: a pre-5.32 box asks only for the latest
non-prerelease, so it is the bootstrap that lets a box choose beta at all. From the
release after it, every MINOR and every non-trivial PATCH ships beta-first:

1. Steps land on `main` as usual (CI green between commits).
2. The release commit sets **all six version spots (CHANGELOG heading included)** to
   `X.Y.Z-beta.1`; push; CI green; tag `vX.Y.Z-beta.1`. The release workflow marks any
   tag containing `-` as a GitHub **prerelease**: beta boxes are offered it, stable
   boxes never see it.
3. Fixes found in beta land on `main` and ship as `-beta.2`, `-beta.3`, … each with
   its own CHANGELOG heading.
4. **Promotion is the maintainer's call** ("promote"). The promotion commit changes
   only version strings and the CHANGELOG (fold the beta headings into one
   `## [X.Y.Z]` entry with a "Beta history" line); no code. Push, CI green, tag
   `vX.Y.Z`. Both channels are offered it. **One standard exception to
   version-only:** folding away the individual beta headings removes the literal
   CHANGELOG heading `tests/test_upgrading_doc.py`'s floor canary checks for
   directly, so the promotion commit also makes that test accept the floor on
   the newest stable entry's own Beta history line (this fix is now permanent
   code — a future promotion shouldn't need to repeat it). The floor's own
   *value* doesn't move in the promotion commit itself: `docs/upgrading.md`
   keeps its old baseline through promotion (still true, still worth reading),
   and the **first release commit after promotion** is what starts a fresh
   `docs/upgrading.md` at the new baseline (the old page archives to
   `docs/release-history/upgrading-<old>-to-<new>.md`), moves the test
   floor forward to that release's own version, **and moves
   `JEN_STABLE_VERSION` (top of `.github/workflows/tests.yml`) — the stable
   release the upgrade-from-stable CI job starts from — to the newly promoted
   one** — an un-numbered but standard part of the next Q, not the promotion
   itself.
5. A PATCH to a *stable* release while a later beta soaks is the one branch case:
   `git checkout -b release/X.Y vX.Y.Z` → cherry-pick → bump → tag from that branch →
   delete the branch. Trivial fixes to a beta itself skip the soak (`-beta.N+1`).

Say which channel a tag is for in the commit message and in the final report
("tagged v5.33.0-beta.1 (beta channel)"). Never tag a plain `vX.Y.Z` without the
maintainer's promote; never tag a `-beta.N` on a commit whose six version spots don't
carry that exact suffix (the box would re-install itself forever).

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
10. **Beta first, promote on the maintainer's word (Q38 / v5.32.0+).** A release is
   tagged `vX.Y.Z-beta.N` first (all six version spots carry the suffix); the plain
   `vX.Y.Z` tag is a separate promotion commit that changes only version strings and
   the CHANGELOG, made only when the maintainer says "promote". See "Release
   channels" above for the full flow, including the stable-hotfix branch case.
