# Changelog

*Detailed per-series notes for the 3.x line live in [docs/release-history/](docs/release-history/).*

## [4.4.21] - 2026-08-15

### Fixed: the "restart required" banner could get stuck showing forever after a real restart

Reported directly: after updating a plugin and restarting, the green
"Jen is restarting..." message just sat there — asked "maybe it's
restarted??"

### Two different things, only one of them a bug
That specific green message is a one-time Flask flash notification
triggered by clicking the amber "⚠️ Jen restart required" banner's own
"Restart Jen Now" button — expected to disappear on the next page
load, not a bug, just no auto-refresh to visually confirm completion.

The real, separate bug is in the amber banner itself: 9 call sites
across `settings.py` and `plugins.py` set `restart_pending=true`
(every plugin install/enable/disable/uninstall, several infrastructure
settings saves) — but before this fix, only that one specific button's
own route ever cleared it back to `false`. Any restart triggered
another way — a manual `systemctl restart jen`, the self-update flow,
a server reboot, crash recovery — left the persistent banner stuck
showing "restart required" indefinitely, even after a real restart had
genuinely just happened.

### Fixed
`jen/__init__.py`'s `create_app()` now clears `restart_pending`
unconditionally right after `init_jen_db()`, on every startup — the
app booting at all is definitive proof whatever restart was pending
has now occurred, regardless of what triggered it, so the fix doesn't
depend on any specific UI action having been the cause.

### Tests
Two new tests in `tests/test_settings.py::TestRestartPendingClearedOnStartup`.
The main one directly reproduces the exact stuck-forever scenario —
sets the flag `true` (simulating an earlier plugin action), then calls
a fresh `create_app()` (exactly what runs on every real startup,
regardless of trigger) and confirms the flag clears. Validated the
standard way: reverted the fix, confirmed the test failed with a
specific, accurate assertion message, restored the fix, confirmed both
tests pass. Full suite: **330 passed** (up from 328).

## [4.4.20] - 2026-08-15

### Fixed: every POST form in both bundled plugins was missing its CSRF token

Reported directly: a plain 403 "session security token is missing or
expired" trying to mark an IPAM address as static — on a session that
was genuinely valid.

### Root cause
`csrf_token()` is registered as an app-wide Jinja global via Jen's core
`context_processor` and is genuinely available inside plugin
templates. It was simply never called in any POST form in either
bundled plugin. Five forms total: `edit-form` and `clear-form` in
`plugins/ipam/templates/ipam/subnet.html`; two scan-trigger forms in
`plugins/network-discovery/templates/network_discovery/index.html`
and one in `results.html`. Every submission through any of them hit
Jen's CSRF middleware and was rejected outright, regardless of session
validity.

This had no test coverage because the whole suite runs with
`WTF_CSRF_ENABLED=False` by default (mirroring Flask-WTF's own config
key) — the right default for testing application logic without CSRF
noise, but it meant this entire class of bug (a form silently missing
its token field) had no test surface at all until now.

### Fixed
- All five forms above: added
  `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`.
- **New: `tests/test_plugin_template_csrf.py`** — rather than five
  narrow tests for the five specific forms found, this scans every
  `<form method="POST">` block in every current *and future* plugin
  template file and asserts each one contains `csrf_token` before its
  closing `</form>` — a structural guard for the whole plugin
  ecosystem, not just the routes that happened to get reported.
  Validated the detector itself the standard way: reverted one fix,
  confirmed the test correctly failed with a specific, actionable
  message identifying exactly which form and file, then restored the
  fix and confirmed all tests pass.

### Verification
Reproduced the exact reported 403 end-to-end before touching anything:
real login, real session, real CSRF middleware enabled (`WTF_CSRF_ENABLED=True`,
explicitly overriding the test-suite default), a real POST with no
token confirmed 403, then a token extracted from the real rendered
page confirmed the fix resolves it. Full suite: **328 passed** (up
from 321).

### If you're running the IPAM Lite plugin from its separate repo
**This release does not fix your actual running plugin.** The IPAM
plugin bundled in this repo (`plugins/ipam/`) is a reference copy —
production installs typically run the separate, actively-maintained
`ltkojak/jen-plugin-ipam` repo instead, which has diverged further
(unmanaged-subnet support, a third database table this bundled copy
doesn't have) and had the exact same bug, independently confirmed and
fixed there, released separately as v1.3.2. Install the new
`plugin.zip` from that release through Jen's Plugins settings page —
this jen-kea release alone will not reach it.

## [4.4.19] - 2026-08-15

### Fixed a real regression from v4.4.18: IPAM disappeared from the menu after updating

Reported directly: after updating to v4.4.18, the IPAM plugin was still
installed and its data was fine, but it vanished from the navigation
menu entirely. Root cause was my own change in v4.4.18, and it's worth
being plain about what went wrong.

### What actually happened
v4.4.18's `run_plugin_migrations()` correctly started requiring the new
`{"version": int, "sql": str}` manifest format and rejecting the old
flat-list-of-SQL-strings format. That part was fine — the problem is
what I wired that rejection to. `load_plugins()` treated *any* migration
failure, including a manifest-format mismatch, as a reason to skip
loading the plugin's blueprint and nav entry entirely, not just skip
its migrations. The real installed IPAM plugin (from its own separate
repo, not the copy bundled in jen-kea, and with a schema that had
diverged further — a third `ipam_subnets` table jen-kea's bundled
version doesn't even have) was still on the old manifest format, so it
correctly failed the new validation and then, incorrectly, disappeared
from the UI entirely — even though its actual tables and data were
completely unaffected.

### Fixed
- **Old flat-string manifests are now accepted**, not rejected. Each
  plain SQL string is treated as an implicit migration numbered by its
  1-based position in the list — the exact order the pre-4.4.18 runner
  always executed them in, just now actually tracked going forward.
  Mixed manifests (some old-format strings, some new-format objects)
  are accepted too, since a plugin author might migrate one entry at a
  time rather than all at once.
- **A migration problem of any kind no longer prevents a plugin from
  loading.** `load_plugins()` now logs the failure loudly and proceeds
  to load the plugin's blueprint and nav entry regardless. A schema
  issue with one table should never be able to take down access to a
  plugin's otherwise-working functionality — this is a real, general
  design correction, not just a fix scoped to the format-mismatch case
  that surfaced it.

### Verification
Reproduced Matthew's exact real, diverged IPAM manifest content
(three tables, old format) directly against live MariaDB and confirmed
it now applies correctly with proper version tracking. 6 new tests in
`tests/test_plugin_migrations.py` covering old-format acceptance,
sequential implicit versioning, idempotency, mixed-format manifests,
the real diverged manifest specifically, and — via a new
`TestLoadPluginsDoesNotSkipOnMigrationFailure` class — that
`load_plugins()` genuinely still attempts to load a plugin even when
its migrations fail outright, not just when the manifest format is the
issue. Caught and fixed a test-isolation mistake of my own while
writing these: an early draft reused the `plugin_id` "ipam" already
touched by an earlier test in the same file, causing a false failure
from leftover tracked-migration state rather than a real bug — fixed by
giving the new test its own distinct plugin_id. Full suite:
**321 passed** (up from 315), run exactly as CI executes them.

## [4.4.18] - 2026-08-14

### Tier 2, part 3: plugin migrations finally get the same versioned discipline as core Jen

Last of the isolated-subsystem Tier 2 items. Config-check UI surfacing
is the one remaining item — it touches the actual config-apply path in
`subnets.py`, so it's staying last, same reasoning as before.

### The bug, precisely
`_run_plugin_migrations()` re-executed **every** SQL statement in a
plugin's manifest on **every single install or update**, with no
tracking of what had already run. A single try/except wrapped the
whole batch: any one migration failing silently aborted every
migration after it, logged one error line, and the install/update
route still reported success to the admin. Every migration shipped
happened to be `CREATE TABLE IF NOT EXISTS` (naturally idempotent), so
this was invisible in practice — but any future migration that wasn't
naturally idempotent (an `ALTER TABLE ADD COLUMN`, a data backfill)
would have failed loudly on the second install and taken every later
migration down with it, silently, forever, since nothing ever re-ran
migrations at Jen startup either — only at install/update time.

### Fixed
- **New `plugin_schema_migrations` table** — added as core migration
  10 in `jen/models/migrations.py`, using the exact same versioned,
  transactional, "abort-loudly-on-failure" discipline core Jen's own
  schema migrations have used since migration 1. Composite
  `(plugin_id, version)` key since multiple plugins share the table.
- **`jen/services/plugins.py`: `run_plugin_migrations()`** replaces
  `_run_plugin_migrations()`. Each migration is applied and recorded
  individually — already-applied versions are skipped, a manifest that
  gains a new migration in a later release only applies the new one,
  and a failing migration stops that plugin's remaining migrations and
  returns a real error message identifying which one failed, instead
  of silently reporting success.
- **Manifest format changed**: `db_migrations` is now a list of
  `{"version": int, "description": str, "sql": str}` objects instead
  of a flat list of SQL strings — the version field is what actually
  gets tracked. Both shipped plugins (`plugins/ipam`,
  `plugins/network-discovery`) converted to the new format, SQL content
  unchanged (verified byte-for-byte via a round-trip check before and
  after conversion). Both `plugin.zip` archives rebuilt from the
  updated `manifest.json` — the zip is what `install_plugin()` actually
  downloads and extracts, so the raw file in the repo alone wouldn't
  have been enough.
- **Migrations now also run on every Jen startup** (`load_plugins()`),
  not just at install/update time — mirrors `init_jen_db()` calling
  `run_migrations()` on every boot. A manually-copied plugin, or a
  plugin whose manifest gained a migration in a later release, now
  catches up automatically on restart rather than only if someone
  clicks "Update" again.
- **`install_plugin()` now surfaces a real migration failure** to the
  admin instead of installing the files and quietly logging an error —
  "Plugin files installed, but a DB migration failed: ..." with the
  specific SQL error, rather than a bare success message.

### Tests
`tests/test_plugin_migrations.py` — new file, 16 tests, zero coverage
existed before this. Covers tracking/idempotency, failure handling
(the actual bug), manifest validation (rejects the old flat-string
format cleanly instead of crashing, rejects duplicate version numbers,
applies out-of-list-order migrations in correct version order), and
both real shipped manifests end-to-end against real MariaDB — not
synthetic data. Validated these are genuine regression guards the same
way as the two previous instances of this practice (v4.4.16, v4.4.17):
temporarily swapped in the exact old buggy behavior and confirmed 8 of
16 tests correctly failed against it (specifically: tracking, failure-
handling, and manifest-validation tests — the ones actually exercising
the bug), then restored the fix and confirmed all 16 pass.

## [4.4.17] - 2026-08-14

### Tier 2, part 2: HA status view — a real "no backup" warning, and a genuine correctness fix found along the way

Third and second-to-last item off the Jen maturity roadmap's Tier 2 list
(config-check UI surfacing is the one remaining item, saved for last
since it's the one touching the actual config-apply path).

### Added
- **A persistent "this HA pair currently has no working backup" warning**
  on `/servers`, shown whenever HA mode is configured but no server is
  currently reporting a healthy `hot-standby`/`load-balancing` state.
  This is complementary to the existing `ha_failover` alert, not a
  duplicate of it — that alert only fires once, at the moment of a state
  *transition*, and says nothing about the current state to someone
  loading the page hours later. Checked this specifically before
  building anything: confirmed `ha_failover` genuinely does fire
  correctly (unlike the `rogue_device` alert bug found and fixed
  earlier in this series), so this is filling a real, adjacent gap
  rather than working around a broken alert.

### Fixed
- **The "⚡ ACTIVE" badge only ever checked `role == 'primary'`** —
  meaning if the primary genuinely went offline and the standby took
  over (the entire point of HA), no server would show as active at all,
  since standby's role is never `'primary'`. The correct rule depends
  on the actual reported state: `load-balancing` means both nodes serve
  simultaneously (both active, regardless of role); `hot-standby` means
  only the primary actually serves while both partners are healthy
  (standby genuinely idle); `partner-down` means whichever server is
  reporting it is now serving solo, regardless of its configured role.
  Caught a mistake in my own first draft of this fix by actually testing
  it against a realistic "both servers healthy" scenario before
  shipping: an early version marked *both* nodes active whenever either
  reported `hot-standby`, which is wrong for the normal, most common
  case — only found because I ran it, not because I reasoned about it
  correctly the first time.

### Tests
Three new tests in `tests/test_servers.py::TestHaStatusDerivation`,
each going through the real `/servers` route end to end rather than
testing the derivation logic in isolation — covering healthy
hot-standby (only primary active, no warning), primary-down-standby-
took-over (standby active, warning shown), and load-balancing (both
active, no warning). Validated these are genuine regression guards the
same way as the self-update test in v4.4.16: reverted the active-role
fix back to the original `role == 'primary'`-only logic and confirmed
two of the three tests correctly failed against it, then restored the
fix and confirmed all three pass again.

## [4.4.16] - 2026-08-14

### The self-update mechanism has never updated run.py — likely the most significant bug found this entire audit series

Not a v4.4.15 regression — this bug has existed since the self-update
feature was built. It only became externally visible now because
v4.4.15 was the first release in this whole audit series to actually
change `run.py` itself.

### The bug
`self_update()`'s generated helper script (the one that copies files
from a downloaded release into `/opt/jen`) has a `copy_cmds` list that
included `jen/`, `templates/`, brand icons, the systemd unit, and the
sudoers file — **but never `run.py`**, the actual file systemd executes
as the entry point. Every self-update correctly refreshed the `jen/`
package and correctly reported the new version (`JEN_VERSION`, which
lives in `jen/__init__.py` — part of the package that *did* get
updated), giving every appearance of a complete, successful update —
while `run.py` itself silently stayed frozen at whatever it was from
the last time `install.sh` was run manually, or a fresh install.

**Impact:** anyone using the "Check for Updates" → "Update Now" button
as their actual deployment path, rather than manually running
`install.sh --upgrade`, has had a stale `run.py` this whole time,
regardless of how many releases they've self-updated through. Any past
or future change to `run.py` specifically — SSL/TLS configuration,
port binding, the background scheduler startup call, the
env-var-to-config generation logic for Docker — would never have
actually reached a self-updated installation, silently, with the UI
reporting success and the correct version number throughout.

### How this was found
A very long, methodical debugging session with the actual production
user, working from "the logs still look unformatted after the v4.4.15
logging update" through a sequence of ruled-out hypotheses: Werkzeug
version (tested 2.3.7, 3.0.1, and the exact 3.0.1 running in
production — all correct in isolation), the `www-data` user
specifically, stale `__pycache__` (genuinely stale, genuinely cleared,
made no difference), non-TTY output, real SSL context, real
`create_app()` — every single variable, tested individually and
combined, worked correctly. The actual break was found only by
checksumming the deployed `/opt/jen/run.py` against the shipped
release and discovering a hard mismatch (175 lines deployed vs. 186
shipped) — at which point re-reading `self_update()`'s own file list
made the gap obvious.

### Fixed
- `jen/routes/settings.py`'s `self_update()`: `run.py` added to the
  generated helper script's copy commands and to the post-copy
  `chown`. One line each, but the actual fix is knowing to look for it
  — see `tests/test_self_update.py` below for how this is now
  permanently guarded against.
- **New: `tests/test_self_update.py`** — `self_update()` had zero test
  coverage of any kind before this, which is exactly how a bug this
  fundamental survived indefinitely. The new test builds a real,
  minimal, valid tarball on the fly, mocks only the network calls
  (GitHub API response + tarball download), and intercepts the actual
  generated helper script's file content before cleanup deletes it —
  then asserts a real `cp ... run.py ... run.py` command is present.
  Validated the hard way: first draft used a loose substring check
  (`"run.py" in script`) that passed even against deliberately
  re-broken code, because the `chown` line also happens to mention
  `run.py` — caught by actually reverting the fix and confirming the
  test failed before trusting it, exactly as this whole audit series
  has tried to do throughout. Tightened to a regex requiring an actual
  `cp` command, re-verified it now correctly fails against the broken
  version and passes against the fixed one.

### If you're running a self-updated install
Manually verify `/opt/jen/run.py` actually matches your git checkout's
`run.py` after this update — `sha256sum /opt/jen/run.py ~/jen/run.py`
should show identical hashes. If your checkout is current and the
hashes still don't match, something else copied it out of sync and is
worth investigating separately.

## [4.4.15] - 2026-08-14

### Tier 2, part 1: real observability — expanded metrics and actual logging configuration

First two items off the Jen maturity roadmap's Tier 2 list. Both chosen
specifically because they're additive and don't touch any file that's
ever had a security bug found in it — `subnets.py`/`servers.py` (the
config-check UI and HA status view) are intentionally saved for last.

### Added — `/metrics` expanded from 2 metric families to 7
- `jen_subnet_reserved_hosts` (gauge) — static reservation count per subnet
- `jen_subnet_pool_size` (gauge) — total pool addresses per subnet
- `jen_subnet_utilization_ratio` (gauge) — active/pool_size, 0.0–1.0
- `jen_alerts_sent_total` (**counter**) — cumulative alerts sent, by
  type and status. Confirmed `alert_log` is never pruned anywhere in
  the codebase before treating it as a genuine monotonic counter — a
  fabricated "counter" that occasionally resets would silently break
  every `rate()`/`increase()` panel built on it in Grafana.
- `jen_server_up` (gauge) — per-configured-Kea-server reachability, for
  multi-server/HA visibility beyond the existing aggregate `jen_kea_up`

Pool size and utilization read from the existing `lease_history`
snapshot table (populated every `snapshot_interval_minutes`, 30min
default) rather than querying Kea's live config-get API on every
Prometheus scrape — documented explicitly in the endpoint's docstring,
since that's a real freshness tradeoff, not an oversight. Everything
else (active leases, reservation counts, per-server status) is live,
since freshness matters more than scrape cost for those. This is
deliberately just *more gauges/counters exposed*, not Jen computing
"trend" or "rate" values itself — Prometheus's own scrape-and-store
model already produces a real trend line from repeated gauge scrapes,
and PromQL's `rate()`/`increase()` already produce a real firing rate
from a real counter. Six new tests in `tests/test_dashboard.py`,
including a check that every metric family has both its `HELP` and
`TYPE` comment lines (the actual Prometheus exposition format
contract) and that `jen_alerts_sent_total` is specifically declared a
`counter`, not a `gauge`.

### Added — actual logging configuration (`jen/logging_config.py`)
Jen had **zero explicit logging configuration anywhere** before this —
no `logging.basicConfig()`, no handlers, confirmed by grep across the
whole codebase. In practice this meant every `logger.info(...)` call
in the app was silently discarded by Python's `lastResort` fallback
(a bare `StreamHandler(stderr)` that only handles WARNING and above
when nothing else is configured) — no timestamps, either. The
workaround visible in `jen/models/db.py`: the two "connection pool
initialised" messages were logged at `WARNING` specifically so they'd
actually appear. That workaround is no longer necessary and has been
reverted to proper `INFO` now that logging is genuinely configured;
the two "pool failed, using direct connections" messages correctly
stayed at `WARNING`, since those really are warnings.

- Two output formats: `plain` (default — human-readable, safe for
  `journalctl -u jen -f`, doesn't change existing operator experience)
  or `json` (one JSON object per line: timestamp, level, logger name,
  message, plus any `extra={}` fields — for Loki/ELK/Promtail without
  a log-parsing regex). Configurable via `[server] log_format` in
  `jen.config` or `JEN_LOG_FORMAT`.
- Configurable level (`log_level` / `JEN_LOG_LEVEL`, default `INFO`).
- Optional rotating file output (`log_file` / `JEN_LOG_FILE`,
  `log_retention_days` / `JEN_LOG_RETENTION_DAYS`, default 14 days).
  Stdout/stderr (captured by systemd's journal, which already handles
  its own rotation via `journald.conf`) remains the default — Jen
  doesn't need to reinvent log rotation for the common case, the file
  handler is there for anyone who wants to tail a real file directly
  instead of using journal export tooling.
- Wired into `run.py` in two phases: once immediately with env-var
  fallback only (before `create_app()` runs, since `create_app()`
  itself logs DB pool setup before `extensions.cfg` is populated), and
  again with the real loaded config once `create_app()` returns.
- 11 new tests in `tests/test_logging_config.py`: idempotency (no
  duplicate handlers on repeated calls — would otherwise print every
  line 2x/3x), config-vs-env-var priority, and — genuinely exercised,
  not just asserted — real JSON output actually parses as JSON with
  the claimed fields, and the optional file handler actually creates
  and writes to a real file on disk.

### Verification note
Both features fully verified against the same non-root-user, real-
MariaDB, real-TCP-connection setup established in v4.4.12 — this is
now the standing method for anything claimed "verified" in this repo,
not a one-off. **295 tests passed** (up from 278: 6 new metrics tests
+ 11 new logging tests), run exactly as GitHub's CI runners execute
them. The metrics endpoint's actual exposition-format output was also
rendered unmocked once, by hand, to confirm it degrades gracefully
(`jen_kea_up 0`, no crash) when Kea is genuinely unreachable — not
just that the test assertions pass.

## [4.4.14] - 2026-08-13

### Housekeeping: five orphaned files removed, and a real gap in the deploy process documented

Found by pulling the actual published `v4.4.13` GitHub archive and
diffing it against the working tree that built it — the first time
that check has been done this whole audit series. It surfaced a real
structural gap: the tarball-based deploy process
(`tar xzf --strip-components=1 -C .`) can only add or overwrite files,
never delete one that's no longer in the current tarball but still
sitting in the working tree from an earlier release. See
`docs/ARCHITECTURE.md` §5 for the full writeup.

### Removed
- **`jen.py`** (repo root) — the original pre-2.6.0 monolith. Confirmed
  byte-identical to `legacy/jen.py` (minus the explanatory "LEGACY
  FILE — NOT EXECUTED" header), confirmed never copied anywhere during
  install (`install.sh` only ever copies `legacy/jen.py` to the install
  destination), confirmed not referenced by the Dockerfile since the
  v4.4.9 fix. 6,272 lines of dead duplication.
- **`docs/github-release-2.6.x.md`, `-2.7.x.md`, `-3.1.x.md`, `-3.2.x.md`**
  — confirmed byte-identical duplicates of the properly-organized copies
  already living in `docs/release-history/`, which is what
  `docs/release-history/README.md` actually links to. These four loose
  copies in bare `docs/` were leftover from before that subfolder
  existed.

### Documentation
- `docs/ARCHITECTURE.md` — added the deploy-model gap to the "Known
  gaps" section, including the practical mitigation (periodically diff
  the real published archive against the working tree) rather than
  just noting the problem.

## [4.4.13] - 2026-08-13

### The first release to actually publish since v4.4.10

Not new functional content on its own — this tag exists because
**v4.4.11 never actually became a GitHub Release.** When that tag was
pushed, `release.yml`'s `test` job (correctly) failed on the
`/etc/jen` permission bug documented in v4.4.12, so the `needs: test`
gate correctly blocked `release` from running. The tarball and
changelog entry for v4.4.11 existed in this repo; the published GitHub
Release did not — confirmed directly by checking
`github.com/ltkojak/jen-kea/releases`, which showed v4.4.10 as the
newest entry even after the v4.4.11 tag was pushed. Jen's own
"Check for Updates" feature was reporting the truth the whole time —
there genuinely was nothing newer published to check for.

The v4.4.11 git tag still exists and now permanently points at a
commit that predates the CI fix, so re-running that tag's workflow
would just fail the same way again. Rather than force-move an existing
tag, this cuts a fresh release at current `main` HEAD — which now
carries v4.4.11's real content (the full Tier-1 maturity-roadmap work:
CI test gate, bandit/pip-audit scanning, SECURITY.md, ARCHITECTURE.md,
23 new tests) together with the v4.4.12 CI fix that makes the gate
itself actually pass on real runners.

Once this tag's `release.yml` run goes green end to end, Jen's
"Check for Updates" should correctly show v4.4.13 as available.

## [4.4.12] - 2026-08-13

### Fixed: the new CI itself was broken on real GitHub Actions runners

The `pytest` job added in v4.4.11 passed every local verification —
including a full run against real MariaDB — and still failed
immediately on GitHub's actual runners. Root cause: `init_jen_db()`
unconditionally calls `os.makedirs("/etc/jen/ssl")` and
`os.makedirs("/etc/jen/ssh")` at startup. On a real Jen deployment this
is fine (Jen runs as `www-data`, which owns `/etc/jen`). On a
GitHub-hosted runner, the default `runner` user isn't root and `/etc` is
root-owned — `PermissionError: [Errno 13] Permission denied: '/etc/jen'`
on the very first test's setup, cascading into all 278 tests failing at
setup.

**Why local verification missed this:** every verification run in the
v4.4.11 audit sandbox was executed as root, which meant `/etc/jen` was
always writable without ever being explicitly created or checked. The
bug was invisible under the exact conditions it was tested in.

**Fixed:** `.github/workflows/tests.yml` now explicitly creates and
`chown`s both `/etc/jen` and `/opt/jen` to the runner user before
`pytest` runs, with a comment explaining why this step exists and what
it's compensating for.

**Verification for this fix specifically did not repeat the same
mistake.** Created a genuine non-root user in the audit sandbox,
reproduced the exact `PermissionError` from the GitHub Actions log
under those conditions first, then applied the fix and confirmed
`278 passed` running as that non-root user — over a real TCP connection
to MariaDB (`127.0.0.1`, matching how GitHub's `services:` containers
are actually reached, not a UNIX socket) — with `/etc/jen`, `/opt/jen`,
and `/tmp` all freshly created for that run, matching what an actual
GitHub Actions runner starts with. This is meant to be the standing
practice going forward for anything CI-related: verify under the actual
execution conditions (user, filesystem state, network topology), not
just "run it and see it pass" in an environment that happens to differ
from production in a way that hides the bug.

## [4.4.11] - 2026-08-13

### Process maturity: CI test gate, static analysis, dependency scanning, documented threat model, expanded test coverage

The first pass at "Tier 1" of the Jen maturity roadmap (comparing Jen
against ISC Stork's engineering rigor). None of this is a feature —
it's the process infrastructure that a project needs regardless of team
size, and until now Jen had none of it.

### Added
- **CI now runs the full test suite on every push and PR, and gates every
  tagged release on it passing.** Previously `release.yml` built and
  tagged a release with zero automated test verification — confirmed
  by reading the workflow file directly. New reusable workflow
  (`.github/workflows/tests.yml`) runs `pytest` against a real MariaDB
  service container, called by both a new `ci.yml` (every push/PR) and
  `release.yml` (`release` job now `needs: test`).
- **Static security analysis in CI.** `bandit` runs against `jen/` and
  `plugins/` on every push, diffed against `.github/bandit-baseline.json`
  — a snapshot of the 47 findings that existed at time of writing, each
  manually traced and confirmed safe (whitelisted table names, int()-cast
  values, the SSH trust-on-first-use model — see `docs/ARCHITECTURE.md`).
  New findings introduced after the baseline fail CI; the reviewed
  backlog doesn't block anything. Verified this actually works, not just
  configured it: generated the baseline, then injected a fake
  `shell=True` vulnerability and confirmed bandit still fails CI with
  the baseline present, before reverting the test injection.
- **Dependency vulnerability scanning in CI.** `pip-audit` runs against
  the actual installed dependency set on every push. Verified in a
  properly isolated virtual environment (not the shared audit sandbox,
  which had accumulated unrelated packages across a long session and
  gave a contaminated first result): zero vulnerabilities in any of
  Jen's actual runtime dependencies at their current floor-pinned
  versions, once pip itself is upgraded first.
- **`.github/dependabot.yml`** — watches the GitHub Actions used in these
  workflows and opens PRs to bump pinned commit SHAs forward. Doesn't
  include a `pip` ecosystem entry — Dependabot's pip support needs an
  actual `requirements.txt`/`pyproject.toml` to parse, which Jen
  deliberately doesn't have (dependencies are pinned inline in
  `install.sh`); `pip-audit` in CI covers the same underlying need
  without requiring a manifest file Jen doesn't otherwise use.
- **`SECURITY.md`** — responsible disclosure process, scope, and an
  honest statement of what level of security scrutiny this project has
  actually had (periodic deep-dive audits, not a funded external
  pentest).
- **`docs/ARCHITECTURE.md`** — system overview plus five deliberate
  trust boundaries that previously only lived in CHANGELOG entries and
  audit conversation history: the self-update sudoers grant, the SSH
  host-key trust-on-first-use model, the SSH-based config-push design
  (vs. Kea's native API), API keys being global-scope by design, and
  why dependencies are floor-pinned rather than exact-pinned. Each
  documents both the reasoning and what a future change should watch
  out for.
- **23 new tests** closing coverage gaps in exactly the files where real
  bugs were previously found without any test catching them:
  - `tests/test_servers.py` (new, 8 tests) — full route coverage for
    `servers.py`, including a regression guard that the restart command
    uses the hardened `StrictHostKeyChecking=accept-new` and not the
    old `=no`. Found and fixed a real bug in the test fixtures
    themselves along the way (incomplete mocked server dicts caused a
    `KeyError` on the redirect target's render) — confirmed the fix
    with a live re-run rather than just editing and assuming.
  - `tests/test_ddns.py` (new, 6 tests) — auth boundary, log-fetch error
    handling, and the same SSH-hardening regression guard for both SSH
    call sites in this route. Caught and fixed a test-isolation bug of
    my own while writing this: an early draft mutated the shared global
    `extensions.cfg` object directly, which would have leaked a fake
    config section into every test running afterward; fixed to swap the
    whole reference via `monkeypatch` instead.
  - `tests/test_settings.py` (+6 tests) — direct regression guards that
    `/settings/system/save-mfa-mode` and `/settings/upload-nav-logo`
    (the two routes found missing their `@bp.route(...)` decorator
    entirely in the v4.4.9 audit) are actually registered, actually
    persist/save correctly, and are actually admin-gated. Uses a real,
    PIL-verified 1x1 PNG for the upload test — an initial hand-typed
    PNG byte sequence was subtly invalid and would have made the test
    meaningless; caught by actually decoding it with PIL before trusting it.
  - `tests/test_subnets.py` (+3 tests) — regression guard for the
    `save_subnet_note()` missing-access-check fix from v4.4.9.

### Housekeeping
- Removed a 6th instance of the dangling section-header-comment pattern
  (`# Audit Log` in `jen/routes/ddns.py`, trailing, nothing under it) —
  same leftover-from-refactor issue already cleaned up five times
  across `servers.py` and `subnets.py` in earlier releases.

### Verification note
Every claim above was checked directly in this environment before being
written down, not just asserted: bandit and pip-audit were both actually
run (not just added to a YAML file and assumed correct), the baseline
mechanism was proven with a live fake-vulnerability injection, and the
full test suite — 278 tests, up from 255 — was run against a real
MariaDB instance end to end, including catching and fixing two real
bugs in the new test code itself along the way.

## [4.4.10] - 2026-08-09

### Test infrastructure: full suite now passes 255/255

Closes out the `jen_test.hosts` gap that had been blocking six tests
across every audit round since v4.4.4, plus one flaky test assertion
found in the process. No production code changed.

### Fixed
- **`jen_test` was missing the Kea-side schema tables entirely.** `kea_db`
  and `jen_db` both point at the same single `jen_test` database in
  tests, but `init_jen_db()` only ever created *Jen's* own tables — in
  production, `hosts`/`lease4`/`dhcp4_options` come from Kea's own
  schema installer, not from Jen. `lease4` and `dhcp4_options` had
  apparently been created manually at some point (tests touching them
  already passed), but `hosts` never was, which is exactly why every
  test that needed to `INSERT INTO hosts` failed with `Table
  'jen_test.hosts' doesn't exist` — six tests, across `test_reservations.py`
  and `test_security_fixes.py`, every single audit round since v4.4.4.
  Added `_ensure_kea_schema()` to `tests/conftest.py`: three
  `CREATE TABLE IF NOT EXISTS` statements matching Kea's real
  `dhcp4.sql` schema (trimmed to the columns Jen's own queries actually
  touch), run once per test session alongside the existing
  `init_jen_db()` call. Idempotent regardless of what's already present,
  so the test suite is now fully self-contained — no more manual DB
  setup steps required outside this repo, on any machine.
- **One flaky test assertion.** `test_reservation_hidden_from_restricted_user`
  asserted the literal search query string never appeared anywhere in
  the response — but the search page always echoes the query term back
  in the input box's value and the "No results found for X" message,
  regardless of whether anything actually leaked. That assertion was
  never going to reliably test what it claimed to. Fixed to check the
  actual leaked data (the target reservation's IP address) is absent,
  plus a positive check that the page reports zero results.

### Verification note
Actually installed MariaDB, created a real `jen_test` database, and ran
the complete `pytest` suite end-to-end in this environment for the
first time this whole audit series — previous rounds could only verify
via AST parsing, real imports, and targeted mocked unit tests, since no
live database was available. This is a meaningfully higher bar of
verification: **255 passed, 0 failed**, confirming every fix from
v4.4.4 through v4.4.9 behaves correctly against a real database, not
just in isolated reasoning. (Also had to symlink the test environment's
repo location to `/opt/jen` — `create_app()` hardcodes its
`template_folder` to that production-specific absolute path, which is
correct for how Jen is actually deployed but meant the templates
weren't found from an arbitrary checkout location; unrelated to any
code in this release, just a note for future reference.)

## [4.4.9] - 2026-08-08

### Security & correctness: findings from a full file-by-file audit

This closes out a complete pass through every previously-unread file in
the codebase, prompted by the missing-`@bp.route` bug found in
`settings.py`. Two things turned out to be broken features (not
security bugs on their own), and a real, consistent pattern of subnet-
authorization gaps showed up on secondary/admin-action endpoints —
distinct from the primary list views, which were already solid.

### Fixed — broken features
- **MFA enforcement policy could not be changed through the running
  application at all.** `save_mfa_mode()` was missing its
  `@bp.route(...)` decorator entirely — Flask never registered the URL,
  so the settings form's POST to `/settings/system/save-mfa-mode` was a
  guaranteed 404 on every attempt. Verified the fix by actually
  registering the blueprint against a real Flask app and confirming the
  route now appears in the URL map.
- **Custom nav-bar logo upload was equally broken**, same root cause —
  `upload_nav_logo()` was missing its route decorator too. Both were
  the *only* two instances of this bug anywhere in the app — checked
  systematically across every route file and both plugins.

### Fixed — subnet-authorization gaps
A consistent pattern: primary list views (leases, reservations, devices,
subnets) and the routes fixed in earlier 4.4.x releases were already
correctly scoped to `current_user`'s accessible subnets. Secondary
endpoints added since — mostly dashboard widgets and individual admin
actions — inconsistently inherited that discipline. All of the
following now use the same `add_subnet_restriction()` / `filter_subnet_map()`
/ `can_access_subnet()` pattern already used everywhere else:

- `jen/routes/subnets.py`: `save_subnet_note()` had no access check at
  all — a subnet-restricted admin could write/overwrite notes for any
  subnet_id.
- `jen/routes/dashboard.py`: **three** endpoints leaked data across
  subnet restrictions — `api_lease_history()` (both the specific-subnet
  and the "all subnets" branches), `api_recent_leases()` (the dashboard
  widget showing the 50 most recent leases system-wide), and
  `api_alert_summary()` (alert *message text* can embed subnet names;
  restricted users now get type/channel/status/timestamp but not the
  message body, since `alert_log` has no subnet_id column to filter on
  structurally).
- `jen/routes/leases.py`: **two unauthorized cross-subnet writes**, more
  serious than the read-side leaks — `delete_stale_leases()` deleted
  stale leases across *every* subnet regardless of the acting admin's
  restrictions (verified the generated SQL directly for restricted/
  unrestricted/zero-access cases), and `release_lease()` let any admin
  force-release a lease for any IP with no check it was even in a
  subnet they manage. Also `ipmap()`: the subnet dropdown correctly
  only *offered* accessible subnets, but the URL parameter itself
  wasn't enforced.
- `plugins/network-discovery/plugin.py`: `/api/scan-status/<subnet_id>`
  (fixed in 4.4.8, included here for completeness of the pattern).

### Fixed — other real findings
- **`devices.py`'s `icon_override` field had no validation** before being
  used to build a filesystem path check in `fingerprint.py` — same class
  of gap already closed for the sibling icon upload/delete routes.
  Requires admin access and wasn't independently exploitable (Flask's
  static file serving already rejects traversal), but now matches the
  same validation discipline as every other icon-name input.
- **The `network-discovery` plugin's "rogue device" alert rendered
  blank and was unreachable from the settings UI** — `rogue_device` was
  never added to `DEFAULT_TEMPLATES` or `ALERT_TYPE_LABELS` in
  `alerts.py`. Verified the fix by actually calling
  `render_template_str()` with the plugin's real arguments and
  confirming it renders correctly; also confirmed the alerts settings
  page will now expose it automatically for admins to enable, since
  that page loops over `ALERT_TYPE_LABELS`.
- **`ssl_configured()` required `SSL_COMBINED` to exist unconditionally**,
  but that file is only guaranteed present when certs are uploaded
  through Jen's own UI. Anyone provisioning certs externally (e.g.
  mounting Let's Encrypt/cert-manager output into a Docker volume) had
  valid cert+key files that this check silently rejected, falling back
  to HTTP-only with no explanation. Now matches `run.py`'s own existing
  optional treatment of that file.
- **IPAM plugin**: `save_entry()` now validates the submitted IP is
  actually within the target subnet's own CIDR before storing it
  (previously nothing stopped an orphaned, mismatched entry from being
  created); `_build_address_space()` now caps enumeration at 65,536
  addresses so a mistyped CIDR (a /8 instead of a /24) can't try to
  materialize millions of address entries in memory.
- **Network-discovery plugin's rogue-device detection was IP-only** —
  a `kea_macs` variable was declared and never populated, so a known
  device with a MAC in Kea but a renewed/different IP got wrongly
  flagged "rogue" on every scan. Implemented real MAC-based matching
  alongside the existing IP match; verified with a direct test that a
  device with a matching MAC but different IP now correctly resolves
  as known rather than rogue.

### Housekeeping
- Removed three more dangling section-header comments with nothing
  under them in `jen/routes/subnets.py` (same leftover-from-refactor
  pattern already cleaned up in `servers.py`).
- Removed the dead, duplicate `KEA_SSH_KEY` constant in
  `jen/extensions.py` — it was only ever written, never read; the
  actually-used `SSH_KEY_PATH` now reads directly from config.

### Verification note
Real dependencies are installed in the audit environment used for this
release, which allowed genuine verification beyond static analysis for
several of these: actually registering Flask blueprints and checking
the resulting URL map (the two missing-route fixes), directly calling
`add_subnet_restriction()` with mocked restricted/unrestricted/zero-
access users and inspecting the generated SQL (the `delete_stale_leases`
fix), directly calling `render_template_str()` with the plugin's real
arguments (the `rogue_device` fix), and a mocked-DB unit test for the
MAC cross-referencing fix. Still no live MariaDB available, so the real
`pytest` suite has not been run against this release — needed on your
end before considering it fully verified.

## [4.4.8] - 2026-08-07

### Security & correctness: findings from actually reading every file not yet opened

Following up on the file-inventory exercise: every route/service file that
had never been directly read (not grepped, actually read) turned up real
issues. All fixed, all independently verified rather than just reasoned
about — this pass had real dependencies installed and used them to
directly reproduce two of the bugs below before and after the fix, rather
than trusting static analysis alone.

### Fixed
- **`jen-sudoers` granted `www-data` passwordless execution as `ALL` users**,
  not just root. Narrowed both entries to `ALL=(root)`. The underlying
  design (a predictable `/tmp/jen_update_install.sh` path trusted purely
  by location, not content) is unchanged and remains a known, accepted
  trust boundary tied to the self-update flow's checksum verification —
  this fix removes the unnecessary extra scope, it doesn't change that
  boundary.
- **`network-discovery` plugin: `/api/scan-status/<subnet_id>` was missing
  the subnet-access check** its sibling routes (`/scan/`, `/results/`)
  already had. A subnet-restricted user could poll it for any subnet_id
  and learn scan status, host count, and rogue-device count for subnets
  they don't have access to. Now calls `assert_subnet_access()` like the
  other two routes.
- **SSH host-key verification was effectively disabled everywhere Jen
  connects outbound over SSH** — 6 call sites across `subnets.py` (×3,
  paramiko `AutoAddPolicy()` with no known_hosts ever loaded or saved,
  so every connection trusted a fresh key with zero memory of previous
  connections) and `ddns.py`/`servers.py` (×3, plain `ssh` CLI with
  `StrictHostKeyChecking=no`, which accepts any key unconditionally,
  every time). Consolidated into two shared helpers in
  `jen/services/auth.py`: `ssh_cli_opts()` (switches to
  `StrictHostKeyChecking=accept-new` — same zero-friction first
  connection, but a host key that *changes* afterward is now rejected
  instead of silently accepted) and `paramiko_load_known_hosts()` (loads
  and, after connecting, saves `/etc/jen/ssh/known_hosts`, so
  `AutoAddPolicy` becomes real trust-on-first-use instead of trust-every-
  single-time). New `extensions.SSH_KNOWN_HOSTS` constant.
- **Docker build was broken** — `Dockerfile` had `COPY jen.py
  /opt/jen/jen.py`, but no `jen.py` exists at the repo root (confirmed by
  direct inspection); `docker build .` failed immediately. Leftover from
  before the v2.6.0 refactor to `run.py` + the `jen/` package. Removed.
- **`docker-compose.mysql.yml` shipped active default DB passwords**
  (`changeme_root` / `changeme_jen`) that a user following the documented
  `cp .env.example .env` quick-start would deploy with unless they
  specifically edited those two lines. Compose now requires them
  (`${VAR:?message}` syntax) and refuses to start with a clear error if
  they're left blank, instead of silently falling back to a known
  password. `.env.example` updated to match — both fields now blank by
  default, not pre-filled with a weak value.
- **A DB or admin password containing a literal `%` broke config loading.**
  `jen/config.py` instantiated `configparser.ConfigParser()` with default
  interpolation enabled; a `%` not followed by a valid interpolation
  pattern raises `InterpolationSyntaxError` when the value is read back.
  Reproduced directly (a password of `MyP%ssw0rd` threw the exact error)
  and confirmed the fix (`interpolation=None`) resolves it, in a real
  Python session, not just by inspection. Jen doesn't use config
  interpolation anywhere, so there's no downside to disabling it.
- **A quote character in the admin password broke the interactive
  installer, silently.** `install.sh`'s `_set_admin_password()`
  interpolated the raw password directly into a Python heredoc
  (`generate_password_hash('$pass', ...)`) — a password containing a
  single quote produced a Python `SyntaxError`, and since stderr was
  redirected to `/dev/null` with `|| true` swallowing the exit code, the
  installer printed nothing at all and silently moved on without
  actually setting the password. Reproduced the exact syntax break and
  confirmed the fix directly: the password is now passed via an
  environment variable (`JEN_INSTALL_ADMIN_PASS`) and read with
  `os.environ` inside the heredoc, so no character in the password can
  ever reach the Python source itself.

### Housekeeping
- Removed a dangling `# Reports` section comment with nothing under it at
  the end of `jen/routes/servers.py` — leftover from when reports moved
  to their own `reports.py` file.

## [4.4.7] - 2026-08-07

### Fixed: filter state silently reset by sort-header/pagination clicks on Leases, Reservations, and Devices

Reported: filtering Leases to a subnet, then clicking the "IP Address"
column header to sort, silently dropped the subnet filter back to "All
Subnets." Root cause and scope turned out to be broader than the one
reported case.

**Root cause:** these three pages use HTMX to live-update results when a
filter control (subnet dropdown, search box, per-page selector) changes,
but the HTMX swap target was only `#{page}-table-body` — the `<tbody>`
rows. The `<thead>` sort-link headers and the `<div class="pagination">`
links live *outside* that swap target, in HTML from the last full page
load. Every sort-link and pagination-link `href` had the current
subnet/search/sort/page values baked in via Jinja at render time — so the
moment a filter changed via the HTMX-driven controls without a full page
reload, those baked-in values went stale. Clicking a sort header or a
page number then navigated using the *old* filter values, silently
reverting whatever had just been changed. This affected all three pages
identically — Leases, Reservations, and Devices — since they share the
same HTMX pattern.

**Fix:** widened the HTMX swap target on all three pages from the bare
`<tbody>` to a wrapping `<div id="{page}-results">` containing the whole
table (headers included) and the pagination block, via three new partial
templates:
- `templates/_leases_results.html`
- `templates/_reservations_results.html`
- `templates/_devices_results.html`

Each route's `HX-Request` branch now renders the full results partial
instead of just the row-only partial, so the sort headers and pagination
links are rebuilt with live filter values on every HTMX update, not just
on a full page load. `jen/routes/leases.py`, `jen/routes/reservations.py`,
and `jen/routes/devices.py` updated accordingly.

Also fixed while in this code: Leases' and Reservations' sort-header links
were missing `&per_page=` in their query string (Devices already had it
correctly) — clicking a sort header on those two pages would additionally
have reset the rows-per-page selection back to default. Same root cause,
same fix.

### Verification note
No live database/Flask app available to run the real test suite or an
end-to-end browser check for this fix. Verified: Python syntax (AST) on
all three modified route files, Jinja syntax on all templates including
the three new partials, and — the part that actually matters here — all
three new partials render byte-correctly under Jinja's `StrictUndefined`
mode against representative context matching what each route's
`template_vars` actually provides. Full-page template rendering outside
a real Flask request context isn't practical to verify this way (several
Flask-injected globals aren't reproducible standalone), so this needs a
real click-through on your end before considering it done — specifically:
filter to a subnet on each of the three pages, click each sort header,
and confirm the subnet/search/per-page selections survive.

## [4.4.6] - 2026-08-07

### Housekeeping: test-only fix — no production code changed

- **`tests/conftest.py`: `client` fixture was `scope="session"`** — a
  single `test_client()` (and its cookie jar) shared across the entire
  ~255-test suite run. Any test that logged the shared client into a
  session via `session_transaction()` left that session active for
  whichever test happened to run next in the same process, so any test
  asserting anonymous-access behavior was silently at the mercy of
  execution order rather than actually testing an unauthenticated
  request. Found because `tests/test_database.py` (new in 4.4.5) failed
  when run as part of the full suite but passed cleanly in isolation —
  isolating it is what exposed the leak, since with nothing running
  first the shared client's cookie jar was genuinely empty.
  Fixed by dropping to the (default) function scope, so every test gets
  its own client with an empty cookie jar. `app` stays session-scoped
  (rebuilding the Flask app per test would be expensive); `test_client()`
  itself is cheap to recreate.
  No application code changed — `/database` and every other
  `@_superadmin_required` route were independently confirmed to enforce
  authentication correctly in production via direct `curl` testing before
  this fix; the bug was entirely in how the test suite simulated
  requests, not in the routes themselves.

## [4.4.5] - 2026-08-06

### Hardening: HTTP security headers, opt-in DB TLS, Actions supply-chain pinning, database.py test coverage

A broader audit pass against a general SDLC checklist (application security
headers, dependency/secrets hygiene, CI/CD pipeline, test coverage,
database controls) — scoped down to what actually applies to a
solo-maintained project. Four real gaps closed; none were exploitable bugs
on their own, all are standard hardening for a self-hosted admin panel
managing live DHCP infrastructure.

### Added
- **HTTP security response headers**, set unconditionally via a new
  `after_request` hook in `jen/__init__.py`: `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, and a
  `Content-Security-Policy`. The CSP is deliberately the permissive-but-
  safe version (`script-src`/`style-src` allow `'unsafe-inline'`) rather
  than a strict one — templates use inline `<script>` blocks, inline
  `style=` attributes, and inline `onclick`/`onchange` handlers throughout
  (hand-rolled dashboard JS + HTMX, no bundler), and a strict CSP would
  have broken most pages. It still blocks loading any script/frame/object
  from an external origin, which is the actual clickjacking/injection
  threat for an admin panel. `Strict-Transport-Security` is sent only when
  SSL is actually configured, same gating as `SESSION_COOKIE_SECURE`.
- **Opt-in TLS for the jen_db/kea_db MySQL connections.** New `ssl_ca`
  key under `[jen_db]` and `[kea_db]` in `jen.config` (see updated
  `jen.config.example`). Empty/unset (the default) is a complete no-op —
  every existing install keeps working exactly as before. When set, PyMySQL
  connects with TLS and verifies the server certificate against the given
  CA, covering the pooled connections, the pool's direct-connection
  fallback path, and `dbexport`'s direct connections. Independent
  `ssl_ca` per database since jen_db and kea_db can be on different hosts.
- **`tests/test_database.py`** — `database.py` (export/import/restore/
  migrate, the highest blast-radius route file in the app) had zero test
  coverage of any kind before this release, not even incidental. New
  tests cover the superadmin-only boundary on every route in the file
  (not a sample — all of them), the `os.path.basename()` traversal guard
  on backup download/delete, and the `tmp_path` validation on
  `/database/import/confirm`.
- `restricted_client()` helper moved from `test_security_fixes.py` into
  `conftest.py` so `test_database.py` could reuse it instead of
  duplicating it; `test_security_fixes.py` now imports it.

### Changed
- `.github/workflows/release.yml`: `actions/checkout` and
  `softprops/action-gh-release` pinned to full commit SHAs (with a
  version comment) instead of the mutable `@v4`/`@v2` tags. Tags can be
  moved by a compromised maintainer account — this is the same attack
  class as the real `tj-actions/changed-files` supply-chain incident —
  and this workflow runs with `contents: write` on every tagged release.

## [4.4.4] - 2026-08-06

### Security: full audit, third pass — MFA-reset privilege escalation, subnet leak in search, plugin path hardening

A follow-up audit pass (third in the 4.4.x series) found one more real
privilege-escalation bug and one real subnet-authorization leak, plus two
lower-severity hardening items caught along the way.

### Fixed
- **🔴 A plain admin could strip a superadmin's MFA.** `/mfa/admin-reset/<user_id>`
  was gated with `@admin_required` instead of `@superadmin_required` — the
  newer, equivalent route `/users/reset-mfa/<user_id>` already required
  superadmin, but this older route slipped through. Per the documented
  permission matrix ("admin... cannot manage users"), a regular admin
  shouldn't be able to touch another user's MFA at all. Now requires
  superadmin, matching `/users/reset-mfa/`.
- **🔴 Global search leaked results across subnet restrictions.** `/search`
  queried leases, reservations, and devices with no subnet filtering at
  all, unlike every other list view in Jen (leases, devices, reservations,
  reports, dashboard). A subnet-restricted admin or viewer could search for
  an IP/hostname/MAC fragment and get hits from subnets they have no
  access to. All three result sets now apply the same
  `add_subnet_restriction()` used elsewhere; devices with no recorded
  subnet (`last_subnet_id IS NULL`) remain visible since they can't be
  attributed to a restricted subnet either way.
- **Plugin enable/disable/uninstall accepted an unvalidated `plugin_id`.**
  `install_plugin`/`update_plugin` already validated `plugin_id` against
  `^[a-z0-9\-]{1,64}$` before touching the filesystem; `enable_plugin`,
  `disable_plugin`, and `uninstall_plugin` (which calls `shutil.rmtree()`)
  didn't. All plugin lifecycle functions now validate through a single
  shared `valid_plugin_id()` in `jen/services/plugins.py`, checked at both
  the route and service layer.
- **Legacy password verification used a non-constant-time comparison.**
  `verify_password()`'s fallback path for not-yet-upgraded SHA-256 hashes
  compared with `==` instead of `secrets.compare_digest()`. The pbkdf2
  path was already constant-time via werkzeug; this closes the one
  remaining gap.
- Minor: `delete_custom_icon` didn't validate its `name` parameter the way
  `upload_custom_icon` does. Flask's default `<name>` route converter
  already rejects any path segment containing a slash (encoded or not),
  so this wasn't reachable as traversal — confirmed by testing both raw
  and `%2F`-encoded payloads against the actual route — but the check is
  now there for consistency and in case the route type ever changes.

### Added
- 8 new tests in `tests/test_security_fixes.py` covering the MFA-reset
  authorization fix, subnet-filtered search, and plugin_id validation
  across all four lifecycle functions.

## [4.4.3] - 2026-08-05

### Security: database/plugin privilege escalation, Zip Slip, dependency hardening

Second pass of the same audit that produced 4.4.2. Found two more places
where a subnet-restricted admin (or, for the plugin bug, any admin) could
reach far past what the role is supposed to allow, plus a real Zip Slip
vulnerability and a couple of dependency/deployment hygiene gaps.

### Fixed
- **🔴 Full database export/import/migrate was admin-accessible, not
  superadmin-only.** `/database/export/jen` returns every table including
  `users` (password hashes), `mfa_methods`/`mfa_backup_codes`/`mfa_trusted_devices`
  (MFA secrets), and `api_keys` — none of it scoped to a subnet-restricted
  admin's assigned subnets, because none of it *can* be. `import_confirm`
  and `migrate_run` meant that same restricted admin could overwrite all
  of it, too. All 12 routes in `database.py` now require superadmin;
  `superadmin_required` was already imported in that file and never
  used, which is a pretty good sign this was an oversight rather than a
  choice. Nav links and docs updated to match.
- **🔴 Zip Slip in the plugin installer.** `install_plugin()` extracted
  downloaded plugin archives with plain `zipfile.extractall()`, which
  follows `../` path traversal or absolute paths in archive entries and
  writes wherever they point — not just into the plugin's own directory.
  Added `_safe_extract()`, which validates every archive member resolves
  inside the destination directory before extracting anything.
- **Plugin install/enable/uninstall was admin-accessible.** Installing a
  plugin runs arbitrary Python (`register(app)`) with the full privileges
  of the Jen process itself — DB credentials, sudoers-permitted commands,
  everything. That's a different category of power than "manage
  reservations on my assigned subnets," so it now requires superadmin,
  same as the database fix above. Also added an HTTPS-only check on
  plugin download URLs as cheap defense in depth.
- **Unpinned dependencies everywhere.** `Dockerfile` and `install.sh`
  installed every Python dependency with no version floor. Ran `pip-audit`
  against the actual resolved set and found `pillow` (pulled in
  transitively via `qrcode[pil]`) had several known CVEs below 12.2.0/12.3.0
  — nothing else in Jen's dependency list was affected. All dependencies
  now pinned to current-clean minimum versions in both files.
- **Docker image was missing `dbutils`, `apscheduler`, and `paramiko`** —
  found while fixing the pin above. All three are actually imported by
  the running app (`dbutils` for connection pooling in every DB call,
  `apscheduler` for the backup scheduler, `paramiko` for subnet config
  push over SSH), so a Docker deployment would crash the first time any
  of those code paths ran. `install.sh` already had all three; the
  Dockerfile just never did. Fixed, and added an explicit `pillow`/`PIL`
  check to `install.sh`'s "already present" detection loop, which
  previously never checked for it at all.

### Added
- 13 new tests in `tests/test_security_fixes.py`: superadmin enforcement
  on `database.py` and `plugins.py` routes, and Zip Slip protection
  (parent-directory traversal, absolute paths, and a normal-contents
  sanity check).

## [4.4.2] - 2026-08-05

### Security: full audit fixes — subnet authorization, MFA brute force, SSH command injection

A comprehensive security audit turned up several real gaps, ranging from a
critical command-injection bug reachable by any logged-in user to a
systemic authorization gap in the subnet-restricted-admin feature. All are
fixed in this release; nothing here is theoretical.

### Fixed
- **🔴 Critical: `/ddns?host=` command injection, reachable by any logged-in
  user.** The DNS lookup box on the DDNS page interpolated its `host`
  query parameter directly into a command string executed on the remote
  Kea server over SSH (`dig +short {host} || host {host}`), with zero
  validation and no admin gate on the route. Any authenticated user —
  down to the lowest-privilege role — could run arbitrary commands on the
  Kea server. Fixed by validating the lookup value as a hostname or IP
  before it's used, and by wrapping it in `shlex.quote()` as defense in
  depth. New validators: `valid_dns_lookup_host`, `valid_ssh_target`,
  `valid_unix_username`, `valid_remote_path` (`jen/services/auth.py`).
- **🔴 Subnet-restricted admins could bypass their subnet restrictions on
  every mutating reservation/subnet route.** `current_user.can_access_subnet()`
  was correctly enforced on list/view routes but missing on the routes
  that actually make changes: `reservations.add_reservation_post`,
  `edit_reservation`/`edit_reservation_post`, `delete_reservation`,
  `bulk_delete_reservations`, `import_reservations`, and
  `subnets.edit_subnet_post`/`delete_subnet` all now check access before
  acting. `reservations.export_reservations` and `bulk_export_reservations`
  (reachable by any logged-in user, not just admins) now filter results to
  the caller's accessible subnets instead of dumping everything.
  `devices.edit_device`/`delete_device` got the same check against a
  device's `last_subnet_id`.
- **No rate limiting on `/mfa/verify`.** Password login has had IP/username
  rate limiting for a while; the post-password TOTP/backup-code step had
  none, so a 6-digit TOTP code could be brute-forced with unlimited
  attempts. Added a dedicated, fixed 10-attempt / 15-minute lockout
  (new `mfa_attempts` table, migration 9) — deliberately separate from the
  configurable password rate-limit settings so it can't be disabled or
  made permanent by a config change, and deliberately never permanent
  itself, since a lockout that never expires would let an attacker lock a
  legitimate user out indefinitely just by submitting bad codes.
- **Admin-configured SSH host/user and DDNS log path were not validated**
  before being interpolated into remote shell commands. An admin (or a
  CSRF/phished admin session) could turn "view a log file" into arbitrary
  command execution on the Kea server. Now validated with the same
  `valid_ssh_target`/`valid_unix_username`/`valid_remote_path` checks at
  every save point (`save_infra_ssh`, `save_infra_ddns`, `save_extra_servers`).
- **Self-update trusted a client-submitted `asset_url`,** checking only
  that it started with `https://github.com/` — that would accept a release
  asset from *any* GitHub repo, not just this one. `self_update()` now
  re-derives the release info itself from the GitHub API, pinned to
  `ltkojak/jen-kea`, and verifies the submitted version still matches
  before proceeding. Also added optional SHA256 checksum verification
  against a `SHA256SUMS` file, which `release.yml` now publishes alongside
  every tarball.
- **Session cookie had no `Secure`/`HttpOnly`/`SameSite` flags set.** Added
  `SESSION_COOKIE_HTTPONLY=True` and `SESSION_COOKIE_SAMESITE="Lax"`
  unconditionally, and `SESSION_COOKIE_SECURE` tied to whether SSL is
  actually configured (an unconditional `Secure` flag would silently break
  login for Jen's plain-HTTP-only deployment mode).
- **Secret key silently regenerated on every restart if `/etc/jen/secret_key`
  couldn't be written,** invalidating every session each time with only a
  quiet log line. Now tries a fallback location under `/opt/jen` before
  giving up, and logs a loud, explicit `critical` message (not a `warning`)
  if it ever has to fall back to an ephemeral key.

### Added
- `tests/test_security_fixes.py` — 20 new tests covering the subnet
  authorization checks, the MFA lockout (including that it's never
  permanent), and every new validator.
- `mfa_attempts` table (migration 9).

## [4.4.1] - 2026-08-05

### Bug Fix: Reservation edits silently orphaned notes + two more hover underlines

Found during live testing of 4.4.0's CSRF rollout. CSRF itself checked out
clean — login, a plain form POST, and the HTMX delete all worked with no
false 403s. This is unrelated to CSRF; it's a pre-existing bug this testing
pass happened to surface.

### Fixed
- **🔴 Editing a reservation silently orphaned its notes.** `edit_reservation_post()`
  implements "edit" as Kea `reservation-del` + `reservation-add`. Since
  `hosts.host_id` is an `AUTO_INCREMENT` primary key, the recreated row gets
  a brand new id even when ip/mac/subnet are unchanged — but the route was
  still writing `reservation_notes` against the *old* host_id from the URL.
  The reservation list always looks notes up by the *current* host_id, so
  the note became invisible despite a "Reservation updated" success
  message. (The CSV-import code path in this same file already re-queried
  the host_id after a Kea write — this one spot just didn't follow that
  pattern.) Fixed by re-querying the post-edit host_id and writing notes
  there, cleaning up the orphaned row under the old id.
  A second, subtler bug turned up while fixing this: the first fix attempt
  re-queried the new host_id on the *same* already-open database
  transaction used for the initial lookup — under REPEATABLE READ, that
  transaction's snapshot predates Kea's own write (Kea updates the table
  over its own connection, not this process's), so it could still report
  the stale host_id even after Kea had already committed the new row. Fixed
  by opening a fresh connection/transaction for the re-query. Added
  `TestEditReservation::test_notes_survive_host_id_reassignment`, which
  simulates the real delete-then-reinsert churn (not just a happy-path
  mock) — it caught the transaction-scoping bug directly before this ever
  reached a real deployment.
- **Two more hover-underline gaps**, same root cause as the v4.4.0 logo fix
  (a global `a:hover { text-decoration: underline; }` out-specifying a
  class's base `text-decoration: none;` with no explicit `:hover`
  override): the row action icons (`.btn-act` — edit/pin/delete pencil
  buttons) and the mobile nav drawer links (`.nav-mobile-drawer a`). Fixed
  both the same way — an explicit `:hover { text-decoration: none; }`.
  Audited the rest of the CSS for this exact pattern; nothing else matched.

## [4.4.0] - 2026-08-05

### Feature: CSRF Protection

Jen had no CSRF protection anywhere — no token, no verification on any
POST/PUT/PATCH/DELETE route. A malicious page visited by a logged-in admin
could silently trigger any state-changing action in Jen on their behalf.
Closes that gap app-wide.

### Added
- **`jen/services/csrf.py`** — session-bound, `itsdangerous`-signed tokens
  (already a Flask dependency, no new install required) with a 4-hour
  expiry. Each session gets a random nonce; the token signs that nonce with
  a timestamp, so a token can never validate against a different session
  even if somehow replayed, and expires automatically.
- **`csrf_token()`** available in every template via the existing branding
  context processor.
- **`_csrf_protect()` before_request hook** in `jen/__init__.py`, checking
  all state-changing methods. Exempts requests carrying an
  `Authorization: Bearer` header — Jen sets no CORS headers, so a forged
  cross-site request (form or JS) cannot attach that header, meaning
  API-key auth isn't vulnerable to CSRF the same way session cookies are.
  Also respects `WTF_CSRF_ENABLED` (mirroring Flask-WTF's own config key),
  so the existing test suite's `logged_in_client`-based POST tests needed
  zero changes.
- Applied to **all 91 POST forms** across every template (hidden
  `csrf_token` field), **all 7 JS `fetch()` call sites** (dashboard,
  database_migrate ×2, devices, leases, reservations, subnets — via
  `X-CSRFToken` header), and the one HTMX call (via a single `hx-headers`
  attribute on `<body>` in `base.html`, inherited by any descendant
  element including partials that don't extend base.html themselves).
- **`tests/test_csrf.py`** (18 tests) — 10 direct unit tests of the token
  logic (generation, validation, tampering, expiry, cross-session
  rejection, Bearer detection) and 8 full integration tests through the
  real Flask test client and the actual `before_request` hook, including a
  round trip proving the existing suite is unaffected by default. All 18
  verified passing against a live database, not just reviewed.

### Fixed
- **Logo hover underline.** The global `a:hover { text-decoration:
  underline; }` rule out-specified `.nav-brand`'s base `text-decoration:
  none;` — every *other* nav link already had an explicit `:hover`
  override, this one didn't. Added `.nav-brand:hover { text-decoration:
  none; }`.

### Note on rollout
This release is packaged but intentionally **not auto-tagged**. Per the
agreed plan: the full 179-test suite (161 pre-existing + 18 new) passes
against a live database — but before tagging, do a short live click-through
(login, a plain form save, an HTMX-driven action, a file upload, and one
API-key-authenticated request) to confirm real browser/session behavior
matches what the test client already proved.

## [4.3.9] - 2026-08-04

### Security Fix: SQL injection via unvalidated table/column names in database export/import/migrate + logo hover cosmetic fix

### Fixed
- **🔴 SQL injection via table names in `dbexport.py`.** `export_jen()`,
  `import_jen()`, `import_kea()`, `migrate_jen()`, and `migrate_kea()` all
  interpolated table names into f-string SQL (`` SELECT * FROM `{table}` ``,
  `` DELETE FROM `{tbl}` ``, `` DROP TABLE IF EXISTS `{tbl}` ``, etc.) without
  checking them against the `JEN_TABLES` / `KEA_EXPORT_GROUPS` whitelists
  already defined in the same file. Table names came from `request.form`
  (export/migrate — requires admin auth to reach) or directly from an
  **uploaded file's own JSON keys** (import — the more serious path, since a
  crafted "export" file could carry an injection payload as a table name).
  Added `_validate_tables()` as a single choke point and applied it at every
  call site; `export_kea()`/`migrate_kea()`'s `group` parameter is now also
  validated against `KEA_EXPORT_GROUPS` before use.
- **🔴 Same vulnerability, one layer deeper: column names.** `import_jen()`
  and `import_kea()` also built column lists straight from the *keys of each
  row* in the uploaded file (`cols = list(rows[0].keys())`) and
  backtick-interpolated those into the `INSERT` column list — same injection
  shape, one level down. Added `_get_table_columns()` to fetch the real
  schema and filter untrusted column names down to ones that actually exist
  before they're used. (`migrate_jen`/`migrate_kea` were not affected here —
  their column names come from Jen's own live database, not an uploaded
  file.)
  Added `tests/test_dbexport.py` (11 tests) covering the whitelist logic
  directly, including the exact UNION-injection-shaped payload this closes.
- **Logo hover underline.** Same root cause as earlier CSS gaps this
  release cycle: the global `a:hover { text-decoration: underline; }` rule
  out-specifies `.nav-brand`'s base `text-decoration: none;`, since every
  *other* nav link already had an explicit `:hover` override and this one
  didn't. Added `.nav-brand:hover { text-decoration: none; }`.

### Note
This release does **not** include CSRF protection — a systemic gap found in
the same audit (no `flask_wtf`, no CSRF token anywhere, no verification on
any POST route). It's scoped as its own release (4.4.0) given it touches all
29 form templates plus JS/HTMX calls, rather than being bundled into this
patch.

## [4.3.8] - 2026-08-04

### Bug Fixes: Four more missing CSS classes + a subnet config data-loss bug, found by auditing for repeat patterns

### Fixed
- **🔴 Editing a subnet with more than one Kea pool silently deleted every
  pool after the first.** `edit_subnet_post()` always rewrote
  `s['pools']` as a single-item list built from the form's one pool field —
  regardless of whether the pool was actually changed. Since the edit form
  only ever pre-fills and exposes the *first* pool
  (`_get_subnet_kea_data()`'s `pool_str`), submitting the Edit Subnet form
  for **any** reason on a multi-pool subnet (e.g. just updating DNS servers)
  would overwrite `kea-dhcp4.conf` with only that one pool, discarding the
  rest on save. This is the same root cause as the v4.3.7 IP Map bug — a
  subnet with more than one pool stanza — but here it caused real
  configuration data loss instead of a display gap. Fixed by threading the
  subnet's additional pools through a hidden form field and merging them
  back into `s['pools']` on save instead of discarding them. The edit form
  now also shows a warning when a subnet has multiple pools, listing which
  ones are preserved as-is. Added `tests/test_subnets.py` (6 tests) covering
  multi-pool data collection and the preserve-on-save merge logic
- **`.alert-danger` was undefined**, used in `database.html`,
  `database_import_confirm.html`, and `database_migrate.html` — including the
  "Migration failed — target database was rolled back" message. Aliased to
  the same styling as `.alert-error`
- **`.badge-danger` was undefined**, used in `servers.html` for HA state
  `partner-down` / `terminated` — exactly the states that most need to stand
  out visually
- **`.btn-warning` was undefined**, used on the "🔄 Restart Jen Now" button in
  the nav itself, plus `database.html` and `settings_infrastructure.html`
- **`.nav-dropdown-header` and `.nav-dropdown-divider` had zero CSS**, so the
  account dropdown menu (username/role block and its separator lines)
  rendered with no padding and no visible divider

### Changed
- **Docker image versions were stuck at `3.8.0`** in `Dockerfile` and both
  `docker-compose*.yml` files, several releases stale. Synced to `4.3.8` and
  added checks for all three files to `scripts/release_check.sh` so this
  can't silently drift again
- **Housekeeping**: moved a second batch of orphaned, unreferenced release
  notes (`docs/github-release-2.6.x.md`, `-2.7.x.md`, `-3.1.x.md`,
  `-3.2.x.md`) into `docs/release-history/` alongside the first batch, and
  updated its index

## [4.3.7] - 2026-08-04

### Bug Fix: IP Map only showed the first Kea pool + README mockup rebuilt

### Fixed
- **IP Map silently dropped every pool after the first one.** `_get_pool_range()`
  (added in v4.3.6) `return`ed as soon as it found one pool stanza in the Kea
  config. Larger subnets — e.g. a `/23` configured as two `/24`-sized pools —
  only ever showed the first pool's addresses, making a `/23` look like a
  `/24`. Replaced with `_get_pools()` (collects every pool stanza) and
  `_build_pool_blocks()` (converts each into its own list of IPs using the
  `ipaddress` module, so ranges that cross an octet boundary render
  correctly instead of relying on last-octet-only arithmetic in the
  template). The map now renders one section per pool when a subnet has more
  than one, with a cap of 2048 total addresses so a misconfigured huge pool
  can't blow up the page
- Added `TestIpMapPoolBlocks` (5 tests) covering multi-pool stanzas,
  cross-octet ranges, oversized-pool truncation, no-pool, and malformed IP
  handling — pure logic tests, no DB/Kea connection required. Suite grows
  from 139 to 144 tests

### Changed
- **README dashboard preview replaced.** The v4.3.5 mockup was a generic
  guess at the layout and didn't match the real UI. Rebuilt
  `docs/images/dashboard-preview.svg` to mirror the actual nav bar, subnet
  cards, summary strip, recent-leases table, server status, and alert
  summary — using placeholder IPs/hostnames/MACs only, no real network data

## [4.3.6] - 2026-08-04

### Bug Fix: IP Map grid had no layout CSS

### Fixed
- **IP Map rendered as a single-column list of bare numbers instead of a
  grid.** `.ip-grid`, `.ip-cell`, `.ip-dynamic`, and `.ip-reserved` were
  referenced in `ipmap.html` but never had CSS rules defined anywhere in the
  codebase. This was invisible before v4.3.5 because the page always fell
  back to "Could not determine pool range from Kea config" — fixing that bug
  exposed this pre-existing, previously-unreachable one. Added grid layout
  (`repeat(auto-fill, minmax(56px, 1fr))`) and colored cell states matching
  the page's own legend (free / dynamic lease / reserved)

## [4.3.5] - 2026-08-04

### Bug Fixes: Global Search, IP Map, Devices Filter Bar

### Fixed
- **Global Search was completely broken** (`Unknown column 'name' in 'SELECT'`).
  The devices search query referenced a `name` column that has never existed
  — the actual column is `device_name`. Query now selects `device_name AS name`
  so results render correctly without any template changes
- **IP Map always showed "Could not determine pool range from Kea config,"**
  even with a valid pool configured. The `/ipmap` route never fetched the pool
  range or built the `used`/`pool_start`/`pool_end`/`subnet_id` context the
  template actually reads — those variables were simply never passed. Added a
  `_get_pool_range()` helper (mirrors the pattern already used in
  `subnets.py`) that queries live Kea config for the active subnet's pool, and
  the route now merges leases + reservations into a single `used` map for the
  grid
- **Stray, unlabeled checkbox on the Devices page.** The global
  `.filter-bar input { min-width: 140px }` rule was also being applied to the
  "Stale only" checkbox, stretching its layout box and shoving the "Stale
  only" label text out of view. Scoped the rule to exclude
  `input[type=checkbox]`

### Housekeeping
- Moved the orphaned `RELEASE-3.3.x.md` … `RELEASE-3.7.x.md` files out of the
  repo root into `docs/release-history/` with an index. They were unreferenced
  duplicates of history already captured in this CHANGELOG
- Added a dashboard preview mockup (`docs/images/dashboard-preview.svg`) to
  the top of README.md

## [4.3.4] - 2026-08-02

### MFA Method Fixes: Second Authenticator + Last-Used Tracking

### Fixed
- **A second enrolled TOTP authenticator could never log in.** verify_totp
  fetched only the FIRST enabled method's secret, so codes from any additional
  authenticator (e.g. iPhone + Keeper) silently failed verification. All
  enabled methods are now checked
- **Enrolled methods always showed "Last used never"** — nothing ever wrote
  mfa_methods.last_used. Successful verification now stamps the specific
  method that matched, so the MFA page shows which authenticator was used and
  when. Tracking failures can never block a valid login

### Added
- tests/test_mfa_methods.py: 4 tests — second-method verification,
  correct per-method stamping, first-method regression, wrong-code rejection.
  Suite grows from 135 to 139 tests

### Developer Notes
- Verified end-to-end in the live-server harness (login → MFA verify with each
  authenticator's code via curl) and in-process against MariaDB. An initial
  false test failure was traced to the harness checker connection's
  REPEATABLE READ snapshot hiding later writes — fixed with autocommit reads;
  the application code was correct

## [4.3.3] - 2026-08-02

### Root Cause Found: Werkzeug UserAgent Always Falsy

### Fixed
- **Every trusted device showed "Unknown device" because the User-Agent was
  never read, on any request, from any client.** The idiom
  `request.user_agent.string if request.user_agent else ""` is broken on
  werkzeug 2.1+: `UserAgent.__bool__` keys off the parsed `.browser` field,
  and werkzeug removed built-in UA parsing — so the object is ALWAYS falsy
  even with the header present, and the expression always returned "".
  Reproduced end-to-end in a live server harness (real login → MFA verify →
  remember-device via curl with a genuine UA: header list showed User-Agent
  present while the stored value was empty). All three read sites now use
  `request.headers.get("User-Agent", "")`. Post-fix, the same harness stores
  "sandboxhost — Windows · Chrome 147" plus the full raw UA
- Existing "<hostname> — Unknown device" rows self-heal on the next login
  from each device via the 4.3.1 heal path, which now receives a real UA

### Added
- 3 regression tests: the falsy-UserAgent trap (fails if upstream ever changes
  it), the correct direct-header read, and a grep guard asserting
  `request.user_agent` never reappears anywhere in jen/. Suite grows from
  132 to 135 tests

## [4.3.2] - 2026-08-02

### Documentation Version Sync + Release Guard

### Fixed
- README Installation and Upgrading sections, and the admin guide, still
  referenced `jen-v3.8.0.tar.gz` — the release process had only been updating
  the version badge, not the document bodies, since 3.8.1

### Added
- `scripts/release_check.sh`: pre-package guard that verifies the release
  version in `jen/__init__.py` matches `install.sh`, the README badge, the top
  CHANGELOG entry, and every tarball reference in README.md and
  docs/admin-guide.md — and fails the release on any stale or missing
  reference. Run before every package alongside the AST and Jinja checks

## [4.3.1] - 2026-08-02

### Trusted Device Heal Resilience + UA Diagnostics

### Fixed
- Trusted-device names could freeze as "<hostname> — Unknown device": the
  self-heal only retried names *starting with* "unknown", so once a hostname
  prefix was written the row never healed again. The heal now triggers on
  "Unknown" or a raw UA fragment anywhere in the name
- A request arriving without a User-Agent header could permanently degrade a
  row (observed in the field: valid client IP, empty UA, same request). The
  heal now prefers the live UA, falls back to the stored one, never replaces
  an existing name with a worse candidate, and never overwrites a stored
  user_agent with an empty value
- Duplicate fingerprint import in mfa_routes.py removed

### Added
- Diagnostics: trust creation and trusted-device checks log a warning with the
  full header-name list whenever the User-Agent header is absent, so UA-less
  clients can be identified from the journal
- Render-time fallback on the Trusted Devices page: rows whose stored name
  still says "Unknown" but that have a raw user_agent on file display the
  parsed name
- 5 heal-resilience tests covering the exact field scenarios (frozen row,
  UA-less request, stored-UA fallback, legacy raw-UA row, no-degrade
  guarantee). Suite grows from 127 to 132 tests

## [4.3.0] - 2026-08-01

### Trusted Device Identification

Trusted MFA devices now show meaningful names instead of "Unknown" or raw
user-agent dumps.

### Added
- Friendly device descriptions built from two sources: the connecting IP is
  resolved against Jen's own network knowledge (active Kea lease hostname
  first, then the devices table) and the user agent is parsed into a short
  label — e.g. "kojak-pc — Windows · Chrome 147" or "iPhone (iOS 18.7) · Safari"
- New helpers in `jen/services/fingerprint.py`: `friendly_user_agent()`,
  `client_hostname()`, `describe_client_device()` — hostname lookup is
  best-effort and never raises during login
- Migration 8: `mfa_trusted_devices` gains `ip_address` and `user_agent`
  columns (first real use of the versioned migration system)
- Trusted Devices page shows the friendly name with the IP as a subline and
  the full raw user agent as a hover tooltip
- **Self-healing:** existing rows with empty/"Unknown"/raw-UA names are
  automatically renamed the next time that device is used to log in —
  no manual cleanup needed. Deliberate healthy names are never overwritten
- `tests/test_device_identity.py`: 10 tests for UA parsing (including
  Edge-vs-Chrome and Safari-vs-Chrome disambiguation) and description
  format. Suite grows from 117 to 127 tests

### Developer Notes
- Integration-tested against real MariaDB: migration 8 on an existing v4.2
  schema (single migration applied), idempotent re-run, hostname resolution
  from a live lease row, metadata stored at creation, legacy-row self-heal on
  validation, and healthy-name preservation

## [4.2.0] - 2026-08-01

### Versioned Schema Migrations

Final phase of the architecture roadmap (4.0.0 AppConfig → 4.1.0 connection
lifecycle → 4.2.0 migrations).

### Fixed
- **Privilege-escalation bug: deliberate 'admin' users were silently promoted to
  superadmin on every restart.** The un-gated 3.5.0 legacy migration ran
  `UPDATE users SET role='superadmin' WHERE role='admin'` at each startup,
  conflicting with the three-tier RBAC added later, where 'admin' is a valid
  mid-tier role. The promotion is now version-gated (runs once) and scoped to
  genuine pre-3.5 schemas (detected by the role ENUM lacking 'superadmin'), so
  modern installs never have their admins touched. **Note:** any user that was
  already promoted by this bug remains superadmin — review Settings → Users
  once after upgrading and demote as needed.

### Changed
- New `jen/models/migrations.py` owns the entire schema: a `schema_migrations`
  table records (version, description, applied_at); an ordered registry of 7
  migrations covers the baseline (all 20 tables, final definitions) plus the
  historical guarded ALTERs and the legacy Telegram data migration
- `init_jen_db()` reduced from ~370 lines of inline DDL to: run pending
  migrations, then seed the default admin if no users exist. New schema changes
  must be appended as numbered migrations, never added to init
- Migration failures abort app startup loudly rather than serving a
  half-migrated schema; every migration is also written idempotently
  (MySQL DDL auto-commits), so a crash mid-migration recovers cleanly on the
  next start
- Self-update flow now applies schema changes automatically: the post-update
  service restart runs any pending migrations
- Existing installs adopt the system transparently: on first 4.2.0 start all 7
  migrations no-op against the current schema and are recorded

### Added
- `tests/test_migrations.py`: 8 tests — registry integrity, recorded state,
  idempotent re-run, and an admin-role regression probe proving deliberate
  'admin' users survive restarts. Suite grows from 109 to 117 tests

### Developer Notes
- Full integration matrix validated against a real MariaDB instance: fresh
  install, idempotent re-run, existing-install adoption (deliberate admins
  preserved), genuine pre-3.5 legacy upgrade (legacy admin promoted, viewer
  untouched, password widened, columns added, Telegram migrated), crash
  recovery from a lost version row, and end-to-end init with seeding

## [4.1.0] - 2026-07-31

### Connection Context Managers

Second phase of the architecture roadmap (4.0.0 AppConfig → 4.1.0 connection
lifecycle → 4.2.0 migrations). No user-facing feature changes.

### Changed
- New `jen_db()` / `kea_db()` context managers in `jen/models/db.py`: commit on
  clean exit, rollback on exception, and guaranteed return of the connection to
  the pool on every path — early return, exception, or normal exit. A failed
  request can no longer leave a half-applied transaction on a pooled connection
- All 142 hand-managed connection sites across routes, services, and models
  converted to `with` blocks (131 with-blocks after dual-connection merges).
  Explicit mid-block `db.commit()` calls are preserved, so commit timing is
  unchanged; the context manager's final commit is a harmless no-op after them
- Service modules (alerts, auth, mfa) gained lazy `__jen_db_ctx` / `__kea_db_ctx`
  wrappers matching their existing circular-import-avoidance pattern
- Several pre-existing connection leaks on early-return paths fixed as a
  by-product (e.g. dashboard top-devices with no accessible subnets, API device
  lookup 404 path)
- Shadowing local variables named `kea_db` / `jen_db` in search and reservations
  renamed to `kdb` / `jdb`
- dbexport's direct (non-pooled) migration/backup connections intentionally
  left as-is — different lifecycle, out of scope

### Added
- `tests/test_db_context.py`: 6 unit tests asserting the context manager
  guarantees with mocked connections — suite grows from 103 to 109 tests

### Developer Notes
- Conversion was done with a conservative per-function transformer that bailed
  to manual review on any non-standard shape (early closes, try/finally,
  non-LIFO dual-connection closes). First transformer draft mis-handled
  branch-nested early closes; it was caught in review, fully reset, and redone
  with a corrected termination rule before anything was packaged

## [4.0.0] - 2026-07-31

### Configuration Architecture Overhaul — AppConfig

Major internal refactor eliminating the global-mutable-config-state design that
caused the stale-config bug class patched in v3.8.1. No user-facing feature
changes; the version bump reflects the architectural change.

### Changed
- New `AppConfig` class in `jen/config.py` is the single source of truth for all
  configuration: it owns loading, validation, writing, and derivation of every
  config value. Every write method (`write_value`, `write_values`,
  `write_subnets`, `mutate`) writes to disk and immediately re-derives all
  runtime values, so the on-disk file, the parsed config, and the derived
  globals can never diverge
- All config-derived globals in `jen/extensions.py` are now assigned exclusively
  by `AppConfig.apply()` — zero direct assignments remain anywhere in routes,
  services, or models (previously 14 scattered mutation sites across
  settings.py, subnets.py, and fingerprint.py)
- Settings routes (Kea API, Kea DB, Jen DB, SSH, extra servers, DDNS, HA, ports)
  rewritten to use batched `write_values()` / `mutate()` calls — each save is a
  single write + reload instead of multiple writes with hand-rolled global updates
- `save_extra_servers` section rewrite now goes through `app_config.mutate()`
- Subnet add/delete no longer manually assigns `SUBNET_MAP` — the write reloads it
- `derive_kea_servers` fallback credentials now come from the parser being
  derived, not from globals (removes an ordering dependency)
- Removed redundant import-time path reassignments in `fingerprint.py`
- Config file path is read dynamically on every operation (never cached) so the
  test suite can repoint it

### Compatibility
- `load_config()`, `init_extensions_from_config()`, `write_config_value()`,
  `write_subnets_config()`, `load_kea_servers()`, `load_subnet_map()` are
  preserved as thin wrappers delegating to `app_config` — existing callers and
  plugins are unaffected. Note: `write_config_value()` now reloads after
  writing (previously it only wrote to disk), which is the intended
  consistency guarantee
- All extensions globals remain plain module attributes, so the test suite's
  direct patching in conftest.py continues to work unchanged

### Added
- `tests/test_appconfig.py`: 10 tests asserting the consistency guarantees
  (disk/memory sync after every write path, derived-structure re-derivation,
  wrapper behavior, validation errors) — suite grows from 93 to 103 tests

## [3.8.1] - 2026-07-31

### Full Audit Fixes

### Fixed
- Reservations CSV export, CSV import, and bulk export were broken — the `csv` module was never imported in `jen/routes/reservations.py` (NameError caught silently, features non-functional)
- Saving additional Kea servers (Settings → Infrastructure) always returned a 500 — `save_extra_servers` referenced undefined `cfg` and `CONFIG_FILE`; now loads a fresh config from disk, writes via `extensions.CONFIG_FILE`, and reloads `KEA_SERVERS` from the new config instead of the stale in-memory one
- Any database error during user creation returned a 500 instead of a friendly message — `except pymysql.IntegrityError` referenced an unimported module, and the NameError raised while evaluating the except clause bypassed the fallback handler
- Saving Kea API settings re-applied the old in-memory values instead of the freshly saved ones — hot-reload now reads from the newly loaded config and updates `extensions.cfg`

### Changed
- OUI fingerprint database deduplicated: 68 duplicate MAC prefixes with conflicting vendor values removed (last-wins semantics preserved — runtime behavior verified identical), entries now sorted
- CHANGELOG reordered consistently newest-first; added 3.6.0 pointer entry (details in RELEASE-3.6.0.md)
- Internal lab IP addresses in tests/README.md and CHANGELOG.md replaced with RFC 5737 documentation addresses
- Alert channel delete now shows the channel name in the confirmation message and audit log
- Dead code cleanup: unused variables, no-op `global` declaration, f-strings without placeholders

### Developer Notes
- Pre-package Jinja validation must register `hostname` as a no-op filter alongside `utcfmt`/`utcdate`/`utctime` — it's registered in `jen/__init__.py` and used by 7 templates

## [3.8.0] - 2026-07-17

### Subnet Create & Delete — Full Subnet Lifecycle Management

Jen could previously only edit subnets that already existed in Kea's config. There was no way to create a brand-new subnet, or delete one, from within Jen at all. The "Add Subnet" button that previously lived in Settings → Infrastructure only added a friendly-name mapping inside Jen — it never touched Kea's actual configuration, so a subnet still had to be provisioned manually via SSH before Jen could do anything with it. This release closes that gap.

**➕ Add Subnet** (Network → Subnets → Add Subnet)

A new page for creating a real subnet in Kea from scratch:
- Subnet ID auto-suggested as the next available unused ID (checked against both Kea's live config and Jen's own subnet map)
- Friendly name, CIDR, address pool, lease duration, renew/rebind timers, router/gateway, and DNS servers — the same fields Edit Subnet already supports
- Full validation before anything touches Kea: subnet ID uniqueness, valid CIDR, pool range falls within the CIDR, valid IPs for router/DNS, no CIDR overlap with any existing subnet
- Same safe-write pattern as Edit Subnet: backup config → append new subnet4 block → validate with `kea-dhcp4 -t` → only write and restart if validation passes, otherwise the original config is left untouched
- On success, the subnet is also registered in Jen's own name/CIDR mapping automatically — one action instead of two

**🗑️ Delete Subnet** (button on each subnet card)

- Blocked with a clear message if the subnet still has active leases or reservations — deleting Kea config out from under live leases would orphan them, so this is a hard block, not a force-override
- Once clear, removes the subnet4 block from Kea via the same backup/validate/restart safety path
- Automatically removes the subnet from Jen's own mapping so it disappears from the UI cleanly
- Confirmation required before submission, consistent with other destructive actions across Jen

**Consolidation:** The old editable "Subnet Map" form in Settings → Infrastructure is replaced with a simple read-only summary table pointing to Network → Subnets, where subnet creation, editing, and deletion now all live in one place instead of two.

**UI:** Both buttons use a labeled style (icon + text) rather than the compact icon-only buttons used on dense list pages — appropriate given these are low-frequency, high-consequence actions on a page with only a handful of cards, not a scannable table of dozens of rows.

**Also fixed in passing:** the subnet card header referenced a template variable (`s.subnet`) that didn't exist in the data the route actually provided (`s.cidr`) — CIDR was silently not displaying next to the subnet name badge. Corrected to reference the right field.

## [3.7.15] - 2026-07-17

### Fix: Unreadable Dropdown Options + Backup Code Login Ignoring "Remember Device"

**Grey/unreadable text in select dropdowns:** Native `<select>` dropdown option lists (e.g. "Remember for: 24 hours / 30 days / 60 days / 90 days / Forever" on the MFA challenge page) rendered with very low contrast — all unselected options appeared grey-on-grey. Root cause: no `color-scheme` CSS property was declared anywhere in the app. Browsers render native form control popups (dropdown lists, date pickers, etc.) using a light-mode default unless the page explicitly declares `color-scheme: dark`. Fixed by adding `color-scheme: dark` / `color-scheme: light` to the theme root in `base.html` (dynamically matching whichever theme is active) and to the three standalone pre-login pages that don't extend `base.html` (`login.html`, `mfa_challenge.html`, `error.html`).

**Backup code login completely ignored "Remember this device":** The MFA challenge page has two separate login forms — one for authenticator codes, one for backup codes. Only the authenticator form had the "Remember this device" checkbox and duration selector; the backup code form had no such UI at all, and the backend code path for backup-code verification never read `remember_device`/`remember_days` or set a trust cookie, regardless of what was submitted. This meant logging in via backup code could never establish a trusted device, full stop — every backup-code login would always re-prompt for MFA next time. Fixed by adding the same "Remember this device" UI to the backup code form (with distinct element IDs to avoid collision with the authenticator form) and adding matching remember-device logic to the backup-code success path in `mfa_routes.py`.

**Note on the originally reported issue:** the specific re-prompt-via-Authenticator-tab behavior reported alongside these bugs was not reproducible from code alone — the trusted-device check logic (`expires_at IS NULL OR expires_at > NOW()`) and the "forever" cookie duration fix from 3.7.11 both verified correct on inspection. Since the trust cookie is scoped per-browser, re-prompting after using a different browser, device, or after clearing cookies is expected behavior, not a bug. If MFA re-prompts persist unexpectedly on the *same* browser, check Settings → Audit Log filtered to `MFA_VERIFY` to confirm whether a trust was actually established on the prior login (the audit entry includes `trusted=forever` or `trusted=<days>` when successful, absent when "remember" wasn't checked).

## [3.7.14] - 2026-07-16

### Audit: Minor Ownership Gap in Self-Update

Full re-audit of the codebase following 3.7.13. Found one small issue: the self-update file-copy helper correctly `chown`'d the `jen/` and `templates/` directories back to `www-data` after installation, but not `static/icons/brands/`. Since the entire helper script runs as root via `sudo`, freshly copied brand icon SVGs would end up root-owned. In practice this is usually harmless since files are typically world-readable by default, but it's inconsistent with how every other installed path is handled and could cause a permission issue depending on umask. Fixed to include brand icons in the ownership fix-up, with a fallback (`|| true`) since the directory may not exist on older installs.

Everything else in this audit checked out clean: Python/template syntax, version consistency, auth coverage on all routes (core + plugins), subnet access control, DB migrations running automatically on every restart (confirming self-update's schema changes will apply), tarball structure consistency between the release workflow and self-update's extraction logic, and the DNS override and unified action button fixes from recent releases all remain stable.

**Known limitation (pre-existing, not introduced by recent work):** Jen does not use CSRF tokens on any form across the application. This is an architectural characteristic of the whole app, not a regression — flagging it here for visibility rather than as something this release addresses.

## [3.7.13] - 2026-07-16

### Full Audit Fixes — Self-Update Scope & Overlay Reliability

Full audit of the codebase following the recent self-update work turned up two real issues, both in the self-update mechanism itself.

**🔴 Self-update silently skipped static assets and system files:** The file-copy step copied everything from the release tarball except `static/` and `plugins/` wholesale. This meant any future release that changed `static/js`, `static/css`, or added brand icons would silently fail to apply via the GUI self-update — only a manual `sudo ./install.sh` would pick those up. It also blindly copied non-runtime repo files (`README.md`, `tests/`, `docs/`, `CHANGELOG.md`, `jen.service`, `jen-sudoers`, etc.) into `/opt/jen/` as inert clutter, while never actually installing `jen.service` to `/etc/systemd/system/` or `jen-sudoers` to `/etc/sudoers.d/` — meaning systemd unit or sudoers changes (like the fix in 3.7.10) would never propagate through self-update, only through the manual installer. Fixed by scoping the self-update copy to exactly what `install.sh` installs: the `jen/` package, `templates/`, brand icons only from `static/icons/brands/` (never touching user-uploaded `static/icons/custom/`), plus proper installation of `jen.service` (with `systemctl daemon-reload`) and `jen-sudoers` (validated with `visudo -c` before installing, to avoid ever locking out sudo with a malformed file).

**🟡 Update progress overlay showed false "Update complete" on failure:** The overlay was triggered by a client-side `sessionStorage` flag set unconditionally before form submission, with no awareness of whether the update actually succeeded server-side. If the update failed (bad download, DB backup failure, file copy error), the overlay would still appear, poll for up to 40 seconds, then falsely report "Update complete — reloading" while the real error flash message sat hidden behind the overlay the entire time. Fixed by only triggering the polling overlay when the server confirms success via a `?updated=X.Y.Z` query parameter on the redirect — error paths redirect without that parameter, so the error flash message displays normally instead of being masked.

## [3.7.12] - 2026-07-16

### Self-Update UX — Progress Overlay + Auto-Refresh

Two usability gaps in the GUI self-update flow (Settings → Infrastructure):

**No progress feedback during update:** Clicking "Update Now" just sat there while the download/install happened server-side, with no visual indication anything was in progress. Added a full-screen overlay with a spinner and status messages ("Downloading update package…" → "Installing files…" → "Restarting Jen…") that appears the moment the button is clicked.

**No auto-refresh after restart:** After the update completed and Jen restarted, the page showed a static "restarting" flash message but never came back on its own — you had to manually refresh to see the new version. Now the page polls `/settings/infrastructure/check-update` every 2 seconds after triggering an update; once Jen responds again (confirming the restart completed), the page auto-reloads. The overlay persists across the redirect using `sessionStorage` so it stays visible through the brief window where Jen is down mid-restart.

## [3.7.11] - 2026-07-15

### Fix: 500 Error on MFA Login When "Remember Forever" Selected

Selecting "Forever" from the Remember Device dropdown during MFA verification caused a 500 error: `invalid literal for int() with base 10: 'forever'`. The login actually succeeded underneath (clicking "Back to Dashboard" landed logged in) but the response crashed before it could redirect.

**Root cause 1** (`jen/services/mfa.py`): `create_trusted_device_token()` checked `int(remember_days) > 0 and remember_days != "forever"` — Python evaluates left to right, so `int("forever")` threw before the `!= "forever"` check ever ran. Fixed by reordering the check to test the string comparison first.

**Root cause 2** (`jen/routes/mfa_routes.py`): The MFA challenge route did `days = int(request.form.get("remember_days", 30))` unconditionally, with no handling for the literal `"forever"` value the dropdown actually submits. Fixed to keep `remember_days` as a string, pass it through as-is, and only convert to int for the cookie `max_age` calculation when it isn't `"forever"` (in which case a 10-year cookie is set instead).

## [3.7.10] - 2026-07-01

### Fix: Restart After GUI Self-Update Failing Silently

The self-update flow correctly downloaded and installed v3.7.9's files (confirmed on disk) but the automatic restart at the end failed with `Failed to restart jen.service: Interactive authentication required.` — Jen kept running the old process in memory even though the files on disk were updated, so the UI still showed the old version.

Root cause: `subprocess.run(["/usr/bin/systemctl", "restart", "jen"])` was calling `systemctl` directly, not through `sudo`. The `jen-sudoers` NOPASSWD rule for `systemctl restart jen` only takes effect when the command is actually invoked via `sudo` — calling the binary directly as `www-data` has no elevated permission and systemd's polkit layer requires interactive authentication, which fails immediately in a non-interactive web request context. This bug existed in all 5 restart call sites (manual restart button, port change, SSH key generation, plugin restart, self-update) — it just happened to not matter for infrastructure changes since those are edited less often and errors there were easy to miss in the flash message.

Fixed by adding `/usr/bin/sudo` as the first argument to all 5 `subprocess.run()` restart calls. Also corrected the sudoers file itself, which whitelisted `/bin/systemctl` while the code called `/usr/bin/systemctl` — a path mismatch that would have blocked the sudo grant even with the sudo prefix added.

## [3.7.9] - 2026-06-29

### Fix: Wrong Table Name Broke Reservations Page (regression from 3.7.8)

The DNS override fix in 3.7.8 queried a table called `dhcpv4_options` with `name='domain-name-servers'` — that table doesn't exist in Kea's schema. The correct table, used correctly everywhere else in this same file, is `dhcp4_options` filtered by `code=6`. This broke the entire Reservations page with "Table 'kea.dhcpv4_options' doesn't exist". Fixed to match the working query pattern already used by `edit_reservation`, CSV export, and dry-run import in the same file.

## [3.7.8] - 2026-06-29

### Fix: DNS Override Not Showing in Reservations List

The reservations list route fetched hostname and notes for each row but never queried the Kea `dhcpv4_options` table for per-host DNS overrides. Every row showed "default" regardless of whether an override was set.

Fixed by adding a `dhcpv4_options` lookup per host in the reservations list query. The DNS Override column now shows a green "● Override" indicator when an override is set (with the actual DNS value in the tooltip on hover), and "default" in muted grey when none is configured.

## [3.7.7] - 2026-06-11

### Fix: GUI Self-Update Now Works Correctly

Two bugs in the self-update mechanism introduced in 3.7.4:

**File copy permission failure:** The update route ran as `www-data` which has no write access to `/opt/jen/`. Files were being downloaded and extracted correctly but the copy step silently failed because `shutil.copy2()` can't write to root-owned directories. Fixed by generating a temporary shell script and running it via `sudo /bin/bash` (covered by the sudoers entry). The sudoers file is updated to allow `www-data` to run `/tmp/jen_update_install.sh`.

**No database backup:** The GUI update bypassed the DB backup prompt that exists in the shell installer. Fixed by adding a "Back up database before updating" checkbox (checked by default) to the update UI. When checked, a full Jen DB export is written to `/etc/jen/backups/` before any files are touched. If the backup fails, the update is aborted.

## [3.7.6] - 2026-06-11

### UI Polish — Unified Action Button System

All row-level action buttons across every page now use a consistent three-button system: ✏️ edit (neutral), 📌 pin/reserve (neutral, green on hover), ✕ delete (red border, always visible as destructive). All three are identical 28×28px buttons. A subtle vertical divider separates constructive actions from the delete button to reduce misclick risk.

Pages updated: Leases, Reservations, Devices, Database backups, API Keys, Saved Searches, Alert Channels, Custom Icons, Plugins, Infrastructure Settings (inline remove buttons), System Settings (logo remove).

The old pattern of mixed `btn-danger` (solid red), `btn-success` (solid green), and `btn-secondary` (grey) row buttons is replaced throughout. Page-level danger buttons (Apply & Restart Kea, Delete Stale, Start Migration, Revoke All) are intentionally left as solid red — those are high-impact actions that should remain prominent.

Three new CSS classes added to `base.html`: `.btn-act`, `.btn-act-edit`, `.btn-act-pin`, `.btn-act-del`, `.btn-act-divider`.

## [3.7.5] - 2026-06-10

### Installer — Three Fixes

**Remove redundant "Skip" option from upgrade config prompt:** The config choice during an upgrade previously offered three options: Keep / Reconfigure / Skip. Options 1 and 3 both did exactly the same thing (set `CONFIGURE=false` and continue). Skip has been removed — it's now a clean 1/2 choice: Keep existing config or Reconfigure.

**Database backup prompt during upgrade:** The installer already backed up application files (`run.py` and `jen/` package) before every upgrade, but never offered to back up the Jen database. Now prompts "Create a Jen database backup before upgrading?" (default yes). Reads connection details from the existing config file and runs `mysqldump` to `/etc/jen/backups/jen-db-TIMESTAMP.sql`. If the dump fails, a warning is shown but the upgrade continues.

**Skip `apt-get update` on upgrades:** On a fresh install, updating the package lists is necessary to find packages. On an upgrade, all dependencies are already installed and the update just adds 15-30 seconds of network delay for no benefit. `apt-get update` is now skipped when `IS_UPGRADE=true`.

## [3.7.4] - 2026-06-10

### GitHub Actions Auto-Release + Jen Self-Update

**GitHub Actions release workflow** (`.github/workflows/release.yml`): Pushing a version tag (e.g. `git tag v3.7.4 && git push origin v3.7.4`) now automatically triggers a GitHub Actions job that builds the release tarball, extracts all matching `3.7.x` entries from `CHANGELOG.md`, and creates a GitHub Release with the tarball attached and the changelog as release notes. No more manual release creation.

**Jen self-update from the UI** (Settings → Infrastructure): A new "Jen Updates" card shows the running version and a "Check for Updates" button. Clicking it hits the GitHub releases API and compares to the running version. If a newer release exists, it shows the version, publish date, a link to the release notes, and an "Update Now" button. Clicking Update downloads the release tarball from GitHub, extracts and installs it over `/opt/jen/`, preserves config/plugins/custom icons, and restarts Jen automatically. SuperAdmin only.

## [3.7.3] - 2026-06-10

### Fix: Trailing dot stripped from hostnames

Kea sometimes stores hostnames with a trailing dot (`tardis.` instead of `tardis`) because some DHCP clients send the hostname as a fully-qualified domain name with the root label included — technically valid but visually wrong. Added a `hostname` Jinja filter that strips trailing dots, applied everywhere hostnames are displayed: Leases, Dashboard recent leases, Reservations, Devices, Search results, IP Map, and the top devices JS widget.

## [3.7.1] - 2026-06-09

### Full Audit Fixes

Two issues found during full end-to-end audit of 3.7.0:

**🔴 `/opt/jen/plugins/` not created by installer:** The `mkdir -p` block in `install.sh` that creates the Jen directory structure was missing `/opt/jen/plugins/`. On a fresh install, attempting to install a plugin before the directory existed would fail. Fixed by adding `"$INSTALL_DIR/plugins"` to the mkdir block.

**🟡 Duplicate condition on network section-tabs:** The `{% if %}` block controlling when the Network section-tabs bar renders had the plugin endpoint check written twice (`or (plugin_nav_items and ...) or (plugin_nav_items and ...)`). Harmless — the condition evaluated correctly — but redundant. Cleaned up to a single check.

## [3.7.0] - 2026-06-09

### Plugin Architecture — Separate Repositories

Plugins now live in their own dedicated GitHub repositories rather than in the `plugins/` subfolder of the main Jen repo.

**What changed:**
- `plugins/network-discovery/` removed from main repo → now at `github.com/ltkojak/jen-plugin-network-discovery`
- `plugins/ipam/` removed from main repo → now at `github.com/ltkojak/jen-plugin-ipam`
- `plugins/registry.json` remains in the main repo — this is correct, the registry is part of Jen core
- `registry.json` `download_url` values updated to point at the new repos

**Why:** Plugin issues, PRs, release tags, and commit history now live in their own namespace. A bug fix to IPAM gets a tag on the IPAM repo, not a Jen core version bump. Community contributors can submit plugins by opening a PR to `registry.json` pointing at their own repo. The main Jen repo stays lean.

**No user-visible changes.** Install, enable, disable, and update flows are identical. The only difference is where the plugin zip is downloaded from.

**Versioning going forward:**
- Jen core: `3.7.x` for plugin architecture changes, `4.0` for plugin framework v2
- Plugins: independently versioned in their own repos

## [3.6.0] - 2026-06-08

Plugin framework and plugin manager. Full details in RELEASE-3.6.0.md.

## [3.5.17] - 2026-06-05

### Full Audit Fixes — Security, iOS Compatibility, UX

Five issues found in the full 3.5.16 audit, all fixed in one release.

**🔴 Security — `tmp_path` path traversal in database import:** The import confirm form submitted a base64-encoded file path that the server decoded and opened with no validation. An admin could have encoded any server path (e.g. `/etc/jen/jen.config`) to read it as an import file. Fixed by validating the decoded path starts with `/tmp/jen_import_` before use. Admin-only route, so severity was medium — but worth fixing.

**🟡 iOS/iPad — All native `confirm()` dialogs replaced:** 19 templates were still using `onsubmit="return confirm(...)"` or `onclick="return confirm(...)"`. iOS Safari suppresses native dialogs in certain WebKit contexts (home screen PWA mode, WKWebView), causing destructive buttons to silently do nothing — the same issue that broke the subnet editor in 3.5.9. Fixed by adding a `jenConfirm(message, callback)` function to `base.html` that shows an in-page modal overlay. All 19 call sites replaced — forms use a `data-confirm` attribute with a global handler that also fires after HTMX swaps (for partials like `_device_rows.html`). Affected pages: delete device, release lease, revoke API key, delete backup, confirm import, delete stale leases, remove MFA method, revoke trusted device, delete saved filter, restart Kea, remove SSL certificate, generate SSH key, delete alert channel, reset alert template, delete custom icon, reset MFA, delete user, bulk delete reservations.

**🟡 Devices page — type-filter badges now HTMX:** The device type filter badges (Mobile, IoT, Smart TV, etc.) were plain `<a href>` links causing a full page reload. Clicking "IoT" while a search was active would still trigger a full reload. Replaced with `<button>` elements that update the hidden `type` input in the HTMX filter form and trigger the live filter — consistent with how subnet/search/stale filters already work.

**🟢 Edit Subnet — disable confirm button when nothing changed:** The in-page confirmation panel's "Yes, apply and restart" button is now disabled when no fields have been modified. Prevents accidentally triggering a Kea restart when you open the confirm panel without changing anything.

**🟢 Audit Log Retention:** The audit log had no retention limit and would grow indefinitely. Added a "Keep audit log entries for N days" setting to Settings → System. Defaults to 90 days. Cleanup runs immediately when the setting is saved, and then daily at 00:05 via APScheduler. Set to 0 to keep forever. The current row count is shown on the settings page so you can see how large the log has grown.

## [3.5.16] - 2026-06-02

### Dashboard — Uniform Widget Spacing

The gaps between widget sections were inconsistent — the space between the subnet cards and the totals bar was 16px (from the flex gap) but the gaps below were ~32px because `.card` elements have a global `margin-bottom: 16px` that was stacking on top of the flex gap. Added a CSS rule to zero out `margin-bottom` on elements inside `#dash-widgets` so only the flex `gap: 16px` controls spacing, making all inter-widget gaps identical.

## [3.5.15] - 2026-06-02

### Dashboard — Consistent Gap Between All Widget Sections

Previous attempts only addressed the gap between the three subnet cards within the stat-grid, not the space between the separate widget sections (subnet cards → totals → recently issued leases → server status → alert summary). Each widget was a bare div with no margin, so they all ran together.

Fixed by wrapping all dashboard widgets in a single `display:flex; flex-direction:column; gap:16px` container. This applies a consistent 16px gap between every widget section uniformly — the subnet card grid, totals bar, recent leases, server status, and alert summary all sit visually separated from each other. Removed the now-redundant `margin-bottom` from `.stat-grid` since the flex gap handles all inter-widget spacing.

## [3.5.14] - 2026-06-02

### Dashboard — Fix Card Spacing (Revert 3.5.13 Mistake)

3.5.13 added padding inside the cards instead of space between them, making each card taller and reintroducing the scrollbar. Reverted card padding to original 20px. Gap between cards stays at 20px (up from 16px) which is what actually creates visible separation between them. Container padding reduced from 24px to 20px uniform to recover the vertical space the extra gap consumed.

## [3.5.13] - 2026-06-02

### Dashboard — More Breathing Room Between Subnet Cards

Increased the gap between subnet cards from 16px to 20px, and the internal card padding from `20px` to `22px 24px` (slightly more horizontal). Cards no longer look pressed together on a wide screen with all three subnets visible.

## [3.5.12] - 2026-06-02

### Dashboard — Subnet Card Layout Fix

The dashboard subnet cards were squishing the gateway and DNS rows because the grid minimum column width (280px) was too narrow once the extra row was added. Increased `minmax(280px, 1fr)` to `minmax(340px, 1fr)` so each card has enough room before the grid reflows to fewer columns. Also added `word-break: break-all` and a space-after-comma formatter on DNS values so `9.9.9.9,149.112.112.112` displays as `9.9.9.9, 149.112.112.112` and wraps cleanly if the card is narrow.

## [3.5.11] - 2026-06-02

### Fix: DNS/Gateway missing from Subnets page + Dashboard scroll trim

**Subnets page — DNS and Gateway not showing:** The `kea_subnets` dict built in the subnets list route was parsing timers and pools from Kea config but never parsing `option-data`. So `routers` and `dns_servers` were always empty strings even though the data was there. Fixed by adding the same `option-data` loop that `_get_subnet_kea_data()` (used by the edit page) already had. The dashboard was getting the data correctly via its own config-get enrichment added in 3.5.10 — the subnets page was the only place missing it.

**Dashboard scroll:** The page content was just barely tall enough to trigger a scrollbar with nothing extra to see. Reduced container bottom padding from 24px to 8px, and added `margin-bottom: 0` overrides for the last `.stat-grid` and last `.card` on any page so trailing whitespace doesn't accumulate. The dashboard now fits cleanly without a scrollbar in its default widget configuration.

## [3.5.10] - 2026-06-02

### Subnets — Show Router and DNS Servers (Dashboard + Subnets Page)

Both the dashboard subnet cards and the Network → Subnets page now display the Router/Gateway and DNS Servers for each subnet.

**Dashboard:** Each subnet card now shows a Gateway and DNS row below the pool utilisation bar. The values are fetched from Kea config on page load (same `config-get` call the subnets page uses) and rendered server-side — no extra API round trips. If Kea is unreachable the cards render cleanly without the section.

**Subnets page:** Same information added below the Address Pools section on each card. DNS entries are shown as individual monospace badges (one per server). Gateway shown as a single badge.

Both displays are hidden entirely if a subnet has no router or DNS configured in Kea — clean cards for subnets that don't have those options set.

## [3.5.9] - 2026-06-02

### Edit Subnet — iOS Fix + Current Value Display

**iOS / iPad — Apply & Restart button did nothing:** The form used `onsubmit="return confirm('...')"` which calls the browser's native confirm dialog. iOS Safari suppresses native dialogs in certain WebKit contexts (PWA mode, home screen apps, some embedded views). The dialog fires, iOS blocks it, `confirm()` returns false, and the form never submits — silently.

Fixed by replacing the native dialog with an in-page confirmation panel. Clicking "Apply & Restart Kea" now slides open a panel below the form showing a summary of what will change — no dialog, no popup. Two buttons: "Yes, apply and restart" and "Cancel". Works on iOS, iPad, and desktop.

**Current value always visible:** Each field now shows its current Kea value in the hint text below the input. If a value is not set in the Kea config the hint shows a yellow "Not currently set in Kea config" warning. This makes it immediately obvious when a field (like DNS servers) has never been configured through Kea.

**Change summary before confirming:** The confirmation panel shows a diff of what will actually change — old value struck through, new value highlighted. If no fields were modified it says so rather than submitting a no-op restart.

## [3.5.8] - 2026-05-19

### Fix: Alert Summary Widget "Could not load alerts"

The dashboard Alert Summary widget showed "Could not load alerts" on every page load. The `/api/alert-summary` endpoint was returning 404 — it had no route registered.

When the `api_top_devices` function was inserted into `dashboard.py` in 3.5.7, the str_replace operation accidentally ate the `@bp.route("/api/alert-summary")` decorator and `def api_alert_summary():` line from the function immediately following it. The docstring and body survived intact but the function was unreachable — Flask never registered the route. Fixed by restoring the two missing lines.

## [3.5.7] - 2026-05-19

### Notification Channels + Dashboard Widgets

**Notification Channels**

**Pushover support added.** Pushover ($5 one-time per platform) is now a supported alert channel — enter your User Key and Application API Token in the channel config. The first line of the alert message is used as the push notification title, the rest as the body.

**Multiple simultaneous channels now work.** The "Add Channel" modal was disabling the channel type selector whenever any channel already existed, making it impossible to add a second channel through the UI. The backend has always supported multiple active channels (it iterates all enabled channels and fires each one). The UI restriction is removed — you can now configure any number of channels simultaneously. For example: ntfy.sh for phone notifications AND Telegram for a group chat.

New channels in this release: Pushover (📲). Existing channels unaffected: Telegram, Slack, ntfy.sh, Discord, Generic Webhook, Email/SMTP.

Test button available per channel (always was, now works across all channel types including Pushover).

**Dashboard Widgets**

Two new optional dashboard widgets — both off by default. Enable them via the ✨ Customize button.

**📈 Lease Sparklines per Subnet (30 days)** — One SVG sparkline card per subnet showing the hourly active lease count trend over the last 30 days. Each card shows the subnet name, CIDR, current active count, and the trend delta (e.g. +3 or -2 vs 30 days ago). Uses the existing `/api/lease-history?days=30` endpoint — no new DB queries. Requires at least one day of lease history snapshots to display data (snapshots are taken every 30 minutes by the background thread).

**📱 Top Active Devices (30 days)** — Table of the 10 most recently active devices on your accessible subnets in the last 30 days. Shows device name/hostname, IP, subnet, last seen timestamp, and manufacturer. Reserved devices are badged with 📌. Respects subnet access control — restricted users only see devices on their assigned subnets. Powered by new `/api/top-devices` endpoint.

**New API endpoint:** `GET /api/top-devices` — returns top 10 recently active devices filtered by the current user's subnet access.

## [3.5.6] - 2026-05-19

### Fix: "Data too long for column 'password'" on Password Reset

Setting a user's password via the new edit modal failed with `(1406, "Data too long for column 'password' at row 1")`. The existing migration to widen the `password` column only matched `varchar(256)` exactly. If your installation had a different initial column size (e.g. `varchar(128)`, `varchar(255)`, or any other size under 512), the migration condition never matched and the column stayed narrow.

werkzeug scrypt hashes are ~162 characters, so any column under 162 causes the error. The migration now parses the actual numeric width from `SHOW COLUMNS` and widens to `VARCHAR(512)` whenever the current width is less than 512, regardless of what the exact original size was.

## [3.5.5] - 2026-05-19

### Users Page — Redesigned with Edit Modal

The user management page was redesigned from a cluttered inline-form table to a clean read-only table with a proper edit modal.

**What changed:**

**Clean table view.** Each row shows Username, Role badge, Subnet access summary, MFA status, and Timeout as read-only values. No inline forms in the table cells.

**Edit button per row.** Opens a modal with all editable fields in one place: role, subnet access, session timeout, password reset, MFA reset, and delete. The modal pre-populates with the user's current values.

**Password reset.** SuperAdmins can now set a new password for any user from the edit modal. Leave the password fields blank to keep the existing password.

**MFA reset.** SuperAdmins can wipe a user's MFA enrollment (methods, backup codes, and trusted devices) from the edit modal. The user will be prompted to re-enroll on next login. The button is disabled if the user has no MFA enrolled.

**"+ Add User" button** in the page header opens a modal — no more right-panel form that competed with the table. The add modal includes username, password, role, subnet access, and session timeout.

**"Change my password" removed** from this page. It lives on the user's own profile page — no reason to have it in two places.

**Unified edit route.** New `POST /users/edit/<id>` handles role + subnets + timeout + optional password in a single form submission. The old `set-role`, `set-subnets`, and `set-timeout` routes still exist for backward compatibility.

**New route:** `POST /users/reset-mfa/<id>` — SuperAdmin only. Disables all MFA methods, deletes backup codes, and deletes trusted devices for the specified user.

## [3.5.4] - 2026-05-19

### Full End-to-End Audit — Two Fixes

Complete audit covering Python syntax (34 files), template syntax (41 files), version string consistency (7 locations), security (SQL injection, open redirect, hardcoded secrets, debug mode, file upload path traversal), permission matrix enforcement, subnet filter coverage, HTMX partials, blueprint registration, DB schema, session cache completeness, and installer integrity.

**🔴 Fix — Stale `admin_required` in `jen/__init__.py`:** A dead `admin_required` decorator from before the shared `access.py` module existed was still sitting in `__init__.py` with the old `role != "admin"` check. It wasn't imported or called by anything (confirmed by grep), so it posed no runtime risk — but it was misleading and would confuse anyone reading the code. Removed.

**🔴 Fix — Test suite uses old `'admin'` role:** The test fixtures in `conftest.py`, `test_auth.py`, `test_users.py`, and `test_reservations.py` were still creating and asserting on `role='admin'` — which no longer exists as the top-level admin role since 3.5.0 promoted all `admin` accounts to `superadmin`. Tests would fail if run. Updated all test role references to `'superadmin'`.

**🟢 All other checks clean:**
- All 34 Python files and 41 templates parse without errors
- All 7 version strings consistent at 3.5.4
- No unprotected routes (all have `@login_required` or intentional public access)
- All f-string SQL values are hardcoded or `int()`-cast from settings — no user-controlled interpolation
- Open redirect on `?next=` correctly validates against `://` and `//` prefixes
- No hardcoded credentials or secrets
- Flask debug mode not enabled in production path
- File uploads (favicon, SVG icon, nav logo) all save to hardcoded paths; `icon_name` validated as alphanumeric-only before use in path
- All 7 data routes confirmed applying `filter_subnet_map()` or `add_subnet_restriction()`
- SuperAdmin-only decorator used exclusively in `users.py` — correct
- `subnet_access` included in both the DB query and session cache on login and load_user
- Scheduled backup `gzip.decompress` fix from 3.5.3 confirmed in place
- nav endpoint lists consistent (the extra `api.api_keys` count is from the section-tab active-state check on the API Keys tab itself — correct)

## [3.5.3] - 2026-05-19

### Scheduled Database Backups — Silent Failure Fix

Scheduled backups (via APScheduler) were failing silently on every run. The `results` list would show `"Jen: FAILED — BadGzipFile"` / `"Kea: FAILED — BadGzipFile"` in the `last_status` column but the error was swallowed so no flash or log entry appeared in the UI.

**Root cause:** `run_scheduled_backup()` in `dbexport.py` called `gzip.decompress(content)` on the bytes returned by `export_jen()` and `export_kea()`. But those functions return plain JSON bytes — `json.dumps(...).encode("utf-8")`. They are not gzip-compressed. Only `_write_backup()` applies gzip compression when writing to disk. The double-decompress caused `BadGzipFile` immediately. The manual "Back Up Now" button in the Database UI used the correct pattern (`json.loads(content.decode("utf-8"))`) and worked fine — this bug was isolated to the scheduled path.

**Fix:** Removed the `gzip.decompress()` call. Scheduled backups now use the same `json.loads(content.decode("utf-8"))` pattern as the manual backup route.

**Secondary fix:** Made the `last_run` date comparison in `scheduler.py` more robust. The guard that prevents running a backup twice in one day used `hasattr(last_run, "date")` which works for Python `datetime` objects but would silently skip the check if `last_run` was a string. Now handles both `datetime` and string-formatted dates gracefully.

## [3.5.2] - 2026-05-19

### Full Audit of 3.5.x Multi-Tenancy Changes

Complete audit of all access control changes introduced in 3.5.0/3.5.1. Several gaps found and fixed:

**`api.py` — legacy inline role checks:** Four routes in the API key management section (`/settings/api-keys`, create, revoke, delete) used inline `if current_user.role != "admin"` checks instead of the shared `_admin_required` decorator. These blocked superadmin users from accessing API key management. Fixed to `role not in ("superadmin", "admin")`.

**`mfa.py` — MFA required_admins mode excluded superadmin:** The `needs_mfa_for_role()` function checked `user.role == "admin"` when MFA mode is `required_admins`. SuperAdmin users would not be prompted for MFA even with that setting enabled. Fixed to `role in ("superadmin", "admin")`.

**`servers.html` — SSH action buttons excluded superadmin:** Two places in the Servers template conditionally showed restart/sync buttons only for `role == 'admin'`. SuperAdmins couldn't use them. Fixed to `role in ('superadmin', 'admin')`.

**`user_profile.html` — badge logic excluded superadmin:** The role badge on the profile page showed `badge-admin` only for `admin` role, so superadmin got `badge-viewer` styling. Fixed to `role in ('superadmin', 'admin')`.

**Unfiltered `SUBNET_MAP` passed to templates:** Several routes passed the full `extensions.SUBNET_MAP` directly to templates that render subnet dropdowns, meaning restricted users would see all subnets in form selects even if they couldn't access them:
- `add_reservation` — now passes `filter_subnet_map()`
- `edit_reservation` — now passes `filter_subnet_map()`
- `edit_subnet` GET — now passes `filter_subnet_map()` + access check before loading
- `ipmap` — now passes `filter_subnet_map()`
- `reports` — now iterates over `filter_subnet_map()` and passes filtered map
- `search` — now uses `filter_subnet_map()` for subnet name lookup

**Correctly left as full map (intentional):**
- `about.html` — informational page, no subnet data shown
- `users.html` — SuperAdmin-only page that needs all subnets for the assignment UI
- `servers.html` — admin-only page, server list is not subnet-restricted

## [3.5.1] - 2026-05-19

### Fix: Admin→SuperAdmin Migration Not Firing on Existing Installs

The 3.5.0 migration that promotes legacy `admin` users to `superadmin` was gated inside `if 'superadmin' not in ENUM` — meaning it only ran the first time the ENUM was expanded. If the ENUM expansion happened but the UPDATE failed, or if the session cache still held the old role, users would get "SuperAdmin access required" errors when navigating to the Users page.

**Fix:** The `UPDATE users SET role='superadmin' WHERE role='admin'` now runs unconditionally on every startup (it's idempotent — if there's nothing to promote, rowcount=0 and nothing happens). The ENUM expansion is still guarded since `ALTER TABLE` is not idempotent, but the promotion UPDATE always runs.

**If you're seeing "SuperAdmin access required" on 3.5.0:** Either deploy 3.5.1 (which fixes it on restart), or run manually:
```sql
UPDATE users SET role='superadmin' WHERE role='admin';
```
Then log out and back in to clear the session cache.

## [3.5.0] - 2026-05-19

### Multi-Tenancy — Three-Tier Role System with Subnet-Level Access Control

**New role model:**

| Role | Access |
|------|--------|
| ⭐ SuperAdmin | Full access to everything, all subnets, always. Cannot be subnet-restricted. |
| 🔧 Admin | Full management capability on assigned subnets. Can access Settings, Database, Audit. Cannot manage users or assign roles. |
| 👁️ Viewer | Read-only access on assigned subnets. Cannot access Settings, Database, or Audit. |

**Migration:** All existing `admin` users are automatically promoted to `superadmin` on first startup. Existing `viewer` users remain as `viewer` with `subnet_access = NULL` (all subnets). Zero manual steps required.

**Subnet access:** `NULL` means all subnets (unrestricted). A JSON array of subnet IDs means restricted to those subnets. SuperAdmins are always unrestricted regardless of the stored value.

**What gets filtered by subnet access:**
- Leases page — only shows leases in accessible subnets
- Reservations page — only shows reservations in accessible subnets
- Devices page — only shows devices last seen in accessible subnets
- Dashboard — only shows subnet cards for accessible subnets; recent leases filtered
- Network / Subnets page — only shows accessible subnets
- `/api/stats` endpoint — only returns stats for accessible subnets

**User Management page** is now SuperAdmin-only. Changes:
- Role is a live dropdown (change role without a separate form)
- Subnet access is a multi-select per user (select multiple or "All Subnets")
- SuperAdmin users show "All (unrestricted)" for subnet access — cannot be restricted
- Delete protects against deleting the last SuperAdmin
- Role change protects against demoting the last SuperAdmin
- Cannot demote your own account from SuperAdmin
- Role reference card explains the permission matrix

**New route:** `POST /users/set-role/<id>` — SuperAdmin only
**New route:** `POST /users/set-subnets/<id>` — SuperAdmin only

**Shared access module:** `jen/services/access.py` — replaces the duplicated `_admin_required` decorator that existed in every route file. Now provides `admin_required`, `superadmin_required`, and `add_subnet_restriction()` helper imported by all routes.

**DB migration:** `ALTER TABLE users MODIFY role ENUM('superadmin','admin','viewer')` + `ALTER TABLE users ADD COLUMN subnet_access JSON DEFAULT NULL` — both run automatically on startup via `init_jen_db()`.

## [3.4.9] - 2026-05-19

### Dashboard — Alert Summary Banner Always Showing Incorrectly

The "All recent alerts failed to send" warning banner on the Alert Summary dashboard widget was appearing even when all alerts had delivered successfully.

**Root cause:** The JS check used `a.status !== 'sent'` to detect failures, but `alerts.py` writes status as `"ok"` on success (not `"sent"`). Since `"ok" !== "sent"` is always true, every successfully delivered alert was counted as a failure, making `allFailed` always `true` whenever there were any alerts in the log at all.

**Fix:** Changed the check to `a.status !== 'ok'` to match what the service actually writes. Also added a `data.alerts.length > 0` guard so the banner never fires on an empty log. Fixed the per-row success indicator in the same widget for the same mismatch (`a.status === 'sent' || a.status === 'ok'` → `a.status === 'ok'`).

## [3.4.8] - 2026-05-19

### Full Audit — One Fix Found

Full audit of all 32 Python files, 41 templates, version strings, nav consistency, auth coverage, DB schema, HTMX partials, installer, and tarball structure.

**One real bug found:** The desktop nav Settings link was missing `settings.settings_icons` from its active-state endpoint list. So when navigating to Settings → Icons, the Settings nav item would go grey/inactive even though you were on a Settings page. The mobile drawer and section-tabs block both already included `settings.settings_icons` correctly — only the desktop nav-link was missing it. Fixed by adding it to the endpoint list on that one line in `base.html`.

**Everything else confirmed clean:**
- All 32 Python files parse without syntax errors
- All 41 Jinja2 templates parse without syntax errors
- All 7 version strings consistent at 3.4.8 across install.sh, `__init__.py`, Dockerfile, docker-compose files, README badge, config example, and docs
- All routes have `@login_required` or are intentionally public (API routes use `_api_auth()`, `/mfa/verify` has no login because user isn't authenticated yet)
- Silent `except: pass` blocks reviewed — all are in non-critical paths (Kea version enrichment, pool size calculations, Prometheus metrics, optional data joins) where silent fallback is correct behaviour
- All HTMX partials exist (`_lease_rows.html`, `_device_rows.html`, `_reservation_row.html`, `_recent_leases_rows.html`)
- Nav order Desktop and Mobile both: Dashboard → Management → Network → Database → Settings → About
- All endpoint groups consistent across desktop nav, mobile drawer, and section-tabs — except the icons fix above
- DB schema tables all accounted for
- Installer has correct dependency list (paramiko, apscheduler), pre-upgrade backup prompt, and `_box_line` banner fix
- Tarball extracts cleanly to `jen/` folder

**On the Alert Summary banner ("All recent alerts failed to send"):** Not a leftover from troubleshooting — it's live production logic. The dashboard checks if every alert in the recent log has a status other than `sent`, and if so shows that warning. It means your Telegram notifications are genuinely failing. Go to Settings → Alerts, check your bot token and chat ID are still valid (Telegram bots can be revoked, and chat IDs can change if the bot was re-added to a channel).

## [3.4.7] - 2026-05-06

### Database — Nav Reorder + Standard Section-Tabs

**Nav reorder:** Database moved from between Management and Network to between Network and Settings, matching its role as an infrastructure-level admin tool rather than a day-to-day management function. The order is now: Dashboard | Management | Network | Database | Settings | About.

**Standard section-tabs:** The Database page previously used a custom JavaScript tab switcher (show/hide divs with `display:none`, hash-based routing). Replaced with the same `?tab=` query parameter pattern and `section-tabs` bar in `base.html` used by Management, Network, and Settings. Each tab is a real link (`/database?tab=export`, `/database?tab=import`, etc.) — fully bookmarkable, works with browser back/forward, no JavaScript required for navigation. The section-tabs bar renders from `base.html` like all other sections.

**Post-action redirects:** Each form action (export error, backup, import, schedule save) now redirects back to the correct tab instead of always landing on the export tab.

## [3.4.6] - 2026-05-06

### Edit Subnet — Validation + Safe Config Write (Critical Fix)

**What happened:** Editing VLAN70's DNS servers with a typo (`9.9.9.9,149,112.112.112` — a period replaced with a comma) wrote an invalid value to `kea-dhcp4.conf`. The previous code did no IP address validation and no config testing before restarting Kea. Kea crashed and stayed down in a restart loop until the config was manually repaired.

**Three-layer fix:**

**Layer 1 — Server-side IP validation before SSH.** Before touching anything on the remote server, the POST handler now validates every IP in the router and DNS fields using Python's `ipaddress.IPv4Address`. If any value fails (not a valid IPv4 address), the user gets a flash error with the specific bad value highlighted, and no SSH connection is made. Pool format is also still validated with regex. Timer values are validated as positive integers.

**Layer 2 — Config test before writing.** The remote Python script now writes the new config to a `.jen_tmp` temp file first, then runs `kea-dhcp4 -t <tmpfile>` to validate it. Only if the test passes (exit code 0, no ERROR in output) does it `os.replace()` the temp file into the real config path. If the test fails, the temp file is deleted and the original config is left completely untouched.

**Layer 3 — Only restart after confirmed write.** Kea is only restarted after the remote script returns `ok` (config written and tested). If the script returns `testerror:...`, Kea is NOT restarted and the error message from `kea-dhcp4 -t` is shown in the UI. The original config is never modified.

**Result:** Bad input now causes a friendly error in the UI at step 1. If somehow bad data gets past validation, the `kea-dhcp4 -t` test catches it at step 2. In both cases, Kea stays running on the original config.

## [3.4.5] - 2026-05-06

### Security Audit + DNS Format Normalization

Full audit of the entire codebase prompted by a question about DNS server formatting on the Edit Subnet page.

**DNS server format (non-issue confirmed):** Kea accepts comma-separated values with or without spaces in the `domain-name-servers` option data field. Jen already normalizes DNS input at line 191 of `subnets.py` — `",".join(s.strip() for s in ...)` — stripping spaces before writing to `kea-dhcp4.conf`. The space visible in the UI is just what Kea stored in its config previously. No fix needed.

**🔴 Fixed — Open redirect via `?next=` parameter:** After a successful login requiring MFA, Jen stored `request.args.get("next")` directly into the session without validation. An attacker could craft a URL like `/login?next=https://evil.com` and redirect a victim there after MFA completion. Fixed by validating the `next` param before storing — rejects any value containing `://` or starting with `//` (i.e. anything that looks like an external URL). Only relative paths starting with `/` are accepted.

**🔴 Fixed — `/metrics` endpoint unauthenticated:** The Prometheus metrics endpoint was publicly accessible with no authentication, exposing subnet names, CIDRs, and live lease counts to anyone who could reach the Jen port. Added optional Bearer token protection: set `metrics_token = your-secret` in the `[server]` section of `jen.config` to require `Authorization: Bearer <token>` on all `/metrics` requests. If `metrics_token` is not set, the endpoint remains open (existing behavior, useful for scrapers in trusted networks). Also accepts `?token=` query param for scrapers that don't support custom headers. Documented in `jen.config.example`.

**🟡 Cleaned up — Double `@bp.route` on `remove_trusted_device`:** The function had two `@bp.route` decorators stacked directly. Flask correctly applies `@login_required` to both routes in this pattern, so there was no actual auth gap. Added a `# legacy alias` comment to make the intent clear.

**🟢 Confirmed clean — full audit findings:**
- All settings routes have `@login_required` + `@_admin_required` — confirmed via automated check
- All SQL f-strings use parameterized values for user input; f-string interpolation only used for column/table names from internal hardcoded sources (never user input)
- No `render_template_string` anywhere — no template injection risk
- No hardcoded credentials in source code
- Error handler returns generic message, no stack traces
- File upload paths all use `os.path.basename()` — no path traversal risk
- API key auth (`_api_auth()`) correctly rejects requests without a valid Bearer token
- Rate limiting and session timeout both implemented and confirmed working
- MFA trusted-devices/remove: two routes on one function — Flask applies `@login_required` to both; no auth gap, just clarified with comment

## [3.4.4] - 2026-05-05

### Leases — "Cursor closed" Error Fix

The reservation lookup added in 3.4.3 caused "Could not load leases: Cursor closed" on every page load. The bug: after the main lease query ran inside a `with db.cursor() as cur:` block, the `with` block exited and closed that cursor. The reservation lookup then called `cur.execute()` on the already-closed cursor — outside the `with` block. Fixed by opening a fresh `with db.cursor() as res_cur:` block for the reservation query.

## [3.4.3] - 2026-05-05

### Leases — Smarter Action Buttons Based on Reservation Status

Previously every active lease showed a 📌 "Create reservation" button and a ✕ "Release lease" button, regardless of whether that device already had a reservation. This was wrong on both counts:

- **📌 Create reservation** on an already-reserved device would attempt to create a duplicate reservation in Kea, which would error or silently conflict.
- **✕ Release lease** on a reserved device is pointless — Kea will immediately re-issue the same lease to the same MAC since a reservation exists. The device never actually loses its IP.

**Fix:** The leases route now cross-references the Kea `hosts` table to determine which leases have an existing reservation. It does this in a single batch query (one `WHERE HEX(dhcp_identifier) IN (...)` call against all MACs on the page) rather than per-row, so there's no performance impact.

**New behavior in `_lease_rows.html`:**
- **Has reservation →** Shows a single 📋 grey button that links to `/reservations?search=<MAC>`, filtered directly to that device's reservation. No create button, no release button.
- **No reservation →** Shows the 📌 create button and ✕ release button as before.

## [3.4.2] - 2026-05-05

### Devices — HTMX Filter Actually Broken

The HTMX filter on the Devices page wasn't working at all. Two bugs in 3.4.1:

1. **No `<form>` wrapper.** HTMX collects input values by serializing the nearest form ancestor. The filter bar was a `<div>` with HTMX attributes but no `<form>` element — so HTMX fired requests with no query params. Fixed by wrapping the inputs in `<form method="GET" style="display:contents;">` with the HTMX attributes on the form, matching the pattern used on Leases and Reservations.

2. **`type` filter not included.** The type_filter param (used by the device-type badge bar) was missing from the HTMX form entirely, so clicking a type badge then using the search box would silently drop the type filter. Added `<input type="hidden" name="type" value="{{ type_filter }}">`.

## [3.4.1] - 2026-05-04

### Leases / Reservations / Devices — Pagination & HTMX Fixes

**Filter lost on page change:** Pagination links on all three pages now include all active filter params (subnet, search, sort, direction, per_page, expired/stale flags). Navigating between pages no longer drops any filter.

**Default: no pagination (show all).** Previously all three pages hard-coded `LIMIT 50` regardless. Now the default is no limit — all matching rows are returned. A "Show all / 50 / 100 / 250 per page" selector in the filter bar lets users opt-in to pagination when working with very large datasets. The `per_page` param is preserved through sorting, filtering, and pagination.

**HTMX on Devices page.** Devices was the only one of the three using a plain GET form with `onchange=submit()`. Replaced with the same HTMX live-filter pattern as Leases and Reservations — `hx-get`, `hx-target="#devices-table-body"`, `hx-trigger="change from:select, input delay:400ms"`. Created `_device_rows.html` partial (mirrors the pattern of `_lease_rows.html` and `_reservation_row.html`). Devices now has instant live filtering without page reloads.

**Single source of truth for device rows.** Replaced the inline row loop in `devices.html` with `{% include '_device_rows.html' %}`, same as was done for leases in v3.3.16. The type-filter badge links now preserve all active filters (subnet, stale, per_page, sort, dir).

## [3.4.0] - 2026-05-04

### Database Management (new feature)

New top-level **🗄️ Database** menu item — visible to admins only, hidden entirely from viewers.

**Every operation clearly identifies which database it operates on** — Jen (🟢 green, users/settings/devices/audit) or Kea (🟡 yellow, reservations/options/leases). The target host and database name are displayed on every screen.

**Export** — Download a compressed `.json.gz` export of either database. Jen exports are table-selectable (users, devices, settings, alerts, audit log, API keys, MFA data, etc.). Kea offers two clearly-labelled export types: Reservations (hosts + dhcp4_options, permanent — the one you want) and Active Leases (lease4, transient — rarely needed). Export files include a metadata header with Jen version, schema version, export timestamp, and table list.

**Import / Restore** — Upload an export file. Jen reads the metadata header first and shows exactly what's in the file (tables and row counts) before touching anything. Schema version mismatches are detected and warned. Jen and Kea exports are automatically identified — you cannot accidentally import the wrong file into the wrong database. Import runs in a full transaction — rolls back completely on any failure. Jen imports support table selection and replace vs. merge mode. Kea imports support skip vs. overwrite duplicate handling.

**Scheduled Backups** — Configure daily or weekly automatic backups with retention count (keep last N). Backups saved to `/opt/jen/backups/` with `chmod 600`. APScheduler runs in-process — no cron required. The Backups tab shows all stored backups with database label, size, date, and per-file Download and Delete buttons.

**Migration Wizard** — Three-step UI to copy a database to a new server. Step 1: choose Jen or Kea. Step 2: enter target credentials with a live connection test. Step 3: confirm and run. Progress streams to the browser in real-time via SSE. On any failure, the target database is rolled back and all created tables are dropped — leaving the target completely clean. Row counts are verified after copy before committing.

**Pre-upgrade backup prompt** — The installer now asks "Create a database backup before upgrading? [Y/n]" before applying any upgrade. Backups saved to `/opt/jen/backups/` with version stamp in filename.

**New dependencies:** `apscheduler<4` (scheduled backup engine), `paramiko` (already added in 3.3.14).

**New DB table:** `backup_schedule` (singleton row, stores schedule config, last run time and status).

**New files:** `jen/routes/database.py`, `jen/services/dbexport.py`, `jen/services/scheduler.py`, `templates/database.html`, `templates/database_import_confirm.html`, `templates/database_migrate.html`.

## [3.3.16] - 2026-05-04

### Leases — Action Buttons Disappear on Search

**Bug:** After typing in the leases search box, the green 📌 (Reserve) and red ✕ (Release) action buttons disappeared from all rows. They stayed gone even after clearing the typed text — the only recovery was hitting the Clear button which does a full page reload.

**Root cause:** The search box uses HTMX for live filtering (`hx-get="/leases"`, `hx-target="#leases-table-body"`, `hx-swap="innerHTML"`). When typing, HTMX swaps in `_lease_rows.html` — but that partial template was missing the entire action buttons column. It only rendered IP, hostname, MAC, subnet, obtained, and expires columns. The full `leases.html` had the correct row markup inline, but HTMX bypassed that and used the incomplete partial. Once the partial replaced the rows, clearing the search box triggered another HTMX fetch (not a full reload), which also used the incomplete partial — so buttons stayed gone.

**Fix:** Rewrote `_lease_rows.html` to include all columns plus the action buttons column with the same `show_expired` / `current_user.role == 'admin'` guards as the full template. Also replaced the duplicate inline row loop in `leases.html` with `{% include '_lease_rows.html' %}` so both the initial page load and HTMX swaps share a single source of truth — this kind of drift between the partial and the full template can't happen again.

## [3.3.15] - 2026-05-03

### Installer Banner Fix + UX Improvements

**Installer banner overflow:** The version/copyright lines in `install.sh`'s ASCII box banner used hardcoded space padding. As the version number grew (e.g. `3.3.14` vs `3.3.3`), the extra character pushed the right `║` border out of alignment. Fixed by switching those two lines from hardcoded `echo -e` with manual padding to `_box_line` calls, which dynamically calculate visible string length (stripping ANSI codes) and pad to exactly 54 chars. The box will stay aligned for any version string going forward.

**Installer restart warning:** Added an explicit warning line before the Jen service restart during upgrades: "Jen web UI will be briefly unreachable during restart (~3s)". Previously the service restarted silently during the spinner, which could be confusing.

**Edit Subnet co-location warning:** Updated the warning banner on the Edit Subnet page to note that if Jen runs on the same host as Kea, the Jen web UI may also briefly drop when Kea is restarted. This is relevant for single-server homelabs where Jen and Kea share a host.

**Audit finding — false alarm on unprotected DB calls:** Initial audit flagged `mfa_routes.py` and `reservations.py` as having more DB calls than try blocks. Deeper analysis confirmed all DB calls are actually protected — the discrepancy was from nested try blocks and import statements being counted as DB calls. No code changes needed.

## [3.3.14] - 2026-05-03

### Missing paramiko Dependency

`paramiko` (SSH library used by the edit-subnet feature to connect to Kea servers) was not included in `install.sh`'s dependency list. This caused a "No module named 'paramiko'" error on the Subnets page whenever an edit was attempted. Added `paramiko` to both the package detection loop and the `pip3 install` command in `install.sh`.

## [3.3.13] - 2026-05-03

### Edit Subnet — Three Bugs Fixed

**Bug 1 — Changes not being applied:** The POST handler was reading `request.form.get("config")` (a raw config blob that was never in the form) and trying to set `s['subnet']` with it. The individual fields (`pool`, `valid_lifetime`, etc.) sent by the form were never read. Nothing was ever written to the Kea config. Rewrote the POST handler to correctly read each form field and patch only those fields in the config.

**Bug 2 — Fields showing blank:** The GET route passed `extensions.SUBNET_MAP[subnet_id]` which only contains `name`, `cidr`, `subnet` — no pools, timers, or options. The template tried to render `subnet.pools`, `subnet.valid_lifetime`, `subnet.options` which were all missing. Added `_get_subnet_kea_data()` helper that calls `config-get` on the active Kea server and extracts the current pool, timers, and option-data (routers, DNS) for the subnet. These are passed to the template as the `kea` context object.

**Bug 3 — All fields required:** Added "leave blank to keep current" logic. The POST handler now checks each field individually — if it's an empty string, that field is skipped entirely in the config update script. Only provided fields are written. If no fields have values, reports "nothing to change" without restarting Kea. Pool format is validated before SSH is attempted.

Also fixed the systemctl restart command to try both `kea-dhcp4-server` and `isc-kea-dhcp4-server` service names for broader compatibility.

## [3.3.12] - 2026-04-30

### Mobile Section Tabs — Actual Root Cause Fixed

3.3.11's CSS-only fix (`touch-action: pan-x`) didn't work because a global JS `touchstart` handler on all `a[href]` elements was calling `e.preventDefault()` on every touch event — including horizontal swipes — and immediately navigating. This completely blocked the scroll container from ever receiving the horizontal gesture, making CSS `touch-action` irrelevant.

**Fix:** Replaced the `touchstart`-based instant navigation with a three-event pattern: `touchstart` records the start position, `touchmove` sets a `didScroll` flag if horizontal movement exceeds vertical by more than 6px, and `touchend` only navigates if `didScroll` is false. Horizontal swipes now pass through to the scroll container correctly. Tap navigation still works with effectively zero perceptible delay.

## [3.3.11] - 2026-04-30

### Mobile Section Tabs — Horizontal Scroll Fix

The Settings page section sub-tabs (System / Alerts / Infrastructure / Users / Audit Log / API Keys / API Docs / Icons) extend off-screen on mobile. The container had `overflow-x: auto` for scrolling, but on iOS the swipe gesture was being captured by the tab `<a>` links as a tap rather than passing through to the container as a horizontal scroll — meaning users couldn't reach the rightmost tabs.

**Fix:** Added `touch-action: pan-x` to the `.section-tabs` container which explicitly tells iOS the horizontal swipe gesture should be interpreted as scroll, not tap. Added `overscroll-behavior-x: contain` so horizontal scroll on tabs doesn't bleed into back/forward gestures. Added `-webkit-touch-callout: none` to individual tabs to prevent long-press menus from interfering.

## [3.3.10] - 2026-04-30

### Mobile Nav — ACTUAL Root Cause Found

After many failed attempts at this clipping bug, the diagnostic screenshots from 3.3.9 finally revealed the real cause: **the mobile navigation drawer was being rendered ALWAYS VISIBLE on mobile, sitting above the nav bar**, not the nav being clipped by the iOS status bar.

The drawer used `transform: translateY(-110%)` to hide itself off-screen at the top, then `transform: translateY(0)` (via `.open` class) to slide it down. On iOS WebKit (Brave, Edge, possibly Safari), `translateY(-110%)` on a `position: fixed` element with `height: auto` was being computed as `translateY(0)` — meaning the drawer was sitting visible at the top of every page load. When the mobile media query also set `display: block` on the drawer (originally to enable the slide animation), this guaranteed the drawer stayed visible. The "clipped Jen logo" appearance was actually the drawer overlapping the nav bar from above.

**Fix:** Replaced the transform-based hide/show with simple `display: none` (default) / `display: block` (when `.open` class is added). The slide-down animation is gone but the drawer now reliably hides on every iOS browser. Removed the `display: block` override from the mobile media query that was forcing the drawer visible. Reverted the 50px hardcoded padding-top floor and section-tabs/drawer top calc inflation from 3.3.9 — those weren't fixing anything since the actual problem was elsewhere. Standard `env(safe-area-inset-top)` on nav padding-top is sufficient.

Added `max-height: calc(100vh - 120px); overflow-y: auto` on the drawer so it scrolls if it has more items than fit on screen.

## [3.3.9] - 2026-04-30

### Mobile Nav — Hardcoded iOS Status Bar Clearance

3.3.8's `env(safe-area-inset-top)` approach didn't fix the mobile nav clipping. Hypothesis: Brave/Edge on iOS aren't returning the expected value from `env(safe-area-inset-top)` — possibly because `viewport-fit=cover` engagement varies by browser, or iOS reports 0 for that var when the page is in a non-fullscreen state.

**Fix:** Use `max(50px, calc(... + env(safe-area-inset-top)))` on the mobile nav padding-top. The hardcoded 50px guarantees clearance under the iOS status bar / Dynamic Island regardless of what `env()` returns. On browsers/devices where `env()` works correctly, the larger value wins (e.g., on a 14 Pro the inset can be 59px). Section sub-tabs and mobile drawer top offsets updated to dock under the now-taller mobile nav.

## [3.3.8] - 2026-04-30

### Mobile Nav Clipping — Real Fix

Diagnostic build 3.3.7 confirmed templates were deploying correctly. The screenshots revealed the actual bug: when a flow element above the sticky nav was removed (or when scrolling under iOS's collapsing browser chrome), the sticky nav would slide up *under* the iOS status bar overlay instead of docking below it. This is because the body's `padding-top: env(safe-area-inset-top)` was being respected at scroll position 0 but not when sticky positioning recomputed during scroll/layout changes.

**Fix:** Moved the `env(safe-area-inset-top/left/right)` from `body { padding }` to `.nav { padding-top/left/right }`. The nav now owns its own status-bar protection — its content edge always sits below the inset regardless of sticky behavior, scroll state, or surrounding flow changes. Section sub-tabs and mobile drawer top offsets updated to `calc(56px + env(safe-area-inset-top))` to dock correctly under the now-taller nav.

**Diagnostic artifacts removed:** the red deploy-verification banner and the purple debug nav background from 3.3.7 are gone.

## [3.3.7] - 2026-04-30

### DIAGNOSTIC BUILD — Mobile Nav Clipping Investigation

This is a **forensic diagnostic build** to determine why nav clipping fixes haven't taken effect on iOS. After three rounds of CSS changes (3.3.3 re-issues + 3.3.5) the same vertical-stacked clipped logo persists, despite the markup being restructured to side-by-side. This build adds:

- A bright **red banner across the top** that says "v3.3.7 DEPLOYED — if you see this banner, the new template IS loading. Tap to dismiss." If this doesn't appear, the new HTML isn't being served (caching, install issue, Docker volume override, etc).
- A bright **purple background on the mobile nav** (only at viewport ≤768px) so we can see at a glance whether the new CSS is applying.

Once we confirm whether the new template is reaching the browser, the actual fix can be applied in the next version. The red banner and purple nav will be removed in 3.3.8.

> 3.3.6 was skipped (reserved for the failed re-issue we converted to a real version bump).

## [3.3.5] - 2026-04-30

### Mobile Nav Layout Fix

Bumped mobile nav `min-height` from 48px to 56px and added vertical padding to give the branding logo column room to breathe. The previous fixed 48px nav height was clipping the top of taller branded logos when stacked with the version label below. Section sub-tabs and mobile drawer top offsets updated to match (48px → 56px).

> Note: 3.3.4 was skipped. Two prior in-place re-issues of 3.3.3 didn't resolve the mobile nav clipping fully, so we're moving forward with a real version bump.

## [3.3.3] - 2026-04-30

### Mobile Fixes

- **iOS safe-area inset support.** On iPhones with a notch or Dynamic Island, the Jen logo and version badge at the top of the nav bar were being clipped by the status bar. Added `env(safe-area-inset-top/left/right)` padding to the body so the nav now sits below the system UI cleanly. The mobile drawer's fixed `top` was also updated to `calc(48px + env(safe-area-inset-top))` so it docks correctly under the nav. Issue was reported on iOS Safari/Brave at viewport widths under 768px.
- **Mobile nav drawer z-index.** The Dashboard link in the hamburger menu was being hidden by section sub-tabs (Subnets/Servers/DDNS, Leases/Reservations/Devices, etc) on pages other than the dashboard itself. The drawer had `z-index: 98` and the section tabs had `z-index: 99`, so the tabs rendered on top of the drawer's first item. Drawer bumped to `z-index: 101`.

## [3.2.0] - 2026-04-29

### Dashboard Enhancements

**1. Lease History Charts**
7-day utilization sparklines on each subnet card, drawn with Canvas API (no external charting library). Color-coded by utilization: blue (normal) → yellow (≥75%) → red (≥90%). Time range selector: 24h, 3d, 7d, 30d. Uses the `lease_history` table that has been collecting snapshots every 30 minutes — data was there, just never displayed.

**2. Totals Summary Row**
New widget showing aggregate counts across all subnets: total active leases, dynamic, reserved, overall pool utilization percentage, and subnet count. Updates live with each api/stats poll.

**3. Alert Summary Widget**
Real data from `alert_log` — last 10 alerts with timestamp, type, message, and send status. Previously hardcoded "No recent alerts." Link to alert configuration. Hidden by default, enable in Customize.

**4. Recent Leases HTMX**
Time window selector (30min → 24h) now updates the table live via HTMX without reloading the page. Consistent with reservations and leases pages.

**5. Subnet Card Links**
Clicking a subnet stat card navigates to `/leases?subnet=ID` — filtered to that subnet. Cursor changes to pointer to indicate clickability.

**6. Last Updated Timestamp**
Small "Updated HH:MM:SS" text next to the refresh dot, updated after each api/stats poll.

**7. Customize Panel Improvements**
- New widgets (Lease History Charts, Totals Summary) added to customize panel
- Checkboxes now correctly reflect current saved state on panel open (previously unchecked by default even when widgets were active)
- Default widget set updated to include lease history charts and totals

## [3.1.0] - 2026-04-29

### Phase 3 — HTMX

HTMX 1.9.12 added for partial page updates. Served locally from `/static/js/htmx.min.js` — works fully offline, no CDN dependency. Downloaded automatically during install if internet is available.

**Reservations page:**
- Delete button now removes just the row — no full page reload, no scroll position reset
- Filter form (subnet, search) updates the table body live — 400ms debounce on typing, instant on select change
- Both features degrade gracefully: delete falls back to form POST, filter falls back to GET on submit

**Leases page:**
- Filter form (subnet, minutes, search) updates the table body live — 400ms debounce on typing
- Changing subnet or time window is instant, no full page reload

**Devices page:**
- Already had JavaScript modal editing — no HTMX needed, behaviour unchanged

## [3.0.2] - 2026-04-29

### Fixed — Bugs found by test suite
- `MAC_RE` and `HOST_RE` undefined in `jen/services/auth.py` — used in `valid_mac()` and `valid_hostname()` but never defined at module level. Every reservation add/edit that validated a MAC address was raising `NameError` in production. Added compiled regex patterns at module level.
- `SUBNET_NAMES` undefined in `jen/routes/search.py` — global search was raising `NameError` on every search request. Replaced with inline dict comprehension from `extensions.SUBNET_MAP`.
- `api/stats` error response missing `servers` key — when the Kea DB query failed, the JSON response omitted `servers`, breaking the dashboard server status JS update.

## [3.0.0] - 2026-04-29

### Phase 1 — Connection Pooling
`dbutils.pooled_db.PooledDB` replaces raw `pymysql.connect()` in `jen/models/db.py`. Two persistent connections per database maintained at startup. `get_jen_db()` / `get_kea_db()` borrow from the pool (~0ms) instead of opening a new TCP connection (~1s on remote host). Falls back to direct connections if `dbutils` not installed.

### Phase 2 — Automated Test Suite
69 tests across 6 modules covering all critical paths:
- `test_auth.py` — login, logout, auth required, rate limiting (17 tests)
- `test_dashboard.py` — dashboard load, api/stats, Kea-down graceful degradation (10 tests)
- `test_users.py` — password hashing unit tests, user CRUD, session cache invalidation (16 tests)
- `test_reservations.py` — add/delete reservation, input validation, settings pages (11 tests)
- `test_leases.py` — lease list, search, IP map (6 tests)
- `test_settings.py` — settings cache, branding/session/ports save, audit log (9 tests)

Tests use a separate `jen_test` database. Kea API is mocked. Each test starts with clean state. Run with: `pytest tests/ -v`

Setup: create `jen_test` database once, then `pytest tests/ -v` from the jen/ directory. See `tests/README.md` for full instructions.

## [2.9.0] - 2026-04-29

### Added — Connection Pooling

**`dbutils.pooled_db.PooledDB`** replaces raw `pymysql.connect()` calls in `jen/models/db.py`.

Previously every `get_jen_db()` and `get_kea_db()` call opened a new TCP connection to the database server (~1 second on a remote host) and closed it when done. With pooling:

- Jen maintains 2 persistent connections to each database, opened at startup
- `get_jen_db()` borrows a connection from the pool (~0ms)
- `db.close()` returns it to the pool rather than closing the TCP connection
- Pool grows to 10 connections under concurrent load, then blocks until one is free
- `ping=1` detects and replaces stale connections automatically

**Result:** Every page load, API poll, and action that queries the database is now effectively free from a connection overhead perspective. The 1-second login latency caused by MySQL TCP handshake is eliminated.

**Fallback:** If `dbutils` is not installed, `get_jen_db()` / `get_kea_db()` fall back to direct `pymysql.connect()` automatically so the app still starts.

**New:** `reset_pools()` in `db.py` tears down and recreates both pools — called if DB credentials change at runtime.

**Requires:** `pip3 install dbutils` — added to `install.sh` and `Dockerfile` automatically.

## [2.8.16] - 2026-04-29

### Fixed
- Login still sluggish after 2.8.15 — remaining synchronous DB operations on the login path:
  - `record_login_attempt()` on failed logins — synchronous INSERT, now fires async in background thread
  - Redundant `get_rate_limit_settings()` and `is_locked_out()` calls on failed login path — already have the data from the initial query, removed duplicate calls
  - `is_trusted_device()` was doing a synchronous `UPDATE mfa_trusted_devices SET last_used=NOW()` that blocked the response — UPDATE moved to background thread, SELECT still synchronous (needed to determine MFA redirect)
  - Removed duplicate `return redirect(url_for('mfa_routes.mfa_verify'))` — dead code from 2.6.x transformation

## [2.8.15] - 2026-04-29

### Fixed — Root cause of sluggishness found
Timing breakdown revealed `route:1022ms` on POST /login with `pre-route:0ms`. The login handler itself takes 12ms — the remaining ~1000ms was `audit()` blocking the response.

**`audit()` was synchronous** — it opened a DB connection, ran an INSERT into `audit_log`, committed, and closed before returning. Called on every save, login, logout, and config change across 55 call sites in 10 blueprints. On a network database this takes ~200-1000ms per call.

**Fix:** `audit()` now fires in a background daemon thread. The INSERT happens after the response is already sent. Request context values are captured before the thread starts.

**`clear_login_attempts()` also made async** — same pattern, also blocked the login response.

## [2.8.12] - 2026-04-29

### Added
- Request timing middleware — any request taking over 100ms is logged at WARNING level with method, path, and elapsed time. View with: `sudo journalctl -u jen -f | grep SLOW`. This will tell us exactly which requests are slow and by how much, so we can stop guessing.

## [2.8.11] - 2026-04-29

### Fixed
- Remaining sluggishness — two more DB connections per page load found and eliminated:
  - **Avatar query in context processor** — `inject_branding()` opened a DB connection on every single template render to fetch the user's avatar URL. Avatar is now cached in the Flask session and only re-queried on first load. Cache is invalidated automatically when the user uploads or removes their avatar.
  - **`ssl_configured()` in before_request** — called `os.path.exists()` on cert files on every request. Result is now cached at startup since SSL certs don't change at runtime without a restart.
- `check_session_timeout` now skips static asset requests entirely — no point running session logic for `/static/` files.

## [2.8.10] - 2026-04-29

### Fixed
- **Root cause of ~2 second delay found and fixed.** `check_session_timeout` in `before_request` calls `get_global_setting()` twice on every single request — to check if timeouts are enabled, and to read the timeout duration. Each call opened a new DB connection, queried, and closed it. With a network database that's 2 round trips × every page load, every API poll, every asset fetch.

  `get_global_setting()` now caches all settings in memory for 30 seconds, loaded in a single `SELECT * FROM settings` query. Cache is invalidated immediately on any `set_global_setting()` call so changes in Settings pages take effect within 30 seconds at most.

  Effect: the 2 DB connections per request become 0 (cache hit) or 1 (cache miss, loads all settings at once). This should eliminate the remaining delay entirely.

## [2.8.9] - 2026-04-29

### Improved
- SSL context hardened: minimum TLS 1.2, explicit cipher suite preference for ECDHE+AESGCM and ECDHE+CHACHA20, SSLv2/v3 disabled. This enables TLS 1.3 when both client and server support it, which reduces handshake to 1 round trip vs 2 for TLS 1.2, and enables 0-RTT on session resumption.

### Note
- Remaining ~2s login delay on HTTPS via domain name is likely network path latency (DNS resolution, Cloudflare tunnel, reverse proxy) rather than anything in Jen — login itself takes 12ms. Test on direct LAN IP (`http://192.0.2.11:5050`) to confirm: if instant there, the delay is in the network path not Jen.

## [2.8.8] - 2026-04-29

### Fixed
- Server status showing "Offline" on dashboard — placeholder `up=None` evaluated as falsy in `{% if s.up %}` rendering "Offline" instead of a loading state. Fixed template to handle three states: `None` → "Checking...", `True` → "Online", `False` → "Offline".
- Server status card now updates correctly when `/api/stats` returns — JS `updateStats()` now reads `servers` array from the response and updates status, HA state, and version cells by element ID. `/api/stats` expanded to include `ha_state`, `version`, and `role` per server.

## [2.8.7] - 2026-04-29

### Fixed
- Dashboard blank after 2.8.6 — passing `stats={}` meant no subnet cards were rendered server-side, so `updateStats()` had no DOM elements to update. The JS only fills in existing elements, it doesn't create them.

  Dashboard now renders card shells immediately using `extensions.SUBNET_MAP` (always available, no DB or Kea calls needed) with `…` placeholders. Server status renders from the config server list with unknown status. `/api/stats` fills in the real numbers within seconds of page load. Result: page appears instantly with structure, data populates quickly.

## [2.8.6] - 2026-04-29

### Fixed
- Post-login delay — timing instrumentation revealed login itself takes 12ms. The delay was the dashboard loading synchronously after the redirect. The dashboard route was making 4-6 sequential HTTP calls to the Kea API (config-get, version-get per server, kea_is_up, get_all_server_status) plus 3 DB queries per subnet, all before returning the page.

  Dashboard route now returns immediately with the page skeleton. Subnet stats, Kea status, and server info are populated by the existing `/api/stats` poll that already runs every 30 seconds. Recent leases (the only thing needing server-side device fingerprinting) still load synchronously but are capped at 50 rows instead of 200.

- Removed login timing instrumentation added in 2.8.4/2.8.5.

## [2.8.5] - 2026-04-29

### Fixed
- Login timing log never appeared — Flask's default log level is WARNING, but timing was logged at INFO which is silently filtered. Switched to WARNING. Also moved timing capture outside the `verify_password` block so both successful and failed logins are measured.

## [2.8.4] - 2026-04-29

### Added
- Login timing instrumentation — after a successful login, Jen now logs the time breakdown at INFO level:
  ```
  LOGIN TIMING: db_connect=Xms  db_queries=Xms  hash_verify=Xms
  ```
  This tells us exactly where the remaining latency is: DB connection overhead, query time, or hash verification. View with: `sudo journalctl -u jen -n 20 --no-pager | grep TIMING`

## [2.8.3] - 2026-04-29

### Fixed
- Login still slow after 2.8.2 — `needs_rehash()` in `jen/models/user.py` was silently returning `False` on every call because it tried to import `werkzeug.security.check_needs_rehash` which does not exist in this werkzeug version. The `except Exception: return False` swallowed the `ImportError` quietly, so the 1M-iteration hash stored on existing installs was never being detected or upgraded.

  Replaced with direct hash string parsing: `pbkdf2:sha256:ITERATIONS$salt$hash` — extracts the iteration count and returns `True` if it isn't 260,000. No werkzeug dependency. Works correctly for 260K (False), 1M (True), and scrypt (False — scrypt is already fast).

  **On first login after this update:** Jen detects the 1M-iteration hash, verifies it (slow, one last time), rehashes at 260K, and stores the new hash. Every login after that is fast.

## [2.8.2] - 2026-04-29

### Fixed
- Login still slow after 2.8.1 — the hash itself is now fast (260K iterations, ~190ms) but the login route was opening **7 separate DB connections** per login attempt: 3 for `get_rate_limit_settings()` reading settings one at a time, 1 for the rate limit query, 1 for the user lookup, 1 for `user_has_mfa()`, and 1 for `user_needs_mfa()` → `get_mfa_mode()`. On a network database each connection adds latency.

  Refactored `login()` to use a **single DB connection** for the entire flow: user lookup, all settings (rate limit + MFA mode) in one `WHERE setting_key IN (...)` query, and MFA enrollment check — all in one round trip. The 7 connections are now 1 (plus an optional 2nd for password rehash if needed).

- Removed duplicate `clear_login_attempts` and `User()` constructor calls — both were called twice due to a copy-paste error from the 2.6.x transformation.

## [2.8.1] - 2026-04-29

### Fixed
- Login delay of 2-3 seconds — root cause was werkzeug 3.x raising the default `pbkdf2:sha256` iteration count from 260,000 to 1,000,000. `hash_password()` in `jen/models/user.py` was calling `generate_password_hash(p, method="pbkdf2:sha256")` without pinning iterations, so werkzeug 3.x silently used 1M iterations. Pinned to `pbkdf2:sha256:260000` — meets NIST SP 800-132 minimum and keeps login under 200ms.
- Added transparent rehash on login: users whose passwords were stored at 1M iterations (hashed between 2.7.4 and 2.8.0) are automatically upgraded to 260K on their next successful login — no action required.

## [2.8.0] - 2026-04-29

### Changed
- **`jen.py` retired** — moved to `legacy/jen.py` with an explanatory header. No longer copied to `/opt/jen/jen.py` on install. The entry point has been `run.py` since 2.6.0; the monolith is kept in `legacy/` for reference only.
- **Backup and rollback updated** — now backs up and restores `run.py` instead of `jen.py`.
- **Version detection updated** — installer checks `legacy/jen.py` as a final fallback for very old pre-2.6 installations.

### Fixed — Docker
- `Dockerfile` was copying `jen.py` only — missing `run.py`, `jen/` package, and `werkzeug` pip package. Fixed all three.
- `CMD` was `python3 /opt/jen/jen.py` — updated to `python3 /opt/jen/run.py`.
- Both `docker-compose.yml` files now use `env_file: .env` — no more hardcoded environment variables in compose files.
- Healthcheck in compose files now correctly tries both HTTP and HTTPS.

### Added — Docker
- Full environment variable support in `run.py` — Docker users can configure Jen entirely via `.env` without mounting a `jen.config`. If `JEN_KEA_API_URL` is set, `run.py` auto-generates `/etc/jen/jen.config` from env vars on first start.
- `.env.example` expanded to cover all configurable values: Kea API, Kea DB, Jen DB, ports, SSH, DDNS provider, subnet map (`JEN_SUBNETS=1=Production,10.0.0.0/24;30=IoT,10.30.0.0/24`).
- Both compose files updated with clear Option A (env vars) / Option B (mounted config) comments.

### Verified
- Full smoke test of all 14 blueprints — every `render_template` call references an existing template, every `url_for` call references a valid namespaced endpoint, all `flash` categories valid.

## [2.7.5] - 2026-04-29

### Added
- **Settings → Infrastructure → Server Ports** card — change HTTP and HTTPS ports from the UI without editing jen.config manually. Behaviour adapts to SSL state:
  - **HTTP only:** HTTP port field editable, HTTPS port field disabled with a note to configure SSL first
  - **HTTPS enabled:** both HTTP (redirect) and HTTPS port fields editable
  - Saving triggers an automatic Jen restart (port changes require rebinding the server socket)
  - Validation: ports must be 1024–65535 and HTTP ≠ HTTPS when SSL is active

### Fixed
- `save_ports` route was redirecting to Settings → System instead of Settings → Infrastructure where the form now lives

## [2.7.4] - 2026-04-29

### Fixed
- Login 500 error: `name 'User' is not defined` in `auth.py` — `User` class was used directly but never imported from `jen.models.user`. Added `from jen.models.user import User`.
- Login error: `Data too long for column 'password'` — werkzeug 3.x changed its default hash method from `pbkdf2:sha256` (103 chars) to `scrypt` (162 chars), exceeding the `VARCHAR(256)` column. Widened schema to `VARCHAR(512)` and added a startup migration that ALTERs the column on existing installations automatically.

## [2.7.3] - 2026-04-29

### Fixed
- Upgrade mode version transition arrow `→` was thin and hard to read in terminal fonts. Replaced with `==>` in bold cyan between yellow old version and bold green new version, making the transition clearly visible.

## [2.7.2] - 2026-04-29

### Fixed
- Existing version showed `v—` or `unknown` — `run.py` only imports `JEN_VERSION` from the `jen` package, it doesn't define it, so using it as the version source always returned empty. Installer now reads `jen/__init__.py` as the canonical source (falling back to `jen.py` for pre-2.6 installs). Version pattern tightened to `"[0-9]+\.[0-9]+\.[0-9]+"` to avoid matching non-version strings.
- Blank line before `[OK] Keeping existing configuration` was inserted into the wrong location in two of the three code paths (inside a `case` pattern and before a `&&` continuation), causing a bash syntax error. Fixed all three paths correctly.

## [2.7.1] - 2026-04-29

### Fixed
- Box borders misaligned — ANSI escape codes inflate raw string length causing manual space padding to land in the wrong place. Replaced all hand-padded box lines with a `_box_line()` helper that measures visible character width (stripping ANSI, handling UTF-8 multibyte chars) and pads to exactly 54 inner chars. All box lines now render at exactly 58 visible characters regardless of content or colour codes.
- `vunknown` in upgrade mode banner — version detection regex included the surrounding quotes but `tr -d '"'` wasn't stripping a leading `v` that appeared in some grep outputs. Added `v` to the tr delete set.
- `prompt_yn` now loops on invalid input — only `y`, `Y`, `yes`, `n`, `N`, `no`, or Enter (uses default) are accepted. Any other character re-prompts with a message.
- Config mode choice now loops on invalid input — only `1`, `2`, `3`, or Enter (defaults to `1`) are accepted. Any other input shows an error and re-prompts.
- Added blank line before `[OK] Keeping existing configuration` so it doesn't appear smashed against the menu.

## [2.7.0] - 2026-04-29

### Changed — Professional Installer Overhaul

Complete rewrite of `install.sh` and `uninstall.sh`.

**install.sh — new features:**

- BBS/ANSI terminal aesthetic — teal block banner, spinner animations, coloured status indicators, bordered summary box
- Auto-detects fresh install vs upgrade — no flags needed for the common case
- Flag system: `--upgrade` (non-interactive upgrade), `--configure` (re-run wizard only), `--repair` (reinstall files, keep config), `--unattended` (fully silent for CI/CD), `--docker` (Docker path)
- Fresh install wizard: live connection tests against Kea API, Kea DB, and Jen DB with pass/fail shown inline; admin password set during install (no more default `admin/admin`)
- DDNS wizard covers all four providers: Technitium, Pi-hole, AdGuard, SSH/Bind9
- Spinner animations on slow operations (apt-get, pip, connection tests, file copy)
- Post-install summary in a bordered ANSI box: URL, login, config path, log command, next steps
- Upgrade mode shows version transition (e.g. `2.6.7 → 2.7.0`)
- Repair mode reinstalls files and restarts service without touching config

**uninstall.sh — new features:**

- Matching BBS/ANSI aesthetic with red theme
- Shows all installed components and their paths before asking anything
- Three-level removal: app only (default) / app + config / full wipe
- Full wipe requires typing `DELETE` to confirm
- Preserves SSL certs, SSH keys, and backups by default so reinstall is painless
- Detects installed version and shows current service status

## [2.6.7] - 2026-04-29

### Fixed — Offline audit pass (2.6.x close-out)
Full static analysis of all 14 blueprints before declaring 2.6.x complete. Found and fixed 8 issues:

- `mfa_routes.py`: `load_user()` called bare — the login_manager user loader isn't directly importable from blueprints. Added a local `_load_user()` helper that queries the DB directly, identical logic to the registered loader.
- `dashboard.py`, `devices.py`, `leases.py`, `reservations.py`: `DEVICE_TYPE_DISPLAY` used but never imported from `jen.services.fingerprint`. Added explicit import alongside the `__fp` alias in each file.

**2.6.x is now complete.** All 14 blueprints pass a full targeted audit: zero bare `cfg`, zero unnamespaced `url_for`, zero missing service constant imports, zero missing wrapper functions, all 14 blueprints and 33 templates syntax-valid.

## [2.6.6] - 2026-04-29

### Fixed
- Settings → Alerts 500 error: `DEFAULT_TEMPLATES` and `ALERT_TYPE_LABELS` used in `settings.py` but never imported from `jen.services.alerts` — added explicit import
- Alert background thread error: `__get_global_setting` called in `alerts.py` but the lazy wrapper function was never defined — added missing wrapper

## [2.6.5] - 2026-04-29

### Fixed — Full blueprint audit pass
Complete audit of all 13 route blueprints identified 154 issues in two categories:

**Bare `cfg` references (46):** `cfg` was used directly in `ddns.py`, `servers.py`, `settings.py`, and `dashboard.py` instead of `extensions.cfg`. These caused 500 errors on Servers, DDNS, Settings → Alerts, and Settings → Infrastructure pages.

**Unnamespaced `url_for` calls (108):** All `url_for('endpoint')` calls used pre-blueprint bare names. Flask blueprints require `url_for('blueprint.endpoint')`. Fixed across all 13 blueprints — `auth`, `dashboard`, `devices`, `leases`, `mfa_routes`, `reports`, `reservations`, `search`, `servers`, `settings`, `subnets`, `users`.

Note: `subnets.py` contains a local variable also named `cfg` (the Kea config-get result dict) — those `.get()` calls are correct as-is and were not changed.

## [2.6.4] - 2026-04-29

### Fixed
- Navigation sub-tabs completely missing after blueprint migration — all `request.endpoint` checks in `base.html` used bare endpoint names (e.g. `'leases'`) but Flask blueprints namespace endpoints as `blueprint.function` (e.g. `'leases.leases'`). Updated all 20+ endpoint checks throughout the template.

## [2.6.3] - 2026-04-29

### Fixed
- `get_manufacturer_icon_url` and `DEVICE_TYPE_DISPLAY` not resolved in dashboard, leases, reservations, and devices blueprints — the automated transformation script missed these because they appear as keyword argument values rather than standalone calls
- `get_global_setting` not resolved in `alerts.py` background thread — the lazy wrapper was defined but the calls still used the bare name

## [2.6.2] - 2026-04-28

### Changed — Code Modularization (Phase 2 — Complete)
All 104 routes migrated from `jen.py` into 14 Flask Blueprint modules under `jen/routes/`. The `jen.service` systemd unit now runs `run.py` instead of `jen.py`. `jen.py` is retained as a compatibility reference but is no longer the entry point.

**14 route blueprints:**
- `jen/routes/api.py` — REST API v1 + API key management
- `jen/routes/auth.py` — login, logout
- `jen/routes/dashboard.py` — dashboard, stats, metrics, Prometheus
- `jen/routes/ddns.py` — DDNS status page
- `jen/routes/devices.py` — device inventory
- `jen/routes/leases.py` — leases, IP map
- `jen/routes/mfa_routes.py` — MFA enrollment and verification
- `jen/routes/reports.py` — reports
- `jen/routes/reservations.py` — reservations including bulk operations
- `jen/routes/search.py` — global search and saved searches
- `jen/routes/servers.py` — Kea server management
- `jen/routes/settings.py` — all Settings pages
- `jen/routes/subnets.py` — subnet view and editing
- `jen/routes/users.py` — user management and profile

**Entry point change:**
`ExecStart=/usr/bin/python3 /opt/jen/run.py` (was `jen.py`)

**No behaviour changes.** All routes, URLs, and features are identical.

## [2.6.1] - 2026-04-28

### Fixed
- `install.sh` was not copying the new `jen/` package directory or `run.py` to `/opt/jen/` — the modularization would have been silently missing on all installs
- Backup now also snapshots the `jen/` package before upgrading so rollback can restore it
- Rollback now also restores the `jen/` package alongside `jen.py`

### Added
- Post-install verification now imports all 9 `jen/` package modules and reports success or any import issues

## [2.6.0] - 2026-04-28

### Changed — Code Modularization (Phase 1)
`jen.py` remains the functional monolith and is fully intact. A parallel `jen/` package has been introduced alongside it with all business logic extracted into proper modules. No behaviour changes — this is a structural refactor only.

**New package structure:**
- `jen/__init__.py` — application factory (`create_app()`)
- `jen/extensions.py` — shared state hub (cfg, KEA_SERVERS, SUBNET_MAP, all globals)
- `jen/config.py` — config loading, writing, subnet map parsing
- `jen/models/db.py` — database connections and schema init/migrations
- `jen/models/user.py` — User model, password hashing, audit logging, global settings
- `jen/services/kea.py` — Kea API communication, HA detection, active server routing
- `jen/services/alerts.py` — alert channels, templates, check_alerts background loop
- `jen/services/fingerprint.py` — OUI database, device classification, manufacturer icons
- `jen/services/mfa.py` — TOTP, backup codes, trusted devices
- `jen/services/auth.py` — input validators, login rate limiting
- `jen/routes/` — blueprint directory (empty in 2.6.x, populated in 2.7.x)
- `run.py` — new entry point (loads monolith via compatibility shim for 2.6.x)

**Why this approach:**
The `extensions.py` singleton pattern means all modules share the same global state without circular imports. Any module that writes `extensions.KEA_SERVERS = new_value` has that change visible to every other module immediately, because Python module objects are singletons.

**What's next (2.7.x):**
Routes will be migrated from `jen.py` into Blueprint modules one section at a time. Once complete, `jen.py` becomes `run.py` calling `create_app()` and the monolith is retired.

## [2.5.10] - 2026-04-28

### Added
- Servers page warning when multiple servers configured but `ha_mode` not set — shows alert with direct link to Settings → Infrastructure → High Availability

### Improved
- `install.sh` template validation: replaced file count check with full Jinja parse validation — broken templates now cause installer rollback rather than silent bad install

### Updated
- `docs/user-guide.md` — Mobile Access, ntfy/Discord channels, and Kea Servers/HA sections added
- `docs/faq.md` — Mobile, High Availability, and DDNS Providers FAQ sections added
- `docs/troubleshooting.md` — HA troubleshooting, Mobile troubleshooting, and Alert Channels sections added

## [2.5.9] - 2026-04-28

### Fixed
- `settings_alerts.html` had a stray `{% else %}🔗{% endif %}` fragment left over from before ntfy/discord channel types were added — caused a Jinja template parse error on the Alert Settings page. All 33 templates now validated clean.

## [2.5.8] - 2026-04-28

### Fixed
- Servers page crashed with "Encountered unknown tag 'endif'" — the HA state reference card and a duplicate `{% block scripts %}` / `{% endblock %}` were appended outside the content block during the 2.5.x rewrite, causing Jinja to fail parsing the template. Removed the duplicate block and restored correct template structure.

## [2.5.7] - 2026-04-28

### Fixed
- Sub-tab links (Management, Network, Settings section tabs) had iOS 300ms tap delay. Applied global `touchstart` instant navigation to every `<a href>` on every page — covers sub-tabs, pagination, sort headers, action links, and anything else that navigates. Replaces the per-group whack-a-mole approach with one fix that covers everything.

## [2.5.6] - 2026-04-28

### Fixed
- Mobile hamburger drawer showed 9 expanded individual page links instead of matching the desktop nav's 5 grouped items (Dashboard, Management, Network, Settings, About). Drawer now mirrors the desktop exactly — tapping Management lands on Leases and the Management sub-tabs (Leases, Reservations, Devices) appear below, same as desktop. Active state detection matches desktop grouping.

## [2.5.5] - 2026-04-28

### Fixed
- Hamburger drawer links had a noticeable delay before navigating on iOS — `touch-action: manipulation` CSS fixes `click` events but not `href` navigation. Fixed by adding `touchstart` listeners on drawer links that call `e.preventDefault()` and navigate immediately via `window.location.href`, bypassing the 300ms delay entirely.

## [2.5.4] - 2026-04-28

### Fixed
- iOS/mobile double-tap required on all interactive elements — root cause was missing `touch-action: manipulation`. Applied globally to all buttons, links, inputs, selects, labels, table cells, and anything with `onclick`. Single tap now fires immediately on all interactive elements across the entire app.
- Nav on iPhone was a horizontally-scrolling bar of tiny links — replaced with hamburger (☰) menu that opens a full-width drawer with large tap targets (52px minimum). Desktop nav unchanged.

### Added
- Three distinct responsive breakpoints: desktop (>1024px full layout), iPad (769–1024px, hides low-priority columns), iPhone (≤768px, hamburger nav + table card reflow)
- `mobile-cards` CSS class: on iPhone, data tables reflow into individual cards per row showing field labels, eliminating horizontal scrolling on Leases, Reservations, and Devices pages
- `hide-mobile` and `hide-tablet` column classes: MAC addresses, timestamps, and other secondary data hidden on small screens but available via card label on mobile
- `viewport-fit=cover` for iPhone notch/Dynamic Island safe area support
- All form inputs use `font-size: 16px` on mobile to prevent iOS auto-zoom on focus
- Minimum 44px tap targets on all buttons and pagination controls (Apple HIG guideline)
- Scrollbar-hidden section tabs for clean tab overflow on mobile

## [2.5.3] - 2026-04-27

### Added
- Default favicon.ico shipped with Jen — teal circle with white "J", transparent background, available in 16×16 through 256×256. Eliminates blank browser tab icon on fresh installs.

### Fixed
- Removed `static/favicon.ico` from `.gitignore` and `.dockerignore` so the default favicon is tracked and included in Docker builds. User-uploaded replacements via Settings still work as before.

## [2.5.2] - 2026-04-27

### Security
- Replaced SHA-256 password hashing with werkzeug `pbkdf2:sha256` (salted, iterated). Existing users are automatically migrated to the new hash on their next successful login — no manual database changes required.

### Fixed
- Bare `except:` clauses in alert channel JSON parsing replaced with `except (json.JSONDecodeError, ValueError)`
- Default DDNS log path was still `kea-ddns-technitium.log` — changed to `kea-ddns.log`

### Updated
- `docs/release-notes.md` — 2.5.2 entry added

## [2.5.1] - 2026-04-27

### Added
- Pi-hole DNS provider for DDNS hostname lookup — supports both v5 (api.php) and v6 (REST API with session auth)
- AdGuard Home DNS provider for DDNS hostname lookup — Basic Auth REST API
- SSH/Bind9/Unbound DNS provider — runs `dig` over existing SSH connection, no extra config needed
- Active server TTL cache (10s) in `get_active_kea_server()` to avoid hammering `ha-heartbeat` on every page load

### Fixed
- Hardcoded `theelders` in DDNS SSH timeout error message — now uses configured `KEA_SSH_HOST`
- Hardcoded `matthew` as default SSH username in subnet edit — now uses configured `KEA_SSH_USER`
- `generic` DNS provider renamed to `ssh` for clarity (both values still accepted)
- DDNS settings UI now shows correct field sections per provider with dynamic show/hide
- DNS provider fields properly initialised on page load (not just on dropdown change)

### Updated
- `jen.config.example` — documented all four DNS providers with example config blocks
- `docs/admin-guide.md` — DDNS provider section updated with Pi-hole, AdGuard, SSH options

## [2.5.0] - 2026-04-26

### Added
- ntfy alert channel — supports ntfy.sh and self-hosted ntfy, configurable topic/token/priority
- Discord alert channel — Discord webhook integration with bold text formatting
- `ha_failover` alert type — fires when any Kea server's HA state changes
- `get_active_kea_server()` — automatically routes config-get and subnet editing to the active HA node
- HA state monitoring in `check_alerts()` — tracks HA state per server, alerts on state changes
- HA Configuration card in Settings → Infrastructure — ha_mode dropdown and server name field
- `/settings/infrastructure/save-ha` route to save HA settings
- Servers page HA enhancements — ⚡ ACTIVE indicator, HA mode banner, improved state badge colors
- DDNS `dns_provider` config option — `technitium`, `generic` (dig/host over SSH), or `none`
- Generic DNS lookup via SSH for non-Technitium setups
- `jen.config.example` — documented `ha_mode`, `role`, `name` in `[kea]`; `dns_provider` in `[ddns]`; example `[kea_server_2]` block

### Changed
- All `kea_command("config-get")` calls now use `get_active_kea_server()` — correct behaviour in HA setups
- DDNS page subtitle no longer hardcodes "Technitium DNS"
- Settings → Infrastructure DDNS section — replaced Technitium-specific form with provider-agnostic form

### Updated
- `docs/admin-guide.md` — HA configuration, DDNS provider config, ntfy/Discord setup
- `docs/release-notes.md` — 2.5.0 entry

## [2.4.10] - 2026-04-26

### Updated
- `docs/user-guide.md` — added Device Inventory, device fingerprinting, API Keys, MFA, and Settings → Icons sections (all missing since 2.x)
- `docs/faq.md` — added FAQ sections for device fingerprinting, randomized MACs, REST API, and MFA
- `docs/wiki-home.md` — version reference updated to 2.4.10
- `jen.config.example` — version comment updated to 2.4.10
- `Dockerfile`, `docker-compose.yml`, `docker-compose.mysql.yml` — version bumped to 2.4.10

## [2.4.9] - 2026-04-26

### Fixed
- Fix Dockerfile missing pip packages for MFA: `pyotp`, `qrcode[pil]`, `authlib`, `cryptography`
- Fix Dockerfile not copying `static/icons/brands/` — brand SVGs missing in Docker deployments
- Fix custom icons not persisting across container updates — added `jen-icons` volume in both compose files
- Bump Docker image tag to `jen-dhcp:2.4.9`

### Updated
- `docs/release-notes.md` — complete 2.x release history added
- `docs/admin-guide.md` — updated for MFA, REST API, device fingerprinting, custom icons, Prometheus metrics
- `docs/docker.md` — added `jen-icons` volume to persistent data table
- `docs/installation.md`, `docs/wiki-home.md` — version references updated

## [2.4.8] - 2026-04-25

### Fixed
- Fix device edit modal not opening for devices with names/owners: use data-* attributes instead of inline onclick

## [2.4.7] - 2026-04-25

### Fixed
- Fix device edit modal not opening: attempt to HTML-escape quotes in onclick (superseded by 2.4.8)

## [2.4.6] - 2026-04-25

### Fixed
- Add try/catch debug to edit modal to surface JS errors

## [2.4.5] - 2026-04-25

### Fixed
- Fix device edit silently failing for devices with longer icon names (e.g. `raspberrypi`, `philipshue`): `device_icon_override` column was VARCHAR(10) which truncated/errored on names longer than 10 chars. Widened to VARCHAR(50). Auto-migration fixes existing installs.
- Replace plain icon name dropdown with visual icon picker in edit modal — shows actual brand logo previews in a grid so you can see what you're selecting.

## [2.4.4] - 2026-04-25

### Fixed
- Fix device badges not showing on Leases, Reservations, and Dashboard: MACs from Kea are uppercase (`78:C4:FA`) but devices table stores lowercase (`78:c4:fa`) — lookup was silently failing. `get_device_info_map` now normalizes all MACs to lowercase, and the badge macro does the same.
- Fix Apple TV showing Apple logo instead of Apple TV logo: `classify_device` now returns manufacturer "Apple TV" for appletv hostnames, and `MANUFACTURER_ICON_MAP` maps "Apple TV" → `appletv.svg` (custom icon).
- Fix `pw08tf8v` (Lenovo) not being identified: added missing Lenovo OUI `c0:a5:e8`.

### Added
- Icon override in device edit modal — choose any bundled or custom icon to use for a specific device, independent of device type. Useful for Apple TV, HomePod, or any device where the auto-detected icon isn't specific enough.
- Subnet filter dropdown on Device Inventory page — filter devices by subnet alongside search and stale filter.

## [2.4.3] - 2026-04-25

### Added
- Manual device type override in the Device Inventory edit modal — choose from a dropdown (Apple, Android, IoT, TV, Gaming, etc.) to override auto-detection for any device. Overridden devices show a 🔒 indicator and a dashed badge border. Setting back to "Auto-detect" clears the override.
- Auto-detection loop now respects manual overrides — if a device has a manual type set, the background tracker will not overwrite it on subsequent lease updates.
- Device fingerprint badges now appear on Leases, Reservations, and Dashboard recently issued leases pages — small manufacturer logo/icon badge next to the hostname on every row.
- API `/api/v1/leases` endpoint now returns `manufacturer` and `device_type` fields per lease.
- Shared `_device_badge.html` Jinja macro keeps badge rendering consistent across all pages.

## [2.4.2] - 2026-04-25

### Fixed
- Fix iPhones/iPads not being identified: iOS 14+ uses randomized (private) MAC addresses by default — the OUI lookup always returns Unknown for these. Added hostname-based fallback detection so devices with `iphone`/`ipad` in the hostname are identified as Apple regardless of MAC. Same fallback now catches Echo/Alexa, Chromecast, Roku, Ring, Sonos, and gaming consoles by hostname when OUI is unknown.
- Add missing Roku OUI `50:06:f5` and Amazon Echo Show OUIs `50:d4:5c`, `b0:8b:a8` plus several other missing Amazon prefixes.

## [2.4.1] - 2026-04-25

### Added
- Brand SVG logos in Device Inventory — 24 bundled Simple Icons SVGs replace emoji for identified manufacturers (Apple, Samsung, Cisco, Dell, HP, Lenovo, Intel, LG, Google, Raspberry Pi, Roku, Ring, Sonos, Ubiquiti, Netgear, Synology, QNAP, Philips Hue, TP-Link, PlayStation, Epson, Espressif, VMware, QEMU)
- Custom icon management at Settings → Icons — upload your own SVG to override any bundled icon or add new manufacturers. Custom icons take priority over bundled ones and survive upgrades (stored in `/opt/jen/static/icons/custom/`)
- Icon display uses white-tinted SVG logos with colored badge backgrounds matching device type

## [2.4.0] - 2026-04-24

### Added
- Device fingerprinting via OUI (MAC address manufacturer lookup) — automatically identifies device manufacturer and type for every device in the inventory
- OUI database covering 800+ prefixes across Apple, Samsung, Amazon, Google, Raspberry Pi, Espressif (ESP8266/ESP32/Tasmota/ESPHome), Meross, TP-Link/Kasa, Roku, Ring, Ecobee, Sonos, Nest, Ubiquiti, Cisco, Netgear, Synology, QNAP, Lutron, Philips Hue, Nintendo, PlayStation, Xbox, Intel, Dell, HP, Lenovo, LG, Canon/Epson/Brother printers, VMware/QEMU/Hyper-V virtual machines, and more
- Hostname-based sub-classification for Apple devices: distinguishes iPhone/iPad (📱) from MacBook/iMac (💻) from Apple TV (📺)
- Device type badge in inventory table — shows manufacturer name and emoji icon (📱 💻 🔌 📺 🎮 🖨️ 🗄️ 🌐 🥧 etc.)
- Device type filter bar above inventory — click any type to filter the full inventory
- Auto-migration: adds `manufacturer`, `device_type`, `device_icon` columns to existing `devices` table on first run

## [2.3.8] - 2026-04-24

### Fixed
- Fix lease release button (✕ on Leases page) — `/leases/release` route was missing entirely; added with proper audit logging
- Fix MFA trusted device revoke buttons — template used `/mfa/revoke-device/<id>` and `/mfa/revoke-all-devices` but routes were named differently; added alias routes and the missing revoke-all route
- Fix MFA policy Save button in Settings → System — `/settings/system/save-mfa-mode` route was missing; added
- Fix CSV Import on Reservations page — `/reservations/import` route was missing entirely; added with full dry-run support, duplicate detection, and per-row error reporting

## [2.3.7] - 2026-04-24

### Fixed
- Fix Add Reservation form not pre-selecting the correct subnet when arriving from the Leases pin button: the `selected` attribute comparison used `s.id` but the template iterates as `sid` — option was never matched so the form always defaulted to the first subnet (Production)

## [2.3.6] - 2026-04-24

### Fixed
- Fix 404 when clicking the pin (📌) button on the Leases page: button was POSTing to `/leases/make-reservation` which never existed. Changed to a GET link to `/reservations/add` with IP, MAC, hostname, and subnet pre-filled as query params. The Add Reservation form now pre-populates all fields when arriving from a lease row.

## [2.3.5] - 2026-04-23

### Fixed
- Fix API keys and all REST API v1 routes returning 404: routes were appended after the `if __name__ == "__main__"` block which starts `serve_forever()` — the server was already running and blocking before the route decorators at the bottom of the file ever executed. Moved all API routes before the main block so they register correctly at startup.

## [2.3.4] - 2026-04-23

### Fixed
- Fix Reservations rows taller than Leases: root cause was emoji buttons (🗑️ ✏️) rendering taller than their line-height and stretching table rows. Replaced with plain text equivalents (✕ ✏) in Reservations, Devices, and Saved Searches action columns to match the plain-text buttons already used in Leases.

## [2.3.3] - 2026-04-23

### Fixed
- Fix Reservations rows taller than Leases rows: hostname column text was wrapping to two lines when the column was narrow (7-column table). Added `white-space:nowrap` to hostname cells on Leases, Reservations, and Devices. Also removed remaining `font-size:11px` inline overrides from Devices date cells.

## [2.3.2] - 2026-04-23

### Fixed
- Fix table row inconsistency between Leases and Reservations pages — inline `font-size:12px` overrides on individual `<td>` cells were fighting the global 13px rule. Removed inline font-size from data cells; added `td.mono { font-size: 12px }` CSS rule so monospace cells (IPs, MACs, timestamps) are consistently slightly smaller across all pages without per-cell overrides.

## [2.3.1] - 2026-04-23

### Fixed
- Fix `/api/docs` returning JSON 404 — path starts with `/api/` so the API 404 handler intercepted it before the login redirect could fire. Moved to `/settings/api-docs` so it's treated as a settings page.

## [2.3.0] - 2026-04-23

### Added
- REST API v1 — read-only API at `/api/v1/` with the following endpoints:
  - `GET /api/v1/health` — Kea status and Jen version (no auth required)
  - `GET /api/v1/subnets` — subnet utilization stats with pool sizes and utilization percentages
  - `GET /api/v1/leases` — active leases, filterable by subnet/MAC/hostname
  - `GET /api/v1/leases/{mac}` — single device lease lookup with `active` boolean
  - `GET /api/v1/devices` — device inventory, filterable by MAC/name/subnet
  - `GET /api/v1/devices/{mac}` — single device with `online` status and current lease
  - `GET /api/v1/reservations` — all reservations, filterable by subnet
- API key management in Settings → API Keys — generate, revoke, and delete keys; key shown once at creation
- Live API documentation at `/api/docs` — all endpoints documented with parameters, example requests/responses, and ready-to-paste Home Assistant YAML and Zabbix HTTP agent config
- `api_keys` table added to Jen database automatically on first run after upgrade

### Fixed
- Standardized table row height and font size (13px) across all pages — Leases, Reservations, Devices, Users, Audit Log were all slightly different

## [2.2.38] - 2026-04-21

### Fixed
- Fix dashboard Server Status widget showing useless placeholder text — now fetches real server status (online/offline, HA state, version) and displays it inline, with a "View Details" link to the Servers page
- Fix sorting only applying to current page on Leases, Reservations, and Devices — client-side JS sorting only sorts the visible page. All three pages now use server-side ORDER BY with `?sort=column&dir=asc|desc` URL parameters, so sorting is applied before pagination across the full dataset. Column headers are now clickable sort links with ↑/↓ indicators. Sort state is preserved through pagination.

## [2.2.37] - 2026-04-17

### Fixed
- Fix DDNS log reading: my restoration in v2.2.34 incorrectly used paramiko (which was never installed or needed). The original implementation always used `subprocess` to call the system `ssh` binary directly — no extra dependencies required. Reverted to subprocess-based SSH. Removed all paramiko references introduced in v2.2.35/2.2.36.

## [2.2.36] - 2026-04-17

### Fixed
- Fix DDNS page showing "X Error" with no detail: `log_message` was never displayed in the template, making SSH errors invisible. Added Detail row to Log Info card and logger.error calls so errors appear both on screen and in journalctl.

## [2.2.35] - 2026-04-17

### Fixed
- Fix DDNS page crashing with "cannot access local variable 'paramiko'": `paramiko` was imported inside the try block but referenced in the except clause — if the import itself failed, the variable was undefined. Moved `paramiko` to top-level imports with a `HAS_PARAMIKO` guard.
- Fix Subnets page showing empty lease duration, 0.0h timers, and no address pools: route was only fetching active/reserved counts from the DB but never fetching lease times, renew/rebind timers, or pool ranges from the Kea API config-get. All subnet config data now fetched from Kea and passed to template.

## [2.2.34] - 2026-04-17

### Fixed
- Fix DDNS log showing "File not found": log lives on the Kea server (theelders), not on bigben where Jen runs. Route was restored with a plain local `open()` call instead of the original SSH-based log reading via paramiko. Restored SSH log fetch.

### Changed
- Remove hamburger/mobile panel nav entirely — now that the desktop nav is flat links with no dropdowns, the same nav works on all screen sizes. On small screens the nav scrolls horizontally. Simpler, more consistent, eliminates the messy mobile-only code path.

## [2.2.33] - 2026-04-17

### Fixed
- Fix nav logo version number alignment: when a logo image is set, version number now centers beneath the logo instead of left-justifying awkwardly beside it

## [2.2.32] - 2026-04-17

### Fixed
- Fix branding nav color section: had a nested `<form>` inside a `<form>` for the Reset button (invalid HTML — browsers silently ignore inner forms). Split into two separate forms. Reset button now always visible, disabled/greyed out when no custom color is set rather than hidden.

## [2.2.31] - 2026-04-17

### Fixed
- Fix About page error: `lease_counts` was referenced in the template but never passed by the route

### Changed
- Rework Custom Branding in Settings: replace pointless app-name text field with nav logo image upload (PNG/SVG/JPG/WebP, max 200KB) — logo replaces "Jen" text in nav bar when set. Nav bar color picker kept. Added missing save routes (`/settings/upload-nav-logo`, `/settings/remove-nav-logo`, `/settings/save-nav-color`) which previously didn't exist, making the old branding form completely non-functional.

## [2.2.30] - 2026-04-17

### Changed
- Replace dropdown nav menus with flat nav links + contextual section tab bars — eliminates iPad/touch double-tap issues entirely. Management, Network, and Settings are now direct links; when you're inside a section, a sticky tab bar appears below the nav showing all pages in that section. Profile avatar dropdown preserved as-is.
- Rename "Admin" nav item to "Settings"; moved Users and Audit Log into Settings section tabs alongside System, Alerts, Infrastructure
- Moved Reports from Network to Management section tabs
- About is now a direct top-level nav link (no submenu needed)
- Mobile hamburger menu updated to match new structure with Settings section replacing Admin

## [2.2.29] - 2026-04-17

### Fixed
- Fix dashboard recent leases time filter definitively: `expire` in Kea's lease4 table is a `TIMESTAMP` column (not a Unix integer), so all `UNIX_TIMESTAMP()` arithmetic was producing NULL comparisons and showing every active lease regardless of window. Also discovered `valid_lifetime` is stored per-lease in the lease4 row — no need to look it up from Kea config. Query now uses correct `expire - INTERVAL valid_lifetime SECOND > NOW() - INTERVAL N SECOND` timestamp arithmetic.

## [2.2.28] - 2026-04-17

### Fixed
- Fix time selector immediately snapping back to "Last 30 min": `hours` was passed to template as `str(float)` so `1.0 != "1"`, `4.0 != "4"` etc. — no option ever matched so browser defaulted to first item and form auto-submitted. Now strips trailing `.0` so values match option strings exactly.
- Add logging of dashboard lease lifetime values and query errors to help diagnose the recent leases time filter issue

## [2.2.27] - 2026-04-16

### Fixed
- Fix dashboard recent leases still showing all leases: previous fix hardcoded `86400s` lease lifetime which didn't match actual Kea config. Now reads `valid-lifetime` from Kea API config-get (with per-subnet overrides) and uses the real lease duration to calculate `issued_at = expire - valid_lifetime`. Time window filtering and "Obtained" timestamps are now accurate.

## [2.2.26] - 2026-04-16

### Fixed
- Fix dashboard "Recently Issued Leases" showing all active leases regardless of time window — query had no time filter and used `expire DESC` (future expiry) instead of filtering by when the lease was issued. Now filters by `expire - 86400 > NOW() - window` to approximate issue time
- Fix dashboard time selector resetting to "Last 30 min" on every page load — route never read the `hours` query parameter and never passed it back to the template; both fixed
- Fix trusted device "Remember this device" not persisting across logout — cookie was written as `jen_trusted` but read back as `jen_trusted_device`; name mismatch meant the cookie was never found on subsequent logins, always prompting for MFA again

## [2.2.25] - 2026-04-16

### Fixed
- Fix enrolled TOTP methods not showing on MFA settings page: DB schema uses column `name` but queries referenced non-existent column `device_name` — SELECT was failing silently (caught by bare `except`) returning empty list, and INSERT would also fail on new enrollments. Both corrected to use `name`.

## [2.2.24] - 2026-04-16

### Fixed
- Fix dashboard layout broken by malformed HTML from route restoration: closing `</div>` for stat cards was misplaced mid-template with a stray HTML comment, causing all subnet cards to render incorrectly
- Fix dashboard JS placed inside `{% block title %}` instead of `{% block scripts %}`, meaning `saveDashPrefs()` and related functions were injected into the page `<title>` tag rather than as executable JavaScript — Save Layout button silently did nothing
- Fix widget ID mismatch: HTML used `dash-subnet-stats` (hyphens) but JS referenced `dash-subnet_stats` (underscores); standardised to underscores throughout

## [2.2.23] - 2026-04-16

### Fixed
- Fix `mfa_verify` route rendering nonexistent `mfa_verify.html` — the template was always named `mfa_challenge.html`; route now renders the correct template and passes `has_totp` context variable it requires
- Fix field name collision in `mfa_challenge.html` — the "remember for" select was also named `remember_device` instead of `remember_days`, causing the days value to be lost on submit

## [2.2.22] - 2026-04-16

### Fixed
- Fix MFA verify route using `current_user` (who isn't logged in yet at verify time) — now correctly reads `mfa_pending_user_id` from session, calls `login_user()` only after successful code verification, and clears pending session keys on success
- Fix `mfa_enroll` template variable mismatches introduced during route restoration: `new_secret` → `secret`, action `setup_totp` → `enroll`, field `name` → `device_name` — enrollment form was silently broken and could not actually enroll a new authenticator

## [2.2.21] - 2026-04-16

### Fixed
- Fix login completely broken: `app.secret_key` was set to `os.urandom(24).hex()` on every startup, generating a new random key each time. This caused sessions to be invalidated on every restart and made login impossible with multiple gunicorn workers (each worker got a different key). Secret key is now generated once and persisted to `/etc/jen/secret_key`, then loaded on startup so sessions are stable across restarts and workers

## [2.2.20] - 2026-04-16

### Fixed
- Fix login form blanking username/password fields on failed login attempts — template now repopulates the username field and all failed login render paths pass `prefill_username` back to the template

## [2.2.19] - 2026-04-16

### Fixed
- Fix MFA redirect on login: `url_for("mfa_challenge")` corrected to `url_for("mfa_verify")`, resolving the "Could not build url for endpoint 'mfa_challenge'" error on the login page

## [1.0.0] - 2026-04-10

Initial public release.

### Features
- Dashboard with live subnet utilization, recently issued leases, Kea health indicator, auto-refresh
- Lease browser — filter by subnet, time window, search by IP/MAC/hostname
- Manual lease release and stale lease cleanup
- Lease history (expired leases)
- Visual IP address map per subnet
- Reservations — add, edit, delete with duplicate detection
- Per-reservation notes field
- Per-reservation DNS override
- Bulk CSV import and export for reservations
- Subnet editing via SSH — pool ranges, lease times, scope options
- Auto-backup and rollback on subnet edit failure
- Audit log — all changes tracked with user, timestamp, source IP
- DDNS status page with Technitium log viewer and hostname lookup
- Telegram alerts — Kea down/up, new device lease, utilization threshold
- Login rate limiting — configurable attempts, lockout duration, mode
- HTTPS via SSL certificate upload in UI
- SSH key generation for subnet editing in Settings
- Session timeout — global and per-user
- Dark/light mode toggle
- Sortable columns and pagination
- Prometheus metrics endpoint
- Guided installer with bare metal and Docker support
- Uninstaller
- Docker support (external MySQL and bundled MySQL modes)
- Full documentation

