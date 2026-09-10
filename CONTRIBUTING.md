# Contributing to Jen

Jen is a solo-maintained, open-source homelab project. Contributions are
welcome, but it helps to know up front what fits and what doesn't — this
document is that.

## The short version

- **Bug fixes, small well-scoped improvements, docs, tests:** very
  welcome. Open a PR.
- **New features / subsystems:** open an issue first to check it fits the
  project's direction before you write code.
- **Security issues:** do **not** open a public issue — see
  [`SECURITY.md`](SECURITY.md).

## What Jen is (and isn't)

Jen is a single Flask app that manages ISC Kea DHCP servers for a
homelab-to-small-business operator — a handful of servers, one admin,
agentless. Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) before
proposing anything that touches deployment, the self-update flow, SSH,
or the Kea communication paths; it's the record of why those are the way
they are.

Things that are a **good fit**:

- Fixes to management workflows (leases, reservations, subnets, devices)
- Additional alert channels, using the existing channel abstraction
- IPv6 parity for a v4 feature that doesn't have it yet
- Better validation, clearer errors, accessibility fixes
- Documentation and test coverage

Things that are a **hard sell** — open an issue first, and expect a
"probably not" on some of these:

- An agent that runs on the Kea servers (the agentless design is
  deliberate — see ARCHITECTURE §1)
- PostgreSQL support, or swapping the ORM-less `db.py` layer
- A rewrite of the frontend to a SPA framework
- Anything that makes `sudo ./install.sh` no longer a fully automatic
  upgrade
- Dependencies added for convenience rather than need — the list is
  deliberately small and floor-pinned

## Development setup

Jen's code runs on **Linux** (hardcoded `/opt/jen`, `/etc/jen`, `/tmp`
paths; SSH; systemd). On Windows, work through WSL or a Linux VM.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt      # app deps + test/lint tooling
```

Running the test suite needs a MariaDB/MySQL with a `jen_test` database
reachable (it serves as both `jen_db` and `kea_db`; `conftest.py` builds
the Kea-side tables):

```bash
JEN_DB_HOST=127.0.0.1 JEN_DB_USER=jen JEN_DB_PASS=... \
  python3 -m pytest tests/ -v
```

To run the app locally (Linux):

```bash
JEN_ROOT=$(pwd) python3 run.py     # expects /etc/jen/jen.config or JEN_* env vars
```

## Before you open a PR

CI runs on every push and PR, and every one of these gates must be green:

```bash
ruff check .                                   # lint
ruff format --check .                          # formatting
bandit -r jen/ plugins/ -ll -b .github/bandit-baseline.json
pip-audit
python3 -m pytest tests/                       # full suite, needs the DB
```

`ruff` is pinned to an exact version in `requirements-dev.txt` — match it
so formatting doesn't churn.

A few project-specific rules the tests enforce, worth knowing before they
fail on you:

- **Subnet scoping.** Any route that touches leases, reservations,
  devices, or subnets must also apply subnet restriction
  (`add_subnet_restriction()` for queries, `assert_subnet_access()` /
  `current_user.can_access_subnet()` for single objects). This is the
  single most common real bug in this codebase — ARCHITECTURE §2.
- **Migrations are append-only.** A schema change is a new numbered
  migration in `jen/models/migrations.py`, never an edit to an existing
  one, plus a test in `tests/test_migrations.py`.
- **Dependencies live in `requirements.txt` only.** Never re-list a
  package inline in `install.sh`, the `Dockerfile`, or CI —
  `tests/test_dependency_consistency.py` fails if you do.
- **`sudo`-invoked commands.** If you change a command string that's run
  via `sudo`, update `jen-sudoers` in the same commit to match it
  byte-for-byte — `sudo` matches literally.
- **Don't bump the version.** `JEN_VERSION` and the other version strings
  move together at release time, not per-PR. Leave them alone; the
  maintainer bumps them with the `CHANGELOG.md` entry.
- **American spelling** in code, comments, log lines, UI text and docs
  (`color`, `behavior`, `initialize`, `utilization`).

## Commit and PR style

- Focused commits with a clear message explaining *why*, not just what.
- One logical change per PR where practical.
- Add or update tests for behavior changes.
- If your change is user-visible, note it in the PR description so it can
  go in the changelog — `CHANGELOG.md` entries are narrative prose, not
  terse bullets.

## Licensing

Jen is GPL v3. By contributing you agree your contribution is licensed
under the same terms.
