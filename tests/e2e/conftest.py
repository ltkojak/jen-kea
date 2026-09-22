"""
tests/e2e/conftest.py
──────────────────────
v5.39.0 (Q40) — the browser end-to-end suite. A real Flask app (the
same create_app() production uses) served by werkzeug on an ephemeral
port in a background thread, a fake Kea Control Agent (stdlib
http.server, see _fake_kea_server.py) on another ephemeral port, and
one seeded superadmin — all inside this same pytest process, so
Playwright drives an actual browser against actual Jen code and an
actual MariaDB, not mocks.

Skipped entirely (not an error) wherever playwright isn't installed —
the whole default `pytest`/`pytest tests/` run never imports this file
successfully and moves on; only an explicit `pytest tests/e2e` needs
`playwright install chromium` first. Verified locally: a plain
`pytest --collect-only` on a box with no playwright installed exits 0
and collects everything else; only targeting tests/e2e/ directly turns
the same missing import into a real (expected) error.
"""

import os
import sys
import threading
import time
import urllib.request

import pymysql
import pymysql.cursors
import pytest

pytest.importorskip("playwright")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tests.conftest import TEST_DB, _ensure_kea_schema, _patch_extensions
from tests.e2e._fake_kea_server import FakeKeaServer, build_dhcp4_config

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "e2e-Sup3rSecret!1"
FRESH_USERNAME = "e2e_fresh_admin"
FRESH_PASSWORD = "e2e-Temp0rary!1"

E2E_SUBNETS = {
    1: {"name": "Office", "cidr": "10.99.0.0/24"},
    2: {"name": "Guest", "cidr": "10.99.1.0/24"},
}

# v5.54.0-era (Q62) — JEN_E2E_DATASET=demo swaps the 22 journeys' two-subnet
# fixture for tests/e2e/demo_data.py's fictional homelab, used only by
# tests/e2e/test_docs_screenshots.py. The default (unset, or anything else)
# is the existing dataset every other e2e test depends on by id and name —
# this module never imports demo_data unless asked to.
DATASET = os.environ.get("JEN_E2E_DATASET", "default")


def _current_subnets() -> dict:
    if DATASET == "demo":
        from tests.e2e import demo_data

        return demo_data.SUBNETS
    return E2E_SUBNETS


def _reset_test_db():
    """Same shape as tests/conftest.py's test_database teardown, run as
    setup here instead — the e2e job's MariaDB starts empty, but a local
    run against a box that already ran the unit suite should not inherit
    that suite's tables and rows."""
    conn = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor)
    try:
        with conn.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            cur.execute("SHOW TABLES")
            tables = [list(row.values())[0] for row in cur.fetchall()]
            for t in tables:
                cur.execute(f"DROP TABLE IF EXISTS `{t}`")
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
        conn.commit()
    finally:
        conn.close()


def _wait_until_up(base_url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{base_url}/login", timeout=1)
            return
        except Exception as e:
            last_err = e
            time.sleep(0.2)
    raise RuntimeError(f"live server never came up at {base_url}: {last_err}")


def _seed_users():
    from jen.models.db import jen_db
    from jen.models.user import hash_password

    with jen_db() as db, db.cursor() as cur:
        cur.execute(
            "UPDATE users SET password=%s, must_change_password=0, role='superadmin' WHERE username=%s",
            (hash_password(ADMIN_PASSWORD), ADMIN_USERNAME),
        )
        cur.execute(
            "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, 'superadmin', 1)",
            (FRESH_USERNAME, hash_password(FRESH_PASSWORD)),
        )


@pytest.fixture(scope="session", autouse=True)
def test_database():
    """Overrides tests/conftest.py's autouse session fixture of the same
    name — that one exists to set up the unit suite's isolated DB once;
    this suite's own live_server fixture below does its own one-time
    setup (_reset_test_db + _patch_extensions + _ensure_kea_schema +
    init_jen_db), so running both would just double the work."""
    yield


@pytest.fixture(autouse=True)
def clean_tables():
    """Overrides tests/conftest.py's autouse per-test fixture of the
    same name. Root cause of a real bug found running this suite in CI:
    that fixture resets the 'admin' user's password to
    hash_password("admin") and deletes every other user after EVERY
    test — because tests/e2e/ sits under tests/, pytest applies it here
    too, and it silently clobbered this suite's e2e-seeded admin/fresh-
    account passwords the moment the very first journey finished, so
    every login after that first one failed with "Invalid username or
    password" for no visible server-side reason. This suite seeds its
    users once per session in live_server and every journey is meant to
    share that one baseline, not get it reset between tests."""
    yield


@pytest.fixture(scope="session")
def fake_kea():
    dhcp4_config = None
    if DATASET == "demo":
        from tests.e2e import demo_data

        dhcp4_config = build_dhcp4_config(
            demo_data.SUBNETS,
            demo_data.SUBNET_ROUTERS,
            dns=demo_data.SUBNET_DNS,
            pool_range=demo_data.SUBNET_POOL_RANGE,
            valid_lifetime=demo_data.SUBNET_VALID_LIFETIME,
        )
    server = FakeKeaServer(dhcp4_config=dhcp4_config)
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="session")
def live_server(fake_kea):
    _reset_test_db()
    _patch_extensions()
    _ensure_kea_schema()

    from jen.config import app_config
    from jen.models.db import reset_pools

    reset_pools()

    # _patch_extensions() already wrote a working jen.config at
    # extensions.CONFIG_FILE; point [kea] at the fake Control Agent and
    # give the subnets/dashboard/leases journeys two real subnets to
    # render, through the same choke-point API a real save would use
    # (CLAUDE.md "Configuration is a single choke point") — a raw
    # extensions.* assignment here would just get overwritten the moment
    # create_app() -> app_config.reload() re-reads the file from disk.
    app_config.write_value("kea", "api_url", f"http://127.0.0.1:{fake_kea.port}", reload=False)
    app_config.write_subnets(_current_subnets(), reload=False)

    import jen as jen_pkg
    import jen.config as jen_config

    jen_config.ssl_configured = lambda: False
    # jen/__init__.py imports `ssl_configured` by name at module load, so
    # patching jen.config.ssl_configured alone doesn't reach
    # _ssl_configured_cached()'s already-bound reference — same fix
    # tests/conftest.py's `app` fixture applies, for the same reason
    # (SESSION_COOKIE_SECURE must come out False under plain HTTP).
    jen_pkg._ssl_configured_cache = False

    app = jen_pkg.create_app()
    app.config.update(TESTING=True, SECRET_KEY="e2e-secret-not-for-production")
    # WTF_CSRF_ENABLED is deliberately left at its default (True) — the
    # whole point of this suite is exercising the real page, CSRF token
    # included.

    from jen.models.db import init_jen_db

    init_jen_db()
    _seed_users()
    if DATASET == "demo":
        from jen.models.db import jen_db
        from tests.e2e import demo_data

        with jen_db() as db:
            demo_data.seed(db)

    from werkzeug.serving import make_server

    # "localhost", not the raw 127.0.0.1 it resolves to: the passkey
    # journeys need a real hostname for WebAuthn's RP ID (RP id = request
    # host minus port, jen/services/passkeys.py) — an IP address there is
    # the kind of thing some WebAuthn implementations refuse outright.
    httpd = make_server("localhost", 0, app)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    base_url = f"http://localhost:{httpd.server_port}"
    _wait_until_up(base_url)

    yield base_url

    httpd.shutdown()
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def base_url(live_server):
    """Overrides pytest-base-url's own `base_url` fixture (a
    pytest-playwright dependency) — that one is session-scoped and reads
    a `--base-url` CLI option we never pass, so shadowing it here with
    the live app's real URL is the documented way to supply it
    programmatically. Must stay session-scoped: pytest-base-url's own
    internal fixture requests it at session scope, and a function-scoped
    override here is a hard ScopeMismatch, not just unused (caught in
    CI — every test errored at setup)."""
    return live_server


def login(page, base_url, username, password, expect_url):
    """Submit the real login form and wait for the post-login redirect.
    On failure, surfaces whatever the page actually says (a flash
    message, or the URL it got stuck on) instead of a bare Playwright
    timeout — that message is the difference between a five-second fix
    and another round of guessing from a CI log."""
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)
    page.click(".btn-login")
    try:
        page.wait_for_url(expect_url, timeout=10000)
    except Exception:
        alerts = page.locator(".alert").all_text_contents()
        raise AssertionError(
            f"login as {username!r} did not reach {expect_url!r} — stuck at {page.url!r}; on-page alerts: {alerts!r}"
        ) from None
    return page


@pytest.fixture
def logged_in_page(page, base_url):
    """A page already past login, as the always-ready superadmin — the
    journey most tests actually care about starts here, not at the
    login form (login itself is its own journey below)."""
    return login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
