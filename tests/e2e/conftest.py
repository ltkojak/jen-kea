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
from tests.e2e._fake_kea_server import FakeKeaServer

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "e2e-Sup3rSecret!1"
FRESH_USERNAME = "e2e_fresh_admin"
FRESH_PASSWORD = "e2e-Temp0rary!1"

E2E_SUBNETS = {
    1: {"name": "Office", "cidr": "10.99.0.0/24"},
    2: {"name": "Guest", "cidr": "10.99.1.0/24"},
}


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


@pytest.fixture(scope="session")
def fake_kea():
    server = FakeKeaServer()
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
    app_config.write_subnets(E2E_SUBNETS, reload=False)

    import jen as jen_pkg
    import jen.config as jen_config

    jen_config.ssl_configured = lambda: False

    app = jen_pkg.create_app()
    app.config.update(TESTING=True, SECRET_KEY="e2e-secret-not-for-production")
    # WTF_CSRF_ENABLED is deliberately left at its default (True) — the
    # whole point of this suite is exercising the real page, CSRF token
    # included.

    from jen.models.db import init_jen_db

    init_jen_db()
    _seed_users()

    from werkzeug.serving import make_server

    httpd = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{httpd.server_port}"
    _wait_until_up(base_url)

    yield base_url

    httpd.shutdown()
    thread.join(timeout=5)


@pytest.fixture
def base_url(live_server):
    return live_server


@pytest.fixture
def logged_in_page(page, base_url):
    """A page already past login, as the always-ready superadmin — the
    journey most tests actually care about starts here, not at the
    login form (login itself is its own journey below)."""
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', ADMIN_USERNAME)
    page.fill('input[name="password"]', ADMIN_PASSWORD)
    page.click(".btn-login")
    page.wait_for_url(f"{base_url}/")
    return page
