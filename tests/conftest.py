"""
tests/conftest.py
─────────────────
Pytest fixtures shared across all test modules.
"""

import configparser
import os
import sys
import time
from datetime import datetime, timezone

import pymysql
import pymysql.cursors
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Test DB config ────────────────────────────────────────────────────────────
def _get_test_db_config():
    cfg = configparser.ConfigParser()
    cfg_path = os.environ.get("JEN_CONFIG", "/etc/jen/jen.config")
    if os.path.exists(cfg_path):
        cfg.read(cfg_path)
        return {
            "host":     cfg.get("jen_db", "host"),
            "user":     cfg.get("jen_db", "user"),
            "password": cfg.get("jen_db", "password"),
            "database": "jen_test",
        }
    return {
        "host":     os.environ.get("JEN_DB_HOST", "localhost"),
        "user":     os.environ.get("JEN_DB_USER", "jen"),
        "password": os.environ.get("JEN_DB_PASS", ""),
        "database": "jen_test",
    }

TEST_DB = _get_test_db_config()


# ── Minimal Kea-side schema for the test DB ──────────────────────────────────
# jen_test serves as both kea_db and jen_db in tests (see below), but Jen's
# own init_jen_db() only creates Jen's tables — in production the Kea-side
# tables (hosts, lease4, dhcp4_options) come from Kea's own schema installer,
# not from Jen. lease4 and dhcp4_options were apparently created manually at
# some point (tests touching them already passed), but hosts was never
# added, which has been failing six tests across every audit round since
# v4.4.4. CREATE TABLE IF NOT EXISTS on all three makes this idempotent and
# self-contained regardless of what's already present, so the test suite
# never again depends on manual DB setup steps outside this file. Columns
# match Kea's real dhcp4.sql schema, trimmed to what Jen's own queries
# actually touch.
_KEA_SCHEMA_TABLES = [
    """CREATE TABLE IF NOT EXISTS lease4 (
        address INT UNSIGNED PRIMARY KEY NOT NULL,
        hwaddr VARBINARY(20),
        client_id VARBINARY(128),
        valid_lifetime INT UNSIGNED,
        expire TIMESTAMP NULL,
        subnet_id INT UNSIGNED,
        fqdn_fwd TINYINT(1) DEFAULT 0,
        fqdn_rev TINYINT(1) DEFAULT 0,
        hostname VARCHAR(255),
        state INT UNSIGNED DEFAULT 0,
        user_context TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS hosts (
        host_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        dhcp_identifier VARBINARY(128) NOT NULL,
        dhcp_identifier_type TINYINT NOT NULL,
        dhcp4_subnet_id INT UNSIGNED DEFAULT NULL,
        dhcp6_subnet_id INT UNSIGNED DEFAULT NULL,
        ipv4_address INT UNSIGNED DEFAULT NULL,
        hostname VARCHAR(255) DEFAULT NULL,
        dhcp4_client_classes VARCHAR(255) DEFAULT NULL,
        dhcp6_client_classes VARCHAR(255) DEFAULT NULL,
        dhcp4_next_server INT UNSIGNED DEFAULT NULL,
        dhcp4_server_hostname VARCHAR(64) DEFAULT NULL,
        dhcp4_boot_file_name VARCHAR(128) DEFAULT NULL,
        user_context TEXT,
        auth_key VARCHAR(16) DEFAULT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS dhcp4_options (
        option_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        code SMALLINT UNSIGNED NOT NULL,
        value BLOB,
        formatted_value TEXT,
        space VARCHAR(128),
        persistent TINYINT(1) NOT NULL DEFAULT 0,
        dhcp_client_class VARCHAR(128) DEFAULT NULL,
        dhcp4_subnet_id INT UNSIGNED DEFAULT NULL,
        host_id INT UNSIGNED DEFAULT NULL,
        scope_id TINYINT UNSIGNED NOT NULL DEFAULT 0
    )""",
    # v5.0 Phase 1 — lease6/ipv6_reservations, columns taken directly from
    # Kea's real dhcpdb_create.mysql (isc-projects/kea), not memory: address
    # is VARCHAR(39) — NOT the INET_ATON-style INT lease4 uses — duid is
    # VARBINARY like hwaddr, and hwaddr/hwtype/hwaddr_source were added in a
    # later ALTER (schema 2.0) so they're nullable here on purpose.
    """CREATE TABLE IF NOT EXISTS lease6 (
        address VARCHAR(39) PRIMARY KEY NOT NULL,
        duid VARBINARY(128),
        valid_lifetime INT UNSIGNED,
        expire TIMESTAMP NULL,
        subnet_id INT UNSIGNED,
        pref_lifetime INT UNSIGNED,
        lease_type TINYINT,
        iaid INT UNSIGNED,
        prefix_len TINYINT UNSIGNED,
        fqdn_fwd TINYINT(1) DEFAULT 0,
        fqdn_rev TINYINT(1) DEFAULT 0,
        hostname VARCHAR(255),
        hwaddr VARBINARY(20),
        hwtype SMALLINT UNSIGNED,
        hwaddr_source INT UNSIGNED,
        state INT UNSIGNED DEFAULT 0,
        user_context TEXT
    )""",
    # ipv6_reservations is a real one-to-many junction table off hosts —
    # type 0=IA_NA (address), 2=IA_PD (delegated prefix); prefix_len is 128
    # for a plain address reservation, less than 128 for a delegated prefix.
    """CREATE TABLE IF NOT EXISTS ipv6_reservations (
        reservation_id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        address VARCHAR(39) NOT NULL,
        prefix_len TINYINT(3) UNSIGNED NOT NULL DEFAULT 128,
        type TINYINT(4) UNSIGNED NOT NULL DEFAULT 0,
        dhcp6_iaid INT UNSIGNED DEFAULT NULL,
        host_id INT UNSIGNED NOT NULL
    )""",
]


def _ensure_kea_schema():
    """Create the Kea-side tables in jen_test if they aren't already there.
    Safe to call every test run — CREATE TABLE IF NOT EXISTS is a no-op
    against an already-correct schema."""
    conn = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor)
    try:
        with conn.cursor() as cur:
            for ddl in _KEA_SCHEMA_TABLES:
                cur.execute(ddl)
        conn.commit()
    finally:
        conn.close()


def _patch_extensions():
    from jen import extensions
    extensions.JEN_DB_HOST = TEST_DB["host"]
    extensions.JEN_DB_USER = TEST_DB["user"]
    extensions.JEN_DB_PASS = TEST_DB["password"]
    extensions.JEN_DB_NAME = TEST_DB["database"]
    extensions.KEA_DB_HOST = TEST_DB["host"]
    extensions.KEA_DB_USER = TEST_DB["user"]
    extensions.KEA_DB_PASS = TEST_DB["password"]
    extensions.KEA_DB_NAME = "jen_test"
    extensions.KEA_API_URL  = "http://localhost:18000"
    extensions.KEA_API_USER = "test"
    extensions.KEA_API_PASS = "test"
    # v5.0 — KEA6_* must be reset alongside their v4 counterparts. Any test
    # that calls AppConfig.reload()/apply() against an isolated config (see
    # tests/test_appconfig.py) writes directly to these extensions globals
    # (by design — see jen/config.py), and _kea6_targets_same_db() in
    # jen/models/db.py compares KEA6_DB_HOST against KEA_DB_HOST at
    # connection time. Resetting only the v4 fields here left KEA6_DB_HOST
    # stuck on a stale value from whichever isolated-config test last ran,
    # making the two appear to genuinely differ and triggering a real (and
    # failing) second connection pool for tests that never touch v6 at
    # all. Mirroring KEA_* here is correct for the overwhelming common
    # case this whole fallback exists for.
    extensions.KEA6_API_URL  = "http://localhost:18000"
    extensions.KEA6_API_USER = "test"
    extensions.KEA6_API_PASS = "test"
    extensions.KEA6_DB_HOST = TEST_DB["host"]
    extensions.KEA6_DB_USER = TEST_DB["user"]
    extensions.KEA6_DB_PASS = TEST_DB["password"]
    extensions.KEA6_DB_NAME = "jen_test"
    extensions.SUBNET6_MAP = {}
    extensions.KEA_SERVERS  = [{
        "id": 1, "name": "Test Kea", "api_url": "http://localhost:18000",
        "api_user": "test", "api_pass": "test", "ssh_host": "",
        "ssh_user": "", "ssh_key": "", "kea_conf": "", "role": "primary",
    }]
    extensions.SUBNET_MAP = {
        1: {"name": "Test Network", "cidr": "10.99.0.0/24"}
    }
    extensions.HTTP_PORT  = 5099
    extensions.HTTPS_PORT = 8499
    extensions.CONFIG_FILE = "/tmp/jen_test.config"

    cfg = configparser.ConfigParser()
    cfg["kea"]    = {"api_url": "http://localhost:18000",
                     "api_user": "test", "api_pass": "test"}
    cfg["kea_db"] = {"host": TEST_DB["host"], "user": TEST_DB["user"],
                     "password": TEST_DB["password"], "database": "jen_test"}
    cfg["jen_db"] = {"host": TEST_DB["host"], "user": TEST_DB["user"],
                     "password": TEST_DB["password"], "database": "jen_test"}
    cfg["server"] = {"http_port": "5099", "https_port": "8499"}
    cfg["subnets"] = {"1": "Test Network, 10.99.0.0/24"}
    with open("/tmp/jen_test.config", "w") as f:
        cfg.write(f)
    extensions.cfg = cfg


# ── Session-scoped: create schema once ───────────────────────────────────────
@pytest.fixture(scope="session", autouse=True)
def test_database():
    _patch_extensions()
    from jen.models.db import reset_pools, init_jen_db

    # Fix 1: patch ssl_configured to always return False in tests
    # so redirect_to_https never fires a 301
    import jen.config as jen_config
    import jen
    jen_config.ssl_configured = lambda: False
    # Also patch the cached version in __init__
    jen._ssl_configured_cache = False

    reset_pools()
    init_jen_db()
    _ensure_kea_schema()
    yield

    try:
        db = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor)
        with db.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            cur.execute("SHOW TABLES")
            tables = [list(row.values())[0] for row in cur.fetchall()]
            for t in tables:
                cur.execute(f"DROP TABLE IF EXISTS `{t}`")
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
        db.commit()
        db.close()
    except Exception:
        pass


@pytest.fixture(scope="session")
def app():
    _patch_extensions()
    from jen.models.db import reset_pools
    reset_pools()

    import jen as jen_pkg
    import jen.config as jen_config
    jen_config.ssl_configured = lambda: False

    flask_app = jen_pkg.create_app()
    flask_app.config.update({
        "TESTING":          True,
        "SECRET_KEY":       "test-secret-key-not-for-production",
        "WTF_CSRF_ENABLED": False,
        # Fix 2: no SERVER_NAME — causes 404 on POST routes due to port mismatch
        # Flask test client handles routing without SERVER_NAME set
    })

    # Fix 3: patch _ssl_configured_cached so redirect_to_https never fires 301
    import jen as jen_mod
    jen_mod._ssl_configured_cache = False

    return flask_app


@pytest.fixture
def client(app):
    """v4.4.5 fix: this was scope='session' — a single test_client() (and
    its cookie jar) shared across the entire ~255-test run. Any test that
    logged the shared client into a session via session_transaction() left
    that session active for whichever test happened to run next, so tests
    asserting anonymous-access behavior would silently inherit whatever
    role the previous test's session was in, depending purely on
    execution order. Function scope means every test gets its own client
    with an empty cookie jar. app stays session-scoped (expensive to
    rebuild); test_client() itself is cheap."""
    return app.test_client()


@pytest.fixture
def db():
    conn = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor)
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def clean_tables(db):
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM login_attempts")
        cur.execute("DELETE FROM audit_log")
        cur.execute("DELETE FROM mfa_methods")
        cur.execute("DELETE FROM mfa_trusted_devices")
        cur.execute("DELETE FROM mfa_backup_codes")
        cur.execute("DELETE FROM settings")
        cur.execute("DELETE FROM devices")
        cur.execute("DELETE FROM saved_searches")
        cur.execute("DELETE FROM alert_channels")
        cur.execute("DELETE FROM alert_log")
        from jen.models.user import hash_password, _invalidate_settings_cache
        cur.execute(
            "UPDATE users SET password=%s, role='superadmin', session_timeout=NULL "
            "WHERE username='admin'",
            (hash_password("admin"),)
        )
        cur.execute("DELETE FROM users WHERE username != 'admin'")
        _invalidate_settings_cache()
    db.commit()


@pytest.fixture
def logged_in_client(client):
    """
    Test client with active admin session.
    Fix 4: last_active must be current time or session timeout fires immediately.
    """
    now = datetime.now(timezone.utc).isoformat()
    with client.session_transaction() as sess:
        sess["_user_cache"] = {
            "id": 1, "username": "admin",
            "role": "superadmin", "session_timeout": None
        }
        sess["_user_id"] = "1"
        sess["_fresh"]   = True
        sess["last_active"] = now
    return client


@pytest.fixture
def mock_kea(monkeypatch):
    from jen.services import kea as kea_svc
    monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {
        "result": 0, "text": "mocked",
        "arguments": {"subnet4": [], "Dhcp4": {}, "hosts": []}
    })
    monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: True)
    monkeypatch.setattr(kea_svc, "get_active_kea_server",
                        lambda: {"id": 1, "name": "Test Kea",
                                 "api_url": "http://localhost:18000",
                                 "api_user": "test", "api_pass": "test"})
    monkeypatch.setattr(kea_svc, "get_all_server_status", lambda: [{
        "server": {"id": 1, "name": "Test Kea"}, "up": True,
        "ha_state": None, "version": "2.4.0", "role": "primary"
    }])


# ── Shared test helpers ─────────────────────────────────────────────────────
# Not a fixture — a plain function, imported directly by test modules that
# need a non-superadmin (or subnet-restricted) logged-in client. Originally
# lived only in test_security_fixes.py; moved here in v4.4.5 so
# test_database.py could reuse it instead of duplicating it.
def restricted_client(client, db, allowed_subnets, role="admin", username="restricted1"):
    """Create a DB user restricted to `allowed_subnets` and log the test
    client in as that user (bypassing the login form, same pattern as the
    `logged_in_client` fixture)."""
    import json as _json
    from datetime import datetime, timezone
    from jen.models.user import hash_password
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password, role, subnet_access) VALUES (%s, %s, %s, %s)",
            (username, hash_password("testpass123"), role, _json.dumps(allowed_subnets))
        )
        user_id = cur.lastrowid
    db.commit()

    with client.session_transaction() as sess:
        sess["_user_cache"] = {
            "id": user_id, "username": username, "role": role,
            "session_timeout": None, "subnet_access": allowed_subnets,
        }
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True
        sess["last_active"] = datetime.now(timezone.utc).isoformat()
    return client, user_id
