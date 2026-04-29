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


@pytest.fixture(scope="session")
def client(app):
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
            "UPDATE users SET password=%s, role='admin', session_timeout=NULL "
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
            "role": "admin", "session_timeout": None
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
