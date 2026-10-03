"""
tests/conftest.py
─────────────────
Pytest fixtures shared across all test modules.
"""

import configparser
import os
import sys
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
            "host": cfg.get("jen_db", "host"),
            "user": cfg.get("jen_db", "user"),
            "password": cfg.get("jen_db", "password"),
            "database": "jen_test",
        }
    return {
        "host": os.environ.get("JEN_DB_HOST", "localhost"),
        "user": os.environ.get("JEN_DB_USER", "jen"),
        "password": os.environ.get("JEN_DB_PASS", ""),
        "database": "jen_test",
    }


TEST_DB = _get_test_db_config()


# ── The Kea-side schema for the test DB ─────────────────────────────────────────
# jen_test serves as both kea_db and jen_db in tests (see below), but Jen's own init_jen_db() only creates
# Jen's tables — in production the Kea-side tables come from Kea's own schema installer (`kea-admin
# db-init`), never from Jen.
#
# v5.67.0-beta.13 (Q127) — these tables used to be trimmed to the columns Jen's queries touch: no unique key
# beyond the primary key, no foreign key, no lookup table. That is why nothing in this suite could ever see
# what Kea's real schema does to an import or a migration. The reservation tables below are now Kea's own
# definitions — copied from `SHOW CREATE TABLE` against the database `kea-admin db-init mysql` creates for
# Kea 3.2.0 (schema_version 35.0; 3.0.3 is 30.0 and has the same reservation tables), as recorded by
# tests/kea_compat/test_db_moves.py::test_schema_facts_and_the_scope_kea_gives_a_hosts_options in
# kea-compat.yml run 37078598469 (artifact kea-compat-3.2.0/schema-3.2.0.json) — with three honest
# departures, each commented where it is:
#   * no collation clause (MariaDB's utf8mb4_uca1400_ai_ci does not exist on the MySQL 8 leg);
#   * no foreign key into the config-backend tables (dhcp4_client_class, dhcp4_pool, dhcp4_shared_network,
#     dhcp4_subnet): this suite does not create those tables, and no reservation test touches them;
#   (v5.67.0-beta.16, Q130: a FOURTH departure was removed — ipv6_reservations.address and lease6.address are
#   BINARY(16) here, as in every real 3.x, so a test that seeds an IPv6 address seeds sixteen bytes
#   (`ipaddress.IPv6Address(x).packed`, or INET6_ATON in SQL) and Jen's readers have to convert them, exactly as
#   they do against Kea. lease6.duid is VARBINARY(130) like the real one.)
# What matters for Q127 is all here: the UNIQUE keys on hosts, the options and IPv6 reservations' foreign keys
# to hosts (Kea declares BOTH an ON DELETE CASCADE and a legacy NO ACTION constraint on the options), the
# lookup tables with their rows, `schema_version`, and `client_classes longtext NOT NULL` — which has no
# default, so an INSERT that omits it is an ERROR in strict mode (it was a silent implicit default before
# Q127 made import errors real).
# tests/test_kea_test_schema.py keeps tests/system/compose/mariadb-init.sql, which defines the same tables
# for the system stack, from drifting away from this list.
_KEA_SCHEMA_TABLES = [
    """CREATE TABLE IF NOT EXISTS host_identifier_type (
        type TINYINT NOT NULL,
        name VARCHAR(32) DEFAULT NULL,
        PRIMARY KEY (type)
    ) ENGINE=InnoDB""",
    "INSERT IGNORE INTO host_identifier_type VALUES (0, 'hw-address'), (1, 'duid'), (2, 'circuit-id'), "
    "(3, 'client-id'), (4, 'flex-id')",
    """CREATE TABLE IF NOT EXISTS dhcp_option_scope (
        scope_id TINYINT UNSIGNED NOT NULL,
        scope_name VARCHAR(32) DEFAULT NULL,
        PRIMARY KEY (scope_id)
    ) ENGINE=InnoDB""",
    "INSERT IGNORE INTO dhcp_option_scope VALUES (0, 'global'), (1, 'subnet'), (2, 'client-class'), (3, 'host'), "
    "(4, 'shared-network'), (5, 'pool'), (6, 'pd-pool')",
    """CREATE TABLE IF NOT EXISTS schema_version (
        version INT NOT NULL,
        minor INT DEFAULT NULL,
        PRIMARY KEY (version)
    ) ENGINE=InnoDB""",
    "INSERT IGNORE INTO schema_version VALUES (35, 0)",
    """CREATE TABLE IF NOT EXISTS lease4 (
        address INT UNSIGNED PRIMARY KEY NOT NULL,
        hwaddr VARBINARY(20),
        client_id VARBINARY(255),
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
        host_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        dhcp_identifier VARBINARY(255) NOT NULL,
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
        user_context TEXT DEFAULT NULL,
        auth_key VARCHAR(32) DEFAULT NULL,
        PRIMARY KEY (host_id),
        UNIQUE KEY key_dhcp4_identifier_subnet_id (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id),
        UNIQUE KEY key_dhcp6_identifier_subnet_id (dhcp_identifier, dhcp_identifier_type, dhcp6_subnet_id),
        KEY fk_host_identifier_type (dhcp_identifier_type),
        KEY hosts_by_hostname (hostname),
        KEY key_dhcp4_ipv4_address_subnet_id_identifier (ipv4_address, dhcp4_subnet_id),
        CONSTRAINT fk_host_identifier_type FOREIGN KEY (dhcp_identifier_type) REFERENCES host_identifier_type (type)
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS dhcp4_options (
        option_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        code TINYINT UNSIGNED NOT NULL,
        value BLOB DEFAULT NULL,
        formatted_value TEXT DEFAULT NULL,
        space VARCHAR(128) DEFAULT NULL,
        persistent TINYINT(1) NOT NULL DEFAULT 0,
        dhcp_client_class VARCHAR(128) DEFAULT NULL,
        dhcp4_subnet_id INT UNSIGNED DEFAULT NULL,
        host_id INT UNSIGNED DEFAULT NULL,
        scope_id TINYINT UNSIGNED NOT NULL,
        user_context TEXT DEFAULT NULL,
        shared_network_name VARCHAR(128) DEFAULT NULL,
        pool_id BIGINT UNSIGNED DEFAULT NULL,
        modification_ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        cancelled TINYINT(1) NOT NULL DEFAULT 0,
        client_classes LONGTEXT NOT NULL,
        PRIMARY KEY (option_id),
        UNIQUE KEY option_id_UNIQUE (option_id),
        KEY fk_options_host1_idx (host_id),
        KEY fk_dhcp4_option_scope (scope_id),
        CONSTRAINT fk_dhcp4_option_scope FOREIGN KEY (scope_id) REFERENCES dhcp_option_scope (scope_id),
        CONSTRAINT fk_dhcp4_options_Host FOREIGN KEY (host_id) REFERENCES hosts (host_id)
            ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT fk_options_host1 FOREIGN KEY (host_id) REFERENCES hosts (host_id)
            ON DELETE NO ACTION ON UPDATE NO ACTION
    ) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS dhcp6_options (
        option_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        code SMALLINT UNSIGNED NOT NULL,
        value BLOB DEFAULT NULL,
        formatted_value TEXT DEFAULT NULL,
        space VARCHAR(128) DEFAULT NULL,
        persistent TINYINT(1) NOT NULL DEFAULT 0,
        dhcp_client_class VARCHAR(128) DEFAULT NULL,
        dhcp6_subnet_id INT UNSIGNED DEFAULT NULL,
        host_id INT UNSIGNED DEFAULT NULL,
        scope_id TINYINT UNSIGNED NOT NULL,
        user_context TEXT DEFAULT NULL,
        shared_network_name VARCHAR(128) DEFAULT NULL,
        pool_id BIGINT UNSIGNED DEFAULT NULL,
        pd_pool_id BIGINT UNSIGNED DEFAULT NULL,
        modification_ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        cancelled TINYINT(1) NOT NULL DEFAULT 0,
        client_classes LONGTEXT NOT NULL,
        PRIMARY KEY (option_id),
        UNIQUE KEY option_id_UNIQUE (option_id),
        KEY fk_options_host1_idx (host_id),
        KEY fk_dhcp6_option_scope (scope_id),
        CONSTRAINT fk_dhcp6_option_scope FOREIGN KEY (scope_id) REFERENCES dhcp_option_scope (scope_id),
        CONSTRAINT fk_dhcp6_options_Host FOREIGN KEY (host_id) REFERENCES hosts (host_id)
            ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT fk_options_host10 FOREIGN KEY (host_id) REFERENCES hosts (host_id)
            ON DELETE NO ACTION ON UPDATE NO ACTION
    ) ENGINE=InnoDB""",
    # v5.0 Phase 1 — lease6, trimmed (Jen only reads it); address BINARY(16) and duid VARBINARY(130) as in Kea.
    """CREATE TABLE IF NOT EXISTS lease6 (
        address BINARY(16) PRIMARY KEY NOT NULL,
        duid VARBINARY(130),
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
    # ipv6_reservations is a real one-to-many junction table off hosts — type 0=IA_NA (address), 2=IA_PD
    # (delegated prefix); prefix_len is 128 for a plain address reservation, less for a delegated prefix.
    # `address` is BINARY(16), as in every real 3.x (Q130).
    """CREATE TABLE IF NOT EXISTS ipv6_reservations (
        reservation_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        address BINARY(16) NOT NULL,
        prefix_len TINYINT UNSIGNED NOT NULL DEFAULT 128,
        type TINYINT UNSIGNED NOT NULL DEFAULT 0,
        dhcp6_iaid INT UNSIGNED DEFAULT NULL,
        host_id INT UNSIGNED NOT NULL,
        excluded_prefix BINARY(16) DEFAULT NULL,
        excluded_prefix_len TINYINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (reservation_id),
        KEY fk_ipv6_reservations_host_idx (host_id),
        KEY key_dhcp6_address_prefix_len (address, prefix_len),
        CONSTRAINT fk_ipv6_reservations_Host FOREIGN KEY (host_id) REFERENCES hosts (host_id)
            ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB""",
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
    extensions.KEA_API_URL = "http://localhost:18000"
    extensions.KEA_API_USER = "test"
    extensions.KEA_API_PASS = "test"
    # v5.10.0 — reset the connection-mode globals too: a test that calls
    # AppConfig.apply() against an isolated config (test_appconfig,
    # test_kea6_config) writes these directly, and 'ca' must be restored
    # for every test that doesn't care.
    extensions.KEA_CONNECTION_MODE = "ca"
    extensions.KEA_API_CA = ""
    extensions.KEA_API_TLS_VERIFY = True
    extensions.KEA_API_CLIENT_CERT = ""
    extensions.KEA_API_CLIENT_KEY = ""
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
    extensions.KEA6_API_URL = "http://localhost:18000"
    extensions.KEA6_API_USER = "test"
    extensions.KEA6_API_PASS = "test"
    extensions.KEA6_DB_HOST = TEST_DB["host"]
    extensions.KEA6_DB_USER = TEST_DB["user"]
    extensions.KEA6_DB_PASS = TEST_DB["password"]
    extensions.KEA6_DB_NAME = "jen_test"
    extensions.SUBNET6_MAP = {}
    extensions.KEA_SERVERS = [
        {
            "id": 1,
            "name": "Test Kea",
            "api_url": "http://localhost:18000",
            "api_user": "test",
            "api_pass": "test",
            # v5.10.3 — mirror what derive_kea_servers() produces; a server's
            # v6 endpoint is read off its own dict now, not the KEA6_* globals.
            "api6_url": "",
            "api6_user": "",
            "api6_pass": "",
            "ssh_host": "",
            "ssh_user": "",
            "ssh_key": "",
            "kea_conf": "",
            "role": "primary",
        }
    ]
    extensions.SUBNET_MAP = {1: {"name": "Test Network", "cidr": "10.99.0.0/24"}}
    extensions.HTTP_PORT = 5099
    extensions.HTTPS_PORT = 8499
    extensions.WORKER_THREADS = 8
    extensions.TRUSTED_PROXIES = []
    extensions.CONFIG_FILE = "/tmp/jen_test.config"

    # v5.13.0 — user-writable content is under CONTENT_DIR now. Repoint the
    # whole subtree at a throwaway tmp dir and BOTH plugin trees at absent
    # paths so the app fixture never pulls the real shipped plugins in and
    # never writes into the checkout.
    _content = "/tmp/jen_test_content"
    extensions.CONTENT_DIR = _content
    extensions.CONTENT_ICONS_DIR = os.path.join(_content, "icons")
    extensions.CONTENT_BRANDING_DIR = os.path.join(_content, "branding")
    extensions.CONTENT_BACKUP_DIR = os.path.join(_content, "backups")
    extensions.CONTENT_PLUGIN_DIR = os.path.join(_content, "plugins")
    extensions.CONTENT_PLUGINS_ENABLED_DIR = os.path.join(_content, "plugins-enabled")
    extensions.CONTENT_PLUGIN_REQUESTS_DIR = os.path.join(_content, "plugin-requests")
    extensions.CONTENT_KEYS_DIR = os.path.join(_content, "keys")
    extensions.ICONS_CUSTOM_DIR = extensions.CONTENT_ICONS_DIR
    extensions.NAV_LOGO_PATH = os.path.join(extensions.CONTENT_BRANDING_DIR, "nav_logo")
    extensions.FAVICON_PATH = os.path.join(extensions.CONTENT_BRANDING_DIR, "favicon.ico")
    extensions.PLUGIN_DIR = extensions.CONTENT_PLUGIN_DIR
    extensions.PLUGIN_DIR_BUNDLED = "/tmp/jen_test_plugins_bundled_absent"
    # v5.27.0 (Q23) — the root-owned tree is real production infra
    # (/opt/jen/plugins-installed); tests must never read/write it.
    extensions.PLUGIN_DIR_ROOT = "/tmp/jen_test_plugins_root_absent"
    try:
        import jen.services.dbexport as _dbe

        _dbe.BACKUP_DIR = extensions.CONTENT_BACKUP_DIR
    except Exception:
        pass
    # v5.4.0 — repoint the MFA-secret encryption key off /etc/jen so the
    # suite works on a dev box where /etc/jen isn't writable (CI creates
    # it, a laptop running pytest may not). Same direct-assignment pattern
    # as CONFIG_FILE above. Drop any cached Fernet bound to a stale path.
    extensions.MFA_KEY_PATH = "/tmp/jen_test_mfa_key"
    try:
        from jen.services.crypto import reset_key_cache

        reset_key_cache()
    except Exception:
        pass

    cfg = configparser.ConfigParser()
    cfg["kea"] = {"api_url": "http://localhost:18000", "api_user": "test", "api_pass": "test"}
    cfg["kea_db"] = {
        "host": TEST_DB["host"],
        "user": TEST_DB["user"],
        "password": TEST_DB["password"],
        "database": "jen_test",
    }
    cfg["jen_db"] = {
        "host": TEST_DB["host"],
        "user": TEST_DB["user"],
        "password": TEST_DB["password"],
        "database": "jen_test",
    }
    cfg["server"] = {"http_port": "5099", "https_port": "8499"}
    cfg["subnets"] = {"1": "Test Network, 10.99.0.0/24"}
    with open("/tmp/jen_test.config", "w") as f:
        cfg.write(f)
    extensions.cfg = cfg


# ── Session-scoped: create schema once ───────────────────────────────────────
@pytest.fixture(scope="session", autouse=True)
def test_database():
    _patch_extensions()
    import jen

    # Fix 1: patch ssl_configured to always return False in tests
    # so redirect_to_https never fires a 301
    import jen.config as jen_config
    from jen.models.db import init_jen_db, reset_pools

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
    flask_app.config.update(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-key-not-for-production",
            "WTF_CSRF_ENABLED": False,
            # Fix 2: no SERVER_NAME — causes 404 on POST routes due to port mismatch
            # Flask test client handles routing without SERVER_NAME set
        }
    )

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
def _not_a_systemd_host(monkeypatch):
    """v5.67.0-beta.6 (Q118) — GitHub Actions' own hosted runner is itself
    a systemd-managed host (the runner agent is a systemd service), and
    INVOCATION_ID is inherited down through every child process it spawns
    — including this very pytest job. jen.services.runtime.deployment()
    correctly reads that as "systemd," which is exactly right for a real
    Jen unit but wrong for a test suite that has always run as a plain
    dev/CI checkout (and still does — JEN_ROOT is set for exactly this).
    Confirmed by a real CI failure the first time this Q's own tests ran:
    install_plugin() routed to the root-privileged service path a
    dev-checkout test never expected. Cleared before every test; a test
    that wants to exercise the real systemd branch sets either var back
    with its own monkeypatch, same as any other fixture override."""
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    monkeypatch.delenv("JEN_SERVICE_MANAGER", raising=False)


@pytest.fixture(autouse=True)
def _reset_capabilities_cache():
    """v5.64.0 (Q83) — jen.services.capabilities caches a server's Kea version
    for 60 s; every test starts (and ends) with none, so one test's mocked
    Kea can never answer for the next."""
    from jen.services import capabilities

    capabilities.invalidate()
    yield
    capabilities.invalidate()


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
        from jen.models.user import _invalidate_settings_cache, hash_password

        cur.execute(
            "UPDATE users SET password=%s, role='superadmin', session_timeout=NULL WHERE username='admin'",
            (hash_password("admin"),),
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
        sess["_user_cache"] = {"id": 1, "username": "admin", "role": "superadmin", "session_timeout": None}
        sess["_user_id"] = "1"
        sess["_fresh"] = True
        sess["last_active"] = now
        sess["auth_at"] = now  # v5.17.0 — recent_auth_required treats this session as freshly authed
    return client


@pytest.fixture
def mock_kea(monkeypatch):
    from jen.services import kea as kea_svc

    monkeypatch.setattr(
        kea_svc,
        "kea_command",
        lambda *a, **kw: {"result": 0, "text": "mocked", "arguments": {"subnet4": [], "Dhcp4": {}, "hosts": []}},
    )
    monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: True)
    monkeypatch.setattr(
        kea_svc,
        "get_active_kea_server",
        lambda: {
            "id": 1,
            "name": "Test Kea",
            "api_url": "http://localhost:18000",
            "api_user": "test",
            "api_pass": "test",
        },
    )
    monkeypatch.setattr(
        kea_svc,
        "get_all_server_status",
        lambda: [
            {
                "server": {"id": 1, "name": "Test Kea"},
                "up": True,
                "ha_state": None,
                "version": "2.4.0",
                "role": "primary",
            }
        ],
    )


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
            (username, hash_password("testpass123"), role, _json.dumps(allowed_subnets)),
        )
        user_id = cur.lastrowid
    db.commit()

    with client.session_transaction() as sess:
        sess["_user_cache"] = {
            "id": user_id,
            "username": username,
            "role": role,
            "session_timeout": None,
            "subnet_access": allowed_subnets,
        }
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True
        _now = datetime.now(timezone.utc).isoformat()
        sess["last_active"] = _now
        sess["auth_at"] = _now
    return client, user_id
