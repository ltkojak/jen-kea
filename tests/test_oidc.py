"""
tests/test_oidc.py
───────────────────
v5.25.0 (Q21) — OpenID Connect single sign-on: config parsing,
map_role()'s matching matrix, the users.auth_provider/external_id
migration, and lazy client registration. The callback/route/session
flow (find_or_create_user, establish_session, the actual login/callback
routes, the settings card, the Users page badge) is covered once those
land — see this file's later classes as the feature grows across steps.

No network anywhere in this file.
"""

import configparser

import pytest

from jen import extensions
from jen.models.migrations import applied_versions
from jen.services import oidc

_OIDC_DEFAULTS = {
    "OIDC_ENABLED": False,
    "OIDC_ISSUER": "",
    "OIDC_CLIENT_ID": "",
    "OIDC_CLIENT_SECRET": "",
    "OIDC_SCOPES": "openid profile email",
    "OIDC_USERNAME_CLAIM": "preferred_username",
    "OIDC_ROLE_CLAIM": "groups",
    "OIDC_ROLE_MAP": "superadmin=jen-superadmin;admin=jen-admin;viewer=jen-viewer",
    "OIDC_DEFAULT_ROLE": "viewer",
    "OIDC_AUTO_CREATE": True,
    "OIDC_BUTTON_LABEL": "Sign in with SSO",
    "OIDC_REDIRECT_URI": "",
    "OIDC_LOCAL_LOGIN": True,
}


def _reset_oidc_extensions():
    for key, value in _OIDC_DEFAULTS.items():
        setattr(extensions, key, value)


@pytest.fixture(autouse=True)
def _oidc_extension_isolation():
    """Every test in this file either reads or mutates the module-level
    OIDC_* extensions globals directly — reset before and after so tests
    can't leak state into each other or into unrelated test files."""
    _reset_oidc_extensions()
    yield
    _reset_oidc_extensions()


class TestParseRoleMap:
    def test_basic_pairs(self):
        assert oidc.parse_role_map("superadmin=g1;admin=g2;viewer=g3") == {
            "superadmin": ["g1"],
            "admin": ["g2"],
            "viewer": ["g3"],
        }

    def test_comma_list_on_one_role(self):
        assert oidc.parse_role_map("admin=g1,g2, g3") == {"admin": ["g1", "g2", "g3"]}

    def test_blank_is_empty(self):
        assert oidc.parse_role_map("") == {}
        assert oidc.parse_role_map(None) == {}

    def test_malformed_segments_skipped_not_raised(self):
        # no '=', unknown role name, empty value list — none of these
        # may raise; a config typo must not turn login into a 500.
        assert oidc.parse_role_map("garbage;unknownrole=x;admin=") == {}

    def test_whitespace_tolerant(self):
        assert oidc.parse_role_map(" superadmin = g1 ; admin = g2 ") == {
            "superadmin": ["g1"],
            "admin": ["g2"],
        }


class TestMapRole:
    def test_list_claim_single_match(self):
        assert oidc.map_role({"groups": ["jen-admin"]}) == "admin"

    def test_list_claim_multiple_groups_returns_highest(self):
        assert oidc.map_role({"groups": ["jen-viewer", "jen-superadmin", "jen-admin"]}) == "superadmin"

    def test_string_claim_space_separated(self):
        assert oidc.map_role({"groups": "jen-viewer jen-admin"}) == "admin"

    def test_no_match_falls_back_to_default_role(self):
        extensions.OIDC_DEFAULT_ROLE = "viewer"
        assert oidc.map_role({"groups": ["nothing-mapped"]}) == "viewer"

    def test_default_role_none_denies(self):
        extensions.OIDC_DEFAULT_ROLE = "none"
        assert oidc.map_role({"groups": ["nothing-mapped"]}) is None

    def test_missing_claim_entirely_uses_default(self):
        extensions.OIDC_DEFAULT_ROLE = "admin"
        assert oidc.map_role({}) == "admin"

    def test_custom_role_claim_name(self):
        extensions.OIDC_ROLE_CLAIM = "roles"
        assert oidc.map_role({"roles": ["jen-superadmin"]}) == "superadmin"

    def test_custom_role_map(self):
        extensions.OIDC_ROLE_MAP = "admin=engineering"
        extensions.OIDC_DEFAULT_ROLE = "none"
        assert oidc.map_role({"groups": ["engineering"]}) == "admin"
        # "jen-admin" isn't in this custom map at all, and default_role is
        # "none" — an unmapped group must deny, not fall through to a
        # stale default from the built-in role_map.
        assert oidc.map_role({"groups": ["jen-admin"]}) is None


class TestConfigParsing:
    """AppConfig.apply() against an isolated [oidc] section — same
    fixture shape as tests/test_appconfig.py's isolated_config."""

    @pytest.fixture
    def isolated_oidc_config(self, tmp_path):
        from jen.config import app_config

        original_path = extensions.CONFIG_FILE
        cfg = configparser.ConfigParser()
        cfg["kea"] = {"api_url": "http://1.2.3.4:8000", "api_user": "u1", "api_pass": "p1"}
        cfg["kea_db"] = {"host": "dbhost", "user": "du", "password": "dp", "database": "kea"}
        cfg["jen_db"] = {"host": "dbhost", "user": "ju", "password": "jp", "database": "jen"}
        cfg["server"] = {"http_port": "5050", "https_port": "8443"}
        cfg["oidc"] = {
            "enabled": "true",
            "issuer": "https://idp.example.com",
            "client_id": "jen",
            "client_secret": "s3cret",
            "role_map": "superadmin=g-super;admin=g-admin",
            "default_role": "none",
            "auto_create": "false",
            "local_login": "false",
        }
        path = tmp_path / "jen.config"
        with open(path, "w") as f:
            cfg.write(f)
        extensions.CONFIG_FILE = str(path)
        app_config.reload()
        yield path
        extensions.CONFIG_FILE = original_path
        from tests.conftest import _patch_extensions

        _patch_extensions()

    def test_enabled_section_derives_all_fields(self, isolated_oidc_config):
        assert extensions.OIDC_ENABLED is True
        assert extensions.OIDC_ISSUER == "https://idp.example.com"
        assert extensions.OIDC_CLIENT_ID == "jen"
        assert extensions.OIDC_CLIENT_SECRET == "s3cret"
        assert extensions.OIDC_ROLE_MAP == "superadmin=g-super;admin=g-admin"
        assert extensions.OIDC_DEFAULT_ROLE == "none"
        assert extensions.OIDC_AUTO_CREATE is False
        assert extensions.OIDC_LOCAL_LOGIN is False

    def test_no_oidc_section_defaults_to_disabled(self, tmp_path):
        from jen.config import app_config

        original_path = extensions.CONFIG_FILE
        cfg = configparser.ConfigParser()
        cfg["kea"] = {"api_url": "http://1.2.3.4:8000", "api_user": "u1", "api_pass": "p1"}
        cfg["kea_db"] = {"host": "dbhost", "user": "du", "password": "dp", "database": "kea"}
        cfg["jen_db"] = {"host": "dbhost", "user": "ju", "password": "jp", "database": "jen"}
        cfg["server"] = {"http_port": "5050", "https_port": "8443"}
        path = tmp_path / "jen.config"
        with open(path, "w") as f:
            cfg.write(f)
        extensions.CONFIG_FILE = str(path)
        try:
            app_config.reload()
            assert extensions.OIDC_ENABLED is False
            assert extensions.OIDC_LOCAL_LOGIN is True
            assert extensions.OIDC_AUTO_CREATE is True
            assert extensions.OIDC_DEFAULT_ROLE == "viewer"
        finally:
            extensions.CONFIG_FILE = original_path
            from tests.conftest import _patch_extensions

            _patch_extensions()


class TestLazyRegistration:
    """The pinned Gotcha: create_app() (and therefore init_oidc(), the
    function it calls) must never make a network request during
    registration — the discovery document is fetched lazily, on the
    first actual login attempt, not at startup."""

    def test_init_oidc_enabled_makes_no_network_call(self, monkeypatch):
        import requests
        from flask import Flask

        def _boom(*_a, **_kw):
            raise AssertionError("init_oidc() made a network call during registration")

        monkeypatch.setattr(requests.sessions.Session, "request", _boom)

        extensions.OIDC_ENABLED = True
        extensions.OIDC_ISSUER = "https://idp.example.com"
        extensions.OIDC_CLIENT_ID = "jen"
        extensions.OIDC_CLIENT_SECRET = "s3cret"

        app = Flask(__name__)
        app.secret_key = "test"
        oidc.init_oidc(app)
        assert oidc.oidc_client() is not None

    def test_init_oidc_disabled_registers_no_client(self):
        from flask import Flask

        extensions.OIDC_ENABLED = False
        app = Flask(__name__)
        app.secret_key = "test"
        oidc.init_oidc(app)
        assert oidc.oidc_client() is None


class TestMigration22UserColumns:
    def test_migration_recorded(self):
        assert 22 in applied_versions()

    def test_columns_present_with_expected_defaults(self):
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM users LIKE 'auth_provider'")
            auth_provider = cur.fetchone()
            cur.execute("SHOW COLUMNS FROM users LIKE 'external_id'")
            external_id = cur.fetchone()
        assert "varchar" in auth_provider["Type"].lower()
        assert auth_provider["Default"] == "local"
        assert auth_provider["Null"] == "NO"
        assert "varchar" in external_id["Type"].lower()
        assert external_id["Null"] == "YES"

    def test_unique_key_present(self):
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW INDEX FROM users WHERE Key_name = 'uq_users_provider_ext'")
            rows = cur.fetchall()
        cols = {r["Column_name"] for r in rows}
        assert cols == {"auth_provider", "external_id"}

    def test_rerun_is_idempotent(self):
        from jen.models.db import jen_db
        from jen.models.migrations import _m022_users_oidc_columns

        with jen_db() as db:
            _m022_users_oidc_columns(db)  # must not raise on a second run

    def test_existing_users_default_to_local_with_no_external_id(self):
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT auth_provider, external_id FROM users WHERE username='admin'")
            row = cur.fetchone()
        assert row["auth_provider"] == "local"
        assert row["external_id"] is None
