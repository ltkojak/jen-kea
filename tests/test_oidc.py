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


class _StubOidcClient:
    """Stands in for the authlib client oidc.oidc_client() would return
    — no network, no real token/state validation (that's authlib's own
    code, not this feature's). `token` is what authorize_access_token()
    returns; set it to an Exception instance to simulate a failed
    exchange."""

    def __init__(self, token=None):
        self.token = token or {"userinfo": {}}
        self.authorize_redirect_calls = []
        self.authorize_redirect_kwargs = []  # v5.28.0 (Q24, D1) — records e.g. prompt="login"
        self.userinfo_called = False

    def authorize_redirect(self, redirect_uri, **kwargs):
        from flask import redirect as flask_redirect

        self.authorize_redirect_calls.append(redirect_uri)
        self.authorize_redirect_kwargs.append(kwargs)
        return flask_redirect("https://idp.example.com/authorize")

    def authorize_access_token(self):
        if isinstance(self.token, Exception):
            raise self.token
        return self.token

    def userinfo(self, token=None):
        self.userinfo_called = True
        return (self.token or {}).get("userinfo", {})


class TestLoginPageSsoUi:
    def test_no_button_when_disabled(self, client):
        r = client.get("/login")
        assert b"Sign in with SSO" not in r.data

    def test_button_shown_when_client_registered(self, client, monkeypatch):
        extensions.OIDC_ENABLED = True
        extensions.OIDC_BUTTON_LABEL = "Sign in with SSO"
        monkeypatch.setattr(oidc, "oidc_client", lambda: _StubOidcClient())
        r = client.get("/login")
        assert b"Sign in with SSO" in r.data

    def test_button_hidden_when_enabled_but_client_not_registered(self, client):
        # A config typo (e.g. issuer missing) can leave OIDC_ENABLED true
        # with no client actually registered — the button must not show
        # a dead link.
        extensions.OIDC_ENABLED = True
        r = client.get("/login")
        assert b"Sign in with SSO" not in r.data

    def test_local_form_hidden_when_local_login_false(self, client):
        extensions.OIDC_LOCAL_LOGIN = False
        r = client.get("/login")
        assert b'name="password"' not in r.data

    def test_local_form_escape_hatch(self, client):
        extensions.OIDC_LOCAL_LOGIN = False
        r = client.get("/login?local=1")
        assert b'name="password"' in r.data

    def test_local_form_shown_by_default(self, client):
        r = client.get("/login")
        assert b'name="password"' in r.data


class TestLoginOidcRedirect:
    def test_redirects_to_authorize_when_configured(self, client, monkeypatch):
        stub = _StubOidcClient()
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        r = client.get("/login/oidc", follow_redirects=False)
        assert r.status_code == 302
        assert stub.authorize_redirect_calls

    def test_flashes_and_redirects_when_not_configured(self, client):
        r = client.get("/login/oidc", follow_redirects=True)
        assert r.status_code == 200
        assert b"not configured" in r.data.lower()

    def test_next_is_stashed_in_session_when_safe(self, client, monkeypatch):
        monkeypatch.setattr(oidc, "oidc_client", lambda: _StubOidcClient())
        client.get("/login/oidc?next=/subnets")
        with client.session_transaction() as sess:
            assert sess.get("oidc_next") == "/subnets"

    def test_unsafe_next_is_dropped(self, client, monkeypatch):
        monkeypatch.setattr(oidc, "oidc_client", lambda: _StubOidcClient())
        client.get("/login/oidc?next=https://evil.example.com/")
        with client.session_transaction() as sess:
            assert sess.get("oidc_next") == ""


class TestOidcCallback:
    def _claims_token(self, **claims):
        base = {"sub": "idp-subject-1", "preferred_username": "ssouser1", "groups": ["jen-admin"]}
        base.update(claims)
        return {"userinfo": base}

    def test_first_login_creates_user_with_random_unusable_password(self, client, db, monkeypatch):
        stub = _StubOidcClient(token=self._claims_token())
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)

        r = client.get("/login/oidc/callback", follow_redirects=True)
        assert r.status_code == 200

        with db.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username='ssouser1'")
            row = cur.fetchone()
        assert row is not None
        assert row["auth_provider"] == "oidc"
        assert row["external_id"] == "idp-subject-1"
        assert row["role"] == "admin"
        assert row["must_change_password"] == 0

        # The random password is unusable for local login — see
        # TestLocalLoginRefusedForOidcUser for the generic-refusal check;
        # here we only need the account to actually BE oidc-provider'd,
        # which the row assertions above already confirm.

    def test_second_login_updates_role_on_change(self, client, db, monkeypatch):
        stub = _StubOidcClient(token=self._claims_token())
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        client.get("/login/oidc/callback")

        stub.token = self._claims_token(groups=["jen-superadmin"])
        client.get("/login/oidc/callback")

        with db.cursor() as cur:
            cur.execute("SELECT role FROM users WHERE username='ssouser1'")
            row = cur.fetchone()
        assert row["role"] == "superadmin"

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM audit_log WHERE action='oidc_role_change'")
            assert cur.fetchone()["cnt"] == 1

    def test_username_collision_with_local_account_is_refused(self, client, db, monkeypatch):
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES ('ssouser1', %s, 'viewer')",
                (hash_password("localpass123"),),
            )
        db.commit()

        stub = _StubOidcClient(token=self._claims_token())
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        r = client.get("/login/oidc/callback", follow_redirects=True)
        assert r.status_code == 200
        assert b"already exists" in r.data

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE username='ssouser1'")
            assert cur.fetchone()["cnt"] == 1  # no duplicate created
            cur.execute("SELECT auth_provider FROM users WHERE username='ssouser1'")
            assert cur.fetchone()["auth_provider"] == "local"

    def test_no_role_mapped_is_refused(self, client, monkeypatch):
        extensions.OIDC_DEFAULT_ROLE = "none"
        stub = _StubOidcClient(token=self._claims_token(groups=["some-other-group"]))
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        r = client.get("/login/oidc/callback", follow_redirects=True)
        assert r.status_code == 200
        assert b"no role mapped" in r.data.lower()

    def test_token_exchange_failure_flashes_generic_message(self, client, monkeypatch):
        stub = _StubOidcClient(token=RuntimeError("boom"))
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        r = client.get("/login/oidc/callback", follow_redirects=True)
        assert r.status_code == 200
        assert b"boom" not in r.data
        assert b"sso failed" in r.data.lower() or b"try again" in r.data.lower()

    def test_locked_out_ip_refused_before_token_exchange(self, client, monkeypatch):
        from jen.services import auth as auth_svc

        monkeypatch.setattr(auth_svc, "is_locked_out", lambda ip, username: (True, 5))
        stub = _StubOidcClient(token=self._claims_token())
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        r = client.get("/login/oidc/callback", follow_redirects=True)
        assert r.status_code == 200
        assert not stub.userinfo_called
        # authorize_access_token itself must never have been reached —
        # simplest proof is that no user was created.

    def test_successful_callback_establishes_real_session(self, client, monkeypatch):
        stub = _StubOidcClient(token=self._claims_token())
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        client.get("/login/oidc/callback")
        with client.session_transaction() as sess:
            assert sess.get("_user_cache", {}).get("username") == "ssouser1"
            assert sess.get("_user_cache", {}).get("role") == "admin"
            assert "last_active" in sess
            assert "auth_at" in sess

    def test_mfa_not_triggered_even_when_globally_required(self, client, monkeypatch):
        from jen.models.user import set_global_setting

        set_global_setting("mfa_mode", "required_all")
        stub = _StubOidcClient(token=self._claims_token())
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        client.get("/login/oidc/callback")
        with client.session_transaction() as sess:
            assert "mfa_pending_user_id" not in sess
            assert sess.get("_user_cache", {}).get("username") == "ssouser1"

    def test_next_roundtrip(self, client, monkeypatch):
        stub = _StubOidcClient(token=self._claims_token())
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        with client.session_transaction() as sess:
            sess["oidc_next"] = "/subnets"
        r = client.get("/login/oidc/callback", follow_redirects=False)
        assert r.headers["Location"].endswith("/subnets")

    def test_userinfo_endpoint_used_when_username_and_role_claims_absent(self, client, monkeypatch):
        # token["userinfo"] present but carrying neither username_claim
        # nor role_claim (a minimal id_token, say) -> the fallback to
        # client.userinfo() must fire, and its return value is what
        # actually gets used to find/create the user.
        real_claims = self._claims_token(sub="idp-subject-2", preferred_username="ssouser2")["userinfo"]
        stub = _StubOidcClient(token={"userinfo": {"sub": "idp-subject-2"}})

        def _userinfo(token=None):
            stub.userinfo_called = True
            return real_claims

        stub.userinfo = _userinfo
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        client.get("/login/oidc/callback")
        assert stub.userinfo_called


class TestLocalLoginRefusedForOidcUser:
    def test_local_login_generic_message_for_oidc_user(self, client, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role, auth_provider, external_id) "
                "VALUES ('ssolocal1', 'scrypt:unusable', 'admin', 'oidc', 'sub-xyz')"
            )
        db.commit()
        r = client.post("/login", data={"username": "ssolocal1", "password": "whatever"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"Invalid username or password" in r.data

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM login_attempts WHERE username='ssolocal1'")
            assert cur.fetchone()["cnt"] == 1


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


@pytest.fixture
def isolated_oidc_settings_config(tmp_path):
    """Point AppConfig at a throwaway jen.config so save-oidc route POSTs
    write there, not the real file — same pattern as
    tests/test_kea6_settings_save.py's isolated_config."""
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
    app_config.reload()
    yield path
    extensions.CONFIG_FILE = original_path
    from tests.conftest import _patch_extensions

    _patch_extensions()


def _on_disk(path):
    p = configparser.ConfigParser()
    p.read(str(path))
    return p


class TestOidcSettingsRoute:
    _SAVE_URL = "/settings/save-oidc"

    def _post(self, client, **fields):
        base = {
            "issuer": "https://idp.example.com",
            "client_id": "jen",
            "scopes": "openid profile email",
            "username_claim": "preferred_username",
            "role_claim": "groups",
            "role_map": "superadmin=jen-superadmin;admin=jen-admin;viewer=jen-viewer",
            "default_role": "viewer",
        }
        base.update(fields)
        return client.post(self._SAVE_URL, data=base, follow_redirects=True)

    def test_save_persists_to_disk(self, logged_in_client, isolated_oidc_settings_config):
        r = self._post(logged_in_client, enabled="1", client_secret="s3cret", auto_create="1", local_login="1")
        assert r.status_code == 200
        on_disk = _on_disk(isolated_oidc_settings_config)
        assert on_disk.get("oidc", "enabled") == "true"
        assert on_disk.get("oidc", "issuer") == "https://idp.example.com"
        assert on_disk.get("oidc", "client_secret") == "s3cret"
        assert extensions.OIDC_ENABLED is True

    def test_blank_client_secret_keeps_existing_value(self, logged_in_client, isolated_oidc_settings_config):
        self._post(logged_in_client, enabled="1", client_secret="s3cret")
        self._post(logged_in_client, enabled="1", client_secret="")
        on_disk = _on_disk(isolated_oidc_settings_config)
        assert on_disk.get("oidc", "client_secret") == "s3cret"

    def test_client_secret_never_appears_in_a_get_response(self, logged_in_client, isolated_oidc_settings_config):
        self._post(logged_in_client, enabled="1", client_secret="s3cretvalue12345")
        r = logged_in_client.get("/settings/security")
        assert r.status_code == 200
        assert b"s3cretvalue12345" not in r.data

    def test_enabling_without_https_issuer_is_refused(self, logged_in_client, isolated_oidc_settings_config):
        r = self._post(logged_in_client, enabled="1", issuer="http://idp.example.com")
        assert r.status_code == 200
        assert b"https" in r.data.lower()
        assert not _on_disk(isolated_oidc_settings_config).has_section("oidc")

    def test_localhost_http_issuer_is_allowed(self, logged_in_client, isolated_oidc_settings_config):
        r = self._post(logged_in_client, enabled="1", issuer="http://localhost:9000")
        assert r.status_code == 200
        assert _on_disk(isolated_oidc_settings_config).get("oidc", "issuer") == "http://localhost:9000"

    def test_enabling_without_client_id_is_refused(self, logged_in_client, isolated_oidc_settings_config):
        r = self._post(logged_in_client, enabled="1", client_id="")
        assert r.status_code == 200
        assert b"client id" in r.data.lower()

    def test_malformed_role_map_is_refused(self, logged_in_client, isolated_oidc_settings_config):
        r = self._post(logged_in_client, role_map="garbage-with-no-equals-sign")
        assert r.status_code == 200
        assert b"could not be parsed" in r.data.lower()

    def test_blank_role_map_is_allowed(self, logged_in_client, isolated_oidc_settings_config):
        r = self._post(logged_in_client, role_map="")
        assert r.status_code == 200
        assert _on_disk(isolated_oidc_settings_config).get("oidc", "role_map") == ""

    def test_requires_superadmin(self, client, db, isolated_oidc_settings_config):
        from tests.conftest import restricted_client as _restricted_client

        c, _ = _restricted_client(client, db, allowed_subnets=None, role="admin", username="oidc_settings_admin1")
        r = self._post(c, enabled="1")
        assert r.status_code == 200
        assert b"SuperAdmin access required." in r.data
        assert not _on_disk(isolated_oidc_settings_config).has_section("oidc")
