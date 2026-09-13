"""
tests/test_mfa_stepup.py
────────────────────────
v5.17.0 (Q6 6A) — the MFA-management routes require recent auth
(`session["auth_at"]` within 10 minutes). A stale or missing stamp
bounces the user through `GET /auth/reauth`, which re-verifies the
password (and a code, if the user has MFA) before letting the action
through and stamping a fresh `auth_at`.
"""

from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from jen.models.db import jen_db


def _stale(client, minutes=11):
    with client.session_transaction() as sess:
        sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def _backup_code_count():
    with jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS c FROM mfa_backup_codes WHERE user_id=1")
        return cur.fetchone()["c"]


@pytest.fixture
def admin_totp():
    """A TOTP method for the admin (user 1). Raw secret, like the app's
    pre-5.4 rows — decrypt_secret passes a non-`v1:` blob straight
    through."""
    secret = pyotp.random_base32()
    with jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM mfa_methods WHERE name='_stepup_probe'")
        cur.execute(
            "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) "
            "VALUES (1, 'totp', %s, '_stepup_probe', 1)",
            (secret,),
        )
    yield secret
    with jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM mfa_methods WHERE name='_stepup_probe'")
        cur.execute("DELETE FROM login_attempts WHERE username='admin'")


class TestFreshSessionPassesThrough:
    def test_fresh_login_reaches_the_enroll_page(self, logged_in_client):
        r = logged_in_client.get("/mfa/enroll")
        assert r.status_code == 200
        assert b"secret" in r.data  # the enrollment form rendered


class TestStaleSessionIsBounced:
    def test_get_enroll_redirects_to_reauth(self, logged_in_client):
        _stale(logged_in_client)
        r = logged_in_client.get("/mfa/enroll", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/auth/reauth" in r.headers["Location"]

    def test_regenerate_backup_codes_does_nothing_while_stale(self, logged_in_client):
        before = _backup_code_count()
        _stale(logged_in_client)
        r = logged_in_client.post("/mfa/regenerate-backup-codes", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/auth/reauth" in r.headers["Location"]
        assert _backup_code_count() == before  # not regenerated

    def test_reauth_next_is_remembered_for_a_post_route(self, logged_in_client):
        _stale(logged_in_client)
        logged_in_client.post(
            "/mfa/regenerate-backup-codes",
            headers={"Referer": "http://localhost/mfa/enroll"},
        )
        with logged_in_client.session_transaction() as sess:
            assert sess.get("reauth_next") == "/mfa/enroll"


class TestReauth:
    def test_wrong_password_fails_and_records_an_attempt(self, logged_in_client, db):
        _stale(logged_in_client)
        logged_in_client.get("/mfa/enroll")  # sets reauth_next
        r = logged_in_client.post("/auth/reauth", data={"password": "nope"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"Confirmation failed" in r.data
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM login_attempts WHERE username='admin'")
            assert cur.fetchone()["c"] >= 1
        # auth_at was NOT refreshed — the gated route still bounces
        assert "/auth/reauth" in logged_in_client.get("/mfa/enroll").headers.get("Location", "")

    def test_correct_password_no_mfa_returns_to_the_stored_page_and_unlocks(self, logged_in_client):
        _stale(logged_in_client)
        logged_in_client.get("/mfa/enroll")
        with logged_in_client.session_transaction() as sess:
            sess["reauth_next"] = "/mfa/trusted-devices"
        r = logged_in_client.post("/auth/reauth", data={"password": "admin"}, follow_redirects=False)
        assert r.status_code in (301, 302)
        assert r.headers["Location"].endswith("/mfa/trusted-devices")
        # the gated route now works
        assert logged_in_client.get("/mfa/trusted-devices").status_code == 200

    def test_correct_password_but_missing_code_fails_when_mfa_enrolled(self, logged_in_client, admin_totp):
        _stale(logged_in_client)
        logged_in_client.get("/mfa/enroll")
        r = logged_in_client.post("/auth/reauth", data={"password": "admin"}, follow_redirects=True)
        assert b"Confirmation failed" in r.data

    def test_correct_password_and_totp_unlocks(self, logged_in_client, admin_totp):
        _stale(logged_in_client)
        logged_in_client.get("/mfa/enroll")
        with logged_in_client.session_transaction() as sess:
            sess["reauth_next"] = "/mfa/enroll"
        code = pyotp.TOTP(admin_totp).now()
        r = logged_in_client.post("/auth/reauth", data={"password": "admin", "code": code}, follow_redirects=False)
        assert r.status_code in (301, 302)
        assert logged_in_client.get("/mfa/enroll").status_code == 200


class TestOidcStepUp:
    """v5.28.0 (Q24, D1) — an OIDC-managed account has no usable local
    password (find_or_create_user sets a discarded random one), so
    recent_auth_required must send it through a fresh SSO round trip
    (auth.reauth_oidc) instead of reauth()'s password/MFA form."""

    def _claims_token(self, **claims):
        base = {"sub": "idp-subject-stepup1", "preferred_username": "ssostepup1", "groups": ["jen-admin"]}
        base.update(claims)
        return {"userinfo": base}

    def _login_via_oidc(self, client, monkeypatch, **claims):
        from jen.services import oidc
        from tests.test_oidc import _StubOidcClient

        stub = _StubOidcClient(token=self._claims_token(**claims))
        monkeypatch.setattr(oidc, "oidc_client", lambda: stub)
        client.get("/login/oidc/callback")
        return stub

    def test_stale_session_redirects_to_reauth_oidc_not_the_password_form(self, client, db, monkeypatch):
        self._login_via_oidc(client, monkeypatch)
        _stale(client)
        r = client.get("/mfa/trusted-devices", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/auth/reauth/oidc" in r.headers["Location"]

        r2 = client.get("/auth/reauth", follow_redirects=False)
        assert r2.status_code in (301, 302)
        assert "/auth/reauth/oidc" in r2.headers["Location"]

    def test_reauth_oidc_kicks_off_a_fresh_authorize_redirect_with_prompt_login(self, client, db, monkeypatch):
        stub = self._login_via_oidc(client, monkeypatch)
        _stale(client)
        client.get("/mfa/trusted-devices")  # sets reauth_next
        r = client.get("/auth/reauth/oidc", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert stub.authorize_redirect_kwargs[-1].get("prompt") == "login"
        with client.session_transaction() as sess:
            assert sess.get("oidc_reauth_pending") is True

    def test_matching_sub_confirms_identity_and_returns_to_reauth_next(self, client, db, monkeypatch):
        stub = self._login_via_oidc(client, monkeypatch)
        _stale(client)
        client.get("/mfa/trusted-devices")
        client.get("/auth/reauth/oidc")

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM users WHERE username='ssostepup1'")
            before = cur.fetchone()["c"]

        stub.token = self._claims_token()  # same sub as the original login
        r = client.get("/login/oidc/callback", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert r.headers["Location"].endswith("/mfa/trusted-devices")

        with client.session_transaction() as sess:
            assert "oidc_reauth_pending" not in sess
        assert client.get("/mfa/trusted-devices").status_code == 200  # no longer bounced

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM users WHERE username='ssostepup1'")
            assert cur.fetchone()["c"] == before  # no new row created
            cur.execute("SELECT role FROM users WHERE username='ssostepup1'")
            assert cur.fetchone()["role"] == "admin"  # unchanged

    def test_mismatched_sub_is_refused_and_recorded(self, client, db, monkeypatch):
        stub = self._login_via_oidc(client, monkeypatch)
        _stale(client)
        client.get("/mfa/trusted-devices")
        client.get("/auth/reauth/oidc")

        with client.session_transaction() as sess:
            stale_auth_at = sess["auth_at"]

        stub.token = self._claims_token(sub="a-different-subject")
        r = client.get("/login/oidc/callback", follow_redirects=True)
        assert r.status_code == 200
        assert b"match the account" in r.data

        with client.session_transaction() as sess:
            assert sess["auth_at"] == stale_auth_at  # not refreshed
        assert "/auth/reauth" in client.get("/mfa/trusted-devices", follow_redirects=False).headers["Location"]

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM login_attempts WHERE username='oidc'")
            assert cur.fetchone()["c"] >= 1


class TestForcedEnrollmentUnaffected:
    """A user in the password-verified-but-not-a-session forced-enrollment
    state must still reach /mfa/enroll — recent_auth_required is a no-op
    when there's no Flask-Login session."""

    def test_pending_enroll_user_reaches_enroll(self, client, db):
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username='_stepup_forced'")
            cur.execute(
                "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, 'admin', 0)",
                ("_stepup_forced", hash_password("forcedpass123")),
            )
            cur.execute(
                "INSERT INTO settings (setting_key, setting_value) VALUES ('mfa_mode', 'required_all') "
                "ON DUPLICATE KEY UPDATE setting_value='required_all'"
            )
        db.commit()
        from jen.models.user import _invalidate_settings_cache

        _invalidate_settings_cache()
        try:
            r = client.post(
                "/login",
                data={"username": "_stepup_forced", "password": "forcedpass123"},
                follow_redirects=False,
            )
            assert "/mfa/enroll" in r.headers["Location"]
            assert client.get("/mfa/enroll").status_code == 200
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username='_stepup_forced'")
                cur.execute("DELETE FROM settings WHERE setting_key='mfa_mode'")
            db.commit()
            _invalidate_settings_cache()
