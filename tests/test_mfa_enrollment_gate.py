"""
tests/test_mfa_enrollment_gate.py
─────────────────────────────────
v5.8.0 — when MFA is mandatory but a user hasn't set it up, login used
to call login_user() before redirecting to /mfa/enroll, leaving a fully
authenticated Flask-Login session one navigation away from the whole
app. Login now holds them in a pre-authenticated *pending* state until
they enroll and verify a factor. This is the integration test the
external review asked for: prove nothing else is reachable in between.
"""

import re

import pyotp
import pytest

from jen.models.db import jen_db
from jen.models.user import _invalidate_settings_cache, hash_password, set_global_setting

USERNAME = "_mfa_gate_probe"
PASSWORD = "gatepass123"


@pytest.fixture
def required_all_unenrolled(app):
    set_global_setting("mfa_mode", "required_all")
    _invalidate_settings_cache()
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username=%s", (USERNAME,))
            cur.execute(
                "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, 'admin', 0)",
                (USERNAME, hash_password(PASSWORD)),
            )
            cur.execute("SELECT id FROM users WHERE username=%s", (USERNAME,))
            uid = cur.fetchone()["id"]
            cur.execute("DELETE FROM mfa_methods WHERE user_id=%s", (uid,))
        db.commit()
    yield uid
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_methods WHERE user_id=%s", (uid,))
            cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=%s", (uid,))
            cur.execute("DELETE FROM users WHERE username=%s", (USERNAME,))
        db.commit()
    set_global_setting("mfa_mode", "off")
    _invalidate_settings_cache()


def _login(client):
    return client.post("/login", data={"username": USERNAME, "password": PASSWORD}, follow_redirects=False)


class TestPendingEnrollmentIsNotAuthenticated:
    def test_login_redirects_to_enroll_not_dashboard(self, client, required_all_unenrolled):
        r = _login(client)
        assert r.status_code in (301, 302)
        assert "/mfa/enroll" in r.headers["Location"]

    def test_no_flask_login_session_yet(self, client, required_all_unenrolled):
        _login(client)
        with client.session_transaction() as sess:
            assert "_user_id" not in sess
            assert sess.get("mfa_pending_enroll") is True

    def test_protected_pages_stay_unreachable_after_login(self, client, required_all_unenrolled):
        _login(client)
        for path in ("/", "/leases", "/settings/system", "/users", "/api/stats"):
            r = client.get(path, follow_redirects=False)
            assert r.status_code in (301, 302, 401), f"{path} reachable while enrollment pending ({r.status_code})"
            if r.status_code in (301, 302):
                assert "/login" in r.headers["Location"], f"{path} did not bounce to login"

    def test_enroll_page_is_reachable_for_the_pending_user(self, client, required_all_unenrolled):
        _login(client)
        r = client.get("/mfa/enroll")
        assert r.status_code == 200
        assert b'name="secret"' in r.data

    def test_verify_page_bounces_pending_enroll_user_to_enroll(self, client, required_all_unenrolled):
        _login(client)
        r = client.get("/mfa/verify", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/mfa/enroll" in r.headers["Location"]

    def test_pending_user_cannot_manage_mfa(self, client, required_all_unenrolled):
        _login(client)
        r = client.post("/mfa/enroll", data={"action": "new_backup_codes"}, follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/mfa/enroll" in r.headers["Location"]
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) c FROM mfa_backup_codes WHERE user_id=%s", (required_all_unenrolled,))
                assert cur.fetchone()["c"] == 0


class TestCompletingEnrollmentAuthenticates:
    def test_enroll_then_dashboard_is_reachable(self, client, mock_kea, required_all_unenrolled):
        _login(client)
        page = client.get("/mfa/enroll").data.decode()
        secret = re.search(r'name="secret"\s+value="([A-Z2-7]+)"', page).group(1)
        r = client.post(
            "/mfa/enroll",
            data={"action": "enroll", "secret": secret, "code": pyotp.TOTP(secret).now(), "device_name": "probe"},
            follow_redirects=False,
        )
        assert r.status_code == 200  # backup-codes page
        assert b"backup" in r.data.lower()
        with client.session_transaction() as sess:
            assert "_user_id" in sess
            assert "mfa_pending_enroll" not in sess
        # and now the app is actually reachable
        assert client.get("/", follow_redirects=False).status_code == 200
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) c FROM mfa_methods WHERE user_id=%s AND enabled=1", (required_all_unenrolled,)
                )
                assert cur.fetchone()["c"] == 1

    def test_bad_code_does_not_authenticate(self, client, required_all_unenrolled):
        _login(client)
        page = client.get("/mfa/enroll").data.decode()
        secret = re.search(r'name="secret"\s+value="([A-Z2-7]+)"', page).group(1)
        client.post(
            "/mfa/enroll",
            data={"action": "enroll", "secret": secret, "code": "000000", "device_name": "probe"},
            follow_redirects=False,
        )
        with client.session_transaction() as sess:
            assert "_user_id" not in sess
