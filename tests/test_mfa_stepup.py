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
