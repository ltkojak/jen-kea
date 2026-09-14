"""
tests/test_passkey_login.py
───────────────────────────
v5.31.0 (Q31) — a passkey as the second factor at login (/mfa/verify's
Passkey tab → /mfa/passkey/login/{begin,finish}) and as the stand-in for
a code on /auth/reauth (step-up). py_webauthn's verifier is faked at
its boundary; what's tested is Jen's gating and session handling: the
pre-login pending state, lockout, single-use challenge, session
rotation, "remember this device", audit rows, and the reauth window.
"""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from jen.models.db import jen_db
from jen.models.user import hash_password
from jen.services import passkeys

USERNAME = "_passkey_login_probe"
PASSWORD = "loginpass123"
CRED_B64 = "Y3JlZC1s"  # base64url(b"cred-l")


def _fake_auth(new_sign_count=1, ok=True):
    def fake(**kwargs):
        if not ok:
            from webauthn.helpers.exceptions import InvalidAuthenticationResponse

            raise InvalidAuthenticationResponse("signature invalid (internal)")
        return SimpleNamespace(new_sign_count=new_sign_count, user_verified=True)

    return fake


def _seed_passkey(user_id, sign_count=0):
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, name) "
                "VALUES (%s, %s, 'cGs', %s, 'Probe passkey')",
                (user_id, CRED_B64, sign_count),
            )
        db.commit()


@pytest.fixture
def passkey_user(app):
    """A local user whose only second factor is a passkey."""
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username=%s", (USERNAME,))
            cur.execute(
                "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, 'admin', 0)",
                (USERNAME, hash_password(PASSWORD)),
            )
            cur.execute("SELECT id FROM users WHERE username=%s", (USERNAME,))
            uid = cur.fetchone()["id"]
        db.commit()
    _seed_passkey(uid, sign_count=3)
    yield uid
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username=%s", (USERNAME,))  # FKs cascade
            cur.execute("DELETE FROM audit_log WHERE username=%s OR details LIKE %s", (USERNAME, f"{USERNAME}%"))
        db.commit()


def _login(client):
    return client.post("/login", data={"username": USERNAME, "password": PASSWORD}, follow_redirects=False)


def _begin(client):
    return client.post("/mfa/passkey/login/begin")


def _finish(client, remember=None, days="30", cred=CRED_B64):
    body = {"response": {"id": cred, "rawId": cred, "response": {}}}
    if remember:
        body["remember_device"] = "1"
        body["remember_days"] = days
    return client.post("/mfa/passkey/login/finish", data=json.dumps(body), content_type="application/json")


class TestChallengePage:
    def test_login_lands_on_the_passkey_tab(self, client, passkey_user):
        r = _login(client)
        assert r.status_code in (301, 302) and "/mfa/verify" in r.headers["Location"]
        page = client.get("/mfa/verify").data.decode()
        assert 'data-tab="passkey"' in page
        assert "Use passkey" in page
        assert "/mfa/passkey/login/begin" in page
        # No TOTP enrolled → no Authenticator tab; backup codes stay offered.
        assert 'data-tab="totp"' not in page
        assert 'data-tab="backup"' in page

    def test_totp_only_user_sees_no_passkey_tab(self, client, db):
        page = None
        with jen_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username='_totp_only_probe'")
                cur.execute(
                    "INSERT INTO users (username, password, role, must_change_password) "
                    "VALUES ('_totp_only_probe', %s, 'viewer', 0)",
                    (hash_password("x" * 12),),
                )
                cur.execute("SELECT id FROM users WHERE username='_totp_only_probe'")
                uid = cur.fetchone()["id"]
                cur.execute(
                    "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) VALUES (%s, 'totp', 'x', 'p', 1)",
                    (uid,),
                )
            conn.commit()
        try:
            with client.session_transaction() as sess:
                sess["mfa_pending_user_id"] = uid
                sess["mfa_pending_username"] = "_totp_only_probe"
            page = client.get("/mfa/verify").data.decode()
        finally:
            with jen_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM users WHERE username='_totp_only_probe'")
                conn.commit()
        assert 'data-tab="totp"' in page
        assert 'data-tab="passkey"' not in page


class TestLoginCeremony:
    def test_begin_without_a_pending_login_is_refused(self, client):
        r = _begin(client)
        assert r.status_code == 401

    def test_begin_lists_the_credential_and_parks_state(self, client, passkey_user):
        _login(client)
        r = _begin(client)
        assert r.status_code == 200, r.data
        options = json.loads(r.get_json()["options"])
        assert options["rpId"] == "localhost"
        assert [c["id"] for c in options["allowCredentials"]] == [CRED_B64]
        with client.session_transaction() as sess:
            assert sess["passkey_auth"]["user_id"] == passkey_user
            assert "_user_id" not in sess  # still not logged in

    def test_finish_signs_the_user_in(self, client, passkey_user, monkeypatch, db):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_authentication_response", _fake_auth(4))
        _login(client)
        _begin(client)
        r = _finish(client)
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body["ok"] is True and body["next"] == "/"
        assert "jen_trusted" not in " ".join(r.headers.getlist("Set-Cookie"))
        with client.session_transaction() as sess:
            assert sess.get("_user_id") == str(passkey_user)
            assert "mfa_pending_user_id" not in sess
            assert "passkey_auth" not in sess
            assert sess.get("auth_at")
        assert client.get("/", follow_redirects=False).status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT sign_count, last_used FROM webauthn_credentials WHERE user_id=%s", (passkey_user,))
            row = cur.fetchone()
            assert row["sign_count"] == 4 and row["last_used"] is not None
            cur.execute("SELECT COUNT(*) c FROM audit_log WHERE action='PASSKEY_VERIFY' AND details=%s", (USERNAME,))
            assert cur.fetchone()["c"] == 1

    def test_finish_honours_remember_device(self, client, passkey_user, monkeypatch, db):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_authentication_response", _fake_auth(4))
        _login(client)
        _begin(client)
        r = _finish(client, remember=True, days="60")
        assert r.status_code == 200, r.data
        cookie = " ".join(c for c in r.headers.getlist("Set-Cookie") if c.startswith("jen_trusted="))
        assert "jen_trusted=" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM mfa_trusted_devices WHERE user_id=%s", (passkey_user,))
            assert cur.fetchone()["c"] == 1
            cur.execute(
                "SELECT details FROM audit_log WHERE action='PASSKEY_VERIFY' AND details LIKE %s", (f"{USERNAME}%",)
            )
            assert cur.fetchone()["details"] == f"{USERNAME} trusted=60"

    def test_failed_assertion_counts_as_a_failed_attempt(self, client, passkey_user, monkeypatch, db):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_authentication_response", _fake_auth(ok=False))
        _login(client)
        _begin(client)
        r = _finish(client)
        assert r.status_code == 400
        assert "internal" not in r.data.decode()
        with client.session_transaction() as sess:
            assert "_user_id" not in sess
            assert "passkey_auth" not in sess  # challenge consumed even on failure
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM mfa_attempts WHERE user_id=%s", (passkey_user,))
            assert cur.fetchone()["c"] == 1
            cur.execute(
                "SELECT details FROM audit_log WHERE action='MFA_FAILED' AND details LIKE %s", (f"{USERNAME}%",)
            )
            assert cur.fetchone()["details"] == f"{USERNAME} method=passkey"

    def test_finish_without_begin_is_refused(self, client, passkey_user, monkeypatch):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_authentication_response", _fake_auth(4))
        _login(client)
        assert _finish(client).status_code == 400

    def test_counter_regression_is_refused(self, client, passkey_user, monkeypatch):
        # Stored counter is 3 (fixture); an assertion reporting 3 again is a clone.
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_authentication_response", _fake_auth(3))
        _login(client)
        _begin(client)
        assert _finish(client).status_code == 400

    def test_locked_out_user_cannot_begin(self, client, passkey_user, db):
        from jen.services.auth import MFA_MAX_ATTEMPTS, record_mfa_attempt

        for _ in range(MFA_MAX_ATTEMPTS):
            record_mfa_attempt(passkey_user)
        _login(client)
        r = _begin(client)
        assert r.status_code == 429
        assert "Too many failed codes" in r.get_json()["error"]


class TestReauthWithPasskey:
    @pytest.fixture
    def admin_passkey(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM webauthn_credentials WHERE user_id=1")
        db.commit()
        _seed_passkey(1)
        yield
        with db.cursor() as cur:
            cur.execute("DELETE FROM webauthn_credentials WHERE user_id=1")
        db.commit()

    def test_reauth_page_offers_the_passkey(self, logged_in_client, admin_passkey):
        page = logged_in_client.get("/auth/reauth").data.decode()
        assert "Use passkey" in page
        assert "/mfa/passkey/reauth/begin" in page

    def test_assertion_then_password_confirms(self, logged_in_client, admin_passkey, monkeypatch):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_authentication_response", _fake_auth(1))
        with logged_in_client.session_transaction() as sess:
            sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            sess["reauth_next"] = "/mfa/trusted-devices"
        r = logged_in_client.post("/mfa/passkey/reauth/begin")
        assert r.status_code == 200, r.data
        r = logged_in_client.post(
            "/mfa/passkey/reauth/finish",
            data=json.dumps({"response": {"id": CRED_B64, "rawId": CRED_B64, "response": {}}}),
            content_type="application/json",
        )
        assert r.status_code == 200, r.data
        with logged_in_client.session_transaction() as sess:
            assert sess.get("reauth_passkey_at")
        r = logged_in_client.post("/auth/reauth", data={"password": "admin"}, follow_redirects=False)
        assert r.status_code in (301, 302)
        assert r.headers["Location"].endswith("/mfa/trusted-devices")
        with logged_in_client.session_transaction() as sess:
            assert "reauth_passkey_at" not in sess  # single use
            assert passkeys.stamp_is_fresh(sess.get("auth_at"), 60)

    def test_password_alone_still_fails_for_a_passkey_holder(self, logged_in_client, admin_passkey):
        r = logged_in_client.post("/auth/reauth", data={"password": "admin"}, follow_redirects=True)
        assert b"Confirmation failed" in r.data

    def test_stale_assertion_stamp_is_ignored(self, logged_in_client, admin_passkey):
        with logged_in_client.session_transaction() as sess:
            sess["reauth_passkey_at"] = (
                datetime.now(timezone.utc) - timedelta(seconds=passkeys.REAUTH_WINDOW_SECONDS + 5)
            ).isoformat()
        r = logged_in_client.post("/auth/reauth", data={"password": "admin"}, follow_redirects=True)
        assert b"Confirmation failed" in r.data


class TestStampFreshness:
    def test_fresh_and_stale(self):
        now = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
        assert passkeys.stamp_is_fresh((now - timedelta(seconds=10)).isoformat(), 120, now=now)
        assert not passkeys.stamp_is_fresh((now - timedelta(seconds=121)).isoformat(), 120, now=now)
        assert not passkeys.stamp_is_fresh((now + timedelta(seconds=5)).isoformat(), 120, now=now)  # future
        assert not passkeys.stamp_is_fresh(None, 120, now=now)
        assert not passkeys.stamp_is_fresh("garbage", 120, now=now)
