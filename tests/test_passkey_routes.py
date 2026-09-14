"""
tests/test_passkey_routes.py
────────────────────────────
v5.31.0 (Q31) — the passkey enrolment surface on /mfa/enroll and the two
JSON halves of the registration ceremony. The WebAuthn verification
itself is faked at py_webauthn's boundary (see tests/test_passkeys.py);
what's under test here is Jen's gating: who may enrol (a logged-in user,
or one held in forced enrolment — nobody else), the single-use session
state, the last-factor rule on removal, admin reset, and the audit rows.
"""

import json
import re
from types import SimpleNamespace

import pytest

from jen.models.db import jen_db
from jen.models.user import _invalidate_settings_cache, hash_password, set_global_setting

USERNAME = "_passkey_probe"
PASSWORD = "passkeypass123"


def _fake_registration(credential_id=b"cred-r"):
    def fake(**kwargs):
        return SimpleNamespace(
            credential_id=credential_id,
            credential_public_key=b"pk",
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000002",
        )

    return fake


@pytest.fixture
def clean_admin_passkeys(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM webauthn_credentials WHERE user_id=1")
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM webauthn_credentials WHERE user_id=1")
        cur.execute("DELETE FROM audit_log WHERE action LIKE 'PASSKEY_%%' AND user_id=1")
    db.commit()


@pytest.fixture
def required_all_unenrolled(app):
    """A user under mfa_mode=required_all with no factor — login parks
    them in forced enrolment (mirrors tests/test_mfa_enrollment_gate.py)."""
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
        db.commit()
    yield uid
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username=%s", (USERNAME,))  # FKs cascade the MFA rows
        db.commit()
    set_global_setting("mfa_mode", "off")
    _invalidate_settings_cache()


def _begin(client):
    return client.post("/mfa/passkey/register/begin", headers={"X-CSRFToken": "x"})


def _finish(client, name="Probe key", response=None):
    return client.post(
        "/mfa/passkey/register/finish",
        data=json.dumps(
            {"name": name, "response": response or {"id": "Y3JlZC1y", "rawId": "Y3JlZC1y", "response": {}}}
        ),
        content_type="application/json",
    )


class TestEnrolPage:
    def test_page_offers_passkeys_not_coming_soon(self, logged_in_client, clean_admin_passkeys):
        page = logged_in_client.get("/mfa/enroll").data.decode()
        assert "Add a Passkey" in page
        assert "Coming Soon" not in page
        assert "/mfa/passkey/register/begin" in page
        assert 'id="passkey-unsupported"' in page  # feature-detect fallback is in the markup

    def test_enrolled_passkeys_are_listed_with_a_remove_form(self, logged_in_client, clean_admin_passkeys, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, name) "
                "VALUES (1, 'abc', 'def', 0, 'Probe YubiKey')"
            )
        db.commit()
        page = logged_in_client.get("/mfa/enroll").data.decode()
        assert "Probe YubiKey" in page
        assert 'name="action" value="remove_passkey"' in page


class TestRegistrationCeremony:
    def test_anonymous_is_refused(self, client):
        r = _begin(client)
        assert r.status_code == 401
        assert r.get_json()["ok"] is False

    def test_begin_returns_options_and_parks_state(self, logged_in_client, clean_admin_passkeys):
        r = _begin(logged_in_client)
        assert r.status_code == 200, r.data
        options = json.loads(r.get_json()["options"])
        assert options["rp"]["id"] == "localhost"
        assert options["user"]["name"] == "admin"
        with logged_in_client.session_transaction() as sess:
            assert sess["passkey_reg"]["challenge"] == options["challenge"]
            assert sess["passkey_reg"]["user_id"] == 1

    def test_finish_stores_the_passkey_and_audits(self, logged_in_client, clean_admin_passkeys, monkeypatch, db):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", _fake_registration())
        _begin(logged_in_client)
        r = _finish(logged_in_client, name="Probe key")
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body["ok"] is True and body["name"] == "Probe key"
        assert body["next"].endswith("/mfa/passkey/enrolled")
        with db.cursor() as cur:
            cur.execute("SELECT name, credential_id FROM webauthn_credentials WHERE user_id=1")
            rows = cur.fetchall()
            assert [(r["name"], r["credential_id"]) for r in rows] == [("Probe key", "Y3JlZC1y")]
            cur.execute(
                "SELECT details FROM audit_log WHERE action='PASSKEY_ENROLL' AND user_id=1 ORDER BY id DESC LIMIT 1"
            )
            assert "name=Probe key" in cur.fetchone()["details"]
        # The challenge is single-use: it left the session.
        with logged_in_client.session_transaction() as sess:
            assert "passkey_reg" not in sess

    def test_finish_without_begin_is_refused(self, logged_in_client, clean_admin_passkeys, monkeypatch):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", _fake_registration())
        r = _finish(logged_in_client)
        assert r.status_code == 400
        assert "start again" in r.get_json()["error"]

    def test_finish_cannot_be_replayed(self, logged_in_client, clean_admin_passkeys, monkeypatch):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", _fake_registration())
        _begin(logged_in_client)
        assert _finish(logged_in_client).status_code == 200
        assert (
            _finish(logged_in_client, response={"id": "b3RoZXI", "rawId": "b3RoZXI", "response": {}}).status_code == 400
        )

    def test_library_failure_is_a_400_with_a_safe_message(self, logged_in_client, clean_admin_passkeys, monkeypatch):
        from webauthn.helpers.exceptions import InvalidRegistrationResponse

        def boom(**kwargs):
            raise InvalidRegistrationResponse("attestation statement mismatch: secret internals")

        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", boom)
        _begin(logged_in_client)
        r = _finish(logged_in_client)
        assert r.status_code == 400
        assert "secret internals" not in r.data.decode()

    def test_enrolled_page_shows_backup_codes_once_for_a_first_factor(
        self, logged_in_client, clean_admin_passkeys, monkeypatch, db
    ):
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=1")
        db.commit()
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", _fake_registration())
        _begin(logged_in_client)
        nxt = _finish(logged_in_client).get_json()["next"]
        page = logged_in_client.get(nxt).data.decode()
        assert "backup" in page.lower()
        assert re.search(r"[A-Z0-9]{8}-[A-Z0-9]{8}", page)
        # Second visit: codes were popped, plain redirect to the MFA page.
        r = logged_in_client.get(nxt, follow_redirects=False)
        assert r.status_code in (301, 302) and "/mfa/enroll" in r.headers["Location"]


class TestForcedEnrolment:
    """A user parked in forced enrolment may enrol a passkey as their
    FIRST factor, and only then gets a real session."""

    def _login(self, client):
        return client.post("/login", data={"username": USERNAME, "password": PASSWORD}, follow_redirects=False)

    def test_pending_user_can_begin_and_finish(self, client, required_all_unenrolled, monkeypatch, db):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", _fake_registration())
        self._login(client)
        with client.session_transaction() as sess:
            assert "_user_id" not in sess and sess.get("mfa_pending_enroll") is True
        r = _begin(client)
        assert r.status_code == 200, r.data
        assert json.loads(r.get_json()["options"])["user"]["name"] == USERNAME
        r = _finish(client, name="first key")
        assert r.status_code == 200, r.data
        with client.session_transaction() as sess:
            assert "_user_id" in sess
            assert "mfa_pending_enroll" not in sess
            assert sess.get("passkey_backup_codes")
        assert client.get("/", follow_redirects=False).status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM webauthn_credentials WHERE user_id=%s", (required_all_unenrolled,))
            assert cur.fetchone()["c"] == 1

    def test_pending_user_still_cannot_reach_the_app_before_finishing(self, client, required_all_unenrolled):
        self._login(client)
        _begin(client)
        assert client.get("/", follow_redirects=False).status_code in (301, 302)


class TestRemoval:
    def _seed(self, db, name):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, name) "
                "VALUES (1, %s, 'pk', 0, %s)",
                (name, name),
            )
            cur.execute("SELECT id FROM webauthn_credentials WHERE user_id=1 AND name=%s", (name,))
            row_id = cur.fetchone()["id"]
        db.commit()
        return row_id

    def test_remove_passkey_and_audit(self, logged_in_client, clean_admin_passkeys, db):
        cred_id = self._seed(db, "to-remove")
        r = logged_in_client.post(
            "/mfa/enroll", data={"action": "remove_passkey", "cred_id": str(cred_id)}, follow_redirects=True
        )
        assert r.status_code == 200
        assert b"Passkey removed" in r.data
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM webauthn_credentials WHERE id=%s", (cred_id,))
            assert cur.fetchone()["c"] == 0
            cur.execute("SELECT COUNT(*) c FROM audit_log WHERE action='PASSKEY_REMOVE' AND user_id=1")
            assert cur.fetchone()["c"] >= 1

    def test_last_factor_is_kept_when_mfa_is_required(self, logged_in_client, clean_admin_passkeys, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_methods WHERE user_id=1")
        db.commit()
        set_global_setting("mfa_mode", "required_all")
        _invalidate_settings_cache()
        try:
            cred_id = self._seed(db, "only-factor")
            r = logged_in_client.post(
                "/mfa/enroll", data={"action": "remove_passkey", "cred_id": str(cred_id)}, follow_redirects=True
            )
            assert b"add another factor before removing" in r.data
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) c FROM webauthn_credentials WHERE id=%s", (cred_id,))
                assert cur.fetchone()["c"] == 1
        finally:
            set_global_setting("mfa_mode", "off")
            _invalidate_settings_cache()

    def test_admin_reset_removes_passkeys_too(self, logged_in_client, clean_admin_passkeys, db):
        # Reset the admin account's own MFA (user 1) through the superadmin route.
        self._seed(db, "reset-me")
        r = logged_in_client.post("/mfa/admin-reset/1", follow_redirects=True)
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM webauthn_credentials WHERE user_id=1")
            assert cur.fetchone()["c"] == 0
