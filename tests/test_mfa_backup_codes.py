"""
tests/test_mfa_backup_codes.py
──────────────────────────────
v5.8.0 — backup codes were completely non-functional: generated and
hashed as `XXXXXXXX-XXXXXXXX` but the challenge path stripped the dash
before re-hashing, so no entered code ever matched. And redemption was a
SELECT-then-UPDATE, so two requests could both spend one code. These
tests cover the canonicalisation (already-issued codes must still work),
single-use, and atomicity.
"""

import concurrent.futures

import pyotp
import pytest

from jen.models.db import jen_db
from jen.services import crypto, mfa

USER_ID = 1


@pytest.fixture
def backup_codes():
    codes = mfa.generate_backup_codes(USER_ID)
    yield codes
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=%s", (USER_ID,))
        db.commit()


class TestCanonicalisation:
    def test_code_as_issued_verifies(self, backup_codes):
        assert mfa.verify_backup_code(USER_ID, backup_codes[0]) is True

    def test_code_without_dash_verifies(self, backup_codes):
        assert mfa.verify_backup_code(USER_ID, backup_codes[1].replace("-", "")) is True

    def test_lowercase_and_spaced_verifies(self, backup_codes):
        messy = f"  {backup_codes[2].lower().replace('-', ' ')}  "
        assert mfa.verify_backup_code(USER_ID, messy) is True

    def test_six_digit_totp_style_code_is_not_a_backup_code(self, backup_codes):
        assert mfa.verify_backup_code(USER_ID, "123456") is False

    def test_wrong_length_or_non_hex_is_rejected(self, backup_codes):
        assert mfa.verify_backup_code(USER_ID, "ZZZZZZZZ-ZZZZZZZZ") is False
        assert mfa.verify_backup_code(USER_ID, "abc") is False
        assert mfa.verify_backup_code(USER_ID, "") is False


class TestSingleUse:
    def test_code_works_once_then_never_again(self, backup_codes):
        code = backup_codes[3]
        assert mfa.verify_backup_code(USER_ID, code) is True
        assert mfa.verify_backup_code(USER_ID, code) is False
        # a different, still-unused code is unaffected
        assert mfa.verify_backup_code(USER_ID, backup_codes[4]) is True

    def test_concurrent_redemptions_of_one_code_yield_exactly_one_success(self, backup_codes):
        code = backup_codes[5]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(lambda _: mfa.verify_backup_code(USER_ID, code), range(8)))
        assert results.count(True) == 1, results


class TestBackupCodeLoginFlow:
    """The end-to-end path the review asked for: enrolled user with a
    lost authenticator signs in with a backup code, which is then spent."""

    PW = "bkpflow123"

    @pytest.fixture
    def enrolled_user(self, app):
        from jen.models.user import hash_password

        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username='_bkp_flow'")
                cur.execute(
                    "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, 'viewer', 0)",
                    ("_bkp_flow", hash_password(self.PW)),
                )
                cur.execute("SELECT id FROM users WHERE username='_bkp_flow'")
                uid = cur.fetchone()["id"]
                cur.execute(
                    "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) VALUES (%s,'totp',%s,'x',1)",
                    (uid, crypto.encrypt_secret(pyotp.random_base32())),
                )
            db.commit()
        codes = mfa.generate_backup_codes(uid)
        yield uid, codes
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM mfa_methods WHERE user_id=%s", (uid,))
                cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=%s", (uid,))
                cur.execute("DELETE FROM users WHERE username='_bkp_flow'")
            db.commit()

    def test_login_with_backup_code_authenticates_and_consumes_it(self, client, enrolled_user):
        uid, codes = enrolled_user
        r = client.post("/login", data={"username": "_bkp_flow", "password": self.PW}, follow_redirects=False)
        assert "/mfa/verify" in r.headers["Location"]
        with client.session_transaction() as sess:
            assert "_user_id" not in sess  # not authenticated yet

        r = client.post("/mfa/verify", data={"code": codes[0]}, follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/mfa/verify" not in r.headers["Location"]
        with client.session_transaction() as sess:
            assert "_user_id" in sess
            assert "mfa_pending_user_id" not in sess

        # that code is now spent; a second login can't reuse it
        client.get("/logout")
        client.post("/login", data={"username": "_bkp_flow", "password": self.PW})
        r = client.post("/mfa/verify", data={"code": codes[0]}, follow_redirects=True)
        assert b"invalid" in r.data.lower() or b"incorrect" in r.data.lower()
        with client.session_transaction() as sess:
            assert "_user_id" not in sess
