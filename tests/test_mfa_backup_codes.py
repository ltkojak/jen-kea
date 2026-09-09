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

import pytest

from jen.models.db import jen_db
from jen.services import mfa

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
