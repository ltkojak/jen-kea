"""
tests/test_mfa_methods.py
─────────────────────────
TOTP multi-method verification and last_used tracking (v4.3.4).

Prior bugs: verify_totp only checked the FIRST enrolled method's secret
(a second authenticator could never log in), and mfa_methods.last_used
was never written (methods showed "Last used never" forever).
"""

import time

import pyotp
import pytest

from jen.models.db import jen_db
from jen.services import mfa


@pytest.fixture
def two_totp_methods():
    """Seed two distinct TOTP methods for user 1; clean up after."""
    secrets = {"_probe_iPhone": pyotp.random_base32(),
               "_probe_Keeper": pyotp.random_base32()}
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_methods WHERE name LIKE '\\_probe\\_%'")
            for name, sec in secrets.items():
                cur.execute(
                    "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) "
                    "VALUES (1, 'totp', %s, %s, 1)", (sec, name))
        db.commit()
    yield secrets
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_methods WHERE name LIKE '\\_probe\\_%'")
        db.commit()


def _last_used():
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("SELECT name, last_used FROM mfa_methods "
                        "WHERE name LIKE '\\_probe\\_%' ORDER BY name")
            return {r["name"]: r["last_used"] for r in cur.fetchall()}


class TestMultiMethodTotp:

    def test_second_method_verifies(self, two_totp_methods):
        code = pyotp.TOTP(two_totp_methods["_probe_Keeper"]).now()
        assert mfa.verify_totp(1, code) is True

    def test_matching_method_gets_last_used(self, two_totp_methods):
        code = pyotp.TOTP(two_totp_methods["_probe_Keeper"]).now()
        assert mfa.verify_totp(1, code)
        time.sleep(0.3)
        state = _last_used()
        assert state["_probe_Keeper"] is not None
        assert state["_probe_iPhone"] is None

    def test_first_method_still_verifies_and_stamps(self, two_totp_methods):
        code = pyotp.TOTP(two_totp_methods["_probe_iPhone"]).now()
        assert mfa.verify_totp(1, code)
        time.sleep(0.3)
        assert _last_used()["_probe_iPhone"] is not None

    def test_wrong_code_rejected_nothing_stamped(self, two_totp_methods):
        assert mfa.verify_totp(1, "000000") is False
        state = _last_used()
        assert state["_probe_iPhone"] is None and state["_probe_Keeper"] is None
