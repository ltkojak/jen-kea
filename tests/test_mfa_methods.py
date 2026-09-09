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
    secrets = {"_probe_iPhone": pyotp.random_base32(), "_probe_Keeper": pyotp.random_base32()}
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_methods WHERE name LIKE '\\_probe\\_%'")
            for name, sec in secrets.items():
                cur.execute(
                    "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) "
                    "VALUES (1, 'totp', %s, %s, 1)",
                    (sec, name),
                )
        db.commit()
    yield secrets
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_methods WHERE name LIKE '\\_probe\\_%'")
        db.commit()


def _last_used():
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("SELECT name, last_used FROM mfa_methods WHERE name LIKE '\\_probe\\_%' ORDER BY name")
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


def _probe_ids():
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("SELECT id, name FROM mfa_methods WHERE name LIKE '\\_probe\\_%' ORDER BY name")
            return {r["name"]: r["id"] for r in cur.fetchall()}


def _probe_count():
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM mfa_methods WHERE name LIKE '\\_probe\\_%'")
            return cur.fetchone()["c"]


class TestLastFactorProtection:
    """v5.8.0 — a required-MFA user must not be able to remove their only
    authenticator (would lock the policy out on next login / let a stolen
    session switch MFA off)."""

    def _set_mode(self, mode):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("mfa_mode", mode)
        _invalidate_settings_cache()

    def test_cannot_remove_only_factor_when_required(self, logged_in_client, two_totp_methods):
        self._set_mode("required_all")
        try:
            ids = _probe_ids()
            # drop one so exactly one _probe_ method is left
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM mfa_methods WHERE id=%s", (ids["_probe_Keeper"],))
                db.commit()
            r = logged_in_client.post(
                "/mfa/enroll",
                data={"action": "remove", "method_id": ids["_probe_iPhone"]},
                follow_redirects=True,
            )
            assert r.status_code == 200
            assert _probe_count() == 1, "the last required factor was removed"
        finally:
            self._set_mode("off")

    def test_can_remove_one_of_two_when_required(self, logged_in_client, two_totp_methods):
        self._set_mode("required_all")
        try:
            ids = _probe_ids()
            logged_in_client.post(
                "/mfa/enroll", data={"action": "remove", "method_id": ids["_probe_iPhone"]}, follow_redirects=True
            )
            assert _probe_count() == 1
        finally:
            self._set_mode("off")

    def test_can_remove_last_factor_when_mfa_not_required(self, logged_in_client, two_totp_methods):
        self._set_mode("off")
        ids = _probe_ids()
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM mfa_methods WHERE id=%s", (ids["_probe_Keeper"],))
            db.commit()
        logged_in_client.post(
            "/mfa/enroll", data={"action": "remove", "method_id": ids["_probe_iPhone"]}, follow_redirects=True
        )
        assert _probe_count() == 0

    def test_count_helper_returns_none_on_db_error_and_removal_is_blocked(self, logged_in_client, two_totp_methods):
        """v5.8.1 — fail CLOSED: if we can't count the remaining factors,
        a required-MFA user is not allowed to remove one."""
        from unittest.mock import patch

        from jen.routes import mfa_routes

        with patch("jen.models.db.jen_db", side_effect=RuntimeError("db down")):
            assert mfa_routes._remaining_mfa_factor_count(1, None) is None

        self._set_mode("required_all")
        try:
            ids = _probe_ids()
            with patch("jen.routes.mfa_routes._remaining_mfa_factor_count", return_value=None):
                logged_in_client.post(
                    "/mfa/enroll",
                    data={"action": "remove", "method_id": ids["_probe_iPhone"]},
                    follow_redirects=True,
                )
            assert _probe_count() == 2, "removal went through despite an unknown factor count"
        finally:
            self._set_mode("off")
