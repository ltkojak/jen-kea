"""v7.0.0-beta.10 (Q224) - the DB-backed rows of the pass on 7.0.0-beta.9.

AJ4  `/settings/logs` is for unrestricted callers only (ARCHITECTURE §2): a subnet-scoped admin is redirected, an unrestricted admin and a superadmin read it.
AJ5  `set_user_subnets` and `edit_user` refuse a subnet id that is not a whole number (the rule `add_user` has had since Q171); nothing stores None (unrestricted) for it.
AJ14 an admin makes the session timeout and login rate limiting STRICTER only; a superadmin may loosen them.
AJ15 the Users page prints the minutes the server applies for an account, not the stored row.
AJ18 the Security page bounds its attempts, lockout minutes and the audit retention.

Needs the database (the `client`, `db` and `logged_in_client` fixtures of tests/conftest.py)."""

import json

import pytest

from tests.conftest import restricted_client


def _admin(client, db, name, subnets):
    """An ADMIN account restricted to `subnets` (a list), or unrestricted (None), logged in."""
    from datetime import datetime, timezone

    from jen.models.user import hash_password

    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password, role, subnet_access) VALUES (%s, %s, %s, %s)",
            (name, hash_password("testpass123"), "admin", json.dumps(subnets) if subnets is not None else None),
        )
        user_id = cur.lastrowid
    db.commit()
    with client.session_transaction() as sess:
        sess["_user_cache"] = {
            "id": user_id,
            "username": name,
            "role": "admin",
            "session_timeout": None,
            "subnet_access": subnets,
        }
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True
        now = datetime.now(timezone.utc).isoformat()
        sess["last_active"] = now
        sess["auth_at"] = now
    return client, user_id


def _setting(db, key):
    from jen.models.user import get_global_setting

    return get_global_setting(key, None)


def _set(db, key, value):
    from jen.models.user import set_global_setting

    assert set_global_setting(key, value)


class TestAScopedAdminReadsNoLog:
    """AJ4."""

    @pytest.mark.parametrize("url", ["/settings/logs", "/settings/logs?tab=alerts", "/settings/logs?tab=audit&page=2"])
    def test_a_scoped_admin_is_redirected(self, client, db, url):
        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_logs_scoped")
        r = c.get(url)
        assert r.status_code == 302 and "/servers" in r.headers["Location"], (r.status_code, r.headers.get("Location"))

    def test_an_unrestricted_admin_reads_it(self, client, db):
        c, _uid = _admin(client, db, "_logs_admin_all", None)
        assert c.get("/settings/logs").status_code == 200
        assert c.get("/settings/logs?tab=alerts").status_code == 200

    def test_a_superadmin_reads_it(self, logged_in_client):
        assert logged_in_client.get("/settings/logs").status_code == 200

    def test_a_scoped_viewer_is_refused_too(self, client, db):
        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_logs_viewer")
        assert c.get("/settings/logs").status_code in (302, 403)


class TestASubnetIdThatIsNotAWholeNumberRefusesTheForm:
    """AJ5. `²` passes `str.isdigit()` and `int()` raises on it; the two siblings of `add_user` stored None - an UNRESTRICTED account - for it."""

    def _user(self, db, name, subnets="[1]"):
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role, subnet_access) VALUES (%s, %s, 'admin', %s)",
                (name, hash_password("x" * 12), subnets),
            )
            uid = cur.lastrowid
        db.commit()
        return uid

    def _access(self, db, uid):
        with db.cursor() as cur:
            cur.execute("SELECT subnet_access FROM users WHERE id=%s", (uid,))
            return cur.fetchone()["subnet_access"]

    @pytest.mark.parametrize("bad", [["²"], ["²", "1"], ["abc"], ["1", " 2"]])
    def test_set_user_subnets_refuses_and_keeps_the_stored_access(self, logged_in_client, db, bad):
        uid = self._user(db, f"_sub_set_{abs(hash(tuple(bad))) % 10000}")
        r = logged_in_client.post(f"/users/set-subnets/{uid}", data={"subnet_ids": bad}, follow_redirects=True)
        assert r.status_code == 200 and b"Subnet ids must be numbers" in r.data
        assert self._access(db, uid) == "[1]", "nothing was stored: not None (all subnets), not a shorter list"

    @pytest.mark.parametrize("bad", [["²"], ["²", "1"]])
    def test_edit_user_refuses_and_keeps_the_stored_access(self, logged_in_client, db, bad):
        uid = self._user(db, f"_sub_edit_{abs(hash(tuple(bad))) % 10000}")
        r = logged_in_client.post(
            f"/users/edit/{uid}", data={"role": "admin", "timeout": "", "subnet_ids": bad}, follow_redirects=True
        )
        assert r.status_code == 200 and b"Subnet ids must be numbers" in r.data
        assert self._access(db, uid) == "[1]"

    def test_a_whole_number_list_is_stored_as_submitted(self, logged_in_client, db):
        uid = self._user(db, "_sub_ok")
        logged_in_client.post(f"/users/set-subnets/{uid}", data={"subnet_ids": ["1", "2"]}, follow_redirects=True)
        assert json.loads(self._access(db, uid)) == [1, 2]


class TestAnAdminMakesThePolicyStricterOnly:
    """AJ14: the two global authentication knobs beside the MFA mode get its ratchet (Q171)."""

    def test_an_admin_cannot_turn_the_session_timeout_off(self, client, db):
        _set(db, "session_timeout_enabled", "true")
        _set(db, "session_timeout_minutes", "60")
        c, _uid = _admin(client, db, "_ratchet_s1", None)
        r = c.post(
            "/settings/save-session", data={"timeout_minutes": "60", "timeout_enabled": "false"}, follow_redirects=True
        )
        assert b"Only a superadmin can make the session timeout less strict" in r.data
        assert _setting(db, "session_timeout_enabled") == "true"

    def test_an_admin_cannot_lengthen_it_but_may_shorten_it(self, client, db):
        _set(db, "session_timeout_enabled", "true")
        _set(db, "session_timeout_minutes", "60")
        c, _uid = _admin(client, db, "_ratchet_s2", None)
        c.post(
            "/settings/save-session", data={"timeout_minutes": "120", "timeout_enabled": "true"}, follow_redirects=True
        )
        assert _setting(db, "session_timeout_minutes") == "60"
        c.post(
            "/settings/save-session", data={"timeout_minutes": "30", "timeout_enabled": "true"}, follow_redirects=True
        )
        assert _setting(db, "session_timeout_minutes") == "30"

    def test_a_superadmin_may_loosen_it(self, logged_in_client, db):
        _set(db, "session_timeout_enabled", "true")
        _set(db, "session_timeout_minutes", "30")
        logged_in_client.post(
            "/settings/save-session", data={"timeout_minutes": "0", "timeout_enabled": "true"}, follow_redirects=True
        )
        assert _setting(db, "session_timeout_minutes") == "0"
        _set(db, "session_timeout_minutes", "60")

    def test_an_admin_cannot_turn_rate_limiting_off_or_loosen_it(self, client, db):
        _set(db, "rl_mode", "both")
        _set(db, "rl_max_attempts", "10")
        _set(db, "rl_lockout_minutes", "15")
        c, _uid = _admin(client, db, "_ratchet_r1", None)
        for data in (
            {"max_attempts": "10", "lockout_minutes": "15", "mode": "off"},
            {"max_attempts": "11", "lockout_minutes": "15", "mode": "both"},
            {"max_attempts": "10", "lockout_minutes": "14", "mode": "both"},
            {"max_attempts": "0", "lockout_minutes": "15", "mode": "both"},
        ):
            r = c.post("/settings/save-rate-limit", data=data, follow_redirects=True)
            assert b"Only a superadmin can make login rate limiting less strict" in r.data, data
        assert (_setting(db, "rl_mode"), _setting(db, "rl_max_attempts"), _setting(db, "rl_lockout_minutes")) == (
            "both",
            "10",
            "15",
        )
        r = c.post(
            "/settings/save-rate-limit",
            data={"max_attempts": "5", "lockout_minutes": "30", "mode": "ip"},
            follow_redirects=True,
        )
        assert b"Rate limiting settings saved" in r.data
        assert (_setting(db, "rl_mode"), _setting(db, "rl_max_attempts"), _setting(db, "rl_lockout_minutes")) == (
            "ip",
            "5",
            "30",
        )
        _set(db, "rl_mode", "both")
        _set(db, "rl_max_attempts", "10")
        _set(db, "rl_lockout_minutes", "15")


class TestTheSecurityPageBoundsItsNumbers:
    """AJ18."""

    @pytest.mark.parametrize(
        "data, field",
        [
            ({"max_attempts": "1001", "lockout_minutes": "15", "mode": "both"}, b"Max attempts must be"),
            ({"max_attempts": "10", "lockout_minutes": "10081", "mode": "both"}, b"Lockout duration must be"),
            ({"max_attempts": "²", "lockout_minutes": "15", "mode": "both"}, b"Max attempts must be"),
            ({"max_attempts": "10", "lockout_minutes": "1" * 30, "mode": "both"}, b"Lockout duration must be"),
        ],
    )
    def test_out_of_bounds_is_refused_with_the_bound_named(self, logged_in_client, db, data, field):
        before = _setting(db, "rl_lockout_minutes")
        r = logged_in_client.post("/settings/save-rate-limit", data=data, follow_redirects=True)
        assert r.status_code == 200 and field in r.data
        assert _setting(db, "rl_lockout_minutes") == before

    def test_the_stored_text_is_canonical(self, logged_in_client, db):
        logged_in_client.post(
            "/settings/save-rate-limit",
            data={"max_attempts": "007", "lockout_minutes": "0015", "mode": "both"},
            follow_redirects=True,
        )
        assert (_setting(db, "rl_max_attempts"), _setting(db, "rl_lockout_minutes")) == ("7", "15")
        _set(db, "rl_max_attempts", "10")

    @pytest.mark.parametrize("days", ["3651", "²", "-1", "1" * 25])
    def test_audit_retention_out_of_bounds_is_refused(self, logged_in_client, db, days):
        before = _setting(db, "audit_retention_days")
        r = logged_in_client.post(
            "/settings/save-audit-retention", data={"audit_retention_days": days}, follow_redirects=True
        )
        assert b"must be a whole number of days from 0" in r.data
        assert _setting(db, "audit_retention_days") == before

    def test_a_locked_out_check_runs_with_the_parameterized_window(self, db):
        """The lockout window is a parameter now: the statement runs on the real engine with the bound value."""
        from jen.services import auth

        _set(db, "rl_mode", "both")
        _set(db, "rl_max_attempts", "2")
        _set(db, "rl_lockout_minutes", str(auth.MAX_LOCKOUT_MINUTES))
        try:
            auth.record_login_attempt("203.0.113.9", "_rl_param")
            auth.record_login_attempt("203.0.113.9", "_rl_param")
            locked, minutes = auth.is_locked_out("203.0.113.9", "_rl_param")
            assert locked is True and 1 <= minutes <= auth.MAX_LOCKOUT_MINUTES, (locked, minutes)
        finally:
            _set(db, "rl_max_attempts", "10")
            _set(db, "rl_lockout_minutes", "15")
            with db.cursor() as cur:
                cur.execute("DELETE FROM login_attempts WHERE username='_rl_param'")
            db.commit()


class TestTheUsersPagePrintsTheMinutesTheServerApplies:
    """AJ15: a stored `session_timeout` outside 0..1440 (a hand edit, an earlier release) reads as the global; the page says "(global)" instead of printing the row."""

    def test_an_out_of_range_row_prints_as_the_global(self, logged_in_client, db):
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role, session_timeout) VALUES (%s, %s, 'viewer', %s)",
                ("_tm_1441", hash_password("x" * 12), 1441),
            )
            cur.execute(
                "INSERT INTO users (username, password, role, session_timeout) VALUES (%s, %s, 'viewer', %s)",
                ("_tm_45", hash_password("x" * 12), 45),
            )
        db.commit()
        html = logged_in_client.get("/settings/users").data.decode()
        assert "1441m" not in html
        assert "45m" in html
