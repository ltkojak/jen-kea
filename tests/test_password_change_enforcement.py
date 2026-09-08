"""
tests/test_password_change_enforcement.py
────────────────────────────────────────────
v5.2.7 — SECURITY FIX. A fresh install seeds an 'admin'/'admin'
superadmin with nothing enforcing that the obvious default ever
actually gets changed — the README says to change it immediately, but
that was advisory only, not enforced anywhere in the application. See
the users.must_change_password migration's docstring
(jen/models/migrations.py) for the full rationale.

These tests cover: the seed/creation paths that set the flag, the
before_request enforcement middleware that redirects while it's set,
the new force_password_change route's validation, and that clearing
the flag correctly propagates via the existing session-cache
invalidation already used for password changes.
"""

from datetime import datetime, timezone

from jen.models.user import hash_password


def _client_with_must_change_password(client, db, role="superadmin", username="mustchange1"):
    """Insert a user with must_change_password=1 set and log the test
    client in as that user, bypassing the login form — same pattern as
    conftest's logged_in_client/restricted_client fixtures, extended
    with the one field those don't set."""
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password, role, must_change_password) "
            "VALUES (%s, %s, %s, 1)",
            (username, hash_password("originalpass123"), role)
        )
        user_id = cur.lastrowid
    db.commit()

    with client.session_transaction() as sess:
        sess["_user_cache"] = {
            "id": user_id, "username": username, "role": role,
            "session_timeout": None, "subnet_access": None,
            "must_change_password": True,
        }
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True
        sess["last_active"] = datetime.now(timezone.utc).isoformat()
    return client, user_id


class TestDefaultAdminSeedSetsFlag:

    def test_seed_sql_includes_must_change_password(self):
        """Direct check of db.py's seed statement, since exercising the
        real seed path requires an entirely empty users table — which
        the test DB never is once conftest has run once. Confirms the
        actual INSERT text sets the flag, rather than assuming."""
        import inspect

        import jen.models.db as db_module
        source = inspect.getsource(db_module.init_jen_db)
        assert "must_change_password" in source
        assert "'admin'" in source or '"admin"' in source


class TestNewUserCreationSetsFlag:

    def test_add_user_sets_must_change_password(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username=%s", ("newhire1",))
        db.commit()

        r = logged_in_client.post("/users/add", data={
            "username": "newhire1", "password": "temporarypass123",
            "role": "viewer", "timeout": "",
        }, follow_redirects=True)
        assert r.status_code == 200

        with db.cursor() as cur:
            cur.execute("SELECT must_change_password FROM users WHERE username=%s", ("newhire1",))
            row = cur.fetchone()
        assert row is not None, "user was not created"
        assert row["must_change_password"] == 1


class TestEnforcementMiddleware:

    def test_flagged_user_redirected_away_from_dashboard(self, client, db):
        client, _ = _client_with_must_change_password(client, db)
        r = client.get("/", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/force-password-change" in r.headers.get("Location", "")

    def test_flagged_user_can_still_reach_the_change_password_page_itself(self, client, db):
        client, _ = _client_with_must_change_password(client, db)
        r = client.get("/force-password-change")
        assert r.status_code == 200
        assert b"Password Change Required" in r.data

    def test_flagged_user_can_still_log_out(self, client, db):
        client, _ = _client_with_must_change_password(client, db)
        r = client.get("/logout", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/force-password-change" not in r.headers.get("Location", "")

    def test_unflagged_user_not_redirected(self, logged_in_client):
        r = logged_in_client.get("/", follow_redirects=False)
        assert r.status_code == 200

    def test_flagged_user_blocked_from_unrelated_settings_page(self, client, db):
        client, _ = _client_with_must_change_password(client, db)
        r = client.get("/settings/system", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/force-password-change" in r.headers.get("Location", "")


class TestForcePasswordChangeRoute:

    def test_rejects_short_password(self, client, db):
        client, _ = _client_with_must_change_password(client, db, username="mustchange2")
        r = client.post("/force-password-change",
                        data={"new_password": "short", "confirm_password": "short"},
                        follow_redirects=True)
        assert r.status_code == 200
        assert b"at least 8 characters" in r.data

    def test_rejects_mismatched_confirmation(self, client, db):
        client, _ = _client_with_must_change_password(client, db, username="mustchange3")
        r = client.post("/force-password-change",
                        data={"new_password": "newpassword123", "confirm_password": "different123"},
                        follow_redirects=True)
        assert r.status_code == 200
        assert b"do not match" in r.data

    def test_rejects_reusing_the_literal_default(self, client, db):
        """The whole point of this feature is defeated if someone can
        just type 'admin' again as the 'new' password."""
        client, _ = _client_with_must_change_password(client, db, username="mustchange4")
        r = client.post("/force-password-change",
                        data={"new_password": "admin", "confirm_password": "admin"},
                        follow_redirects=True)
        assert r.status_code == 200
        assert b"other than the default" in r.data

    def test_rejects_password_matching_username(self, client, db):
        client, _ = _client_with_must_change_password(client, db, username="mustchange5")
        r = client.post("/force-password-change",
                        data={"new_password": "mustchange5", "confirm_password": "mustchange5"},
                        follow_redirects=True)
        assert r.status_code == 200
        assert b"other than the default" in r.data

    def test_successful_change_clears_flag_and_allows_normal_access(self, client, db):
        client, user_id = _client_with_must_change_password(client, db, username="mustchange6")
        r = client.post("/force-password-change",
                        data={"new_password": "brandnewpassword123", "confirm_password": "brandnewpassword123"},
                        follow_redirects=True)
        assert r.status_code == 200
        assert b"Password changed successfully" in r.data

        with db.cursor() as cur:
            cur.execute("SELECT must_change_password FROM users WHERE id=%s", (user_id,))
            assert cur.fetchone()["must_change_password"] == 0

        # And the enforcement middleware no longer blocks normal navigation
        r2 = client.get("/", follow_redirects=False)
        assert r2.status_code == 200

    def test_does_not_require_current_password(self, client, db):
        """Deliberately different from the general change_password()
        route: reaching this page at all already proves the user knows
        the current password (they just logged in with it)."""
        client, _ = _client_with_must_change_password(client, db, username="mustchange7")
        r = client.post("/force-password-change",
                        data={"new_password": "somethingnew123", "confirm_password": "somethingnew123"},
                        follow_redirects=True)
        assert r.status_code == 200
        assert b"Current password" not in r.data


class TestGeneralChangePasswordRouteDuringEnforcement:
    """/users/change-password is not in the enforcement middleware's
    allowlist (only /force-password-change and /logout are — see
    jen/__init__.py's _enforce_password_change()), and that's
    intentional: the whole point of this feature is that the rest of
    the application, including this alternate password-change route,
    is genuinely unavailable until the dedicated screen is used. An
    earlier version of this test incorrectly assumed this route would
    still work during enforcement and clear the flag — it doesn't,
    because the middleware correctly redirects the request away before
    change_password()'s own logic ever runs. This test now verifies
    that block is real, rather than assuming the route is reachable.
    """

    def test_change_password_route_is_blocked_during_enforcement(self, client, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role, must_change_password) "
                "VALUES (%s, %s, 'admin', 1)",
                ("mustchange8", hash_password("originalpass123"))
            )
            user_id = cur.lastrowid
        db.commit()

        with client.session_transaction() as sess:
            sess["_user_cache"] = {
                "id": user_id, "username": "mustchange8", "role": "admin",
                "session_timeout": None, "subnet_access": None,
                "must_change_password": True,
            }
            sess["_user_id"] = str(user_id)
            sess["_fresh"] = True
            sess["last_active"] = datetime.now(timezone.utc).isoformat()

        r = client.post("/users/change-password", data={
            "current_password": "originalpass123",
            "new_password": "differentnewpass123",
            "confirm_password": "differentnewpass123",
        }, follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/force-password-change" in r.headers.get("Location", "")

        # And the password genuinely wasn't changed, since the request
        # never reached change_password()'s own logic at all.
        with db.cursor() as cur:
            cur.execute("SELECT must_change_password FROM users WHERE id=%s", (user_id,))
            assert cur.fetchone()["must_change_password"] == 1


class TestGeneralChangePasswordSqlAlsoClearsFlag:
    """Defense in depth: verifies change_password()'s own UPDATE
    statement clears must_change_password, in case a future change to
    the enforcement middleware's allowlist ever makes this route
    reachable while the flag is set. Checked via source inspection
    rather than an HTTP-level test — the class above already
    establishes that this route is unreachable via HTTP while the flag
    is set, by design, so constructing an HTTP integration test for
    "the flag also clears here" would either be circular or depend on
    fragile cross-test state (e.g. assuming no other test in the full
    suite has already changed the shared default admin account's
    password), rather than testing anything this specific change
    actually guards against.
    """

    def test_change_password_update_statement_clears_flag(self):
        import inspect

        import jen.routes.users as users_module
        source = inspect.getsource(users_module.change_password)
        assert "must_change_password=0" in source, (
            "change_password()'s UPDATE statement no longer clears "
            "must_change_password — if the enforcement middleware's "
            "allowlist is ever changed to permit this route, an "
            "account could get stuck unable to clear the flag"
        )
