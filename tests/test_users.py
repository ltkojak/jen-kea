"""
tests/test_users.py
───────────────────
Tests for user management — create, password change, role, session timeout.
"""

from jen.models.user import hash_password, needs_rehash, verify_password


class TestPasswordHashing:
    """Unit tests for password hashing functions."""

    def test_hash_password_produces_scrypt(self):
        """v5.7.0 — hash_password uses scrypt:32768:8:1."""
        h = hash_password("testpassword")
        assert h.startswith("scrypt:32768:8:1$")

    def test_hash_password_is_salted(self):
        """Two hashes of same password are different (different salts)."""
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2

    def test_verify_password_correct(self):
        """verify_password returns True for correct password."""
        h = hash_password("mypassword")
        assert verify_password(h, "mypassword") is True

    def test_verify_password_wrong(self):
        """verify_password returns False for wrong password."""
        h = hash_password("mypassword")
        assert verify_password(h, "wrongpassword") is False

    def test_needs_rehash_true_for_legacy_pbkdf2_260k(self):
        """v5.7.0 — a pbkdf2:260000 hash (Jen's old default) now needs
        upgrading to scrypt on next login."""
        from werkzeug.security import generate_password_hash

        h = generate_password_hash("test", method="pbkdf2:sha256:260000")
        assert needs_rehash(h) is True

    def test_needs_rehash_true_for_1m(self):
        """1M iteration pbkdf2 hash needs rehash."""
        from werkzeug.security import generate_password_hash

        h = generate_password_hash("test", method="pbkdf2:sha256:1000000")
        assert needs_rehash(h) is True

    def test_needs_rehash_false_for_current_scrypt(self):
        """A hash at the current scrypt params does not need rehash."""
        h = hash_password("test")
        assert h.startswith("scrypt:32768:8:1$")
        assert needs_rehash(h) is False

    def test_needs_rehash_true_for_offparam_scrypt(self):
        """scrypt at non-current cost parameters is upgraded on next login."""
        from werkzeug.security import generate_password_hash

        h = generate_password_hash("test", method="scrypt:16384:8:1")
        assert needs_rehash(h) is True

    def test_needs_rehash_false_for_empty(self):
        """Empty string does not need rehash."""
        assert needs_rehash("") is False


class TestUserManagement:
    """User management routes."""

    def test_user_list_requires_admin(self, logged_in_client):
        """User list is accessible to admin."""
        r = logged_in_client.get("/settings/users")
        assert r.status_code == 200

    def test_create_user(self, logged_in_client, db):
        """Admin can create a new user."""
        r = logged_in_client.post(
            "/users/add",
            data={
                "username": "testuser",
                "password": "testpass123",
                "role": "viewer",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username='testuser'")
            user = cur.fetchone()
        assert user is not None
        assert user["role"] == "viewer"

    def test_create_user_duplicate_fails(self, logged_in_client, db):
        """Cannot create user with duplicate username."""
        # First create the user directly in DB
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES ('dupuser', %s, 'viewer')",
                (hash_password("pass123"),),
            )
        db.commit()
        # Try to create same user via route
        r = logged_in_client.post(
            "/users/add", data={"username": "dupuser", "password": "pass456", "role": "viewer"}, follow_redirects=True
        )
        assert r.status_code == 200
        # Should still only have 1 dupuser
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM users WHERE username='dupuser'")
            count = cur.fetchone()["cnt"]
        assert count == 1

    def test_change_password(self, logged_in_client, db):
        """User can change their own password."""
        r = logged_in_client.post(
            "/users/change-password",
            data={
                "current_password": "admin",
                "new_password": "newpass123",
                "confirm_password": "newpass123",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE username='admin'")
            row = cur.fetchone()
        assert verify_password(row["password"], "newpass123")

    def test_change_password_wrong_current(self, logged_in_client):
        """Wrong current password is rejected."""
        r = logged_in_client.post(
            "/users/change-password",
            data={
                "current_password": "wrongcurrent",
                "new_password": "newpass123",
                "confirm_password": "newpass123",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"incorrect" in r.data.lower() or b"wrong" in r.data.lower() or b"invalid" in r.data.lower()

    def test_change_password_mismatch(self, logged_in_client):
        """Mismatched new passwords are rejected."""
        r = logged_in_client.post(
            "/users/change-password",
            data={
                "current_password": "admin",
                "new_password": "newpass123",
                "confirm_password": "differentpass",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"match" in r.data.lower()

    def test_set_session_timeout(self, logged_in_client, db):
        """Admin can set session timeout for a user."""
        r = logged_in_client.post("/users/set-timeout/1", data={"timeout": "60"}, follow_redirects=True)
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT session_timeout FROM users WHERE id=1")
            row = cur.fetchone()
        assert row["session_timeout"] == 60

    def test_session_timeout_cache_invalidated(self, logged_in_client):
        """Setting session timeout clears _user_cache from session."""
        with logged_in_client.session_transaction() as sess:
            sess["_user_cache"] = {"id": 1, "username": "admin", "role": "superadmin", "session_timeout": None}
        logged_in_client.post("/users/set-timeout/1", data={"session_timeout": "30"})
        with logged_in_client.session_transaction() as sess:
            assert "_user_cache" not in sess


class TestAboutPageDeploymentDetailIsAdminOnly:
    """v5.10.4 — /about listed the HTTP/HTTPS ports, the on-disk config
    and app paths, and the Kea SSH host to any logged-in user. Those
    rows are admin-only now. The markers below target the table-cell
    markup (`>Label</td>`), not bare prose, so a changelog entry that
    mentions "the Kea SSH host" doesn't trip the absence check."""

    def test_admin_sees_the_deployment_rows(self, logged_in_client):
        r = logged_in_client.get("/about")
        assert r.status_code == 200
        assert b">Kea SSH Host</td>" in r.data
        assert b">App Directory</td>" in r.data

    def test_viewer_does_not_see_the_deployment_rows(self, client, db):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, allowed_subnets=[1], role="viewer")
        r = c.get("/about")
        assert r.status_code == 200
        assert b">Kea SSH Host</td>" not in r.data
        assert b">App Directory</td>" not in r.data
        assert b">Config File</td>" not in r.data
        # the page itself still renders for a viewer
        assert b"About Jen" in r.data


class TestOidcUsersPage:
    """v5.25.0 (Q21) — the Users page's SSO badge, the edit form's
    protections for an IdP-managed account (role/password are ignored
    server-side even if somehow submitted — a disabled <select>/<input>
    just isn't sent by a normal browser, so this is defense in depth,
    not the only guard), and the "Link to SSO" route."""

    def _seed_oidc_user(self, db, username="ssouser_edit1", role="admin", external_id="sub-abc"):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role, auth_provider, external_id) "
                "VALUES (%s, 'scrypt:unusable', %s, 'oidc', %s)",
                (username, role, external_id),
            )
            user_id = cur.lastrowid
        db.commit()
        return user_id

    def test_sso_badge_shown_for_oidc_user(self, logged_in_client, db):
        self._seed_oidc_user(db)
        r = logged_in_client.get("/settings/users")
        assert r.status_code == 200
        assert b"SSO" in r.data

    def test_edit_ignores_submitted_role_for_oidc_user(self, logged_in_client, db):
        user_id = self._seed_oidc_user(db, role="admin")
        r = logged_in_client.post(
            f"/users/edit/{user_id}",
            data={"role": "viewer", "timeout": ""},
            follow_redirects=True,
        )
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT role FROM users WHERE id=%s", (user_id,))
            assert cur.fetchone()["role"] == "admin"

    def test_edit_ignores_submitted_password_for_oidc_user(self, logged_in_client, db):
        user_id = self._seed_oidc_user(db)
        with db.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE id=%s", (user_id,))
            before = cur.fetchone()["password"]
        logged_in_client.post(
            f"/users/edit/{user_id}",
            data={"role": "admin", "new_password": "brandnewpass123", "confirm_password": "brandnewpass123"},
            follow_redirects=True,
        )
        with db.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE id=%s", (user_id,))
            after = cur.fetchone()["password"]
        assert after == before

    def test_edit_still_allows_subnet_and_timeout_changes(self, logged_in_client, db):
        user_id = self._seed_oidc_user(db, role="admin")
        r = logged_in_client.post(
            f"/users/edit/{user_id}",
            data={"role": "admin", "timeout": "45", "subnet_ids": "all"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT session_timeout FROM users WHERE id=%s", (user_id,))
            assert cur.fetchone()["session_timeout"] == 45

    def test_link_to_sso_converts_a_local_user(self, logged_in_client, db):
        from jen.models.user import hash_password as _hash

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES ('link_me1', %s, 'viewer')",
                (_hash("localpass123"),),
            )
            user_id = cur.lastrowid
        db.commit()

        r = logged_in_client.post(
            f"/users/link-sso/{user_id}", data={"external_id": "idp-sub-999"}, follow_redirects=True
        )
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT auth_provider, external_id, must_change_password FROM users WHERE id=%s", (user_id,))
            row = cur.fetchone()
        assert row["auth_provider"] == "oidc"
        assert row["external_id"] == "idp-sub-999"
        assert row["must_change_password"] == 0

    def test_link_to_sso_requires_external_id(self, logged_in_client, db):
        from jen.models.user import hash_password as _hash

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES ('link_me2', %s, 'viewer')",
                (_hash("localpass123"),),
            )
            user_id = cur.lastrowid
        db.commit()

        r = logged_in_client.post(f"/users/link-sso/{user_id}", data={"external_id": ""}, follow_redirects=True)
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT auth_provider FROM users WHERE id=%s", (user_id,))
            assert cur.fetchone()["auth_provider"] == "local"

    def test_link_to_sso_refuses_duplicate_external_id(self, logged_in_client, db):
        self._seed_oidc_user(db, username="ssouser_dupe1", external_id="dupe-sub")
        from jen.models.user import hash_password as _hash

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES ('link_me3', %s, 'viewer')",
                (_hash("localpass123"),),
            )
            user_id = cur.lastrowid
        db.commit()

        r = logged_in_client.post(f"/users/link-sso/{user_id}", data={"external_id": "dupe-sub"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"already linked" in r.data.lower()
        with db.cursor() as cur:
            cur.execute("SELECT auth_provider FROM users WHERE id=%s", (user_id,))
            assert cur.fetchone()["auth_provider"] == "local"
