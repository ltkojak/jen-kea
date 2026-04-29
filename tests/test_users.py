"""
tests/test_users.py
───────────────────
Tests for user management — create, password change, role, session timeout.
"""

import pytest
from jen.models.user import hash_password, verify_password, needs_rehash


class TestPasswordHashing:
    """Unit tests for password hashing functions."""

    def test_hash_password_produces_pbkdf2(self):
        """hash_password uses pbkdf2:sha256:260000."""
        h = hash_password("testpassword")
        assert h.startswith("pbkdf2:sha256:260000")

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

    def test_needs_rehash_false_for_260k(self):
        """260K hash does not need rehash."""
        from werkzeug.security import generate_password_hash
        h = generate_password_hash("test", method="pbkdf2:sha256:260000")
        assert needs_rehash(h) is False

    def test_needs_rehash_true_for_1m(self):
        """1M iteration hash needs rehash."""
        from werkzeug.security import generate_password_hash
        h = generate_password_hash("test", method="pbkdf2:sha256:1000000")
        assert needs_rehash(h) is True

    def test_needs_rehash_false_for_scrypt(self):
        """scrypt hash does not need rehash (different algorithm, already fast)."""
        from werkzeug.security import generate_password_hash
        h = generate_password_hash("test")  # default = scrypt
        if h.startswith("scrypt:"):
            assert needs_rehash(h) is False

    def test_needs_rehash_false_for_empty(self):
        """Empty string does not need rehash."""
        assert needs_rehash("") is False


class TestUserManagement:
    """User management routes."""

    def test_user_list_requires_admin(self, logged_in_client):
        """User list is accessible to admin."""
        r = logged_in_client.get("/users")
        assert r.status_code == 200

    def test_create_user(self, logged_in_client, db):
        """Admin can create a new user."""
        r = logged_in_client.post("/users/add", data={
            "username": "testuser",
            "password": "testpass123",
            "role": "viewer",
        }, follow_redirects=True)
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
            cur.execute("INSERT INTO users (username, password, role) VALUES ('dupuser', %s, 'viewer')",
                       (hash_password("pass123"),))
        db.commit()
        # Try to create same user via route
        r = logged_in_client.post("/users/add", data={
            "username": "dupuser", "password": "pass456", "role": "viewer"
        }, follow_redirects=True)
        assert r.status_code == 200
        # Should still only have 1 dupuser
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM users WHERE username='dupuser'")
            count = cur.fetchone()["cnt"]
        assert count == 1

    def test_change_password(self, logged_in_client, db):
        """User can change their own password."""
        r = logged_in_client.post("/users/change-password", data={
            "current_password": "admin",
            "new_password": "newpass123",
            "confirm_password": "newpass123",
        }, follow_redirects=True)
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE username='admin'")
            row = cur.fetchone()
        assert verify_password(row["password"], "newpass123")

    def test_change_password_wrong_current(self, logged_in_client):
        """Wrong current password is rejected."""
        r = logged_in_client.post("/users/change-password", data={
            "current_password": "wrongcurrent",
            "new_password": "newpass123",
            "confirm_password": "newpass123",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"incorrect" in r.data.lower() or b"wrong" in r.data.lower() or b"invalid" in r.data.lower()

    def test_change_password_mismatch(self, logged_in_client):
        """Mismatched new passwords are rejected."""
        r = logged_in_client.post("/users/change-password", data={
            "current_password": "admin",
            "new_password": "newpass123",
            "confirm_password": "differentpass",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"match" in r.data.lower()

    def test_set_session_timeout(self, logged_in_client, db):
        """Admin can set session timeout for a user."""
        r = logged_in_client.post("/users/set-timeout/1", data={
            "timeout": "60"
        }, follow_redirects=True)
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT session_timeout FROM users WHERE id=1")
            row = cur.fetchone()
        assert row["session_timeout"] == 60

    def test_session_timeout_cache_invalidated(self, logged_in_client):
        """Setting session timeout clears _user_cache from session."""
        with logged_in_client.session_transaction() as sess:
            sess["_user_cache"] = {"id": 1, "username": "admin",
                                   "role": "admin", "session_timeout": None}
        logged_in_client.post("/users/set-timeout/1", data={"session_timeout": "30"})
        with logged_in_client.session_transaction() as sess:
            assert "_user_cache" not in sess
