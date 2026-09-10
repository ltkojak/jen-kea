"""
tests/test_auth.py
──────────────────
Tests for login, logout, session handling, and rate limiting.
"""


class TestLogin:
    """Login route — POST /login"""

    def test_login_success(self, client):
        """Correct credentials redirect to dashboard."""
        r = client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/" in r.headers["Location"]

    def test_login_wrong_password(self, client):
        """Wrong password returns login page with error."""
        r = client.post("/login", data={"username": "admin", "password": "wrongpassword"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"Invalid username or password" in r.data

    def test_login_wrong_username(self, client):
        """Non-existent username returns login page with error."""
        r = client.post("/login", data={"username": "nobody", "password": "admin"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"Invalid username or password" in r.data

    def test_login_empty_username(self, client):
        """Empty username returns login page with error."""
        r = client.post("/login", data={"username": "", "password": "admin"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"required" in r.data.lower()

    def test_login_empty_password(self, client):
        """Empty password returns login page with error."""
        r = client.post("/login", data={"username": "admin", "password": ""}, follow_redirects=True)
        assert r.status_code == 200
        assert b"required" in r.data.lower()

    def test_login_get_shows_form(self, client):
        """GET /login returns login form."""
        r = client.get("/login")
        assert r.status_code == 200
        assert b"login" in r.data.lower()

    def test_login_populates_session_cache(self, client):
        """Successful login stores user data in session cache."""
        client.post("/login", data={"username": "admin", "password": "admin"})
        with client.session_transaction() as sess:
            cache = sess.get("_user_cache")
        assert cache is not None
        assert cache["username"] == "admin"
        assert cache["role"] == "superadmin"

    def test_login_sets_last_active(self, client):
        """Successful login sets last_active in session."""
        client.post("/login", data={"username": "admin", "password": "admin"})
        with client.session_transaction() as sess:
            assert "last_active" in sess

    def test_login_rotates_the_session(self, client):
        """v5.17.0 (Q6 6B) — whatever the pre-auth session carried is
        dropped; only the fresh authenticated keys remain."""
        with client.session_transaction() as sess:
            sess["stale_pre_auth_key"] = "leak-me"
        client.post("/login", data={"username": "admin", "password": "admin"})
        with client.session_transaction() as sess:
            assert "stale_pre_auth_key" not in sess
            assert sess.get("_user_cache", {}).get("username") == "admin"
            assert "auth_at" in sess


class TestPasswordRehashOnLogin:
    """v5.8.0 — a legacy hash is upgraded to the current scheme on a
    successful login, synchronously and conditionally so a concurrent
    password change can't be clobbered by a stale rehash."""

    def _mk_user(self, db, username, stored_hash):
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username=%s", (username,))
            cur.execute(
                "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, 'viewer', 0)",
                (username, stored_hash),
            )
        db.commit()

    def _password_of(self, db, username):
        with db.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE username=%s", (username,))
            return cur.fetchone()["password"]

    def test_legacy_pbkdf2_is_upgraded_to_scrypt_on_login(self, client, db):
        from werkzeug.security import generate_password_hash

        old = generate_password_hash("rehashme123", method="pbkdf2:sha256:260000")
        self._mk_user(db, "_rehash_probe", old)
        try:
            r = client.post(
                "/login", data={"username": "_rehash_probe", "password": "rehashme123"}, follow_redirects=False
            )
            assert r.status_code in (302, 303)
            after = self._password_of(db, "_rehash_probe")
            assert after.startswith("scrypt:")
            assert after != old
            # the same password still verifies against the upgraded hash
            from jen.models.user import verify_password

            assert verify_password(after, "rehashme123")
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username='_rehash_probe'")
            db.commit()

    def test_current_scrypt_hash_is_left_untouched(self, client, db):
        from jen.models.user import hash_password

        current = hash_password("alreadygood123")
        self._mk_user(db, "_rehash_noop", current)
        try:
            client.post("/login", data={"username": "_rehash_noop", "password": "alreadygood123"})
            assert self._password_of(db, "_rehash_noop") == current
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username='_rehash_noop'")
            db.commit()

    def test_rehash_update_is_conditional_on_the_verified_hash(self):
        """The write must be scoped to the hash we just verified so a
        password change landing mid-login isn't overwritten by the old one."""
        import pathlib

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "routes" / "auth.py").read_text(
            encoding="utf-8"
        )
        assert "UPDATE users SET password=%s WHERE id=%s AND password=%s" in src
        assert "threading.Thread(target=_rehash" not in src  # no more fire-and-forget


class TestLogout:
    """Logout route — GET confirms, POST acts (v5.17.0 / Q6 6C)."""

    def test_get_logout_shows_a_confirm_page_and_keeps_the_session(self, logged_in_client):
        r = logged_in_client.get("/logout")
        assert r.status_code == 200
        assert b"Sign out" in r.data
        # still authenticated — a following protected GET works
        assert logged_in_client.get("/", follow_redirects=False).status_code == 200

    def test_post_logout_redirects_to_login(self, logged_in_client):
        r = logged_in_client.post("/logout", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "login" in r.headers["Location"]

    def test_post_logout_clears_the_session(self, logged_in_client):
        with logged_in_client.session_transaction() as sess:
            sess["_avatar_url"] = "data:image/png;base64,test"
        logged_in_client.post("/logout")
        with logged_in_client.session_transaction() as sess:
            assert "_user_cache" not in sess
            assert "_avatar_url" not in sess
            assert "_user_id" not in sess


class TestAuthRequired:
    """Unauthenticated access to protected routes."""

    def test_dashboard_requires_login(self, client):
        """Dashboard redirects to login when not authenticated."""
        r = client.get("/", follow_redirects=False)
        assert r.status_code in (301, 302, 308)

    def test_leases_requires_login(self, client):
        """Leases page redirects to login when not authenticated."""
        r = client.get("/leases", follow_redirects=False)
        assert r.status_code in (301, 302, 308)

    def test_settings_requires_login(self, client):
        """Settings redirects to login when not authenticated."""
        r = client.get("/settings/system", follow_redirects=False)
        assert r.status_code in (301, 302, 308)

    def test_api_stats_requires_login(self, client):
        """API stats redirects to login when not authenticated."""
        r = client.get("/api/stats", follow_redirects=False)
        assert r.status_code in (301, 302, 308)


class TestRateLimiting:
    """Login rate limiting."""

    def test_rate_limit_tracks_attempts(self, client, db):
        """Failed logins are recorded in login_attempts — synchronously
        as of v5.8.0 (no sleep needed; a parallel burst can no longer
        outrun its own failure records)."""
        for _ in range(3):
            client.post("/login", data={"username": "admin", "password": "wrong"})
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE username='admin'")
            count = cur.fetchone()["cnt"]
        assert count == 3

    def test_failure_recording_is_synchronous(self):
        """The record_* functions must not defer the INSERT to a thread —
        that's the race that let a parallel burst skip the lockout."""
        import inspect

        from jen.services import auth

        for fn in (auth.record_login_attempt, auth.record_mfa_attempt):
            src = inspect.getsource(fn)
            assert "threading" not in src and "Thread(" not in src, f"{fn.__name__} still defers its write"

    def test_no_fire_and_forget_writes_in_auth_or_user_models(self):
        """v5.17.0 (Q6 6F) — audit() and the clear_* rate-limit resets are
        synchronous now; a whole file grep is the durable guard."""
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        for rel in ("jen/services/auth.py", "jen/models/user.py"):
            src = (root / rel).read_text(encoding="utf-8")
            assert "threading.Thread" not in src, f"{rel} still starts a background thread"

    def test_prune_helper_runs_at_most_once_an_hour(self, monkeypatch):
        """v5.10.4 — the 24h login_attempts cleanup DELETE no longer
        rides along on every failed login; _maybe_prune_login_attempts
        gates it to once per process-hour."""
        from jen.services import auth

        monkeypatch.setattr(auth, "_last_prune", 0.0)

        class FakeCur:
            def __init__(self):
                self.deletes = 0

            def execute(self, sql, *args):
                if sql.strip().upper().startswith("DELETE"):
                    self.deletes += 1

        cur = FakeCur()
        # _last_prune is 0.0; first call is >1h past that, so it prunes.
        assert auth._maybe_prune_login_attempts(cur, now=10_000.0) is True
        assert auth._maybe_prune_login_attempts(cur, now=10_000.0 + 3599) is False
        assert auth._maybe_prune_login_attempts(cur, now=10_000.0 + 3601) is True
        assert cur.deletes == 2

    def test_record_login_attempt_does_not_prune_on_every_call(self, db, monkeypatch):
        from jen.services import auth

        monkeypatch.setattr(auth, "_last_prune", 0.0)

        # First call is allowed to prune. Seed a stale row AFTER it, then
        # a second call within the hour must leave that row alone.
        auth.record_login_attempt("1.2.3.4", "u1")
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO login_attempts (ip_address, username, attempted_at) "
                "VALUES ('9.9.9.9', 'stale', DATE_SUB(NOW(), INTERVAL 48 HOUR))"
            )
        db.commit()
        auth.record_login_attempt("1.2.3.4", "u2")

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM login_attempts WHERE username='stale'")
            assert cur.fetchone()["c"] == 1, "second call within the hour pruned anyway"
            cur.execute("SELECT COUNT(*) AS c FROM login_attempts WHERE username IN ('u1', 'u2')")
            assert cur.fetchone()["c"] == 2, "both failed-login INSERTs must be recorded"

    def test_rate_limit_lockout(self, client, db):
        """Exceed max attempts triggers lockout message."""
        # Set tight rate limit
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO settings (setting_key, setting_value) "
                "VALUES ('rl_max_attempts', '3'), "
                "('rl_lockout_minutes', '15'), "
                "('rl_mode', 'username')"
                "ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)"
            )
        db.commit()

        # Invalidate settings cache
        from jen.models.user import _invalidate_settings_cache

        _invalidate_settings_cache()

        # Pre-populate attempts to trigger lockout
        with db.cursor() as cur:
            for _ in range(3):
                cur.execute("INSERT INTO login_attempts (ip_address, username) VALUES ('127.0.0.1', 'admin')")
        db.commit()

        r = client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"Too many failed" in r.data or b"locked" in r.data.lower()
