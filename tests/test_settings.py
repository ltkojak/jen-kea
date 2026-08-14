"""
tests/test_settings.py
──────────────────────
Tests for global settings — branding, session timeout, MFA mode,
alert templates, and the settings cache.
"""

import pytest
from jen.models.user import get_global_setting, set_global_setting, _invalidate_settings_cache


class TestRestartPendingClearedOnStartup:
    """v4.4.21: 9 call sites (settings.py, plugins.py) set
    restart_pending=true, but before this fix only one specific button's
    route (restart_jen()) ever cleared it back to false. Any restart
    triggered another way — manual systemctl restart, self-update, a
    server reboot — left the persistent "restart required" banner stuck
    forever. Fixed by clearing the flag unconditionally in create_app()
    itself, since the app booting at all is proof a restart just
    happened, regardless of what triggered it."""

    def test_stuck_flag_is_cleared_by_a_fresh_create_app_call(self):
        from jen.models.user import get_global_setting, set_global_setting
        # Simulate the exact stuck-forever scenario: some earlier action
        # (a plugin install, an infrastructure settings save) left the
        # flag set to true, and — critically — the restart that follows
        # is NOT triggered through the one specific "Restart Jen Now"
        # button route.
        set_global_setting("restart_pending", "true")
        assert get_global_setting("restart_pending") == "true"

        # create_app() is exactly what runs on every real app startup,
        # regardless of how that startup was triggered — this is the
        # actual mechanism being tested, not a mock of it.
        from jen import create_app
        create_app()

        assert get_global_setting("restart_pending") == "false", (
            "restart_pending was still 'true' after a fresh create_app() "
            "call — the persistent restart-required banner would stay "
            "stuck showing even after a real restart just happened"
        )

    def test_clearing_survives_even_without_a_prior_true_value(self):
        # Edge case: nothing was ever pending — startup shouldn't error
        # or behave differently just because there was nothing to clear.
        from jen.models.user import get_global_setting, set_global_setting
        set_global_setting("restart_pending", "false")
        from jen import create_app
        create_app()
        assert get_global_setting("restart_pending") == "false"


class TestSettingsCache:
    """Settings cache — get_global_setting/set_global_setting."""

    def test_get_default_when_not_set(self):
        """get_global_setting returns default for missing key."""
        _invalidate_settings_cache()
        val = get_global_setting("nonexistent_key_xyz", "mydefault")
        assert val == "mydefault"

    def test_set_and_get(self):
        """set_global_setting persists and get_global_setting retrieves."""
        _invalidate_settings_cache()
        set_global_setting("test_cache_key", "hello")
        _invalidate_settings_cache()
        val = get_global_setting("test_cache_key", "")
        assert val == "hello"

    def test_cache_invalidated_on_set(self):
        """set_global_setting invalidates the in-memory cache."""
        _invalidate_settings_cache()
        set_global_setting("cache_test", "first")
        # Cache is now populated with "first"
        set_global_setting("cache_test", "second")
        # Cache should be invalidated; next read goes to DB
        val = get_global_setting("cache_test", "")
        assert val == "second"

    def test_cache_returns_fresh_value(self):
        """Cache TTL: value set externally is visible after cache invalidation."""
        set_global_setting("ttl_test", "original")
        _invalidate_settings_cache()
        val = get_global_setting("ttl_test", "")
        assert val == "original"


class TestSystemSettings:
    """System settings save routes."""

    def test_save_branding(self, logged_in_client):
        """Branding settings can be saved."""
        r = logged_in_client.post("/settings/save-nav-color", data={
            "nav_color": "#00ff00",
        }, follow_redirects=True)
        assert r.status_code == 200

    def test_save_session_timeout(self, logged_in_client):
        """Session timeout settings can be saved."""
        r = logged_in_client.post("/settings/save-session", data={
            "session_timeout_enabled": "true",
            "session_timeout_minutes": "60",
        }, follow_redirects=True)
        assert r.status_code == 200

    def test_save_ports(self, logged_in_client, monkeypatch):
        """Port settings can be saved (restart mocked)."""
        import threading
        monkeypatch.setattr(threading, "Thread",
                           lambda target, daemon: type("T", (), {
                               "start": lambda self: None
                           })())
        r = logged_in_client.post("/settings/save-ports", data={
            "http_port": "5050",
            "https_port": "8443",
        }, follow_redirects=True)
        assert r.status_code == 200


class TestMfaModeAndNavLogoRoutesRegression:
    """v4.4.9 regression guard: both save_mfa_mode() and upload_nav_logo()
    were missing their @bp.route(...) decorator entirely — Flask never
    registered the URLs, so every attempt through the UI was a guaranteed
    404, and the MFA enforcement policy could not be changed through the
    running application at all. Checked systematically across every route
    file and both plugins at the time; these were the only two instances.
    These tests exist specifically to make sure that class of bug (a
    route silently never being registered, with no startup error) can't
    silently reappear."""

    def test_save_mfa_mode_route_is_registered(self, logged_in_client):
        r = logged_in_client.post("/settings/system/save-mfa-mode",
                                   data={"mfa_mode": "optional"},
                                   follow_redirects=False)
        assert r.status_code != 404

    def test_save_mfa_mode_actually_persists(self, logged_in_client):
        from jen.models.user import get_global_setting
        r = logged_in_client.post("/settings/system/save-mfa-mode",
                                   data={"mfa_mode": "required_admins"},
                                   follow_redirects=True)
        assert r.status_code == 200
        assert get_global_setting("mfa_mode") == "required_admins"

    def test_save_mfa_mode_rejects_invalid_value(self, logged_in_client):
        r = logged_in_client.post("/settings/system/save-mfa-mode",
                                   data={"mfa_mode": "not_a_real_mode"},
                                   follow_redirects=True)
        assert r.status_code == 200
        assert b"invalid mfa mode" in r.data.lower()

    def test_save_mfa_mode_requires_admin(self, client, db):
        from tests.conftest import restricted_client as _restricted_client
        _restricted_client(client, db, allowed_subnets=None, role="viewer",
                            username="mfamode_viewer1")
        r = client.post("/settings/system/save-mfa-mode",
                        data={"mfa_mode": "optional"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"admin access required" in r.data.lower()

    def test_upload_nav_logo_route_is_registered(self, logged_in_client, tmp_path, monkeypatch):
        from jen import extensions
        from io import BytesIO
        # Redirect the logo write path to a tmp dir — don't touch the
        # real /opt/jen/static path during a test run.
        monkeypatch.setattr(extensions, "NAV_LOGO_PATH", str(tmp_path / "nav_logo"))
        monkeypatch.setattr(extensions, "STATIC_DIR", str(tmp_path))

        # Minimal valid 1x1 PNG — generated with PIL and verified valid
        # rather than hand-typed (a hand-typed attempt at this had a
        # subtle byte error that would have made the test meaningless).
        png_bytes = bytes.fromhex(
            "89504e470d0a1a0a0000000d4948445200000001000000010802000000"
            "907753de0000000c49444154789c63f8cfc0000003010100c9fe92ef00"
            "00000049454e44ae426082"
        )
        r = logged_in_client.post(
            "/settings/upload-nav-logo",
            data={"logo": (BytesIO(png_bytes), "logo.png")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert r.status_code != 404
        assert b"nav logo updated" in r.data.lower()
        assert (tmp_path / "nav_logo.png").exists()

    def test_upload_nav_logo_requires_admin(self, client, db):
        from tests.conftest import restricted_client as _restricted_client
        from io import BytesIO
        _restricted_client(client, db, allowed_subnets=None, role="viewer",
                            username="navlogo_viewer1")
        r = client.post(
            "/settings/upload-nav-logo",
            data={"logo": (BytesIO(b"fake"), "logo.png")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"admin access required" in r.data.lower()


class TestAuditLog:
    """Audit logging."""

    def test_audit_written_on_login(self, client, db):
        """Successful login creates audit log entry."""
        import time
        client.post("/login", data={"username": "admin", "password": "admin"})
        time.sleep(1.0)  # audit is async — remote DB thread needs time
        with db.cursor() as cur:
            cur.execute("SELECT * FROM audit_log WHERE action='LOGIN' "
                       "AND username='admin' ORDER BY created_at DESC LIMIT 1")
            row = cur.fetchone()
        assert row is not None
        assert row["action"] == "LOGIN"

    def test_audit_written_on_logout(self, logged_in_client, db):
        """Logout creates audit log entry."""
        import time
        logged_in_client.get("/logout")
        time.sleep(1.0)
        with db.cursor() as cur:
            cur.execute("SELECT * FROM audit_log WHERE action='LOGOUT' "
                       "ORDER BY created_at DESC LIMIT 1")
            row = cur.fetchone()
        assert row is not None
