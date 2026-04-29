"""
tests/test_settings.py
──────────────────────
Tests for global settings — branding, session timeout, MFA mode,
alert templates, and the settings cache.
"""

import pytest
from jen.models.user import get_global_setting, set_global_setting, _invalidate_settings_cache


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
