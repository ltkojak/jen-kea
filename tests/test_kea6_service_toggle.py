"""
tests/test_kea6_service_toggle.py
─────────────────────────────────
Turning DHCPv6 on and off: the lease6-history migration, the SSH orchestration in set_ipv6_service_state(), the toggle route, the context processor, and the infrastructure settings template.

Split out of the monolithic tests/test_kea6.py in v5.6.1.
"""

from jen import extensions
from jen.models import migrations as migrations_module
from tests._kea6_helpers import FakeSSHClient


class TestLease6HistoryMigration:
    def test_migration_registered_and_sequential(self):
        versions = [v for v, _, _ in migrations_module.MIGRATIONS]
        assert 11 in versions
        assert versions == sorted(versions)
        # v5.1.11 — migrations 12/13 (session-cache token_version, per-key
        # API subnet scope) legitimately supersede 11 as the latest; this
        # no longer asserts 11 is last, only that whatever comes after it
        # continues strictly increasing (registry-wide invariant already
        # enforced in migrations.py, re-checked here for this neighborhood).
        idx = versions.index(11)
        assert versions[idx:] == sorted(versions[idx:])

    def test_creates_table_idempotently(self, db):
        with db.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS lease6_history")
        db.commit()
        migrations_module._m011_lease6_history(db)
        migrations_module._m011_lease6_history(db)  # must not raise second time
        db.commit()
        with db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM lease6_history")
            cols = {row["Field"] for row in cur.fetchall()}
        assert cols == {
            "id",
            "subnet_id",
            "snapshot_time",
            "active_na",
            "active_ta",
            "active_pd",
            "reserved_na",
            "reserved_pd",
        }


class TestSetIpv6ServiceState:
    def _server(self, **overrides):
        s = {
            "id": 1,
            "name": "theelders",
            "ssh_host": "10.10.11.250",
            "ssh_user": "matthew",
            "kea_conf": "/etc/kea/kea-dhcp4.conf",
        }
        s.update(overrides)
        return s

    def test_skips_servers_without_ssh_host(self, monkeypatch):
        from jen.services import kea6 as kea6_module

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "no-ssh", "ssh_host": ""}])
        results = kea6_module.set_ipv6_service_state(True)
        assert results == []

    def test_enable_fails_cleanly_when_config_missing(self, monkeypatch):
        from jen.services import kea6 as kea6_module

        server = self._server()
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        fake_ssh = FakeSSHClient([("no", "")])  # _config_exists check -> "no"
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        results = kea6_module.set_ipv6_service_state(True)
        assert len(results) == 1
        assert results[0]["ok"] is False
        assert "kea-dhcp6.conf" in results[0]["message"]
        # Never attempted a systemctl call once the config check failed.
        assert not any("systemctl" in c for c in fake_ssh.calls)
        assert fake_ssh.closed is True

    def test_enable_succeeds_when_config_present_and_systemctl_ok(self, monkeypatch):
        from jen.services import kea6 as kea6_module

        server = self._server()
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        fake_ssh = FakeSSHClient([("yes", ""), ("done", "")])
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        results = kea6_module.set_ipv6_service_state(True)
        assert results == [{"name": "theelders", "ok": True, "message": "kea-dhcp6-server enabled and started"}]
        assert any("enable --now" in c for c in fake_ssh.calls)
        assert any("isc-kea-dhcp6-server" in c for c in fake_ssh.calls)  # dual-name fallback present

    def test_disable_does_not_check_config_existence(self, monkeypatch):
        """Disabling should never block on the config file being present —
        you must always be able to turn v6 off, even if the conf vanished."""
        from jen.services import kea6 as kea6_module

        server = self._server()
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        fake_ssh = FakeSSHClient([("done", "")])
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        results = kea6_module.set_ipv6_service_state(False)
        assert results[0]["ok"] is True
        assert "disable --now" in fake_ssh.calls[0]
        assert len(fake_ssh.calls) == 1  # no config-existence check call at all

    def test_ssh_connect_failure_reported_per_server_not_fatal(self, monkeypatch):
        from jen.services import kea6 as kea6_module

        s1 = self._server(name="theelders", ssh_host="10.10.11.250")
        s2 = self._server(name="standby", ssh_host="10.10.11.249")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [s1, s2])

        def flaky_connect(server):
            if server["name"] == "theelders":
                raise TimeoutError("no route to host")
            return FakeSSHClient([("done", "")])

        monkeypatch.setattr(kea6_module, "_connect_ssh", flaky_connect)
        results = kea6_module.set_ipv6_service_state(False)
        assert len(results) == 2
        by_name = {r["name"]: r for r in results}
        assert by_name["theelders"]["ok"] is False
        assert "no route to host" in by_name["theelders"]["message"]
        assert by_name["standby"]["ok"] is True

    def test_kea6_conf_path_derived_from_v4_kea_conf(self):
        from jen.services import kea6 as kea6_module

        server = self._server(kea_conf="/etc/kea/kea-dhcp4.conf")
        assert kea6_module._kea6_conf_path(server) == "/etc/kea/kea-dhcp6.conf"


class TestToggleIpv6Route:
    def test_requires_superadmin(self, client, db):
        """admin (not superadmin) must be rejected — blast radius per plan."""
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        resp = c.post("/settings/infrastructure/toggle-ipv6", data={"enable": "true"}, follow_redirects=False)
        assert resp.status_code == 302  # redirected away, access denied
        from jen.models.user import _invalidate_settings_cache
        from jen.services.kea6 import is_ipv6_enabled

        _invalidate_settings_cache()
        assert is_ipv6_enabled() is False

    def test_no_ssh_configured_anywhere_declines_gracefully(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "solo", "ssh_host": ""}])
        resp = logged_in_client.post(
            "/settings/infrastructure/toggle-ipv6", data={"enable": "true"}, follow_redirects=False
        )
        assert resp.status_code == 302
        from jen.models.user import _invalidate_settings_cache
        from jen.services.kea6 import is_ipv6_enabled

        _invalidate_settings_cache()
        assert is_ipv6_enabled() is False

    def test_enable_flag_only_set_when_all_servers_succeed(self, logged_in_client, monkeypatch, db):
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "s1", "ssh_host": "1.2.3.4"}])
        monkeypatch.setattr(
            kea6_module, "set_ipv6_service_state", lambda enable: [{"name": "s1", "ok": False, "message": "boom"}]
        )
        from jen.models.user import _invalidate_settings_cache

        logged_in_client.post("/settings/infrastructure/toggle-ipv6", data={"enable": "true"})
        _invalidate_settings_cache()
        from jen.services.kea6 import is_ipv6_enabled

        assert is_ipv6_enabled() is False  # partial/total failure -> stays off

    def test_enable_flag_set_when_all_servers_succeed(self, logged_in_client, monkeypatch, db):
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "s1", "ssh_host": "1.2.3.4"}])
        monkeypatch.setattr(
            kea6_module, "set_ipv6_service_state", lambda enable: [{"name": "s1", "ok": True, "message": "ok"}]
        )
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        logged_in_client.post("/settings/infrastructure/toggle-ipv6", data={"enable": "true"})
        _invalidate_settings_cache()
        from jen.services.kea6 import is_ipv6_enabled

        try:
            assert is_ipv6_enabled() is True
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_disable_always_flips_flag_off_even_on_partial_failure(self, logged_in_client, monkeypatch, db):
        import jen.services.kea6 as kea6_module
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "s1", "ssh_host": "1.2.3.4"}])
        monkeypatch.setattr(
            kea6_module,
            "set_ipv6_service_state",
            lambda enable: [{"name": "s1", "ok": False, "message": "network unreachable"}],
        )
        logged_in_client.post("/settings/infrastructure/toggle-ipv6", data={"enable": "false"})
        _invalidate_settings_cache()
        from jen.services.kea6 import is_ipv6_enabled

        assert is_ipv6_enabled() is False


class TestIpv6ContextProcessor:
    def test_ipv6_enabled_false_by_default_for_authenticated_user(self, logged_in_client, db):
        from jen.models.user import _invalidate_settings_cache

        _invalidate_settings_cache()
        resp = logged_in_client.get("/")
        assert resp.status_code == 200
        # No v6 nav markup should be present anywhere while disabled — the
        # nav template itself hasn't been built yet (Phase 2), so this just
        # locks in that the page renders cleanly with the flag off.
        assert resp.request.path == "/"


class TestSettingsKeaTemplate:
    def test_superadmin_sees_kea6_card(self, logged_in_client, db):
        from jen.models.user import _invalidate_settings_cache

        _invalidate_settings_cache()
        resp = logged_in_client.get("/settings/kea")
        assert resp.status_code == 200
        assert b"Kea6 Control Plane" in resp.data
        assert b"Enable IPv6" in resp.data

    def test_admin_does_not_see_kea6_card(self, client, db):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        resp = c.get("/settings/kea")
        assert resp.status_code == 200
        assert b"Kea6 Control Plane" not in resp.data

    def test_enabled_state_shows_disable_button(self, logged_in_client, db):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/settings/kea")
            assert b"Disable IPv6" in resp.data
            assert b'value="false"' in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_disabled_state_shows_enable_button(self, logged_in_client, db):
        from jen.models.user import _invalidate_settings_cache

        _invalidate_settings_cache()
        resp = logged_in_client.get("/settings/kea")
        assert b"Enable IPv6" in resp.data
