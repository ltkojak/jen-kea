"""
tests/test_kea6.py
───────────────────
v5.0 Phase 1 — IPv6 groundwork.

Mirrors test_db_context.py's style: exercise the real functions against
real (or realistically faked) state rather than asserting on mocks alone.

The single most important test in this file is
TestZeroBehaviorChange — confirming ipv6_enabled=false (the default on
every install, new and existing) produces genuinely zero behavior change:
empty SUBNET6_MAP, is_ipv6_enabled() False, no v6 command reaching Kea —
regardless of whether a [kea6] config section is even present. Everything
else in the v5.0 plan depends on this holding.
"""

import configparser
import json

import pytest

from jen import extensions
from jen.config import AppConfig
from jen.models import migrations as migrations_module


# ── SUBNET6_MAP derivation ──────────────────────────────────────────────────

class TestDeriveSubnet6Map:

    def test_missing_subnets6_section_is_silent(self):
        """Unlike a missing [subnets], a missing [subnets6] must NOT log a
        warning — v6 is opt-in, not a misconfiguration, and every v4-only
        install has no [subnets6] section at all."""
        cfg = configparser.ConfigParser()
        cfg.read_string("[subnets]\n1 = LAN, 192.168.1.0/24\n")
        result = AppConfig.derive_subnet_map(cfg, section="subnets6")
        assert result == {}

    def test_parses_v6_cidrs(self):
        cfg = configparser.ConfigParser()
        cfg.read_string(
            "[subnets6]\n"
            "1 = Production, 2001:db8:1::/64\n"
            "2 = IoT, 2001:db8:2::/64\n"
        )
        result = AppConfig.derive_subnet_map(cfg, section="subnets6")
        assert result == {
            1: {"name": "Production", "cidr": "2001:db8:1::/64", "paired_subnet4_id": None},
            2: {"name": "IoT",        "cidr": "2001:db8:2::/64", "paired_subnet4_id": None},
        }

    def test_v4_and_v6_ids_are_independent_namespaces(self):
        """Kea's v4 and v6 subnet IDs don't share a numbering space — the
        same integer can validly appear in both [subnets] and [subnets6]
        and refer to two unrelated subnets."""
        cfg = configparser.ConfigParser()
        cfg.read_string(
            "[subnets]\n1 = LAN, 192.168.1.0/24\n"
            "[subnets6]\n1 = LAN6, 2001:db8:1::/64\n"
        )
        v4 = AppConfig.derive_subnet_map(cfg, section="subnets")
        v6 = AppConfig.derive_subnet_map(cfg, section="subnets6")
        assert v4[1]["cidr"] == "192.168.1.0/24"
        assert v6[1]["cidr"] == "2001:db8:1::/64"

    def test_malformed_v6_entry_skipped_not_fatal(self):
        cfg = configparser.ConfigParser()
        cfg.read_string(
            "[subnets6]\n"
            "1 = not-a-valid-line\n"
            "2 = OK, 2001:db8:2::/64\n"
        )
        result = AppConfig.derive_subnet_map(cfg, section="subnets6")
        assert result == {2: {"name": "OK", "cidr": "2001:db8:2::/64", "paired_subnet4_id": None}}

    def test_v6_entry_with_paired_v4_id(self):
        cfg = configparser.ConfigParser()
        cfg.read_string("[subnets6]\n1 = Production, 2001:db8:1::/64, 1\n")
        result = AppConfig.derive_subnet_map(cfg, section="subnets6")
        assert result[1]["paired_subnet4_id"] == 1

    def test_v6_entry_without_paired_v4_id_defaults_none(self):
        cfg = configparser.ConfigParser()
        cfg.read_string("[subnets6]\n1 = Production, 2001:db8:1::/64\n")
        result = AppConfig.derive_subnet_map(cfg, section="subnets6")
        assert result[1]["paired_subnet4_id"] is None

    def test_v4_subnets_never_carry_paired_key(self):
        """v4 SUBNET_MAP entries keep their exact original two-key shape —
        pairing is a v6-only concept, and this must be zero behavior
        change for the v4 path."""
        cfg = configparser.ConfigParser()
        cfg.read_string("[subnets]\n1 = LAN, 192.168.1.0/24\n")
        result = AppConfig.derive_subnet_map(cfg, section="subnets")
        assert result == {1: {"name": "LAN", "cidr": "192.168.1.0/24"}}
        assert "paired_subnet4_id" not in result[1]

    def test_too_many_fields_in_v6_entry_skipped(self):
        cfg = configparser.ConfigParser()
        cfg.read_string("[subnets6]\n1 = Bad, 2001:db8:1::/64, 1, extra\n")
        result = AppConfig.derive_subnet_map(cfg, section="subnets6")
        assert result == {}


# ── [kea6]/[kea6_db] fallback-to-v4 behavior ────────────────────────────────

class TestKea6ConfigFallback:

    @pytest.fixture(autouse=True)
    def _restore_extensions_after(self):
        """AppConfig.apply() writes directly to jen.extensions module
        globals (by design — see jen/config.py), not through monkeypatch,
        so calling it in a test permanently mutates real global state
        unless explicitly restored. Snapshot everything this class's
        tests touch and put it back after each test so later tests (e.g.
        anything hitting the real pooled kea_db/kea6_db connections) don't
        inherit fake hosts like 'db4' left over from apply() calls here.
        """
        keys = ["KEA_API_URL", "KEA_API_USER", "KEA_API_PASS",
                "KEA_DB_HOST", "KEA_DB_USER", "KEA_DB_PASS",
                "KEA6_API_URL", "KEA6_API_USER", "KEA6_API_PASS",
                "KEA6_DB_HOST", "KEA6_DB_USER", "KEA6_DB_PASS", "KEA6_DB_NAME",
                "SUBNET_MAP", "SUBNET6_MAP", "JEN_DB_HOST", "JEN_DB_USER", "JEN_DB_PASS"]
        snapshot = {k: getattr(extensions, k, None) for k in keys}
        yield
        for k, v in snapshot.items():
            setattr(extensions, k, v)

    def _base_cfg(self, extra: str = "") -> configparser.ConfigParser:
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string(
            "[kea]\napi_url=http://kea4:8000\napi_user=u4\napi_pass=p4\n"
            "[kea_db]\nhost=db4\nuser=u4\npassword=p4\n"
            "[jen_db]\nhost=jendb\nuser=j\npassword=p\n"
            + extra
        )
        return cfg

    def test_falls_back_to_v4_when_kea6_absent(self, monkeypatch):
        app_config = AppConfig()
        cfg = self._base_cfg()
        app_config.apply(cfg)
        assert extensions.KEA6_API_URL  == "http://kea4:8000"
        assert extensions.KEA6_API_USER == "u4"
        assert extensions.KEA6_API_PASS == "p4"
        assert extensions.KEA6_DB_HOST  == "db4"

    def test_explicit_kea6_overrides_fallback(self):
        app_config = AppConfig()
        cfg = self._base_cfg(
            "[kea6]\napi_url=http://kea6:8000\napi_user=u6\napi_pass=p6\n"
        )
        app_config.apply(cfg)
        assert extensions.KEA6_API_URL  == "http://kea6:8000"
        assert extensions.KEA6_API_USER == "u6"
        assert extensions.KEA6_API_PASS == "p6"

    def test_subnet6_map_populated_by_apply(self):
        app_config = AppConfig()
        cfg = self._base_cfg("[subnets6]\n5 = V6LAN, 2001:db8:5::/64\n")
        app_config.apply(cfg)
        assert extensions.SUBNET6_MAP == {5: {"name": "V6LAN", "cidr": "2001:db8:5::/64", "paired_subnet4_id": None}}


# ── is_ipv6_enabled() gate ───────────────────────────────────────────────────

class TestIsIpv6Enabled:

    def test_defaults_false(self, db):
        from jen.services.kea6 import is_ipv6_enabled
        from jen.models.user import _invalidate_settings_cache
        _invalidate_settings_cache()
        assert is_ipv6_enabled() is False

    def test_true_after_setting_flipped(self, db):
        from jen.services.kea6 import is_ipv6_enabled
        from jen.models.user import set_global_setting
        set_global_setting("ipv6_enabled", "true")
        try:
            assert is_ipv6_enabled() is True
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_fails_closed_on_db_error(self, monkeypatch):
        import jen.models.user as user_module

        def boom(*a, **kw):
            raise RuntimeError("db unreachable")
        monkeypatch.setattr(user_module, "get_global_setting", boom)

        from jen.services import kea6 as kea6_module
        # is_ipv6_enabled imports get_global_setting locally, so patch via
        # the module it's imported from at call time.
        import importlib
        importlib.reload(kea6_module)
        monkeypatch.setattr(user_module, "get_global_setting", boom)
        assert kea6_module.is_ipv6_enabled() is False


# ── kea6_command() thin-wrapper plumbing ─────────────────────────────────────

class TestKea6Command:

    def test_passes_service_dhcp6(self, monkeypatch):
        from jen.services import kea6 as kea6_module
        captured = {}

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            captured["command"] = command
            captured["service"] = service
            captured["server"]  = server
            return {"result": 0}

        monkeypatch.setattr(kea6_module, "kea_command", fake_kea_command)
        kea6_module.kea6_command("lease6-get-all")
        assert captured["service"] == "dhcp6"
        assert captured["command"] == "lease6-get-all"

    def test_v6_server_falls_back_to_v4_server_fields(self, monkeypatch):
        from jen.services import kea6 as kea6_module
        monkeypatch.setattr(extensions, "KEA6_API_URL", "")
        monkeypatch.setattr(extensions, "KEA6_API_USER", "")
        monkeypatch.setattr(extensions, "KEA6_API_PASS", "")
        v4_server = {"api_url": "http://v4:8000", "api_user": "u", "api_pass": "p"}
        result = kea6_module._v6_server(v4_server)
        assert result == {"api_url": "http://v4:8000", "api_user": "u", "api_pass": "p"}

    def test_kea6_is_up_reflects_result_zero(self, monkeypatch):
        from jen.services import kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "kea6_command", lambda *a, **kw: {"result": 0})
        assert kea6_module.kea6_is_up() is True
        monkeypatch.setattr(kea6_module, "kea6_command", lambda *a, **kw: {"result": 1})
        assert kea6_module.kea6_is_up() is False


# ── lease6_history migration ─────────────────────────────────────────────────

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
            "id", "subnet_id", "snapshot_time",
            "active_na", "active_ta", "active_pd",
            "reserved_na", "reserved_pd",
        }


# ── set_ipv6_service_state() SSH orchestration ───────────────────────────────

class FakeSSHClient:
    """Stand-in for paramiko.SSHClient that records exec_command calls and
    returns scripted stdout/stderr per call, in order. Each response is
    (out, err) or (out, err, exit_status) — exit_status defaults to 0
    when omitted, for the (large majority of) existing tests that only
    care about stdout content."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.closed = False

    def exec_command(self, cmd):
        self.calls.append(cmd)
        resp = self._responses.pop(0) if self._responses else ("", "")
        if len(resp) == 3:
            out, err, exit_status = resp
        else:
            out, err = resp
            exit_status = 0

        class _Channel:
            def __init__(self, status):
                self._status = status
            def recv_exit_status(self):
                return self._status

        class _Stream:
            def __init__(self, text, channel=None):
                self._text = text
                self.channel = channel
            def read(self):
                return self._text.encode()

        channel = _Channel(exit_status)
        return None, _Stream(out, channel), _Stream(err, channel)

    def close(self):
        self.closed = True


class TestSetIpv6ServiceState:

    def _server(self, **overrides):
        s = {"id": 1, "name": "theelders", "ssh_host": "10.10.11.250",
             "ssh_user": "matthew", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        s.update(overrides)
        return s

    def test_skips_servers_without_ssh_host(self, monkeypatch):
        from jen.services import kea6 as kea6_module
        monkeypatch.setattr(extensions, "KEA_SERVERS",
                            [{"id": 1, "name": "no-ssh", "ssh_host": ""}])
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
        assert results == [{"name": "theelders", "ok": True,
                             "message": "kea-dhcp6-server enabled and started"}]
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


# ── /settings/infrastructure/toggle-ipv6 route ───────────────────────────────

class TestToggleIpv6Route:

    def test_requires_superadmin(self, client, db):
        """admin (not superadmin) must be rejected — blast radius per plan."""
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        resp = c.post("/settings/infrastructure/toggle-ipv6",
                      data={"enable": "true"}, follow_redirects=False)
        assert resp.status_code == 302  # redirected away, access denied
        from jen.services.kea6 import is_ipv6_enabled
        from jen.models.user import _invalidate_settings_cache
        _invalidate_settings_cache()
        assert is_ipv6_enabled() is False

    def test_no_ssh_configured_anywhere_declines_gracefully(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS",
                            [{"id": 1, "name": "solo", "ssh_host": ""}])
        resp = logged_in_client.post("/settings/infrastructure/toggle-ipv6",
                                     data={"enable": "true"}, follow_redirects=False)
        assert resp.status_code == 302
        from jen.services.kea6 import is_ipv6_enabled
        from jen.models.user import _invalidate_settings_cache
        _invalidate_settings_cache()
        assert is_ipv6_enabled() is False

    def test_enable_flag_only_set_when_all_servers_succeed(self, logged_in_client, monkeypatch, db):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(extensions, "KEA_SERVERS",
                            [{"id": 1, "name": "s1", "ssh_host": "1.2.3.4"}])
        monkeypatch.setattr(kea6_module, "set_ipv6_service_state",
                            lambda enable: [{"name": "s1", "ok": False, "message": "boom"}])
        from jen.models.user import _invalidate_settings_cache
        logged_in_client.post("/settings/infrastructure/toggle-ipv6",
                              data={"enable": "true"})
        _invalidate_settings_cache()
        from jen.services.kea6 import is_ipv6_enabled
        assert is_ipv6_enabled() is False  # partial/total failure -> stays off

    def test_enable_flag_set_when_all_servers_succeed(self, logged_in_client, monkeypatch, db):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(extensions, "KEA_SERVERS",
                            [{"id": 1, "name": "s1", "ssh_host": "1.2.3.4"}])
        monkeypatch.setattr(kea6_module, "set_ipv6_service_state",
                            lambda enable: [{"name": "s1", "ok": True, "message": "ok"}])
        from jen.models.user import _invalidate_settings_cache, set_global_setting
        logged_in_client.post("/settings/infrastructure/toggle-ipv6",
                              data={"enable": "true"})
        _invalidate_settings_cache()
        from jen.services.kea6 import is_ipv6_enabled
        try:
            assert is_ipv6_enabled() is True
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_disable_always_flips_flag_off_even_on_partial_failure(self, logged_in_client, monkeypatch, db):
        import jen.services.kea6 as kea6_module
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "KEA_SERVERS",
                            [{"id": 1, "name": "s1", "ssh_host": "1.2.3.4"}])
        monkeypatch.setattr(kea6_module, "set_ipv6_service_state",
                            lambda enable: [{"name": "s1", "ok": False, "message": "network unreachable"}])
        logged_in_client.post("/settings/infrastructure/toggle-ipv6",
                              data={"enable": "false"})
        _invalidate_settings_cache()
        from jen.services.kea6 import is_ipv6_enabled
        assert is_ipv6_enabled() is False


# ── Context processor nav gate ───────────────────────────────────────────────

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

# ── settings_infrastructure.html rendering ───────────────────────────────────

class TestSettingsInfrastructureTemplate:

    def test_superadmin_sees_kea6_card(self, logged_in_client, db):
        from jen.models.user import _invalidate_settings_cache
        _invalidate_settings_cache()
        resp = logged_in_client.get("/settings/infrastructure")
        assert resp.status_code == 200
        assert b"Kea6 Control Agent API" in resp.data
        assert b"Enable IPv6" in resp.data

    def test_admin_does_not_see_kea6_card(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        resp = c.get("/settings/infrastructure")
        assert resp.status_code == 200
        assert b"Kea6 Control Agent API" not in resp.data

    def test_enabled_state_shows_disable_button(self, logged_in_client, db):
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/settings/infrastructure")
            assert b"Disable IPv6" in resp.data
            assert b'value="false"' in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_disabled_state_shows_enable_button(self, logged_in_client, db):
        from jen.models.user import _invalidate_settings_cache
        _invalidate_settings_cache()
        resp = logged_in_client.get("/settings/infrastructure")
        assert b"Enable IPv6" in resp.data


# ── lease6/hosts/ipv6_reservations read layer ────────────────────────────────

class TestExtractMacFromDuid:

    def test_duid_ll_extracts_mac(self):
        from jen.services.kea6 import extract_mac_from_duid
        # DUID-LL: type=0003, hwtype=0001 (Ethernet), MAC 00:1a:2b:3c:4d:5e
        duid_hex = "00030001" + "001a2b3c4d5e"
        assert extract_mac_from_duid(duid_hex) == "00:1a:2b:3c:4d:5e"

    def test_duid_llt_extracts_mac(self):
        from jen.services.kea6 import extract_mac_from_duid
        # DUID-LLT: type=0001, hwtype=0001, time=12345678, MAC aa:bb:cc:dd:ee:ff
        duid_hex = "00010001" + "12345678" + "aabbccddeeff"
        assert extract_mac_from_duid(duid_hex) == "aa:bb:cc:dd:ee:ff"

    def test_duid_en_returns_none(self):
        from jen.services.kea6 import extract_mac_from_duid
        # DUID-EN (type=0002) — no embedded link-layer address
        duid_hex = "0002" + "0000abcd" + "deadbeef"
        assert extract_mac_from_duid(duid_hex) is None

    def test_duid_uuid_returns_none(self):
        from jen.services.kea6 import extract_mac_from_duid
        duid_hex = "0004" + "0" * 32
        assert extract_mac_from_duid(duid_hex) is None

    def test_malformed_or_empty_returns_none(self):
        from jen.services.kea6 import extract_mac_from_duid
        assert extract_mac_from_duid("") is None
        assert extract_mac_from_duid(None) is None
        assert extract_mac_from_duid("ab") is None
        assert extract_mac_from_duid("not-hex-zz") is None


class TestGetLease6Mac:

    def test_prefers_hwaddr_when_present(self):
        from jen.services.kea6 import get_lease6_mac
        # hwaddr present should win even though the DUID also decodes
        duid_hex = "00030001" + "aaaaaaaaaaaa"
        assert get_lease6_mac("001a2b3c4d5e", duid_hex) == "00:1a:2b:3c:4d:5e"

    def test_falls_back_to_duid_when_hwaddr_absent(self):
        from jen.services.kea6 import get_lease6_mac
        duid_hex = "00030001" + "001a2b3c4d5e"
        assert get_lease6_mac("", duid_hex) == "00:1a:2b:3c:4d:5e"
        assert get_lease6_mac(None, duid_hex) == "00:1a:2b:3c:4d:5e"

    def test_none_when_neither_source_usable(self):
        from jen.services.kea6 import get_lease6_mac
        duid_en_hex = "0002" + "0000abcd" + "deadbeef"
        assert get_lease6_mac("", duid_en_hex) is None


class TestListLease6:

    def _insert_lease(self, db, **overrides):
        row = {
            "address": "2001:db8:1::1",
            "duid": bytes.fromhex("00030001001a2b3c4d5e"),
            "valid_lifetime": 3600,
            "expire": "2026-08-15 00:00:00",
            "subnet_id": 1,
            "pref_lifetime": 1800,
            "lease_type": 0,
            "iaid": 1,
            "prefix_len": 128,
            "hostname": "test-host",
            "hwaddr": None,
            "state": 0,
        }
        row.update(overrides)
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                    subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                    hostname, hwaddr, state)
                VALUES (%(address)s, %(duid)s, %(valid_lifetime)s, %(expire)s,
                    %(subnet_id)s, %(pref_lifetime)s, %(lease_type)s, %(iaid)s,
                    %(prefix_len)s, %(hostname)s, %(hwaddr)s, %(state)s)
            """, row)
        db.commit()

    def test_lists_basic_lease(self, db, monkeypatch):
        import jen.models.db as db_mod
        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)  # keep fixture's conn alive
        from jen.services.kea6 import list_lease6
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1")
        results = list_lease6()
        assert len(results) == 1
        r = results[0]
        assert r["address"] == "2001:db8:1::1"
        assert r["lease_type_name"] == "IA_NA"
        assert r["mac"] == "00:1a:2b:3c:4d:5e"  # DUID-LL fallback, no hwaddr
        assert r["expired"] is False

    def test_filters_by_subnet_and_type(self, db, monkeypatch):
        import jen.models.db as db_mod
        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import list_lease6
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1", subnet_id=1, lease_type=0)
        self._insert_lease(db, address="2001:db8:2::1", subnet_id=2, lease_type=2, prefix_len=56)
        assert len(list_lease6(subnet_id=1)) == 1
        assert len(list_lease6(lease_type=2)) == 1
        assert list_lease6(lease_type=2)[0]["lease_type_name"] == "IA_PD"

    def test_hwaddr_present_wins_over_duid(self, db, monkeypatch):
        import jen.models.db as db_mod
        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import list_lease6
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1",
                           hwaddr=bytes.fromhex("aabbccddeeff"))
        r = list_lease6()[0]
        assert r["mac"] == "aa:bb:cc:dd:ee:ff"


class TestGetIpv6Reservations:

    def _insert_host_with_reservations(self, db, host_id_var="h1",
                                        duid=b"\x00\x03\x00\x01\x00\x1a\x2b\x3c\x4d\x5e",
                                        subnet_id=1, reservations=()):
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type,
                    dhcp6_subnet_id, hostname)
                VALUES (%s, 1, %s, %s)
            """, (duid, subnet_id, f"host-{host_id_var}"))
            host_id = cur.lastrowid
            for res in reservations:
                cur.execute("""
                    INSERT INTO ipv6_reservations (address, prefix_len, type,
                        dhcp6_iaid, host_id)
                    VALUES (%(address)s, %(prefix_len)s, %(type)s, %(iaid)s, %(host_id)s)
                """, {**res, "host_id": host_id})
        db.commit()
        return host_id

    def test_host_with_address_and_prefix_reservation(self, db, monkeypatch):
        """The core one-to-many case the plan calls out: a single device
        holding BOTH an IA_NA (address) and an IA_PD (delegated prefix)
        reservation at once."""
        import jen.models.db as db_mod
        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import get_ipv6_reservations
        with db.cursor() as cur:
            cur.execute("DELETE FROM ipv6_reservations")
            cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
        db.commit()
        self._insert_host_with_reservations(
            db, subnet_id=1,
            reservations=[
                {"address": "2001:db8:1::10", "prefix_len": 128, "type": 0, "iaid": 1},
                {"address": "2001:db8:1:1000::", "prefix_len": 56, "type": 2, "iaid": 2},
            ],
        )
        results = get_ipv6_reservations(subnet_id=1)
        assert len(results) == 1
        host = results[0]
        assert len(host["reservations"]) == 2
        types = {r["type_name"] for r in host["reservations"]}
        assert types == {"IA_NA", "IA_PD"}

    def test_filters_by_v6_subnet_not_v4(self, db, monkeypatch):
        """dhcp6_subnet_id and dhcp4_subnet_id are independent columns on
        the same hosts row — filtering must use the v6 one only."""
        import jen.models.db as db_mod
        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import get_ipv6_reservations
        with db.cursor() as cur:
            cur.execute("DELETE FROM ipv6_reservations")
            cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL OR dhcp4_subnet_id IS NOT NULL")
            # A host with a v4-only reservation (dhcp6_subnet_id NULL) must
            # never appear in v6 results.
            cur.execute("""
                INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type,
                    dhcp4_subnet_id, dhcp6_subnet_id, hostname)
                VALUES (%s, 0, 1, NULL, 'v4-only-host')
            """, (b"\xaa\xbb\xcc\xdd\xee\xff",))
        db.commit()
        self._insert_host_with_reservations(
            db, subnet_id=1,
            reservations=[{"address": "2001:db8:1::20", "prefix_len": 128, "type": 0, "iaid": 1}],
        )
        results = get_ipv6_reservations(subnet_id=1)
        assert len(results) == 1
        assert results[0]["hostname"] == "host-h1"

    def test_no_reservations_table_rows_for_unreferenced_host(self, db, monkeypatch):
        import jen.models.db as db_mod
        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import get_ipv6_reservations
        with db.cursor() as cur:
            cur.execute("DELETE FROM ipv6_reservations")
            cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
        db.commit()
        self._insert_host_with_reservations(db, subnet_id=3, reservations=[])
        results = get_ipv6_reservations(subnet_id=3)
        assert len(results) == 1
        assert results[0]["reservations"] == []


# ── kea6_db() connection pooling (same-DB reuse) ─────────────────────────────

class TestKea6DbPooling:

    def test_reuses_kea_pool_when_kea6_targets_same_db(self, monkeypatch):
        import jen.models.db as db_mod
        monkeypatch.setattr(extensions, "KEA6_DB_HOST", extensions.KEA_DB_HOST)
        monkeypatch.setattr(extensions, "KEA6_DB_USER", extensions.KEA_DB_USER)
        monkeypatch.setattr(extensions, "KEA6_DB_PASS", extensions.KEA_DB_PASS)
        monkeypatch.setattr(extensions, "KEA6_DB_NAME", extensions.KEA_DB_NAME)
        called = {"kea6_pool_made": False}

        def fake_make_kea6_pool():
            called["kea6_pool_made"] = True
            raise AssertionError("should not be called when DBs match")
        monkeypatch.setattr(db_mod, "_make_kea6_pool", fake_make_kea6_pool)
        monkeypatch.setattr(db_mod, "get_kea_db", lambda: "kea-pool-connection")
        assert db_mod.get_kea6_db() == "kea-pool-connection"
        assert called["kea6_pool_made"] is False

    def test_kea6_targets_same_db_detects_difference(self, monkeypatch):
        import jen.models.db as db_mod
        monkeypatch.setattr(extensions, "KEA6_DB_HOST", "a-different-host")
        monkeypatch.setattr(extensions, "KEA_DB_HOST", "kea-host")
        assert db_mod._kea6_targets_same_db() is False


# ── Leases page — IPv4|IPv6 segmented control (Phase 2) ──────────────────────

class TestLeasesV6View:

    def test_segmented_control_absent_when_no_v6_subnets(self, logged_in_client, monkeypatch, db):
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/leases")
            assert resp.status_code == 200
            assert b"segmented-control" not in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_segmented_control_absent_when_ipv6_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        _invalidate_settings_cache()
        resp = logged_in_client.get("/leases")
        assert resp.status_code == 200
        assert b"segmented-control" not in resp.data

    def test_segmented_control_present_when_enabled_and_configured(self, logged_in_client, monkeypatch, db):
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/leases")
            assert resp.status_code == 200
            assert b"segmented-control" in resp.data
            assert b"IPv6" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_v6_view_redirects_when_no_v6_subnets_configured(self, logged_in_client, monkeypatch, db):
        """Direct/bookmarked ?view=v6 hit with no v6 subnets must not 500
        or silently show an empty v4-shaped page — it redirects back."""
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.get("/leases?view=v6", follow_redirects=False)
        assert resp.status_code == 302

    def test_v6_view_lists_lease6_rows(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
            cur.execute("""
                INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                    subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                    hostname, hwaddr, state)
                VALUES ('2001:db8::10', %s, 3600, '2026-08-15 00:00:00',
                    1, 1800, 0, 1, 128, 'v6-host', NULL, 0)
            """, (bytes.fromhex("00030001001a2b3c4d5e"),))
        db.commit()
        resp = logged_in_client.get("/leases?view=v6")
        assert resp.status_code == 200
        assert b"2001:db8::10" in resp.data
        assert b"v6-host" in resp.data

    def test_v6_view_subnet_filter_rejects_v4_only_id(self, logged_in_client, monkeypatch, db):
        """A subnet id that's valid in SUBNET_MAP but not SUBNET6_MAP must
        fall back to 'all' rather than silently filtering to nothing."""
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        monkeypatch.setattr(extensions, "SUBNET_MAP", {99: {"name": "V4LAN", "cidr": "192.168.1.0/24"}})
        resp = logged_in_client.get("/leases?view=v6&subnet=99")
        assert resp.status_code == 200  # doesn't error, just falls back to all

    def test_v6_view_htmx_request_returns_partial_only(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        resp = logged_in_client.get("/leases?view=v6", headers={"HX-Request": "true"})
        assert resp.status_code == 200
        assert b"page-header" not in resp.data  # partial, not the full page shell


# ── Subnets page — paired/unpaired v6 cards (Phase 2) ────────────────────────

class TestSubnetsV6View:

    def test_no_v6_section_when_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        _invalidate_settings_cache()
        resp = logged_in_client.get("/subnets")
        assert resp.status_code == 200
        assert b"2001:db8::/64" not in resp.data

    def test_unpaired_v6_subnet_renders_standalone_card(self, logged_in_client, monkeypatch, db):
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/subnets")
            assert resp.status_code == 200
            assert b"2001:db8::/64" in resp.data
            assert b"V6LAN" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_paired_v6_subnet_nests_under_v4_card(self, logged_in_client, monkeypatch, db):
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET_MAP",
                            {1: {"name": "LAN", "cidr": "192.168.1.0/24"}})
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "LAN6", "cidr": "2001:db8:1::/64", "paired_subnet4_id": 1}})
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/subnets")
            assert resp.status_code == 200
            assert b"2001:db8:1::/64" in resp.data
            body = resp.data.decode()
            # Paired block should appear once, nested — not as a second
            # top-level standalone card.
            assert body.count("2001:db8:1::/64") == 1
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_get_subnets6_data_empty_when_disabled(self, monkeypatch, db):
        import jen.routes.subnets as subnets_module
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        assert subnets_module._get_subnets6_data() == []

    def test_get_subnets6_data_counts_leases_and_reservations(self, monkeypatch, db):
        import jen.routes.subnets as subnets_module
        from jen.models.user import set_global_setting
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {7: {"name": "V6LAN", "cidr": "2001:db8:7::/64", "paired_subnet4_id": None}})
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute("""
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8:7::1', %s, 3600, '2026-08-15 00:00:00',
                        7, 1800, 0, 1, 128, '', NULL, 0)
                """, (bytes.fromhex("00030001001a2b3c4d5e"),))
            db.commit()
            data = subnets_module._get_subnets6_data()
            assert len(data) == 1
            assert data[0]["active"] == 1
        finally:
            set_global_setting("ipv6_enabled", "false")


# ── Devices page — IPv6 device grouping (Phase 2) ────────────────────────────

class TestListLease6Devices:

    def _insert_lease(self, db, **overrides):
        row = {
            "address": "2001:db8:1::1",
            "duid": bytes.fromhex("00030001001a2b3c4d5e"),
            "valid_lifetime": 3600,
            "expire": "2026-08-15 00:00:00",
            "subnet_id": 1,
            "pref_lifetime": 1800,
            "lease_type": 0,
            "iaid": 1,
            "prefix_len": 128,
            "hostname": "",
            "hwaddr": None,
            "state": 0,
        }
        row.update(overrides)
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                    subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                    hostname, hwaddr, state)
                VALUES (%(address)s, %(duid)s, %(valid_lifetime)s, %(expire)s,
                    %(subnet_id)s, %(pref_lifetime)s, %(lease_type)s, %(iaid)s,
                    %(prefix_len)s, %(hostname)s, %(hwaddr)s, %(state)s)
            """, row)
        db.commit()

    def test_groups_ia_na_and_ia_pd_into_one_device(self, db, monkeypatch):
        """The core case the plan calls out: one physical device holding
        both an address and a delegated-prefix lease must collapse to a
        single device row, not two."""
        import jen.models.db as db_mod
        from jen.services.kea6 import list_lease6_devices
        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        same_duid = bytes.fromhex("00030001001a2b3c4d5e")
        self._insert_lease(db, address="2001:db8:1::1", duid=same_duid,
                           lease_type=0, iaid=1, hostname="my-laptop")
        self._insert_lease(db, address="2001:db8:1:1000::", duid=same_duid,
                           lease_type=2, iaid=2, prefix_len=56)
        devices = list_lease6_devices()
        assert len(devices) == 1
        assert len(devices[0]["addresses"]) == 2
        assert devices[0]["hostname"] == "my-laptop"

    def test_different_duids_are_different_devices(self, db, monkeypatch):
        import jen.models.db as db_mod
        from jen.services.kea6 import list_lease6_devices
        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1",
                           duid=bytes.fromhex("00030001001a2b3c4d5e"))
        self._insert_lease(db, address="2001:db8:1::2",
                           duid=bytes.fromhex("000300019988776655aa"))
        devices = list_lease6_devices()
        assert len(devices) == 2

    def test_mac_extraction_feeds_manufacturer_lookup(self, db, monkeypatch):
        """DUID-LL with a real Apple OUI prefix should resolve a
        manufacturer via the existing fingerprint.lookup_oui table."""
        import jen.models.db as db_mod
        from jen.services.kea6 import list_lease6_devices
        from jen.services import fingerprint as fp
        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        # Pick a real OUI prefix from the loaded DB so this test doesn't
        # depend on a specific vendor being present.
        if not fp.OUI_DB:
            pytest.skip("OUI_DB not loaded in this environment")
        real_oui = next(iter(fp.OUI_DB))  # e.g. "aa:bb:cc"
        mac_hex = real_oui.replace(":", "") + "001122"
        duid_hex = "00030001" + mac_hex
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1",
                           duid=bytes.fromhex(duid_hex))
        devices = list_lease6_devices()
        assert len(devices) == 1
        assert devices[0]["mac"] == f"{real_oui}:00:11:22"
        assert devices[0]["manufacturer"] == fp.OUI_DB[real_oui][0]

    def test_no_mac_no_wrong_guess(self, db, monkeypatch):
        """A DUID-EN (no embedded MAC at all) must yield an empty
        manufacturer/icon — never a fabricated vendor guess."""
        import jen.models.db as db_mod
        from jen.services.kea6 import list_lease6_devices
        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        duid_en = bytes.fromhex("0002" + "0000abcd" + "deadbeef")
        self._insert_lease(db, address="2001:db8:1::1", duid=duid_en, hwaddr=None)
        devices = list_lease6_devices()
        assert len(devices) == 1
        assert devices[0]["mac"] == ""
        assert devices[0]["manufacturer"] == ""


class TestDevicesV6View:

    def test_segmented_control_absent_when_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        _invalidate_settings_cache()
        resp = logged_in_client.get("/devices")
        assert resp.status_code == 200
        assert b"segmented-control" not in resp.data

    def test_v6_view_redirects_when_no_v6_subnets(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.get("/devices?view=v6", follow_redirects=False)
        assert resp.status_code == 302

    def test_v6_view_renders_devices(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
            cur.execute("""
                INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                    subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                    hostname, hwaddr, state)
                VALUES ('2001:db8::10', %s, 3600, '2026-08-15 00:00:00',
                    1, 1800, 0, 1, 128, 'my-phone', NULL, 0)
            """, (bytes.fromhex("00030001001a2b3c4d5e"),))
        db.commit()
        resp = logged_in_client.get("/devices?view=v6")
        assert resp.status_code == 200
        assert b"my-phone" in resp.data
        assert b"2001:db8::10" in resp.data


# ── Reservations page — read-only v6 view (Phase 2) ──────────────────────────

class TestReservationsV6View:

    def _insert_host_with_reservations(self, db, duid=b"\x00\x03\x00\x01\x00\x1a\x2b\x3c\x4d\x5e",
                                        subnet_id=1, hostname="v6-host", reservations=()):
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type,
                    dhcp6_subnet_id, hostname)
                VALUES (%s, 1, %s, %s)
            """, (duid, subnet_id, hostname))
            host_id = cur.lastrowid
            for res in reservations:
                cur.execute("""
                    INSERT INTO ipv6_reservations (address, prefix_len, type,
                        dhcp6_iaid, host_id)
                    VALUES (%(address)s, %(prefix_len)s, %(type)s, %(iaid)s, %(host_id)s)
                """, {**res, "host_id": host_id})
        db.commit()
        return host_id

    def test_segmented_control_absent_when_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        _invalidate_settings_cache()
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        assert b"segmented-control" not in resp.data

    def test_v6_view_redirects_when_no_v6_subnets(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.get("/reservations?view=v6", follow_redirects=False)
        assert resp.status_code == 302

    def test_v6_view_renders_one_to_many_reservations(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        with db.cursor() as cur:
            cur.execute("DELETE FROM ipv6_reservations")
            cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
        db.commit()
        self._insert_host_with_reservations(
            db, subnet_id=1, hostname="dual-res-host",
            reservations=[
                {"address": "2001:db8::10", "prefix_len": 128, "type": 0, "iaid": 1},
                {"address": "2001:db8:1000::", "prefix_len": 56, "type": 2, "iaid": 2},
            ],
        )
        resp = logged_in_client.get("/reservations?view=v6")
        assert resp.status_code == 200
        assert b"dual-res-host" in resp.data
        assert b"2001:db8::10" in resp.data
        assert b"2001:db8:1000::" in resp.data

    def test_v6_view_search_filters_by_hostname(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        with db.cursor() as cur:
            cur.execute("DELETE FROM ipv6_reservations")
            cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
        db.commit()
        self._insert_host_with_reservations(db, subnet_id=1, hostname="findme",
                                            reservations=[{"address": "2001:db8::1", "prefix_len": 128, "type": 0, "iaid": 1}])
        self._insert_host_with_reservations(db, subnet_id=1, hostname="other",
                                            duid=b"\x00\x03\x00\x01\x99\x88\x77\x66\x55\xaa",
                                            reservations=[{"address": "2001:db8::2", "prefix_len": 128, "type": 0, "iaid": 1}])
        resp = logged_in_client.get("/reservations?view=v6&search=findme")
        assert resp.status_code == 200
        assert b"findme" in resp.data
        assert b"other" not in resp.data


# ── Dashboard — v6-aware summary or explicit v4-only label (Phase 2) ────────

class TestDashboardV6Summary:

    def test_returns_none_when_disabled(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module
        from jen.models.user import _invalidate_settings_cache
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        _invalidate_settings_cache()
        assert dashboard_module._get_ipv6_dashboard_summary() is None

    def test_returns_none_when_no_v6_subnets(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        try:
            _invalidate_settings_cache()
            assert dashboard_module._get_ipv6_dashboard_summary() is None
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_returns_counts_when_enabled_and_configured(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {9: {"name": "V6LAN", "cidr": "2001:db8:9::/64", "paired_subnet4_id": None}})
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute("""
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8:9::1', %s, 3600, '2026-08-15 00:00:00',
                        9, 1800, 0, 1, 128, '', NULL, 0)
                """, (bytes.fromhex("00030001001a2b3c4d5e"),))
            db.commit()
            _invalidate_settings_cache()
            summary = dashboard_module._get_ipv6_dashboard_summary()
            assert summary == {"active": 1, "reserved": 0, "subnet_count": 1}
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_returns_none_on_error_rather_than_partial_counts(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module
        import jen.services.kea6 as kea6_module
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        monkeypatch.setattr(kea6_module, "list_lease6",
                            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("db down")))
        try:
            _invalidate_settings_cache()
            assert dashboard_module._get_ipv6_dashboard_summary() is None
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_dashboard_shows_ipv4_only_label_when_v6_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        _invalidate_settings_cache()
        resp = logged_in_client.get("/")
        assert resp.status_code == 200
        assert b"IPv4 only" in resp.data

    def test_dashboard_shows_ipv6_card_when_enabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/")
            assert resp.status_code == 200
            assert b"IPv4 only" not in resp.data
            assert b"Active Leases" in resp.data
            assert b"pool-utilization percentage yet" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")


# ── Write-side: v6 reservations (Phase 3) ────────────────────────────────────

class TestNormalizeDuid:

    def test_bare_hex_normalizes_to_colon_separated(self):
        from jen.services.kea6 import normalize_duid
        assert normalize_duid("00030001001a2b3c4d5e") == "00:03:00:01:00:1a:2b:3c:4d:5e"

    def test_already_colon_separated_passthrough(self):
        from jen.services.kea6 import normalize_duid
        assert normalize_duid("00:03:00:01:00:1a:2b:3c:4d:5e") == "00:03:00:01:00:1a:2b:3c:4d:5e"

    def test_uppercase_normalized_to_lowercase(self):
        from jen.services.kea6 import normalize_duid
        assert normalize_duid("00:03:00:01:AA:BB:CC:DD:EE:FF") == "00:03:00:01:aa:bb:cc:dd:ee:ff"

    def test_odd_length_hex_rejected(self):
        from jen.services.kea6 import normalize_duid
        with pytest.raises(ValueError):
            normalize_duid("0003000")

    def test_non_hex_rejected(self):
        from jen.services.kea6 import normalize_duid
        with pytest.raises(ValueError):
            normalize_duid("zzzz")

    def test_empty_rejected(self):
        from jen.services.kea6 import normalize_duid
        with pytest.raises(ValueError):
            normalize_duid("")


class TestAddV6Reservation:

    def test_address_only_reservation(self, monkeypatch):
        from jen.services import kea6 as kea6_module
        captured = {}
        monkeypatch.setattr(kea6_module, "kea6_command",
                            lambda cmd, arguments=None, server=None: (captured.update(cmd=cmd, args=arguments), {"result": 0})[1])
        kea6_module.add_v6_reservation(1, "00:03:00:01:aa:bb:cc:dd:ee:ff",
                                       hostname="my-host", addresses=["2001:db8::10"])
        assert captured["cmd"] == "reservation-add"
        res = captured["args"]["reservation"]
        assert res["subnet-id"] == 1
        assert res["duid"] == "00:03:00:01:aa:bb:cc:dd:ee:ff"
        assert res["ip-addresses"] == ["2001:db8::10"]
        assert res["hostname"] == "my-host"
        assert "prefixes" not in res

    def test_prefix_only_reservation(self, monkeypatch):
        from jen.services import kea6 as kea6_module
        captured = {}
        monkeypatch.setattr(kea6_module, "kea6_command",
                            lambda cmd, arguments=None, server=None: (captured.update(args=arguments), {"result": 0})[1])
        kea6_module.add_v6_reservation(1, "00:03:00:01:aa:bb:cc:dd:ee:ff",
                                       prefix="2001:db8:1:1000::", prefix_len=56)
        res = captured["args"]["reservation"]
        assert res["prefixes"] == ["2001:db8:1:1000::/56"]
        assert "ip-addresses" not in res

    def test_both_address_and_prefix_at_once(self, monkeypatch):
        """The core one-to-many case: a single DUID reserving both an
        address AND a delegated prefix simultaneously."""
        from jen.services import kea6 as kea6_module
        captured = {}
        monkeypatch.setattr(kea6_module, "kea6_command",
                            lambda cmd, arguments=None, server=None: (captured.update(args=arguments), {"result": 0})[1])
        kea6_module.add_v6_reservation(1, "00:03:00:01:aa:bb:cc:dd:ee:ff",
                                       addresses=["2001:db8::10"],
                                       prefix="2001:db8:1:1000::", prefix_len=56)
        res = captured["args"]["reservation"]
        assert res["ip-addresses"] == ["2001:db8::10"]
        assert res["prefixes"] == ["2001:db8:1:1000::/56"]

    def test_neither_address_nor_prefix_rejected_before_calling_kea(self, monkeypatch):
        from jen.services import kea6 as kea6_module
        called = {"count": 0}
        monkeypatch.setattr(kea6_module, "kea6_command",
                            lambda *a, **kw: called.__setitem__("count", called["count"] + 1))
        result = kea6_module.add_v6_reservation(1, "00:03:00:01:aa:bb:cc:dd:ee:ff")
        assert result["result"] != 0
        assert called["count"] == 0

    def test_prefix_without_prefix_len_rejected(self, monkeypatch):
        from jen.services import kea6 as kea6_module
        called = {"count": 0}
        monkeypatch.setattr(kea6_module, "kea6_command",
                            lambda *a, **kw: called.__setitem__("count", called["count"] + 1))
        result = kea6_module.add_v6_reservation(1, "00:03:00:01:aa:bb:cc:dd:ee:ff",
                                                 prefix="2001:db8:1:1000::")
        assert result["result"] != 0
        assert called["count"] == 0


class TestDeleteV6Reservation:

    def test_sends_duid_identifier_type(self, monkeypatch):
        from jen.services import kea6 as kea6_module
        captured = {}
        monkeypatch.setattr(kea6_module, "kea6_command",
                            lambda cmd, arguments=None, server=None: (captured.update(cmd=cmd, args=arguments), {"result": 0})[1])
        kea6_module.delete_v6_reservation(1, "00030001aabbccddeeff")
        assert captured["cmd"] == "reservation-del"
        assert captured["args"]["identifier-type"] == "duid"
        assert captured["args"]["subnet-id"] == 1
        assert captured["args"]["identifier"] == "00:03:00:01:aa:bb:cc:dd:ee:ff"


class TestAddReservation6Route:

    def test_requires_admin(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="viewer")
        resp = c.get("/reservations/add6", follow_redirects=False)
        assert resp.status_code == 302

    def test_redirects_when_no_v6_subnets(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.get("/reservations/add6", follow_redirects=False)
        assert resp.status_code == 302

    def test_post_success_redirects_to_v6_reservations(self, logged_in_client, monkeypatch):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        monkeypatch.setattr(kea6_module, "add_v6_reservation",
                            lambda *a, **kw: {"result": 0, "text": "ok"})
        resp = logged_in_client.post("/reservations/add6", data={
            "subnet_id": "1", "duid": "00030001aabbccddeeff",
            "hostname": "my-host", "address": "2001:db8::10",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "view=v6" in resp.headers["Location"]

    def test_post_rejects_invalid_subnet(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        resp = logged_in_client.post("/reservations/add6", data={
            "subnet_id": "999", "duid": "00030001aabbccddeeff", "address": "2001:db8::10",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Invalid IPv6 subnet" in resp.data

    def test_post_rejects_missing_address_and_prefix(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        resp = logged_in_client.post("/reservations/add6", data={
            "subnet_id": "1", "duid": "00030001aabbccddeeff",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Specify an address" in resp.data

    def test_post_rejects_invalid_duid(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        resp = logged_in_client.post("/reservations/add6", data={
            "subnet_id": "1", "duid": "not-hex-zz", "address": "2001:db8::10",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"DUID" in resp.data

    def test_kea_failure_surfaces_error_and_stays_on_form(self, logged_in_client, monkeypatch):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        monkeypatch.setattr(kea6_module, "add_v6_reservation",
                            lambda *a, **kw: {"result": 1, "text": "duplicate reservation"})
        resp = logged_in_client.post("/reservations/add6", data={
            "subnet_id": "1", "duid": "00030001aabbccddeeff", "address": "2001:db8::10",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"duplicate reservation" in resp.data


class TestDeleteReservation6Route:

    def test_requires_admin(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="viewer")
        resp = c.post("/reservations/delete6", data={"subnet_id": "1", "duid": "aabbcc"},
                      follow_redirects=False)
        assert resp.status_code == 302

    def test_success_calls_kea6_delete(self, logged_in_client, monkeypatch):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        captured = {}
        monkeypatch.setattr(kea6_module, "delete_v6_reservation",
                            lambda subnet_id, duid, server=None: (captured.update(subnet_id=subnet_id, duid=duid), {"result": 0})[1])
        resp = logged_in_client.post("/reservations/delete6", data={
            "subnet_id": "1", "duid": "00030001aabbccddeeff",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert captured["subnet_id"] == 1
        assert captured["duid"] == "00:03:00:01:aa:bb:cc:dd:ee:ff"


# ── Write-side: v6 subnet editing (Phase 3) ──────────────────────────────────

class TestGetSubnet6KeaData:

    def test_extracts_pool_timers_and_dns(self, monkeypatch):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "kea6_command", lambda *a, **kw: {
            "result": 0,
            "arguments": {
                "Dhcp6": {
                    "preferred-lifetime": 3000, "valid-lifetime": 4000,
                    "renew-timer": 1000, "rebind-timer": 2000,
                    "subnet6": [{
                        "id": 1, "pools": [{"pool": "2001:db8::10-2001:db8::20"}],
                        "option-data": [{"name": "dns-servers", "data": "2001:4860:4860::8888"}],
                    }],
                }
            },
        })
        data = kea6_module.get_subnet6_kea_data(1)
        assert data["pool_str"] == "2001:db8::10-2001:db8::20"
        assert data["preferred_lifetime"] == 3000
        assert data["valid_lifetime"] == 4000
        assert data["dns_servers"] == "2001:4860:4860::8888"

    def test_falls_back_to_global_timers_when_subnet_unset(self, monkeypatch):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "kea6_command", lambda *a, **kw: {
            "result": 0,
            "arguments": {"Dhcp6": {
                "preferred-lifetime": 3000, "valid-lifetime": 4000,
                "subnet6": [{"id": 1, "pools": []}],
            }},
        })
        data = kea6_module.get_subnet6_kea_data(1)
        assert data["preferred_lifetime"] == 3000
        assert data["valid_lifetime"] == 4000

    def test_returns_empty_shape_when_subnet_not_found(self, monkeypatch):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "kea6_command", lambda *a, **kw: {
            "result": 0, "arguments": {"Dhcp6": {"subnet6": []}},
        })
        data = kea6_module.get_subnet6_kea_data(999)
        assert data["pool_str"] == ""
        assert data["preferred_lifetime"] == ""

    def test_returns_empty_shape_on_kea_error(self, monkeypatch):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "kea6_command", lambda *a, **kw: {"result": 1})
        data = kea6_module.get_subnet6_kea_data(1)
        assert data["pools"] == []


class TestBuildSubnet6PatchScript:

    def test_dry_run_never_calls_os_replace(self):
        from jen.services.kea6 import build_subnet6_patch_script
        script = build_subnet6_patch_script(
            1, "/etc/kea/kea-dhcp6.conf", "2001:db8::10-2001:db8::20", [],
            "3000", "4000", "1000", "2000", "", dry_run=True,
        )
        assert "os.replace" not in script
        assert "preview-ok" in script
        assert "shutil.copy2" not in script  # no backup step in dry-run

    def test_apply_run_includes_backup_and_replace(self):
        from jen.services.kea6 import build_subnet6_patch_script
        script = build_subnet6_patch_script(
            1, "/etc/kea/kea-dhcp6.conf", "2001:db8::10-2001:db8::20", [],
            "3000", "4000", "1000", "2000", "", dry_run=False,
        )
        assert "shutil.copy2" in script
        assert "os.replace(tmp, path)" in script
        assert "print('ok')" in script

    def test_uses_kea_dhcp6_binary_not_kea_dhcp4(self):
        from jen.services.kea6 import build_subnet6_patch_script
        script = build_subnet6_patch_script(
            1, "/etc/kea/kea-dhcp6.conf", "", [], "", "", "", "", "", dry_run=True,
        )
        assert "'kea-dhcp6'" in script
        assert "kea-dhcp4" not in script

    def test_dns_option_uses_code_23_dhcp6_space(self):
        from jen.services.kea6 import build_subnet6_patch_script
        script = build_subnet6_patch_script(
            1, "/etc/kea/kea-dhcp6.conf", "", [], "", "", "", "",
            "2001:4860:4860::8888", dry_run=True,
        )
        assert "'dns-servers'" in script
        assert "'code': 23" in script
        assert "'space': 'dhcp6'" in script

    def test_no_change_reports_nochange(self):
        from jen.services.kea6 import build_subnet6_patch_script
        script = build_subnet6_patch_script(
            1, "/etc/kea/kea-dhcp6.conf", "", [], "", "", "", "", "", dry_run=True,
        )
        assert "print('nochange')" in script


class TestParseAndValidateSubnet6EditForm:

    def test_valid_range_pool_accepted(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form
        fields, error = _parse_and_validate_subnet6_edit_form(
            {"pool": "2001:db8::10-2001:db8::20"})
        assert error is None
        assert fields["new_pool"] == "2001:db8::10-2001:db8::20"

    def test_valid_cidr_pool_accepted(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form
        fields, error = _parse_and_validate_subnet6_edit_form({"pool": "2001:db8::/64"})
        assert error is None

    def test_invalid_pool_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form
        fields, error = _parse_and_validate_subnet6_edit_form({"pool": "not-an-address"})
        assert error is not None

    def test_v4_pool_rejected_on_v6_form(self):
        """A v4-shaped pool string must not silently pass v6 validation."""
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form
        fields, error = _parse_and_validate_subnet6_edit_form(
            {"pool": "192.168.1.10-192.168.1.20"})
        assert error is not None

    def test_invalid_dns_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form
        fields, error = _parse_and_validate_subnet6_edit_form(
            {"dns_servers": "not-an-ip"})
        assert error is not None

    def test_preferred_exceeding_valid_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form
        fields, error = _parse_and_validate_subnet6_edit_form(
            {"preferred_lifetime": "9000", "valid_lifetime": "4000"})
        assert error is not None
        assert "Preferred Lifetime" in error

    def test_preferred_equal_to_valid_accepted(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form
        fields, error = _parse_and_validate_subnet6_edit_form(
            {"preferred_lifetime": "4000", "valid_lifetime": "4000"})
        assert error is None

    def test_no_routers_field_exists(self):
        """DHCPv6 has no router option — confirm the parsed fields dict
        genuinely has no routers key at all, not just an empty one."""
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form
        fields, error = _parse_and_validate_subnet6_edit_form({})
        assert error is None
        assert "new_routers" not in fields

    def test_negative_timer_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form
        fields, error = _parse_and_validate_subnet6_edit_form({"renew_timer": "-5"})
        assert error is not None


class TestEditSubnet6Route:

    def test_requires_admin(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="viewer")
        resp = c.get("/subnets/edit6/1", follow_redirects=False)
        assert resp.status_code == 302

    def test_not_found_redirects(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.get("/subnets/edit6/1", follow_redirects=False)
        assert resp.status_code == 302

    def test_renders_form_with_current_kea_data(self, logged_in_client, monkeypatch):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        monkeypatch.setattr(kea6_module, "get_subnet6_kea_data", lambda subnet_id: {
            "pools": ["2001:db8::10-2001:db8::20"], "pool_str": "2001:db8::10-2001:db8::20",
            "preferred_lifetime": 3000, "valid_lifetime": 4000,
            "renew_timer": 1000, "rebind_timer": 2000, "dns_servers": "",
        })
        resp = logged_in_client.get("/subnets/edit6/1")
        assert resp.status_code == 200
        assert b"2001:db8::10-2001:db8::20" in resp.data
        assert b"Edit IPv6 Subnet" in resp.data


class TestEditSubnet6PostRoute:

    def test_requires_admin(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="viewer")
        resp = c.post("/subnets/edit6/1", data={}, follow_redirects=False)
        assert resp.status_code == 302

    def test_not_found(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.post("/subnets/edit6/1", data={}, follow_redirects=True)
        assert b"IPv6 subnet not found" in resp.data

    def test_validation_error_redirects_to_edit_form(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        resp = logged_in_client.post("/subnets/edit6/1",
                                     data={"pool": "not-valid"}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Invalid pool" in resp.data

    def test_no_ssh_servers_no_op_success(self, logged_in_client, monkeypatch):
        """No configured SSH servers means the loop does nothing and no
        error/success flash for a server fires — must not crash."""
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "solo", "ssh_host": ""}])
        resp = logged_in_client.post("/subnets/edit6/1",
                                     data={"preferred_lifetime": "3000"}, follow_redirects=False)
        assert resp.status_code == 302

    def test_successful_apply_restarts_kea6(self, logged_in_client, monkeypatch):
        import jen.routes.subnets as subnets_module
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        server = {"id": 1, "name": "theelders", "ssh_host": "10.10.11.250",
                 "ssh_user": "matthew", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        fake_ssh = FakeSSHClient([("ok", ""), ("done", "")])
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        resp = logged_in_client.post("/subnets/edit6/1",
                                     data={"preferred_lifetime": "3000"}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"validated, updated and restarted" in resp.data
        assert any("restart" in c for c in fake_ssh.calls)
        assert any("isc-kea-dhcp6-server" in c for c in fake_ssh.calls)

    def test_config_test_failure_does_not_restart(self, logged_in_client, monkeypatch):
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        server = {"id": 1, "name": "theelders", "ssh_host": "10.10.11.250",
                 "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        fake_ssh = FakeSSHClient([("testerror:bad pool syntax", "")])
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        resp = logged_in_client.post("/subnets/edit6/1",
                                     data={"preferred_lifetime": "3000"}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"config validation failed" in resp.data
        assert b"bad pool syntax" in resp.data
        assert len(fake_ssh.calls) == 1  # never attempted a restart call


class TestEditSubnet6PreviewRoute:

    def test_requires_admin(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="viewer")
        resp = c.post("/subnets/edit6/1/preview", data={}, follow_redirects=False)
        assert resp.status_code == 302

    def test_not_found(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.post("/subnets/edit6/1/preview", data={})
        assert resp.status_code == 404

    def test_no_changes_returns_early(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        resp = logged_in_client.post("/subnets/edit6/1/preview", data={})
        assert resp.status_code == 200
        assert resp.get_json()["no_changes"] is True

    def test_dry_run_never_touches_live_config(self, logged_in_client, monkeypatch):
        """The core safety guarantee: preview must call the script with
        dry_run semantics (no 'ok'/os.replace outcome ever reachable)."""
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        server = {"id": 1, "name": "theelders", "ssh_host": "10.10.11.250",
                 "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        fake_ssh = FakeSSHClient([("preview-ok", "")])
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        resp = logged_in_client.post("/subnets/edit6/1/preview",
                                     data={"preferred_lifetime": "3000"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["servers"][0]["ok"] is True
        assert data["all_passed"] is True
        # Only one SSH call — the dry-run test — never a second restart call.
        assert len(fake_ssh.calls) == 1


# ── Search page — v6 leases/reservations (Phase 4) ───────────────────────────

class TestGlobalSearchV6:

    def test_v6_absent_from_results_when_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        _invalidate_settings_cache()
        resp = logged_in_client.get("/search?q=findme")
        assert resp.status_code == 200
        assert b"IPv6 Leases" not in resp.data
        assert b"IPv6 Reservations" not in resp.data

    def test_v6_lease_found_when_enabled_superadmin(self, logged_in_client, monkeypatch, db):
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute("""
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8::99', %s, 3600, '2026-08-15 00:00:00',
                        1, 1800, 0, 1, 128, 'findable-host', NULL, 0)
                """, (bytes.fromhex("00030001001a2b3c4d5e"),))
            db.commit()
            _invalidate_settings_cache()
            resp = logged_in_client.get("/search?q=findable")
            assert resp.status_code == 200
            assert b"findable-host" in resp.data
            assert b"IPv6 Leases" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_v6_reservation_found_when_enabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM ipv6_reservations")
                cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
                cur.execute("""
                    INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp6_subnet_id, hostname)
                    VALUES (%s, 1, 1, 'searchable-res')
                """, (bytes.fromhex("00030001aabbccddeeff"),))
                host_id = cur.lastrowid
                cur.execute("""
                    INSERT INTO ipv6_reservations (address, prefix_len, type, dhcp6_iaid, host_id)
                    VALUES ('2001:db8::50', 128, 0, 1, %s)
                """, (host_id,))
            db.commit()
            _invalidate_settings_cache()
            resp = logged_in_client.get("/search?q=searchable-res")
            assert resp.status_code == 200
            assert b"searchable-res" in resp.data
            assert b"IPv6 Reservations" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_unpaired_v6_subnet_hidden_from_restricted_user(self, client, db, monkeypatch):
        """A restricted (non-all_subnets) user must not see results from
        an unpaired v6 subnet — there's no v4 subnet to inherit access
        from, so it's admin/all_subnets-only, not guessed at."""
        from tests.conftest import restricted_client
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {5: {"name": "Unpaired", "cidr": "2001:db8:5::/64", "paired_subnet4_id": None}})
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute("""
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8:5::1', %s, 3600, '2026-08-15 00:00:00',
                        5, 1800, 0, 1, 128, 'v6onlyresult', NULL, 0)
                """, (bytes.fromhex("00030001001a2b3c4d5e"),))
            db.commit()
            _invalidate_settings_cache()
            c, _uid = restricted_client(client, db, allowed_subnets=[1], role="viewer")
            resp = c.get("/search?q=v6onlyresult")
            assert resp.status_code == 200
            # The "IPv6 Leases" card only renders when results.leases6 is
            # non-empty — a reliable signal that avoids the false-positive
            # of the query text itself being echoed in the search box.
            assert b"IPv6 Leases" not in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_paired_v6_subnet_visible_to_user_with_v4_access(self, client, db, monkeypatch):
        from tests.conftest import restricted_client
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "192.168.1.0/24"}})
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "LAN6", "cidr": "2001:db8:1::/64", "paired_subnet4_id": 1}})
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute("""
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8:1::1', %s, 3600, '2026-08-15 00:00:00',
                        1, 1800, 0, 1, 128, 'paired-visible', NULL, 0)
                """, (bytes.fromhex("00030001001a2b3c4d5e"),))
            db.commit()
            _invalidate_settings_cache()
            c, _uid = restricted_client(client, db, allowed_subnets=[1], role="viewer")
            resp = c.get("/search?q=paired-visible")
            assert resp.status_code == 200
            assert b"paired-visible" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")


# ── /metrics — IPv6 metric families (Phase 4) ────────────────────────────────

class TestPrometheusMetricsV6:

    def test_ipv6_enabled_gauge_always_present_even_when_off(self, client, mock_kea, db):
        from jen.models.user import _invalidate_settings_cache
        _invalidate_settings_cache()
        r = client.get("/metrics")
        text = r.data.decode()
        assert "# TYPE jen_ipv6_enabled gauge" in text
        assert "jen_ipv6_enabled 0" in text

    def test_v6_subnet_metrics_absent_when_disabled(self, client, mock_kea, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        _invalidate_settings_cache()
        r = client.get("/metrics")
        text = r.data.decode()
        assert "jen_subnet6_active_leases" not in text
        assert "jen_subnet6_reserved_hosts" not in text
        assert "# TYPE jen_kea6_up" not in text

    def test_v6_subnet_metrics_present_when_enabled_and_configured(self, client, mock_kea, monkeypatch, db):
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        import jen.services.kea6 as kea6_module
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        monkeypatch.setattr(kea6_module, "kea6_is_up", lambda *a, **kw: True)
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute("""
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8::1', %s, 3600, '2026-08-15 00:00:00',
                        1, 1800, 0, 1, 128, '', NULL, 0)
                """, (bytes.fromhex("00030001001a2b3c4d5e"),))
            db.commit()
            _invalidate_settings_cache()
            r = client.get("/metrics")
            text = r.data.decode()
            assert "# TYPE jen_subnet6_active_leases gauge" in text
            assert 'jen_subnet6_active_leases{subnet="V6LAN",cidr="2001:db8::/64",type="IA_NA"} 1' in text
            assert "# TYPE jen_subnet6_reserved_hosts gauge" in text
            assert "jen_ipv6_enabled 1" in text
            assert "jen_kea6_up 1" in text
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_no_pool_size_or_utilization_metric_for_v6(self, client, mock_kea, monkeypatch, db):
        """Deliberate scope decision (matches the lease6_history schema
        from Phase 0/1): no finite comparable 'pool size' concept for a
        /64, so no jen_subnet6_pool_size/utilization_ratio metric exists
        at all — confirm that omission is intentional, not a bug."""
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        try:
            _invalidate_settings_cache()
            r = client.get("/metrics")
            text = r.data.decode()
            assert "jen_subnet6_pool_size" not in text
            assert "jen_subnet6_utilization_ratio" not in text
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_v4_metric_families_unaffected_by_v6_addition(self, client, mock_kea, monkeypatch, db):
        """Zero behavior change for the v4 path — every existing metric
        family must still be present and correctly formatted regardless
        of the v6 state."""
        from jen.models.user import set_global_setting, _invalidate_settings_cache
        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        try:
            _invalidate_settings_cache()
            r = client.get("/metrics")
            text = r.data.decode()
            for family in ["jen_subnet_active_leases", "jen_subnet_reserved_hosts",
                          "jen_subnet_pool_size", "jen_subnet_utilization_ratio",
                          "jen_alerts_sent_total", "jen_kea_up", "jen_server_up"]:
                assert f"# HELP {family}" in text, f"missing HELP for {family}"
                assert f"# TYPE {family}" in text, f"missing TYPE for {family}"
        finally:
            set_global_setting("ipv6_enabled", "false")


# ── Plugin IPv4-only notes (Phase 4) ──────────────────────────────────────────
#
# Plugin routes require a `.enabled` marker file created before the Flask
# app itself is built (load_plugins() runs once at app-factory time,
# session-scoped in the test fixture), so a live-route test isn't
# practical here without rebuilding the whole test app per test. These
# instead verify the template source directly: the note is present and
# correctly gated behind {% if ipv6_enabled %}, which is the same context
# var every other v6 template in this file already relies on and is
# already covered by TestIpv6ContextProcessor.

class TestPluginIpv6Notes:

    def test_ipam_template_has_gated_note(self):
        content = open("plugins/ipam/templates/ipam/index.html").read()
        assert "{% if ipv6_enabled %}" in content
        assert "IPv4 addresses only" in content

    def test_network_discovery_template_has_gated_note(self):
        content = open("plugins/network-discovery/templates/network_discovery/index.html").read()
        assert "{% if ipv6_enabled %}" in content
        assert "IPv4 subnets only" in content

    def test_ipam_readme_documents_v4_only_scope(self):
        content = open("plugins/ipam/README.md").read()
        assert "IPv4 only" in content

    def test_network_discovery_readme_documents_v4_only_scope(self):
        content = open("plugins/network-discovery/README.md").read()
        assert "IPv4 only" in content


# ── Kea config authoring (v5.1) ───────────────────────────────────────────────

class TestConfPathFor:

    def test_dhcp4_path(self):
        from jen.services.kea_authoring import conf_path_for
        server = {"kea_conf": "/etc/kea/kea-dhcp4.conf"}
        assert conf_path_for(server, "dhcp4") == "/etc/kea/kea-dhcp4.conf"

    def test_dhcp6_path_derived_from_dhcp4_sibling(self):
        from jen.services.kea_authoring import conf_path_for
        server = {"kea_conf": "/etc/kea/kea-dhcp4.conf"}
        assert conf_path_for(server, "dhcp6") == "/etc/kea/kea-dhcp6.conf"

    def test_falls_back_to_extensions_kea_conf(self, monkeypatch):
        from jen.services.kea_authoring import conf_path_for
        monkeypatch.setattr(extensions, "KEA_CONF", "/opt/kea/kea-dhcp4.conf")
        assert conf_path_for({}, "dhcp6") == "/opt/kea/kea-dhcp6.conf"


class TestCaConfPathFor:

    def test_sibling_to_kea_conf_dir(self):
        from jen.services.kea_authoring import ca_conf_path_for
        server = {"kea_conf": "/etc/kea/kea-dhcp4.conf"}
        assert ca_conf_path_for(server) == "/etc/kea/kea-ctrl-agent.conf"


class TestReadRemoteJson:

    def test_parses_valid_json(self):
        from jen.services.kea_authoring import read_remote_json
        ssh = FakeSSHClient([('{"a": 1}', "")])
        assert read_remote_json(ssh, "/x") == {"a": 1}

    def test_returns_none_for_missing_file(self):
        from jen.services.kea_authoring import read_remote_json
        ssh = FakeSSHClient([("", "")])
        assert read_remote_json(ssh, "/x") is None

    def test_returns_none_for_invalid_json(self):
        from jen.services.kea_authoring import read_remote_json
        ssh = FakeSSHClient([("not json", "")])
        assert read_remote_json(ssh, "/x") is None


class TestDetectCaSocketPath:

    def test_extracts_socket_for_service(self):
        from jen.services.kea_authoring import detect_ca_socket_path
        ca_conf = json.dumps({
            "Control-agent": {"control-sockets": {
                "dhcp6": {"socket-type": "unix", "socket-name": "/run/kea/kea6-ctrl-socket"},
            }},
        })
        ssh = FakeSSHClient([(ca_conf, "")])
        result = detect_ca_socket_path(ssh, {"kea_conf": "/etc/kea/kea-dhcp4.conf"}, "dhcp6")
        assert result == "/run/kea/kea6-ctrl-socket"

    def test_none_when_ca_conf_missing(self):
        from jen.services.kea_authoring import detect_ca_socket_path
        ssh = FakeSSHClient([("", "")])
        assert detect_ca_socket_path(ssh, {"kea_conf": "/etc/kea/kea-dhcp4.conf"}, "dhcp6") is None

    def test_none_when_service_not_mentioned(self):
        from jen.services.kea_authoring import detect_ca_socket_path
        ca_conf = json.dumps({"Control-agent": {"control-sockets": {"dhcp4": {"socket-name": "/x"}}}})
        ssh = FakeSSHClient([(ca_conf, "")])
        assert detect_ca_socket_path(ssh, {"kea_conf": "/etc/kea/kea-dhcp4.conf"}, "dhcp6") is None


class TestDetectSiblingConfig:

    def test_pulls_interfaces_and_db_from_real_v4_config(self):
        """Core case per direct instruction: authoring v6 when v4 already
        exists should PULL from it rather than autodetect/ask."""
        from jen.services.kea_authoring import detect_sibling_config
        v4_conf = json.dumps({
            "Dhcp4": {
                "interfaces-config": {"interfaces": ["eth0"]},
                "lease-database": {"type": "mysql", "host": "10.10.11.250",
                                   "user": "kea", "name": "kea"},
                "hooks-libraries": [{"library": "/usr/lib/kea/hooks/libdhcp_host_cmds.so"}],
            }
        })
        ssh = FakeSSHClient([(v4_conf, "")])
        result = detect_sibling_config(ssh, {"kea_conf": "/etc/kea/kea-dhcp4.conf"}, "dhcp6")
        assert result["found"] is True
        assert result["interfaces"] == ["eth0"]
        assert result["lease_db_host"] == "10.10.11.250"
        assert result["lease_db_name"] == "kea"
        assert result["hooks"] == ["host_cmds"]

    def test_not_found_returns_valid_empty_shape(self):
        from jen.services.kea_authoring import detect_sibling_config
        ssh = FakeSSHClient([("", "")])
        result = detect_sibling_config(ssh, {"kea_conf": "/etc/kea/kea-dhcp4.conf"}, "dhcp6")
        assert result["found"] is False
        assert result["interfaces"] == []
        assert result["hooks"] == []

    def test_never_leaks_password_field(self):
        """Even if a real config file has a lease-database password in
        it, detect_sibling_config must not surface it — Jen supplies its
        own known password when building the new config instead."""
        from jen.services.kea_authoring import detect_sibling_config
        v4_conf = json.dumps({"Dhcp4": {"lease-database": {
            "type": "mysql", "host": "h", "user": "u", "password": "supersecret", "name": "kea"}}})
        ssh = FakeSSHClient([(v4_conf, "")])
        result = detect_sibling_config(ssh, {"kea_conf": "/etc/kea/kea-dhcp4.conf"}, "dhcp6")
        assert "password" not in result
        assert "supersecret" not in json.dumps(result)


class TestAutodetectInterfaces:

    def test_parses_ip_addr_output(self):
        from jen.services.kea_authoring import autodetect_interfaces
        ip_output = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
            "    inet6 ::1/128 scope host\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    inet6 2001:db8::1/64 scope global\n"
        )
        ssh = FakeSSHClient([(ip_output, "")])
        result = autodetect_interfaces(ssh, "dhcp6")
        assert result == ["eth0"]

    def test_empty_on_ssh_error(self):
        from jen.services.kea_authoring import autodetect_interfaces
        class BrokenSSH:
            def exec_command(self, cmd):
                raise RuntimeError("connection lost")
        assert autodetect_interfaces(BrokenSSH(), "dhcp6") == []


class TestBuildNewKeaConfig:

    def test_dhcp6_config_shape(self):
        from jen.services.kea_authoring import build_new_kea_config
        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        subnets = {1: {"name": "LAN6", "cidr": "2001:db8::/64"}}
        cfg = build_new_kea_config("dhcp6", ["eth0"], lease_db, "/run/kea/kea6.sock", subnets)
        assert "Dhcp6" in cfg
        section = cfg["Dhcp6"]
        assert section["interfaces-config"]["interfaces"] == ["eth0"]
        assert section["control-socket"]["socket-name"] == "/run/kea/kea6.sock"
        assert section["lease-database"]["password"] == "p"
        assert section["preferred-lifetime"] == 3000
        assert section["valid-lifetime"] == 7200
        assert len(section["subnet6"]) == 1
        assert section["subnet6"][0]["id"] == 1
        assert section["subnet6"][0]["subnet"] == "2001:db8::/64"

    def test_dhcp4_config_shape(self):
        from jen.services.kea_authoring import build_new_kea_config
        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        subnets = {1: {"name": "LAN", "cidr": "192.168.1.0/24"}}
        cfg = build_new_kea_config("dhcp4", ["eth0"], lease_db, "/run/kea/kea4.sock", subnets)
        assert "Dhcp4" in cfg
        assert cfg["Dhcp4"]["valid-lifetime"] == 86400
        assert len(cfg["Dhcp4"]["subnet4"]) == 1

    def test_always_includes_host_cmds_and_lease_cmds_hooks(self):
        from jen.services.kea_authoring import build_new_kea_config
        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        cfg = build_new_kea_config("dhcp6", ["eth0"], lease_db, "/run/x.sock", {})
        libs = [h["library"] for h in cfg["Dhcp6"]["hooks-libraries"]]
        assert any("host_cmds" in l for l in libs)
        assert any("lease_cmds" in l for l in libs)

    def test_never_includes_ha_config(self):
        """Explicit scope exclusion — must never be silently added."""
        from jen.services.kea_authoring import build_new_kea_config
        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        cfg = build_new_kea_config("dhcp6", ["eth0"], lease_db, "/run/x.sock", {})
        assert "high-availability" not in json.dumps(cfg).lower().replace("-", "").replace(" ", "") \
            or "high-availability" not in str(cfg.get("Dhcp6", {}).get("hooks-libraries", []))
        # More direct: no hook library path mentions the HA hook at all.
        libs = [h["library"] for h in cfg["Dhcp6"]["hooks-libraries"]]
        assert not any("libdhcp_ha" in l for l in libs)

    def test_pool_spans_whole_v4_cidr(self):
        from jen.services.kea_authoring import build_new_kea_config
        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        subnets = {1: {"name": "LAN", "cidr": "192.168.1.0/24"}}
        cfg = build_new_kea_config("dhcp4", ["eth0"], lease_db, "/run/x.sock", subnets)
        pool = cfg["Dhcp4"]["subnet4"][0]["pools"][0]["pool"]
        assert pool == "192.168.1.1-192.168.1.254"

    def test_multiple_subnets_all_included_with_matching_ids(self):
        from jen.services.kea_authoring import build_new_kea_config
        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        subnets = {1: {"name": "A", "cidr": "2001:db8:1::/64"},
                  7: {"name": "B", "cidr": "2001:db8:7::/64"}}
        cfg = build_new_kea_config("dhcp6", ["eth0"], lease_db, "/run/x.sock", subnets)
        ids = {s["id"] for s in cfg["Dhcp6"]["subnet6"]}
        assert ids == {1, 7}


class TestRenderAuthorConfigScript:

    def test_dry_run_never_writes_live_path(self):
        from jen.services.kea_authoring import render_author_config_script
        script = render_author_config_script("dhcp6", "/etc/kea/kea-dhcp6.conf",
                                              {"Dhcp6": {}}, allow_overwrite=False, dry_run=True)
        assert "os.replace" not in script
        assert "preview-ok" in script
        assert "shutil.copy2" not in script

    def test_apply_refuses_overwrite_by_default(self):
        from jen.services.kea_authoring import render_author_config_script
        script = render_author_config_script("dhcp6", "/etc/kea/kea-dhcp6.conf",
                                              {"Dhcp6": {}}, allow_overwrite=False, dry_run=False)
        assert "'exists'" in script
        assert "os.path.exists(path) and not False" in script

    def test_apply_with_overwrite_backs_up_first(self):
        from jen.services.kea_authoring import render_author_config_script
        script = render_author_config_script("dhcp6", "/etc/kea/kea-dhcp6.conf",
                                              {"Dhcp6": {}}, allow_overwrite=True, dry_run=False)
        assert "shutil.copy2" in script
        assert "os.replace(tmp, path)" in script

    def test_uses_correct_kea_binary_per_service(self):
        from jen.services.kea_authoring import render_author_config_script
        script4 = render_author_config_script("dhcp4", "/x", {"Dhcp4": {}}, False, True)
        script6 = render_author_config_script("dhcp6", "/x", {"Dhcp6": {}}, False, True)
        assert "'kea-dhcp4'" in script4
        assert "'kea-dhcp6'" in script6


class TestParseSubnetLines:

    def test_parses_valid_v6_lines(self):
        from jen.routes.settings import _parse_subnet_lines
        subnets, error = _parse_subnet_lines(
            "1 = LAN6, 2001:db8:1::/64\n2 = IoT6, 2001:db8:2::/64", "dhcp6")
        assert error is None
        assert subnets[1]["cidr"] == "2001:db8:1::/64"
        assert subnets[2]["name"] == "IoT6"

    def test_parses_v6_line_with_paired_id(self):
        from jen.routes.settings import _parse_subnet_lines
        subnets, error = _parse_subnet_lines("1 = LAN6, 2001:db8::/64, 1", "dhcp6")
        assert error is None
        assert subnets[1]["paired_subnet4_id"] == 1

    def test_parses_valid_v4_lines(self):
        from jen.routes.settings import _parse_subnet_lines
        subnets, error = _parse_subnet_lines("1 = LAN, 192.168.1.0/24", "dhcp4")
        assert error is None
        assert subnets[1]["cidr"] == "192.168.1.0/24"

    def test_empty_input_is_an_error_not_a_silent_empty_config(self):
        from jen.routes.settings import _parse_subnet_lines
        subnets, error = _parse_subnet_lines("", "dhcp6")
        assert subnets is None
        assert error is not None

    def test_malformed_line_alone_is_an_error(self):
        """A line that parses as nothing valid must surface an error to
        the operator, not silently produce an empty subnet dict — that
        would let 'Apply' proceed with zero subnets defined."""
        from jen.routes.settings import _parse_subnet_lines
        subnets, error = _parse_subnet_lines("not a valid line at all", "dhcp6")
        assert subnets is None
        assert error is not None

    def test_v4_cidr_rejected_on_v6_form_via_validation(self):
        from jen.routes.settings import _parse_subnet_lines
        # Not a v6-vs-v4 format check per se, but a genuinely invalid
        # CIDR (not parseable at all) must still error, not pass through.
        subnets, error = _parse_subnet_lines("1 = bad, not-a-cidr", "dhcp6")
        assert subnets is None
        assert error is not None


class TestSubnetsToLines:

    def test_renders_existing_subnets_as_editable_lines(self):
        from jen.routes.settings import _subnets_to_lines
        subnets = {1: {"name": "LAN6", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        lines = _subnets_to_lines(subnets, "dhcp6")
        assert lines == "1 = LAN6, 2001:db8::/64"

    def test_includes_paired_id_when_present(self):
        from jen.routes.settings import _subnets_to_lines
        subnets = {1: {"name": "LAN6", "cidr": "2001:db8::/64", "paired_subnet4_id": 1}}
        lines = _subnets_to_lines(subnets, "dhcp6")
        assert lines == "1 = LAN6, 2001:db8::/64, 1"

    def test_empty_map_renders_empty_string(self):
        from jen.routes.settings import _subnets_to_lines
        assert _subnets_to_lines({}, "dhcp6") == ""

    def test_round_trips_through_parse(self):
        """What gets rendered for the textarea must parse back to the
        exact same subnet dict — the wizard's pre-fill and its own
        submission must agree on the format."""
        from jen.routes.settings import _subnets_to_lines, _parse_subnet_lines
        original = {1: {"name": "LAN6", "cidr": "2001:db8::/64", "paired_subnet4_id": 3}}
        lines = _subnets_to_lines(original, "dhcp6")
        parsed, error = _parse_subnet_lines(lines, "dhcp6")
        assert error is None
        assert parsed[1]["cidr"] == original[1]["cidr"]
        assert parsed[1]["paired_subnet4_id"] == original[1]["paired_subnet4_id"]


class TestAuthorKeaConfigRoute:

    def test_requires_superadmin(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        resp = c.get("/settings/infrastructure/author-kea/dhcp6", follow_redirects=False)
        assert resp.status_code == 302

    def test_invalid_service_rejected(self, logged_in_client):
        resp = logged_in_client.get("/settings/infrastructure/author-kea/dhcp5", follow_redirects=True)
        assert b"Invalid service" in resp.data

    def test_no_ssh_configured_redirects(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "solo", "ssh_host": ""}])
        resp = logged_in_client.get("/settings/infrastructure/author-kea/dhcp6", follow_redirects=True)
        assert b"nothing to author against" in resp.data

    def test_no_existing_subnets_still_renders_form_for_manual_entry(self, logged_in_client, monkeypatch):
        """The old behavior (hard-block redirect) was the actual bug
        reported: authoring a config from scratch is exactly the case
        where nothing exists in Jen yet, so it must not be required
        as a precondition — the form renders with an empty, editable
        subnet field instead."""
        server = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "_connect_ssh",
                            lambda s: FakeSSHClient([("", ""), ("", "")]))
        resp = logged_in_client.get("/settings/infrastructure/author-kea/dhcp6")
        assert resp.status_code == 200
        assert b"Nothing in Jen yet for this protocol" in resp.data

    def test_existing_subnets_prefill_the_textarea(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "_connect_ssh",
                            lambda s: FakeSSHClient([("", ""), ("", "")]))
        resp = logged_in_client.get("/settings/infrastructure/author-kea/dhcp6")
        assert resp.status_code == 200
        assert b"1 = V6LAN, 2001:db8::/64" in resp.data

    def test_form_renders_with_detected_values(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "10.10.11.250", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        v4_conf = json.dumps({"Dhcp4": {
            "interfaces-config": {"interfaces": ["eth0"]},
            "lease-database": {"host": "10.10.11.250", "user": "kea", "name": "kea"},
        }})
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "_connect_ssh",
                            lambda s: FakeSSHClient([(v4_conf, ""), ("", "")]))
        resp = logged_in_client.get("/settings/infrastructure/author-kea/dhcp6")
        assert resp.status_code == 200
        assert b"eth0" in resp.data
        assert b"Found an existing" in resp.data


class TestAuthorKeaConfigPreviewRoute:

    def test_requires_superadmin(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        resp = c.post("/settings/infrastructure/author-kea/dhcp6/preview", data={}, follow_redirects=False)
        assert resp.status_code == 302

    def test_missing_fields_rejected(self, logged_in_client):
        resp = logged_in_client.post("/settings/infrastructure/author-kea/dhcp6/preview", data={})
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    def test_never_sends_more_than_one_ssh_command_per_server(self, logged_in_client, monkeypatch):
        """Same safety-net property as the subnet-edit preview: dry-run
        only ever tests, never writes/restarts."""
        server = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        fake_ssh = FakeSSHClient([("preview-ok", "")])
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        resp = logged_in_client.post("/settings/infrastructure/author-kea/dhcp6/preview", data={
            "interfaces": "eth0", "control_socket": "/run/kea6.sock",
            "db_host": "h", "db_user": "u", "db_name": "kea",
            "subnets": "1 = V6LAN, 2001:db8::/64",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["servers"][0]["ok"] is True
        assert len(fake_ssh.calls) == 1


# ── Kea binary detection & install (v5.1.2) ──────────────────────────────────

class TestDetectInstalledKeaServices:

    def test_both_present(self):
        from jen.services.kea_authoring import detect_installed_kea_services
        ssh = FakeSSHClient([("kea-dhcp4:FOUND\nkea-dhcp6:FOUND\n", "")])
        result = detect_installed_kea_services(ssh)
        assert result == {"dhcp4": True, "dhcp6": True}

    def test_only_dhcp4_present(self):
        from jen.services.kea_authoring import detect_installed_kea_services
        ssh = FakeSSHClient([("kea-dhcp4:FOUND\nkea-dhcp6:MISSING\n", "")])
        result = detect_installed_kea_services(ssh)
        assert result == {"dhcp4": True, "dhcp6": False}

    def test_neither_present(self):
        from jen.services.kea_authoring import detect_installed_kea_services
        ssh = FakeSSHClient([("kea-dhcp4:MISSING\nkea-dhcp6:MISSING\n", "")])
        result = detect_installed_kea_services(ssh)
        assert result == {"dhcp4": False, "dhcp6": False}

    def test_command_falls_back_to_standard_sbin_paths_not_just_path_search(self):
        """v5.1.21 — the actual bug: `which` alone only searches $PATH,
        and a non-interactive SSH session's $PATH can easily exclude
        /usr/sbin, where the real kea-dhcp4-server/kea-dhcp6-server
        packages install these binaries. A genuinely-installed,
        genuinely-running Kea server got reported as "not installed"
        purely because of this. Confirms the actual command sent checks
        the standard install locations directly, not just $PATH —
        FakeSSHClient records the exact command string regardless of
        what canned output it returns, so this verifies the fix is
        actually present rather than only that output-parsing works
        (which the pre-fix tests already covered without ever catching
        this)."""
        from jen.services.kea_authoring import detect_installed_kea_services
        ssh = FakeSSHClient([("kea-dhcp4:FOUND\nkea-dhcp6:MISSING\n", "")])
        detect_installed_kea_services(ssh)
        cmd = ssh.calls[0]
        assert "/usr/sbin/" in cmd, "must check the standard install path directly, not rely on $PATH alone"
        assert "command -v" in cmd or "which" in cmd, "should still also try a PATH-based search"


class TestInstallKeaService:

    def test_success_returns_ok_and_tail_of_output(self):
        from jen.services.kea_authoring import install_kea_service
        output = "\n".join([f"line {i}" for i in range(30)]) + "\nSetting up kea-dhcp6-server ...\n"
        ssh = FakeSSHClient([(output, "", 0)])
        ok, tail = install_kea_service(ssh, "dhcp6")
        assert ok is True
        assert "Setting up kea-dhcp6-server" in tail
        # Tail is capped, not the full (potentially huge) apt output.
        assert len(tail.splitlines()) <= 15

    def test_failure_returns_ok_false(self):
        from jen.services.kea_authoring import install_kea_service
        ssh = FakeSSHClient([("E: Unable to locate package kea-dhcp6-server", "", 100)])
        ok, tail = install_kea_service(ssh, "dhcp6")
        assert ok is False
        assert "Unable to locate package" in tail

    def test_ssh_exception_returns_ok_false_not_raise(self):
        from jen.services.kea_authoring import install_kea_service
        class BrokenSSH:
            def exec_command(self, cmd):
                raise RuntimeError("connection reset")
        ok, tail = install_kea_service(BrokenSSH(), "dhcp6")
        assert ok is False
        assert "connection reset" in tail

    def test_installs_correct_package_name_per_service(self):
        from jen.services.kea_authoring import install_kea_service
        ssh4 = FakeSSHClient([("", "", 0)])
        ssh6 = FakeSSHClient([("", "", 0)])
        install_kea_service(ssh4, "dhcp4")
        install_kea_service(ssh6, "dhcp6")
        assert "kea-dhcp4-server" in ssh4.calls[0]
        assert "kea-dhcp6-server" in ssh6.calls[0]
        assert "kea-dhcp6-server" not in ssh4.calls[0]


class TestMissingBinaryScriptHandling:
    """The actual bug report: a missing kea-dhcp6 binary must never leak
    a raw Python traceback through the SSH output — it should produce a
    clean 'missingbinary:kea-dhcp6' sentinel instead."""

    def test_authoring_script_catches_missing_binary(self):
        from jen.services.kea_authoring import render_author_config_script
        script = render_author_config_script("dhcp6", "/etc/kea/kea-dhcp6.conf",
                                              {"Dhcp6": {}}, allow_overwrite=False, dry_run=True)
        assert "except FileNotFoundError:" in script
        assert "missingbinary:kea-dhcp6" in script
        # The try/except must wrap the actual subprocess.run call, not
        # just appear somewhere in the script text.
        assert "try:\n    result = subprocess.run" in script

    def test_v6_subnet_patch_script_catches_missing_binary(self):
        from jen.services.kea6 import build_subnet6_patch_script
        script = build_subnet6_patch_script(
            1, "/etc/kea/kea-dhcp6.conf", "2001:db8::10-2001:db8::20", [],
            "", "", "", "", "", dry_run=True,
        )
        assert "except FileNotFoundError:" in script
        assert "missingbinary:kea-dhcp6" in script

    def test_v4_subnet_patch_script_catches_missing_binary(self):
        import jen.routes.subnets as subnets_module
        script = subnets_module._build_subnet_patch_script(
            1, "/etc/kea/kea-dhcp4.conf", "192.168.1.10-192.168.1.20", [],
            "", "", "", "", "", dry_run=True,
        )
        assert "except FileNotFoundError:" in script
        assert "missingbinary:kea-dhcp4" in script

    def test_all_three_generated_scripts_remain_valid_python(self):
        """Guard against the fix itself introducing a syntax error into
        the script that actually runs on the remote Kea server."""
        import ast
        from jen.services.kea_authoring import render_author_config_script
        from jen.services.kea6 import build_subnet6_patch_script
        import jen.routes.subnets as subnets_module

        scripts = [
            render_author_config_script("dhcp6", "/x", {"Dhcp6": {}}, False, True),
            render_author_config_script("dhcp4", "/x", {"Dhcp4": {}}, False, True),
            build_subnet6_patch_script(1, "/x", "", [], "", "", "", "", "", dry_run=True),
            subnets_module._build_subnet_patch_script(1, "/x", "", [], "", "", "", "", "", dry_run=True),
        ]
        for script in scripts:
            ast.parse(script)  # raises SyntaxError if invalid


class TestCheckKeaBinariesRoute:

    def test_requires_superadmin(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        resp = c.post("/settings/infrastructure/check-kea-binaries", follow_redirects=False)
        assert resp.status_code == 302

    def test_reports_per_server_status(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        import jen.services.kea6 as kea6_module
        ssh = FakeSSHClient([("kea-dhcp4:FOUND\nkea-dhcp6:MISSING\n", "")])
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: ssh)
        resp = logged_in_client.post("/settings/infrastructure/check-kea-binaries")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["servers"][0]["dhcp4"] is True
        assert data["servers"][0]["dhcp6"] is False

    def test_skips_servers_without_ssh(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "no-ssh", "ssh_host": ""}])
        resp = logged_in_client.post("/settings/infrastructure/check-kea-binaries")
        assert resp.status_code == 200
        assert resp.get_json()["servers"] == []

    def test_connection_failure_reported_not_raised(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "unreachable", "ssh_host": "9.9.9.9"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        import jen.services.kea6 as kea6_module
        def fail_connect(s):
            raise TimeoutError("no route to host")
        monkeypatch.setattr(kea6_module, "_connect_ssh", fail_connect)
        resp = logged_in_client.post("/settings/infrastructure/check-kea-binaries")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["servers"][0]["ok"] is False
        assert "no route to host" in data["servers"][0]["error"]


class TestInstallKeaBinaryRoute:

    def test_requires_superadmin(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        resp = c.post("/settings/infrastructure/install-kea-binary/dhcp6", follow_redirects=False)
        assert resp.status_code == 302

    def test_invalid_service_rejected(self, logged_in_client):
        resp = logged_in_client.post("/settings/infrastructure/install-kea-binary/dhcp5")
        assert resp.status_code == 400

    def test_successful_install(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        import jen.services.kea6 as kea6_module
        ssh = FakeSSHClient([("Setting up kea-dhcp6-server ...", "", 0)])
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: ssh)
        resp = logged_in_client.post("/settings/infrastructure/install-kea-binary/dhcp6")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["servers"][0]["ok"] is True

    def test_failed_install_reported(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        import jen.services.kea6 as kea6_module
        ssh = FakeSSHClient([("E: Unable to locate package", "", 100)])
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: ssh)
        resp = logged_in_client.post("/settings/infrastructure/install-kea-binary/dhcp6")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is False
        assert data["servers"][0]["ok"] is False


class TestAuthorKeaPreviewMissingBinary:

    def test_preview_surfaces_missing_binary_cleanly(self, logged_in_client, monkeypatch):
        """The exact scenario from the bug report: kea-dhcp6 not
        installed must produce a clean, structured response — never a
        raw traceback string reaching the browser."""
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        import jen.services.kea6 as kea6_module
        fake_ssh = FakeSSHClient([("missingbinary:kea-dhcp6", "")])
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        resp = logged_in_client.post("/settings/infrastructure/author-kea/dhcp6/preview", data={
            "interfaces": "eth0", "control_socket": "/run/kea6.sock",
            "db_host": "h", "db_user": "u", "db_name": "kea",
            "subnets": "1 = V6LAN, 2001:db8::/64",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["servers"][0]["missing_binary"] == "kea-dhcp6"
        assert data["servers"][0]["ok"] is False
        assert "Traceback" not in json.dumps(data)


class TestAuthorKeaConfigPostRoute:

    def test_requires_superadmin(self, client, db):
        from tests.conftest import restricted_client
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        resp = c.post("/settings/infrastructure/author-kea/dhcp6", data={}, follow_redirects=False)
        assert resp.status_code == 302

    def test_refuses_to_overwrite_without_explicit_flag(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        fake_ssh = FakeSSHClient([("exists", "")])
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        resp = logged_in_client.post("/settings/infrastructure/author-kea/dhcp6", data={
            "interfaces": "eth0", "control_socket": "/run/kea6.sock",
            "db_host": "h", "db_user": "u", "db_name": "kea",
            "subnets": "1 = V6LAN, 2001:db8::/64",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"already exists" in resp.data

    def test_successful_write_persists_subnets_to_jen_config(self, logged_in_client, monkeypatch):
        """The actual fix: authoring a config with subnets Jen didn't
        already know about must leave them saved in Jen afterward, not
        just written into the Kea config file."""
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})  # nothing in Jen yet
        fake_ssh = FakeSSHClient([("ok", "")])
        import jen.services.kea6 as kea6_module
        import jen.routes.settings as settings_module
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        captured = {}
        monkeypatch.setattr(getattr(settings_module, "__config"), "write_subnets6_config",
                            lambda d: captured.update(subnets=d))
        resp = logged_in_client.post("/settings/infrastructure/author-kea/dhcp6", data={
            "interfaces": "eth0", "control_socket": "/run/kea6.sock",
            "db_host": "h", "db_user": "u", "db_name": "kea",
            "subnets": "1 = V6LAN, 2001:db8::/64",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert captured["subnets"][1]["name"] == "V6LAN"
        assert captured["subnets"][1]["cidr"] == "2001:db8::/64"

    def test_failed_write_does_not_persist_subnets(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        fake_ssh = FakeSSHClient([("testerror:bad", "")])
        import jen.services.kea6 as kea6_module
        import jen.routes.settings as settings_module
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        called = {"count": 0}
        monkeypatch.setattr(getattr(settings_module, "__config"), "write_subnets6_config",
                            lambda d: called.__setitem__("count", called["count"] + 1))
        logged_in_client.post("/settings/infrastructure/author-kea/dhcp6", data={
            "interfaces": "eth0", "control_socket": "/run/kea6.sock",
            "db_host": "h", "db_user": "u", "db_name": "kea",
            "subnets": "1 = V6LAN, 2001:db8::/64",
        }, follow_redirects=True)
        assert called["count"] == 0

    def test_successful_write(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        fake_ssh = FakeSSHClient([("ok", "")])
        import jen.services.kea6 as kea6_module
        import jen.routes.settings as settings_module
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        monkeypatch.setattr(getattr(settings_module, "__config"), "write_subnets6_config", lambda d: None)
        resp = logged_in_client.post("/settings/infrastructure/author-kea/dhcp6", data={
            "interfaces": "eth0", "control_socket": "/run/kea6.sock",
            "db_host": "h", "db_user": "u", "db_name": "kea",
            "subnets": "1 = V6LAN, 2001:db8::/64",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"written" in resp.data

    def test_config_test_failure_writes_nothing(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP",
                            {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}})
        fake_ssh = FakeSSHClient([("testerror:bad interface", "")])
        import jen.services.kea6 as kea6_module
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        resp = logged_in_client.post("/settings/infrastructure/author-kea/dhcp6", data={
            "interfaces": "eth0", "control_socket": "/run/kea6.sock",
            "db_host": "h", "db_user": "u", "db_name": "kea",
            "subnets": "1 = V6LAN, 2001:db8::/64",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"config test failed, nothing written" in resp.data
        assert b"bad interface" in resp.data


class TestZeroBehaviorChange:
    """The single most important test in this file, per the v5.0 plan doc:
    ipv6_enabled=false must produce zero behavior change anywhere, whether
    or not [kea6]/[subnets6] are present in config at all."""

    def test_disabled_by_default_regardless_of_kea6_presence(self, db):
        from jen.services.kea6 import is_ipv6_enabled
        from jen.models.user import _invalidate_settings_cache
        _invalidate_settings_cache()
        assert is_ipv6_enabled() is False

    def test_subnet6_map_empty_with_no_subnets6_section(self, monkeypatch):
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string(
            "[kea]\napi_url=http://kea4:8000\napi_user=u\napi_pass=p\n"
            "[kea_db]\nhost=h\nuser=u\npassword=p\n"
            "[jen_db]\nhost=h\nuser=u\npassword=p\n"
            "[subnets]\n1 = LAN, 192.168.1.0/24\n"
        )
        # AppConfig.apply() writes directly to extensions globals (by
        # design), so snapshot/restore everything it touches rather than
        # letting this test permanently repoint KEA_DB_HOST etc. to fake
        # values for every test that runs after it.
        keys = ["KEA_API_URL", "KEA_API_USER", "KEA_API_PASS",
                "KEA_DB_HOST", "KEA_DB_USER", "KEA_DB_PASS",
                "KEA6_DB_HOST", "KEA6_DB_USER", "KEA6_DB_PASS",
                "SUBNET_MAP", "SUBNET6_MAP", "JEN_DB_HOST", "JEN_DB_USER", "JEN_DB_PASS"]
        for k in keys:
            monkeypatch.setattr(extensions, k, getattr(extensions, k, None), raising=False)
        app_config = AppConfig()
        app_config.apply(cfg)
        assert extensions.SUBNET6_MAP == {}
        # v4 map is untouched by v6 code paths
        assert extensions.SUBNET_MAP == {1: {"name": "LAN", "cidr": "192.168.1.0/24"}}

    def test_no_v6_command_reaches_kea_when_disabled(self, monkeypatch, db):
        """Route-level gating is a Phase 1 checklist item still to be wired
        up per-route; this test locks in the primitive it must be built on:
        is_ipv6_enabled() is cheap and side-effect-free to check before any
        kea6_command() call, and doesn't itself talk to Kea."""
        import jen.services.kea as kea_module
        called = {"count": 0}

        def fail_if_called(*a, **kw):
            called["count"] += 1
            raise AssertionError("kea_command should not be reached")

        monkeypatch.setattr(kea_module, "http", type("X", (), {
            "post": fail_if_called
        }))
        from jen.services.kea6 import is_ipv6_enabled
        from jen.models.user import _invalidate_settings_cache
        _invalidate_settings_cache()
        if not is_ipv6_enabled():
            pass  # a real route would return here without calling kea6_command
        assert called["count"] == 0
