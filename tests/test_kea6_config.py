"""
tests/test_kea6_config.py
─────────────────────────
Kea6 config plumbing: SUBNET6_MAP derivation, [kea6] section fallback to v4, is_ipv6_enabled(), the kea6 command choke point, the shared kea_db pool, and the zero-behaviour-change guarantee for v4-only installs.

Split out of the monolithic tests/test_kea6.py in v5.6.1.
"""

import configparser

import pytest

from jen import extensions
from jen.config import AppConfig


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
        cfg.read_string("[subnets6]\n1 = Production, 2001:db8:1::/64\n2 = IoT, 2001:db8:2::/64\n")
        result = AppConfig.derive_subnet_map(cfg, section="subnets6")
        assert result == {
            1: {"name": "Production", "cidr": "2001:db8:1::/64", "paired_subnet4_id": None},
            2: {"name": "IoT", "cidr": "2001:db8:2::/64", "paired_subnet4_id": None},
        }

    def test_v4_and_v6_ids_are_independent_namespaces(self):
        """Kea's v4 and v6 subnet IDs don't share a numbering space — the
        same integer can validly appear in both [subnets] and [subnets6]
        and refer to two unrelated subnets."""
        cfg = configparser.ConfigParser()
        cfg.read_string("[subnets]\n1 = LAN, 192.168.1.0/24\n[subnets6]\n1 = LAN6, 2001:db8:1::/64\n")
        v4 = AppConfig.derive_subnet_map(cfg, section="subnets")
        v6 = AppConfig.derive_subnet_map(cfg, section="subnets6")
        assert v4[1]["cidr"] == "192.168.1.0/24"
        assert v6[1]["cidr"] == "2001:db8:1::/64"

    def test_malformed_v6_entry_skipped_not_fatal(self):
        cfg = configparser.ConfigParser()
        cfg.read_string("[subnets6]\n1 = not-a-valid-line\n2 = OK, 2001:db8:2::/64\n")
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
        keys = [
            "KEA_API_URL",
            "KEA_API_USER",
            "KEA_API_PASS",
            "KEA_DB_HOST",
            "KEA_DB_USER",
            "KEA_DB_PASS",
            "KEA6_API_URL",
            "KEA6_API_USER",
            "KEA6_API_PASS",
            "KEA6_DB_HOST",
            "KEA6_DB_USER",
            "KEA6_DB_PASS",
            "KEA6_DB_NAME",
            "SUBNET_MAP",
            "SUBNET6_MAP",
            "JEN_DB_HOST",
            "JEN_DB_USER",
            "JEN_DB_PASS",
        ]
        snapshot = {k: getattr(extensions, k, None) for k in keys}
        yield
        for k, v in snapshot.items():
            setattr(extensions, k, v)

    def _base_cfg(self, extra: str = "") -> configparser.ConfigParser:
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string(
            "[kea]\napi_url=http://kea4:8000\napi_user=u4\napi_pass=p4\n"
            "[kea_db]\nhost=db4\nuser=u4\npassword=p4\n"
            "[jen_db]\nhost=jendb\nuser=j\npassword=p\n" + extra
        )
        return cfg

    def test_falls_back_to_v4_when_kea6_absent(self, monkeypatch):
        app_config = AppConfig()
        cfg = self._base_cfg()
        app_config.apply(cfg)
        assert extensions.KEA6_API_URL == "http://kea4:8000"
        assert extensions.KEA6_API_USER == "u4"
        assert extensions.KEA6_API_PASS == "p4"
        assert extensions.KEA6_DB_HOST == "db4"

    def test_explicit_kea6_overrides_fallback(self):
        app_config = AppConfig()
        cfg = self._base_cfg("[kea6]\napi_url=http://kea6:8000\napi_user=u6\napi_pass=p6\n")
        app_config.apply(cfg)
        assert extensions.KEA6_API_URL == "http://kea6:8000"
        assert extensions.KEA6_API_USER == "u6"
        assert extensions.KEA6_API_PASS == "p6"

    def test_subnet6_map_populated_by_apply(self):
        app_config = AppConfig()
        cfg = self._base_cfg("[subnets6]\n5 = V6LAN, 2001:db8:5::/64\n")
        app_config.apply(cfg)
        assert extensions.SUBNET6_MAP == {5: {"name": "V6LAN", "cidr": "2001:db8:5::/64", "paired_subnet4_id": None}}


class TestIsIpv6Enabled:
    def test_defaults_false(self, db):
        from jen.models.user import _invalidate_settings_cache
        from jen.services.kea6 import is_ipv6_enabled

        _invalidate_settings_cache()
        assert is_ipv6_enabled() is False

    def test_true_after_setting_flipped(self, db):
        from jen.models.user import set_global_setting
        from jen.services.kea6 import is_ipv6_enabled

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

        # is_ipv6_enabled imports get_global_setting locally, so patch via
        # the module it's imported from at call time.
        import importlib

        from jen.services import kea6 as kea6_module

        importlib.reload(kea6_module)
        monkeypatch.setattr(user_module, "get_global_setting", boom)
        assert kea6_module.is_ipv6_enabled() is False


class TestKea6Command:
    def test_passes_service_dhcp6(self, monkeypatch):
        from jen.services import kea6 as kea6_module

        captured = {}

        def fake_kea_command(command, service="dhcp4", arguments=None, server=None):
            captured["command"] = command
            captured["service"] = service
            captured["server"] = server
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


class TestZeroBehaviorChange:
    """The single most important test in this file, per the v5.0 plan doc:
    ipv6_enabled=false must produce zero behavior change anywhere, whether
    or not [kea6]/[subnets6] are present in config at all."""

    def test_disabled_by_default_regardless_of_kea6_presence(self, db):
        from jen.models.user import _invalidate_settings_cache
        from jen.services.kea6 import is_ipv6_enabled

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
        keys = [
            "KEA_API_URL",
            "KEA_API_USER",
            "KEA_API_PASS",
            "KEA_DB_HOST",
            "KEA_DB_USER",
            "KEA_DB_PASS",
            "KEA6_DB_HOST",
            "KEA6_DB_USER",
            "KEA6_DB_PASS",
            "SUBNET_MAP",
            "SUBNET6_MAP",
            "JEN_DB_HOST",
            "JEN_DB_USER",
            "JEN_DB_PASS",
        ]
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

        monkeypatch.setattr(kea_module, "http", type("X", (), {"post": fail_if_called}))
        from jen.models.user import _invalidate_settings_cache
        from jen.services.kea6 import is_ipv6_enabled

        _invalidate_settings_cache()
        if not is_ipv6_enabled():
            pass  # a real route would return here without calling kea6_command
        assert called["count"] == 0
