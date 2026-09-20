"""
tests/test_kea_readiness.py
───────────────────────────
v5.38.0 (Q37) — the Kea 3.2 readiness group: the pure scanner in
jen/services/kea_readiness.py (runs with --noconftest) and the five
`kea32_*` checks in jen/services/health.py (which read Jen's config
globals and a fabricated ctx, no Kea, no DB beyond the autouse fixture).
"""

import pytest

from jen import extensions
from jen.services import health
from jen.services import kea_readiness as kr

# ── the pure scanner ─────────────────────────────────────────────────────────


class TestScanRemovedKeys:
    def test_empty_and_clean_configs(self):
        assert kr.scan_removed_keys(None) == []
        assert kr.scan_removed_keys({}) == []
        clean = {
            "subnet4": [
                {"id": 1, "subnet": "10.0.0.0/24", "client-classes": ["a"], "evaluate-additional-classes": ["b"]}
            ],
            "client-classes": [{"name": "a", "test": "member('ALL')", "only-in-additional-list": True}],
            "reservations-global": False,
            "dhcp-ddns": {"enable-updates": True, "server-ip": "127.0.0.1"},
            "ddns-qualifying-suffix": "example.lan",
        }
        assert kr.scan_removed_keys(clean) == []

    def test_each_removed_key_found_with_its_path(self):
        cfg = {
            "reservation-mode": "all",
            "subnet4": [
                {"id": 7, "subnet": "10.0.7.0/24", "require-client-classes": ["x"], "client-class": "g"},
                {"id": 8, "subnet": "10.0.8.0/24", "pools": [{"pool": "10.0.8.10 - 10.0.8.20", "client-class": "p"}]},
            ],
            "shared-networks": [
                {"name": "campus", "reservation-mode": "global", "subnet4": [{"id": 9, "subnet": "10.0.9.0/24"}]}
            ],
            "client-classes": [{"name": "pxe", "test": "member('ALL')", "only-if-required": True}],
            "dhcp-ddns": {"enable-updates": True, "qualifying-suffix": "old.lan", "override-no-update": True},
        }
        found = kr.scan_removed_keys(cfg)
        paths = {f["path"]: f for f in found}
        assert set(paths) == {
            "Dhcp4.reservation-mode",
            "Dhcp4.subnet4[id 7].require-client-classes",
            "Dhcp4.subnet4[id 7].client-class",
            "Dhcp4.subnet4[id 8].pools[0].client-class",
            "Dhcp4.shared-networks['campus'].reservation-mode",
            "Dhcp4.client-classes['pxe'].only-if-required",
            "Dhcp4.dhcp-ddns.qualifying-suffix",
            "Dhcp4.dhcp-ddns.override-no-update",
        }
        assert paths["Dhcp4.subnet4[id 7].require-client-classes"]["replacement"] == "evaluate-additional-classes"
        assert paths["Dhcp4.reservation-mode"]["since"] == "1.9.1"
        assert all(f["hint"] for f in found)

    def test_ddns_keys_only_count_inside_the_dhcp_ddns_block(self):
        # a subnet-level "hostname-char-set" is the NEW location, not a removed key
        cfg = {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "hostname-char-set": "[^A-Za-z0-9.-]"}]}
        assert kr.scan_removed_keys(cfg) == []

    def test_minor_of_and_summarize(self):
        assert kr.minor_of((3, 0, 1)) == "3.0" and kr.minor_of(None) is None
        ok = health.Check("a", "a", "readiness", "ok")
        warn = health.Check("b", "b", "readiness", "warn")
        skip = health.Check("c", "c", "readiness", "skip")
        assert kr.summarize([ok, skip]) == {"ready": True, "actions": 0, "checked": 1}
        assert kr.summarize([ok, warn]) == {"ready": False, "actions": 1, "checked": 2}
        assert kr.summarize([skip, skip]) == {"ready": False, "actions": 0, "checked": 0}


# ── the checks ───────────────────────────────────────────────────────────────


def _status(name, version, up=True, sid=1):
    return {"server": {"id": sid, "name": name}, "up": up, "ha_state": None, "version": version}


def _ctx(**over):
    base = {
        "server_status": [_status("kea-a", "2.6.1")],
        "active_server": {"id": 1, "name": "kea-a"},
        "dhcp4_config": {"subnet4": [], "hooks-libraries": []},
        "subnet_filter": lambda _sid: True,
    }
    base.update(over)
    return base


@pytest.fixture
def single_ca(monkeypatch):
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
    monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "api_url": "http://a:8000"}])
    monkeypatch.setattr(extensions, "D2_API_URL", "")
    monkeypatch.setattr(extensions, "KEA6_API_URL", "")
    monkeypatch.setattr("jen.services.kea6.is_ipv6_enabled", lambda: False)


class TestRegistration:
    def test_five_checks_in_the_readiness_group_at_the_end(self):
        ids = [i for i in health.CHECK_IDS if i.startswith("kea32_")]
        assert ids == [
            "kea32_control_transport",
            "kea32_helper_version",
            "kea32_removed_keys",
            "kea32_ha_versions_match",
            "kea32_d2_socket",
        ]
        assert all(health._CHECK_META[i][1] == "readiness" for i in ids)
        assert health.GROUP_ORDER[-1] == "readiness" and "3.2" in health.GROUP_LABELS["readiness"]
        assert "Control Agent" in health.group_banner("readiness") and health.group_banner("kea") == ""

    def test_docker_single_server_skips_never_fails(self, single_ca, monkeypatch):
        """The gotcha: a CA-less single box with no helper, no HA, no DDNS."""
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        monkeypatch.setattr(extensions.cfg, "get", lambda s, k, fallback=None: fallback)
        ctx = _ctx()
        assert health._kea32_helper_version(ctx).status == "skip"
        assert health._kea32_ha_versions_match(ctx).status == "skip"
        assert health._kea32_d2_socket(ctx).status == "skip"
        assert health._kea32_removed_keys(ctx).status == "ok"
        assert health._kea32_control_transport(ctx).status == "ok"


class TestControlTransport:
    def test_ca_mode_below_30_warns_with_the_plan(self, single_ca):
        c = health._kea32_control_transport(_ctx())
        assert c.status == "warn" and "before you upgrade" in c.detail and "Set up direct socket" in c.detail

    def test_ca_mode_on_30_fails(self, single_ca):
        c = health._kea32_control_transport(_ctx(server_status=[_status("kea-a", "3.0.0")]))
        assert c.status == "fail" and "Control Agent" in c.detail

    def test_direct_mode_missing_daemon_sockets_warn(self, single_ca, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [{"id": 1, "name": "kea-a", "api_url": "http://a:8004"}, {"id": 2, "name": "kea-b", "api_url": ""}],
        )
        ctx = _ctx(dhcp4_config={"dhcp-ddns": {"enable-updates": True}})
        c = health._kea32_control_transport(ctx)
        assert c.status == "warn"
        assert (
            "kea-b: kea-dhcp4" in c.detail and "kea-a: kea-dhcp-ddns" in c.detail and "kea-b: kea-dhcp-ddns" in c.detail
        )

    def test_direct_mode_complete_is_ok(self, single_ca, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        monkeypatch.setattr(extensions, "D2_API_URL", "http://a:8053")
        ctx = _ctx(dhcp4_config={"dhcp-ddns": {"enable-updates": True}})
        c = health._kea32_control_transport(ctx)
        assert c.status == "ok" and "2 daemon(s)" in c.detail


class TestHelperVersion:
    def test_behind_and_unknown(self, single_ca, monkeypatch):
        from jen.services import kea_host

        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [{"id": 1, "name": "kea-a", "ssh_host": "a"}, {"id": 2, "name": "kea-b", "ssh_host": "b"}],
        )
        monkeypatch.setattr(kea_host, "helper_status", lambda: {"1": {"version": 2}})
        c = health._kea32_helper_version(_ctx())
        assert c.status == "warn" and "kea-a (v2)" in c.detail and "kea-b never recorded" in c.detail

    def test_current_is_ok(self, single_ca, monkeypatch):
        from jen.services import kea_host

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "a"}])
        monkeypatch.setattr(kea_host, "helper_status", lambda: {"1": {"version": kea_host.JEN_HELPER_SHIPPED_VERSION}})
        c = health._kea32_helper_version(_ctx())
        assert c.status == "ok"


class TestRemovedKeysCheck:
    def test_lists_findings_and_points_at_classes(self, single_ca):
        cfg = {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "require-client-classes": ["x"]}]}
        c = health._kea32_removed_keys(_ctx(dhcp4_config=cfg))
        assert c.status == "warn" and "subnet4[id 1].require-client-classes" in c.detail
        assert c.fix_url == "/subnets/classes"

    def test_reservation_mode_points_at_servers_and_truncates(self, single_ca):
        cfg = {
            "reservation-mode": "all",
            "subnet4": [
                {"id": i, "subnet": f"10.0.{i}.0/24", "require-client-classes": ["x"], "client-class": "g"}
                for i in range(1, 4)
            ],
        }
        c = health._kea32_removed_keys(_ctx(dhcp4_config=cfg))
        assert c.status == "warn" and "7 key(s)" in c.detail and "and 4 more" in c.detail
        assert c.fix_url == "/servers"

    def test_unavailable_config_skips(self, single_ca):
        assert health._kea32_removed_keys(_ctx(dhcp4_config=None)).status == "skip"


class TestHaVersionsMatch:
    def _ha(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a"}, {"id": 2, "name": "kea-b"}])
        monkeypatch.setattr(
            extensions.cfg,
            "get",
            lambda s, k, fallback=None: "hot-standby" if (s, k) == ("kea", "ha_mode") else fallback,
        )

    def test_mismatch_warns(self, single_ca, monkeypatch):
        self._ha(monkeypatch)
        ctx = _ctx(server_status=[_status("kea-a", "3.0.1"), _status("kea-b", "2.6.1", sid=2)])
        c = health._kea32_ha_versions_match(ctx)
        assert c.status == "warn" and "one node at a time" in c.detail

    def test_match_ok_and_one_down_skips(self, single_ca, monkeypatch):
        self._ha(monkeypatch)
        ctx = _ctx(server_status=[_status("kea-a", "3.0.1"), _status("kea-b", "3.0.3", sid=2)])
        assert health._kea32_ha_versions_match(ctx).status == "ok"
        ctx = _ctx(server_status=[_status("kea-a", "3.0.1"), _status("kea-b", "3.0.3", up=False, sid=2)])
        assert health._kea32_ha_versions_match(ctx).status == "skip"


class TestD2Socket:
    def test_ca_mode_with_ddns_warns(self, single_ca):
        c = health._kea32_d2_socket(_ctx(dhcp4_config={"dhcp-ddns": {"enable-updates": True}}))
        assert c.status == "warn" and "own http control socket" in c.detail

    def test_direct_mode_answers(self, single_ca, monkeypatch):
        from jen.services import kea as kea_svc

        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        monkeypatch.setattr(extensions, "D2_API_URL", "http://a:8053")
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "arguments": {"extended": "3.0.1"}})
        c = health._kea32_d2_socket(_ctx(dhcp4_config={"dhcp-ddns": {"enable-updates": True}}))
        assert c.status == "ok" and "8053" not in c.detail and "its own control socket" in c.detail

    def test_direct_mode_without_url_warns(self, single_ca, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        c = health._kea32_d2_socket(_ctx(dhcp4_config={"dhcp-ddns": {"enable-updates": True}}))
        assert c.status == "warn" and "[d2] api_url" in c.detail


class TestPageAndSettingsLine:
    def test_health_partial_renders_the_banner(self, logged_in_client, mock_kea):
        r = logged_in_client.get("/health-center/data?partial=1")
        body = r.data.decode()
        assert r.status_code == 200
        assert "Kea 3.2 readiness" in body and "Jen checks the parts it can see" in body
        assert 'data-check="kea32_control_transport"' in body

    def test_readiness_checks_helper_returns_only_the_group(self, mock_kea):
        checks = health.readiness_checks()
        assert checks and all(c.group == "readiness" for c in checks) and len(checks) == 5

    def test_settings_kea_shows_the_one_liner(self, logged_in_client, mock_kea):
        body = logged_in_client.get("/settings/kea").data.decode()
        assert "Kea 3.2" in body and "Health Center" in body
