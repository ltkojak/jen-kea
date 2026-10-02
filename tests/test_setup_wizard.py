"""
tests/test_setup_wizard.py
────────────────────────────
v5.67.0 (Q115) — the /setup wizard. jen/services/setup_wizard.py's own
state-machine helpers (current_step, needs_entry_redirect,
test_kea_connection) are pure enough to unit-test with monkeypatched
settings/HTTP — no DB or Flask needed; the route tests below (access
control, the one-time redirect) need the real app and show as errors
without a DB, same as every other route test in this suite.
"""

from unittest.mock import MagicMock, patch

import pytest

from jen.services import setup_wizard

# ── current_step() / all_resolved() — pure given get_state() ────────────────


class TestCurrentStep:
    def test_nothing_resolved_starts_at_the_first_step(self, monkeypatch):
        monkeypatch.setattr(setup_wizard, "get_state", dict)
        assert setup_wizard.current_step() == setup_wizard.STEPS[0]

    def test_first_step_done_moves_to_the_second(self, monkeypatch):
        monkeypatch.setattr(setup_wizard, "get_state", lambda: {setup_wizard.STEPS[0]: "done"})
        assert setup_wizard.current_step() == setup_wizard.STEPS[1]

    def test_a_skipped_step_counts_as_resolved(self, monkeypatch):
        monkeypatch.setattr(setup_wizard, "get_state", lambda: {setup_wizard.STEPS[0]: "skipped"})
        assert setup_wizard.current_step() == setup_wizard.STEPS[1]

    def test_everything_resolved_stays_on_the_last_step(self, monkeypatch):
        monkeypatch.setattr(setup_wizard, "get_state", lambda: dict.fromkeys(setup_wizard.STEPS, "done"))
        assert setup_wizard.current_step() == setup_wizard.STEPS[-1]
        assert setup_wizard.all_resolved() is True

    def test_not_all_resolved_when_one_is_missing(self, monkeypatch):
        state = dict.fromkeys(setup_wizard.STEPS, "done")
        del state[setup_wizard.STEPS[0]]
        monkeypatch.setattr(setup_wizard, "get_state", lambda: state)
        assert setup_wizard.all_resolved() is False


class TestGetState:
    def test_unknown_keys_and_values_are_dropped(self, monkeypatch):
        monkeypatch.setattr(
            "jen.models.user.get_global_setting",
            lambda key, default="": '{"connect": "done", "not-a-step": "done", "found": "whatever"}',
        )
        assert setup_wizard.get_state() == {"connect": "done"}

    def test_absent_or_malformed_json_is_empty(self, monkeypatch):
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "")
        assert setup_wizard.get_state() == {}
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "{not json")
        assert setup_wizard.get_state() == {}

    def test_set_step_rejects_an_unknown_step_or_status(self):
        with pytest.raises(ValueError):
            setup_wizard.set_step("not-a-real-step", "done")
        with pytest.raises(ValueError):
            setup_wizard.set_step(setup_wizard.STEPS[0], "maybe")


# ── entry / one-time redirect ────────────────────────────────────────────────


class TestEntryRedirect:
    def test_kea_connected_needs_both_url_and_subnets(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_URL", "")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        assert setup_wizard.kea_connected() is False

        monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea:8000")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        assert setup_wizard.kea_connected() is False

        monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea:8000")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.0.0.0/24"}})
        assert setup_wizard.kea_connected() is True

    def test_needs_redirect_only_once_and_only_when_disconnected(self, monkeypatch):
        monkeypatch.setattr(setup_wizard, "kea_connected", lambda: False)
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "false")
        assert setup_wizard.needs_entry_redirect() is True

        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "true")
        assert setup_wizard.needs_entry_redirect() is False

        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "false")
        monkeypatch.setattr(setup_wizard, "kea_connected", lambda: True)
        assert setup_wizard.needs_entry_redirect() is False

    def test_mark_shown_writes_the_flag(self):
        with patch("jen.models.user.set_global_setting") as set_mock:
            setup_wizard.mark_entry_redirect_shown()
            set_mock.assert_called_once_with(setup_wizard._REDIRECT_SHOWN_KEY, "true")


# ── test_kea_connection() — mocked HTTP, no real socket ─────────────────────


def _kea_response(version_text="2.7.5"):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"result": 0, "arguments": {"extended": version_text}, "text": ""}
    return resp


# test_kea_connection() is tested against real local servers in tests/test_setup_connection_modes.py
# (v5.67.0-beta.8, Q120) — the mocked-requests.post tests that used to live here asserted the very
# behaviour that was the bug (any answer to a service-style probe is "ca").


# ── save_connection() — pure, write_values mocked ───────────────────────────


class TestSaveConnection:
    def test_writes_the_four_tls_keys_even_when_empty(self, monkeypatch):
        """v5.67.0-beta.5 (Q117, item f) — unlike the password fields,
        the TLS keys are always written (not conditional): an unchecked
        Advanced TLS expander means "no TLS material", which must
        actively clear whatever a previous save left behind."""
        calls = []
        monkeypatch.setattr("jen.config.app_config.write_values", lambda items: calls.append(items))
        setup_wizard.save_connection(
            api_url="http://kea:8000",
            api_user="u",
            api_pass="",
            mode="ca",
            kea_db_host="kea-db",
            kea_db_user="kea",
            kea_db_pass="",
            kea_db_name="kea",
        )
        assert calls == [
            [
                ("kea", "api_url", "http://kea:8000"),
                ("kea", "api_user", "u"),
                ("kea", "connection_mode", "ca"),
                ("kea", "api_ca", ""),
                ("kea", "api_tls_verify", "true"),
                ("kea", "api_client_cert", ""),
                ("kea", "api_client_key", ""),
                ("kea_db", "host", "kea-db"),
                ("kea_db", "user", "kea"),
                ("kea_db", "database", "kea"),
            ]
        ]

    def test_writes_the_submitted_tls_material(self, monkeypatch):
        calls = []
        monkeypatch.setattr("jen.config.app_config.write_values", lambda items: calls.append(items))
        setup_wizard.save_connection(
            api_url="https://kea:8004",
            api_user="u",
            api_pass="",
            mode="direct",
            kea_db_host="kea-db",
            kea_db_user="kea",
            kea_db_pass="",
            kea_db_name="kea",
            api_ca="/etc/jen/ssl/kea-ca.pem",
            api_tls_verify=False,
            api_client_cert="/etc/jen/ssl/client.pem",
            api_client_key="/etc/jen/ssl/client.key",
        )
        items = {k: v for section, k, v in calls[0] if section == "kea"}
        assert items["api_ca"] == "/etc/jen/ssl/kea-ca.pem"
        assert items["api_tls_verify"] == "false"
        assert items["api_client_cert"] == "/etc/jen/ssl/client.pem"
        assert items["api_client_key"] == "/etc/jen/ssl/client.key"


class TestSaveConnectionPortAndPools:
    """v5.67.0-beta.8 (Q120, item g)."""

    def _save(self, monkeypatch, **over):
        calls, resets = [], []
        monkeypatch.setattr("jen.config.app_config.write_values", lambda items: calls.append(items))
        monkeypatch.setattr("jen.models.db.reset_kea_pools", lambda: resets.append(True))
        kwargs = {
            "api_url": "http://kea:8000",
            "api_user": "u",
            "api_pass": "",
            "mode": "ca",
            "kea_db_host": "kea-db",
            "kea_db_user": "kea",
            "kea_db_pass": "",
            "kea_db_name": "kea",
        }
        kwargs.update(over)
        setup_wizard.save_connection(**kwargs)
        return calls, resets

    def test_the_kea_pools_are_reset_after_the_write(self, monkeypatch):
        order = []
        monkeypatch.setattr("jen.config.app_config.write_values", lambda items: order.append("write"))
        monkeypatch.setattr("jen.models.db.reset_kea_pools", lambda: order.append("reset"))
        setup_wizard.save_connection(
            api_url="http://kea:8000",
            api_user="u",
            api_pass="",
            mode="ca",
            kea_db_host="h",
            kea_db_user="u",
            kea_db_pass="",
            kea_db_name="kea",
        )
        assert order == ["write", "reset"], "the pool must be rebuilt AFTER the new settings are in place"

    def test_the_port_is_written_only_when_given(self, monkeypatch):
        calls, _ = self._save(monkeypatch)
        assert not [i for i in calls[0] if i[1] == "port"]
        calls, _ = self._save(monkeypatch, kea_db_port=3307)
        assert ("kea_db", "port", "3307") in calls[0]

    def test_a_blank_password_is_never_written(self, monkeypatch):
        calls, _ = self._save(monkeypatch)
        assert not [i for i in calls[0] if i[1] in ("api_pass", "password")]
        calls, _ = self._save(monkeypatch, api_pass="a", kea_db_pass="b")
        assert ("kea", "api_pass", "a") in calls[0] and ("kea_db", "password", "b") in calls[0]


class TestTestKeaDb:
    def test_it_tests_with_the_port_and_ca_the_pool_will_use(self, monkeypatch):
        from jen import extensions

        seen = []
        monkeypatch.setattr("jen.services.dbexport.test_connection", lambda *a: seen.append(a) or (True, {}))
        monkeypatch.setattr(extensions, "KEA_DB_PORT", 3307)
        monkeypatch.setattr(extensions, "KEA_DB_SSL_CA", "/etc/jen/ssl/db-ca.pem")
        setup_wizard.test_kea_db("h", "u", "p", "kea")
        assert seen == [("h", 3307, "u", "p", "kea", "/etc/jen/ssl/db-ca.pem")]

    def test_a_typed_port_wins_over_the_saved_one(self, monkeypatch):
        from jen import extensions

        seen = []
        monkeypatch.setattr("jen.services.dbexport.test_connection", lambda *a: seen.append(a) or (True, {}))
        monkeypatch.setattr(extensions, "KEA_DB_PORT", 3307)
        monkeypatch.setattr(extensions, "KEA_DB_SSL_CA", "")
        setup_wizard.test_kea_db("h", "u", "p", "kea", port=3310)
        assert seen[0][1] == 3310


# ── probe_v6() / enable_v6() — mocked kea.probe_command, no real Kea ────────


def _v6_replies(arguments=None, version="3.2.0", config_error=None):
    """A fake kea.probe_command: version-get answers, config-get answers `arguments` (or fails)."""

    def fake(url, user, pwd, command, **kw):
        if command == "version-get":
            return {"result": 0, "arguments": {"extended": version}, "text": ""}, ""
        assert command == "config-get"
        if config_error:
            return None, config_error
        return {"result": 0, "arguments": arguments}, ""

    return fake


@pytest.fixture
def no_known_v6(monkeypatch):
    from jen import extensions

    monkeypatch.setattr(extensions, "SUBNET6_MAP", {})


class TestProbeV6:
    def test_ok_shape_with_subnets(self, monkeypatch, no_known_v6):
        args = {"Dhcp6": {"subnet6": [{"id": 1, "subnet": "2001:db8::/64"}, {"id": 2, "subnet": "2001:db8:1::/64"}]}}
        monkeypatch.setattr("jen.services.kea.probe_command", _v6_replies(args))
        result = setup_wizard.probe_v6("http://kea:8000", "u", "p", omit_service=False)
        assert result["ok"] is True
        assert result["version"] == "3.2.0"
        assert result["subnet6_count"] == 2
        assert result["proposed_subnets6"] == {
            1: {"name": "Subnet1", "cidr": "2001:db8::/64", "paired_subnet4_id": None},
            2: {"name": "Subnet2", "cidr": "2001:db8:1::/64", "paired_subnet4_id": None},
        }
        assert result["orphaned_subnets6"] == {}

    def test_unreachable_is_a_clean_failure(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea.probe_command", lambda *a, **kw: (None, "connection refused"))
        result = setup_wizard.probe_v6("http://kea:8000", "u", "p", omit_service=False)
        assert result["ok"] is False
        assert result["error"] == "connection refused"
        assert result["subnet6_count"] == 0
        assert result["proposed_subnets6"] == {}

    def test_a_failed_config_get_is_not_an_answer(self, monkeypatch):
        """Item c/d — this used to read as ok with 0 subnets, and "Manage IPv6 in Jen" would replace
        [subnets6] with nothing. The version is still reported; nothing is proposed."""
        monkeypatch.setattr("jen.services.kea.probe_command", _v6_replies(config_error="config-get not permitted"))
        result = setup_wizard.probe_v6("http://kea:8000", "u", "p", omit_service=False)
        assert result["ok"] is False
        assert "config-get failed: config-get not permitted" in result["error"]
        assert result["version"] == "3.2.0"
        assert result["proposed_subnets6"] == {}

    def test_a_dhcp4_endpoint_is_not_a_dhcp6_answer(self, monkeypatch):
        """Item d — any Kea endpoint used to pass: a dhcp4 control socket answers version-get."""
        monkeypatch.setattr("jen.services.kea.probe_command", _v6_replies({"Dhcp4": {"subnet4": []}, "hash": "abc"}))
        result = setup_wizard.probe_v6("http://kea:8004", "u", "p", omit_service=True)
        assert result["ok"] is False
        assert "not kea-dhcp6" in result["error"] and "Dhcp4" in result["error"]
        assert result["subnet6_count"] == 0

    def test_a_missing_dhcp6_key_is_not_zero_subnets(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea.probe_command", _v6_replies({}))
        result = setup_wizard.probe_v6("http://kea:8000", "u", "p", omit_service=False)
        assert result["ok"] is False and "not kea-dhcp6" in result["error"]

    def test_a_dhcp6_with_no_subnets_is_a_real_answer(self, monkeypatch, no_known_v6):
        monkeypatch.setattr("jen.services.kea.probe_command", _v6_replies({"Dhcp6": {}}))
        result = setup_wizard.probe_v6("http://kea:8000", "u", "p", omit_service=False)
        assert result["ok"] is True and result["subnet6_count"] == 0

    def test_a_known_subnet_keeps_its_name_and_pairing(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(
            extensions,
            "SUBNET6_MAP",
            {
                1: {"name": "Office v6", "cidr": "2001:db8::/64", "paired_subnet4_id": 10},
                9: {"name": "Gone", "cidr": "2001:db8:9::/64", "paired_subnet4_id": None},
            },
        )
        args = {"Dhcp6": {"subnet6": [{"id": 1, "subnet": "2001:db8::/64"}, {"id": 2, "subnet": "2001:db8:2::/64"}]}}
        monkeypatch.setattr("jen.services.kea.probe_command", _v6_replies(args))
        result = setup_wizard.probe_v6("http://kea:8000", "u", "p", omit_service=False)
        assert result["proposed_subnets6"][1] == {"name": "Office v6", "cidr": "2001:db8::/64", "paired_subnet4_id": 10}
        assert result["proposed_subnets6"][2]["name"] == "Subnet2"
        assert result["orphaned_subnets6"] == {
            9: {"name": "Gone", "cidr": "2001:db8:9::/64", "paired_subnet4_id": None}
        }


class TestMergeSubnets6:
    def test_same_id_and_network_keeps_the_entry(self):
        known = {1: {"name": "Office", "cidr": "2001:db8::/64", "paired_subnet4_id": 4}}
        proposed, orphaned = setup_wizard.merge_subnets6(
            {1: "2001:DB8:0::/64"}, known
        )  # same network, spelled differently
        assert proposed == {1: known[1]}
        assert orphaned == {}

    def test_a_reused_id_on_a_different_network_gets_a_default_name_and_no_pairing(self):
        known = {1: {"name": "Office", "cidr": "2001:db8::/64", "paired_subnet4_id": 4}}
        proposed, orphaned = setup_wizard.merge_subnets6({1: "2001:db8:ffff::/64"}, known)
        assert proposed == {1: {"name": "Subnet1", "cidr": "2001:db8:ffff::/64", "paired_subnet4_id": None}}
        assert orphaned == {}

    def test_what_the_daemon_did_not_report_is_orphaned_never_dropped(self):
        known = {5: {"name": "Old", "cidr": "2001:db8:5::/64", "paired_subnet4_id": None}}
        proposed, orphaned = setup_wizard.merge_subnets6({}, known)
        assert proposed == {} and orphaned == known


class TestEnableV6:
    """v5.67.0-beta.8 (Q120, item c) — a merge into what Jen already has, not a replace."""

    def _run(self, monkeypatch, known, proposed, remove=frozenset(), write_error=None):
        from jen import extensions

        calls = {"subnets6": [], "values": [], "flag": []}
        monkeypatch.setattr(extensions, "SUBNET6_MAP", known)

        def write_subnets6(subnets):
            if write_error:
                raise ValueError(write_error)
            calls["subnets6"].append(subnets)

        monkeypatch.setattr("jen.config.app_config.write_values", lambda items: calls["values"].append(items))
        monkeypatch.setattr("jen.config.app_config.write_subnets6", write_subnets6)
        monkeypatch.setattr("jen.models.user.set_global_setting", lambda key, value: calls["flag"].append((key, value)))
        error = setup_wizard.enable_v6("http://kea:8006", proposed, remove)
        return error, calls

    def test_writes_endpoint_subnets_and_the_flag(self, monkeypatch):
        proposed = {1: {"name": "Subnet1", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        error, calls = self._run(monkeypatch, {}, proposed)
        assert error is None
        assert calls["values"] == [[("kea6", "api_url", "http://kea:8006")]]
        assert calls["subnets6"] == [proposed]
        assert calls["flag"] == [("ipv6_enabled", "true")]

    def test_what_jen_already_has_survives_unless_it_was_ticked_for_removal(self, monkeypatch):
        known = {
            1: {"name": "Office v6", "cidr": "2001:db8::/64", "paired_subnet4_id": 10},
            9: {"name": "Gone", "cidr": "2001:db8:9::/64", "paired_subnet4_id": None},
            8: {"name": "Other", "cidr": "2001:db8:8::/64", "paired_subnet4_id": 3},
        }
        proposed = {1: dict(known[1]), 2: {"name": "Subnet2", "cidr": "2001:db8:2::/64", "paired_subnet4_id": None}}
        _error, calls = self._run(monkeypatch, known, proposed, remove={9})
        written = calls["subnets6"][0]
        assert set(written) == {1, 2, 8}, "9 was removed on purpose; 8 was not reported but nobody asked to drop it"
        assert written[1]["paired_subnet4_id"] == 10 and written[1]["name"] == "Office v6"

    def test_a_refused_name_changes_nothing_else(self, monkeypatch):
        """The subnets are written first: a ValueError leaves no URL, no flag — no half-enabled IPv6."""
        proposed = {1: {"name": "Bad=Name", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        error, calls = self._run(monkeypatch, {}, proposed, write_error="name contains a forbidden character")
        assert error == "name contains a forbidden character"
        assert calls["values"] == [] and calls["flag"] == []


class TestHaPeerView:
    """v5.67.0-beta.8 (Q120, item m) — Kea's HA peers and the servers Jen manages are two facts."""

    HA = {
        "this_server_name": "server1",
        "mode": "hot-standby",
        "peers": [
            {"name": "server1", "url": "http://192.0.2.1:8000/", "role": "primary"},
            {"name": "server2", "url": "http://192.0.2.2:8000/", "role": "standby"},
        ],
    }

    def test_two_peers_and_one_managed_server_read_as_two_facts(self):
        view = setup_wizard.ha_peer_view(
            self.HA, [{"id": 1, "name": "Kea Server 1", "api_url": "http://192.0.2.1:8000"}]
        )
        assert (view["detected"], view["managed"]) == (2, 1)
        by_name = {p["name"]: p for p in view["peers"]}
        assert by_name["server1"]["managed"] is True and by_name["server1"]["add_url"] == ""
        assert by_name["server2"]["managed"] is False
        assert by_name["server2"]["add_url"] == "http://192.0.2.2:8000"
        assert by_name["server2"]["add_role"] == "standby"

    def test_a_peer_already_managed_by_host_or_by_name_is_not_offered(self):
        servers = [
            {"id": 1, "name": "Kea Server 1", "api_url": "http://192.0.2.1:8000"},
            {"id": 2, "name": "x", "api_url": "http://192.0.2.2:8004"},
        ]
        view = setup_wizard.ha_peer_view(self.HA, servers)
        assert (view["detected"], view["managed"]) == (2, 2)
        assert all(p["managed"] for p in view["peers"])
        by_name = setup_wizard.ha_peer_view(self.HA, [{"id": 7, "name": "Server2", "api_url": "http://other:8000"}])
        assert {p["name"]: p["managed"] for p in by_name["peers"]}["server2"] is True

    def test_no_ha_hook_is_none(self):
        assert setup_wizard.ha_peer_view(None, []) is None

    def test_roles_map_to_jens_own(self):
        lb = dict(self.HA, mode="load-balancing", peers=[{"name": "a", "url": "http://a:1", "role": "secondary"}])
        assert setup_wizard.ha_peer_view(lb, [])["peers"][0]["add_role"] == "peer"
        hs = dict(self.HA, peers=[{"name": "a", "url": "http://a:1", "role": "primary"}])
        assert setup_wizard.ha_peer_view(hs, [])["peers"][0]["add_role"] == "primary"

    def test_an_ipv6_peer_url_stays_bracketed_and_carries_no_credentials(self):
        ha = dict(self.HA, peers=[{"name": "p", "url": "http://user:pw@[2001:db8::2]:8000/x", "role": "standby"}])
        peer = setup_wizard.ha_peer_view(ha, [])["peers"][0]
        assert peer["add_url"] == "http://[2001:db8::2]:8000"
        assert "pw" not in peer["add_url"]


# ── discover() — service layer mocked, no real Kea ──────────────────────────


class TestDiscover:
    def test_shape_when_everything_answers(self, monkeypatch):
        caps = MagicMock(
            reachable=True,
            kea_version_text="2.7.5",
            host_cmds=True,
            lease_cmds=True,
            ha_commands=False,
            ddns=False,
        )
        monkeypatch.setattr("jen.services.capabilities.for_primary", lambda **kw: caps)
        monkeypatch.setattr(
            "jen.services.kea.kea_command",
            lambda *a, **kw: {"result": 0, "arguments": {"Dhcp4": {"subnet4": []}}},
        )
        monkeypatch.setattr("jen.services.kea_ha.ha_config", lambda cfg: None)
        monkeypatch.setattr(
            "jen.services.config_drift.fetch_live_subnet_map",
            lambda family="v4": {1: "10.0.0.0/24", 2: "10.0.1.0/24"},
        )
        monkeypatch.setattr(setup_wizard, "_ipv6_enabled", lambda: False)

        found = setup_wizard.discover()
        assert found["reachable"] is True
        assert found["kea_version"] == "2.7.5"
        assert found["hooks"] == {"host_cmds": True, "lease_cmds": True, "ha_commands": False, "ddns": False}
        assert found["ha"] is None
        assert found["ipv6_enabled"] is False
        assert found["proposed_subnets"] == {
            1: {"name": "Subnet1", "cidr": "10.0.0.0/24"},
            2: {"name": "Subnet2", "cidr": "10.0.1.0/24"},
        }
        assert found["orphaned_subnets"] == {}

    def _mock_discover_deps(self, monkeypatch, *, live_subnets, known_subnets):
        from jen import extensions

        caps = MagicMock(
            reachable=True, kea_version_text="2.7.5", host_cmds=True, lease_cmds=True, ha_commands=False, ddns=False
        )
        monkeypatch.setattr("jen.services.capabilities.for_primary", lambda **kw: caps)
        monkeypatch.setattr(
            "jen.services.kea.kea_command",
            lambda *a, **kw: {"result": 0, "arguments": {"Dhcp4": {"subnet4": []}}},
        )
        monkeypatch.setattr("jen.services.kea_ha.ha_config", lambda cfg: None)
        monkeypatch.setattr("jen.services.config_drift.fetch_live_subnet_map", lambda family="v4": live_subnets)
        monkeypatch.setattr(setup_wizard, "_ipv6_enabled", lambda: False)
        monkeypatch.setattr(extensions, "SUBNET_MAP", known_subnets)

    def test_a_subnet_jen_already_knows_by_the_same_id_and_cidr_keeps_its_name(self, monkeypatch):
        # v5.67.0-beta.5 (Q117, item h) — this used to re-propose
        # "Subnet<id>" for every live subnet every time /setup was
        # revisited, renaming away whatever the operator had already
        # called it.
        self._mock_discover_deps(
            monkeypatch,
            live_subnets={1: "10.0.0.0/24"},
            known_subnets={1: {"name": "Office LAN", "cidr": "10.0.0.0/24"}},
        )
        found = setup_wizard.discover()
        assert found["proposed_subnets"] == {1: {"name": "Office LAN", "cidr": "10.0.0.0/24"}}

    def test_a_changed_cidr_under_a_reused_id_proposes_a_fresh_default_name(self, monkeypatch):
        self._mock_discover_deps(
            monkeypatch,
            live_subnets={1: "10.0.9.0/24"},
            known_subnets={1: {"name": "Office LAN", "cidr": "10.0.0.0/24"}},
        )
        found = setup_wizard.discover()
        assert found["proposed_subnets"] == {1: {"name": "Subnet1", "cidr": "10.0.9.0/24"}}

    def test_a_known_subnet_kea_did_not_report_is_orphaned_not_dropped(self, monkeypatch):
        self._mock_discover_deps(
            monkeypatch,
            live_subnets={1: "10.0.0.0/24"},
            known_subnets={
                1: {"name": "Office LAN", "cidr": "10.0.0.0/24"},
                2: {"name": "Old VLAN", "cidr": "10.0.1.0/24"},
            },
        )
        found = setup_wizard.discover()
        assert found["proposed_subnets"] == {1: {"name": "Office LAN", "cidr": "10.0.0.0/24"}}
        assert found["orphaned_subnets"] == {2: {"name": "Old VLAN", "cidr": "10.0.1.0/24"}}

    def test_a_failed_config_get_does_not_raise(self, monkeypatch):
        caps = MagicMock(
            reachable=False, kea_version_text="", host_cmds=False, lease_cmds=False, ha_commands=False, ddns=False
        )
        monkeypatch.setattr("jen.services.capabilities.for_primary", lambda **kw: caps)
        monkeypatch.setattr(
            "jen.services.kea.kea_command", lambda *a, **kw: (_ for _ in ()).throw(ConnectionError("down"))
        )
        monkeypatch.setattr("jen.services.config_drift.fetch_live_subnet_map", lambda family="v4": {})
        monkeypatch.setattr(setup_wizard, "_ipv6_enabled", lambda: False)

        found = setup_wizard.discover()
        assert found["reachable"] is False
        assert found["ha"] is None
        assert found["proposed_subnets"] == {}


class TestSaveSubnets:
    """v5.67.0-beta.5 (Q117, item h) — save_subnets() merges into Jen's
    FULL existing subnet map; it never replaces it wholesale, and never
    drops an orphaned subnet unless its id is explicitly in
    `remove_ids`."""

    def _mock_subnet_map(self, monkeypatch, known_subnets):
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", known_subnets)

    def test_renames_apply_and_everything_else_survives(self, monkeypatch):
        self._mock_subnet_map(
            monkeypatch,
            {
                1: {"name": "Office LAN", "cidr": "10.0.0.0/24"},
                2: {"name": "Old VLAN", "cidr": "10.0.1.0/24"},
            },
        )
        calls = []
        monkeypatch.setattr("jen.config.app_config.write_subnets", lambda d: calls.append(d))
        merged, error = setup_wizard.save_subnets({1: {"name": "Renamed LAN", "cidr": "10.0.0.0/24"}})
        assert error is None
        assert merged == {
            1: {"name": "Renamed LAN", "cidr": "10.0.0.0/24"},
            2: {"name": "Old VLAN", "cidr": "10.0.1.0/24"},
        }
        assert calls == [merged]

    def test_remove_ids_drops_only_the_checked_orphans(self, monkeypatch):
        self._mock_subnet_map(
            monkeypatch,
            {
                1: {"name": "Office LAN", "cidr": "10.0.0.0/24"},
                2: {"name": "Old VLAN", "cidr": "10.0.1.0/24"},
                3: {"name": "Another Old One", "cidr": "10.0.2.0/24"},
            },
        )
        monkeypatch.setattr("jen.config.app_config.write_subnets", lambda d: None)
        merged, error = setup_wizard.save_subnets({}, remove_ids={2})
        assert error is None
        assert merged == {
            1: {"name": "Office LAN", "cidr": "10.0.0.0/24"},
            3: {"name": "Another Old One", "cidr": "10.0.2.0/24"},
        }

    def test_an_unchecked_orphan_is_never_dropped(self, monkeypatch):
        self._mock_subnet_map(
            monkeypatch, {1: {"name": "A", "cidr": "10.0.0.0/24"}, 2: {"name": "B", "cidr": "10.0.1.0/24"}}
        )
        monkeypatch.setattr("jen.config.app_config.write_subnets", lambda d: None)
        merged, error = setup_wizard.save_subnets({})
        assert error is None
        assert 2 in merged

    def test_a_bad_name_is_refused_and_nothing_is_written(self, monkeypatch):
        self._mock_subnet_map(monkeypatch, {1: {"name": "A", "cidr": "10.0.0.0/24"}})
        calls = []
        monkeypatch.setattr(
            "jen.config.app_config.write_subnets",
            lambda d: calls.append(d) or (_ for _ in ()).throw(ValueError("subnet 1: Name must not contain a comma")),
        )
        merged, error = setup_wizard.save_subnets({1: {"name": "A, B", "cidr": "10.0.0.0/24"}})
        assert error == "subnet 1: Name must not contain a comma"
        assert calls  # write_subnets WAS called (it's the one that raised) — caller sees the error, not a crash


# ── step 3: the Kea host helper — pure/mocked parts ─────────────────────────


class TestSshTarget:
    def test_ready_needs_both_host_and_user(self):
        assert setup_wizard.ssh_target_ready({"ssh_host": "", "ssh_user": ""}) is False
        assert setup_wizard.ssh_target_ready({"ssh_host": "kea.lan", "ssh_user": ""}) is False
        assert setup_wizard.ssh_target_ready({"ssh_host": "", "ssh_user": "jen"}) is False
        assert setup_wizard.ssh_target_ready({"ssh_host": "kea.lan", "ssh_user": "jen"}) is True

    def test_save_rejects_an_invalid_host_or_user(self):
        ok, err = setup_wizard.save_ssh_target("-oProxyCommand=x", "jen")
        assert ok is False and err

        ok, err = setup_wizard.save_ssh_target("kea.lan", "not a valid user!")
        assert ok is False and err

    def test_save_writes_kea_ssh_section_on_success(self, monkeypatch):
        calls = []
        monkeypatch.setattr("jen.config.app_config.write_values", lambda items: calls.append(items))
        ok, err = setup_wizard.save_ssh_target("kea.lan", "jen")
        assert ok is True and err == ""
        assert calls == [[("kea_ssh", "host", "kea.lan"), ("kea_ssh", "user", "jen")]]


class TestTestSsh:
    def test_ok_when_connect_succeeds(self, monkeypatch):
        ssh = MagicMock()
        monkeypatch.setattr("jen.services.kea6._connect_ssh", lambda server: ssh)
        result = setup_wizard.test_ssh({"ssh_host": "kea.lan"})
        assert result == {"ok": True, "detail": ""}
        ssh.close.assert_called_once()

    def test_failure_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea6._connect_ssh", lambda server: (_ for _ in ()).throw(OSError("refused")))
        result = setup_wizard.test_ssh({"ssh_host": "kea.lan"})
        assert result["ok"] is False
        assert "refused" in result["detail"]


class TestHelperWrappers:
    def test_helper_status_passes_through_check_helper(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea_host.check_helper", lambda server: {"ok": True, "version": 6})
        assert setup_wizard.helper_status({"id": 1}) == {"ok": True, "version": 6}

    def test_install_helper_step_passes_through_install_helper(self, monkeypatch):
        sentinel = {"ok": False, "version": None, "code": "sudoerror", "detail": "no dice"}
        monkeypatch.setattr("jen.services.kea_host.install_helper", lambda server: sentinel)
        assert setup_wizard.install_helper_step(_SSH_SERVER) is sentinel

    def test_install_helper_step_refuses_without_an_ssh_target(self, monkeypatch):
        """v5.67.0-beta.8 (Q120, item a) — nothing to connect to, so nothing is attempted."""

        def never(server):
            raise AssertionError("must not reach kea_host without an SSH host and user")

        monkeypatch.setattr("jen.services.kea_host.install_helper", never)
        for server in ({"id": 1}, {"id": 1, "ssh_host": "kea.lan"}, {"id": 1, "ssh_user": "jen"}):
            result = setup_wizard.install_helper_step(server)
            assert result["ok"] is False and result["code"] == "no-ssh"
            assert result["detail"] == setup_wizard.NO_SSH_TARGET

    def test_helper_download_command_passes_through(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea_host._helper_download_command", lambda: "curl ... | sudo bash")
        assert setup_wizard.helper_download_command() == "curl ... | sudo bash"


# ── step 4: baseline — mocked ────────────────────────────────────────────────


_SSH_SERVER = {"id": 1, "name": "kea-a", "ssh_host": "kea.lan", "ssh_user": "jen"}


class TestCaptureBaseline:
    def test_unreadable_config_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea_host.read_config", lambda server, service, errors=None: None)
        result = setup_wizard.capture_baseline(_SSH_SERVER, "dhcp4")
        assert result["ok"] is False and result["revision"] is None
        assert "SSH" in result["detail"]

    def test_the_transports_own_reason_is_what_the_operator_reads(self, monkeypatch):
        def read(server, service, errors=None):
            errors.append("SSH to jen@kea.lan failed — OSError: refused")

        monkeypatch.setattr("jen.services.kea_host.read_config", read)
        result = setup_wizard.capture_baseline(_SSH_SERVER, "dhcp4")
        assert result["detail"] == "SSH to jen@kea.lan failed — OSError: refused"

    def test_a_readable_config_returns_the_latest_revision(self, monkeypatch):
        monkeypatch.setattr("jen.services.kea_host.read_config", lambda server, service, errors=None: {"Dhcp4": {}})
        monkeypatch.setattr(
            "jen.services.config_revisions.latest", lambda server_id, service: {"id": 1, "source": "baseline"}
        )
        result = setup_wizard.capture_baseline(_SSH_SERVER, "dhcp4")
        assert result == {"ok": True, "revision": {"id": 1, "source": "baseline"}, "detail": ""}

    def test_refuses_early_without_an_ssh_host(self, monkeypatch):
        """v5.67.0-beta.8 (Q120, item a) — "Skip" on the helper step, then "Capture baseline"."""

        def never(server, service, errors=None):
            raise AssertionError("must not read a config with no SSH host to read it from")

        monkeypatch.setattr("jen.services.kea_host.read_config", never)
        result = setup_wizard.capture_baseline({"id": 1, "ssh_host": "", "ssh_user": ""}, "dhcp4")
        assert result["ok"] is False
        assert result["detail"] == setup_wizard.NO_SSH_TARGET


# ── step 5: recovery point ───────────────────────────────────────────────────


class TestRecoveryBundleStatus:
    """v5.67.0-beta.5 (Q117, item i) — real bundle state, not "was a
    button clicked". routes/database.py's recovery_bundle() route is the
    only writer of these three settings, only once its stream has
    actually finished sending."""

    def _mock_settings(self, monkeypatch, store):
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": store.get(key, default))

    def test_never_downloaded(self, monkeypatch):
        self._mock_settings(monkeypatch, {})
        status = setup_wizard.recovery_bundle_status()
        assert status == {"exists": False, "at": "", "size": 0, "excluded_audit_history": False, "fresh": False}

    def test_downloaded_after_this_setup_run_started_is_fresh(self, monkeypatch):
        self._mock_settings(
            monkeypatch,
            {
                setup_wizard._STARTED_KEY: "2026-10-01T10:00:00",
                "last_recovery_bundle_at": "2026-10-01T10:05:00",
                "last_recovery_bundle_size": "12345",
                "last_recovery_bundle_excluded_audit": "true",
            },
        )
        status = setup_wizard.recovery_bundle_status()
        assert status["exists"] is True
        assert status["fresh"] is True
        assert status["size"] == 12345
        assert status["excluded_audit_history"] is True

    def test_an_old_bundle_from_before_this_setup_run_is_not_fresh(self, monkeypatch):
        self._mock_settings(
            monkeypatch,
            {
                setup_wizard._STARTED_KEY: "2026-10-01T10:00:00",
                "last_recovery_bundle_at": "2026-01-01T00:00:00",
                "last_recovery_bundle_size": "999",
                "last_recovery_bundle_excluded_audit": "false",
            },
        )
        status = setup_wizard.recovery_bundle_status()
        assert status["exists"] is True
        assert status["fresh"] is False

    def test_malformed_timestamp_is_not_fresh_not_raised(self, monkeypatch):
        self._mock_settings(
            monkeypatch,
            {setup_wizard._STARTED_KEY: "2026-10-01T10:00:00", "last_recovery_bundle_at": "not-a-timestamp"},
        )
        status = setup_wizard.recovery_bundle_status()
        assert status["exists"] is True
        assert status["fresh"] is False

    def test_an_aware_started_against_a_naive_bundle_time_does_not_raise(self, monkeypatch):
        """v5.67.0-beta.7 (Q119, item f) — the real-world shape: _STARTED_KEY
        is always written aware (utc_iso()), but a value stored before
        this fix (or written by code this fix didn't reach) could still be
        naive. A bare datetime.fromisoformat() comparison between the two
        raises TypeError, which the try/except here only ever caught as
        ValueError — this is the exact mismatch that was reproduced as a
        500 on every admin's /setup/recovery, its "done" POST, and
        /getting-started."""
        self._mock_settings(
            monkeypatch,
            {
                setup_wizard._STARTED_KEY: setup_wizard.utc_iso(),
                "last_recovery_bundle_at": "2099-01-01T00:00:00",  # naive, in the future relative to "now"
            },
        )
        status = setup_wizard.recovery_bundle_status()  # must not raise
        assert status["exists"] is True
        assert status["fresh"] is True


class TestUtcIsoAndParseUtc:
    """v5.67.0-beta.7 (Q119, item f) — the one aware-UTC pair every
    caller that needs to compare against the wizard's own clock uses,
    replacing the old _utcnow_iso() (which had no matching parser, so
    every caller rolled its own datetime.fromisoformat() and none of
    them normalized a naive value to UTC first)."""

    def test_utc_iso_round_trips_through_parse_utc(self):
        parsed = setup_wizard.parse_utc(setup_wizard.utc_iso())
        assert parsed.tzinfo is not None

    def test_parse_utc_treats_a_naive_value_as_utc(self):
        from datetime import timezone

        parsed = setup_wizard.parse_utc("2026-10-01T10:00:00")
        assert parsed.tzinfo == timezone.utc

    def test_parse_utc_preserves_a_non_utc_aware_offset(self):
        parsed = setup_wizard.parse_utc("2026-10-01T10:00:00+05:00")
        assert parsed.utcoffset().total_seconds() == 5 * 3600

    def test_an_aware_and_a_naive_timestamp_compare_without_raising(self):
        aware = setup_wizard.parse_utc(setup_wizard.utc_iso())
        naive = setup_wizard.parse_utc("2099-01-01T00:00:00")
        assert naive > aware  # must not raise TypeError

    def test_parse_utc_still_raises_valueerror_for_genuine_garbage(self):
        import pytest

        with pytest.raises(ValueError):
            setup_wizard.parse_utc("not-a-timestamp")


# ── the wizard's own clock ───────────────────────────────────────────────────


class TestWizardClock:
    def test_mark_started_only_writes_once(self, monkeypatch):
        store = {}
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": store.get(key, default))
        monkeypatch.setattr("jen.models.user.set_global_setting", lambda key, value: store.__setitem__(key, value))
        setup_wizard.mark_started()
        first = store[setup_wizard._STARTED_KEY]
        setup_wizard.mark_started()
        assert store[setup_wizard._STARTED_KEY] == first

    def test_elapsed_seconds_is_none_before_started(self, monkeypatch):
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "")
        assert setup_wizard.elapsed_seconds() is None

    def _store(self, monkeypatch, seed=None):
        store = dict(seed or {})
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": store.get(key, default))
        monkeypatch.setattr("jen.models.user.set_global_setting", lambda key, value: store.__setitem__(key, value))
        return store

    def test_the_completion_time_is_stored_when_the_last_step_resolves(self, monkeypatch):
        """v5.67.0-beta.8 (Q120, item j)."""
        store = self._store(monkeypatch)
        for step in setup_wizard.STEPS[:-1]:
            setup_wizard.set_step(step, "done")
        assert setup_wizard._COMPLETED_KEY not in store
        setup_wizard.set_step(setup_wizard.STEPS[-1], "skipped")
        assert setup_wizard.parse_utc(store[setup_wizard._COMPLETED_KEY])

    def test_a_later_revisit_does_not_move_the_completion_time(self, monkeypatch):
        store = self._store(monkeypatch)
        for step in setup_wizard.STEPS:
            setup_wizard.set_step(step, "done")
        first = store[setup_wizard._COMPLETED_KEY]
        setup_wizard.set_step(setup_wizard.STEPS[0], "skipped")
        assert store[setup_wizard._COMPLETED_KEY] == first

    def test_a_finished_wizard_reports_its_own_duration_not_the_time_since(self, monkeypatch):
        """The bug: "took N minutes" grew forever, measured to now."""
        self._store(
            monkeypatch,
            {
                setup_wizard._STARTED_KEY: "2026-01-01T10:00:00+00:00",
                setup_wizard._COMPLETED_KEY: "2026-01-01T10:42:30+00:00",
            },
        )
        assert setup_wizard.elapsed_seconds() == 42 * 60 + 30

    def test_an_unfinished_wizard_still_measures_to_now(self, monkeypatch):
        from datetime import datetime, timedelta, timezone

        started = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        self._store(monkeypatch, {setup_wizard._STARTED_KEY: started})
        assert 5 * 60 <= setup_wizard.elapsed_seconds() < 5 * 60 + 30

    def test_an_unreadable_completion_time_falls_back_to_now(self, monkeypatch):
        from datetime import datetime, timedelta, timezone

        started = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        self._store(
            monkeypatch,
            {setup_wizard._STARTED_KEY: started, setup_wizard._COMPLETED_KEY: "not a time"},
        )
        assert 2 * 60 <= setup_wizard.elapsed_seconds() < 2 * 60 + 30

    def test_get_state_never_starts_the_clock(self, monkeypatch):
        """get_state() is called by onboarding.checklist() on every page
        load — it must never have the side effect mark_started() has."""
        calls = []
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "")
        monkeypatch.setattr("jen.models.user.set_global_setting", lambda key, value: calls.append((key, value)))
        setup_wizard.get_state()
        assert calls == []


# ── routes — access control ─────────────────────────────────────────────────


class TestSetupAccessControl:
    def test_superadmin_sees_the_connect_step(self, logged_in_client):
        r = logged_in_client.get("/setup/connect")
        assert r.status_code == 200
        assert b"Kea API URL" in r.data

    def test_admin_is_turned_away(self, client, db):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, allowed_subnets=[1], role="admin")
        r = c.get("/setup/connect")
        assert r.status_code != 200
        assert b"Kea API URL" not in r.data

    def test_viewer_is_turned_away(self, client, db):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, allowed_subnets=[1], role="viewer")
        r = c.get("/setup/connect")
        assert r.status_code != 200
        assert b"Kea API URL" not in r.data

    def test_setup_home_redirects_to_the_current_step(self, logged_in_client):
        r = logged_in_client.get("/setup/")
        assert r.status_code == 302
        assert "/setup/connect" in r.headers["Location"]

    @pytest.mark.parametrize(
        "path,marker",
        [
            ("/setup/helper", b"Kea host helper"),
            ("/setup/baseline", b"Capture a baseline"),
            ("/setup/recovery", b"recovery point"),
            ("/setup/investigate", b"Investigate a client"),
        ],
    )
    def test_superadmin_sees_each_remaining_step(self, logged_in_client, path, marker):
        r = logged_in_client.get(path)
        assert r.status_code == 200
        assert marker.lower() in r.data.lower()

    @pytest.mark.parametrize("path", ["/setup/helper", "/setup/baseline", "/setup/recovery", "/setup/investigate"])
    def test_admin_is_turned_away_from_every_remaining_step(self, client, db, path):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, allowed_subnets=[1], role="admin")
        r = c.get(path)
        assert r.status_code != 200

    @pytest.mark.parametrize("path", ["/setup/helper", "/setup/baseline", "/setup/recovery", "/setup/investigate"])
    def test_viewer_is_turned_away_from_every_remaining_step(self, client, db, path):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, allowed_subnets=[1], role="viewer")
        r = c.get(path)
        assert r.status_code != 200


class TestInvestigateVisitRedirect:
    """v5.67.0-beta.5 (Q117, item k) — the wizard's own last step used to
    open only the narrow /tools/explain page; the full six-tab
    Investigation page (jen/routes/client.py, since v5.63.0) is what a
    superadmin actually lands on now."""

    def test_choosing_a_lease_opens_the_investigation_page_overview_tab(self, logged_in_client, db):
        r = logged_in_client.post("/setup/investigate/visit", data={"mac": "aa:bb:cc:dd:ee:ff"})
        assert r.status_code == 302
        assert r.headers["Location"] == "/client?q=aa:bb:cc:dd:ee:ff"

    def test_skipping_without_a_mac_stays_on_the_step(self, logged_in_client, db):
        r = logged_in_client.post("/setup/investigate/visit", data={})
        assert r.status_code == 302
        assert "/setup/investigate" in r.headers["Location"]
        assert "/client" not in r.headers["Location"]


class TestSshFailuresAreNotA500:
    """v5.67.0-beta.8 (Q120, item a) — "Skip" on the helper step, then "Capture baseline" (no SSH host), and
    "Install the helper" before the key is authorised (the normal first try) both used to propagate a
    paramiko or socket exception out of the route."""

    def _server(self, monkeypatch, **over):
        server = {"id": 1, "name": "kea-a", "ssh_host": "", "ssh_user": "", **over}
        monkeypatch.setattr(setup_wizard, "primary_server", lambda: server)
        return server

    def test_capture_baseline_with_no_ssh_host_says_so(self, logged_in_client, db, monkeypatch):
        self._server(monkeypatch)
        r = logged_in_client.post("/setup/baseline", data={}, follow_redirects=True)
        assert r.status_code == 200
        assert b"Set the SSH host and user" in r.data

    def test_capture_baseline_over_a_refused_connection_names_the_connection(self, logged_in_client, db, monkeypatch):
        self._server(monkeypatch, ssh_host="kea.lan", ssh_user="jen")

        def refused(server):
            raise OSError("Connection refused")

        monkeypatch.setattr("jen.services.kea6._connect_ssh", refused)
        r = logged_in_client.post("/setup/baseline", data={}, follow_redirects=True)
        assert r.status_code == 200
        assert b"SSH to jen@kea.lan failed" in r.data

    def test_install_the_helper_before_the_key_is_authorised_is_a_message_not_a_500(
        self, logged_in_client, db, monkeypatch
    ):
        self._server(monkeypatch, ssh_host="kea.lan", ssh_user="jen")

        def refused(server):
            raise OSError("Authentication failed.")

        monkeypatch.setattr("jen.services.kea6._connect_ssh", refused)
        r = logged_in_client.post("/setup/helper", data={"action": "install"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"SSH to jen@kea.lan failed" in r.data

    def test_install_the_helper_with_no_ssh_target_says_so(self, logged_in_client, db, monkeypatch):
        self._server(monkeypatch)
        r = logged_in_client.post("/setup/helper", data={"action": "install"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"Set the SSH host and user" in r.data


# ── the one-time entry redirect ─────────────────────────────────────────────
#
# v5.67.0 (Q115 step 3) — moved from force_password_change() to
# dashboard() itself: an answers-file install with
# JEN_INITIAL_ADMIN_PASSWORD already set never passes through forced
# password change at all (init_jen_db() seeds must_change_password=0
# directly), so the forced-password-change hook alone never fired for
# that path. dashboard() is the one page every successful login of every
# kind (forced change, a normal login, OIDC, a passkey) actually reaches.


class TestEntryRedirectOnDashboard:
    def _superadmin_session(self, client):
        with client.session_transaction() as sess:
            sess["_user_cache"] = {"id": 1, "username": "admin", "role": "superadmin", "session_timeout": None}
            sess["_user_id"] = "1"
            sess["_fresh"] = True

    def _admin_session(self, client):
        with client.session_transaction() as sess:
            sess["_user_cache"] = {"id": 1, "username": "admin", "role": "admin", "session_timeout": None}
            sess["_user_id"] = "1"
            sess["_fresh"] = True

    def test_superadmin_lands_on_setup_when_kea_is_unset(self, client, db, monkeypatch):
        from jen import extensions
        from jen.services import setup_wizard as sw

        monkeypatch.setattr(extensions, "KEA_API_URL", "")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "false")
        monkeypatch.setattr(sw, "mark_entry_redirect_shown", lambda: None)
        self._superadmin_session(client)
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 302
        assert "/setup" in r.headers["Location"]

    def test_the_redirect_fires_only_once(self, client, db, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_URL", "")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "true")
        self._superadmin_session(client)
        r = client.get("/", follow_redirects=False)
        assert r.status_code != 302 or "/setup" not in r.headers.get("Location", "")

    def test_non_superadmin_is_never_redirected(self, client, db, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_URL", "")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda key, default="": "false")
        self._admin_session(client)
        r = client.get("/", follow_redirects=False)
        assert r.status_code != 302 or "/setup" not in r.headers.get("Location", "")

    def test_force_password_change_always_goes_to_the_dashboard(self, client, db):
        with db.cursor() as cur:
            cur.execute("UPDATE users SET must_change_password=1 WHERE username='admin'")
        db.commit()
        self._superadmin_session(client)
        r = client.post(
            "/force-password-change",
            data={"new_password": "a-real-password-3", "confirm_password": "a-real-password-3"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "/setup" not in r.headers["Location"]


# ── v5.67.0-beta.8 (Q120) — the wizard's routes ─────────────────────────────


_CONNECTED = {
    "ok": True,
    "mode": "direct",
    "url": "http://kea.test:8000",
    "version": "3.2.0",
    "version_text": "3.2.0",
    "identified": "Dhcp4",
    "attempts": [{"url": "http://kea.test:8000", "typed": True, "mode": "direct", "error": ""}],
}


class TestConnectRoute:
    FORM = {
        "api_url": "http://kea.test:8000",
        "api_user": "u",
        "api_pass": "",
        "kea_db_host": "dbhost",
        "kea_db_user": "kea",
        "kea_db_pass": "",
        "kea_db_name": "kea",
    }

    def _capture(self, monkeypatch, connection=None, db_result=(True, {})):
        seen = {"conn": [], "db": [], "save": [], "steps": []}

        def fake_conn(url, user, password, **kw):
            seen["conn"].append({"url": url, "user": user, "password": password, **kw})
            return connection or _CONNECTED

        def fake_db(host, user, password, database, **kw):
            seen["db"].append({"host": host, "password": password, "database": database, **kw})
            return db_result

        monkeypatch.setattr(setup_wizard, "test_kea_connection", fake_conn)
        monkeypatch.setattr(setup_wizard, "test_kea_db", fake_db)
        monkeypatch.setattr(setup_wizard, "save_connection", lambda **kw: seen["save"].append(kw))
        monkeypatch.setattr(setup_wizard, "set_step", lambda *a: seen["steps"].append(a))
        return seen

    def test_a_blank_password_tests_with_the_stored_credential(self, logged_in_client, monkeypatch):
        """Item n — saved passwords are never rendered, so a revisit shows blank fields."""
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_PASS", "stored-api")
        monkeypatch.setattr(extensions, "KEA_DB_PASS", "stored-db")
        seen = self._capture(monkeypatch)
        r = logged_in_client.post("/setup/connect", data=self.FORM)
        assert r.status_code == 302 and r.headers["Location"].endswith("/setup/found")
        assert seen["conn"][0]["password"] == "stored-api"
        assert seen["db"][0]["password"] == "stored-db"
        # and the SAVE keeps the stored value: it is handed the blank one, which it never writes
        assert seen["save"][0]["api_pass"] == "" and seen["save"][0]["kea_db_pass"] == ""

    def test_a_typed_password_is_what_gets_tested(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_PASS", "stored-api")
        seen = self._capture(monkeypatch)
        logged_in_client.post("/setup/connect", data=dict(self.FORM, api_pass="typed", kea_db_pass="typed-db"))
        assert seen["conn"][0]["password"] == "typed" and seen["db"][0]["password"] == "typed-db"

    def test_a_form_with_no_client_certificate_probes_with_none_not_the_saved_one(self, logged_in_client, monkeypatch):
        """Item f."""
        from jen.services import kea

        seen = self._capture(monkeypatch)
        logged_in_client.post("/setup/connect", data=self.FORM)
        assert seen["conn"][0]["cert"] is kea.NO_CLIENT_CERT

    def test_an_unidentifiable_answer_keeps_the_mode_already_saved_for_that_url(self, logged_in_client, monkeypatch):
        """Item b — re-submitting Connect must not flip an existing direct-mode install."""
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea.test:8000/")
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        seen = self._capture(monkeypatch)
        logged_in_client.post("/setup/connect", data=self.FORM)
        assert seen["conn"][0]["default_mode"] == "direct"
        # a DIFFERENT url has no saved mode to keep
        logged_in_client.post("/setup/connect", data=dict(self.FORM, api_url="http://other.test:8000"))
        assert seen["conn"][1]["default_mode"] == "ca"

    def test_the_error_for_the_typed_url_comes_first_and_the_guess_second(self, logged_in_client, monkeypatch):
        """Item e — this used to flash attempts[-1], always the :8004 guess."""
        failed = {
            "ok": False,
            "mode": None,
            "url": None,
            "version": "",
            "version_text": "",
            "identified": None,
            "attempts": [
                {"url": "http://kea.test", "typed": True, "mode": "direct", "error": "401 Unauthorized"},
                {"url": "http://kea.test:8004", "typed": False, "mode": "direct", "error": "connection refused"},
            ],
        }
        self._capture(monkeypatch, connection=failed)
        r = logged_in_client.post("/setup/connect", data=dict(self.FORM, api_url="http://kea.test"))
        page = r.data.decode()
        assert "at http://kea.test: 401 Unauthorized" in page
        assert "Also tried http://kea.test:8004" in page
        assert page.index("401 Unauthorized") < page.index("Also tried")

    def test_a_bad_database_port_is_refused_before_anything_is_tested(self, logged_in_client, monkeypatch):
        seen = self._capture(monkeypatch)
        for bad in ("abc", "0", "70000"):
            r = logged_in_client.post("/setup/connect", data=dict(self.FORM, kea_db_port=bad))
            assert r.status_code == 200 and b"valid database port" in r.data
        assert seen["conn"] == [] and seen["save"] == []

    def test_the_typed_database_port_is_tested_and_saved(self, logged_in_client, monkeypatch):
        seen = self._capture(monkeypatch)
        logged_in_client.post("/setup/connect", data=dict(self.FORM, kea_db_port="3307"))
        assert seen["db"][0]["port"] == 3307
        assert seen["save"][0]["kea_db_port"] == 3307

    def test_an_answer_that_could_not_be_identified_says_so(self, logged_in_client, monkeypatch):
        self._capture(monkeypatch, connection=dict(_CONNECTED, identified=None, mode="ca"))
        r = logged_in_client.post("/setup/connect", data=self.FORM, follow_redirects=True)
        assert b"could not tell whether" in r.data

    def test_a_blank_form_renders_the_saved_password_hint_and_the_port(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_API_PASS", "stored-api")
        monkeypatch.setattr(extensions, "KEA_DB_PASS", "")
        r = logged_in_client.get("/setup/connect")
        assert b"leave blank to keep it" in r.data
        assert b'name="kea_db_port"' in r.data


class TestFoundRoute:
    def _found(self, **over):
        base = {
            "reachable": True,
            "kea_version": "3.2.0",
            "connection_mode": "direct",
            "hooks": {"host_cmds": True, "lease_cmds": True, "ha_commands": False, "ddns": False},
            "ha": None,
            "ha_view": None,
            "ipv6_enabled": False,
            "proposed_subnets": {1: {"name": "Subnet1", "cidr": "10.0.0.0/24"}},
            "orphaned_subnets": {},
        }
        base.update(over)
        return base

    def test_kea_unreachable_at_post_saves_nothing_and_leaves_the_step_open(self, logged_in_client, monkeypatch):
        """Item j — the typed names were dropped and the step marked done with subnets=0."""
        steps, saved = [], []
        monkeypatch.setattr(setup_wizard, "discover", lambda: self._found(reachable=False, proposed_subnets={}))
        monkeypatch.setattr(setup_wizard, "set_step", lambda *a: steps.append(a))
        monkeypatch.setattr(setup_wizard, "save_subnets", lambda *a: saved.append(a) or ({}, None))
        r = logged_in_client.post("/setup/found", data={"name_1": "Office"})
        assert r.status_code == 200
        assert b"Kea did not answer" in r.data
        assert steps == [] and saved == []

    def test_skipping_is_still_possible_when_kea_is_down(self, logged_in_client, monkeypatch):
        steps = []
        monkeypatch.setattr(setup_wizard, "discover", lambda: self._found(reachable=False, proposed_subnets={}))
        monkeypatch.setattr(setup_wizard, "set_step", lambda *a: steps.append(a))
        r = logged_in_client.post("/setup/found", data={"action": "skip"})
        assert r.status_code == 302 and steps == [("found", "skipped")]
        page = logged_in_client.get("/setup/found")
        assert b'value="skip"' in page.data, "an unreachable Kea must not leave the step with no way out"

    def test_the_page_shows_two_facts_and_an_add_this_peer_action(self, logged_in_client, monkeypatch):
        """Item m."""
        ha = {
            "this_server_name": "s1",
            "mode": "hot-standby",
            "peers": [
                {"name": "s1", "url": "http://192.0.2.1:8000/", "role": "primary"},
                {"name": "s2", "url": "http://192.0.2.2:8000/", "role": "standby"},
            ],
        }
        view = setup_wizard.ha_peer_view(ha, [{"id": 1, "name": "Kea Server 1", "api_url": "http://192.0.2.1:8000"}])
        monkeypatch.setattr(setup_wizard, "discover", lambda: self._found(ha=ha, ha_view=view))
        r = logged_in_client.get("/setup/found")
        page = r.data.decode()
        assert "Kea HA peers detected" in page and "Servers Jen manages" in page
        assert "Add this peer to Jen" in page
        assert "add_server_url=http%3A%2F%2F192.0.2.2%3A8000" in page
        assert "s1</strong>" not in page, "this very server is managed; only the other peer is offered"

    def test_enabling_ipv6_passes_the_ticked_removals_through(self, logged_in_client, monkeypatch):
        from jen.services import capabilities

        monkeypatch.setattr(setup_wizard, "discover", lambda: self._found())
        monkeypatch.setattr(capabilities, "is_direct", lambda: False)
        probe = {
            "ok": True,
            "error": "",
            "version": "3.2.0",
            "version_text": "3.2.0",
            "subnet6_count": 1,
            "proposed_subnets6": {1: {"name": "Subnet1", "cidr": "2001:db8::/64", "paired_subnet4_id": None}},
            "orphaned_subnets6": {
                8: {"name": "Old8", "cidr": "2001:db8:8::/64", "paired_subnet4_id": None},
                9: {"name": "Old9", "cidr": "2001:db8:9::/64", "paired_subnet4_id": None},
            },
        }
        monkeypatch.setattr(setup_wizard, "probe_v6", lambda *a, **kw: probe)
        calls = []
        monkeypatch.setattr(setup_wizard, "enable_v6", lambda url, proposed, remove: calls.append((url, remove)))
        r = logged_in_client.post("/setup/found", data={"action": "enable_v6", "remove6_9": "1"})
        assert r.status_code == 302
        assert calls and calls[0][1] == {9}, "only the ticked orphan, never 8"

    def test_a_refused_v6_name_is_shown_and_enables_nothing(self, logged_in_client, monkeypatch):
        from jen.services import capabilities

        monkeypatch.setattr(setup_wizard, "discover", lambda: self._found())
        monkeypatch.setattr(capabilities, "is_direct", lambda: False)
        probe = {
            "ok": True,
            "error": "",
            "version": "3.2.0",
            "version_text": "",
            "subnet6_count": 0,
            "proposed_subnets6": {},
            "orphaned_subnets6": {},
        }
        monkeypatch.setattr(setup_wizard, "probe_v6", lambda *a, **kw: probe)
        monkeypatch.setattr(setup_wizard, "enable_v6", lambda *a: "name contains a forbidden character")
        r = logged_in_client.post("/setup/found", data={"action": "enable_v6"})
        assert r.status_code == 200 and b"IPv6 was not enabled" in r.data


class TestRecoveryStatusAndNext:
    def test_the_status_endpoint_reports_freshness_without_caching(self, logged_in_client, monkeypatch):
        status = {
            "exists": True,
            "at": "2026-10-02T10:00:00+00:00",
            "size": 99,
            "excluded_audit_history": False,
            "fresh": True,
        }
        monkeypatch.setattr(setup_wizard, "recovery_bundle_status", lambda: status)
        r = logged_in_client.get("/setup/recovery/status")
        assert r.status_code == 200
        assert r.get_json() == {"fresh": True, "at": "2026-10-02T10:00:00+00:00", "size": 99}
        assert "no-store" in r.headers["Cache-Control"]

    def test_the_status_endpoint_is_superadmin_only(self, client, db):
        from tests.conftest import restricted_client

        c, _ = restricted_client(client, db, allowed_subnets=[1], role="admin", username="status_admin")
        assert c.get("/setup/recovery/status").status_code != 200

    def test_the_status_endpoint_needs_a_login(self, client):
        r = client.get("/setup/recovery/status")
        assert r.status_code in (301, 302, 401)

    def test_the_wizard_page_posts_next_and_carries_the_poll_script(self, logged_in_client):
        r = logged_in_client.get("/setup/recovery")
        assert b'name="next" value="setup"' in r.data
        assert b"/setup/recovery/status" in r.data and b'id="recovery-continue"' in r.data

    def test_a_refused_bundle_from_the_wizard_returns_to_the_wizard(self, logged_in_client):
        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": "short", "passphrase_confirm": "short", "next": "setup"},
        )
        assert r.status_code == 302 and r.headers["Location"].endswith("/setup/recovery")
        mismatch = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": "correct horse battery staple", "passphrase_confirm": "nope", "next": "setup"},
        )
        assert mismatch.headers["Location"].endswith("/setup/recovery")

    @pytest.mark.parametrize(
        "nxt", [None, "databases", "", "https://evil.example/", "//evil.example", "/setup/recovery"]
    )
    def test_anything_but_the_two_known_pages_goes_to_settings(self, logged_in_client, nxt):
        data = {"passphrase": "short", "passphrase_confirm": "short"}
        if nxt is not None:
            data["next"] = nxt
        r = logged_in_client.post("/settings/databases/recovery-bundle", data=data)
        assert r.status_code == 302
        assert "evil.example" not in r.headers["Location"]
        assert "/settings/databases" in r.headers["Location"] and "tab=recovery" in r.headers["Location"]
