"""
tests/test_direct_socket_credentials.py
───────────────────────────────────────
v5.69.0-beta.13 (Q182, X4) - the direct-socket routes and CRED-004. Pure (`py -m pytest --noconftest tests/test_direct_socket_credentials.py`): a real temporary jen.config, the real
writer, the route's own edit function.

  * the pair that was pushed into the daemon's config and ANSWERED the probe is written as the endpoint's own when the resolver would withhold it at the new address (a socket set up by
    IP on a server Jen reaches by name) - never dropped (subagent S2);
  * `_daemon_creds` is `credentials.resolve`'s answer, at the address the endpoint is about to be given - there is no second decider (S3);
  * the routes type the ONE endpoint they repoint, not the server's three (so a second endpoint's password is not carried along unseen);
  * removing a socket leaves the user and password with no address, and the next address is a move that must be typed (S4b).
"""

import configparser

import pytest

from jen import extensions
from jen.config import AppConfig, ConfigChangeRefused, app_config
from jen.routes.settings import infrastructure as infra
from jen.services import credentials as cred
from jen.services import kea

HOSTNAME = """
[kea]
connection_mode = direct
api_url = http://kea-a.lan:8004
api_user = u
api_pass = S
[kea_db]
host = db1
user = k
password = KDB
[jen_db]
host = jh
user = j
password = JP
[server]
"""


@pytest.fixture(autouse=True)
def _a_scanner_may_hold_the_file_for_a_moment_on_windows(monkeypatch):
    """On a Windows dev box an indexer can hold a freshly written file for a moment and `os.replace` then raises PermissionError (the rule is not in question). Retried; no effect elsewhere."""
    import os
    import sys
    import time

    if sys.platform != "win32":
        return
    real = os.replace

    def replace(src, dst, *a, **k):
        for attempt in range(6):
            try:
                return real(src, dst, *a, **k)
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.05 * (attempt + 1))

    monkeypatch.setattr(os, "replace", replace)


PRIMARY = {"id": 1, "name": "kea-a", "api_url": "http://kea-a.lan:8004", "api_user": "u", "api_pass": "S"}


@pytest.fixture(autouse=True)
def _a_real_file(tmp_path, monkeypatch):
    path = tmp_path / "jen.config"
    path.write_text(HOSTNAME, encoding="utf-8")
    monkeypatch.setattr(extensions, "CONFIG_FILE", str(path))
    monkeypatch.setattr(app_config, "reload", lambda: None)
    monkeypatch.setattr("jen.config._identity_guards", [])
    return path


def _parse(text):
    p = configparser.ConfigParser(interpolation=None)
    p.read_string(text)
    return p


class TestTheProbedPairIsTheEndpointsOwn:
    def test_a_socket_set_up_by_ip_on_a_primary_named_by_hostname_keeps_the_pair_it_was_probed_with(self, _a_real_file):
        fn, changed = infra._direct_socket_edit(PRIMARY, "dhcp6", "http://10.0.0.5:8006", "u", "S")
        app_config.mutate(fn, reload=False, typed={"kea6"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert on_disk.get("kea6", "api_url") == "http://10.0.0.5:8006"
        assert (on_disk.get("kea6", "api_user"), on_disk.get("kea6", "api_pass")) == ("u", "S")
        assert on_disk.get("kea6", "api_pass_shared") == "1"
        assert any("kea6" in c and "kept" in c for c in changed)
        servers = AppConfig.derive_kea_servers(on_disk, quiet=True)
        assert kea._endpoint_for(servers[0], "dhcp6") == ("http://10.0.0.5:8006", "u", "S"), (
            "what the transport sends is the pair the daemon answered the probe with"
        )

    def test_the_same_host_spelled_the_same_way_writes_no_override(self, _a_real_file):
        fn, _changed = infra._direct_socket_edit(PRIMARY, "dhcp6", "http://kea-a.lan:8006", "u", "S")
        app_config.mutate(fn, reload=False, typed={"kea6"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert not on_disk.has_option("kea6", "api_pass") and cred.resolve(on_disk)["kea6"].password == "S"

    def test_a_pair_that_differs_from_the_servers_is_written_as_before(self, _a_real_file):
        fn, _changed = infra._direct_socket_edit(PRIMARY, "dhcp6", "http://10.0.0.5:8006", "six", "6pw")
        app_config.mutate(fn, reload=False, typed={"kea6"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert (on_disk.get("kea6", "api_user"), on_disk.get("kea6", "api_pass")) == ("six", "6pw")
        assert not on_disk.has_option("kea6", "api_pass_shared")

    def test_an_additional_servers_d2_socket_by_ip_keeps_its_pair(self, _a_real_file):
        _a_real_file.write_text(
            HOSTNAME + "[kea_server_2]\nname = b\napi_url = http://kea-b.lan:8004\napi_user = su\napi_pass = SP\n",
            encoding="utf-8",
        )
        server = {"id": 2, "name": "b", "api_url": "http://kea-b.lan:8004", "api_user": "su", "api_pass": "SP"}
        fn, _changed = infra._direct_socket_edit(server, "d2", "http://10.0.0.6:53001", "su", "SP")
        app_config.mutate(fn, reload=False, typed={"server_2_d2"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert (on_disk.get("kea_server_2", "api_d2_user"), on_disk.get("kea_server_2", "api_d2_pass")) == ("su", "SP")
        assert cred.resolve(on_disk)["server_2_d2"].password == "SP"

    def test_the_writer_still_wants_that_one_endpoint_typed(self, _a_real_file):
        """Narrowing `typed` to the endpoint the route repoints does not weaken the rule: the probed pair is the same secret on a second host, and it is refused unless that endpoint is typed."""
        fn, _changed = infra._direct_socket_edit(PRIMARY, "dhcp6", "http://10.0.0.5:8006", "u", "S")
        before = _a_real_file.read_bytes()
        with pytest.raises(ConfigChangeRefused):
            app_config.mutate(fn, reload=False, typed=set())
        assert _a_real_file.read_bytes() == before
        assert (
            infra._endpoint_name(PRIMARY, "dhcp6") == "kea6" and infra._endpoint_name({"id": 3}, "d2") == "server_3_d2"
        )


class TestDaemonCredsIsTheResolversAnswer:
    """S3: the form's defaults are what `credentials.resolve` gives the endpoint at the address it is about to have - the old fallback to the server's v4 pair was a second decider."""

    def test_a_different_spelling_of_the_host_is_withheld_and_the_default_is_nothing(self):
        assert infra._daemon_creds(PRIMARY, "dhcp6", "http://10.0.0.5:8006") == ("", "")

    def test_the_same_host_inherits_the_servers_pair(self):
        assert infra._daemon_creds(PRIMARY, "dhcp6", "http://kea-a.lan:8006") == ("u", "S")

    def test_it_is_resolve_for_an_endpoint_already_configured(self, _a_real_file):
        _a_real_file.write_text(HOSTNAME + "[kea6]\napi_url = http://10.0.0.5:8006\n", encoding="utf-8")
        resolved = cred.resolve(_parse(_a_real_file.read_text(encoding="utf-8")))["kea6"]
        assert resolved.withheld == "kea"
        assert infra._daemon_creds(PRIMARY, "dhcp6") == (resolved.user, resolved.password) == ("", "")

    def test_the_servers_own_endpoint_returns_its_own_pair(self):
        assert infra._daemon_creds(PRIMARY, "dhcp4", "http://10.0.0.5:8004") == ("u", "S")

    def test_an_unknown_server_has_none(self):
        assert infra._daemon_creds({"id": 9}, "dhcp4") == ("", "")


class TestARemovedSocketLeavesTheCredentialsAndTheNextAddressIsAMove:
    def test_s4b(self, _a_real_file, monkeypatch):
        _a_real_file.write_text(
            HOSTNAME + "[kea6]\napi_url = http://10.0.0.5:8006\napi_user = u\napi_pass = S\napi_pass_shared = 1\n",
            encoding="utf-8",
        )

        def remove(cfg):  # the route's own `_apply` for dhcp6 in direct mode: the address key goes, nothing else
            cfg.remove_option("kea6", "api_url")

        app_config.mutate(remove, reload=False, typed={"kea6"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert on_disk.has_option("kea6", "api_user") and on_disk.has_option("kea6", "api_pass")
        assert not on_disk.has_option("kea6", "api_url")

        def give_it_an_address(cfg):
            cfg.set("kea6", "api_url", "http://elsewhere:8006")

        before = _a_real_file.read_bytes()
        with pytest.raises(ConfigChangeRefused, match="first address"):
            app_config.mutate(give_it_an_address, reload=False)
        assert _a_real_file.read_bytes() == before
        app_config.mutate(give_it_an_address, reload=False, typed={"kea6"})


SWITCHED = (
    HOSTNAME.replace("http://kea-a.lan:8004", "http://10.0.0.5:8001")
    + "direct_prev_api_url = http://kea-a.lan:8000\n[kea6]\napi_pass = K6\n"
)


class TestSwitchingBackByNameIsAskedBeforeTheKeaHostIsTouched:
    """Second pass (Q182) P2-1: the socket was set up by IP, the Control Agent is restored by NAME; the daemon that rides it (kea6, with its own saved password and no address) follows. The
    refusal used to arrive AFTER the daemon was changed and restarted, with a remedy the Remove button cannot perform. The preflight asks the move question, and the route types what it re-derives."""

    @staticmethod
    def _switch_back(cfg):
        cfg.set("kea", "api_url", "http://kea-a.lan:8000")
        cfg.set("kea", "connection_mode", "ca")
        cfg.remove_option("kea", "direct_prev_api_url")

    def test_untyped_the_preflight_refuses_with_the_sentence(self, _a_real_file):
        _a_real_file.write_text(SWITCHED, encoding="utf-8")
        with pytest.raises(ConfigChangeRefused, match="first address"):
            app_config.preflight_identity_change(self._switch_back, typed={"kea"})

    def test_with_the_derived_daemon_typed_by_the_route_it_passes_and_the_write_follows(self, _a_real_file):
        _a_real_file.write_text(SWITCHED, encoding="utf-8")
        app_config.preflight_identity_change(self._switch_back, typed={"kea", "kea6"})
        app_config.mutate(self._switch_back, reload=False, typed={"kea", "kea6"})
        on_disk = _parse(_a_real_file.read_text(encoding="utf-8"))
        assert on_disk.get("kea", "connection_mode") == "ca" and cred.resolve(on_disk)["kea6"].password == "K6"

    def test_the_route_types_exactly_the_endpoints_that_follow_the_control_agent(self, _a_real_file):
        """The route's own computation, on the real file: the derived endpoints of the server after the change - not the ones that have an address of their own."""
        _a_real_file.write_text(SWITCHED + "[d2]\napi_url = http://dd:53001\napi_pass = D\n", encoding="utf-8")
        preview = app_config._read_parser()
        self._switch_back(preview)
        derived = cred.resolve(preview)
        names = {
            n
            for n in infra._endpoints_of_server(PRIMARY)
            if n in derived and not derived[n].url_own and cred.RIDES_THE_CONTROL_AGENT.fullmatch(n)
        }
        assert names == {"kea6"}


class TestARemoveSocketRouteTypesOnlyWhatAlreadyWentToThisBox:
    """Second pass (Q183) findings 1 and 2: beta.13's "Remove socket" routes typed the endpoints they repoint or re-derive, so a password typed for a DIFFERENT host (a Kea6 url on `b`, a
    primary retargeted to `z`) went to the Control Agent's host. `_typed_for_removal` types an endpoint only when the address it is leaving was on THIS box (the server's SSH host)."""

    SERVER = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5", "api_url": "http://10.0.0.5:8004"}

    @pytest.fixture(autouse=True)
    def _no_dns(self, monkeypatch):
        def fail(*a, **k):
            raise OSError("no resolver in a pure test")

        monkeypatch.setattr("socket.getaddrinfo", fail)

    @staticmethod
    def _switch_back(prev="http://kea-a.lan:8000"):
        def fn(cfg):
            cfg.set("kea", "api_url", prev)
            cfg.set("kea", "connection_mode", "ca")
            if cfg.has_option("kea", "direct_prev_api_url"):
                cfg.remove_option("kea", "direct_prev_api_url")

        return fn

    def _typed(self, text, server, service, apply_fn, _a_real_file):
        _a_real_file.write_text(text, encoding="utf-8")
        return infra._typed_for_removal(server, service, app_config._read_parser(), apply_fn)

    def test_the_primary_on_the_box_and_a_daemon_that_had_an_address_there_are_typed(self, _a_real_file):
        text = (
            SWITCHED.replace("[kea6]\napi_pass = K6\n", "") + "[kea6]\napi_url = http://10.0.0.5:8006\napi_pass = K6\n"
        )

        def apply(cfg):
            self._switch_back()(cfg)
            cfg.remove_option("kea6", "api_url")

        assert self._typed(text, self.SERVER, "dhcp4", apply, _a_real_file) == {"kea", "kea6"}

    def test_f1_a_daemon_whose_password_has_no_address_is_not_typed(self, _a_real_file):
        """K6 typed for host b, its address removed, then the switch-back: nothing says where K6 belongs, so the route does not claim it was typed."""
        text = SWITCHED  # [kea6] api_pass = K6, no address
        typed = self._typed(text, self.SERVER, "dhcp4", self._switch_back(), _a_real_file)
        assert typed == {"kea"}
        with pytest.raises(ConfigChangeRefused, match="first address"):
            app_config.preflight_identity_change(self._switch_back(), typed=typed)

    def test_f1_a_daemon_whose_address_was_on_another_host_is_not_typed(self, _a_real_file):
        text = SWITCHED.replace("[kea6]\napi_pass = K6\n", "[kea6]\napi_url = https://b:8006\napi_pass = K6\n")

        def apply(cfg):
            self._switch_back()(cfg)
            cfg.remove_option("kea6", "api_url")

        assert self._typed(text, self.SERVER, "dhcp4", apply, _a_real_file) == {"kea"}

    def test_f2_a_stale_previous_address_after_the_primary_was_retargeted_is_not_typed(self, _a_real_file):
        server = dict(self.SERVER, api_url="http://z:8004")
        text = SWITCHED.replace("http://10.0.0.5:8001", "http://z:8004").replace("[kea6]\napi_pass = K6\n", "")
        typed = self._typed(text, server, "dhcp4", self._switch_back("https://a:8000"), _a_real_file)
        assert typed == set()
        with pytest.raises(ConfigChangeRefused, match="moved to a different host"):
            app_config.preflight_identity_change(self._switch_back("https://a:8000"), typed=typed)

    def test_f3_removing_a_dhcp6_socket_whose_address_was_on_another_host_is_not_typed(self, _a_real_file):
        text = HOSTNAME.replace("connection_mode = direct\n", "") + "[kea6]\napi_url = https://b:8006\napi_pass = K6\n"

        def apply(cfg):
            cfg.remove_option("kea6", "api_url")

        typed = self._typed(text, self.SERVER, "dhcp6", apply, _a_real_file)
        assert typed == set()
        with pytest.raises(ConfigChangeRefused, match="moved to a different host"):
            app_config.preflight_identity_change(apply, typed=typed)

    def test_removing_a_dhcp6_socket_that_was_on_the_box_is_typed(self, _a_real_file):
        text = HOSTNAME + "[kea6]\napi_url = http://10.0.0.5:8006\napi_pass = K6\n"

        def apply(cfg):
            cfg.remove_option("kea6", "api_url")

        assert self._typed(text, self.SERVER, "dhcp6", apply, _a_real_file) == {"kea6"}

    def test_a_name_that_resolves_to_the_ssh_hosts_address_is_the_same_box(self, monkeypatch):
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda host, port, *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))] if host in ("kea-a.lan", "10.0.0.5") else [],
        )
        assert infra._same_box("http://kea-a.lan:8000", "10.0.0.5") is True
        assert infra._same_box("http://other.lan:8000", "10.0.0.5") is False

    def test_a_name_that_does_not_resolve_is_not_evidence(self):
        assert infra._same_box("http://nowhere.invalid:8000", "10.0.0.5") is False
        assert infra._same_box("", "10.0.0.5") is False and infra._same_box("http://a:1", "") is False
