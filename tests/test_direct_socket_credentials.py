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
from tests.probe import credential_probe as probe

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


class TestTheRemoveFormInfersNothing:
    """Z1 (v5.69.0-beta.15, Q184): the Remove-socket routes infer nothing. Beta.13 typed what they re-derived, beta.14 typed what had "already gone to this box" by comparing the address an
    endpoint LEAVES with the SSH host - and a proxy, a tunnel or a jump host each made that comparison wrong in a different direction (a secret to the Control Agent's host; a legitimate
    switch-back refused). The form has the password field every credential-moving form has, and the route types the endpoint it repoints only when the person typed a password, ticked
    No password, or ticked the saved one. These drive the REAL route body on a real jen.config (`probe.route_remove`); Flask is the only dependency."""

    PROXY = probe.PROXY

    def test_the_helpers_that_inferred_a_box_are_gone(self):
        import inspect

        assert not hasattr(infra, "_typed_for_removal") and not hasattr(infra, "_same_box")
        source = inspect.getsource(infra)
        assert "def _same_box" not in source and "def _typed_for_removal" not in source and "getaddrinfo(" not in source

    def test_a_control_agent_on_a_proxy_is_refused_untyped_and_the_kea_host_is_never_touched(self):
        r = probe.route_remove(self.PROXY, "dhcp4")
        assert r["touched"] is False and r["changed"] is False and r["text"] == self.PROXY
        assert "moved to a different host" in r["flashes"] and "Nothing was changed" in r["flashes"]

    def test_the_same_with_the_password_typed_is_written_with_that_password(self):
        r = probe.route_remove(self.PROXY, "dhcp4", {"password": "CAPW"})
        p = _parse(r["text"])
        assert r["touched"] and (p.get("kea", "api_pass"), p.get("kea", "api_url")) == ("CAPW", "http://proxy.lan:8000")
        assert p.get("kea", "connection_mode") == "ca" and not p.has_option("kea", "direct_prev_api_url")

    def test_no_password_is_an_answer_and_it_removes_the_user_too(self):
        """AA1 (Q185): no authentication is no user. `_auth` sends `Basic user:` when EITHER field is set, so a socket declared unauthenticated used to reach the Control Agent with a header
        carrying the socket's username."""
        r = probe.route_remove(self.PROXY, "dhcp4", {"no_password": "1"})
        p = _parse(r["text"])
        assert r["touched"] and p.get("kea", "api_pass") == "" and not p.has_option("kea", "api_user")
        assert "user and password cleared" in r["flashes"]
        assert probe.sends(r["text"], "kea") == [("http://proxy.lan:8000", "no header")]

    @pytest.mark.parametrize(
        ("service", "section", "user_key"), [("dhcp6", "kea6", "api_user"), ("d2", "d2", "api_user")]
    )
    @pytest.mark.parametrize("mode", ["direct", "ca"])
    def test_a_daemons_no_password_removes_its_user_in_either_mode(self, service, section, user_key, mode):
        base = probe.DIRECT if mode == "direct" else probe.BASE
        url = "http://10.0.0.5:8006" if mode == "direct" else "https://b:8006"
        text = base + f"[{section}]\napi_url = {url}\napi_user = x\napi_pass = K6\n"
        r = probe.route_remove(text, service, {"no_password": "1"})
        p = _parse(r["text"])
        assert r["touched"] and not p.has_option(section, user_key) and p.get(section, "api_pass") == ""

    def test_an_extra_servers_no_password_removes_its_user_and_sends_no_header(self):
        assert probe.q185_aa1_s13_an_extra_servers_no_password_sends_no_header_too() == (
            True,
            False,
            "",
            [("http://kea-b.lan:8000", "no header")],
        )

    def test_a_typed_user_beside_no_password_or_a_restore_is_refused_whole_before_anything_is_sent(self):
        assert probe.q185_aa1_s3_a_typed_user_beside_no_password_or_a_restore_is_refused_whole() == (
            False,
            True,
            True,
            False,
            True,
            True,
        )

    def test_a_typed_user_with_a_typed_password_is_the_ordinary_answer(self):
        r = probe.route_remove(self.PROXY, "dhcp4", {"user": "cu", "password": "CAPW"})
        p = _parse(r["text"])
        assert r["touched"] and (p.get("kea", "api_user"), p.get("kea", "api_pass")) == ("cu", "CAPW")

    def test_a_same_host_switch_back_with_nothing_typed_says_the_saved_pair_was_discarded(self):
        r = probe.route_remove(
            probe._direct_on(
                "http://10.0.0.5:8004",
                "http://10.0.0.5:8000",
                "direct_prev_api_user = cu\ndirect_prev_api_pass = CAP\n",
            ),
            "dhcp4",
        )
        assert r["touched"] and "DISCARDED" in r["flashes"] and "tick Restore" in r["flashes"]
        assert not _parse(r["text"]).has_option("kea", "direct_prev_api_pass")

    def test_the_placeholder_says_what_blank_does(self):
        import pathlib

        page = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "settings_kea.html").read_text(
            encoding="utf-8"
        )
        assert "(blank keeps the socket's pair)" in page

    def test_a_restored_copy_keeps_its_shared_marker(self):
        assert probe.q185_aa3_s6_a_restored_copy_keeps_its_shared_marker() == ("1", False, "CAP", "1", False)

    def test_the_audit_row_says_when_only_the_user_was_typed(self):
        assert probe.q185_aa3_s4_the_audit_row_says_what_was_done_with_the_password_and_the_user() == (
            "unchanged user=typed",
            "typed user=typed",
        )

    def test_the_remove_form_is_offered_for_a_daemon_socket_still_configured_in_control_agent_mode(self):
        """AA3 (Q185): after the primary is switched back (mode `ca`) a Kea6 or D2 socket that still has its own address in Jen's settings can be removed from the page - order A of the round trip
        is a route the page has, not only one the tests reach."""
        import pathlib

        page = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "settings_kea.html").read_text(
            encoding="utf-8"
        )
        assert (
            "(infra.kea_connection_mode == 'direct' and service == 'dhcp4') or (service != 'dhcp4' and current_url)"
            in page
        )

    def test_two_answers_are_refused_before_anything_is_sent(self):
        for form in ({"password": "x", "no_password": "1"}, {"password": "x", "restore_saved": "1"}):
            r = probe.route_remove(self.PROXY, "dhcp4", form)
            assert not r["touched"] and "Choose one" in r["flashes"] and r["text"] == self.PROXY

    def test_a_jump_host_ssh_target_does_not_matter_to_a_typed_switch_back(self):
        text = self.PROXY.replace("proxy.lan", "kea-a.lan")
        assert probe.route_remove(text, "dhcp4", {"password": "CAPW"}, ssh_host="10.9.9.9")["touched"]
        assert not probe.route_remove(text, "dhcp4", ssh_host="10.9.9.9")["touched"]

    def test_a_daemon_password_with_no_address_is_never_typed_by_the_button_and_is_named(self):
        text = self.PROXY + "[kea6]\napi_pass = K6\n"
        r = probe.route_remove(text, "dhcp4", {"password": "CAPW"})
        assert not r["touched"] and "Kea6 API" in r["flashes"] and "Settings" in r["flashes"] and r["text"] == text

    @pytest.mark.parametrize(("service", "section"), [("dhcp6", "kea6"), ("d2", "d2")])
    def test_a_daemons_removal_in_control_agent_mode_leaves_no_pair_of_its_own(self, service, section):
        url = "https://b:8006" if service == "dhcp6" else "https://b:53001"
        text = probe.BASE + f"[{section}]\napi_url = {url}\napi_user = x\napi_pass = K6\napi_pass_shared = 1\n"
        r = probe.route_remove(text, service)
        p = _parse(r["text"])
        assert r["touched"] and not p.has_section(section), (
            "the section had nothing left but the socket's pair and address"
        )
        assert cred.resolve(p)[section].password == "PS", (
            "the daemon now inherits the Control Agent's password and has none of its own"
        )

    @pytest.mark.parametrize(("service", "section"), [("dhcp6", "kea6"), ("d2", "d2")])
    def test_a_daemons_removal_in_direct_mode_keeps_its_pair_and_clears_only_the_address(self, service, section):
        url = "http://10.0.0.5:8006" if service == "dhcp6" else "http://10.0.0.5:53001"
        text = probe.DIRECT + f"[{section}]\napi_url = {url}\napi_user = x\napi_pass = K6\n"
        p = _parse(probe.route_remove(text, service)["text"])
        assert (p.get(section, "api_pass"), p.has_option(section, "api_url")) == ("K6", False)

    def test_the_round_trip_in_both_orders(self):
        ca = probe.BASE.replace("https://a:8000", "http://kea-a.lan:8000").replace("api_user = pu", "api_user = cu")
        ca = ca.replace("api_pass = PS", "api_pass = CAP")
        _, t4 = probe._setup(ca, "dhcp4", "http://10.0.0.5:8004", "sock", "SOCKPW", {"kea"})
        assert _parse(t4).get("kea", "direct_prev_api_pass") == "CAP" and _parse(t4).get("kea", "api_pass") == "SOCKPW"
        _, t46 = probe._setup(t4, "dhcp6", "http://10.0.0.5:8006", "six", "SIXPW", {"kea6"})
        # A: the primary first, restoring its own pair; the daemon (still with its own address) is not re-derived; then the daemon in Control Agent mode
        a1 = probe.route_remove(t46, "dhcp4", {"restore_saved": "1"})
        a2 = probe.route_remove(a1["text"], "dhcp6")
        end = _parse(a2["text"])
        assert (
            a1["touched"]
            and a2["touched"]
            and end.get("kea", "api_pass") == "CAP"
            and end.get("kea", "api_user") == "cu"
        )
        assert not end.has_section("kea6") and cred.resolve(end)["kea6"].password == "CAP"
        assert not any(k.startswith("direct_prev") for k in end["kea"])
        # B: the daemon first (direct mode keeps its pair, no address), then the primary - refused, naming the daemon, until that pair is cleared
        b1 = probe.route_remove(t46, "dhcp6")
        b2 = probe.route_remove(b1["text"], "dhcp4", {"restore_saved": "1"})
        assert b1["touched"] and not b2["touched"] and "Kea6 API" in b2["flashes"] and b2["text"] == b1["text"]

    def test_the_saved_pair_is_restored_only_when_asked_and_is_forgotten_when_superseded(self):
        text = probe._direct_on(
            "http://10.0.0.5:8004", "http://kea-a.lan:8000", "direct_prev_api_user = cu\ndirect_prev_api_pass = CAP\n"
        )
        untouched = probe.route_remove(
            text, "dhcp4"
        )  # nothing typed, nothing ticked: the socket's pair would reach the Control Agent's host
        assert not untouched["touched"] and untouched["text"] == text
        typed = _parse(probe.route_remove(text, "dhcp4", {"password": "NEW"})["text"])
        assert typed.get("kea", "api_pass") == "NEW" and not typed.has_option("kea", "direct_prev_api_pass")

    def test_an_extra_servers_switch_back_follows_the_same_rule(self):
        text = (
            probe.BASE + "[kea_server_2]\nname = b\napi_url = http://10.0.0.6:8004\napi_user = su\napi_pass = SP\n"
            "direct_prev_api_url = http://kea-b.lan:8000\ndirect_prev_api_pass = CB\n"
        )
        text = text.replace("[kea]\n", "[kea]\nconnection_mode = direct\n", 1)
        assert not probe.route_remove(text, "dhcp4", server_id=2, ssh_host="10.0.0.6")["touched"]
        back = _parse(
            probe.route_remove(text, "dhcp4", {"restore_saved": "1"}, server_id=2, ssh_host="10.0.0.6")["text"]
        )
        assert (back.get("kea_server_2", "api_pass"), back.get("kea_server_2", "api_url")) == (
            "CB",
            "http://kea-b.lan:8000",
        )

    def test_a_restore_with_no_saved_pair_or_no_saved_address_is_refused_before_anything_is_sent(self):
        """Second pass (Q184) finding 1: a pair left without its address (an older release's removal) is not offered and not restored."""
        orphan = probe.PROXY.replace("direct_prev_api_url = http://proxy.lan:8000\n", "direct_prev_api_pass = APW\n")
        r = probe.route_remove(orphan, "dhcp4", {"restore_saved": "1"})
        assert not r["touched"] and "no saved Control Agent" in r["flashes"] and r["text"] == orphan
        bare = probe.route_remove(probe.PROXY, "dhcp4", {"restore_saved": "1"})
        assert not bare["touched"] and "no saved Control Agent" in bare["flashes"]

    def test_a_daemon_that_inherited_the_primarys_pair_is_named_when_the_switch_back_takes_it_away(self):
        r = probe.q184_p2_3_a_daemon_that_inherited_the_primarys_pair_is_named_after_the_switch_back()
        assert r == (True, True, True)

    def test_the_user_can_be_typed_and_a_userless_saved_pair_restores_a_blank_password(self):
        typed, touched, restored = (
            probe.q184_p2_5_the_form_can_name_the_control_agents_user_and_a_userless_pair_restores_a_blank_password()
        )
        assert typed == ("cu", "CAP") and touched and restored == ("cu", "")

    def test_the_restore_box_is_not_checked_until_the_person_checks_it(self):
        import pathlib

        page = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "settings_kea.html").read_text(
            encoding="utf-8"
        )
        line = next(x for x in page.splitlines() if 'name="restore_saved"' in x)
        assert "checked" not in line.replace("unchecked", ""), (
            "a bare click on the button must not be a typed act by default"
        )
        assert "infra.prev_urls.get(server_id)" in line, "the label names the address the pair was saved for"

    def test_the_audit_row_says_what_was_done_with_the_password(self):
        import inspect

        source = inspect.getsource(infra.remove_direct_socket)
        assert "password={answer}" in source and '"restored"' in source and '"typed"' in source

    def test_the_form_has_the_field_and_the_boxes_and_says_where_the_password_goes(self):
        import pathlib

        page = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "settings_kea.html").read_text(
            encoding="utf-8"
        )
        for needle in ('name="password"', 'name="no_password"', 'name="restore_saved"', "The password Jen will use at"):
            assert needle in page, needle

    def test_the_saved_password_is_masked_in_a_support_bundle(self):
        from jen.services import support_bundle

        out = support_bundle.redact_ini_text("[kea]\ndirect_prev_api_user = cu\ndirect_prev_api_pass = CAP\n")
        assert "CAP" not in out and "direct_prev_api_user = cu" in out
