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

    def test_clearing_the_primarys_user_does_not_change_what_a_dependant_sends(self):
        """Second pass (Q185, finding 1): a Kea6 with a password of its own and no user inherits the primary's user; No password on the primary keeps the user the Kea6 was sending."""
        assert probe.q185_sp1_a_dependant_keeps_the_user_it_was_sending_when_its_parents_user_is_cleared() == (
            True,
            [("http://10.0.0.5:8006", ("su", "K6"))],
            [("http://10.0.0.5:8006", ("su", "K6"))],
            False,
            "su",
        )

    def test_the_audit_row_names_what_was_done_to_the_user(self):
        """Finding 2: the user is reported as it was handled (cleared, restored, typed) - a crafted user field on a daemon is ignored and the row says `unchanged`."""
        assert probe.q185_sp2_the_audit_row_names_what_was_done_to_the_user() == (
            "none user=cleared",
            "restored user=restored",
            "typed user=unchanged",
        )

    def test_a_stale_shared_marker_does_not_follow_a_restore(self):
        assert probe.q185_sp6_a_stale_shared_marker_does_not_follow_a_restore() == (True, "PS", False, False)

    def test_the_mode_is_read_as_the_resolver_reads_it(self):
        """H1: `Direct ` in a hand-edited file is direct (the resolver strips and lower-cases); anything but direct is `ca`."""
        assert probe.q185_h1_the_mode_is_read_as_the_resolver_reads_it() == (
            "direct",
            "direct",
            "direct",
            "ca",
            "ca",
            "ca",
            "ca",
        )

    def test_the_confirm_text_says_the_ca_mode_removal_drops_the_daemons_own_pair(self):
        import pathlib

        page = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "settings_kea.html").read_text(
            encoding="utf-8"
        )
        assert "and its own user and password (they were the socket's; it then uses the Control Agent's)" in page

    def test_an_existing_rows_address_is_judged_stripped(self):
        """Finding 7: the extra-servers form hands the SAME stripped address to the check that it stores."""
        import pathlib

        src = (
            pathlib.Path(__file__).resolve().parent.parent / "jen" / "routes" / "settings" / "infrastructure.py"
        ).read_text(encoding="utf-8")
        assert 'prev.get("api_url"), api_url.strip(), api_pass, stored_secret' in src

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

    def test_the_user_can_be_typed_and_a_passwordless_saved_pair_restores_no_password_key(self):
        typed, touched, restored = (
            probe.q184_p2_5_the_form_can_name_the_control_agents_user_and_a_passwordless_pair_restores_no_password_key()
        )
        assert typed == ("cu", "CAP") and touched and restored == ("cu", None)

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


class TestARemovalNeverLeavesJenPointingAtTheSocketItRemoved:
    """AB3 (Q186): a dhcp4 removal that flips Jen to Control Agent mode needs a Control Agent address to flip TO."""

    def test_no_saved_address_and_no_other_direct_server_is_refused_before_the_host_is_touched(self):
        no_prev, equal = probe.q186_ab3_s1_no_saved_control_agent_address_is_refused_before_the_host_is_touched()
        assert no_prev == (False, 0, False, True) and equal == (False, 0, False, True)

    def test_the_forms_address_is_identified_as_a_control_agent_first_and_then_the_removal_proceeds(self):
        touched, url, mode, pair, asked, events, sent = (
            probe.q186_ab3_s2_the_forms_address_is_identified_first_and_then_the_removal_proceeds()
        )
        assert touched and url == "http://ca.lan:8000" and mode == "ca" and pair == ("cu", "CAPW")
        assert asked == ["http://ca.lan:8000"] and events[:2] == ["identify", "apply"], "asked BEFORE the socket goes"
        assert sent == [("http://ca.lan:8000", ("cu", "CAPW"))]

    def test_an_address_that_is_no_control_agent_or_has_no_answer_is_refused_whole(self):
        out = probe.q186_ab3_s3_an_address_that_is_not_a_control_agent_or_not_typed_for_is_refused_whole()
        assert out[:5] == ((False, False),) * 5 and out[5:] == (True, True, True, True)

    def test_another_server_keeping_direct_mode_needs_no_address(self):
        touched, url, mode, said = probe.q186_ab3_s4_another_server_keeping_direct_mode_needs_no_address()
        assert touched and mode == "direct" and url == "http://10.0.0.5:8004" and said

    def test_a_saved_address_is_restored_and_a_typed_one_wins_over_it(self):
        plain, typed, both = probe.q186_ab3_s5_a_saved_address_is_restored_and_a_typed_one_wins_over_it()
        assert plain == "http://kea-a.lan:8000"
        assert typed == ("http://ca.lan:8000", "NEWPW", False, False), (
            "the pair saved for the other address goes with it"
        )
        assert both == (False, True)

    def test_the_page_offers_the_address_field_only_where_there_is_none_to_return_to(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        page = (root / "templates" / "settings_kea.html").read_text(encoding="utf-8")
        assert "server_id in infra.needs_ca_url" in page and 'name="ca_url"' in page
        route = (root / "jen" / "routes" / "settings" / "infrastructure.py").read_text(encoding="utf-8")
        assert '"needs_ca_url": _needs_ca_url' in route


class TestASavedAddressIsIdentifiedLikeATypedOne:
    """Second pass (Q186, finding 1): the saved Control Agent address is restored only if it answers as a Control Agent, whatever its spelling."""

    def test_an_alias_or_an_earlier_socket_is_refused_and_a_real_control_agent_is_not(self):
        rows = probe.q186_sp1_a_saved_address_that_only_differs_as_text_is_identified_before_it_is_restored()
        assert all(not touched and asked and mode == "direct" for touched, asked, _url, mode in rows[:5])
        assert rows[5][0] and rows[5][3] == "ca" and rows[5][1] == ["http://kea-a.lan:8000"]


class TestOneListenerIsOneListener:
    """Q187 (AC5): `keep_direct` counts servers by their effective dhcp4 endpoint - a second record of the very socket being removed is not another server on its own socket."""

    def test_a_second_record_of_the_same_socket_is_refused_and_named(self):
        twin, both, named = (
            probe.q187_ac5_s1_a_second_record_of_the_same_socket_is_refused_and_never_keeps_direct_mode()
        )
        assert twin == (False, False, True) and both == (False, False, True), (
            "refused before the host is touched, nothing changed"
        )
        assert named == (True, False), "the twin is named; the genuine other server is not what is refused"

    def test_two_spellings_of_one_host_are_the_operators_to_keep_apart_and_the_sentence_says_so(self):
        assert (
            probe.q187_ac5_s2_two_spellings_of_one_host_are_the_operators_to_keep_apart_and_the_sentence_says_so()
            == (
                True,
                "direct",
                True,
                True,
            )
        )


class TestTheControlAgentAddressIsAlwaysOfferedAndTheProbeUsesTheResolver:
    """Q187 (AC4)."""

    def test_the_form_always_offers_the_field_and_says_which_wording_applies(self):
        import pathlib

        page = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "settings_kea.html").read_text(
            encoding="utf-8"
        )
        assert 'name="ca_url"' in page
        assert "{% if service == 'dhcp4' %}<label>The Control Agent's address (" in page, (
            "offered for every dhcp4 form, not only when none is saved"
        )
        assert "required: Jen has none to return to" in page and "blank uses the saved address" in page
        assert "{% if service == 'dhcp4' and server_id in infra.needs_ca_url %}" not in page, "the old gate is gone"

    def test_the_identify_pair_is_the_resolvers_for_a_half_nobody_typed(self):
        touched, pairs = probe.q187_ac4_s1_the_identify_pair_is_the_resolvers_for_a_half_nobody_typed()
        assert touched and pairs == [("http://10.0.0.5:8100", "pu", "PS")]


class TestTheSmallOnesOfQ188:
    """AD9."""

    def test_the_twin_refusal_covers_dhcp6_and_d2(self):
        kea6, d2, fine = probe.q188_ad9_s1_the_twin_refusal_covers_dhcp6_and_d2()
        assert kea6 == (False, False, True) and d2 == (False, False, True), (
            "refused before the host is touched, naming the other record"
        )
        assert fine[:2] == (True, True) and fine[2] is False, "a record at a different address is no reason to refuse"

    def test_ipv6_literals_are_compared_as_addresses_and_names_stay_as_written(self):
        assert probe.q188_ad9_s2_ipv6_literals_are_compared_as_addresses_and_names_stay_as_written() == (
            True,
            True,
            False,
            True,
            False,
            True,
        )


class TestTheProbeRowsOfQ189:
    """AE6g: the rows the probe harness reaches for the inventory, the host's record, the recovery note and the pre-read."""

    def test_every_inventory_shape_is_a_target_a_refusal_or_left_alone(self):
        assert probe.q189_ae1_every_inventory_shape_is_a_target_a_refusal_or_left_alone() == {
            "complete": (1, 0, 0, 0),
            "administrators trust": (0, 1, 0, 0),
            "copy missing": (0, 1, 0, 0),
            "key missing": (0, 1, 0, 0),
            "malformed": (0, 1, 0, 0),
            "not a pair": (0, 1, 0, 0),
            "external": (0, 0, 1, 0),
            "directory missing": (0, 1, 0, 0),
            "earlier Jen CA": (0, 1, 0, 0),
        }

    def test_an_unlistable_directory_is_a_refusal_never_an_empty_set(self):
        assert probe.q189_ae1_an_unlistable_directory_is_a_refusal_never_an_empty_set() == (1, True, True, [])

    def test_the_reviews_sequence_records_the_pair_the_host_accepted(self):
        raised, record_is_a2, prev_is_a2, stale, live_is_a2 = (
            probe.q189_ae2_the_reviews_sequence_records_the_pair_the_host_accepted()
        )
        assert (raised, record_is_a2, prev_is_a2, stale) == ("OSError", True, True, True)
        assert live_is_a2 is False, "Jen's live copy is still the CA-B pair - and the record does not point at it"

    def test_a_read_only_directory_loses_the_record_and_the_answer_is_unknown(self):
        assert probe.q189_ae2_a_read_only_ssl_directory_loses_the_record_and_host_material_says_unknown() == (
            True,
            None,
            False,
        )

    def test_a_note_that_is_not_a_note_is_never_written_over(self):
        refused, after = probe.q189_ae3_a_note_that_is_not_a_note_is_refused_unchanged_and_set_aside_on_request()
        assert all(row == (True, True, "malformed") for row in refused) and len(refused) == 4
        assert after == ("done", True, len("{broken json!!!"), True, "", "ok")

    def test_a_removal_whose_preread_is_cut_sends_nothing_for_each_channel_exception(self):
        assert (
            probe.q189_ae4_a_removal_whose_preread_is_cut_sends_nothing_and_says_so()
            == ((False, False, True, True),) * 3
        )


class TestTheProbeRowsOfQ190:
    """AF1-AF3: whose CA a trust path is (by certificate identity), an address with user-info, and the shape of each entry of the recovery record."""

    def test_the_bundle_a_trust_path_names_is_judged_by_certificate_identity(self):
        assert probe.q190_af1_the_bundle_a_trust_path_names_is_judged_by_certificate_identity_not_by_its_path() == {
            "jens file": ("jens-file", True, 0, 1, 0),
            "equivalent spelling": ("jens-file", True, 0, 1, 0),
            "byte copy": ("copy", True, 0, 1, 0),
            "bundle with another": ("bundle", True, 0, 1, 0),
            "another only": ("other", False, 0, 0, 1),
            "unreadable": ("unreadable", None, 0, 1, 0),
            "empty": ("none", None, 0, 0, 1),
        }

    def test_a_url_with_user_info_is_refused_shown_without_it_and_scrubbed(self):
        assert probe.q190_af2_a_url_with_user_info_is_refused_shown_without_it_and_scrubbed_from_text() == (
            False,
            True,
            "https://10.0.0.5:8004",
            False,
            True,
        )

    def test_every_entry_of_the_note_has_a_shape(self):
        assert probe.q190_af3_every_entry_of_the_note_has_a_shape_and_an_unrecognised_one_is_refused() == {
            "empty list": "read",
            "attention": "read",
            "outcome without ids": "read",
            "5.65.x single note": "read",
            "empty entry": "refused",
            "unknown status": "refused",
            "unknown category": "refused",
            "mixed": "refused",
            "top-level list": "refused",
        }


class TestTheProbeRowsOfQ191:
    """AG1-AG2: the client pair is judged by certificate like the bundle (a copy, a pair no Jen CA issued and a pair that does not load are a refusal under a Jen-issued target), and the sweep sees the twin
    refusal's address by where the value was READ."""

    def test_the_client_pair_is_judged_by_certificate(self):
        assert probe.q191_ag1_the_client_pair_is_judged_by_certificate_like_the_bundle() == {
            "none": ("none", 1, 0),
            "jens-file": ("jens-file", 1, 0),
            "copy": ("copy", 1, 1),
            "other": ("other", 1, 1),
            "unreadable": ("unreadable", 1, 1),
            "half": ("unreadable", 1, 1),
        }

    def test_the_sweep_sees_the_twin_refusal_by_provenance(self):
        assert probe.q191_ag2_the_twin_refusal_shape_is_seen_by_the_sweep_by_provenance_not_by_name() == [
            "_socket_now",
            "here",
        ]


class TestTheProbeRowsOfQ192:
    """AH1-AH3: the staged client pair is proved against an external endpoint, a damaged CA creates nothing, and a pair is a pair only when the key is the certificate's."""

    def test_a_damaged_ca_is_named_and_ensure_ca_creates_nothing(self):
        assert probe.q192_ah2_a_damaged_ca_is_named_and_ensure_ca_creates_nothing() == {
            "fresh": ("none", "created", False),
            "key-missing": ("damaged", "refused", True),
            "cert-missing": ("damaged", "refused", True),
            "cert-malformed": ("damaged", "refused", True),
            "key-malformed": ("damaged", "refused", True),
            "mismatched": ("damaged", "refused", True),
            "invalid-public-key": ("damaged", "refused", True),
            "absent-beside-a-server-copy": ("damaged", "refused", True),
            "absent-beside-the-client-pair": ("damaged", "refused", True),
        }

    def test_a_pair_is_a_pair_only_when_the_key_is_the_certificates(self):
        assert probe.q192_ah3_a_pair_is_a_pair_only_when_the_key_is_the_certificates() == {
            "valid": ("ok", False, "ok"),
            "unrelated-key": ("damaged", True, "ok"),
            "malformed-cert": ("damaged", True, "ok"),
            "malformed-key": ("damaged", True, "ok"),
            "earlier-jen-ca": ("damaged", True, "ok"),
            "other-ca": ("damaged", True, "ok"),
            "key-missing": ("damaged", True, "ok"),
        }

    def test_the_staged_client_pair_is_proved_against_an_external_endpoint(self):
        assert probe.q192_ah1_the_staged_client_pair_is_proved_against_an_external_endpoint_before_promotion() == {
            "answers-both": (False, False, True),
            "refuses-the-staged-pair": (True, False, False),
            "answers-neither": (False, True, False),
            "no-client-pair": (False, False, True),
        }


class TestTheProbeRowsOfQ193:
    """AI2-AI4: Prepare works under a damaged CA, every damaged-CA sentence carries the same two actions, a failed probe is a certificate rejection or a transport fault."""

    def test_prepare_accepts_a_damaged_ca_and_refuses_only_the_absence_of_one(self):
        assert probe.q193_ai2_prepare_accepts_a_damaged_ca_and_refuses_only_the_absence_of_one() == {
            "ok": ("ok", True, False, True),
            "key-missing": ("damaged", True, False, True),
            "none": ("none", False, True, False),
        }

    def test_every_damaged_ca_sentence_names_the_same_two_actions(self):
        assert probe.q193_ai3_every_damaged_ca_sentence_names_the_same_two_actions() == {
            "key-missing": ("damaged", "fail", True, True),
            "cert-missing": ("damaged", "fail", True, True),
            "cert-malformed": ("damaged", "fail", True, True),
            "both-missing-beside-the-client-pair": ("damaged", "fail", True, True),
        }

    def test_a_failed_probe_is_classified(self):
        assert probe.q193_ai4_a_failed_probe_is_classified_a_certificate_rejection_or_a_transport_fault() == {
            "SSLError: tlsv13 alert certificate required": "",
            "client certificate rejected": "",
            "Read timed out": "a timeout",
            "Connection refused": "a refused connection",
            "ConnectionResetError: Connection reset by peer": "a lost connection",
            "": "no answer",
            "something odd": "a transport error",
            "HTTPSConnectionPool(host='tls-kea.lan', port=8000): Read timed out.": "a timeout",
            "HTTPSConnectionPool(host='kea.lan', port=8000): Max retries exceeded (Caused by ConnectTimeoutError('Connection to kea-alerts.lan timed out'))": "a timeout",
        }


class TestTheProbeRowsOfQ194:
    """AJ1/AJ2: a CA that cannot sign is damaged (never replaced), and a missing certificate directory is created or refused (never assumed writable)."""

    def test_a_ca_that_cannot_sign_is_damaged_never_replaced(self):
        assert probe.q194_aj1_a_ca_that_is_not_a_certificate_signing_authority_is_damaged_never_replaced() == {
            "ok": ("ok", False, False),
            "not-ca": ("damaged", True, True),
            "expired": ("damaged", True, True),
            "no-key-cert-sign": ("damaged", True, True),
            "tampered-signature": ("damaged", True, True),
        }

    def test_a_missing_certificate_directory_is_created_or_refused(self):
        assert probe.q194_aj2_a_missing_certificate_directory_is_created_or_refused_never_assumed_writable() == {
            "writable-parent": (False, False),
            "read-only-parent": (True, False),
        }


class TestTheProbeRowsOfQ195:
    """AK1: in a recovery an external endpoint is judged by the replacement identity - the live pair fails BECAUSE the CA being replaced is the one it trusts."""

    def test_in_a_recovery_an_external_endpoint_is_judged_by_the_replacement_identity(self):
        assert probe.q195_ak1_in_a_recovery_an_external_endpoint_is_judged_by_the_replacement_identity() == {
            "recovery: live rejected, staged accepted": "",
            "recovery: live rejected, staged rejected": "prepare",
            "recovery: live rejected, staged timed out": "probe",
            "recovery: live timed out": "answer",
            "recovery: live fails to verify the daemon": "answer",
            "recovery: live closed in the TLS 1.3 handshake, staged accepted": "",
            "recovery: live closed in the TLS 1.3 handshake, staged closed": "prepare",
            "recovery: live fails to resolve a host called kea-alert": "answer",
            "recovery: live gets a protocol-version alert": "answer",
            "healthy: live rejected": "answer",
            "healthy: live accepted, staged rejected": "depends",
        }


class TestTheProbeRowsOfQ196:
    """AL1/AL2: a CA is healthy when the real verifier accepts what Jen issues from it; one daemon is one rotation target."""

    def test_a_ca_is_healthy_when_the_real_verifier_accepts_what_jen_issues_from_it(self):
        assert probe.q196_al1_a_ca_is_healthy_when_the_real_verifier_accepts_what_jen_issues_from_it() == {
            "jen's own": ("ok", False),
            "eku-none": ("ok", False),
            "eku-server-and-client": ("ok", False),
            "eku-clientauth-only": ("damaged", True),
            "eku-serverauth-only": ("damaged", True),
            "name-constraints-exclude-all": ("damaged", True),
            "name-constraints-permit-own-domain": ("ok", False),
        }

    def test_one_daemon_is_one_rotation_target(self):
        assert probe.q196_al2_one_daemon_is_one_rotation_target() == {
            "distinct hosts": (2, 0, False),
            "same host and service": (2, 1, False),
            "same host spelled two ways": (2, 1, True),
            "a trailing dot is a different name": (2, 0, False),
            "dhcp4 and dhcp6 on one host": (2, 0, False),
        }


class TestTheProbeRowsOfQ197:
    """AM1/AM2/AM4/AM5: the daemon's verifier judges at the gate; a healthy CA that cannot sign for a name is told so; one daemon is one record at the setup; stale records are forgotten locally."""

    def test_the_daemons_verifier_judges_at_the_gate(self):
        assert probe.q197_am1_the_daemons_verifier_judges_at_the_gate() == {
            "jen's own": ("ok", "damaged"),
            "eku-anyeku": ("damaged", "damaged"),
            "aki-not-ski": ("damaged", "damaged"),
            "eku-anyeku-server-and-client": ("ok", "damaged"),
            "aki-keyid-matches-ski": ("ok", "damaged"),
            "aki-wrong-serial": ("damaged", "damaged"),
        }

    def test_a_name_the_ca_cannot_sign_for_is_a_name_refusal_not_a_damaged_ca(self):
        assert probe.q197_am2_a_name_the_ca_cannot_sign_for_is_a_name_refusal_not_a_damaged_ca() == {
            "ip outside the permitted range": ("NameRefused", ["10.0.0.5"]),
            "ssh host outside the permitted domain": ("NameRefused", ["kea-a.elsewhere.net"]),
            "a name as the bind (underscore)": ("BindNotAnAddress", ["kea_host"]),
            "a name as the bind (trailing dot)": ("BindNotAnAddress", ["kea-a."]),
            "an underscore as the SSH host": ("issued", []),
            "a damaged CA": ("CaDamaged", []),
            "a name the CA permits": ("issued", []),
        }

    def test_one_daemon_two_records_at_the_setup(self):
        assert probe.q197_am5_one_daemon_two_records_at_the_setup() == {
            "no other record": "",
            "another record on the same host": "kea-b",
            "another record on another host": "",
            "the other service of the same host": "",
            "a trailing dot is a different name": "",
        }

    def test_stale_records_are_listed_and_forgotten_locally(self):
        assert probe.q197_am4_stale_records_are_listed_and_forgotten_locally() == (
            ["7-dhcp4"],
            ["7-dhcp4"],
            [],
            "jen",
        )


class TestTheProbeRowsOfQ198:
    """AN1/AN2/AN3: a refusal changes nothing; parked is not stale; the first issuer name is the one OpenSSL compares."""

    def test_a_refusal_changes_nothing_for_a_target_it_never_touched(self):
        assert probe.q198_an1_a_refusal_changes_nothing_for_a_target_it_never_touched() == (True, True, True, True)

    def test_a_record_for_a_configured_server_is_parked_not_stale(self):
        assert probe.q198_an2_a_record_for_a_configured_server_is_parked_not_stale() == (
            ["2-dhcp4"],
            ["7-dhcp4"],
            ["7-dhcp4"],
            ["2-dhcp4"],
            True,
        )

    def test_the_first_issuer_directory_name_is_the_one_openssl_compares(self):
        assert probe.q198_an3_the_first_issuer_directory_name_is_the_one_openssl_compares() == {
            "aki-two-dirnames-wrong-first": "damaged",
            "aki-two-dirnames-right-first": "ok",
            "aki-dnsname-issuer": "ok",
            "aki-uri-issuer": "ok",
            "aki-dns-first-right-dirname": "ok",
            "aki-dns-first-wrong-dirname": "damaged",
            "aki-all-none": "damaged",
            "issuer-string-type-differs": "ok",
        }


class TestTheProbeRowsOfQ201:
    """AQ1/AQ2/AQ3: roles by order; a recovery judges the record group; a pending note is reconciled from the files."""

    def test_a_certificates_names_carry_their_roles_in_their_order(self):
        assert probe.q201_aq1_a_certificates_names_carry_their_roles_in_their_order() == (
            "jen",
            "refuse",
            "refuse",
            "refuse",
        )

    def test_a_recovery_judges_the_record_group(self):
        assert probe.q201_aq2_a_recovery_judges_the_record_group() == (True, True, False, False)

    def test_a_scope_is_a_different_link_for_a_secret_and_no_scope_for_a_certificate(self):
        assert probe.q201_aq5_a_scope_is_a_different_link_for_a_secret_and_no_scope_for_a_certificate() == (
            False,
            False,
            True,
        )

    def test_a_pending_note_is_reconciled_from_the_files(self):
        assert probe.q201_aq3_a_pending_note_is_reconciled_from_the_files() == (
            ["ghost kea-dhcp4"],
            ["rotation-pending"],
            ["tls-superseded"],
        )


class TestTheProbeRowsOfQ202:
    """AR1/AR2/AR5: a pending note belongs to its CA generation; a certificate that names nothing proves nothing; the URL is judged as the TLS stack judges it."""

    def test_a_pending_note_is_refreshed_only_under_its_own_ca_fingerprint(self):
        assert probe.q202_ar1_a_pending_note_is_refreshed_only_under_its_own_ca_fingerprint() == (True, False, True)

    def test_a_certificate_that_names_nothing_proves_nothing(self):
        assert probe.q202_ar2_a_certificate_that_names_nothing_proves_nothing() == ("refuse", True, True)

    def test_the_url_is_judged_as_the_tls_stack_judges_it(self):
        assert probe.q202_ar5_the_url_is_judged_as_the_tls_stack_judges_it() == ("jen", "refuse", "refuse")


class TestTheProbeRowsOfQ200:
    """AP1/AP2/AP3: the SSH host is the mutation target; a forget whose fact cannot be stored deletes nothing; an orphan is judged by the certificate it holds."""

    def test_the_ssh_host_is_the_target_and_each_name_matches_its_own(self):
        assert probe.q200_ap1_the_ssh_host_is_the_target_and_each_name_matches_its_own() == (
            "jen",
            "refuse",
            "refuse",
            "refuse",
        )

    def test_a_forget_whose_fact_cannot_be_stored_deletes_nothing(self):
        assert probe.q200_ap2_a_forget_whose_fact_cannot_be_stored_deletes_nothing() == (
            [],
            ["2-dhcp4"],
            True,
            ["2-dhcp4"],
        )

    def test_an_orphan_is_judged_by_the_certificate_it_holds(self):
        assert probe.q200_ap3_an_orphan_is_judged_by_the_certificate_it_holds() == (
            "unknown",
            "current",
            "superseded",
            "unknown",
        )


class TestTheProbeRowsOfQ199:
    """AO1/AO3/AO6/AO7: a parked record is an earlier CA's after a rotation; a name is compared as OpenSSL compares it; a key without its certificate is an orphan record; a record carries its destination."""

    def test_a_parked_record_after_a_rotation_is_an_earlier_cas(self):
        assert probe.q199_ao1_a_parked_record_after_a_rotation_is_an_earlier_cas() == (
            ["2-dhcp4"],
            "jen",
            "refuse",
            True,
            True,
        )

    def test_a_name_is_compared_the_way_openssl_compares_it(self):
        assert probe.q199_ao3_a_name_is_compared_the_way_openssl_compares_it() == {
            "utf8 vs bmp, ascii": "ok",
            "utf8 vs printable, ascii": "ok",
            "utf8 vs t61, ascii": "ok",
            "utf8 vs t61, non-ascii": "damaged",
            "utf8, letter case": "ok",
            "utf8, white space": "ok",
            "visible vs visible": "damaged",
        }

    def test_a_key_without_its_certificate_is_an_orphan_record(self):
        assert probe.q199_ao6_a_key_without_its_certificate_is_an_orphan_record() == (
            [False],
            ["7-dhcp4"],
            ["7-dhcp4"],
            ["notes.txt"],
            ["notes.txt"],
        )

    def test_a_record_carries_its_destination(self):
        assert probe.q199_ao7_a_record_carries_its_destination() == ("jen", "jen", "jen", "refuse")


class TestTheSecondPassOfQ187:
    """The executed findings of the adversarial pass on beta.18's routes, each as a probe row."""

    def test_an_inherited_password_is_never_sent_to_the_saved_address_on_a_different_host(self):
        touched, pairs, typed = (
            probe.q187_sp1_an_inherited_password_is_not_sent_to_the_saved_address_on_a_different_host()
        )
        assert touched and pairs == [("http://proxy.lan:8100", "", "")], (
            "asked with what the writer will leave at that host: nothing"
        )
        assert typed == [("http://proxy.lan:8100", "tu", "TYPED")], "a typed pair is what the person typed"

    def test_a_typed_address_that_is_another_servers_own_is_refused(self):
        refused, accepted = probe.q187_sp8_a_typed_address_that_is_another_servers_own_is_refused()
        assert refused[:3] == (False, False, True) and accepted[0] is True

    def test_a_removal_clears_only_the_probe_pending_note_of_the_socket_it_removed(self):
        done, nothing_touched, nothing_resolved, daemon = (
            probe.q187_sp4_a_removal_clears_only_the_probe_pending_note_of_the_socket_it_removed()
        )
        # (Q199 AO1: a removal also ends the two durable facts about the socket it removed - `tls-superseded` and `record-forgotten`)
        assert done == [
            (1, "dhcp4", ("probe-pending", "tls-superseded", "record-forgotten", "rotation-pending"))
        ] and daemon == [(1, "dhcp6", ("probe-pending", "tls-superseded", "record-forgotten", "rotation-pending"))]
        assert nothing_touched and nothing_resolved == [], "a removal that removed nothing proves nothing"

    def test_a_singular_entry_with_nothing_to_remove_is_not_said_to_be_rewritten(self):
        assert probe.q187_sp10_a_singular_unix_entry_with_nothing_to_remove_is_not_said_to_be_rewritten() == (
            True,
            False,
        )

    def test_describe_socket_prints_one_short_printable_line(self):
        assert probe.q187_sp6_describe_socket_prints_one_short_printable_line() == (True, False)


class TestTheSmallOnes:
    """Q187 (AC6)."""

    def test_a_typed_address_beside_a_saved_pair_says_the_pair_was_discarded(self):
        touched, said, url, pair, left = (
            probe.q187_ac6_s1_a_typed_address_beside_a_saved_pair_says_the_pair_was_discarded()
        )
        assert touched and said and url == "http://ca.lan:8000" and pair == ("nu", "NEW") and left is False

    def test_the_keep_direct_branch_identifies_a_saved_alias_like_the_rest(self):
        refused, genuine = probe.q187_ac6_s2_the_keep_direct_branch_identifies_a_saved_alias_like_the_rest()
        assert refused == (False, False, True) and genuine == (True, "direct")

    def test_the_singular_control_socket_is_removed_and_said(self):
        touched, host, said = probe.q187_ac6_s3_the_singular_control_socket_is_removed_and_said()
        assert touched and host == {"Dhcp4": {"control-sockets": []}} and said

    def test_a_write_failure_sentence_prints_the_class_and_errno_never_the_path(self):
        assert probe.q187_ac6_s4_a_write_failure_sentence_prints_the_class_and_errno_never_the_path() == (
            True,
            False,
            False,
        )

    def test_odd_entries_print_plainly_and_a_bad_snapshot_is_refused(self):
        described, typeless, weird, bad_list, bad_str = (
            probe.q187_ac6_s5_odd_entries_print_plainly_and_a_snapshot_that_is_not_a_list_of_entries_is_refused()
        )
        assert described == "http ?:?" and typeless == "unix ?" and weird == "? ?:?"
        assert bad_list == bad_str == "unsupported"

    def test_the_sweep_s11b_knows_the_three_new_names(self):

        from tests import test_invariant_sweeps as sweeps

        for name in ("api", "named", "kept"):
            assert sweeps._S11B_NAMES.search(name), name


class TestARestorePutsBackAbsenceAndTheKeepNeedsAnOwnPassword:
    """AB4/AB5 (Q186): what the Control Agent had is saved as it WAS and a restore puts every half back as it was; the dependant keep writes a user only beside a password of its own."""

    def test_every_saved_state_round_trips_and_the_transport_sends_what_it_sent_before(self):
        rows = probe.q186_ab4_s1_a_restore_puts_back_each_half_as_it_was_user_present_or_absent_by_password_present_blank_or_absent()
        assert rows == ((True, True, True, False),) * 6, "user present/absent x password present/blank/absent"

    def test_the_no_authentication_state_sends_no_header_after_the_round_trip(self):
        ca = "[kea]\napi_url = http://kea-a.lan:8000\n" + probe.BASE[probe.BASE.index("[kea_db]") :]
        assert probe.sends(ca, "kea") == [("http://kea-a.lan:8000", "no header")]
        _, t4 = probe._setup(ca, "dhcp4", "http://10.0.0.5:8004", "sock", "SOCKPW", {"kea"})
        assert probe.parse(t4).get("kea", "direct_prev_api_user_absent") == "1"
        assert probe.parse(t4).get("kea", "direct_prev_api_pass_absent") == "1"
        back = probe.route_remove(t4, "dhcp4", {"restore_saved": "1"})
        assert probe.sends(back["text"], "kea") == [("http://kea-a.lan:8000", "no header")]

    def test_an_additional_server_that_inherited_the_primarys_pair_inherits_it_again(self):
        before, flags, touched, own, after = (
            probe.q186_ab4_s2_an_additional_server_that_inherited_the_primarys_pair_inherits_again()
        )
        assert flags == ("1", "1") and touched and own == (False, False)
        assert before == after == [("https://a:8001", ("pu", "PS"))]

    def test_the_dependant_keep_writes_a_user_only_beside_a_password_of_its_own(self):
        inherited, own = (
            probe.q186_ab4_s3_the_dependant_keep_writes_a_user_only_when_the_dependants_password_is_its_own()
        )
        assert inherited == (True, False, [("http://10.0.0.5:8006", "no header")]), (
            "dk1: nothing of its own, nothing kept"
        )
        assert own == (True, "su", [("http://10.0.0.5:8006", ("su", "K6"))]), (
            "dk2: an own password keeps the user it was sending"
        )

    def test_a_stale_shared_marker_is_cleared_when_a_setup_writes_the_saved_pair(self):
        assert probe.q186_ab5_s1_a_stale_shared_marker_is_cleared_when_a_setup_writes_the_saved_pair() == (
            False,
            "PS",
            "http://kea-a.lan:8000",
        )

    def test_a_typed_daemon_password_in_control_agent_mode_is_paired_with_the_control_agents_user(self):
        """Second pass (Q186, finding 2): the daemon's own user was the SOCKET's (Z2 clears it); keeping it beside a typed password sent the Control Agent the socket's user name."""
        typed, cleared, sent = (
            probe.q186_ab5_s2_a_typed_daemon_password_on_the_control_agent_mode_form_is_paired_with_the_control_agents_user()
        )
        assert typed[:2] == (None, "NEWPW") and cleared == (False, False)
        assert sent == [("https://a:8000", ("pu", "NEWPW"))], "the Control Agent's user, the typed password"

    def test_the_page_reads_the_mode_the_way_the_resolver_does(self):
        import pathlib

        route = (
            pathlib.Path(__file__).resolve().parent.parent / "jen" / "routes" / "settings" / "infrastructure.py"
        ).read_text(encoding="utf-8")
        assert '"kea_connection_mode": _mode_of(extensions.cfg)' in route
