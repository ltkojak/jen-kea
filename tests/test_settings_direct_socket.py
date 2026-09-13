"""
tests/test_settings_direct_socket.py
────────────────────────────────────
v5.29.0 (Q29, B1/B2) — Settings → Kea → "Set up direct socket": Jen
adds the daemon's own http control socket to its config over SSH
(kea_changeset.apply_change on that one server), restarts it, probes
the new socket, and only if it answers AS that daemon writes its own
config (per-daemon URL, and `connection_mode = direct` for dhcp4).
Driven by tests/_kea_host_fakes.py::FakeHelper for the Kea-host side
and test_kea_probe's _FakeHTTP for the command API — no SSH, no Kea.

The property every test here protects: a failed probe (didn't answer,
or answered as the Control Agent) leaves Jen's settings untouched —
the 2026-09-13 dashboard-blank trap can't be produced through this
path.
"""

import configparser

import pytest

from jen import extensions
from jen.config import app_config
from jen.services import kea as kea_svc
from jen.services import kea_host
from tests._kea_host_fakes import FakeHelper
from tests.test_kea_probe import _FakeHTTP, _ok

CA_URL = "http://1.2.3.4:8000"
SOCK = "http://10.0.0.5:8004"
DHCP4_OK = [{"result": 0, "arguments": {"Dhcp4": {}}}]
AS_CA = [{"result": 0, "arguments": {"Control-agent": {}}}]


@pytest.fixture
def isolated_config(tmp_path):
    """A throwaway jen.config with an SSH host on the primary (the flow
    edits the daemon's config over SSH) and a second, SSH-less server."""
    original_path = extensions.CONFIG_FILE
    cfg = configparser.ConfigParser()
    cfg["kea"] = {"api_url": CA_URL, "api_user": "u4", "api_pass": "p4"}
    cfg["kea_db"] = {"host": "dbhost", "user": "du", "password": "dp", "database": "kea"}
    cfg["jen_db"] = {"host": "dbhost", "user": "ju", "password": "jp", "database": "jen"}
    cfg["server"] = {"http_port": "5050", "https_port": "8443"}
    cfg["subnets"] = {"1": "LAN, 192.168.1.0/24"}
    cfg["kea_ssh"] = {"host": "10.0.0.5", "user": "kea", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
    cfg["kea_server_2"] = {
        "name": "standby",
        "api_url": "http://kea02:8000",
        "api_user": "u2",
        "api_pass": "p2",
        "ssh_host": "10.0.0.6",
        "ssh_user": "kea",
    }
    path = tmp_path / "jen.config"
    with open(path, "w") as f:
        cfg.write(f)
    extensions.CONFIG_FILE = str(path)
    app_config.reload()
    yield path
    extensions.CONFIG_FILE = original_path
    from tests.conftest import _patch_extensions

    _patch_extensions()


def _on_disk(path):
    p = configparser.ConfigParser()
    p.read(str(path))
    return p


@pytest.fixture
def fake(monkeypatch):
    f = FakeHelper()
    f.configs[(1, "dhcp4")] = {
        "Dhcp4": {
            "interfaces-config": {"interfaces": ["eth0"]},
            "control-socket": {"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"},
            "subnet4": [],
        }
    }
    f.configs[(1, "dhcp6")] = {"Dhcp6": {"control-socket": {"socket-type": "unix", "socket-name": "/run/kea/kea6"}}}
    f.configs[(1, "d2")] = {"DhcpDdns": {"ip-address": "127.0.0.1"}}
    f.configs[(2, "dhcp4")] = {"Dhcp4": {"control-socket": {"socket-type": "unix", "socket-name": "/run/kea/kea4"}}}
    for k in list(f.configs):
        f.shas[k] = f"sha-{k[0]}-{k[1]}"
    f.responses["test-config"] = {"ok": True}
    f.responses["apply-config"] = {"ok": True, "backup": None, "sha256": "sha-new"}
    f.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
    monkeypatch.setattr(kea_host, "helper_call", f.helper_call)
    monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "helper_status", dict)
    monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a, **k: None)
    monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
    return f


@pytest.fixture
def http(monkeypatch):
    """`http(replies, config_replies)` — the version check on the current
    endpoint, the probe of the new socket, and the identity config-get
    all go through kea_svc.http."""

    def _install(replies, config_replies=None):
        fk = _FakeHTTP(replies, config_replies)
        monkeypatch.setattr(kea_svc, "http", fk)
        return fk

    return _install


def _setup(client, server_id=1, service="dhcp4", follow=True, **over):
    data = {"scheme": "http", "address": "10.0.0.5", "port": "8004", "user": "kea-api", "password": "s3cret"}
    data.update(over)
    return client.post(
        f"/settings/infrastructure/direct-socket/{server_id}/{service}", data=data, follow_redirects=follow
    )


def _happy_http(http):
    """Current CA endpoint answers Kea 3.0.4; the new socket answers and
    identifies as Dhcp4."""
    return http(
        {"1.2.3.4:8000": _ok("3.0.4"), "10.0.0.5:8004": _ok("3.0.4")}, config_replies={"10.0.0.5:8004": DHCP4_OK}
    )


class TestHttpFlowSuccess:
    def test_writes_the_socket_restarts_probes_and_switches_jen_to_direct(
        self, logged_in_client, db, isolated_config, fake, http
    ):
        fk = _happy_http(http)
        r = _setup(logged_in_client)
        assert r.status_code == 200

        # Kea side: read → test → apply → restart, on server 1 only.
        assert [op for op in fake.ops() if op != "read-config"] == ["test-config", "apply-config", "service"]
        assert {sid for (sid, _op, _p) in fake.calls} == {1}
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]
        assert "control-socket" not in applied
        assert applied["control-sockets"][0] == {"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"}
        assert applied["control-sockets"][1] == {
            "socket-type": "http",
            "socket-address": "10.0.0.5",
            "socket-port": 8004,
            "authentication": {"type": "basic", "realm": "kea", "clients": [{"user": "kea-api", "password": "s3cret"}]},
        }
        assert fake.payload_for("service")["action"] == "restart"

        # Probe: version-get with no service field, then config-get, both at
        # the NEW url. (Later calls at that url are the settings page
        # rendering after the redirect, now in direct mode — kea_is_up.)
        probe_calls = [c for c in fk.calls if "10.0.0.5:8004" in c["url"]]
        assert [c["json"]["command"] for c in probe_calls[:2]] == ["version-get", "config-get"]
        assert all("service" not in c["json"] for c in probe_calls)
        assert probe_calls[0]["auth"] == ("kea-api", "s3cret")

        # Jen side, written only after the probe.
        on_disk = _on_disk(isolated_config)
        assert on_disk.get("kea", "connection_mode") == "direct"
        assert on_disk.get("kea", "api_url") == SOCK
        assert on_disk.get("kea", "api_user") == "kea-api"
        assert on_disk.get("kea", "api_pass") == "s3cret"
        assert on_disk.get("kea", "direct_prev_api_url") == CA_URL
        assert extensions.KEA_CONNECTION_MODE == "direct"
        assert b"answers directly at http://10.0.0.5:8004" in r.data

    def test_blank_credentials_default_to_the_pair_jen_already_uses(
        self, logged_in_client, db, isolated_config, fake, http
    ):
        fk = _happy_http(http)
        _setup(logged_in_client, user="", password="")
        entry = fake.payload_for("apply-config")["config"]["Dhcp4"]["control-sockets"][1]
        assert entry["authentication"]["clients"] == [{"user": "u4", "password": "p4"}]
        probe = next(c for c in fk.calls if "10.0.0.5:8004" in c["url"])
        assert probe["auth"] == ("u4", "p4")

    def test_socket_already_present_still_probes_and_writes(self, logged_in_client, db, isolated_config, fake, http):
        """A re-run after a firewall fix: set_control_socket says nochange,
        so nothing is applied or restarted — but the probe and the Jen
        config write still happen."""
        from jen.services.kea_authoring import build_control_socket

        fake.configs[(1, "dhcp4")]["Dhcp4"]["control-sockets"] = [
            fake.configs[(1, "dhcp4")]["Dhcp4"].pop("control-socket"),
            build_control_socket("http", "10.0.0.5", 8004, "kea-api", "s3cret"),
        ]
        _happy_http(http)
        r = _setup(logged_in_client)
        assert "apply-config" not in fake.ops()
        assert "service" not in fake.ops()
        assert _on_disk(isolated_config).get("kea", "connection_mode") == "direct"
        assert b"already has exactly this socket" in r.data

    def test_dhcp6_on_the_primary_writes_kea6_url_and_not_the_mode(
        self, logged_in_client, db, isolated_config, fake, http
    ):
        http(
            {"1.2.3.4:8000": _ok("3.0.4"), "10.0.0.5:8006": _ok("3.0.4")},
            config_replies={"10.0.0.5:8006": [{"result": 0, "arguments": {"Dhcp6": {}}}]},
        )
        r = _setup(logged_in_client, service="dhcp6", port="8006", user="u4", password="p4")
        on_disk = _on_disk(isolated_config)
        assert on_disk.get("kea6", "api_url") == "http://10.0.0.5:8006"
        # Same pair as [kea] → no redundant [kea6] override.
        assert not on_disk.has_option("kea6", "api_user")
        assert on_disk.get("kea", "connection_mode", fallback="ca") == "ca"
        assert b"still in Control Agent mode" in r.data
        assert fake.payload_for("apply-config")["service"] == "dhcp6"

    def test_dhcp6_with_its_own_credentials_writes_the_override(
        self, logged_in_client, db, isolated_config, fake, http
    ):
        http(
            {"1.2.3.4:8000": _ok("3.0.4"), "10.0.0.5:8006": _ok("3.0.4")},
            config_replies={"10.0.0.5:8006": [{"result": 0, "arguments": {"Dhcp6": {}}}]},
        )
        _setup(logged_in_client, service="dhcp6", port="8006", user="six", password="6pw")
        on_disk = _on_disk(isolated_config)
        assert on_disk.get("kea6", "api_user") == "six"
        assert on_disk.get("kea6", "api_pass") == "6pw"

    def test_d2_on_the_primary_writes_d2_url(self, logged_in_client, db, isolated_config, fake, http):
        http(
            {"1.2.3.4:8000": _ok("3.0.4"), "10.0.0.5:53001": _ok("3.0.4")},
            config_replies={"10.0.0.5:53001": [{"result": 0, "arguments": {"DhcpDdns": {}}}]},
        )
        _setup(logged_in_client, service="d2", port="53001")
        on_disk = _on_disk(isolated_config)
        assert on_disk.get("d2", "api_url") == "http://10.0.0.5:53001"
        assert fake.payload_for("apply-config")["config"]["DhcpDdns"]["control-sockets"][0]["socket-port"] == 53001

    def test_extra_server_writes_its_own_section_and_warns_about_the_others(
        self, logged_in_client, db, isolated_config, fake, http
    ):
        http({"kea02:8000": _ok("3.0.4"), "10.0.0.6:8004": _ok("3.0.4")}, config_replies={"10.0.0.6:8004": DHCP4_OK})
        r = _setup(logged_in_client, server_id=2, address="10.0.0.6")
        on_disk = _on_disk(isolated_config)
        assert on_disk.get("kea_server_2", "api_url") == "http://10.0.0.6:8004"
        assert on_disk.get("kea_server_2", "direct_prev_api_url") == "http://kea02:8000"
        assert on_disk.get("kea", "connection_mode") == "direct"
        # The primary still points at its Control Agent — named in the warning.
        assert b"still point at something that isn" in r.data
        assert CA_URL.encode() in r.data


class TestHttpFlowRefusesToMisconfigureJen:
    """Every branch here must leave [kea] exactly as the fixture wrote it."""

    def _assert_untouched(self, path):
        on_disk = _on_disk(path)
        assert on_disk.get("kea", "api_url") == CA_URL
        assert on_disk.get("kea", "connection_mode", fallback="ca") == "ca"
        assert not on_disk.has_option("kea", "direct_prev_api_url")

    def test_socket_answering_as_the_control_agent_is_not_adopted(
        self, logged_in_client, db, isolated_config, fake, http
    ):
        http({"1.2.3.4:8000": _ok("3.0.4"), "10.0.0.5:8004": _ok("3.0.4")}, config_replies={"10.0.0.5:8004": AS_CA})
        r = _setup(logged_in_client)
        assert "apply-config" in fake.ops()  # the Kea edit itself happened
        self._assert_untouched(isolated_config)
        assert b"answered as the Control Agent, not kea-dhcp4" in r.data
        assert b"none of its settings were changed" in r.data

    def test_socket_that_does_not_answer_is_not_adopted(self, logged_in_client, db, isolated_config, fake, http):
        http({"1.2.3.4:8000": _ok("3.0.4")})  # nothing at :8004
        r = _setup(logged_in_client)
        assert "apply-config" in fake.ops()
        self._assert_untouched(isolated_config)
        assert b"answer a version-get" in r.data  # "didn't" — Jinja escapes the apostrophe
        assert b"firewall" in r.data

    def test_restart_failure_stops_before_the_probe(self, logged_in_client, db, isolated_config, fake, http):
        fk = http(
            {"1.2.3.4:8000": _ok("3.0.4"), "10.0.0.5:8004": _ok("3.0.4")}, config_replies={"10.0.0.5:8004": DHCP4_OK}
        )
        fake.responses["service"] = {"ok": False, "error": "systemctl failed", "detail": "unit failed"}
        r = _setup(logged_in_client)
        self._assert_untouched(isolated_config)
        assert b"did NOT restart" in r.data
        assert not any("10.0.0.5:8004" in c["url"] for c in fk.calls)

    def test_preflight_failure_aborts_with_no_write(self, logged_in_client, db, isolated_config, fake, http):
        http({"1.2.3.4:8000": _ok("3.0.4")})
        fake.responses["test-config"] = {"ok": False, "error": "testerror", "detail": "unknown parameter"}
        r = _setup(logged_in_client)
        assert "apply-config" not in fake.ops()
        self._assert_untouched(isolated_config)
        assert b"config validation failed" in r.data

    def test_kea_older_than_272_is_refused_before_any_ssh(self, logged_in_client, db, isolated_config, fake, http):
        http({"1.2.3.4:8000": _ok("2.6.1")})
        r = _setup(logged_in_client)
        assert fake.calls == []
        self._assert_untouched(isolated_config)
        assert b"predates per-daemon control sockets" in r.data

    def test_unreachable_current_endpoint_does_not_block(self, logged_in_client, db, isolated_config, fake, http):
        """A Kea 3.2 box with the Control Agent gone answers nothing in ca
        mode — the version check must not stand in the way of the fix."""
        http({"10.0.0.5:8004": _ok("3.2.0")}, config_replies={"10.0.0.5:8004": DHCP4_OK})
        _setup(logged_in_client)
        assert _on_disk(isolated_config).get("kea", "connection_mode") == "direct"

    @pytest.mark.parametrize(
        "address,phrase",
        [
            ("0.0.0.0", b"Refusing to bind 0.0.0.0"),
            ("::", b"Refusing to bind 0.0.0.0"),
            ("kea.example", b"must be an IP literal"),
            ("", b"must be an IP literal"),
        ],
    )
    def test_bad_bind_address_is_refused_before_any_ssh(
        self, logged_in_client, db, isolated_config, fake, http, address, phrase
    ):
        http({"1.2.3.4:8000": _ok("3.0.4")})
        r = _setup(logged_in_client, address=address)
        assert fake.calls == []
        assert phrase in r.data
        self._assert_untouched(isolated_config)

    @pytest.mark.parametrize("port", ["0", "70000", "abc"])
    def test_bad_port_is_refused(self, logged_in_client, db, isolated_config, fake, http, port):
        http({"1.2.3.4:8000": _ok("3.0.4")})
        r = _setup(logged_in_client, port=port)
        assert fake.calls == []
        assert b"between 1 and 65535" in r.data

    def test_the_control_agents_own_address_is_refused(self, logged_in_client, db, isolated_config, fake, http):
        http({"1.2.3.4:8000": _ok("3.0.4")})
        r = _setup(logged_in_client, address="1.2.3.4", port="8000")
        assert fake.calls == []
        assert b"own address on Kea Server 1" in r.data

    def test_https_is_not_offered_yet(self, logged_in_client, db, isolated_config, fake, http):
        http({"1.2.3.4:8000": _ok("3.0.4")})
        r = _setup(logged_in_client, scheme="https")
        assert fake.calls == []
        assert b"Only an http socket" in r.data

    def test_server_without_ssh_host_is_refused(self, logged_in_client, db, isolated_config, fake, http, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(extensions.KEA_SERVERS[0], ssh_host="")])
        http({"1.2.3.4:8000": _ok("3.0.4")})
        r = _setup(logged_in_client)
        assert fake.calls == []
        assert b"has no SSH host configured" in r.data

    def test_unknown_service_and_server_are_refused(self, logged_in_client, db, isolated_config, fake, http):
        http({})
        assert b"Unknown Kea service" in _setup(logged_in_client, service="ca").data
        assert b"Unknown Kea server" in _setup(logged_in_client, server_id=9).data
        assert fake.calls == []

    def test_superadmin_only(self, client, db, isolated_config, fake, http):
        from tests.conftest import restricted_client

        http({"1.2.3.4:8000": _ok("3.0.4")})
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        r = _setup(c, follow=False)
        assert r.status_code == 302
        assert "/settings/kea" not in r.headers["Location"]  # bounced to the dashboard, not back to the form
        assert fake.calls == []
        self._assert_untouched(isolated_config)


class TestSwitchBack:
    @pytest.fixture
    def direct_primary(self, isolated_config, fake):
        """The primary already on its own socket, mode direct, CA URL remembered."""
        from jen.services.kea_authoring import build_control_socket

        app_config.write_values(
            [
                ("kea", "connection_mode", "direct"),
                ("kea", "api_url", SOCK),
                ("kea", "direct_prev_api_url", CA_URL),
            ]
        )
        fake.configs[(1, "dhcp4")]["Dhcp4"]["control-sockets"] = [
            fake.configs[(1, "dhcp4")]["Dhcp4"].pop("control-socket"),
            build_control_socket("http", "10.0.0.5", 8004, "u4", "p4"),
        ]
        return isolated_config

    def test_removes_the_socket_restores_the_ca_url_and_mode(self, logged_in_client, db, direct_primary, fake, http):
        http({})  # the standby's v4 URL answers nothing → it isn't on a direct socket
        r = logged_in_client.post("/settings/infrastructure/direct-socket/1/dhcp4/remove", follow_redirects=True)
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["control-sockets"]
        assert [s["socket-type"] for s in applied] == ["unix"]
        assert fake.payload_for("service")["action"] == "restart"
        on_disk = _on_disk(direct_primary)
        assert on_disk.get("kea", "api_url") == CA_URL
        assert not on_disk.has_option("kea", "direct_prev_api_url")
        assert on_disk.get("kea", "connection_mode") == "ca"
        assert b"switched back to Control Agent mode" in r.data

    def test_mode_stays_direct_while_another_server_answers_as_dhcp4(
        self, logged_in_client, db, direct_primary, fake, http
    ):
        http({"kea02:8000": _ok("3.0.4")}, config_replies={"kea02:8000": DHCP4_OK})
        r = logged_in_client.post("/settings/infrastructure/direct-socket/1/dhcp4/remove", follow_redirects=True)
        on_disk = _on_disk(direct_primary)
        assert on_disk.get("kea", "api_url") == CA_URL
        assert on_disk.get("kea", "connection_mode") == "direct"
        assert b"stays in direct mode" in r.data
        assert b"standby" in r.data

    def test_dhcp6_switch_back_clears_the_override_only(self, logged_in_client, db, isolated_config, fake, http):
        app_config.write_values([("kea", "connection_mode", "direct"), ("kea6", "api_url", "http://10.0.0.5:8006")])
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp6-server", "state": "active"}
        http({})
        r = logged_in_client.post("/settings/infrastructure/direct-socket/1/dhcp6/remove", follow_redirects=True)
        on_disk = _on_disk(isolated_config)
        assert not on_disk.has_section("kea6")
        assert on_disk.get("kea", "connection_mode") == "direct"  # dhcp6 never touches the mode
        assert b"no http/https control socket to remove" in r.data  # the fixture's dhcp6 config had none
        assert b"inherits the v4 URL" in r.data

    def test_aborted_kea_edit_leaves_jen_untouched(self, logged_in_client, db, direct_primary, fake, http):
        fake.responses["test-config"] = {"ok": False, "error": "testerror", "detail": "nope"}
        http({})
        logged_in_client.post("/settings/infrastructure/direct-socket/1/dhcp4/remove", follow_redirects=True)
        on_disk = _on_disk(direct_primary)
        assert on_disk.get("kea", "api_url") == SOCK
        assert on_disk.get("kea", "connection_mode") == "direct"

    def test_superadmin_only(self, client, db, direct_primary, fake, http):
        from tests.conftest import restricted_client

        http({})
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        r = c.post("/settings/infrastructure/direct-socket/1/dhcp4/remove")
        assert r.status_code == 302
        assert "/settings/kea" not in r.headers["Location"]
        assert fake.calls == []
        assert _on_disk(direct_primary).get("kea", "connection_mode") == "direct"


class TestSettingsPage:
    def test_superadmin_sees_the_form_with_the_ssh_host_as_bind_default(
        self, logged_in_client, db, isolated_config, mock_kea
    ):
        body = logged_in_client.get("/settings/kea").data
        assert b'action="/settings/infrastructure/direct-socket/1/dhcp4"' in body
        assert b'name="address" value="10.0.0.5"' in body
        assert b'name="port" value="8004"' in body
        assert b"Set up direct socket for kea-dhcp4" in body
        # the standby's row carries its own form with its own id
        assert b'action="/settings/infrastructure/direct-socket/2/dhcp4"' in body
        assert b'name="address" value="10.0.0.6"' in body
        # a plain <details>, no script of its own (tests/test_csp.py covers
        # the inline-handler rule page-wide)
        assert b'<details class="direct-socket-setup"' in body

    def test_switch_back_only_in_direct_mode(self, logged_in_client, db, isolated_config, mock_kea):
        body = logged_in_client.get("/settings/kea").data
        assert b"/direct-socket/1/dhcp4/remove" not in body
        app_config.write_value("kea", "connection_mode", "direct")
        body = logged_in_client.get("/settings/kea").data
        assert b"/direct-socket/1/dhcp4/remove" in body

    def test_ssh_less_server_gets_the_hint_not_the_form(self, logged_in_client, db, isolated_config, mock_kea):
        app_config.write_values([("kea_ssh", "host", "")])
        body = logged_in_client.get("/settings/kea").data
        assert b'action="/settings/infrastructure/direct-socket/1/dhcp4"' not in body
        assert b"Needs an SSH host for this server" in body

    def test_hidden_when_kea_is_known_to_predate_272(
        self, logged_in_client, db, isolated_config, mock_kea, monkeypatch
    ):
        monkeypatch.setattr(
            kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "arguments": {"extended": "2.6.1"}, "text": ""}
        )
        body = logged_in_client.get("/settings/kea").data
        assert b"Set up direct socket" not in body

    def test_admin_does_not_see_it(self, client, db, isolated_config, mock_kea):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        body = c.get("/settings/kea").data
        assert b"Set up direct socket" not in body


class TestProbeWordingPointsAtTheButton:
    """Q28 (2026-09-13): the maintainer read the Kea 3.0.x "warn"
    recommendation and couldn't tell WHERE the http socket goes."""

    def test_control_agent_identity_below_32_names_the_file_key_and_button(self, logged_in_client, db, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        fk = _FakeHTTP({"localhost:18000": _ok("3.0.4")}, {"localhost:18000": AS_CA})
        monkeypatch.setattr(kea_svc, "http", fk)
        data = logged_in_client.post("/settings/infrastructure/probe-kea").get_json()
        text = data["recommendation"]["text"]
        assert data["recommendation"]["level"] == "warn"
        assert "control-sockets" in text
        assert "kea-dhcp4.conf" in text
        assert "Set up direct socket" in text
        assert "8004" in text

    def test_control_agent_identity_at_32_points_at_the_button_not_authoring(self, logged_in_client, db, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        fk = _FakeHTTP({"localhost:18000": _ok("3.2.0")}, {"localhost:18000": AS_CA})
        monkeypatch.setattr(kea_svc, "http", fk)
        text = logged_in_client.post("/settings/infrastructure/probe-kea").get_json()["recommendation"]["text"]
        assert "Set up direct socket" in text
        assert "Author a starting" not in text

    def test_config_get_wrong_daemon_error_points_at_the_button(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        fk = _FakeHTTP({}, {"localhost:18000": AS_CA})
        monkeypatch.setattr(kea_svc, "http", fk)
        res = kea_svc.kea_command("config-get", "dhcp4")
        assert res["result"] == 1
        assert "Set up direct socket" in res["text"]
