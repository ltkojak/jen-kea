"""
tests/test_kea_authoring.py
───────────────────────────
jen/services/kea_authoring.py — generating a starting kea-dhcp4/6 config when none exists: path detection, remote JSON reads, CA socket and sibling-config detection, interface autodetect, config/script building, subnet-line parsing, and every author/binary route.

Split out of the monolithic tests/test_kea6.py in v5.6.1.
"""

import json

import pytest

from jen import extensions
from tests._kea6_helpers import FakeSSHClient


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

        ca_conf = json.dumps(
            {
                "Control-agent": {
                    "control-sockets": {
                        "dhcp6": {"socket-type": "unix", "socket-name": "/run/kea/kea6-ctrl-socket"},
                    }
                },
            }
        )
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

        v4_conf = json.dumps(
            {
                "Dhcp4": {
                    "interfaces-config": {"interfaces": ["eth0"]},
                    "lease-database": {"type": "mysql", "host": "10.10.11.250", "user": "kea", "name": "kea"},
                    "hooks-libraries": [{"library": "/usr/lib/kea/hooks/libdhcp_host_cmds.so"}],
                }
            }
        )
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

        v4_conf = json.dumps(
            {
                "Dhcp4": {
                    "lease-database": {
                        "type": "mysql",
                        "host": "h",
                        "user": "u",
                        "password": "supersecret",
                        "name": "kea",
                    }
                }
            }
        )
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
        assert any("host_cmds" in lib for lib in libs)
        assert any("lease_cmds" in lib for lib in libs)

    def test_never_includes_ha_config(self):
        """Explicit scope exclusion — must never be silently added."""
        from jen.services.kea_authoring import build_new_kea_config

        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        cfg = build_new_kea_config("dhcp6", ["eth0"], lease_db, "/run/x.sock", {})
        assert "high-availability" not in json.dumps(cfg).lower().replace("-", "").replace(
            " ", ""
        ) or "high-availability" not in str(cfg.get("Dhcp6", {}).get("hooks-libraries", []))
        # More direct: no hook library path mentions the HA hook at all.
        libs = [h["library"] for h in cfg["Dhcp6"]["hooks-libraries"]]
        assert not any("libdhcp_ha" in lib for lib in libs)

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
        subnets = {1: {"name": "A", "cidr": "2001:db8:1::/64"}, 7: {"name": "B", "cidr": "2001:db8:7::/64"}}
        cfg = build_new_kea_config("dhcp6", ["eth0"], lease_db, "/run/x.sock", subnets)
        ids = {s["id"] for s in cfg["Dhcp6"]["subnet6"]}
        assert ids == {1, 7}

    def test_ca_mode_keeps_the_singular_control_socket_map(self):
        """v5.10.1 — no http_socket (the ca default) must produce exactly
        what every prior release did: the singular control-socket map,
        never a control-sockets list."""
        from jen.services.kea_authoring import build_new_kea_config

        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        cfg = build_new_kea_config("dhcp4", ["eth0"], lease_db, "/run/kea/kea4.sock", {})
        section = cfg["Dhcp4"]
        assert section["control-socket"] == {"socket-type": "unix", "socket-name": "/run/kea/kea4.sock"}
        assert "control-sockets" not in section

    def test_direct_mode_emits_control_sockets_list_with_http_entry(self):
        from jen.services.kea_authoring import build_new_kea_config

        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        http_socket = {"address": "0.0.0.0", "port": 8004, "user": "kea-api", "password": "s3cret"}
        cfg = build_new_kea_config("dhcp4", ["eth0"], lease_db, "/run/kea/kea4.sock", {}, http_socket=http_socket)
        section = cfg["Dhcp4"]
        assert "control-socket" not in section
        socks = section["control-sockets"]
        assert {s["socket-type"] for s in socks} == {"unix", "http"}
        unix = next(s for s in socks if s["socket-type"] == "unix")
        assert unix["socket-name"] == "/run/kea/kea4.sock"  # kept alongside
        http = next(s for s in socks if s["socket-type"] == "http")
        assert http["socket-address"] == "0.0.0.0"
        assert http["socket-port"] == 8004
        assert http["authentication"] == {
            "type": "basic",
            "realm": "kea",
            "clients": [{"user": "kea-api", "password": "s3cret"}],
        }

    def test_direct_mode_still_never_includes_ha(self):
        from jen.services.kea_authoring import build_new_kea_config

        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        http_socket = {"port": 8006, "user": "u", "password": "p"}
        cfg = build_new_kea_config("dhcp6", ["eth0"], lease_db, "/run/x.sock", {}, http_socket=http_socket)
        libs = [h["library"] for h in cfg["Dhcp6"]["hooks-libraries"]]
        assert not any("libdhcp_ha" in lib for lib in libs)


class TestSocketPortFromUrl:
    @pytest.mark.parametrize(
        "url,fallback,expected",
        [
            ("http://kea:8004", 8000, 8004),
            ("https://kea.example:9443", 8000, 9443),
            ("http://kea", 8000, 8000),  # no explicit port
            ("", 8006, 8006),
            ("not a url", 8000, 8000),
        ],
    )
    def test_parse(self, url, fallback, expected):
        from jen.services.kea_authoring import socket_port_from_url

        assert socket_port_from_url(url, fallback) == expected


class TestRenderAuthorConfigScript:
    def test_dry_run_never_writes_live_path(self):
        from jen.services.kea_authoring import render_author_config_script

        script = render_author_config_script(
            "dhcp6", "/etc/kea/kea-dhcp6.conf", {"Dhcp6": {}}, allow_overwrite=False, dry_run=True
        )
        assert "os.replace" not in script
        assert "preview-ok" in script
        assert "shutil.copy2" not in script

    def test_apply_refuses_overwrite_by_default(self):
        from jen.services.kea_authoring import render_author_config_script

        script = render_author_config_script(
            "dhcp6", "/etc/kea/kea-dhcp6.conf", {"Dhcp6": {}}, allow_overwrite=False, dry_run=False
        )
        assert "'exists'" in script
        assert "os.path.exists(path) and not False" in script

    def test_apply_with_overwrite_backs_up_first(self):
        from jen.services.kea_authoring import render_author_config_script

        script = render_author_config_script(
            "dhcp6", "/etc/kea/kea-dhcp6.conf", {"Dhcp6": {}}, allow_overwrite=True, dry_run=False
        )
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

        subnets, error = _parse_subnet_lines("1 = LAN6, 2001:db8:1::/64\n2 = IoT6, 2001:db8:2::/64", "dhcp6")
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
        from jen.routes.settings import _parse_subnet_lines, _subnets_to_lines

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

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: FakeSSHClient([("", ""), ("", "")]))
        resp = logged_in_client.get("/settings/infrastructure/author-kea/dhcp6")
        assert resp.status_code == 200
        assert b"Nothing in Jen yet for this protocol" in resp.data

    def test_existing_subnets_prefill_the_textarea(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: FakeSSHClient([("", ""), ("", "")]))
        resp = logged_in_client.get("/settings/infrastructure/author-kea/dhcp6")
        assert resp.status_code == 200
        assert b"1 = V6LAN, 2001:db8::/64" in resp.data

    def test_form_renders_with_detected_values(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "10.10.11.250", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        v4_conf = json.dumps(
            {
                "Dhcp4": {
                    "interfaces-config": {"interfaces": ["eth0"]},
                    "lease-database": {"host": "10.10.11.250", "user": "kea", "name": "kea"},
                }
            }
        )
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: FakeSSHClient([(v4_conf, ""), ("", "")]))
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
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        fake_ssh = FakeSSHClient([("preview-ok", "")])
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        resp = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp6/preview",
            data={
                "interfaces": "eth0",
                "control_socket": "/run/kea6.sock",
                "db_host": "h",
                "db_user": "u",
                "db_name": "kea",
                "subnets": "1 = V6LAN, 2001:db8::/64",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["servers"][0]["ok"] is True
        assert len(fake_ssh.calls) == 1

    def test_direct_mode_preview_config_carries_the_http_control_socket(self, logged_in_client, monkeypatch):
        """v5.10.1 — in connection_mode = direct the previewed (and later
        written) config must expose the daemon's own http command socket,
        or Jen can't reach the Kea it just authored."""
        server = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "192.168.1.0/24"}})
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        monkeypatch.setattr(extensions, "KEA_API_URL", "http://1.2.3.4:8004")
        monkeypatch.setattr(extensions, "KEA_API_USER", "kea-api")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "s3cret")
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: FakeSSHClient([("preview-ok", "")]))
        resp = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data={
                "interfaces": "eth0",
                "control_socket": "/run/kea/kea4-ctrl-socket",
                "db_host": "h",
                "db_user": "u",
                "db_name": "kea",
                "subnets": "1 = LAN, 192.168.1.0/24",
            },
        )
        assert resp.status_code == 200
        socks = resp.get_json()["config"]["Dhcp4"]["control-sockets"]
        http = next(s for s in socks if s["socket-type"] == "http")
        assert http["socket-port"] == 8004
        assert http["authentication"]["clients"] == [{"user": "kea-api", "password": "s3cret"}]

    def test_direct_mode_without_api_credentials_is_refused(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        monkeypatch.setattr(extensions, "KEA_API_USER", "")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "")
        resp = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data={
                "interfaces": "eth0",
                "control_socket": "/run/kea/kea4-ctrl-socket",
                "db_host": "h",
                "db_user": "u",
                "db_name": "kea",
                "subnets": "1 = LAN, 192.168.1.0/24",
            },
        )
        assert resp.status_code == 400
        assert "username and password" in resp.get_json()["error"]


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

        script = render_author_config_script(
            "dhcp6", "/etc/kea/kea-dhcp6.conf", {"Dhcp6": {}}, allow_overwrite=False, dry_run=True
        )
        assert "except FileNotFoundError:" in script
        assert "missingbinary:kea-dhcp6" in script
        # The try/except must wrap the actual subprocess.run call, not
        # just appear somewhere in the script text.
        assert "try:\n    result = subprocess.run" in script

    def test_v6_subnet_patch_script_catches_missing_binary(self):
        from jen.services.kea6 import build_subnet6_patch_script

        script = build_subnet6_patch_script(
            1,
            "/etc/kea/kea-dhcp6.conf",
            "2001:db8::10-2001:db8::20",
            [],
            "",
            "",
            "",
            "",
            "",
            dry_run=True,
        )
        assert "except FileNotFoundError:" in script
        assert "missingbinary:kea-dhcp6" in script

    def test_v4_subnet_patch_script_catches_missing_binary(self):
        import jen.routes.subnets as subnets_module

        script = subnets_module._build_subnet_patch_script(
            1,
            "/etc/kea/kea-dhcp4.conf",
            "192.168.1.10-192.168.1.20",
            [],
            "",
            "",
            "",
            "",
            "",
            dry_run=True,
        )
        assert "except FileNotFoundError:" in script
        assert "missingbinary:kea-dhcp4" in script

    def test_all_three_generated_scripts_remain_valid_python(self):
        """Guard against the fix itself introducing a syntax error into
        the script that actually runs on the remote Kea server."""
        import ast

        import jen.routes.subnets as subnets_module
        from jen.services.kea6 import build_subnet6_patch_script
        from jen.services.kea_authoring import render_author_config_script

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
        resp = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp6/preview",
            data={
                "interfaces": "eth0",
                "control_socket": "/run/kea6.sock",
                "db_host": "h",
                "db_user": "u",
                "db_name": "kea",
                "subnets": "1 = V6LAN, 2001:db8::/64",
            },
        )
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
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        fake_ssh = FakeSSHClient([("exists", "")])
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        resp = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp6",
            data={
                "interfaces": "eth0",
                "control_socket": "/run/kea6.sock",
                "db_host": "h",
                "db_user": "u",
                "db_name": "kea",
                "subnets": "1 = V6LAN, 2001:db8::/64",
            },
            follow_redirects=True,
        )
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
        import jen.routes.settings as settings_module
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        captured = {}
        monkeypatch.setattr(
            getattr(settings_module, "__config"), "write_subnets6_config", lambda d: captured.update(subnets=d)
        )
        resp = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp6",
            data={
                "interfaces": "eth0",
                "control_socket": "/run/kea6.sock",
                "db_host": "h",
                "db_user": "u",
                "db_name": "kea",
                "subnets": "1 = V6LAN, 2001:db8::/64",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert captured["subnets"][1]["name"] == "V6LAN"
        assert captured["subnets"][1]["cidr"] == "2001:db8::/64"

    def test_failed_write_does_not_persist_subnets(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        fake_ssh = FakeSSHClient([("testerror:bad", "")])
        import jen.routes.settings as settings_module
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        called = {"count": 0}
        monkeypatch.setattr(
            getattr(settings_module, "__config"),
            "write_subnets6_config",
            lambda d: called.__setitem__("count", called["count"] + 1),
        )
        logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp6",
            data={
                "interfaces": "eth0",
                "control_socket": "/run/kea6.sock",
                "db_host": "h",
                "db_user": "u",
                "db_name": "kea",
                "subnets": "1 = V6LAN, 2001:db8::/64",
            },
            follow_redirects=True,
        )
        assert called["count"] == 0

    def test_successful_write(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        fake_ssh = FakeSSHClient([("ok", "")])
        import jen.routes.settings as settings_module
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        monkeypatch.setattr(getattr(settings_module, "__config"), "write_subnets6_config", lambda d: None)
        resp = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp6",
            data={
                "interfaces": "eth0",
                "control_socket": "/run/kea6.sock",
                "db_host": "h",
                "db_user": "u",
                "db_name": "kea",
                "subnets": "1 = V6LAN, 2001:db8::/64",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"written" in resp.data

    def test_config_test_failure_writes_nothing(self, logged_in_client, monkeypatch):
        server = {"id": 1, "name": "theelders", "ssh_host": "1.2.3.4", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        fake_ssh = FakeSSHClient([("testerror:bad interface", "")])
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fake_ssh)
        resp = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp6",
            data={
                "interfaces": "eth0",
                "control_socket": "/run/kea6.sock",
                "db_host": "h",
                "db_user": "u",
                "db_name": "kea",
                "subnets": "1 = V6LAN, 2001:db8::/64",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"config test failed, nothing written" in resp.data
        assert b"bad interface" in resp.data
