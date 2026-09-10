"""
tests/test_kea_authoring.py
───────────────────────────
jen/services/kea_authoring.py — generating a starting kea-dhcp4/6 config when none exists: path detection, remote JSON reads, CA socket and sibling-config detection, interface autodetect, config/script building, subnet-line parsing, and every author/binary route.

Split out of the monolithic tests/test_kea6.py in v5.6.1.
"""

import base64
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
        """api_socket=None (the ca default) must produce exactly what
        every prior release did: the singular control-socket map."""
        from jen.services.kea_authoring import build_new_kea_config

        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        cfg = build_new_kea_config("dhcp4", ["eth0"], lease_db, "/run/kea/kea4.sock", {})
        section = cfg["Dhcp4"]
        assert section["control-socket"] == {"socket-type": "unix", "socket-name": "/run/kea/kea4.sock"}
        assert "control-sockets" not in section

    def test_direct_http_socket_is_scheme_typed_with_no_tls_keys(self):
        from jen.services.kea_authoring import build_new_kea_config

        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        sock = {
            "scheme": "http",
            "address": "10.0.0.5",
            "port": 8004,
            "user": "kea-api",
            "password": "s3cret",
            "tls": None,
        }
        cfg = build_new_kea_config("dhcp4", ["eth0"], lease_db, "/run/kea/kea4.sock", {}, api_socket=sock)
        socks = cfg["Dhcp4"]["control-sockets"]
        assert "control-socket" not in cfg["Dhcp4"]
        assert {s["socket-type"] for s in socks} == {"unix", "http"}
        http = next(s for s in socks if s["socket-type"] == "http")
        assert http["socket-address"] == "10.0.0.5"
        assert http["socket-port"] == 8004
        assert "trust-anchor" not in http and "cert-required" not in http
        assert http["authentication"]["clients"] == [{"user": "kea-api", "password": "s3cret"}]

    def test_direct_https_socket_carries_the_tls_keys(self):
        from jen.services.kea_authoring import build_new_kea_config

        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        sock = {
            "scheme": "https",
            "address": "10.0.0.5",
            "port": 8004,
            "user": "ka",
            "password": "pw",
            "tls": {
                "trust_anchor": "/etc/kea/tls/ca",
                "cert_file": "/etc/kea/tls/s.crt",
                "key_file": "/etc/kea/tls/s.key",
                "cert_required": False,
            },
        }
        cfg = build_new_kea_config("dhcp4", ["eth0"], lease_db, "/run/x.sock", {}, api_socket=sock)
        https = next(s for s in cfg["Dhcp4"]["control-sockets"] if s["socket-type"] == "https")
        assert https["trust-anchor"] == "/etc/kea/tls/ca"
        assert https["cert-file"] == "/etc/kea/tls/s.crt"
        assert https["key-file"] == "/etc/kea/tls/s.key"
        assert https["cert-required"] is False

    def test_direct_mode_still_never_includes_ha(self):
        from jen.services.kea_authoring import build_new_kea_config

        lease_db = {"host": "h", "user": "u", "password": "p", "name": "kea"}
        sock = {"scheme": "http", "address": "10.0.0.5", "port": 8006, "user": "u", "password": "p", "tls": None}
        cfg = build_new_kea_config("dhcp6", ["eth0"], lease_db, "/run/x.sock", {}, api_socket=sock)
        libs = [h["library"] for h in cfg["Dhcp6"]["hooks-libraries"]]
        assert not any("libdhcp_ha" in lib for lib in libs)


class TestRedactSecrets:
    def test_replaces_every_password_key(self):
        from jen.services.kea_authoring import redact_secrets

        cfg = {
            "Dhcp4": {
                "lease-database": {"password": "dbpw", "host": "h"},
                "control-sockets": [
                    {"socket-type": "unix"},
                    {"authentication": {"clients": [{"user": "u", "password": "sockpw"}]}},
                ],
            }
        }
        red = redact_secrets(cfg)
        assert red["Dhcp4"]["lease-database"]["password"] == "********"
        assert red["Dhcp4"]["control-sockets"][1]["authentication"]["clients"][0]["password"] == "********"
        assert red["Dhcp4"]["lease-database"]["host"] == "h"  # non-secret untouched
        assert cfg["Dhcp4"]["lease-database"]["password"] == "dbpw"  # deep copy, original intact


class TestAutodetectAddresses:
    def test_parses_ip_o_addr_and_drops_loopback(self):
        from jen.services.kea_authoring import autodetect_addresses

        out = (
            "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
            "3: eth0    inet6 2001:db8::5/64 scope global\n"
            "1: lo    inet 127.0.0.1/8 scope host lo\n"
        )
        assert autodetect_addresses(FakeSSHClient([(out, "")])) == ["10.0.0.5", "2001:db8::5"]

    def test_empty_on_ssh_failure(self):
        from jen.services.kea_authoring import autodetect_addresses

        class Boom:
            def exec_command(self, cmd):
                raise RuntimeError("no ssh")

        assert autodetect_addresses(Boom()) == []


class TestSocketPortFromUrl:
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("http://kea:8004", 8004),
            ("https://kea.example:9443", 9443),
            ("http://kea", None),  # v5.10.2 — no explicit port is an error, not a guess
            ("https://kea", None),
            ("", None),
            ("not a url", None),
        ],
    )
    def test_parse(self, url, expected):
        from jen.services.kea_authoring import socket_port_from_url

        assert socket_port_from_url(url) == expected


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

    def test_direct_mode_form_renders_bind_picker_preselecting_the_endpoint_ip(self, logged_in_client, monkeypatch):
        """v5.10.2 — direct mode: autodetect_addresses runs (a 4th
        exec_command on the same session — the fake must not run dry),
        the bind picker preselects the endpoint IP."""
        server = {"id": 1, "name": "s1", "ssh_host": "10.0.0.5", "api_url": "http://10.0.0.5:8004"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "192.168.1.0/24"}})
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        monkeypatch.setattr(extensions, "KEA_API_URL", "http://10.0.0.5:8004")
        addr_out = "2: eth0    inet 10.0.0.5/24 scope global eth0\n3: eth1    inet 172.16.0.9/24 scope global eth1\n"
        import jen.services.kea6 as kea6_module

        # sibling-config read, autodetect_interfaces, ca-socket read, autodetect_addresses
        monkeypatch.setattr(
            kea6_module, "_connect_ssh", lambda s: FakeSSHClient([("", ""), ("", ""), ("", ""), (addr_out, "")])
        )
        resp = logged_in_client.get("/settings/infrastructure/author-kea/dhcp4")
        assert resp.status_code == 200
        body = resp.data
        assert b'name="bind_address_1"' in body  # v5.10.3 — per server
        assert b'<option value="10.0.0.5" selected>' in body
        assert b'value="172.16.0.9"' in body
        assert b"Credentials are transmitted without encryption" in body  # http warning

    def test_direct_mode_two_servers_each_get_their_own_picker(self, logged_in_client, monkeypatch):
        """v5.10.3 — 5.10.2 detected one address on the FIRST ssh server and
        offered it for every server; an HA pair has two management IPs."""
        s1 = {"id": 1, "name": "kea01", "ssh_host": "10.10.10.20", "api_url": "http://10.10.10.20:8004"}
        s2 = {"id": 2, "name": "kea02", "ssh_host": "10.10.10.21", "api_url": "http://10.10.10.21:8004"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [s1, s2])
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "192.168.1.0/24"}})
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        import jen.services.kea6 as kea6_module

        fakes = {
            # target server: sibling, interfaces, ca-socket, addresses
            "10.10.10.20": FakeSSHClient(
                [("", ""), ("", ""), ("", ""), ("2: eth0    inet 10.10.10.20/24 scope global eth0\n", "")]
            ),
            # other servers: addresses only
            "10.10.10.21": FakeSSHClient([("2: eth0    inet 10.10.10.21/24 scope global eth0\n", "")]),
        }
        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: fakes[s["ssh_host"]])
        body = logged_in_client.get("/settings/infrastructure/author-kea/dhcp4").data
        assert b'name="bind_address_1"' in body and b'name="bind_address_2"' in body
        assert b'<option value="10.10.10.20" selected>' in body
        assert b'<option value="10.10.10.21" selected>' in body
        # neither picker defaults to all-interfaces, and the old "one at a
        # time" workaround text is gone
        assert b'<option value="0.0.0.0" selected>' not in body
        assert b"one at a time" not in body

    def test_direct_dhcp6_without_a_v6_url_says_so_up_front(self, logged_in_client, monkeypatch):
        """v5.10.3 (bug 8) — the GET page used to fall back to scheme
        'http' with an empty host and only the POST explained the real
        problem."""
        server = {"id": 1, "name": "s1", "ssh_host": "10.0.0.5", "api_url": "http://10.0.0.5:8004"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        monkeypatch.setattr(extensions, "KEA6_API_URL", "")
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", lambda s: FakeSSHClient([("", ""), ("", ""), ("", "")]))
        body = logged_in_client.get("/settings/infrastructure/author-kea/dhcp6").data
        assert b"no kea-dhcp6 control-socket URL is configured" in body
        assert b"disabled" in body  # Preview button
        assert b"Credentials are transmitted without encryption" not in body


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

    # ── v5.10.2 direct-mode authoring ──────────────────────────────────────
    def _direct_form(self, **over):
        f = {
            "interfaces": "eth0",
            "control_socket": "/run/kea/kea4-ctrl-socket",
            "db_host": "h",
            "db_user": "u",
            "db_name": "kea",
            "subnets": "1 = LAN, 192.168.1.0/24",
            # v5.10.3 — the bind address is per server (id 1 by default here).
            "bind_address_1": "10.0.0.5",
        }
        f.update(over)
        return f

    def _direct_setup(self, monkeypatch, servers, connect_map=None):
        # derive_kea_servers() always populates api_user/api_pass and the
        # api6_* keys on every server dict; mirror that here so
        # _endpoint_for() resolves the way it does in production.
        for s in servers:
            s.setdefault("api_user", "kea-api")
            s.setdefault("api_pass", "s3cret")
            for k in ("api6_url", "api6_user", "api6_pass"):
                s.setdefault(k, "")
        monkeypatch.setattr(extensions, "KEA_SERVERS", servers)
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "192.168.1.0/24"}})
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        import jen.services.kea6 as kea6_module

        cmap = connect_map or {}

        def _connect(server):
            return cmap.get(server.get("name"), FakeSSHClient([("preview-ok", "")]))

        monkeypatch.setattr(kea6_module, "_connect_ssh", _connect)

    def test_direct_preview_http_socket_from_this_servers_url(self, logged_in_client, monkeypatch):
        srv = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "api_url": "http://1.2.3.4:8004"}
        self._direct_setup(monkeypatch, [srv])
        data = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview", data=self._direct_form()
        ).get_json()
        assert data["servers"][0]["ok"] is True
        socks = data["servers"][0]["config"]["Dhcp4"]["control-sockets"]
        http = next(s for s in socks if s["socket-type"] == "http")
        assert http["socket-port"] == 8004
        assert http["socket-address"] == "10.0.0.5"
        # redacted in the browser payload
        assert http["authentication"]["clients"][0]["password"] == "********"

    def test_direct_preview_is_per_server_not_the_primarys_socket(self, logged_in_client, monkeypatch):
        primary = {"id": 1, "name": "p1", "ssh_host": "1.1.1.1", "api_url": "http://1.1.1.1:8004"}
        standby = {
            "id": 2,
            "name": "s2",
            "ssh_host": "2.2.2.2",
            "api_url": "http://2.2.2.2:9004",
            "api_user": "u2",
            "api_pass": "p2",
        }
        monkeypatch.setattr(extensions, "KEA_API_URL", "http://1.1.1.1:8004")
        monkeypatch.setattr(extensions, "KEA_API_USER", "u1")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "p1")
        self._direct_setup(monkeypatch, [primary, standby])
        data = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data=self._direct_form(bind_address_2="10.0.0.6"),
        ).get_json()
        by_name = {r["name"]: r for r in data["servers"]}
        p_http = next(s for s in by_name["p1"]["config"]["Dhcp4"]["control-sockets"] if s["socket-type"] == "http")
        s_http = next(s for s in by_name["s2"]["config"]["Dhcp4"]["control-sockets"] if s["socket-type"] == "http")
        assert p_http["socket-port"] == 8004
        assert s_http["socket-port"] == 9004  # standby's OWN port, not the primary's
        assert data["all_passed"] is True

    def test_direct_preview_one_server_missing_a_port_only_fails_that_one(self, logged_in_client, monkeypatch):
        good = {"id": 1, "name": "good", "ssh_host": "1.1.1.1", "api_url": "http://1.1.1.1:8004"}
        bad = {"id": 2, "name": "bad", "ssh_host": "2.2.2.2", "api_url": "http://2.2.2.2"}  # no port
        monkeypatch.setattr(extensions, "KEA_API_URL", "http://1.1.1.1:8004")
        monkeypatch.setattr(extensions, "KEA_API_USER", "u")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "p")
        self._direct_setup(monkeypatch, [good, bad])
        data = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data=self._direct_form(bind_address_2="10.0.0.6"),
        ).get_json()
        by_name = {r["name"]: r for r in data["servers"]}
        assert by_name["good"]["ok"] is True
        assert by_name["bad"]["ok"] is False
        assert "explicit port" in by_name["bad"]["message"]
        assert data["all_passed"] is False

    def test_direct_preview_hostname_bind_address_is_400(self, logged_in_client, monkeypatch):
        srv = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "api_url": "http://1.2.3.4:8004"}
        monkeypatch.setattr(extensions, "KEA_API_URL", "http://1.2.3.4:8004")
        monkeypatch.setattr(extensions, "KEA_API_USER", "u")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "p")
        self._direct_setup(monkeypatch, [srv])
        r = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data=self._direct_form(bind_address_1="kea.example.com"),
        )
        assert r.status_code == 400
        assert "IP address" in r.get_json()["error"]

    def test_direct_preview_0000_bind_is_a_warning_not_a_block(self, logged_in_client, monkeypatch):
        srv = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "api_url": "http://1.2.3.4:8004"}
        monkeypatch.setattr(extensions, "KEA_API_URL", "http://1.2.3.4:8004")
        monkeypatch.setattr(extensions, "KEA_API_USER", "u")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "p")
        self._direct_setup(monkeypatch, [srv])
        data = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data=self._direct_form(bind_address_1="0.0.0.0"),
        ).get_json()
        assert data["servers"][0]["ok"] is True
        assert data["all_passed"] is True
        assert "every interface" in data["servers"][0]["warning"]

    def test_direct_preview_https_needs_tls_paths(self, logged_in_client, monkeypatch):
        srv = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "api_url": "https://1.2.3.4:8004"}
        monkeypatch.setattr(extensions, "KEA_API_URL", "https://1.2.3.4:8004")
        monkeypatch.setattr(extensions, "KEA_API_USER", "u")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "p")
        self._direct_setup(monkeypatch, [srv])
        r = logged_in_client.post("/settings/infrastructure/author-kea/dhcp4/preview", data=self._direct_form())
        assert r.status_code == 400
        assert "https" in r.get_json()["error"]

    def test_direct_preview_https_with_tls_paths_and_tlsmissing(self, logged_in_client, monkeypatch):
        srv = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "api_url": "https://1.2.3.4:8004"}
        monkeypatch.setattr(extensions, "KEA_API_URL", "https://1.2.3.4:8004")
        monkeypatch.setattr(extensions, "KEA_API_USER", "u")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "p")
        self._direct_setup(monkeypatch, [srv], {"s1": FakeSSHClient([("tlsmissing:/etc/kea/tls/s.key", "")])})
        data = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data=self._direct_form(
                tls_cert_file="/etc/kea/tls/s.crt",
                tls_key_file="/etc/kea/tls/s.key",
                tls_trust_anchor="/etc/kea/tls/ca.crt",
            ),
        ).get_json()
        assert data["servers"][0]["ok"] is False
        assert "TLS file not found" in data["servers"][0]["message"]
        https = next(s for s in data["servers"][0]["config"]["Dhcp4"]["control-sockets"] if s["socket-type"] == "https")
        assert https["cert-file"] == "/etc/kea/tls/s.crt"

    def test_direct_preview_never_leaks_a_password_to_the_browser(self, logged_in_client, monkeypatch):
        srv = {"id": 1, "name": "s1", "ssh_host": "1.2.3.4", "api_url": "http://1.2.3.4:8004", "api_pass": "s3cretsock"}
        monkeypatch.setattr(extensions, "KEA_DB_PASS", "s3cretdb")
        fake = FakeSSHClient([("preview-ok", "")])
        self._direct_setup(monkeypatch, [srv], {"s1": fake})

        body = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview", data=self._direct_form()
        ).get_data(as_text=True)
        assert "s3cretsock" not in body and "s3cretdb" not in body

        # but the REAL passwords reached the remote script
        b64 = fake.calls[0].split("echo ")[1].split(" |")[0]
        script = base64.b64decode(b64).decode()
        assert "s3cretsock" in script and "s3cretdb" in script

    # ── v5.10.3: the bind address is per server ────────────────────────────
    def _pair_of_servers(self, monkeypatch):
        s1 = {"id": 1, "name": "kea01", "ssh_host": "10.10.10.20", "api_url": "http://10.10.10.20:8004"}
        s2 = {"id": 2, "name": "kea02", "ssh_host": "10.10.10.21", "api_url": "http://10.10.10.21:8004"}
        self._direct_setup(monkeypatch, [s1, s2])
        return s1, s2

    def test_each_server_binds_its_own_address(self, logged_in_client, monkeypatch):
        """5.10.2 wrote one bind address into every server's socket — kea02
        was told to bind kea01's management IP."""
        self._pair_of_servers(monkeypatch)
        data = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data=self._direct_form(bind_address_1="10.10.10.20", bind_address_2="10.10.10.21"),
        ).get_json()
        by_name = {r["name"]: r for r in data["servers"]}
        for name, want in (("kea01", "10.10.10.20"), ("kea02", "10.10.10.21")):
            sock = next(s for s in by_name[name]["config"]["Dhcp4"]["control-sockets"] if s["socket-type"] == "http")
            assert sock["socket-address"] == want
            assert by_name[name]["bind_address"] == want
            assert "warning" not in by_name[name]
        assert data["all_passed"] is True

    def test_binding_another_servers_address_warns_but_still_passes(self, logged_in_client, monkeypatch):
        self._pair_of_servers(monkeypatch)
        data = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data=self._direct_form(bind_address_1="10.10.10.20", bind_address_2="10.10.10.20"),
        ).get_json()
        by_name = {r["name"]: r for r in data["servers"]}
        assert "warning" not in by_name["kea01"]
        assert "10.10.10.21" in by_name["kea02"]["warning"]  # Jen connects there
        assert data["all_passed"] is True  # a warning, not a block

    def test_a_server_with_no_bind_address_fails_only_itself(self, logged_in_client, monkeypatch):
        self._pair_of_servers(monkeypatch)
        data = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data=self._direct_form(bind_address_1="10.10.10.20"),  # nothing for server 2
        ).get_json()
        by_name = {r["name"]: r for r in data["servers"]}
        assert by_name["kea01"]["ok"] is True
        assert by_name["kea02"]["ok"] is False
        assert "no bind address" in by_name["kea02"]["message"]
        assert data["all_passed"] is False

    def test_a_hostname_bind_address_names_the_server(self, logged_in_client, monkeypatch):
        self._pair_of_servers(monkeypatch)
        r = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data=self._direct_form(bind_address_1="kea01.example", bind_address_2="10.10.10.21"),
        )
        assert r.status_code == 400
        assert "kea01" in r.get_json()["error"]

    def test_the_custom_field_overrides_the_select(self, logged_in_client, monkeypatch):
        self._pair_of_servers(monkeypatch)
        data = logged_in_client.post(
            "/settings/infrastructure/author-kea/dhcp4/preview",
            data=self._direct_form(
                bind_address_1="10.10.10.20",
                bind_address_2="10.10.10.21",
                bind_address_custom_2="192.168.50.9",
            ),
        ).get_json()
        by_name = {r["name"]: r for r in data["servers"]}
        assert by_name["kea02"]["bind_address"] == "192.168.50.9"


class TestAuthorBindCandidates:
    """v5.10.3 — one picker per ssh server, each from its OWN detected
    addresses and its OWN endpoint. FakeSSHClient returns ("", "") past the
    end of its reply list, so these assert the option VALUES; a
    short-changed fake would otherwise pass vacuously."""

    def _setup(self, monkeypatch, servers, connect):
        for s in servers:
            s.setdefault("api_user", "u")
            s.setdefault("api_pass", "p")
            for k in ("api6_url", "api6_user", "api6_pass"):
                s.setdefault(k, "")
        monkeypatch.setattr(extensions, "KEA_SERVERS", servers)
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "_connect_ssh", connect)

    def test_each_server_offers_its_own_addresses(self, logged_in_client, monkeypatch):
        from jen.routes.settings.authoring import _author_bind_candidates

        s1 = {"id": 1, "name": "kea01", "ssh_host": "10.10.10.20", "api_url": "http://10.10.10.20:8004"}
        s2 = {"id": 2, "name": "kea02", "ssh_host": "10.10.10.21", "api_url": "http://10.10.10.21:8004"}
        fakes = {
            "10.10.10.20": FakeSSHClient([("2: eth0    inet 10.10.10.20/24 scope global eth0\n", "")]),
            "10.10.10.21": FakeSSHClient(
                [
                    (
                        "2: eth0    inet 10.10.10.21/24 scope global eth0\n3: eth1    inet 172.16.0.9/24 scope global eth1\n",
                        "",
                    )
                ]
            ),
        }
        self._setup(monkeypatch, [s1, s2], lambda s: fakes[s["ssh_host"]])
        by_id = {c["id"]: c for c in _author_bind_candidates("dhcp4")}
        assert by_id[1]["options"] == ["10.10.10.20"]
        assert by_id[1]["preselect"] == "10.10.10.20"
        assert by_id[2]["options"] == ["10.10.10.21", "172.16.0.9"]
        assert by_id[2]["preselect"] == "10.10.10.21"

    def test_target_addresses_are_reused_without_a_second_ssh(self, logged_in_client, monkeypatch):
        from jen.routes.settings.authoring import _author_bind_candidates

        s1 = {"id": 1, "name": "kea01", "ssh_host": "10.10.10.20", "api_url": "http://10.10.10.20:8004"}
        connects = []

        def _connect(s):
            connects.append(s["ssh_host"])
            return FakeSSHClient([("", "")])

        self._setup(monkeypatch, [s1], _connect)
        by_id = {c["id"]: c for c in _author_bind_candidates("dhcp4", s1, ["10.10.10.20", "172.16.0.9"])}
        assert connects == []  # the caller already fetched these
        assert by_id[1]["options"] == ["10.10.10.20", "172.16.0.9"]

    def test_a_connection_failure_still_offers_the_endpoint_ip(self, logged_in_client, monkeypatch):
        from jen.routes.settings.authoring import _author_bind_candidates

        s1 = {"id": 1, "name": "kea01", "ssh_host": "10.10.10.20", "api_url": "http://10.10.10.20:8004"}

        def _boom(s):
            raise TimeoutError("no route to host")

        self._setup(monkeypatch, [s1], _boom)
        c = _author_bind_candidates("dhcp4")[0]
        assert c["options"] == ["10.10.10.20"]
        assert c["preselect"] == "10.10.10.20"

    def test_an_unresolvable_endpoint_reports_the_error_and_no_options(self, logged_in_client, monkeypatch):
        from jen.routes.settings.authoring import _author_bind_candidates

        s1 = {"id": 1, "name": "kea01", "ssh_host": "10.10.10.20", "api_url": "http://10.10.10.20:8004"}
        self._setup(monkeypatch, [s1], lambda s: FakeSSHClient([("", "")]))
        monkeypatch.setattr(extensions, "KEA6_API_URL", "")
        c = _author_bind_candidates("dhcp6")[0]  # direct + dhcp6, no v6 URL
        assert "kea-dhcp6 control-socket" in c["endpoint_error"]
        assert c["options"] == [] and c["preselect"] == ""


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
