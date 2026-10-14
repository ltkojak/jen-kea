"""
tests/test_ddns.py
────────────────────
ddns.py had no dedicated test file before this — flagged in the Jen
maturity roadmap (Tier 1). The route's lookup-validator rejection path
was already covered in tests/test_security_fixes.py
(TestRemoteCommandValidators::test_ddns_lookup_route_rejects_invalid_host);
this file covers what wasn't: the auth boundary, the SSH log-fetch
branch's error handling, and — the actual regression this file exists
to guard against — that both SSH call sites in this route use the
hardened auth.ssh_cli_opts() (StrictHostKeyChecking=accept-new) rather
than the old inline StrictHostKeyChecking=no flags fixed in v4.4.8.
"""

import json
from unittest.mock import MagicMock, patch

import pytest


class TestDdnsPageAuth:
    def test_requires_login(self, client):
        r = client.get("/ddns", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        assert "login" in r.headers.get("Location", "").lower()


class TestDdnsLogFetch:
    """v5.11.0 — the DDNS log read goes through jen.services.kea_host.tail_log
    (helper op `tail-log` / legacy `sudo tail`). Stub it here."""

    def _stub_tail(self, monkeypatch, result):
        from jen.services import kea_host

        calls = []
        monkeypatch.setattr(kea_host, "tail_log", lambda srv, path, lines=200: (calls.append((path, lines)), result)[1])
        return calls

    def test_ssh_host_not_configured(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [])
        calls = self._stub_tail(monkeypatch, {"ok": True, "code": "ok", "lines": []})
        r = logged_in_client.get("/ddns")
        assert r.status_code == 200
        assert b"ssh host not configured" in r.data.lower()
        assert calls == []

    def test_successful_log_fetch_shows_newest_first(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "ssh_host": "10.0.0.5", "ssh_user": "kea"}])
        calls = self._stub_tail(monkeypatch, {"ok": True, "code": "ok", "lines": ["oldest", "newest"]})
        r = logged_in_client.get("/ddns")
        assert r.status_code == 200
        assert calls and calls[0][0] == extensions.DDNS_LOG
        body = r.data.decode()
        assert body.index("newest") < body.index("oldest")  # reversed for display

    def test_missing_log_file(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "ssh_host": "10.0.0.5", "ssh_user": "kea"}])
        self._stub_tail(monkeypatch, {"ok": False, "code": "missing", "detail": "log file not found"})
        r = logged_in_client.get("/ddns")
        assert r.status_code == 200
        assert b"log file not found" in r.data.lower()

    def test_ssh_error_is_reported(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "ssh_host": "10.0.0.5", "ssh_user": "kea"}])
        self._stub_tail(monkeypatch, {"ok": False, "code": "error", "detail": "connection timed out"})
        r = logged_in_client.get("/ddns")
        assert r.status_code == 200
        assert b"ssh error" in r.data.lower()


class TestDdnsSshLookupProvider:
    """dns_provider='ssh' does a dig/host lookup over SSH — same hardened
    ssh_cli_opts() regression guard as the log-fetch path above."""

    def test_ssh_lookup_uses_hardened_ssh_opts(self, logged_in_client, monkeypatch):
        import configparser

        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")  # skip log fetch branch

        # extensions.cfg is a session-shared global (built once by
        # _patch_extensions()) — swap the whole reference via monkeypatch
        # rather than mutating it in place, so the original is restored
        # automatically at teardown instead of leaking a "ddns" section
        # into every test that runs after this one.
        test_cfg = configparser.ConfigParser()
        test_cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        test_cfg["ddns"] = {"dns_provider": "ssh"}
        monkeypatch.setattr(extensions, "cfg", test_cfg)

        fake_active_server = {"ssh_host": "10.0.0.5", "ssh_user": "kea"}
        fake_lookup_result = MagicMock(returncode=0, stdout="10.99.0.50\n", stderr="")

        with (
            patch("jen.services.kea.get_active_kea_server", return_value=fake_active_server),
            patch("jen.routes.ddns.subprocess.run", return_value=fake_lookup_result) as mock_run,
        ):
            r = logged_in_client.get("/ddns", query_string={"host": "test-host.local"})
            assert r.status_code == 200
            assert mock_run.called
            call_args = mock_run.call_args[0][0]
            assert "StrictHostKeyChecking=accept-new" in call_args
            assert "StrictHostKeyChecking=no" not in call_args


class TestDdnsStatusTab:
    """v5.23.0 (Q19) — mode, per-server enable-updates, and D2 up/version/
    stats, added to the Status tab alongside the pre-existing log+lookup
    content above."""

    def test_default_tab_is_status(self, logged_in_client, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        r = logged_in_client.get("/ddns")
        assert r.status_code == 200
        assert b"Recent Log Activity" in r.data

    def test_mode_shows_provider_when_a_provider_is_configured(self, logged_in_client, mock_kea, monkeypatch):
        """Q176 adjustment: this used to rely on `technitium` being the default when [ddns] is absent. There is no default provider now, so the test configures one."""
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        test_cfg = __import__("configparser").ConfigParser()
        test_cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        test_cfg["ddns"] = {"dns_provider": "technitium"}
        monkeypatch.setattr(extensions, "cfg", test_cfg)
        r = logged_in_client.get("/ddns?tab=status")
        assert r.status_code == 200
        assert b"Provider (technitium)" in r.data

    def test_mode_shows_d2_when_no_provider_and_dhcp4_has_it_enabled(self, logged_in_client, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")

        test_cfg = __import__("configparser").ConfigParser()
        test_cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        test_cfg["ddns"] = {"dns_provider": "none"}
        monkeypatch.setattr(extensions, "cfg", test_cfg)

        def fake_command(cmd, service="dhcp4", arguments=None, server=None, timeout=10):
            if cmd == "config-get":
                return {"result": 0, "arguments": {"Dhcp4": {"dhcp-ddns": {"enable-updates": True}}}}
            return {"result": 0, "arguments": {}}

        monkeypatch.setattr(kea_svc, "kea_command", fake_command)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: extensions.KEA_SERVERS[0])
        r = logged_in_client.get("/ddns?tab=status")
        assert r.status_code == 200
        body = r.data.decode()
        assert ">D2<" in body
        assert "✓ Enabled" in body

    def test_d2_status_ok_shows_version_and_stats(self, logged_in_client, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")

        def fake_command(cmd, service="dhcp4", arguments=None, server=None, timeout=10):
            if cmd == "config-get":
                return {"result": 0, "arguments": {"Dhcp4": {"dhcp-ddns": {"enable-updates": True}}}}
            if cmd == "version-get":
                return {"result": 0, "text": "2.6.1"}
            if cmd == "statistic-get-all":
                return {"result": 0, "arguments": {"ncr-received": [[5, "t"]], "update-error": [[1, "t"]]}}
            return {"result": 1, "text": "unexpected"}

        monkeypatch.setattr(kea_svc, "kea_command", fake_command)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: extensions.KEA_SERVERS[0])
        r = logged_in_client.get("/ddns?tab=status")
        assert r.status_code == 200
        body = r.data.decode()
        assert "2.6.1" in body
        assert "update-error" in body

    def test_d2_status_skip_when_disabled_everywhere(self, logged_in_client, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        r = logged_in_client.get("/ddns?tab=status")
        assert r.status_code == 200
        assert b"DDNS updates disabled in dhcp4" in r.data

    def test_unknown_tab_falls_back_to_status(self, logged_in_client, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        r = logged_in_client.get("/ddns?tab=bogus")
        assert r.status_code == 200
        assert b"Recent Log Activity" in r.data


class TestDdnsViewerRestriction:
    def test_viewer_requesting_naming_tab_sees_status_instead(self, client, db, monkeypatch, mock_kea):
        from jen import extensions
        from tests.conftest import restricted_client

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        restricted_client(client, db, allowed_subnets=None, role="viewer", username="ddns_viewer1")
        r = client.get("/ddns?tab=naming")
        assert r.status_code == 200
        assert b"Recent Log Activity" in r.data
        assert b"Save DDNS Naming" not in r.data

    def test_admin_can_see_naming_tab(self, logged_in_client, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        r = logged_in_client.get("/ddns?tab=naming")
        assert r.status_code == 200
        assert b"Could not read kea-dhcp4.conf" in r.data  # no SSH configured in this fixture


class TestDdnsNamingTab:
    """v5.23.0 (Q19) — the Naming tab reads from / writes to every
    SSH-configured server via jen.services.kea_config_edit.set_ddns4."""

    def _wire(self, monkeypatch, dhcp4=None):
        from jen import extensions
        from jen.services import kea as kea_svc
        from jen.services import kea_host
        from tests._kea_host_fakes import FakeHelper

        dhcp4 = dhcp4 if dhcp4 is not None else {"dhcp-ddns": {"enable-updates": False}}
        monkeypatch.setattr(
            extensions, "KEA_SERVERS", [{"id": 1, "name": "Kea A", "ssh_host": "10.0.0.5", "ssh_user": "kea"}]
        )
        monkeypatch.setattr(
            kea_svc,
            "get_active_kea_server",
            lambda: {"id": 1, "name": "Kea A", "ssh_host": "10.0.0.5", "ssh_user": "kea"},
        )
        fake = FakeHelper()
        fake.configs[(1, "dhcp4")] = {"Dhcp4": dhcp4}
        fake.shas[(1, "dhcp4")] = "abc123"
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "backup": None, "sha256": "def456"}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
        monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a, **k: None)
        return fake

    def test_get_renders_existing_values(self, logged_in_client, monkeypatch):
        self._wire(
            monkeypatch,
            {
                "dhcp-ddns": {"enable-updates": True, "server-ip": "127.0.0.2"},
                "ddns-qualifying-suffix": "example.com",
            },
        )
        r = logged_in_client.get("/ddns?tab=naming")
        assert r.status_code == 200
        assert b'value="127.0.0.2"' in r.data
        assert b"example.com" in r.data

    def test_get_applies_kea_defaults_when_absent(self, logged_in_client, monkeypatch):
        self._wire(monkeypatch, {})
        r = logged_in_client.get("/ddns?tab=naming")
        assert r.status_code == 200
        assert b'value="myhost"' in r.data  # ddns-generated-prefix default

    def test_post_pushes_to_every_ssh_server_and_restarts(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/ddns/naming/save",
            data={
                "enable-updates": "1",
                "server-ip": "127.0.0.1",
                "server-port": "53001",
                "ncr-protocol": "UDP",
                "ncr-format": "JSON",
                "ddns-qualifying-suffix": "lan.example.com",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]
        assert applied["dhcp-ddns"]["enable-updates"] is True
        assert applied["ddns-qualifying-suffix"] == "lan.example.com"
        assert "service" in fake.ops()

    def test_post_uses_expect_sha256_from_a_fresh_read_not_a_stale_form_value(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        logged_in_client.post("/ddns/naming/save", data={"enable-updates": "1"})
        applied_payload = fake.payload_for("apply-config")
        assert applied_payload["expect_sha256"] == "abc123"  # the sha FakeHelper's read-config actually returned

    def test_post_replace_client_name_rejects_bad_values(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        logged_in_client.post("/ddns/naming/save", data={"ddns-replace-client-name": "not-a-real-choice"})
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]
        assert applied["ddns-replace-client-name"] == "never"

    def test_post_requires_admin(self, client, db, monkeypatch):
        """admin_required redirects (not a 403) — same behavior as every
        other admin-gated route in this app."""
        from tests.conftest import restricted_client

        fake = self._wire(monkeypatch)
        restricted_client(client, db, allowed_subnets=None, role="viewer", username="ddns_naming_viewer1")
        r = client.post("/ddns/naming/save", data={"enable-updates": "1"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"Admin access required" in r.data
        assert "apply-config" not in fake.ops()

    def test_no_ssh_server_flashes_and_does_not_crash(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "Kea A", "ssh_host": ""}])
        r = logged_in_client.post("/ddns/naming/save", data={"enable-updates": "1"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"No Kea server has SSH configured" in r.data

    def test_non_numeric_server_port_flashes_not_500(self, logged_in_client, monkeypatch):
        """v5.28.0 (Q24, D3) — server-port used to reach a bare int()
        with no try/except, a raw 500 on any non-numeric input."""
        fake = self._wire(monkeypatch)
        r = logged_in_client.post("/ddns/naming/save", data={"server-port": "abc"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"DDNS server port must be 1-65535" in r.data
        assert "apply-config" not in fake.ops()

    def test_out_of_range_server_port_is_rejected(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post("/ddns/naming/save", data={"server-port": "99999"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"DDNS server port must be 1-65535" in r.data
        assert "apply-config" not in fake.ops()

    def test_invalid_server_ip_is_rejected(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post("/ddns/naming/save", data={"server-ip": "not-an-ip"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"DDNS server address must be an IPv4 or IPv6 address" in r.data
        assert "apply-config" not in fake.ops()

    def test_ipv6_server_ip_is_accepted(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post("/ddns/naming/save", data={"server-ip": "2001:db8::53"}, follow_redirects=True)
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]
        assert applied["dhcp-ddns"]["server-ip"] == "2001:db8::53"


class TestParseDnsServers:
    """v5.28.0 (Q24, D3) — jen/routes/ddns.py::_parse_dns_servers, the
    D2 domain forms' "ip[:port]" parser."""

    def _parse(self, raw):
        from jen.routes.ddns import _parse_dns_servers

        return _parse_dns_servers(raw)

    def test_v4_no_port_defaults_to_53(self):
        assert self._parse("10.0.0.53") == ([("10.0.0.53", 53)], None)

    def test_v4_with_port(self):
        assert self._parse("10.0.0.53:5353") == ([("10.0.0.53", 5353)], None)

    def test_bare_v6_no_port_defaults_to_53(self):
        assert self._parse("2001:db8::53") == ([("2001:db8::53", 53)], None)

    def test_bracketed_v6_no_port(self):
        assert self._parse("[2001:db8::53]") == ([("2001:db8::53", 53)], None)

    def test_bracketed_v6_with_port(self):
        assert self._parse("[2001:db8::53]:5353") == ([("2001:db8::53", 5353)], None)

    def test_bad_address_gives_a_generic_message(self):
        servers, err = self._parse("not-an-ip")
        assert servers == []
        assert "not a valid IP address" in err

    def test_non_numeric_port_gives_a_range_message(self):
        servers, err = self._parse("10.0.0.53:abc")
        assert servers == []
        assert "1-65535" in err

    def test_out_of_range_port_is_rejected(self):
        servers, err = self._parse("10.0.0.53:0")
        assert servers == []
        assert "1-65535" in err
        servers, err = self._parse("10.0.0.53:70000")
        assert servers == []
        assert "1-65535" in err

    def test_unbracketed_v6_plus_port_that_cannot_stand_alone_is_actionable(self):
        """A fully-expanded 8-group v6 address with a trailing ":NNN" —
        invalid as one address, but valid with that last segment
        dropped — is the realistic "forgot the brackets" typo."""
        servers, err = self._parse("2001:db8:0:0:0:0:0:1:53")
        assert servers == []
        assert "[addr]:port" in err

    def test_ambiguous_bare_v6_with_a_trailing_number_group_is_accepted_whole(self):
        """A bare v6 address is never split — this is itself a
        perfectly valid (if unusual) IPv6 address, not "v6 plus port"."""
        assert self._parse("2001:db8::53:53") == ([("2001:db8::53:53", 53)], None)


class TestDdnsD2ConfigTab:
    """v5.23.0 (Q19) — D2's own config (kea-dhcp-ddns.conf), read from
    the active server and pushed to every SSH-configured one."""

    def _wire(self, monkeypatch, d2cfg=None):
        from jen import extensions
        from jen.services import kea as kea_svc
        from jen.services import kea_host
        from tests._kea_host_fakes import FakeHelper

        d2cfg = d2cfg if d2cfg is not None else {}
        monkeypatch.setattr(
            extensions, "KEA_SERVERS", [{"id": 1, "name": "Kea A", "ssh_host": "10.0.0.5", "ssh_user": "kea"}]
        )
        monkeypatch.setattr(
            kea_svc,
            "get_active_kea_server",
            lambda: {"id": 1, "name": "Kea A", "ssh_host": "10.0.0.5", "ssh_user": "kea"},
        )
        fake = FakeHelper()
        fake.configs[(1, "d2")] = {"DhcpDdns": d2cfg}
        fake.shas[(1, "d2")] = "d2sha1"
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "backup": None, "sha256": "d2sha2"}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp-ddns-server", "state": "active"}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
        monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a, **k: None)
        return fake

    def test_get_renders_domains_and_keys(self, logged_in_client, monkeypatch):
        self._wire(
            monkeypatch,
            {
                "forward-ddns": {
                    "ddns-domains": [
                        {"name": "example.com.", "key-name": "tsig1", "dns-servers": [{"ip-address": "10.0.0.53"}]}
                    ]
                },
                "tsig-keys": [{"name": "tsig1", "algorithm": "hmac-sha256", "secret": "s3cr3t"}],
            },
        )
        r = logged_in_client.get("/ddns?tab=d2config")
        assert r.status_code == 200
        assert b"example.com." in r.data
        assert b"tsig1" in r.data
        assert b"hmac-sha256" in r.data
        assert b"s3cr3t" not in r.data  # write-only, never re-displayed

    def test_ipv6_dns_server_renders_bracketed_in_the_table(self, logged_in_client, monkeypatch):
        """v5.28.0 (Q24, D3) — an unbracketed v6:port in the domain
        table would itself be ambiguous/unparseable if ever re-typed
        into the add form."""
        self._wire(
            monkeypatch,
            {
                "forward-ddns": {
                    "ddns-domains": [
                        {"name": "example.com.", "dns-servers": [{"ip-address": "2001:db8::53", "port": 53}]}
                    ]
                },
            },
        )
        r = logged_in_client.get("/ddns?tab=d2config")
        assert r.status_code == 200
        assert b"[2001:db8::53]:53" in r.data

    def test_domain_add_rejects_a_bad_zone_name(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/ddns/d2config/domain/add",
            data={"direction": "forward", "name": "no-trailing-dot", "servers": "10.0.0.53"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"fully-qualified" in r.data
        assert "apply-config" not in fake.ops()

    def test_domain_add_rejects_a_bad_server(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/ddns/d2config/domain/add",
            data={"direction": "forward", "name": "example.com.", "servers": "not-an-ip"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"not a valid IP" in r.data
        assert "apply-config" not in fake.ops()

    def test_domain_add_pushes_to_every_server(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/ddns/d2config/domain/add",
            data={"direction": "forward", "name": "example.com.", "servers": "10.0.0.53:53\n10.0.0.54"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["DhcpDdns"]["forward-ddns"]["ddns-domains"][0]
        assert applied["name"] == "example.com."
        assert applied["dns-servers"] == [
            {"ip-address": "10.0.0.53", "port": 53},
            {"ip-address": "10.0.0.54", "port": 53},
        ]
        assert "service" in fake.ops()

    def test_domain_add_accepts_a_bracketed_ipv6_server(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/ddns/d2config/domain/add",
            data={"direction": "forward", "name": "example.com.", "servers": "[2001:db8::53]:53"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["DhcpDdns"]["forward-ddns"]["ddns-domains"][0]
        assert applied["dns-servers"] == [{"ip-address": "2001:db8::53", "port": 53}]

    def test_domain_remove(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch, {"forward-ddns": {"ddns-domains": [{"name": "example.com."}]}})
        r = logged_in_client.post(
            "/ddns/d2config/domain/remove",
            data={"direction": "forward", "name": "example.com."},
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["DhcpDdns"]["forward-ddns"]["ddns-domains"]
        assert applied == []

    def test_tsig_add_rejects_bad_algorithm(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/ddns/d2config/tsig/add",
            data={"name": "tsig1", "algorithm": "rot13", "secret": "x"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"Invalid TSIG algorithm" in r.data
        assert "apply-config" not in fake.ops()

    def test_tsig_add_requires_a_secret(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/ddns/d2config/tsig/add",
            data={"name": "tsig1", "algorithm": "hmac-sha256", "secret": ""},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"secret is required" in r.data
        assert "apply-config" not in fake.ops()

    def test_tsig_add_pushes_and_secret_never_appears_in_the_flash_redirect(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/ddns/d2config/tsig/add",
            data={"name": "tsig1", "algorithm": "hmac-sha256", "secret": "topsecretvalue"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["DhcpDdns"]["tsig-keys"][0]
        assert applied == {"name": "tsig1", "algorithm": "hmac-sha256", "secret": "topsecretvalue"}
        assert b"topsecretvalue" not in r.data

    def test_tsig_remove_refused_while_referenced(self, logged_in_client, monkeypatch):
        fake = self._wire(
            monkeypatch,
            {
                "forward-ddns": {"ddns-domains": [{"name": "example.com.", "key-name": "tsig1"}]},
                "tsig-keys": [{"name": "tsig1", "algorithm": "hmac-sha256", "secret": "x"}],
            },
        )
        r = logged_in_client.post("/ddns/d2config/tsig/remove", data={"name": "tsig1"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"still referenced" in r.data
        assert "apply-config" not in fake.ops()

    def test_post_routes_require_admin(self, client, db, monkeypatch):
        from tests.conftest import restricted_client

        fake = self._wire(monkeypatch)
        restricted_client(client, db, allowed_subnets=None, role="viewer", username="ddns_d2_viewer1")
        r = client.post(
            "/ddns/d2config/domain/add",
            data={"direction": "forward", "name": "example.com.", "servers": "10.0.0.53"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"Admin access required" in r.data
        assert "apply-config" not in fake.ops()


class TestDdnsVerifyTab:
    def test_no_input_shows_the_form_only(self, logged_in_client, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        r = logged_in_client.get("/ddns?tab=verify")
        assert r.status_code == 200
        assert b"Verify DNS" in r.data

    def test_invalid_hostname_shows_an_error(self, logged_in_client, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        r = logged_in_client.get("/ddns", query_string={"tab": "verify", "hostname": "not valid host!"})
        assert r.status_code == 200
        assert b"Invalid hostname" in r.data

    def test_forward_and_reverse_match(self, logged_in_client, mock_kea, monkeypatch):
        import socket

        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: [(None, None, None, None, ("10.0.0.50", 0))])
        monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("host.example.com", [], [ip]))
        r = logged_in_client.get(
            "/ddns", query_string={"tab": "verify", "hostname": "host.example.com", "ip": "10.0.0.50"}
        )
        assert r.status_code == 200
        body = r.data.decode()
        assert "10.0.0.50" in body
        assert "host.example.com" in body
        assert body.count("✓ Yes") == 2  # forward matches given IP, reverse matches given hostname

    def test_forward_lookup_failure_is_shown(self, logged_in_client, mock_kea, monkeypatch):
        import socket

        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")

        def raise_gaierror(host, port):
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", raise_gaierror)
        r = logged_in_client.get("/ddns", query_string={"tab": "verify", "hostname": "nope.example.com"})
        assert r.status_code == 200
        assert b"Name or service not known" in r.data


class TestDdnsReconcileRoute:
    """v5.47.0 (Q48) — GET /ddns/reconcile: row-building (reservations
    then active leases, subnet-restricted), the cached
    dns_reconcile_last summary, CSV export, and the limit/verdict
    params. The verdict logic itself is jen.services.dns_reconcile's
    own job, thoroughly covered without a DB in
    tests/test_dns_reconcile.py — these tests mock the resolver (same
    socket.getaddrinfo/gethostbyaddr TestDdnsVerifyTab already mocks),
    not jen.services.dns_reconcile.reconcile."""

    def _clean(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE hostname LIKE 'q48-%'")
            cur.execute("DELETE FROM lease4 WHERE hostname LIKE 'q48-%'")
        db.commit()

    def _seed(self, db, subnet_id=1):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('AABBCCDDEE01'), 0, %s, INET_ATON('10.0.0.10'), 'q48-reserved')",
                (subnet_id,),
            )
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state, hostname) VALUES "
                "(INET_ATON('10.0.0.20'), UNHEX('AABBCCDDEE02'), %s, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0, 'q48-leased')",
                (subnet_id,),
            )
        db.commit()

    def _mock_matching_resolver(self, monkeypatch):
        """Every name resolves forward+reverse to exactly what's asked —
        every row scores "ok"."""
        import socket

        def getaddrinfo(host, port):
            ip = {"q48-reserved": "10.0.0.10", "q48-leased": "10.0.0.20"}.get(host, "0.0.0.0")
            return [(None, None, None, None, (ip, 0))]

        def gethostbyaddr(ip):
            name = {"10.0.0.10": "q48-reserved", "10.0.0.20": "q48-leased"}.get(ip, "unknown")
            return (name, [], [ip])

        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(socket, "gethostbyaddr", gethostbyaddr)

    def test_requires_admin(self, client, db, mock_kea):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=None, role="viewer", username="reconcile_viewer1")
        r = client.get("/ddns/reconcile", follow_redirects=True)
        assert r.status_code == 200
        assert b"Admin access required." in r.data

    def test_reservation_and_lease_rows_both_appear(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.0.0.0/24"}})
        self._clean(db)
        self._seed(db)
        self._mock_matching_resolver(monkeypatch)
        try:
            r = logged_in_client.get("/ddns/reconcile")
            assert r.status_code == 200
            body = r.data.decode()
            assert "q48-reserved" in body
            assert "q48-leased" in body
            # Not asserting an exact total — the shared test fixtures may
            # already carry other hosts/leases with a hostname on subnet
            # 1, and this test only needs to confirm its own two rows
            # made it into the page, not that it's the only data present.
        finally:
            self._clean(db)

    def test_all_matched_scores_ok(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.0.0.0/24"}})
        self._clean(db)
        self._seed(db)
        self._mock_matching_resolver(monkeypatch)
        try:
            # Filter to verdict=ok rather than asserting an exact "ok (N)"
            # count — other hosts/leases with a hostname on subnet 1 may
            # already exist from shared test fixtures and would inflate
            # N; both of THIS test's rows resolving correctly and landing
            # in the ok-filtered view is the actual thing under test.
            r = logged_in_client.get("/ddns/reconcile", query_string={"verdict": "ok"})
            assert r.status_code == 200
            body = r.data.decode()
            assert "q48-reserved" in body
            assert "q48-leased" in body
        finally:
            self._clean(db)

    def test_subnet_restriction_hides_other_subnets_rows(self, client, db, mock_kea, monkeypatch):
        from jen import extensions
        from tests.conftest import restricted_client

        monkeypatch.setattr(
            extensions,
            "SUBNET_MAP",
            {1: {"name": "LAN", "cidr": "10.0.0.0/24"}, 2: {"name": "IOT", "cidr": "10.0.1.0/24"}},
        )
        self._clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('AABBCCDDEE01'), 0, 1, INET_ATON('10.0.0.10'), 'q48-reserved')"
            )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('AABBCCDDEE03'), 0, 2, INET_ATON('10.0.1.10'), 'q48-other-subnet')"
            )
        db.commit()
        self._mock_matching_resolver(monkeypatch)
        restricted_client(client, db, allowed_subnets=[1], role="admin", username="reconcile_restricted1")
        try:
            r = client.get("/ddns/reconcile")
            assert r.status_code == 200
            body = r.data.decode()
            assert "q48-reserved" in body
            assert "q48-other-subnet" not in body
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM hosts WHERE hostname LIKE 'q48-%'")
            db.commit()

    def test_caches_summary_for_health_check(self, logged_in_client, db, mock_kea, monkeypatch):
        import json

        from jen import extensions
        from jen.models.user import get_global_setting

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.0.0.0/24"}})
        self._clean(db)
        self._seed(db)
        self._mock_matching_resolver(monkeypatch)
        try:
            r = logged_in_client.get("/ddns/reconcile")
            assert r.status_code == 200
            raw = get_global_setting("dns_reconcile_last", "")
            assert raw
            summary = json.loads(raw)
            # >= not == — other hosts/leases with a hostname on subnet 1
            # may already exist from shared test fixtures; this test only
            # needs to confirm its own two matching rows are counted in,
            # not that they're the only rows in the run.
            assert summary["total"] >= 2
            assert summary["verdicts"]["ok"] >= 2
            assert "ts" in summary
        finally:
            self._clean(db)

    def test_limit_is_clamped(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.0.0.0/24"}})
        self._clean(db)
        self._mock_matching_resolver(monkeypatch)
        r = logged_in_client.get("/ddns/reconcile", query_string={"limit": "99999"})
        assert r.status_code == 200
        assert b'value="1000"' in r.data
        r2 = logged_in_client.get("/ddns/reconcile", query_string={"limit": "0"})
        assert r2.status_code == 200
        assert b'value="1"' in r2.data

    def test_verdict_filter_narrows_results(self, logged_in_client, db, mock_kea, monkeypatch):
        import socket

        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.0.0.0/24"}})
        self._clean(db)
        self._seed(db)

        # q48-reserved matches, q48-leased doesn't resolve at all.
        def getaddrinfo(host, port):
            if host == "q48-reserved":
                return [(None, None, None, None, ("10.0.0.10", 0))]
            raise socket.gaierror("NXDOMAIN")

        def gethostbyaddr(ip):
            if ip == "10.0.0.10":
                return ("q48-reserved", [], [ip])
            raise OSError("no PTR")

        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(socket, "gethostbyaddr", gethostbyaddr)
        try:
            r = logged_in_client.get("/ddns/reconcile", query_string={"verdict": "missing-forward"})
            assert r.status_code == 200
            body = r.data.decode()
            assert "q48-leased" in body
            assert "q48-reserved" not in body
        finally:
            self._clean(db)

    def test_csv_export(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "10.0.0.0/24"}})
        self._clean(db)
        self._seed(db)
        self._mock_matching_resolver(monkeypatch)
        try:
            r = logged_in_client.get("/ddns/reconcile", query_string={"format": "csv"})
            assert r.status_code == 200
            assert r.mimetype == "text/csv"
            body = r.data.decode()
            assert "q48-reserved" in body
            assert "q48-leased" in body
            assert body.startswith("name,ip,source,expected_a,observed_a,expected_ptr,observed_ptr,verdict")
        finally:
            self._clean(db)


class TestDdnsReconcileBusy:
    """v5.49.0-beta.4 (Q55-D) - single-flight: an overlapping reconciliation
    does no work and gets the page with a notice (HTTP 200)."""

    def test_second_run_gets_the_notice_not_an_error(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen.services import dns_reconcile

        def busy(*a, **k):
            raise dns_reconcile.ReconcileBusy("running")

        monkeypatch.setattr(dns_reconcile, "reconcile", busy)
        r = logged_in_client.get("/ddns/reconcile")
        assert r.status_code == 200
        assert b"already running" in r.data


class TestReconcileHealthCacheIsFleetWide:
    """v5.49.0-beta.6 (Q56-2) - the cached Health summary is fleet-wide: only an
    unrestricted run writes it, and expired names are scoped like the rest."""

    SEEDED = json.dumps({"ts": "2026-09-20T00:00:00+00:00", "total": 4242, "verdicts": {"ok": 4242}})

    def _stub_verify(self, monkeypatch):
        from jen.routes import ddns

        monkeypatch.setattr(ddns, "_run_verify", lambda h, ip: {"forward_ips": [ip], "reverse_name": h})

    def test_a_scoped_run_does_not_overwrite_the_cache_and_says_so(self, client, db, mock_kea, monkeypatch):
        from jen import extensions
        from jen.models.user import get_global_setting, set_global_setting
        from tests.conftest import restricted_client

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "A", "cidr": "10.0.0.0/24"}})
        self._stub_verify(monkeypatch)
        set_global_setting("dns_reconcile_last", self.SEEDED)
        c, _ = restricted_client(client, db, allowed_subnets=[1], role="admin", username="recon_scoped1")
        r = c.get("/ddns/reconcile", query_string={"limit": 5})
        assert r.status_code == 200
        assert b"Not cached for the Health Center" in r.data
        assert get_global_setting("dns_reconcile_last", "") == self.SEEDED

    def test_an_unrestricted_run_still_writes_it(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen.models.user import get_global_setting, set_global_setting

        self._stub_verify(monkeypatch)
        set_global_setting("dns_reconcile_last", self.SEEDED)
        logged_in_client.get("/ddns/reconcile", query_string={"limit": 5})
        assert get_global_setting("dns_reconcile_last", "") != self.SEEDED

    def test_expired_names_are_scoped_to_the_callers_subnets(self, client, db, mock_kea, monkeypatch):
        from jen import extensions
        from jen.services import dns_reconcile
        from tests.conftest import restricted_client

        monkeypatch.setattr(
            extensions, "SUBNET_MAP", {1: {"name": "A", "cidr": "10.0.0.0/24"}, 2: {"name": "B", "cidr": "10.1.0.0/24"}}
        )
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hostname IN ('expired-a-host','expired-b-host')")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) VALUES "
                "(INET_ATON('10.0.0.201'), UNHEX('AABBCC000A01'), 3600, NOW(), 1, 2, 'expired-a-host'), "
                "(INET_ATON('10.1.0.201'), UNHEX('AABBCC000B01'), 3600, NOW(), 2, 2, 'expired-b-host')"
            )
        db.commit()
        seen = {}

        def capture(rows, resolve, **kw):
            seen["expired"] = kw.get("expired_names")
            return []

        monkeypatch.setattr(dns_reconcile, "reconcile", capture)
        try:
            c, _ = restricted_client(client, db, allowed_subnets=[1], role="admin", username="recon_scoped2")
            c.get("/ddns/reconcile")
            assert "expired-a-host" in seen["expired"] and "expired-b-host" not in seen["expired"]
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE hostname IN ('expired-a-host','expired-b-host')")
            db.commit()


class TestNoDefaultProviderAndTwoWriters:
    """v5.69.0-beta.7 (Q176): a fresh install is "Not configured", not "Provider (technitium)" tailing a log that does not exist; and a run_script hook loaded beside D2's
    updates is two writers - said on the Status tab, never silent, never a block."""

    HOOK = {"library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_run_script.so"}

    def _status(self, logged_in_client, monkeypatch, dhcp4, provider=None):
        from jen import extensions
        from jen.services import kea as kea_svc

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        test_cfg = __import__("configparser").ConfigParser()
        test_cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections() if s != "ddns"})
        if provider is not None:
            test_cfg["ddns"] = {"dns_provider": provider}
        monkeypatch.setattr(extensions, "cfg", test_cfg)

        def fake_command(cmd, service="dhcp4", arguments=None, server=None, timeout=10):
            if cmd == "config-get":
                return {"result": 0, "arguments": {"Dhcp4": dhcp4}}
            return {"result": 0, "arguments": {}, "text": "2.6.1"}

        monkeypatch.setattr(kea_svc, "kea_command", fake_command)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: extensions.KEA_SERVERS[0])
        r = logged_in_client.get("/ddns?tab=status")
        assert r.status_code == 200
        return r.data.decode()

    def test_the_mode_is_none_with_no_ddns_section_and_no_updates(self, monkeypatch):
        from jen import extensions
        from jen.routes import ddns as ddns_route

        test_cfg = __import__("configparser").ConfigParser()
        monkeypatch.setattr(extensions, "cfg", test_cfg)
        assert ddns_route._ddns_mode(False) == "none"

    def test_the_mode_follows_what_is_configured(self, monkeypatch):
        from jen import extensions
        from jen.routes import ddns as ddns_route

        for ddns_section, updates, expect in (
            ({}, True, "d2"),
            ({"dns_provider": "pihole"}, False, "provider"),
            ({"dns_provider": "pihole"}, True, "d2"),
            ({"dns_provider": "none"}, False, "none"),
            ({"mode": "both"}, False, "both"),
            ({"mode": "nonsense"}, False, "none"),
        ):
            test_cfg = __import__("configparser").ConfigParser()
            if ddns_section:
                test_cfg["ddns"] = ddns_section
            monkeypatch.setattr(extensions, "cfg", test_cfg)
            assert ddns_route._ddns_mode(updates) == expect, (ddns_section, updates)

    def test_the_status_tab_says_not_configured_and_points_at_the_section(self, logged_in_client, monkeypatch):
        body = self._status(logged_in_client, monkeypatch, {})
        assert "Not configured" in body and "/settings/kea#kea-ddns" in body
        assert "Provider (technitium)" not in body

    def test_the_hook_with_updates_on_is_two_writers(self, logged_in_client, monkeypatch):
        body = self._status(
            logged_in_client, monkeypatch, {"dhcp-ddns": {"enable-updates": True}, "hooks-libraries": [self.HOOK]}
        )
        assert "libdhcp_run_script.so loaded" in body and "two writers" in body

    def test_the_hook_with_updates_off_is_loaded_and_not_two_writers(self, logged_in_client, monkeypatch):
        body = self._status(
            logged_in_client, monkeypatch, {"dhcp-ddns": {"enable-updates": False}, "hooks-libraries": [self.HOOK]}
        )
        assert "libdhcp_run_script.so loaded" in body and "two writers" not in body

    def test_no_hook_says_not_loaded_and_no_warning(self, logged_in_client, monkeypatch):
        body = self._status(logged_in_client, monkeypatch, {"dhcp-ddns": {"enable-updates": True}})
        assert "libdhcp_run_script.so not loaded" in body and "two writers" not in body

    def test_no_technitium_default_anywhere_under_jen_or_legacy(self):
        import pathlib

        offenders = []
        for root in ("jen", "legacy"):
            for p in pathlib.Path(root).rglob("*.py"):
                text = p.read_text(encoding="utf-8", errors="ignore")
                if 'fallback="technitium"' in text or '"dns_provider", "technitium"' in text:
                    offenders.append(p.as_posix())
        assert offenders == [], offenders


class TestTheNamingTabWarnsOfTwoWriters:
    """The Naming tab (Q176): a loaded run_script hook makes turning updates on a two-writers change. The form asks first (data-confirm); the saved result says it again."""

    HOOK = {"library": "/usr/lib/kea/hooks/libdhcp_run_script.so"}

    def _wire(self, monkeypatch, dhcp4):
        return TestDdnsNamingTab()._wire(monkeypatch, dhcp4)

    @staticmethod
    def _flashes(client):
        """What the save queued for the next page (the page itself carries the banner, so a rendered body cannot tell the two apart)."""
        with client.session_transaction() as sess:
            return [(cat, msg) for cat, msg in sess.get("_flashes", [])]

    def test_the_form_asks_first_when_a_hook_is_loaded_and_updates_are_off(self, logged_in_client, monkeypatch):
        self._wire(monkeypatch, {"dhcp-ddns": {"enable-updates": False}, "hooks-libraries": [self.HOOK]})
        body = logged_in_client.get("/ddns?tab=naming").data.decode()
        assert 'data-confirm="' in body and "two writers" in body and "libdhcp_run_script.so" in body

    def test_the_form_does_not_ask_with_no_hook(self, logged_in_client, monkeypatch):
        self._wire(monkeypatch, {"dhcp-ddns": {"enable-updates": False}})
        body = logged_in_client.get("/ddns?tab=naming").data.decode()
        form = body.split("DDNS Naming", 1)[1].split("Save DDNS Naming")[0]
        assert "two writers" not in body and "data-confirm" not in form

    def test_the_saved_result_flashes_the_warning_when_updates_went_on_beside_a_hook(
        self, logged_in_client, monkeypatch
    ):
        fake = self._wire(monkeypatch, {"dhcp-ddns": {"enable-updates": False}, "hooks-libraries": [self.HOOK]})
        logged_in_client.post("/ddns/naming/save", data={"enable-updates": "1"})
        assert "apply-config" in fake.ops(), "the save is not blocked"
        flashed = self._flashes(logged_in_client)
        assert any(cat == "warning" and "two writers" in msg and "turn one off" in msg for cat, msg in flashed), flashed

    def test_no_warning_when_the_save_leaves_updates_off(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch, {"dhcp-ddns": {"enable-updates": False}, "hooks-libraries": [self.HOOK]})
        logged_in_client.post("/ddns/naming/save", data={"ddns-generated-prefix": "x"})
        assert "apply-config" in fake.ops()
        assert not any("two writers" in msg for _cat, msg in self._flashes(logged_in_client))

    def test_no_warning_without_a_hook(self, logged_in_client, monkeypatch):
        fake = self._wire(monkeypatch, {"dhcp-ddns": {"enable-updates": False}})
        logged_in_client.post("/ddns/naming/save", data={"enable-updates": "1"})
        assert "apply-config" in fake.ops()
        assert not any("two writers" in msg for _cat, msg in self._flashes(logged_in_client))


class TestSecondPassFixes:
    """Q176's adversarial pass: a failed config-get is not "Not configured"; an upgrade keeps the lookups it had; the muted log row; the Naming pre-save read records no history."""

    def test_a_config_get_that_failed_is_unknown_not_not_configured(self, monkeypatch):
        from jen import extensions
        from jen.routes import ddns as ddns_route

        monkeypatch.setattr(extensions, "cfg", __import__("configparser").ConfigParser())
        assert ddns_route._ddns_mode(None) == "unknown"
        assert ddns_route._ddns_mode(False) == "none"
        assert ddns_route._ddns_mode(True) == "d2"
        test_cfg = __import__("configparser").ConfigParser()
        test_cfg["ddns"] = {"dns_provider": "pihole"}
        monkeypatch.setattr(extensions, "cfg", test_cfg)
        assert ddns_route._ddns_mode(None) == "provider", "a configured provider is still known"

    def test_the_status_tab_says_unknown_when_kea_does_not_answer(self, logged_in_client, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
        test_cfg = __import__("configparser").ConfigParser()
        monkeypatch.setattr(extensions, "cfg", test_cfg)
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **k: {"result": 1, "text": "down"})
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: extensions.KEA_SERVERS[0])
        body = logged_in_client.get("/ddns?tab=status").data.decode()
        assert "could not be read" in body and "Not configured" not in body

    def test_an_upgraded_config_with_a_url_and_no_provider_key_still_looks_names_up(self, monkeypatch):
        from jen import extensions
        from jen.routes import ddns as ddns_route

        test_cfg = __import__("configparser").ConfigParser()
        test_cfg["ddns"] = {"api_url": "http://dns:5380", "api_token": "t"}
        monkeypatch.setattr(extensions, "cfg", test_cfg)
        assert ddns_route._ddns_mode(False) == "provider"

    def test_the_status_tab_mutes_a_missing_log_when_nothing_is_configured(self, logged_in_client, monkeypatch):
        from jen import extensions
        from jen.services import kea as kea_svc
        from jen.services import kea_host

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(extensions, "cfg", __import__("configparser").ConfigParser())
        monkeypatch.setattr(kea_host, "tail_log", lambda *a, **k: {"ok": False, "code": "missing"})
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **k: {"result": 0, "arguments": {"Dhcp4": {}}})
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: extensions.KEA_SERVERS[0])
        body = logged_in_client.get("/ddns?tab=status").data.decode()
        assert "Not configured" in body and "no DDNS log is configured" in body and "File not found" not in body

    def test_the_naming_save_reads_the_hook_for_a_value_and_records_no_history(self):
        import inspect

        from jen.routes import ddns as ddns_route

        src = inspect.getsource(ddns_route.ddns_naming_save)
        assert "capture=False" in src and "timeout=" in src


class TestACredentialBelongsToItsProvider:
    """v5.69.0-beta.8 (Q177, DNS-CRED-001): a token typed for Technitium was kept when the provider became Pi-hole with a blank password, stored as the Pi-hole password, and POSTed to
    the Pi-hole URL. A stored credential is kept only for the provider it was typed for; the form shows only the saved provider's endpoint; a lookup never sends an empty one."""

    @pytest.fixture
    def cfg(self, monkeypatch):
        import configparser

        import jen.config as config
        from jen import extensions

        parser = configparser.ConfigParser()
        parser.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections() if s != "ddns"})
        monkeypatch.setattr(extensions, "cfg", parser)
        monkeypatch.setattr(type(config.app_config), "mutate", lambda self, fn, reload=True: fn(parser))

        class Handle:
            def write(self, values):
                if parser.has_section("ddns"):
                    parser.remove_section("ddns")
                parser["ddns"] = dict(values)

            def get(self, key):
                return parser.get("ddns", key, fallback=None)

        handle = Handle()
        handle.write({})
        return handle

    @pytest.mark.parametrize(
        "before,after,token,expect",
        [
            ("technitium", "pihole", "", None),
            ("technitium", "adguard", "", None),
            ("pihole", "technitium", "", None),
            ("adguard", "pihole", "", None),
            ("technitium", "none", "", None),
            ("technitium", "ssh", "", None),
            ("none", "pihole", "", None),
            ("pihole", "pihole", "", "OLD"),
            ("technitium", "pihole", "NEW", "NEW"),
        ],
    )
    def test_a_switch_never_carries_the_old_token(self, logged_in_client, cfg, before, after, token, expect):
        cfg.write({"dns_provider": before, "api_url": "http://old.local", "api_token": "OLD"})
        # (Q178 adjustment: the same-provider row used to post a different URL as well and expect the token kept; a changed endpoint is a changed place - CRED-002 -
        # so that row now posts the URL it was saved with, and TestADifferentEndpointIsNotTheSameProvider holds the changed-URL cases)
        url = "http://old.local" if before == after else "http://next.local"
        logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={"dns_provider": after, f"api_url_{after}": url, f"api_token_{after}": token},
        )
        assert cfg.get("api_token") == expect

    def test_an_upgraded_file_with_a_token_and_no_provider_key_is_technitiums(self, logged_in_client, cfg):
        cfg.write(
            {"api_url": "http://old.local", "api_token": "OLD"}
        )  # no dns_provider: the years when absent meant technitium
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": "pihole", "api_url_pihole": "http://p"}
        )
        assert cfg.get("api_token") is None
        cfg.write({"api_url": "http://old.local", "api_token": "OLD"})
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": "technitium", "api_url_technitium": "http://t"}
        )
        assert cfg.get("api_token") == "OLD", "the provider it was typed for keeps it"

    def test_the_checkbox_removes_it_for_the_same_provider(self, logged_in_client, cfg):
        cfg.write({"dns_provider": "pihole", "api_url": "http://old.local", "api_token": "OLD"})
        logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={"dns_provider": "pihole", "api_url_pihole": "http://old.local", "clear_api_token": "1"},
        )
        assert cfg.get("api_token") is None

    def test_a_switch_without_a_token_warns(self, logged_in_client, cfg):
        cfg.write({"dns_provider": "technitium", "api_url": "http://old.local", "api_token": "OLD"})
        r = logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={"dns_provider": "pihole", "api_url_pihole": "http://p"},
            follow_redirects=True,
        )
        assert b"enter its token or password" in r.data and b"was not carried over" in r.data

    @pytest.mark.parametrize(
        "data", [{"dns_provider": "pihole", "api_token_pihole": "T"}, {"dns_provider": "none"}, {"dns_provider": "ssh"}]
    )
    def test_no_warning_when_a_token_was_typed_or_the_provider_has_none(self, logged_in_client, cfg, data):
        cfg.write({"dns_provider": "technitium", "api_token": "OLD"})
        r = logged_in_client.post("/settings/infrastructure/save-ddns", data=data, follow_redirects=True)
        assert b"was not carried over" not in r.data

    def test_the_lookup_never_sends_an_empty_or_foreign_credential(self, monkeypatch, cfg):
        import requests

        from jen.routes import ddns as ddns_route

        calls = []
        monkeypatch.setattr(requests, "post", lambda *a, **k: calls.append(("post", a, k)) or pytest.fail("sent"))
        monkeypatch.setattr(requests, "get", lambda *a, **k: calls.append(("get", a, k)) or pytest.fail("sent"))
        cfg.write({"dns_provider": "pihole", "api_url": "http://pi.hole"})  # no token
        assert "not configured" in ddns_route._provider_lookup("host.example").lower()
        cfg.write({"dns_provider": "adguard", "api_url": "http://ag.local", "api_user": "admin"})
        assert "not configured" in ddns_route._provider_lookup("host.example").lower()
        cfg.write({"dns_provider": "technitium", "api_url": "http://t.local"})
        assert "not configured" in ddns_route._provider_lookup("host.example").lower()
        assert calls == []

    def test_the_form_prefills_only_the_saved_providers_block(self, logged_in_client, mock_kea, cfg):
        cfg.write({"dns_provider": "technitium", "api_url": "http://tech.local", "api_token": "T"})
        body = logged_in_client.get("/settings/kea").get_data(as_text=True)
        assert 'name="api_url_technitium" value="http://tech.local"' in body
        assert 'name="api_url_pihole" value=""' in body and 'name="api_url_adguard" value=""' in body
        assert 'name="api_user_adguard" value=""' in body
        card = body[body.index('id="kea-dns-provider"') :]
        card = card[: card.index("Save DDNS")]
        assert card.count("(unchanged)") == 1 and card.count("(not set)") == 2
        assert 'value="T"' not in card, "the token itself is never printed"

    def test_a_fresh_install_shows_not_set_everywhere(self, logged_in_client, mock_kea, cfg):
        body = logged_in_client.get("/settings/kea").get_data(as_text=True)
        card = body[body.index('id="kea-dns-provider"') :]
        card = card[: card.index("Save DDNS")]
        assert "(unchanged)" not in card and card.count("(not set)") == 3


class TestTheModeSaysWhatItKnows:
    """v5.69.0-beta.8 (Q177, DDNS-STATUS-001): an explicit `mode = none` is honoured (it was documented and ignored), and a loaded run_script hook is a mode of its own -
    `hook` - beside D2 and the provider, which stay separate facts. A failed read is `unknown`, never "Not configured"."""

    @pytest.mark.parametrize(
        "explicit,updates,hook,provider,expect",
        [
            ("", False, False, "none", "none"),
            ("", True, False, "none", "d2"),
            ("", False, True, "none", "hook"),
            ("", True, True, "none", "d2"),
            ("", False, False, "pihole", "provider"),
            ("", False, True, "pihole", "hook"),
            ("none", False, False, "pihole", "none"),
            ("d2", False, False, "none", "d2"),
            ("provider", True, False, "none", "provider"),
            ("both", False, False, "none", "both"),
            ("hook", False, False, "pihole", "hook"),
            ("", None, None, "none", "unknown"),
            ("", None, None, "pihole", "provider"),
            ("nonsense", False, False, "none", "none"),
        ],
    )
    def test_the_derivation(self, monkeypatch, explicit, updates, hook, provider, expect):
        import configparser

        from jen import extensions
        from jen.routes import ddns as ddns_route

        parser = configparser.ConfigParser()
        parser["ddns"] = {k: v for k, v in (("mode", explicit), ("dns_provider", provider)) if v}
        monkeypatch.setattr(extensions, "cfg", parser)
        assert ddns_route._ddns_mode(updates, hook) == expect

    def test_the_status_body_for_a_hook_says_outside_jens_view_and_not_not_configured(
        self, logged_in_client, monkeypatch
    ):
        body = TestNoDefaultProviderAndTwoWriters()._status(
            logged_in_client,
            monkeypatch,
            {"dhcp-ddns": {"enable-updates": False}, "hooks-libraries": [{"library": "/x/libdhcp_run_script.so"}]},
        )
        assert "outside Jen's view" in body and "Not configured" not in body
        assert "libdhcp_run_script.so loaded" in body, "the lease-hook row is its own fact"

    def test_the_guide_lists_the_five_explicit_values(self):
        import pathlib

        text = pathlib.Path("docs/admin-guide.md").read_text(encoding="utf-8")
        para = text[text.index("`[ddns] mode` picks") :].split("\n", 1)[0]
        for value in ("`provider`", "`d2`", "`both`", "`none`", "`hook`"):
            assert value in para
        assert "display-only" in para and "unknown" in para


class TestACredentialSecondPass:
    """Q177's adversarial pass: a token is never stored for a provider that has no credential field; the switch warning says what is true; the audit line says what happened to the token."""

    @pytest.fixture
    def cfg(self, monkeypatch):
        return self._build(monkeypatch)

    @staticmethod
    def _build(monkeypatch):
        import configparser

        import jen.config as config
        from jen import extensions

        parser = configparser.ConfigParser()
        parser.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections() if s != "ddns"})
        monkeypatch.setattr(extensions, "cfg", parser)
        monkeypatch.setattr(type(config.app_config), "mutate", lambda self, fn, reload=True: fn(parser))

        class Handle:
            def write(self, values):
                if parser.has_section("ddns"):
                    parser.remove_section("ddns")
                parser["ddns"] = dict(values)

            def get(self, key):
                return parser.get("ddns", key, fallback=None)

        return Handle()

    @pytest.mark.parametrize("provider", ["none", "ssh", "generic"])
    def test_a_token_for_a_provider_with_no_credential_is_not_stored(self, logged_in_client, cfg, provider):
        cfg.write({"dns_provider": provider})
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": provider, "api_token": "CRAFTED"}
        )
        assert cfg.get("api_token") is None

    def test_a_switch_with_no_stored_token_still_asks_but_does_not_claim_one_was_dropped(self, logged_in_client, cfg):
        cfg.write({"dns_provider": "none"})
        r = logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={"dns_provider": "pihole", "api_url_pihole": "http://p"},
            follow_redirects=True,
        )
        assert b"enter its token or password" in r.data and b"was not carried over" not in r.data

    def test_the_audit_line_says_what_became_of_the_token(self, logged_in_client, cfg, db):
        cfg.write({"dns_provider": "technitium", "api_token": "OLD"})
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": "pihole", "api_url_pihole": "http://p"}
        )
        with db.cursor() as cur:
            cur.execute(
                "SELECT details FROM audit_log WHERE action='SAVE_INFRA' AND entity='ddns' ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
        assert row and "token=removed" in row["details"] and "OLD" not in row["details"]

    def test_the_lookup_message_says_what_is_missing_and_never_sends(self, monkeypatch, cfg):
        import requests

        from jen.routes import ddns as ddns_route

        monkeypatch.setattr(requests, "post", lambda *a, **k: pytest.fail("sent"))
        monkeypatch.setattr(requests, "get", lambda *a, **k: pytest.fail("sent"))
        cfg.write({"dns_provider": "pihole", "api_url": "http://pi.hole"})
        msg = ddns_route._provider_lookup("h.example")
        assert "password or API token" in msg and "empty credential is never sent" in msg


class TestADifferentEndpointIsNotTheSameProvider:
    """v5.69.0-beta.9 (Q178, CRED-002): beta.8 compared providers only, so Technitium at A -> Technitium at B with a blank token kept A's token and the lookup sent it to B."""

    @pytest.fixture
    def cfg(self, monkeypatch):
        return TestACredentialSecondPass._build(monkeypatch)

    @pytest.mark.parametrize("provider", ["technitium", "pihole", "adguard"])
    def test_a_new_address_with_a_blank_token_removes_it_and_warns(self, logged_in_client, cfg, provider):
        cfg.write({"dns_provider": provider, "api_url": "http://a.example:5380", "api_token": "OLD"})
        r = logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={"dns_provider": provider, f"api_url_{provider}": "http://b.example:5380"},
            follow_redirects=True,
        )
        assert cfg.get("api_token") is None
        assert b"enter its token or password" in r.data and b"was not carried over" in r.data

    @pytest.mark.parametrize(
        "url", ["https://A.example:443/api", "https://a.example", "https://a.example/other/path?x=1"]
    )
    def test_the_same_address_spelled_differently_keeps_the_token(self, logged_in_client, cfg, url):
        cfg.write({"dns_provider": "technitium", "api_url": "https://a.example/api", "api_token": "OLD"})
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": "technitium", "api_url_technitium": url}
        )
        assert cfg.get("api_token") == "OLD"

    def test_a_new_address_with_a_typed_token_stores_only_the_new_one(self, logged_in_client, cfg):
        cfg.write({"dns_provider": "pihole", "api_url": "http://a.example", "api_token": "OLD"})
        logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={"dns_provider": "pihole", "api_url_pihole": "http://b.example", "api_token_pihole": "NEW"},
        )
        assert cfg.get("api_token") == "NEW"

    def test_a_blank_address_beside_a_blank_stored_one_is_not_a_change(self, logged_in_client, cfg):
        cfg.write({"dns_provider": "technitium", "api_token": "OLD"})
        logged_in_client.post("/settings/infrastructure/save-ddns", data={"dns_provider": "technitium"})
        assert cfg.get("api_token") == "OLD", "no address names no place a token could go"
