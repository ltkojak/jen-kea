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

from unittest.mock import MagicMock, patch


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
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")
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
