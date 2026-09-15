"""
tests/test_isc_dhcp_import_wizard.py
────────────────────────────────────
v5.37.0 (Q36) — /subnets/import-isc (upload) feeding the shared review →
preview → apply wizard at /subnets/import-isc/… . The parser/mapper is
covered in tests/test_isc_dhcp_import.py; this drives the fixture
dhcpd.conf (+ dhcpd.leases) through the routes with kea_host's helper
faked the way tests/test_win_dhcp_import_wizard.py does.
"""

import io

from tests.conftest import restricted_client as _restricted_client

_CONF_PATH = "tests/fixtures/dhcpd.conf"
_LEASES_PATH = "tests/fixtures/dhcpd.leases"
_SUBNETS = ["10.0.1.0", "10.0.2.0", "10.0.3.0", "10.0.4.0", "10.0.5.0", "192.168.99.0"]


def _bytes(path):
    with open(path, "rb") as f:
        return f.read()


class TestIscDhcpImportWizard:
    _EMPTY_DHCP4 = {"Dhcp4": {"subnet4": [], "client-classes": [], "shared-networks": []}}

    def _wire(self, monkeypatch, dhcp4=None):
        from jen import extensions
        from jen.services import kea as kea_svc
        from jen.services import kea_host
        from tests._kea_host_fakes import FakeHelper

        dhcp4 = dhcp4 if dhcp4 is not None else self._EMPTY_DHCP4
        monkeypatch.setattr(
            extensions, "KEA_SERVERS", [{"id": 1, "name": "Kea A", "ssh_host": "10.0.0.5", "ssh_user": "kea"}]
        )
        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        self._written = {}
        monkeypatch.setattr("jen.config.write_subnets_config", lambda m: self._written.update(m))
        self._reservation_calls = []

        def _fake_kea_command(command, *a, **kw):
            if command == "version-get":
                return {"result": 0, "arguments": {"extended": "3.0.0"}}
            if command == "reservation-add":
                self._reservation_calls.append(kw.get("arguments", {}).get("reservation"))
                return {"result": 0, "text": "added"}
            return {"result": 0, "arguments": dhcp4}

        monkeypatch.setattr(kea_svc, "kea_command", _fake_kea_command)
        monkeypatch.setattr(
            kea_svc,
            "get_active_kea_server",
            lambda: {"id": 1, "name": "Kea A", "api_url": "http://x", "api_user": "u", "api_pass": "p"},
        )
        fake = FakeHelper()
        fake.configs[(1, "dhcp4")] = dhcp4

        def _apply_resp(server, op, payload):
            fake.configs[(server.get("id"), payload.get("service"))] = payload.get("config")
            return {"ok": True, "backup": None}

        fake.responses["apply-config"] = _apply_resp
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        fake.responses["test-config"] = {"ok": True}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
        return fake

    def _upload(self, client, with_leases=False):
        data = {"conf_file": (io.BytesIO(_bytes(_CONF_PATH)), "dhcpd.conf")}
        if with_leases:
            data["leases_file"] = (io.BytesIO(_bytes(_LEASES_PATH)), "dhcpd.leases")
        return client.post("/subnets/import-isc", data=data, content_type="multipart/form-data")

    def _review_form(self, include=None, classes=True):
        form = {}
        for i, sid in enumerate(_SUBNETS):
            form[f"id_{sid}"] = str(50 + i)
            form[f"name_{sid}"] = f"net{i}"
        for sid in include if include is not None else _SUBNETS:
            form[f"include_{sid}"] = "1"
        form["server_options"] = "1"
        if classes:
            form["classes"] = "1"
        return form

    # ── access ──────────────────────────────────────────────────────────

    def test_requires_login(self, client):
        assert client.get("/subnets/import-isc", follow_redirects=False).status_code in (301, 302, 308)

    def test_non_superadmin_redirected_with_flash(self, client, db, monkeypatch, mock_kea):
        c, _ = _restricted_client(client, db, allowed_subnets=None, role="admin", username="isc_import_admin1")
        r = c.get("/subnets/import-isc", follow_redirects=True)
        assert r.status_code == 200 and b"SuperAdmin access required." in r.data

    # ── upload + review ─────────────────────────────────────────────────

    def test_upload_page_and_subnets_entry_link(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets/import-isc")
        assert r.status_code == 200 and b"Import from ISC DHCP" in r.data and b'name="leases_file"' in r.data
        assert b"/subnets/import-isc" in logged_in_client.get("/subnets").data

    def test_upload_parses_and_review_lists_subnets_and_line_numbered_warnings(
        self, logged_in_client, monkeypatch, mock_kea
    ):
        self._wire(monkeypatch)
        r = self._upload(logged_in_client)
        assert r.status_code == 302 and r.headers["Location"].endswith("/subnets/import-isc/review")
        r2 = logged_in_client.get("/subnets/import-isc/review")
        body = r2.data.decode()
        assert r2.status_code == 200
        assert "Office LAN" in body and "Students" in body and "192.168.99.0/24" in body
        assert "warning(s) from the dhcpd.conf" in body and "line 22" in body and "include" in body
        assert "<th>Subnet</th>" in body and "Shared network" in body and "CAMPUS" in body
        assert "dhcpd.leases" not in body.split("Review Import", 1)[1].split("<form", 1)[0]
        assert 'name="classes"' in body and "the_boss_laptop" in body
        assert 'name="server_options" value="1" checked' in body

    def test_leases_file_is_counted_never_imported(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        self._upload(logged_in_client, with_leases=True)
        body = logged_in_client.get("/subnets/import-isc/review").data.decode()
        assert "<strong>4</strong> active lease(s)" in body and "<strong>2</strong> inside" in body
        assert "<strong>1</strong> on an address that becomes a reservation" in body
        assert "never imported" in body

    def test_upload_without_subnets_flashes(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/import-isc",
            data={"conf_file": (io.BytesIO(b"option domain-name 'x';\n"), "dhcpd.conf")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200 and b"is it really a dhcpd.conf" in r.data

    def test_upload_rejects_oversized_file(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/import-isc",
            data={"conf_file": (io.BytesIO(b"#" + b"a" * (5 * 1024 * 1024 + 1)), "dhcpd.conf")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200 and b"5 MB" in r.data

    def test_review_without_token_names_the_right_file(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets/import-isc/review", follow_redirects=True)
        assert r.status_code == 200 and b"upload the dhcpd.conf again" in r.data

    # ── preview + apply ─────────────────────────────────────────────────

    def test_preview_runs_test_config_and_words_the_report_for_subnets(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        self._upload(logged_in_client)
        r = logged_in_client.post("/subnets/import-isc/preview", data=self._review_form())
        body = r.data.decode()
        assert r.status_code == 200
        assert "Kea accepted this config" in body and "10.0.1.0/24" in body
        assert "subnet Office LAN: mapped to subnet 50" in body and "scope Office LAN" not in body
        assert "test-config" in fake.ops()
        assert "/subnets/import-isc/apply" in body

    def test_apply_writes_config_classes_guards_and_reservations(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        self._upload(logged_in_client)
        logged_in_client.post("/subnets/import-isc/preview", data=self._review_form())
        r = logged_in_client.post("/subnets/import-isc/apply", follow_redirects=True)
        assert r.status_code == 200 and b"Kea restarted" in r.data

        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]
        office = next(s for s in applied["subnet4"] if s["subnet"] == "10.0.1.0/24")
        assert office["id"] == 50 and office["next-server"] == "10.0.0.5"
        guards = {p["pool"]: p.get("client-class") for p in office["pools"]}
        assert guards["10.0.1.210 - 10.0.1.219"] == "voip-phones"
        assert guards["10.0.1.220 - 10.0.1.229"] == "not_printers"
        classes = {c["name"] for c in applied["client-classes"]}
        assert {"pxe-clients", "printers", "not_printers", "the_boss_laptop"} <= classes
        assert applied["shared-networks"][0]["name"] == "CAMPUS"
        assert {o["code"] for o in applied["option-data"]} == {15, 6, 42, 119}
        assert "service" in fake.ops()
        assert sorted(r["ip-address"] for r in self._reservation_calls) == [
            "10.0.1.50",
            "10.0.1.51",
            "10.0.2.6",
            "10.0.4.10",
            "10.0.4.11",
        ]
        assert set(self._written) == {50, 51, 52, 53, 54, 55}
        assert self._written[50]["cidr"] == "10.0.1.0/24"

    def test_global_classes_can_be_left_out(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        self._upload(logged_in_client)
        logged_in_client.post(
            "/subnets/import-isc/preview", data=self._review_form(include=["10.0.5.0"], classes=False)
        )
        logged_in_client.post("/subnets/import-isc/apply", follow_redirects=True)
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]
        assert not applied.get("client-classes")
        assert [s["subnet"] for s in applied["subnet4"]] == ["10.0.5.0/24"]

    def test_windows_wizard_wording_is_unchanged(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets/import-windows/review", follow_redirects=True)
        assert b"upload the export again" in r.data
