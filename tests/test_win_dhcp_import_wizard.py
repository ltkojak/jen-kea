"""
tests/test_win_dhcp_import_wizard.py
─────────────────────────────────────
v5.24.0 (Q20) — the /subnets/import-windows/* wizard routes in
jen/routes/subnets.py: upload, review, preview, apply. win_dhcp_import.py's
own parser/mapper logic is exercised in tests/test_win_dhcp_import.py; this
file drives the same real fixture through the routes end-to-end (upload ->
review -> preview -> apply), with kea_host's helper faked the same way
tests/test_subnet_classes.py and tests/test_subnets.py already do.

Note: superadmin_required/admin_required REDIRECT (302 + flash), they never
return 403 — see tests/test_settings_blueprint.py's precedent. A
non-superadmin test here asserts the real redirect+flash, not a 403.
"""

import io

from tests.conftest import restricted_client as _restricted_client

_FIXTURE_PATH = "tests/fixtures/windows-dhcp-export.xml"
_BILLION_LAUGHS_PATH = "tests/fixtures/billion-laughs.xml"


def _fixture_bytes():
    with open(_FIXTURE_PATH, "rb") as f:
        return f.read()


class TestWinDhcpImportWizard:
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
        monkeypatch.setattr("jen.config.write_subnets_config", lambda m: self._written.update(m))

        reservation_calls = []

        def _fake_kea_command(command, *a, **kw):
            if command == "version-get":
                return {"result": 0, "arguments": {"extended": "3.0.0"}}
            if command == "config-get":
                return {"result": 0, "arguments": dhcp4}
            if command == "reservation-add":
                reservation_calls.append(kw.get("arguments", {}).get("reservation"))
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
        fake.responses["apply-config"] = {"ok": True, "backup": None}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        fake.responses["test-config"] = {"ok": True}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
        self._written = {}
        self._reservation_calls = reservation_calls
        return fake

    def _upload(self, client):
        return client.post(
            "/subnets/import-windows",
            data={"xml_file": (io.BytesIO(_fixture_bytes()), "export.xml")},
            content_type="multipart/form-data",
        )

    # ── access control ──────────────────────────────────────────────────

    def test_requires_login(self, client):
        r = client.get("/subnets/import-windows", follow_redirects=False)
        assert r.status_code in (301, 302, 308)

    def test_non_superadmin_redirected_with_flash(self, client, db, monkeypatch, mock_kea):
        c, _ = _restricted_client(client, db, allowed_subnets=None, role="admin", username="win_import_admin1")
        r = c.get("/subnets/import-windows", follow_redirects=True)
        assert r.status_code == 200
        assert b"SuperAdmin access required." in r.data

    # ── upload (step 1) ─────────────────────────────────────────────────

    def test_upload_parses_and_redirects_to_review(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = self._upload(logged_in_client)
        assert r.status_code == 302
        assert "/subnets/import-windows/review" in r.headers["Location"]

        r2 = logged_in_client.get("/subnets/import-windows/review")
        assert r2.status_code == 200
        assert b"LAN" in r2.data
        assert b"Guest WiFi" in r2.data
        assert b"Solo Subnet" in r2.data

    def test_upload_rejects_oversized_file(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        oversized = b"<DHCPServer></DHCPServer>" + b"a" * (5 * 1024 * 1024 + 1)
        r = logged_in_client.post(
            "/subnets/import-windows",
            data={"xml_file": (io.BytesIO(oversized), "export.xml")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"5 MB" in r.data

    def test_upload_billion_laughs_flashes_not_500(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        with open(_BILLION_LAUGHS_PATH, "rb") as f:
            data = f.read()
        r = logged_in_client.post(
            "/subnets/import-windows",
            data={"xml_file": (io.BytesIO(data), "export.xml")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"Could not parse" in r.data

    def test_review_without_token_redirects_to_upload(self, logged_in_client, monkeypatch, mock_kea):
        r = logged_in_client.get("/subnets/import-windows/review", follow_redirects=True)
        assert r.status_code == 200
        assert b"upload the export again" in r.data

    def test_token_expiry_sends_back_to_step_one(self, logged_in_client, monkeypatch, mock_kea):
        import time

        from jen.routes import subnets as subnets_mod

        self._wire(monkeypatch)
        self._upload(logged_in_client)
        for entry in subnets_mod._WIN_IMPORT_PLANS.values():
            entry["expires"] = time.time() - 1
        r = logged_in_client.get("/subnets/import-windows/review", follow_redirects=True)
        assert r.status_code == 200
        assert b"upload the export again" in r.data

    # ── preview (step 2) ────────────────────────────────────────────────

    def _review_form(self, include=("10.0.1.0", "10.0.3.0")):
        form = {"id_10.0.1.0": "50", "name_10.0.1.0": "LAN", "id_10.0.2.0": "51", "name_10.0.2.0": "Guest WiFi"}
        form.update({"id_10.0.3.0": "52", "name_10.0.3.0": "Solo Subnet"})
        for sid in include:
            form[f"include_{sid}"] = "1"
        return form

    def test_preview_runs_test_config_and_shows_diff(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        self._upload(logged_in_client)
        r = logged_in_client.post("/subnets/import-windows/preview", data=self._review_form())
        assert r.status_code == 200
        assert b"Kea accepted this config" in r.data
        assert b"10.0.1.0/24" in r.data or b"10.0.1.0" in r.data
        assert "test-config" in fake.ops()

    def test_preview_missing_id_flashes_and_returns_to_review(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        self._upload(logged_in_client)
        form = self._review_form()
        form["id_10.0.1.0"] = ""
        r = logged_in_client.post("/subnets/import-windows/preview", data=form, follow_redirects=True)
        assert r.status_code == 200
        assert b"valid whole-number subnet ID" in r.data

    def test_preview_duplicate_ids_flashes(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        self._upload(logged_in_client)
        form = self._review_form()
        form["id_10.0.3.0"] = form["id_10.0.1.0"]
        r = logged_in_client.post("/subnets/import-windows/preview", data=form, follow_redirects=True)
        assert r.status_code == 200
        assert b"same subnet ID" in r.data

    def test_existing_cidr_is_skipped_and_reported(self, logged_in_client, monkeypatch, mock_kea):
        dhcp4 = {
            "Dhcp4": {
                "subnet4": [{"id": 99, "subnet": "10.0.3.0/24", "pools": []}],
                "client-classes": [],
                "shared-networks": [],
            }
        }
        self._wire(monkeypatch, dhcp4=dhcp4)
        self._upload(logged_in_client)
        r = logged_in_client.post("/subnets/import-windows/preview", data=self._review_form())
        assert r.status_code == 200
        assert b"already" in r.data.lower() or b"skip" in r.data.lower()

    # ── apply (step 3) ──────────────────────────────────────────────────

    def test_apply_writes_config_and_reservations(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        self._upload(logged_in_client)
        logged_in_client.post("/subnets/import-windows/preview", data=self._review_form())
        r = logged_in_client.post("/subnets/import-windows/apply", follow_redirects=True)
        assert r.status_code == 200

        assert "apply-config" in fake.ops()
        applied_cfg = fake.payload_for("apply-config")["config"]
        applied_subnets = {s["subnet"] for s in applied_cfg["Dhcp4"]["subnet4"]}
        assert "10.0.1.0/24" in applied_subnets
        assert "10.0.3.0/24" in applied_subnets

        assert "service" in fake.ops()

        # LAN has 1 importable reservation (the "Both" and non-MAC rows are skipped)
        assert len(self._reservation_calls) == 1
        assert self._reservation_calls[0]["ip-address"] == "10.0.1.5"
        assert self._reservation_calls[0]["hw-address"] == "00:11:22:33:44:55"

        assert 50 in self._written or 52 in self._written

    def test_apply_without_preview_redirects_to_upload(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        self._upload(logged_in_client)
        r = logged_in_client.post("/subnets/import-windows/apply", follow_redirects=True)
        assert r.status_code == 200
        assert b"upload the export again" in r.data

    def test_apply_pushes_exactly_the_previewed_config(self, logged_in_client, monkeypatch, mock_kea):
        """v5.28.0 (Q24, C4) — apply must never re-run to_kea(); the
        applied payload has to be byte-identical to what preview already
        ran test_config() against."""
        fake = self._wire(monkeypatch)
        self._upload(logged_in_client)
        logged_in_client.post("/subnets/import-windows/preview", data=self._review_form())
        logged_in_client.post("/subnets/import-windows/apply", follow_redirects=True)
        assert fake.payload_for("test-config")["config"] == fake.payload_for("apply-config")["config"]

    def test_apply_refused_when_the_preview_config_test_failed(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        fake.responses["test-config"] = {"ok": False, "error": "testerror", "detail": "bad config"}
        self._upload(logged_in_client)
        logged_in_client.post("/subnets/import-windows/preview", data=self._review_form())
        r = logged_in_client.post("/subnets/import-windows/apply", follow_redirects=True)
        assert r.status_code == 200
        assert b"Preview the import" in r.data
        assert "apply-config" not in fake.ops()

    def test_apply_refused_when_the_config_changed_since_preview(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        self._upload(logged_in_client)
        logged_in_client.post("/subnets/import-windows/preview", data=self._review_form())
        # The live config moved underneath the preview (a different admin
        # edit, say) — apply must refuse rather than push a config that
        # was never actually tested against what's live now.
        fake.configs[(1, "dhcp4")] = {"Dhcp4": {**self._EMPTY_DHCP4["Dhcp4"], "valid-lifetime": 9999}}
        r = logged_in_client.post("/subnets/import-windows/apply", follow_redirects=True)
        assert r.status_code == 200
        assert b"changed since you previewed" in r.data
        assert "apply-config" not in fake.ops()

    def test_restart_failure_defers_reservations_until_the_retry_route(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        fake.responses["service"] = {"ok": False, "error": "systemctl failed", "detail": "unit not found"}
        self._upload(logged_in_client)
        logged_in_client.post("/subnets/import-windows/preview", data=self._review_form())
        r = logged_in_client.post("/subnets/import-windows/apply", follow_redirects=True)
        assert r.status_code == 200
        assert b"did not restart cleanly" in r.data
        assert self._reservation_calls == []  # deferred, not attempted against a stale-config Kea
        assert self._written == {}

        from jen.routes import subnets as subnets_mod

        assert any(subnets_mod._WIN_IMPORT_PLANS.values())  # the plan is kept, not popped

        r2 = logged_in_client.post("/subnets/import-windows/apply-reservations", follow_redirects=True)
        assert r2.status_code == 200
        assert len(self._reservation_calls) == 1
        assert 50 in self._written or 52 in self._written
        assert not subnets_mod._WIN_IMPORT_PLANS  # now finished and popped
