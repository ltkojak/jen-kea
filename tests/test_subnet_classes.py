"""
tests/test_subnet_classes.py
─────────────────────────────
v5.19.0 (Q13) — the client-classes list/edit/preview/save/delete/reorder/
attach routes in jen/routes/subnets.py, exercising kea_classes.py and
kea_config_edit.py's class functions end-to-end through the routes.
"""

from tests.conftest import restricted_client as _restricted_client


class TestClientClassRoutes:
    _DHCP4 = {
        "Dhcp4": {
            "client-classes": [
                {
                    "name": "printers",
                    "test": "option[60].hex == 'PXEClient'",
                    "user-context": {
                        "jen": {
                            "builder": {
                                "rules": [{"field": "vendor_class", "op": "equals", "value": "PXEClient"}],
                                "combinator": "all",
                                "negate": False,
                            },
                            "v": 1,
                        }
                    },
                },
                {"name": "voip", "test": "option[60].hex == 'VoIP'"},
            ],
            "subnet4": [
                {
                    "id": 10,
                    "subnet": "10.0.10.0/24",
                    "pools": [{"pool": "10.0.10.10 - 10.0.10.99"}],
                    "client-classes": ["printers"],
                },
            ],
            "shared-networks": [
                {"name": "guest", "subnet4": [{"id": 70, "subnet": "10.0.70.0/24"}]},
            ],
        }
    }

    _SUBNET_MAP = {10: {"name": "LAN", "cidr": "10.0.10.0/24"}, 70: {"name": "Guest", "cidr": "10.0.70.0/24"}}

    def _wire(self, monkeypatch, dhcp4=None):
        from jen import extensions
        from jen.services import kea as kea_svc
        from jen.services import kea_host
        from tests._kea_host_fakes import FakeHelper

        dhcp4 = dhcp4 or self._DHCP4
        monkeypatch.setattr(
            extensions, "KEA_SERVERS", [{"id": 1, "name": "Kea A", "ssh_host": "10.0.0.5", "ssh_user": "kea"}]
        )
        monkeypatch.setattr(extensions, "SUBNET_MAP", dict(self._SUBNET_MAP))

        def _fake_kea_command(command, *a, **kw):
            if command == "version-get":
                return {"result": 0, "arguments": {"extended": "3.0.0"}}
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
        return fake

    # ── list ──────────────────────────────────────────────────────────

    def test_requires_login(self, client):
        r = client.get("/subnets/classes", follow_redirects=False)
        assert r.status_code in (301, 302, 308)

    def test_list_shows_classes_in_evaluation_order(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets/classes")
        assert r.status_code == 200
        body = r.data.decode()
        assert body.index("printers") < body.index("voip")

    def test_list_shows_guided_badge_for_matching_builder(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets/classes")
        assert b"guided" in r.data

    # ── new / preview / save (guided) ───────────────────────────────────

    def test_preview_guided_runs_test_config(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/classes/preview",
            data={
                "is_new": "1",
                "orig_name": "",
                "name": "voice",
                "mode": "guided",
                "combinator": "all",
                "rule_field": "vendor_class",
                "rule_op": "equals",
                "rule_value": "VoIP",
            },
        )
        assert r.status_code == 200
        assert b"option[60].hex ==" in r.data
        assert b"VoIP" in r.data
        assert "test-config" in fake.ops()

    def test_preview_failing_test_config_shows_error_and_does_not_apply(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        fake.responses["test-config"] = {"ok": False, "error": "testerror", "detail": "bad expression"}
        r = logged_in_client.post(
            "/subnets/classes/preview",
            data={"is_new": "1", "orig_name": "", "name": "voice", "mode": "advanced", "test": "garbage("},
        )
        assert r.status_code == 200
        assert b"bad expression" in r.data
        assert "apply-config" not in fake.ops()

    def test_preview_ssh_failure_shows_an_error_row_not_a_500(self, logged_in_client, monkeypatch, mock_kea):
        # v5.19.1 (14G) — an SSH/helper failure on a legacy-path host used
        # to raise straight out of the route, so the htmx target got a
        # bare 500 instead of an error message.
        from jen.services import kea_host

        self._wire(monkeypatch)

        def _raise(*_a, **_kw):
            raise RuntimeError("boom")

        monkeypatch.setattr(kea_host, "helper_call", _raise)
        r = logged_in_client.post(
            "/subnets/classes/preview",
            data={"is_new": "1", "orig_name": "", "name": "voice", "mode": "advanced", "test": "1 == 1"},
        )
        assert r.status_code == 200
        # Jinja escapes the apostrophe in "Couldn't" to &#39; — check the
        # unambiguous rest of the sentence instead of the literal text.
        assert b"validate against Kea A" in r.data
        assert b"see server logs" in r.data
        assert b"boom" not in r.data

    def test_save_new_guided_class_pushes_expression_and_user_context(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/classes/save",
            data={
                "is_new": "1",
                "orig_name": "",
                "name": "voice",
                "mode": "guided",
                "combinator": "all",
                "rule_field": "vendor_class",
                "rule_op": "equals",
                "rule_value": "VoIP",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["client-classes"]
        voice = next(c for c in applied if c["name"] == "voice")
        assert voice["test"] == "option[60].hex == 'VoIP'"
        assert voice["user-context"]["jen"]["builder"]["rules"][0]["value"] == "VoIP"

    def test_save_new_advanced_class(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/classes/save",
            data={"is_new": "1", "orig_name": "", "name": "manual", "mode": "advanced", "test": "member('printers')"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["client-classes"]
        manual = next(c for c in applied if c["name"] == "manual")
        assert manual["test"] == "member('printers')"
        assert "user-context" not in manual

    def test_save_only_additional_without_attachment_warns(self, logged_in_client, monkeypatch, mock_kea):
        # v5.19.1 (14F) — Q13's own pinned gotcha ("warn if
        # only-in-additional-list is ticked but the class isn't attached
        # as additional anywhere") was never implemented.
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/classes/save",
            data={
                "is_new": "0",
                "orig_name": "voip",
                "mode": "advanced",
                "test": "option[60].hex == 'VoIP'",
                "only_additional": "1",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"is not attached as an Additional class anywhere yet" in r.data
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["client-classes"]
        voip = next(c for c in applied if c["name"] == "voip")
        assert voip.get("only-in-additional-list") is True

    def test_save_only_additional_with_attachment_no_warning(self, logged_in_client, monkeypatch, mock_kea):
        import copy

        dhcp4 = copy.deepcopy(self._DHCP4)
        dhcp4["Dhcp4"]["subnet4"][0]["evaluate-additional-classes"] = ["voip"]
        self._wire(monkeypatch, dhcp4=dhcp4)
        r = logged_in_client.post(
            "/subnets/classes/save",
            data={
                "is_new": "0",
                "orig_name": "voip",
                "mode": "advanced",
                "test": "option[60].hex == 'VoIP'",
                "only_additional": "1",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"is not attached as an Additional class anywhere yet" not in r.data

    def test_edit_page_shows_only_additional_banner_when_unattached(self, logged_in_client, monkeypatch, mock_kea):
        import copy

        dhcp4 = copy.deepcopy(self._DHCP4)
        dhcp4["Dhcp4"]["client-classes"][1]["only-in-additional-list"] = True  # voip
        self._wire(monkeypatch, dhcp4=dhcp4)
        r = logged_in_client.get("/subnets/classes/edit?name=voip")
        assert r.status_code == 200
        assert b"is not attached as an Additional class anywhere yet" in r.data

    def test_edit_page_hides_banner_when_attached(self, logged_in_client, monkeypatch, mock_kea):
        import copy

        dhcp4 = copy.deepcopy(self._DHCP4)
        dhcp4["Dhcp4"]["client-classes"][1]["only-in-additional-list"] = True  # voip
        dhcp4["Dhcp4"]["subnet4"][0]["evaluate-additional-classes"] = ["voip"]
        self._wire(monkeypatch, dhcp4=dhcp4)
        r = logged_in_client.get("/subnets/classes/edit?name=voip")
        assert r.status_code == 200
        assert b"is not attached as an Additional class anywhere yet" not in r.data

    def test_save_rejects_builtin_name(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/classes/save",
            data={"is_new": "1", "orig_name": "", "name": "DROP", "mode": "advanced", "test": "1 == 1"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"built-in" in r.data.lower()
        assert "apply-config" not in fake.ops()

    def test_save_rejects_invalid_name(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/classes/save",
            data={"is_new": "1", "orig_name": "", "name": "1bad", "mode": "advanced", "test": "1 == 1"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"invalid class name" in r.data.lower()
        assert "apply-config" not in fake.ops()

    def test_editing_existing_class_keeps_name_fixed(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/classes/save",
            data={
                "is_new": "0",
                "orig_name": "voip",
                "name": "renamed-attempt",
                "mode": "advanced",
                "test": "option[60].hex == 'VoIP2'",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["client-classes"]
        names = [c["name"] for c in applied]
        assert "voip" in names
        assert "renamed-attempt" not in names
        assert next(c for c in applied if c["name"] == "voip")["test"] == "option[60].hex == 'VoIP2'"

    # ── delete ────────────────────────────────────────────────────────

    def test_delete_referenced_class_refused_with_reference_list(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post("/subnets/classes/delete", data={"name": "printers"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"still referenced by" in r.data
        assert b"subnet 10" in r.data
        assert "apply-config" not in fake.ops()

    def test_delete_unreferenced_class_ok(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post("/subnets/classes/delete", data={"name": "voip"}, follow_redirects=True)
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["client-classes"]
        assert all(c["name"] != "voip" for c in applied)

    # ── reorder ───────────────────────────────────────────────────────

    def test_reorder_moves_class_down(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/classes/reorder", data={"name": "printers", "direction": "down"}, follow_redirects=True
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["client-classes"]
        assert [c["name"] for c in applied] == ["voip", "printers"]

    # ── attach ────────────────────────────────────────────────────────

    def test_attach_to_nested_subnet_in_shared_network(self, logged_in_client, monkeypatch, mock_kea):
        dhcp4 = {
            "Dhcp4": {
                "client-classes": [{"name": "printers", "test": "1 == 1"}],
                "shared-networks": [
                    {"name": "guest", "subnet4": [{"id": 70, "subnet": "10.0.70.0/24"}]},
                ],
            }
        }
        fake = self._wire(monkeypatch, dhcp4=dhcp4)
        r = logged_in_client.post(
            "/subnets/classes/attach",
            data={"name": "printers", "scope_level": "subnet", "scope_key": "70", "mode": "guard", "attach": "1"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["shared-networks"][0]["subnet4"][0]
        assert applied["client-classes"] == ["printers"]

    # ── access control ────────────────────────────────────────────────

    def test_restricted_admin_forbidden(self, client, db, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        c, _ = _restricted_client(client, db, allowed_subnets=[10], role="admin", username="classes_restricted1")
        r = c.get("/subnets/classes", follow_redirects=True)
        assert r.status_code == 200
        assert b"access to all subnets" in r.data

    def test_viewer_forbidden(self, client, db, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        c, _ = _restricted_client(client, db, allowed_subnets=None, role="viewer", username="classes_viewer1")
        r = c.get("/subnets/classes", follow_redirects=True)
        assert b"admin access required" in r.data.lower()

    # ── subnet card (v5.19.0 step 3) ─────────────────────────────────────

    def test_subnet_card_shows_the_classes_line(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets")
        assert r.status_code == 200
        assert b"Classes: printers" in r.data
