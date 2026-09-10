class TestSaveSubnetNoteAccessControl:
    """v4.4.9: save_subnet_note() had no can_access_subnet() check at
    all, unlike every sibling route on this page (edit_subnet,
    edit_subnet_post, delete_subnet all check it) — a subnet-restricted
    admin could write/overwrite notes for any subnet_id."""

    def test_rejected_for_out_of_scope_subnet(self, client, db):
        from tests.conftest import restricted_client as _restricted_client

        _restricted_client(client, db, allowed_subnets=[999], role="admin", username="subnetnote_restricted1")
        r = client.post("/subnets/save-note", data={"subnet_id": "1", "notes": "should not be allowed"})
        assert r.status_code == 403
        data = r.get_json()
        assert data["ok"] is False
        assert "access" in data["error"].lower()

    def test_allowed_within_scope(self, logged_in_client):
        r = logged_in_client.post("/subnets/save-note", data={"subnet_id": "1", "notes": "allowed note"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True

    def test_rejects_non_integer_subnet_id(self, logged_in_client):
        r = logged_in_client.post("/subnets/save-note", data={"subnet_id": "not-a-number", "notes": "x"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is False


class TestParseAndValidateSubnetEditForm:
    """v4.4.24: extracted from edit_subnet_post() so the new preview
    endpoint can share the exact same validation rather than
    duplicating it and risking the two drifting apart — the same
    class of bug already found and fixed for the plugin registry and
    the CSRF tokens."""

    def _form(self, **kwargs):
        class FakeForm(dict):
            def get(self, k, default=""):
                return dict.get(self, k, default)

        return FakeForm(kwargs)

    def test_valid_full_form_returns_no_error(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form

        fields, error = _parse_and_validate_subnet_edit_form(
            self._form(
                pool="10.0.0.10-10.0.0.200",
                valid_lifetime="3600",
                renew_timer="1800",
                rebind_timer="3150",
                routers="10.0.0.1",
                dns_servers="9.9.9.9, 1.1.1.1",
            )
        )
        assert error is None
        assert fields["new_pool"] == "10.0.0.10-10.0.0.200"

    def test_empty_form_is_valid_no_op(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form

        fields, error = _parse_and_validate_subnet_edit_form(self._form())
        assert error is None
        assert not any(fields.values())

    def test_bad_pool_format_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form

        fields, error = _parse_and_validate_subnet_edit_form(self._form(pool="not-a-pool"))
        assert fields is None
        assert "Invalid pool format" in error

    def test_bad_router_ip_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form

        fields, error = _parse_and_validate_subnet_edit_form(self._form(routers="999.999.999.999"))
        assert fields is None
        assert "Invalid router IP" in error

    def test_bad_dns_ip_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form

        fields, error = _parse_and_validate_subnet_edit_form(self._form(dns_servers="not.an.ip"))
        assert fields is None
        assert "Invalid DNS server IP" in error

    def test_negative_timer_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form

        fields, error = _parse_and_validate_subnet_edit_form(self._form(valid_lifetime="-5"))
        assert fields is None
        assert "Valid Lifetime must be a positive integer" in error

    def test_zero_timer_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form

        fields, error = _parse_and_validate_subnet_edit_form(self._form(renew_timer="0"))
        assert fields is None
        assert "Renew Timer must be a positive integer" in error

    def test_non_numeric_timer_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form

        fields, error = _parse_and_validate_subnet_edit_form(self._form(rebind_timer="abc"))
        assert fields is None
        assert "Rebind Timer must be a positive integer" in error


# v5.11.0 — the config-mutation logic that used to live in
# _build_subnet_patch_script() (and its byte-for-byte test here) moved to
# jen/services/kea_config_edit.py; see tests/test_kea_config_edit.py.


class TestComputeSubnetEditDiff:
    def test_only_submitted_fields_appear_in_diff(self, monkeypatch):
        from jen.routes import subnets as subnets_mod

        monkeypatch.setattr(
            subnets_mod,
            "_get_subnet_kea_data",
            lambda sid: {
                "pool_str": "10.0.0.10-10.0.0.100",
                "pools": ["10.0.0.10-10.0.0.100"],
                "valid_lifetime": 3600,
                "renew_timer": 1800,
                "rebind_timer": 3150,
                "routers": "10.0.0.1",
                "dns_servers": "9.9.9.9",
            },
        )
        fields = {
            "new_pool": "10.0.0.10-10.0.0.250",
            "extra_pools": [],
            "new_lifetime": "",
            "new_renew": "",
            "new_rebind": "",
            "new_routers": "",
            "new_dns": "",
        }
        diff = subnets_mod._compute_subnet_edit_diff(1, fields)
        assert len(diff) == 1
        assert diff[0]["field"] == "Primary Pool"
        assert diff[0]["old"] == "10.0.0.10-10.0.0.100"
        assert diff[0]["new"] == "10.0.0.10-10.0.0.250"

    def test_unset_current_value_shows_placeholder(self, monkeypatch):
        from jen.routes import subnets as subnets_mod

        monkeypatch.setattr(
            subnets_mod,
            "_get_subnet_kea_data",
            lambda sid: {
                "pool_str": "",
                "pools": [],
                "valid_lifetime": "",
                "renew_timer": "",
                "rebind_timer": "",
                "routers": "",
                "dns_servers": "",
            },
        )
        fields = {
            "new_pool": "",
            "extra_pools": [],
            "new_lifetime": "",
            "new_renew": "",
            "new_rebind": "",
            "new_routers": "10.0.0.1",
            "new_dns": "",
        }
        diff = subnets_mod._compute_subnet_edit_diff(1, fields)
        assert diff[0]["field"] == "Routers"
        assert diff[0]["old"] == "(unset)"


class TestEditSubnetPreviewRoute:
    """Route-level tests using the real Flask test client. Paths that
    reach the per-server loop are covered with a FakeHelper (v5.11.0 —
    the preview reads the config via kea_host.read_config, patches it
    locally, and kea_host.test_config()s the candidate)."""

    def test_requires_login(self, client):
        r = client.post("/subnets/edit/1/preview", follow_redirects=False)
        assert r.status_code in (301, 302, 308)

    def test_nonexistent_subnet_returns_404(self, logged_in_client):
        r = logged_in_client.post("/subnets/edit/9999/preview")
        assert r.status_code == 404
        assert r.get_json()["ok"] is False

    def test_out_of_scope_subnet_returns_403(self, client, db):
        from tests.conftest import restricted_client as _restricted_client

        _restricted_client(client, db, allowed_subnets=[999], role="admin", username="preview_restricted1")
        r = client.post("/subnets/edit/1/preview")
        assert r.status_code == 403

    def test_invalid_form_returns_400_with_same_message_as_real_submit(self, logged_in_client):
        r = logged_in_client.post("/subnets/edit/1/preview", data={"pool": "garbage"})
        assert r.status_code == 400
        assert "Invalid pool format" in r.get_json()["error"]

    def test_empty_form_reports_no_changes_without_touching_ssh(self, logged_in_client, monkeypatch):
        from jen import extensions

        # If this reaches SSH code at all despite being a no-op, this
        # would raise instead of the route handling it gracefully.
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "ssh_host": "10.0.0.5", "ssh_user": "kea"}])
        r = logged_in_client.post("/subnets/edit/1/preview", data={})
        assert r.status_code == 200
        data = r.get_json()
        assert data["no_changes"] is True
        assert data["diff"] == []

    def test_server_with_no_ssh_host_is_skipped(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "ssh_host": ""}])
        monkeypatch.setattr("jen.routes.subnets._get_subnet_kea_data", lambda sid: {"pool_str": "", "pools": []})
        r = logged_in_client.post("/subnets/edit/1/preview", data={"pool": "10.0.0.10-10.0.0.200"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["servers"] == []
        assert data["all_passed"] is True

    def _one_server(self, monkeypatch):
        from jen import extensions
        from jen.services import kea_host

        monkeypatch.setattr(
            extensions, "KEA_SERVERS", [{"id": 1, "name": "Test Kea", "ssh_host": "10.0.0.5", "ssh_user": "kea"}]
        )
        monkeypatch.setattr("jen.routes.subnets._get_subnet_kea_data", lambda sid: {"pool_str": "", "pools": []})
        from tests._kea_host_fakes import FakeHelper

        fake = FakeHelper()
        fake.configs[(1, "dhcp4")] = {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}]}}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
        return fake

    def test_helper_test_pass_reports_ok(self, logged_in_client, monkeypatch):
        fake = self._one_server(monkeypatch)
        fake.responses["test-config"] = {"ok": True}
        r = logged_in_client.post("/subnets/edit/1/preview", data={"pool": "10.0.0.10-10.0.0.200"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["all_passed"] is True
        assert data["servers"][0]["ok"] is True
        assert data["servers"][0]["message"] == "Config test passed"
        assert "test-config" in fake.ops()

    def test_helper_test_fail_reports_error_and_all_passed_false(self, logged_in_client, monkeypatch):
        fake = self._one_server(monkeypatch)
        fake.responses["test-config"] = {"ok": False, "error": "testerror", "detail": "ERROR: bad pool range"}
        r = logged_in_client.post("/subnets/edit/1/preview", data={"pool": "10.0.0.10-10.0.0.200"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["all_passed"] is False
        assert data["servers"][0]["ok"] is False
        assert "bad pool range" in data["servers"][0]["message"]

    def test_preview_never_calls_edit_subnet_post_or_writes_audit_log(self, logged_in_client, monkeypatch, db):
        """The whole point of a preview — confirm it genuinely doesn't
        apply anything, by checking the audit log stays empty for this
        subnet after a preview call, the same signal edit_subnet_post
        itself writes to on a real apply."""
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [])  # no servers to even contact
        monkeypatch.setattr("jen.routes.subnets._get_subnet_kea_data", lambda sid: {"pool_str": "", "pools": []})

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM audit_log WHERE action='EDIT_SUBNET'")
            before = cur.fetchone()["cnt"]

        r = logged_in_client.post("/subnets/edit/1/preview", data={"pool": "10.0.0.10-10.0.0.200"})
        assert r.status_code == 200

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM audit_log WHERE action='EDIT_SUBNET'")
            after = cur.fetchone()["cnt"]
        assert after == before, (
            "preview must never write an EDIT_SUBNET audit entry — that's edit_subnet_post's job alone"
        )


class TestGetSubnetKeaData:
    """_get_subnet_kea_data() must return ALL of a subnet's pools, not just
    the first — this backs the Edit Subnet form and, until v4.3.8, a bug
    downstream of this function silently discarded every pool after the
    first whenever the edit form was submitted."""

    def test_returns_all_pools_for_multi_pool_subnet(self, monkeypatch):
        from jen.routes import subnets as subnets_mod
        from jen.services import kea as kea_svc

        fake_config = {
            "result": 0,
            "arguments": {
                "Dhcp4": {
                    "valid-lifetime": 3600,
                    "renew-timer": 900,
                    "rebind-timer": 1800,
                    "subnet4": [
                        {
                            "id": 1,
                            "subnet": "10.10.10.0/23",
                            "pools": [
                                {"pool": "10.10.10.50 - 10.10.10.250"},
                                {"pool": "10.10.11.50 - 10.10.11.250"},
                            ],
                            "option-data": [],
                        }
                    ],
                }
            },
        }
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: fake_config)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1})

        data = subnets_mod._get_subnet_kea_data(1)
        assert data["pools"] == ["10.10.10.50 - 10.10.10.250", "10.10.11.50 - 10.10.11.250"]
        # pool_str (used to prefill the single-line form field) is only the first
        assert data["pool_str"] == "10.10.10.50 - 10.10.10.250"

    def test_single_pool_subnet_unaffected(self, monkeypatch):
        from jen.routes import subnets as subnets_mod
        from jen.services import kea as kea_svc

        fake_config = {
            "result": 0,
            "arguments": {
                "Dhcp4": {
                    "subnet4": [{"id": 2, "pools": [{"pool": "10.10.30.10 - 10.10.30.200"}], "option-data": []}],
                }
            },
        }
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: fake_config)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1})

        data = subnets_mod._get_subnet_kea_data(2)
        assert data["pools"] == ["10.10.30.10 - 10.10.30.200"]
        assert data["pool_str"] == "10.10.30.10 - 10.10.30.200"


class TestEditSubnetExtraPoolsPreserved:
    """Regression test for the v4.3.8 fix: submitting the edit-subnet form on
    a subnet with 2+ Kea pools must not silently drop every pool after the
    first. The route reads a hidden 'extra_pools' field (pipe-delimited) and
    must fold those back into the pools written to kea-dhcp4.conf."""

    def test_extra_pools_form_field_parsed_correctly(self):
        # Mirrors the parsing line in edit_subnet_post()
        raw = "10.10.11.50 - 10.10.11.250|10.10.12.1 - 10.10.12.50"
        extra_pools = [p.strip() for p in raw.split("|") if p.strip()]
        assert extra_pools == ["10.10.11.50 - 10.10.11.250", "10.10.12.1 - 10.10.12.50"]

    def test_empty_extra_pools_field_parses_to_empty_list(self):
        raw = ""
        extra_pools = [p.strip() for p in raw.split("|") if p.strip()]
        assert extra_pools == []

    def test_pool_merge_expression_preserves_extra_pools(self):
        """kea_config_edit.patch_subnet4 builds s['pools'] as
        [primary] + [extra…]. Exercise that same expression here; the
        end-to-end coverage is in tests/test_kea_config_edit.py."""
        new_pool = "10.10.10.50 - 10.10.10.250"
        extra_pools = ["10.10.11.50 - 10.10.11.250"]
        pools = [{"pool": new_pool}] + [{"pool": p} for p in extra_pools]
        assert pools == [
            {"pool": "10.10.10.50 - 10.10.10.250"},
            {"pool": "10.10.11.50 - 10.10.11.250"},
        ]

    def test_no_extra_pools_leaves_single_pool_unchanged(self):
        new_pool = "10.10.30.10 - 10.10.30.200"
        extra_pools = []
        pools = [{"pool": new_pool}] + [{"pool": p} for p in extra_pools]
        assert pools == [{"pool": "10.10.30.10 - 10.10.30.200"}]


class TestSubnetApplyViaHostClient:
    """v5.11.0 — add / delete / edit_subnet_post push through
    jen.services.kea_host (helper op `apply-config` + `service restart`),
    with kea_config_edit doing the local mutation."""

    def _wire(self, monkeypatch, subnet4=None):
        from jen import extensions
        from jen.services import kea_host
        from tests._kea_host_fakes import FakeHelper

        monkeypatch.setattr(
            extensions, "KEA_SERVERS", [{"id": 1, "name": "Kea A", "ssh_host": "10.0.0.5", "ssh_user": "kea"}]
        )
        monkeypatch.setattr("jen.config.write_subnets_config", lambda m: None)
        fake = FakeHelper()
        fake.configs[(1, "dhcp4")] = {"Dhcp4": {"subnet4": subnet4 if subnet4 is not None else []}}
        fake.responses["apply-config"] = {"ok": True, "backup": None}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
        return fake

    def test_add_subnet_pushes_apply_and_restart(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        monkeypatch.setattr("jen.routes.subnets._get_kea_subnet_ids", lambda: set())
        r = logged_in_client.post(
            "/subnets/add",
            data={"subnet_id": "42", "name": "New", "cidr": "10.9.42.0/24", "pool": "10.9.42.10-10.9.42.200"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        ops = fake.ops()
        assert "apply-config" in ops and "service" in ops
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["subnet4"]
        assert [s["id"] for s in applied] == [42]
        assert fake.payload_for("service") == {"service": "dhcp4", "action": "restart"}

    def test_delete_subnet_removes_block_and_restarts(self, logged_in_client, monkeypatch, mock_kea, db):
        fake = self._wire(monkeypatch, subnet4=[{"id": 1, "subnet": "10.0.0.0/24"}])
        # delete_subnet refuses if the subnet still has active leases /
        # reservations — clear them so the push path is reached.
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id=1")
        db.commit()
        r = logged_in_client.post("/subnets/delete/1", follow_redirects=True)
        assert r.status_code == 200
        assert fake.payload_for("apply-config")["config"]["Dhcp4"]["subnet4"] == []
        assert "service" in fake.ops()

    def test_edit_subnet_post_no_change_does_not_apply(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch, subnet4=[{"id": 1, "subnet": "10.0.0.0/24"}])
        r = logged_in_client.post("/subnets/edit/1", data={}, follow_redirects=True)
        assert r.status_code == 200
        assert "apply-config" not in fake.ops()

    def test_edit_subnet_post_applies_the_patched_config(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch, subnet4=[{"id": 1, "subnet": "10.0.0.0/24"}])
        r = logged_in_client.post("/subnets/edit/1", data={"pool": "10.0.0.10-10.0.0.99"}, follow_redirects=True)
        assert r.status_code == 200
        s = fake.payload_for("apply-config")["config"]["Dhcp4"]["subnet4"][0]
        assert s["pools"] == [{"pool": "10.0.0.10-10.0.0.99"}]

    def test_legacy_fallback_flashes_a_warning(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch, subnet4=[{"id": 1}])
        fake.missing_for.add(1)  # helper not installed → legacy path

        # legacy read_config + apply + restart all go through _connect_ssh
        from tests._kea6_helpers import FakeSSHClient

        seq = [
            FakeSSHClient([('{"Dhcp4": {"subnet4": [{"id": 1}]}}', "")]),  # legacy `cat`
            FakeSSHClient([("ok", "")]),  # legacy apply
            FakeSSHClient([("done", "")]),  # legacy restart
        ]
        monkeypatch.setattr(
            "jen.services.kea6._connect_ssh", lambda s: seq.pop(0) if seq else FakeSSHClient([("", "")])
        )
        r = logged_in_client.post("/subnets/edit/1", data={"pool": "10.0.0.5-10.0.0.9"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"legacy root" in r.data


class TestSharedNetworks:
    """v5.15.0 — subnets inside Dhcp4.shared-networks are visible and
    editable; new routes create/delete networks and move subnets."""

    def _wire(self, monkeypatch, dhcp4):
        from jen import extensions
        from jen.services import kea as kea_svc
        from jen.services import kea_host
        from tests._kea_host_fakes import FakeHelper

        monkeypatch.setattr(
            extensions, "KEA_SERVERS", [{"id": 1, "name": "Kea A", "ssh_host": "10.0.0.5", "ssh_user": "kea"}]
        )
        # ssh_ready gate on the Subnets page: key file present + SSH host set
        monkeypatch.setattr(extensions, "SSH_KEY_PATH", __file__)
        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr("jen.config.write_subnets_config", lambda m: None)
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "arguments": dhcp4})
        monkeypatch.setattr(
            kea_svc,
            "get_active_kea_server",
            lambda: {"id": 1, "name": "Kea A", "api_url": "http://x", "api_user": "u", "api_pass": "p"},
        )
        fake = FakeHelper()
        fake.configs[(1, "dhcp4")] = {"Dhcp4": dhcp4["Dhcp4"]}
        fake.responses["apply-config"] = {"ok": True, "backup": None}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
        return fake

    _NESTED = {
        "Dhcp4": {
            "subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "pools": [{"pool": "10.0.0.10 - 10.0.0.99"}]}],
            "shared-networks": [
                {
                    "name": "guest",
                    "interface": "eth1",
                    "subnet4": [
                        {"id": 70, "subnet": "10.0.70.0/24", "pools": [{"pool": "10.0.70.10 - 10.0.70.99"}]},
                        {"id": 71, "subnet": "10.0.71.0/24"},
                    ],
                },
                {"name": "iot", "subnet4": []},
            ],
        }
    }

    def _seed_map(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(
            extensions,
            "SUBNET_MAP",
            {
                1: {"name": "LAN", "cidr": "10.0.0.0/24"},
                70: {"name": "Guest", "cidr": "10.0.70.0/24"},
                71: {"name": "Guest2", "cidr": "10.0.71.0/24"},
            },
        )

    def test_page_groups_nested_subnets_under_a_heading(self, logged_in_client, monkeypatch, mock_kea):
        self._seed_map(monkeypatch)
        self._wire(monkeypatch, self._NESTED)
        r = logged_in_client.get("/subnets")
        assert r.status_code == 200
        body = r.data.decode()
        assert "Shared network: guest" in body and "eth1" in body
        assert ">shared<" in body  # the chip
        assert "New shared network" in body

    def test_edit_a_nested_subnet_applies_the_change(self, logged_in_client, monkeypatch, mock_kea):
        self._seed_map(monkeypatch)
        fake = self._wire(monkeypatch, self._NESTED)
        r = logged_in_client.post("/subnets/edit/70", data={"pool": "10.0.70.5-10.0.70.250"}, follow_redirects=True)
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["shared-networks"][0]["subnet4"][0]
        assert applied["pools"] == [{"pool": "10.0.70.5-10.0.70.250"}]

    def test_add_subnet_into_a_shared_network(self, logged_in_client, monkeypatch, mock_kea):
        self._seed_map(monkeypatch)
        monkeypatch.setattr("jen.routes.subnets._get_kea_subnet_ids", lambda: set())
        fake = self._wire(monkeypatch, self._NESTED)
        r = logged_in_client.post(
            "/subnets/add",
            data={
                "subnet_id": "72",
                "name": "Cam",
                "cidr": "10.0.72.0/24",
                "pool": "10.0.72.10-10.0.72.99",
                "shared_network": "guest",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200
        guest = fake.payload_for("apply-config")["config"]["Dhcp4"]["shared-networks"][0]
        assert [s["id"] for s in guest["subnet4"]] == [70, 71, 72]

    def test_create_shared_network(self, logged_in_client, monkeypatch, mock_kea):
        self._seed_map(monkeypatch)
        fake = self._wire(monkeypatch, self._NESTED)
        r = logged_in_client.post(
            "/subnets/shared-networks/add", data={"name": "cameras", "interface": "eth2"}, follow_redirects=True
        )
        assert r.status_code == 200
        names = [n["name"] for n in fake.payload_for("apply-config")["config"]["Dhcp4"]["shared-networks"]]
        assert "cameras" in names

    def test_create_shared_network_rejects_bad_name(self, logged_in_client, monkeypatch, mock_kea):
        self._seed_map(monkeypatch)
        fake = self._wire(monkeypatch, self._NESTED)
        for bad in ("../etc", "has space", "semi;colon"):
            r = logged_in_client.post("/subnets/shared-networks/add", data={"name": bad}, follow_redirects=True)
            assert b"Invalid shared network name" in r.data
        assert "apply-config" not in fake.ops()

    def test_delete_non_empty_shared_network_refused(self, logged_in_client, monkeypatch, mock_kea):
        self._seed_map(monkeypatch)
        fake = self._wire(monkeypatch, self._NESTED)
        r = logged_in_client.post("/subnets/shared-networks/delete", data={"name": "guest"}, follow_redirects=True)
        assert b"still has subnets" in r.data
        assert "apply-config" not in fake.ops()

    def test_delete_empty_shared_network(self, logged_in_client, monkeypatch, mock_kea):
        self._seed_map(monkeypatch)
        fake = self._wire(monkeypatch, self._NESTED)
        r = logged_in_client.post("/subnets/shared-networks/delete", data={"name": "iot"}, follow_redirects=True)
        assert r.status_code == 200
        left = [n["name"] for n in fake.payload_for("apply-config")["config"]["Dhcp4"]["shared-networks"]]
        assert left == ["guest"]

    def test_move_subnet_into_a_network(self, logged_in_client, monkeypatch, mock_kea):
        self._seed_map(monkeypatch)
        fake = self._wire(monkeypatch, self._NESTED)
        r = logged_in_client.post("/subnets/move/1", data={"shared_network": "iot"}, follow_redirects=True)
        assert r.status_code == 200
        cfg = fake.payload_for("apply-config")["config"]["Dhcp4"]
        assert cfg.get("subnet4", []) == []
        assert [s["id"] for s in cfg["shared-networks"][1]["subnet4"]] == [1]

    def test_move_nochange_does_not_apply(self, logged_in_client, monkeypatch, mock_kea):
        self._seed_map(monkeypatch)
        fake = self._wire(monkeypatch, self._NESTED)
        r = logged_in_client.post("/subnets/move/1", data={"shared_network": ""}, follow_redirects=True)
        assert b"already there" in r.data
        assert "apply-config" not in fake.ops()

    def test_restricted_admin_cannot_move_a_subnet_they_do_not_own(self, client, db, monkeypatch, mock_kea):
        from tests.conftest import restricted_client as _rc

        self._seed_map(monkeypatch)
        fake = self._wire(monkeypatch, self._NESTED)
        _rc(client, db, allowed_subnets=[1], role="admin", username="sn_restricted")
        r = client.post("/subnets/move/70", data={"shared_network": "iot"}, follow_redirects=True)
        assert b"do not have access" in r.data
        assert "apply-config" not in fake.ops()

    def test_restricted_admin_cannot_delete_a_network(self, client, db, monkeypatch, mock_kea):
        from tests.conftest import restricted_client as _rc

        self._seed_map(monkeypatch)
        fake = self._wire(monkeypatch, self._NESTED)
        _rc(client, db, allowed_subnets=[1], role="admin", username="sn_restricted2")
        r = client.post("/subnets/shared-networks/delete", data={"name": "iot"}, follow_redirects=True)
        assert b"access to all subnets" in r.data
        assert "apply-config" not in fake.ops()

    def test_audit_rows_written(self, logged_in_client, monkeypatch, mock_kea, db):
        self._seed_map(monkeypatch)
        self._wire(monkeypatch, self._NESTED)
        logged_in_client.post("/subnets/shared-networks/add", data={"name": "aud1"}, follow_redirects=True)
        logged_in_client.post("/subnets/move/1", data={"shared_network": "iot"}, follow_redirects=True)
        with db.cursor() as cur:
            cur.execute("SELECT action FROM audit_log WHERE action IN ('ADD_SHARED_NETWORK','MOVE_SUBNET')")
            actions = {r["action"] for r in cur.fetchall()}
        assert {"ADD_SHARED_NETWORK", "MOVE_SUBNET"} <= actions
