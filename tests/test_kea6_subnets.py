"""
tests/test_kea6_subnets.py
──────────────────────────
DHCPv6 subnet editing: the v6 Subnets view, reading subnet6 data from Kea, building the patch script, form validation, and the edit / edit-post / edit-preview routes.

Split out of the monolithic tests/test_kea6.py in v5.6.1.
"""

from jen import extensions


class TestSubnetsV6View:
    def test_no_v6_section_when_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        _invalidate_settings_cache()
        resp = logged_in_client.get("/subnets")
        assert resp.status_code == 200
        assert b"2001:db8::/64" not in resp.data

    def test_unpaired_v6_subnet_renders_standalone_card(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/subnets")
            assert resp.status_code == 200
            assert b"2001:db8::/64" in resp.data
            assert b"V6LAN" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_paired_v6_subnet_nests_under_v4_card(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "192.168.1.0/24"}})
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "LAN6", "cidr": "2001:db8:1::/64", "paired_subnet4_id": 1}}
        )
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/subnets")
            assert resp.status_code == 200
            assert b"2001:db8:1::/64" in resp.data
            body = resp.data.decode()
            # Paired block should appear once, nested — not as a second
            # top-level standalone card.
            assert body.count("2001:db8:1::/64") == 1
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_get_subnets6_data_empty_when_disabled(self, monkeypatch, db):
        import jen.routes.subnets as subnets_module

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        assert subnets_module._get_subnets6_data() == []

    def test_get_subnets6_data_counts_leases_and_reservations(self, monkeypatch, db):
        import jen.routes.subnets as subnets_module
        from jen.models.user import set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {7: {"name": "V6LAN", "cidr": "2001:db8:7::/64", "paired_subnet4_id": None}}
        )
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute(
                    """
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8:7::1', %s, 3600, '2026-08-15 00:00:00',
                        7, 1800, 0, 1, 128, '', NULL, 0)
                """,
                    (bytes.fromhex("00030001001a2b3c4d5e"),),
                )
            db.commit()
            data = subnets_module._get_subnets6_data()
            assert len(data) == 1
            assert data[0]["active"] == 1
        finally:
            set_global_setting("ipv6_enabled", "false")


class TestGetSubnet6KeaData:
    def test_extracts_pool_timers_and_dns(self, monkeypatch):
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(
            kea6_module,
            "kea6_command",
            lambda *a, **kw: {
                "result": 0,
                "arguments": {
                    "Dhcp6": {
                        "preferred-lifetime": 3000,
                        "valid-lifetime": 4000,
                        "renew-timer": 1000,
                        "rebind-timer": 2000,
                        "subnet6": [
                            {
                                "id": 1,
                                "pools": [{"pool": "2001:db8::10-2001:db8::20"}],
                                "option-data": [{"name": "dns-servers", "data": "2001:4860:4860::8888"}],
                            }
                        ],
                    }
                },
            },
        )
        data = kea6_module.get_subnet6_kea_data(1)
        assert data["pool_str"] == "2001:db8::10-2001:db8::20"
        assert data["preferred_lifetime"] == 3000
        assert data["valid_lifetime"] == 4000
        assert data["dns_servers"] == "2001:4860:4860::8888"

    def test_falls_back_to_global_timers_when_subnet_unset(self, monkeypatch):
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(
            kea6_module,
            "kea6_command",
            lambda *a, **kw: {
                "result": 0,
                "arguments": {
                    "Dhcp6": {
                        "preferred-lifetime": 3000,
                        "valid-lifetime": 4000,
                        "subnet6": [{"id": 1, "pools": []}],
                    }
                },
            },
        )
        data = kea6_module.get_subnet6_kea_data(1)
        assert data["preferred_lifetime"] == 3000
        assert data["valid_lifetime"] == 4000

    def test_returns_empty_shape_when_subnet_not_found(self, monkeypatch):
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(
            kea6_module,
            "kea6_command",
            lambda *a, **kw: {
                "result": 0,
                "arguments": {"Dhcp6": {"subnet6": []}},
            },
        )
        data = kea6_module.get_subnet6_kea_data(999)
        assert data["pool_str"] == ""
        assert data["preferred_lifetime"] == ""

    def test_returns_empty_shape_on_kea_error(self, monkeypatch):
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(kea6_module, "kea6_command", lambda *a, **kw: {"result": 1})
        data = kea6_module.get_subnet6_kea_data(1)
        assert data["pools"] == []


# v5.11.0 — build_subnet6_patch_script() is gone; the v6 subnet-patch
# mutation lives in jen/services/kea_config_edit.py::patch_subnet6
# (tests/test_kea_config_edit.py).


class TestParseAndValidateSubnet6EditForm:
    def test_valid_range_pool_accepted(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form

        fields, error = _parse_and_validate_subnet6_edit_form({"pool": "2001:db8::10-2001:db8::20"})
        assert error is None
        assert fields["new_pool"] == "2001:db8::10-2001:db8::20"

    def test_valid_cidr_pool_accepted(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form

        fields, error = _parse_and_validate_subnet6_edit_form({"pool": "2001:db8::/64"})
        assert error is None

    def test_invalid_pool_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form

        fields, error = _parse_and_validate_subnet6_edit_form({"pool": "not-an-address"})
        assert error is not None

    def test_v4_pool_rejected_on_v6_form(self):
        """A v4-shaped pool string must not silently pass v6 validation."""
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form

        fields, error = _parse_and_validate_subnet6_edit_form({"pool": "192.168.1.10-192.168.1.20"})
        assert error is not None

    def test_invalid_dns_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form

        fields, error = _parse_and_validate_subnet6_edit_form({"dns_servers": "not-an-ip"})
        assert error is not None

    def test_preferred_exceeding_valid_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form

        fields, error = _parse_and_validate_subnet6_edit_form({"preferred_lifetime": "9000", "valid_lifetime": "4000"})
        assert error is not None
        assert "Preferred Lifetime" in error

    def test_preferred_equal_to_valid_accepted(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form

        fields, error = _parse_and_validate_subnet6_edit_form({"preferred_lifetime": "4000", "valid_lifetime": "4000"})
        assert error is None

    def test_no_routers_field_exists(self):
        """DHCPv6 has no router option — confirm the parsed fields dict
        genuinely has no routers key at all, not just an empty one."""
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form

        fields, error = _parse_and_validate_subnet6_edit_form({})
        assert error is None
        assert "new_routers" not in fields

    def test_negative_timer_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet6_edit_form

        fields, error = _parse_and_validate_subnet6_edit_form({"renew_timer": "-5"})
        assert error is not None


class TestEditSubnet6Route:
    def test_requires_admin(self, client, db):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[], role="viewer")
        resp = c.get("/subnets/edit6/1", follow_redirects=False)
        assert resp.status_code == 302

    def test_not_found_redirects(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.get("/subnets/edit6/1", follow_redirects=False)
        assert resp.status_code == 302

    def test_renders_form_with_current_kea_data(self, logged_in_client, monkeypatch):
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        monkeypatch.setattr(
            kea6_module,
            "get_subnet6_kea_data",
            lambda subnet_id: {
                "pools": ["2001:db8::10-2001:db8::20"],
                "pool_str": "2001:db8::10-2001:db8::20",
                "preferred_lifetime": 3000,
                "valid_lifetime": 4000,
                "renew_timer": 1000,
                "rebind_timer": 2000,
                "dns_servers": "",
            },
        )
        resp = logged_in_client.get("/subnets/edit6/1")
        assert resp.status_code == 200
        assert b"2001:db8::10-2001:db8::20" in resp.data
        assert b"Edit IPv6 Subnet" in resp.data


class TestEditSubnet6PostRoute:
    def test_requires_admin(self, client, db):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[], role="viewer")
        resp = c.post("/subnets/edit6/1", data={}, follow_redirects=False)
        assert resp.status_code == 302

    def test_not_found(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.post("/subnets/edit6/1", data={}, follow_redirects=True)
        assert b"IPv6 subnet not found" in resp.data

    def test_validation_error_redirects_to_edit_form(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        resp = logged_in_client.post("/subnets/edit6/1", data={"pool": "not-valid"}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Invalid pool" in resp.data

    def test_no_ssh_servers_no_op_success(self, logged_in_client, monkeypatch):
        """No configured SSH servers means the loop does nothing and no
        error/success flash for a server fires — must not crash."""
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "solo", "ssh_host": ""}])
        resp = logged_in_client.post("/subnets/edit6/1", data={"preferred_lifetime": "3000"}, follow_redirects=False)
        assert resp.status_code == 302

    def _v6_helper(self, monkeypatch, subnet6=None):
        from jen.services import kea_host
        from tests._kea_host_fakes import FakeHelper

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [{"id": 1, "name": "theelders", "ssh_host": "10.10.11.250", "kea_conf": "/etc/kea/kea-dhcp4.conf"}],
        )
        fake = FakeHelper()
        fake.configs[(1, "dhcp6")] = {"Dhcp6": {"subnet6": subnet6 if subnet6 is not None else [{"id": 1}]}}
        fake.responses["apply-config"] = {"ok": True, "backup": None}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp6-server", "state": "active"}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
        return fake

    def test_successful_apply_restarts_kea6(self, logged_in_client, monkeypatch):
        fake = self._v6_helper(monkeypatch)
        resp = logged_in_client.post("/subnets/edit6/1", data={"preferred_lifetime": "3000"}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"validated, updated and restarted" in resp.data
        assert fake.payload_for("service") == {"service": "dhcp6", "action": "restart"}
        s = fake.payload_for("apply-config")["config"]["Dhcp6"]["subnet6"][0]
        assert s["preferred-lifetime"] == 3000

    def test_config_test_failure_does_not_restart(self, logged_in_client, monkeypatch):
        fake = self._v6_helper(monkeypatch)
        fake.responses["apply-config"] = {"ok": False, "error": "testerror", "detail": "bad pool syntax"}
        resp = logged_in_client.post("/subnets/edit6/1", data={"preferred_lifetime": "3000"}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"config validation failed" in resp.data
        assert b"bad pool syntax" in resp.data
        assert "service" not in fake.ops()  # never attempted a restart


class TestEditSubnet6PreviewRoute:
    def test_requires_admin(self, client, db):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[], role="viewer")
        resp = c.post("/subnets/edit6/1/preview", data={}, follow_redirects=False)
        assert resp.status_code == 302

    def test_not_found(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.post("/subnets/edit6/1/preview", data={})
        assert resp.status_code == 404

    def test_no_changes_returns_early(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        resp = logged_in_client.post("/subnets/edit6/1/preview", data={})
        assert resp.status_code == 200
        assert resp.get_json()["no_changes"] is True

    def test_dry_run_never_touches_live_config(self, logged_in_client, monkeypatch):
        """The core safety guarantee: preview only test_config()s, never
        apply_config() / service_action()."""
        from jen.services import kea_host
        from tests._kea_host_fakes import FakeHelper

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        server = {"id": 1, "name": "theelders", "ssh_host": "10.10.11.250", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        fake = FakeHelper()
        fake.configs[(1, "dhcp6")] = {"Dhcp6": {"subnet6": [{"id": 1}]}}
        fake.responses["test-config"] = {"ok": True}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
        resp = logged_in_client.post("/subnets/edit6/1/preview", data={"preferred_lifetime": "3000"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["servers"][0]["ok"] is True
        assert data["all_passed"] is True
        assert "apply-config" not in fake.ops() and "service" not in fake.ops()
