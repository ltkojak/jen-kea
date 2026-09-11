"""
tests/test_subnet_options.py
─────────────────────────────
v5.18.0 (Q12) — the DHCP options hierarchy page and its set/remove
routes (jen/routes/subnets.py::dhcp_options_page/_set/_remove,
jen/services/dhcp_options.py).
"""

from tests.conftest import restricted_client as _restricted_client


class TestDhcpOptionsRoutes:
    _DHCP4 = {
        "Dhcp4": {
            "valid-lifetime": 3600,
            "option-data": [
                {"name": "ntp-servers", "code": 42, "space": "dhcp4", "csv-format": True, "data": "1.1.1.1"}
            ],
            "subnet4": [
                {
                    "id": 10,
                    "subnet": "10.0.10.0/24",
                    "pools": [{"pool": "10.0.10.10 - 10.0.10.99"}],
                    "option-data": [
                        {"name": "routers", "code": 3, "space": "dhcp4", "csv-format": True, "data": "10.0.10.1"}
                    ],
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

    # ── page ──────────────────────────────────────────────────────────

    def test_requires_login(self, client):
        r = client.get("/subnets/options", follow_redirects=False)
        assert r.status_code in (301, 302, 308)

    def test_global_page_loads(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets/options")
        assert r.status_code == 200
        assert b"ntp-servers" in r.data

    def test_subnet_page_loads_and_shows_managed_option(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets/options?level=subnet&key=10")
        assert r.status_code == 200
        assert b"routers" in r.data
        assert b"managed by Edit form" in r.data

    def test_shared_network_page_loads(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets/options?level=shared-network&key=guest")
        assert r.status_code == 200

    def test_pool_page_loads_and_shows_the_effective_panel(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets/options?level=pool&key=10:10.0.10.10 - 10.0.10.99")
        assert r.status_code == 200
        assert b"Effective options" in r.data

    def test_unknown_level_falls_back_to_global(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets/options?level=bogus", follow_redirects=True)
        assert r.status_code == 200
        assert b"Global options" in r.data

    # ── set / remove ──────────────────────────────────────────────────

    def test_add_global_option_pushes_apply_config_and_restarts(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/options/set",
            data={"level": "global", "key": "", "code": "41", "data": "10.0.0.1, 10.0.0.2"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["option-data"]
        nis = [o for o in applied if o["name"] == "nis-servers"]
        assert nis and nis[0]["data"] == "10.0.0.1, 10.0.0.2"
        assert "service" in fake.ops()

    def test_add_subnet_option_lands_in_the_right_subnet(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/options/set",
            data={"level": "subnet", "key": "10", "code": "66", "data": "tftp.local"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        subnet10 = fake.payload_for("apply-config")["config"]["Dhcp4"]["subnet4"][0]
        tftp = [o for o in subnet10["option-data"] if o["name"] == "tftp-server-name"]
        assert tftp and tftp[0]["data"] == "tftp.local"

    def test_custom_code_is_written_as_hex_with_csv_format_false(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/options/set",
            data={"level": "global", "key": "", "code": "220", "name": "my-thing", "data": "0a1b2c", "custom": "1"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"]["option-data"]
        custom = [o for o in applied if o.get("code") == 220]
        assert custom and custom[0]["csv-format"] is False
        assert custom[0]["data"] == "0a1b2c"

    def test_remove_option(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/options/remove", data={"level": "global", "key": "", "code": "42"}, follow_redirects=True
        )
        assert r.status_code == 200
        applied = fake.payload_for("apply-config")["config"]["Dhcp4"].get("option-data", [])
        assert not [o for o in applied if o.get("code") == 42]

    def test_invalid_value_rejected_with_flash_and_no_push(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/options/set",
            data={"level": "global", "key": "", "code": "3", "data": "not-an-ip"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"ipv4" in r.data.lower()
        assert "apply-config" not in fake.ops()

    def test_managed_code_refused_at_subnet_level(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/options/set",
            data={"level": "subnet", "key": "10", "code": "3", "data": "10.0.10.9"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"managed by the edit subnet form" in r.data.lower()
        assert "apply-config" not in fake.ops()

    def test_unknown_catalog_code_without_custom_flag_is_rejected(self, logged_in_client, monkeypatch, mock_kea):
        fake = self._wire(monkeypatch)
        r = logged_in_client.post(
            "/subnets/options/set",
            data={"level": "global", "key": "", "code": "9999", "data": "x"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"unknown catalog option" in r.data.lower()
        assert "apply-config" not in fake.ops()

    # ── access control ────────────────────────────────────────────────

    def test_restricted_admin_forbidden_on_global(self, client, db, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        c, _ = _restricted_client(client, db, allowed_subnets=[10], role="admin", username="opts_restricted1")
        r = c.get("/subnets/options?level=global", follow_redirects=True)
        assert r.status_code == 200
        assert b"access to all subnets" in r.data

    def test_restricted_admin_forbidden_on_shared_network(self, client, db, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        c, _ = _restricted_client(client, db, allowed_subnets=[10], role="admin", username="opts_restricted2")
        r = c.get("/subnets/options?level=shared-network&key=guest", follow_redirects=True)
        assert r.status_code == 200
        assert b"access to all subnets" in r.data

    def test_restricted_admin_can_reach_their_own_subnet(self, client, db, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        c, _ = _restricted_client(client, db, allowed_subnets=[10], role="admin", username="opts_restricted3")
        r = c.get("/subnets/options?level=subnet&key=10")
        assert r.status_code == 200

    def test_restricted_admin_cannot_reach_a_subnet_outside_their_scope(self, client, db, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        c, _ = _restricted_client(client, db, allowed_subnets=[999], role="admin", username="opts_restricted4")
        r = c.get("/subnets/options?level=subnet&key=10", follow_redirects=True)
        assert r.status_code == 200
        assert b"do not have access" in r.data.lower()

    def test_viewer_forbidden(self, client, db, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        c, _ = _restricted_client(client, db, allowed_subnets=None, role="viewer", username="opts_viewer1")
        r = c.get("/subnets/options", follow_redirects=True)
        assert b"admin access required" in r.data.lower()

    # ── subnet card + audit ───────────────────────────────────────────

    def test_subnet_card_shows_the_options_line(self, logged_in_client, monkeypatch, mock_kea):
        self._wire(monkeypatch)
        r = logged_in_client.get("/subnets")
        assert r.status_code == 200
        assert b"Options: 1 here" in r.data

    def test_audit_row_written_on_set(self, logged_in_client, monkeypatch, mock_kea, db):
        self._wire(monkeypatch)
        logged_in_client.post(
            "/subnets/options/set",
            data={"level": "global", "key": "", "code": "41", "data": "10.0.0.1"},
            follow_redirects=True,
        )
        with db.cursor() as cur:
            cur.execute("SELECT * FROM audit_log WHERE action='SET_DHCP_OPTION' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
        assert row is not None

    def test_audit_row_written_on_remove(self, logged_in_client, monkeypatch, mock_kea, db):
        self._wire(monkeypatch)
        logged_in_client.post(
            "/subnets/options/remove", data={"level": "global", "key": "", "code": "42"}, follow_redirects=True
        )
        with db.cursor() as cur:
            cur.execute("SELECT * FROM audit_log WHERE action='REMOVE_DHCP_OPTION' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
        assert row is not None
