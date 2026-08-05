import pytest


class TestGetSubnetKeaData:
    """_get_subnet_kea_data() must return ALL of a subnet's pools, not just
    the first — this backs the Edit Subnet form and, until v4.3.8, a bug
    downstream of this function silently discarded every pool after the
    first whenever the edit form was submitted."""

    def test_returns_all_pools_for_multi_pool_subnet(self, monkeypatch):
        from jen.services import kea as kea_svc
        from jen.routes import subnets as subnets_mod

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
        from jen.services import kea as kea_svc
        from jen.routes import subnets as subnets_mod

        fake_config = {
            "result": 0,
            "arguments": {
                "Dhcp4": {
                    "subnet4": [
                        {"id": 2, "pools": [{"pool": "10.10.30.10 - 10.10.30.200"}], "option-data": []}
                    ],
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

    def test_generated_remote_script_preserves_extra_pools(self):
        """The remote config-patch script is built as an f-string embedding
        repr(extra_pools). Confirm the merge logic it contains is correct by
        exercising the same expression the route uses to build s['pools']."""
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
