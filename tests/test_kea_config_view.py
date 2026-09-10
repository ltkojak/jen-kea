"""
tests/test_kea_config_view.py
─────────────────────────────
v5.15.0 — jen/services/kea_config_view.py: iterate subnets that Kea
nests inside `shared-networks`, which every config-get consumer used to
skip. TestZeroBehaviorChange proves a config with no shared networks
iterates exactly as a bare `for s in Dhcp4["subnet4"]` did.
"""

from jen.services import kea_config_view as view

_FLAT4 = {
    "subnet4": [
        {"id": 10, "subnet": "10.0.10.0/24"},
        {"id": 20, "subnet": "10.0.20.0/24"},
    ]
}

_NESTED4 = {
    "subnet4": [{"id": 10, "subnet": "10.0.10.0/24"}],
    "shared-networks": [
        {
            "name": "guest",
            "interface": "eth1",
            "option-data": [{"name": "domain-name", "data": "guest.lan"}],
            "subnet4": [
                {"id": 70, "subnet": "10.0.70.0/24"},
                {"id": 71, "subnet": "10.0.71.0/24"},
            ],
        },
        {"name": "iot", "subnet4": [{"id": 80, "subnet": "10.0.80.0/24"}]},
    ],
}

_ALL_NESTED4 = {
    "shared-networks": [
        {"name": "only", "subnet4": [{"id": 5, "subnet": "10.0.5.0/24"}]},
    ]
}


class TestIterSubnet4:
    def test_order_is_top_level_then_networks_in_config_order(self):
        assert [(s["id"], n) for s, n in view.iter_subnet4(_NESTED4)] == [
            (10, None),
            (70, "guest"),
            (71, "guest"),
            (80, "iot"),
        ]

    def test_works_when_there_is_no_top_level_subnet4_key(self):
        assert [(s["id"], n) for s, n in view.iter_subnet4(_ALL_NESTED4)] == [(5, "only")]

    def test_missing_or_odd_shapes_yield_empty(self):
        assert view.iter_subnet4(None) == []
        assert view.iter_subnet4({}) == []
        assert view.iter_subnet4({"subnet4": "nonsense"}) == []
        assert view.iter_subnet4({"shared-networks": {}}) == []

    def test_returned_dicts_are_the_live_objects(self):
        s, _ = view.iter_subnet4(_NESTED4)[1]
        assert s is _NESTED4["shared-networks"][0]["subnet4"][0]


class TestByIdAndSummary:
    def test_by_id_finds_nested(self):
        s, name = view.subnet4_by_id(_NESTED4, 71)
        assert s["subnet"] == "10.0.71.0/24" and name == "guest"

    def test_by_id_finds_top_level(self):
        s, name = view.subnet4_by_id(_NESTED4, 10)
        assert name is None

    def test_by_id_missing_is_none(self):
        assert view.subnet4_by_id(_NESTED4, 999) is None

    def test_shared_networks4_summary(self):
        assert view.shared_networks4(_NESTED4) == [
            {"name": "guest", "interface": "eth1", "subnet_ids": [70, 71], "option_data_count": 1},
            {"name": "iot", "interface": None, "subnet_ids": [80], "option_data_count": 0},
        ]

    def test_shared_networks4_empty_when_none(self):
        assert view.shared_networks4(_FLAT4) == []


class TestZeroBehaviorChange:
    """A config with no shared-networks must iterate exactly as a bare
    `for s in Dhcp4['subnet4']` loop did before v5.15.0."""

    def test_iter_matches_the_old_bare_loop(self):
        old = list(_FLAT4["subnet4"])
        new = [s for s, _n in view.iter_subnet4(_FLAT4)]
        assert new == old
        assert all(n is None for _s, n in view.iter_subnet4(_FLAT4))

    def test_by_id_matches_the_old_lookup(self):
        old = next((s for s in _FLAT4["subnet4"] if s["id"] == 20), None)
        assert view.subnet4_by_id(_FLAT4, 20)[0] is old


_NESTED6 = {
    "subnet6": [{"id": 100, "subnet": "2001:db8:a::/64"}],
    "shared-networks": [
        {"name": "v6net", "subnet6": [{"id": 200, "subnet": "2001:db8:b::/64"}]},
    ],
}


class TestIterSubnet6:
    def test_v6_twin(self):
        assert [(s["id"], n) for s, n in view.iter_subnet6(_NESTED6)] == [(100, None), (200, "v6net")]

    def test_v6_by_id(self):
        assert view.subnet6_by_id(_NESTED6, 200)[1] == "v6net"

    def test_v6_shared_networks(self):
        assert view.shared_networks6(_NESTED6) == [
            {"name": "v6net", "interface": None, "subnet_ids": [200], "option_data_count": 0}
        ]
