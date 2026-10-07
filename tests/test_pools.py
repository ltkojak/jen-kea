"""
tests/test_pools.py
───────────────────
v5.68.0-beta.18 (Q153) - one pool utility behind every capacity number. Pool size used to be computed four ways (the last pool wins; a CIDR
pool skipped; a sum that still skipped CIDR; a whole-subnet count compared with each pool in turn) and three parsers read the same syntax.
Pure: no database, no Flask (`pytest --noconftest tests/test_pools.py`).
"""

import pytest

from jen.services import pools

TWO_RANGES = [{"pool": "10.0.0.10 - 10.0.0.59"}, {"pool": "10.0.0.100-10.0.0.159"}]  # 50 + 60
A_CIDR = [{"pool": "10.0.1.0/26"}]  # 64


class TestParse:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("10.0.0.1 - 10.0.0.3", (167772161, 167772163)),
            ("10.0.0.1-10.0.0.3", (167772161, 167772163)),
            ("  10.0.0.1  -  10.0.0.3 ", (167772161, 167772163)),
            ("10.0.0.0/30", (167772160, 167772163)),
            ("10.0.0.5/32", (167772165, 167772165)),
            ("10.0.0.7 - 10.0.0.7", (167772167, 167772167)),
        ],
    )
    def test_the_forms_kea_accepts(self, text, expected):
        assert pools.parse_pool(text) == expected

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "   ",
            "x",
            None,
            "10.0.0.9 - 10.0.0.1",
            "10.0.0.1 - nope",
            "10.0.0.1 -",
            "- 10.0.0.1",
            "10.0.0.0/33",
            "2001:db8::/64",
        ],
    )
    def test_anything_else_is_none_not_an_exception(self, bad):
        assert pools.parse_pool(bad) is None

    def test_a_cidr_outside_the_given_network_is_refused(self):
        import ipaddress

        net = ipaddress.IPv4Network("10.0.0.0/24")
        assert pools.parse_pool("10.0.0.0/26", net) == (167772160, 167772223)
        assert pools.parse_pool("10.9.0.0/26", net) is None

    def test_subnet_contexts_parser_is_this_one(self):
        import ipaddress

        from jen.services import subnet_context as sc

        net = ipaddress.IPv4Network("10.0.0.0/24")
        assert sc.parse_pool("10.0.0.1-10.0.0.3", net) == (167772161, 167772163, "10.0.0.1 - 10.0.0.3")
        assert sc.parse_pool("10.0.0.0/30", net) == (167772160, 167772163, "10.0.0.0/30")


class TestSize:
    def test_two_ranges_add(self):
        assert pools.total_pool_size(TWO_RANGES) == 110

    def test_a_cidr_only_subnet_has_its_whole_block(self):
        assert pools.total_pool_size(A_CIDR) == 64

    def test_mixed_ranges_and_cidrs_add(self):
        assert pools.total_pool_size(TWO_RANGES + A_CIDR) == 174

    def test_strings_and_dicts_are_both_accepted(self):
        assert pools.total_pool_size(["10.0.0.10 - 10.0.0.59", {"pool": "10.0.0.100-10.0.0.159"}]) == 110

    def test_the_last_pool_does_not_win(self):
        """The old snapshot kept `pool_sizes[id] = <the last pool's size>`: 60, not 110."""
        assert pools.total_pool_size(TWO_RANGES) != 60

    def test_overlapping_and_touching_pools_are_one_union_never_double_counted(self):
        assert pools.total_pool_size(["10.0.0.10 - 10.0.0.30", "10.0.0.20 - 10.0.0.40"]) == 31
        assert pools.total_pool_size(["10.0.0.10 - 10.0.0.19", "10.0.0.20 - 10.0.0.29"]) == 20
        assert pools.pool_ranges(["10.0.0.10 - 10.0.0.19", "10.0.0.20 - 10.0.0.29"]) == [(167772170, 167772189)]

    def test_unreadable_pools_are_left_out_and_nothing_is_zero(self):
        assert pools.total_pool_size(["nope", {"pool": ""}, {"nothing": 1}, None, "10.0.0.1 - 10.0.0.2"]) == 2
        assert pools.total_pool_size([]) == 0 and pools.total_pool_size(None) == 0


class TestMembership:
    def test_inside_either_pool_and_outside_both(self):
        assert pools.address_in_pools("10.0.0.10", TWO_RANGES) and pools.address_in_pools("10.0.0.159", TWO_RANGES)
        assert not pools.address_in_pools("10.0.0.60", TWO_RANGES) and not pools.address_in_pools(
            "10.0.0.99", TWO_RANGES
        )

    def test_an_int_a_cidr_pool_and_junk(self):
        assert pools.address_in_pools(167772165, TWO_RANGES + A_CIDR) is False
        assert (
            pools.address_in_pools("10.0.1.63", A_CIDR) is True and pools.address_in_pools("10.0.1.64", A_CIDR) is False
        )
        assert pools.address_in_pools("not-an-ip", TWO_RANGES) is False


class FakeCursor:
    """Answers `SELECT COUNT(*)` for lease4 from a list of (address, active) rows, honouring the BETWEEN bounds."""

    def __init__(self, leases):
        self.leases, self.statements, self._n = leases, [], 0

    def execute(self, sql, params=()):
        self.statements.append((sql, params))
        subnet_id, lo, hi = params
        self._n = sum(1 for a, sid, active in self.leases if active and sid == subnet_id and lo <= a <= hi)

    def fetchone(self):
        return {"cnt": self._n}


def _ip(text):
    import ipaddress

    return int(ipaddress.IPv4Address(text))


class TestConsumption:
    def test_one_count_per_merged_range_summed_over_the_union(self):
        leases = [(_ip("10.0.0.10") + i, 1, True) for i in range(5)] + [
            (_ip("10.0.0.100") + i, 1, True) for i in range(3)
        ]
        cur = FakeCursor(leases)
        assert pools.consumption(cur, 1, TWO_RANGES) == 8
        assert len(cur.statements) == 2 and all("BETWEEN" in s for s, _ in cur.statements)

    def test_the_query_asks_for_the_current_lease_predicate_and_the_subnet(self):
        cur = FakeCursor([])
        pools.consumption(cur, 7, TWO_RANGES)
        sql, params = cur.statements[0]
        assert "state = 0 AND expire > NOW()" in sql and "subnet_id=%s" in sql and params[0] == 7

    def test_an_active_lease_outside_every_pool_consumes_nothing(self):
        """A reservation's address outside the pools is active (it IS a current lease) and is not pool consumption."""
        leases = [(_ip("10.0.0.5"), 1, True), (_ip("10.0.0.99"), 1, True), (_ip("10.0.0.12"), 1, True)]
        assert pools.consumption(FakeCursor(leases), 1, TWO_RANGES) == 1

    def test_another_subnets_lease_in_the_same_range_is_not_counted(self):
        assert pools.consumption(FakeCursor([(_ip("10.0.0.12"), 2, True)]), 1, TWO_RANGES) == 0

    def test_no_readable_pool_runs_no_query_and_consumes_nothing(self):
        cur = FakeCursor([(_ip("10.0.0.12"), 1, True)])
        assert pools.consumption(cur, 1, []) == 0 and pools.consumption(cur, 1, ["junk"]) == 0
        assert cur.statements == []

    def test_the_hundred_leases_over_two_pools_case_that_read_as_200_and_50_percent(self):
        """100 active leases over pools of 50 and 200: one subnet, 40 % - not 200 % of one pool and 50 % of the other."""
        big = [{"pool": "10.1.0.0 - 10.1.0.49"}, {"pool": "10.1.1.0 - 10.1.1.199"}]
        leases = [(_ip("10.1.1.0") + i, 1, True) for i in range(100)]
        used, size = pools.consumption(FakeCursor(leases), 1, big), pools.total_pool_size(big)
        assert (used, size, round(used / size * 100)) == (100, 250, 40)


class TestTheOldParsersAreGone:
    def test_nothing_defines_a_second_pool_parser(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent / "jen"
        for name, path in (
            ("pool_bounds", "services/dhcp_explain.py"),
            ("_pool_range", "services/config_doctor.py"),
        ):
            assert f"def {name}(" not in (root / path).read_text(encoding="utf-8"), f"{path} still defines {name}"

    def test_no_capacity_path_parses_a_pool_by_hand(self):
        """The four sites that summed or overwrote a pool size by splitting on '-' now call pools.total_pool_size."""
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent / "jen"
        for path in ("services/alerts.py", "routes/dashboard.py", "routes/api.py"):
            text = (root / path).read_text(encoding="utf-8")
            assert 'if "-" in p' not in text and "ps.split" not in text, f"{path} parses a pool itself"
            assert "total_pool_size" in text, f"{path} does not use the one utility"
