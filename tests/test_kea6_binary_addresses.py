"""
tests/test_kea6_binary_addresses.py
───────────────────────────────────
v5.67.0-beta.16 (Q130) — Kea 3.x stores lease6.address and ipv6_reservations.address (and excluded_prefix) as
BINARY(16). Jen's IPv6 readers assumed VARCHAR(39) text, so on a real Kea 3 database with IPv6 management on the
IPv6 pages printed sixteen raw bytes where an address belongs, and an address search on lease6 (`address LIKE`)
matched nothing. The unit suite's tables are binary now (tests/conftest.py), so everything here seeds bytes and runs
against the real MariaDB/MySQL; tests/kea_compat/test_db_moves.py asserts the same column types against ISC's own
schema on every supported Kea.
"""

import ipaddress

import pytest

from jen.services import kea6


def packed(text):
    return ipaddress.IPv6Address(text).packed


class TestAddrText:
    def test_sixteen_bytes_become_the_compressed_text(self):
        assert kea6._addr_text(packed("2001:db8::10")) == "2001:db8::10"
        assert kea6._addr_text(packed("2001:0db8:0000:0000:0000:0000:0000:0010")) == "2001:db8::10"
        assert kea6._addr_text(bytearray(packed("fe80::1"))) == "fe80::1"
        assert kea6._addr_text(memoryview(packed("::1"))) == "::1"
        assert kea6._addr_text(bytes(16)) == "::"

    def test_text_passes_through_unchanged(self):
        assert kea6._addr_text("2001:db8::10") == "2001:db8::10"
        assert kea6._addr_text("") == ""

    def test_none_stays_none(self):
        assert kea6._addr_text(None) is None

    def test_bytes_that_are_not_an_addresss_width_are_read_as_text_not_guessed_at(self):
        assert kea6._addr_text(b"2001:db8::10") == "2001:db8::10"
        assert kea6._addr_text(b"\xff\xfe\xfd") == "���"  # never an exception

    def test_every_address_a_reader_returns_goes_through_it(self):
        import inspect

        src = inspect.getsource(kea6)
        assert '"address": _addr_text(row["address"])' in src
        assert '_addr_text(row["excluded_prefix"])' in src
        assert '"address": row["address"]' not in src, "a raw column value is returned somewhere"


class TestSearchHelpers:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("2001:db8::10", "2001:db8::10"),
            (" 2001:DB8::10 ", "2001:db8::10"),
            ("2001:0db8:0:0:0:0:0:10", "2001:db8::10"),
            ("::1", "::1"),
            ("2001:db8", None),
            ("2001:db8:", None),
            ("db8", None),
            ("host-1", None),
            ("10.0.0.1", None),
            ("", None),
        ],
    )
    def test_only_a_whole_address_is_an_exact_search(self, text, expected):
        assert kea6._complete_v6_address(text) == expected

    def test_a_fragment_matches_the_text_the_hostname_and_the_duid(self):
        row = {"address": packed("2001:db8:1::ab"), "hostname": "Printer-One", "duid_hex": "00030001AABBCCDDEEFF"}

        def match(s):
            return kea6._lease6_search_filter(s)(row)

        assert match("2001:db8") and match("DB8:1") and match("::ab") and match("AB")
        assert match("0db8"), "the expanded spelling matches too"
        assert match("printer") and match("one")
        assert match("aabb") and match("00:03:00:01"), "a typed colon is ignored in the DUID"
        assert not match("2002") and not match("scanner") and not match("ffff0000")


@pytest.fixture
def v6db(db, monkeypatch):
    import jen.models.db as db_mod

    monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
    monkeypatch.setattr(db, "close", lambda: None)  # keep the fixture's connection alive
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease6")
        cur.execute("DELETE FROM ipv6_reservations")
        cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
    db.commit()
    yield db
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease6")
        cur.execute("DELETE FROM ipv6_reservations")
        cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
    db.commit()


def _lease(db, address, duid="00030001001a2b3c4d5e", hostname="", subnet_id=1, lease_type=0, state=0, prefix_len=128):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease6 (address, duid, valid_lifetime, expire, subnet_id, pref_lifetime, lease_type, iaid, "
            "prefix_len, hostname, hwaddr, state) VALUES (%s, %s, 3600, '2037-01-01 00:00:00', %s, 1800, %s, 1, %s, "
            "%s, NULL, %s)",
            (packed(address), bytes.fromhex(duid), subnet_id, lease_type, prefix_len, hostname, state),
        )
    db.commit()


class TestLeasesComeBackAsAddresses:
    def test_the_address_is_text_not_sixteen_bytes(self, v6db):
        _lease(v6db, "2001:db8::10", hostname="h")
        rows = kea6.list_lease6()
        assert [r["address"] for r in rows] == ["2001:db8::10"]
        assert isinstance(rows[0]["address"], str)

    def test_rows_are_in_numeric_address_order(self, v6db):
        for a in ("2001:db8::100", "2001:db8::2", "2001:db8::10", "2001:db8::1"):
            _lease(v6db, a, duid="0003000100" + a.replace(":", "")[-2:].rjust(2, "0") + "00000000")
        assert [r["address"] for r in kea6.list_lease6()] == [
            "2001:db8::1",
            "2001:db8::2",
            "2001:db8::10",
            "2001:db8::100",
        ], "binary order is numeric order (the text order was ::1, ::10, ::100, ::2)"

    def test_a_delegated_prefix_reads_back_too(self, v6db):
        _lease(v6db, "2001:db8:1000::", lease_type=2, prefix_len=56)
        assert [(r["address"], r["lease_type_name"], r["prefix_len"]) for r in kea6.list_lease6()] == [
            ("2001:db8:1000::", "IA_PD", 56)
        ]

    def test_the_derived_views_carry_text_addresses(self, v6db):
        _lease(v6db, "2001:db8::10", duid="00030001001a2b3c4d5e")
        devices = kea6.list_lease6_devices()
        assert devices[0]["addresses"][0]["address"] == "2001:db8::10"
        assert kea6.lease6_devices_without_hwaddr()[0]["addresses"][0]["address"] == "2001:db8::10"


class TestSearchingABinaryColumn:
    def _seed(self, db):
        _lease(db, "2001:db8::10", duid="00030001aaaaaaaaaaaa", hostname="alpha")
        _lease(db, "2001:db8::100", duid="00030001bbbbbbbbbbbb", hostname="beta")
        _lease(db, "2001:db8:1::10", duid="00030001cccccccccccc", hostname="gamma")
        _lease(db, "fd00::1", duid="00030001dddddddddddd", hostname="delta")

    def _addresses(self, **kw):
        return [r["address"] for r in kea6.list_lease6(**kw)]

    def test_a_whole_address_is_an_exact_match_not_a_prefix_of_its_neighbours(self, v6db):
        self._seed(v6db)
        assert self._addresses(search="2001:db8::10") == ["2001:db8::10"], "::100 must not match ::10"
        assert self._addresses(search="fd00::1") == ["fd00::1"]

    def test_an_exact_search_accepts_any_spelling_of_the_address(self, v6db):
        self._seed(v6db)
        assert self._addresses(search="2001:0db8:0000:0000:0000:0000:0000:0010") == ["2001:db8::10"]
        assert self._addresses(search="2001:DB8::10") == ["2001:db8::10"]

    def test_a_hostname_or_a_duid_fragment_still_finds_its_lease(self, v6db):
        self._seed(v6db)
        assert self._addresses(search="alpha") == ["2001:db8::10"]
        assert self._addresses(search="bbbbbbbb") == ["2001:db8::100"]

    def test_a_fragment_is_filtered_in_python_over_the_converted_text(self, v6db):
        self._seed(v6db)
        assert self._addresses(search="2001:db8") == ["2001:db8::10", "2001:db8::100", "2001:db8:1::10"]
        assert self._addresses(search="db8:1") == ["2001:db8:1::10"]
        assert self._addresses(search="8:1:") == ["2001:db8:1::10"]

    def test_a_fragment_matches_the_expanded_spelling_too(self, v6db):
        self._seed(v6db)
        assert self._addresses(search="0db8:0000") == ["2001:db8::10", "2001:db8::100"]

    def test_a_fragment_also_matches_hostname_and_duid_like_before(self, v6db):
        self._seed(v6db)
        assert self._addresses(search="ELT") == ["fd00::1"], "case-insensitive hostname fragment (delta)"
        assert self._addresses(search="00:03:00:01:cc") == ["2001:db8:1::10"], "a typed colon is ignored in a DUID"

    def test_no_match_is_empty_not_an_error(self, v6db):
        self._seed(v6db)
        assert self._addresses(search="nothing-like-this") == []
        assert self._addresses(search="2001:db8::ffff") == []

    def test_the_search_composes_with_the_other_filters(self, v6db):
        _lease(v6db, "2001:db8::10", hostname="a", subnet_id=1)
        _lease(v6db, "2001:db8::11", duid="00030001eeeeeeeeeeee", hostname="b", subnet_id=2)
        _lease(v6db, "2001:db8::12", duid="00030001ffffffffffff", hostname="c", subnet_id=1, state=1)
        assert self._addresses(search="2001:db8", subnet_id=1) == ["2001:db8::10"]
        assert self._addresses(search="2001:db8", subnet_id=1, show_expired=True) == ["2001:db8::10", "2001:db8::12"]
        assert self._addresses(search="2001:db8::11", subnet_id=1) == []

    def test_a_search_with_a_percent_or_underscore_is_just_text(self, v6db):
        self._seed(v6db)
        assert self._addresses(search="20%1") == []
        assert self._addresses(search="alp_a") == []

    def test_the_exact_path_uses_inet6_aton_and_no_like_on_the_address(self):
        import inspect

        src = inspect.getsource(kea6.list_lease6)
        assert "address = INET6_ATON(%s)" in src
        assert "address LIKE %s" not in src, "the SQL must never LIKE-match the binary column"


class TestReservationsComeBackAsAddresses:
    def _host(self, db, reservations):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp6_subnet_id, hostname) "
                "VALUES (%s, 1, 1, 'res-host')",
                (bytes.fromhex("00030001001a2b3c4d5e"),),
            )
            host_id = cur.lastrowid
            for r in reservations:
                cur.execute(
                    "INSERT INTO ipv6_reservations (address, prefix_len, type, dhcp6_iaid, host_id, excluded_prefix, "
                    "excluded_prefix_len) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (
                        packed(r["address"]),
                        r["prefix_len"],
                        r["type"],
                        1,
                        host_id,
                        packed(r["excluded"]) if r.get("excluded") else None,
                        r.get("excluded_len", 0),
                    ),
                )
        db.commit()

    def test_address_and_excluded_prefix_are_text(self, v6db):
        self._host(
            v6db,
            [
                {"address": "2001:db8::10", "prefix_len": 128, "type": 0},
                {
                    "address": "2001:db8:1000::",
                    "prefix_len": 56,
                    "type": 2,
                    "excluded": "2001:db8:1000:ff00::",
                    "excluded_len": 64,
                },
            ],
        )
        host = kea6.get_ipv6_reservations(subnet_id=1)[0]
        by_type = {r["type_name"]: r for r in host["reservations"]}
        assert by_type["IA_NA"]["address"] == "2001:db8::10"
        assert by_type["IA_NA"]["excluded_prefix"] == "" and by_type["IA_NA"]["excluded_prefix_len"] == 0
        assert by_type["IA_PD"]["address"] == "2001:db8:1000::"
        assert by_type["IA_PD"]["excluded_prefix"] == "2001:db8:1000:ff00::"
        assert by_type["IA_PD"]["excluded_prefix_len"] == 64
        assert all(isinstance(r["address"], str) for r in host["reservations"])


class TestReservationSearchPredicate:
    """v5.67.0-beta.17 (Q131) — one predicate for the global search over a v6 subnet's reservations."""

    HOST = {
        "hostname": "Printer-One",
        "duid_hex": "00030001AABBCCDDEEFF",
        "reservations": [{"address": "2001:db8::10"}, {"address": "2001:db8:1000::"}],
    }

    def match(self, needle, host=None):
        return kea6._reservation6_matches(host or self.HOST, needle)

    def test_hostname_duid_and_addresses_in_both_spellings(self):
        assert self.match("printer") and self.match("ONE")
        assert self.match("aabbcc") and self.match("00:03:00:01"), "a typed colon is ignored in the DUID"
        assert self.match("2001:db8::10") and self.match("db8:1000")
        assert self.match("2001:0db8") and self.match("0000:0000:0010"), "the expanded spelling"
        assert self.match("2001:0DB8:0000:0000:0000:0000:0000:0010"), "case-insensitive"

    def test_every_reservation_of_the_host_counts(self):
        assert self.match("1000::") and self.match("2001:0db8:1000")

    def test_non_matches_and_an_empty_search(self):
        assert not self.match("scanner") and not self.match("ffff0000") and not self.match("2002:db8")
        assert not self.match("") and not self.match("   ") and not self.match(None)

    def test_a_host_with_no_reservations_still_matches_by_hostname(self):
        host = {"hostname": "bare", "duid_hex": "", "reservations": []}
        assert self.match("bar", host) and not self.match("2001", host)

    def test_missing_fields_never_raise(self):
        assert not self.match("x", {})
        assert not self.match("x", {"hostname": None, "duid_hex": None, "reservations": [{"address": None}]})
