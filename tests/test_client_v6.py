"""
tests/test_client_v6.py
────────────────────────
v5.68.0-beta.1 (Q134 b) — the Investigation page takes an IPv6 address or a DUID.

An address is resolved through lease6 (or a v6 reservation of it) to the DUID that holds it; a DUID goes straight to its
leases and its reservation; the MAC Kea captured on a lease — else the one a DUID-LL/LLT embeds, labelled as Jen's own reading
— carries the subject on into everything keyed by MAC, so Overview, Timeline and the Dhcp4 tabs work for the same client.
Explain, Trace and Config stay DHCPv4 engines and say so. A v6 object is judged on its v6 subnet's paired v4 subnet (the
rule Devices and global search already apply); an unpaired v6 subnet is for unrestricted callers only. All of it is gated on
`ipv6_enabled`.

The first groups are pure (`pytest --noconftest -k "not Route"`): the MAC rule and `authorize()` for v6 kinds, including the
moved-client cases. The Route group seeds real binary lease6/ipv6_reservations rows (Q130's rule) and drives the page.
"""

import ipaddress

import pytest

from jen import extensions
from jen.services import client_subject as cs
from jen.services.client_subject import ClientSubject

DUID_LL = "00030001aabbccddee11"  # DUID-LL, hardware type 1, link-layer address aa:bb:cc:dd:ee:11
DUID_EN = "00020000ab0c1122334455"  # DUID-EN: no link-layer address inside


def packed(text):
    return ipaddress.IPv6Address(text).packed


def _lease(address, subnet, *, mac="", mac_source="", duid=DUID_LL, host=""):
    return {
        "address": address,
        "type_name": "IA_NA",
        "prefix_len": 128,
        "subnet_id": subnet,
        "duid_hex": duid,
        "hostname": host,
        "mac": mac,
        "mac_source": mac_source,
    }


def _res(subnet, *, duid=DUID_LL, host="res-host"):
    return {
        "host_id": 1,
        "duid_hex": duid.upper(),
        "dhcp_identifier_type": 1,
        "subnet_id": subnet,
        "hostname": host,
        "client_classes": "",
        "reservations": [{"address": "2001:db8:a::10", "type_name": "IA_NA", "prefix_len": 128}],
    }


@pytest.fixture
def six_subnets(monkeypatch):
    """v6 subnet 7 is paired to v4 subnet 1, 8 to 2, and 9 to nothing."""
    monkeypatch.setattr(
        extensions,
        "SUBNET6_MAP",
        {
            7: {"name": "Alpha6-Net", "cidr": "2001:db8:a::/64", "paired_subnet4_id": 1},
            8: {"name": "Bravo6-SecretNet", "cidr": "2001:db8:b::/64", "paired_subnet4_id": 2},
            9: {"name": "Unpaired6-SecretNet", "cidr": "2001:db8:c::/64", "paired_subnet4_id": None},
        },
    )


class TestTheMacARule:
    def test_the_hardware_address_kea_captured_wins(self):
        leases = [_lease("2001:db8::1", 7, mac="de:ad:be:ef:00:01", mac_source="hwaddr")]
        assert cs.mac_from_v6(leases, DUID_LL) == ("de:ad:be:ef:00:01", "hwaddr")

    def test_a_guess_from_the_lease_row_is_not_kea_capturing_it(self):
        leases = [_lease("2001:db8::1", 7, mac="aa:bb:cc:dd:ee:11", mac_source="duid")]
        assert cs.mac_from_v6(leases, DUID_LL) == ("aa:bb:cc:dd:ee:11", "duid")

    def test_a_duid_ll_or_llt_embeds_one(self):
        assert cs.mac_from_v6([], DUID_LL) == ("aa:bb:cc:dd:ee:11", "duid")
        assert cs.mac_from_v6([], "00010001" + "5f3e2a10" + "aabbccddee22") == ("aa:bb:cc:dd:ee:22", "duid")

    def test_a_duid_en_or_nothing_has_none(self):
        assert cs.mac_from_v6([], DUID_EN) == ("", "")
        assert cs.mac_from_v6([], "") == ("", "")


def _subject(**kw):
    base = {
        "kind": "ipv6",
        "identifier": "2001:db8:a::10",
        "mac": "aa:bb:cc:dd:ee:11",
        "ip": "10.0.0.5",
        "duid": DUID_LL,
        "mac_source": "duid",
        "leases4": [{"ip": "10.0.0.5", "subnet_id": 1, "hostname": "h"}],
        "device": {"mac": "aa:bb:cc:dd:ee:11", "last_subnet_id": 1, "last_hostname": "h", "last_ip": "10.0.0.5"},
        "leases6": [_lease("2001:db8:a::10", 7)],
        "reservations6": [_res(7)],
        "subnet_ids": frozenset({1}),
    }
    base.update(kw)
    return ClientSubject(**base)


class TestAuthorizeForV6Kinds:
    def test_an_unrestricted_caller_gets_the_subject_back_unchanged(self, six_subnets):
        subject = _subject()
        assert cs.authorize(subject, rule="per_object", accessible_ids=None) is subject

    def test_a_caller_who_may_see_the_paired_subnet_keeps_the_v6_objects_and_the_v4_side(self, six_subnets):
        view = cs.authorize(_subject(), rule="per_object", accessible_ids={1})
        assert [a["address"] for a in view.leases6] == ["2001:db8:a::10"]
        assert [h["subnet_id"] for h in view.reservations6] == [7]
        assert view.mac == "aa:bb:cc:dd:ee:11" and view.duid == DUID_LL and view.leases4
        assert cs.names_a_subnet(view)

    def test_a_v6_object_in_a_subnet_paired_to_a_hidden_one_is_dropped_and_so_is_everything_derived_from_it(
        self, six_subnets
    ):
        subject = _subject(leases6=[_lease("2001:db8:b::20", 8)], reservations6=[_res(8)])
        view = cs.authorize(subject, rule="per_object", accessible_ids={1})
        assert view.leases6 == [] and view.reservations6 == []
        assert view.mac == "" and view.mac_source == "" and view.device is None
        assert view.leases4 == [] and view.reservations == []
        assert view.duid == "", "a DUID found through a hidden lease is not the caller's to read"
        assert view.ip == "2001:db8:a::10", "only what the caller typed is left"
        assert not cs.names_a_subnet(view)

    def test_an_unpaired_v6_subnet_is_for_unrestricted_callers_only(self, six_subnets):
        subject = _subject(leases6=[_lease("2001:db8:c::30", 9)], reservations6=[])
        view = cs.authorize(subject, rule="per_object", accessible_ids={1, 2})
        assert view.leases6 == [] and view.mac == "" and not cs.names_a_subnet(view)

    def test_the_mac_is_taken_from_what_survived_never_from_a_lease_that_was_dropped(self, six_subnets):
        hidden = _lease("2001:db8:b::20", 8, mac="de:ad:be:ef:00:99", mac_source="hwaddr")
        shown = _lease("2001:db8:a::10", 7)  # no captured hwaddr: the DUID's own is all there is
        subject = _subject(leases6=[hidden, shown], mac="de:ad:be:ef:00:99", mac_source="hwaddr")
        view = cs.authorize(subject, rule="per_object", accessible_ids={1})
        assert view.mac == "aa:bb:cc:dd:ee:11" and view.mac_source == "duid"

    def test_a_typed_duid_whose_leases_are_hidden_keeps_the_mac_it_embeds_and_the_v4_side_it_finds_by_it(
        self, six_subnets
    ):
        subject = _subject(kind="duid", identifier=DUID_LL, leases6=[_lease("2001:db8:b::20", 8)], reservations6=[])
        view = cs.authorize(subject, rule="per_object", accessible_ids={1})
        assert view.leases6 == []
        assert view.mac == "aa:bb:cc:dd:ee:11" and view.mac_source == "duid"
        assert view.leases4, (
            "the caller can derive this MAC from the DUID they typed: their own subnets' v4 objects show"
        )

    def test_but_a_mac_that_only_a_hidden_lease_gave_is_not_kept(self, six_subnets):
        hidden = _lease("2001:db8:b::20", 8, mac="de:ad:be:ef:00:99", mac_source="hwaddr")
        subject = _subject(kind="duid", identifier=DUID_LL, leases6=[hidden], reservations6=[], mac="de:ad:be:ef:00:99")
        view = cs.authorize(subject, rule="per_object", accessible_ids={1})
        assert view.mac == "" and view.leases4 == [] and view.device is None

    def test_a_v4_object_in_a_hidden_subnet_is_still_judged_on_its_own(self, six_subnets):
        subject = _subject(leases4=[{"ip": "10.0.1.5", "subnet_id": 2, "hostname": "h"}])
        view = cs.authorize(subject, rule="per_object", accessible_ids={1})
        assert view.leases4 == [] and view.leases6, "the v6 side is visible, the v4 lease in subnet 2 is not"

    def test_found_counts_a_v6_only_subject(self):
        assert ClientSubject(kind="duid", leases6=[_lease("2001:db8::1", 7)]).found
        assert ClientSubject(kind="duid", reservations6=[_res(7)]).found
        assert not ClientSubject(kind="duid").found


class TestResolveWithStubbedLoaders:
    """resolve() for an IPv6 address or a DUID, with the database-backed loaders replaced by what they would return - the
    wiring (which loader gets what, how the MAC carries the subject on) is what is under test; the loaders themselves are
    exercised against real rows in the Route group."""

    MAC = "aa:bb:cc:dd:ee:11"

    @pytest.fixture
    def stubs(self, monkeypatch, six_subnets):
        monkeypatch.setattr(cs, "_v6_enabled", lambda: True)
        leases = [_lease("2001:db8:a::10", 7, duid=DUID_LL, mac=self.MAC, mac_source="duid", host="alpha6")]
        monkeypatch.setattr(
            cs,
            "load_leases6_for",
            lambda duid_hex="", address="": [
                lease
                for lease in leases
                if (duid_hex and lease["duid_hex"] == duid_hex) or (address and lease["address"] == address)
            ],
        )
        monkeypatch.setattr(
            cs,
            "load_reservations6",
            lambda duid_hex="", mac="", addresses=(): [_res(7)] if duid_hex == DUID_LL else [],
        )
        monkeypatch.setattr(
            cs,
            "load_device",
            lambda mac: (
                {"mac": mac, "last_subnet_id": 1, "last_hostname": "h", "last_ip": "10.0.0.5"}
                if mac == self.MAC
                else None
            ),
        )
        monkeypatch.setattr(
            cs,
            "load_leases4",
            lambda mac, ip="": [{"ip": "10.0.0.5", "subnet_id": 1, "hostname": "h"}] if mac == self.MAC else [],
        )
        monkeypatch.setattr(cs, "load_reservations4", lambda hw_hex="", cid_hex="": [])

    @pytest.mark.parametrize("typed", ["2001:db8:a::10", "2001:DB8:A:0:0:0:0:10"])
    def test_an_address_resolves_through_its_lease_to_the_duid_the_mac_and_the_v4_side(self, stubs, typed):
        s = cs.resolve(typed)
        assert s.kind == "ipv6" and s.duid == DUID_LL
        assert s.mac == self.MAC and s.mac_source == "duid"
        assert [a["address"] for a in s.leases6] == ["2001:db8:a::10"] and len(s.reservations6) == 1
        assert s.leases4 and s.device and s.ip == "10.0.0.5" and s.hostname == "h"
        assert s.subnet_ids == {1}, "the v4 subnet of its v4 lease and the one its v6 subnet is paired with"
        assert s.found

    @pytest.mark.parametrize("typed", [f"duid:{DUID_LL}", DUID_LL, DUID_LL.upper()])
    def test_a_duid_resolves_the_same_client(self, stubs, typed):
        s = cs.resolve(typed)
        assert s.kind == "duid" and s.duid == DUID_LL and s.mac == self.MAC and s.leases4 and s.leases6

    def test_a_duid_en_has_its_v6_facts_and_no_v4_side(self, stubs, monkeypatch):
        monkeypatch.setattr(
            cs, "load_leases6_for", lambda duid_hex="", address="": [_lease("2001:db8:a::99", 7, duid=DUID_EN)]
        )
        s = cs.resolve(f"duid:{DUID_EN}")
        assert s.mac == "" and s.mac_source == "" and s.leases4 == [] and s.device is None
        assert s.found and s.leases6[0]["address"] == "2001:db8:a::99"

    def test_an_unknown_address_is_an_empty_subject(self, stubs):
        s = cs.resolve("2001:db8:a::ffff")
        assert not s.found and s.duid == "" and s.mac == "" and s.ip == "2001:db8:a::ffff"

    def test_with_ipv6_off_nothing_is_looked_up(self, stubs, monkeypatch):
        monkeypatch.setattr(cs, "_v6_enabled", lambda: False)
        called = []
        monkeypatch.setattr(cs, "load_leases6_for", lambda **kw: called.append(kw) or [])
        s = cs.resolve("2001:db8:a::10")
        assert not s.found and called == [] and s.ip == "2001:db8:a::10"

    def test_a_reserved_address_nobody_holds_names_its_duid_through_the_reservation(self, stubs, monkeypatch):
        monkeypatch.setattr(cs, "load_leases6_for", lambda duid_hex="", address="": [])
        monkeypatch.setattr(
            cs,
            "load_reservations6",
            lambda duid_hex="", mac="", addresses=(): [_res(7)] if addresses or duid_hex else [],
        )
        s = cs.resolve("2001:db8:a::10")
        assert s.duid == DUID_LL and s.mac == self.MAC and len(s.reservations6) == 1 and s.leases6 == []


class TestTheAlertMatcherKnowsV6Tokens:
    def test_an_address_matches_as_a_whole_token_only(self):
        from jen.routes.client import _alert_matcher

        m = _alert_matcher("", "", ["2001:db8::1"])
        assert m.search("lease for 2001:db8::1 renewed") and m.search("2001:DB8::1.")
        assert not m.search("lease for 2001:db8::10 renewed"), "a longer address is not this one"
        assert not m.search("lease for 12001:db8::1 renewed") and not m.search("2001:db8::1:5")

    def test_v4_and_v6_tokens_and_the_mac_can_all_be_asked_for_at_once(self):
        from jen.routes.client import _alert_matcher

        m = _alert_matcher("aa:bb:cc:dd:ee:11", "10.0.0.5", ["2001:db8::1", "2001:db8::1"])
        assert m.search("MAC aa:bb:cc:dd:ee:11") and m.search("IP 10.0.0.5") and m.search("2001:db8::1")
        assert not m.search("10.0.0.50")
        assert _alert_matcher("", "", []) is None


# ── Route tests (need the unit suite's database) ────────────────────────────────

A_MAC, A_MAC_HEX = "aa:bb:cc:dd:ee:11", "AABBCCDDEE11"
B_MAC, B_MAC_HEX = "bb:cc:dd:ee:ff:22", "BBCCDDEEFF22"
DUID_B = "00030001bbccddeeff22"
CAPTURED_MAC = "de:ad:be:ef:00:44"
DUID_C = "00020000ab0c1122334466"  # DUID-EN with a hwaddr Kea captured


@pytest.fixture
def v6world(db, monkeypatch, six_subnets):
    from jen.models.user import _invalidate_settings_cache, set_global_setting

    monkeypatch.setattr("jen.routes.client.dhcp4_config", lambda force=False: None)
    monkeypatch.setattr(
        extensions,
        "SUBNET_MAP",
        {1: {"name": "Alpha-A", "cidr": "10.0.0.0/24"}, 2: {"name": "Bravo-B", "cidr": "10.0.1.0/24"}},
    )
    set_global_setting("ipv6_enabled", "true")
    _invalidate_settings_cache()
    _wipe(db)
    with db.cursor() as cur:
        for mac_hex, ip, subnet in ((A_MAC_HEX, "10.0.0.5", 1), (B_MAC_HEX, "10.0.1.5", 2)):
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state, hostname) VALUES "
                "(inet_aton(%s), UNHEX(%s), %s, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0, %s)",
                (ip, mac_hex, subnet, f"v4-{subnet}"),
            )
        cur.execute(
            "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) VALUES "
            "(%s, '10.0.0.5', 'v4-1', 1, NOW(), NOW()), (%s, '10.0.1.5', 'v4-2', 2, NOW(), NOW())",
            (A_MAC, B_MAC),
        )
        # A (subnet 7 -> A), B (subnet 8 -> B), C (unpaired subnet 9, hardware address captured by Kea)
        for address, duid, subnet, host, hwaddr in (
            ("2001:db8:a::10", DUID_LL, 7, "alpha6", None),
            ("2001:db8:b::20", DUID_B, 8, "bravo6", None),
            ("2001:db8:c::30", DUID_C, 9, "charlie6", bytes.fromhex(CAPTURED_MAC.replace(":", ""))),
        ):
            cur.execute(
                "INSERT INTO lease6 (address, duid, valid_lifetime, expire, subnet_id, pref_lifetime, lease_type, iaid, "
                "prefix_len, hostname, hwaddr, state) VALUES (%s, %s, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), %s, 1800, "
                "0, 1, 128, %s, %s, 0)",
                (packed(address), bytes.fromhex(duid), subnet, host, hwaddr),
            )
        # A's v6 reservation: an address and a delegated prefix with an excluded prefix
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp6_subnet_id, hostname) VALUES (%s, 1, 7, 'alpha6-res')",
            (bytes.fromhex(DUID_LL),),
        )
        host_id = cur.lastrowid
        cur.execute(
            "INSERT INTO ipv6_reservations (address, prefix_len, type, dhcp6_iaid, host_id, excluded_prefix, "
            "excluded_prefix_len) VALUES (%s, 128, 0, 1, %s, NULL, 0), (%s, 56, 2, 1, %s, %s, 64)",
            (packed("2001:db8:a::10"), host_id, packed("2001:db8:a:1000::"), host_id, packed("2001:db8:a:1000:ff00::")),
        )
    db.commit()
    yield
    _wipe(db)


def _wipe(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease6")
        cur.execute("DELETE FROM ipv6_reservations")
        cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN (%s, %s)", (A_MAC_HEX, B_MAC_HEX))
        cur.execute("DELETE FROM devices WHERE mac IN (%s, %s)", (A_MAC, B_MAC))
    db.commit()


class TestRouteAnIpv6AddressOrADuid:
    @pytest.mark.parametrize("typed", ["2001:db8:a::10", "2001:DB8:A:0:0:0:0:10", f"duid:{DUID_LL}", DUID_LL])
    def test_every_spelling_finds_the_same_client(self, logged_in_client, v6world, typed):
        body = logged_in_client.get("/client", query_string={"q": typed}).data.decode()
        assert "No client matched" not in body
        assert "2001:db8:a::10" in body and DUID_LL in body
        assert A_MAC in body and "(read from the DUID)" in body, "the MAC is Jen's reading of the DUID, and says so"
        assert "10.0.0.5" in body, "the v4 side of the same client, found through the MAC"

    def test_the_overview_shows_the_v6_lease_and_the_reservation_with_its_excluded_prefix(
        self, logged_in_client, v6world
    ):
        body = logged_in_client.get("/client", query_string={"q": "2001:db8:a::10"}).data.decode()
        assert "IPv6 address" in body and "alpha6" in body
        assert "2001:db8:a:1000::/56" in body and "excluding 2001:db8:a:1000:ff00::/64" in body

    def test_a_mac_kea_captured_is_labelled_as_captured(self, logged_in_client, v6world):
        body = logged_in_client.get("/client", query_string={"q": "2001:db8:c::30"}).data.decode()
        assert CAPTURED_MAC in body and "(captured by Kea)" in body and "read from the DUID" not in body

    def test_the_dhcp4_tabs_say_what_they_evaluate(self, logged_in_client, v6world):
        body = logged_in_client.get("/client", query_string={"q": "2001:db8:a::10", "tab": "explain"}).data.decode()
        assert "This tab evaluates DHCPv4, for the MAC aa:bb:cc:dd:ee:11" in body

    def test_a_client_with_no_ipv4_identity_says_so_on_every_dhcp4_tab(self, logged_in_client, v6world, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease6 (address, duid, valid_lifetime, expire, subnet_id, pref_lifetime, lease_type, iaid, "
                "prefix_len, hostname, hwaddr, state) VALUES (%s, %s, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 7, 1800, 0, "
                "1, 128, 'en-only', NULL, 0)",
                (packed("2001:db8:a::99"), bytes.fromhex(DUID_EN)),
            )
        db.commit()
        for tab in ("explain", "trace", "config"):
            body = logged_in_client.get("/client", query_string={"q": "2001:db8:a::99", "tab": tab}).data.decode()
            assert "this client has no IPv4 identity Jen can see" in body, tab
        timeline = logged_in_client.get(
            "/client", query_string={"q": "2001:db8:a::99", "tab": "timeline"}
        ).data.decode()
        assert "follows a MAC or an IPv4 address" in timeline

    def test_an_unknown_address_is_no_client(self, logged_in_client, v6world):
        body = logged_in_client.get("/client", query_string={"q": "2001:db8:a::ffff"}).data.decode()
        assert "No client matched" in body

    def test_a_reserved_address_nobody_holds_resolves_through_its_reservation(self, logged_in_client, v6world, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6 WHERE hostname='alpha6'")
        db.commit()
        body = logged_in_client.get("/client", query_string={"q": "2001:db8:a::10"}).data.decode()
        assert "No client matched" not in body and DUID_LL in body and "alpha6-res" in body

    def test_with_ipv6_off_the_page_says_why_and_looks_nothing_up(self, logged_in_client, v6world):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "false")
        _invalidate_settings_cache()
        body = logged_in_client.get("/client", query_string={"q": "2001:db8:a::10"}).data.decode()
        assert "IPv6 is turned off in Jen" in body and DUID_LL not in body and A_MAC not in body

    def test_a_plain_mac_subject_is_unchanged_by_all_of_this(self, logged_in_client, v6world):
        body = logged_in_client.get("/client", query_string={"q": A_MAC}).data.decode()
        assert "10.0.0.5" in body and "(read from the DUID)" not in body
        assert '<div class="stat-label">DUID</div>' not in body, "a MAC subject shows no DUID row"


class TestRouteTheScopeOfAV6Subject:
    def _admin_a(self, client, db, name):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="admin", username=name)
        return client

    def test_a_restricted_admin_sees_a_client_whose_v6_subnet_is_paired_to_theirs(self, client, db, v6world):
        c = self._admin_a(client, db, "_v6_scope_a")
        body = c.get("/client", query_string={"q": "2001:db8:a::10"}).data.decode()
        assert "alpha6" in body and A_MAC in body

    @pytest.mark.parametrize(
        "typed",
        ["2001:db8:b::20", f"duid:{DUID_B}", "2001:db8:c::30"],
        ids=["paired-to-hidden", "typed-duid", "unpaired"],
    )
    def test_nothing_of_a_client_in_a_subnet_they_may_not_see(self, client, db, v6world, typed):
        c = self._admin_a(client, db, "_v6_scope_b")
        body = c.get("/client", query_string={"q": typed}).data.decode()
        assert "No client matched" in body
        for secret in ("bravo6", "charlie6", B_MAC, "10.0.1.5", CAPTURED_MAC, "Bravo-B", "SecretNet"):
            assert secret not in body, f"{secret!r} leaked through {typed}"

    def test_the_changes_tab_never_appears_for_them(self, client, db, v6world):
        c = self._admin_a(client, db, "_v6_scope_c")
        assert "tab=changes" not in c.get("/client", query_string={"q": "2001:db8:a::10"}).data.decode()


class TestRouteTheSearchBoxAndItsV6Rows:
    def test_an_ipv6_address_or_a_duid_goes_straight_to_the_client_page_when_ipv6_is_on(
        self, logged_in_client, v6world
    ):
        for typed in ("2001:db8:a::10", f"duid:{DUID_LL}", DUID_LL):
            assert logged_in_client.get("/search", query_string={"q": typed}).status_code == 302, typed

    def test_with_ipv6_off_the_results_page_is_what_it_always_was(self, logged_in_client, v6world):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "false")
        _invalidate_settings_cache()
        assert logged_in_client.get("/search", query_string={"q": "2001:db8:a::10"}).status_code == 200

    def test_the_v6_result_rows_carry_the_link(self, logged_in_client, v6world):
        body = logged_in_client.get("/search", query_string={"q": "alpha6", "list": "1"}).data.decode()
        # Kea's own HEX() is upper case; the Investigation page accepts either
        assert "IPv6 Leases" in body and f"q=duid%3A{DUID_LL.upper()}" in body
