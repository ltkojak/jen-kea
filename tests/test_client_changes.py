"""
tests/test_client_changes.py
────────────────────────────
v5.68.0-beta.1 (Q134 c) — the Investigation page's Changes tab: the Kea config revisions that touched ONE client's path.

The first groups are pure (they run without a database: `pytest --noconftest tests/test_client_changes.py -k "not Route"`):
what is on a client's path in one config, what a diff of two configs keeps, the walk over a window of revisions — three
seeded revisions of which only ONE touches the client's subnet — and the COST of that walk, measured on every run
because the module docstring promises a number. The Route group drives the real tab against real revisions and enforces
the config-history page's own access rule (an admin who may see every subnet; nobody else even gets the tab).
"""

import copy
import json
import time

import pytest

from jen import extensions
from jen.services import client_changes as cc
from jen.services.client_subject import ClientSubject

MAC = "aa:bb:cc:dd:ee:ff"
LEASE_IP = "10.0.0.120"


def _config(
    *, dns="10.0.0.53", pool_end=200, own_res_dns="9.9.9.9", neighbour_res_dns="8.8.4.4", subnet2_dns="1.1.1.1"
):
    """A Dhcp4 config with a shared network holding subnet 1 (our client's: a pool it is in, a pool it is not in, its own
    reservation and a neighbour's) and a subnet 2 beside it, a class that guards the second pool, and a global option."""
    return {
        "Dhcp4": {
            "valid-lifetime": 3600,
            "option-data": [{"name": "domain-name", "data": "lan.example"}],
            "client-classes": [
                {"name": "voip", "test": "substring(option[60].hex,0,4) == 'Cisc'"},
                {"name": "unrelated", "test": "member('ALL')"},
            ],
            "shared-networks": [
                {
                    "name": "campus",
                    "option-data": [{"name": "routers", "data": "10.0.0.1"}],
                    "subnet4": [
                        {
                            "id": 1,
                            "subnet": "10.0.0.0/24",
                            "option-data": [{"name": "domain-name-servers", "data": dns}],
                            "pools": [
                                {"pool": f"10.0.0.100 - 10.0.0.{pool_end}"},
                                {"pool": "10.0.0.201 - 10.0.0.250", "client-class": "voip"},
                            ],
                            "reservations": [
                                {
                                    "hw-address": MAC,
                                    "ip-address": "10.0.0.50",
                                    "option-data": [{"name": "domain-name-servers", "data": own_res_dns}],
                                },
                                {
                                    "hw-address": "11:22:33:44:55:66",
                                    "ip-address": "10.0.0.51",
                                    "option-data": [{"name": "domain-name-servers", "data": neighbour_res_dns}],
                                },
                            ],
                        }
                    ],
                }
            ],
            "subnet4": [
                {
                    "id": 2,
                    "subnet": "10.0.1.0/24",
                    "option-data": [{"name": "domain-name-servers", "data": subnet2_dns}],
                    "pools": [{"pool": "10.0.1.100 - 10.0.1.200"}],
                }
            ],
        }
    }


def _view(**kw):
    base = {
        "kind": "mac",
        "identifier": MAC,
        "mac": MAC,
        "ip": LEASE_IP,
        "leases4": [{"ip": LEASE_IP, "subnet_id": 1, "hostname": "tv"}],
        "reservations": [{"ip": "10.0.0.50", "subnet_id": 1, "hostname": "tv"}],
        "subnet_ids": frozenset({1}),
        **kw,
    }
    return ClientSubject(**base)


PATH = cc.path_for(_view(), "dhcp4", {1: {"cidr": "10.0.0.0/24"}, 2: {"cidr": "10.0.1.0/24"}}, {}, classes=())


class TestThePath:
    def test_a_mac_client_in_subnet_1(self):
        assert PATH.service == "dhcp4"
        assert PATH.subnet_ids == {1} and PATH.cidrs == {"10.0.0.0/24"}
        assert PATH.identifiers == {"aabbccddeeff"}
        assert PATH.addresses == {LEASE_IP, "10.0.0.50"}

    def test_a_v6_client_is_keyed_by_duid_and_its_v6_subnet(self):
        view = _view(
            kind="duid",
            identifier="x",
            duid="00030001aabbccddeeff",
            leases4=[],
            reservations=[],
            leases6=[{"address": "2001:db8::10", "subnet_id": 7}],
            reservations6=[
                {
                    "subnet_id": 7,
                    "duid_hex": "00030001AABBCCDDEEFF",
                    "reservations": [{"address": "2001:db8:1000::"}],
                }
            ],
        )
        path = cc.path_for(view, "dhcp6", {}, {7: {"cidr": "2001:db8::/64"}})
        assert path.subnet_ids == {7} and path.cidrs == {"2001:db8::/64"}
        assert {"00030001aabbccddeeff", "aabbccddeeff"} == path.identifiers
        assert path.addresses == {"2001:db8::10", "2001:db8:1000::"}

    def test_an_unplaced_client_has_an_empty_path(self):
        assert cc.path_for(
            _view(leases4=[], reservations=[], mac="", subnet_ids=frozenset()), "dhcp4", {}, {}
        ).is_empty()


class TestWhatIsOnThePath:
    def test_the_subnet_its_shared_network_the_pool_it_is_in_and_its_own_reservation(self):
        labels = set(cc.extract(_config(), PATH))
        assert labels == {
            "subnet 1 (10.0.0.0/24)",
            "shared network campus",
            "pool 10.0.0.100 - 10.0.0.200",
            f"reservation {MAC}",
        }

    def test_nothing_of_a_neighbour_a_pool_it_is_not_in_the_other_subnet_or_a_global_option(self):
        out = cc.extract(_config(), PATH)
        blob = json.dumps(out)
        assert "11:22:33:44:55:66" not in blob, "a neighbour's reservation is not on this client's path"
        assert "10.0.0.201" not in blob and "10.0.1." not in blob and "lan.example" not in blob

    def test_the_subnets_own_element_carries_no_pools_or_reservations(self):
        element = cc.extract(_config(), PATH)["subnet 1 (10.0.0.0/24)"]
        assert "pools" not in element and "reservations" not in element
        assert element["option-data"][0]["data"] == "10.0.0.53"

    def test_a_class_joins_the_path_when_the_client_matches_it_or_a_pool_on_the_path_names_it(self):
        assert "class voip" not in cc.extract(_config(), PATH)
        matched = cc.path_for(_view(), "dhcp4", {1: {"cidr": "10.0.0.0/24"}}, {}, classes=("voip",))
        assert "class voip" in cc.extract(_config(), matched)
        assert "class unrelated" not in cc.extract(_config(), matched)
        guarded = copy.deepcopy(_config())
        pools = guarded["Dhcp4"]["shared-networks"][0]["subnet4"][0]["pools"]
        pools[0]["client-class"] = "voip"  # the pool the client is in is now guarded by it
        assert "class voip" in cc.extract(guarded, PATH)

    def test_a_subnet_is_found_by_its_cidr_when_its_id_was_renumbered(self):
        renumbered = copy.deepcopy(_config())
        renumbered["Dhcp4"]["shared-networks"][0]["subnet4"][0]["id"] = 41
        assert "subnet 41 (10.0.0.0/24)" in cc.extract(renumbered, PATH)

    def test_with_no_address_yet_every_pool_of_the_subnet_is_kept(self):
        # the device row alone placed it in subnet 1: no lease, no reservation, so no address to pick a pool by
        no_lease = cc.ClientPath(service="dhcp4", subnet_ids=frozenset({1}), identifiers=frozenset({"aabbccddeeff"}))
        pools = {label for label in cc.extract(_config(), no_lease) if label.startswith("pool ")}
        assert pools == {"pool 10.0.0.100 - 10.0.0.200", "pool 10.0.0.201 - 10.0.0.250"}

    def test_a_global_reservation_is_on_the_path(self):
        cfg = copy.deepcopy(_config())
        cfg["Dhcp4"]["reservations"] = [{"hw-address": MAC.upper(), "ip-address": "10.0.0.50"}]
        assert f"global reservation {MAC.upper()}" in cc.extract(cfg, PATH)

    def test_an_unwrapped_or_malformed_config_never_raises(self):
        inner = _config()["Dhcp4"]
        assert "subnet 1 (10.0.0.0/24)" in cc.extract(inner, PATH)
        for junk in (None, [], "text", {"Dhcp4": None}, {"Dhcp4": {"subnet4": [None, 3, {"id": "x"}]}}):
            assert cc.extract(junk, PATH) == {}


class TestDiffingTwoConfigs:
    def _changes(self, **after):
        return {c["label"]: c for c in cc.diff_paths(_config(), _config(**after), PATH)}

    def test_a_change_to_the_subnets_option_is_one_changed_hunk_with_only_its_own_lines(self):
        changes = self._changes(dns="10.0.0.99")
        assert list(changes) == ["subnet 1 (10.0.0.0/24)"]
        change = changes["subnet 1 (10.0.0.0/24)"]
        assert change["kind"] == "changed"
        assert any(line.startswith("-") and "10.0.0.53" in line for line in change["lines"])
        assert any(line.startswith("+") and "10.0.0.99" in line for line in change["lines"])
        assert not any(line.startswith(("---", "+++")) for line in change["lines"])

    def test_a_change_to_the_clients_own_reservation_is_on_the_path(self):
        assert list(self._changes(own_res_dns="4.4.4.4")) == [f"reservation {MAC}"]

    @pytest.mark.parametrize("after", [{"neighbour_res_dns": "4.4.4.4"}, {"subnet2_dns": "4.4.4.4"}])
    def test_a_neighbours_reservation_or_the_other_subnet_is_not(self, after):
        assert self._changes(**after) == {}

    def test_a_pool_that_moves_is_one_removed_and_one_added(self):
        changes = self._changes(pool_end=210)
        assert {label: c["kind"] for label, c in changes.items()} == {
            "pool 10.0.0.100 - 10.0.0.200": "removed",
            "pool 10.0.0.100 - 10.0.0.210": "added",
        }

    def test_a_subnet_that_appears_or_disappears(self):
        gone = copy.deepcopy(_config())
        gone["Dhcp4"]["shared-networks"][0]["subnet4"] = []
        kinds = {c["label"]: c["kind"] for c in cc.diff_paths(_config(), gone, PATH)}
        assert kinds["subnet 1 (10.0.0.0/24)"] == "removed" and kinds[f"reservation {MAC}"] == "removed"
        assert {c["kind"] for c in cc.diff_paths(gone, _config(), PATH)} == {"added"}

    def test_identical_configs_have_no_changes(self):
        assert cc.diff_paths(_config(), _config(), PATH) == []

    def test_a_secret_in_the_path_is_masked(self):
        before, after = _config(), copy.deepcopy(_config())
        before["Dhcp4"]["shared-networks"][0]["subnet4"][0]["user-context"] = {"password": "old-secret"}
        after["Dhcp4"]["shared-networks"][0]["subnet4"][0]["user-context"] = {"password": "new-secret"}
        out = json.dumps(cc.diff_paths(before, after, PATH))
        assert "old-secret" not in out and "new-secret" not in out

    def test_a_long_diff_is_capped_and_the_rest_counted(self):
        before, after = _config(), copy.deepcopy(_config())
        subnet = after["Dhcp4"]["shared-networks"][0]["subnet4"][0]
        subnet["option-data"] = [{"name": f"opt{i}", "data": str(i)} for i in range(100)]
        (change,) = [c for c in cc.diff_paths(before, after, PATH) if c["label"].startswith("subnet 1")]
        assert len(change["lines"]) == cc.MAX_LINES and change["more"] > 0


def _rows(*configs):
    """Revision rows newest first, as `config_revisions.recent_with_config` returns them (config already decrypted)."""
    n = len(configs)
    return [
        {
            "id": n - i,
            "created_at": None,
            "summary": f"rev {n - i}",
            "username": "admin",
            "source": "jen",
            "config": json.dumps(c),
        }
        for i, c in enumerate(configs)
    ]


class TestTheWalkOverRevisions:
    def test_of_three_revisions_only_the_one_that_touches_the_clients_subnet_is_kept(self):
        base = _config()
        touches_subnet_2_only = _config(subnet2_dns="4.4.4.4")
        touches_subnet_1 = _config(subnet2_dns="4.4.4.4", dns="10.0.0.99")
        # newest first: r3 changes subnet 1's DNS, r2 changes only subnet 2, r1 is the baseline
        out = cc.changes_for_revisions(_rows(touches_subnet_1, touches_subnet_2_only, base), PATH)
        assert out["scanned"] == 2 and out["oldest_unpaired"] is True
        assert [r["id"] for r in out["revisions"]] == [3]
        assert out["revisions"][0]["summary"] == "rev 3" and out["revisions"][0]["changes"][0]["label"].startswith(
            "subnet 1"
        )

    def test_a_single_revision_has_nothing_to_compare_with(self):
        assert cc.changes_for_revisions(_rows(_config()), PATH)["scanned"] == 0
        assert cc.changes_for_revisions([], PATH) == {"scanned": 0, "revisions": [], "oldest_unpaired": True}

    def test_only_the_newest_window_is_compared_and_a_full_window_is_not_unpaired(self):
        configs = [_config(dns=f"10.0.0.{i}") for i in range(10, 0, -1)]  # ten revisions, each a change
        out = cc.changes_for_revisions(_rows(*configs), PATH, limit=4)
        assert out["scanned"] == 4 and out["oldest_unpaired"] is False
        assert [r["id"] for r in out["revisions"]] == [10, 9, 8, 7]

    def test_an_unparseable_revision_is_skipped_not_fatal(self):
        rows = _rows(_config(dns="10.0.0.99"), _config(), _config(dns="10.0.0.7"))
        rows[1]["config"] = "{not json"
        assert cc.changes_for_revisions(rows, PATH)["revisions"] == []


class TestTheCost:
    """The module docstring says what this costs; this measures the pure part on every run. The bound is deliberately
    generous (a slow CI runner is several times a dev box) — it exists to catch an accidental O(n^2), not to be a benchmark."""

    def test_fifty_revisions_of_a_two_hundred_subnet_config(self):
        big = _config()
        for sid in range(100, 300):
            big["Dhcp4"]["subnet4"].append(
                {
                    "id": sid,
                    "subnet": f"10.{sid // 256}.{sid % 256}.0/24",
                    "option-data": [{"name": "domain-name-servers", "data": "10.0.0.53"}],
                    "pools": [{"pool": f"10.{sid // 256}.{sid % 256}.10 - 10.{sid // 256}.{sid % 256}.250"}],
                    "reservations": [
                        {
                            "hw-address": f"02:00:00:00:{sid:02x}:{i:02x}",
                            "ip-address": f"10.{sid // 256}.{sid % 256}.{i + 2}",
                        }
                        for i in range(20)
                    ],
                }
            )
        configs = []
        for i in range(51):
            c = copy.deepcopy(big)
            c["Dhcp4"]["subnet4"][-1]["option-data"][0]["data"] = f"10.9.9.{i}"
            if i % 10 == 0:
                c["Dhcp4"]["shared-networks"][0]["subnet4"][0]["option-data"][0]["data"] = f"10.0.0.{i}"
            configs.append(c)
        rows = _rows(*configs)
        start = time.perf_counter()
        out = cc.changes_for_revisions(rows, PATH)
        elapsed = time.perf_counter() - start
        print(f"\nclient_changes: 51 revisions x {len(rows[0]['config']) // 1024} KB walked in {elapsed:.2f}s")
        # every revision whose neighbour differs on subnet 1's option: i = 0, 9, 10, 19, 20, 29, 30, 39, 40, 49
        assert out["scanned"] == 50 and len(out["revisions"]) == 10
        assert elapsed < 3.0, f"the Changes tab walk took {elapsed:.1f}s - the docstring promises about a second"


# ── Route tests (need the unit suite's database) ────────────────────────────────

B_MAC, B_HEX = "de:ad:be:ef:22:bb", "DEADBEEF22BB"


@pytest.fixture
def servers(db, monkeypatch):
    monkeypatch.setattr("jen.routes.client.dhcp4_config", lambda force=False: None)  # no Kea to ask for matched classes
    monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}])
    monkeypatch.setattr(
        extensions,
        "SUBNET_MAP",
        {1: {"name": "Alpha-A", "cidr": "10.0.0.0/24"}, 2: {"name": "Bravo-B", "cidr": "10.0.1.0/24"}},
    )
    _clean(db)
    yield
    _clean(db)


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM kea_config_revisions")
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", ("AABBCCDDEEFF",))
        cur.execute("DELETE FROM devices WHERE mac=%s", (MAC,))
    db.commit()


def _revision(cfg, summary, source="jen"):
    from jen.services import config_revisions as rev

    return rev.record(1, "dhcp4", cfg, "sha-" + summary, summary, hash_kind="canonical", source=source)


@pytest.fixture
def three_revisions(db, servers):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
            "(inet_aton(%s), UNHEX('AABBCCDDEEFF'), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)",
            (LEASE_IP,),
        )
        cur.execute("INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES (%s, %s, 1)", (MAC, LEASE_IP))
    db.commit()
    _revision(_config(), "baseline", source="baseline")
    _revision(_config(subnet2_dns="4.4.4.4"), "only the bravo subnet")
    _revision(_config(subnet2_dns="4.4.4.4", dns="10.0.0.99"), "alpha dns moved")


class TestRouteTheChangesTab:
    def test_an_unrestricted_admin_sees_only_the_revision_that_touched_the_clients_subnet(
        self, logged_in_client, three_revisions
    ):
        body = logged_in_client.get(f"/client?q={MAC}&tab=changes").data.decode()
        assert "alpha dns moved" in body and "10.0.0.99" in body
        assert "only the bravo subnet" not in body and "4.4.4.4" not in body
        assert "subnet 1 (10.0.0.0/24)" in body
        assert "1 revision compared" not in body and "2 revisions compared" in body

    def test_the_tab_is_offered_to_an_unrestricted_admin(self, logged_in_client, three_revisions):
        assert "tab=changes" in logged_in_client.get(f"/client?q={MAC}").data.decode()

    def test_a_restricted_admin_does_not_get_the_tab_and_cannot_ask_for_it(self, client, db, three_revisions):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="admin", username="_changes_admin")
        page = client.get(f"/client?q={MAC}").data.decode()
        assert "tab=changes" not in page
        forced = client.get(f"/client?q={MAC}&tab=changes").data.decode()
        assert "alpha dns moved" not in forced and "10.0.0.99" not in forced

    def test_a_viewer_does_not_get_it_either(self, client, db, three_revisions):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=None, role="viewer", username="_changes_viewer")
        assert "tab=changes" not in client.get(f"/client?q={MAC}").data.decode()
        assert "alpha dns moved" not in client.get(f"/client?q={MAC}&tab=changes").data.decode()

    def test_no_revisions_at_all_says_so(self, logged_in_client, servers, db):
        with db.cursor() as cur:
            cur.execute("INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES (%s, %s, 1)", (MAC, LEASE_IP))
        db.commit()
        body = logged_in_client.get(f"/client?q={MAC}&tab=changes").data.decode()
        assert "No earlier revision to compare against" in body

    def test_an_undecryptable_revision_is_its_own_message_not_a_500(self, logged_in_client, three_revisions, db):
        with db.cursor() as cur:
            cur.execute("UPDATE kea_config_revisions SET config='v1:not-a-real-token'")
        db.commit()
        r = logged_in_client.get(f"/client?q={MAC}&tab=changes")
        assert r.status_code == 200
        assert "alpha dns moved" not in r.data.decode()


class TestRouteTheElementFilter:
    """v5.68.0-beta.2 (Q135): an Explain verdict links here filtered to the config element it names."""

    def test_the_subnet_the_revision_changed_shows_and_says_it_is_filtered(self, logged_in_client, three_revisions):
        element = "subnet 1 (10.0.0.0/24)"
        body = logged_in_client.get(
            "/client", query_string={"q": MAC, "tab": "changes", "element": element}
        ).data.decode()
        assert "alpha dns moved" in body and "Showing only the changes to" in body

    def test_an_element_nothing_changed_hides_the_revision(self, logged_in_client, three_revisions):
        body = logged_in_client.get(
            "/client", query_string={"q": MAC, "tab": "changes", "element": "pool 10.0.0.100 - 10.0.0.200"}
        ).data.decode()
        assert "alpha dns moved" not in body and "Showing only the changes to" in body
        assert "None of those revisions changed anything" in body

    def test_a_kind_alone_matches_every_element_of_it(self, logged_in_client, three_revisions):
        body = logged_in_client.get(
            "/client", query_string={"q": MAC, "tab": "changes", "element": "subnet"}
        ).data.decode()
        assert "alpha dns moved" in body

    def test_no_filter_is_the_whole_path(self, logged_in_client, three_revisions):
        body = logged_in_client.get("/client", query_string={"q": MAC, "tab": "changes"}).data.decode()
        assert "alpha dns moved" in body and "Showing only the changes to" not in body
