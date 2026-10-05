"""
tests/test_ipv6_access.py
──────────────────────────
v5.68.0-beta.8 (Q143) — ONE IPv6 access rule (jen/services/access.py: `subnet6_visible`, `can_access_subnet6`, `accessible_subnet6_map`,
`assert_subnet6_access`) and every IPv6 surface on it. A user's scope is a list of IPv4 subnet ids; a v6 subnet is judged through the v4
subnet it is paired with, never by comparing its own id with that list, and an unpaired v6 subnet is for unrestricted users only. The review
that found this (ChatGPT, beta.7, item 1) listed the surfaces that did not: a forbidden explicit `?subnet=` fell back to "all" - and "all"
was never filtered; delete-reservation6 and the three edit-subnet6 routes checked nothing about the user; add-reservation6 compared v6 keys
with v4 ids; the Subnets page and the dashboard totalled every v6 subnet; every template was handed the whole map.

The topology (v4 subnets 1, 2, 3; the scoped users see v4 subnets 1 and 2):

    v6 10 -> paired 1   id differs from its pairing                          scoped: ALLOW
    v6  3 -> paired 2   id equals a DENIED v4 id, paired with an allowed one  scoped: ALLOW
    v6  2 -> paired 3   id equals an ALLOWED v4 id, paired with a denied one  scoped: DENY
    v6  1 -> unpaired   id equals an allowed v4 id, but unpaired              scoped: DENY
    v6  5 -> unpaired                                                         scoped: DENY

for a scoped viewer, a scoped admin, an unrestricted admin and a superadmin. The first class is pure (`--noconftest`); the rest run against
the real test database with `ipv6_enabled` on and assert, besides status codes, that a hidden v6 subnet's name, CIDR, addresses and hostnames
appear in no page's HTML (the rule-7 absence assertions).
"""

import types

import pytest
from werkzeug.exceptions import NotFound

from jen import extensions
from jen.services import access

V4 = {
    1: {"name": "LAN-A", "cidr": "192.168.1.0/24"},
    2: {"name": "LAN-B", "cidr": "192.168.2.0/24"},
    3: {"name": "LAN-C", "cidr": "192.168.3.0/24"},
}
V6 = {
    10: {"name": "V6-ALLOWED-PAIRED-10", "cidr": "2001:db8:a10::/64", "paired_subnet4_id": 1},
    3: {"name": "V6-ALLOWED-IDDENIED-3", "cidr": "2001:db8:a3::/64", "paired_subnet4_id": 2},
    2: {"name": "V6-HIDDEN-IDMATCH-2", "cidr": "2001:db8:a2::/64", "paired_subnet4_id": 3},
    1: {"name": "V6-HIDDEN-UNPAIRED-1", "cidr": "2001:db8:a1::/64", "paired_subnet4_id": None},
    5: {"name": "V6-HIDDEN-UNPAIRED-5", "cidr": "2001:db8:a5::/64", "paired_subnet4_id": None},
}
SCOPE = [1, 2]
ALLOWED6 = {10, 3}
HIDDEN6 = {2, 1, 5}


@pytest.fixture
def topology(monkeypatch):
    monkeypatch.setattr(extensions, "SUBNET_MAP", dict(V4))
    monkeypatch.setattr(extensions, "SUBNET6_MAP", {k: dict(v) for k, v in V6.items()})


def _user(scope, authenticated=True):
    """A stand-in for flask_login's current_user as access.py reads it."""
    all_subnets = scope is None
    return types.SimpleNamespace(
        is_authenticated=authenticated,
        all_subnets=all_subnets,
        accessible_subnet_ids=lambda subnet_map: [k for k in subnet_map if all_subnets or k in (scope or [])],
    )


class TestThePolicy:
    @pytest.mark.parametrize("sid", sorted(ALLOWED6))
    def test_a_paired_subnet_follows_its_v4_pairing(self, topology, sid):
        assert access.subnet6_visible(sid, SCOPE) is True

    @pytest.mark.parametrize("sid", sorted(HIDDEN6))
    def test_a_denied_pairing_and_an_unpaired_subnet_are_not_visible_to_a_scoped_user(self, topology, sid):
        assert access.subnet6_visible(sid, SCOPE) is False

    def test_the_v6_id_is_never_compared_with_the_v4_list(self, topology):
        # v6 2 shares its id with an ALLOWED v4 subnet, v6 3 with a denied one: the answers are the opposite of an id comparison
        assert access.subnet6_visible(2, SCOPE) is False and access.subnet6_visible(3, SCOPE) is True

    @pytest.mark.parametrize("sid", sorted(V6))
    def test_an_unrestricted_user_sees_every_v6_subnet(self, topology, sid):
        assert access.subnet6_visible(sid, [], all_subnets=True) is True

    def test_a_subnet_that_is_not_in_the_v6_map_is_visible_to_no_one(self, topology):
        assert access.subnet6_visible(999, SCOPE) is False
        assert access.subnet6_visible(999, [], all_subnets=True) is False
        assert access.subnet6_visible(None, [], all_subnets=True) is False
        assert access.subnet6_visible("abc", SCOPE) is False

    def test_ids_arrive_as_strings_and_ints_alike(self, topology):
        assert access.subnet6_visible("10", ["1", "2"]) is True
        assert access.subnet6_visible(10, [1]) is True

    def test_a_scoped_user_with_no_subnets_sees_nothing(self, topology):
        assert not any(access.subnet6_visible(sid, []) for sid in V6)
        assert not any(access.subnet6_visible(sid, None) for sid in V6)

    def test_a_pairing_to_a_v4_subnet_that_does_not_exist_grants_nothing_to_a_scoped_user(self, topology, monkeypatch):
        monkeypatch.setitem(
            extensions.SUBNET6_MAP, 7, {"name": "V6-GHOST", "cidr": "2001:db8:a7::/64", "paired_subnet4_id": 99}
        )
        assert access.subnet6_visible(7, SCOPE) is False

    def test_paired_v4_id_is_for_display_and_reads_the_pairing(self, topology):
        assert access.paired_v4_id(10) == 1 and access.paired_v4_id(1) is None and access.paired_v4_id(999) is None


class TestTheSessionHelpers:
    @pytest.mark.parametrize(
        "scope,visible",
        [([1, 2], ALLOWED6), ([1], {10}), ([3], {2}), ([2], {3}), ([], set()), (None, set(V6))],
    )
    def test_accessible_subnet6_map_and_can_access_agree(self, topology, monkeypatch, scope, visible):
        monkeypatch.setattr(access, "current_user", _user(scope))
        assert set(access.accessible_subnet6_map()) == visible
        for sid in V6:
            assert access.can_access_subnet6(sid) is (sid in visible), sid

    def test_an_unauthenticated_caller_sees_nothing(self, topology, monkeypatch):
        monkeypatch.setattr(access, "current_user", _user(None, authenticated=False))
        assert access.accessible_subnet6_map() == {} and access.can_access_subnet6(10) is False

    def test_assert_is_a_404_for_a_hidden_subnet_and_for_one_that_does_not_exist(self, topology, monkeypatch):
        monkeypatch.setattr(access, "current_user", _user(SCOPE))
        access.assert_subnet6_access(10)
        for sid in (2, 1, 5, 999):
            with pytest.raises(NotFound):
                access.assert_subnet6_access(sid)

    def test_an_unrestricted_user_passes_the_assert_for_a_known_subnet_only(self, topology, monkeypatch):
        monkeypatch.setattr(access, "current_user", _user(None))
        access.assert_subnet6_access(2)
        with pytest.raises(NotFound):
            access.assert_subnet6_access(999)

    def test_the_map_is_a_copy_an_unrestricted_caller_cannot_edit_the_global_one_through(self, topology, monkeypatch):
        monkeypatch.setattr(access, "current_user", _user(None))
        access.accessible_subnet6_map().pop(10)
        assert 10 in extensions.SUBNET6_MAP

    def test_plugin_api_re_exports_it(self):
        from jen import plugin_api

        assert plugin_api.can_access_subnet6 is access.can_access_subnet6 and "can_access_subnet6" in plugin_api.__all__


class TestTheSourceHoldsTheRuleInOnePlace:
    """The review's finding in one sentence: seven places each carried their own copy of "does this v6 subnet's pairing say yes", and the
    ones that carried none leaked. The word that names the pairing may appear in jen/routes and jen/services only where it is WRITTEN or
    DISPLAYED as configuration, never in a place that judges access."""

    ALLOWED_FILES = {
        "jen/services/access.py",  # the rule
        "jen/config.py",  # reads/derives the [subnets6] third field
        "jen/services/setup_wizard.py",  # proposes/merges the pairing
        "jen/routes/settings/authoring.py",  # renders and parses the editable subnet lines
    }

    def test_paired_subnet4_id_appears_only_in_the_files_that_write_or_display_the_pairing(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        offenders = []
        for sub in ("jen/routes", "jen/services"):
            for path in sorted((root / sub).rglob("*.py")):
                rel = path.relative_to(root).as_posix()
                if rel in self.ALLOWED_FILES:
                    continue
                if "paired_subnet4_id" in path.read_text(encoding="utf-8"):
                    offenders.append(rel)
        assert not offenders, (
            f"{offenders} judge (or copy) the v6 pairing themselves - use access.can_access_subnet6 / accessible_subnet6_map / "
            "assert_subnet6_access / subnet6_visible (docs/ARCHITECTURE.md §2)"
        )

    def test_no_route_hands_a_template_the_whole_v6_map(self):
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parent.parent
        offenders = []
        pattern = re.compile(r"subnet6_(?:map|names)\s*[=:]\s*(?:\{[^}]*\bin\s+)?extensions\.SUBNET6_MAP")
        for path in sorted((root / "jen/routes").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for m in pattern.finditer(text):
                offenders.append(f"{path.relative_to(root).as_posix()}: {m.group(0)}")
        assert not offenders, f"a template is given extensions.SUBNET6_MAP, which names every v6 subnet: {offenders}"


# ── the routes, against the real database ─────────────────────────────────────────────────────────────────────────────────────────

ROLES = {
    "viewer_scoped": ("viewer", SCOPE),
    "admin_scoped": ("admin", SCOPE),
    "admin_all": ("admin", None),
    "superadmin": ("superadmin", None),
}
SCOPED = ("viewer_scoped", "admin_scoped")
UNRESTRICTED = ("admin_all", "superadmin")
ADMINS = ("admin_scoped", "admin_all", "superadmin")


def _addr(sid):
    return f"2001:db8:a{sid}::5"


def _duid(sid):
    return bytes.fromhex("00030001" + f"0200000000{sid:02x}")


@pytest.fixture
def world(db, monkeypatch):
    """IPv6 on, the topology, one v6 lease and one v6 reservation in every v6 subnet."""
    from jen.models.user import _invalidate_settings_cache, set_global_setting

    set_global_setting("ipv6_enabled", "true")
    _invalidate_settings_cache()
    monkeypatch.setattr(extensions, "SUBNET_MAP", dict(V4))
    monkeypatch.setattr(extensions, "SUBNET6_MAP", {k: dict(v) for k, v in V6.items()})
    _wipe(db)
    with db.cursor() as cur:
        for sid in V6:
            cur.execute(
                """INSERT INTO lease6 (address, duid, valid_lifetime, expire, subnet_id, pref_lifetime, lease_type, iaid,
                       prefix_len, hostname, hwaddr, state)
                   VALUES (INET6_ATON(%s), %s, 3600, '2099-01-01 00:00:00', %s, 1800, 0, 1, 128, %s, NULL, 0)""",
                (_addr(sid), _duid(sid), sid, f"lease6-host-{sid}"),
            )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp6_subnet_id, hostname) VALUES (%s, 1, %s, %s)",
                (_duid(sid), sid, f"res6-host-{sid}"),
            )
            host_id = cur.lastrowid
            cur.execute(
                "INSERT INTO ipv6_reservations (address, prefix_len, type, dhcp6_iaid, host_id) VALUES (INET6_ATON(%s), 128, 0, 1, %s)",
                (f"2001:db8:a{sid}::77", host_id),
            )
    db.commit()
    yield
    _wipe(db)
    set_global_setting("ipv6_enabled", "false")
    _invalidate_settings_cache()


def _wipe(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease6")
        cur.execute("DELETE FROM ipv6_reservations")
        cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
    db.commit()


def _as(client, db, role):
    from tests.conftest import restricted_client

    kind, scope = ROLES[role]
    restricted_client(client, db, allowed_subnets=scope, role=kind, username=f"_v6_{role}")
    return client


def _visible_for(role):
    return set(V6) if role in UNRESTRICTED else set(ALLOWED6)


def _assert_only(html, role, *, rows=True):
    """Hidden subnets' names, CIDRs and (when the page lists rows) addresses and hostnames are absent; visible ones are present."""
    visible = _visible_for(role)
    for sid in V6:
        names = [V6[sid]["name"], V6[sid]["cidr"]]
        if rows:
            names += [_addr(sid), f"lease6-host-{sid}", f"res6-host-{sid}"]
        for n in names:
            if sid in visible:
                continue
            assert n not in html, f"{role}: hidden v6 subnet {sid}'s {n!r} is in the page"


VIEWS = {
    "leases": ("/leases", "lease6-host-{sid}"),
    "devices": ("/devices", "lease6-host-{sid}"),
    "reservations": ("/reservations", "res6-host-{sid}"),
}


class TestTheV6ListsShowOnlyWhatTheCallerMaySee:
    @pytest.mark.parametrize("role", ROLES)
    @pytest.mark.parametrize("view", VIEWS)
    def test_the_default_all_view_has_no_row_from_a_hidden_subnet(self, client, db, world, role, view):
        path, marker = VIEWS[view]
        html = _as(client, db, role).get(f"{path}?view=v6").data.decode()
        for sid in V6:
            present = marker.format(sid=sid) in html
            assert present is (sid in _visible_for(role)), (
                f"{role} {view}: row of v6 subnet {sid} {'missing' if not present else 'leaked'}"
            )
        _assert_only(html, role)

    @pytest.mark.parametrize("role", ROLES)
    @pytest.mark.parametrize("view", VIEWS)
    def test_an_explicit_forbidden_subnet_is_a_404_and_never_the_all_view(self, client, db, world, role, view):
        path, _marker = VIEWS[view]
        c = _as(client, db, role)
        for sid in V6:
            r = c.get(f"{path}?view=v6&subnet={sid}")
            if sid in _visible_for(role):
                assert r.status_code == 200, f"{role} {view} subnet {sid}"
                html = r.data.decode()
                assert V6[sid]["name"] in html
                for other in V6:
                    if other != sid:
                        assert _addr(other) not in html and f"lease6-host-{other}" not in html
            else:
                assert r.status_code == 404, f"{role} {view} subnet {sid}: {r.status_code}"
                _assert_only(r.data.decode(), role)

    @pytest.mark.parametrize("view", VIEWS)
    def test_a_subnet_that_does_not_exist_is_the_same_404_for_a_scoped_user(self, client, db, world, view):
        path, _m = VIEWS[view]
        assert _as(client, db, "admin_scoped").get(f"{path}?view=v6&subnet=999").status_code == 404

    @pytest.mark.parametrize("view", VIEWS)
    def test_a_subnet_that_is_not_a_number_is_the_filtered_all_view_not_a_wider_one(self, client, db, world, view):
        path, _m = VIEWS[view]
        r = _as(client, db, "viewer_scoped").get(f"{path}?view=v6&subnet=abc")
        assert r.status_code == 200
        _assert_only(r.data.decode(), "viewer_scoped")

    @pytest.mark.parametrize("role", SCOPED)
    @pytest.mark.parametrize("view", VIEWS)
    def test_the_htmx_partial_is_filtered_too(self, client, db, world, role, view):
        path, _m = VIEWS[view]
        r = _as(client, db, role).get(f"{path}?view=v6", headers={"HX-Request": "true"})
        assert r.status_code == 200
        _assert_only(r.data.decode(), role)

    @pytest.mark.parametrize("role", SCOPED)
    @pytest.mark.parametrize("path", ["/leases", "/devices", "/reservations"])
    def test_the_v4_pages_do_not_name_a_hidden_v6_subnet_either(self, client, db, world, role, path):
        # these pages are handed the v6 map for their segmented control: only the accessible one
        _assert_only(_as(client, db, role).get(path).data.decode(), role, rows=False)

    @pytest.mark.parametrize("role", UNRESTRICTED)
    def test_an_unrestricted_caller_sees_every_v6_subnet_on_every_list(self, client, db, world, role):
        c = _as(client, db, role)
        for path, marker in VIEWS.values():
            html = c.get(f"{path}?view=v6").data.decode()
            assert all(marker.format(sid=sid) in html for sid in V6)


class TestTheDashboardAndSubnetsPageTotalOnlyWhatTheCallerMaySee:
    @pytest.mark.parametrize("role", ROLES)
    def test_the_dashboard_names_no_hidden_subnet_and_totals_only_visible_ones(self, client, db, world, role):
        html = _as(client, db, role).get("/").data.decode()
        _assert_only(html, role, rows=False)
        n = len(_visible_for(role))
        assert f"+ {n} IPv6" in html, f"{role}: the v6 subnet count is not {n}"

    @pytest.mark.parametrize("role", ROLES)
    def test_the_dashboard_v6_totals_count_only_visible_subnets(self, client, db, world, role):
        import re

        html = _as(client, db, role).get("/").data.decode()
        n = len(_visible_for(role))
        # one lease and one reservation per v6 subnet: Active (v6) and Reserved (v6) are the visible count
        assert len(re.findall(rf">{n}</div>", html)) >= 2, f"{role}: the v6 active/reserved totals are not {n}"

    @pytest.mark.parametrize("role", ROLES)
    def test_the_subnets_page_lists_only_visible_v6_subnets(self, client, db, world, role):
        html = _as(client, db, role).get("/subnets").data.decode()
        _assert_only(html, role, rows=False)
        for sid in _visible_for(role):
            assert V6[sid]["name"] in html, f"{role}: visible v6 subnet {sid} is missing from the Subnets page"

    @pytest.mark.parametrize("role", ROLES)
    def test_the_live_stats_poll_carries_only_visible_v6_subnets(self, client, db, world, role):
        import json

        r = _as(client, db, role).get("/api/stats")
        assert r.status_code == 200
        body = json.loads(r.data)
        got = {int(k) for k in (body.get("subnets6") or {})}
        assert got == _visible_for(role), f"{role}: /api/stats subnets6 = {got}"


class TestGlobalSearch:
    @pytest.mark.parametrize("role", ROLES)
    def test_search_finds_only_visible_v6_leases_and_reservations(self, client, db, world, role):
        c = _as(client, db, role)
        for what in ("lease6-host", "res6-host"):
            html = c.get(f"/search?q={what}").data.decode()
            for sid in V6:
                assert (f"{what}-{sid}" in html) is (sid in _visible_for(role)), f"{role} search {what}-{sid}"
            _assert_only(html, role, rows=False)


class TestAddReservation6:
    @pytest.fixture
    def adds(self, monkeypatch):
        calls = []
        from jen.services import kea6

        monkeypatch.setattr(
            kea6,
            "add_v6_reservation",
            lambda subnet_id, duid, **kw: calls.append((subnet_id, duid, kw)) or {"result": 0},
        )
        return calls

    def _post(self, c, sid):
        return c.post(
            "/reservations/add6",
            data={
                "subnet_id": str(sid),
                "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
                "hostname": "newhost",
                "address": f"2001:db8:a{sid}::99",
            },
        )

    @pytest.mark.parametrize("role", ADMINS)
    def test_the_form_offers_only_visible_subnets(self, client, db, world, adds, role):
        html = _as(client, db, role).get("/reservations/add6").data.decode()
        _assert_only(html, role, rows=False)
        for sid in _visible_for(role):
            assert V6[sid]["name"] in html

    @pytest.mark.parametrize("sid", sorted(HIDDEN6))
    def test_a_post_into_a_hidden_subnet_is_refused_and_nothing_is_written(self, client, db, world, adds, sid):
        r = self._post(_as(client, db, "admin_scoped"), sid)
        assert r.status_code in (400, 404) and adds == [], f"subnet {sid}: {r.status_code}, calls {adds}"
        assert b"V6-HIDDEN" not in r.data

    @pytest.mark.parametrize("sid", sorted(ALLOWED6))
    def test_a_post_into_an_allowed_subnet_is_written(self, client, db, world, adds, sid):
        r = self._post(_as(client, db, "admin_scoped"), sid)
        assert r.status_code in (200, 302) and [c[0] for c in adds] == [sid]

    @pytest.mark.parametrize("sid", sorted(V6))
    def test_an_unrestricted_admin_may_write_into_any_v6_subnet(self, client, db, world, adds, sid):
        r = self._post(_as(client, db, "admin_all"), sid)
        assert r.status_code in (200, 302) and [c[0] for c in adds] == [sid]


class TestDeleteReservation6:
    @pytest.fixture
    def deletes(self, monkeypatch):
        calls = []
        from jen.services import kea6

        monkeypatch.setattr(
            kea6, "delete_v6_reservation", lambda subnet_id, duid: calls.append((subnet_id, duid)) or {"result": 0}
        )
        return calls

    def _post(self, c, sid):
        return c.post("/reservations/delete6", data={"subnet_id": str(sid), "duid": _duid(sid).hex()})

    @pytest.mark.parametrize("sid", sorted(HIDDEN6))
    def test_a_scoped_admin_cannot_delete_a_reservation_in_a_hidden_subnet(self, client, db, world, deletes, sid):
        r = self._post(_as(client, db, "admin_scoped"), sid)
        assert r.status_code in (302, 400, 404) and deletes == [], f"subnet {sid} was reached: {deletes}"
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM hosts WHERE dhcp6_subnet_id=%s", (sid,))
            assert cur.fetchone()["n"] == 1, "the row is still there"

    @pytest.mark.parametrize("sid", sorted(ALLOWED6))
    def test_a_scoped_admin_can_delete_in_a_visible_subnet(self, client, db, world, deletes, sid):
        self._post(_as(client, db, "admin_scoped"), sid)
        assert deletes == [(sid, _duid(sid).hex())] or [d[0] for d in deletes] == [sid]

    @pytest.mark.parametrize("sid", sorted(V6))
    def test_an_unrestricted_admin_can_delete_in_any(self, client, db, world, deletes, sid):
        self._post(_as(client, db, "admin_all"), sid)
        assert [d[0] for d in deletes] == [sid]


class TestEditSubnet6:
    @pytest.fixture
    def pushes(self, monkeypatch):
        calls = []
        from jen.routes import subnets as routes
        from jen.services import kea_changeset

        monkeypatch.setattr(kea_changeset, "apply_change", lambda *a, **k: calls.append((a, k)))
        monkeypatch.setattr(routes, "_config_shas", lambda service: {})
        return calls

    @pytest.mark.parametrize("sid", sorted(HIDDEN6))
    def test_a_hidden_subnet_is_a_404_on_all_three_routes_and_the_config_is_untouched(
        self, client, db, world, pushes, sid
    ):
        c = _as(client, db, "admin_scoped")
        assert c.get(f"/subnets/edit6/{sid}").status_code == 404
        assert c.post(f"/subnets/edit6/{sid}/preview", data={"preferred_lifetime": "3000"}).status_code == 404
        assert c.post(f"/subnets/edit6/{sid}", data={"preferred_lifetime": "3000"}).status_code == 404
        assert pushes == []

    def test_a_subnet_that_does_not_exist_is_the_same_404(self, client, db, world, pushes):
        c = _as(client, db, "admin_scoped")
        assert c.get("/subnets/edit6/999").status_code == 404
        assert c.post("/subnets/edit6/999/preview", data={}).status_code == 404

    @pytest.mark.parametrize("sid", sorted(ALLOWED6))
    def test_a_visible_subnet_reaches_the_preview(self, client, db, world, pushes, sid):
        r = _as(client, db, "admin_scoped").post(f"/subnets/edit6/{sid}/preview", data={})
        assert r.status_code == 200 and r.get_json()["ok"] is True

    @pytest.mark.parametrize("sid", sorted(V6))
    def test_an_unrestricted_admin_reaches_the_preview_of_any(self, client, db, world, pushes, sid):
        r = _as(client, db, "admin_all").post(f"/subnets/edit6/{sid}/preview", data={})
        assert r.status_code == 200 and r.get_json()["ok"] is True


class TestTheInvestigationAndTimelineFollowTheSameRule:
    @pytest.mark.parametrize("sid", sorted(V6))
    def test_a_v6_address_in_a_hidden_subnet_is_not_found_by_a_scoped_user(self, client, db, world, sid):
        from jen.services import client_subject

        html = _as(client, db, "viewer_scoped").get(f"/client?q={_addr(sid)}").data.decode()
        assert (f"lease6-host-{sid}" in html) is (sid in ALLOWED6), f"v6 subnet {sid}"
        assert V6[sid]["name"] not in html or sid in ALLOWED6
        assert client_subject is not None

    def test_the_timeline_keeps_only_v6_addresses_in_visible_subnets(self, db, world):
        from jen.services import client_subject

        by_visible = {
            sid: client_subject.subnet6_ok(sid, SCOPE)
            if hasattr(client_subject, "subnet6_ok")
            else access.subnet6_visible(sid, SCOPE)
            for sid in V6
        }
        assert {sid for sid, ok in by_visible.items() if ok} == ALLOWED6
