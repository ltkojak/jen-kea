"""
tests/test_nav_prefs.py
───────────────────────
v7.2.0-beta.1 (Q243) - a person's own navigation: favorites after the fixed top items, the phone's bottom bar,
the pin button on the section strip and the Customize navigation page.

The contract, and where each half is held:

* PER PERSON: one row in `user_nav`; nobody reads or writes anyone else's (TestTheRoutes).
* ADD-ONLY: the five fixed top items are always there, in their order, whatever is stored (TestNavContext).
* A SHORTCUT, NEVER ACCESS: a stored id is shown only when it is a destination for this person NOW - role,
  subnet scope and enabled plugins are the navigation's own filters - and an id that does not resolve is
  skipped, never rendered and never an error (TestNavContext, TestTheRoutes).
* THE PHONE BAR IS NEVER EMPTY: no choice that resolves means the default four (TestNavContext).

The first two classes are pure: `py -m pytest --noconftest tests/test_nav_prefs.py -k "Pure or NavContext"`.
"""

import json

import pytest

from jen.routes.settings import nav
from jen.services import nav_prefs

IPAM = {"endpoint": "ipam.index", "label": "IPAM", "icon": "table", "section": "network"}
WOL = {"endpoint": "wol.index", "label": "Wake-on-LAN", "icon": "zap", "section": ""}
FIXED = ["Dashboard", "Management", "Network", "Settings", "About"]


class TestPureEdit:
    OFFERED = ("/a", "/b", "/c", "/d", "/e", "/f")

    def _edit(self, current, action, dest, limit=5, place="top", offered=None):
        return nav_prefs.apply_edit(current, action, dest, offered or self.OFFERED, limit, place)

    def test_add_appends(self):
        assert self._edit(["/a"], "add", "/b") == (["/a", "/b"], None)

    def test_add_twice_is_one_entry_and_no_refusal(self):
        assert self._edit(["/a"], "add", "/a") == (["/a"], None)

    def test_add_of_a_page_that_is_not_offered_is_refused(self):
        assert self._edit([], "add", "/admin-only") == ([], nav_prefs.NOT_OFFERED)

    @pytest.mark.parametrize("bad", ["", None, 7, "x" * 121])
    def test_add_of_a_value_that_is_no_id_is_refused(self, bad):
        assert self._edit(["/a"], "add", bad) == (["/a"], nav_prefs.NOT_OFFERED)

    def test_the_sixth_favorite_is_refused_with_the_sentence(self):
        five = ["/a", "/b", "/c", "/d", "/e"]
        assert self._edit(five, "add", "/f") == (five, nav_prefs.FULL["top"])

    def test_the_fifth_phone_page_is_refused_with_its_own_sentence(self):
        four = ["/a", "/b", "/c", "/d"]
        assert self._edit(four, "add", "/e", limit=4, place="tabbar") == (four, nav_prefs.FULL["tabbar"])

    def test_an_entry_that_does_not_resolve_does_not_count_toward_the_limit(self):
        """A plugin that was switched off leaves its id stored; the person still gets their five."""
        stored = ["plugin:gone.index", "/a", "/b", "/c", "/d"]
        new, refusal = self._edit(stored, "add", "/e")
        assert refusal is None and new == [*stored, "/e"]

    def test_remove(self):
        assert self._edit(["/a", "/b", "/c"], "remove", "/b") == (["/a", "/c"], None)

    def test_remove_of_an_entry_that_is_not_there_changes_nothing(self):
        assert self._edit(["/a"], "remove", "/b") == (["/a"], None)

    def test_up_and_down(self):
        assert self._edit(["/a", "/b", "/c"], "up", "/c") == (["/a", "/c", "/b"], None)
        assert self._edit(["/a", "/b", "/c"], "down", "/a") == (["/b", "/a", "/c"], None)

    def test_up_at_the_top_and_down_at_the_bottom_change_nothing(self):
        assert self._edit(["/a", "/b"], "up", "/a") == (["/a", "/b"], None)
        assert self._edit(["/a", "/b"], "down", "/b") == (["/a", "/b"], None)

    def test_a_move_steps_over_an_entry_the_person_cannot_see(self):
        """Without this a click on Move up would swap with a hidden entry and the page would show no change."""
        assert self._edit(["/a", "plugin:gone.index", "/b"], "up", "/b") == (["/b", "plugin:gone.index", "/a"], None)

    def test_reset_empties_the_list(self):
        assert self._edit(["/a", "/b"], "reset", "") == ([], None)

    def test_an_unknown_action_changes_nothing(self):
        assert self._edit(["/a"], "explode", "/a") == (["/a"], None)

    @pytest.mark.parametrize("raw", [None, "", "not json", "{}", '"/a"', "[1, 2]", json.dumps(["x" * 121])])
    def test_a_stored_value_of_any_other_shape_reads_as_empty(self, raw):
        assert nav_prefs._decode(raw) == []

    def test_a_stored_list_reads_back(self):
        assert nav_prefs._decode('["/leases", "plugin:ipam.index"]') == ["/leases", "plugin:ipam.index"]


class TestNavContext:
    def _ctx(self, endpoint="leases.leases", role="admin", plugins=(IPAM, WOL), all_subnets=True, **prefs):
        return nav.nav_context(endpoint, role, list(plugins), all_subnets=all_subnets, prefs=prefs or None)

    def test_without_a_choice_nothing_changes(self):
        """The default navigation is the one v7.1.0 rendered: no favorites, the default bar, no Favorites group."""
        ctx = self._ctx()
        assert ctx["favorites"] == []
        assert [t["label"] for t in ctx["tabbar"]] == ["Dashboard", "Leases", "Reservations", "Settings"]
        assert [g["id"] for g in ctx["sheet"]][0] == "management"
        assert [t["label"] for t in ctx["top"]] == FIXED

    def test_the_fixed_items_stay_whatever_is_stored(self):
        ctx = self._ctx(top=["/", "/leases", "/subnets", "/settings", "/about", "/reports"])
        assert [t["label"] for t in ctx["top"]] == FIXED
        assert [f["label"] for f in ctx["favorites"]] == ["Reports"], (
            "an address a fixed item links to is never a favorite"
        )

    def test_favorites_in_stored_order_a_plugin_page_among_them(self):
        ctx = self._ctx(top=["plugin:ipam.index", "/health-center", "/settings/kea"])
        assert [f["label"] for f in ctx["favorites"]] == ["IPAM", "Health", "Kea"]
        assert ctx["favorites"][0]["endpoint"] == "ipam.index" and "url" not in ctx["favorites"][0]

    def test_at_most_five_and_each_once(self):
        ids = ["/reports", "/reports", "/devices", "/reservations", "/ddns", "/timeline", "/problems"]
        assert [f["id"] for f in self._ctx(top=ids)["favorites"]] == [
            "/reports",
            "/devices",
            "/reservations",
            "/ddns",
            "/timeline",
        ]

    def test_a_viewer_is_never_shown_a_settings_page_they_stored_as_an_admin(self):
        ctx = self._ctx(role="viewer", top=["/settings/kea", "/tools/doctor", "/reports"])
        assert [f["id"] for f in ctx["favorites"]] == ["/reports"]

    def test_a_subnet_restricted_person_is_not_shown_doctor(self):
        ctx = self._ctx(all_subnets=False, top=["/tools/doctor", "/reports"])
        assert [f["id"] for f in ctx["favorites"]] == ["/reports"]

    def test_a_plugin_that_is_switched_off_is_skipped(self):
        ctx = self._ctx(plugins=(), top=["plugin:ipam.index", "/reports"], tabbar=["plugin:ipam.index"])
        assert [f["id"] for f in ctx["favorites"]] == ["/reports"]
        assert [t["label"] for t in ctx["tabbar"]] == ["Dashboard", "Leases", "Reservations", "Settings"]

    def test_the_favorite_being_shown_is_active(self):
        ctx = self._ctx(endpoint="ipam.index", top=["plugin:ipam.index", "/reports"])
        assert [f["active"] for f in ctx["favorites"]] == [True, False]

    def test_favorites_lead_the_more_sheet(self):
        ctx = self._ctx(top=["/reports"])
        assert ctx["sheet"][0]["id"] == "favorites" and [i["label"] for i in ctx["sheet"][0]["items"]] == ["Reports"]

    def test_the_phone_bar_is_the_persons_own_four(self):
        ctx = self._ctx(endpoint="ipam.index", tabbar=["/", "plugin:ipam.index", "/problems", "/settings", "/reports"])
        assert [t["label"] for t in ctx["tabbar"]] == ["Dashboard", "IPAM", "Problems", "Settings"]
        assert [t["active"] for t in ctx["tabbar"]] == [False, True, False, False]
        assert ctx["tabbar_more_active"] is False

    def test_more_lights_when_no_slot_is_the_page(self):
        assert self._ctx(endpoint="reports.reports", tabbar=["/", "/leases"])["tabbar_more_active"] is True

    def test_a_viewers_bar_cannot_hold_settings(self):
        ctx = self._ctx(role="viewer", tabbar=["/settings", "/settings/kea"])
        assert [t["label"] for t in ctx["tabbar"]] == ["Dashboard", "Leases", "Reservations", "Devices"]

    def test_the_pin_button_names_the_page_being_shown(self):
        assert self._ctx(endpoint="reports.reports")["pin"] == {"id": "/reports", "label": "Reports", "pinned": False}
        assert self._ctx(endpoint="reports.reports", top=["/reports"])["pin"]["pinned"] is True
        assert self._ctx(endpoint="ipam.index")["pin"]["id"] == "plugin:ipam.index"
        assert self._ctx(endpoint="settings.settings_kea")["pin"]["id"] == "/settings/kea"

    def test_no_pin_button_on_a_page_a_fixed_item_links_to_or_without_a_strip(self):
        assert self._ctx(endpoint="leases.leases")["pin"] is None
        assert self._ctx(endpoint="dashboard.dashboard")["pin"] is None
        assert self._ctx(endpoint="users.about")["pin"] is None

    def test_a_plugin_page_outside_the_network_section_has_the_button_too(self):
        """A plugin page that names no section with a strip is shown under the Network strip (nav_context has done that since v5.9.0), and one that names `management` is on
        the Management strip (Q247), so every plugin page can be pinned from where it is."""
        assert self._ctx(endpoint="wol.index")["pin"] == {
            "id": "plugin:wol.index",
            "label": "Wake-on-LAN",
            "pinned": False,
        }

    def test_what_the_customize_page_offers(self):
        top, tabbar = nav.pinnable("admin", [IPAM, WOL])
        top_ids, bar_ids = [d["id"] for d in top], [d["id"] for d in tabbar]
        assert not {"/", "/leases", "/subnets", "/settings", "/about"} & set(top_ids)
        assert bar_ids[:2] == ["/", "/settings"] and "/about" in bar_ids
        assert {"plugin:ipam.index", "plugin:wol.index", "/settings/kea", "/reports"} <= set(top_ids)
        viewer_top, viewer_bar = nav.pinnable("viewer", [IPAM])
        assert not [d for d in viewer_top + viewer_bar if d["id"].startswith("/settings")]
        assert "/tools/doctor" not in [d["id"] for d in viewer_top]

    def test_every_destination_has_one_id(self):
        ids = [d["id"] for d in self._ctx()["destinations"]]
        assert len(ids) == len(set(ids)) and all(ids)


def _stored(db, user_id):
    db.commit()  # end this connection's snapshot before reading what the route's connection wrote
    with db.cursor() as cur:
        cur.execute("SELECT top_row, tabbar FROM user_nav WHERE user_id=%s", (user_id,))
        row = cur.fetchone()
    return None if row is None else {"top": json.loads(row["top_row"]), "tabbar": json.loads(row["tabbar"])}


@pytest.fixture
def clean_nav(db):
    def wipe():
        with db.cursor() as cur:
            cur.execute("DELETE FROM user_nav")
        db.commit()

    wipe()
    yield
    wipe()


class TestTheRoutes:
    def _post(self, client, **form):
        return client.post("/navigation/edit", data=form)

    def test_anonymous_is_sent_to_sign_in(self, client):
        assert client.get("/navigation").status_code in (302, 401)
        assert client.post(
            "/navigation/edit", data={"place": "top", "action": "add", "dest": "/reports"}
        ).status_code in (302, 401)
        assert client.post("/navigation/pin", data={"dest": "/reports"}).status_code in (302, 401)

    def test_the_page_renders_with_nothing_stored(self, logged_in_client, clean_nav):
        r = logged_in_client.get("/navigation")
        body = r.get_data(as_text=True)
        assert r.status_code == 200
        assert "Top row favorites (0 of 5)" in body and "Phone bar (the default pages)" in body
        assert "No favorites yet." in body and "The phone bar shows its default pages." in body

    def test_add_stores_and_the_next_page_shows_it(self, logged_in_client, clean_nav, db):
        r = self._post(logged_in_client, place="top", action="add", dest="/reports")
        assert r.status_code == 302 and r.headers["Location"].endswith("/navigation")
        assert _stored(db, 1) == {"top": ["/reports"], "tabbar": []}
        body = logged_in_client.get("/about").get_data(as_text=True)
        assert 'class="nav-link nav-fav "' in body and '<span class="nav-fav-label">Reports</span>' in body
        assert '<div class="sheet-group-label">Favorites</div>' in body

    def test_one_list_is_kept_when_the_other_is_written(self, logged_in_client, clean_nav, db):
        self._post(logged_in_client, place="top", action="add", dest="/reports")
        self._post(logged_in_client, place="tabbar", action="add", dest="/problems")
        self._post(logged_in_client, place="tabbar", action="add", dest="/")
        assert _stored(db, 1) == {"top": ["/reports"], "tabbar": ["/problems", "/"]}

    def test_the_phone_bar_the_person_chose_is_rendered(self, logged_in_client, clean_nav):
        self._post(logged_in_client, place="tabbar", action="add", dest="/problems")
        body = logged_in_client.get("/about").get_data(as_text=True)
        bar = body.split('<nav class="tabbar"')[1].split("</nav>")[0]
        assert "<span>Problems</span>" in bar and "<span>More</span>" in bar
        assert "<span>Reservations</span>" not in bar

    def test_reset_brings_the_default_bar_back(self, logged_in_client, clean_nav, db):
        self._post(logged_in_client, place="tabbar", action="add", dest="/problems")
        self._post(logged_in_client, place="tabbar", action="reset")
        assert _stored(db, 1)["tabbar"] == []
        bar = logged_in_client.get("/about").get_data(as_text=True).split('<nav class="tabbar"')[1].split("</nav>")[0]
        assert "<span>Reservations</span>" in bar

    def test_a_refusal_is_said_and_nothing_is_stored(self, logged_in_client, clean_nav, db):
        r = logged_in_client.post(
            "/navigation/edit", data={"place": "top", "action": "add", "dest": "/not-a-page"}, follow_redirects=True
        )
        assert nav_prefs.NOT_OFFERED in r.get_data(as_text=True)
        assert _stored(db, 1) is None
        r = logged_in_client.post(
            "/navigation/edit", data={"place": "sidebar", "action": "add", "dest": "/reports"}, follow_redirects=True
        )
        assert nav_prefs.NOT_OFFERED in r.get_data(as_text=True)
        assert _stored(db, 1) is None

    def test_the_sixth_favorite_is_refused_on_the_page(self, logged_in_client, clean_nav, db):
        for dest in ("/reports", "/devices", "/reservations", "/ddns", "/timeline"):
            self._post(logged_in_client, place="top", action="add", dest=dest)
        r = logged_in_client.post(
            "/navigation/edit", data={"place": "top", "action": "add", "dest": "/problems"}, follow_redirects=True
        )
        body = r.get_data(as_text=True)
        assert nav_prefs.FULL["top"] in body and "This list is full." in body
        assert len(_stored(db, 1)["top"]) == 5

    def test_a_viewer_cannot_store_a_settings_page(self, client, db, clean_nav):
        from tests.conftest import restricted_client

        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username='q243_viewer'")
        db.commit()
        viewer, uid = restricted_client(client, db, [1], role="viewer", username="q243_viewer")
        try:
            r = viewer.post(
                "/navigation/edit",
                data={"place": "top", "action": "add", "dest": "/settings/kea"},
                follow_redirects=True,
            )
            assert nav_prefs.NOT_OFFERED in r.get_data(as_text=True)
            assert _stored(db, uid) is None
            viewer.post("/navigation/edit", data={"place": "top", "action": "add", "dest": "/reports"})
            assert _stored(db, uid)["top"] == ["/reports"]
            assert _stored(db, 1) is None, "one person's edit wrote another person's row"
            # an id stored while the person was an admin is not rendered for the viewer they are now
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE user_nav SET top_row=%s WHERE user_id=%s", (json.dumps(["/settings/kea", "/reports"]), uid)
                )
            db.commit()
            body = viewer.get("/about").get_data(as_text=True)
            assert '<span class="nav-fav-label">Reports</span>' in body
            assert "/settings/kea" not in body
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username='q243_viewer'")
            db.commit()

    def test_deleting_the_person_deletes_the_row(self, db, clean_nav):
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username='q243_gone'")
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES ('q243_gone', %s, 'viewer')",
                (hash_password("x-243-x"),),
            )
            uid = cur.lastrowid
        db.commit()
        nav_prefs.save(uid, "top", ["/reports"])
        assert _stored(db, uid) == {"top": ["/reports"], "tabbar": []}
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id=%s", (uid,))
        db.commit()
        assert _stored(db, uid) is None


class TestThePinButton:
    def test_the_strip_offers_to_add_the_page_being_shown(self, logged_in_client, clean_nav):
        body = logged_in_client.get("/reports").get_data(as_text=True)
        assert 'action="/navigation/pin"' in body
        assert '<input type="hidden" name="dest" value="/reports">' in body
        assert "Add to top row" in body and 'aria-pressed="false"' in body

    def test_the_form_never_carries_the_query_it_was_sent(self, logged_in_client, clean_nav):
        """`next` is the path alone: a page does not print back a query string it was sent."""
        body = logged_in_client.get("/reports?days=7&q243marker=1").get_data(as_text=True)
        assert '<input type="hidden" name="next" value="/reports">' in body
        assert "q243marker" not in body

    def test_pin_adds_and_comes_back_and_the_button_turns(self, logged_in_client, clean_nav, db):
        r = logged_in_client.post(
            "/navigation/pin", data={"dest": "/reports", "pinned": "0", "next": "/reports?days=7"}
        )
        assert r.status_code == 302 and r.headers["Location"].endswith("/reports?days=7")
        assert _stored(db, 1)["top"] == ["/reports"]
        body = logged_in_client.get("/reports").get_data(as_text=True)
        assert "Remove from top row" in body and 'aria-pressed="true"' in body
        logged_in_client.post("/navigation/pin", data={"dest": "/reports", "pinned": "1", "next": "/reports"})
        assert _stored(db, 1)["top"] == []

    @pytest.mark.parametrize("bad", ["//evil.example/x", "https://evil.example/", "/\\evil.example", "evil"])
    def test_next_is_only_ever_a_path_on_this_host(self, logged_in_client, clean_nav, bad):
        r = logged_in_client.post("/navigation/pin", data={"dest": "/reports", "pinned": "0", "next": bad})
        assert r.status_code == 302 and r.headers["Location"].endswith("/navigation")

    def test_no_pin_button_on_a_page_a_fixed_item_links_to(self, logged_in_client, clean_nav):
        assert 'action="/navigation/pin"' not in logged_in_client.get("/leases").get_data(as_text=True)

    def test_a_fragment_request_never_reads_the_row(self, logged_in_client, clean_nav, monkeypatch):
        calls = []
        monkeypatch.setattr(nav_prefs, "load", lambda uid: calls.append(uid) or {"top": [], "tabbar": []})
        logged_in_client.get("/about", headers={"HX-Request": "true"})
        assert calls == []
        logged_in_client.get("/about")
        assert calls == [1]

    def test_a_row_that_cannot_be_read_is_the_default_navigation(self, logged_in_client, clean_nav, monkeypatch):
        import jen.models.db as dbmod

        def broken():
            raise RuntimeError("the database is away")

        monkeypatch.setattr(dbmod, "jen_db", broken)
        assert nav_prefs.load(1) == {"top": [], "tabbar": []}


class TestAListOfPagesThatAreGoneCanBeCleared:
    """Q244 (BD2, BD11 of the pass on v7.2.0-beta.1). An id that stops resolving stays stored, by decision: the page comes back with its plugin. With every
    stored id gone the card listed nothing and offered no Reset, so the person could not clear the list from the page."""

    def _store(self, db, top):
        with db.cursor() as cur:
            cur.execute("REPLACE INTO user_nav (user_id, top_row) VALUES (1, %s)", (json.dumps(top),))
        db.commit()

    def _card(self, client):
        body = client.get("/navigation").get_data(as_text=True)
        return body.split('id="navc-top"')[1].split('id="navc-tabbar"')[0]

    def test_reset_is_offered_when_nothing_stored_resolves(self, logged_in_client, clean_nav, db):
        """v7.2.0-beta.1 shows no Reset here."""
        self._store(db, ["plugin:gone.index"])
        card = self._card(logged_in_client)
        assert "Top row favorites (0 of 5)" in card and "No favorites yet." in card
        assert "Reset to default" in card
        assert "1 saved page cannot be shown now" in card and "Reset to default removes it." in card

    def test_reset_then_clears_it(self, logged_in_client, clean_nav, db):
        self._store(db, ["plugin:gone.index", "plugin:gone.too"])
        assert "2 saved pages cannot be shown now" in self._card(logged_in_client)
        logged_in_client.post("/navigation/edit", data={"place": "top", "action": "reset"})
        assert _stored(db, 1)["top"] == []
        card = self._card(logged_in_client)
        assert "cannot be shown now" not in card and "Reset to default" not in card

    def test_the_count_is_of_the_ones_that_do_not_resolve(self, logged_in_client, clean_nav, db):
        self._store(db, ["/reports", "plugin:gone.index", "/reports"])
        card = self._card(logged_in_client)
        assert "Top row favorites (1 of 5)" in card and "1 saved page cannot be shown now" in card

    def test_nothing_is_said_when_every_stored_page_resolves(self, logged_in_client, clean_nav, db):
        self._store(db, ["/reports"])
        card = self._card(logged_in_client)
        assert "cannot be shown now" not in card and "Reset to default" in card

    def test_the_phone_bar_card_says_nothing_of_the_top_rows_pages(self, logged_in_client, clean_nav, db):
        self._store(db, ["plugin:gone.index"])
        body = logged_in_client.get("/navigation").get_data(as_text=True)
        bar = body.split('id="navc-tabbar"')[1]
        assert "cannot be shown now" not in bar and "Reset to default" not in bar


class TestAFavoriteIsDrawnAsTheFixedItemsAre:
    """Q244 (the maintainer, 2026-11-19, on v7.2.0-beta.1). A favorite that is not the page being shown was drawn in the bright text color, beside five fixed
    items that are muted until they are the page being shown or the pointer is on them."""

    def test_no_rule_gives_an_idle_favorite_a_color_of_its_own(self):
        import pathlib
        import re

        css = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "base.html").read_text(encoding="utf-8")
        own = [m for m in re.findall(r"[^{}\n]*\.nav-fav\b[^{}\n]*\{[^}]*\}", css) if "color" in m.split("{", 1)[1]]
        assert own == [], own
        assert ".nav a.nav-link { color: var(--text-muted);" in css
        assert ".nav a.nav-link:hover, .nav a.nav-link.active { background: var(--surface2); color: var(--text);" in css

    def test_a_favorite_carries_the_class_those_rules_are_written_for(self):
        import pathlib

        html = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "base.html").read_text(encoding="utf-8")
        assert 'class="nav-link nav-fav {% if f.active %}active{% endif %}"' in html
