"""
tests/test_view_cookie.py
─────────────────────────
v5.70.0-beta.2 (Q206, AV5): the rows-per-page choice of Leases, Devices and Reservations is remembered per browser in ONE cookie, `jen_view`, that the three list routes set when the URL
carries `per_page` and read when it does not (`jen/services/view_prefs.py`).

TestTheParser, TestTheCookieOnTheWire and TestTheContract are pure (`py -m pytest --noconftest tests/test_view_cookie.py -k "not Routes"`); TestRoutes needs the CI database like every route test.
"""

import json
import re

import pytest
from flask import Flask, make_response, request

from jen.services import view_prefs

PAGES = ["leases", "devices", "reservations"]


class TestTheParser:
    @pytest.mark.parametrize("page", PAGES)
    @pytest.mark.parametrize("value", ["all", "50", "100", "250"])
    def test_each_valid_value_is_kept_for_its_own_page(self, page, value):
        assert view_prefs.parse(json.dumps({page: value})) == {page: value}

    def test_the_three_pages_are_kept_apart(self):
        raw = json.dumps({"leases": "100", "devices": "50", "reservations": "250"})
        assert view_prefs.parse(raw) == {"leases": "100", "devices": "50", "reservations": "250"}

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            "",
            "junk",
            "not json {",
            "[]",
            '["leases","100"]',
            "null",
            "100",
            '"100"',
            "{}",
            '{"leases": 100}',  # a number where a string belongs
            '{"leases": null}',
            '{"leases": ["100"]}',
            '{"leases": "7"}',  # not in the table
            '{"leases": "-1"}',
            '{"leases": "100 "}',
            '{"leases": "ALL"}',
            '{"alerts": "100"}',  # a page the cookie does not know
            '{"__proto__": "100"}',
        ],
    )
    def test_junk_is_ignored(self, raw):
        assert view_prefs.parse(raw) == {}

    def test_an_oversize_cookie_is_ignored_even_when_it_would_otherwise_parse(self):
        raw = json.dumps({"leases": "100", "pad": "x" * 400})
        assert len(raw.encode()) > view_prefs.MAX_COOKIE_BYTES
        assert view_prefs.parse(raw) == {}

    def test_a_cookie_just_inside_the_cap_is_read(self):
        raw = json.dumps({"leases": "100", "pad": "x" * 150}, separators=(",", ":"))
        assert len(raw.encode()) <= view_prefs.MAX_COOKIE_BYTES
        assert view_prefs.parse(raw) == {"leases": "100"}

    def test_a_good_value_survives_beside_a_bad_one(self):
        assert view_prefs.parse('{"leases": "100", "devices": "7"}') == {"leases": "100"}

    def test_a_value_from_another_pages_table_is_ignored(self, monkeypatch):
        # the tables are per page: a value written into one page's row is not valid for another's until that page's row says so
        monkeypatch.setitem(view_prefs.PER_PAGE_TABLE, "devices", ("all", "50", "100", "250", "500"))
        assert view_prefs.parse('{"devices": "500", "leases": "500"}') == {"devices": "500"}

    def test_the_dump_is_compact_and_in_the_tables_order(self):
        assert view_prefs.dump({"reservations": "50", "leases": "100"}) == '{"leases":"100","reservations":"50"}'
        assert len(view_prefs.dump(dict.fromkeys(PAGES, "250")).encode()) <= view_prefs.MAX_COOKIE_BYTES

    def test_a_dump_parses_back_to_itself(self):
        prefs = {"leases": "100", "devices": "all", "reservations": "250"}
        assert view_prefs.parse(view_prefs.dump(prefs)) == prefs


class TestTheContract:
    """`resolve`: the URL wins and is stored when it is in the table; absent, the cookie's value for THIS page; absent too, "all"."""

    @pytest.mark.parametrize("page", PAGES)
    def test_nothing_anywhere_is_all_and_stores_nothing(self, page):
        assert view_prefs.resolve(page, {}, {}) == ("all", {})

    def test_the_cookie_is_used_when_the_url_has_no_per_page(self):
        cookies = {view_prefs.COOKIE: json.dumps({"leases": "100"})}
        assert view_prefs.resolve("leases", {}, cookies) == ("100", {"leases": "100"})

    def test_the_url_wins_over_the_cookie_and_is_stored(self):
        cookies = {view_prefs.COOKIE: json.dumps({"leases": "100", "devices": "50"})}
        assert view_prefs.resolve("leases", {"per_page": "250"}, cookies) == ("250", {"leases": "250", "devices": "50"})

    def test_show_all_is_a_choice_and_replaces_a_remembered_value(self):
        cookies = {view_prefs.COOKIE: json.dumps({"leases": "100"})}
        assert view_prefs.resolve("leases", {"per_page": "all"}, cookies) == ("all", {"leases": "all"})

    def test_a_value_the_table_does_not_hold_is_used_as_the_route_always_used_it_and_never_stored(self):
        cookies = {view_prefs.COOKIE: json.dumps({"leases": "100"})}
        assert view_prefs.resolve("leases", {"per_page": "7"}, cookies) == ("7", {"leases": "100"})
        assert view_prefs.resolve("leases", {"per_page": ""}, cookies) == ("", {"leases": "100"})

    def test_another_pages_value_does_not_leak_across(self):
        cookies = {view_prefs.COOKIE: json.dumps({"leases": "100"})}
        assert view_prefs.resolve("devices", {}, cookies) == ("all", {"leases": "100"})
        assert view_prefs.resolve("reservations", {}, cookies) == ("all", {"leases": "100"})

    def test_a_junk_cookie_is_the_default(self):
        assert view_prefs.resolve("leases", {}, {view_prefs.COOKIE: "}{"}) == ("all", {})

    def test_the_stale_and_history_modes_are_not_in_the_table(self):
        # the cookie remembers rows per page and nothing else: those two modes stay in the URL
        assert set(view_prefs.PER_PAGE_TABLE) == set(PAGES)
        assert view_prefs.parse('{"leases": "100", "stale": "1", "expired": "1"}') == {"leases": "100"}


@pytest.fixture
def mini_app():
    """A bare Flask app whose three routes do exactly what the list routes do with view_prefs - the cookie on the wire, with no database."""
    app = Flask(__name__)

    def make(page):
        def view():
            per_page, stored = view_prefs.resolve(page, request.args, request.cookies)
            return view_prefs.remember(make_response(f"per_page={per_page}"), request, stored)

        view.__name__ = f"view_{page}"
        return view

    for page in PAGES:
        app.add_url_rule(f"/{page}", view_func=make(page))
    return app


def _set_cookie_headers(resp):
    return [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]


class TestTheCookieOnTheWire:
    def test_a_per_page_in_the_url_sets_the_cookie_and_the_next_visit_without_it_uses_it(self, mini_app):
        c = mini_app.test_client()
        r = c.get("/leases?per_page=100")
        assert r.data == b"per_page=100"
        assert len(_set_cookie_headers(r)) == 1
        assert c.get("/leases").data == b"per_page=100"

    def test_the_attributes(self, mini_app):
        header = _set_cookie_headers(mini_app.test_client().get("/leases?per_page=100"))[0]
        assert header.startswith("jen_view=")
        assert "SameSite=Lax" in header
        assert "Path=/" in header
        assert "HttpOnly" not in header, "a display preference, not a secret"
        assert "Secure" not in header, "plain http: a Secure cookie would never come back"
        assert f"Max-Age={view_prefs.MAX_AGE}" in header

    def test_secure_when_the_request_is_https(self, mini_app):
        header = _set_cookie_headers(mini_app.test_client().get("/leases?per_page=100", base_url="https://jen.lan"))[0]
        assert "Secure" in header and "SameSite=Lax" in header and "HttpOnly" not in header

    def test_the_value_is_the_compact_json(self, mini_app):
        mini_app.add_url_rule("/raw", view_func=lambda: request.cookies.get("jen_view", ""))
        c = mini_app.test_client()
        c.get("/leases?per_page=100")
        c.get("/devices?per_page=50")
        assert c.get("/raw").data == b'{"leases":"100","devices":"50"}'

    def test_an_unchanged_choice_does_not_rewrite_the_cookie(self, mini_app):
        c = mini_app.test_client()
        c.get("/leases?per_page=100")
        assert _set_cookie_headers(c.get("/leases?per_page=100")) == []
        assert _set_cookie_headers(c.get("/leases")) == []

    def test_an_explicit_value_wins_and_replaces_the_stored_one(self, mini_app):
        c = mini_app.test_client()
        c.get("/leases?per_page=100")
        r = c.get("/leases?per_page=250")
        assert r.data == b"per_page=250" and len(_set_cookie_headers(r)) == 1
        assert c.get("/leases").data == b"per_page=250"

    def test_no_cookie_is_set_when_nothing_was_chosen(self, mini_app):
        assert _set_cookie_headers(mini_app.test_client().get("/leases")) == []

    def test_a_value_the_table_does_not_hold_is_never_stored(self, mini_app):
        c = mini_app.test_client()
        assert _set_cookie_headers(c.get("/leases?per_page=999")) == []
        assert c.get("/leases").data == b"per_page=all"

    def test_a_junk_cookie_is_taken_away_and_the_page_is_the_default(self, mini_app):
        c = mini_app.test_client()
        c.set_cookie("jen_view", "not-json", domain="localhost")
        r = c.get("/leases")
        assert r.data == b"per_page=all"
        assert any("jen_view=;" in h or 'jen_view="";' in h for h in _set_cookie_headers(r)), _set_cookie_headers(r)

    def test_a_cookie_with_one_good_value_and_one_bad_is_rewritten_clean(self, mini_app):
        c = mini_app.test_client()
        c.set_cookie("jen_view", '{"leases":"100","devices":"7"}', domain="localhost")
        r = c.get("/leases")
        assert r.data == b"per_page=100"
        header = _set_cookie_headers(r)
        assert len(header) == 1 and "devices" not in header[0]

    def test_an_oversize_cookie_is_ignored(self, mini_app):
        c = mini_app.test_client()
        c.set_cookie("jen_view", json.dumps({"leases": "100", "pad": "x" * 500}), domain="localhost")
        assert c.get("/leases").data == b"per_page=all"

    def test_one_pages_choice_is_not_another_pages(self, mini_app):
        c = mini_app.test_client()
        c.get("/leases?per_page=100")
        assert c.get("/devices").data == b"per_page=all"
        assert c.get("/reservations").data == b"per_page=all"


class TestTheRoutesUseIt:
    """Source checks: the three list routes read and set the cookie through view_prefs and nothing else touches it."""

    @pytest.mark.parametrize(
        "name,page", [("leases", "leases"), ("devices", "devices"), ("reservations", "reservations")]
    )
    def test_the_route_resolves_and_remembers(self, name, page):
        import pathlib

        text = pathlib.Path("jen/routes", f"{name}.py").read_text(encoding="utf-8")
        assert f'__view_prefs.resolve("{page}", request.args, request.cookies)' in text
        assert text.count("__view_prefs.remember(") == 2  # the swap and the full page

    def test_no_route_reads_the_cookie_by_hand(self):
        import pathlib

        offenders = [
            p.as_posix()
            for p in sorted(pathlib.Path("jen").rglob("*.py"))
            if re.search(r"""["']jen_view["']""", p.read_text(encoding="utf-8")) and p.name != "view_prefs.py"
        ]
        assert not offenders, offenders


class TestRoutes:
    """Against the real pages (needs the CI database)."""

    @staticmethod
    def _selected(body, value):
        select = re.search(r'<select name="per_page".*?</select>', body, re.S).group(0)
        return re.search(rf'<option value="{value}"\s+selected', select) is not None

    @pytest.mark.parametrize("path", ["/leases", "/devices", "/reservations"])
    def test_a_get_with_per_page_sets_the_cookie_and_the_next_get_without_it_shows_it_selected(
        self, logged_in_client, path
    ):
        r = logged_in_client.get(f"{path}?per_page=100")
        assert r.status_code == 200 and self._selected(r.data.decode(), "100")
        assert [h for h in _set_cookie_headers(r) if h.startswith("jen_view=")], "the choice was not remembered"
        again = logged_in_client.get(path)
        assert self._selected(again.data.decode(), "100"), "the next visit forgot it"

    @pytest.mark.parametrize("path", ["/leases", "/devices", "/reservations"])
    def test_an_explicit_value_wins_over_the_cookie(self, logged_in_client, path):
        logged_in_client.get(f"{path}?per_page=100")
        body = logged_in_client.get(f"{path}?per_page=50").data.decode()
        assert self._selected(body, "50") and not self._selected(body, "100")

    @pytest.mark.parametrize("path", ["/leases", "/devices", "/reservations"])
    def test_the_swap_is_remembered_too(self, logged_in_client, path):
        r = logged_in_client.get(f"{path}?per_page=250", headers={"HX-Request": "true"})
        assert [h for h in _set_cookie_headers(r) if h.startswith("jen_view=")]
        assert self._selected(logged_in_client.get(path).data.decode(), "250")

    def test_clear_keeps_the_remembered_page_size(self, logged_in_client):
        logged_in_client.get("/leases?per_page=100&search=zzz-nothing")
        body = logged_in_client.get("/leases").data.decode()  # the Clear button's href
        assert self._selected(body, "100")

    def test_the_history_and_stale_modes_are_not_remembered(self, logged_in_client):
        logged_in_client.get("/leases?expired=1&per_page=100")
        assert 'name="expired" value="0"' in logged_in_client.get("/leases").data.decode()
        logged_in_client.get("/devices?stale=1&per_page=100")
        assert (
            "checked" not in logged_in_client.get("/devices").data.decode().split('name="stale"', 1)[1].split(">", 1)[0]
        )

    def test_a_scoped_account_with_a_cookie_sees_exactly_what_it_saw_without_one(self, client, db):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="view_cookie_viewer")
        plain = client.get("/leases").data.decode()
        client.set_cookie("jen_view", '{"leases":"250"}', domain="localhost")
        with_cookie = client.get("/leases").data.decode()

        def rows(body):
            return re.findall(r'<tr(?: id="[^"]*")?>.*?</tr>', body, re.S)

        assert rows(with_cookie) == rows(plain)

    def test_junk_in_the_cookie_does_not_break_any_page(self, logged_in_client):
        for junk in ("junk", '{"leases":"7"}', "[1,2]", '{"leases":"100","x":"' + "y" * 400 + '"}'):
            logged_in_client.set_cookie("jen_view", junk, domain="localhost")
            for path in ("/leases", "/devices", "/reservations"):
                assert logged_in_client.get(path).status_code == 200, (junk, path)
