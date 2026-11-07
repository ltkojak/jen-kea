"""
tests/test_session_notice.py
────────────────────────────
v5.70.0-beta.4 (Q208, AX2): the idle sign-out is announced two minutes ahead and comes back to the page. v5.70.0-beta.5 (Q210): the notice is scheduled, moved and ended by the server's clock
and the server's answer, and a page that only refreshes itself does not keep a session alive.

One definition of the deadline (`jen/services/session_timeout.py`) serves the middleware, the `X-Jen-Session-Expires` header, the `<body data-session-expires>` attribute and `POST /session/touch`.
The first class is pure (`py -m pytest --noconftest tests/test_session_notice.py::TestDeadline`); the rest run against the app.
"""

import contextlib
import json
import logging
import pathlib
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pytest

from jen.services import session_timeout as st
from tests.test_csrf import (  # noqa: F401  (the suite's CSRF-on client pattern)
    _valid_token_for,
    csrf_client,
    logged_in_csrf_client,
)


class _User:
    def __init__(self, session_timeout=None):
        self.session_timeout = session_timeout


def _settings(monkeypatch, **values):
    monkeypatch.setattr(st, "get_global_setting", lambda key, default="": values.get(key, default))


def _iso(minutes_ago):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


@contextlib.contextmanager
def _timeout_set(**values):
    """Global settings for the length of a test (the settings cache dropped on the way in and the way out)."""
    from jen.models.user import _invalidate_settings_cache, get_global_setting, set_global_setting

    before = {k: get_global_setting(k, None) for k in values}
    for k, v in values.items():
        set_global_setting(k, v)
    _invalidate_settings_cache()
    try:
        yield
    finally:
        for k, v in before.items():
            set_global_setting(
                k,
                v if v is not None else {"session_timeout_enabled": "true", "session_timeout_minutes": "60"}.get(k, ""),
            )
        _invalidate_settings_cache()


class TestDeadline:
    def test_off_by_the_global_switch_is_none(self, monkeypatch):
        _settings(monkeypatch, session_timeout_enabled="false", session_timeout_minutes="60")
        assert st.deadline({"last_active": _iso(1)}, _User()) is None
        assert st.timeout_minutes(_User()) is None

    def test_a_timeout_of_zero_is_none(self, monkeypatch):
        _settings(monkeypatch, session_timeout_enabled="true", session_timeout_minutes="0")
        assert st.deadline({"last_active": _iso(1)}, _User()) is None

    def test_last_active_plus_the_global_minutes(self, monkeypatch):
        _settings(monkeypatch, session_timeout_enabled="true", session_timeout_minutes="45")
        last = datetime(2026, 11, 2, 12, 0, 0, tzinfo=timezone.utc)
        assert st.deadline({"last_active": last.isoformat()}, _User()) == last + timedelta(minutes=45)
        assert st.expires_at({"last_active": last.isoformat()}, _User()) == int(
            (last + timedelta(minutes=45)).timestamp()
        )

    def test_the_users_own_timeout_wins_over_the_global(self, monkeypatch):
        _settings(monkeypatch, session_timeout_enabled="true", session_timeout_minutes="45")
        last = datetime(2026, 11, 2, 12, 0, 0, tzinfo=timezone.utc)
        assert st.deadline({"last_active": last.isoformat()}, _User(session_timeout=10)) == last + timedelta(minutes=10)

    def test_a_last_active_the_arithmetic_cannot_carry_is_none_never_a_500(self, monkeypatch):
        """Q210 (Y7): `moment + timedelta(minutes=...)` raises OverflowError for a year-9999 value; beta.3's middleware caught everything there, beta.4 narrowed the catch."""
        _settings(monkeypatch, session_timeout_enabled="true", session_timeout_minutes="45")
        assert st.deadline({"last_active": "9999-12-31T23:59:00+00:00"}, _User()) is None
        assert st.expires_at({"last_active": "9999-12-31T23:59:00+00:00"}, _User()) is None

    @pytest.mark.parametrize("bad", [None, "", "not a date", 5, "2026-11-02T12:00:00"])
    def test_a_missing_unreadable_or_naive_last_active_is_none_never_expired(self, monkeypatch, bad):
        _settings(monkeypatch, session_timeout_enabled="true", session_timeout_minutes="45")
        assert st.deadline({"last_active": bad}, _User()) is None
        assert st.deadline({}, _User()) is None


class TestTheHeader:
    def _last(self, client):
        with client.session_transaction() as sess:
            return datetime.fromisoformat(sess["last_active"])

    def test_an_authenticated_html_response_carries_the_deadline(self, logged_in_client):
        r = logged_in_client.get("/leases")
        assert r.status_code == 200
        header = int(r.headers["X-Jen-Session-Expires"])
        from jen.models.user import get_global_setting

        minutes = int(get_global_setting("session_timeout_minutes", "60"))
        assert header == int((self._last(logged_in_client) + timedelta(minutes=minutes)).timestamp())

    def test_the_servers_own_clock_travels_with_the_deadline(self, logged_in_client):
        """SP-3: the page counts down against the SERVER's now, so a browser clock that is wrong changes nothing."""
        r = logged_in_client.get("/leases")
        assert abs(int(r.headers["X-Jen-Session-Now"]) - int(datetime.now(timezone.utc).timestamp())) < 30
        m = re.search(r'<body[^>]*\bdata-session-now="(\d+)"', r.data.decode())
        assert m and abs(int(m.group(1)) - int(r.headers["X-Jen-Session-Now"])) < 5

    def test_the_body_attribute_equals_the_header(self, logged_in_client):
        r = logged_in_client.get("/leases")
        m = re.search(r'<body[^>]*\bdata-session-expires="(\d+)"', r.data.decode())
        assert m and m.group(1) == r.headers["X-Jen-Session-Expires"]

    def test_an_api_poll_does_not_move_the_deadline_and_says_so(self, logged_in_client):
        first = logged_in_client.get("/leases").headers["X-Jen-Session-Expires"]
        second = logged_in_client.get("/api/stats").headers.get("X-Jen-Session-Expires")
        assert second == first, "/api/ polls never extend the session, and the header must not pretend they did"

    def test_anonymous_carries_none(self, client):
        r = client.get("/login")
        assert "X-Jen-Session-Expires" not in r.headers
        assert b"data-session-expires" not in r.data

    def test_static_files_carry_none(self, logged_in_client):
        assert "X-Jen-Session-Expires" not in logged_in_client.get("/static/js/htmx.min.js").headers

    def test_timeout_off_carries_the_word_off_beside_the_servers_clock(self, logged_in_client):
        """THE ONE Q208 CASE Q210 INVERTS, on purpose (AZ1 b / Y4): beta.4 asserted that a switched-off timeout carries NO header, and an absence cannot tell an open page that the
        deadline it holds no longer applies - it walked a live session to the sign-in page. "Off" is a word now, and it comes with the server's clock like every deadline."""
        with _timeout_set(session_timeout_enabled="false"):
            r = logged_in_client.get("/leases")
            assert r.headers["X-Jen-Session-Expires"] == "off"
            assert abs(int(r.headers["X-Jen-Session-Now"]) - int(datetime.now(timezone.utc).timestamp())) < 30
            m = re.search(r'<body[^>]*\bdata-session-expires="([^"]*)"[^>]*\bdata-session-now="(\d+)"', r.data.decode())
            assert m and m.group(1) == "off", (
                "(the script that reads the attribute names it too: only the body tag counts)"
            )

    def test_anonymous_and_static_carry_none_even_when_the_timeout_is_off(self, app, logged_in_client):
        with _timeout_set(session_timeout_enabled="false"):
            assert "X-Jen-Session-Expires" not in logged_in_client.get("/static/js/htmx.min.js").headers
            anon = app.test_client().get("/login")
            assert "X-Jen-Session-Expires" not in anon.headers and b"data-session-expires" not in anon.data


class TestTouch:
    def test_post_moves_last_active_to_now_and_answers_when_it_ends(self, app, logged_in_csrf_client):  # noqa: F811
        c = logged_in_csrf_client
        with c.session_transaction() as sess:
            sess["last_active"] = _iso(30)
        r = c.post("/session/touch", headers={"X-CSRFToken": _valid_token_for(app, c)})
        assert r.status_code == 200
        body = r.get_json()
        assert body["ok"] is True
        with c.session_transaction() as sess:
            last = datetime.fromisoformat(sess["last_active"])
        assert (datetime.now(timezone.utc) - last).total_seconds() < 30
        assert body["expires_at"] == st.expires_at({"last_active": last.isoformat()}, _User())
        assert abs(body["now"] - int(datetime.now(timezone.utc).timestamp())) < 30

    def test_a_get_is_405(self, logged_in_client):
        assert logged_in_client.get("/session/touch").status_code == 405

    def test_a_405_does_not_move_last_active_either(self, logged_in_client):
        """SP-2: the middleware leaves last_active alone for this path - the view is its one writer, so a request the routing or CSRF then refuses cannot extend the session."""
        stale = _iso(30)
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = stale
        for method in ("get", "head"):
            assert getattr(logged_in_client, method)("/session/touch").status_code == 405
        with logged_in_client.session_transaction() as sess:
            assert sess["last_active"] == stale

    def test_without_the_csrf_token_it_is_refused_like_every_post(self, logged_in_csrf_client):  # noqa: F811
        c = logged_in_csrf_client
        stale = _iso(30)
        with c.session_transaction() as sess:
            sess["last_active"] = stale
        r = c.post("/session/touch")
        assert r.status_code in (400, 403)
        with c.session_transaction() as sess:
            assert sess["last_active"] == stale, "a refused touch must not move last_active"

    def test_a_cross_site_post_without_the_token_cannot_extend_a_session(self, logged_in_csrf_client):  # noqa: F811
        c = logged_in_csrf_client
        stale = _iso(30)
        with c.session_transaction() as sess:
            sess["last_active"] = stale
        r = c.post("/session/touch", headers={"Origin": "https://evil.example", "X-CSRFToken": "forged"})
        assert r.status_code in (400, 403)
        with c.session_transaction() as sess:
            assert sess["last_active"] == stale

    def test_anonymous_gets_the_login_redirect_and_nothing_moves(self, app, csrf_client):  # noqa: F811
        """Q215 (Z5): an ANONYMOUS request gets the same `Location` an expired session gets - the WHOLE value, not its path. Six shapes answer the 6-character `/login`; an ordinary page keeps its `next`."""
        token = {"X-CSRFToken": _valid_token_for(app, csrf_client)}
        shapes = [
            ("GET", "/api/stats", "/login"),
            ("GET", "/logout", "/login"),
            ("POST", "/session/touch", "/login"),
            ("POST", "/users/add", "/login"),
            ("POST", "/leases/release", "/login"),
            ("GET", "/leases?q=" + "a" * 4000, "/login"),
            ("GET", "/leases", "/login?next=%2Fleases"),
        ]
        for method, path, expected in shapes:
            r = csrf_client.open(path, method=method, headers=token)
            assert r.status_code == 302, (method, path[:40], r.status_code)
            assert r.headers["Location"] == expected, (method, path[:40], r.headers["Location"])
        with csrf_client.session_transaction() as sess:
            assert "last_active" not in sess

    def test_the_answer_says_null_when_the_timeout_is_off(self, app, logged_in_csrf_client):  # noqa: F811
        """Q210 (AZ1 b): the same state the header says as the word `off` is `expires_at: null` in the body (and `now` still comes with it)."""
        with _timeout_set(session_timeout_enabled="false"):
            c = logged_in_csrf_client
            r = c.post("/session/touch", headers={"X-CSRFToken": _valid_token_for(app, c)})
            assert r.status_code == 200
            assert r.get_json()["ok"] is True and r.get_json()["expires_at"] is None
            assert abs(r.get_json()["now"] - int(datetime.now(timezone.utc).timestamp())) < 30

    def test_it_moves_last_active_and_nothing_else(self, app, logged_in_csrf_client):  # noqa: F811
        c = logged_in_csrf_client
        with c.session_transaction() as sess:
            before = {k: v for k, v in sess.items() if k != "last_active"}
        c.post("/session/touch", headers={"X-CSRFToken": _valid_token_for(app, c)})
        with c.session_transaction() as sess:
            after = {k: v for k, v in sess.items() if k != "last_active"}
        ignore = {
            "_csrf_nonce",
            "_user_cache",
            "_fresh",
            "login_id",
        }  # Flask-Login refreshes its own cache and freshness flag on any request; the middleware labels a session that has no sign-in label yet (Q210, AZ9 b) - once
        assert {k: v for k, v in after.items() if k not in ignore} == {
            k: v for k, v in before.items() if k not in ignore
        }


class TestTheRedirectCarriesNext:
    def _expire(self, client, minutes=24 * 60):
        with client.session_transaction() as sess:
            sess["last_active"] = _iso(minutes)

    def test_an_expired_get_comes_back_to_the_page(self, logged_in_client):
        self._expire(logged_in_client)
        r = logged_in_client.get("/leases?subnet=2")
        assert r.status_code == 302
        assert r.headers["Location"].endswith("/login?next=%2Fleases%3Fsubnet%3D2")

    def test_a_get_without_a_query_carries_the_bare_path(self, logged_in_client):
        self._expire(logged_in_client)
        assert logged_in_client.get("/leases").headers["Location"].endswith("/login?next=%2Fleases")

    def test_an_expired_post_goes_to_the_login_page_with_no_next(self, logged_in_client):
        self._expire(logged_in_client)
        r = logged_in_client.post("/session/touch")
        assert r.status_code == 302
        assert r.headers["Location"].endswith("/login") and "next" not in r.headers["Location"]

    def test_the_expiry_is_still_said_in_words(self, logged_in_client):
        self._expire(logged_in_client)
        page = logged_in_client.get("/leases", follow_redirects=True).data.decode()
        assert "Session expired" in page

    def test_the_login_page_goes_to_next_after_sign_in_and_refuses_an_outside_one(self):
        from jen.routes.auth import _safe_next

        assert _safe_next("/leases?subnet=2") == "/leases?subnet=2"
        assert _safe_next("//evil.example") == ""
        assert _safe_next("/\\evil.example") == ""

    def test_the_keep_branch_measures_next_the_way_the_ordinary_branch_does(self):
        """Q210 (Y5): the sign-in request the browser makes at the deadline carries `next`; a 4,015-character one used to come back as a 4,033-character Location (a request-line overflow).
        It is dropped like the ordinary branch drops it - the bare sign-in page."""
        long_next = "/leases?search=" + "a" * 4000
        assert st.login_redirect_location("/login", "GET", "/login?next=x", long_next) == "/login"
        short = "/leases?search=" + "a" * 100
        assert st.login_redirect_location("/login", "GET", "/login?next=x", short).startswith("/login?next=")

    def test_a_path_that_looks_like_a_host_is_not_followed_out(self, logged_in_client):
        self._expire(logged_in_client)
        r = logged_in_client.get("//evil.example/x")
        loc = r.headers.get("Location", "")
        # whatever the app answers, the redirect never leaves this host through `next`
        assert "evil.example" not in urlsplit(loc).netloc
        if "next=" in loc:
            from urllib.parse import parse_qs

            from jen.routes.auth import _safe_next

            assert _safe_next(parse_qs(urlsplit(loc).query).get("next", [""])[0]) == ""


class TestMiddlewareUnchanged:
    """The branches of the old `check_session_timeout`. (The login cases around tests/test_auth.py:56 are not timeout cases, and these branches had no test at all before this Q: this class is
    the net that was missing, written against the OLD behavior and run against the new.)"""

    def _last(self, client):
        with client.session_transaction() as sess:
            return sess.get("last_active")

    def test_inside_the_timeout_the_session_lives_and_is_touched(self, logged_in_client):
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = _iso(5)
        assert logged_in_client.get("/leases").status_code == 200
        assert (datetime.now(timezone.utc) - datetime.fromisoformat(self._last(logged_in_client))).total_seconds() < 30

    def test_past_the_timeout_the_session_ends_with_a_flash(self, logged_in_client):
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = _iso(24 * 60)
        r = logged_in_client.get("/leases")
        assert r.status_code == 302
        with logged_in_client.session_transaction() as sess:
            assert "_user_id" not in sess

    def test_a_session_without_last_active_is_given_one(self, logged_in_client):
        with logged_in_client.session_transaction() as sess:
            sess.pop("last_active", None)
        assert logged_in_client.get("/leases").status_code == 200
        assert self._last(logged_in_client)

    def test_an_unreadable_last_active_does_not_end_the_session_and_is_replaced(self, logged_in_client):
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = "garbage"
        assert logged_in_client.get("/leases").status_code == 200
        datetime.fromisoformat(self._last(logged_in_client))

    def test_api_and_metrics_do_not_touch_last_active(self, logged_in_client):
        stale = _iso(10)
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = stale
        logged_in_client.get("/api/stats")
        assert self._last(logged_in_client) == stale

    def test_timeout_off_never_ends_the_session_and_touches_it(self, logged_in_client):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("session_timeout_enabled", "false")
        _invalidate_settings_cache()
        try:
            with logged_in_client.session_transaction() as sess:
                sess["last_active"] = _iso(24 * 60)
            assert logged_in_client.get("/leases").status_code == 200
            assert (
                datetime.now(timezone.utc) - datetime.fromisoformat(self._last(logged_in_client))
            ).total_seconds() < 30
        finally:
            set_global_setting("session_timeout_enabled", "true")
            _invalidate_settings_cache()


class TestTheTouchPathIsNotTouchedByTheMiddleware:
    def test_the_path_list(self):
        assert st.NO_TOUCH_PATHS == ("/session/touch",)

    def test_the_middleware_names_it_in_every_branch(self):
        """Q210 (AZ3, second pass 5): all three branches that can write `last_active` ask `extends()`, the one definition (it names the touch path, `/api/`, `/metrics` and the poll marker)."""
        text = pathlib.Path("jen/__init__.py").read_text(encoding="utf-8")
        assert text.count("session_timeout_svc.NO_TOUCH_PATHS") == 0, (
            "no branch names the list itself any more: extends() does, once"
        )
        assert (
            text.count("if extends:") == 3
            and "session_timeout_svc.extends(request.path, request.headers, request.args, request.method)" in text
        )


class TestTheReturnAddress:
    """`login_redirect_location`: a GET of an ordinary page comes back to itself; nothing that would loop, land a person on JSON, or leave this host is ever a `next`."""

    @pytest.mark.parametrize(
        ("method", "full_path", "expected"),
        [
            ("GET", "/leases?subnet=2", "/login?next=%2Fleases%3Fsubnet%3D2"),
            ("GET", "/leases?", "/login?next=%2Fleases"),
            ("GET", "/leases?search=a%26b&page=2", "/login?next=%2Fleases%3Fsearch%3Da%2526b%26page%3D2"),
            ("POST", "/leases?", "/login"),
            ("PUT", "/leases?", "/login"),
            ("GET", "/login?", "/login"),
            ("GET", "/logout?", "/login"),
            ("GET", "/api/stats?", "/login"),
            ("GET", "/metrics?", "/login"),
            ("GET", "/session/touch?", "/login"),
            ("GET", "/auth/reauth?", "/login"),
            ("GET", "/static/js/x.js?", "/login"),
            ("GET", "//evil.example/x?", "/login"),
            ("GET", "evil?", "/login"),
        ],
    )
    def test_where_an_expired_session_goes(self, method, full_path, expected):
        assert st.login_redirect_location("/login", method, full_path) == expected

    @pytest.mark.parametrize(
        ("next_arg", "expected"),
        [
            ("/leases", "/login?next=%2Fleases"),
            ("/leases?subnet=2", "/login?next=%2Fleases%3Fsubnet%3D2"),
            ("//evil.example", "/login"),
            ("https://evil.example/", "/login"),
            ("/\\evil.example", "/login"),
            ("", "/login"),
        ],
    )
    def test_the_deadline_navigation_keeps_its_next_through_the_expired_sign_in_request(self, next_arg, expected):
        """The dialog's script goes to /login?next=<page> at the deadline; the server already ended the session, so ITS request is the expired one - and its `next` must survive."""
        assert st.login_redirect_location("/login", "GET", "/login?next=x", next_arg) == expected

    def test_a_very_long_path_carries_no_next(self):
        """SP-13: percent-encoding grows a path ~1.7x; a sign-in request line past the server's limit is a 400, not a page."""
        long = "/leases?search=" + "a" * (st.MAX_NEXT + 50)
        assert st.login_redirect_location("/login", "GET", long) == "/login"
        assert st.login_redirect_location("/login", "GET", "/leases?search=" + "a" * 100).startswith("/login?next=")

    def test_whatever_it_builds_the_sign_in_page_accepts_back(self):
        from urllib.parse import parse_qs, urlsplit

        from jen.routes.auth import _safe_next

        for path in ("/leases?subnet=2", "/devices?search=x%20y", "/reservations?page=3&per_page=50"):
            location = st.login_redirect_location("/login", "GET", path)
            back = parse_qs(urlsplit(location).query)["next"][0]
            assert _safe_next(back) == path


class TestTheDialogScript:
    """Source pins for the client side of the notice (SP-3, SP-6, SP-7 and Q210's Y1, Y4, Y10, Y14 and the reviewer's three additions); the behavior itself is tests/e2e/test_session_notice.py.
    Q210 moved the script, byte for byte where it did not change, from base.html to templates/_session_watch.html."""

    BASE = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
    WATCH = pathlib.Path("templates/_session_watch.html").read_text(encoding="utf-8")
    FORCED = pathlib.Path("templates/force_password_change.html").read_text(encoding="utf-8")

    def test_the_watch_is_one_included_file(self):
        assert '{% include "_session_watch.html" %}' in self.BASE
        assert '_session_watch.html" %}' in self.FORCED and "session_watch_standalone=true" in self.FORCED
        assert "function goToLogin()" not in self.BASE and '<div id="jen-session-overlay"' not in self.BASE
        assert self.WATCH.count('<script nonce="{{ csp_nonce }}">') == 1
        assert self.WATCH.count('<div id="jen-session-overlay"') == 1
        assert "included, never returned for an htmx swap" in self.WATCH

    def test_time_is_counted_against_the_servers_clock_on_a_monotonic_timer(self):
        """Q208 pinned `Date.now() / 1000 + skew` here. AZ9 (c) moves the watch to the browser's MONOTONIC clock (`performance.now()`, anchored at the server's `now` each reply), so that pin is rewritten:
        a wall-clock change while the page is open must move nothing, and the wall clock is no longer read at all."""
        assert "function nowS() { return anchorServer + (performance.now() - anchorPerf) / 1000; }" in self.WATCH
        assert "Date.now" not in self.WATCH
        assert "X-Jen-Session-Now" in self.WATCH and "data-session-now" in self.WATCH

    def test_every_timer_is_scheduled_on_that_same_clock(self):
        """Q208 pinned the existence of `skew` and `nowS` - and the scheduler beside them read the browser's own clock (Y1): a browser behind never reached the dialog, a browser ahead spun a zero-delay timer."""
        block = self.WATCH[self.WATCH.index("function arm()") : self.WATCH.index("// value: an epoch second")]
        assert "(expires - lead - nowS()) * 1000" in block and "setTimeout(check, armedMs)" in block
        assert "(expires - lead) * 1000 - Date.now()" not in self.WATCH
        check = self.WATCH[self.WATCH.index("function check()") : self.WATCH.index("function arm()")]
        assert check.index("openDialog(); return;") < check.index("arm();"), (
            "the dialog opens BEFORE the timer is re-armed, so the spin cannot recur"
        )

    def test_a_deadline_is_taken_only_with_the_servers_clock_and_never_from_an_older_reply(self):
        assert "if (!(sn > 0) || sn < lastServerNow) return;" in self.WATCH

    def test_a_reply_is_authoritative_in_both_directions_and_off_is_a_word(self):
        block = self.WATCH[self.WATCH.index("function ingest(") : self.WATCH.index("function stayFailed(")]
        assert "if (fromStorage && (off ? !expires : n <= expires)) return;" in block, (
            "a value from another tab only ever moves the deadline forward"
        )
        assert "if (n !== expires) {" in block and "expires = n;" in block, "a reply moves it either way"
        off = block[block.index("if (off) {") : block.index("if (n !== expires)")]
        for step in ("expires = 0;", "stopWarn();", "closeDialog();", "store('off:' + sn + ':' + lastActive);"):
            assert step in off, step
        assert "value === 'off'" in block

    def test_an_absurd_deadline_is_ignored(self):
        assert (
            "var MAX_AHEAD = 31622400;" in self.WATCH
            and "if (!off && (!(n > sn) || n > sn + MAX_AHEAD)) return;" in self.WATCH
        )
        assert "if (!off && !/^[0-9]{1,12}$/.test(String(value))) return;" in self.WATCH, (
            "digits only: parseInt would read 12abc as 12"
        )

    def test_leaving_happens_once_and_stops_the_timers(self):
        block = self.WATCH[self.WATCH.index("function goToLogin()") : self.WATCH.index("function signOut()")]
        assert "if (leaving) return;" in block and "stopWarn();" in block and "clearInterval(tickTimer)" in block

    def test_a_redirect_is_judged_by_where_it_went(self):
        """Q208 pinned the literal line `if (r.redirected) { goToLogin(); return null; }`, which is what made Y10 possible: a redirect to the forced password change, to https or to a proxy's canonical
        host is not the session's end. The pin is rewritten to the rule SP-6's own fix row stated: only a redirect to the sign-in page."""
        block = self.WATCH[
            self.WATCH.index("function stay()") : self.WATCH.index("if (stayBtn) stayBtn.addEventListener")
        ]
        assert (
            "if (r.redirected) {" in block
            and "u.pathname === '/login'" in block
            and "window.location.assign(u.href)" in block
        )
        assert block.count("goToLogin()") == 1

    def test_a_failure_of_the_touch_is_not_an_expiry(self):
        block = self.WATCH[
            self.WATCH.index("function stay()") : self.WATCH.index("if (stayBtn) stayBtn.addEventListener")
        ]
        assert "r.status === 403" in block and block.count("stayFailed(") >= 4
        assert 'id="jen-session-failed"' in self.WATCH

    def test_the_cross_tab_key_belongs_to_one_sign_in(self):
        assert "var KEY_PREFIX = 'jen-session-expires:';" in self.WATCH
        assert "KEY_PREFIX + (document.body.getAttribute('data-session-login') || '')" in self.WATCH
        sign_out = self.WATCH[self.WATCH.index("function signOut()") : self.WATCH.index("function tick()")]
        assert "forget();" in sign_out
        assert "expires + ':' + sn + ':' + lastActive" in self.WATCH, (
            "a stored value carries the deadline, the server's clock and the session state"
        )

    def test_the_hooks_the_browser_tests_drive(self):
        assert "window.jenSessionWatch = {" in self.WATCH
        for hook in ("ingest: ingest", "expires: function()", "state: function()"):
            assert hook in self.WATCH, hook
        assert (
            "{ expires: expires, lead: lead, armed: armedMs, open: dialogOpen(), lastServerNow: lastServerNow }"
            in self.WATCH
        )


class TestAPollNeverExtends:
    """Q210 (AZ3, Y3): a request that only refreshes a view says so with `X-Jen-Poll: 1`, and the middleware never moves `last_active` for it. The header can only STOP an extension."""

    def test_every_self_refreshing_element_carries_the_header(self):
        found = []
        for path in sorted(pathlib.Path("templates").rglob("*.html")) + sorted(pathlib.Path("plugins").rglob("*.html")):
            text = path.read_text(encoding="utf-8")
            for m in re.finditer(r'<[^<>]*hx-trigger="every [^<>]*>', text):
                found.append((str(path), '"X-Jen-Poll": "1"' in m.group(0)))
        assert len(found) >= 3, (
            f"the three pages that refresh themselves (Health Center, HA maintenance, a Trace watch): {found}"
        )
        assert all(ok for _, ok in found), [p for p, ok in found if not ok]

    def test_a_marked_request_leaves_last_active_byte_identical_and_an_unmarked_one_moves_it(self, logged_in_client):
        stale = _iso(10)
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = stale
        assert logged_in_client.get("/leases", headers={"X-Jen-Poll": "1"}).status_code == 200
        with logged_in_client.session_transaction() as sess:
            assert sess["last_active"] == stale
        assert logged_in_client.get("/leases").status_code == 200
        with logged_in_client.session_transaction() as sess:
            assert sess["last_active"] != stale

    def test_health_centers_own_poll_does_not_extend_the_session(self, logged_in_client):
        stale = _iso(10)
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = stale
        r = logged_in_client.get("/health-center/data?partial=1", headers={"X-Jen-Poll": "1"})
        assert r.status_code == 200
        with logged_in_client.session_transaction() as sess:
            assert sess["last_active"] == stale

    def test_only_the_exact_value_counts(self, logged_in_client):
        """'1' is the marker; anything else is an ordinary request and extends (the header is not a switch with a wider meaning)."""
        for value in ("0", "true", "", "1, 1", "11"):
            stale = _iso(10)
            with logged_in_client.session_transaction() as sess:
                sess["last_active"] = stale
            logged_in_client.get("/leases", headers={"X-Jen-Poll": value})
            with logged_in_client.session_transaction() as sess:
                assert sess["last_active"] != stale, repr(value)

    def test_a_poll_by_an_anonymous_client_is_the_login_redirect(self, app):
        r = app.test_client().get("/health-center/data?partial=1", headers={"X-Jen-Poll": "1"})
        assert r.status_code == 302 and urlsplit(r.headers["Location"]).path == "/login"

    def test_health_centers_poll_without_the_header_does_extend(self, logged_in_client):
        """The control for the row above: the same URL, no marker, moves it (the header is what makes the difference)."""
        stale = _iso(10)
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = stale
        assert logged_in_client.get("/health-center/data?partial=1").status_code == 200
        with logged_in_client.session_transaction() as sess:
            assert sess["last_active"] != stale

    def test_a_reload_that_marks_itself_does_not_extend_either(self, logged_in_client):
        """Second pass 3: the Servers page reloads itself every 30 s, and a navigation cannot carry a header - `?_poll=1` is the same marker for it."""
        stale = _iso(10)
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = stale
        logged_in_client.get("/leases?_poll=1")
        with logged_in_client.session_transaction() as sess:
            assert sess["last_active"] == stale
        assert "_poll" in pathlib.Path("templates/servers.html").read_text(encoding="utf-8")
        assert "searchParams.delete('_poll')" in pathlib.Path("templates/base.html").read_text(encoding="utf-8")

    def test_every_fetch_inside_an_interval_carries_the_marker(self):
        """Q215 (Z4): the source half asks EVERY `fetch(` / `jenFetch(` inside a `setInterval` body, read to the matching bracket (the Q210 test read 600 characters past each `setInterval`, and the update
        screen's second request sat past them). A click is activity and stays unmarked; a request that repeats on its own is a poll."""
        seen = []
        for path, line, body in _set_interval_calls():
            assert body, (path, line)
            for m in re.finditer(r"\b(?:jenFetch|fetch)\(", body):
                args = _call_args(body, m.end() - 1)
                seen.append((path, line))
                assert args and "'X-Jen-Poll': '1'" in args.replace('"', "'"), (path, line, (args or "")[:80])
        assert len(seen) >= 4, f"the scan would be vacuous: {seen}"

    def test_twelve_check_update_polls_end_in_a_sign_out(self, logged_in_client, monkeypatch):
        """Q215 (Z4), through the real middleware: under a one-minute timeout, twelve marked polls 50 s apart do not keep the session alive (signed out at the second); the same twelve unmarked ones do
        (that was the update screen's second request, which kept an unattended page signed in for as long as it polled)."""

        class _Gone:
            status_code = 404

        monkeypatch.setattr("requests.get", lambda *a, **k: _Gone())

        def shift(seconds):
            with logged_in_client.session_transaction() as sess:
                base = datetime.fromisoformat(sess["last_active"])
                sess["last_active"] = (base - timedelta(seconds=seconds)).isoformat()

        def run(headers):
            logged_in_client.get("/leases")  # a click: the session starts from now
            for n in range(1, 13):
                shift(50)
                r = logged_in_client.get("/settings/infrastructure/check-update", headers=headers)
                if r.status_code == 302:
                    return n
            return None

        with _timeout_set(session_timeout_minutes="1", session_timeout_enabled="true"):
            assert run({"X-Jen-Poll": "1"}) == 2
            with logged_in_client.session_transaction() as sess:
                assert "_user_id" not in sess

    def test_twelve_unmarked_check_update_calls_keep_a_session_alive(self, logged_in_client, monkeypatch):
        class _Gone:
            status_code = 404

        monkeypatch.setattr("requests.get", lambda *a, **k: _Gone())
        with _timeout_set(session_timeout_minutes="1", session_timeout_enabled="true"):
            logged_in_client.get("/leases")
            for _ in range(12):
                with logged_in_client.session_transaction() as sess:
                    base = datetime.fromisoformat(sess["last_active"])
                    sess["last_active"] = (base - timedelta(seconds=50)).isoformat()
                assert logged_in_client.get("/settings/infrastructure/check-update").status_code == 200

    def test_a_post_with_the_query_marker_extends_like_the_plain_post(self, logged_in_client):
        """Q215 (Z13): `?_poll=1` is a GET's marker (a navigation cannot carry the header). On a POST it is nothing: `POST /settings/save-session?_poll=1` moves `last_active` like the plain POST."""
        stale = _iso(10)
        form = {"timeout_minutes": "60", "timeout_enabled": "true"}
        for url in ("/settings/save-session", "/settings/save-session?_poll=1"):
            with logged_in_client.session_transaction() as sess:
                sess["last_active"] = stale
            assert logged_in_client.post(url, data=form).status_code == 302
            with logged_in_client.session_transaction() as sess:
                assert sess["last_active"] != stale, url
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = stale
        logged_in_client.post("/settings/save-session", data=form, headers={"X-Jen-Poll": "1"})
        with logged_in_client.session_transaction() as sess:
            assert sess["last_active"] == stale, "the header form still denies an extension, on any method"

    def test_the_bounded_pollers_send_the_marker_too(self):
        for name in (
            "templates/plugins.html",
            "templates/settings_system.html",
            "templates/setup_recovery.html",
            "plugins/network-discovery/templates/network_discovery/index.html",
        ):
            assert "X-Jen-Poll" in pathlib.Path(name).read_text(encoding="utf-8"), name

    def test_with_the_timeout_off_the_api_poll_does_not_write_it_either(self, logged_in_client):
        """Second pass 5: the timeout-off and no-last_active branches used to name the touch path and the marker themselves and forgot /api/."""
        stale = _iso(10)
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = stale
        with _timeout_set(session_timeout_enabled="false"):
            logged_in_client.get("/api/stats")
            with logged_in_client.session_transaction() as sess:
                assert sess["last_active"] == stale

    def test_a_poll_past_the_deadline_is_signed_out_like_any_request(self, logged_in_client):
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = _iso(24 * 60)
        r = logged_in_client.get("/leases", headers={"X-Jen-Poll": "1"})
        assert r.status_code == 302
        with logged_in_client.session_transaction() as sess:
            assert "_user_id" not in sess

    def test_the_middleware_has_one_definition_of_what_extends(self):
        text = pathlib.Path("jen/__init__.py").read_text(encoding="utf-8")
        assert "session_timeout_svc.extends(request.path, request.headers, request.args, request.method)" in text
        assert st.extends("/leases", {}) and not st.extends("/leases", {"X-Jen-Poll": "1"})
        assert not st.extends("/servers", {}, {"_poll": "1"}) and st.extends("/servers", {}, {"_poll": "0"})
        assert (
            not st.extends("/api/stats", {}) and not st.extends("/metrics", {}) and not st.extends("/session/touch", {})
        )


class TestTheBootstrapSkipsTheSamePaths:
    """Y22: a session with no `last_active` is given one by the middleware - except for a poll and the touch path, which are the two requests that must not write it."""

    def _bare(self, client):
        with client.session_transaction() as sess:
            sess.pop("last_active", None)

    def test_a_poll_leaves_it_unset(self, logged_in_client):
        self._bare(logged_in_client)
        assert logged_in_client.get("/leases", headers={"X-Jen-Poll": "1"}).status_code == 200
        with logged_in_client.session_transaction() as sess:
            assert "last_active" not in sess

    def test_the_touch_path_leaves_it_unset(self, logged_in_client):
        self._bare(logged_in_client)
        assert logged_in_client.get("/session/touch").status_code == 405
        with logged_in_client.session_transaction() as sess:
            assert "last_active" not in sess

    def test_an_ordinary_page_sets_it(self, logged_in_client):
        self._bare(logged_in_client)
        assert logged_in_client.get("/leases").status_code == 200
        with logged_in_client.session_transaction() as sess:
            assert datetime.fromisoformat(sess["last_active"])

    def test_with_the_timeout_off_a_poll_does_not_write_it_either(self, logged_in_client):
        stale = _iso(10)
        with logged_in_client.session_transaction() as sess:
            sess["last_active"] = stale
        with _timeout_set(session_timeout_enabled="false"):
            logged_in_client.get("/leases", headers={"X-Jen-Poll": "1"})
            with logged_in_client.session_transaction() as sess:
                assert sess["last_active"] == stale


class TestTheSettingIsReadOnce:
    """Q210 (AZ4, Y6): the global timeout is read through ONE coercion. A hand-edited row that is not a whole number of minutes from 0 to 1440 reads as 60 and is logged once per process."""

    @pytest.mark.parametrize(
        "bad", ["x", "", "60.5", "1e3", "9" * 20, "-5", "1441", " 5", "\uff15", "\u0665", "\u00b2", "1234567", None]
    )
    def test_a_value_that_is_not_a_whole_number_of_minutes_reads_as_the_default(self, monkeypatch, bad):
        _settings(monkeypatch, session_timeout_enabled="true", session_timeout_minutes=bad)
        assert st.timeout_minutes(_User()) == 60

    @pytest.mark.parametrize(
        ("good", "expected"), [("0", None), ("1", 1), ("1440", 1440), ("45", 45), (45, 45), ("00005", 5)]
    )
    def test_a_whole_number_in_range_is_taken_as_it_is(self, monkeypatch, good, expected):
        _settings(monkeypatch, session_timeout_enabled="true", session_timeout_minutes=good)
        assert st.timeout_minutes(_User()) == expected

    def test_the_users_own_timeout_goes_through_the_same_coercion(self, monkeypatch):
        _settings(monkeypatch, session_timeout_enabled="true", session_timeout_minutes="45")
        assert st.timeout_minutes(_User(session_timeout=10)) == 10
        assert st.timeout_minutes(_User(session_timeout=99999)) == 45, "out of range: the global applies"
        assert st.timeout_minutes(_User(session_timeout=0)) == 45, "0 is 'use the global' for a user, as it always was"

    def test_the_writers_call_the_one_parser(self):
        """Second pass 2: the writers said `isdigit()` (which accepts full-width and Arabic-Indic digits, and 500s on `\u00b2`), the reader said ASCII - an administrator typing `\uff15` was told it was saved and got 60
        minutes. One parser, `session_timeout.parse_minutes`, in all four writers."""
        for name in ("jen/routes/settings/security.py", "jen/routes/users.py"):
            text = pathlib.Path(name).read_text(encoding="utf-8")
            assert "__session_timeout.parse_minutes(" in text, name
            assert "timeout.isdigit()" not in text and "timeout_raw.isdigit()" not in text, name

    @pytest.mark.parametrize(
        ("typed", "stored"), [("\uff15", None), ("\u0665", None), ("\u00b2", None), ("00005", "5"), ("30", "30")]
    )
    def test_the_session_form_stores_what_the_reader_applies(self, logged_in_client, typed, stored):
        with _timeout_set(session_timeout_minutes="60"):
            r = logged_in_client.post(
                "/settings/save-session", data={"timeout_minutes": typed, "timeout_enabled": "true"}
            )
            assert r.status_code == 302, "a refusal or a save, never a 500"
            from jen.models.user import get_global_setting

            assert get_global_setting("session_timeout_minutes", "60") == (stored or "60")

    def test_it_is_logged_once_per_process_and_cut_to_forty_characters(self, monkeypatch, caplog):
        st._warned.clear()
        _settings(monkeypatch, session_timeout_enabled="true", session_timeout_minutes="x" * 100)
        with caplog.at_level(logging.WARNING, logger=st.__name__):
            for _ in range(5):
                assert st.timeout_minutes(_User()) == 60
        records = [r for r in caplog.records if r.name == st.__name__]
        assert len(records) == 1
        assert "x" * 41 not in records[0].getMessage()

    def test_every_path_still_answers_with_a_hand_edited_row(self, logged_in_client):
        """Beta.4: `int("x")` in a before_request made every request a 500 - `/logout` included, so the person could not even sign out."""
        with _timeout_set(session_timeout_minutes="x"):
            for path in ("/leases", "/login", "/logout", "/api/stats"):
                assert logged_in_client.get(path).status_code < 500, path


class TestEveryDeadlineCarriesNow:
    """Q210 (AZ9 a): a deadline without the server's clock beside it is useless to the page (it cannot order two replies), so no response carries one without the other."""

    PATHS = ("/leases", "/api/stats", "/no-such-page-q210", "/session/touch")

    def test_no_response_carries_a_deadline_without_the_clock(self, logged_in_client):
        seen = 0
        for path in self.PATHS:
            r = logged_in_client.get(path)
            if "X-Jen-Session-Expires" in r.headers:
                seen += 1
                assert re.fullmatch(r"\d+", r.headers["X-Jen-Session-Now"]), path
        assert seen >= 2, "the rule would be vacuous if the headers were never sent"

    def test_the_same_holds_when_the_timeout_is_off(self, logged_in_client):
        with _timeout_set(session_timeout_enabled="false"):
            for path in self.PATHS:
                r = logged_in_client.get(path)
                if "X-Jen-Session-Expires" in r.headers:
                    assert r.headers["X-Jen-Session-Expires"] == "off" and "X-Jen-Session-Now" in r.headers, path

    def test_the_touch_answer_carries_it_in_the_body_and_the_header(self, app, logged_in_csrf_client):  # noqa: F811
        c = logged_in_csrf_client
        r = c.post("/session/touch", headers={"X-CSRFToken": _valid_token_for(app, c)})
        assert r.status_code == 200
        assert re.fullmatch(r"\d+", str(r.get_json()["now"])) and re.fullmatch(r"\d+", r.headers["X-Jen-Session-Now"])
        assert r.headers["X-Jen-Session-Expires"] == str(r.get_json()["expires_at"])

    def test_every_deadline_also_carries_the_session_state_it_was_computed_from(self, logged_in_client):
        """Second pass 1: the clock orders replies SENT, not the cookie they were built from; `X-Jen-Session-Active` (the epoch second of last_active) orders the state."""
        r = logged_in_client.get("/leases")
        with logged_in_client.session_transaction() as sess:
            last = int(datetime.fromisoformat(sess["last_active"]).timestamp())
        assert r.headers["X-Jen-Session-Active"] == str(last)
        m = re.search(r'<body[^>]*\bdata-session-active="(\d+)"', r.data.decode())
        assert m and m.group(1) == str(last)

    def test_the_touch_answer_carries_it_too(self, app, logged_in_csrf_client):  # noqa: F811
        c = logged_in_csrf_client
        r = c.post("/session/touch", headers={"X-CSRFToken": _valid_token_for(app, c)})
        assert re.fullmatch(r"\d+", str(r.get_json()["active"])) and r.headers["X-Jen-Session-Active"] == str(
            r.get_json()["active"]
        )

    def test_the_script_ignores_a_reply_built_from_an_older_session_state(self):
        text = pathlib.Path("templates/_session_watch.html").read_text(encoding="utf-8")
        assert "if (!(ac >= 0) || ac < lastActive) return;" in text and "if (ac > lastActive) lastActive = ac;" in text

    def test_the_script_ignores_a_deadline_that_arrives_without_a_clock(self):
        text = pathlib.Path("templates/_session_watch.html").read_text(encoding="utf-8")
        assert "if (!(sn > 0) || sn < lastServerNow) return;" in text

    def test_the_script_ignores_a_deadline_that_arrives_without_its_state_source(self):
        """The guard is a strict read of the state, and the server's word for "none" is `0` (the executed half is TestTheWatchScriptRuns)."""
        text = pathlib.Path("templates/_session_watch.html").read_text(encoding="utf-8")
        assert "/^[0-9]{1,12}$/.test(String(active)) ? parseInt(active, 10) : -1;" in text

    @pytest.mark.parametrize("timeout_enabled", ["true", "false"])
    def test_off_carries_a_numeric_state(self, logged_in_client, timeout_enabled):
        """Q215 (Z2 a): `X-Jen-Session-Active` travels beside EVERY `X-Jen-Session-Expires` - `off` and a session with no readable `last_active` included (`0` there). Over the paths the
        middleware answers differently (an extending page, a poll, an error page, the touch path) none carries a deadline without its state."""
        paths = (
            "/leases",
            "/devices",
            "/reservations",
            "/servers",
            "/api/stats",
            "/no-such-page-q215",
            "/session/touch",
            "/settings/system",
        )
        seen = 0
        with _timeout_set(session_timeout_enabled=timeout_enabled):
            for kind in ("with_last_active", "without_last_active"):
                for path in paths:
                    with logged_in_client.session_transaction() as sess:
                        if kind == "without_last_active":
                            sess.pop("last_active", None)
                    for headers in ({}, {"X-Jen-Poll": "1"}):
                        r = logged_in_client.get(path, headers=headers)
                        if "X-Jen-Session-Expires" in r.headers:
                            seen += 1
                            assert re.fullmatch(r"\d+", r.headers.get("X-Jen-Session-Active", "")), (
                                kind,
                                path,
                                headers,
                            )
        assert seen >= 20, "the rule would be vacuous if the headers were seldom sent"


class TestTheLoginIdIsPerLogin:
    """Q210 (AZ9 b): `session["login_id"]` is a label for ONE sign-in. It names the browser's cross-tab key, so a different account signing in within one browser profile never reads the old value.
    It is not a secret (the session cookie is the credential)."""

    ROW = {
        "id": 1,
        "username": "admin",
        "role": "superadmin",
        "session_timeout": None,
        "subnet_access": None,
        "must_change_password": 0,
        "token_version": 0,
        "password": "pbkdf2:sha256:x$y$z",
    }

    def test_two_sign_ins_get_two_labels(self, app):
        from flask import session

        from jen.services import oidc

        ids = []
        for _ in range(2):
            with app.test_request_context():
                oidc.establish_session(dict(self.ROW), "a test sign-in")
                ids.append(session["login_id"])
        assert ids[0] != ids[1] and all(re.fullmatch(r"[0-9a-f]{16}", i) for i in ids)

    def test_a_sign_out_clears_it(self, logged_in_client):
        logged_in_client.get("/leases")
        with logged_in_client.session_transaction() as sess:
            assert sess.get("login_id")
        logged_in_client.post("/logout")
        with logged_in_client.session_transaction() as sess:
            assert "login_id" not in sess

    def test_the_body_attribute_equals_the_sessions_and_is_stable(self, logged_in_client):
        """A session opened before the label existed (a fixture, an upgrade with a person signed in) is given one by the first request and keeps it."""
        pages = [logged_in_client.get("/leases").data.decode() for _ in range(2)]
        with logged_in_client.session_transaction() as sess:
            mine = sess["login_id"]
        for page in pages:
            m = re.search(r'<body[^>]*\bdata-session-login="([0-9a-f]*)"', page)
            assert m and m.group(1) == mine

    def test_a_poll_as_the_first_request_still_names_the_login(self, logged_in_client):
        """Q215 (Z19): a poll never writes `last_active`, so a page whose FIRST authenticated request is one has no deadline to announce - and used to render no login label either, so the browser's
        cross-tab key degenerated to the bare prefix. The label exists from the session's first request; only the deadline attributes depend on the announcement."""
        with logged_in_client.session_transaction() as sess:
            sess.pop("last_active", None)
            sess.pop("login_id", None)
        page = logged_in_client.get("/leases", headers={"X-Jen-Poll": "1"}).data.decode()
        body = re.search(r"<body[^>]*>", page).group(0)
        assert re.search(r'\bdata-session-login="[0-9a-f]{16}"', body), body
        assert "data-session-expires" not in body and "data-session-active" not in body, body

    def test_every_place_that_signs_a_person_in_sets_it(self):
        """Whole tree, not a file list: any function in jen/ that calls `login_user` must also set `login_id` (Q210's own lesson: a definition's fix is a fix to every use)."""
        import ast

        offenders, sites = [], 0
        for path in sorted(pathlib.Path("jen").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
                calls = [
                    c
                    for c in ast.walk(fn)
                    if isinstance(c, ast.Call) and getattr(c.func, "id", getattr(c.func, "attr", "")) == "login_user"
                ]
                if not calls:
                    continue
                sites += 1
                if "login_id" not in ast.get_source_segment(path.read_text(encoding="utf-8"), fn):
                    offenders.append(f"{path}:{fn.name}")
        assert sites >= 3, (
            "the walk found fewer sign-in sites than exist (establish_session and the two second-factor paths)"
        )
        assert not offenders, offenders


class TestTheForcedChangeScreenHasTheNotice:
    """Q210 (AZ1 d, Y10, Y11): the forced password change is not built on base.html, so it carried no idle notice at all; and the gate answered `POST /session/touch` with a redirect to its own form."""

    def test_the_template_includes_the_watch_and_carries_the_attributes(self):
        text = pathlib.Path("templates/force_password_change.html").read_text(encoding="utf-8")
        assert '{% include "_session_watch.html" %}' in text
        assert "data-session-expires" in text and "data-session-now" in text and "data-session-login" in text

    def test_the_standalone_dialog_is_styled_by_a_static_file_not_inline_hex(self):
        """tests/test_theme.py's hex wall is about templates: the standalone page's dialog colors live in static/css/session-watch.css, which the include links only for that page."""
        watch = pathlib.Path("templates/_session_watch.html").read_text(encoding="utf-8")
        assert "/static/css/session-watch.css" in watch and "<style" not in watch
        assert ".jen-dialog-overlay" in pathlib.Path("static/css/session-watch.css").read_text(encoding="utf-8")

    def test_the_gate_names_the_touch_endpoint(self):
        text = pathlib.Path("jen/__init__.py").read_text(encoding="utf-8")
        assert 'url_for("auth.session_touch")' in text

    def test_a_flagged_person_gets_the_dialog_and_the_deadline(self, client, db):
        from tests.test_password_change_enforcement import _client_with_must_change_password

        c, _ = _client_with_must_change_password(client, db, username="q210notice1")
        r = c.get("/force-password-change")
        assert r.status_code == 200 and b'id="jen-session-overlay"' in r.data
        assert re.search(
            rb'<body[^>]*data-session-expires="\d+"[^>]*data-session-now="\d+"[^>]*data-session-login="[0-9a-f]{16}"',
            r.data,
        )
        assert "X-Jen-Session-Expires" in r.headers

    def test_the_touch_is_a_json_answer_for_them_not_a_redirect(self, client, db):
        from tests.test_password_change_enforcement import _client_with_must_change_password

        c, _ = _client_with_must_change_password(client, db, username="q210notice2")
        stale = _iso(30)
        with c.session_transaction() as sess:
            sess["last_active"] = stale
        r = c.post("/session/touch")
        assert r.status_code == 200 and r.get_json()["ok"] is True and "Location" not in r.headers
        with c.session_transaction() as sess:
            assert sess["last_active"] != stale


# ── Q215: the scans over every script in the tree, and the watch script run ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _script_files():
    """Every page and script a browser runs from this tree: the core templates, the bundled plugins' templates and scripts, and our own static scripts (not the vendored, minified ones)."""
    for root in ("templates", "plugins", "static"):
        for path in sorted(pathlib.Path(root).rglob("*")):
            if path.suffix in (".html", ".js") and ".min." not in path.name:
                yield path


def _call_args(text, open_at):
    """The text of a call from its opening parenthesis to the matching closing one (strings, template literals and comments skipped), or None when it does not close. Q215: the pass's own blindness
    was reading a fixed number of characters past a `setInterval(`; this reads to the matching bracket."""
    depth, i, n = 0, open_at, len(text)
    while i < n:
        c = text[i]
        if c in "'\"`":
            quote = c
            i += 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_at : i + 1]
        i += 1
    return None


def _in_own_frame(body, needle):
    """True when `needle` occurs in the callback's OWN function body, not inside a function nested in it (a `.then(function...)`, a `setTimeout(function...)`, an arrow): a reload there runs once, after the
    work the interval was waiting for, and clears the interval first."""
    frames, pending_function, i, n = [], False, 0, len(body)
    while i < n:
        c = body[i]
        if c in "'\"`":
            quote = c
            i += 1
            while i < n and body[i] != quote:
                i += 2 if body[i] == "\\" else 1
        elif body.startswith("//", i):
            end = body.find("\n", i)
            i = n if end < 0 else end
            continue
        elif body.startswith("/*", i):
            end = body.find("*/", i + 2)
            i = n if end < 0 else end + 1
        elif (
            body.startswith("function", i)
            and not (body[i - 1].isalnum() or body[i - 1] == "_")
            or body.startswith("=>", i)
        ):
            pending_function = True
        elif c == "{":
            frames.append(pending_function)
            pending_function = False
        elif c == "}":
            if frames:
                frames.pop()
        elif body.startswith(needle, i) and sum(frames) == 1:
            return True
        i += 1
    return False


def _set_interval_calls():
    found = []
    for path in _script_files():
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"\bsetInterval\(", text):
            found.append((path.as_posix(), text.count("\n", 0, m.start()) + 1, _call_args(text, m.end() - 1)))
    return found


class TestARepeatingReloadReadsTheDialog:
    """Q215 (Z1, BE1): a page that reloads ITSELF on a timer must leave the "Still there?" dialog alone - the Servers page's 30 s reload took the Stay signed in click with it. The scan is the whole
    tree (templates, plugins, static), so the next page that reloads itself cannot ship without the term."""

    def test_every_interval_in_the_tree_is_read_to_its_end(self):
        calls = _set_interval_calls()
        assert len(calls) >= 8, f"the scan found too few setInterval calls to be the tree: {calls}"
        assert all(body for _, _, body in calls), [(p, ln) for p, ln, body in calls if not body]

    def test_every_interval_that_reloads_its_own_page_reads_the_dialog(self):
        reloading = [
            (p, ln, body) for p, ln, body in _set_interval_calls() if body and _in_own_frame(body, "location.reload(")
        ]
        assert reloading, "the Servers page's refresh is one: the scan would be vacuous if it found none"
        assert [p for p, _, _ in reloading] == ["templates/servers.html"], [(p, ln) for p, ln, _ in reloading]
        for path, line, body in reloading:
            assert "window.jenSessionWatch && window.jenSessionWatch.state().open" in body, (path, line)


class TestTheOneDefinition:
    """Q215 (Z13, Z15): `session_timeout.extends()` is the ONE definition of what moves `last_active`, and it says what the middleware does."""

    def test_static_is_not_an_extension(self):
        assert st.extends("/static/css/print.css", {}) is False
        assert st.extends("/static/js/htmx.min.js", {}, {"_poll": "0"}) is False
        assert st.extends("/leases", {}) is True

    def test_the_query_marker_is_a_gets(self):
        """A navigation cannot carry the header, so a GET may say `?_poll=1`; on a POST (or anything that is not a GET) the query marker is nothing, and the header form stays as it is."""
        assert st.is_poll({}, {"_poll": "1"}, "GET") is True
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            assert st.is_poll({}, {"_poll": "1"}, method) is False, method
            assert st.is_poll({"X-Jen-Poll": "1"}, {}, method) is True, method
        assert st.is_poll({"X-Jen-Poll": "yes"}, {"_poll": "true"}, "GET") is False, (
            "a marker denies, it never grants: any value but 1 is no marker"
        )
        assert st.extends("/settings/save-session", {}, {"_poll": "1"}, "POST") is True
        assert st.extends("/servers", {}, {"_poll": "1"}, "GET") is False


class TestTheWatchScriptRuns:
    """Q215: the watch script RUN, not read. Node is the engine (the suite's existing precedent, tests/test_dashboard_chart.py); the DOM it touches is a stub of exactly what the script reads. Skipped where
    node is absent - the browser half of every row is tests/e2e/test_session_notice.py."""

    NODE = shutil.which("node")
    SECOND = 1_000_000_000

    def _script(self):
        text = pathlib.Path("templates/_session_watch.html").read_text(encoding="utf-8")
        body = re.search(r'<script nonce="\{\{ csp_nonce \}\}">(.*?)</script>', text, re.S).group(1)
        return body.replace("{{ csrf_token()|tojson }}", '"t"')

    def _run(self, calls, attrs=None):
        prelude = (
            "var out = {}, pending = new Set(), listeners = {}, attrs = " + json.dumps(attrs or {}) + ";\n"
            "var realST = setTimeout, realCT = clearTimeout;\n"
            "globalThis.setTimeout = function(fn, ms) { var id = realST(function() { pending.delete(id); fn(); }, ms); pending.add(id); return id; };\n"
            "globalThis.clearTimeout = function(id) { pending.delete(id); realCT(id); };\n"
            "globalThis.window = globalThis;\n"
            "globalThis.document = { hidden: false, activeElement: null,\n"
            "  body: { getAttribute: function(n) { return n in attrs ? attrs[n] : null; } },\n"
            "  getElementById: function() { return null; },\n"
            "  addEventListener: function(t, f) { (listeners[t] = listeners[t] || []).push(f); },\n"
            "  removeEventListener: function() {} };\n"
            "globalThis.addEventListener = function() {};\n"
            "globalThis.localStorage = { setItem: function() {}, removeItem: function() {}, getItem: function() { return null; } };\n"
            "globalThis.location = { assign: function(u) { out.assigned = u; }, pathname: '/', search: '' };\n"
        )
        js = (
            prelude
            + self._script()
            + "\nvar w = window.jenSessionWatch, S = "
            + str(self.SECOND)
            + ";\n"
            + calls
            + "\nconsole.log(JSON.stringify(out)); process.exit(0);\n"
        )
        done = subprocess.run(  # nosec B603 - a fixed interpreter and a script built in this file
            [self.NODE, "-e", js], capture_output=True, text=True, timeout=30, check=True, encoding="utf-8"
        )
        return json.loads(done.stdout)

    @pytest.mark.skipif(
        NODE is None, reason="node is not installed; the e2e tests drive the same script in a real browser"
    )
    def test_a_deadline_without_its_state_or_its_clock_moves_nothing(self):
        out = self._run(
            """
w.ingest(String(S + 3600), false, String(S), String(S - 5));
out.first = w.state().expires;
out.noState = [undefined, null, '', 'abc', '-5', '1.5', '1234567890123'].map(function(a) { w.ingest(String(S + 7200), false, String(S + 1), a); return w.state().expires; });
out.noClock = [undefined, null, '', 'abc', '0', '-1'].map(function(c) { w.ingest(String(S + 9000), false, c, String(S - 5)); return w.state().expires; });
out.zeroAfterAReal = (function() { w.ingest(String(S + 9000), false, String(S + 2), '0'); return w.state().expires; })();
w.ingest(String(S + 7200), false, String(S + 1), String(S - 5));
out.genuine = w.state().expires;
"""
        )
        assert out["first"] == self.SECOND + 3600
        assert out["noState"] == [self.SECOND + 3600] * 7, out["noState"]
        assert out["noClock"] == [self.SECOND + 3600] * 6, out["noClock"]
        assert out["zeroAfterAReal"] == self.SECOND + 3600, (
            "a reply that says the session has no state is older than one that had it"
        )
        assert out["genuine"] == self.SECOND + 7200, (
            "the guard is not a wedge: the same reply WITH its state and clock is taken"
        )

    @pytest.mark.skipif(
        NODE is None, reason="node is not installed; the e2e tests drive the same script in a real browser"
    )
    def test_the_first_reply_of_a_session_with_no_state_is_taken_with_a_zero(self):
        out = self._run("w.ingest(String(S + 3600), false, String(S), '0'); out.expires = w.state().expires;")
        assert out["expires"] == self.SECOND + 3600

    @pytest.mark.skipif(
        NODE is None, reason="node is not installed; the e2e tests drive the same script in a real browser"
    )
    def test_a_clock_a_day_ahead_of_the_anchor_is_ignored_and_a_genuine_one_still_re_anchors(self):
        out = self._run(
            """
w.ingest(String(S + 3600), false, String(S), String(S - 5));
w.ingest(String(S + 86400 + 900), false, String(S + 86400 + 500), String(S - 5));
out.afterTheDayAheadClock = w.state().expires;
w.ingest(String(S + 10000), false, String(S + 50), String(S - 5));
out.afterAGenuineOne = w.state().expires;
out.lastServerNow = w.state().lastServerNow;
"""
        )
        assert out["afterTheDayAheadClock"] == self.SECOND + 3600
        assert out["afterAGenuineOne"] == self.SECOND + 10000 and out["lastServerNow"] == self.SECOND + 50

    @pytest.mark.skipif(
        NODE is None, reason="node is not installed; the e2e tests drive the same script in a real browser"
    )
    def test_twenty_focus_events_leave_one_pending_timer(self):
        """Z16: every tab focus stacked one more `setTimeout` (the pass: 1 at rest, 29 after twenty). A timer is cleared before its id is forgotten."""
        out = self._run(
            """
w.ingest(String(S + 3600), false, String(S), String(S - 5));
out.atRest = pending.size;
for (var i = 0; i < 20; i++) { listeners.visibilitychange.forEach(function(f) { f(); }); }
out.afterTwenty = pending.size;
"""
        )
        assert out["atRest"] == 1 and out["afterTwenty"] <= 1, out
