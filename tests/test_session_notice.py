"""
tests/test_session_notice.py
────────────────────────────
v5.70.0-beta.4 (Q208, AX2): the idle sign-out is announced two minutes ahead and comes back to the page.

One definition of the deadline (`jen/services/session_timeout.py`) serves the middleware, the `X-Jen-Session-Expires` header, the `<body data-session-expires>` attribute and `POST /session/touch`.
The first class is pure (`py -m pytest --noconftest tests/test_session_notice.py::TestDeadline`); the rest run against the app.
"""

import pathlib
import re
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

    def test_timeout_off_carries_none_and_no_attribute(self, logged_in_client):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("session_timeout_enabled", "false")
        _invalidate_settings_cache()
        try:
            r = logged_in_client.get("/leases")
            assert "X-Jen-Session-Expires" not in r.headers
            assert not re.search(rb"<body[^>]*data-session-expires", r.data), (
                "(the script that reads the attribute names it too: only the body tag counts)"
            )
        finally:
            set_global_setting("session_timeout_enabled", "true")
            _invalidate_settings_cache()


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
        r = csrf_client.post("/session/touch", headers={"X-CSRFToken": _valid_token_for(app, csrf_client)})
        assert r.status_code == 302 and urlsplit(r.headers["Location"]).path == "/login"
        with csrf_client.session_transaction() as sess:
            assert "last_active" not in sess

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
        }  # Flask-Login refreshes its own cache and freshness flag on any request
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

    def test_the_middleware_names_it_in_both_branches(self):
        text = pathlib.Path("jen/__init__.py").read_text(encoding="utf-8")
        assert text.count("session_timeout_svc.NO_TOUCH_PATHS") == 2


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
    """Source pins for the second pass's client-side fixes (SP-3, SP-6, SP-7); the behavior itself is tests/e2e/test_session_notice.py."""

    BASE = pathlib.Path("templates/base.html").read_text(encoding="utf-8")

    def test_time_is_counted_against_the_servers_clock(self):
        assert "function nowS() { return Date.now() / 1000 + skew; }" in self.BASE
        assert "if (sn > 0) skew = sn - Date.now() / 1000;" in self.BASE
        assert "X-Jen-Session-Now" in self.BASE and "data-session-now" in self.BASE

    def test_leaving_happens_once_and_stops_the_timers(self):
        block = self.BASE[self.BASE.index("function goToLogin()") : self.BASE.index("function signOut()")]
        assert (
            "if (leaving) return;" in block
            and "clearTimeout(warnTimer)" in block
            and "clearInterval(tickTimer)" in block
        )

    def test_only_a_redirect_means_the_session_ended(self):
        block = self.BASE[self.BASE.index("function stay()") : self.BASE.index("if (stayBtn) stayBtn.addEventListener")]
        assert block.count("goToLogin()") == 1 and "if (r.redirected) { goToLogin(); return null; }" in block
        assert "r.status === 403" in block and block.count("stayFailed(") >= 4
        assert 'id="jen-session-failed"' in self.BASE
