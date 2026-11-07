"""
tests/e2e/test_session_notice.py
────────────────────────────────
v5.70.0-beta.4 (Q208, AX2): the idle sign-out is announced two minutes ahead and comes back to the page, in a real browser.

The browser's clock is moved with Playwright's `page.clock`; the SERVER's clock has to move with it (a touch is the server's `now`), so the fixture below shifts the two `datetime` names the
timeout middleware and `POST /session/touch` use. Both move by the same number of seconds, which is what a real two minutes before the deadline looks like from either side.

v5.70.0-beta.5 (Q210, AZ1 and AZ9): the notice counts on the SERVER's clock, kept against the browser's monotonic clock - so a browser whose clock is wrong, or is changed while the page is open, sees
the dialog at the right moment and never spins a timer. The watch exposes `window.jenSessionWatch.state()` and `.ingest(value, fromStorage, serverNow)`, which is how these tests drive it without a
server round trip. `page.clock` drives `performance.now()` as well as `Date`, so every fast-forward below moves the watch's own clock.
"""

import re
from datetime import datetime, timedelta, timezone

import pytest
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import expect

from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e


@pytest.fixture
def server_clock(monkeypatch):
    import jen
    import jen.routes.auth as auth
    import jen.services.session_timeout as session_timeout

    class Shifted(datetime):
        offset = timedelta(0)

        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + cls.offset

    monkeypatch.setattr(jen, "datetime", Shifted)
    monkeypatch.setattr(auth, "datetime", Shifted)
    monkeypatch.setattr(session_timeout, "datetime", Shifted)
    yield Shifted


@pytest.fixture
def timeout_settings():
    """The global idle-timeout settings, put back after a test that changes them (the server runs in this process, so the setter is the superadmin's own)."""
    from jen.models.user import _invalidate_settings_cache, get_global_setting, set_global_setting

    before = {k: get_global_setting(k, None) for k in ("session_timeout_enabled", "session_timeout_minutes")}

    def put(**values):
        for key, value in values.items():
            set_global_setting(key, value)
        _invalidate_settings_cache()

    yield put
    for key, value in before.items():
        set_global_setting(
            key,
            value if value is not None else {"session_timeout_enabled": "true", "session_timeout_minutes": "60"}[key],
        )
    _invalidate_settings_cache()


def _signed_in_on_leases(page, base_url, skew_seconds=0, init_script=None):
    """Sign in and open Leases with the browser's clock `skew_seconds` from the server's (negative: the browser is behind). `init_script` runs before the page's own scripts."""
    page.clock.install(time=datetime.now(timezone.utc) + timedelta(seconds=skew_seconds))
    if init_script:
        page.add_init_script(init_script)
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    page.goto(f"{base_url}/leases?subnet=1")
    deadline = int(page.locator("body").get_attribute("data-session-expires"))
    return deadline


def _jump_to(page, server_clock, deadline, remaining):
    """Both clocks to `remaining` seconds before `deadline`."""
    now = page.evaluate("Math.floor(Date.now() / 1000)")
    jump = deadline - remaining - now
    assert jump > 0
    server_clock.offset = timedelta(seconds=jump)
    page.clock.fast_forward(jump * 1000)


def _to_remaining(page, remaining):
    """Move only the BROWSER's clock until `remaining` seconds are left on the server's deadline, whatever the browser's wall clock says (the watch counts on the server's clock, so a browser
    that is behind or ahead is the same page with a different `Date`). Nothing server-side moves: this tests the page."""
    # the page polls /api/stats every 30 s, and a fast-forward fires that poll: its reply carries the REAL server clock, which (correctly) re-anchors the watch and would undo the jump.
    # This helper moves only the browser, so the poll is refused for the rest of the test.
    page.route("**/api/stats*", lambda route: route.abort())
    st = page.evaluate("window.jenSessionWatch.state()")
    jump = st["expires"] - remaining - st["lastServerNow"]
    assert jump > 0
    page.clock.fast_forward(jump * 1000)


def _active(page):
    """The session state the page's first deadline was computed from (`data-session-active`). Q215 (Z2): the watch takes a deadline only with the state it came from beside it, so a test that drives
    `ingest` by hand names one - this one is the state the page already holds, which is what a genuine reply to the same session says."""
    return int(page.locator("body").get_attribute("data-session-active"))


#: counts the timers that are PENDING (set, and neither fired nor cleared): the number that grew by one with every tab focus before Q215 (Z16); it wraps the page's own `setTimeout`/`clearTimeout`
PENDING_COUNTER = (
    "window.__pending = new Set(); (function() { var set = window.setTimeout, clear = window.clearTimeout; "
    "window.setTimeout = function(fn, ms) { var id = set.call(window, function() { window.__pending.delete(id); return fn.apply(this, arguments); }, ms); window.__pending.add(id); return id; }; "
    "window.clearTimeout = function(id) { window.__pending.delete(id); return clear.call(window, id); }; })();"
)


def _left_seconds(page):
    m, s = page.locator("#jen-session-left").inner_text().split(":")
    return int(m) * 60 + int(s)


class TestTheSessionDialog:
    def test_it_opens_two_minutes_ahead_and_stay_signed_in_closes_it_and_moves_the_deadline(
        self, page, base_url, server_clock
    ):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, 119)
        overlay = page.locator("#jen-session-overlay")
        expect(overlay).to_be_visible()
        expect(overlay).to_have_attribute("role", "alertdialog")
        expect(page.locator("#jen-session-stay")).to_be_focused()
        expect(page.locator("#jen-session-text")).to_contain_text("You will be signed out in 1:")
        page.get_by_role("button", name="Stay signed in").click()
        expect(overlay).to_be_hidden()
        assert page.evaluate("window.jenSessionWatch.expires()") > deadline + 3000, (
            "the touch moved the deadline an hour on"
        )

    def test_the_countdown_runs(self, page, base_url, server_clock):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, 119)
        text = page.locator("#jen-session-left")
        expect(text).to_have_text(re.compile(r"1:[45]\d"))
        before = text.inner_text()
        page.clock.run_for(5000)
        expect(text).not_to_have_text(before)
        assert text.inner_text() < before, "the countdown runs down"

    def test_escape_is_stay_signed_in_and_tab_stays_inside_the_dialog(self, page, base_url, server_clock):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, 100)
        expect(page.locator("#jen-session-overlay")).to_be_visible()
        page.keyboard.press("Tab")
        expect(page.locator("#jen-session-out")).to_be_focused()
        page.keyboard.press("Tab")
        expect(page.locator("#jen-session-stay")).to_be_focused()
        page.keyboard.press("Escape")
        expect(page.locator("#jen-session-overlay")).to_be_hidden()

    def test_past_the_deadline_with_no_answer_the_page_goes_to_sign_in_and_remembers_where_it_was(
        self, page, base_url, server_clock
    ):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, -3)
        page.wait_for_url(re.compile(r".*/login\?next=(%2F|/)leases(%3F|\?)subnet(%3D|=)1"), timeout=15000)

    def test_signing_in_again_comes_back_to_the_page(self, page, base_url, server_clock):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, -3)
        page.wait_for_url(re.compile(r".*/login\?next="), timeout=15000)
        server_clock.offset = timedelta(0)
        page.fill('input[name="username"]', ADMIN_USERNAME)
        page.fill('input[name="password"]', ADMIN_PASSWORD)
        page.click(".btn-login")
        page.wait_for_url(re.compile(r".*/leases\?subnet=1"), timeout=15000)

    def test_another_tabs_touch_closes_the_dialog_here(self, page, base_url, server_clock):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, 100)
        overlay = page.locator("#jen-session-overlay")
        expect(overlay).to_be_visible()
        # what the second tab's response would do: a later deadline arrives through the storage event, with that tab's server clock beside it
        later = page.evaluate("window.jenSessionWatch.expires()") + 3600
        page.evaluate(
            f"window.jenSessionWatch.ingest({later}, true, window.jenSessionWatch.state().lastServerNow, {_active(page)})"
        )
        expect(overlay).to_be_hidden()

    def test_sign_out_now_signs_out(self, page, base_url, server_clock):
        deadline = _signed_in_on_leases(page, base_url)
        _jump_to(page, server_clock, deadline, 100)
        page.get_by_role("button", name="Sign out now").click()
        page.wait_for_url(re.compile(r".*/login"), timeout=15000)


class TestTheBrowsersClockIsNotTheServers:
    """Q210 (AZ1 a, Y1): the warning was SCHEDULED against the browser's own clock while every other read of the time was corrected for the server's: a browser behind never opened the dialog, a browser
    ahead asked for a zero-delay timer, `check()` re-armed with zero again and the tab spun."""

    def test_a_browser_two_minutes_behind_still_sees_the_dialog(self, page, base_url):
        _signed_in_on_leases(page, base_url, skew_seconds=-120)
        _to_remaining(page, 100)
        expect(page.locator("#jen-session-overlay")).to_be_visible()
        assert 90 <= _left_seconds(page) <= 100, "the countdown reads the server's deadline, not the browser's"

    def test_a_day_ahead_and_a_day_behind(self, browser, base_url):
        for skew in (86_400, -86_400):
            ctx = browser.new_context()
            try:
                page = ctx.new_page()
                _signed_in_on_leases(page, base_url, skew_seconds=skew)
                _to_remaining(page, 119)
                expect(page.locator("#jen-session-overlay")).to_be_visible()
                assert 100 <= _left_seconds(page) <= 119, (skew, _left_seconds(page))
            finally:
                ctx.close()

    def test_a_browser_ahead_does_not_spin(self, browser, base_url):
        """A `setTimeout` counter is installed before the page's own scripts. A browser two hours fast makes the same number of timer requests as the control, within 2 (beta.4: about 455 in 1.5 s)."""
        counter = (
            "window.__timers = 0; (function() { var orig = window.setTimeout; "
            "window.setTimeout = function() { window.__timers++; return orig.apply(this, arguments); }; })();"
        )
        counts, pending = {}, {}
        for label, skew in (("control", 0), ("ahead", 7_200)):
            ctx = browser.new_context()
            try:
                page = ctx.new_page()
                _signed_in_on_leases(page, base_url, skew_seconds=skew, init_script=counter + PENDING_COUNTER)
                page.wait_for_timeout(1500)
                counts[label] = page.evaluate("window.__timers")
                pending[label] = page.evaluate("window.__pending.size")
            finally:
                ctx.close()
        assert abs(counts["ahead"] - counts["control"]) <= 2, counts
        assert pending["control"] <= 1 and pending["ahead"] <= 1, pending  # Q215 (Z16): pending timers, not calls

    def test_a_wall_clock_jump_while_the_page_is_open_moves_nothing(self, page, base_url):
        """AZ9 (c): the countdown is the monotonic clock's. Moving the browser's system time an hour on mid-countdown leaves the dialog counting down from where it was."""
        _signed_in_on_leases(page, base_url)
        _to_remaining(page, 100)
        expect(page.locator("#jen-session-overlay")).to_be_visible()
        before = _left_seconds(page)
        page.clock.set_system_time(datetime.now(timezone.utc) + timedelta(hours=1))
        page.clock.run_for(3000)
        after = _left_seconds(page)
        assert before - 5 <= after <= before, (before, after)
        expect(page.locator("#jen-session-overlay")).to_be_visible()


class TestTheDeadlineIsTheServersWord:
    """Q210 (AZ1 b, Y4; AZ9 a): a deadline that arrives in a response is authoritative in both directions, and "off" is a word."""

    def test_an_older_response_never_moves_the_deadline(self, page, base_url):
        _signed_in_on_leases(page, base_url)
        st = page.evaluate("window.jenSessionWatch.state()")
        d, s = st["expires"], st["lastServerNow"]
        a = _active(page)
        page.evaluate(f"window.jenSessionWatch.ingest({d + 600}, false, {s + 200}, {a})")
        assert page.evaluate("window.jenSessionWatch.expires()") == d + 600
        page.evaluate(f"window.jenSessionWatch.ingest({d + 100}, false, {s + 100}, {a})")
        after = page.evaluate("window.jenSessionWatch.state()")
        assert after["expires"] == d + 600 and after["lastServerNow"] == s + 200, (
            "a reply from an earlier second is ignored, either way"
        )
        page.evaluate(f"window.jenSessionWatch.ingest({d + 900}, false, {s + 200}, {a})")
        assert page.evaluate("window.jenSessionWatch.expires()") == d + 900, (
            "two replies from one second: the later arrival is taken"
        )

    def test_a_slow_reply_built_from_an_older_session_state_is_ignored(self, page, base_url):
        """Second pass 1: the server's clock orders replies SENT, the session state they were computed from orders what they SAY. A reply stamped later but built from the cookie before a touch must not pull
        the extended deadline back (it closed the dialog and then walked a live session to the sign-in form)."""
        _signed_in_on_leases(page, base_url)
        st = page.evaluate("window.jenSessionWatch.state()")
        d, s = st["expires"], st["lastServerNow"]
        a = int(
            page.locator("body").get_attribute("data-session-active")
        )  # the session state the first deadline came from
        page.evaluate(
            f"window.jenSessionWatch.ingest({d + 3600}, false, {s + 2}, {a + 50})"
        )  # the touch: a newer state
        assert page.evaluate("window.jenSessionWatch.expires()") == d + 3600
        page.evaluate(
            f"window.jenSessionWatch.ingest({d}, false, {s + 8}, {a})"
        )  # the slow reply: later clock, OLDER state
        assert page.evaluate("window.jenSessionWatch.expires()") == d + 3600
        page.evaluate(
            f"window.jenSessionWatch.ingest({d + 600}, false, {s + 9}, {a + 50})"
        )  # the same state, a cut timeout: both directions still move
        assert page.evaluate("window.jenSessionWatch.expires()") == d + 600

    def test_a_deadline_with_no_clock_beside_it_is_ignored(self, page, base_url):
        _signed_in_on_leases(page, base_url)
        d = page.evaluate("window.jenSessionWatch.expires()")
        page.evaluate(f"window.jenSessionWatch.ingest({d + 600}, false)")
        assert page.evaluate("window.jenSessionWatch.expires()") == d

    def test_a_deadline_with_no_state_beside_it_is_ignored(self, page, base_url):
        """Q215 (Z2): the clock guard's sibling. A deadline that arrives without the session state it was computed from - missing, empty, or not a number - is a reply that is not ours, and moves nothing."""
        _signed_in_on_leases(page, base_url)
        st = page.evaluate("window.jenSessionWatch.state()")
        d, s = st["expires"], st["lastServerNow"]
        for n, state in enumerate(("undefined", "null", "''", "'abc'", "'-5'")):
            page.evaluate(f"window.jenSessionWatch.ingest({d + 600}, false, {s + 1 + n}, {state})")
            assert page.evaluate("window.jenSessionWatch.expires()") == d, state
        page.evaluate(f"window.jenSessionWatch.ingest({d + 600}, false, {s + 10}, {_active(page)})")
        assert page.evaluate("window.jenSessionWatch.expires()") == d + 600, "the same reply WITH its state is taken"

    def test_a_shortened_deadline_rearms_at_once(self, page, base_url):
        _signed_in_on_leases(page, base_url)
        st = page.evaluate("window.jenSessionWatch.state()")
        s = st["lastServerNow"] + 1
        assert st["armed"] > 3_000_000, "an hour away: the timer is long"
        page.evaluate(f"window.jenSessionWatch.ingest({s + 600}, false, {s}, {_active(page)})")
        st = page.evaluate("window.jenSessionWatch.state()")
        assert st["expires"] == s + 600 and st["lead"] == 120
        assert 478_000 <= st["armed"] <= 480_000, st
        expect(page.locator("#jen-session-overlay")).to_be_hidden()
        page.clock.fast_forward(481_000)
        expect(page.locator("#jen-session-overlay")).to_be_visible()

    def test_off_clears_everything(self, page, base_url):
        _signed_in_on_leases(page, base_url)
        _to_remaining(page, 100)
        expect(page.locator("#jen-session-overlay")).to_be_visible()
        login_id = page.locator("body").get_attribute("data-session-login")
        assert page.evaluate(f"localStorage.getItem('jen-session-expires:{login_id}')"), (
            "the deadline was written under this sign-in's key"
        )
        s = page.evaluate("window.jenSessionWatch.state().lastServerNow") + 1
        page.evaluate(f"window.jenSessionWatch.ingest('off', false, {s}, {_active(page)})")
        st = page.evaluate("window.jenSessionWatch.state()")
        assert st["expires"] == 0 and st["armed"] is None and st["open"] is False
        stored = page.evaluate(f"localStorage.getItem('jen-session-expires:{login_id}')")
        assert stored and stored.startswith("off:"), (
            "a second tab learns `off` from the stored value (a removal tells it nothing); sign-out removes the key"
        )
        expect(page.locator("#jen-session-overlay")).to_be_hidden()

    def test_re_enabled_after_off(self, page, base_url):
        _signed_in_on_leases(page, base_url)
        d = page.evaluate("window.jenSessionWatch.expires()")
        s = page.evaluate("window.jenSessionWatch.state().lastServerNow")
        page.evaluate(f"window.jenSessionWatch.ingest('off', false, {s + 1}, {_active(page)})")
        assert page.evaluate("window.jenSessionWatch.state().armed") is None
        page.evaluate(f"window.jenSessionWatch.ingest({d}, false, {s + 2}, {_active(page)})")
        st = page.evaluate("window.jenSessionWatch.state()")
        assert st["expires"] == d and st["armed"] is not None and st["armed"] > 0

    def test_a_shorter_deadline_reaches_an_open_page(self, page, base_url, timeout_settings):
        """The timeout is cut while a page is open; the page's next request carries the earlier value and the dialog opens at it (beta.4 ignored an earlier value and signed the person out unannounced)."""
        _signed_in_on_leases(page, base_url)
        before = page.evaluate("window.jenSessionWatch.expires()")
        timeout_settings(session_timeout_enabled="true", session_timeout_minutes="5")
        page.evaluate("window.jenFetch('/api/stats')")
        page.wait_for_function("(d) => window.jenSessionWatch.expires() < d - 3000", arg=before)
        _to_remaining(page, 100)
        expect(page.locator("#jen-session-overlay")).to_be_visible()

    def test_a_switched_off_timeout_reaches_an_open_page(self, page, base_url, timeout_settings):
        """The timeout is switched off while a page is open; the response carries `off`, so the page does not walk a live session to the sign-in form at its old deadline."""
        _signed_in_on_leases(page, base_url)
        timeout_settings(session_timeout_enabled="false")
        page.evaluate("window.jenFetch('/api/stats')")
        page.wait_for_function("() => window.jenSessionWatch.expires() === 0")
        url = page.url
        page.clock.fast_forward(2 * 3600 * 1000)
        page.wait_for_timeout(500)
        assert page.url == url, "no navigation: the session is alive and the timeout is off"
        expect(page.locator("#jen-session-overlay")).to_be_hidden()


class TestTwoTabsOfOneSignIn:
    """Q210 (AZ9 b): the cross-tab value lives under a key that belongs to one sign-in."""

    def test_another_tab_extends_this_one(self, page, base_url):
        _signed_in_on_leases(page, base_url)
        second = page.context.new_page()
        second.goto(f"{base_url}/leases?subnet=1")
        token = second.evaluate("JSON.parse(document.body.getAttribute('hx-headers'))['X-CSRFToken']")
        page.wait_for_timeout(
            500
        )  # the second tab's own first paint reaches this one through the storage event: read the deadline AFTER it settles
        before = page.evaluate("window.jenSessionWatch.expires()")
        second.wait_for_timeout(1100)  # a later second, so the touch's deadline is later than the one both tabs hold
        second.evaluate(
            "(t) => window.jenFetch('/session/touch', { method: 'POST', headers: { 'X-CSRFToken': t }, credentials: 'same-origin' })",
            token,
        )
        page.wait_for_function("(d) => window.jenSessionWatch.expires() > d", arg=before)
        second.close()

    def test_a_second_tab_is_told_the_timeout_was_switched_off(self, page, base_url):
        _signed_in_on_leases(page, base_url)
        second = page.context.new_page()
        second.goto(f"{base_url}/leases?subnet=1")
        page.wait_for_timeout(500)
        s = second.evaluate("window.jenSessionWatch.state().lastServerNow") + 1
        second.evaluate(f"window.jenSessionWatch.ingest('off', false, {s}, {_active(second)})")
        page.wait_for_function("() => window.jenSessionWatch.expires() === 0")
        second.close()

    def test_a_value_written_under_another_sign_ins_key_is_not_read(self, page, base_url):
        _signed_in_on_leases(page, base_url)
        second = page.context.new_page()
        second.goto(f"{base_url}/leases?subnet=1")
        page.wait_for_timeout(
            500
        )  # the second tab's own first paint reaches this one through the storage event: read the state AFTER it settles
        st = page.evaluate("window.jenSessionWatch.state()")
        later = st["expires"] + 7200
        # Q215 (Z2): a value written by a tab carries `<deadline>:<clock>:<state>` - the watch ignores one without its state. The state is the SECOND tab's own: both tabs share one session cookie, the
        # second tab's navigation moved `last_active`, and the first tab may already have taken a reply that says so - its own first-paint state would then be an older one and would be ignored
        active = _active(second)
        second.evaluate(
            f"localStorage.setItem('jen-session-expires:0123456789abcdef', '{later}:{st['lastServerNow'] + 5}:{active}')"
        )
        page.wait_for_timeout(500)
        assert page.evaluate("window.jenSessionWatch.expires()") == st["expires"], (
            "another sign-in's key moved nothing here"
        )
        # the positive control: the same write under THIS sign-in's key is read, so the line above is not vacuous
        login_id = page.locator("body").get_attribute("data-session-login")
        second.evaluate(
            f"localStorage.setItem('jen-session-expires:{login_id}', '{later}:{st['lastServerNow'] + 5}:{active}')"
        )
        page.wait_for_function("(d) => window.jenSessionWatch.expires() > d", arg=st["expires"])
        second.close()


class TestABackgroundTabAndTheServer:
    def test_a_background_tab_resuming_past_the_lead_opens_the_dialog(self, page, base_url):
        """A tab in the background has its long timers throttled or stopped. The held-timer shim stands in for that: no timer longer than a minute ever fires, the clock moves past deadline - lead, and
        only the tab becoming visible again can open the dialog - with the right remaining time."""
        hold = (
            "window.__held = 0; (function() { var orig = window.setTimeout; "
            "window.setTimeout = function(f, d) { if (d > 60000) { window.__held++; return 0; } return orig.apply(this, arguments); }; })();"
        )
        _signed_in_on_leases(page, base_url, init_script=hold)
        assert page.evaluate("window.__held") >= 1, "the watch's long timer was held"
        _to_remaining(page, 100)
        expect(page.locator("#jen-session-overlay")).to_be_hidden()
        # the tab is shown again: the page reads `document.hidden` (a headless tab may report it hidden), so it is pinned to false for the event
        page.evaluate(
            "Object.defineProperty(document, 'hidden', { value: false, configurable: true }); document.dispatchEvent(new Event('visibilitychange'))"
        )
        expect(page.locator("#jen-session-overlay")).to_be_visible()
        assert 90 <= _left_seconds(page) <= 100

    def test_the_server_rejects_an_expired_session_whatever_the_browser_shows(self, page, base_url, server_clock):
        """The browser's clock is not advanced and the dialog never opens; the SERVER's clock is past the deadline, so the next request is the sign-in redirect."""
        _signed_in_on_leases(page, base_url)
        server_clock.offset = timedelta(hours=3)
        page.goto(f"{base_url}/leases?subnet=1")
        page.wait_for_url(re.compile(r".*/login"), timeout=15000)
        server_clock.offset = timedelta(0)


class TestTheTimersDoNotStack:
    """Q215 (Z16): the watch holds ONE pending timer. Every tab focus used to call `check()`, which forgot the pending timer's id without clearing it and armed another - the pass counted 1 at rest and
    29 after twenty focus events (each of them a call to `check()` a minute from now)."""

    def test_twenty_tab_focus_events_leave_one_pending_timer(self, browser, base_url):
        ctx = browser.new_context()
        try:
            page = ctx.new_page()
            _signed_in_on_leases(page, base_url, init_script=PENDING_COUNTER)
            at_rest = page.evaluate("window.__pending.size")
            for _ in range(20):
                page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
            after = page.evaluate("window.__pending.size")
            assert at_rest <= 1 and after <= 1, (at_rest, after)
        finally:
            ctx.close()


class TestAPageThatReloadsItselfLeavesTheDialogAlone:
    """Q215 (Z1): the Servers page reloads itself every 30 s unless a menu, a <details>, the confirm overlay, a sheet or a field is open. The Still there? dialog was not on that list, so the reload landed
    under it and took a Stay signed in click in flight - the session then ended with the person sitting at the page. The browser half is real time: the page's interval is real, and so is the wait."""

    def _servers(self, page, base_url):
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        page.goto(f"{base_url}/servers")
        page.evaluate("window.__sentinel = 1")

    def _age(self, page, ms):
        """Wait until the page is `ms` old. Polled with `evaluate`, not `wait_for_function` with a string: the page's CSP forbids the `eval` that one runs on."""
        for _ in range((ms + 15_000) // 250):
            if page.evaluate("performance.now()") >= ms:
                return
            page.wait_for_timeout(250)
        raise AssertionError(f"the page never reached age {ms} ms")

    def test_the_servers_page_does_not_reload_under_the_dialog(self, page, base_url):
        self._servers(page, base_url)
        self._age(page, 5_000)
        # a 40-second span: the dialog opens 20 s before the end (page age 25 s), the page's own 30-second interval fires at 30 s plus however long the script took to start (a slow render is a few
        # seconds), and the deadline itself is at 45 s - so the check at 36 s is after the tick on any render that took under 6 s and before the sign-out.
        # The state passed is above the session's real one on purpose: the page's own `/api/stats` reply every 30 s is then ignored by the watch's state guard instead of moving the deadline and
        # closing the dialog (what a genuine reply would do - the test is about the reload, not about that).
        st = page.evaluate("window.jenSessionWatch.state()")
        sn = st["lastServerNow"] + 5
        page.evaluate(f"window.jenSessionWatch.ingest({sn + 40}, false, {sn}, {max(_active(page), sn)})")
        self._age(page, 26_000)
        expect(page.locator("#jen-session-overlay")).to_be_visible()
        before = _left_seconds(page)
        self._age(page, 36_000)
        assert page.evaluate("window.__sentinel") == 1, "the 30-second reload fired under the open dialog"
        assert page.evaluate("window.jenSessionWatch.state().open") is True
        assert _left_seconds(page) < before, "the countdown continued"

    def test_the_control_reloads_within_forty_seconds(self, page, base_url):
        """Without the dialog the same page reloads itself on schedule: the sentinel is gone by then, so the test above proves the dialog is the reason and not a page that never reloads."""
        self._servers(page, base_url)
        for _ in range(80):
            try:
                if page.evaluate("window.__sentinel === undefined"):
                    return
            except PlaywrightError:  # the reload is in flight: the old document is gone
                pass
            page.wait_for_timeout(500)
        raise AssertionError("the Servers page never reloaded itself in 40 s")
