"""
tests/e2e/test_form_submit_progress.py
──────────────────────────────────────────
v5.65.10 (Q99 f) — the full-page submit handler and the shared progress bar in base.html.

Four bugs, each only visible in a browser:
  * a form whose response is a DOWNLOAD never navigates, so `pageshow` never reset the disabled
    button and the sweeping bar: a second export needed a reload;
  * the document `submit` listener ignored `event.defaultPrevented`, so a form that refused its own
    submission (a validation message) still had its button disabled;
  * Enter in a field of a form whose handler prevents the default started a bar nothing would stop;
  * htmx fires `afterRequest` after every terminal path, so also stopping on `responseError`
    decremented twice for a 4xx/5xx and hid the bar while another request was still in flight.

The mechanism tests inject a form and dispatch events, so they do not depend on any one page's
markup; the export test drives the real Settings → Databases button.
"""

import pytest

pytestmark = pytest.mark.e2e

INJECT = """
([attrs, prevent]) => {
    const f = document.createElement('form');
    f.id = 'q99-form'; f.method = 'POST'; f.action = '/nowhere';
    for (const [k, v] of Object.entries(attrs)) f.setAttribute(k, v);
    f.innerHTML = '<input type="text" name="x"><button type="submit" id="q99-btn">Go</button>';
    if (prevent) f.addEventListener('submit', e => e.preventDefault());
    document.body.appendChild(f);
}
"""

# A synthetic submit event never navigates, so the page stays put for the assertions.
# (Q251) The dashboard these tests stand on makes htmx requests of its own, and each one starts and stops the same bar: read in a second `evaluate`, the bar's
# state was sometimes the dashboard's (one of the five tests failed about one run in five, on the tag and on the release before it, a different one each time).
# So the bar is reset, the event fired and the three facts read in ONE synchronous script: no request of the page can start or end between them.
FIRE = """() => {
    jenProgress.reset();
    document.getElementById('q99-form').dispatchEvent(new Event('submit', {cancelable: true, bubbles: true}));
    const b = document.getElementById('q99-btn');
    return {disabled: b.disabled, busy: b.getAttribute('aria-busy'), active: document.getElementById('jen-progress').classList.contains('active')};
}"""


class TestSubmitHandler:
    def test_a_plain_form_disables_its_button_and_starts_the_bar(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/")
        page.evaluate(INJECT, [{}, False])
        seen = page.evaluate(FIRE)
        assert seen["disabled"] is True
        assert seen["active"] is True

    def test_a_form_that_refused_its_own_submission_is_left_alone(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/")
        page.evaluate(INJECT, [{}, True])
        seen = page.evaluate(FIRE)
        assert seen["disabled"] is False
        assert seen["busy"] is None
        assert seen["active"] is False

    def test_a_download_form_keeps_its_button_and_the_bar_stops_on_a_timer(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/")
        page.evaluate(INJECT, [{"data-download": ""}, False])
        seen = page.evaluate(FIRE)
        assert seen["disabled"] is False
        assert seen["active"] is True
        page.wait_for_function(
            "() => !document.getElementById('jen-progress').classList.contains('active')", timeout=6000
        )


class TestProgressCounter:
    def test_a_failed_request_stops_the_bar_once_not_twice(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/")
        # (Q252) one synchronous script, as the three tests above (Q251): read in a second `evaluate`, the bar was sometimes the dashboard's own request's
        # (about one run in twenty on v7.2.0). Both facts are read where no request of the page can start or end between the events and the reading.
        seen = page.evaluate(
            """() => {
                const active = () => document.getElementById('jen-progress').classList.contains('active');
                jenProgress.reset();
                document.body.dispatchEvent(new CustomEvent('htmx:beforeRequest'));   // the request that will fail
                document.body.dispatchEvent(new CustomEvent('htmx:beforeRequest'));   // one still in flight
                // htmx 1.9 fires both of these for a 4xx/5xx
                document.body.dispatchEvent(new CustomEvent('htmx:responseError'));
                document.body.dispatchEvent(new CustomEvent('htmx:afterRequest'));
                const stillUp = active();
                document.body.dispatchEvent(new CustomEvent('htmx:afterRequest'));
                return {still_up: stillUp, hidden: !active()};
            }"""
        )
        assert seen["still_up"] is True, "the second request is still in flight: the bar must stay up"
        assert seen["hidden"] is True


class TestExportIsUsableTwice:
    def test_the_jen_database_export_button_works_a_second_time_without_a_reload(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/database?tab=export")
        button = page.locator('form[action="/database/export/jen"] button[type=submit]')
        with page.expect_download(timeout=30000) as first:
            button.click()
        assert first.value.suggested_filename
        page.wait_for_function(
            "() => !document.querySelector('form[action=\"/database/export/jen\"] button[type=submit]').disabled",
            timeout=6000,
        )
        with page.expect_download(timeout=30000) as second:
            button.click()
        assert second.value.suggested_filename
