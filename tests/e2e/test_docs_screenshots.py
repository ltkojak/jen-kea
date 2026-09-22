"""
tests/e2e/test_docs_screenshots.py
────────────────────────────────────
v5.54.0-era (Q62) — the README's screenshots, generated in CI from
tests/e2e/demo_data.py's fictional homelab instead of the maintainer's real
network. Skipped entirely unless JEN_E2E_DATASET=demo (the `e2e` job's
second pytest step); the default e2e run never collects a screenshot here.

Each capture waits for networkidle AND a page-specific proof that real data
rendered (a "Loading…" or empty-state screenshot is a test FAILURE, not an
artifact worth shipping) before saving, viewport-only (full_page=False — the
frame is what the README shows, same as the maintainer's own references).
Every captured page's text is run through a leak guard against
demo_data.FORBIDDEN before the file is even written: the dataset is
fictional by construction, and this is what proves it stayed that way.
"""

import contextlib
import os

import pytest

from tests.e2e import demo_data
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, DATASET, login

if DATASET != "demo":
    pytest.skip("only runs with JEN_E2E_DATASET=demo", allow_module_level=True)

pytestmark = pytest.mark.e2e

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS_DIR = os.path.join(ROOT, "artifacts", "docs")
MAX_BYTES = 500 * 1024
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

DESKTOP = {"width": 1600, "height": 1000}
PHONE = {"width": 390, "height": 844}


def _leak_guard(page, name):
    text = page.evaluate("() => document.body.innerText").lower()
    hits = [f for f in demo_data.FORBIDDEN if f in text]
    assert not hits, f"{name}: leaked real-network marker(s) {hits} — the demo dataset is not supposed to contain these"


def _save(page, name):
    os.makedirs(DOCS_DIR, exist_ok=True)
    path = os.path.join(DOCS_DIR, f"{name}.png")
    page.screenshot(path=path, full_page=False)
    size = os.path.getsize(path)
    assert size <= MAX_BYTES, f"{name}.png is {size} bytes, over the {MAX_BYTES} limit"
    with open(path, "rb") as f:
        assert f.read(8) == PNG_MAGIC, f"{name}.png is not a PNG"


def _wait_rendered(page, predicate_js, what):
    with contextlib.suppress(Exception):
        # a lingering long-poll is not "still loading" — the predicate below is the real check
        page.wait_for_load_state("networkidle", timeout=15000)
    try:
        page.wait_for_function(predicate_js, timeout=15000)
    except Exception as e:
        raise AssertionError(f"{what}: page never showed real data (still 'Loading…' or empty) — {e}") from None


NO_LOADING_JS = "!document.body.innerText.includes('Loading...') && !document.body.innerText.includes('Loading…')"


@pytest.fixture(scope="module")
def desktop_context(browser):
    ctx = browser.new_context(viewport=DESKTOP, device_scale_factor=1, bypass_csp=True)
    yield ctx
    ctx.close()


@pytest.fixture(scope="module")
def phone_context(browser):
    ctx = browser.new_context(viewport=PHONE, device_scale_factor=2, is_mobile=True, has_touch=True, bypass_csp=True)
    yield ctx
    ctx.close()


@pytest.fixture(scope="module")
def desktop(desktop_context, base_url):
    page = desktop_context.new_page()
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    page.close()


@pytest.fixture(scope="module")
def phone(phone_context, base_url):
    page = phone_context.new_page()
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    yield page
    page.close()


class TestDesktopScreenshots:
    def test_dashboard(self, desktop, base_url):
        desktop.goto(f"{base_url}/", wait_until="load")
        _wait_rendered(
            desktop,
            "() => { const el = document.querySelector('.stat-card .stat-value'); "
            "return !!el && el.textContent.trim() !== '' && el.textContent.trim() !== '…' "
            f"&& !isNaN(parseInt(el.textContent, 10)) && ({NO_LOADING_JS}); }}",
            "dashboard",
        )
        _leak_guard(desktop, "dashboard")
        _save(desktop, "dashboard")

    def test_leases(self, desktop, base_url):
        # Production (id 10) filtered via the URL, same as a real bookmark would —
        # the unfiltered page shows every subnet's rows, all 1000px+ tall (Q62 spec).
        desktop.goto(f"{base_url}/leases?subnet=10", wait_until="load")
        _wait_rendered(
            desktop,
            f"() => document.querySelectorAll('table.rowlist tbody tr').length >= 20 && ({NO_LOADING_JS})",
            "leases",
        )
        _leak_guard(desktop, "leases")
        _save(desktop, "leases")

    def test_reservations(self, desktop, base_url):
        desktop.goto(f"{base_url}/reservations", wait_until="load")
        _wait_rendered(
            desktop,
            f"() => document.querySelectorAll('table.rowlist tbody tr').length > 0 && ({NO_LOADING_JS})",
            "reservations",
        )
        _leak_guard(desktop, "reservations")
        _save(desktop, "reservations")

    def test_subnets(self, desktop, base_url):
        desktop.goto(f"{base_url}/subnets", wait_until="load")
        _wait_rendered(
            desktop,
            "() => document.body.innerText.includes('Production') && document.body.innerText.includes('Lab') "
            f"&& ({NO_LOADING_JS})",
            "subnets",
        )
        _leak_guard(desktop, "subnets")
        _save(desktop, "subnets")

    def test_reports(self, desktop, base_url):
        desktop.goto(f"{base_url}/reports", wait_until="load")
        _wait_rendered(
            desktop,
            "() => { const m = document.body.innerText.match(/(\\d+) data points/); "
            f"return !!m && parseInt(m[1], 10) > 0 && ({NO_LOADING_JS}); }}",
            "reports",
        )
        # Scroll to IoT's own chart card — the one demo_data.py gives a rising
        # trend, so it's the only one with a dashed projection line to show.
        # (Production, first in subnet order, has a flat trend and never draws
        # one — framing on it would never satisfy "the dashed projection on IoT".)
        # Chart.js keeps resizing/animating canvases for a while after the "N
        # data points" text this test already waited on is correct, which
        # shifts every card's height below it — two earlier attempts here each
        # scrolled correctly, then drifted by the time the screenshot was
        # actually taken. A long settle wait, then a scroll that re-reads and
        # re-corrects its own target in a tight synchronous loop (getBoundingClientRect
        # forces a layout flush, so each iteration sees the scroll the previous
        # one just made) immediately before the screenshot, with no Python
        # round trip in between to leave a gap for another resize to land in.
        desktop.wait_for_timeout(1500)
        in_view = desktop.evaluate(
            "() => {"
            "  const find = () => [...document.querySelectorAll('.card-title')].find(e => e.textContent.includes('IoT'));"
            "  let r = null;"
            "  for (let i = 0; i < 8; i++) {"
            "    const t = find();"
            "    if (!t) return false;"
            "    r = t.closest('.card').getBoundingClientRect();"
            "    if (r.top >= 0 && r.top < 150) return true;"
            "    window.scrollBy(0, r.top - 60);"
            "  }"
            "  return r ? (r.top >= 0 && r.top < 300) : false;"
            "}"
        )
        assert in_view, "reports: IoT's chart card never settled near the top of the frame"
        _leak_guard(desktop, "reports")
        _save(desktop, "reports")


class TestPhoneScreenshots:
    def test_phone_dashboard(self, phone, base_url):
        phone.goto(f"{base_url}/", wait_until="load")
        _wait_rendered(
            phone,
            "() => { const el = document.querySelector('.stat-card .stat-value'); "
            "return !!el && el.textContent.trim() !== '' && el.textContent.trim() !== '…' "
            f"&& !isNaN(parseInt(el.textContent, 10)) && ({NO_LOADING_JS}); }}",
            "phone-dashboard",
        )
        _leak_guard(phone, "phone-dashboard")
        _save(phone, "phone-dashboard")

    def test_phone_leases(self, phone, base_url):
        phone.goto(f"{base_url}/leases?subnet=10", wait_until="load")
        _wait_rendered(
            phone,
            f"() => document.querySelectorAll('table.rowlist tbody tr').length >= 3 && ({NO_LOADING_JS})",
            "phone-leases",
        )
        _leak_guard(phone, "phone-leases")
        _save(phone, "phone-leases")

    def test_phone_more(self, phone, base_url):
        phone.goto(f"{base_url}/", wait_until="load")
        _wait_rendered(phone, f"() => ({NO_LOADING_JS})", "phone-more (dashboard load)")
        phone.click('.tabbar button[data-sheet-open="more-sheet"]')
        phone.wait_for_selector("#more-sheet.open", timeout=10000)
        phone.wait_for_timeout(200)  # the sheet's open transition
        _leak_guard(phone, "phone-more")
        _save(phone, "phone-more")
