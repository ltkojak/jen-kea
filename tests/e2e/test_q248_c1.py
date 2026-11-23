"""
tests/e2e/test_q248_c1.py
─────────────────────────
Q248, the theme colors and the button sizes, in a real browser (V4 to V7, V18 and V8's button half).

tests/test_q248_c1.py holds the plain color pairs of every preset to 4.5:1 with theme.py's own arithmetic. This file measures what the browser DRAWS:
for each of the seven presets it picks the theme the way a person does (`localStorage['jen-theme-pick']`), opens the dashboard, Leases, Devices and
Settings - Kea, and reads the COMPUTED color of the text of a primary button, of muted text (a help line, an idle top-row item, an idle tab of the
strip, a table header, a card's label), of each of the four banners, of a manufacturer badge, a subnet badge and a status badge - against the color
really behind it: every background from the element up to the first opaque one, composited (a chip is a color-mix or an alpha, not a formula). Each
is at least 4.5:1. On 7.2.0-beta.5 white on the accent was 1.6:1 in High contrast, Dark's muted text 3.2:1 and Light's warning banner 2.3:1.

The banners are real flashed messages: the four categories are put into the signed-in session and the next page prints them.

Stage c2 added three samples of a status word printed as plain text on a card (the Control Agent's "Connected", the SSH card's "No key generated" and
a required field's star: the success, warning and danger inks with no chip under them) and the icon a toast carries.

The second half measures heights (V18, V8): on Leases, Settings - Kea and Customize navigation, at 1440 and at 390 px, a `.btn` beside another `.btn`
is the same height and sits on the same line (its top at the same pixel), and none is under 24 px.
"""

import contextlib

import pymysql
import pymysql.cursors
import pytest

from jen.services import theme
from tests.conftest import TEST_DB
from tests.e2e import conftest as e2e
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

pytestmark = pytest.mark.e2e

THEMES = list(theme.PRESETS)
AA = 4.5
DESKTOP = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}

#: three devices whose device-type colors are the hardest to read: Apple's gray (1.1:1 on Retro), the "unknown" gray (2.1:1 on Dark) and PC's blue
DEVICES = (
    ("aa:bb:cc:24:80:01", "10.99.0.201", "c1-apple", "Apple", "apple", 0),
    ("aa:bb:cc:24:80:02", "10.99.0.202", "c1-acme", "Acme Devices", "unknown", 0),
    ("aa:bb:cc:24:80:03", "10.99.0.203", "c1-dell", "Dell", "pc", 400),
)
MAKERS = [d[3] for d in DEVICES]
FLASHES = [
    ("info", "c1 information line."),
    ("warning", "c1 warning line."),
    ("error", "c1 error line."),
    ("success", "c1 success line."),
]

#: sample name -> (page, CSS selector, the texts an element must have one of, or None for any)
SAMPLES = {
    "primary button": ("/settings/kea", ".btn-primary", None),
    "help line": ("/settings/kea", ".form-hint", None),
    "idle top-row item": ("/", ".nav a.nav-link:not(.active)", None),
    "card label": ("/", ".stat-label, .stat-meta", None),
    "idle tab of the strip": ("/leases", ".section-tab:not(.active)", None),
    "table header": ("/leases", "thead th", None),
    "information banner": ("/leases", ".alert-info .alert-text", ["c1 information line."]),
    "warning banner": ("/leases", ".alert-warning .alert-text", ["c1 warning line."]),
    "error banner": ("/leases", ".alert-error .alert-text", ["c1 error line."]),
    "success banner": ("/leases", ".alert-success .alert-text", ["c1 success line."]),
    "manufacturer badge": ("/leases", "td span[title]", MAKERS),
    "subnet badge": ("/leases", '.badge[class*="badge-tone-"]', None),
    "manufacturer badge on Devices": ("/devices", "td span[title]", MAKERS),
    "status badge": ("/devices", ".badge-dynamic, .badge-stale, .badge-reserved", None),
    # stage c2: a status word printed as plain text on a card is its token's ink (Light's warning was 2.6:1 on white)
    "success status text": ("/settings/kea", ".u-d5881b", None),
    "warning status text": ("/settings/kea", ".u-0051c0", None),
    "danger status text": ("/tools/explain", "label .u-497726", None),
}

# The look-over's own measurement (pass/ui-review-720b5/test_ui_look.py): the text color, with the element's and its ancestors' opacity, over the
# backdrop - every background color from the element up to the first opaque one, composited over white (what a browser paints under a page).
MEASURE_JS = """
([selector, texts]) => {
  const rgba = c => { const m = c.match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const p = m[1].split(/[ ,/]+/).filter(Boolean).map(parseFloat); return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1]; };
  const srgb = c => { const m = c.match(/color\\(srgb ([^)]+)\\)/); if (!m) return null; const p = m[1].split(/[ /]+/).filter(Boolean).map(parseFloat); return [p[0] * 255, p[1] * 255, p[2] * 255, p.length > 3 ? p[3] : 1]; };
  const parse = c => rgba(c) || srgb(c);
  const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
  const over = (top, under) => { const a = top[3]; return [top[0] * a + under[0] * (1 - a), top[1] * a + under[1] * (1 - a), top[2] * a + under[2] * (1 - a), 1]; };
  const shown = el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.closest('[hidden], .sheet, .nav-dropdown-content'); };
  const backdrop = el => {
    const layers = []; let e = el, image = false;
    while (e && e.nodeType === 1) {
      const s = getComputedStyle(e);
      if (s.backgroundImage && s.backgroundImage !== 'none') image = true;
      const c = parse(s.backgroundColor);
      if (c && c[3] > 0) { layers.push(c); if (c[3] >= 1) break; }
      e = e.parentElement;
    }
    let base = [255, 255, 255, 1];
    for (let i = layers.length - 1; i >= 0; i--) base = over(layers[i], base);
    return {color: base, image};
  };
  const out = [];
  for (const el of document.querySelectorAll(selector)) {
    const text = el.textContent.trim().replace(/\\s+/g, ' ');
    if (!text || !shown(el)) continue;
    if (texts && !texts.some(t => text === t || text.endsWith(' ' + t))) continue;
    const s = getComputedStyle(el);
    let fg = parse(s.color); if (!fg) continue;
    let op = 1; for (let e = el; e && e.nodeType === 1; e = e.parentElement) op *= parseFloat(getComputedStyle(e).opacity);
    const bd = backdrop(el); if (bd.image) continue;
    fg = over([fg[0], fg[1], fg[2], fg[3] * op], bd.color);
    const l1 = lum(fg), l2 = lum(bd.color);
    out.push({text: text.slice(0, 40), ratio: Math.round((Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05) * 100) / 100, fg: fg.slice(0, 3).map(Math.round), bg: bd.color.slice(0, 3).map(Math.round)});
  }
  return out;
}
"""

# Every visible .btn, with its box; the test pairs the ones that sit beside each other.
BUTTONS_JS = """
() => {
  const shown = el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.closest('[hidden], .sheet:not(.open), .nav-dropdown-content, .action-menu-dropdown'); };
  return [...document.querySelectorAll('.btn')].filter(shown).map(el => { const r = el.getBoundingClientRect(); return {text: el.textContent.trim().replace(/\\s+/g, ' ').slice(0, 30), cls: el.className, x: r.left, y: r.top, w: r.width, h: Math.round(r.height * 100) / 100}; });
}
"""


def _db():
    return pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor, autocommit=True)


def _clear(cur):
    for mac, *_ in DEVICES:
        cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (mac.replace(":", ""),))
        cur.execute("DELETE FROM devices WHERE mac=%s", (mac,))


@pytest.fixture(scope="module")
def c1_rows(live_server):
    """Three leases with a known manufacturer each (one last seen 400 days ago, so Devices shows a Stale badge beside two Dynamic ones)."""
    subnet_id = sorted(e2e._current_subnets())[0]
    conn = _db()
    try:
        with conn.cursor() as cur:
            _clear(cur)
            for mac, ip, host, maker, kind, days in DEVICES:
                cur.execute(
                    "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) "
                    "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 30 MINUTE), %s, %s, 0)",
                    (ip, mac.replace(":", ""), subnet_id, host),
                )
                cur.execute(
                    "INSERT INTO devices (mac, device_name, last_ip, last_hostname, last_subnet_id, manufacturer, device_type, device_icon, "
                    "first_seen, last_seen) VALUES (%s, %s, %s, %s, %s, %s, %s, '', "
                    "DATE_SUB(NOW(), INTERVAL %s DAY), DATE_SUB(NOW(), INTERVAL %s DAY))",
                    (mac, None, ip, host, subnet_id, maker, kind, days + 1, days),
                )
        yield
    finally:
        with conn.cursor() as cur:
            _clear(cur)
        conn.close()


def _flash(ctx, base_url):
    """Put the four categories into the signed-in session, as `flash()` would: the next full page prints them, once."""
    app = e2e.LIVE_APP
    name = app.config.get("SESSION_COOKIE_NAME", "session")
    serializer = app.session_interface.get_signing_serializer(app)
    cookie = next(c for c in ctx.cookies(base_url) if c["name"] == name)
    data = serializer.loads(cookie["value"])
    data["_flashes"] = [list(f) for f in FLASHES]
    ctx.add_cookies([{"name": name, "value": serializer.dumps(data), "url": base_url, "httpOnly": True}])


def _open(page, base_url, path):
    page.goto(f"{base_url}{path}", wait_until="load")
    with contextlib.suppress(Exception):  # a page that keeps polling is still a page that has drawn
        page.wait_for_load_state("networkidle", timeout=6000)


@pytest.fixture(scope="module")
def measured(browser, base_url, c1_rows):
    """(theme, sample) -> the list of {text, ratio, fg, bg} of every element of that sample the page shows. One sign-in, one walk."""
    ctx = browser.new_context(viewport=DESKTOP)
    page = ctx.new_page()
    login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
    pages = []
    for path, _sel, _texts in SAMPLES.values():
        if path not in pages:
            pages.append(path)
    out = {}
    for theme_id in THEMES:
        page.evaluate("(t) => localStorage.setItem('jen-theme-pick', t)", theme_id)
        for path in pages:
            if path == "/leases":
                _flash(ctx, base_url)
            _open(page, base_url, path)
            assert page.evaluate("() => document.documentElement.dataset.theme") == theme_id
            for sample, (sample_path, selector, texts) in SAMPLES.items():
                if sample_path == path:
                    out[(theme_id, sample)] = page.evaluate(MEASURE_JS, [selector, texts])
    page.evaluate("() => localStorage.removeItem('jen-theme-pick')")
    ctx.close()
    return out


@pytest.mark.parametrize("theme_id", THEMES)
@pytest.mark.parametrize("sample", list(SAMPLES))
def test_the_text_reads_in_every_theme(measured, theme_id, sample):
    rows = measured[(theme_id, sample)]
    assert rows, f"{theme_id}: the page shows no {sample} ({SAMPLES[sample][1]} on {SAMPLES[sample][0]})"
    worst = min(rows, key=lambda r: r["ratio"])
    assert worst["ratio"] >= AA, (
        f"{theme_id}: {sample} {worst['text']!r} is {worst['ratio']}:1 (text rgb{tuple(worst['fg'])} on rgb{tuple(worst['bg'])}); "
        f"{sum(1 for r in rows if r['ratio'] < AA)} of {len(rows)} under {AA}:1"
    )


def test_every_manufacturer_seeded_is_measured(measured):
    """The three hardest device colors are all on the page, in the theme where each was worst."""
    for theme_id in THEMES:
        shown = [r["text"] for r in measured[(theme_id, "manufacturer badge")]]
        assert {m for m in MAKERS if any(t.endswith(m) for t in shown)} == set(MAKERS), (theme_id, shown)


@pytest.mark.parametrize("theme_id", ["phosphor", "ember"])
def test_a_warning_banner_is_not_the_color_of_an_information_banner(measured, theme_id):
    """V7: in Phosphor the two banners were one amber, text and chip alike."""
    info = measured[(theme_id, "information banner")][0]
    warning = measured[(theme_id, "warning banner")][0]
    assert info["fg"] != warning["fg"] and info["bg"] != warning["bg"], (theme_id, info, warning)
    # and not a shade apart: the two text colors differ by more than 60 in at least one channel
    assert max(abs(a - b) for a, b in zip(info["fg"], warning["fg"], strict=True)) > 60, (
        theme_id,
        info["fg"],
        warning["fg"],
    )


def test_the_status_samples_are_the_three_tokens(measured):
    """What each sample is, said by the page: the Control Agent's "Connected", the SSH card's "No key generated" and a required field's star."""
    texts = {s: [r["text"] for r in measured[("light", s)]] for s in SAMPLES if s.endswith("status text")}
    assert any(t.startswith("● Connected") for t in texts["success status text"]), texts
    assert any("No key generated" in t for t in texts["warning status text"]), texts
    assert texts["danger status text"] == ["*"], texts


@pytest.mark.parametrize(
    ("kind", "icon"),
    [("warning", "triangle-alert"), ("info", "info"), ("success", "circle-check"), ("error", "circle-x")],
)
def test_a_toast_carries_its_categorys_icon(logged_in_page, kind, icon):
    """Stage c2: `jenToast` builds the icon a flash of the same category carries, before its text."""
    page = logged_in_page
    page.evaluate("([k]) => { jenToast('c2 ' + k + ' toast.', k); }", [kind])
    toast = page.locator(f".toast.alert-{kind}", has_text=f"c2 {kind} toast.")
    assert toast.evaluate(
        "(el) => [el.children[0].tagName.toLowerCase(), el.children[0].getAttribute('class'), el.children[0].getAttribute('aria-hidden'), "
        "el.children[0].firstElementChild.getAttribute('href'), el.children[1].className, el.children[0].getBoundingClientRect().width > 8]"
    ) == ["svg", "ico", "true", f"#i-{icon}", "alert-text", True]


def _beside(a, b):
    """Two boxes in one row: they overlap vertically by more than half the shorter one, and the gap between them is under 40 px."""
    overlap = min(a["y"] + a["h"], b["y"] + b["h"]) - max(a["y"], b["y"])
    gap = max(a["x"], b["x"]) - min(a["x"] + a["w"], b["x"] + b["w"])
    return overlap > min(a["h"], b["h"]) / 2 and -1 <= gap < 40


@pytest.fixture(scope="module")
def buttons(browser, base_url, c1_rows):
    """(width, path) -> every visible .btn with its box."""
    out = {}
    for name, viewport in (("1440", DESKTOP), ("390", PHONE)):
        ctx = browser.new_context(viewport=viewport)
        page = ctx.new_page()
        login(page, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, f"{base_url}/")
        for path in ("/leases", "/settings/kea", "/navigation"):
            _open(page, base_url, path)
            out[(name, path)] = page.evaluate(BUTTONS_JS)
        ctx.close()
    return out


@pytest.mark.parametrize("width", ["1440", "390"])
@pytest.mark.parametrize("path", ["/leases", "/settings/kea", "/navigation"])
def test_a_button_is_the_height_of_the_button_beside_it(buttons, width, path):
    found = buttons[(width, path)]
    assert len(found) >= 2, (width, path, found)
    uneven = []
    for i, a in enumerate(found):
        for b in found[i + 1 :]:
            if _beside(a, b) and (abs(a["h"] - b["h"]) > 0.5 or abs(a["y"] - b["y"]) > 0.5):
                uneven.append(
                    f"{a['text']!r} {a['h']} at {a['y']} ({a['cls']}) beside {b['text']!r} {b['h']} at {b['y']} ({b['cls']})"
                )
    assert uneven == [], f"{path} at {width}: {uneven}"


@pytest.mark.parametrize("width", ["1440", "390"])
@pytest.mark.parametrize("path", ["/leases", "/settings/kea", "/navigation"])
def test_no_button_is_under_24_px(buttons, width, path):
    short = [f"{b['text']!r} {b['h']} ({b['cls']})" for b in buttons[(width, path)] if b["h"] < 24]
    assert short == [], f"{path} at {width}: {short}"


def test_a_primary_and_a_secondary_button_are_one_height_and_the_small_size_is_one_height(buttons):
    """V18's two numbers: 29 against 31 px, and a small size that came in three heights."""
    sizes = {"btn": set(), "btn-sm": set()}
    kinds = set()
    for (width, _path), found in buttons.items():
        if width != "1440":
            continue
        for b in found:
            classes = b["cls"].split()
            sizes["btn-sm" if "btn-sm" in classes else "btn"].add(b["h"])
            kinds |= {c for c in classes if c in ("btn-primary", "btn-secondary")}
    assert kinds == {"btn-primary", "btn-secondary"}, kinds
    assert sizes["btn-sm"] == {24}, sizes
    assert len(sizes["btn"]) <= 2 and min(sizes["btn"]) >= 32, sizes  # 32, and 34 in an action bar (its own min-height)
