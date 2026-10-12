"""
tests/e2e/test_gui_tour.py
───────────────────────────
The GUI tour (hygiene audit, 2026-10-10): every GET route Jen and its bundled plugins register is
opened in a real browser, as FOUR accounts - a superadmin, an admin with every subnet, an admin
restricted to one subnet and a viewer - and the result is written down: the HTTP status, the
browser's console errors and uncaught page errors, the words a server-side failure leaves in the
page ("Internal Server Error", "Traceback", "UndefinedError"), the load time and a screenshot. Every
link on every page that points back into Jen is followed too, once per account, so query-string
variants and detail pages the url_map does not name are visited as well.

The report (`artifacts/tour/report.md` + `report.json`) and the screenshots are the deliverable: the
`e2e` job uploads them on every run. The test itself FAILS only on what is unambiguously a bug for any
account: a 5xx, an uncaught page error, or a failure marker in the page. A 403 or a 404 for a route an
account may not use is the correct answer and is only recorded - and so is NOT repeated as a console error
(the browser logs "Failed to load resource" for the page's own 4xx), and a file download is a pass.

Runs only with JEN_E2E_TOUR=1 (its own step in .github/workflows/tests.yml, on the demo dataset so the
pages have rows to show). It is a tour, not a journey: nothing is submitted, nothing is changed - GET only.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import os
import re
import time

import pytest

from tests.e2e import conftest as e2e
from tests.e2e.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login

if os.environ.get("JEN_E2E_TOUR") != "1":
    pytest.skip("only runs with JEN_E2E_TOUR=1", allow_module_level=True)

pytestmark = pytest.mark.e2e

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOUR_DIR = os.path.join(ROOT, "artifacts", "tour")
DESKTOP = {"width": 1440, "height": 900}

TOUR_PASSWORD = "e2e-Tour!Pass1"
ACCOUNTS = {
    # name: (role, subnet_access JSON or None)
    "superadmin": ("superadmin", None),
    "admin_all": ("admin", None),
    "admin_scoped": ("admin", "[10]"),
    "viewer": ("viewer", None),
}

#: what the page says when the server failed behind a 200 or a partial - never acceptable for any account
FAILURE_MARKERS = ("Internal Server Error", "Traceback (most recent call last)", "UndefinedError", "jinja2.exceptions")

#: the browser's own console line for a response with an error status - the status is already in the report, so the line is not a second finding
CONSOLE_NOISE = re.compile(r"^Failed to load resource: the server responded with a status of \d{3}")

#: what Playwright raises for a navigation that turns into a file download: the route answered with a file, which is a pass
DOWNLOAD_STARTS = "Download is starting"

#: sample URL arguments per converter name; a converter not listed here is recorded as "skipped (no sample)". A tuple is every value to try (a rule is built once for each).
SAMPLE_ARGS = {
    "mac": "aa:bb:cc:dd:ee:01",
    "filename": "nav_logo.png",
    "source": ("isc", "windows"),
    "subnet_id": 10,
    "server_id": 1,
    "user_id": 1,
    "target_id": 1,
    "host_id": 1,
    "rev_id": 1,
    "device_id": 1,
    "switch_id": 1,
    "sink_id": 1,
    "key_id": 1,
    "channel_id": 1,
    "search_id": 1,
    "ifindex": 1,
    "plugin_id": "ipam",
    "kind": "kea",
    "service": "dhcp4",
    "name": "default",
    "action": "status",
    "step": "1",
}

#: routes that are not pages (downloads, redirects out, the logout) - visited for status only, no screenshot
NO_SCREENSHOT = re.compile(r"/(logout|export|download|\.csv|\.json|bundle|sw\.js|manifest\.json)")

MAX_CRAWL_PER_ACCOUNT = 250


def _app():
    app = getattr(e2e, "LIVE_APP", None)
    assert app is not None, "conftest.live_server publishes the app as LIVE_APP for the tour"
    return app


def _slug(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", url).strip("_")[:120] or "root"


def _routes(app) -> list[tuple[str, str]]:
    """(endpoint, concrete path) for every GET rule, with sample arguments; a rule whose converter has no sample is listed as skipped."""
    out, skipped = [], []
    for rule in app.url_map.iter_rules():
        if "GET" not in (rule.methods or ()):
            continue
        if rule.endpoint == "static" or rule.rule.startswith("/static/") or "<path:" in rule.rule:
            continue
        missing = [a for a in rule.arguments if a not in SAMPLE_ARGS]
        if missing:
            skipped.append((rule.endpoint, rule.rule, missing))
            continue
        names = sorted(rule.arguments)
        choices = [SAMPLE_ARGS[a] if isinstance(SAMPLE_ARGS[a], tuple) else (SAMPLE_ARGS[a],) for a in names]
        built = False
        for combo in itertools.product(*choices):
            try:
                with app.test_request_context():
                    from flask import url_for

                    path = url_for(rule.endpoint, **dict(zip(names, combo, strict=True)))
            except Exception:  # a value this rule has no variant for (the other `source`)
                continue
            built = True
            out.append((rule.endpoint, path))
        if not built:
            skipped.append((rule.endpoint, rule.rule, ["url_for failed for every sample"]))
    _routes.skipped = skipped
    return sorted(set(out), key=lambda t: t[1])


@pytest.fixture(scope="module", autouse=True)
def _accounts(live_server):
    from jen.models.db import jen_db
    from jen.models.user import hash_password

    with jen_db() as db, db.cursor() as cur:
        for name, (role, access) in ACCOUNTS.items():
            if name == "superadmin":
                continue
            cur.execute("DELETE FROM users WHERE username=%s", (f"tour_{name}",))
            cur.execute(
                "INSERT INTO users (username, password, role, subnet_access, must_change_password) VALUES (%s, %s, %s, %s, 0)",
                (f"tour_{name}", hash_password(TOUR_PASSWORD), role, access),
            )
    yield


def _client_mac() -> str | None:
    from jen.models.db import kea_db

    with kea_db() as db, db.cursor() as cur:
        cur.execute("SELECT HEX(hwaddr) AS h FROM lease4 WHERE hwaddr IS NOT NULL ORDER BY expire DESC LIMIT 1")
        row = cur.fetchone()
    if not row:
        return None
    h = row["h"] if isinstance(row, dict) else row[0]
    return ":".join(h[i : i + 2].lower() for i in range(0, 12, 2)) if h and len(h) == 12 else None


def _visit(page, base_url, path, console, errors):
    console.clear()
    errors.clear()
    started = time.monotonic()
    try:
        resp = page.goto(f"{base_url}{path}", wait_until="load", timeout=30000)
        status = resp.status if resp is not None else None
    except Exception as e:  # a navigation failure is a finding, not a crash of the tour
        ms = int((time.monotonic() - started) * 1000)
        if DOWNLOAD_STARTS in str(e):
            return {"status": None, "download": True, "ms": ms, "title": "(a file download)"}
        return {"status": None, "error": f"navigation: {e}"[:300], "ms": ms}
    with contextlib.suppress(Exception):  # a long poll is not "still loading"
        page.wait_for_load_state("networkidle", timeout=8000)
    ms = int((time.monotonic() - started) * 1000)
    text = page.evaluate("() => document.body ? document.body.innerText : ''")
    markers = [m for m in FAILURE_MARKERS if m in text]
    links = page.evaluate(
        "() => [...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href')).filter(h => h && h.startsWith('/') && !h.startsWith('//'))"
    )
    return {
        "status": status,
        "final_url": page.url.replace(base_url, ""),
        "ms": ms,
        "markers": markers,
        "console_errors": list(console)[:5],
        "page_errors": list(errors)[:5],
        "title": page.title()[:80],
        "links": sorted(set(links)),
    }


def _tour(browser, base_url, username, password, routes):
    ctx = browser.new_context(viewport=DESKTOP, device_scale_factor=1)
    page = ctx.new_page()
    console, errors = [], []
    page.on(
        "console",
        lambda m: console.append(m.text[:200]) if m.type == "error" and not CONSOLE_NOISE.match(m.text) else None,
    )
    page.on("pageerror", lambda e: errors.append(str(e)[:200]))
    login(page, base_url, username, password, re.compile(r".*"))
    rows = []
    seen = set()
    queue = [(ep, p) for ep, p in routes]
    crawled = 0
    while queue:
        endpoint, path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        r = _visit(page, base_url, path, console, errors)
        r.update(endpoint=endpoint, path=path)
        shot = None
        if not NO_SCREENSHOT.search(path) and r.get("status") not in (None, 302, 303):
            folder = os.path.join(TOUR_DIR, username)
            os.makedirs(folder, exist_ok=True)
            shot = os.path.join(folder, _slug(path) + ".png")
            try:
                page.screenshot(path=shot, full_page=False)
            except Exception:
                shot = None
        r["screenshot"] = os.path.relpath(shot, ROOT) if shot else None
        rows.append(r)
        if endpoint != "(crawl)":
            for link in r.pop("links", []):
                if link not in seen and crawled < MAX_CRAWL_PER_ACCOUNT and not NO_SCREENSHOT.search(link):
                    queue.append(("(crawl)", link))
                    crawled += 1
        else:
            r.pop("links", None)
    ctx.close()
    return rows


def _write_report(report: dict):
    os.makedirs(TOUR_DIR, exist_ok=True)
    with open(os.path.join(TOUR_DIR, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1, default=str)
    lines = [
        "# GUI tour",
        "",
        f"routes: {report['route_count']}; skipped (no sample argument): {len(report['skipped'])}",
        "",
    ]
    for account, rows in report["accounts"].items():
        bad = [
            r
            for r in rows
            if (r.get("status") or 0) >= 500 or r.get("markers") or r.get("page_errors") or r.get("error")
        ]
        lines += [
            f"## {account}: {len(rows)} pages, {len(bad)} failing",
            "",
            "| status | ms | path | title | errors |",
            "|---|---|---|---|---|",
        ]
        for r in rows:
            errs = "; ".join(
                r.get("markers", [])
                + r.get("page_errors", [])
                + r.get("console_errors", [])
                + ([r["error"]] if r.get("error") else [])
            )
            shown = "download" if r.get("download") else r.get("status")
            lines.append(f"| {shown} | {r.get('ms')} | `{r['path']}` | {r.get('title', '')} | {errs[:160]} |")
        lines.append("")
    lines += ["## skipped routes (no sample argument)", ""] + [
        f"- `{rule}` ({ep}): {miss}" for ep, rule, miss in report["skipped"]
    ]
    with open(os.path.join(TOUR_DIR, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def test_every_get_route_renders_for_every_account(browser, base_url):
    app = _app()
    routes = _routes(app)
    mac = _client_mac()
    if mac:
        routes += [
            ("client", f"/client?q={mac}"),
            ("explain", f"/tools/explain?mac={mac}&subnet=10"),
            ("trace", f"/tools/trace?mac={mac}&server=1"),
        ]
    routes += [
        ("not-found", "/this-page-does-not-exist"),
        ("leases-filtered", "/leases?subnet=10"),
        ("problems-filtered", "/problems?server=1&kind=nak"),
    ]
    report = {"route_count": len(routes), "skipped": _routes.skipped, "accounts": {}}
    report["accounts"][ADMIN_USERNAME] = _tour(browser, base_url, ADMIN_USERNAME, ADMIN_PASSWORD, routes)
    for name in ACCOUNTS:
        if name == "superadmin":
            continue
        report["accounts"][f"tour_{name}"] = _tour(browser, base_url, f"tour_{name}", TOUR_PASSWORD, routes)
    _write_report(report)

    failures = []
    # every GET route must have a sample for its converters: a route the tour cannot build is a page nobody opened
    assert not _routes.skipped, f"routes with no sample argument - add them to SAMPLE_ARGS: {_routes.skipped}"
    for account, rows in report["accounts"].items():
        for r in rows:
            if (r.get("status") or 0) >= 500 or r.get("markers") or r.get("page_errors") or r.get("error"):
                failures.append(
                    f"{account} {r['path']}: status {r.get('status')} {r.get('markers')} {r.get('page_errors')} {r.get('error', '')}"
                )
    assert not failures, (
        "pages that failed for some account (the full tour is in artifacts/tour/report.md):\n"
        + "\n".join(failures[:60])
    )
