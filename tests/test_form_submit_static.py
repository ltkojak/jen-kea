"""
tests/test_form_submit_static.py
──────────────────────────────────
v5.65.10 (Q99 f) — the source-level half of the full-page-submit fixes, runnable without a browser
(tests/e2e/test_form_submit_progress.py drives the behaviour). A download form that lacks
`data-download` leaves its button disabled and the bar sweeping until the page is left; the shared
progress bar must stop on `htmx:afterRequest` alone.
"""

import re
from pathlib import Path

import pytest

BASE = Path("templates/base.html").read_text(encoding="utf-8")

# POST forms whose response is a file (Content-Disposition), which never navigate
DOWNLOAD_FORMS = ["/database/export/jen", "/database/export/kea", "/settings/databases/recovery-bundle"]


@pytest.mark.parametrize("action", DOWNLOAD_FORMS)
def test_each_download_form_opts_out_of_the_disable_and_the_sweep(action):
    html = Path("templates/database.html").read_text(encoding="utf-8")
    tag = re.search(r'<form\b[^>]*action="' + re.escape(action) + r'"[^>]*>', html)
    assert tag, f"{action} form not found"
    assert "data-download" in tag.group(0)


def test_every_post_route_that_sends_a_file_has_a_data_download_form_or_a_script_submit():
    """Grep the routes that answer a POST with a Content-Disposition; each must be one of the forms
    above or be submitted from script (form.submit() fires no `submit` event, so it never disables)."""
    routes = []
    for path in Path("jen/routes").rglob("*.py"):
        src = path.read_text(encoding="utf-8")
        for m in re.finditer(r'@bp\.route\("([^"]+)",\s*methods=\["POST"\]\)(.*?)(?=\n@bp\.route|\Z)', src, re.S):
            if "Content-Disposition" in m.group(2):
                routes.append(m.group(1))
    assert routes, "the scan found no POST download route - the pattern broke"
    templates = "\n".join(p.read_text(encoding="utf-8") for p in Path("templates").glob("*.html"))
    for route in routes:
        if route in DOWNLOAD_FORMS:
            continue
        form = re.search(r'<form\b[^>]*action="' + re.escape(route) + r'"[^>]*>', templates)
        assert form is None or "data-download" in form.group(0), (
            f"{route} answers a POST with a file but its <form> has no data-download"
        )


def test_the_submit_listener_honours_defaultPrevented_before_it_touches_the_form():
    assert re.search(
        r"if \(e\.defaultPrevented\) return;\s*"
        r"if \(e\.target && e\.target\.tagName === 'FORM'\) "
        r"jenBeginFullPageSubmit\(e\.target, e\.submitter\);",
        BASE,
    )


def test_the_progress_bar_stops_on_afterRequest_only():
    assert "addEventListener('htmx:afterRequest', stop)" in BASE
    assert "addEventListener('htmx:responseError'" not in BASE


def test_a_download_form_starts_a_timed_bar_and_never_disables():
    m = re.search(r"if \(form\.hasAttribute\('data-download'\)\) \{(.*?)\n        \}", BASE, re.S)
    assert m, "the data-download branch is missing"
    body = m.group(1)
    assert "setTimeout(jenProgress.stop, 2000)" in body and "disabled" not in body and "return;" in body


def test_a_control_inside_a_card_header_does_not_fold_the_card():
    """v5.65.10 (Q99 m): the phone accordion toggled on any click in .card-header, including Alerts' Expand all."""
    src = Path("templates/_card_toc.html").read_text(encoding="utf-8")
    m = re.search(r"header\.addEventListener\('click', function\(e\) \{(.*?)\n            \}\);", src, re.S)
    assert m, "the header click handler is missing"
    body = m.group(1)
    assert "e.target.closest('button, a, input, select')" in body
    assert body.index("closest") < body.index("classList.toggle")
