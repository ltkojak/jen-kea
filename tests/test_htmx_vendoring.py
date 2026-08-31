"""
tests/test_htmx_vendoring.py
─────────────────────────────
v5.1.14 — static/js/htmx.min.js had been a 42-byte placeholder comment
("// HTMX 1.9.12 - replace with actual file") instead of the real
library, present since at least v5.1.9 (the earliest version audited)
and likely far longer than that. Every hx-get/hx-trigger/hx-target/
hx-push-url attribute across the entire app was silently inert — no
JS ever executed to interpret them. Subnet filters, live-updating
dashboard widgets, and every other htmx-driven interaction appeared to
accept a selection (the browser's own <select> retained whatever the
user picked, since that's native DOM behavior unrelated to JS) while
the underlying request never fired, or the plain non-JS form fallback
silently produced an unfiltered result depending on the exact page.

This class of bug was already identified and fixed once before, for
Chart.js (see test_reports.py's TestReportsChartJsVendoring) — that
fix's own docstring explicitly named htmx.min.js as following "the
same convention," but no equivalent verification was ever written for
it. This file closes that gap using the same pattern, so a vendored
asset silently regressing to a placeholder — whether from a bad
packaging step, a self-update copy issue, or a manual edit — fails CI
immediately instead of shipping invisibly for years.

Why this specific bug produced no visible test failures despite 617
prior passing tests: every htmx-behavior test in this suite (e.g.
test_alerts.py's TestHTMXRoutes, test_kea6.py's htmx-partial tests)
sends a raw HX-Request header directly via the Flask test client and
asserts on the server's response shape. That's a legitimate way to
test the server-side "is this an htmx request" branch, but it never
loads a real browser or JS engine, so it cannot detect that the
client-side library making that header get sent in the first place
was never actually present in the shipped bundle.
"""

import pathlib


class TestHtmxVendoring:

    def test_no_external_cdn_reference_for_htmx_anywhere(self):
        """htmx must be served locally, not from a CDN — matches the
        same offline-homelab reasoning as the Chart.js fix."""
        for path in pathlib.Path("templates").rglob("*.html"):
            content = path.read_text(errors="ignore")
            assert "unpkg.com/htmx" not in content, f"{path} references htmx via CDN"
            assert "cdnjs.cloudflare.com/ajax/libs/htmx" not in content, f"{path} references htmx via CDN"

    def test_vendored_htmx_file_exists_and_is_nonempty(self):
        path = pathlib.Path("static/js/htmx.min.js")
        assert path.exists()
        # The placeholder that shipped for this exact bug was 42 bytes.
        # A real 1.9.x minified build is in the tens of KB — 20,000 is a
        # generous floor that catches any placeholder-sized stub without
        # being brittle to minor version/minification differences.
        assert path.stat().st_size > 20_000, (
            f"static/js/htmx.min.js is only {path.stat().st_size} bytes — "
            "looks like a placeholder, not the real vendored library"
        )

    def test_vendored_htmx_is_real_htmx_not_arbitrary_content(self):
        """Content-level check, not just a size check — a large file full
        of the wrong content would still pass the size assertion above."""
        content = pathlib.Path("static/js/htmx.min.js").read_text(errors="ignore")
        # UMD export path htmx's own build always contains, survives minification
        assert "e.htmx=e.htmx||t()" in content or "htmx.org" in content.lower() or "htmx:load" in content
        assert "htmx:load" in content  # a real htmx event name, always present

    def test_base_template_references_local_vendored_htmx(self):
        content = pathlib.Path("templates/base.html").read_text(errors="ignore")
        assert 'src="/static/js/htmx.min.js"' in content
