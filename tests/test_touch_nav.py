"""
tests/test_touch_nav.py
──────────────────────────
v5.55.1 (Q64) — base.html used to bind touchstart/touchmove/touchend on
EVERY `a[href]` and navigate on touchend unless the gesture looked like a
horizontal swipe (in the tree since v2.5.10, c9401b4). A vertical scroll
that started on any link and ended there — the ordinary way to scroll a
phone page — navigated instead. The block is deleted; native click
handling (already correct, and the reason `touch-action: manipulation`
and the viewport meta exist) is what actually fires now.

This is the source guard: no `touchstart`/`touchmove`/`touchend` listener
anywhere under templates/ or static/js/ navigates a page. Q58's sheets and
Q61's arrange mode were grepped first (2026-09-22, against 3b66725) — neither
uses touch events; ALLOWED stays empty. If a future feature has a real,
narrow reason to listen for one of these (a swipe gesture, a drag handle),
list it here explicitly with the reason rather than looking the other way —
an entry here is a decision, not an oversight.

The real behavior (a touch drag scrolls without navigating, a tap still
navigates) is proven for real in tests/e2e/test_mobile.py::TestTouchNav via
a CDP-driven touch drag; this file only proves the listener is gone.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent

# (file, reason) — a file allowed to bind one of these listeners, and why.
# Empty on purpose; see the module docstring.
ALLOWED: dict[str, str] = {}

_TOUCH_LISTENER_RE = re.compile(r"""addEventListener\(\s*['"](touchstart|touchmove|touchend)['"]""")


def _scan_files():
    return sorted((ROOT / "templates").rglob("*.html")) + sorted((ROOT / "static" / "js").glob("*.js"))


class TestNoTouchNavigationListener:
    def test_no_touch_listener_anywhere_outside_the_allowlist(self):
        offenders = []
        for path in _scan_files():
            rel = path.relative_to(ROOT).as_posix()
            if rel in ALLOWED:
                continue
            if path.name in ("htmx.min.js", "chart.umd.min.js"):
                continue  # vendored, not ours
            hits = _TOUCH_LISTENER_RE.findall(path.read_text(encoding="utf-8"))
            if hits:
                offenders.append((rel, hits))
        assert offenders == [], f"touch listeners found outside the allow-list: {offenders}"

    def test_allowlist_entries_still_need_it(self):
        # Catches an ALLOWED entry going stale (the listener it excused was
        # since removed, so the entry should be too).
        for rel in ALLOWED:
            path = ROOT / rel
            assert path.exists(), rel
            assert _TOUCH_LISTENER_RE.search(path.read_text(encoding="utf-8")), (
                f"{rel} is allow-listed for a touch listener that is no longer there — remove the entry"
            )

    def test_the_scanner_catches_a_real_one(self):
        # A regression test for the scanner itself: a bare touchend listener
        # (the exact shape the old base.html block used) must be caught.
        assert _TOUCH_LISTENER_RE.search("a.addEventListener('touchend', function(e) { window.location.href = x; })")
        assert _TOUCH_LISTENER_RE.search('a.addEventListener("touchstart", handler)')
        assert not _TOUCH_LISTENER_RE.search("a.addEventListener('click', handler)")

    def test_the_deleted_blocks_own_comment_is_gone_too(self):
        # The old block's identifying comment — if this still matches, the
        # deletion in base.html was incomplete.
        base = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
        assert "Instant navigation on touchstart" not in base
