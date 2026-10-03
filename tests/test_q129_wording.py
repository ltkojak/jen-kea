"""
tests/test_q129_wording.py
──────────────────────────
v5.67.0-beta.15 (Q129, item f) — three sentences that said something the product did not.

* The restore warning for a plugin whose code is not on the machine said "its database row is kept", which reads as
  "its data is kept" — the data is NOT restored by that run; it stays inside the bundle (tests/test_restore_lifecycle.py
  asserts the live message; this file asserts the admin guide agrees with it).
* The Reports point tooltip printed "Total active" as dynamic + reserved. `reserved` is the COUNT of reservations
  (`hosts` rows), not of active leases, so the figure matched neither the new "Total active" line on the chart nor the
  card; it prints `active_leases` now.
* The lenient restore report double-indented "(none)" (tests/test_restore_lifecycle.py).
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


class TestRestoreWording:
    def test_the_message_and_the_admin_guide_say_the_same_thing(self):
        src = _read("jen/tools/restore.py")
        guide = _read("docs/admin-guide.md")
        assert "database row is kept" not in src and "database row is kept" not in guide
        for text in (src, guide):
            assert "will NOT be restored by this run" in text or "is **not** restored by this run" in text
            assert "still inside the bundle" in text and "run the restore again" in text

    def test_it_agrees_with_what_the_importer_itself_says(self):
        importer = _read("jen/services/dbexport.py")
        assert "was not restored; it is still inside this export/bundle" in importer


class TestReportsTooltip:
    def _after_body(self):
        html = _read("templates/reports.html")
        start = html.index("afterBody: function(items)")
        return html[start : html.index("scales:", start)]

    def test_the_point_tooltip_prints_active_leases(self):
        body = self._after_body()
        assert "const sum = total[idx] || 0;" in body
        assert "dynamic[idx]" not in body and "reserved[idx]" not in body
        assert "Total active: ${sum}" in body

    def test_total_is_the_active_leases_series(self):
        html = _read("templates/reports.html")
        assert re.search(r"const total = h\.data\.map\(d => d\.active_leases\);", html)
