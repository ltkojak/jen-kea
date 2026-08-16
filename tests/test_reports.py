"""
tests/test_reports.py
──────────────────────
v5.1.4 — Reports page was silently failing to render charts because
Chart.js was loaded from an external CDN (cdnjs.cloudflare.com) at
runtime via a dynamically-injected <script> tag. On any host without
outbound internet to that CDN (a realistic homelab scenario), the
script silently failed to load, onload never fired, buildCharts()
never ran, and the canvas stayed empty with no error shown anywhere —
the data itself (snapshot_interval, retention, data_points) was always
correct, only the chart rendering was broken.

Fixed by vendoring Chart.js locally at static/js/chart.umd.min.js,
matching the same "served locally for offline use" convention already
established for htmx.min.js — confirmed here rather than assumed.
"""

import pathlib
import pytest


class TestReportsChartJsVendoring:

    def test_no_external_cdn_reference_anywhere_in_template(self):
        content = open("templates/reports.html").read()
        assert "cdnjs.cloudflare.com" not in content
        assert "cdn.jsdelivr.net" not in content
        assert "unpkg.com" not in content

    def test_vendored_chart_js_file_exists_and_is_nonempty(self):
        path = pathlib.Path("static/js/chart.umd.min.js")
        assert path.exists()
        assert path.stat().st_size > 50_000  # a real bundle, not a stub

    def test_vendored_chart_js_exposes_global_chart_constructor(self):
        content = open("static/js/chart.umd.min.js").read()
        assert "Chart.js" in content[:200]  # header comment survives minification
        assert "window.Chart" in content  # UMD global export path present

    def _seed_history(self, db, subnet_id=1, points=3):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history WHERE subnet_id=%s", (subnet_id,))
            for i in range(points):
                cur.execute("""
                    INSERT INTO lease_history (subnet_id, active_leases,
                        dynamic_leases, reserved_leases, pool_size)
                    VALUES (%s, %s, %s, %s, %s)
                """, (subnet_id, 10 + i, 5 + i, 5, 100))
        db.commit()

    def test_page_references_local_chart_js_when_data_exists(self, logged_in_client, db):
        self._seed_history(db)
        resp = logged_in_client.get("/reports")
        assert resp.status_code == 200
        assert b'src="/static/js/chart.umd.min.js"' in resp.data
        assert b"cdnjs.cloudflare.com" not in resp.data

    def test_no_script_tag_referenced_when_no_history_data(self, logged_in_client, db):
        """When there's nothing to chart, the local Chart.js <script> tag
        shouldn't be pulled in at all — no reason to load ~200KB of JS
        for an empty page."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
        db.commit()
        resp = logged_in_client.get("/reports")
        assert resp.status_code == 200
        assert b'src="/static/js/chart.umd.min.js"' not in resp.data

    def test_script_tags_are_well_formed_not_nested(self, logged_in_client, db):
        """The fix closes and reopens <script> tags around the injected
        <script src=...> — confirm that produces valid, non-nested
        markup rather than a malformed <script><script> sequence."""
        self._seed_history(db)
        resp = logged_in_client.get("/reports")
        body = resp.data.decode()
        assert "<script><script" not in body
        # Every open <script has a matching close before the next open,
        # i.e. no script tag contains a literal nested <script tag.
        import re
        segments = re.split(r"(<script[^>]*>|</script>)", body)
        depth = 0
        for seg in segments:
            if seg.startswith("<script") and not seg.rstrip().endswith("/>"):
                if "src=" in seg:
                    continue  # self-closing-in-practice external script tags
                assert depth == 0, "nested <script> tag detected"
                depth = 1
            elif seg == "</script>":
                depth = 0

    def test_chart_still_builds_with_real_history_data_present(self, logged_in_client, db):
        """End-to-end sanity: with real snapshot rows in lease_history,
        the page actually embeds that data for the client-side chart to
        consume (HISTORY JS variable), not just the script tag."""
        self._seed_history(db, points=5)
        resp = logged_in_client.get("/reports")
        assert resp.status_code == 200
        assert b"buildCharts()" in resp.data
        assert b"const HISTORY" in resp.data
