"""
tests/test_dashboard_chart.py
─────────────────────────────
v5.69.0-beta.6 (Q175) - the Utilization History chart showed 24h, 7 days and 30 days as the same flat line: (a) `drawSparkline` scaled y to `Math.max(100, max(vals))`, so on a 60 px
canvas a subnet at 26% with a two-point swing was one pixel tall, and (b) nothing said what window the line covered or that the box had only six days of snapshots. The y-range is the
data's own band and the label carries the window's span. The API was never the cause (`days` is honoured; the buckets are hourly) and its contract is pinned here too.

The JS is checked three ways: the source says what it should (no database), the two functions are RUN under node when it is installed, and the dashboard's e2e test reads the label in a
real browser (tests/e2e/test_dashboard_arrange.py).
"""

import json
import pathlib
import re
import shutil
import subprocess

import pytest

TEMPLATE = pathlib.Path(__file__).resolve().parent.parent / "templates" / "dashboard.html"


def _source():
    return TEMPLATE.read_text(encoding="utf-8")


def _function(name):
    src = _source()
    start = src.index(f"function {name}(")
    depth = 0
    for i in range(src.index("{", start), len(src)):
        depth += {"{": 1, "}": -1}.get(src[i], 0)
        if depth == 0:
            return src[start : i + 1]
    raise AssertionError(name)


class TestTheChartSource:
    def test_the_band_function_exists_and_the_fixed_scale_is_gone(self):
        assert "function sparklineBand" in _source()
        assert "Math.max(100" not in _function("drawSparkline")

    def test_draw_uses_the_band_and_prints_its_edges(self):
        body = _function("drawSparkline")
        assert "sparklineBand(vals)" in body
        assert "band.lo" in body and "band.hi" in body
        assert "10px sans-serif" in body and "text-muted" in body

    def test_the_label_carries_the_window_and_the_apis_own_days(self):
        src = _source()
        assert "spanText(known, data.days" in src, (
            "the window text comes from the API's clamped answer, not the select's value"
        )
        assert "% of the pool · " in src and " in the pools · " in src

    def test_the_select_still_reloads_the_chart(self):
        assert "getElementById('history-days').addEventListener('change', loadHistory)" in _source()

    def test_the_subnet_card_sparklines_are_untouched(self):
        src = _source()
        assert "30d ago" in src and "active now" in src and "max = Math.max.apply(null, points) || 1" in src

    def test_nothing_is_inline_handled(self):
        assert "onchange=" not in _source()


NODE = shutil.which("node")


def _run(js):
    out = subprocess.run(  # nosec B603 - a fixed interpreter and a script built in this file
        [NODE, "-e", js], capture_output=True, text=True, timeout=30, check=True, encoding="utf-8"
    )
    return json.loads(out.stdout)


@pytest.mark.skipif(NODE is None, reason="node is not installed; the e2e test reads the label in a real browser")
class TestTheChartFunctionsRun:
    def _harness(self, calls):
        return f"""
{_function("sparklineBand")}
{_function("spanText")}
var out = {{}};
{calls}
console.log(JSON.stringify(out));
"""

    def test_a_flat_series_gets_a_band_around_itself_not_zero_to_one_hundred(self):
        out = _run(self._harness("out.band = sparklineBand([26, 26.4, 25.9, 26.2]);"))
        assert out["band"] == {"lo": 23, "hi": 29}

    def test_the_band_is_clamped_to_zero_and_one_hundred(self):
        out = _run(self._harness("out.a = sparklineBand([0, 1]); out.b = sparklineBand([99, 100]);"))
        assert out["a"]["lo"] == 0 and out["b"]["hi"] == 100

    def test_a_wide_swing_is_padded_by_a_quarter_of_it(self):
        out = _run(self._harness("out.band = sparklineBand([20, 60]);"))
        assert out["band"] == {"lo": 10, "hi": 70}

    def test_one_value_has_a_nonzero_height(self):
        out = _run(self._harness("out.band = sparklineBand([50, 50]);"))
        assert out["band"]["hi"] > out["band"]["lo"]

    def test_the_span_names_the_window_and_the_min_and_max(self):
        js = """
var now = Date.now();
function t(hoursAgo) { return new Date(now - hoursAgo * 3600000).toISOString().slice(0, 19).replace('T', ' '); }
function pts(n) { var a = []; for (var i = n; i >= 0; i--) a.push({t: t(i), pct: 24.1 + (i % 3) * 1.1}); return a; }
out.day = spanText(pts(24), 1);
out.week = spanText(pts(24 * 7 + 1), 7);
out.month = spanText(pts(24 * 30 + 1), 30);
out.young = spanText(pts(24 * 6), 30);
out.hours = spanText(pts(5), 1);
"""
        out = _run(self._harness(js))
        assert re.fullmatch(r"24h: 24\.1–26\.3%", out["day"]), out["day"]
        assert out["week"].startswith("7d: 24.1–26.3%") and "snapshots" not in out["week"], out["week"]
        assert out["month"].startswith("30d: ") and "snapshots" not in out["month"], out["month"]
        assert out["young"].endswith("(6 days of snapshots so far)"), out["young"]
        assert out["hours"].startswith("24h: ") and "under a day of snapshots so far" in out["hours"], out["hours"]

    def test_every_label_matches_the_shape_the_e2e_test_reads(self):
        js = """
var now = Date.now();
function t(h) { return new Date(now - h * 3600000).toISOString().slice(0, 19).replace('T', ' '); }
var a = []; for (var i = 24; i >= 0; i--) a.push({t: t(i), pct: 25 + (i % 2)});
out.a = '25% of the pool · 50 in the pools · ' + spanText(a, 1);
"""
        out = _run(self._harness(js))
        assert re.fullmatch(
            r"\d+(\.\d)?% of the pool · \d+ in the pools · (24h|30d): \d+(\.\d)?–\d+(\.\d)?%", out["a"]
        ), out["a"]


class TestTheHistoryApiHonoursItsWindow:
    """The API was never the cause: `days` is honoured, clamped to 1..90, the buckets are hourly, and the body says which window it answered."""

    SID = 1

    @pytest.fixture
    def seeded(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history WHERE subnet_id=%s", (self.SID,))
            for i in range(48):  # 48 hourly snapshots, the newest an hour old: pool_used rising 10 -> 57 of 200
                cur.execute(
                    "INSERT INTO lease_history (subnet_id, snapshot_time, active_leases, pool_used, pool_size) "
                    "VALUES (%s, DATE_SUB(NOW(), INTERVAL %s HOUR), %s, %s, 200)",
                    (self.SID, 48 - i, 10 + i, 10 + i),
                )
        db.commit()
        yield
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history WHERE subnet_id=%s", (self.SID,))
        db.commit()

    def _get(self, client, days):
        body = client.get(f"/api/lease-history?days={days}").get_json()
        return body, body["history"].get(str(self.SID), [])

    def test_one_day_is_at_most_twenty_five_buckets_and_says_so(self, logged_in_client, seeded):
        body, points = self._get(logged_in_client, 1)
        assert body["days"] == 1 and 0 < len(points) <= 25

    def test_seven_days_has_all_forty_eight_and_says_so(self, logged_in_client, seeded):
        body, points = self._get(logged_in_client, 7)
        assert body["days"] == 7 and len(points) == 48

    def test_zero_days_is_clamped_to_one(self, logged_in_client, seeded):
        body, points = self._get(logged_in_client, 0)
        assert body["days"] == 1 and len(points) <= 25

    def test_four_hundred_days_is_clamped_to_ninety(self, logged_in_client, seeded):
        body, points = self._get(logged_in_client, 400)
        assert body["days"] == 90 and len(points) == 48

    def test_the_percentage_is_pool_use_over_the_pool(self, logged_in_client, seeded):
        _body, points = self._get(logged_in_client, 7)
        assert points[0]["pct"] == 5.0 and points[-1]["pct"] == 28.5  # 10/200 and 57/200

    def test_the_window_changes_the_series_not_just_the_label(self, logged_in_client, seeded):
        _b1, day = self._get(logged_in_client, 1)
        _b7, week = self._get(logged_in_client, 7)
        assert len(day) < len(week) and day[0]["pct"] > week[0]["pct"]
