"""
tests/test_capacity.py
──────────────────────
v5.36.0 (Q35) — pool exhaustion forecast. Pure:
`python -m pytest --noconftest tests/test_capacity.py`.
"""

from datetime import date, datetime, timedelta

import pytest

from jen.services import capacity as cap

TODAY = date(2026, 9, 15)


def _rows(series, pool_size=254, per_day=2, start=None):
    """series: list of daily peaks (oldest first, ending yesterday);
    each day gets `per_day` snapshots, the peak being the given value."""
    start = start or TODAY - timedelta(days=len(series))
    rows = []
    for i, peak in enumerate(series):
        d = start + timedelta(days=i)
        for k in range(per_day):
            active = peak if k == per_day - 1 else max(0, peak - 5)
            rows.append(
                {
                    "snapshot_time": datetime(d.year, d.month, d.day, 8 + k * 6),
                    "active_leases": active,
                    "pool_size": pool_size,
                }
            )
    return rows


class TestDailyPeaks:
    def test_peak_per_day_and_ordering(self):
        rows = _rows([10, 20, 30])
        peaks = cap.daily_peaks(rows)
        assert [v for _d, v in peaks] == [10, 20, 30]
        assert peaks[0][0] < peaks[1][0] < peaks[2][0]

    def test_only_rows_with_the_current_pool_size_count(self):
        old = _rows([100, 110, 120], pool_size=128, start=TODAY - timedelta(days=10))
        new = _rows([30, 40], pool_size=254, start=TODAY - timedelta(days=2))
        assert cap.current_pool_size(old + new) == 254
        assert [v for _d, v in cap.daily_peaks(old + new)] == [30, 40]

    def test_string_timestamps_from_the_reports_query(self):
        rows = [
            {"ts": "2026-09-10 08:00", "active_leases": 5, "pool_size": 10},
            {"ts": "2026-09-10 20:00", "active_leases": 9, "pool_size": 10},
        ]
        assert cap.daily_peaks(rows) == [(date(2026, 9, 10), 9)]

    def test_high_water_spans_pool_sizes(self):
        rows = _rows([100], pool_size=128, start=TODAY - timedelta(days=5)) + _rows([40], pool_size=254)
        assert cap.high_water(rows) == {"peak": 100, "on": TODAY - timedelta(days=5)}


class TestForecast:
    def test_linear_rise_projects_the_crossing(self):
        # 100 → 190 over 10 days (x=0..9, today is x=10) at +10/day; 90% of 254 = 228.6 → x≈12.9
        rows = _rows(list(range(100, 200, 10)))
        f = cap.forecast(rows, today=TODAY)
        assert f["trend"] == "rising" and f["days"] == 10
        assert 9.9 <= f["slope_per_day"] <= 10.1 and f["r2"] > 0.99
        assert f["days_to_90pct"] == 3 and f["date_90"] == (TODAY + timedelta(days=3)).isoformat()
        assert f["days_to_100pct"] == 5
        assert "reaches 90% in ~3 days" in cap.summary_line(f)

    def test_projection_starts_today_and_stops_at_the_pool(self):
        rows = _rows(list(range(100, 200, 10)))  # +10/day, the line hits the pool at x=15.4 → day 6
        f = cap.forecast(rows, today=TODAY)
        proj = f["projection"]
        assert proj[0][0] == TODAY.isoformat() and proj[-1][0] == (TODAY + timedelta(days=6)).isoformat()
        assert proj[-1][1] == 254 and all(v <= 254 for _d, v in proj)
        assert proj[0][1] == 200  # intercept 100 + 10 * x_today(10)

    def test_projection_is_capped_at_thirty_days_for_a_slow_rise(self):
        rows = _rows([10 + i // 10 for i in range(30)])
        assert len(cap.forecast(rows, today=TODAY)["projection"]) == cap.PROJECTION_DAYS + 1

    def test_flat_and_falling_have_no_exhaustion_date(self):
        f = cap.forecast(_rows([50] * 12), today=TODAY)
        assert f["trend"] == "flat" and f["days_to_90pct"] is None
        assert "flat" in cap.summary_line(f)
        f = cap.forecast(_rows(list(range(200, 80, -10))), today=TODAY)
        assert f["trend"] == "falling" and f["days_to_90pct"] is None

    def test_insufficient_history(self):
        f = cap.forecast(_rows([10, 20, 30]), today=TODAY)
        assert f["trend"] == "insufficient" and f["days"] == 3
        assert "not enough history (3 of 7 days needed)" in cap.summary_line(f)

    def test_no_pool_size(self):
        f = cap.forecast(_rows([10] * 10, pool_size=0), today=TODAY)
        assert f["trend"] == "no-pool" and "no pool size" in cap.summary_line(f)

    def test_slow_rise_beyond_the_horizon(self):
        rows = _rows([10 + i // 10 for i in range(30)])  # ~+0.1/day
        f = cap.forecast(rows, today=TODAY)
        assert f["trend"] == "rising" and f["days_to_90pct"] is None and f["beyond_horizon"] is True
        assert "more than 365 days out" in cap.summary_line(f)

    def test_already_past_ninety_percent(self):
        rows = _rows(list(range(220, 250, 3)))
        f = cap.forecast(rows, today=TODAY)
        assert f["days_to_90pct"] == 0 and "already at or above 90%" in cap.summary_line(f)

    def test_window_excludes_old_days_and_resize_restarts_the_fit(self):
        old = _rows([200] * 20, pool_size=128, start=TODAY - timedelta(days=60))
        new = _rows(list(range(50, 130, 8)), pool_size=254)  # 10 days, +8/day
        f = cap.forecast(old + new, today=TODAY)
        assert f["days"] == 10 and f["pool_size"] == 254 and f["trend"] == "rising"

    def test_noise_does_not_break_the_fit(self):
        import random

        rng = random.Random(7)
        rows = _rows([100 + 5 * i + rng.randint(-4, 4) for i in range(20)])
        f = cap.forecast(rows, today=TODAY)
        assert f["trend"] == "rising" and 4 <= f["slope_per_day"] <= 6 and f["days_to_90pct"] is not None

    @pytest.mark.parametrize("bad", [[], [{"snapshot_time": "garbage", "active_leases": 1, "pool_size": 10}]])
    def test_garbage_rows_are_harmless(self, bad):
        f = cap.forecast(bad, today=TODAY)
        assert f["trend"] in ("no-pool", "insufficient")


class TestProjectionForEveryTrend:
    """v5.67.0-beta.12 (Q124) — the dashed line is drawn for rising, flat AND falling trends whenever the fit
    exists; only the exhaustion fields stay rising-only. Before, a falling or flat subnet had an empty
    projection, and the Reports chart struck "Projected (trend)" through in its legend."""

    EXHAUSTION = ("days_to_90pct", "date_90", "days_to_100pct", "date_100")

    def _assert_no_exhaustion(self, f):
        assert all(f[k] is None for k in self.EXHAUSTION) and f["beyond_horizon"] is False

    def test_a_falling_trend_has_a_full_clamped_projection_and_no_exhaustion(self):
        f = cap.forecast(_rows(list(range(200, 80, -10))), today=TODAY)  # -10/day
        assert f["trend"] == "falling"
        proj = f["projection"]
        assert len(proj) == cap.PROJECTION_DAYS + 1
        assert (
            proj[0][0] == TODAY.isoformat() and proj[-1][0] == (TODAY + timedelta(days=cap.PROJECTION_DAYS)).isoformat()
        )
        assert all(0 <= v <= 254 for _d, v in proj)
        assert [v for _d, v in proj] == sorted((v for _d, v in proj), reverse=True)  # never rises
        self._assert_no_exhaustion(f)

    def test_a_falling_line_never_goes_below_zero(self):
        f = cap.forecast(_rows(list(range(200, 80, -10))), today=TODAY)
        # the fit reaches zero well inside 30 days: today's value is ~80, falling 10/day
        assert min(v for _d, v in f["projection"]) == 0 and f["projection"][-1][1] == 0

    def test_a_flat_trend_has_a_full_projection_holding_its_level(self):
        f = cap.forecast(_rows([50] * 12), today=TODAY)
        assert f["trend"] == "flat"
        assert len(f["projection"]) == cap.PROJECTION_DAYS + 1
        assert {v for _d, v in f["projection"]} == {50}
        self._assert_no_exhaustion(f)

    def test_a_flat_line_above_the_pool_is_clamped_to_it(self):
        f = cap.forecast(_rows([300] * 12, pool_size=254), today=TODAY)
        assert f["trend"] == "flat" and {v for _d, v in f["projection"]} == {254}

    def test_projection_days_is_honoured(self):
        f = cap.forecast(_rows([50] * 12), today=TODAY, projection_days=10)
        assert len(f["projection"]) == 11

    def test_a_rising_trend_is_unchanged_it_still_stops_the_day_it_reaches_the_pool(self):
        f = cap.forecast(_rows(list(range(100, 200, 10))), today=TODAY)
        assert f["trend"] == "rising" and f["days_to_90pct"] == 3
        assert f["projection"][-1] == ((TODAY + timedelta(days=6)).isoformat(), 254)

    @pytest.mark.parametrize(
        "rows, trend", [(_rows([10, 20, 30]), "insufficient"), (_rows([10] * 10, pool_size=0), "no-pool")]
    )
    def test_no_fit_means_no_projection(self, rows, trend):
        f = cap.forecast(rows, today=TODAY)
        assert f["trend"] == trend and f["projection"] == []

    def test_the_card_sentence_carries_the_horizon_for_falling_and_flat(self):
        falling = cap.forecast(_rows(list(range(200, 80, -10))), today=TODAY)
        assert cap.summary_line(falling).endswith(f"falling — about 0 in {cap.PROJECTION_DAYS} days")
        slower = cap.forecast(_rows(list(range(120, 60, -5))), today=TODAY)  # -5/day: ~55 left at 12 days, 0 in 11
        assert slower["trend"] == "falling"
        last = slower["projection"][-1][1]
        assert f"about {last} in {cap.PROJECTION_DAYS} days" in cap.summary_line(slower)
        flat = cap.forecast(_rows([50] * 12), today=TODAY)
        assert cap.summary_line(flat).endswith("flat — holding near 50")

    def test_the_sentence_never_hard_codes_the_horizon(self):
        f = cap.forecast(_rows([50] * 12), today=TODAY, projection_days=10)
        assert cap.summary_line(
            cap.forecast(_rows(list(range(200, 80, -10))), today=TODAY, projection_days=10)
        ).endswith("in 10 days")
        assert "holding near 50" in cap.summary_line(f)

    def test_a_line_without_a_projection_falls_back_to_the_plain_words(self):
        # callers that hand summary_line a dict with no projection key (older fakes) still get a sentence
        f = {"trend": "falling", "slope_per_day": -1.0, "days": 10}
        assert cap.summary_line(f).endswith("— falling")
        assert cap.summary_line({**f, "trend": "flat"}).endswith("— flat")


class TestProjectionNote:
    """The one muted line under a chart that has no dashed projection — in words, so the legend never has to
    carry a struck-out entry."""

    def test_insufficient_says_how_many_more_days(self):
        f = cap.forecast(_rows([10, 20, 30]), today=TODAY)
        assert cap.projection_note(f) == "No projection yet: 4 more day(s) of history needed."

    def test_one_day_short_is_still_a_positive_number(self):
        f = cap.forecast(_rows([10, 20, 30, 40, 50, 60]), today=TODAY)
        assert "1 more day(s)" in cap.projection_note(f)

    def test_no_pool(self):
        f = cap.forecast(_rows([10] * 10, pool_size=0), today=TODAY)
        assert cap.projection_note(f) == "No projection: this subnet has no pool."

    @pytest.mark.parametrize("series", [[50] * 12, list(range(200, 80, -10)), list(range(100, 200, 10))])
    def test_a_chart_with_a_projection_needs_no_note(self, series):
        assert cap.projection_note(cap.forecast(_rows(series), today=TODAY)) == ""


class TestPoolUsedIsTheConsumptionSeries:
    """v5.68.0-beta.19 (Q154): the forecast fits the leases INSIDE the pools (`pool_used`), ignores a row whose pool_used is NULL, and never
    reads a row without the key as anything but the legacy `active_leases` caller it is."""

    @staticmethod
    def _with_used(series, used_series, pool_size=100):
        rows = _rows(series, pool_size=pool_size, per_day=1)
        for row, used in zip(rows, used_series, strict=True):
            row["pool_used"] = used
        return rows

    def test_thirty_reservations_outside_the_pool_do_not_move_the_forecast(self):
        """80 in the pool plus 30 outside: whole-subnet active is 110 (110 %), pool use is 80 (80 %)."""
        flat_in_pool = [80] * 10
        rows = self._with_used([110] * 10, flat_in_pool)
        f = cap.forecast(rows, today=TODAY)
        assert f["latest_peak"] == 80 and f["pct_now"] == 80.0 and f["trend"] == "flat"
        assert cap.high_water(rows)["peak"] == 80

    def test_a_null_pool_used_is_ignored_never_read_as_zero(self):
        rows = self._with_used([50] * 10, [None] * 6 + [60, 60, 60, 60])
        peaks = cap.daily_peaks(rows)
        assert [v for _d, v in peaks] == [60, 60, 60, 60], "the six rows from before the column are not 0 and not 50"
        assert cap.forecast(rows, today=TODAY)["trend"] == "insufficient"
        assert cap.forecast(rows, today=TODAY)["days"] == 4

    def test_all_null_is_insufficient_history_and_no_high_water(self):
        rows = self._with_used([50] * 10, [None] * 10)
        assert cap.high_water(rows) is None
        f = cap.forecast(rows, today=TODAY)
        assert f["trend"] == "insufficient" and f["days"] == 0 and f["latest_peak"] == 0

    def test_enough_new_rows_after_old_null_ones_forecast_normally(self):
        rows = self._with_used([10] * 18, [None] * 8 + [10 + 3 * i for i in range(10)])
        f = cap.forecast(rows, today=TODAY)
        assert f["trend"] == "rising" and f["days"] == 10 and f["days_to_90pct"] is not None

    def test_a_row_with_no_pool_used_key_falls_back_to_active_leases(self):
        rows = _rows([10 + 5 * i for i in range(10)])
        assert "pool_used" not in rows[0]
        assert cap.forecast(rows, today=TODAY)["trend"] == "rising"

    def test_the_used_accessor(self):
        assert cap.used({"pool_used": 7, "active_leases": 99}) == 7
        assert cap.used({"pool_used": None, "active_leases": 99}) is None
        assert cap.used({"active_leases": 99}) == 99
