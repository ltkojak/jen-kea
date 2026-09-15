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

    def test_projection_is_capped_at_thirty_days_and_empty_when_not_rising(self):
        rows = _rows([10 + i // 10 for i in range(30)])
        assert len(cap.forecast(rows, today=TODAY)["projection"]) == 31
        assert cap.forecast(_rows([50] * 12), today=TODAY)["projection"] == []

    def test_flat_and_falling(self):
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
