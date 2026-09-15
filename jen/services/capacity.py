"""
jen/services/capacity.py
────────────────────────
v5.36.0 (Q35) — pool exhaustion forecast on the lease history Jen
already collects (`lease_history`: one row per subnet per snapshot with
`active_leases` and `pool_size`).

Pure. The route / Health check / API hand in rows and get back numbers.

Method: daily peaks of `active_leases` over the last `window_days`
(default 30), least-squares line through them, projected forward to the
day the line crosses 90 % and 100 % of the pool. A pool resize makes
older peaks incomparable, so only rows carrying the *current* pool size
are fitted. Fewer than `min_days` distinct days → "insufficient"; a
slope at or below zero → "flat" / "falling"; a crossing more than
`horizon_days` out is reported as beyond the horizon rather than as a
date nobody should plan around.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

WINDOW_DAYS = 30
MIN_DAYS = 7
HORIZON_DAYS = 365
WARN_DAYS = 30
FAIL_DAYS = 7


def _day(ts) -> date | None:
    if isinstance(ts, datetime):
        return ts.date()
    if isinstance(ts, date):
        return ts
    if isinstance(ts, str) and len(ts) >= 10:
        try:
            return date.fromisoformat(ts[:10])
        except ValueError:
            return None
    return None


def current_pool_size(rows: list[dict]) -> int:
    """The pool size of the newest row (0 when there are no rows or it
    is unknown)."""
    newest = None
    for r in rows or []:
        d = _day(r.get("snapshot_time") or r.get("ts"))
        if d is None:
            continue
        if newest is None or d >= newest[0]:
            newest = (d, int(r.get("pool_size") or 0))
    return newest[1] if newest else 0


def daily_peaks(rows: list[dict], pool_size: int | None = None) -> list[tuple[date, int]]:
    """[(day, peak active_leases)] ascending, for rows whose pool_size
    equals `pool_size` (default: the current one). Rows with no usable
    timestamp are skipped."""
    if pool_size is None:
        pool_size = current_pool_size(rows)
    peaks: dict[date, int] = {}
    for r in rows or []:
        if int(r.get("pool_size") or 0) != pool_size:
            continue
        d = _day(r.get("snapshot_time") or r.get("ts"))
        if d is None:
            continue
        active = int(r.get("active_leases") or 0)
        peaks[d] = max(peaks.get(d, 0), active)
    return sorted(peaks.items())


def high_water(rows: list[dict]) -> dict | None:
    """{'peak': n, 'on': date} over ALL rows (any pool size)."""
    best = None
    for r in rows or []:
        d = _day(r.get("snapshot_time") or r.get("ts"))
        active = int(r.get("active_leases") or 0)
        if d is not None and (best is None or active > best["peak"]):
            best = {"peak": active, "on": d}
    return best


def _fit(points: list[tuple[int, int]]) -> tuple[float, float, float]:
    """Least squares (slope, intercept, r²) for [(x, y)]."""
    n = len(points)
    sx = sum(p[0] for p in points)
    sy = sum(p[1] for p in points)
    sxx = sum(p[0] * p[0] for p in points)
    sxy = sum(p[0] * p[1] for p in points)
    den = n * sxx - sx * sx
    if den == 0:
        return 0.0, sy / n if n else 0.0, 0.0
    slope = (n * sxy - sx * sy) / den
    intercept = (sy - slope * sx) / n
    mean_y = sy / n
    ss_tot = sum((p[1] - mean_y) ** 2 for p in points)
    ss_res = sum((p[1] - (slope * p[0] + intercept)) ** 2 for p in points)
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot else 1.0
    return slope, intercept, max(0.0, min(1.0, r2))


def forecast(
    rows: list[dict],
    *,
    today: date | None = None,
    window_days: int = WINDOW_DAYS,
    min_days: int = MIN_DAYS,
    horizon_days: int = HORIZON_DAYS,
) -> dict:
    """The forecast for one subnet's rows. Always returns the same keys:
    trend ('rising' | 'flat' | 'falling' | 'insufficient' | 'no-pool'),
    slope_per_day, r2, days (distinct days fitted), pool_size,
    latest_peak, pct_now, days_to_90pct, date_90, days_to_100pct,
    date_100 (None when not reached inside the horizon or not rising),
    beyond_horizon (bool)."""
    today = today or date.today()
    pool = current_pool_size(rows)
    out = {
        "trend": "insufficient",
        "slope_per_day": 0.0,
        "r2": 0.0,
        "days": 0,
        "pool_size": pool,
        "latest_peak": 0,
        "pct_now": 0.0,
        "days_to_90pct": None,
        "date_90": None,
        "days_to_100pct": None,
        "date_100": None,
        "beyond_horizon": False,
    }
    if pool <= 0:
        out["trend"] = "no-pool"
        return out
    peaks = [(d, v) for d, v in daily_peaks(rows, pool) if d >= today - timedelta(days=window_days)]
    out["days"] = len(peaks)
    if peaks:
        out["latest_peak"] = peaks[-1][1]
        out["pct_now"] = round(100.0 * peaks[-1][1] / pool, 1)
    if len(peaks) < min_days:
        return out
    origin = peaks[0][0]
    points = [((d - origin).days, v) for d, v in peaks]
    slope, intercept, r2 = _fit(points)
    out["slope_per_day"] = round(slope, 3)
    out["r2"] = round(r2, 3)
    if slope > 0.05:
        out["trend"] = "rising"
    elif slope < -0.05:
        out["trend"] = "falling"
        return out
    else:
        out["trend"] = "flat"
        return out
    x_today = (today - origin).days
    for key, frac in (("90", 0.9), ("100", 1.0)):
        target = frac * pool
        x_cross = (target - intercept) / slope
        days_out = max(0, int(round(x_cross - x_today)))
        if peaks[-1][1] >= target:
            days_out = 0
        if days_out > horizon_days:
            out["beyond_horizon"] = True
            continue
        out[f"days_to_{key}pct"] = days_out
        out[f"date_{key}"] = (today + timedelta(days=days_out)).isoformat()
    return out


def summary_line(f: dict) -> str:
    """One sentence for the Reports card / Health detail."""
    if f["trend"] == "no-pool":
        return "no pool size recorded yet"
    if f["trend"] == "insufficient":
        return f"not enough history ({f['days']} of {MIN_DAYS} days needed)"
    base = f"trend {f['slope_per_day']:+.2f}/day over {f['days']} days"
    if f["trend"] == "flat":
        return base + " — flat"
    if f["trend"] == "falling":
        return base + " — falling"
    if f["days_to_90pct"] is not None:
        if f["days_to_90pct"] == 0:
            return base + f" — already at or above 90% ({f['pct_now']}%)"
        return base + f" — reaches 90% in ~{f['days_to_90pct']} days ({f['date_90']})"
    return base + f" — rising, but 90% is more than {HORIZON_DAYS} days out"
