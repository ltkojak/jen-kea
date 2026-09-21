"""
jen/services/reltime.py
───────────────────────
v5.52.0 (Q59) — a datetime as a short relative time for a phone row: "in 3 d",
"2 h ago", "now". Backs the `relfmt` Jinja filter (create_app). Naive values are
UTC, which is what Kea's and Jen's own timestamps are. Pure.
"""

from datetime import datetime, timezone


def relative_time(value, now=None):
    if not value:
        return "—"
    try:
        now = now or datetime.now(timezone.utc)
        v = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        secs = int((v - now).total_seconds())
    except Exception:
        return str(value)
    n = abs(secs)
    if n < 60:
        return "now"
    if n < 3600:
        span = f"{n // 60} min"
    elif n < 86400:
        span = f"{n // 3600} h"
    else:
        span = f"{n // 86400} d"
    return f"in {span}" if secs > 0 else f"{span} ago"
