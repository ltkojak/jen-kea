"""
jen/services/reltime.py
───────────────────────
v5.52.0 (Q59) — a datetime as a short relative time for a phone row: "in 3 d",
"2 h ago", "now". Backs the `relfmt` Jinja filter (create_app). Naive values are
UTC, which is what Kea's and Jen's own timestamps are. Pure.
"""

from datetime import datetime, timezone


def _int(value, *, through_float=False):
    """`value` as a whole number, or None when it is not one the arithmetic can carry: not a number (TypeError, ValueError) or `float("inf")` (OverflowError). The ONE coercion the three
    helpers below share (Q215, Z7: `duration_short` caught two of the three and an infinity was a 500). `through_float` reads "12.5" and "1e3" as 12 and 1000, which `duration_short` always did."""
    try:
        return int(float(value)) if through_float else int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def duration_short(seconds) -> str:
    """A length of time as the shortest honest phrase (Q205, AU9): "45 s", "90 min", "1 h", "2 h 30 min", "1 d", "1 d 12 h". Under a minute it is seconds; from a minute to two hours
    it is whole minutes (or "1 h" when it is exactly an hour); from two hours it is hours with the minutes that are left; from a day it is days with the hours that are left. Falls
    back to an em dash for a value that is not a non-negative number, so a template never prints 12.0h or None. Pure."""
    total = _int(seconds, through_float=True)
    if total is None or total < 0:
        return "—"
    if total < 60:
        return f"{total} s"
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days} d" + (f" {hours} h" if hours else "")
    if total < 7200:
        return "1 h" if total // 60 == 60 else f"{total // 60} min"
    return f"{hours} h" + (f" {minutes} min" if minutes else "")


def number(count) -> str:
    """A count with thousands separators, "12,345" (Q208, AX5). Always the US grouping, whatever the reader's locale: the product is written in American English and a count keeps one shape.
    A value that is not a whole number reads as 0, the same coercion `plural` makes. The `|number` filter."""
    n = _int(count) or 0
    return f"{n:,}"


def plural(count, singular, plural_form=None) -> str:
    """ "1 lease", "145 leases", "0 leases", "12,000 leases" (Q205, AU10; grouped in Q208): the count and the noun that agrees with it. `plural_form` for a noun that does not take an s
    (`entry` -> `entries`). The `|plural` filter."""
    n = _int(count) or 0
    word = singular if n == 1 else (plural_form or singular + "s")
    return f"{n:,} {word}"


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
