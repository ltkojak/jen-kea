"""
jen/services/setting_bounds.py
──────────────────────────────
ONE table of the whole-number settings a page writes with a bound, and ONE reader that applies the same bound (Q226, AL5, AL8, AL9, AL11; BOUND-001).

Q224 bounded three numbers on their forms; Q225 made two readers apply the bound; the pass on 7.0.0-beta.11 found six more readers taking a stored value raw, a page
printing the stored text where the server applies something else, and a retention of 0 that deleted a whole table. The rule is one sentence: a bounded number is read
through `bounded_setting`, which puts a row that is not a whole number at its default and one past either bound at the nearer bound, so a value stored by an earlier
release, by hand, or by a form that bounded less than this table says reaches no statement and no policy outside the bound. The forms read their bounds from this
table too (`bounds(key)`), so the way in and the way out cannot disagree; `tests/test_a_bounded_number_is_read_as_it_is_written.py` holds every writer to it.
"""

from jen.services.text import whole

#: key -> (default, lowest, highest). 0 keeps its meanings where the table says it may be stored (rate limiting: unlimited / until cleared; the audit log: keep forever).
SETTING_BOUNDS: dict[str, tuple[int, int, int]] = {
    "rl_max_attempts": (10, 0, 1000),
    "rl_lockout_minutes": (15, 0, 7 * 24 * 60),
    "audit_retention_days": (90, 0, 3650),
    "history_retention_days": (90, 1, 365),
    "events_retention_days": (90, 1, 3650),
    "alert_log_retention_days": (180, 1, 3650),
    "snapshot_interval_minutes": (30, 5, 1440),
    "stale_device_days": (30, 1, 365),
    "alert_threshold_pct": (80, 1, 100),
    "pool_exhaustion_free": (5, 1, 1_000_000),
}


def bounds(key: str) -> tuple[int, int, int]:
    """(default, lowest, highest) for `key`; a key that is not in the table is a programming error, never a guess."""
    return SETTING_BOUNDS[key]


def clamp(key: str, raw) -> int:
    """The number the server APPLIES for a stored text: the default for a value that is not a whole number, the nearer bound for one outside them."""
    default, lo, hi = SETTING_BOUNDS[key]
    return min(max(whole(raw, default), lo), hi)


def bounded_setting(key: str) -> int:
    """`clamp(key, <the stored row>)`: the one reader of a bounded settings number."""
    from jen.models.user import get_global_setting

    return clamp(key, get_global_setting(key, str(SETTING_BOUNDS[key][0])))


def in_bounds(key: str, raw) -> bool:
    """Is `raw` a whole number inside the table's bounds for `key`? The forms' test, so a form and the reader bound the same way."""
    _default, lo, hi = SETTING_BOUNDS[key]
    value = whole(raw)
    return value is not None and lo <= value <= hi
