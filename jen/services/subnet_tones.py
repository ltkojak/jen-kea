"""
jen/services/subnet_tones.py
────────────────────────────
v5.70.0-beta.1 (Q205, AU1) - a subnet's badge tone is chosen per subnet, from seven, and nothing is derived from its name.

The tone is stored in `subnet_notes.badge_color` (migration 37) beside the subnet's note; NULL, or a value that is not one of the seven, renders blue, so an upgrade changes nothing
on screen until a tone is picked. `tone_for(subnet_id)` is the one reader: a dict keyed by id, loaded ONCE per request (flask `g`) by one query, never a class built from a name. The
dict carries ids and tone names only - a hidden subnet's id is not printed anywhere by this module, and a template calls it only for a subnet it is already showing (the callers'
rows are the caller's own, Q204 RBAC-005).
"""

TONES = ("blue", "green", "red", "orange", "yellow", "purple", "mono")
DEFAULT_TONE = "blue"  # one constant: an unset tone is blue so the upgrade is invisible (Q205 deviation named: grey is the other choice)


def valid_tone(value) -> bool:
    return isinstance(value, str) and value in TONES


def _load() -> dict:
    """{subnet_id: tone} for every subnet with a stored tone; {} when the table cannot be read (a cosmetic read: the badge is blue)."""
    try:
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT subnet_id, badge_color FROM subnet_notes WHERE badge_color IS NOT NULL")
            return {int(r["subnet_id"]): r["badge_color"] for r in cur.fetchall() if valid_tone(r["badge_color"])}
    except Exception:
        return {}


def tones() -> dict:
    """The per-request map. Outside a request there is no cache to keep it in and it is read fresh."""
    try:
        from flask import g, has_request_context
    except ImportError:  # pragma: no cover
        return _load()
    if not has_request_context():
        return _load()
    cached = getattr(g, "_subnet_tones", None)
    if cached is None:
        cached = g._subnet_tones = _load()
    return cached


def tone_for(subnet_id) -> str:
    try:
        return tones().get(int(subnet_id), DEFAULT_TONE)
    except (TypeError, ValueError):
        return DEFAULT_TONE


def forget() -> None:
    """Drop this request's cache (the picker's route calls it after a write so a render in the same request sees the new tone)."""
    try:
        from flask import g, has_request_context

        if has_request_context() and hasattr(g, "_subnet_tones"):
            del g._subnet_tones
    except ImportError:  # pragma: no cover
        pass
