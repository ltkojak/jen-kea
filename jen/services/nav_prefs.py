"""
jen/services/nav_prefs.py
─────────────────────────
v7.2.0-beta.1 (Q243) - a person's own navigation: the favorites after the fixed top
items and the slots of the phone's bottom bar. One row per person in `user_nav`
(migration 40), each list a short JSON array of destination ids in a VARCHAR
(the `dashboard_prefs` shape: MySQL 8 refuses a literal DEFAULT on TEXT/JSON).

A destination id is a page's address (`/leases`, `/settings/kea`) or
`plugin:<endpoint>`; `jen/routes/settings/nav.py` is the one place that says which
ids exist for a person and resolves the stored ones on every render. What is stored
here is a SHORTCUT list and nothing else: it grants nothing, and an id the person may
no longer open is skipped at render, never shown.

The edit itself (`apply_edit`) is pure. `load` never raises: the navigation is on
every page, and a page is served with the default navigation when the row cannot be read.
"""

import json
import logging

logger = logging.getLogger(__name__)

PLACES = ("top", "tabbar")
_COLUMN = {"top": "top_row", "tabbar": "tabbar"}
#: an id is an address or `plugin:<endpoint>`; nothing Jen defines comes near this, and a longer value is refused before it is stored
MAX_ID_LENGTH = 120

#: the sentences a refused edit is answered with (the route flashes them as they are)
FULL = {
    "top": "The top row holds five favorites. Remove one first.",
    "tabbar": "The phone bar holds four pages. Remove one first.",
}
NOT_OFFERED = "That page cannot be added."


def _decode(raw):
    """A stored list -> a list of strings; anything else stored there (a hand edit, a truncated value) is an empty list."""
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and 0 < len(v) <= MAX_ID_LENGTH]


def load(user_id):
    """`{"top": [ids], "tabbar": [ids]}` for this person; both empty when there is no row or the row cannot be read."""
    from jen.models.db import jen_db

    out = {"top": [], "tabbar": []}
    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT top_row, tabbar FROM user_nav WHERE user_id=%s", (user_id,))
            row = cur.fetchone()
    except Exception as e:  # the default navigation is served; the cause is logged, never shown
        logger.warning(f"could not read the navigation of user {user_id}: {type(e).__name__}")
        return out
    if row:
        out["top"] = _decode(row.get("top_row"))
        out["tabbar"] = _decode(row.get("tabbar"))
    return out


def save(user_id, place, ids):
    """Store one list for this person (the other is kept). Raises what the database raises: the caller says the change was not saved."""
    from jen.models.db import jen_db

    column = _COLUMN[
        place
    ]  # a KeyError here is a caller's defect: `place` is never taken from a request without `in PLACES`
    value = json.dumps(list(ids))
    with jen_db() as db, db.cursor() as cur:
        # the column name is one of two literals above, never a request value
        cur.execute(
            f"INSERT INTO user_nav (user_id, {column}) VALUES (%s, %s) ON DUPLICATE KEY UPDATE {column}=VALUES({column})",  # nosec B608
            (user_id, value),
        )


def apply_edit(current, action, dest, offered, limit, place):
    """Pure. One edit of one list -> `(new_list, refusal)`; `refusal` is None when the edit stands, else the sentence to show and the list is unchanged.

    `current` is the stored list (it may hold ids that do not resolve for this person today: they are kept, in place), `offered` the ids this person may add to this
    list now, `limit` how many RESOLVING entries the list may hold. Actions: add, remove, up, down, reset. An unknown action, or a remove/up/down of an id that is not
    in the list, changes nothing and is not an error (a second click, a stale page)."""
    current = list(current)
    offered = set(offered)
    if action == "reset":
        return [], None
    if not isinstance(dest, str) or not dest or len(dest) > MAX_ID_LENGTH:
        return current, NOT_OFFERED
    if action == "add":
        if dest in current:
            return current, None
        if dest not in offered:
            return current, NOT_OFFERED
        if sum(1 for i in current if i in offered) >= limit:
            return current, FULL[place]
        return [*current, dest], None
    if dest not in current:
        return current, None
    at = current.index(dest)
    if action == "remove":
        return current[:at] + current[at + 1 :], None
    if action in ("up", "down"):
        # move past the nearest neighbor that RESOLVES: an entry the person cannot see is not a step
        step = -1 if action == "up" else 1
        to = at + step
        while 0 <= to < len(current) and current[to] not in offered:
            to += step
        if 0 <= to < len(current):
            current[at], current[to] = current[to], current[at]
        return current, None
    return current, None
