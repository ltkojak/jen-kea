"""
jen/services/view_prefs.py
──────────────────────────
v5.70.0-beta.2 (Q206, AV5): the rows-per-page choice of a list page is remembered per browser, in ONE cookie, `jen_view`.

Why a cookie and not localStorage like the theme and the time pick (`jen-time-pick`): those are applied by the browser to a page that is already rendered; the page SIZE is decided by
the server before the HTML exists, and a client-side re-request would show the full list first. The cookie is a display preference - no secret, not HttpOnly, SameSite=Lax, Secure
when the request is https - and it carries nothing a route authorises on: a restricted account's cookie changes how many of ITS OWN rows a page shows, never which rows.

Shape: a JSON object `{"leases": "100", "devices": "50"}`, at most 200 bytes. The parser is the whole contract: a value is accepted only from the page's OWN table, anything else
(junk, oversize, not JSON, not an object, a page it does not know, a number where a string belongs, a value from another page's table) is dropped, and the cookie is rewritten clean.
The routes call `resolve()` for the page size and `remember()` on the response; they never read `request.cookies` themselves.

Not remembered: the history (`expired=1`) and stale (`stale=1`) modes. A page that opened into history because you looked at it yesterday would surprise; they stay in the URL.
"""

import json

COOKIE = "jen_view"
MAX_COOKIE_BYTES = 200
MAX_AGE = 365 * 24 * 3600

# Each page's own table of accepted values. Today they happen to be the same four, but the TABLE is per page: a value valid for one page is not valid for another until it is
# written into that page's row.
_PER_PAGE_VALUES = ("all", "50", "100", "250")
PER_PAGE_TABLE = {
    "leases": _PER_PAGE_VALUES,
    "devices": _PER_PAGE_VALUES,
    "reservations": _PER_PAGE_VALUES,
}


def parse(raw):
    """The cookie's value as a clean {page: per_page} dict - only known pages, only values in that page's table. Never raises; anything unusable is {}."""
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8", "replace")) > MAX_COOKIE_BYTES:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    clean = {}
    for page, table in PER_PAGE_TABLE.items():
        value = data.get(page)
        if isinstance(value, str) and value in table:
            clean[page] = value
    return clean


def dump(prefs):
    """The canonical text of a clean dict (compact, keys in the table's order)."""
    return json.dumps({p: prefs[p] for p in PER_PAGE_TABLE if p in prefs}, separators=(",", ":"))


def resolve(page, args, cookies):
    """(per_page, stored) for `page`: the page size to use and the clean dict to keep.

    A `per_page` in the URL wins and is stored when it is in the page's table; absent, the cookie's value for this page; absent too, "all". An argument that is NOT in the table is
    used the way the routes always used it (their own int() fallback) and is never stored."""
    stored = parse(cookies.get(COOKIE))
    table = PER_PAGE_TABLE[page]
    explicit = args.get("per_page")
    if explicit is not None:
        if explicit in table:
            stored = {**stored, page: explicit}
        return explicit, stored
    return stored.get(page, "all"), stored


def remember(response, request, stored):
    """Write the cookie on `response` when what the browser holds is not already the canonical `stored` (a changed choice, or a junk cookie to be rewritten clean). Returns `response`."""
    held = request.cookies.get(COOKIE)
    if not stored:
        if held is not None:  # a cookie with nothing usable in it: take it away rather than keep rewriting nothing
            response.delete_cookie(COOKIE, path="/", samesite="Lax")
        return response
    text = dump(stored)
    if held != text:
        response.set_cookie(
            COOKIE, text, max_age=MAX_AGE, path="/", samesite="Lax", secure=bool(request.is_secure), httponly=False
        )
    return response


def subnet_filter_name(subnet_filter, accessible_subnet_map):
    """The name of the subnet a list is filtered to, for the summary line and the filtered empty state (Q206, AV4/AV6); "" when no subnet filter is in force.

    The caller has already reset a subnet it may not see (or that does not exist) to "all", and the lookup is in the caller's OWN map besides - a hidden subnet's name is not reachable from
    here, whatever `subnet_filter` says. A subnet with no name prints its number."""
    if subnet_filter == "all":
        return ""
    try:
        sid = int(subnet_filter)
    except (TypeError, ValueError):
        return ""
    info = accessible_subnet_map.get(sid)
    if info is None:
        return ""
    return info.get("name") or f"subnet {sid}"
