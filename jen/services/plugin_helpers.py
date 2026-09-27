"""
jen/services/plugin_helpers.py
────────────────────────────────
v5.65.10 (Q99 l) — the small helpers the seven bundled plugins each copied by hand, once, behind
`jen.plugin_api`. Every one of them replaces code that had already drifted between copies (two
failure conventions for "not a MAC", four plugins with a subnet-from-IP lookup, a `LIKE` that
treated a typed `%` as a wildcard in two of them and not in the other two), so a fix lands in one
place. Additive: `PLUGIN_API_VERSION` stays 3.

    normalize_mac(raw)               "AA-BB-CC-DD-EE-FF" -> "aa:bb:cc:dd:ee:ff", or None when it is not a MAC
    like_pattern(text)               "%text%" with the caller's own %, _ and backslash taken literally
    in_placeholders(values)          "%s,%s,%s" for a dynamic IN (...) — never the values themselves
    subnet_for_ip(ip)                the Kea subnet id whose CIDR holds `ip`, or None
    search_scope(ids, all, column)   (sql, params) limiting a search provider's own query to the caller's
                                     subnets, or None when the caller may see nothing
    require_write(...)               decorator: admins only, before the route touches the request
    subnet_or_404(subnet_id)         (subnet, None) or (None, (json 404 response))  — no flash, one answer
                                     for "not yours" and "not there"

Nothing here does work at import time.
"""

import ipaddress
import re
from functools import wraps

from flask import flash, jsonify, redirect, request, url_for

from jen import extensions

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_COLUMN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")


def normalize_mac(raw) -> str | None:
    """A MAC in any of the usual spellings (`aa:bb:..`, `AA-BB-..`, `aabb.ccdd.eeff`, bare hex) as
    lowercase colon-separated, or None. Anything that is not a string of exactly twelve hex digits
    once separators are dropped is None, including an empty value and a non-string one (a JSON body's
    `"mac": 5` used to raise inside `re.sub`). One convention: callers that allow a blank check
    `if raw` first."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(cleaned) != 12:
        return None
    mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return mac if _MAC_RE.match(mac) else None


def like_pattern(text) -> str:
    """`%text%` for a `LIKE` with the user's own `%`, `_` and backslash matched literally. A search for
    `10.0_1` must not match `10.0x1`, and a lone `%` must not match every row. The default MySQL/MariaDB
    escape character is the backslash, so no `ESCAPE` clause is needed."""
    escaped = str(text).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def in_placeholders(values) -> str:
    """`%s,%s,...` sized to `values`, for a dynamic `IN (...)`. An empty list gives `NULL`, so
    `IN (NULL)` is valid SQL that matches nothing instead of a syntax error."""
    n = len(list(values))
    return ",".join(["%s"] * n) if n else "NULL"


def subnet_for_ip(ip) -> int | None:
    """The id of the Kea subnet (from the unfiltered map) whose CIDR contains `ip`, or None: an
    unparseable address, or one in no Kea subnet. Derive a row's subnet from where the address IS,
    never from a `subnet_id` the caller typed (docs/ARCHITECTURE.md §2); None means "no attributable
    subnet", which is for unrestricted callers only (`can_access_subnet`)."""
    try:
        addr = ipaddress.IPv4Address(str(ip).strip())
    except ValueError:
        return None
    for sid, info in extensions.SUBNET_MAP.items():
        try:
            if addr in ipaddress.IPv4Network(info["cidr"], strict=False):
                return sid
        except (KeyError, ValueError):
            continue
    return None


def search_scope(accessible_ids, all_subnets, column):
    """For a `register_search_provider` callback: the SQL fragment and parameters that limit the
    provider's OWN query to the caller's subnets, or None when the caller may see nothing.

        scope = search_scope(accessible_subnet_ids, all_subnets, "r.subnet_id")
        if scope is None:
            return []
        clause, params = scope
        cur.execute(f"... WHERE (label LIKE %s) AND {clause} ORDER BY ... LIMIT 20", (like, *params))

    Jen re-filters every returned row anyway (the Q55 rule), but that runs AFTER the provider's own
    `LIMIT`: a provider that filters only afterwards can spend its 20 rows on other subnets' matches and
    hand a restricted caller nothing. Filter in the query, so the limit applies to what the caller may see.
    An unrestricted caller gets `1=1`. `column` must be a plain (optionally table-qualified) column name."""
    if not _COLUMN_RE.match(column or ""):
        raise ValueError(f"search_scope: {column!r} is not a column name")
    if all_subnets:
        return "1=1", []
    ids = sorted({int(i) for i in (accessible_ids or [])})
    if not ids:
        return None
    return f"{column} IN ({in_placeholders(ids)})", ids


def require_write(message="Viewers can look at this but not change it.", redirect_endpoint="dashboard.dashboard"):
    """Route decorator (put it directly under `@login_required`): admin or superadmin only. Checked
    BEFORE the route reads `request.form` or `request.files`. A page route flashes `message` and
    redirects to `redirect_endpoint`; a JSON or `/api/` request gets a 403 JSON body instead of a flash
    that would surface on the next page."""

    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            from jen.services.access import is_admin_or_above

            if is_admin_or_above():
                return fn(*args, **kwargs)
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": message}), 403
            flash(message, "error")
            return redirect(url_for(redirect_endpoint))

        return wrapped

    return deco


def subnet_or_404(subnet_id):
    """For a JSON or poll route that acts on one subnet: `(subnet_info, None)` when the session user
    may see it, else `(None, (response, 404))`. No flash (a flash queued on an answer that is not a page
    shows on the NEXT page), and the same 404 for a subnet that does not exist and one the caller may not
    see, so the answer is not an oracle."""
    from jen.services.access import assert_subnet_access

    subnet = extensions.SUBNET_MAP.get(subnet_id)
    if subnet is None or not assert_subnet_access(subnet_id, notify=False):
        return None, (jsonify({"error": "not found"}), 404)
    return subnet, None
