"""
jen/services/session_timeout.py
───────────────────────────────
The idle-session deadline, defined ONCE (v5.70.0-beta.4, Q208 AX2).

`check_session_timeout` (the before_request middleware in jen/__init__.py) decides whether a session has expired, the `X-Jen-Session-Expires` response header and the
`<body data-session-expires>` attribute tell the browser when, and `POST /session/touch` moves it. All three read `deadline()`, so the number the person is shown is the
number the server enforces. The rule is the one the middleware has always applied: the user's own `session_timeout` (minutes) wins over the global
`session_timeout_minutes` (default 60); the global switch `session_timeout_enabled == "false"` or a timeout of 0 turns it off.
"""

from datetime import datetime, timedelta, timezone

from jen.models.user import get_global_setting


def timeout_minutes(user):
    """The idle timeout in minutes for `user`, or None when the timeout is off (the global switch, or a timeout of 0)."""
    if get_global_setting("session_timeout_enabled", "true") == "false":
        return None
    timeout = user.session_timeout or int(get_global_setting("session_timeout_minutes", "60"))
    if int(timeout) == 0:
        return None
    return int(timeout)


def deadline(session, user):
    """`session["last_active"]` plus the timeout, as an aware datetime - or None when the timeout is off, the session has no (readable) `last_active` yet, or the moment is
    naive. None is never read as 'expired': the middleware keeps its own branches for a session without a usable `last_active`."""
    minutes = timeout_minutes(user)
    if minutes is None:
        return None
    last = session.get("last_active")
    if not last:
        return None
    try:
        moment = datetime.fromisoformat(last)
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:
        return None
    return moment + timedelta(minutes=minutes)


def expires_at(session, user):
    """`deadline()` as whole epoch seconds (what the header, the body attribute and /session/touch carry), or None."""
    when = deadline(session, user)
    return int(when.timestamp()) if when is not None else None


#: paths whose address is never worth coming back to: the sign-in and sign-out pages themselves (an expired session that asks for /login would otherwise come back to /login?next=/login...),
#: the session endpoints, the JSON poll and the metrics scrape (a person signed in again would land on raw JSON), and static files
NO_RETURN_PREFIXES = (
    "/login",
    "/logout",
    "/auth/",
    "/session/",
    "/api/",
    "/metrics",
    "/static/",
    "/force-password-change",
)


def login_redirect_location(login_url, method, full_path, next_arg=""):
    """Where an expired session is sent: the sign-in page, and for a GET of an ordinary page the same page again as `?next=` (the sign-in page's `_safe_next` is the only parser of it). A POST
    carries nothing - its form data is gone either way - and neither does a path in NO_RETURN_PREFIXES. `full_path` is Flask's `request.full_path` (a bare path ends in a `?`).

    One exception to 'the sign-in page carries nothing': when the browser itself went to `/login?next=...` at the deadline (the session dialog's script does) and the server has already ended the
    session, the sign-in page it is sent on to keeps that `next` - if it is one `_safe_next` accepts - so the person still comes back to the page they were on."""
    from urllib.parse import quote

    path = full_path[:-1] if full_path.endswith("?") else full_path
    if method == "GET" and (path == "/login" or path.startswith("/login?")) and next_arg:
        from jen.routes.auth import _safe_next

        kept = _safe_next(next_arg)
        return login_url + "?next=" + quote(kept, safe="") if kept else login_url
    if method != "GET" or path.startswith(NO_RETURN_PREFIXES) or not path.startswith("/") or path.startswith("//"):
        return login_url
    return login_url + "?next=" + quote(path, safe="")


def now():
    return datetime.now(timezone.utc)
