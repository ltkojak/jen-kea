"""
jen/services/session_timeout.py
───────────────────────────────
The idle-session deadline, defined ONCE (v5.70.0-beta.4, Q208 AX2).

`check_session_timeout` (the before_request middleware in jen/__init__.py) decides whether a session has expired, the `X-Jen-Session-Expires` response header and the
`<body data-session-expires>` attribute tell the browser when, and `POST /session/touch` moves it. All three read `deadline()`, so the number the person is shown is the
number the server enforces. The rule is the one the middleware has always applied: the user's own `session_timeout` (minutes) wins over the global
`session_timeout_minutes` (default 60); the global switch `session_timeout_enabled == "false"` or a timeout of 0 turns it off.

v5.70.0-beta.5 (Q210): the setting is read through ONE coercion (`_whole_minutes`), a deadline the arithmetic cannot carry is "no usable last_active", "the timeout is off" is announced
as a word (`OFF`) and never as an absence, and a request that only refreshes a view (`X-Jen-Poll: 1`) never moves `last_active` (`extends`).
"""

import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

from jen.models.user import get_global_setting

_log = logging.getLogger(__name__)

#: what the header, the body attribute and the touch answer carry when the idle timeout is switched off (Q210, AZ1 b): "off" is a word, not an absence
OFF = "off"

#: the request header a page that refreshes ITSELF sends (a health poll, a watch): it may only ever STOP an extension of the session, never cause one (Q210, AZ3)
POLL_HEADER = "X-Jen-Poll"

#: the longest idle timeout the settings accept, in minutes (the writers refuse more; the reader treats more as unreadable)
MAX_MINUTES = 1440
DEFAULT_MINUTES = 60

_WHOLE = re.compile(r"[0-9]{1,4}")
_warned = set()


def _whole_minutes(raw):
    """`raw` as a whole number of minutes in 0..1440, or None when it is not one (`x`, "", `60.5`, `1e3`, a 20-digit string, `-5`, a bool)."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if 0 <= raw <= MAX_MINUTES else None
    if isinstance(raw, str) and _WHOLE.fullmatch(raw):
        value = int(raw)
        return value if value <= MAX_MINUTES else None
    return None


def _global_minutes():
    """The global `session_timeout_minutes` setting through the one coercion. A hand-edited row that is not a whole number of minutes in 0..1440 reads as 60 (the default) and is logged
    once per process: the three writers already refuse such a value, so this is the reader's guard - a bad row must never be a 500 on every request, `/logout` included."""
    raw = get_global_setting("session_timeout_minutes", str(DEFAULT_MINUTES))
    minutes = _whole_minutes(raw)
    if minutes is None:
        key = repr(raw)[:40]
        if key not in _warned:
            _warned.add(key)
            _log.warning(
                "session_timeout_minutes is %s, not a whole number of minutes from 0 to %d: using %d",
                key,
                MAX_MINUTES,
                DEFAULT_MINUTES,
            )
        return DEFAULT_MINUTES
    return minutes


def timeout_minutes(user):
    """The idle timeout in minutes for `user`, or None when the timeout is off (the global switch, or a timeout of 0)."""
    if get_global_setting("session_timeout_enabled", "true") == "false":
        return None
    own = _whole_minutes(getattr(user, "session_timeout", None))
    timeout = own or _global_minutes()
    if timeout == 0:
        return None
    return timeout


def deadline(session, user):
    """`session["last_active"]` plus the timeout, as an aware datetime - or None when the timeout is off, the session has no (readable) `last_active` yet, or the moment is
    naive or past what the arithmetic can carry (a year-9999 value). None is never read as 'expired': the middleware keeps its own branches for a session without a usable `last_active`."""
    minutes = timeout_minutes(user)
    if minutes is None:
        return None
    last = session.get("last_active")
    if not last:
        return None
    try:
        moment = datetime.fromisoformat(last)
        if moment.tzinfo is None:
            return None
        return moment + timedelta(minutes=minutes)
    except (TypeError, ValueError, OverflowError):
        return None


def expires_at(session, user):
    """`deadline()` as whole epoch seconds (what the header, the body attribute and /session/touch carry), or None."""
    when = deadline(session, user)
    try:
        return int(when.timestamp()) if when is not None else None
    except (OverflowError, OSError, ValueError):  # a moment `timestamp()` cannot express on this platform
        return None


def announcement(session, user):
    """What the browser is told about the deadline: the epoch second it ends, `OFF` when the person's idle timeout is switched off, or None when there is nothing to say yet (the session has
    no readable `last_active`). Only the browser's watch reads it; the server enforces `deadline()` whatever it shows."""
    if timeout_minutes(user) is None:
        return OFF
    return expires_at(session, user)


def is_poll(headers):
    """True when the request says it only refreshes a view (`X-Jen-Poll: 1`). The header can only stop an extension of the session, so a forged one is the forger's own loss."""
    return headers.get(POLL_HEADER) == "1"


def extends(path, headers):
    """Whether an authenticated request to `path` moves `last_active` - the ONE definition. Not `/api/` (the dashboard's poll), `/metrics`, `/session/touch` (its own writer: a request it
    refuses must not have extended the session) or a request marked `X-Jen-Poll: 1`. The one request that moves it on purpose is a CSRF-checked POST to `/session/touch`."""
    return not (path.startswith("/api/") or path == "/metrics" or path in NO_TOUCH_PATHS or is_poll(headers))


def new_login_id():
    """A label for ONE sign-in (set where a session is established; it names the browser's cross-tab storage key so two accounts in one profile never read each other's deadline).
    Not a secret: the session cookie is the credential."""
    return secrets.token_hex(8)


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
    session, the sign-in page it is sent on to keeps that `next` - if it is one `_safe_next` accepts and it measures up to MAX_NEXT the way the ordinary one does - so the person still comes
    back to the page they were on."""
    from urllib.parse import quote

    path = full_path[:-1] if full_path.endswith("?") else full_path
    if method == "GET" and (path == "/login" or path.startswith("/login?")) and next_arg:
        from jen.routes.auth import _safe_next

        kept = _safe_next(next_arg)
        encoded = quote(kept, safe="") if kept else ""
        return login_url + "?next=" + encoded if encoded and len(encoded) <= MAX_NEXT else login_url
    if method != "GET" or path.startswith(NO_RETURN_PREFIXES) or not path.startswith("/") or path.startswith("//"):
        return login_url
    encoded = quote(path, safe="")
    if len(encoded) > MAX_NEXT:
        return login_url
    return login_url + "?next=" + encoded


#: paths whose own view writes `last_active`; the middleware does not touch the session for them (a refused request must not extend it)
NO_TOUCH_PATHS = ("/session/touch",)

#: a `next` longer than this (encoded) is dropped: the sign-in request would otherwise outgrow a server's request-line limit and the person would get a 400 instead of the page
MAX_NEXT = 1500


def now():
    return datetime.now(timezone.utc)


def now_epoch():
    return int(now().timestamp())
