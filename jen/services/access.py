"""
jen/services/access.py
──────────────────────
Shared access control decorators and helpers for the three-tier
role system: superadmin > admin > viewer.

Permission matrix
─────────────────
SuperAdmin : full access to everything, all subnets, always
Admin      : full management capability on assigned subnets only;
             can access Settings, Audit; cannot manage users or touch
             Database (export/import/migrate — v4.4.2, see database.py)
Viewer     : read-only on assigned subnets; cannot access Settings/DB/Audit

Import decorators from here rather than defining them per-route-file.
"""

from functools import wraps

from flask import abort, flash, redirect, request, session, url_for
from flask_login import current_user

# ── Role check helpers ────────────────────────────────────────────────────────


def is_superadmin():
    return current_user.is_authenticated and current_user.role == "superadmin"


def is_admin_or_above():
    return current_user.is_authenticated and current_user.role in ("superadmin", "admin")


def is_any_role():
    return current_user.is_authenticated


# ── Decorators ────────────────────────────────────────────────────────────────


def superadmin_required(f):
    """Restrict to superadmin only (user management, role assignment)."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        if current_user.role != "superadmin":
            flash("SuperAdmin access required.", "error")
            return redirect(url_for("dashboard.dashboard"))
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    """Restrict to admin or superadmin (settings, database, subnet editing, etc.)."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        if current_user.role not in ("superadmin", "admin"):
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard.dashboard"))
        return f(*args, **kwargs)

    return decorated


def viewer_or_above(f):
    """Any authenticated user (superadmin, admin, viewer)."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return decorated


# ── Step-up (recent-auth) gate — v5.17.0 (Q6 6A) ─────────────────────────────
#
# A live session isn't enough for the security-sensitive MFA-management
# routes: `session["auth_at"]` (ISO-UTC, set wherever a password — and MFA
# if enrolled — was just verified) must be within `minutes`, else the user
# is bounced through GET /auth/reauth to confirm their password.


def auth_is_recent(minutes: int) -> bool:
    from datetime import datetime, timezone

    raw = session.get("auth_at")
    if not raw:
        return False
    try:
        when = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).total_seconds() <= minutes * 60


def _same_origin_path(url) -> str | None:
    """The path (+query) of `url` if it is same-origin (or relative), else
    None. Used to sanitise `request.referrer` before storing it as a
    post-reauth redirect target."""
    if not url:
        return None
    from urllib.parse import urlparse

    p = urlparse(url)
    if p.scheme and p.scheme not in ("http", "https"):
        return None
    if p.netloc and p.netloc != request.host:
        return None
    path = p.path or "/"
    if not path.startswith("/") or path.startswith("//"):
        return None
    return path + (f"?{p.query}" if p.query else "")


def _reauth_return_target() -> str:
    if request.method == "GET":
        return (request.full_path or request.path).rstrip("?") or request.path
    # A POST route has no GET page of its own — return to the page that
    # held the button, falling back to the MFA/security page.
    return _same_origin_path(request.referrer) or url_for("mfa_routes.mfa_enroll")


def recent_auth_required(minutes: int = 10):
    def deco(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Not a Flask-Login session yet (forced MFA enrollment) or not
            # logged in at all — the route's own @login_required / pending
            # logic handles that; nothing to step up.
            if not current_user.is_authenticated:
                return f(*args, **kwargs)
            if auth_is_recent(minutes):
                return f(*args, **kwargs)
            session["reauth_next"] = _reauth_return_target()
            from jen.services import oidc as _oidc

            if _oidc.is_oidc_user(current_user.id):
                flash("Confirm your identity with your sign-on provider to continue.", "warning")
                return redirect(url_for("auth.reauth_oidc"))
            flash("Confirm your password to continue.", "warning")
            return redirect(url_for("auth.reauth"))

        return decorated

    return deco


# ── Subnet access helpers ─────────────────────────────────────────────────────


def get_accessible_subnet_map():
    """
    Return SUBNET_MAP filtered to subnets the current user can access.
    SuperAdmins and users with subnet_access=None get the full map.
    """
    from jen import extensions

    return current_user.filter_subnet_map(extensions.SUBNET_MAP)


def assert_subnet_access(subnet_id, *, notify=True):
    """
    Return True if current user can access subnet_id.
    Flashes an error and returns False if not. `notify=False` for a JSON or poll route (v5.65.10):
    a flash queued on an answer that is not a page shows up on the NEXT page the person opens.
    """
    if current_user.can_access_subnet(subnet_id):
        return True
    if notify:
        flash("You do not have access to that subnet.", "error")
    return False


# ── IPv6 subnet access: ONE rule (v5.68.0-beta.8, Q143) ───────────────────────
#
# A user's scope is a list of IPv4 subnet ids. A v6 subnet has no scope of its own: a decision about it can only be made through the
# v4 subnet it is paired with (`[subnets6]`'s third field, `paired_subnet4_id`) - never by comparing the v6 subnet's OWN id with
# that list (two numbering spaces; an id that happens to match means nothing). The policy, stated once and in docs/ARCHITECTURE.md §2:
#
#   * an unrestricted user (all_subnets: a superadmin, or no subnet list) sees every v6 subnet Jen knows;
#   * a PAIRED v6 subnet is accessible exactly when its paired v4 subnet id is in the user's list;
#   * an UNPAIRED v6 subnet has no v4 side to inherit access from: unrestricted users only.
#
# A subnet that is not in Jen's v6 map is accessible to no one (it has no pairing to judge). Everything below that touches the
# pairing lives in THIS module; tests/test_ipv6_access.py refuses the string `paired_subnet4_id` anywhere else in jen/routes and
# jen/services except the files that write or display the pairing (config.py, setup_wizard.py, settings/authoring.py).


def paired_v4_id(subnet6_id):
    """The v4 subnet id a v6 subnet is paired to, or None (unpaired, or not a known v6 subnet). For DISPLAY - nesting a v6 card
    inside its v4 card; every ACCESS decision goes through `subnet6_visible` and the trio below."""
    from jen import extensions

    info = extensions.SUBNET6_MAP.get(_as_int(subnet6_id))
    paired = info.get("paired_subnet4_id") if info else None
    return _as_int(paired)


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def subnet6_visible(subnet6_id, accessible_v4_ids, *, all_subnets: bool = False) -> bool:
    """The policy as a pure function, for the services that stay Flask-free and are handed the caller's scope (`client_subject`,
    `timeline`): may a caller who sees `accessible_v4_ids` (an iterable of v4 subnet ids) - or everything, when `all_subnets` -
    see something in v6 subnet `subnet6_id`? A subnet not in the v6 map is False for everyone."""
    from jen import extensions

    sid = _as_int(subnet6_id)
    info = extensions.SUBNET6_MAP.get(sid) if sid is not None else None
    if info is None:
        return False
    if all_subnets:
        return True
    paired = _as_int(info.get("paired_subnet4_id"))
    return paired is not None and paired in {
        i for i in (_as_int(x) for x in (accessible_v4_ids or ())) if i is not None
    }


def can_access_subnet6(subnet6_id) -> bool:
    """May the SESSION user see something in v6 subnet `subnet6_id`? See the policy above. Unknown subnet: False."""
    from jen import extensions

    if not current_user.is_authenticated:
        return False
    return subnet6_visible(
        subnet6_id,
        [] if current_user.all_subnets else current_user.accessible_subnet_ids(extensions.SUBNET_MAP),
        all_subnets=current_user.all_subnets,
    )


def accessible_subnet6_map() -> dict:
    """SUBNET6_MAP restricted to the v6 subnets the session user may see (the whole map for an unrestricted user). The only v6 map a
    template, a loop or a query may be given - never `extensions.SUBNET6_MAP` itself, which names and numbers every subnet."""
    from jen import extensions

    if not current_user.is_authenticated:
        return {}
    if current_user.all_subnets:
        return dict(extensions.SUBNET6_MAP)
    ids = set(current_user.accessible_subnet_ids(extensions.SUBNET_MAP))
    return {sid: info for sid, info in extensions.SUBNET6_MAP.items() if subnet6_visible(sid, ids)}


def assert_subnet6_access(subnet6_id) -> None:
    """Abort 404 unless the session user may see v6 subnet `subnet6_id` - the same answer for "no such subnet" and "not yours", so a
    scoped user cannot probe which v6 subnet ids exist, and never a fallback to some wider view."""
    if not can_access_subnet6(subnet6_id):
        abort(404)


# Device fields that describe WHERE a client is / what is recorded about it
# there; hidden when the device's own subnet is not the caller's.
_DEVICE_PLACEMENT_FIELDS = ("last_ip", "last_hostname", "last_subnet_id", "device_name", "owner", "notes")


def filter_client_view(view: dict, accessible_ids) -> dict:
    """The single rule for showing ONE client (a MAC) to a caller who may see
    only some subnets. `view` is `{"device", "lease", "reservation", ...}` as
    the Timeline / device API build it; `accessible_ids` is `None` for an
    unrestricted caller (returned untouched) else the set of subnet ids the
    caller may see.

    A client that moved subnets used to leak through its OLD one: the caller
    was authorised on a single "subject" subnet and then handed the lease and
    reservation from ANY subnet. Now every object is judged on ITS OWN subnet:

    * `lease` / `reservation` are dropped unless their `subnet_id` is accessible;
    * the device keeps its MAC and first/last-seen bookends, but its placement
      fields (last_ip, last_hostname, last_subnet_id, name, owner, notes) are
      blanked when `last_subnet_id` is None (unattributed — unrestricted
      callers only) or not accessible;
    * `subnet_id` is recomputed from what is left, so it is None when nothing
      remains — the caller then refuses (403), it never guesses.
    """
    if accessible_ids is None:
        return view
    ids = {int(i) for i in accessible_ids}

    def ok(sid):
        try:
            return sid is not None and int(sid) in ids
        except (TypeError, ValueError):
            return False

    out = dict(view)
    lease = view.get("lease")
    out["lease"] = lease if lease and ok(lease.get("subnet_id")) else None
    res = view.get("reservation")
    out["reservation"] = res if res and ok(res.get("subnet_id")) else None
    device = view.get("device")
    if device and not ok(device.get("last_subnet_id")):
        device = {**device, **dict.fromkeys(_DEVICE_PLACEMENT_FIELDS)}
    out["device"] = device
    if device and ok(device.get("last_subnet_id")):
        out["subnet_id"] = device["last_subnet_id"]
    elif out["lease"]:
        out["subnet_id"] = out["lease"]["subnet_id"]
    elif out["reservation"]:
        out["subnet_id"] = out["reservation"]["subnet_id"]
    else:
        out["subnet_id"] = None
    return out


# ── Diagnostic-surface coverage (v5.62.1, Q81) ────────────────────────────────
#
# tests/test_authz_matrix.py::SURFACES is a hand-maintained list of every
# route that can show data about a client across subnets a restricted caller
# must not see. It was complete the day it was audited; nothing stopped the
# next diagnostic route shipping without a row. `diagnostic_surface` makes
# that an invariant instead of a convention: every route it marks MUST have
# a matching SURFACES row, and the matrix test enforces the set equality
# both ways (see `collect_diagnostic_surfaces` below and the two-way test).

DIAGNOSTIC_SURFACES: list[tuple[str, tuple[str, ...], str]] = []


def diagnostic_surface(*, subject="client"):
    """Mark a route as part of the diagnostic surface. Does nothing at
    request time — it only tags the view function; Flask doesn't bind a
    Blueprint route's endpoint/methods/rule into `app.url_map` until
    `app.register_blueprint()` runs, so the actual triple can't be known at
    decoration time. `collect_diagnostic_surfaces()` resolves it once, right
    after every blueprint is registered (`jen/__init__.py`).

    Apply it as the innermost decorator (directly above `def`, below any
    `@login_required`/`@_admin_required`): every decorator in this module
    uses `functools.wraps`, which merges `__dict__`, so the tag written here
    survives being wrapped by the decorators above it.
    """

    def deco(f):
        f._diagnostic_surface_subject = subject
        return f

    return deco


def collect_diagnostic_surfaces(app) -> None:
    """Populate DIAGNOSTIC_SURFACES from every route `diagnostic_surface`
    tagged, once, right after every blueprint has been registered on `app`."""
    DIAGNOSTIC_SURFACES.clear()
    for rule in app.url_map.iter_rules():
        view = app.view_functions.get(rule.endpoint)
        if view is None or not hasattr(view, "_diagnostic_surface_subject"):
            continue
        methods = tuple(sorted((rule.methods or set()) - {"HEAD", "OPTIONS"}))
        DIAGNOSTIC_SURFACES.append((rule.endpoint, methods, rule.rule))


def add_subnet_restriction(where_clauses, params, table_alias="l", column="subnet_id"):
    """
    If the current user has restricted subnet access, append a
    WHERE clause limiting results to their assigned subnets.

    Usage:
        where, params = add_subnet_restriction(where, params, "l", "subnet_id")
    """
    from jen import extensions

    if not current_user.all_subnets:
        ids = current_user.accessible_subnet_ids(extensions.SUBNET_MAP)
        if not ids:
            # User has no subnet access at all — return nothing
            where_clauses.append("1=0")
        else:
            placeholders = ",".join(["%s"] * len(ids))
            where_clauses.append(f"{table_alias}.{column} IN ({placeholders})")
            params.extend(ids)
    return where_clauses, params
