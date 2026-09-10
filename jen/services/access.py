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

from flask import flash, redirect, request, session, url_for
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


def assert_subnet_access(subnet_id):
    """
    Return True if current user can access subnet_id.
    Flashes an error and returns False if not.
    """
    if current_user.can_access_subnet(subnet_id):
        return True
    flash("You do not have access to that subnet.", "error")
    return False


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
