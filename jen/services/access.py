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
from flask import flash, redirect, url_for
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


def add_subnet_restriction(where_clauses, params, table_alias="l",
                           column="subnet_id"):
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
            where_clauses.append(
                f"{table_alias}.{column} IN ({placeholders})"
            )
            params.extend(ids)
    return where_clauses, params
