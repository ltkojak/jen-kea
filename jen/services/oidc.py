"""
jen/services/oidc.py
─────────────────────
OpenID Connect single sign-on (v5.25.0, Q21). Local accounts keep
working exactly as before — this is an additional login path, not a
replacement. An IdP-managed ("oidc") user has its role re-evaluated on
every login, never enrolls Jen's own MFA, and never has a usable local
password.

Registration with the IdP (`init_oidc`) is lazy: `OAuth.register()`
only records the client's configuration — the `.well-known/openid-
configuration` discovery document isn't fetched until the first actual
login attempt (`authorize_redirect`/`authorize_access_token`), so a
misconfigured or unreachable issuer never blocks app startup.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone

from jen import extensions
from jen.services import auth as _auth

logger = logging.getLogger(__name__)

_oauth = None

# Highest-privilege first — map_role() returns the first of these whose
# mapped claim values intersect what the token actually carries.
_ROLES_BY_RANK = ("superadmin", "admin", "viewer")


def init_oidc(app) -> None:
    """Called once from create_app(). No-op (and no client registered)
    unless [oidc] enabled=true — every other function in this module is
    written to behave correctly with oidc_client() returning None."""
    global _oauth

    if not extensions.OIDC_ENABLED:
        _oauth = None
        return

    from authlib.integrations.flask_client import OAuth

    _oauth = OAuth(app)
    _oauth.register(
        "oidc",
        client_id=extensions.OIDC_CLIENT_ID,
        client_secret=extensions.OIDC_CLIENT_SECRET,
        server_metadata_url=extensions.OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": extensions.OIDC_SCOPES},
    )


def oidc_client():
    """The registered authlib client, or None when SSO isn't enabled/configured."""
    return _oauth.oidc if _oauth else None


def parse_role_map(raw: str) -> dict[str, list[str]]:
    """`"superadmin=g1,g2;admin=g3"` -> {"superadmin": ["g1","g2"], "admin": ["g3"]}.
    A malformed segment (no '=', an unknown role name, an empty value
    list) is skipped rather than raised — a config typo must not turn
    into a 500 on every login attempt."""
    out: dict[str, list[str]] = {}
    for segment in (raw or "").split(";"):
        segment = segment.strip()
        if not segment or "=" not in segment:
            continue
        role, _, values_raw = segment.partition("=")
        role = role.strip()
        if role not in _ROLES_BY_RANK:
            continue
        values = [v.strip() for v in values_raw.split(",") if v.strip()]
        if values:
            out[role] = values
    return out


def map_role(claims: dict) -> str | None:
    """Highest of superadmin > admin > viewer among the groups this
    token's role_claim actually carries. role_claim may be a list claim
    or a space-separated string claim (both are real-world IdP shapes).
    Falls back to OIDC_DEFAULT_ROLE when nothing matches; "none" (or an
    unmapped, non-matching claim with default_role="none") returns None,
    which the caller treats as "deny this login"."""
    raw = claims.get(extensions.OIDC_ROLE_CLAIM)
    if raw is None:
        groups: list[str] = []
    elif isinstance(raw, str):
        groups = raw.split()
    else:
        groups = [str(g) for g in raw]
    group_set = set(groups)

    role_map = parse_role_map(extensions.OIDC_ROLE_MAP)
    for role in _ROLES_BY_RANK:
        if group_set & set(role_map.get(role, [])):
            return role

    default = extensions.OIDC_DEFAULT_ROLE
    return None if default == "none" else default


def _candidate_username(claims: dict) -> str | None:
    """preferred_username (or whatever username_claim names) may contain
    '@' or spaces — sanitize with the same validator a local username has
    to pass. Falls back to email, then sub, warning in the audit detail
    either way (v5.25.0 Gotcha)."""
    for key in (extensions.OIDC_USERNAME_CLAIM, "email", "sub"):
        raw = str(claims.get(key) or "").strip()[:100]
        if raw and _auth.valid_username(raw):
            return raw
    return None


def find_or_create_user(claims: dict) -> tuple[dict | None, str]:
    """Match ONLY on (auth_provider='oidc', external_id=sub) — never on
    username or email, both of which an IdP can reassign or reuse in
    ways `sub` never is. Returns (user_row, "ok") on success, or
    (None, reason) — reason is one of: no_subject, no_role,
    auto_create_disabled, no_username, username_collision."""
    from jen.models.db import jen_db
    from jen.models.user import audit, hash_password

    sub = str(claims.get("sub") or "").strip()
    if not sub:
        return None, "no_subject"

    with jen_db() as db, db.cursor() as cur:
        cur.execute(
            "SELECT id, username, role, session_timeout, subnet_access, "
            "token_version, must_change_password, auth_provider, external_id "
            "FROM users WHERE auth_provider='oidc' AND external_id=%s",
            (sub,),
        )
        row = cur.fetchone()

        role = map_role(claims)

        if row:
            if role is None:
                audit("oidc_denied", row["username"], "no role mapped for current groups")
                return None, "no_role"
            if role != row["role"]:
                cur.execute("UPDATE users SET role=%s WHERE id=%s", (role, row["id"]))
                audit("oidc_role_change", row["username"], f"{row['role']} -> {role}")
                row["role"] = role
            return row, "ok"

        if not extensions.OIDC_AUTO_CREATE:
            return None, "auto_create_disabled"

        if role is None:
            audit("oidc_denied", sub, "no role mapped for current groups")
            return None, "no_role"

        username = _candidate_username(claims)
        if not username:
            return None, "no_username"

        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            audit("oidc_denied", username, f"username collision on first OIDC login (sub={sub})")
            return None, "username_collision"

        random_password = hash_password(secrets.token_urlsafe(32))
        cur.execute(
            "INSERT INTO users (username, password, role, auth_provider, external_id, must_change_password) "
            "VALUES (%s, %s, %s, 'oidc', %s, 0)",
            (username, random_password, role, sub),
        )
        new_id = cur.lastrowid
        audit("oidc_create", username, f"role={role} sub={sub}")

        cur.execute(
            "SELECT id, username, role, session_timeout, subnet_access, "
            "token_version, must_change_password, auth_provider, external_id "
            "FROM users WHERE id=%s",
            (new_id,),
        )
        return cur.fetchone(), "ok"


def establish_session(row: dict, detail: str) -> None:
    """The login_user() + last_active + auth_at + _user_cache block —
    extracted from auth.py's login() so the local-password path and the
    OIDC callback can never drift apart on what "signed in" means for
    session state. `row` needs the same columns login()'s own SELECT
    already reads: id, username, role, session_timeout, subnet_access,
    token_version, must_change_password."""
    from flask import session
    from flask_login import login_user

    from jen.models.user import User, audit

    user = User(
        row["id"],
        row["username"],
        row["role"],
        row.get("session_timeout"),
        row.get("subnet_access"),
        row.get("must_change_password"),
    )
    session.clear()
    login_user(user)
    now = datetime.now(timezone.utc).isoformat()
    session["last_active"] = now
    session["auth_at"] = now
    session["_user_cache"] = {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "session_timeout": user.session_timeout,
        "subnet_access": row.get("subnet_access"),
        "token_version": row.get("token_version", 0),
        "must_change_password": bool(row.get("must_change_password")),
    }
    audit("LOGIN", "auth", detail)
