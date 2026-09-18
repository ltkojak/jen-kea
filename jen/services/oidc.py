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

import json
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


def _groups_from_claims(claims: dict, claim_name: str) -> set[str]:
    """role_claim/subnet grouping both read the same claim shape: a list
    claim, or a space-separated string claim (both are real-world IdP
    shapes)."""
    raw = claims.get(claim_name)
    if raw is None:
        return set()
    if isinstance(raw, str):
        return set(raw.split())
    return {str(g) for g in raw}


def map_role(claims: dict) -> str | None:
    """Highest of superadmin > admin > viewer among the groups this
    token's role_claim actually carries. Falls back to OIDC_DEFAULT_ROLE
    when nothing matches; "none" (or an unmapped, non-matching claim
    with default_role="none") returns None, which the caller treats as
    "deny this login"."""
    group_set = _groups_from_claims(claims, extensions.OIDC_ROLE_CLAIM)

    role_map = parse_role_map(extensions.OIDC_ROLE_MAP)
    for role in _ROLES_BY_RANK:
        if group_set & set(role_map.get(role, [])):
            return role

    default = extensions.OIDC_DEFAULT_ROLE
    return None if default == "none" else default


def parse_subnet_map(raw: str) -> dict[str, set[int] | str]:
    """`"group1:1,2;group2:*"` -> `{"group1": {1, 2}, "group2": "*"}`.
    Same forgiving-on-typo behavior as parse_role_map(): a malformed
    segment (no ':', an empty group name, or a value list with no valid
    subnet id and not exactly '*') is skipped rather than raised — a
    config typo must not turn into a 500 on every login."""
    out: dict[str, set[int] | str] = {}
    for segment in (raw or "").split(";"):
        segment = segment.strip()
        if not segment or ":" not in segment:
            continue
        group, _, values_raw = segment.partition(":")
        group = group.strip()
        values_raw = values_raw.strip()
        if not group:
            continue
        if values_raw == "*":
            out[group] = "*"
            continue
        ids = {int(v) for v in values_raw.split(",") if v.strip().isdigit()}
        if ids:
            out[group] = ids
    return out


def map_subnet_access(claims: dict) -> str | None:
    """The `users.subnet_access` value (None = all subnets, else a JSON
    array string — same convention as jen/routes/users.py's
    set_user_subnets()) this login's groups resolve to under
    `[oidc] subnet_map`, applied on every OIDC login AFTER map_role().

    No subnet_map configured at all -> None (unrestricted), unchanged
    from pre-Q47 behavior — this feature is opt-in and must never
    silently narrow an existing SSO deployment's access. Once a map IS
    configured: any matching group mapped to '*' wins outright (None,
    unrestricted); otherwise the allowed set is the union over every
    matching group; a login whose groups match nothing in the map gets
    an empty set (all_subnets False, sees nothing) unless
    `[oidc] subnet_map_default = all` says to fall back to
    unrestricted for that case specifically."""
    raw = extensions.OIDC_SUBNET_MAP
    if not (raw or "").strip():
        return None

    subnet_map = parse_subnet_map(raw)
    groups = _groups_from_claims(claims, extensions.OIDC_ROLE_CLAIM)

    if any(subnet_map.get(g) == "*" for g in groups):
        return None

    union: set[int] = set()
    matched = False
    for g in groups:
        value = subnet_map.get(g)
        if value is None:
            continue
        matched = True
        if isinstance(value, set):
            union |= value

    if not matched:
        return None if extensions.OIDC_SUBNET_MAP_DEFAULT == "all" else json.dumps([])

    return json.dumps(sorted(union))


def external_id_for(user_id: int) -> str | None:
    """v5.28.0 (Q24, D1) — the `sub` this account was created/linked
    against, for the step-up reauth callback to compare a fresh token's
    `sub` against. None for a local account or a nonexistent id."""
    from jen.models.db import jen_db

    with jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT external_id FROM users WHERE id=%s AND auth_provider='oidc'", (user_id,))
        row = cur.fetchone()
    return row["external_id"] if row else None


def is_oidc_user(user_id: int) -> bool:
    """True if this account is IdP-managed. `User` (jen/models/user.py)
    doesn't carry auth_provider as an attribute — the handful of call
    sites that need it (MFA enrollment, the Users-page edit form) ask
    here rather than widening every User(...) construction for one
    rarely-needed field."""
    from jen.models.db import jen_db

    with jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT auth_provider FROM users WHERE id=%s", (user_id,))
        row = cur.fetchone()
    return bool(row) and row["auth_provider"] == "oidc"


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
            subnet_access = map_subnet_access(claims)
            if subnet_access != row.get("subnet_access"):
                cur.execute("UPDATE users SET subnet_access=%s WHERE id=%s", (subnet_access, row["id"]))
                audit("OIDC_SUBNET_SCOPE", row["username"], f"{row.get('subnet_access')} -> {subnet_access}")
                row["subnet_access"] = subnet_access
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
        subnet_access = map_subnet_access(claims)
        cur.execute(
            "INSERT INTO users (username, password, role, auth_provider, external_id, must_change_password, "
            "subnet_access) VALUES (%s, %s, %s, 'oidc', %s, 0, %s)",
            (username, random_password, role, sub, subnet_access),
        )
        new_id = cur.lastrowid
        audit("oidc_create", username, f"role={role} sub={sub} subnet_access={subnet_access or 'all'}")

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
