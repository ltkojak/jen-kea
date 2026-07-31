"""
jen/models/user.py
──────────────────
Flask-Login User model, password hashing, and global settings helpers.
"""

import hashlib
import json
import logging

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)


class User(UserMixin):
    def __init__(self, id, username, role, session_timeout=None, subnet_access=None):
        self.id              = id
        self.username        = username
        self.role            = role
        self.session_timeout = session_timeout
        # subnet_access: None = all subnets; list of int subnet_ids = restricted
        if subnet_access is None:
            self._subnet_access = None
        elif isinstance(subnet_access, str):
            try:
                self._subnet_access = json.loads(subnet_access)
            except Exception:
                self._subnet_access = None
        else:
            self._subnet_access = subnet_access

    def get_id(self):
        return str(self.id)

    # ── Role helpers ──────────────────────────────────────────────────────────

    @property
    def is_superadmin(self):
        return self.role == "superadmin"

    @property
    def is_admin_or_above(self):
        """True for superadmin and admin — can make changes."""
        return self.role in ("superadmin", "admin")

    @property
    def is_viewer(self):
        return self.role == "viewer"

    # ── Subnet access helpers ─────────────────────────────────────────────────

    @property
    def all_subnets(self):
        """True if this user can see all subnets (superadmin or unrestricted)."""
        return self.is_superadmin or self._subnet_access is None

    def can_access_subnet(self, subnet_id: int) -> bool:
        """Return True if this user has access to the given subnet_id."""
        if self.all_subnets:
            return True
        return int(subnet_id) in [int(s) for s in (self._subnet_access or [])]

    def filter_subnet_map(self, subnet_map: dict) -> dict:
        """Return a filtered copy of SUBNET_MAP containing only accessible subnets."""
        if self.all_subnets:
            return subnet_map
        return {k: v for k, v in subnet_map.items() if self.can_access_subnet(k)}

    def accessible_subnet_ids(self, subnet_map: dict) -> list:
        """Return list of accessible subnet_ids from the given map."""
        return list(self.filter_subnet_map(subnet_map).keys())

    @property
    def subnet_access_list(self):
        """Return the raw subnet_access list, or None for all subnets."""
        return self._subnet_access


def hash_password(p: str) -> str:
    """
    Hash a password using pbkdf2:sha256 with 260,000 iterations.

    Iteration count is explicitly pinned rather than using werkzeug's default
    because werkzeug 3.x raised the default from 260,000 to 1,000,000, making
    login take 2-3 seconds on typical homelab hardware. 260,000 meets the NIST
    SP 800-132 minimum and keeps login sub-200ms.

    check_password_hash reads parameters from the stored hash, so existing
    hashes at any iteration count continue to verify correctly.
    """
    return generate_password_hash(p, method="pbkdf2:sha256:260000")


def verify_password(stored_hash: str, provided_password: str) -> bool:
    """
    Verify a password against a stored hash.
    Supports:
      - pbkdf2:sha256 hashes at any iteration count (werkzeug 2.x and 3.x)
      - Legacy plain SHA-256 hex hashes (pre-2.5.2)
    check_password_hash reads cost parameters from the stored hash, so
    hashes at any iteration count verify correctly without migration.
    """
    if stored_hash and stored_hash.startswith("pbkdf2:"):
        return check_password_hash(stored_hash, provided_password)
    # Legacy SHA-256 — accept and flag for upgrade
    return stored_hash == hashlib.sha256(provided_password.encode()).hexdigest()


def needs_rehash(stored_hash: str) -> bool:
    """
    Return True if the stored hash should be upgraded to 260K iterations.
    Parses the iteration count directly from the hash string rather than
    relying on werkzeug's check_needs_rehash (not available in all versions).
    """
    if not stored_hash or not stored_hash.startswith("pbkdf2:sha256:"):
        return False
    try:
        # Hash format: pbkdf2:sha256:ITERATIONS$salt$hash
        iterations = int(stored_hash.split(":")[2].split("$")[0])
        return iterations != 260000
    except (IndexError, ValueError):
        return False


_settings_cache: dict = {}
_settings_cache_ts: float = 0
_SETTINGS_CACHE_TTL: float = 30.0  # seconds


def _invalidate_settings_cache() -> None:
    """Call after any set_global_setting to flush the cache immediately."""
    global _settings_cache_ts
    _settings_cache_ts = 0


def get_global_setting(key: str, default=None):
    """
    Read a value from the settings table.
    Results are cached for 30 seconds to avoid a DB round trip on every
    request — check_session_timeout in before_request calls this twice
    per page load otherwise.
    """
    import time
    global _settings_cache, _settings_cache_ts
    now = time.time()
    if now - _settings_cache_ts > _SETTINGS_CACHE_TTL:
        # Cache expired — reload all settings in one query
        from jen.models.db import jen_db
        try:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT setting_key, setting_value FROM settings")
                    _settings_cache = {r["setting_key"]: r["setting_value"]
                                       for r in cur.fetchall()}
            _settings_cache_ts = now
        except Exception as e:
            logger.error(f"get_global_setting cache reload: {e}")
            return default
    return _settings_cache.get(key, default)


def set_global_setting(key: str, value: str) -> None:
    """Upsert a value in the settings table and invalidate the cache."""
    from jen.models.db import jen_db
    try:
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO settings (setting_key, setting_value)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE setting_value=%s
                """, (key, value, value))
            db.commit()
        _invalidate_settings_cache()
    except Exception as e:
        logger.error(f"set_global_setting({key}): {e}")


def audit(action: str, entity: str, details: str = "") -> None:
    """
    Write an entry to the audit log asynchronously.
    Runs in a background thread so it never blocks the HTTP response.
    """
    from flask import request
    from flask_login import current_user
    import threading

    # Capture request context values now, before the thread runs
    try:
        user_id  = current_user.id       if current_user.is_authenticated else None
        username = current_user.username if current_user.is_authenticated else "system"
        ip       = request.remote_addr   if request else None
    except Exception:
        user_id, username, ip = None, "system", None

    def _write():
        from jen.models.db import jen_db
        try:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("""
                        INSERT INTO audit_log (user_id, username, action, entity, details, ip_address)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (user_id, username, action, entity, details, ip))
                db.commit()
        except Exception as e:
            logger.error(f"audit({action}, {entity}): {e}")

    threading.Thread(target=_write, daemon=True).start()
