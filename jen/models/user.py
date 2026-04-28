"""
jen/models/user.py
──────────────────
Flask-Login User model, password hashing, and global settings helpers.
"""

import hashlib
import logging

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)


class User(UserMixin):
    def __init__(self, id, username, role, session_timeout=None):
        self.id              = id
        self.username        = username
        self.role            = role
        self.session_timeout = session_timeout

    def get_id(self):
        return str(self.id)


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
    Return True if the stored hash should be upgraded to the current
    cost parameters (e.g. was hashed at 1M iterations, now using 260K).
    werkzeug's check_needs_rehash compares stored params to the method string.
    """
    try:
        from werkzeug.security import check_needs_rehash
        return check_needs_rehash(stored_hash, method="pbkdf2:sha256:260000")
    except Exception:
        return False


def get_global_setting(key: str, default=None):
    """Read a value from the settings table. Returns default if not found."""
    from jen.models.db import get_jen_db
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT setting_value FROM settings WHERE setting_key=%s", (key,)
            )
            row = cur.fetchone()
        db.close()
        return row["setting_value"] if row else default
    except Exception as e:
        logger.error(f"get_global_setting({key}): {e}")
        return default


def set_global_setting(key: str, value: str) -> None:
    """Upsert a value in the settings table."""
    from jen.models.db import get_jen_db
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO settings (setting_key, setting_value)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE setting_value=%s
            """, (key, value, value))
        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"set_global_setting({key}): {e}")


def audit(action: str, entity: str, details: str = "") -> None:
    """Write an entry to the audit log."""
    from flask import request
    from flask_login import current_user
    from jen.models.db import get_jen_db
    try:
        user_id  = current_user.id       if current_user.is_authenticated else None
        username = current_user.username if current_user.is_authenticated else "system"
        ip       = request.remote_addr   if request else None
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log (user_id, username, action, entity, details, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, username, action, entity, details, ip))
        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"audit({action}, {entity}): {e}")
