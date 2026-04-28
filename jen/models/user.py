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
    """Hash a password using werkzeug pbkdf2-sha256 (salted, iterated)."""
    return generate_password_hash(p, method="pbkdf2:sha256")


def verify_password(stored_hash: str, provided_password: str) -> bool:
    """
    Verify a password against a stored hash.
    Supports both legacy plain SHA-256 (hex) hashes and new pbkdf2 hashes
    so existing users are migrated transparently on next login.
    """
    if stored_hash and stored_hash.startswith("pbkdf2:"):
        return check_password_hash(stored_hash, provided_password)
    # Legacy SHA-256 — accept and flag for upgrade
    return stored_hash == hashlib.sha256(provided_password.encode()).hexdigest()


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
