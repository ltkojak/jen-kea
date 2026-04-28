"""
jen/services/mfa.py
───────────────────
TOTP multi-factor authentication helpers: enrollment, verification,
backup codes, trusted devices.
"""

import hashlib
import logging
import secrets
import time

logger = logging.getLogger(__name__)


def __get_jen_db():
    from jen.models.db import get_jen_db
    return get_jen_db()

def __get_global_setting(key, default=None):
    from jen.models.user import get_global_setting
    return get_global_setting(key, default)

def get_mfa_mode():
    return __get_global_setting("mfa_mode", "off")  # off, optional, required_admins, required_all

def user_needs_mfa(user):
    mode = get_mfa_mode()
    if mode == "off":
        return False
    if mode == "optional":
        return False  # user chooses to enroll
    if mode == "required_admins":
        return user.role == "admin"
    if mode == "required_all":
        return True
    return False

def user_has_mfa(user_id):
    try:
        db = __get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM mfa_methods WHERE user_id=%s AND enabled=1", (user_id,))
            totp = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM webauthn_credentials WHERE user_id=%s", (user_id,))
            passkeys = cur.fetchone()["cnt"]
        db.close()
        return (totp + passkeys) > 0
    except Exception:
        return False

def generate_backup_codes(user_id):
    """Generate 8 single-use backup codes."""
    import secrets
    codes = [secrets.token_hex(4).upper() + "-" + secrets.token_hex(4).upper() for _ in range(8)]
    try:
        db = __get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=%s", (user_id,))
            for code in codes:
                cur.execute("INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES (%s, %s)",
                           (user_id, hashlib.sha256(code.encode()).hexdigest()))
        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"Backup code generation error: {e}")
    return codes

def verify_backup_code(user_id, code):
    code_hash = hashlib.sha256(code.strip().upper().encode()).hexdigest()
    try:
        db = __get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id FROM mfa_backup_codes WHERE user_id=%s AND code_hash=%s AND used=0",
                       (user_id, code_hash))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE mfa_backup_codes SET used=1, used_at=NOW() WHERE id=%s", (row["id"],))
                db.commit()
                db.close()
                return True
        db.close()
        return False
    except Exception:
        return False

def verify_totp(user_id, code):
    try:
        import pyotp
        db = __get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT secret FROM mfa_methods WHERE user_id=%s AND method_type='totp' AND enabled=1",
                       (user_id,))
            row = cur.fetchone()
        db.close()
        if not row:
            return False
        totp = pyotp.TOTP(row["secret"])
        return totp.verify(code.strip(), valid_window=1)
    except Exception as e:
        logger.error(f"TOTP verify error: {e}")
        return False

def get_trusted_device_token(request):
    return request.cookies.get("jen_trusted")

def is_trusted_device(user_id, request):
    token = get_trusted_device_token(request)
    if not token:
        return False
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        db = __get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT id FROM mfa_trusted_devices
                WHERE user_id=%s AND token_hash=%s
                AND (expires_at IS NULL OR expires_at > NOW())
            """, (user_id, token_hash))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE mfa_trusted_devices SET last_used=NOW() WHERE id=%s", (row["id"],))
                db.commit()
        db.close()
        return bool(row)
    except Exception:
        return False

def create_trusted_device_token(user_id, remember_days, device_name="Unknown Device"):
    import secrets
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = None
    if remember_days and int(remember_days) > 0 and remember_days != "forever":
        from datetime import timedelta
        expires_at = (datetime.now(timezone.utc) + timedelta(days=int(remember_days))).strftime('%Y-%m-%d %H:%M:%S')
    try:
        db = __get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO mfa_trusted_devices (user_id, token_hash, device_name, expires_at)
                VALUES (%s, %s, %s, %s)
            """, (user_id, token_hash, device_name, expires_at))
        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"Trusted device error: {e}")
    return token

