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
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def __get_jen_db():
    from jen.models.db import get_jen_db
    return get_jen_db()

def __jen_db_ctx():
    from jen.models.db import jen_db
    return jen_db()

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
        return user.role in ("superadmin", "admin")
    if mode == "required_all":
        return True
    return False

def user_has_mfa(user_id):
    try:
        with __jen_db_ctx() as db:
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM mfa_methods WHERE user_id=%s AND enabled=1", (user_id,))
                totp = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM webauthn_credentials WHERE user_id=%s", (user_id,))
                passkeys = cur.fetchone()["cnt"]
        return (totp + passkeys) > 0
    except Exception:
        return False

def generate_backup_codes(user_id):
    """Generate 8 single-use backup codes."""
    import secrets
    codes = [secrets.token_hex(4).upper() + "-" + secrets.token_hex(4).upper() for _ in range(8)]
    try:
        with __jen_db_ctx() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=%s", (user_id,))
                for code in codes:
                    cur.execute("INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES (%s, %s)",
                               (user_id, hashlib.sha256(code.encode()).hexdigest()))
            db.commit()
    except Exception as e:
        logger.error(f"Backup code generation error: {e}")
    return codes

def verify_backup_code(user_id, code):
    code_hash = hashlib.sha256(code.strip().upper().encode()).hexdigest()
    try:
        with __jen_db_ctx() as db:
            with db.cursor() as cur:
                cur.execute("SELECT id FROM mfa_backup_codes WHERE user_id=%s AND code_hash=%s AND used=0",
                           (user_id, code_hash))
                row = cur.fetchone()
                if row:
                    cur.execute("UPDATE mfa_backup_codes SET used=1, used_at=NOW() WHERE id=%s", (row["id"],))
                    db.commit()
                    return True
        return False
    except Exception:
        return False

def verify_totp(user_id, code):
    try:
        import pyotp
        with __jen_db_ctx() as db:
            with db.cursor() as cur:
                cur.execute("SELECT secret FROM mfa_methods WHERE user_id=%s AND method_type='totp' AND enabled=1",
                           (user_id,))
                row = cur.fetchone()
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
        with __jen_db_ctx() as db:
            with db.cursor() as cur:
                cur.execute("""
                    SELECT id, device_name, user_agent FROM mfa_trusted_devices
                    WHERE user_id=%s AND token_hash=%s
                    AND (expires_at IS NULL OR expires_at > NOW())
                """, (user_id, token_hash))
                row = cur.fetchone()
        if row:
            # Capture request data NOW — the thread must not touch `request`.
            # werkzeug 2.1+ UserAgent is always falsy (no built-in parsing) — read header directly (v4.3.3)
            ua = request.headers.get("User-Agent", "")
            ip = request.remote_addr or ""
            if not ua:
                # Diagnostic (v4.3.1): some requests arrive without a UA header
                # and previously froze healed names at "Unknown device".
                logger.warning(
                    f"Trusted-device check from {ip} with no User-Agent header; "
                    f"headers present: {sorted(k for k, _ in request.headers)}"
                )
            name = row.get("device_name") or ""
            stored_ua = row.get("user_agent") or ""
            # Self-heal: empty, containing "Unknown", or a raw UA dump anywhere.
            needs_heal = (not name.strip()
                          or "unknown" in name.lower()
                          or "Mozilla/" in name)
            new_name = None
            if needs_heal:
                from jen.services.fingerprint import describe_client_device
                # Prefer the live UA; fall back to the stored one so rows can
                # heal even from UA-less requests.
                heal_ua = ua or stored_ua
                candidate = describe_client_device(ip, heal_ua)
                # Never replace an existing name with a worse one.
                if "unknown" not in candidate.lower() or not name.strip():
                    new_name = candidate
            # Only persist a UA when we actually have one — an empty live UA
            # must not clobber a previously stored good value.
            persist_ua = ua or stored_ua
            # Update last_used (and healed metadata) async — don't block login
            import threading
            def _update(rid, healed_name, cur_ip, cur_ua):
                try:
                    with __jen_db_ctx() as db2:
                        with db2.cursor() as cur2:
                            if healed_name:
                                cur2.execute("""
                                    UPDATE mfa_trusted_devices
                                    SET last_used=NOW(), device_name=%s,
                                        ip_address=%s, user_agent=%s
                                    WHERE id=%s
                                """, (healed_name, cur_ip, cur_ua, rid))
                            else:
                                cur2.execute(
                                    "UPDATE mfa_trusted_devices SET last_used=NOW(), ip_address=%s WHERE id=%s",
                                    (cur_ip, rid))
                        db2.commit()
                except Exception:
                    pass
            threading.Thread(target=_update, args=(row["id"], new_name, ip, persist_ua), daemon=True).start()
        return bool(row)
    except Exception:
        return False

def create_trusted_device_token(user_id, remember_days, device_name="Unknown Device",
                                ip_address=None, user_agent=None):
    import secrets
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = None
    if remember_days and remember_days != "forever" and int(remember_days) > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=int(remember_days))).strftime('%Y-%m-%d %H:%M:%S')
    try:
        with __jen_db_ctx() as db:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO mfa_trusted_devices
                        (user_id, token_hash, device_name, expires_at, ip_address, user_agent)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (user_id, token_hash, device_name, expires_at, ip_address, user_agent))
            db.commit()
    except Exception as e:
        logger.error(f"Trusted device error: {e}")
    return token

