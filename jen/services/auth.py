"""
jen/services/auth.py
────────────────────
Input validation helpers and login rate-limiting functions.
"""

import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

# ── Compiled validation patterns ──────────────────────────────────────────────
MAC_RE  = re.compile(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$')
HOST_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
                     r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')


def __get_jen_db():
    from jen.models.db import get_jen_db
    return get_jen_db()

def __get_global_setting(key, default=None):
    from jen.models.user import get_global_setting
    return get_global_setting(key, default)

def valid_ip(ip):
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

def valid_mac(mac):
    return bool(MAC_RE.match(mac.strip()))

def valid_hostname(hostname):
    if not hostname:
        return True  # optional
    return len(hostname) <= 253 and bool(HOST_RE.match(hostname))

def valid_cidr(cidr):
    try:
        ipaddress.ip_network(cidr.strip(), strict=False)
        return True
    except ValueError:
        return False

def valid_pool(pool):
    """Validate pool format: x.x.x.x-y.y.y.y"""
    if not pool:
        return True  # optional
    parts = pool.strip().split("-")
    if len(parts) != 2:
        return False
    return valid_ip(parts[0]) and valid_ip(parts[1])

def valid_dns(dns):
    """Validate comma-separated IP list"""
    if not dns:
        return True  # optional
    return all(valid_ip(ip.strip()) for ip in dns.split(","))

def valid_positive_int(val):
    try:
        return int(val) > 0
    except (ValueError, TypeError):
        return False

def sanitize_search(search):
    """Strip characters that could cause SQL issues"""
    return re.sub(r'[^\w\s\.\:\-]', '', search)[:100]


# ─────────────────────────────────────────
# Rate limiting
# ─────────────────────────────────────────
def get_rate_limit_settings():
    return {
        "max_attempts": int(__get_global_setting("rl_max_attempts", "10")),
        "lockout_minutes": int(__get_global_setting("rl_lockout_minutes", "15")),
        "mode": __get_global_setting("rl_mode", "both"),  # ip, username, both, off
    }

def record_login_attempt(ip, username):
    """Fire-and-forget — don't block the response."""
    import threading
    def _record():
        try:
            db = __get_jen_db()
            with db.cursor() as cur:
                cur.execute("INSERT INTO login_attempts (ip_address, username) VALUES (%s, %s)", (ip, username))
                cur.execute("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)")
            db.commit()
            db.close()
        except Exception as e:
            logger.error(f"Rate limit record error: {e}")
    threading.Thread(target=_record, daemon=True).start()

def clear_login_attempts(ip, username):
    """Fire-and-forget — don't block the login response."""
    import threading
    def _clear():
        try:
            db = __get_jen_db()
            with db.cursor() as cur:
                cur.execute("DELETE FROM login_attempts WHERE ip_address=%s OR username=%s", (ip, username))
            db.commit()
            db.close()
        except Exception as e:
            logger.error(f"Rate limit clear error: {e}")
    threading.Thread(target=_clear, daemon=True).start()

def is_locked_out(ip, username):
    rl = get_rate_limit_settings()
    mode = rl["mode"]
    max_attempts = rl["max_attempts"]
    lockout_minutes = rl["lockout_minutes"]

    # Rate limiting disabled
    if mode == "off" or max_attempts == 0:
        return False, 0

    try:
        db = __get_jen_db()
        with db.cursor() as cur:
            # Rolling window: only count attempts within the lockout period.
            # This ensures old attempts don't contribute to new lockouts.
            # If lockout_minutes=0 (permanent lockout), use a 24h detection
            # window to find the triggering burst, then lock permanently.
            if lockout_minutes > 0:
                window = f"DATE_SUB(NOW(), INTERVAL {lockout_minutes} MINUTE)"
            else:
                window = "DATE_SUB(NOW(), INTERVAL 1440 MINUTE)"  # 24h rolling window

            count = 0
            if mode in ("ip", "both"):
                cur.execute(
                    f"SELECT COUNT(*) as cnt FROM login_attempts "
                    f"WHERE ip_address=%s AND attempted_at >= {window}", (ip,))
                count = max(count, cur.fetchone()["cnt"])
            if mode in ("username", "both"):
                cur.execute(
                    f"SELECT COUNT(*) as cnt FROM login_attempts "
                    f"WHERE username=%s AND attempted_at >= {window}", (username,))
                count = max(count, cur.fetchone()["cnt"])

            if count >= max_attempts:
                if lockout_minutes > 0:
                    # Calculate time remaining in the lockout window from
                    # the FIRST attempt in the current window, not the last.
                    # Lock expires when the oldest attempt in the window ages out.
                    field = "ip_address" if mode in ("ip", "both") else "username"
                    val = ip if mode in ("ip", "both") else username
                    cur.execute(f"""
                        SELECT CEIL(
                            ({lockout_minutes} * 60) -
                            TIMESTAMPDIFF(SECOND, MIN(attempted_at), NOW())
                        ) as remaining
                        FROM login_attempts
                        WHERE {field}=%s AND attempted_at >= {window}
                    """, (val,))
                    row = cur.fetchone()
                    remaining_secs = max(0, int(row["remaining"] or 0)) if row else 0
                    remaining_mins = max(1, (remaining_secs + 59) // 60)
                else:
                    remaining_mins = 999  # permanent until admin clears
                db.close()
                return True, remaining_mins
        db.close()
        return False, 0
    except Exception as e:
        logger.error(f"Rate limit check error: {e}")
        return False, 0

# ─────────────────────────────────────────
# MFA Engine
# ─────────────────────────────────────────
