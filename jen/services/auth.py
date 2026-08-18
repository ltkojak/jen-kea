"""
jen/services/auth.py
────────────────────
Input validation helpers and login rate-limiting functions.
"""

import ipaddress
import logging
import re

from jen import extensions

logger = logging.getLogger(__name__)

# ── Compiled validation patterns ──────────────────────────────────────────────
MAC_RE  = re.compile(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$')
HOST_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
                     r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')


def __get_jen_db():
    from jen.models.db import get_jen_db
    return get_jen_db()

def __jen_db_ctx():
    from jen.models.db import jen_db
    return jen_db()

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


# ── SSH / remote-command target validation (v4.4.2) ───────────────────────────
# These guard every value that ends up interpolated into a command string
# executed on a *remote* shell over `ssh user@host "command"` — the local
# subprocess.run() call itself is always list-args (safe), but the remote
# side re-parses that command string through its own shell, so anything
# placed there needs to be validated first. Used for: the DDNS log path,
# the free-text DNS lookup host a user can submit, and the configured SSH
# host/user themselves (also guards against a host value like "-oProxyCommand=..."
# being read as an ssh flag rather than a target).
UNIX_USERNAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
SAFE_REMOTE_PATH_RE = re.compile(r'^/[A-Za-z0-9_./-]+$')

def valid_ssh_target(value):
    """A hostname or IP, and not something that could be parsed as an ssh flag."""
    value = (value or "").strip()
    if not value or value.startswith("-"):
        return False
    return valid_hostname(value) or valid_ip(value)

def valid_unix_username(value):
    value = (value or "").strip()
    return bool(UNIX_USERNAME_RE.match(value))

def valid_remote_path(value):
    """Absolute path, no shell metacharacters, whitespace, or quotes."""
    value = (value or "").strip()
    return bool(SAFE_REMOTE_PATH_RE.match(value))

def valid_dns_lookup_host(value):
    """What a user is allowed to type into the DDNS 'look up this host' box."""
    value = (value or "").strip()
    if not value or len(value) > 253:
        return False
    return valid_hostname(value) or valid_ip(value)


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
            with __jen_db_ctx() as db:
                with db.cursor() as cur:
                    cur.execute("INSERT INTO login_attempts (ip_address, username) VALUES (%s, %s)", (ip, username))
                    cur.execute("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)")
                db.commit()
        except Exception as e:
            logger.error(f"Rate limit record error: {e}")
    threading.Thread(target=_record, daemon=True).start()

def clear_login_attempts(ip, username):
    """Fire-and-forget — don't block the login response."""
    import threading
    def _clear():
        try:
            with __jen_db_ctx() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM login_attempts WHERE ip_address=%s OR username=%s", (ip, username))
                db.commit()
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
        with __jen_db_ctx() as db:
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
                    return True, remaining_mins
        return False, 0
    except Exception as e:
        logger.error(f"Rate limit check error: {e}")
        return False, 0

# ─────────────────────────────────────────
# MFA rate limiting
# ─────────────────────────────────────────
# Fixed (not admin-configurable) — the post-password TOTP/backup-code step
# had no throttling at all before v4.4.2. Deliberately separate from the
# rl_* password-login settings above: an admin turning password rate
# limiting off (or making it permanent) must not affect this, and this
# must never be a permanent lockout since it would let an attacker lock
# a legitimate user out indefinitely just by submitting bad codes.
MFA_MAX_ATTEMPTS = 10
MFA_LOCKOUT_MINUTES = 15

def record_mfa_attempt(user_id):
    """Fire-and-forget — don't block the response."""
    import threading
    def _record():
        try:
            with __jen_db_ctx() as db:
                with db.cursor() as cur:
                    cur.execute("INSERT INTO mfa_attempts (user_id) VALUES (%s)", (user_id,))
                    cur.execute("DELETE FROM mfa_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)")
                db.commit()
        except Exception as e:
            logger.error(f"MFA rate limit record error: {e}")
    threading.Thread(target=_record, daemon=True).start()

def clear_mfa_attempts(user_id):
    """Fire-and-forget — don't block the response."""
    import threading
    def _clear():
        try:
            with __jen_db_ctx() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM mfa_attempts WHERE user_id=%s", (user_id,))
                db.commit()
        except Exception as e:
            logger.error(f"MFA rate limit clear error: {e}")
    threading.Thread(target=_clear, daemon=True).start()

def is_mfa_locked_out(user_id):
    """Returns (locked: bool, remaining_minutes: int). Always a timed
    lockout — never permanent (see MFA_LOCKOUT_MINUTES note above)."""
    try:
        with __jen_db_ctx() as db:
            with db.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) as cnt FROM mfa_attempts "
                    "WHERE user_id=%s AND attempted_at >= DATE_SUB(NOW(), INTERVAL %s MINUTE)",
                    (user_id, MFA_LOCKOUT_MINUTES)
                )
                count = cur.fetchone()["cnt"]
                if count >= MFA_MAX_ATTEMPTS:
                    cur.execute(
                        "SELECT CEIL(%s - TIMESTAMPDIFF(SECOND, MIN(attempted_at), NOW()) / 60) as remaining "
                        "FROM mfa_attempts WHERE user_id=%s AND attempted_at >= DATE_SUB(NOW(), INTERVAL %s MINUTE)",
                        (MFA_LOCKOUT_MINUTES * 60, user_id, MFA_LOCKOUT_MINUTES)
                    )
                    row = cur.fetchone()
                    remaining = max(1, int(row["remaining"] or 1)) if row else MFA_LOCKOUT_MINUTES
                    return True, remaining
        return False, 0
    except Exception as e:
        logger.error(f"MFA rate limit check error: {e}")
        return False, 0


# ─────────────────────────────────────────
# MFA Engine
# ─────────────────────────────────────────


def ssh_cli_opts() -> list:
    """v4.4.8 — shared SSH option list for every plain `ssh` CLI subprocess
    call in the app (ddns.py, servers.py). Previously each call site had
    its own copy of these flags, and two of the three used
    StrictHostKeyChecking=no with no UserKnownHostsFile at all — meaning
    every single connection silently trusted whatever host key was
    presented, with nothing ever persisted to compare against on a later
    connection. accept-new is the middle ground: still zero setup
    friction on first connect (same UX as before), but a host key that
    *changes* after being recorded will now cause the connection to be
    refused instead of silently accepted, which is the actual MITM
    protection StrictHostKeyChecking exists for.
    """
    import os
    os.makedirs(os.path.dirname(extensions.SSH_KNOWN_HOSTS), exist_ok=True)
    return [
        "-i", extensions.SSH_KEY_PATH,
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={extensions.SSH_KNOWN_HOSTS}",
    ]


def paramiko_load_known_hosts(ssh_client) -> None:
    """v4.4.8 — pair with paramiko.AutoAddPolicy() so a first connection
    to a new host is still accepted automatically (same UX as before),
    but the accepted key is persisted to extensions.SSH_KNOWN_HOSTS and
    checked on every later connection — previously nothing was ever
    loaded or saved, so AutoAddPolicy trusted a fresh key on literally
    every single call, with no memory between connections at all.

    v5.1.9 — a failure here must not be swallowed. If the known_hosts
    file can't be loaded (corruption, permissions, disk error), silently
    continuing means AutoAddPolicy treats every previously-pinned host as
    brand new and re-trusts whatever key is presented — quietly
    disabling host-key verification. Raise instead, so the caller's
    existing SSH try/except surfaces this as a real connection failure
    that gets fixed rather than a warning nobody sees."""
    import os
    os.makedirs(os.path.dirname(extensions.SSH_KNOWN_HOSTS), exist_ok=True)
    if not os.path.exists(extensions.SSH_KNOWN_HOSTS):
        open(extensions.SSH_KNOWN_HOSTS, "a").close()
    try:
        ssh_client.load_host_keys(extensions.SSH_KNOWN_HOSTS)
    except Exception as e:
        raise RuntimeError(
            f"Could not load SSH known_hosts file ({extensions.SSH_KNOWN_HOSTS}); "
            f"refusing to connect without host-key verification: {e}"
        ) from e
