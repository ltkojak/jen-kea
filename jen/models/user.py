"""
jen/models/user.py
──────────────────
Flask-Login User model, password hashing, and global settings helpers.
"""

import hashlib
import json
import logging
import secrets
import threading

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)


class User(UserMixin):
    def __init__(self, id, username, role, session_timeout=None, subnet_access=None, must_change_password=False):
        self.id = id
        self.username = username
        self.role = role
        self.session_timeout = session_timeout
        self.must_change_password = bool(must_change_password)
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


# werkzeug 3.1's own default. n=2**15, r=8, p=1 → ~32 MB and ~50-100ms
# per hash on homelab hardware: memory-hard (unlike pbkdf2, which a GPU
# chews through), still fast enough for interactive login. The transient
# 32 MB is per in-flight hash — at the default 8 worker threads a burst
# of simultaneous logins costs ~256 MB briefly, freed the moment each
# hash returns.
_SCRYPT_METHOD = "scrypt:32768:8:1"


def password_fingerprint(password_hash) -> str:
    """A short, one-way tag of a stored password hash (v5.69.0-beta.2, Q171). A login's cached session carries it; `load_user` compares it with the row on every request, so a
    session opened before a password was changed ends on its next request. It reveals nothing: it is the first 16 hex digits of SHA-256 over a salted scrypt hash, and "" for an
    account with no usable password (a row the caller did not read the password of)."""
    if not password_hash:
        return ""
    return hashlib.sha256(str(password_hash).encode("utf-8")).hexdigest()[:16]


def hash_password(p: str) -> str:
    """
    Hash a password with scrypt (werkzeug's current default KDF), pinned
    to explicit cost parameters so a future werkzeug default change is a
    deliberate `needs_rehash()` bump here, not a silent one.

    History: Jen used pbkdf2:sha256:260000 through v5.6.x — pbkdf2 because
    that was werkzeug 2.x's default, pinned at 260k because werkzeug 3.x
    raised its default to 1,000,000 (2-3s logins). v5.7.0 moves new and
    re-hashed passwords to scrypt for its memory-hardness; existing pbkdf2
    hashes keep verifying and are upgraded on next login (see needs_rehash).
    """
    return generate_password_hash(p, method=_SCRYPT_METHOD)


def verify_password(stored_hash: str, provided_password: str) -> bool:
    """
    Verify a password against a stored hash.
    Supports:
      - scrypt hashes (v5.7.0+ default)
      - pbkdf2:sha256 hashes at any iteration count (v2.x-v5.6.x, werkzeug 2.x/3.x)
      - Legacy plain SHA-256 hex hashes (pre-2.5.2)
    check_password_hash reads the algorithm and cost parameters from the
    stored hash itself, so every format above verifies without migration.
    """
    if stored_hash and stored_hash.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_hash, provided_password)
    # Legacy SHA-256 — accept and flag for upgrade. Constant-time compare:
    # this is a straight string equality check, not a proper KDF, so it's
    # the one comparison here that's actually timing-attackable.
    if not stored_hash:
        return False
    computed = hashlib.sha256(provided_password.encode()).hexdigest()
    return secrets.compare_digest(stored_hash, computed)


def needs_rehash(stored_hash: str) -> bool:
    """
    Return True if the stored hash should be re-generated with the current
    scheme (`_SCRYPT_METHOD`) on the next successful login. Parses the hash
    string directly rather than relying on werkzeug's check_needs_rehash
    (not available in all versions).

    - Any `pbkdf2:*` hash          → True  (v5.7.0 moved off pbkdf2)
    - `scrypt:*` at other params   → True
    - `scrypt:32768:8:1`           → False (already current)
    - anything else / empty        → False (legacy SHA-256 is handled by
                                     the caller's own not-a-KDF check)
    """
    if not stored_hash:
        return False
    if stored_hash.startswith("pbkdf2:"):
        return True
    if stored_hash.startswith("scrypt:"):
        # Hash format: scrypt:N:r:p$salt$hash
        return stored_hash.split("$", 1)[0] != _SCRYPT_METHOD
    return False


_settings_cache: dict = {}
_settings_cache_ts: float = 0
_settings_next_try_mono: float = 0  # earliest MONOTONIC time a FAILED reload is attempted again (v5.68.0-beta.23, Q158: set from the clock AFTER the failure)
_settings_ever_loaded: bool = False  # has the cache EVER been read from the database in this process?
_settings_refresh_lock = threading.Lock()  # v5.68.0-beta.22 (Q157): one reload at a time
_SETTINGS_CACHE_TTL: float = 30.0  # seconds
#: v5.68.0-beta.21 (Q156): after a failed reload the next one waits this long. A failed reload used to leave the cache timestamp alone, so the very next
#: call reloaded again - and with the Jen database down each attempt costs a pool creation (10 s) and a direct connect (10 s): `check_session_timeout`
#: on every request and ~4 reads per subnet per alert-loop pass made a pass take minutes and the 5 s kea_down cadence was lost.
_SETTINGS_RETRY_S: float = 5.0
#: v5.69.0-beta.3 (Q172): bumped by every invalidation. A reload remembers the version it started under; if a write invalidated the cache while its SELECT was in flight,
#: what it read may predate that write, so it does NOT stamp the cache fresh - the next read reloads (the write used to be hidden for a whole TTL: ipv6_enabled, the
#: investigation switch, the session timeout).
_settings_version: int = 0


def _invalidate_settings_cache() -> None:
    """Call after any set_global_setting to flush the cache immediately."""
    global _settings_cache_ts, _settings_next_try_mono, _settings_version
    _settings_version += 1
    _settings_cache_ts = 0
    _settings_next_try_mono = 0


def settings_ever_loaded() -> bool:
    """True once the settings table has been read successfully in this process. False means `get_global_setting` has only ever returned its default
    (the Jen database was unreachable) - a caller that must not act on a default (the daily summary's "already sent today?") asks first."""
    return _settings_ever_loaded


STALE_DEVICE_DAYS_DEFAULT = 30


def get_stale_device_days() -> int:
    """`stale_device_days` as a positive integer, or the default of 30 when the stored value is not one (v5.69.0-beta.5, Q174). Three readers did `int(get_global_setting(...))`
    on their own - the Devices page and the Reservations page outside any `try`, so one corrupt row in the settings table was a 500 for both lists; the alert loop inside one
    whose handler skipped the stale, drift, snapshot and summary work of every cycle. A table edit is the only way to store a bad value; this makes it harmless."""
    try:
        days = int(get_global_setting("stale_device_days", str(STALE_DEVICE_DAYS_DEFAULT)))
    except (TypeError, ValueError):
        return STALE_DEVICE_DAYS_DEFAULT
    return days if days > 0 else STALE_DEVICE_DAYS_DEFAULT


def get_global_setting(key: str, default=None, strict: bool = False):
    """
    Read a value from the settings table.
    Results are cached for 30 seconds to avoid a DB round trip on every
    request — check_session_timeout in before_request calls this twice
    per page load otherwise.

    `strict=True` (v5.69.0-beta.19, Q188): read THIS key from the table, bypassing the cache, and RAISE when the table cannot be read - a caller that must not turn "the database is
    down" into "nothing is recorded" (Health's row for unproved recoveries) asks this way. The cold-start default and the stale cache are exactly what it must not return.
    """
    import time

    if strict:
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT setting_value FROM settings WHERE setting_key = %s", (key,))
            row = cur.fetchone()
        if row is None:
            return default
        return row["setting_value"] if isinstance(row, dict) else row[0]

    global _settings_cache, _settings_cache_ts, _settings_next_try_mono, _settings_ever_loaded
    now = time.time()
    # Cache expired - ONE thread reloads (v5.68.0-beta.22, Q157). `_settings_next_try` moved only after a reload FAILED, so N threads that saw
    # an expired cache all reloaded: with the database down and `check_session_timeout` on every request, a burst of requests was a burst of
    # 10 s connects. The holder reloads; everyone else returns the stale cache at once (`default` only when nothing was ever read - and then
    # they wait for the holder, once, and re-check: a first load is not a place to hand out defaults).
    #
    # v5.68.0-beta.23 (Q158): the cooldown is counted from the END of the failed attempt, on a monotonic clock. beta.22 set `now + _SETTINGS_RETRY_S`
    # from the reading taken BEFORE the connect: a failing connect that took 12 s (a 10 s timeout plus a pool creation) put the deadline 7 s in the PAST,
    # and the threads that had waited behind the holder on a cold start (blocking acquire while nothing was ever loaded) re-checked against it and each
    # connected again. A waiter now takes a fresh reading under the lock and, inside the cooldown, returns what it has (`default` on a cold start).
    if (
        now - _settings_cache_ts > _SETTINGS_CACHE_TTL
        and time.monotonic() >= _settings_next_try_mono
        and _settings_refresh_lock.acquire(blocking=not _settings_ever_loaded)
    ):
        try:
            now = time.time()
            if now - _settings_cache_ts > _SETTINGS_CACHE_TTL and time.monotonic() >= _settings_next_try_mono:
                from jen.models.db import jen_db

                started_under = _settings_version
                try:
                    with jen_db() as db, db.cursor() as cur:
                        cur.execute("SELECT setting_key, setting_value FROM settings")
                        _settings_cache = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}
                    # a write that landed while the SELECT was in flight invalidated the cache: what was read may predate it, so it is served but not stamped fresh
                    _settings_cache_ts = now if started_under == _settings_version else 0
                    _settings_next_try_mono = 0
                    _settings_ever_loaded = True
                except Exception as e:
                    # keep serving what was last read and do not try again for _SETTINGS_RETRY_S after THIS failure ended
                    _settings_next_try_mono = time.monotonic() + _SETTINGS_RETRY_S
                    logger.error(f"get_global_setting cache reload: {e}")
        finally:
            _settings_refresh_lock.release()
    return _settings_cache.get(key, default)


def set_global_setting(key: str, value: str) -> bool:
    """Upsert a value in the settings table and invalidate the cache. True when it was written, False when it was not (logged): the caller that
    records a FACT with it (`daily_summary_sent`, an alert's delivery state) can say whether it is stored (v5.68.0-beta.22, Q157)."""
    from jen.models.db import jen_db

    try:
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO settings (setting_key, setting_value)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE setting_value=%s
                """,
                    (key, value, value),
                )
            db.commit()
        _invalidate_settings_cache()
        return True
    except Exception as e:
        logger.error(f"set_global_setting({key}): {e}")
        return False


def update_global_setting(key: str, mutate) -> bool:
    """Read-modify-write ONE settings row as a locked transaction (v5.69.0-beta.19, Q188, AD5). Two workers doing `get_global_setting` then `set_global_setting` on the same row each read the
    old value and the second write erased the first's change (two incidents recorded at once kept one). Here one connection: the row is created with `INSERT IGNORE` (so two FIRST writers lock
    the same row), `SELECT ... FOR UPDATE` reads it under the lock, `mutate(current: str) -> str | None` returns the new value (None: leave it), one UPDATE, commit. The settings cache is
    invalidated on success. Returns True when the row now holds what `mutate` returned (or `mutate` asked for no change); False - logged, never raised - when it could not be written, so the
    caller never reports as done what is not."""
    from jen.models.db import jen_db

    # (second pass, Q188: `INSERT IGNORE` on a row that EXISTS takes a shared lock on the duplicate record, and two transactions that both hold it and then ask for the exclusive lock of
    # `SELECT ... FOR UPDATE` deadlock - one loses its update. So the row is created in its OWN autocommitted statement first, and the transaction that follows only ever takes the exclusive lock.
    # A deadlock or lock-wait timeout that still happens is retried, because the loser rolled back and nothing was written.)
    last: Exception | None = None
    for _attempt in range(3):
        try:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES (%s, %s)", (key, ""))
                db.commit()  # the row exists now, and no lock on it is held
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT setting_value FROM settings WHERE setting_key = %s FOR UPDATE", (key,))
                    row = cur.fetchone()
                    current = (row["setting_value"] if isinstance(row, dict) else row[0]) if row is not None else ""
                    new = mutate(current or "")
                    if new is not None and new != current:
                        cur.execute("UPDATE settings SET setting_value = %s WHERE setting_key = %s", (new, key))
                db.commit()
            _invalidate_settings_cache()
            return True
        except Exception as e:
            last = e
            code = e.args[0] if getattr(e, "args", None) and isinstance(e.args[0], int) else None
            if code in (1213, 1205):  # deadlock victim / lock wait timeout: nothing was written
                continue
            break
    # the class and, for a database error, its code - never the message: a transaction refused because the stored value is not what its caller expects (Q189, AE3) must not
    # print that value, and a database message can carry the row
    code = last.args[0] if last is not None and getattr(last, "args", None) and isinstance(last.args[0], int) else None
    logger.error(f"update_global_setting({key}): {type(last).__name__}" + (f" (error {code})" if code else ""))
    return False


def audit(action: str, entity: str, details: str = "") -> None:
    """
    Write an entry to the audit log.

    v5.17.0 (Q6 6F) — synchronous. The old fire-and-forget thread meant a
    security-relevant event (LOGIN, LOGOUT, REAUTH, ADMIN_RESET_MFA, …)
    could still be in flight — or lost to an error nobody saw — when the
    response returned, and a test that checks "was this audited?" needed a
    sleep. A single INSERT is cheap; block on it.
    """
    user_id, username, ip = _audit_identity()

    from jen.models.db import jen_db

    try:
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO audit_log (user_id, username, action, entity, details, ip_address)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """,
                    (user_id, username, action, entity, details, ip),
                )
            db.commit()
    except Exception as e:
        logger.error(f"audit({action}, {entity}): {e}")


def _audit_identity() -> tuple:
    """(user id, username, ip) of whoever the current request is, the way `audit()` has always resolved them; ("system" and no ip) outside a request."""
    from flask import request
    from flask_login import current_user

    try:
        user_id = current_user.id if current_user.is_authenticated else None
        username = current_user.username if current_user.is_authenticated else "system"
        ip = request.remote_addr if request else None
    except Exception:
        user_id, username, ip = None, "system", None
    return user_id, username, ip


def set_global_setting_and_audit(key: str, value: str, action: str, entity: str, details: str = "") -> bool:
    """Write a setting AND its audit row in ONE transaction (v5.68.0-beta.27, Q162, item 3). `set_global_setting` then `audit()` are two commits, and `audit()`
    logs and returns on failure: a decision that is only worth making if it is on record (the acknowledgement of an unreadable investigation record) could be
    committed with no durable record of who asserted what. Here one connection carries both statements; any exception rolls BOTH back, is logged, and the
    answer is False. True means the setting is stored AND the audit row is written. The settings cache is invalidated on success."""
    user_id, username, ip = _audit_identity()

    from jen.models.db import jen_db

    try:
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO settings (setting_key, setting_value)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE setting_value=%s
                """,
                    (key, value, value),
                )
                cur.execute(
                    """
                    INSERT INTO audit_log (user_id, username, action, entity, details, ip_address)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """,
                    (user_id, username, action, entity, details, ip),
                )
            db.commit()
        _invalidate_settings_cache()
        return True
    except Exception as e:
        logger.error(f"set_global_setting_and_audit({key}, {action}): {e}")
        return False
