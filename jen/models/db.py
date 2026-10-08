"""
jen/models/db.py
────────────────
Database connection helpers and schema initialization.

Connection pooling via dbutils.pooled_db.PooledDB keeps a small number of
TCP connections open permanently so requests reuse existing connections
instead of paying the ~1s TCP + MySQL handshake cost on every request.

Pool is initialized lazily on first use so startup doesn't block if the
DB is temporarily unavailable.
"""

import logging
import os
import threading
import time
from contextlib import contextmanager, suppress

import pymysql
import pymysql.cursors

from jen import extensions

logger = logging.getLogger(__name__)

# ── Connection pools ──────────────────────────────────────────────────────────
# Initialized once on first use. Thread-safe — PooledDB handles locking.

_jen_pool = None
_kea_pool = None
_pool_lock = threading.Lock()

_POOL_MIN = 2  # connections kept open permanently
_POOL_MAX = 10  # maximum concurrent connections

#: v5.68.0-beta.21 (Q156): a pool whose creation FAILED is not re-attempted for this long. `_make_jen_pool()` opens `mincached` connections with a 10 s
#: connect timeout, and a failed one left `_jen_pool` None, so with the database down EVERY call re-attempted it (10 s) and then a direct connect (10 s) -
#: up to 20 s per call, per settings read, per request. Within the window only the direct connect is tried (once per call).
_POOL_RETRY_S = 10.0
_pool_failed_at: dict = {}  # "jen" / "kea" -> time.monotonic() of the last failed pool creation


def _pool_recently_failed(name: str) -> bool:
    failed = _pool_failed_at.get(name)
    return failed is not None and time.monotonic() - failed < _POOL_RETRY_S


def _ssl_kwargs(ca_path: str) -> dict:
    """v4.4.5 — opt-in TLS for MySQL/MariaDB connections. Empty ca_path
    (the default) means no ssl= kwarg is passed at all, so this is a
    no-op for every existing install unless jen_db/ssl_ca or
    kea_db/ssl_ca is explicitly set in config. PyMySQL treats a
    present-but-empty ssl dict as "use TLS, verify against system CA
    store", so this always verifies rather than just encrypting blindly
    — set ssl_ca to the specific CA if MariaDB is using a self-signed
    cert, which is the common case for a homelab-issued cert."""
    if not ca_path:
        return {}
    return {"ssl": {"ca": ca_path}}


def _make_jen_pool():
    """Create the Jen DB connection pool."""
    from dbutils.pooled_db import PooledDB

    return PooledDB(
        creator=pymysql,
        mincached=_POOL_MIN,
        maxcached=_POOL_MAX,
        maxconnections=_POOL_MAX,
        blocking=True,  # wait for a connection rather than raise
        ping=1,  # ping before use to detect stale connections
        host=extensions.JEN_DB_HOST,
        user=extensions.JEN_DB_USER,
        password=extensions.JEN_DB_PASS,
        database=extensions.JEN_DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        charset="utf8mb4",
        **_ssl_kwargs(extensions.JEN_DB_SSL_CA),
    )


def _make_kea_pool():
    """Create the Kea DB connection pool."""
    from dbutils.pooled_db import PooledDB

    return PooledDB(
        creator=pymysql,
        mincached=_POOL_MIN,
        maxcached=_POOL_MAX,
        maxconnections=_POOL_MAX,
        blocking=True,
        ping=1,
        host=extensions.KEA_DB_HOST,
        port=extensions.KEA_DB_PORT,
        user=extensions.KEA_DB_USER,
        password=extensions.KEA_DB_PASS,
        database=extensions.KEA_DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        charset="utf8mb4",
        **_ssl_kwargs(extensions.KEA_DB_SSL_CA),
    )


def get_jen_db() -> pymysql.connections.Connection:
    """
    Return a pooled connection to the Jen database.
    On first call the pool is created and TCP connections are established.
    Subsequent calls return an already-open connection from the pool (~0ms).
    Caller must call db.close() to return the connection to the pool.
    """
    global _jen_pool
    if _jen_pool is None:
        direct = False
        with _pool_lock:
            if _jen_pool is None:  # double-checked locking
                if _pool_recently_failed("jen"):
                    direct = True
                else:
                    try:
                        _jen_pool = _make_jen_pool()
                        _pool_failed_at.pop("jen", None)
                        logger.info("Jen DB connection pool initialized (dbutils)")
                    except Exception as e:
                        _pool_failed_at["jen"] = time.monotonic()
                        logger.warning(f"Jen DB pool failed, using direct connections: {e}")
                        direct = True
        if direct:
            # outside the lock: a direct connect that hangs must not queue every other caller behind it
            return pymysql.connect(
                host=extensions.JEN_DB_HOST,
                user=extensions.JEN_DB_USER,
                password=extensions.JEN_DB_PASS,
                database=extensions.JEN_DB_NAME,
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=10,
                **_ssl_kwargs(extensions.JEN_DB_SSL_CA),
            )
    return _jen_pool.connection()


def get_kea_db() -> pymysql.connections.Connection:
    """
    Return a pooled connection to the Kea database.
    Falls back to a direct connection if the pool is unavailable.
    """
    global _kea_pool
    if _kea_pool is None:
        direct = False
        with _pool_lock:
            if _kea_pool is None:
                if _pool_recently_failed("kea"):
                    direct = True
                else:
                    try:
                        _kea_pool = _make_kea_pool()
                        _pool_failed_at.pop("kea", None)
                        logger.info("Kea DB connection pool initialized (dbutils)")
                    except Exception as e:
                        _pool_failed_at["kea"] = time.monotonic()
                        logger.warning(f"Kea DB pool failed, using direct connections: {e}")
                        direct = True
        if direct:
            return pymysql.connect(
                host=extensions.KEA_DB_HOST,
                port=extensions.KEA_DB_PORT,
                user=extensions.KEA_DB_USER,
                password=extensions.KEA_DB_PASS,
                database=extensions.KEA_DB_NAME,
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=10,
                **_ssl_kwargs(extensions.KEA_DB_SSL_CA),
            )
    return _kea_pool.connection()


# ── Kea6 DB (v5.0 Phase 1) ──────────────────────────────────────────────────
# lease6/hosts/ipv6_reservations can live in the same MySQL database as
# lease4/hosts (the common case — [kea6_db] falls back to [kea_db] at
# config-load time, so extensions.KEA6_DB_HOST already equals
# extensions.KEA_DB_HOST when [kea6_db] is absent) or a genuinely separate
# database, since Kea itself supports both. Rather than always opening a
# second pool to what's frequently the identical host/db, _kea6_targets_same_db()
# detects the common case and reuses the existing kea_pool — a real second
# pool is only created when the v6 connection info actually differs.

_kea6_pool = None


def _kea6_targets_same_db() -> bool:
    """True when [kea6_db] is absent/identical to [kea_db] — the common
    case per Phase 0 research (theelders would run both on one server)."""
    return (
        extensions.KEA6_DB_HOST == extensions.KEA_DB_HOST
        and extensions.KEA6_DB_PORT == extensions.KEA_DB_PORT
        and extensions.KEA6_DB_USER == extensions.KEA_DB_USER
        and extensions.KEA6_DB_PASS == extensions.KEA_DB_PASS
        and extensions.KEA6_DB_NAME == extensions.KEA_DB_NAME
    )


def _make_kea6_pool():
    """Create a distinct Kea6 DB connection pool — only called when the v6
    connection info genuinely differs from v4's (see _kea6_targets_same_db)."""
    from dbutils.pooled_db import PooledDB

    return PooledDB(
        creator=pymysql,
        mincached=_POOL_MIN,
        maxcached=_POOL_MAX,
        maxconnections=_POOL_MAX,
        blocking=True,
        ping=1,
        host=extensions.KEA6_DB_HOST,
        port=extensions.KEA6_DB_PORT,
        user=extensions.KEA6_DB_USER,
        password=extensions.KEA6_DB_PASS,
        database=extensions.KEA6_DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
        charset="utf8mb4",
        **_ssl_kwargs(extensions.KEA6_DB_SSL_CA),
    )


def get_kea6_db() -> pymysql.connections.Connection:
    """
    Return a pooled connection for reading lease6/hosts/ipv6_reservations.
    Reuses get_kea_db()'s pool when v6 targets the same database as v4
    (the common case) rather than opening a redundant second pool to the
    identical host; only creates jen's own kea6_pool when the connection
    info genuinely differs.
    """
    global _kea6_pool
    if _kea6_targets_same_db():
        return get_kea_db()
    if _kea6_pool is None:
        with _pool_lock:
            if _kea6_pool is None:
                try:
                    _kea6_pool = _make_kea6_pool()
                    logger.info("Kea6 DB connection pool initialized (dbutils)")
                except Exception as e:
                    logger.warning(f"Kea6 DB pool failed, using direct connections: {e}")
                    return pymysql.connect(
                        host=extensions.KEA6_DB_HOST,
                        port=extensions.KEA6_DB_PORT,
                        user=extensions.KEA6_DB_USER,
                        password=extensions.KEA6_DB_PASS,
                        database=extensions.KEA6_DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor,
                        connect_timeout=10,
                        **_ssl_kwargs(extensions.KEA6_DB_SSL_CA),
                    )
    return _kea6_pool.connection()


# ── Context managers (v4.1.0) ─────────────────────────────────────────────────
# Preferred way to use a connection. Guarantees the connection is returned
# to the pool on every path (early return, exception, or normal exit),
# commits on clean exit, and rolls back on exception so a failed request
# can never leave a half-applied transaction on a pooled connection.
#
#     with jen_db() as db:
#         with db.cursor() as cur:
#             cur.execute(...)
#
# Explicit db.commit() calls inside the block remain valid and are honored
# immediately; the final commit on clean exit is then a harmless no-op.


@contextmanager
def jen_db():
    """Yield a pooled Jen DB connection; commit/rollback/return automatically."""
    db = get_jen_db()
    try:
        yield db
        db.commit()
    except Exception:
        with suppress(Exception):
            db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def kea_db():
    """Yield a pooled Kea DB connection; commit/rollback/return automatically."""
    db = get_kea_db()
    try:
        yield db
        db.commit()
    except Exception:
        with suppress(Exception):
            db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def kea6_db():
    """
    Yield a pooled connection for reading lease6/hosts/ipv6_reservations —
    v5.0 Phase 1. Same commit/rollback/return guarantees as jen_db()/kea_db().
    Jen never writes through this connection (it doesn't own those tables,
    same as lease4 today), but the same transactional discipline applies
    regardless.
    """
    db = get_kea6_db()
    try:
        yield db
        db.commit()
    except Exception:
        with suppress(Exception):
            db.rollback()
        raise
    finally:
        db.close()


def _drop_pool(pool) -> None:
    """Close a pool's idle connections (PooledDB.close()), falling back to forgetting them. The
    original reset only cleared `_idle_cache`, which drops the references without closing the
    sockets — the server saw them idle until its own timeout."""
    with suppress(Exception):
        pool.close()
        return
    with suppress(Exception):
        pool._idle_cache.clear()


def reset_kea_pools() -> None:
    """Tear down the Kea (and Kea6) pools only, so the next kea_db()/kea6_db() dials whatever
    extensions.KEA_DB_* / KEA6_DB_* now say — host, port, credentials and ssl_ca alike. v5.67.0-beta.8
    (Q120, item g) — the setup wizard's Connect step saves new Kea database settings through
    app_config.write_values(), which re-derives the extensions globals but does not touch a pool that
    already exists; a pool created while the config still held placeholders kept dialling them until a
    restart. Jen's own pool is left alone: this changes nothing about it."""
    global _kea_pool, _kea6_pool
    with _pool_lock:
        _pool_failed_at.pop("kea", None)  # the settings just changed: dial them now, not after the retry window
        if _kea_pool is not None:
            _drop_pool(_kea_pool)
            _kea_pool = None
        if _kea6_pool is not None:
            _drop_pool(_kea6_pool)
            _kea6_pool = None
    logger.info("Kea DB connection pools reset")


def reset_pools() -> None:
    """
    Tear down and recreate all connection pools (jen, kea, kea6).
    Called after config changes that update DB credentials or host.
    """
    global _jen_pool
    with _pool_lock:
        _pool_failed_at.pop("jen", None)
        if _jen_pool is not None:
            _drop_pool(_jen_pool)
            _jen_pool = None
    reset_kea_pools()
    logger.info("DB connection pools reset")


def init_jen_db() -> None:
    """
    Initialize the Jen database: run all pending schema migrations,
    then seed the default admin account if no users exist.
    Called once at startup by the app factory.

    Schema is owned by jen/models/migrations.py (v4.2.0) — do NOT add
    CREATE TABLE or ALTER statements here; append a new numbered
    migration instead.
    """
    import secrets

    from jen.models.migrations import run_migrations
    from jen.models.user import hash_password  # local import avoids circular

    os.makedirs(os.path.join(extensions.CONFIG_DIR, "ssl"), exist_ok=True)
    os.makedirs(os.path.join(extensions.CONFIG_DIR, "ssh"), exist_ok=True)
    os.makedirs(extensions.STATIC_DIR, exist_ok=True)

    run_migrations()

    # ── Default admin user (runtime seed, not a migration) ────────────────
    # JEN_INITIAL_ADMIN_PASSWORD (v5.6.0): the Docker install path can't run
    # install.sh's _set_admin_password() the way bare metal does, so it
    # passes the operator-chosen password through this env var for the
    # first-boot seed only. When it's set we seed with that password and
    # must_change_password=0 (they picked it deliberately). The env var is
    # only read here, at initial seed — it is never stored.
    #
    # v5.17.0 (Q6 6G) — with no env var, the seed no longer uses the
    # literal "admin". It generates a random token, forces a change on
    # first login, and writes the credential to
    # <CONTENT_DIR>/initial-admin-password (0600) as well as printing it
    # once. force_password_change() deletes that file on success.
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM users")
            if cur.fetchone()["cnt"] == 0:
                initial_pw = os.environ.get("JEN_INITIAL_ADMIN_PASSWORD", "").strip()
                if initial_pw:
                    cur.execute(
                        "INSERT INTO users (username, password, role, must_change_password) "
                        "VALUES ('admin', %s, 'superadmin', 0)",
                        (hash_password(initial_pw),),
                    )
                    print("Created superadmin 'admin' from JEN_INITIAL_ADMIN_PASSWORD.")
                else:
                    generated = secrets.token_urlsafe(12)
                    cur.execute(
                        "INSERT INTO users (username, password, role, must_change_password) "
                        "VALUES ('admin', %s, 'superadmin', 1)",
                        (hash_password(generated),),
                    )
                    _write_initial_admin_password(generated)
                    print(
                        f"Created superadmin 'admin' — initial password written to "
                        f"{os.path.join(extensions.CONTENT_DIR, 'initial-admin-password')} "
                        f"(also shown here once): {generated}\n"
                        f"You will be required to change it on first login."
                    )
        db.commit()


def _write_initial_admin_password(password: str) -> None:
    """v5.17.0 (Q6 6G) — drop the generated bootstrap credential at
    <CONTENT_DIR>/initial-admin-password, mode 0600. Best-effort: on a
    Docker/dev box where CONTENT_DIR isn't writable the printed line is
    still the fallback."""
    path = os.path.join(extensions.CONTENT_DIR, "initial-admin-password")
    try:
        os.makedirs(extensions.CONTENT_DIR, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, f"admin\n{password}\n".encode())
        finally:
            os.close(fd)
        os.chmod(path, 0o600)
    except OSError as e:
        logger.warning(f"could not write {path}: {e}")
