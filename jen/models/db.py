"""
jen/models/db.py
────────────────
Database connection helpers and schema initialisation.

Connection pooling via dbutils.pooled_db.PooledDB keeps a small number of
TCP connections open permanently so requests reuse existing connections
instead of paying the ~1s TCP + MySQL handshake cost on every request.

Pool is initialised lazily on first use so startup doesn't block if the
DB is temporarily unavailable.
"""

import json
import logging
import os
import threading
from contextlib import contextmanager

import pymysql
import pymysql.cursors

from jen import extensions

logger = logging.getLogger(__name__)

# ── Connection pools ──────────────────────────────────────────────────────────
# Initialised once on first use. Thread-safe — PooledDB handles locking.

_jen_pool  = None
_kea_pool  = None
_pool_lock = threading.Lock()

_POOL_MIN  = 2   # connections kept open permanently
_POOL_MAX  = 10  # maximum concurrent connections


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
        creator      = pymysql,
        mincached    = _POOL_MIN,
        maxcached    = _POOL_MAX,
        maxconnections = _POOL_MAX,
        blocking     = True,          # wait for a connection rather than raise
        ping         = 1,             # ping before use to detect stale connections
        host         = extensions.JEN_DB_HOST,
        user         = extensions.JEN_DB_USER,
        password     = extensions.JEN_DB_PASS,
        database     = extensions.JEN_DB_NAME,
        cursorclass  = pymysql.cursors.DictCursor,
        connect_timeout = 10,
        charset      = "utf8mb4",
        **_ssl_kwargs(extensions.JEN_DB_SSL_CA),
    )


def _make_kea_pool():
    """Create the Kea DB connection pool."""
    from dbutils.pooled_db import PooledDB
    return PooledDB(
        creator      = pymysql,
        mincached    = _POOL_MIN,
        maxcached    = _POOL_MAX,
        maxconnections = _POOL_MAX,
        blocking     = True,
        ping         = 1,
        host         = extensions.KEA_DB_HOST,
        user         = extensions.KEA_DB_USER,
        password     = extensions.KEA_DB_PASS,
        database     = extensions.KEA_DB_NAME,
        cursorclass  = pymysql.cursors.DictCursor,
        connect_timeout = 10,
        charset      = "utf8mb4",
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
        with _pool_lock:
            if _jen_pool is None:           # double-checked locking
                try:
                    _jen_pool = _make_jen_pool()
                    logger.info("Jen DB connection pool initialised (dbutils)")
                except Exception as e:
                    logger.warning(f"Jen DB pool failed, using direct connections: {e}")
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
        with _pool_lock:
            if _kea_pool is None:
                try:
                    _kea_pool = _make_kea_pool()
                    logger.info("Kea DB connection pool initialised (dbutils)")
                except Exception as e:
                    logger.warning(f"Kea DB pool failed, using direct connections: {e}")
                    return pymysql.connect(
                        host=extensions.KEA_DB_HOST,
                        user=extensions.KEA_DB_USER,
                        password=extensions.KEA_DB_PASS,
                        database=extensions.KEA_DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor,
                        connect_timeout=10,
                        **_ssl_kwargs(extensions.KEA_DB_SSL_CA),
                    )
    return _kea_pool.connection()


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
# Explicit db.commit() calls inside the block remain valid and are honoured
# immediately; the final commit on clean exit is then a harmless no-op.

@contextmanager
def jen_db():
    """Yield a pooled Jen DB connection; commit/rollback/return automatically."""
    db = get_jen_db()
    try:
        yield db
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
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
        try:
            db.rollback()
        except Exception:
            pass
        raise
    finally:
        db.close()


def reset_pools() -> None:
    """
    Tear down and recreate both connection pools.
    Called after config changes that update DB credentials or host.
    """
    global _jen_pool, _kea_pool
    with _pool_lock:
        if _jen_pool is not None:
            try: _jen_pool._idle_cache.clear()
            except Exception: pass
            _jen_pool = None
        if _kea_pool is not None:
            try: _kea_pool._idle_cache.clear()
            except Exception: pass
            _kea_pool = None
    logger.info("DB connection pools reset")


def init_jen_db() -> None:
    """
    Initialise the Jen database: run all pending schema migrations,
    then seed the default admin account if no users exist.
    Called once at startup by the app factory.

    Schema is owned by jen/models/migrations.py (v4.2.0) — do NOT add
    CREATE TABLE or ALTER statements here; append a new numbered
    migration instead.
    """
    from jen.models.user import hash_password       # local import avoids circular
    from jen.models.migrations import run_migrations

    os.makedirs("/etc/jen/ssl",  exist_ok=True)
    os.makedirs("/etc/jen/ssh",  exist_ok=True)
    os.makedirs(extensions.STATIC_DIR, exist_ok=True)

    run_migrations()

    # ── Default admin user (runtime seed, not a migration) ────────────────
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM users")
            if cur.fetchone()["cnt"] == 0:
                cur.execute(
                    "INSERT INTO users (username, password, role) VALUES (%s, %s, 'superadmin')",
                    ("admin", hash_password("admin"))
                )
                print("Created default superadmin user: admin / admin")
        db.commit()
