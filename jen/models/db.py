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
                    logger.info("Jen DB connection pool initialised")
                except Exception as e:
                    logger.error(f"Failed to create Jen DB pool: {e}")
                    # Fall back to direct connection if dbutils unavailable
                    return pymysql.connect(
                        host=extensions.JEN_DB_HOST,
                        user=extensions.JEN_DB_USER,
                        password=extensions.JEN_DB_PASS,
                        database=extensions.JEN_DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor,
                        connect_timeout=10,
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
                    logger.info("Kea DB connection pool initialised")
                except Exception as e:
                    logger.error(f"Failed to create Kea DB pool: {e}")
                    return pymysql.connect(
                        host=extensions.KEA_DB_HOST,
                        user=extensions.KEA_DB_USER,
                        password=extensions.KEA_DB_PASS,
                        database=extensions.KEA_DB_NAME,
                        cursorclass=pymysql.cursors.DictCursor,
                        connect_timeout=10,
                    )
    return _kea_pool.connection()


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
    Create all Jen tables if they don't exist and run any pending
    migrations. Called once at startup by the app factory.
    """
    from jen.models.user import hash_password   # local import avoids circular

    os.makedirs("/etc/jen/ssl",  exist_ok=True)
    os.makedirs("/etc/jen/ssh",  exist_ok=True)
    os.makedirs(extensions.STATIC_DIR, exist_ok=True)

    db = get_jen_db()
    try:
        with db.cursor() as cur:
            # ── Core tables ────────────────────────────────────────────────
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password VARCHAR(512) NOT NULL,
                    role ENUM('admin','viewer') NOT NULL DEFAULT 'viewer',
                    session_timeout INT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("SHOW COLUMNS FROM users LIKE 'avatar_url'")
            if not cur.fetchone():
                cur.execute("ALTER TABLE users ADD COLUMN avatar_url MEDIUMTEXT DEFAULT NULL")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    username VARCHAR(100),
                    action VARCHAR(50),
                    entity VARCHAR(100),
                    details TEXT,
                    ip_address VARCHAR(45),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_created (created_at)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reservation_notes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    host_id INT UNIQUE NOT NULL,
                    notes TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    setting_key VARCHAR(100) PRIMARY KEY,
                    setting_value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    mac VARCHAR(17) UNIQUE NOT NULL,
                    device_name VARCHAR(200) DEFAULT NULL,
                    owner VARCHAR(200) DEFAULT NULL,
                    notes TEXT DEFAULT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    last_ip VARCHAR(45) DEFAULT NULL,
                    last_hostname VARCHAR(253) DEFAULT NULL,
                    last_subnet_id INT DEFAULT NULL,
                    manufacturer VARCHAR(100) DEFAULT NULL,
                    device_type VARCHAR(30) DEFAULT NULL,
                    device_icon VARCHAR(10) DEFAULT NULL,
                    manufacturer_override VARCHAR(100) DEFAULT NULL,
                    device_type_override VARCHAR(30) DEFAULT NULL,
                    device_icon_override VARCHAR(50) DEFAULT NULL,
                    INDEX idx_mac (mac),
                    INDEX idx_last_seen (last_seen)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS subnet_notes (
                    subnet_id INT PRIMARY KEY,
                    notes TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS mfa_methods (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    method_type VARCHAR(20) NOT NULL,
                    secret TEXT,
                    name VARCHAR(100) DEFAULT 'Authenticator',
                    enabled TINYINT(1) DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP NULL,
                    INDEX idx_user (user_id),
                    UNIQUE KEY unique_user_method (user_id, method_type, name)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS mfa_backup_codes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    code_hash VARCHAR(64) NOT NULL,
                    used TINYINT(1) DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    used_at TIMESTAMP NULL,
                    INDEX idx_user (user_id)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS mfa_trusted_devices (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    token_hash VARCHAR(64) NOT NULL,
                    device_name VARCHAR(200),
                    expires_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user (user_id),
                    INDEX idx_token (token_hash)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS saved_searches (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    name VARCHAR(100) NOT NULL,
                    page VARCHAR(50) NOT NULL,
                    params TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_prefs (
                    user_id INT PRIMARY KEY,
                    widgets TEXT NOT NULL DEFAULT '["subnet_stats","recent_leases"]',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS webauthn_credentials (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    credential_id TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    sign_count INT DEFAULT 0,
                    name VARCHAR(100) DEFAULT 'Passkey',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP NULL,
                    INDEX idx_user (user_id)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS lease_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    subnet_id INT NOT NULL,
                    snapshot_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active_leases INT DEFAULT 0,
                    dynamic_leases INT DEFAULT 0,
                    reserved_leases INT DEFAULT 0,
                    pool_size INT DEFAULT 0,
                    INDEX idx_subnet_time (subnet_id, snapshot_time),
                    INDEX idx_time (snapshot_time)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alert_channels (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    channel_type VARCHAR(20) NOT NULL,
                    channel_name VARCHAR(100) NOT NULL,
                    enabled TINYINT(1) DEFAULT 0,
                    config JSON,
                    alert_types JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_channel (channel_type, channel_name)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alert_templates (
                    alert_type VARCHAR(50) PRIMARY KEY,
                    template_text TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alert_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    channel_type VARCHAR(20),
                    alert_type VARCHAR(50),
                    message TEXT,
                    status VARCHAR(20),
                    error TEXT,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_sent (sent_at)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45),
                    username VARCHAR(100),
                    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_ip (ip_address),
                    INDEX idx_username (username),
                    INDEX idx_attempted (attempted_at)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    key_hash VARCHAR(64) NOT NULL UNIQUE,
                    key_prefix VARCHAR(8) NOT NULL,
                    created_by INT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP NULL,
                    active TINYINT(1) DEFAULT 1,
                    INDEX idx_hash (key_hash)
                )
            """)

            # ── Default admin user ─────────────────────────────────────────
            cur.execute("SELECT COUNT(*) as cnt FROM users")
            if cur.fetchone()["cnt"] == 0:
                cur.execute(
                    "INSERT INTO users (username, password, role) VALUES (%s, %s, 'admin')",
                    ("admin", hash_password("admin"))
                )
                print("Created default admin user: admin / admin")

        # ── Migrations ─────────────────────────────────────────────────────
        with db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM devices LIKE 'manufacturer'")
            if not cur.fetchone():
                cur.execute("ALTER TABLE devices ADD COLUMN manufacturer VARCHAR(100) DEFAULT NULL")
                cur.execute("ALTER TABLE devices ADD COLUMN device_type VARCHAR(30) DEFAULT NULL")
                cur.execute("ALTER TABLE devices ADD COLUMN device_icon VARCHAR(10) DEFAULT NULL")
                db.commit()
                logger.info("Migration: added manufacturer columns to devices")

            cur.execute("SHOW COLUMNS FROM devices LIKE 'manufacturer_override'")
            if not cur.fetchone():
                cur.execute("ALTER TABLE devices ADD COLUMN manufacturer_override VARCHAR(100) DEFAULT NULL")
                cur.execute("ALTER TABLE devices ADD COLUMN device_type_override VARCHAR(30) DEFAULT NULL")
                cur.execute("ALTER TABLE devices ADD COLUMN device_icon_override VARCHAR(50) DEFAULT NULL")
                db.commit()
                logger.info("Migration: added override columns to devices")
            else:
                cur.execute("SHOW COLUMNS FROM devices LIKE 'device_icon_override'")
                col = cur.fetchone()
                if col and "varchar(10)" in str(col.get("Type", "")).lower():
                    cur.execute("ALTER TABLE devices MODIFY COLUMN device_icon_override VARCHAR(50) DEFAULT NULL")
                    db.commit()

        # ── Migrate legacy Telegram settings ───────────────────────────────
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM alert_channels WHERE channel_type='telegram'")
            if cur.fetchone()["cnt"] == 0:
                cur.execute("""
                    SELECT setting_key, setting_value FROM settings
                    WHERE setting_key IN
                    ('telegram_token','telegram_chat_id','telegram_enabled',
                     'alert_kea_down','alert_new_lease','alert_utilization')
                """)
                old = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}
                token   = old.get("telegram_token", "")
                chat_id = old.get("telegram_chat_id", "")
                if token and chat_id:
                    enabled = 1 if old.get("telegram_enabled") == "true" else 0
                    alert_types = []
                    if old.get("alert_kea_down",    "true")  == "true": alert_types += ["kea_down", "kea_up"]
                    if old.get("alert_new_lease",   "false") == "true": alert_types.append("new_lease")
                    if old.get("alert_utilization", "true")  == "true": alert_types.append("utilization_high")
                    cur.execute("""
                        INSERT INTO alert_channels
                            (channel_type, channel_name, enabled, config, alert_types)
                        VALUES ('telegram', 'Telegram', %s, %s, %s)
                    """, (enabled,
                          json.dumps({"token": token, "chat_id": chat_id}),
                          json.dumps(alert_types)))
                    print("Migrated legacy Telegram settings to alert_channels table.")

        # ── Migration: widen password column for werkzeug 3.x scrypt hashes ─
        with db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM users LIKE 'password'")
            col = cur.fetchone()
            if col and 'varchar(256)' in str(col.get('Type', '')).lower():
                cur.execute(
                    "ALTER TABLE users MODIFY COLUMN password VARCHAR(512) NOT NULL"
                )
                db.commit()
                logger.info("Migration: widened users.password to VARCHAR(512)")

        db.commit()
    finally:
        db.close()
