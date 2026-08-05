"""
jen/models/migrations.py
────────────────────────
Versioned schema migrations for the Jen database (v4.2.0).

Design
──────
- A `schema_migrations` table records every applied migration
  (version, description, applied_at).
- MIGRATIONS is an ordered registry of (version, description, fn).
  Each fn receives an open pooled connection and applies one migration.
- run_migrations() applies every unapplied migration in order and
  records it in the same transaction as the migration's data changes.
  On failure the exception propagates, the version is NOT recorded,
  and app startup aborts loudly — a half-migrated schema must never
  serve requests silently.

Rules for writing migrations (MySQL/MariaDB)
────────────────────────────────────────────
1. DDL auto-commits and cannot be rolled back. Every migration MUST
   therefore also be idempotent (CREATE TABLE IF NOT EXISTS, guarded
   ALTERs via SHOW COLUMNS) so that a crash between a DDL statement
   and the version INSERT recovers cleanly on the next startup.
2. Versions are integers, strictly increasing, never reused, never
   edited after release. New schema changes append a new version.
3. One-time data fixes belong here too (see migration 6) — that is
   the entire point: "runs exactly once" is now enforced by the
   version table instead of hoped-for by conditional guards.

Upgrade path
────────────
- Existing installs: their tables already exist, so the baseline and
  historical migrations no-op via their guards and are simply recorded.
- Fresh installs: the baseline creates the final current schema and
  the historical migrations no-op.
- Self-update flow: the service restart after an update runs pending
  migrations automatically at startup.
"""

import logging

logger = logging.getLogger(__name__)


def _column_missing(cur, table: str, column: str) -> bool:
    cur.execute(f"SHOW COLUMNS FROM {table} LIKE %s", (column,))
    return cur.fetchone() is None


def _column_type(cur, table: str, column: str) -> str:
    cur.execute(f"SHOW COLUMNS FROM {table} LIKE %s", (column,))
    row = cur.fetchone()
    return str(row.get("Type", "")).lower() if row else ""


# ── Migration 1: baseline schema (final current definitions) ─────────────────

_BASELINE_TABLES = [
    """CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(512) NOT NULL,
        role ENUM('superadmin','admin','viewer') NOT NULL DEFAULT 'viewer',
        subnet_access JSON DEFAULT NULL COMMENT 'NULL = all subnets; JSON array of subnet_ids = restricted',
        session_timeout INT DEFAULT NULL,
        avatar_url MEDIUMTEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS audit_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        username VARCHAR(100),
        action VARCHAR(50),
        entity VARCHAR(100),
        details TEXT,
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_created (created_at)
    )""",
    """CREATE TABLE IF NOT EXISTS reservation_notes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        host_id INT UNIQUE NOT NULL,
        notes TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS settings (
        setting_key VARCHAR(100) PRIMARY KEY,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS devices (
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
    )""",
    """CREATE TABLE IF NOT EXISTS subnet_notes (
        subnet_id INT PRIMARY KEY,
        notes TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS mfa_methods (
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
    )""",
    """CREATE TABLE IF NOT EXISTS mfa_backup_codes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        code_hash VARCHAR(64) NOT NULL,
        used TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        used_at TIMESTAMP NULL,
        INDEX idx_user (user_id)
    )""",
    """CREATE TABLE IF NOT EXISTS mfa_trusted_devices (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token_hash VARCHAR(64) NOT NULL,
        device_name VARCHAR(200),
        expires_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user (user_id),
        INDEX idx_token (token_hash)
    )""",
    """CREATE TABLE IF NOT EXISTS saved_searches (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(100) NOT NULL,
        page VARCHAR(50) NOT NULL,
        params TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS dashboard_prefs (
        user_id INT PRIMARY KEY,
        widgets TEXT NOT NULL DEFAULT '["subnet_stats","recent_leases"]',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        credential_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INT DEFAULT 0,
        name VARCHAR(100) DEFAULT 'Passkey',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP NULL,
        INDEX idx_user (user_id)
    )""",
    """CREATE TABLE IF NOT EXISTS lease_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        subnet_id INT NOT NULL,
        snapshot_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        active_leases INT DEFAULT 0,
        dynamic_leases INT DEFAULT 0,
        reserved_leases INT DEFAULT 0,
        pool_size INT DEFAULT 0,
        INDEX idx_subnet_time (subnet_id, snapshot_time),
        INDEX idx_time (snapshot_time)
    )""",
    """CREATE TABLE IF NOT EXISTS alert_channels (
        id INT AUTO_INCREMENT PRIMARY KEY,
        channel_type VARCHAR(20) NOT NULL,
        channel_name VARCHAR(100) NOT NULL,
        enabled TINYINT(1) DEFAULT 0,
        config JSON,
        alert_types JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_channel (channel_type, channel_name)
    )""",
    """CREATE TABLE IF NOT EXISTS alert_templates (
        alert_type VARCHAR(50) PRIMARY KEY,
        template_text TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS alert_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        channel_type VARCHAR(20),
        alert_type VARCHAR(50),
        message TEXT,
        status VARCHAR(20),
        error TEXT,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_sent (sent_at)
    )""",
    """CREATE TABLE IF NOT EXISTS login_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(45),
        username VARCHAR(100),
        attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_ip (ip_address),
        INDEX idx_username (username),
        INDEX idx_attempted (attempted_at)
    )""",
    """CREATE TABLE IF NOT EXISTS api_keys (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        key_hash VARCHAR(64) NOT NULL UNIQUE,
        key_prefix VARCHAR(8) NOT NULL,
        created_by INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP NULL,
        active TINYINT(1) DEFAULT 1,
        INDEX idx_hash (key_hash)
    )""",
    """CREATE TABLE IF NOT EXISTS plugins (
        id           VARCHAR(100) PRIMARY KEY,
        name         VARCHAR(200) NOT NULL,
        version      VARCHAR(50)  NOT NULL,
        description  TEXT,
        author       VARCHAR(200),
        requires_jen VARCHAR(50),
        installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        enabled      TINYINT(1) DEFAULT 1
    )""",
    """CREATE TABLE IF NOT EXISTS backup_schedule (
        id INT PRIMARY KEY DEFAULT 1,
        enabled TINYINT(1) DEFAULT 0,
        frequency ENUM('daily','weekly') DEFAULT 'daily',
        hour INT DEFAULT 2,
        keep_count INT DEFAULT 7,
        include_jen TINYINT(1) DEFAULT 1,
        include_kea TINYINT(1) DEFAULT 1,
        last_run DATETIME DEFAULT NULL,
        last_status VARCHAR(255) DEFAULT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS mfa_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user (user_id),
        INDEX idx_attempted (attempted_at)
    )""",
]


def _m001_baseline(db):
    """All tables with their final current definitions (no-op if present)."""
    with db.cursor() as cur:
        for ddl in _BASELINE_TABLES:
            cur.execute(ddl)


def _m002_users_avatar(db):
    """users.avatar_url for installs created before avatars existed."""
    with db.cursor() as cur:
        if _column_missing(cur, "users", "avatar_url"):
            cur.execute("ALTER TABLE users ADD COLUMN avatar_url MEDIUMTEXT DEFAULT NULL")


def _m003_devices_manufacturer(db):
    """devices manufacturer/type/icon columns (fingerprinting feature)."""
    with db.cursor() as cur:
        if _column_missing(cur, "devices", "manufacturer"):
            cur.execute("ALTER TABLE devices ADD COLUMN manufacturer VARCHAR(100) DEFAULT NULL")
            cur.execute("ALTER TABLE devices ADD COLUMN device_type VARCHAR(30) DEFAULT NULL")
            cur.execute("ALTER TABLE devices ADD COLUMN device_icon VARCHAR(10) DEFAULT NULL")


def _m004_devices_overrides(db):
    """devices override columns; widen device_icon_override to VARCHAR(50)."""
    with db.cursor() as cur:
        if _column_missing(cur, "devices", "manufacturer_override"):
            cur.execute("ALTER TABLE devices ADD COLUMN manufacturer_override VARCHAR(100) DEFAULT NULL")
            cur.execute("ALTER TABLE devices ADD COLUMN device_type_override VARCHAR(30) DEFAULT NULL")
            cur.execute("ALTER TABLE devices ADD COLUMN device_icon_override VARCHAR(50) DEFAULT NULL")
        elif "varchar(10)" in _column_type(cur, "devices", "device_icon_override"):
            cur.execute("ALTER TABLE devices MODIFY COLUMN device_icon_override VARCHAR(50) DEFAULT NULL")


def _m005_widen_password(db):
    """Widen users.password for werkzeug 3.x scrypt hashes."""
    import re
    with db.cursor() as cur:
        col_type = _column_type(cur, "users", "password")
        m = re.search(r"varchar\((\d+)\)", col_type)
        if (m and int(m.group(1)) < 512) or ("char" in col_type and "varchar" not in col_type):
            cur.execute("ALTER TABLE users MODIFY COLUMN password VARCHAR(512) NOT NULL")


def _m006_superadmin_role(db):
    """
    3.5.0 RBAC migration, now correctly one-time AND correctly scoped:
    expand role ENUM, promote legacy 'admin' rows to superadmin, add
    subnet_access — but ONLY on a genuine pre-3.5 schema (detected by
    the role ENUM lacking 'superadmin').

    IMPORTANT: prior to v4.2.0 the legacy promotion ran on EVERY startup,
    which silently escalated deliberately-created 'admin' users (a valid
    role in the current 3-tier RBAC) to superadmin on each restart.
    Version-gating plus the pre-3.5 schema check fixes both problems:
    legacy installs get promoted exactly once; modern installs adopting
    this migration system never have their admins touched.
    """
    with db.cursor() as cur:
        # Discriminator: a pre-3.5 schema lacks 'superadmin' in the role ENUM.
        # Only then are existing 'admin' rows legacy full-access accounts that
        # must be promoted. On any ≥3.5 schema (including adoption of this
        # migration system by an existing install), 'admin' rows are deliberate
        # mid-tier RBAC accounts and MUST NOT be touched.
        is_pre_35_schema = "superadmin" not in _column_type(cur, "users", "role")
        if is_pre_35_schema:
            cur.execute("""
                ALTER TABLE users
                MODIFY COLUMN role ENUM('superadmin','admin','viewer')
                NOT NULL DEFAULT 'viewer'
            """)
            cur.execute("UPDATE users SET role='superadmin' WHERE role='admin'")
            if cur.rowcount:
                logger.info(f"Migration 6: promoted {cur.rowcount} legacy admin(s) to superadmin")
        if _column_missing(cur, "users", "subnet_access"):
            cur.execute("""
                ALTER TABLE users
                ADD COLUMN subnet_access JSON DEFAULT NULL
                COMMENT 'NULL = all subnets; JSON array of subnet_ids = restricted'
            """)


def _m007_telegram_legacy(db):
    """Migrate legacy Telegram settings-table config to alert_channels."""
    import json
    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) as cnt FROM alert_channels WHERE channel_type='telegram'")
        if cur.fetchone()["cnt"]:
            return
        cur.execute("""
            SELECT setting_key, setting_value FROM settings
            WHERE setting_key IN
            ('telegram_token','telegram_chat_id','telegram_enabled',
             'alert_kea_down','alert_new_lease','alert_utilization')
        """)
        old = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}
        token, chat_id = old.get("telegram_token", ""), old.get("telegram_chat_id", "")
        if not (token and chat_id):
            return
        enabled = 1 if old.get("telegram_enabled") == "true" else 0
        alert_types = []
        if old.get("alert_kea_down", "true") == "true":
            alert_types += ["kea_down", "kea_up"]
        if old.get("alert_new_lease", "false") == "true":
            alert_types.append("new_lease")
        if old.get("alert_utilization", "true") == "true":
            alert_types.append("utilization_high")
        cur.execute("""
            INSERT INTO alert_channels
                (channel_type, channel_name, enabled, config, alert_types)
            VALUES ('telegram', 'Telegram', %s, %s, %s)
        """, (enabled, json.dumps({"token": token, "chat_id": chat_id}),
              json.dumps(alert_types)))
        logger.info("Migration 7: migrated legacy Telegram settings to alert_channels")


def _m008_trusted_device_metadata(db):
    """mfa_trusted_devices: store client IP and raw user agent so trusted
    devices can be identified (friendly name + tooltip) and self-healed."""
    with db.cursor() as cur:
        if _column_missing(cur, "mfa_trusted_devices", "ip_address"):
            cur.execute("ALTER TABLE mfa_trusted_devices ADD COLUMN ip_address VARCHAR(45) DEFAULT NULL")
        if _column_missing(cur, "mfa_trusted_devices", "user_agent"):
            cur.execute("ALTER TABLE mfa_trusted_devices ADD COLUMN user_agent TEXT DEFAULT NULL")


def _m009_mfa_attempts(db):
    """mfa_attempts: brute-force throttling for the post-password TOTP/backup
    code step, which previously had no rate limiting at all (v4.4.2)."""
    with db.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS mfa_attempts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_user (user_id),
            INDEX idx_attempted (attempted_at)
        )""")


# ── Registry ──────────────────────────────────────────────────────────────────

MIGRATIONS = [
    (1, "Baseline schema (all tables, current definitions)", _m001_baseline),
    (2, "users.avatar_url column",                            _m002_users_avatar),
    (3, "devices manufacturer/type/icon columns",             _m003_devices_manufacturer),
    (4, "devices override columns + widen icon override",     _m004_devices_overrides),
    (5, "Widen users.password to VARCHAR(512)",               _m005_widen_password),
    (6, "Superadmin role, one-time legacy admin promotion, subnet_access",
                                                              _m006_superadmin_role),
    (7, "Migrate legacy Telegram settings to alert_channels", _m007_telegram_legacy),
    (8, "mfa_trusted_devices ip_address + user_agent columns", _m008_trusted_device_metadata),
    (9, "mfa_attempts table for MFA brute-force throttling",   _m009_mfa_attempts),
]

# Registry sanity: strictly increasing versions, never reordered
assert all(a[0] < b[0] for a, b in zip(MIGRATIONS, MIGRATIONS[1:])), \
    "MIGRATIONS versions must be strictly increasing"


# ── Runner ────────────────────────────────────────────────────────────────────

def latest_version() -> int:
    return MIGRATIONS[-1][0]


def applied_versions() -> set:
    """Return the set of applied migration versions (empty if table absent)."""
    from jen.models.db import jen_db
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("SHOW TABLES LIKE 'schema_migrations'")
            if not cur.fetchone():
                return set()
            cur.execute("SELECT version FROM schema_migrations")
            return {r["version"] for r in cur.fetchall()}


def run_migrations() -> int:
    """
    Apply all pending migrations in order. Returns the number applied.
    Raises on failure so app startup aborts rather than serving a
    half-migrated schema.
    """
    from jen.models.db import jen_db

    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INT PRIMARY KEY,
                    description VARCHAR(255) NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    applied = applied_versions()
    count = 0
    for version, description, fn in MIGRATIONS:
        if version in applied:
            continue
        logger.warning(f"Applying schema migration {version}: {description}")
        with jen_db() as db:
            fn(db)
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO schema_migrations (version, description) VALUES (%s, %s)",
                    (version, description)
                )
        count += 1
    if count:
        logger.warning(f"Applied {count} schema migration(s); now at version {latest_version()}")
    return count
