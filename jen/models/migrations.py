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


def _index_exists(cur, table: str, index_name: str) -> bool:
    cur.execute(
        "SELECT COUNT(*) AS cnt FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND INDEX_NAME = %s",
        (table, index_name),
    )
    return cur.fetchone()["cnt"] > 0


def _column_nullable(cur, table: str, column: str) -> bool:
    cur.execute(f"SHOW COLUMNS FROM {table} LIKE %s", (column,))
    row = cur.fetchone()
    return bool(row) and str(row.get("Null", "")).upper() == "YES"


def _foreign_key_exists(cur, table: str, constraint_name: str) -> bool:
    cur.execute(
        "SELECT COUNT(*) AS cnt FROM information_schema.TABLE_CONSTRAINTS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND CONSTRAINT_NAME = %s "
        "AND CONSTRAINT_TYPE = 'FOREIGN KEY'",
        (table, constraint_name),
    )
    return cur.fetchone()["cnt"] > 0


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
    # dashboard_prefs.widgets is VARCHAR, not TEXT, on purpose: MySQL 8
    # forbids a literal DEFAULT on a TEXT/BLOB/JSON column (MariaDB allows
    # it). The value is a short JSON array of widget ids. See migration 19.
    """CREATE TABLE IF NOT EXISTS dashboard_prefs (
        user_id INT PRIMARY KEY,
        widgets VARCHAR(512) NOT NULL DEFAULT '["subnet_stats","recent_leases"]',
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
        subnet_scope JSON DEFAULT NULL COMMENT 'NULL = all subnets; JSON array of subnet_ids = only alert on those',
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
        subnet_access JSON DEFAULT NULL COMMENT 'NULL = all subnets; JSON array of subnet_ids = restricted to those',
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
    # v5.16.0 — every Kea config Jen writes is recorded here with a diff
    # against the previous one, viewable and restorable. MEDIUMTEXT (not
    # JSON) sidesteps MariaDB's implicit json_valid CHECK and MySQL 8's
    # no-literal-DEFAULT-on-TEXT rule; `config` is stored as
    # crypto.encrypt_secret(json.dumps(cfg, indent=2, sort_keys=True))
    # (v5.20.0 — a "v1:"-prefixed Fernet token, so diffs of the
    # decrypted body stay stable). `service` is VARCHAR(8) — Q19 reuses
    # this table with service='d2'. `hash_kind` (v5.20.0) records what
    # `sha256` actually hashes: 'raw' (helper v2, the file's own bytes),
    # 'canonical' (v1/legacy, sha256 of the canonical JSON — a DIFFERENT
    # quantity), or 'legacy' (a pre-5.20.0 row whose kind was never
    # recorded).
    """CREATE TABLE IF NOT EXISTS kea_config_revisions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        server_id INT NOT NULL,
        service VARCHAR(8) NOT NULL,
        sha256 CHAR(64) NOT NULL,
        hash_kind VARCHAR(12) NOT NULL DEFAULT 'legacy',
        config MEDIUMTEXT NOT NULL,
        summary VARCHAR(255) NOT NULL DEFAULT '',
        username VARCHAR(64) NOT NULL DEFAULT '',
        source VARCHAR(16) NOT NULL DEFAULT 'jen',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_server_service (server_id, service, id)
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
        cur.execute(
            """
            INSERT INTO alert_channels
                (channel_type, channel_name, enabled, config, alert_types)
            VALUES ('telegram', 'Telegram', %s, %s, %s)
        """,
            (enabled, json.dumps({"token": token, "chat_id": chat_id}), json.dumps(alert_types)),
        )
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


def _m010_plugin_schema_migrations(db):
    """plugin_schema_migrations: v4.4.18 — tracking table so plugin DB
    migrations (jen/services/plugins.py) can finally use the same
    versioned-and-recorded discipline core Jen has used since migration 1,
    instead of re-executing every migration from every plugin's manifest
    on every single install/update with no tracking of what already ran.
    Composite (plugin_id, version) key since multiple plugins share this
    one table — mirrors schema_migrations above, just plugin-scoped."""
    with db.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS plugin_schema_migrations (
            plugin_id VARCHAR(100) NOT NULL,
            version INT NOT NULL,
            description VARCHAR(255) NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (plugin_id, version)
        )""")


def _m011_lease6_history(db):
    """lease6_history: v5.0 Phase 1 — IPv6 rollout, first schema piece.

    A deliberately SEPARATE table from lease_history, not columns bolted
    onto it: v4's single active_leases/dynamic_leases/pool_size model
    doesn't map onto v6, where IA_NA (address), IA_TA (rare, real), and
    IA_PD (delegated prefix) are three different, non-comparable
    quantities. Flattening them into one number or a discriminator column
    would lose exactly the distinction this table exists to preserve.

    Deliberately NO pool_size-equivalent column: a /64 has no meaningful
    finite "pool size" the way a v4 /24 does. A real utilization-style view
    for v6, if ever wanted, is a Phase 2/4 UI decision to make on purpose —
    not something to bake into the snapshot schema now just because v4 had
    an analogous column.

    Jen doesn't own lease6/hosts/ipv6_reservations at all (same as lease4
    today) — no migration needed for those, only for this table, which is
    Jen's own periodic snapshot data.

    ipv6_enabled defaults to false (settings table, not this migration), so
    this table stays empty and unreferenced on a v4-only install: nothing
    ever writes to or reads from it until the toggle is flipped.
    """
    with db.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS lease6_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            subnet_id INT NOT NULL,
            snapshot_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active_na INT DEFAULT 0,
            active_ta INT DEFAULT 0,
            active_pd INT DEFAULT 0,
            reserved_na INT DEFAULT 0,
            reserved_pd INT DEFAULT 0,
            INDEX idx_subnet_time (subnet_id, snapshot_time),
            INDEX idx_time (snapshot_time)
        )""")


def _m012_users_token_version(db):
    """users.token_version: v5.1.11 — load_user()'s session-cache fast path
    previously trusted session['_user_cache'] (role/subnet_access/
    session_timeout) indefinitely once set at login, with no way for the
    server to invalidate a single already-open session. An admin demoting
    a user, restricting their subnets, shortening their timeout, or even
    deleting their account outright had no effect on that user's current
    session until it happened to expire on its own (using the OLD,
    possibly-longer cached timeout). Bumping this counter on any such
    change lets load_user() cheaply detect a stale cache (one indexed
    single-column SELECT) and force a real refresh, without giving up the
    original point of the cache — avoiding a full row fetch on every
    request for the common case where nothing has changed."""
    with db.cursor() as cur:
        if _column_missing(cur, "users", "token_version"):
            cur.execute("ALTER TABLE users ADD COLUMN token_version INT NOT NULL DEFAULT 0")


def _m013_api_keys_subnet_access(db):
    """api_keys.subnet_access: v5.1.11 — API keys previously had no scope
    of their own at all; any valid key returned every subnet's leases/
    devices/reservations regardless of who created it. That meant a
    subnet-restricted admin (subnet_access IS allowed to restrict admins,
    not just viewers — see users.subnet_access) could create a key and use
    it to read subnets they have no UI access to themselves — the key
    silently had MORE access than its creator. Rather than have keys
    inherit the creating user's own subnet_access (which would break if
    that user's access changes later, or if they're later deleted), each
    key gets its own independent scope, chosen explicitly at creation
    time — same NULL-means-unrestricted convention as users.subnet_access,
    for the same reason: a key covering a plugin's needs today shouldn't
    silently change scope because someone edited an unrelated admin
    account."""
    with db.cursor() as cur:
        if _column_missing(cur, "api_keys", "subnet_access"):
            cur.execute(
                "ALTER TABLE api_keys ADD COLUMN subnet_access JSON DEFAULT NULL "
                "COMMENT 'NULL = all subnets; JSON array of subnet_ids = restricted to those'"
            )


def _m014_alert_subnet_scope(db):
    """alert_channels.subnet_scope: v5.1.16 — every alert channel got
    every subnet's new_lease/new_device/new_reserved_lease/utilization/
    stale_reservation alerts, with no way to scope a channel to only
    the subnets someone actually wants pinged about (e.g. IoT and
    Production, but not a test VLAN). Same NULL-means-unrestricted
    convention as api_keys.subnet_access and users.subnet_access — for
    the same operational reason as those: a channel's notification
    scope shouldn't have to be re-derived from anything else, and
    everyone's existing channels keep alerting on everything by default
    (NULL) unless someone deliberately narrows one down.

    This is a notification preference, not an access-control boundary —
    unlike the api_keys/users versions of this pattern, a malformed or
    unparseable subnet_scope value is treated as "no restriction" (send
    anyway) rather than "deny all", since silently going quiet on every
    alert due to a JSON typo is a worse failure mode here than
    occasionally over-notifying."""
    with db.cursor() as cur:
        if _column_missing(cur, "alert_channels", "subnet_scope"):
            cur.execute(
                "ALTER TABLE alert_channels ADD COLUMN subnet_scope JSON DEFAULT NULL "
                "COMMENT 'NULL = all subnets; JSON array of subnet_ids = only alert on those'"
            )


def _m015_users_must_change_password(db):
    """users.must_change_password: v5.2.7 security fix. A fresh install
    seeds an 'admin'/'admin' superadmin with nothing enforcing that the
    obvious default ever actually gets changed — the README says to
    change it immediately, but that's advisory, not enforced anywhere
    in the application. Given Jen manages real DHCP infrastructure, a
    forgotten default credential has a much larger blast radius than
    the same oversight on a low-stakes app.

    This column, combined with a before_request hook (see jen/__init__.py)
    that redirects every authenticated request to a forced password-
    change screen while it's set, makes the rest of the application
    genuinely unavailable until the password is changed — not just
    documented as something you should do. Also set on newly-created
    user accounts (add_user() in jen/routes/users.py), since a
    superadmin setting another user's initial password is the same
    category of concern as the default seed itself.
    """
    with db.cursor() as cur:
        if _column_missing(cur, "users", "must_change_password"):
            cur.execute("ALTER TABLE users ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 0")


def _m016_backfill_must_change_password_for_existing_admin_admin(db):
    """
    v5.3.3 fix — a real gap in migration 15 found by a third-party
    review: that migration only ADDED the must_change_password column
    with DEFAULT 0, which is correct for brand-new rows going forward,
    but means every row that ALREADY existed at the moment migration
    15 ran got the "already fine, no need to change" default — even
    one whose password was, and still is, the literal string "admin".
    Only a genuinely FRESH install was actually protected (db.py's
    seed logic explicitly sets the flag at INSERT time); an
    already-running instance that upgraded through migration 15
    without anyone ever having changed the default admin/admin
    credential got a new column that quietly did nothing for them.

    This can't be fixed by editing migration 15's own function body —
    the migration runner tracks applied versions in schema_migrations
    and never re-invokes an already-applied migration, which by now
    describes most of the currently-deployed installations (anything
    that reached v5.2.7 or later already has migration 15 recorded as
    applied). A new, separate migration is the only way to reach
    those installations: it runs exactly once, the first time each
    database applies it, regardless of how long ago migration 15 ran
    there.

    Checks every user row whose flag isn't already set, and verifies
    (not compares hashes directly — hashes are salted, so identical
    passwords never produce identical hashes) whether the stored
    password still matches the literal string "admin". Deliberately
    checks every user, not just the superadmin/admin username: an
    admin-created account is just as much a "someone else knows this
    password" concern as the default seed itself (matching the same
    reasoning migration 15's own docstring already gives for why
    add_user() sets this flag too).
    """
    from jen.models.user import verify_password

    with db.cursor() as cur:
        cur.execute("SELECT id, password FROM users WHERE must_change_password = 0")
        rows = cur.fetchall()
        flagged_ids = [row["id"] for row in rows if row["password"] and verify_password(row["password"], "admin")]
        for user_id in flagged_ids:
            cur.execute("UPDATE users SET must_change_password = 1 WHERE id = %s", (user_id,))


def _m017_encrypt_mfa_secrets(db):
    """
    v5.4.0 — `mfa_methods.secret` (the TOTP shared secret) was stored as
    plaintext base32. Anyone able to read that one column — a downloaded
    or misplaced DB export, a read replica, a compromised DB account, SQL
    injection anywhere in the app, a shared DB host — could generate valid
    second-factor codes for every enrolled user, defeating MFA entirely.

    A TOTP secret has to be stored reversibly (Jen recomputes the current
    code from it every 30s), so the fix is encryption with a key kept
    outside the database — see jen/services/crypto.py. This migration
    wraps every existing plaintext value with encrypt_secret(), producing
    a "v1:"-prefixed Fernet token. New enrolments encrypt at INSERT time
    (jen/routes/mfa_routes.py); verification decrypts on read
    (jen/services/mfa.py::verify_totp), with a legacy-plaintext passthrough
    so a row this migration somehow hasn't reached still works.

    Idempotent: rows already in "v1:" form are skipped by the WHERE
    clause, so a re-run (or a crash partway through, since the UPDATEs and
    the schema_migrations INSERT share one transaction) is safe. If the
    encryption key can't be created or persisted, encrypt_secret() raises
    and this migration aborts app startup rather than recording itself as
    applied — the same fail-loud contract every migration here follows.
    """
    from jen.services.crypto import PREFIX, encrypt_secret

    with db.cursor() as cur:
        cur.execute(
            "SELECT id, secret FROM mfa_methods WHERE secret IS NOT NULL AND secret <> '' AND secret NOT LIKE %s",
            (PREFIX + "%",),
        )
        rows = cur.fetchall()
        for row in rows:
            cur.execute(
                "UPDATE mfa_methods SET secret = %s WHERE id = %s",
                (encrypt_secret(row["secret"]), row["id"]),
            )
        if rows:
            logger.warning("Migration 17: encrypted %d existing MFA secret(s) at rest", len(rows))


def _m018_encrypt_alert_channel_config(db):
    """
    v5.7.0 — `alert_channels.config` is a JSON blob holding every
    notification channel's delivery credentials: Telegram bot tokens,
    SMTP passwords, Pushover keys, ntfy tokens, Slack/Discord/webhook
    URLs (which themselves embed a secret). Stored as plaintext it had
    the same exposure as the pre-v5.4.0 TOTP secrets — any read of that
    one column (a stray DB export, a read replica, SQL injection, a
    shared DB host) hands over working credentials for every channel.

    Same fix as migration 17: wrap the value with crypto.encrypt_secret()
    so it becomes a `v1:`-prefixed Fernet token, key kept in /etc/jen
    outside the database. The whole blob is encrypted (not per-field) so
    a new channel type with new secret fields is covered automatically.
    New saves encrypt at write time (jen/routes/settings/alerts.py via
    alerts.encode_channel_config); every read goes through
    alerts.get_channel_config(), which decrypts, with a legacy-plaintext
    passthrough for any row this migration hasn't reached.

    The `config` column is MySQL `JSON` (MariaDB enforces `json_valid()`
    on it), so the encrypted value is stored as a JSON string *literal*
    — `json.dumps("v1:…")`, i.e. the token in double quotes — which stays
    valid JSON. encode_channel_config() does that wrapping; the WHERE
    clause below matches its `"v1:…` shape.

    Idempotent: rows already wrapped are skipped, so a re-run or a crash
    partway through is safe. If the encryption key can't be
    created/persisted, encode_channel_config() raises and startup aborts
    rather than recording this as applied.
    """
    from jen.services.alerts import encode_channel_config, get_channel_config

    with db.cursor() as cur:
        cur.execute(
            "SELECT id, config FROM alert_channels WHERE config IS NOT NULL AND config <> '' AND config NOT LIKE %s",
            ('"v1:%',),
        )
        rows = cur.fetchall()
        for row in rows:
            parsed = get_channel_config(row)  # legacy plaintext JSON object → dict
            cur.execute(
                "UPDATE alert_channels SET config = %s WHERE id = %s",
                (encode_channel_config(parsed), row["id"]),
            )
        if rows:
            logger.warning("Migration 18: encrypted %d alert channel config blob(s) at rest", len(rows))


def _m019_dashboard_widgets_varchar(db):
    """
    v5.8.0 — `dashboard_prefs.widgets` was `TEXT NOT NULL DEFAULT '[…]'`.
    MariaDB allows a literal default on a TEXT column; MySQL 8 rejects it
    (error 1101), so the baseline schema wouldn't even build on MySQL —
    which the CI MySQL leg caught, and which contradicts the documented
    "MySQL or MariaDB" support. The value is a short JSON array of widget
    ids, so VARCHAR(512) holds it with room to spare and takes the
    default on both engines.

    Idempotent: skipped when the column is already VARCHAR.
    """
    with db.cursor() as cur:
        if "varchar" not in _column_type(cur, "dashboard_prefs", "widgets"):
            cur.execute(
                "ALTER TABLE dashboard_prefs MODIFY widgets "
                'VARCHAR(512) NOT NULL DEFAULT \'["subnet_stats","recent_leases"]\''
            )
            logger.info("Migration 19: dashboard_prefs.widgets TEXT → VARCHAR(512)")


def _m020_kea_config_revisions(db):
    """
    v5.16.0 — `kea_config_revisions` records every Kea config Jen writes
    (and every external change it notices), with a stable-diffable JSON
    body, so history is viewable and revisions restorable. In the
    baseline for a fresh DB; this creates it on an existing one.
    Idempotent (CREATE TABLE IF NOT EXISTS).
    """
    with db.cursor() as cur:
        cur.execute(
            """CREATE TABLE IF NOT EXISTS kea_config_revisions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                server_id INT NOT NULL,
                service VARCHAR(8) NOT NULL,
                sha256 CHAR(64) NOT NULL,
                config MEDIUMTEXT NOT NULL,
                summary VARCHAR(255) NOT NULL DEFAULT '',
                username VARCHAR(64) NOT NULL DEFAULT '',
                source VARCHAR(16) NOT NULL DEFAULT 'jen',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                KEY idx_server_service (server_id, service, id)
            )"""
        )
    logger.info("Migration 20: kea_config_revisions table")


def _m021_config_revision_hash_kind_and_encrypt(db):
    """
    v5.20.0 — two related fixes to `kea_config_revisions` (migration 20,
    v5.16.0), both from the 2026-09-11 audit:

    (a) `hash_kind` records what `sha256` actually hashes. Helper v2
    hashes the raw config-file bytes ("raw"); a v1/legacy host has no
    raw hash, so Jen falls back to `sha256(canonical(cfg))`
    ("canonical") — a DIFFERENT quantity stored in the same CHAR(64)
    column with nothing to distinguish them. A host upgraded v1→v2
    would compare its first raw-bytes read against a stale canonical
    sha and record a spurious "external" revision; restoring on such a
    host would pass the canonical sha as `expect_sha256` to a v2 helper
    that only understands raw bytes, and always conflict. Existing rows
    predate this distinction entirely, so they get "legacy" — an
    explicit "unknown", not a guess.

    (b) `config` bodies were stored as plaintext MEDIUMTEXT. A Kea
    config can carry lease-database/hosts-database passwords,
    control-socket basic-auth credentials, and HA peer basic-auth
    passwords — the same exposure migrations 17/18 already fixed for
    MFA secrets and alert-channel config. Same fix: wrap with
    `crypto.encrypt_secret()` (a "v1:"-prefixed Fernet token; the
    column is MEDIUMTEXT, not JSON, so no `json_valid()` concern).
    Reads decrypt with a legacy-plaintext passthrough
    (`jen/services/config_revisions.py`).

    Idempotent: the ADD COLUMN is skipped if already present; the
    re-encrypt WHERE clause skips rows already wrapped, so a re-run (or
    a crash partway through — both run in the same transaction as the
    `schema_migrations` INSERT) is safe. A missing/unreadable
    encryption key makes `encrypt_secret()` raise, aborting startup
    rather than recording this as applied — the same fail-loud contract
    as 17/18.
    """
    from jen.services.crypto import PREFIX, encrypt_secret

    with db.cursor() as cur:
        if _column_missing(cur, "kea_config_revisions", "hash_kind"):
            cur.execute("ALTER TABLE kea_config_revisions ADD COLUMN hash_kind VARCHAR(12) NOT NULL DEFAULT 'legacy'")
            logger.info("Migration 21: kea_config_revisions.hash_kind column added")

        cur.execute(
            "SELECT id, config FROM kea_config_revisions "
            "WHERE config IS NOT NULL AND config <> '' AND config NOT LIKE %s",
            (PREFIX + "%",),
        )
        rows = cur.fetchall()
        for row in rows:
            cur.execute(
                "UPDATE kea_config_revisions SET config = %s WHERE id = %s",
                (encrypt_secret(row["config"]), row["id"]),
            )
        if rows:
            logger.warning("Migration 21: encrypted %d existing config revision(s) at rest", len(rows))


def _m022_users_oidc_columns(db):
    """
    v5.25.0 (Q21) — single sign-on via OpenID Connect. `auth_provider`
    distinguishes a local-password account ('local', the default — every
    existing user stays exactly as they are) from an IdP-managed one
    ('oidc'); `external_id` is the IdP's own stable subject (the `sub`
    claim). A repeat OIDC login is matched ONLY on
    (auth_provider, external_id) — never on username or email, since
    those can be reassigned or reused at the IdP in ways `sub` never is
    (see jen/services/oidc.py::find_or_create_user). The unique key is
    what makes that lookup actually enforce one row per (provider,
    external_id) pair; MySQL/MariaDB treat every NULL in a unique index
    as distinct from every other NULL, so local users (external_id
    always NULL) never collide with each other on it.

    Idempotent: each ADD COLUMN / ADD UNIQUE KEY is skipped if already
    present, so a re-run (or a crash partway through) is safe.
    """
    with db.cursor() as cur:
        if _column_missing(cur, "users", "auth_provider"):
            cur.execute("ALTER TABLE users ADD COLUMN auth_provider VARCHAR(16) NOT NULL DEFAULT 'local'")
            logger.info("Migration 22: users.auth_provider column added")
        if _column_missing(cur, "users", "external_id"):
            cur.execute("ALTER TABLE users ADD COLUMN external_id VARCHAR(255) NULL")
            logger.info("Migration 22: users.external_id column added")
        if not _index_exists(cur, "users", "uq_users_provider_ext"):
            cur.execute("ALTER TABLE users ADD UNIQUE KEY uq_users_provider_ext (auth_provider, external_id)")
            logger.info("Migration 22: uq_users_provider_ext unique key added")


# Every table that names a user by id, and the FK each one gets in
# migration 23. CASCADE for "this row is meaningless without its user";
# api_keys.created_by is handled separately below (SET NULL, and the
# column has to become nullable first).
_M023_CASCADE_TABLES = (
    "mfa_methods",
    "mfa_backup_codes",
    "mfa_trusted_devices",
    "mfa_attempts",
    "webauthn_credentials",
    "saved_searches",
    "dashboard_prefs",
)


def _m023_user_foreign_keys(db):
    """
    v5.25.0 (Q21, folded in from Q8C) — every table that names a user by
    id gets a real foreign key, so deleting a user can no longer leave
    orphaned MFA/search/dashboard rows behind (`users.py::delete_user`
    doesn't run any manual per-table cleanup today — checked the actual
    code, not assumed — so this migration is the first thing that
    actually enforces this, not a belt-and-braces addition to an
    existing manual delete). CASCADE for the tables above; `api_keys`
    is different — a key a since-deleted user created should keep
    working, just with no attributable creator, so `created_by` becomes
    nullable and gets SET NULL instead of CASCADE.

    Before each ALTER: delete rows that already point at a user that no
    longer exists — a real orphan predates this migration (nothing
    enforced referential integrity before it), and the ALTER fails
    outright (error 1452) if even one survives. Idempotent via
    information_schema.TABLE_CONSTRAINTS; every column here is a plain
    INT, matching users.id exactly (a type mismatch is error 1215 —
    verified against the baseline schema for all eight tables before
    writing this).
    """
    with db.cursor() as cur:
        for table in _M023_CASCADE_TABLES:
            cur.execute(f"DELETE FROM {table} WHERE user_id NOT IN (SELECT id FROM users)")
            if cur.rowcount:
                logger.warning(f"Migration 23: deleted {cur.rowcount} orphaned {table} row(s)")
            constraint = f"fk_{table}_user_id"
            if not _foreign_key_exists(cur, table, constraint):
                cur.execute(
                    f"ALTER TABLE {table} ADD CONSTRAINT {constraint} "
                    f"FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"
                )
                logger.info(f"Migration 23: {constraint} added")

        if _column_nullable(cur, "api_keys", "created_by") is False:
            cur.execute("ALTER TABLE api_keys MODIFY COLUMN created_by INT NULL")
            logger.info("Migration 23: api_keys.created_by made nullable")
        cur.execute(
            "UPDATE api_keys SET created_by = NULL "
            "WHERE created_by IS NOT NULL AND created_by NOT IN (SELECT id FROM users)"
        )
        if cur.rowcount:
            logger.warning(f"Migration 23: nulled {cur.rowcount} orphaned api_keys.created_by reference(s)")
        if not _foreign_key_exists(cur, "api_keys", "fk_api_keys_created_by"):
            cur.execute(
                "ALTER TABLE api_keys ADD CONSTRAINT fk_api_keys_created_by "
                "FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL"
            )
            logger.info("Migration 23: fk_api_keys_created_by added")


# ── Registry ──────────────────────────────────────────────────────────────────

MIGRATIONS = [
    (1, "Baseline schema (all tables, current definitions)", _m001_baseline),
    (2, "users.avatar_url column", _m002_users_avatar),
    (3, "devices manufacturer/type/icon columns", _m003_devices_manufacturer),
    (4, "devices override columns + widen icon override", _m004_devices_overrides),
    (5, "Widen users.password to VARCHAR(512)", _m005_widen_password),
    (6, "Superadmin role, one-time legacy admin promotion, subnet_access", _m006_superadmin_role),
    (7, "Migrate legacy Telegram settings to alert_channels", _m007_telegram_legacy),
    (8, "mfa_trusted_devices ip_address + user_agent columns", _m008_trusted_device_metadata),
    (9, "mfa_attempts table for MFA brute-force throttling", _m009_mfa_attempts),
    (10, "plugin_schema_migrations tracking table", _m010_plugin_schema_migrations),
    (11, "lease6_history table (v5.0 IPv6 Phase 1)", _m011_lease6_history),
    (12, "users.token_version column for session-cache invalidation", _m012_users_token_version),
    (13, "api_keys.subnet_access column for per-key scope", _m013_api_keys_subnet_access),
    (14, "alert_channels.subnet_scope + users global setting for reserved-lease recurrence", _m014_alert_subnet_scope),
    (15, "users.must_change_password column for forced password-change enforcement", _m015_users_must_change_password),
    (
        16,
        "backfill must_change_password for existing users still on the literal default password",
        _m016_backfill_must_change_password_for_existing_admin_admin,
    ),
    (17, "Encrypt existing plaintext mfa_methods.secret values at rest (v5.4.0)", _m017_encrypt_mfa_secrets),
    (18, "Encrypt existing plaintext alert_channels.config blobs at rest (v5.7.0)", _m018_encrypt_alert_channel_config),
    (
        19,
        "dashboard_prefs.widgets TEXT → VARCHAR(512) for MySQL 8 portability (v5.8.0)",
        _m019_dashboard_widgets_varchar,
    ),
    (20, "kea_config_revisions table — Kea config history + restore (v5.16.0)", _m020_kea_config_revisions),
    (
        21,
        "kea_config_revisions.hash_kind column + encrypt existing config bodies at rest (v5.20.0)",
        _m021_config_revision_hash_kind_and_encrypt,
    ),
    (22, "users.auth_provider/external_id columns for OIDC single sign-on (v5.25.0)", _m022_users_oidc_columns),
    (
        23,
        "Foreign keys from mfa_*/webauthn_credentials/saved_searches/dashboard_prefs/api_keys to users (v5.25.0)",
        _m023_user_foreign_keys,
    ),
]

# Registry sanity: strictly increasing versions, never reordered
# strict=False here is deliberate, not an oversight — MIGRATIONS and
# MIGRATIONS[1:] are intentionally different lengths (by exactly one
# element, by construction, to compare each adjacent pair); strict=True
# would make this assertion always raise.
assert all(a[0] < b[0] for a, b in zip(MIGRATIONS, MIGRATIONS[1:], strict=False)), (
    "MIGRATIONS versions must be strictly increasing"
)


# ── Runner ────────────────────────────────────────────────────────────────────


def latest_version() -> int:
    return MIGRATIONS[-1][0]


def applied_versions() -> set:
    """Return the set of applied migration versions (empty if table absent)."""
    from jen.models.db import jen_db

    with jen_db() as db, db.cursor() as cur:
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

    with jen_db() as db, db.cursor() as cur:
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
                    "INSERT INTO schema_migrations (version, description) VALUES (%s, %s)", (version, description)
                )
        count += 1
    if count:
        logger.warning(f"Applied {count} schema migration(s); now at version {latest_version()}")
    return count
