#!/usr/bin/env python3
# Jen - The Kea DHCP Management Console
# Copyright (C) 2026 Matthew Thibodeau
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# https://www.gnu.org/licenses/gpl-3.0.txt
"""
Jen - The Kea DHCP Management Console
Version 1.0.2
"""

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, send_from_directory, Response, session)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
import pymysql
import requests
import hashlib
import os
import re
import ssl
import subprocess
import threading
import configparser
import csv
import io
import json
import ipaddress
import logging
from datetime import datetime, timezone
from functools import wraps
from werkzeug.serving import make_server
from werkzeug.security import generate_password_hash, check_password_hash

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

JEN_VERSION = "2.6.7"

# ─────────────────────────────────────────
# App setup
# ─────────────────────────────────────────
app = Flask(__name__, static_folder="/opt/jen/static")
# Load or generate a persistent secret key so sessions survive restarts
# and are consistent across gunicorn workers
_SECRET_KEY_FILE = "/etc/jen/secret_key"
def _load_secret_key():
    try:
        if os.path.exists(_SECRET_KEY_FILE):
            with open(_SECRET_KEY_FILE, "r") as _f:
                _key = _f.read().strip()
            if len(_key) >= 32:
                return _key
        _key = os.urandom(32).hex()
        os.makedirs("/etc/jen", exist_ok=True)
        with open(_SECRET_KEY_FILE, "w") as _f:
            _f.write(_key)
        os.chmod(_SECRET_KEY_FILE, 0o640)
        return _key
    except Exception as _e:
        # Fallback: not persistent but at least won't crash
        import logging
        logging.getLogger("jen").warning(f"Could not persist secret key: {_e}")
        return os.urandom(32).hex()
app.secret_key = _load_secret_key()

# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
CONFIG_FILE = "/etc/jen/jen.config"

def load_config():
    cfg = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(
            f"Config file not found: {CONFIG_FILE}\n"
            f"Copy jen.config.example to {CONFIG_FILE} and fill in your values."
        )
    cfg.read(CONFIG_FILE)
    required = [("kea","api_url"),("kea","api_user"),("kea","api_pass"),
                ("kea_db","host"),("kea_db","user"),("kea_db","password"),
                ("jen_db","host"),("jen_db","user"),("jen_db","password")]
    missing = [(s,k) for s,k in required if not cfg.has_option(s,k) or not cfg.get(s,k).strip()]
    if missing:
        raise ValueError(f"Missing required config values: {missing}")
    return cfg

cfg = load_config()

def write_config_value(section, key, value):
    """Update a single config value and write back to disk."""
    parser = configparser.ConfigParser()
    parser.read(CONFIG_FILE)
    if not parser.has_section(section):
        parser.add_section(section)
    parser.set(section, key, value)
    with open(CONFIG_FILE, 'w') as f:
        parser.write(f)

def write_subnets_config(subnet_dict):
    """Rewrite the [subnets] section entirely."""
    parser = configparser.ConfigParser()
    parser.read(CONFIG_FILE)
    if parser.has_section('subnets'):
        parser.remove_section('subnets')
    parser.add_section('subnets')
    for sid, info in subnet_dict.items():
        parser.set('subnets', str(sid), f"{info['name']}, {info['cidr']}")
    with open(CONFIG_FILE, 'w') as f:
        parser.write(f)



KEA_API_URL  = cfg.get("kea", "api_url")
KEA_API_USER = cfg.get("kea", "api_user")
KEA_API_PASS = cfg.get("kea", "api_pass")

KEA_DB_HOST = cfg.get("kea_db", "host")
KEA_DB_USER = cfg.get("kea_db", "user")
KEA_DB_PASS = cfg.get("kea_db", "password")
KEA_DB_NAME = cfg.get("kea_db", "database", fallback="kea")

JEN_DB_HOST = cfg.get("jen_db", "host")
JEN_DB_USER = cfg.get("jen_db", "user")
JEN_DB_PASS = cfg.get("jen_db", "password")
JEN_DB_NAME = cfg.get("jen_db", "database", fallback="jen")

HTTP_PORT  = cfg.getint("server", "http_port",  fallback=5050)
HTTPS_PORT = cfg.getint("server", "https_port", fallback=8443)

KEA_SSH_HOST = cfg.get("kea_ssh", "host",     fallback="")
KEA_SSH_USER = cfg.get("kea_ssh", "user",     fallback="")
KEA_SSH_KEY  = cfg.get("kea_ssh", "key_path", fallback="/etc/jen/ssh/jen_rsa")
KEA_CONF     = cfg.get("kea_ssh", "kea_conf", fallback="/etc/kea/kea-dhcp4.conf")

def load_kea_servers():
    """Load all configured Kea servers. Server 1 always comes from [kea] section."""
    servers = []
    # Server 1 — always from [kea] section
    servers.append({
        "id": 1,
        "name": cfg.get("kea", "name", fallback="Kea Server 1"),
        "api_url": cfg.get("kea", "api_url"),
        "api_user": cfg.get("kea", "api_user"),
        "api_pass": cfg.get("kea", "api_pass"),
        "ssh_host": cfg.get("kea_ssh", "host", fallback=""),
        "ssh_user": cfg.get("kea_ssh", "user", fallback=""),
        "ssh_key":  cfg.get("kea_ssh", "key_path", fallback="/etc/jen/ssh/jen_rsa"),
        "kea_conf": cfg.get("kea_ssh", "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
        "role":     cfg.get("kea", "role", fallback="primary"),
    })
    # Additional servers — [kea_server_2], [kea_server_3], etc.
    n = 2
    while cfg.has_section(f"kea_server_{n}"):
        sec = f"kea_server_{n}"
        servers.append({
            "id": n,
            "name": cfg.get(sec, "name", fallback=f"Kea Server {n}"),
            "api_url": cfg.get(sec, "api_url", fallback=""),
            "api_user": cfg.get(sec, "api_user", fallback=KEA_API_USER),
            "api_pass": cfg.get(sec, "api_pass", fallback=KEA_API_PASS),
            "ssh_host": cfg.get(sec, "ssh_host", fallback=""),
            "ssh_user": cfg.get(sec, "ssh_user", fallback=""),
            "ssh_key":  cfg.get(sec, "ssh_key",  fallback="/etc/jen/ssh/jen_rsa"),
            "kea_conf": cfg.get(sec, "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
            "role":     cfg.get(sec, "role", fallback="standby"),
        })
        n += 1
    return servers

KEA_SERVERS = load_kea_servers()

# Parse subnet map with validation
SUBNET_MAP = {}
if cfg.has_section("subnets"):
    for key, val in cfg.items("subnets"):
        try:
            parts = [p.strip() for p in val.split(",")]
            if len(parts) != 2:
                logger.warning(f"Skipping malformed subnet entry '{key}': expected 'Name, CIDR'")
                continue
            name, cidr = parts
            ipaddress.ip_network(cidr, strict=False)  # validate CIDR
            SUBNET_MAP[int(key)] = {"name": name, "cidr": cidr}
        except ValueError as e:
            logger.warning(f"Skipping invalid subnet entry '{key} = {val}': {e}")

if not SUBNET_MAP:
    logger.warning("No valid subnets found in [subnets] config section.")

SSL_CERT     = "/etc/jen/ssl/certificate.crt"
SSL_KEY      = "/etc/jen/ssl/private.key"
SSL_CA       = "/etc/jen/ssl/ca_bundle.crt"
SSL_COMBINED = "/etc/jen/ssl/combined.crt"
FAVICON_PATH = "/opt/jen/static/favicon.ico"
STATIC_DIR   = "/opt/jen/static"
NAV_LOGO_PATH = "/opt/jen/static/nav_logo"  # no extension — we detect it
SSH_KEY_PATH = cfg.get("kea_ssh", "key_path", fallback="/etc/jen/ssh/jen_rsa")
DDNS_LOG     = cfg.get("ddns", "log_path", fallback="/var/log/kea/kea-ddns.log")

def ssl_configured():
    return os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY)

# ─────────────────────────────────────────
# Validation helpers
# ─────────────────────────────────────────
MAC_RE  = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', re.IGNORECASE)
HOST_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')

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
# Login Manager
# ─────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access Jen."

class User(UserMixin):
    def __init__(self, id, username, role, session_timeout):
        self.id = id
        self.username = username
        self.role = role
        self.session_timeout = session_timeout

@login_manager.user_loader
def load_user(user_id):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, username, role, session_timeout FROM users WHERE id=%s", (user_id,))
            row = cur.fetchone()
        db.close()
        if row:
            return User(row["id"], row["username"], row["role"], row["session_timeout"])
    except Exception as e:
        logger.error(f"load_user error: {e}")
    return None

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

@app.before_request
def check_session_timeout():
    if current_user.is_authenticated:
        # Check if session timeout is enabled
        timeout_enabled = get_global_setting("session_timeout_enabled", "true")
        if timeout_enabled == "false":
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            return
        timeout = current_user.session_timeout or int(get_global_setting("session_timeout_minutes", "60"))
        if int(timeout) == 0:
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            return
        now = datetime.now(timezone.utc)
        last = session.get("last_active")
        if not last:
            # First request after login — initialize
            session["last_active"] = now.isoformat()
        else:
            try:
                elapsed = (now - datetime.fromisoformat(last)).total_seconds() / 60
                if elapsed > int(timeout):
                    logout_user()
                    flash("Session expired. Please log in again.", "error")
                    return redirect(url_for("login"))
            except Exception:
                pass
            # Only update last_active on real page requests, not background API polls
            if not request.path.startswith("/api/") and not request.path == "/metrics":
                session["last_active"] = now.isoformat()

@app.before_request
def redirect_to_https():
    if ssl_configured() and not request.is_secure:
        host = request.host.split(":")[0]
        return redirect(f"https://{host}:{HTTPS_PORT}{request.path}", code=301)

# ─────────────────────────────────────────
# Error handlers
# ─────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return render_template("error.html", code=404, message="Page not found."), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"500 error on {request.path}: {e}")
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error"}), 500
    return render_template("error.html", code=500, message="An unexpected error occurred. Check the Jen logs for details."), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception on {request.path}: {e}", exc_info=True)
    if request.path.startswith("/api/"):
        return jsonify({"error": str(e)}), 500
    flash(f"An error occurred: {str(e)}", "error")
    return redirect(request.referrer or url_for("dashboard"))

# ─────────────────────────────────────────
# Jen MySQL
# ─────────────────────────────────────────
def get_jen_db():
    return pymysql.connect(
        host=JEN_DB_HOST, user=JEN_DB_USER, password=JEN_DB_PASS,
        database=JEN_DB_NAME, cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5
    )

def get_kea_db():
    return pymysql.connect(
        host=KEA_DB_HOST, user=KEA_DB_USER, password=KEA_DB_PASS,
        database=KEA_DB_NAME, cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5
    )

def init_jen_db():
    os.makedirs("/etc/jen/ssl", exist_ok=True)
    os.makedirs("/etc/jen/ssh", exist_ok=True)
    os.makedirs(STATIC_DIR, exist_ok=True)
    db = get_jen_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password VARCHAR(64) NOT NULL,
                    role ENUM('admin','viewer') NOT NULL DEFAULT 'viewer',
                    session_timeout INT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Migrate: add avatar_url if missing
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
            cur.execute("SELECT COUNT(*) as cnt FROM users")
            if cur.fetchone()["cnt"] == 0:
                cur.execute(
                    "INSERT INTO users (username, password, role) VALUES (%s, %s, 'admin')",
                    ("admin", hash_password("admin"))
                )
                print("Created default admin user: admin / admin")
        # Migrate: add fingerprinting columns to devices table if not present
        with db.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM devices LIKE 'manufacturer'")
            if not cur.fetchone():
                cur.execute("ALTER TABLE devices ADD COLUMN manufacturer VARCHAR(100) DEFAULT NULL")
                cur.execute("ALTER TABLE devices ADD COLUMN device_type VARCHAR(30) DEFAULT NULL")
                cur.execute("ALTER TABLE devices ADD COLUMN device_icon VARCHAR(10) DEFAULT NULL")
                db.commit()
                logger.info("Migration: added manufacturer/device_type/device_icon to devices table")
            # Migrate: add override columns
            cur.execute("SHOW COLUMNS FROM devices LIKE 'manufacturer_override'")
            if not cur.fetchone():
                cur.execute("ALTER TABLE devices ADD COLUMN manufacturer_override VARCHAR(100) DEFAULT NULL")
                cur.execute("ALTER TABLE devices ADD COLUMN device_type_override VARCHAR(30) DEFAULT NULL")
                cur.execute("ALTER TABLE devices ADD COLUMN device_icon_override VARCHAR(50) DEFAULT NULL")
                db.commit()
                logger.info("Migration: added manufacturer/device_type/device_icon override columns to devices table")
            else:
                # Fix VARCHAR(10) → VARCHAR(50) if needed
                cur.execute("SHOW COLUMNS FROM devices LIKE 'device_icon_override'")
                col = cur.fetchone()
                if col and 'varchar(10)' in str(col.get('Type','')).lower():
                    cur.execute("ALTER TABLE devices MODIFY COLUMN device_icon_override VARCHAR(50) DEFAULT NULL")
                    db.commit()
        # Migrate old Telegram settings in a fresh cursor
        import json as _json
        with db.cursor() as cur2:
            cur2.execute("SELECT COUNT(*) as cnt FROM alert_channels WHERE channel_type='telegram'")
            if cur2.fetchone()["cnt"] == 0:
                cur2.execute("SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('telegram_token','telegram_chat_id','telegram_enabled','alert_kea_down','alert_new_lease','alert_utilization')")
                old_settings = {row["setting_key"]: row["setting_value"] for row in cur2.fetchall()}
                token = old_settings.get("telegram_token", "")
                chat_id = old_settings.get("telegram_chat_id", "")
                if token and chat_id:
                    enabled = 1 if old_settings.get("telegram_enabled") == "true" else 0
                    alert_types = []
                    if old_settings.get("alert_kea_down", "true") == "true":
                        alert_types += ["kea_down", "kea_up"]
                    if old_settings.get("alert_new_lease", "false") == "true":
                        alert_types.append("new_lease")
                    if old_settings.get("alert_utilization", "true") == "true":
                        alert_types.append("utilization_high")
                    cur2.execute("""
                        INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types)
                        VALUES ('telegram', 'Telegram', %s, %s, %s)
                    """, (enabled, _json.dumps({"token": token, "chat_id": chat_id}), _json.dumps(alert_types)))
                    print("Migrated existing Telegram settings to new alert_channels table.")
        db.commit()
    finally:
        db.close()

def hash_password(p):
    """Hash a password using werkzeug pbkdf2-sha256 (salted, iterated)."""
    return generate_password_hash(p, method="pbkdf2:sha256")

def verify_password(stored_hash, provided_password):
    """
    Verify a password against a stored hash.
    Supports both legacy SHA-256 (plain hex) and new pbkdf2 hashes for migration.
    """
    if stored_hash and stored_hash.startswith("pbkdf2:"):
        return check_password_hash(stored_hash, provided_password)
    else:
        # Legacy SHA-256 — accept and flag for upgrade
        import hashlib
        return stored_hash == hashlib.sha256(provided_password.encode()).hexdigest()

# ─────────────────────────────────────────
# Rate limiting
# ─────────────────────────────────────────
def get_rate_limit_settings():
    return {
        "max_attempts": int(get_global_setting("rl_max_attempts", "10")),
        "lockout_minutes": int(get_global_setting("rl_lockout_minutes", "15")),
        "mode": get_global_setting("rl_mode", "both"),  # ip, username, both, off
    }

def record_login_attempt(ip, username):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("INSERT INTO login_attempts (ip_address, username) VALUES (%s, %s)", (ip, username))
            # Clean up old attempts beyond the maximum useful window (24h)
            cur.execute("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)")
        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"Rate limit record error: {e}")

def clear_login_attempts(ip, username):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM login_attempts WHERE ip_address=%s OR username=%s", (ip, username))
        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"Rate limit clear error: {e}")

def is_locked_out(ip, username):
    rl = get_rate_limit_settings()
    mode = rl["mode"]
    max_attempts = rl["max_attempts"]
    lockout_minutes = rl["lockout_minutes"]

    # Rate limiting disabled
    if mode == "off" or max_attempts == 0:
        return False, 0

    try:
        db = get_jen_db()
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
def get_mfa_mode():
    return get_global_setting("mfa_mode", "off")  # off, optional, required_admins, required_all

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
        db = get_jen_db()
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
        db = get_jen_db()
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
        db = get_jen_db()
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
        db = get_jen_db()
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
        db = get_jen_db()
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
        db = get_jen_db()
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

def get_global_setting(key, default=None):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT setting_value FROM settings WHERE setting_key=%s", (key,))
            row = cur.fetchone()
        db.close()
        return row["setting_value"] if row else default
    except Exception:
        return default

def set_global_setting(key, value):
    db = get_jen_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE setting_value=%s, updated_at=CURRENT_TIMESTAMP
            """, (key, value, value))
        db.commit()
    finally:
        db.close()

def audit(action, entity, details=""):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log (user_id, username, action, entity, details, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                current_user.id if current_user.is_authenticated else None,
                current_user.username if current_user.is_authenticated else "system",
                action, entity, details, request.remote_addr
            ))
        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"Audit log error: {e}")

# ─────────────────────────────────────────
# Kea API
# ─────────────────────────────────────────
def kea_command(command, service="dhcp4", arguments=None, server=None):
    """Send command to a specific Kea server or the default (server 1)."""
    if server is None:
        url  = KEA_API_URL
        user = KEA_API_USER
        pwd  = KEA_API_PASS
    else:
        url  = server["api_url"]
        user = server["api_user"]
        pwd  = server["api_pass"]
    payload = {"command": command, "service": [service]}
    if arguments:
        payload["arguments"] = arguments
    try:
        resp = requests.post(url, json=payload, auth=(user, pwd), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data[0] if isinstance(data, list) else data
    except requests.exceptions.ConnectionError:
        return {"result": 1, "text": f"Cannot connect to Kea API at {url}"}
    except requests.exceptions.Timeout:
        return {"result": 1, "text": "Kea API request timed out."}
    except Exception as e:
        return {"result": 1, "text": str(e)}

def kea_command_all(command, service="dhcp4", arguments=None):
    """Send command to ALL configured Kea servers. Returns list of (server, result)."""
    results = []
    for server in KEA_SERVERS:
        result = kea_command(command, service, arguments, server=server)
        results.append((server, result))
    return results

@app.context_processor
def inject_branding():
    avatar_url = None
    if current_user and current_user.is_authenticated:
        try:
            db = get_jen_db()
            with db.cursor() as cur:
                cur.execute("SELECT avatar_url FROM users WHERE id=%s", (current_user.id,))
                row = cur.fetchone()
                if row:
                    avatar_url = row.get("avatar_url")
            db.close()
        except Exception:
            pass
    # Detect nav logo file (any extension)
    nav_logo_url = None
    for ext in ("png", "svg", "jpg", "jpeg", "webp"):
        if os.path.exists(f"{NAV_LOGO_PATH}.{ext}"):
            nav_logo_url = f"/static/nav_logo.{ext}?v={int(os.path.getmtime(f'{NAV_LOGO_PATH}.{ext}'))}"
            break
    return {
        "branding_name": "Jen",
        "branding_nav_color": get_global_setting("branding_nav_color", ""),
        "branding_nav_logo": nav_logo_url,
        "current_user_avatar": avatar_url,
        "jen_version": JEN_VERSION,
    }

def kea_is_up(server=None):
    result = kea_command("version-get", server=server)
    return result.get("result") == 0

def get_all_server_status():
    """Get status of all Kea servers."""
    statuses = []
    for server in KEA_SERVERS:
        up = kea_is_up(server=server)
        ha_state = None
        ha_partner = None
        if up and len(KEA_SERVERS) > 1:
            # Try to get HA status
            ha_result = kea_command("ha-heartbeat", server=server)
            if ha_result.get("result") == 0:
                args = ha_result.get("arguments", {})
                ha_state = args.get("state", "unknown")
                ha_partner = args.get("partner-state", "")
        statuses.append({
            "server": server,
            "up": up,
            "ha_state": ha_state,
            "ha_partner": ha_partner,
        })
    return statuses

_active_server_cache = {"server": None, "ts": 0}

def get_active_kea_server():
    """
    Returns the best server to send commands to.
    For HA setups: returns the server in 'hot-standby' primary role or 'partner-down' state.
    For single server: returns server 1.
    Falls back to first available server.
    Result is cached for 10 seconds to avoid hammering ha-heartbeat on every page load.
    """
    import time
    if len(KEA_SERVERS) == 1:
        return KEA_SERVERS[0]
    # Use cached result if fresh
    now = time.time()
    if _active_server_cache["server"] and (now - _active_server_cache["ts"]) < 10:
        return _active_server_cache["server"]
    # For HA: query ha-heartbeat on each server, prefer the primary in active state
    active_states = ("hot-standby", "load-balancing", "partner-down")
    for server in KEA_SERVERS:
        if not kea_is_up(server=server):
            continue
        ha = kea_command("ha-heartbeat", server=server)
        if ha.get("result") == 0:
            state = ha.get("arguments", {}).get("state", "")
            role = server.get("role", "primary")
            if state in active_states and role == "primary":
                _active_server_cache["server"] = server
                _active_server_cache["ts"] = now
                return server
    # Fallback: return first reachable server
    for server in KEA_SERVERS:
        if kea_is_up(server=server):
            _active_server_cache["server"] = server
            _active_server_cache["ts"] = now
            return server
    return KEA_SERVERS[0]

def format_mac(raw_bytes):
    if not raw_bytes:
        return ""
    return ":".join(f"{b:02x}" for b in raw_bytes)

# ─────────────────────────────────────────
# OUI Device Fingerprinting
# ─────────────────────────────────────────

# (manufacturer, device_type, icon)
# device_type values: apple, android, windows, linux, amazon, iot, tv, printer,
#                     nas, network, voip, gaming, raspberry_pi, unknown
OUI_DB = {
    # Apple
    "00:03:93": ("Apple", "apple", "🍎"), "00:05:02": ("Apple", "apple", "🍎"),
    "00:0a:27": ("Apple", "apple", "🍎"), "00:0a:95": ("Apple", "apple", "🍎"),
    "00:0d:93": ("Apple", "apple", "🍎"), "00:11:24": ("Apple", "apple", "🍎"),
    "00:14:51": ("Apple", "apple", "🍎"), "00:16:cb": ("Apple", "apple", "🍎"),
    "00:17:f2": ("Apple", "apple", "🍎"), "00:19:e3": ("Apple", "apple", "🍎"),
    "00:1b:63": ("Apple", "apple", "🍎"), "00:1c:b3": ("Apple", "apple", "🍎"),
    "00:1d:4f": ("Apple", "apple", "🍎"), "00:1e:52": ("Apple", "apple", "🍎"),
    "00:1e:c2": ("Apple", "apple", "🍎"), "00:1f:5b": ("Apple", "apple", "🍎"),
    "00:1f:f3": ("Apple", "apple", "🍎"), "00:21:e9": ("Apple", "apple", "🍎"),
    "00:22:41": ("Apple", "apple", "🍎"), "00:23:12": ("Apple", "apple", "🍎"),
    "00:23:32": ("Apple", "apple", "🍎"), "00:23:6c": ("Apple", "apple", "🍎"),
    "00:23:df": ("Apple", "apple", "🍎"), "00:24:36": ("Apple", "apple", "🍎"),
    "00:25:00": ("Apple", "apple", "🍎"), "00:25:4b": ("Apple", "apple", "🍎"),
    "00:25:bc": ("Apple", "apple", "🍎"), "00:26:08": ("Apple", "apple", "🍎"),
    "00:26:4a": ("Apple", "apple", "🍎"), "00:26:b0": ("Apple", "apple", "🍎"),
    "00:26:bb": ("Apple", "apple", "🍎"), "00:30:65": ("Apple", "apple", "🍎"),
    "00:3e:e1": ("Apple", "apple", "🍎"), "00:50:e4": ("Apple", "apple", "🍎"),
    "00:56:cd": ("Apple", "apple", "🍎"), "00:61:71": ("Apple", "apple", "🍎"),
    "00:6d:52": ("Apple", "apple", "🍎"), "00:88:65": ("Apple", "apple", "🍎"),
    "04:0c:ce": ("Apple", "apple", "🍎"), "04:15:52": ("Apple", "apple", "🍎"),
    "04:1e:64": ("Apple", "apple", "🍎"), "04:26:65": ("Apple", "apple", "🍎"),
    "04:48:9a": ("Apple", "apple", "🍎"), "04:4b:ed": ("Apple", "apple", "🍎"),
    "04:52:f3": ("Apple", "apple", "🍎"), "04:54:53": ("Apple", "apple", "🍎"),
    "04:69:f8": ("Apple", "apple", "🍎"), "04:d3:cf": ("Apple", "apple", "🍎"),
    "04:e5:36": ("Apple", "apple", "🍎"), "04:f1:3e": ("Apple", "apple", "🍎"),
    "08:00:07": ("Apple", "apple", "🍎"), "08:6d:41": ("Apple", "apple", "🍎"),
    "08:70:45": ("Apple", "apple", "🍎"), "08:74:02": ("Apple", "apple", "🍎"),
    "0c:3e:9f": ("Apple", "apple", "🍎"), "0c:4d:e9": ("Apple", "apple", "🍎"),
    "0c:74:c2": ("Apple", "apple", "🍎"), "0c:77:1a": ("Apple", "apple", "🍎"),
    "0c:bc:9f": ("Apple", "apple", "🍎"), "0c:d7:46": ("Apple", "apple", "🍎"),
    "10:1c:0c": ("Apple", "apple", "🍎"), "10:40:f3": ("Apple", "apple", "🍎"),
    "10:41:7f": ("Apple", "apple", "🍎"), "10:93:e9": ("Apple", "apple", "🍎"),
    "10:9a:dd": ("Apple", "apple", "🍎"), "14:10:9f": ("Apple", "apple", "🍎"),
    "14:20:5e": ("Apple", "apple", "🍎"), "14:5a:05": ("Apple", "apple", "🍎"),
    "14:8f:c6": ("Apple", "apple", "🍎"), "14:99:e2": ("Apple", "apple", "🍎"),
    "18:20:32": ("Apple", "apple", "🍎"), "18:34:51": ("Apple", "apple", "🍎"),
    "18:65:90": ("Apple", "apple", "🍎"), "18:81:0e": ("Apple", "apple", "🍎"),
    "18:9e:fc": ("Apple", "apple", "🍎"), "18:af:61": ("Apple", "apple", "🍎"),
    "18:e7:f4": ("Apple", "apple", "🍎"), "1c:1a:c0": ("Apple", "apple", "🍎"),
    "1c:36:bb": ("Apple", "apple", "🍎"), "1c:91:48": ("Apple", "apple", "🍎"),
    "1c:9e:46": ("Apple", "apple", "🍎"), "20:78:f0": ("Apple", "apple", "🍎"),
    "20:a2:e4": ("Apple", "apple", "🍎"), "20:ab:37": ("Apple", "apple", "🍎"),
    "20:c9:d0": ("Apple", "apple", "🍎"), "24:1e:eb": ("Apple", "apple", "🍎"),
    "24:24:0e": ("Apple", "apple", "🍎"), "24:5b:a7": ("Apple", "apple", "🍎"),
    "24:a0:74": ("Apple", "apple", "🍎"), "24:ab:81": ("Apple", "apple", "🍎"),
    "28:0b:5c": ("Apple", "apple", "🍎"), "28:37:37": ("Apple", "apple", "🍎"),
    "28:6a:b8": ("Apple", "apple", "🍎"), "28:6a:ba": ("Apple", "apple", "🍎"),
    "28:cf:da": ("Apple", "apple", "🍎"), "28:cf:e9": ("Apple", "apple", "🍎"),
    "28:e1:4c": ("Apple", "apple", "🍎"), "2c:1f:23": ("Apple", "apple", "🍎"),
    "2c:20:0b": ("Apple", "apple", "🍎"), "2c:be:08": ("Apple", "apple", "🍎"),
    "2c:f0:a2": ("Apple", "apple", "🍎"), "30:10:e4": ("Apple", "apple", "🍎"),
    "30:35:ad": ("Apple", "apple", "🍎"), "30:63:6b": ("Apple", "apple", "🍎"),
    "30:90:ab": ("Apple", "apple", "🍎"), "34:08:bc": ("Apple", "apple", "🍎"),
    "34:15:9e": ("Apple", "apple", "🍎"), "34:36:3b": ("Apple", "apple", "🍎"),
    "34:51:c9": ("Apple", "apple", "🍎"), "34:c0:59": ("Apple", "apple", "🍎"),
    "38:0f:4a": ("Apple", "apple", "🍎"), "38:48:4c": ("Apple", "apple", "🍎"),
    "38:b5:4d": ("Apple", "apple", "🍎"), "38:ca:da": ("Apple", "apple", "🍎"),
    "3c:07:54": ("Apple", "apple", "🍎"), "3c:15:c2": ("Apple", "apple", "🍎"),
    "3c:2e:f9": ("Apple", "apple", "🍎"), "3c:d0:f8": ("Apple", "apple", "🍎"),
    "40:31:3c": ("Apple", "apple", "🍎"), "40:33:1a": ("Apple", "apple", "🍎"),
    "40:3c:fc": ("Apple", "apple", "🍎"), "40:4d:7f": ("Apple", "apple", "🍎"),
    "40:6c:8f": ("Apple", "apple", "🍎"), "40:83:1d": ("Apple", "apple", "🍎"),
    "40:9c:28": ("Apple", "apple", "🍎"), "40:a6:d9": ("Apple", "apple", "🍎"),
    "40:b3:95": ("Apple", "apple", "🍎"), "40:cb:c0": ("Apple", "apple", "🍎"),
    "40:d3:2d": ("Apple", "apple", "🍎"), "44:00:10": ("Apple", "apple", "🍎"),
    "44:2a:60": ("Apple", "apple", "🍎"), "44:4c:0c": ("Apple", "apple", "🍎"),
    "44:d8:84": ("Apple", "apple", "🍎"), "44:fb:42": ("Apple", "apple", "🍎"),
    "48:43:7c": ("Apple", "apple", "🍎"), "48:60:bc": ("Apple", "apple", "🍎"),
    "48:74:6e": ("Apple", "apple", "🍎"), "48:bf:6b": ("Apple", "apple", "🍎"),
    "48:d7:05": ("Apple", "apple", "🍎"), "4c:32:75": ("Apple", "apple", "🍎"),
    "4c:57:ca": ("Apple", "apple", "🍎"), "4c:74:bf": ("Apple", "apple", "🍎"),
    "4c:7c:5f": ("Apple", "apple", "🍎"), "4c:8d:79": ("Apple", "apple", "🍎"),
    "50:2b:73": ("Apple", "apple", "🍎"), "50:32:75": ("Apple", "apple", "🍎"),
    "50:7a:55": ("Apple", "apple", "🍎"), "50:82:d5": ("Apple", "apple", "🍎"),
    "50:ea:d6": ("Apple", "apple", "🍎"), "54:26:96": ("Apple", "apple", "🍎"),
    "54:33:cb": ("Apple", "apple", "🍎"), "54:4e:90": ("Apple", "apple", "🍎"),
    "54:72:4f": ("Apple", "apple", "🍎"), "54:9f:13": ("Apple", "apple", "🍎"),
    "54:ae:27": ("Apple", "apple", "🍎"), "54:e4:3a": ("Apple", "apple", "🍎"),
    "58:1f:aa": ("Apple", "apple", "🍎"), "58:40:4e": ("Apple", "apple", "🍎"),
    "58:55:ca": ("Apple", "apple", "🍎"), "58:7f:57": ("Apple", "apple", "🍎"),
    "58:b0:35": ("Apple", "apple", "🍎"), "5c:59:48": ("Apple", "apple", "🍎"),
    "5c:95:ae": ("Apple", "apple", "🍎"), "5c:ad:cf": ("Apple", "apple", "🍎"),
    "5c:f9:38": ("Apple", "apple", "🍎"), "60:03:08": ("Apple", "apple", "🍎"),
    "60:33:4b": ("Apple", "apple", "🍎"), "60:69:44": ("Apple", "apple", "🍎"),
    "60:8c:4a": ("Apple", "apple", "🍎"), "60:92:17": ("Apple", "apple", "🍎"),
    "60:c5:47": ("Apple", "apple", "🍎"), "60:d9:c7": ("Apple", "apple", "🍎"),
    "60:f4:45": ("Apple", "apple", "🍎"), "60:f8:1d": ("Apple", "apple", "🍎"),
    "60:fb:42": ("Apple", "apple", "🍎"), "64:20:0c": ("Apple", "apple", "🍎"),
    "64:76:ba": ("Apple", "apple", "🍎"), "64:9a:be": ("Apple", "apple", "🍎"),
    "64:a3:cb": ("Apple", "apple", "🍎"), "64:b9:e8": ("Apple", "apple", "🍎"),
    "68:09:27": ("Apple", "apple", "🍎"), "68:5b:35": ("Apple", "apple", "🍎"),
    "68:64:4b": ("Apple", "apple", "🍎"), "68:96:7b": ("Apple", "apple", "🍎"),
    "68:9c:70": ("Apple", "apple", "🍎"), "68:a8:6d": ("Apple", "apple", "🍎"),
    "68:ab:1e": ("Apple", "apple", "🍎"), "6c:19:c0": ("Apple", "apple", "🍎"),
    "6c:40:08": ("Apple", "apple", "🍎"), "6c:72:20": ("Apple", "apple", "🍎"),
    "6c:94:f8": ("Apple", "apple", "🍎"), "6c:96:cf": ("Apple", "apple", "🍎"),
    "70:11:24": ("Apple", "apple", "🍎"), "70:14:a6": ("Apple", "apple", "🍎"),
    "70:3e:ac": ("Apple", "apple", "🍎"), "70:48:0f": ("Apple", "apple", "🍎"),
    "70:56:81": ("Apple", "apple", "🍎"), "70:73:cb": ("Apple", "apple", "🍎"),
    "70:cd:60": ("Apple", "apple", "🍎"), "70:de:e2": ("Apple", "apple", "🍎"),
    "70:ec:e4": ("Apple", "apple", "🍎"), "74:1b:b2": ("Apple", "apple", "🍎"),
    "74:2f:68": ("Apple", "apple", "🍎"), "74:8d:08": ("Apple", "apple", "🍎"),
    "74:e1:b6": ("Apple", "apple", "🍎"), "78:31:c1": ("Apple", "apple", "🍎"),
    "78:4f:43": ("Apple", "apple", "🍎"), "78:67:d7": ("Apple", "apple", "🍎"),
    "78:7e:61": ("Apple", "apple", "🍎"), "78:9f:70": ("Apple", "apple", "🍎"),
    "78:a3:e4": ("Apple", "apple", "🍎"), "78:ca:39": ("Apple", "apple", "🍎"),
    "78:d7:5f": ("Apple", "apple", "🍎"), "7c:01:91": ("Apple", "apple", "🍎"),
    "7c:04:d0": ("Apple", "apple", "🍎"), "7c:11:be": ("Apple", "apple", "🍎"),
    "7c:6d:62": ("Apple", "apple", "🍎"), "7c:c3:a1": ("Apple", "apple", "🍎"),
    "7c:d1:c3": ("Apple", "apple", "🍎"), "7c:f0:5f": ("Apple", "apple", "🍎"),
    "80:00:6e": ("Apple", "apple", "🍎"), "80:49:71": ("Apple", "apple", "🍎"),
    "80:82:23": ("Apple", "apple", "🍎"), "80:86:f2": ("Apple", "apple", "🍎"),
    "80:be:05": ("Apple", "apple", "🍎"), "80:e6:50": ("Apple", "apple", "🍎"),
    "84:29:99": ("Apple", "apple", "🍎"), "84:38:35": ("Apple", "apple", "🍎"),
    "84:78:8b": ("Apple", "apple", "🍎"), "84:85:06": ("Apple", "apple", "🍎"),
    "84:89:ad": ("Apple", "apple", "🍎"), "84:a1:34": ("Apple", "apple", "🍎"),
    "84:b1:53": ("Apple", "apple", "🍎"), "84:fc:ac": ("Apple", "apple", "🍎"),
    "88:1f:a1": ("Apple", "apple", "🍎"), "88:53:2e": ("Apple", "apple", "🍎"),
    "88:63:df": ("Apple", "apple", "🍎"), "88:66:a5": ("Apple", "apple", "🍎"),
    "88:ae:07": ("Apple", "apple", "🍎"), "88:c6:63": ("Apple", "apple", "🍎"),
    "88:e9:fe": ("Apple", "apple", "🍎"), "8c:00:6d": ("Apple", "apple", "🍎"),
    "8c:29:37": ("Apple", "apple", "🍎"), "8c:2d:aa": ("Apple", "apple", "🍎"),
    "8c:4b:14": ("Apple", "apple", "🍎"), "8c:7b:9d": ("Apple", "apple", "🍎"),
    "8c:85:90": ("Apple", "apple", "🍎"), "8c:8e:f2": ("Apple", "apple", "🍎"),
    "90:27:e4": ("Apple", "apple", "🍎"), "90:3c:92": ("Apple", "apple", "🍎"),
    "90:60:f1": ("Apple", "apple", "🍎"), "90:72:40": ("Apple", "apple", "🍎"),
    "90:84:0d": ("Apple", "apple", "🍎"), "90:8d:6c": ("Apple", "apple", "🍎"),
    "90:b0:ed": ("Apple", "apple", "🍎"), "90:b9:31": ("Apple", "apple", "🍎"),
    "90:c1:c6": ("Apple", "apple", "🍎"), "94:bf:2d": ("Apple", "apple", "🍎"),
    "94:e9:6a": ("Apple", "apple", "🍎"), "94:f6:a3": ("Apple", "apple", "🍎"),
    "98:01:a7": ("Apple", "apple", "🍎"), "98:03:d8": ("Apple", "apple", "🍎"),
    "98:10:e7": ("Apple", "apple", "🍎"), "98:46:0a": ("Apple", "apple", "🍎"),
    "98:9e:63": ("Apple", "apple", "🍎"), "98:d6:bb": ("Apple", "apple", "🍎"),
    "98:e0:d9": ("Apple", "apple", "🍎"), "98:f0:ab": ("Apple", "apple", "🍎"),
    "9c:04:eb": ("Apple", "apple", "🍎"), "9c:20:7b": ("Apple", "apple", "🍎"),
    "9c:29:3f": ("Apple", "apple", "🍎"), "9c:35:eb": ("Apple", "apple", "🍎"),
    "9c:4f:da": ("Apple", "apple", "🍎"), "9c:84:bf": ("Apple", "apple", "🍎"),
    "9c:f3:87": ("Apple", "apple", "🍎"), "a0:11:5e": ("Apple", "apple", "🍎"),
    "a0:3b:e3": ("Apple", "apple", "🍎"), "a0:4e:a7": ("Apple", "apple", "🍎"),
    "a0:99:9b": ("Apple", "apple", "🍎"), "a0:d7:95": ("Apple", "apple", "🍎"),
    "a4:5e:60": ("Apple", "apple", "🍎"), "a4:67:06": ("Apple", "apple", "🍎"),
    "a4:b1:97": ("Apple", "apple", "🍎"), "a4:b8:05": ("Apple", "apple", "🍎"),
    "a4:c3:61": ("Apple", "apple", "🍎"), "a4:d1:8c": ("Apple", "apple", "🍎"),
    "a4:d9:31": ("Apple", "apple", "🍎"), "a4:f1:e8": ("Apple", "apple", "🍎"),
    "a8:20:66": ("Apple", "apple", "🍎"), "a8:51:ab": ("Apple", "apple", "🍎"),
    "a8:5b:78": ("Apple", "apple", "🍎"), "a8:60:b6": ("Apple", "apple", "🍎"),
    "a8:86:dd": ("Apple", "apple", "🍎"), "a8:88:08": ("Apple", "apple", "🍎"),
    "a8:96:8a": ("Apple", "apple", "🍎"), "a8:be:27": ("Apple", "apple", "🍎"),
    "a8:fa:d8": ("Apple", "apple", "🍎"), "ac:1f:74": ("Apple", "apple", "🍎"),
    "ac:29:3a": ("Apple", "apple", "🍎"), "ac:3c:0b": ("Apple", "apple", "🍎"),
    "ac:61:ea": ("Apple", "apple", "🍎"), "ac:7f:3e": ("Apple", "apple", "🍎"),
    "ac:87:a3": ("Apple", "apple", "🍎"), "ac:bc:32": ("Apple", "apple", "🍎"),
    "ac:cf:5c": ("Apple", "apple", "🍎"), "ac:de:48": ("Apple", "apple", "🍎"),
    "ac:e4:b5": ("Apple", "apple", "🍎"), "ac:fd:ec": ("Apple", "apple", "🍎"),
    "b0:19:c6": ("Apple", "apple", "🍎"), "b0:34:95": ("Apple", "apple", "🍎"),
    "b0:65:bd": ("Apple", "apple", "🍎"), "b0:70:2d": ("Apple", "apple", "🍎"),
    "b0:9f:ba": ("Apple", "apple", "🍎"), "b4:18:d1": ("Apple", "apple", "🍎"),
    "b4:4b:d2": ("Apple", "apple", "🍎"), "b4:f0:ab": ("Apple", "apple", "🍎"),
    "b8:08:cf": ("Apple", "apple", "🍎"), "b8:17:c2": ("Apple", "apple", "🍎"),
    "b8:41:a4": ("Apple", "apple", "🍎"), "b8:53:ac": ("Apple", "apple", "🍎"),
    "b8:5d:0a": ("Apple", "apple", "🍎"), "b8:63:4d": ("Apple", "apple", "🍎"),
    "b8:78:2e": ("Apple", "apple", "🍎"), "b8:c7:5d": ("Apple", "apple", "🍎"),
    "b8:e8:56": ("Apple", "apple", "🍎"), "b8:f6:b1": ("Apple", "apple", "🍎"),
    "bc:3b:af": ("Apple", "apple", "🍎"), "bc:52:b7": ("Apple", "apple", "🍎"),
    "bc:54:51": ("Apple", "apple", "🍎"), "bc:67:78": ("Apple", "apple", "🍎"),
    "bc:92:6b": ("Apple", "apple", "🍎"), "bc:9f:ef": ("Apple", "apple", "🍎"),
    "bc:a9:20": ("Apple", "apple", "🍎"), "bc:d1:74": ("Apple", "apple", "🍎"),
    "bc:ec:6d": ("Apple", "apple", "🍎"), "c0:1a:da": ("Apple", "apple", "🍎"),
    "c0:84:7a": ("Apple", "apple", "🍎"), "c0:9f:42": ("Apple", "apple", "🍎"),
    "c0:a5:e8": ("Apple", "apple", "🍎"), "c0:cc:f8": ("Apple", "apple", "🍎"),
    "c0:ce:cd": ("Apple", "apple", "🍎"), "c0:d0:12": ("Apple", "apple", "🍎"),
    "c0:f2:fb": ("Apple", "apple", "🍎"), "c4:2c:03": ("Apple", "apple", "🍎"),
    "c4:61:8b": ("Apple", "apple", "🍎"), "c4:b3:01": ("Apple", "apple", "🍎"),
    "c8:1e:e7": ("Apple", "apple", "🍎"), "c8:2a:14": ("Apple", "apple", "🍎"),
    "c8:33:4b": ("Apple", "apple", "🍎"), "c8:3c:85": ("Apple", "apple", "🍎"),
    "c8:6f:1d": ("Apple", "apple", "🍎"), "c8:85:50": ("Apple", "apple", "🍎"),
    "c8:bc:c8": ("Apple", "apple", "🍎"), "c8:d0:83": ("Apple", "apple", "🍎"),
    "c8:e0:eb": ("Apple", "apple", "🍎"), "c8:f6:50": ("Apple", "apple", "🍎"),
    "cc:08:8d": ("Apple", "apple", "🍎"), "cc:20:e8": ("Apple", "apple", "🍎"),
    "cc:25:ef": ("Apple", "apple", "🍎"), "cc:29:f5": ("Apple", "apple", "🍎"),
    "cc:44:63": ("Apple", "apple", "🍎"), "cc:78:ab": ("Apple", "apple", "🍎"),
    "cc:c7:60": ("Apple", "apple", "🍎"), "d0:03:4b": ("Apple", "apple", "🍎"),
    "d0:23:db": ("Apple", "apple", "🍎"), "d0:25:98": ("Apple", "apple", "🍎"),
    "d0:4f:7e": ("Apple", "apple", "🍎"), "d0:81:7a": ("Apple", "apple", "🍎"),
    "d0:a6:37": ("Apple", "apple", "🍎"), "d0:c5:f3": ("Apple", "apple", "🍎"),
    "d0:e1:40": ("Apple", "apple", "🍎"), "d4:61:9d": ("Apple", "apple", "🍎"),
    "d4:90:9c": ("Apple", "apple", "🍎"), "d4:9a:20": ("Apple", "apple", "🍎"),
    "d4:dc:cd": ("Apple", "apple", "🍎"), "d4:f4:6f": ("Apple", "apple", "🍎"),
    "d8:1d:72": ("Apple", "apple", "🍎"), "d8:30:62": ("Apple", "apple", "🍎"),
    "d8:96:95": ("Apple", "apple", "🍎"), "d8:9e:3f": ("Apple", "apple", "🍎"),
    "d8:bb:2c": ("Apple", "apple", "🍎"), "d8:cf:9c": ("Apple", "apple", "🍎"),
    "dc:0c:5c": ("Apple", "apple", "🍎"), "dc:2b:2a": ("Apple", "apple", "🍎"),
    "dc:37:14": ("Apple", "apple", "🍎"), "dc:41:5f": ("Apple", "apple", "🍎"),
    "dc:56:e7": ("Apple", "apple", "🍎"), "dc:86:d8": ("Apple", "apple", "🍎"),
    "dc:9b:9c": ("Apple", "apple", "🍎"), "dc:a4:ca": ("Apple", "apple", "🍎"),
    "dc:a9:04": ("Apple", "apple", "🍎"), "e0:66:78": ("Apple", "apple", "🍎"),
    "e0:ac:cb": ("Apple", "apple", "🍎"), "e0:b5:2d": ("Apple", "apple", "🍎"),
    "e0:f5:c6": ("Apple", "apple", "🍎"), "e4:25:e7": ("Apple", "apple", "🍎"),
    "e4:40:e2": ("Apple", "apple", "🍎"), "e4:50:eb": ("Apple", "apple", "🍎"),
    "e4:8b:7f": ("Apple", "apple", "🍎"), "e4:9a:79": ("Apple", "apple", "🍎"),
    "e4:c6:3d": ("Apple", "apple", "🍎"), "e4:ce:8f": ("Apple", "apple", "🍎"),
    "e4:e0:a6": ("Apple", "apple", "🍎"), "e8:04:0b": ("Apple", "apple", "🍎"),
    "e8:06:88": ("Apple", "apple", "🍎"), "e8:80:2e": ("Apple", "apple", "🍎"),
    "e8:8d:28": ("Apple", "apple", "🍎"), "ec:35:86": ("Apple", "apple", "🍎"),
    "ec:85:2f": ("Apple", "apple", "🍎"), "f0:18:98": ("Apple", "apple", "🍎"),
    "f0:24:75": ("Apple", "apple", "🍎"), "f0:5c:19": ("Apple", "apple", "🍎"),
    "f0:6d:3b": ("Apple", "apple", "🍎"), "f0:79:60": ("Apple", "apple", "🍎"),
    "f0:99:bf": ("Apple", "apple", "🍎"), "f0:b4:79": ("Apple", "apple", "🍎"),
    "f0:c1:f1": ("Apple", "apple", "🍎"), "f0:cb:a1": ("Apple", "apple", "🍎"),
    "f0:d1:a9": ("Apple", "apple", "🍎"), "f0:db:e2": ("Apple", "apple", "🍎"),
    "f0:dc:e2": ("Apple", "apple", "🍎"), "f0:f6:1c": ("Apple", "apple", "🍎"),
    "f4:0f:24": ("Apple", "apple", "🍎"), "f4:1b:a1": ("Apple", "apple", "🍎"),
    "f4:37:b7": ("Apple", "apple", "🍎"), "f4:5c:89": ("Apple", "apple", "🍎"),
    "f4:f1:5a": ("Apple", "apple", "🍎"), "f8:1e:df": ("Apple", "apple", "🍎"),
    "f8:27:93": ("Apple", "apple", "🍎"), "f8:38:80": ("Apple", "apple", "🍎"),
    "f8:62:14": ("Apple", "apple", "🍎"), "f8:87:f1": ("Apple", "apple", "🍎"),
    "fc:25:3f": ("Apple", "apple", "🍎"), "fc:e9:98": ("Apple", "apple", "🍎"),

    # Samsung
    "00:00:f0": ("Samsung", "android", "📱"), "00:02:78": ("Samsung", "android", "📱"),
    "00:07:ab": ("Samsung", "android", "📱"), "00:12:47": ("Samsung", "android", "📱"),
    "00:12:fb": ("Samsung", "android", "📱"), "00:13:77": ("Samsung", "android", "📱"),
    "00:15:b9": ("Samsung", "android", "📱"), "00:16:32": ("Samsung", "android", "📱"),
    "00:16:db": ("Samsung", "android", "📱"), "00:17:c9": ("Samsung", "android", "📱"),
    "00:17:d5": ("Samsung", "android", "📱"), "00:18:af": ("Samsung", "android", "📱"),
    "00:1a:8a": ("Samsung", "android", "📱"), "00:1b:98": ("Samsung", "android", "📱"),
    "00:1c:43": ("Samsung", "android", "📱"), "00:1d:25": ("Samsung", "android", "📱"),
    "00:1e:7d": ("Samsung", "android", "📱"), "00:1f:cc": ("Samsung", "android", "📱"),
    "00:21:19": ("Samsung", "android", "📱"), "00:23:39": ("Samsung", "android", "📱"),
    "00:23:99": ("Samsung", "android", "📱"), "00:24:54": ("Samsung", "android", "📱"),
    "00:24:91": ("Samsung", "android", "📱"), "00:25:66": ("Samsung", "android", "📱"),
    "00:26:37": ("Samsung", "android", "📱"), "00:e3:b2": ("Samsung", "android", "📱"),
    "04:18:d6": ("Samsung", "android", "📱"), "04:b1:67": ("Samsung", "android", "📱"),
    "04:fe:31": ("Samsung", "android", "📱"), "08:08:c2": ("Samsung", "android", "📱"),
    "08:37:3d": ("Samsung", "android", "📱"), "08:d4:0c": ("Samsung", "android", "📱"),
    "08:fc:88": ("Samsung", "android", "📱"), "0c:14:20": ("Samsung", "android", "📱"),
    "0c:71:5d": ("Samsung", "android", "📱"), "0c:89:10": ("Samsung", "android", "📱"),
    "10:1d:c0": ("Samsung", "android", "📱"), "10:30:47": ("Samsung", "android", "📱"),
    "10:d5:42": ("Samsung", "android", "📱"), "14:49:e0": ("Samsung", "android", "📱"),
    "14:bb:6e": ("Samsung", "android", "📱"), "18:3a:2d": ("Samsung", "android", "📱"),
    "18:46:17": ("Samsung", "android", "📱"), "1c:62:b8": ("Samsung", "android", "📱"),
    "1c:66:aa": ("Samsung", "android", "📱"), "20:13:e0": ("Samsung", "android", "📱"),
    "20:6e:9c": ("Samsung", "android", "📱"), "24:4b:03": ("Samsung", "android", "📱"),
    "24:4e:7b": ("Samsung", "android", "📱"), "24:c6:96": ("Samsung", "android", "📱"),
    "28:27:bf": ("Samsung", "android", "📱"), "28:39:26": ("Samsung", "android", "📱"),
    "28:ba:b5": ("Samsung", "android", "📱"), "28:cc:01": ("Samsung", "android", "📱"),
    "2c:ae:2b": ("Samsung", "android", "📱"), "30:07:4d": ("Samsung", "android", "📱"),
    "30:19:66": ("Samsung", "android", "📱"), "30:cd:a7": ("Samsung", "android", "📱"),
    "34:14:5f": ("Samsung", "android", "📱"), "34:23:ba": ("Samsung", "android", "📱"),
    "34:31:11": ("Samsung", "android", "📱"), "34:aa:8b": ("Samsung", "android", "📱"),
    "34:be:00": ("Samsung", "android", "📱"), "34:c3:ac": ("Samsung", "android", "📱"),
    "38:01:97": ("Samsung", "android", "📱"), "38:0a:94": ("Samsung", "android", "📱"),
    "38:16:d1": ("Samsung", "android", "📱"), "3c:5a:37": ("Samsung", "android", "📱"),
    "3c:62:00": ("Samsung", "android", "📱"), "3c:8b:fe": ("Samsung", "android", "📱"),
    "40:0e:85": ("Samsung", "android", "📱"), "40:16:7e": ("Samsung", "android", "📱"),
    "44:4e:1a": ("Samsung", "android", "📱"), "44:78:3e": ("Samsung", "android", "📱"),
    "48:44:f7": ("Samsung", "android", "📱"), "48:5a:3f": ("Samsung", "android", "📱"),
    "4c:3c:16": ("Samsung", "android", "📱"), "4c:bc:98": ("Samsung", "android", "📱"),
    "50:01:bb": ("Samsung", "android", "📱"), "50:32:37": ("Samsung", "android", "📱"),
    "50:85:69": ("Samsung", "android", "📱"), "50:a4:c8": ("Samsung", "android", "📱"),
    "50:b7:c3": ("Samsung", "android", "📱"), "54:40:ad": ("Samsung", "android", "📱"),
    "54:88:0e": ("Samsung", "android", "📱"), "58:ef:68": ("Samsung", "android", "📱"),
    "5c:a3:9d": ("Samsung", "android", "📱"), "5c:e8:eb": ("Samsung", "android", "📱"),
    "5c:f6:dc": ("Samsung", "android", "📱"), "60:6b:bd": ("Samsung", "android", "📱"),
    "60:d0:a9": ("Samsung", "android", "📱"), "64:77:91": ("Samsung", "android", "📱"),
    "68:27:37": ("Samsung", "android", "📱"), "68:48:98": ("Samsung", "android", "📱"),
    "6c:2f:2c": ("Samsung", "android", "📱"), "6c:83:36": ("Samsung", "android", "📱"),
    "70:2c:1f": ("Samsung", "android", "📱"), "70:f9:27": ("Samsung", "android", "📱"),
    "78:1f:db": ("Samsung", "android", "📱"), "78:25:ad": ("Samsung", "android", "📱"),
    "78:40:e4": ("Samsung", "android", "📱"), "7c:1c:4e": ("Samsung", "android", "📱"),
    "7c:64:56": ("Samsung", "android", "📱"), "80:65:6d": ("Samsung", "android", "📱"),
    "84:11:9e": ("Samsung", "android", "📱"), "84:25:db": ("Samsung", "android", "📱"),
    "84:38:38": ("Samsung", "android", "📱"), "84:55:a5": ("Samsung", "android", "📱"),
    "88:32:9b": ("Samsung", "android", "📱"), "88:9b:39": ("Samsung", "android", "📱"),
    "8c:1a:bf": ("Samsung", "android", "📱"), "8c:71:f8": ("Samsung", "android", "📱"),
    "8c:77:12": ("Samsung", "android", "📱"), "90:18:7c": ("Samsung", "android", "📱"),
    "94:35:0a": ("Samsung", "android", "📱"), "94:51:03": ("Samsung", "android", "📱"),
    "94:76:b7": ("Samsung", "android", "📱"), "98:0c:82": ("Samsung", "android", "📱"),
    "9c:02:98": ("Samsung", "android", "📱"), "9c:3a:af": ("Samsung", "android", "📱"),
    "a0:07:98": ("Samsung", "android", "📱"), "a0:0b:ba": ("Samsung", "android", "📱"),
    "a0:21:95": ("Samsung", "android", "📱"), "a0:75:91": ("Samsung", "android", "📱"),
    "a4:eb:d3": ("Samsung", "android", "📱"), "a8:06:00": ("Samsung", "android", "📱"),
    "a8:7d:12": ("Samsung", "android", "📱"), "ac:36:13": ("Samsung", "android", "📱"),
    "ac:5f:3e": ("Samsung", "android", "📱"), "b0:ec:71": ("Samsung", "android", "📱"),
    "b4:3a:28": ("Samsung", "android", "📱"), "b4:62:93": ("Samsung", "android", "📱"),
    "b4:79:a7": ("Samsung", "android", "📱"), "b8:5e:7b": ("Samsung", "android", "📱"),
    "bc:14:85": ("Samsung", "android", "📱"), "bc:20:a4": ("Samsung", "android", "📱"),
    "bc:72:b1": ("Samsung", "android", "📱"), "bc:85:1f": ("Samsung", "android", "📱"),
    "bc:8c:cd": ("Samsung", "android", "📱"), "c0:bd:d1": ("Samsung", "android", "📱"),
    "c4:42:02": ("Samsung", "android", "📱"), "c4:57:6e": ("Samsung", "android", "📱"),
    "c4:62:ea": ("Samsung", "android", "📱"), "c4:73:1e": ("Samsung", "android", "📱"),
    "c8:19:f7": ("Samsung", "android", "📱"), "c8:ba:94": ("Samsung", "android", "📱"),
    "cc:07:ab": ("Samsung", "android", "📱"), "d0:17:6a": ("Samsung", "android", "📱"),
    "d0:22:be": ("Samsung", "android", "📱"), "d0:59:e4": ("Samsung", "android", "📱"),
    "d0:87:e2": ("Samsung", "android", "📱"), "d4:88:90": ("Samsung", "android", "📱"),
    "d4:e8:b2": ("Samsung", "android", "📱"), "d8:57:ef": ("Samsung", "android", "📱"),
    "d8:e0:e1": ("Samsung", "android", "📱"), "dc:71:96": ("Samsung", "android", "📱"),
    "e4:32:cb": ("Samsung", "android", "📱"), "e4:40:e2": ("Samsung", "android", "📱"),
    "e4:92:fb": ("Samsung", "android", "📱"), "e8:03:9a": ("Samsung", "android", "📱"),
    "e8:39:df": ("Samsung", "android", "📱"), "e8:50:8b": ("Samsung", "android", "📱"),
    "ec:1f:72": ("Samsung", "android", "📱"), "ec:9b:f3": ("Samsung", "android", "📱"),
    "f0:25:b7": ("Samsung", "android", "📱"), "f0:5a:09": ("Samsung", "android", "📱"),
    "f0:72:ea": ("Samsung", "android", "📱"), "f4:42:8f": ("Samsung", "android", "📱"),
    "f4:7b:5e": ("Samsung", "android", "📱"), "f4:9f:54": ("Samsung", "android", "📱"),
    "f8:04:2e": ("Samsung", "android", "📱"), "f8:77:b8": ("Samsung", "android", "📱"),
    "fc:00:12": ("Samsung", "android", "📱"), "fc:a1:3e": ("Samsung", "android", "📱"),

    # Amazon
    "00:bb:3a": ("Amazon", "amazon", "📦"), "0c:47:c9": ("Amazon", "amazon", "📦"),
    "0c:54:a5": ("Amazon", "amazon", "📦"), "10:ae:60": ("Amazon", "amazon", "📦"),
    "18:74:2e": ("Amazon", "amazon", "📦"), "1c:12:b0": ("Amazon", "amazon", "📦"),
    "34:d2:70": ("Amazon", "amazon", "📦"), "38:f7:3d": ("Amazon", "amazon", "📦"),
    "40:b4:cd": ("Amazon", "amazon", "📦"), "44:65:0d": ("Amazon", "amazon", "📦"),
    "44:61:32": ("Amazon", "amazon", "📦"), "48:23:35": ("Amazon", "amazon", "📦"),
    "4c:ef:c0": ("Amazon", "amazon", "📦"), "50:dc:e7": ("Amazon", "amazon", "📦"),
    "54:75:d0": ("Amazon", "amazon", "📦"), "68:37:e9": ("Amazon", "amazon", "📦"),
    "6c:56:97": ("Amazon", "amazon", "📦"), "74:c2:46": ("Amazon", "amazon", "📦"),
    "78:e1:03": ("Amazon", "amazon", "📦"), "84:d6:d0": ("Amazon", "amazon", "📦"),
    "88:71:e5": ("Amazon", "amazon", "📦"), "8c:49:62": ("Amazon", "amazon", "📦"),
    "a0:02:dc": ("Amazon", "amazon", "📦"), "ac:63:be": ("Amazon", "amazon", "📦"),
    "b4:7c:59": ("Amazon", "amazon", "📦"), "b8:27:eb": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "bc:ff:4d": ("Amazon", "amazon", "📦"), "c0:ee:fb": ("Amazon", "amazon", "📦"),
    "d4:f5:47": ("Amazon", "amazon", "📦"), "e8:9d:87": ("Amazon", "amazon", "📦"),
    "f0:27:2d": ("Amazon", "amazon", "📦"), "f0:81:73": ("Amazon", "amazon", "📦"),
    "f0:a2:25": ("Amazon", "amazon", "📦"), "fc:65:de": ("Amazon", "amazon", "📦"),
    "fc:a6:67": ("Amazon", "amazon", "📦"),

    # Raspberry Pi
    "b8:27:eb": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "dc:a6:32": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "e4:5f:01": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "28:cd:c1": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "2c:cf:67": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "d8:3a:dd": ("Raspberry Pi", "raspberry_pi", "🥧"),

    # Google
    "00:1a:11": ("Google", "google", "🔍"), "08:9e:08": ("Google", "google", "🔍"),
    "10:9a:dd": ("Google", "google", "🔍"), "1c:f2:9a": ("Google", "google", "🔍"),
    "20:df:b9": ("Google", "google", "🔍"), "48:d6:d5": ("Google", "google", "🔍"),
    "50:dc:e7": ("Google", "google", "🔍"), "54:60:09": ("Google", "google", "🔍"),
    "6c:ad:f8": ("Google", "google", "🔍"), "80:7d:3a": ("Google", "google", "🔍"),
    "94:eb:2c": ("Google", "google", "🔍"), "a4:77:33": ("Google", "google", "🔍"),
    "ac:37:43": ("Google", "google", "🔍"), "d4:f5:47": ("Google", "google", "🔍"),
    "f4:f5:d8": ("Google", "google", "🔍"), "f8:8f:ca": ("Google", "google", "🔍"),
    "00:1a:11": ("Google", "google", "🔍"),

    # Meross
    "48:e1:e9": ("Meross", "iot", "🔌"), "34:29:12": ("Meross", "iot", "🔌"),
    "0c:dc:7e": ("Meross", "iot", "🔌"),

    # TP-Link / Kasa
    "00:1d:0f": ("TP-Link", "iot", "🔌"), "10:fe:ed": ("TP-Link", "iot", "🔌"),
    "14:cc:20": ("TP-Link", "iot", "🔌"), "18:a6:f7": ("TP-Link", "iot", "🔌"),
    "1c:61:b4": ("TP-Link", "iot", "🔌"), "24:69:68": ("TP-Link", "iot", "🔌"),
    "2c:fd:a1": ("TP-Link", "iot", "🔌"), "30:b5:c2": ("TP-Link", "iot", "🔌"),
    "38:10:d5": ("TP-Link", "iot", "🔌"), "3c:84:6a": ("TP-Link", "iot", "🔌"),
    "44:94:fc": ("TP-Link", "iot", "🔌"), "50:3e:aa": ("TP-Link", "iot", "🔌"),
    "54:af:97": ("TP-Link", "iot", "🔌"), "60:32:b1": ("TP-Link", "iot", "🔌"),
    "64:70:02": ("TP-Link", "iot", "🔌"), "6c:5a:b0": ("TP-Link", "iot", "🔌"),
    "70:4f:57": ("TP-Link", "iot", "🔌"), "74:da:38": ("TP-Link", "iot", "🔌"),
    "78:8c:b5": ("TP-Link", "iot", "🔌"), "7c:8b:ca": ("TP-Link", "iot", "🔌"),
    "80:8f:1d": ("TP-Link", "iot", "🔌"), "84:16:f9": ("TP-Link", "iot", "🔌"),
    "90:9a:4a": ("TP-Link", "iot", "🔌"), "98:da:c4": ("TP-Link", "iot", "🔌"),
    "a0:f3:c1": ("TP-Link", "iot", "🔌"), "ac:84:c6": ("TP-Link", "iot", "🔌"),
    "b0:48:7a": ("TP-Link", "iot", "🔌"), "b4:b0:24": ("TP-Link", "iot", "🔌"),
    "b8:27:eb": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "bc:46:99": ("TP-Link", "iot", "🔌"), "c0:06:c3": ("TP-Link", "iot", "🔌"),
    "c4:e9:84": ("TP-Link", "iot", "🔌"), "d8:07:b6": ("TP-Link", "iot", "🔌"),
    "e8:de:27": ("TP-Link", "iot", "🔌"), "ec:08:6b": ("TP-Link", "iot", "🔌"),
    "f4:ec:38": ("TP-Link", "iot", "🔌"), "f8:1a:67": ("TP-Link", "iot", "🔌"),
    "fc:ec:da": ("TP-Link", "iot", "🔌"),

    # Espressif (ESP8266/ESP32 — DIY IoT, ESPHome, Tasmota)
    "10:52:1c": ("Espressif", "iot", "🔌"), "18:fe:34": ("Espressif", "iot", "🔌"),
    "24:0a:c4": ("Espressif", "iot", "🔌"), "24:6f:28": ("Espressif", "iot", "🔌"),
    "2c:f4:32": ("Espressif", "iot", "🔌"), "30:ae:a4": ("Espressif", "iot", "🔌"),
    "34:86:5d": ("Espressif", "iot", "🔌"), "3c:61:05": ("Espressif", "iot", "🔌"),
    "3c:71:bf": ("Espressif", "iot", "🔌"), "40:f5:20": ("Espressif", "iot", "🔌"),
    "48:3f:da": ("Espressif", "iot", "🔌"), "4c:11:ae": ("Espressif", "iot", "🔌"),
    "4c:75:25": ("Espressif", "iot", "🔌"), "50:02:91": ("Espressif", "iot", "🔌"),
    "54:43:54": ("Espressif", "iot", "🔌"), "58:bf:25": ("Espressif", "iot", "🔌"),
    "5c:cf:7f": ("Espressif", "iot", "🔌"), "60:01:94": ("Espressif", "iot", "🔌"),
    "68:c6:3a": ("Espressif", "iot", "🔌"), "70:03:9f": ("Espressif", "iot", "🔌"),
    "78:21:84": ("Espressif", "iot", "🔌"), "7c:87:ce": ("Espressif", "iot", "🔌"),
    "84:0d:8e": ("Espressif", "iot", "🔌"), "84:cc:a8": ("Espressif", "iot", "🔌"),
    "84:f3:eb": ("Espressif", "iot", "🔌"), "8c:aa:b5": ("Espressif", "iot", "🔌"),
    "90:97:d5": ("Espressif", "iot", "🔌"), "94:3c:c6": ("Espressif", "iot", "🔌"),
    "98:f4:ab": ("Espressif", "iot", "🔌"), "a0:20:a6": ("Espressif", "iot", "🔌"),
    "a4:7b:9d": ("Espressif", "iot", "🔌"), "a4:cf:12": ("Espressif", "iot", "🔌"),
    "a4:e5:7c": ("Espressif", "iot", "🔌"), "ac:67:b2": ("Espressif", "iot", "🔌"),
    "b4:e6:2d": ("Espressif", "iot", "🔌"), "bc:dd:c2": ("Espressif", "iot", "🔌"),
    "c4:4f:33": ("Espressif", "iot", "🔌"), "c8:2b:96": ("Espressif", "iot", "🔌"),
    "cc:50:e3": ("Espressif", "iot", "🔌"), "d4:8a:fc": ("Espressif", "iot", "🔌"),
    "d8:a0:1d": ("Espressif", "iot", "🔌"), "dc:06:75": ("Espressif", "iot", "🔌"),
    "dc:4f:22": ("Espressif", "iot", "🔌"), "e0:98:06": ("Espressif", "iot", "🔌"),
    "e4:83:26": ("Espressif", "iot", "🔌"), "e8:06:90": ("Espressif", "iot", "🔌"),
    "e8:db:84": ("Espressif", "iot", "🔌"), "ec:62:60": ("Espressif", "iot", "🔌"),
    "ec:fa:bc": ("Espressif", "iot", "🔌"), "f0:08:d1": ("Espressif", "iot", "🔌"),
    "f4:cf:a2": ("Espressif", "iot", "🔌"), "fc:f5:c4": ("Espressif", "iot", "🔌"),

    # Roku (additional OUIs)
    "50:06:f5": ("Roku", "tv", "📺"), "cc:fd:f7": ("Roku", "tv", "📺"),
    "ac:ae:19": ("Roku", "tv", "📺"), "b0:a7:37": ("Roku", "tv", "📺"),
    "08:05:81": ("Roku", "tv", "📺"), "d8:31:34": ("Roku", "tv", "📺"),

    # Amazon Echo/Echo Show (additional OUIs)
    "50:d4:5c": ("Amazon", "amazon", "📦"), "b0:8b:a8": ("Amazon", "amazon", "📦"),
    "f0:d2:f1": ("Amazon", "amazon", "📦"), "74:c2:46": ("Amazon", "amazon", "📦"),
    "44:65:0d": ("Amazon", "amazon", "📦"), "a4:08:f5": ("Amazon", "amazon", "📦"),
    "cc:9e:a2": ("Amazon", "amazon", "📦"), "40:b4:cd": ("Amazon", "amazon", "📦"),
    "34:d2:70": ("Amazon", "amazon", "📦"), "ac:63:be": ("Amazon", "amazon", "📦"),

    # Ring
    "00:62:6e": ("Ring", "iot", "🔔"), "24:2f:d0": ("Ring", "iot", "🔔"),
    "34:f6:4b": ("Ring", "iot", "🔔"), "a4:da:32": ("Ring", "iot", "🔔"),
    "18:7f:88": ("Ring", "iot", "🔔"), "fc:99:47": ("Ring", "iot", "🔔"),

    # Ecobee
    "44:61:32": ("Amazon/Ecobee", "iot", "🌡️"), "bc:ae:c5": ("Ecobee", "iot", "🌡️"),
    "54:4a:16": ("Ecobee", "iot", "🌡️"),

    # Sonos
    "00:0e:58": ("Sonos", "iot", "🔊"), "34:7e:5c": ("Sonos", "iot", "🔊"),
    "48:a6:b8": ("Sonos", "iot", "🔊"), "54:2a:1b": ("Sonos", "iot", "🔊"),
    "58:6d:8f": ("Sonos", "iot", "🔊"), "5c:aa:fd": ("Sonos", "iot", "🔊"),
    "78:28:ca": ("Sonos", "iot", "🔊"), "94:9f:3e": ("Sonos", "iot", "🔊"),
    "b8:e9:37": ("Sonos", "iot", "🔊"),

    # Nest/Google Nest
    "18:b4:30": ("Nest", "iot", "🌡️"), "64:16:66": ("Nest", "iot", "🌡️"),
    "d4:f5:47": ("Nest", "iot", "🌡️"),

    # Ubiquiti
    "00:15:6d": ("Ubiquiti", "network", "🌐"), "00:27:22": ("Ubiquiti", "network", "🌐"),
    "04:18:d6": ("Ubiquiti", "network", "🌐"), "0c:e2:1a": ("Ubiquiti", "network", "🌐"),
    "18:e8:29": ("Ubiquiti", "network", "🌐"), "24:a4:3c": ("Ubiquiti", "network", "🌐"),
    "24:a4:3c": ("Ubiquiti", "network", "🌐"), "44:d9:e7": ("Ubiquiti", "network", "🌐"),
    "48:2c:a0": ("Ubiquiti", "network", "🌐"), "60:22:32": ("Ubiquiti", "network", "🌐"),
    "68:d7:9a": ("Ubiquiti", "network", "🌐"), "6a:f1:8f": ("Ubiquiti", "network", "🌐"),
    "74:83:c2": ("Ubiquiti", "network", "🌐"), "78:8a:20": ("Ubiquiti", "network", "🌐"),
    "80:2a:a8": ("Ubiquiti", "network", "🌐"), "9c:05:d6": ("Ubiquiti", "network", "🌐"),
    "a4:4e:31": ("Ubiquiti", "network", "🌐"), "ac:8b:a9": ("Ubiquiti", "network", "🌐"),
    "b4:fb:e4": ("Ubiquiti", "network", "🌐"), "dc:9f:db": ("Ubiquiti", "network", "🌐"),
    "e0:63:da": ("Ubiquiti", "network", "🌐"), "e4:38:83": ("Ubiquiti", "network", "🌐"),
    "f0:9f:c2": ("Ubiquiti", "network", "🌐"), "fc:ec:da": ("Ubiquiti", "network", "🌐"),

    # Cisco
    "00:00:0c": ("Cisco", "network", "🌐"), "00:01:42": ("Cisco", "network", "🌐"),
    "00:01:64": ("Cisco", "network", "🌐"), "00:01:96": ("Cisco", "network", "🌐"),
    "00:01:c7": ("Cisco", "network", "🌐"), "00:02:17": ("Cisco", "network", "🌐"),
    "00:04:c0": ("Cisco", "network", "🌐"), "00:05:00": ("Cisco", "network", "🌐"),
    "00:06:7c": ("Cisco", "network", "🌐"), "00:07:50": ("Cisco", "network", "🌐"),
    "00:08:a3": ("Cisco", "network", "🌐"), "00:09:b7": ("Cisco", "network", "🌐"),
    "00:0a:41": ("Cisco", "network", "🌐"), "00:0a:8a": ("Cisco", "network", "🌐"),
    "00:0b:46": ("Cisco", "network", "🌐"), "00:0c:85": ("Cisco", "network", "🌐"),
    "00:0d:28": ("Cisco", "network", "🌐"), "00:0d:bc": ("Cisco", "network", "🌐"),
    "00:0e:08": ("Cisco", "network", "🌐"), "00:0e:38": ("Cisco", "network", "🌐"),
    "00:0f:23": ("Cisco", "network", "🌐"), "00:0f:8f": ("Cisco", "network", "🌐"),
    "00:0f:f7": ("Cisco", "network", "🌐"), "00:10:07": ("Cisco", "network", "🌐"),
    "00:10:79": ("Cisco", "network", "🌐"), "00:10:f6": ("Cisco", "network", "🌐"),
    "00:11:5c": ("Cisco", "network", "🌐"), "00:11:92": ("Cisco", "network", "🌐"),
    "00:12:00": ("Cisco", "network", "🌐"), "00:12:43": ("Cisco", "network", "🌐"),
    "00:12:7f": ("Cisco", "network", "🌐"), "00:13:10": ("Cisco", "network", "🌐"),
    "00:13:5f": ("Cisco", "network", "🌐"), "00:13:c3": ("Cisco", "network", "🌐"),
    "00:14:1b": ("Cisco", "network", "🌐"), "00:14:69": ("Cisco", "network", "🌐"),
    "00:14:a9": ("Cisco", "network", "🌐"), "00:14:f1": ("Cisco", "network", "🌐"),
    "00:15:2b": ("Cisco", "network", "🌐"), "00:15:63": ("Cisco", "network", "🌐"),
    "00:16:46": ("Cisco", "network", "🌐"), "00:16:9d": ("Cisco", "network", "🌐"),
    "00:16:c7": ("Cisco", "network", "🌐"), "00:17:0e": ("Cisco", "network", "🌐"),
    "00:17:59": ("Cisco", "network", "🌐"), "00:17:94": ("Cisco", "network", "🌐"),
    "00:17:df": ("Cisco", "network", "🌐"), "00:18:19": ("Cisco", "network", "🌐"),
    "00:18:b9": ("Cisco", "network", "🌐"), "00:19:06": ("Cisco", "network", "🌐"),
    "00:19:2f": ("Cisco", "network", "🌐"), "00:19:55": ("Cisco", "network", "🌐"),
    "00:19:a9": ("Cisco", "network", "🌐"), "00:1a:2f": ("Cisco", "network", "🌐"),
    "00:1a:6c": ("Cisco", "network", "🌐"), "00:1a:a1": ("Cisco", "network", "🌐"),
    "00:1b:0c": ("Cisco", "network", "🌐"), "00:1b:2a": ("Cisco", "network", "🌐"),
    "00:1b:54": ("Cisco", "network", "🌐"), "00:1b:8f": ("Cisco", "network", "🌐"),
    "00:1b:d5": ("Cisco", "network", "🌐"), "00:1c:10": ("Cisco", "network", "🌐"),
    "00:1c:57": ("Cisco", "network", "🌐"), "00:1c:b0": ("Cisco", "network", "🌐"),
    "00:1c:f6": ("Cisco", "network", "🌐"), "00:1d:45": ("Cisco", "network", "🌐"),
    "00:1d:70": ("Cisco", "network", "🌐"), "00:1d:a1": ("Cisco", "network", "🌐"),
    "00:1d:e5": ("Cisco", "network", "🌐"), "00:1e:13": ("Cisco", "network", "🌐"),
    "00:1e:49": ("Cisco", "network", "🌐"), "00:1e:6b": ("Cisco", "network", "🌐"),
    "00:1e:be": ("Cisco", "network", "🌐"), "00:1e:f7": ("Cisco", "network", "🌐"),
    "00:1f:27": ("Cisco", "network", "🌐"), "00:1f:6c": ("Cisco", "network", "🌐"),
    "00:1f:9e": ("Cisco", "network", "🌐"), "00:1f:ca": ("Cisco", "network", "🌐"),
    "00:20:35": ("Cisco", "network", "🌐"), "00:21:1b": ("Cisco", "network", "🌐"),
    "00:21:55": ("Cisco", "network", "🌐"), "00:21:a0": ("Cisco", "network", "🌐"),
    "00:22:0c": ("Cisco", "network", "🌐"), "00:22:55": ("Cisco", "network", "🌐"),
    "00:22:90": ("Cisco", "network", "🌐"), "00:22:bd": ("Cisco", "network", "🌐"),
    "00:23:04": ("Cisco", "network", "🌐"), "00:23:33": ("Cisco", "network", "🌐"),
    "00:23:5e": ("Cisco", "network", "🌐"), "00:23:ac": ("Cisco", "network", "🌐"),
    "00:23:eb": ("Cisco", "network", "🌐"), "00:24:13": ("Cisco", "network", "🌐"),
    "00:24:50": ("Cisco", "network", "🌐"), "00:24:97": ("Cisco", "network", "🌐"),
    "00:24:c4": ("Cisco", "network", "🌐"), "00:25:45": ("Cisco", "network", "🌐"),
    "00:25:83": ("Cisco", "network", "🌐"), "00:25:b4": ("Cisco", "network", "🌐"),
    "00:26:0a": ("Cisco", "network", "🌐"), "00:26:51": ("Cisco", "network", "🌐"),
    "00:26:99": ("Cisco", "network", "🌐"), "00:26:ca": ("Cisco", "network", "🌐"),
    "00:27:0d": ("Cisco", "network", "🌐"),

    # Netgear
    "00:09:5b": ("Netgear", "network", "🌐"), "00:0f:b5": ("Netgear", "network", "🌐"),
    "00:14:6c": ("Netgear", "network", "🌐"), "00:18:4d": ("Netgear", "network", "🌐"),
    "00:1b:2f": ("Netgear", "network", "🌐"), "00:1e:2a": ("Netgear", "network", "🌐"),
    "00:22:3f": ("Netgear", "network", "🌐"), "00:24:b2": ("Netgear", "network", "🌐"),
    "00:26:f2": ("Netgear", "network", "🌐"), "04:a1:51": ("Netgear", "network", "🌐"),
    "08:02:8e": ("Netgear", "network", "🌐"), "08:36:c9": ("Netgear", "network", "🌐"),
    "0c:80:63": ("Netgear", "network", "🌐"), "10:0c:6b": ("Netgear", "network", "🌐"),
    "10:da:43": ("Netgear", "network", "🌐"), "20:0c:c8": ("Netgear", "network", "🌐"),
    "20:4e:7f": ("Netgear", "network", "🌐"), "28:c6:8e": ("Netgear", "network", "🌐"),
    "2c:b0:5d": ("Netgear", "network", "🌐"), "30:46:9a": ("Netgear", "network", "🌐"),
    "44:94:fc": ("Netgear", "network", "🌐"), "4c:60:de": ("Netgear", "network", "🌐"),
    "6c:b0:ce": ("Netgear", "network", "🌐"), "74:44:01": ("Netgear", "network", "🌐"),
    "9c:d6:43": ("Netgear", "network", "🌐"), "a0:40:a0": ("Netgear", "network", "🌐"),
    "a4:11:62": ("Netgear", "network", "🌐"), "b0:39:56": ("Netgear", "network", "🌐"),
    "c0:3f:0e": ("Netgear", "network", "🌐"), "c4:3d:c7": ("Netgear", "network", "🌐"),
    "c4:04:15": ("Netgear", "network", "🌐"), "e0:46:9a": ("Netgear", "network", "🌐"),
    "e0:91:f5": ("Netgear", "network", "🌐"),

    # Synology (NAS)
    "00:11:32": ("Synology", "nas", "🗄️"), "00:50:43": ("Synology", "nas", "🗄️"),
    "90:09:d0": ("Synology", "nas", "🗄️"), "bc:5f:f4": ("Synology", "nas", "🗄️"),
    "c8:86:4f": ("Synology", "nas", "🗄️"),

    # QNAP (NAS)
    "00:08:9b": ("QNAP", "nas", "🗄️"), "24:5e:be": ("QNAP", "nas", "🗄️"),
    "70:85:c2": ("QNAP", "nas", "🗄️"), "d8:50:e6": ("QNAP", "nas", "🗄️"),

    # Lutron
    "00:17:7f": ("Lutron", "iot", "💡"), "28:43:fc": ("Lutron", "iot", "💡"),
    "a4:b8:a7": ("Lutron", "iot", "💡"), "e0:92:8f": ("Lutron", "iot", "💡"),

    # Philips Hue / Signify
    "00:17:88": ("Philips Hue", "iot", "💡"), "ec:b5:fa": ("Philips Hue", "iot", "💡"),

    # Wemo / Belkin
    "58:ef:68": ("Belkin/Wemo", "iot", "🔌"), "94:10:3e": ("Belkin/Wemo", "iot", "🔌"),
    "b4:75:0e": ("Belkin/Wemo", "iot", "🔌"), "c4:41:1e": ("Belkin/Wemo", "iot", "🔌"),
    "e8:9f:80": ("Belkin/Wemo", "iot", "🔌"),

    # Nintendo
    "00:09:bf": ("Nintendo", "gaming", "🎮"), "00:16:56": ("Nintendo", "gaming", "🎮"),
    "00:17:ab": ("Nintendo", "gaming", "🎮"), "00:19:1d": ("Nintendo", "gaming", "🎮"),
    "00:1a:e9": ("Nintendo", "gaming", "🎮"), "00:1b:ea": ("Nintendo", "gaming", "🎮"),
    "00:1c:be": ("Nintendo", "gaming", "🎮"), "00:1e:35": ("Nintendo", "gaming", "🎮"),
    "00:1f:32": ("Nintendo", "gaming", "🎮"), "00:22:4c": ("Nintendo", "gaming", "🎮"),
    "00:22:d7": ("Nintendo", "gaming", "🎮"), "00:24:44": ("Nintendo", "gaming", "🎮"),
    "00:24:f3": ("Nintendo", "gaming", "🎮"), "00:26:59": ("Nintendo", "gaming", "🎮"),
    "0c:ef:af": ("Nintendo", "gaming", "🎮"), "18:2a:7b": ("Nintendo", "gaming", "🎮"),
    "40:d2:8a": ("Nintendo", "gaming", "🎮"), "58:2f:40": ("Nintendo", "gaming", "🎮"),
    "7c:bb:8a": ("Nintendo", "gaming", "🎮"), "8c:56:c5": ("Nintendo", "gaming", "🎮"),
    "9c:e6:35": ("Nintendo", "gaming", "🎮"), "a4:c0:e1": ("Nintendo", "gaming", "🎮"),
    "b8:ae:6e": ("Nintendo", "gaming", "🎮"), "d8:6b:f7": ("Nintendo", "gaming", "🎮"),
    "e0:66:78": ("Nintendo", "gaming", "🎮"),

    # Sony PlayStation
    "00:04:1f": ("Sony PlayStation", "gaming", "🎮"),
    "00:13:15": ("Sony PlayStation", "gaming", "🎮"),
    "00:15:c1": ("Sony PlayStation", "gaming", "🎮"),
    "00:19:c5": ("Sony PlayStation", "gaming", "🎮"),
    "00:1d:0d": ("Sony PlayStation", "gaming", "🎮"),
    "00:24:8d": ("Sony PlayStation", "gaming", "🎮"),
    "00:26:43": ("Sony PlayStation", "gaming", "🎮"),
    "28:3f:69": ("Sony PlayStation", "gaming", "🎮"),
    "78:c6:81": ("Sony PlayStation", "gaming", "🎮"),
    "bc:60:a7": ("Sony PlayStation", "gaming", "🎮"),
    "f8:46:1c": ("Sony PlayStation", "gaming", "🎮"),

    # Xbox / Microsoft
    "00:0d:3a": ("Microsoft/Xbox", "gaming", "🎮"),
    "00:17:fa": ("Microsoft/Xbox", "gaming", "🎮"),
    "00:1d:d8": ("Microsoft/Xbox", "gaming", "🎮"),
    "00:22:48": ("Microsoft/Xbox", "gaming", "🎮"),
    "00:25:ae": ("Microsoft/Xbox", "gaming", "🎮"),
    "00:50:f2": ("Microsoft", "windows", "🖥️"),
    "28:18:78": ("Microsoft/Xbox", "gaming", "🎮"),
    "30:59:b7": ("Microsoft/Xbox", "gaming", "🎮"),
    "60:45:cb": ("Microsoft/Xbox", "gaming", "🎮"),
    "7c:ed:8d": ("Microsoft/Xbox", "gaming", "🎮"),
    "98:5f:d3": ("Microsoft/Xbox", "gaming", "🎮"),

    # Intel (common in laptops/PCs)
    "00:02:b3": ("Intel", "pc", "🖥️"), "00:03:47": ("Intel", "pc", "🖥️"),
    "00:04:23": ("Intel", "pc", "🖥️"), "00:07:e9": ("Intel", "pc", "🖥️"),
    "00:0c:f1": ("Intel", "pc", "🖥️"), "00:0e:0c": ("Intel", "pc", "🖥️"),
    "00:11:11": ("Intel", "pc", "🖥️"), "00:12:f0": ("Intel", "pc", "🖥️"),
    "00:13:02": ("Intel", "pc", "🖥️"), "00:13:20": ("Intel", "pc", "🖥️"),
    "00:13:e8": ("Intel", "pc", "🖥️"), "00:14:38": ("Intel", "pc", "🖥️"),
    "00:15:17": ("Intel", "pc", "🖥️"), "00:16:76": ("Intel", "pc", "🖥️"),
    "00:16:ea": ("Intel", "pc", "🖥️"), "00:16:eb": ("Intel", "pc", "🖥️"),
    "00:18:de": ("Intel", "pc", "🖥️"), "00:19:d1": ("Intel", "pc", "🖥️"),
    "00:1b:21": ("Intel", "pc", "🖥️"), "00:1c:c0": ("Intel", "pc", "🖥️"),
    "00:1d:e0": ("Intel", "pc", "🖥️"), "00:1e:64": ("Intel", "pc", "🖥️"),
    "00:1e:65": ("Intel", "pc", "🖥️"), "00:1f:3a": ("Intel", "pc", "🖥️"),
    "00:1f:3b": ("Intel", "pc", "🖥️"), "00:1f:3c": ("Intel", "pc", "🖥️"),
    "00:21:6a": ("Intel", "pc", "🖥️"), "00:21:6b": ("Intel", "pc", "🖥️"),
    "00:22:fa": ("Intel", "pc", "🖥️"), "00:22:fb": ("Intel", "pc", "🖥️"),
    "00:23:14": ("Intel", "pc", "🖥️"), "00:24:d7": ("Intel", "pc", "🖥️"),
    "00:26:c7": ("Intel", "pc", "🖥️"), "10:02:b5": ("Intel", "pc", "🖥️"),
    "18:cf:5e": ("Intel", "pc", "🖥️"), "1c:69:7a": ("Intel", "pc", "🖥️"),
    "20:16:d8": ("Intel", "pc", "🖥️"), "38:de:ad": ("Intel", "pc", "🖥️"),
    "40:a8:f0": ("Intel", "pc", "🖥️"), "44:85:00": ("Intel", "pc", "🖥️"),
    "48:51:b7": ("Intel", "pc", "🖥️"), "4c:80:93": ("Intel", "pc", "🖥️"),
    "54:27:1e": ("Intel", "pc", "🖥️"), "5c:f9:dd": ("Intel", "pc", "🖥️"),
    "60:57:18": ("Intel", "pc", "🖥️"), "60:67:20": ("Intel", "pc", "🖥️"),
    "64:5d:86": ("Intel", "pc", "🖥️"), "68:05:ca": ("Intel", "pc", "🖥️"),
    "6c:88:14": ("Intel", "pc", "🖥️"), "70:5a:b6": ("Intel", "pc", "🖥️"),
    "74:e5:f9": ("Intel", "pc", "🖥️"), "78:92:9c": ("Intel", "pc", "🖥️"),
    "7c:5c:f8": ("Intel", "pc", "🖥️"), "80:19:34": ("Intel", "pc", "🖥️"),
    "84:3a:4b": ("Intel", "pc", "🖥️"), "84:7b:eb": ("Intel", "pc", "🖥️"),
    "88:53:95": ("Intel", "pc", "🖥️"), "8c:8d:28": ("Intel", "pc", "🖥️"),
    "90:e2:ba": ("Intel", "pc", "🖥️"), "94:65:9c": ("Intel", "pc", "🖥️"),
    "98:4f:ee": ("Intel", "pc", "🖥️"), "9c:eb:e8": ("Intel", "pc", "🖥️"),
    "a0:36:9f": ("Intel", "pc", "🖥️"), "a0:88:b4": ("Intel", "pc", "🖥️"),
    "a4:4e:31": ("Intel", "pc", "🖥️"), "a4:c3:f0": ("Intel", "pc", "🖥️"),
    "ac:72:89": ("Intel", "pc", "🖥️"), "b0:35:9f": ("Intel", "pc", "🖥️"),
    "b8:ae:ed": ("Intel", "pc", "🖥️"), "bc:0f:9a": ("Intel", "pc", "🖥️"),
    "c4:8e:8f": ("Intel", "pc", "🖥️"), "c8:d9:d2": ("Intel", "pc", "🖥️"),
    "cc:3d:82": ("Intel", "pc", "🖥️"), "d0:50:99": ("Intel", "pc", "🖥️"),
    "d4:be:d9": ("Intel", "pc", "🖥️"), "d8:fc:93": ("Intel", "pc", "🖥️"),
    "e0:06:e6": ("Intel", "pc", "🖥️"), "e8:b4:70": ("Intel", "pc", "🖥️"),
    "ec:08:6b": ("Intel", "pc", "🖥️"), "f4:06:69": ("Intel", "pc", "🖥️"),
    "f8:16:54": ("Intel", "pc", "🖥️"), "f8:63:3f": ("Intel", "pc", "🖥️"),

    # Realtek (common in PCs)
    "00:01:2e": ("Realtek", "pc", "🖥️"), "00:01:6c": ("Realtek", "pc", "🖥️"),
    "00:e0:4c": ("Realtek", "pc", "🖥️"), "10:7b:44": ("Realtek", "pc", "🖥️"),
    "2c:4d:54": ("Realtek", "pc", "🖥️"), "40:16:9f": ("Realtek", "pc", "🖥️"),
    "44:a8:42": ("Realtek", "pc", "🖥️"), "4c:cc:6a": ("Realtek", "pc", "🖥️"),
    "52:54:00": ("Realtek/QEMU", "linux", "🐧"), "54:04:a6": ("Realtek", "pc", "🖥️"),
    "80:fa:5b": ("Realtek", "pc", "🖥️"),

    # Lenovo
    "00:26:b9": ("Lenovo", "pc", "🖥️"), "04:7d:7b": ("Lenovo", "pc", "🖥️"),
    "10:93:e9": ("Lenovo", "pc", "🖥️"), "18:5e:0f": ("Lenovo", "pc", "🖥️"),
    "20:89:84": ("Lenovo", "pc", "🖥️"), "28:d2:44": ("Lenovo", "pc", "🖥️"),
    "40:8d:5c": ("Lenovo", "pc", "🖥️"), "44:37:e6": ("Lenovo", "pc", "🖥️"),
    "48:a4:72": ("Lenovo", "pc", "🖥️"), "4c:79:6e": ("Lenovo", "pc", "🖥️"),
    "50:7b:9d": ("Lenovo", "pc", "🖥️"), "54:ee:75": ("Lenovo", "pc", "🖥️"),
    "5c:f3:70": ("Lenovo", "pc", "🖥️"), "60:02:92": ("Lenovo", "pc", "🖥️"),
    "64:00:6a": ("Lenovo", "pc", "🖥️"), "6c:40:08": ("Lenovo", "pc", "🖥️"),
    "74:04:f1": ("Lenovo", "pc", "🖥️"), "78:2b:46": ("Lenovo", "pc", "🖥️"),
    "80:5e:c0": ("Lenovo", "pc", "🖥️"), "84:2b:2b": ("Lenovo", "pc", "🖥️"),
    "88:70:8c": ("Lenovo", "pc", "🖥️"), "8c:8d:28": ("Lenovo", "pc", "🖥️"),
    "90:2b:34": ("Lenovo", "pc", "🖥️"), "94:65:9c": ("Lenovo", "pc", "🖥️"),
    "98:fa:9b": ("Lenovo", "pc", "🖥️"), "a4:4e:31": ("Lenovo", "pc", "🖥️"),
    "c0:a5:e8": ("Lenovo", "pc", "🖥️"), "c0:b9:62": ("Lenovo", "pc", "🖥️"),
    "d4:81:d7": ("Lenovo", "pc", "🖥️"), "d8:bb:c1": ("Lenovo", "pc", "🖥️"),
    "e8:6a:64": ("Lenovo", "pc", "🖥️"), "f8:16:54": ("Lenovo", "pc", "🖥️"),
    "f8:a9:63": ("Lenovo", "pc", "🖥️"),

    # Dell
    "00:06:5b": ("Dell", "pc", "🖥️"), "00:08:74": ("Dell", "pc", "🖥️"),
    "00:0b:db": ("Dell", "pc", "🖥️"), "00:0d:56": ("Dell", "pc", "🖥️"),
    "00:0f:1f": ("Dell", "pc", "🖥️"), "00:10:18": ("Dell", "pc", "🖥️"),
    "00:11:43": ("Dell", "pc", "🖥️"), "00:12:3f": ("Dell", "pc", "🖥️"),
    "00:13:72": ("Dell", "pc", "🖥️"), "00:14:22": ("Dell", "pc", "🖥️"),
    "00:15:c5": ("Dell", "pc", "🖥️"), "00:16:f0": ("Dell", "pc", "🖥️"),
    "00:18:8b": ("Dell", "pc", "🖥️"), "00:19:b9": ("Dell", "pc", "🖥️"),
    "00:1a:4b": ("Dell", "pc", "🖥️"), "00:1b:fc": ("Dell", "pc", "🖥️"),
    "00:1c:23": ("Dell", "pc", "🖥️"), "00:1d:09": ("Dell", "pc", "🖥️"),
    "00:1e:4f": ("Dell", "pc", "🖥️"), "00:1f:d0": ("Dell", "pc", "🖥️"),
    "00:21:70": ("Dell", "pc", "🖥️"), "00:22:19": ("Dell", "pc", "🖥️"),
    "00:23:ae": ("Dell", "pc", "🖥️"), "00:24:e8": ("Dell", "pc", "🖥️"),
    "00:25:64": ("Dell", "pc", "🖥️"), "00:26:b9": ("Dell", "pc", "🖥️"),
    "08:00:27": ("Dell/VirtualBox", "pc", "🖥️"),
    "10:65:30": ("Dell", "pc", "🖥️"), "10:7d:1a": ("Dell", "pc", "🖥️"),
    "14:18:77": ("Dell", "pc", "🖥️"), "14:58:d0": ("Dell", "pc", "🖥️"),
    "14:fe:b5": ("Dell", "pc", "🖥️"), "18:03:73": ("Dell", "pc", "🖥️"),
    "18:66:da": ("Dell", "pc", "🖥️"), "18:a9:9b": ("Dell", "pc", "🖥️"),
    "1c:40:24": ("Dell", "pc", "🖥️"), "20:04:0f": ("Dell", "pc", "🖥️"),
    "20:47:47": ("Dell", "pc", "🖥️"), "24:b6:fd": ("Dell", "pc", "🖥️"),
    "28:92:4a": ("Dell", "pc", "🖥️"), "2c:76:8a": ("Dell", "pc", "🖥️"),
    "34:17:eb": ("Dell", "pc", "🖥️"), "34:48:ed": ("Dell", "pc", "🖥️"),
    "38:63:bb": ("Dell", "pc", "🖥️"), "3c:a9:f4": ("Dell", "pc", "🖥️"),
    "40:a8:f0": ("Dell", "pc", "🖥️"), "44:a8:42": ("Dell", "pc", "🖥️"),
    "48:4d:7e": ("Dell", "pc", "🖥️"), "4c:ed:fb": ("Dell", "pc", "🖥️"),
    "50:9a:4c": ("Dell", "pc", "🖥️"), "54:bf:64": ("Dell", "pc", "🖥️"),
    "58:8a:5a": ("Dell", "pc", "🖥️"), "5c:26:0a": ("Dell", "pc", "🖥️"),
    "60:03:08": ("Dell", "pc", "🖥️"), "60:57:18": ("Dell", "pc", "🖥️"),
    "64:00:6a": ("Dell", "pc", "🖥️"), "68:05:ca": ("Dell", "pc", "🖥️"),
    "6c:2b:59": ("Dell", "pc", "🖥️"), "74:86:7a": ("Dell", "pc", "🖥️"),
    "74:e6:e2": ("Dell", "pc", "🖥️"), "78:45:c4": ("Dell", "pc", "🖥️"),
    "80:18:44": ("Dell", "pc", "🖥️"), "84:7b:eb": ("Dell", "pc", "🖥️"),
    "90:b1:1c": ("Dell", "pc", "🖥️"), "98:90:96": ("Dell", "pc", "🖥️"),
    "9c:eb:e8": ("Dell", "pc", "🖥️"), "a0:36:9f": ("Dell", "pc", "🖥️"),
    "a4:1f:72": ("Dell", "pc", "🖥️"), "b0:83:fe": ("Dell", "pc", "🖥️"),
    "b8:ac:6f": ("Dell", "pc", "🖥️"), "bc:30:5b": ("Dell", "pc", "🖥️"),
    "c0:f8:7f": ("Dell", "pc", "🖥️"), "c8:1f:66": ("Dell", "pc", "🖥️"),
    "d4:be:d9": ("Dell", "pc", "🖥️"), "d8:9e:f3": ("Dell", "pc", "🖥️"),
    "dc:53:60": ("Dell", "pc", "🖥️"), "e0:db:55": ("Dell", "pc", "🖥️"),
    "e4:b9:7a": ("Dell", "pc", "🖥️"), "e8:b4:70": ("Dell", "pc", "🖥️"),
    "ec:f4:bb": ("Dell", "pc", "🖥️"), "f0:1f:af": ("Dell", "pc", "🖥️"),
    "f8:b1:56": ("Dell", "pc", "🖥️"), "f8:db:88": ("Dell", "pc", "🖥️"),
    "fc:15:b4": ("Dell", "pc", "🖥️"),

    # HP
    "00:01:e6": ("HP", "pc", "🖥️"), "00:02:a5": ("HP", "pc", "🖥️"),
    "00:04:ea": ("HP", "pc", "🖥️"), "00:08:02": ("HP", "pc", "🖥️"),
    "00:0b:cd": ("HP", "pc", "🖥️"), "00:0e:7f": ("HP", "pc", "🖥️"),
    "00:10:83": ("HP", "pc", "🖥️"), "00:11:0a": ("HP", "pc", "🖥️"),
    "00:12:79": ("HP", "pc", "🖥️"), "00:13:21": ("HP", "pc", "🖥️"),
    "00:14:38": ("HP", "pc", "🖥️"), "00:15:60": ("HP", "pc", "🖥️"),
    "00:16:35": ("HP", "pc", "🖥️"), "00:17:08": ("HP", "pc", "🖥️"),
    "00:18:71": ("HP", "pc", "🖥️"), "00:19:bb": ("HP", "pc", "🖥️"),
    "00:1a:4b": ("HP", "pc", "🖥️"), "00:1b:78": ("HP", "pc", "🖥️"),
    "00:1c:c4": ("HP", "pc", "🖥️"), "00:1d:c0": ("HP", "pc", "🖥️"),
    "00:1e:0b": ("HP", "pc", "🖥️"), "00:1f:29": ("HP", "pc", "🖥️"),
    "00:20:e0": ("HP", "pc", "🖥️"), "00:21:5a": ("HP", "pc", "🖥️"),
    "00:22:64": ("HP", "pc", "🖥️"), "00:23:7d": ("HP", "pc", "🖥️"),
    "00:24:81": ("HP", "pc", "🖥️"), "00:25:b3": ("HP", "pc", "🖥️"),
    "00:26:55": ("HP", "pc", "🖥️"), "10:60:4b": ("HP", "pc", "🖥️"),
    "14:02:ec": ("HP", "pc", "🖥️"), "18:a9:05": ("HP", "pc", "🖥️"),
    "1c:c1:de": ("HP", "pc", "🖥️"), "20:16:b9": ("HP", "pc", "🖥️"),
    "24:be:05": ("HP", "pc", "🖥️"), "28:92:4a": ("HP", "pc", "🖥️"),
    "2c:23:3a": ("HP", "pc", "🖥️"), "30:e1:71": ("HP", "pc", "🖥️"),
    "34:64:a9": ("HP", "pc", "🖥️"), "38:ea:a7": ("HP", "pc", "🖥️"),
    "3c:d9:2b": ("HP", "pc", "🖥️"), "40:b0:34": ("HP", "pc", "🖥️"),
    "48:0f:cf": ("HP", "pc", "🖥️"), "4c:39:09": ("HP", "pc", "🖥️"),
    "5c:b9:01": ("HP", "pc", "🖥️"), "64:51:06": ("HP", "pc", "🖥️"),
    "68:b5:99": ("HP", "pc", "🖥️"), "6c:3b:e5": ("HP", "pc", "🖥️"),
    "74:46:a0": ("HP", "pc", "🖥️"), "78:ac:c0": ("HP", "pc", "🖥️"),
    "7c:e9:d3": ("HP", "pc", "🖥️"), "80:ce:62": ("HP", "pc", "🖥️"),
    "84:34:97": ("HP", "pc", "🖥️"), "88:51:fb": ("HP", "pc", "🖥️"),
    "8c:dc:d4": ("HP", "pc", "🖥️"), "90:18:7c": ("HP", "pc", "🖥️"),
    "94:57:a5": ("HP", "pc", "🖥️"), "98:e7:f4": ("HP", "pc", "🖥️"),
    "9c:8e:99": ("HP", "pc", "🖥️"), "a0:1d:48": ("HP", "pc", "🖥️"),
    "a4:5d:36": ("HP", "pc", "🖥️"), "a8:26:d9": ("HP", "pc", "🖥️"),
    "ac:16:2d": ("HP", "pc", "🖥️"), "b0:5a:da": ("HP", "pc", "🖥️"),
    "b4:99:ba": ("HP", "pc", "🖥️"), "b8:ca:3a": ("HP", "pc", "🖥️"),
    "bc:ea:fa": ("HP", "pc", "🖥️"), "c4:34:6b": ("HP", "pc", "🖥️"),
    "c8:d3:ff": ("HP", "pc", "🖥️"), "d0:bf:9c": ("HP", "pc", "🖥️"),
    "d4:c9:ef": ("HP", "pc", "🖥️"), "d8:d3:85": ("HP", "pc", "🖥️"),
    "dc:4a:3e": ("HP", "pc", "🖥️"), "e0:07:1b": ("HP", "pc", "🖥️"),
    "e4:11:5b": ("HP", "pc", "🖥️"), "e8:39:35": ("HP", "pc", "🖥️"),
    "ec:b1:d7": ("HP", "pc", "🖥️"), "f0:92:1c": ("HP", "pc", "🖥️"),
    "f4:39:09": ("HP", "pc", "🖥️"), "f8:b1:56": ("HP", "pc", "🖥️"),
    "fc:15:b4": ("HP", "pc", "🖥️"),

    # Eero (Amazon mesh)
    "20:c0:47": ("Eero", "network", "🌐"), "30:94:d2": ("Eero", "network", "🌐"),
    "50:91:e3": ("Eero", "network", "🌐"), "54:83:3a": ("Eero", "network", "🌐"),
    "68:c6:3a": ("Eero", "network", "🌐"),

    # Sense (home energy)
    "00:00:5e": ("Sense", "iot", "⚡"),

    # LG Electronics
    "00:05:cd": ("LG", "tv", "📺"), "00:1c:62": ("LG", "tv", "📺"),
    "00:1e:75": ("LG", "tv", "📺"), "00:24:83": ("LG", "tv", "📺"),
    "00:26:e2": ("LG", "tv", "📺"), "04:b1:67": ("LG", "tv", "📺"),
    "10:68:3f": ("LG", "tv", "📺"), "14:c9:13": ("LG", "tv", "📺"),
    "18:3d:a2": ("LG", "tv", "📺"), "1c:08:c1": ("LG", "tv", "📺"),
    "28:cd:c1": ("LG", "tv", "📺"), "30:df:18": ("LG", "tv", "📺"),
    "34:d1:21": ("LG", "tv", "📺"), "38:8c:50": ("LG", "tv", "📺"),
    "3c:bd:d8": ("LG", "tv", "📺"), "40:b0:fa": ("LG", "tv", "📺"),
    "48:59:29": ("LG", "tv", "📺"), "4c:0f:6e": ("LG", "tv", "📺"),
    "50:c7:bf": ("LG", "tv", "📺"), "54:4a:16": ("LG", "tv", "📺"),
    "58:ef:68": ("LG", "tv", "📺"), "5c:49:79": ("LG", "tv", "📺"),
    "60:6b:ff": ("LG", "tv", "📺"), "64:99:5d": ("LG", "tv", "📺"),
    "6c:40:08": ("LG", "tv", "📺"), "70:2b:e8": ("LG", "tv", "📺"),
    "78:5d:c8": ("LG", "tv", "📺"), "7c:1c:68": ("LG", "tv", "📺"),
    "80:6c:1b": ("LG", "tv", "📺"), "84:80:de": ("LG", "tv", "📺"),
    "88:36:6c": ("LG", "tv", "📺"), "8c:3c:4a": ("LG", "tv", "📺"),
    "90:61:0c": ("LG", "tv", "📺"), "94:0c:e1": ("LG", "tv", "📺"),
    "a8:16:d0": ("LG", "tv", "📺"), "a8:23:fe": ("LG", "tv", "📺"),
    "ac:f1:df": ("LG", "tv", "📺"), "b4:e6:2d": ("LG", "tv", "📺"),
    "bc:f5:ac": ("LG", "tv", "📺"), "c0:97:27": ("LG", "tv", "📺"),
    "c4:36:6c": ("LG", "tv", "📺"), "c4:4e:ac": ("LG", "tv", "📺"),
    "cc:2d:8c": ("LG", "tv", "📺"), "d8:55:a3": ("LG", "tv", "📺"),
    "e8:5b:5b": ("LG", "tv", "📺"), "ec:9b:5b": ("LG", "tv", "📺"),
    "f4:4e:fd": ("LG", "tv", "📺"), "f8:0c:f3": ("LG", "tv", "📺"),
    "f8:95:c7": ("LG", "tv", "📺"),

    # HP Printers
    "00:01:e7": ("HP Printer", "printer", "🖨️"),
    "00:04:ea": ("HP Printer", "printer", "🖨️"),
    "00:11:85": ("HP Printer", "printer", "🖨️"),
    "00:12:79": ("HP Printer", "printer", "🖨️"),
    "00:13:21": ("HP Printer", "printer", "🖨️"),
    "00:14:38": ("HP Printer", "printer", "🖨️"),
    "00:17:08": ("HP Printer", "printer", "🖨️"),
    "00:1b:78": ("HP Printer", "printer", "🖨️"),
    "00:21:5a": ("HP Printer", "printer", "🖨️"),
    "64:51:06": ("HP Printer", "printer", "🖨️"),
    "9c:8e:99": ("HP Printer", "printer", "🖨️"),
    "a0:d3:c1": ("HP Printer", "printer", "🖨️"),
    "b8:ca:3a": ("HP Printer", "printer", "🖨️"),
    "e0:07:1b": ("HP Printer", "printer", "🖨️"),
    "f4:ce:46": ("HP Printer", "printer", "🖨️"),

    # Canon Printers
    "00:00:85": ("Canon Printer", "printer", "🖨️"),
    "00:1e:8f": ("Canon Printer", "printer", "🖨️"),
    "00:1f:a9": ("Canon Printer", "printer", "🖨️"),
    "04:2e:4e": ("Canon Printer", "printer", "🖨️"),
    "14:49:bc": ("Canon Printer", "printer", "🖨️"),
    "80:92:95": ("Canon Printer", "printer", "🖨️"),
    "84:71:27": ("Canon Printer", "printer", "🖨️"),
    "8c:9c:13": ("Canon Printer", "printer", "🖨️"),

    # Epson Printers
    "00:00:48": ("Epson Printer", "printer", "🖨️"),
    "00:1b:a9": ("Epson Printer", "printer", "🖨️"),
    "00:26:ab": ("Epson Printer", "printer", "🖨️"),
    "44:d2:44": ("Epson Printer", "printer", "🖨️"),
    "64:eb:8c": ("Epson Printer", "printer", "🖨️"),

    # Brother Printers
    "00:1b:a9": ("Brother Printer", "printer", "🖨️"),
    "00:80:77": ("Brother Printer", "printer", "🖨️"),
    "1c:f1:ee": ("Brother Printer", "printer", "🖨️"),
    "30:05:5c": ("Brother Printer", "printer", "🖨️"),
    "3c:2a:f4": ("Brother Printer", "printer", "🖨️"),

    # pfSense / Netgate
    "00:25:90": ("Netgate", "network", "🌐"),

    # Proxmox / VMware virtual
    "00:0c:29": ("VMware", "linux", "🐧"),
    "00:50:56": ("VMware", "linux", "🐧"),
    "00:1c:14": ("VMware", "linux", "🐧"),

    # QEMU/KVM
    "52:54:00": ("QEMU/KVM", "linux", "🐧"),

    # Hyper-V
    "00:15:5d": ("Hyper-V", "windows", "🖥️"),

    # Generic IoT / unknown Tuya/BEKEN chips
    "d0:c9:07": ("Tuya IoT", "iot", "🔌"),
    "60:fb:00": ("Tuya IoT", "iot", "🔌"),
    "84:72:07": ("Tuya IoT", "iot", "🔌"),
    "7c:87:ce": ("Tuya IoT", "iot", "🔌"),
    "f0:f1:2f": ("Tuya IoT", "iot", "🔌"),
}

# Device type display config: (label, CSS color)
DEVICE_TYPE_DISPLAY = {
    "apple":       ("Apple",       "#a8a8a8"),
    "android":     ("Android",     "#a4c639"),
    "windows":     ("Windows",     "#00a4ef"),
    "linux":       ("Linux",       "#e95420"),
    "amazon":      ("Amazon",      "#ff9900"),
    "iot":         ("IoT",         "#00b4d8"),
    "tv":          ("Smart TV",    "#9b59b6"),
    "printer":     ("Printer",     "#7f8c8d"),
    "nas":         ("NAS",         "#16a085"),
    "network":     ("Network",     "#27ae60"),
    "voip":        ("VoIP",        "#2980b9"),
    "gaming":      ("Gaming",      "#e74c3c"),
    "raspberry_pi":("Raspberry Pi","#c7053d"),
    "google":      ("Google",      "#4285f4"),
    "pc":          ("PC",          "#3498db"),
    "unknown":     ("Unknown",     "#555555"),
}

def lookup_oui(mac: str) -> tuple:
    """
    Look up OUI from MAC address.
    Returns (manufacturer, device_type, icon) or ("Unknown", "unknown", "❓")
    Also applies hostname-based sub-classification for Apple devices.
    """
    if not mac or len(mac) < 8:
        return ("Unknown", "unknown", "❓")
    oui = mac[:8].lower()
    result = OUI_DB.get(oui)
    if result:
        return result
    return ("Unknown", "unknown", "❓")

# Map manufacturer names to SVG icon filenames (without .svg)
# Custom user uploads take priority over bundled icons
MANUFACTURER_ICON_MAP = {
    "Apple":            "apple",
    "Apple TV":         "appletv",
    "Android":          "android",  # hostname detected
    "Samsung":          "samsung",
    "Amazon":           "amazon",
    "Amazon/Ecobee":    "amazon",
    "Eero":             "amazon",
    "Google":           "google",
    "Raspberry Pi":     "raspberrypi",
    "Roku":             "roku",
    "Ring":             "ring",
    "Sonos":            "sonos",
    "Ubiquiti":         "ubiquiti",
    "Cisco":            "cisco",
    "Netgear":          "netgear",
    "Synology":         "synology",
    "QNAP":             "qnap",
    "Philips Hue":      "philipshue",
    "TP-Link":          "tplink",
    "Nintendo":         "nintendo",
    "Sony PlayStation": "playstation",
    "Microsoft":        "microsoft",
    "Microsoft/Xbox":   "xbox",
    "Hyper-V":          "microsoft",
    "Dell":             "dell",
    "Dell/VirtualBox":  "dell",
    "HP":               "hp",
    "HP Printer":       "hp",
    "Lenovo":           "lenovo",
    "Intel":            "intel",
    "LG":               "lg",
    "Epson Printer":    "epson",
    "Brother Printer":  "brother",
    "Canon Printer":    "canon",
    "Lutron":           "lutron",
    "Nest":             "googlenest",
    "Espressif":        "espressif",
    "VMware":           "vmware",
    "Realtek/QEMU":     "qemu",
    "QEMU/KVM":         "qemu",
    "Netgate":          "netgate",
    "Meross":           "meross",
    "Ecobee":           "ecobee",
    "Belkin/Wemo":      "belkin",
    "Tuya IoT":         "tuya",
}

ICONS_BUNDLED_DIR = "/opt/jen/static/icons/brands"
ICONS_CUSTOM_DIR  = "/opt/jen/static/icons/custom"

def get_manufacturer_icon_url(manufacturer: str) -> str:
    """
    Returns the URL path to the best available icon for a manufacturer.
    Priority: custom user upload > bundled Simple Icons > None
    """
    icon_name = MANUFACTURER_ICON_MAP.get(manufacturer)
    if not icon_name:
        return None
    # Check custom first
    custom_path = f"{ICONS_CUSTOM_DIR}/{icon_name}.svg"
    if os.path.exists(custom_path):
        return f"/static/icons/custom/{icon_name}.svg"
    # Check bundled
    bundled_path = f"{ICONS_BUNDLED_DIR}/{icon_name}.svg"
    if os.path.exists(bundled_path):
        return f"/static/icons/brands/{icon_name}.svg"
    return None

def classify_device(mac: str, hostname: str = "") -> tuple:
    """
    Returns (manufacturer, device_type, icon) with hostname-based refinement.
    For Apple devices, uses hostname to distinguish iPhone/iPad from Mac.
    Also uses hostname patterns when OUI is unknown (e.g. randomized/private MACs).
    """
    manufacturer, device_type, icon = lookup_oui(mac)

    # Hostname-based refinement for known Apple OUI
    if manufacturer == "Apple" and hostname:
        h = hostname.lower()
        if any(x in h for x in ("iphone", "ipad", "ipod")):
            return (manufacturer, "apple", "📱")
        elif any(x in h for x in ("macbook", "imac", "mac-mini", "mac-pro", "macpro", "macmini")):
            return (manufacturer, "apple", "💻")
        elif "appletv" in h or "apple-tv" in h:
            return ("Apple TV", "apple", "📺")

    # Hostname-based detection for unknown OUIs (randomized MACs, missing OUI entries)
    if manufacturer == "Unknown" and hostname:
        h = hostname.lower()
        if any(x in h for x in ("iphone", "ipad", "ipod")):
            return ("Apple", "apple", "📱")
        elif any(x in h for x in ("macbook", "imac", "mac-mini", "macpro", "macmini")):
            return ("Apple", "apple", "💻")
        elif "appletv" in h or "apple-tv" in h:
            return ("Apple", "apple", "📺")
        elif any(x in h for x in ("android", "pixel", "galaxy", "samsung")):
            return ("Android", "android", "📱")
        elif any(x in h for x in ("echo", "alexa", "kindle", "firetv", "fire-tv")):
            return ("Amazon", "amazon", "📦")
        elif any(x in h for x in ("chromecast", "googletv", "google-tv")):
            return ("Google", "google", "🔍")
        elif "roku" in h:
            return ("Roku", "tv", "📺")
        elif any(x in h for x in ("ring-", "ring_")):
            return ("Ring", "iot", "🔔")
        elif "nest" in h:
            return ("Nest", "iot", "🌡️")
        elif "sonos" in h:
            return ("Sonos", "iot", "🔊")
        elif any(x in h for x in ("meross", "kasa", "wemo", "tuya", "shelly", "tasmota", "espressif", "esphome")):
            return ("IoT Device", "iot", "🔌")
        elif any(x in h for x in ("xbox", "playstation", "nintendo", "switch")):
            return ("Gaming", "gaming", "🎮")
        elif any(x in h for x in ("printer", "print", "hp-", "canon-", "epson-", "brother-")):
            return ("Printer", "printer", "🖨️")

    return (manufacturer, device_type, icon)

def get_device_info_map(mac_list: list) -> dict:
    """
    Given a list of MAC address strings, returns a dict mapping mac -> device info dict.
    Uses override values when set, falls back to auto-detected values.
    Normalizes all MACs to lowercase for consistent lookup.
    Result: {mac: {"manufacturer": str, "device_type": str, "device_icon": str, "icon_url": str, "is_manual": bool}}
    """
    if not mac_list:
        return {}
    # Normalize all input MACs to lowercase
    normalized = [m.lower() for m in mac_list if m]
    if not normalized:
        return {}
    result = {}
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            placeholders = ",".join(["%s"] * len(normalized))
            cur.execute(f"""
                SELECT LOWER(mac) AS mac,
                       COALESCE(manufacturer_override, manufacturer) AS manufacturer,
                       COALESCE(device_type_override, device_type) AS device_type,
                       COALESCE(device_icon_override, device_icon) AS device_icon,
                       manufacturer_override IS NOT NULL AS is_manual
                FROM devices WHERE LOWER(mac) IN ({placeholders})
            """, normalized)
            for row in cur.fetchall():
                mfr = row["manufacturer"] or ""
                dtype = row["device_type"] or "unknown"
                dicon = row["device_icon"] or "❓"
                # If there's an icon override that's a valid icon name, use it directly
                icon_url = None
                if row["is_manual"] and dicon and len(dicon) > 2:
                    # dicon might be an icon name (e.g. "appletv") not an emoji
                    test_custom = f"{ICONS_CUSTOM_DIR}/{dicon}.svg"
                    test_bundled = f"{ICONS_BUNDLED_DIR}/{dicon}.svg"
                    if os.path.exists(test_custom):
                        icon_url = f"/static/icons/custom/{dicon}.svg"
                    elif os.path.exists(test_bundled):
                        icon_url = f"/static/icons/brands/{dicon}.svg"
                    else:
                        icon_url = get_manufacturer_icon_url(mfr)
                else:
                    icon_url = get_manufacturer_icon_url(mfr)
                result[row["mac"]] = {
                    "manufacturer": mfr,
                    "device_type": dtype,
                    "device_icon": dicon,
                    "icon_url": icon_url,
                    "is_manual": bool(row["is_manual"]),
                }
        db.close()
    except Exception as e:
        logger.error(f"get_device_info_map error: {e}")
    return result
# ─────────────────────────────────────────
def send_telegram(message):
    token = get_global_setting("telegram_token")
    chat_id = get_global_setting("telegram_chat_id")
    if not token or not chat_id:
        return False
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
            timeout=10
        )
        data = resp.json()
        if not data.get("ok"):
            logger.error(f"Telegram error: {data.get('description')}")
            return False
        return True
    except Exception as e:
        logger.error(f"Telegram send failed: {e}")
        return False

# ─────────────────────────────────────────
# Alert Engine
# ─────────────────────────────────────────

DEFAULT_TEMPLATES = {
    "kea_down":           "🚨 <b>Kea Alert</b>\n{server_name} is <b>DOWN</b>!",
    "kea_up":             "✅ <b>Kea Alert</b>\n{server_name} is back <b>UP</b>.",
    "ha_failover":        "⚡ <b>HA Failover</b>\n{server_name} state changed: <b>{old_state}</b> → <b>{new_state}</b>",
    "new_lease":          "🆕 <b>New DHCP Lease</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "new_device":         "🔍 <b>Unknown Device</b>\nNew MAC never seen before\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "utilization_high":   "⚠️ <b>Utilization Alert</b>\nSubnet <b>{subnet}</b> ({cidr})\nUsage: <b>{pct}%</b> ({used}/{total} addresses)",
    "utilization_ok":     "✅ <b>Utilization Recovery</b>\nSubnet <b>{subnet}</b> ({cidr})\nUsage back to <b>{pct}%</b> ({used}/{total} addresses)",
    "pool_exhaustion":    "🔴 <b>Pool Exhaustion Warning</b>\nSubnet <b>{subnet}</b> ({cidr})\nOnly <b>{free}</b> addresses remaining!",
    "reservation_added":  "📌 <b>Reservation Added</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nSubnet: {subnet}",
    "reservation_deleted":"🗑️ <b>Reservation Deleted</b>\nIP: {ip}\nMAC: {mac}\nSubnet: {subnet}",
    "stale_reservation":  "⏰ <b>Stale Reservation</b>\nIP: {ip}\nMAC: {mac}\nHostname: {hostname}\nNot seen in {days} days",
    "kea_config_changed": "⚙️ <b>Kea Config Changed</b>\nSubnet {subnet} was modified via Jen\nChange: {details}",
    "daily_summary":      "📊 <b>Daily Summary</b>\n{summary}",
}

ALERT_TYPE_LABELS = {
    "kea_down":           "Kea goes down",
    "kea_up":             "Kea comes back up",
    "ha_failover":        "HA failover / state change",
    "new_lease":          "New dynamic lease",
    "new_device":         "Unknown device detected",
    "utilization_high":   "Subnet utilization high",
    "utilization_ok":     "Subnet utilization recovery",
    "pool_exhaustion":    "Pool exhaustion warning",
    "reservation_added":  "Reservation added",
    "reservation_deleted":"Reservation deleted",
    "stale_reservation":  "Stale reservation detected",
    "kea_config_changed": "Kea config changed via Jen",
    "daily_summary":      "Daily summary",
}

def get_alert_template(alert_type):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT template_text FROM alert_templates WHERE alert_type=%s", (alert_type,))
            row = cur.fetchone()
        db.close()
        if row and row["template_text"]:
            return row["template_text"]
    except Exception:
        pass
    return DEFAULT_TEMPLATES.get(alert_type, "")

def render_template_str(template, **kwargs):
    """Render alert template with variable substitution."""
    try:
        return template.format(**kwargs)
    except KeyError:
        return template

def get_active_channels():
    """Get all enabled alert channels."""
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM alert_channels WHERE enabled=1")
            channels = cur.fetchall()
        db.close()
        return channels
    except Exception as e:
        logger.error(f"get_active_channels error: {e}")
        return []

def channel_handles_alert(channel, alert_type):
    """Check if channel is configured to send this alert type."""
    try:
        alert_types = channel.get("alert_types")
        if not alert_types:
            return False
        if isinstance(alert_types, str):
            import json
            alert_types = json.loads(alert_types)
        return alert_type in alert_types
    except Exception:
        return False

def get_channel_config(channel):
    """Parse channel config JSON."""
    try:
        cfg_data = channel.get("config")
        if not cfg_data:
            return {}
        if isinstance(cfg_data, str):
            import json
            return json.loads(cfg_data)
        return cfg_data
    except Exception:
        return {}

def send_alert(alert_type, log_result=True, **kwargs):
    """Send alert to all enabled channels that handle this alert type."""
    template = get_alert_template(alert_type)
    message = render_template_str(template, **kwargs)
    channels = get_active_channels()
    results = []
    for channel in channels:
        if not channel_handles_alert(channel, alert_type):
            continue
        ctype = channel["channel_type"]
        config = get_channel_config(channel)
        ok = False
        error = ""
        try:
            if ctype == "telegram":
                ok = _send_telegram_channel(message, config)
            elif ctype == "email":
                ok = _send_email_channel(message, alert_type, config)
            elif ctype == "slack":
                ok = _send_slack_channel(message, config)
            elif ctype == "webhook":
                ok = _send_webhook_channel(message, alert_type, config)
            elif ctype == "ntfy":
                ok = _send_ntfy_channel(message, config)
            elif ctype == "discord":
                ok = _send_discord_channel(message, config)
        except Exception as e:
            error = str(e)
            logger.error(f"Alert send error ({ctype}): {e}")
        if log_result:
            try:
                db = get_jen_db()
                with db.cursor() as cur:
                    cur.execute("""
                        INSERT INTO alert_log (channel_type, alert_type, message, status, error)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (ctype, alert_type, message[:500], "ok" if ok else "failed", error[:500] if error else None))
                db.commit()
                db.close()
            except Exception as e:
                logger.error(f"Alert log error: {e}")
        results.append((ctype, ok, error))
    return results

def _send_telegram_channel(message, config):
    token = config.get("token", "")
    chat_id = config.get("chat_id", "")
    if not token or not chat_id:
        return False
    resp = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
        timeout=10
    )
    data = resp.json()
    if not data.get("ok"):
        raise Exception(f"Telegram error: {data.get('description', 'Unknown')}")
    return True

def _send_email_channel(message, alert_type, config):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    host = config.get("smtp_host", "")
    port = int(config.get("smtp_port", 587))
    user = config.get("smtp_user", "")
    password = config.get("smtp_pass", "")
    from_addr = config.get("from_addr", user)
    to_addr = config.get("to_addr", "")
    if not host or not to_addr:
        return False
    # Strip HTML tags for email subject, keep for body
    import re
    subject_text = re.sub(r'<[^>]+>', '', message.split('\n')[0])
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Jen Alert: {subject_text}"
    msg["From"] = from_addr
    msg["To"] = to_addr
    # Plain text version
    plain = re.sub(r'<[^>]+>', '', message).replace('\n', '\n')
    # HTML version
    html_body = message.replace('\n', '<br>').replace('<b>', '<strong>').replace('</b>', '</strong>')
    html = f"<html><body style='font-family:sans-serif;'>{html_body}</body></html>"
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))
    use_tls = config.get("use_tls", "true") == "true"
    with smtplib.SMTP(host, port, timeout=15) as server:
        if use_tls:
            server.starttls()
        if user and password:
            server.login(user, password)
        server.sendmail(from_addr, to_addr, msg.as_string())
    return True

def _send_slack_channel(message, config):
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return False
    import re
    plain = re.sub(r'<[^>]+>', '', message).replace('\n', '\n')
    # Convert HTML bold to Slack bold
    slack_text = message.replace('<b>', '*').replace('</b>', '*')
    slack_text = re.sub(r'<[^>]+>', '', slack_text)
    resp = requests.post(webhook_url, json={"text": slack_text}, timeout=10)
    if resp.status_code != 200:
        raise Exception(f"Slack error {resp.status_code}: {resp.text}")
    return True

def _send_webhook_channel(message, alert_type, config):
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return False
    import re
    plain = re.sub(r'<[^>]+>', '', message).replace('\n', '\n')
    payload_type = config.get("payload_type", "json")
    headers = {"Content-Type": "application/json"}
    custom_header_name = config.get("header_name", "")
    custom_header_value = config.get("header_value", "")
    if custom_header_name:
        headers[custom_header_name] = custom_header_value
    if payload_type == "json":
        payload = {"alert_type": alert_type, "message": plain, "html": message}
    else:
        payload = {"text": plain}
    resp = requests.post(webhook_url, json=payload, headers=headers, timeout=10)
    if resp.status_code not in (200, 201, 202, 204):
        raise Exception(f"Webhook error {resp.status_code}: {resp.text[:200]}")
    return True

def _send_ntfy_channel(message, config):
    """Send alert via ntfy.sh or self-hosted ntfy."""
    import re
    url = config.get("url", "https://ntfy.sh").rstrip("/")
    topic = config.get("topic", "")
    token = config.get("token", "")
    priority = config.get("priority", "default")
    if not topic:
        raise Exception("ntfy topic not configured")
    plain = re.sub(r'<[^>]+>', '', message).strip()
    headers = {"Title": "Jen Alert", "Priority": priority, "Tags": "bell"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.post(f"{url}/{topic}", data=plain.encode("utf-8"),
                         headers=headers, timeout=10)
    if resp.status_code not in (200, 201, 204):
        raise Exception(f"ntfy error: HTTP {resp.status_code} — {resp.text[:200]}")
    return True

def _send_discord_channel(message, config):
    """Send alert via Discord webhook."""
    import re
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        raise Exception("Discord webhook URL not configured")
    text = message.replace("<b>", "**").replace("</b>", "**")
    text = re.sub(r'<[^>]+>', '', text).strip()
    resp = requests.post(webhook_url, json={"content": text, "username": "Jen DHCP"}, timeout=10)
    if resp.status_code not in (200, 204):
        raise Exception(f"Discord error: HTTP {resp.status_code} — {resp.text[:200]}")
    return True

def take_lease_snapshot():
    """Record current lease counts for all subnets."""
    try:
        retention_days = int(get_global_setting("history_retention_days", "90"))
        kdb = get_kea_db()
        jdb = get_jen_db()

        # Get pool sizes from Kea config
        pool_sizes = {}
        result = kea_command("config-get", server=get_active_kea_server())
        if result.get("result") == 0:
            for s in result["arguments"]["Dhcp4"].get("subnet4", []):
                for pool in s.get("pools", []):
                    p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                    if "-" in p:
                        start, end = [x.strip() for x in p.split("-")]
                        pool_sizes[s["id"]] = ip_to_int(end) - ip_to_int(start) + 1

        with kdb.cursor() as kcur:
            with jdb.cursor() as jcur:
                for subnet_id, info in SUBNET_MAP.items():
                    kcur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                    active = kcur.fetchone()["cnt"]
                    kcur.execute("""
                        SELECT COUNT(*) as cnt FROM lease4 l
                        LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                            AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
                        WHERE l.state=0 AND l.subnet_id=%s AND h.host_id IS NULL
                    """, (subnet_id,))
                    dynamic = kcur.fetchone()["cnt"]
                    kcur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                    reserved = kcur.fetchone()["cnt"]
                    pool_size = pool_sizes.get(subnet_id, 0)
                    jcur.execute("""
                        INSERT INTO lease_history (subnet_id, active_leases, dynamic_leases, reserved_leases, pool_size)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (subnet_id, active, dynamic, reserved, pool_size))

                # Purge old history
                jcur.execute(f"DELETE FROM lease_history WHERE snapshot_time < DATE_SUB(NOW(), INTERVAL {retention_days} DAY)")
        jdb.commit()
        kdb.close()
        jdb.close()
    except Exception as e:
        logger.error(f"Snapshot error: {e}")

def send_daily_summary():
    """Build and send daily summary."""
    try:
        lines = ["<b>Daily Network Summary</b>"]
        db = get_kea_db()
        jdb = get_jen_db()
        with db.cursor() as cur:
            for subnet_id, info in SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                active = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                reserved = cur.fetchone()["cnt"]
                lines.append(f"\n<b>{info['name']}</b> ({info['cidr']}): {active} active, {reserved} reserved")
            # New devices in last 24h
            with jdb.cursor() as jcur:
                jcur.execute("SELECT COUNT(*) as cnt FROM devices WHERE first_seen >= DATE_SUB(NOW(), INTERVAL 24 HOUR)")
                new_devices = jcur.fetchone()["cnt"]
                jcur.execute("SELECT COUNT(*) as cnt FROM devices")
                total_devices = jcur.fetchone()["cnt"]
        lines.append(f"\nNew devices (24h): <b>{new_devices}</b>")
        lines.append(f"Total known devices: <b>{total_devices}</b>")
        db.close()
        jdb.close()
        summary = "\n".join(lines)
        send_alert("daily_summary", summary=summary)
    except Exception as e:
        logger.error(f"Daily summary error: {e}")

def ip_to_int(ip):
    parts = ip.strip().split(".")
    return sum(int(x) << (8*(3-i)) for i, x in enumerate(parts))

def check_alerts():
    import time
    last_kea_status = True
    last_seen_leases = set()
    known_macs = set()
    alerted_high_subnets = set()
    alerted_stale_macs = set()
    first_run = True
    last_summary_date = None
    last_snapshot_time = 0
    last_ha_states = {}  # server_id -> last known HA state

    while True:
        try:
            # ── Kea up/down — check all servers ──
            for srv in KEA_SERVERS:
                srv_id = srv["id"]
                srv_up = kea_is_up(server=srv)
                prev_status = last_kea_status if isinstance(last_kea_status, bool) else last_kea_status.get(srv_id, True)
                if not srv_up and prev_status:
                    send_alert("kea_down", server_name=srv["name"])
                elif srv_up and not prev_status:
                    send_alert("kea_up", server_name=srv["name"])
                if isinstance(last_kea_status, dict):
                    last_kea_status[srv_id] = srv_up
                else:
                    last_kea_status = {s["id"]: kea_is_up(server=s) for s in KEA_SERVERS}

                # ── HA state monitoring ──
                if srv_up and len(KEA_SERVERS) > 1:
                    ha = kea_command("ha-heartbeat", server=srv)
                    if ha.get("result") == 0:
                        new_state = ha.get("arguments", {}).get("state", "")
                        old_state = last_ha_states.get(srv_id)
                        if old_state is not None and new_state != old_state:
                            send_alert("ha_failover", server_name=srv["name"],
                                      old_state=old_state, new_state=new_state)
                        last_ha_states[srv_id] = new_state

            kea_up = any(isinstance(last_kea_status, dict) and v for v in last_kea_status.values()) if isinstance(last_kea_status, dict) else last_kea_status

            if kea_up:
                db = get_kea_db()
                try:
                    with db.cursor() as cur:
                        # ── Lease tracking ──
                        cur.execute("""
                            SELECT inet_ntoa(l.address) AS ip, l.hwaddr,
                                   IFNULL(l.hostname,'') AS hostname, l.subnet_id
                            FROM lease4 l
                            LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                                AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
                            WHERE l.state=0 AND h.host_id IS NULL
                        """)
                        current_leases = set()
                        new_lease_rows = []
                        for row in cur.fetchall():
                            current_leases.add(row["ip"])
                            if not first_run and row["ip"] not in last_seen_leases:
                                new_lease_rows.append(row)

                        # ── Device inventory update ──
                        cur.execute("""
                            SELECT inet_ntoa(l.address) AS ip, l.hwaddr,
                                   IFNULL(l.hostname,'') AS hostname, l.subnet_id
                            FROM lease4 l WHERE l.state=0
                        """)
                        all_leases = cur.fetchall()
                        try:
                            jdb = get_jen_db()
                            with jdb.cursor() as jcur:
                                for row in all_leases:
                                    mac = format_mac(row["hwaddr"])
                                    manufacturer, device_type, device_icon = classify_device(mac, row["hostname"] or "")
                                    jcur.execute("""
                                        INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, last_seen,
                                                             manufacturer, device_type, device_icon)
                                        VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s)
                                        ON DUPLICATE KEY UPDATE
                                            last_ip=%s, last_hostname=%s,
                                            last_subnet_id=%s, last_seen=NOW(),
                                            manufacturer=IF(manufacturer_override IS NULL, %s, manufacturer),
                                            device_type=IF(manufacturer_override IS NULL, %s, device_type),
                                            device_icon=IF(manufacturer_override IS NULL, %s, device_icon)
                                    """, (mac, row["ip"], row["hostname"], row["subnet_id"],
                                          manufacturer, device_type, device_icon,
                                          row["ip"], row["hostname"], row["subnet_id"],
                                          manufacturer, device_type, device_icon))
                            jdb.commit()
                            jdb.close()
                        except Exception as e:
                            logger.error(f"Device tracking error: {e}")

                        # ── New lease alerts ──
                        for row in new_lease_rows:
                            mac = format_mac(row["hwaddr"])
                            subnet_name = SUBNET_MAP.get(row["subnet_id"], {}).get("name", f"Subnet {row['subnet_id']}")
                            send_alert("new_lease", ip=row["ip"], mac=mac,
                                      hostname=row["hostname"] or "(none)", subnet=subnet_name)
                            # Unknown device alert
                            if mac not in known_macs:
                                send_alert("new_device", ip=row["ip"], mac=mac,
                                          hostname=row["hostname"] or "(none)", subnet=subnet_name)

                        # Update known MACs
                        for row in all_leases:
                            known_macs.add(format_mac(row["hwaddr"]))

                        last_seen_leases = current_leases
                        first_run = False

                        # ── Utilization alerts ──
                        kea_cfg = kea_command("config-get", server=get_active_kea_server())
                        if kea_cfg.get("result") == 0:
                            threshold = int(get_global_setting("alert_threshold_pct", "80"))
                            exhaustion_threshold = int(get_global_setting("pool_exhaustion_free", "5"))
                            for s in kea_cfg["arguments"]["Dhcp4"].get("subnet4", []):
                                sid = s["id"]
                                if sid not in SUBNET_MAP:
                                    continue
                                info = SUBNET_MAP[sid]
                                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (sid,))
                                active = cur.fetchone()["cnt"]
                                for pool in s.get("pools", []):
                                    p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                                    if "-" in p:
                                        start, end = [x.strip() for x in p.split("-")]
                                        pool_size = ip_to_int(end) - ip_to_int(start) + 1
                                        pct = round(active / pool_size * 100) if pool_size > 0 else 0
                                        free = pool_size - active
                                        subnet_key = f"{sid}"
                                        if pct >= threshold and subnet_key not in alerted_high_subnets:
                                            send_alert("utilization_high", subnet=info["name"],
                                                      cidr=info["cidr"], pct=pct, used=active, total=pool_size)
                                            alerted_high_subnets.add(subnet_key)
                                        elif pct < threshold and subnet_key in alerted_high_subnets:
                                            send_alert("utilization_ok", subnet=info["name"],
                                                      cidr=info["cidr"], pct=pct, used=active, total=pool_size)
                                            alerted_high_subnets.discard(subnet_key)
                                        if free <= exhaustion_threshold:
                                            send_alert("pool_exhaustion", subnet=info["name"],
                                                      cidr=info["cidr"], free=free)

                        # ── Stale reservation alerts ──
                        try:
                            stale_days = int(get_global_setting("stale_device_days", "30"))
                            jdb = get_jen_db()
                            with jdb.cursor() as jcur:
                                jcur.execute(f"""
                                    SELECT mac, last_seen, DATEDIFF(NOW(), last_seen) as days
                                    FROM devices
                                    WHERE last_seen < DATE_SUB(NOW(), INTERVAL {stale_days} DAY)
                                """)
                                stale_rows = jcur.fetchall()
                            jdb.close()
                            for row in stale_rows:
                                if row["mac"] not in alerted_stale_macs:
                                    # Check if has reservation
                                    mac_hex = row["mac"].replace(":", "")
                                    cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, hostname FROM hosts WHERE HEX(dhcp_identifier)=%s", (mac_hex,))
                                    res = cur.fetchone()
                                    if res:
                                        send_alert("stale_reservation", ip=res["ip"] or "",
                                                  mac=row["mac"], hostname=res["hostname"] or "",
                                                  days=row["days"])
                                        alerted_stale_macs.add(row["mac"])
                        except Exception as e:
                            logger.error(f"Stale reservation check error: {e}")

                finally:
                    db.close()

            # ── Lease history snapshot ──
            snapshot_interval = int(get_global_setting("snapshot_interval_minutes", "30")) * 60
            now_ts = time.time()
            if now_ts - last_snapshot_time >= snapshot_interval:
                take_lease_snapshot()
                last_snapshot_time = now_ts

            # ── Daily summary ──
            import datetime as dt
            summary_time = get_global_setting("daily_summary_time", "07:00")
            now = dt.datetime.now()
            today = now.date()
            try:
                h, m = [int(x) for x in summary_time.split(":")]
                summary_due = now.hour == h and now.minute == m
                if summary_due and last_summary_date != today:
                    send_daily_summary()
                    last_summary_date = today
            except Exception:
                pass

        except Exception as e:
            logger.error(f"Alert thread error: {e}")
        time.sleep(30)

# ─────────────────────────────────────────
# Favicon
# ─────────────────────────────────────────
@app.route("/favicon.ico")
def favicon():
    if os.path.exists(FAVICON_PATH):
        return send_from_directory(STATIC_DIR, "favicon.ico")
    return "", 204

# ─────────────────────────────────────────
# Auth
# ─────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:100]
        password = request.form.get("password", "")
        ip = request.remote_addr

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html", jen_version=JEN_VERSION, prefill_username=username)

        # Check rate limit
        locked, remaining = is_locked_out(ip, username)
        if locked:
            if remaining >= 999:
                flash("Account is locked. Contact an administrator.", "error")
            else:
                flash(f"Too many failed attempts. Try again in {remaining} minute(s).", "error")
            return render_template("login.html", jen_version=JEN_VERSION, prefill_username=username)

        try:
            db = get_jen_db()
            with db.cursor() as cur:
                cur.execute(
                    "SELECT id, username, role, session_timeout, password FROM users WHERE username=%s",
                    (username,)
                )
                row = cur.fetchone()
            db.close()
        except Exception as e:
            logger.error(f"Login DB error: {e}")
            flash("Database error. Please try again.", "error")
            return render_template("login.html", jen_version=JEN_VERSION, prefill_username=username)

        if row and verify_password(row["password"], password):
            # Upgrade legacy SHA-256 hash to pbkdf2 on successful login
            if row["password"] and not row["password"].startswith("pbkdf2:"):
                try:
                    db = get_jen_db()
                    with db.cursor() as cur:
                        cur.execute("UPDATE users SET password=%s WHERE id=%s",
                                    (hash_password(password), row["id"]))
                    db.commit()
                    db.close()
                    logger.info(f"Upgraded password hash for user {username} to pbkdf2")
                except Exception as e:
                    logger.error(f"Password hash upgrade error: {e}")
            clear_login_attempts(ip, username)
            user = User(row["id"], row["username"], row["role"], row["session_timeout"])
            clear_login_attempts(ip, username)
            user = User(row["id"], row["username"], row["role"], row["session_timeout"])

            # Check if MFA is required and user has it enrolled
            if user_has_mfa(row["id"]) or user_needs_mfa(user):
                if user_has_mfa(row["id"]) and not is_trusted_device(row["id"], request):
                    # Store pending auth in session and redirect to MFA
                    session["mfa_pending_user_id"] = row["id"]
                    session["mfa_pending_username"] = username
                    session["mfa_next"] = request.args.get("next", url_for("dashboard"))
                    return redirect(url_for("mfa_verify"))
                elif user_needs_mfa(user) and not user_has_mfa(row["id"]):
                    # MFA required but not enrolled — force enrollment
                    session["mfa_pending_user_id"] = row["id"]
                    session["mfa_pending_username"] = username
                    login_user(user)
                    session["last_active"] = datetime.now(timezone.utc).isoformat()
                    flash("MFA is required for your account. Please enroll now.", "warning")
                    return redirect(url_for("mfa_enroll"))

            login_user(user)
            session["last_active"] = datetime.now(timezone.utc).isoformat()
            audit("LOGIN", "auth", f"User {username} logged in from {ip}")
            return redirect(url_for("dashboard"))

        # Failed login — record attempt
        record_login_attempt(ip, username)
        rl = get_rate_limit_settings()
        if rl["max_attempts"] > 0 and rl["mode"] != "off":
            # Count remaining attempts
            locked, remaining = is_locked_out(ip, username)
            if locked:
                flash(f"Too many failed attempts. Account locked for {remaining} minute(s).", "error")
            else:
                try:
                    db = get_jen_db()
                    with db.cursor() as cur:
                        window = f"DATE_SUB(NOW(), INTERVAL {rl['lockout_minutes']} MINUTE)" if rl['lockout_minutes'] > 0 else "'1970-01-01'"
                        cur.execute(f"SELECT COUNT(*) as cnt FROM login_attempts WHERE ip_address=%s AND attempted_at >= {window}", (ip,))
                        attempts = cur.fetchone()["cnt"]
                    db.close()
                    remaining_attempts = rl["max_attempts"] - attempts
                    if remaining_attempts <= 3:
                        flash(f"Invalid username or password. {remaining_attempts} attempt(s) remaining.", "error")
                    else:
                        flash("Invalid username or password.", "error")
                except Exception:
                    flash("Invalid username or password.", "error")
        else:
            flash("Invalid username or password.", "error")
        return render_template("login.html", jen_version=JEN_VERSION, prefill_username=username)

    return render_template("login.html", jen_version=JEN_VERSION, prefill_username="")

@app.route("/logout")
@login_required
def logout():
    audit("LOGOUT", "auth", f"User {current_user.username} logged out")
    logout_user()
    return redirect(url_for("login"))

# ─────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────
@app.route("/")
@login_required
def dashboard():
    try:
        hours = float(request.args.get("hours", "0.5"))
    except ValueError:
        hours = 0.5
    if hours not in (0.5, 1, 4, 8, 12, 24):
        hours = 0.5
    # hours_str must exactly match the option values in the template (no trailing .0)
    hours_str = str(int(hours)) if hours == int(hours) else str(hours)

    stats = {}
    recent = []
    # First fetch Kea config so we know pool sizes AND lease lifetimes
    pool_sizes = {}
    default_lifetime = 86400
    try:
        result = kea_command("config-get", server=get_active_kea_server())
        if result.get("result") == 0:
            cfg = result["arguments"]["Dhcp4"]
            default_lifetime = cfg.get("valid-lifetime", 86400)
            for s in cfg.get("subnet4", []):
                sid = str(s["id"])
                for pool in s.get("pools", []):
                    p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                    if "-" in p:
                        start, end = [x.strip() for x in p.split("-")]
                        pool_sizes[sid] = ip_to_int(end) - ip_to_int(start) + 1
    except Exception:
        pass

    try:
        db = get_kea_db()
        with db.cursor() as cur:
            for subnet_id, info in SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                active = cur.fetchone()["cnt"]
                cur.execute("""
                    SELECT COUNT(*) as cnt FROM lease4 l
                    WHERE l.state=0 AND l.subnet_id=%s
                    AND NOT EXISTS (
                        SELECT 1 FROM hosts h
                        WHERE h.dhcp4_subnet_id=%s AND h.dhcp_identifier=l.hwaddr
                    )
                """, (subnet_id, subnet_id))
                dynamic = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                reserved = cur.fetchone()["cnt"]
                stats[subnet_id] = {"active": active, "dynamic": dynamic,
                                    "reservations": reserved,
                                    "name": info["name"], "cidr": info["cidr"]}

            # issued_at = expire - valid_lifetime (valid_lifetime is stored per-lease in Kea)
            # expire is a TIMESTAMP column, so use INTERVAL arithmetic not UNIX_TIMESTAMP()
            window_seconds = int(hours * 3600)
            logger.info(f"Dashboard: hours={hours}, window={window_seconds}s")
            cur.execute("""
                SELECT inet_ntoa(l.address) AS ip, l.hostname,
                       HEX(l.hwaddr) AS mac_hex, l.subnet_id,
                       (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained
                FROM lease4 l
                WHERE l.state=0
                  AND l.expire > NOW()
                  AND (l.expire - INTERVAL l.valid_lifetime SECOND) > (NOW() - INTERVAL %s SECOND)
                ORDER BY (l.expire - INTERVAL l.valid_lifetime SECOND) DESC
                LIMIT 200
            """, (window_seconds,))
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                sname = SUBNET_MAP.get(row["subnet_id"], {}).get("name", str(row["subnet_id"]))
                recent.append({"ip": row["ip"], "hostname": row["hostname"] or "",
                                "mac": mac, "subnet_id": row["subnet_id"],
                                "subnet_name": sname,
                                "obtained": row["obtained"]})
        db.close()
    except Exception as e:
        logger.error(f"Dashboard DB error: {e}")
        flash(f"Could not load dashboard data: {str(e)}", "error")
    kea_up = kea_is_up()
    server_statuses = []
    try:
        server_statuses = get_all_server_status()
        for s in server_statuses:
            if s["up"]:
                ver = kea_command("version-get", server=s["server"])
                s["version"] = ver.get("arguments", {}).get("extended", ver.get("text", ""))
                s["version"] = s["version"].splitlines()[0] if s["version"] else ""
            else:
                s["version"] = ""
    except Exception:
        pass
    mac_list = [l["mac"] for l in recent if l.get("mac")]
    device_info = get_device_info_map(mac_list)
    return render_template("dashboard.html", stats=stats, recent=recent,
                           kea_up=kea_up, subnet_map=SUBNET_MAP,
                           pool_sizes=pool_sizes, hours=hours_str,
                           server_statuses=server_statuses,
                           device_info=device_info,
                           get_manufacturer_icon_url=get_manufacturer_icon_url,
                           device_type_display=DEVICE_TYPE_DISPLAY)

# ─────────────────────────────────────────
# Leases
# ─────────────────────────────────────────
@app.route("/leases")
@login_required
def leases():
    subnet_filter = request.args.get("subnet", "all")
    minutes = request.args.get("minutes", "")
    search = sanitize_search(request.args.get("search", "").strip())
    show_expired = request.args.get("expired", "0") == "1"
    sort = request.args.get("sort", "expires")
    direction = request.args.get("dir", "desc")
    if direction not in ("asc", "desc"):
        direction = "desc"
    # Map sort keys to SQL columns
    sort_map = {
        "ip": "l.address",
        "hostname": "l.hostname",
        "mac": "l.hwaddr",
        "subnet": "l.subnet_id",
        "obtained": "(l.expire - INTERVAL l.valid_lifetime SECOND)",
        "expires": "l.expire",
    }
    sort_col = sort_map.get(sort, "l.expire")
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 50
    if subnet_filter != "all":
        try:
            if int(subnet_filter) not in SUBNET_MAP:
                subnet_filter = "all"
        except ValueError:
            subnet_filter = "all"
    leases_list = []
    total = 0
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            where = []
            params = []
            if not show_expired:
                where.append("l.state=0")
            if subnet_filter != "all":
                where.append("l.subnet_id=%s")
                params.append(int(subnet_filter))
            if minutes:
                try:
                    mins = int(minutes)
                    where.append("FROM_UNIXTIME(l.expire) >= DATE_SUB(NOW(), INTERVAL %s MINUTE)")
                    params.append(mins)
                except ValueError:
                    pass
            if search:
                where.append("(inet_ntoa(l.address) LIKE %s OR l.hostname LIKE %s OR HEX(l.hwaddr) LIKE %s)")
                s = f"%{search}%"
                params += [s, s, s.replace(":", "")]
            where_str = " AND ".join(where) if where else "1=1"
            cur.execute(f"SELECT COUNT(*) as cnt FROM lease4 l WHERE {where_str}", params)
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT inet_ntoa(l.address) AS ip, l.hostname,
                       HEX(l.hwaddr) AS mac_hex, l.subnet_id, l.state,
                       l.expire,
                       (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained,
                       l.expire AS expires
                FROM lease4 l WHERE {where_str}
                ORDER BY {sort_col} {direction}
                LIMIT {per_page} OFFSET {offset}
            """, params)
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                leases_list.append({**row, "mac": mac,
                                    "subnet_name": SUBNET_MAP.get(row["subnet_id"], {}).get("name", "")})
        db.close()
    except Exception as e:
        flash(f"Could not load leases: {str(e)}", "error")
    pages = max(1, (total + per_page - 1) // per_page)
    # Fetch device fingerprint info for all MACs on this page
    mac_list = [l["mac"] for l in leases_list if l.get("mac")]
    device_info = get_device_info_map(mac_list)
    return render_template("leases.html", leases=leases_list, page=page, pages=pages,
                           total=total, subnet_filter=subnet_filter, minutes=minutes,
                           search=search, show_expired=show_expired, subnet_map=SUBNET_MAP,
                           sort=sort, direction=direction, device_info=device_info,
                           get_manufacturer_icon_url=get_manufacturer_icon_url,
                           device_type_display=DEVICE_TYPE_DISPLAY)

@app.route("/leases/delete-stale", methods=["POST"])
@login_required
@admin_required
def delete_stale_leases():
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE state != 0")
            deleted = cur.rowcount
        db.commit()
        db.close()
        flash(f"Deleted {deleted} expired/stale lease(s).", "success")
        audit("DELETE_STALE_LEASES", "leases", f"Deleted {deleted}")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("leases"))

@app.route("/leases/release", methods=["POST"])
@login_required
@admin_required
def release_lease():
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("No IP address specified.", "error")
        return redirect(url_for("leases"))
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute("UPDATE lease4 SET state=1 WHERE inet_ntoa(address)=%s", (ip,))
            affected = cur.rowcount
        db.commit()
        db.close()
        if affected:
            flash(f"Lease for {ip} released.", "success")
            audit("RELEASE_LEASE", "leases", f"Released {ip} by {current_user.username}")
        else:
            flash(f"No active lease found for {ip}.", "warning")
    except Exception as e:
        flash(f"Error releasing lease: {str(e)}", "error")
    return redirect(url_for("leases"))

@app.route("/ipmap")
@login_required
def ipmap():
    subnet_filter = request.args.get("subnet", list(SUBNET_MAP.keys())[0] if SUBNET_MAP else 1)
    try:
        subnet_filter = int(subnet_filter)
        if subnet_filter not in SUBNET_MAP:
            subnet_filter = list(SUBNET_MAP.keys())[0]
    except (ValueError, IndexError):
        subnet_filter = list(SUBNET_MAP.keys())[0] if SUBNET_MAP else 1
    leases_by_ip = {}
    reservations_by_ip = {}
    cidr = SUBNET_MAP.get(subnet_filter, {}).get("cidr", "")
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT inet_ntoa(address) AS ip, hostname, HEX(hwaddr) AS mac_hex FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_filter,))
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                leases_by_ip[row["ip"]] = {"hostname": row["hostname"] or "", "mac": mac, "type": "dynamic"}
            cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS mac_hex FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_filter,))
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                reservations_by_ip[row["ip"]] = {"hostname": row["hostname"] or "", "mac": mac, "type": "reserved"}
        db.close()
    except Exception as e:
        flash(f"Could not load IP map: {str(e)}", "error")
    return render_template("ipmap.html", leases=leases_by_ip, reservations=reservations_by_ip,
                           subnet_filter=subnet_filter, subnet_map=SUBNET_MAP, cidr=cidr)

# ─────────────────────────────────────────
# Reservations
# ─────────────────────────────────────────
@app.route("/reservations")
@login_required
def reservations():
    subnet_filter = request.args.get("subnet", "all")
    search = sanitize_search(request.args.get("search", "").strip())
    sort = request.args.get("sort", "ip")
    direction = request.args.get("dir", "asc")
    if direction not in ("asc", "desc"):
        direction = "asc"
    sort_map = {
        "ip": "h.ipv4_address",
        "hostname": "h.hostname",
        "mac": "h.dhcp_identifier",
        "subnet": "h.dhcp4_subnet_id",
    }
    sort_col = sort_map.get(sort, "h.ipv4_address")
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 50
    hosts = []
    total = 0
    try:
        kea_db = get_kea_db()
        jen_db = get_jen_db()
        with kea_db.cursor() as cur:
            where = ["h.dhcp4_subnet_id > 0"]
            params = []
            if subnet_filter != "all":
                try:
                    where.append("h.dhcp4_subnet_id=%s")
                    params.append(int(subnet_filter))
                except ValueError:
                    subnet_filter = "all"
            if search:
                where.append("(inet_ntoa(h.ipv4_address) LIKE %s OR h.hostname LIKE %s OR HEX(h.dhcp_identifier) LIKE %s)")
                s = f"%{search}%"
                params += [s, s, s.replace(":", "")]
            cur.execute(f"SELECT COUNT(*) as cnt FROM hosts h WHERE {' AND '.join(where)}", params)
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT h.host_id, inet_ntoa(h.ipv4_address) AS ip,
                       h.hostname, HEX(h.dhcp_identifier) AS mac_hex,
                       h.dhcp4_subnet_id AS subnet_id
                FROM hosts h
                WHERE {' AND '.join(where)}
                ORDER BY {sort_col} {direction}
                LIMIT {per_page} OFFSET {offset}
            """, params)
            rows = cur.fetchall()
            with jen_db.cursor() as jcur:
                for row in rows:
                    mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                    jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (row["host_id"],))
                    note = jcur.fetchone()
                    hosts.append({**row, "mac": mac,
                                  "notes": note["notes"] if note else "",
                                  "subnet_name": SUBNET_MAP.get(row["subnet_id"], {}).get("name", "")})
        kea_db.close()
        jen_db.close()
    except Exception as e:
        flash(f"Could not load reservations: {str(e)}", "error")
    pages = max(1, (total + per_page - 1) // per_page)
    stale_days = int(get_global_setting("stale_device_days", "30"))
    mac_list = [h["mac"] for h in hosts if h.get("mac")]
    device_info = get_device_info_map(mac_list)
    return render_template("reservations.html", hosts=hosts,
                           subnet_filter=subnet_filter, search=search,
                           subnet_map=SUBNET_MAP, page=page, pages=pages,
                           total=total, stale_days=stale_days,
                           sort=sort, direction=direction, device_info=device_info,
                           get_manufacturer_icon_url=get_manufacturer_icon_url,
                           device_type_display=DEVICE_TYPE_DISPLAY)

@app.route("/reservations/add")
@login_required
@admin_required
def add_reservation():
    prefill = {
        "ip": request.args.get("ip", ""),
        "mac": request.args.get("mac", ""),
        "hostname": request.args.get("hostname", ""),
        "subnet_id": request.args.get("subnet_id", ""),
    }
    return render_template("add_reservation.html", subnet_map=SUBNET_MAP, prefill=prefill)

@app.route("/reservations/add", methods=["POST"])
@login_required
@admin_required
def add_reservation_post():
    ip = request.form.get("ip", "").strip()
    mac = request.form.get("mac", "").strip().lower()
    hostname = request.form.get("hostname", "").strip()[:253]
    notes = request.form.get("notes", "").strip()[:1000]
    dns_override = request.form.get("dns_override", "").strip()
    try:
        subnet_id = int(request.form.get("subnet_id", 1))
    except ValueError:
        flash("Invalid subnet.", "error")
        return redirect(url_for("add_reservation"))
    errors = []
    if not valid_ip(ip): errors.append(f"Invalid IP: {ip}")
    if not valid_mac(mac): errors.append(f"Invalid MAC: {mac}")
    if hostname and not valid_hostname(hostname): errors.append(f"Invalid hostname: {hostname}")
    if dns_override and not valid_dns(dns_override): errors.append(f"Invalid DNS: {dns_override}")
    if errors:
        for e in errors: flash(e, "error")
        return redirect(url_for("add_reservation"))
    res = {"subnet-id": subnet_id, "hw-address": mac, "ip-address": ip, "hostname": hostname}
    if dns_override:
        res["option-data"] = [{"name": "domain-name-servers", "data": dns_override}]
    result = kea_command("reservation-add", arguments={"reservation": res})
    if result.get("result") == 0:
        if notes:
            try:
                db = get_kea_db()
                with db.cursor() as cur:
                    cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s", (ip,))
                    row = cur.fetchone()
                    if row:
                        jdb = get_jen_db()
                        with jdb.cursor() as jcur:
                            jcur.execute("INSERT INTO reservation_notes (host_id, notes) VALUES (%s,%s) ON DUPLICATE KEY UPDATE notes=%s",
                                         (row["host_id"], notes, notes))
                        jdb.commit(); jdb.close()
                db.close()
            except Exception:
                pass
        flash(f"Reservation added: {ip} → {mac}", "success")
        audit("ADD_RESERVATION", ip, f"MAC={mac} hostname={hostname}")
        return redirect(url_for("reservations"))
    else:
        flash(f"Kea error: {result.get('text', 'Unknown error')}", "error")
        return redirect(url_for("add_reservation"))

@app.route("/reservations/edit/<int:host_id>")
@login_required
@admin_required
def edit_reservation(host_id):
    try:
        db = get_kea_db()
        jdb = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT host_id, inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE host_id=%s", (host_id,))
            host = cur.fetchone()
            if not host:
                flash("Reservation not found.", "error")
                return redirect(url_for("reservations"))
            mac = ":".join(host["mac_hex"][i:i+2] for i in range(0,12,2)) if host["mac_hex"] else ""
            cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (host_id,))
            dns_row = cur.fetchone()
            host["mac"] = mac
            host["dns_override"] = dns_row["formatted_value"] if dns_row else ""
        with jdb.cursor() as jcur:
            jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (host_id,))
            note = jcur.fetchone()
            host["notes"] = note["notes"] if note else ""
        db.close(); jdb.close()
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for("reservations"))
    return render_template("edit_reservation.html", host=host, subnet_map=SUBNET_MAP)

@app.route("/reservations/edit/<int:host_id>", methods=["POST"])
@login_required
@admin_required
def edit_reservation_post(host_id):
    hostname = request.form.get("hostname", "").strip()[:253]
    notes = request.form.get("notes", "").strip()[:1000]
    dns_override = request.form.get("dns_override", "").strip()
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE host_id=%s", (host_id,))
            host = cur.fetchone()
            if not host:
                flash("Reservation not found.", "error")
                return redirect(url_for("reservations"))
            mac = ":".join(host["mac_hex"][i:i+2] for i in range(0,12,2)) if host["mac_hex"] else ""
            kea_command("reservation-del", arguments={"subnet-id": host["subnet_id"], "identifier-type": "hw-address", "identifier": mac})
            res = {"subnet-id": host["subnet_id"], "hw-address": mac, "ip-address": host["ip"], "hostname": hostname}
            if dns_override:
                res["option-data"] = [{"name": "domain-name-servers", "data": dns_override}]
            result = kea_command("reservation-add", arguments={"reservation": res})
            if result.get("result") != 0:
                flash(f"Kea error: {result.get('text')}", "error")
                return redirect(url_for("edit_reservation", host_id=host_id))
        db.close()
        jdb = get_jen_db()
        with jdb.cursor() as jcur:
            jcur.execute("INSERT INTO reservation_notes (host_id, notes) VALUES (%s,%s) ON DUPLICATE KEY UPDATE notes=%s",
                         (host_id, notes, notes))
        jdb.commit(); jdb.close()
        flash("Reservation updated.", "success")
        audit("EDIT_RESERVATION", host["ip"], f"hostname={hostname}")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("reservations"))

@app.route("/reservations/delete/<int:host_id>", methods=["POST"])
@login_required
@admin_required
def delete_reservation(host_id):
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE host_id=%s", (host_id,))
            host = cur.fetchone()
            if host:
                mac = ":".join(host["mac_hex"][i:i+2] for i in range(0,12,2)) if host["mac_hex"] else ""
                result = kea_command("reservation-del", arguments={"subnet-id": host["subnet_id"], "identifier-type": "hw-address", "identifier": mac})
                if result.get("result") == 0:
                    jdb = get_jen_db()
                    with jdb.cursor() as jcur:
                        jcur.execute("DELETE FROM reservation_notes WHERE host_id=%s", (host_id,))
                    jdb.commit(); jdb.close()
                    flash(f"Reservation {host['ip']} deleted.", "success")
                    audit("DELETE_RESERVATION", host["ip"], f"MAC={mac}")
                else:
                    flash(f"Kea error: {result.get('text')}", "error")
        db.close()
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("reservations"))

@app.route("/reservations/export")
@login_required
def export_reservations():
    try:
        db = get_kea_db()
        jdb = get_jen_db()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ip", "mac", "hostname", "subnet_id", "subnet_name", "dns_override", "notes"])
        with db.cursor() as cur:
            cur.execute("SELECT host_id, inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE dhcp4_subnet_id > 0 ORDER BY ipv4_address")
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)) if row["mac_hex"] else ""
                cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (row["host_id"],))
                dns_row = cur.fetchone()
                dns = dns_row["formatted_value"] if dns_row else ""
                with jdb.cursor() as jcur:
                    jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (row["host_id"],))
                    note = jcur.fetchone()
                subnet_name = SUBNET_MAP.get(row["subnet_id"], {}).get("name", "")
                writer.writerow([row["ip"], mac, row["hostname"] or "", row["subnet_id"], subnet_name, dns, note["notes"] if note else ""])
        db.close(); jdb.close()
        output.seek(0)
        return Response(output.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=reservations.csv"})
    except Exception as e:
        flash(f"Export error: {str(e)}", "error")
        return redirect(url_for("reservations"))

@app.route("/reservations/import", methods=["POST"])
@login_required
@admin_required
def import_reservations():
    dry_run = request.args.get("dry_run", "0") == "1"
    csv_file = request.files.get("csv_file")
    if not csv_file or not csv_file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("reservations"))
    results = {"added": 0, "skipped": 0, "errors": []}
    try:
        stream = io.StringIO(csv_file.stream.read().decode("utf-8-sig"))
        reader = csv.DictReader(stream)
        db = get_kea_db()
        for i, row in enumerate(reader, 1):
            ip = (row.get("ip") or row.get("IP") or "").strip()
            mac = (row.get("mac") or row.get("MAC") or "").strip().lower().replace("-", ":")
            hostname = (row.get("hostname") or row.get("HOSTNAME") or "").strip()
            subnet_id = (row.get("subnet_id") or row.get("SUBNET_ID") or "").strip()
            if not ip or not mac:
                results["errors"].append(f"Row {i}: missing IP or MAC")
                continue
            try:
                subnet_id = int(subnet_id)
                if subnet_id not in SUBNET_MAP:
                    results["errors"].append(f"Row {i}: unknown subnet_id {subnet_id}")
                    continue
            except (ValueError, TypeError):
                results["errors"].append(f"Row {i}: invalid subnet_id")
                continue
            mac_bytes = mac.replace(":", "")
            if len(mac_bytes) != 12:
                results["errors"].append(f"Row {i}: invalid MAC {mac}")
                continue
            if not dry_run:
                with db.cursor() as cur:
                    # Check for duplicate
                    cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s AND dhcp4_subnet_id=%s", (ip, subnet_id))
                    if cur.fetchone():
                        results["skipped"] += 1
                        continue
                    cur.execute("""INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id,
                                   ipv4_address, hostname, dhcp4_client_classes, dhcp6_client_classes)
                                   VALUES (UNHEX(%s), 1, %s, INET_ATON(%s), %s, '', '')""",
                                (mac_bytes, subnet_id, ip, hostname))
            results["added"] += 1
        if not dry_run:
            db.commit()
        db.close()
        if dry_run:
            flash(f"Dry run: {results['added']} would be added, {results['skipped']} skipped. {len(results['errors'])} error(s).", "info")
        else:
            flash(f"Import complete: {results['added']} added, {results['skipped']} skipped. {len(results['errors'])} error(s).", "success")
            audit("IMPORT_RESERVATIONS", "reservations", f"Added {results['added']} by {current_user.username}")
        for err in results["errors"][:10]:
            flash(err, "warning")
    except Exception as e:
        flash(f"Import error: {str(e)}", "error")
    return redirect(url_for("reservations"))

# ─────────────────────────────────────────
# Subnets
# ─────────────────────────────────────────
@app.route("/subnets")
@login_required
def subnets():
    subnet_data = []
    # Fetch Kea config for lease times, timers, pools
    kea_subnets = {}
    try:
        result = kea_command("config-get", server=get_active_kea_server())
        if result.get("result") == 0:
            cfg = result["arguments"]["Dhcp4"]
            global_lifetime = cfg.get("valid-lifetime", 0)
            global_renew = cfg.get("renew-timer", 0)
            global_rebind = cfg.get("rebind-timer", 0)
            for s in cfg.get("subnet4", []):
                pools = []
                for p in s.get("pools", []):
                    pool_str = p.get("pool", "") if isinstance(p, dict) else str(p)
                    if pool_str:
                        pools.append(pool_str)
                kea_subnets[s["id"]] = {
                    "valid_lifetime": s.get("valid-lifetime", global_lifetime),
                    "renew_timer": s.get("renew-timer", global_renew),
                    "rebind_timer": s.get("rebind-timer", global_rebind),
                    "pools": pools,
                }
    except Exception:
        pass
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            for subnet_id, info in SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                active = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                reserved = cur.fetchone()["cnt"]
                kea = kea_subnets.get(subnet_id, {})
                subnet_data.append({
                    "id": subnet_id,
                    "name": info["name"],
                    "cidr": info["cidr"],
                    "active": active,
                    "reserved": reserved,
                    "valid_lifetime": kea.get("valid_lifetime", 0),
                    "renew_timer": kea.get("renew_timer", 0),
                    "rebind_timer": kea.get("rebind_timer", 0),
                    "pools": kea.get("pools", []),
                })
        db.close()
    except Exception as e:
        flash(f"Could not load subnet data: {str(e)}", "error")
    ssh_ready = os.path.exists(SSH_KEY_PATH) and bool(KEA_SSH_HOST)
    subnet_notes = {}
    try:
        jdb = get_jen_db()
        with jdb.cursor() as jcur:
            jcur.execute("SELECT subnet_id, notes FROM subnet_notes")
            for row in jcur.fetchall():
                subnet_notes[row["subnet_id"]] = row["notes"]
        jdb.close()
    except Exception:
        pass
    return render_template("subnets.html", subnets=subnet_data, ssh_ready=ssh_ready,
                           subnet_notes=subnet_notes)

@app.route("/subnets/edit/<int:subnet_id>")
@login_required
@admin_required
def edit_subnet(subnet_id):
    if subnet_id not in SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for("subnets"))
    return render_template("edit_subnet.html", subnet_id=subnet_id,
                           subnet=SUBNET_MAP[subnet_id], subnet_map=SUBNET_MAP)

@app.route("/subnets/edit/<int:subnet_id>", methods=["POST"])
@login_required
@admin_required
def edit_subnet_post(subnet_id):
    if subnet_id not in SUBNET_MAP:
        flash("Subnet not found.", "error")
        return redirect(url_for("subnets"))
    action = request.form.get("action", "")
    config_text = request.form.get("config", "")
    errors = []
    results = []
    for server in KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        try:
            import base64, tempfile
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server["ssh_host"], username=server.get("ssh_user", KEA_SSH_USER),
                        key_filename=SSH_KEY_PATH, timeout=10)
            script = f"""
import json, sys
path = {repr(server.get('kea_conf', '/etc/kea/kea-dhcp4.conf'))}
with open(path) as f: cfg = json.load(f)
for s in cfg.get('Dhcp4', {{}}).get('subnet4', []):
    if s['id'] == {subnet_id}:
        s['subnet'] = {repr(config_text.strip())}
        break
with open(path, 'w') as f: json.dump(cfg, f, indent=2)
print('ok')
"""
            enc = base64.b64encode(script.encode()).decode()
            _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            if "ok" in out:
                ssh.exec_command("sudo systemctl restart isc-kea-dhcp4-server")
                results.append(f"✅ {server.get('name', server['ssh_host'])}: updated")
            else:
                errors.append(f"❌ {server.get('name', server['ssh_host'])}: {err or out}")
            ssh.close()
        except Exception as e:
            errors.append(f"❌ {server.get('name', server.get('ssh_host','?'))}: {str(e)}")
    for r in results: flash(r, "success")
    for e in errors: flash(e, "error")
    audit("EDIT_SUBNET", str(subnet_id), f"action={action}")
    return redirect(url_for("subnets"))

# ─────────────────────────────────────────
# DDNS
# ─────────────────────────────────────────
@app.route("/ddns")
@login_required
def ddns():
    lines = []
    log_status = "ok"
    log_message = ""
    if not KEA_SSH_HOST:
        log_status = "error"
        log_message = "SSH host not configured. Set it in Settings → Infrastructure → SSH."
    else:
        try:
            result = subprocess.run(
                ["ssh", "-i", SSH_KEY_PATH,
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=10",
                 f"{KEA_SSH_USER}@{KEA_SSH_HOST}",
                 f"sudo tail -200 {DDNS_LOG}"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                err = result.stderr.strip()
                if "No such file" in err or "No such file" in result.stdout:
                    log_status = "missing"
                    log_message = f"Log file not found on Kea server: {DDNS_LOG}"
                else:
                    log_status = "error"
                    log_message = f"SSH error: {err or 'unknown error'}"
                    logger.error(f"DDNS SSH error: {err}")
            else:
                raw_lines = result.stdout.splitlines()
                lines = list(reversed(raw_lines))
                if not lines:
                    log_status = "empty"
                    log_message = "Log file exists but contains no entries yet."
        except subprocess.TimeoutExpired:
            log_status = "error"
            log_message = f"SSH connection timed out. Check that {KEA_SSH_HOST} is reachable."
            logger.error("DDNS SSH timeout")
        except Exception as e:
            log_status = "error"
            log_message = f"Could not read DDNS log: {str(e)}"
            logger.error(f"DDNS error: {e}")
    lookup_host = request.args.get("host", "")
    lookup_result = ""
    if lookup_host:
        try:
            dns_provider = cfg.get("ddns", "dns_provider", fallback="technitium")
            if dns_provider == "technitium":
                dns_url = cfg.get("ddns", "api_url", fallback="")
                dns_token = cfg.get("ddns", "api_token", fallback="")
                forward_zone = cfg.get("ddns", "forward_zone", fallback="")
                if dns_url and dns_token:
                    import requests as req
                    r = req.get(f"{dns_url}/api/zones/records/get",
                                params={"token": dns_token, "domain": lookup_host, "zone": forward_zone},
                                timeout=5)
                    data = r.json()
                    records = data.get("response", {}).get("records", [])
                    if records:
                        lookup_result = records
                    else:
                        lookup_result = f"No DNS records found for {lookup_host}"
                else:
                    lookup_result = "Technitium API not configured."

            elif dns_provider == "pihole":
                dns_url = cfg.get("ddns", "api_url", fallback="")
                dns_pass = cfg.get("ddns", "api_token", fallback="")
                if dns_url:
                    import requests as req
                    # Try Pi-hole v6 API first
                    try:
                        auth = req.post(f"{dns_url}/api/auth",
                                        json={"password": dns_pass}, timeout=5)
                        if auth.status_code == 200 and auth.json().get("session", {}).get("valid"):
                            sid = auth.json()["session"]["sid"]
                            r = req.get(f"{dns_url}/api/dns/records",
                                        params={"domain": lookup_host},
                                        headers={"X-FTL-SID": sid}, timeout=5)
                            data = r.json()
                            records = data.get("records", [])
                            lookup_result = records if records else f"No DNS records found for {lookup_host}"
                        else:
                            raise Exception("Auth failed")
                    except Exception:
                        # Fallback to Pi-hole v5 API
                        r = req.get(f"{dns_url}/admin/api.php",
                                    params={"customdns": "", "action": "get", "auth": dns_pass},
                                    timeout=5)
                        data = r.json()
                        matches = [e for e in data.get("data", []) if lookup_host in str(e)]
                        lookup_result = matches if matches else f"No records found for {lookup_host} (Pi-hole v5 API)"
                else:
                    lookup_result = "Pi-hole API URL not configured."

            elif dns_provider == "adguard":
                dns_url = cfg.get("ddns", "api_url", fallback="")
                dns_user = cfg.get("ddns", "api_user", fallback="")
                dns_pass = cfg.get("ddns", "api_token", fallback="")
                if dns_url:
                    import requests as req
                    r = req.get(f"{dns_url}/control/rewrite/list",
                                auth=(dns_user, dns_pass), timeout=5)
                    data = r.json()
                    matches = [e for e in data if lookup_host in str(e.get("domain", ""))]
                    lookup_result = matches if matches else f"No rewrite rules found for {lookup_host}"
                else:
                    lookup_result = "AdGuard Home URL not configured."

            elif dns_provider in ("ssh", "generic"):
                # DNS lookup via dig/host over SSH to Kea server
                active = get_active_kea_server()
                ssh_host = active.get("ssh_host") or KEA_SSH_HOST
                ssh_user = active.get("ssh_user") or KEA_SSH_USER
                if ssh_host:
                    result = subprocess.run(
                        ["ssh", "-i", SSH_KEY_PATH, "-o", "StrictHostKeyChecking=no",
                         "-o", "ConnectTimeout=10",
                         f"{ssh_user}@{ssh_host}",
                         f"dig +short {lookup_host} 2>/dev/null || host {lookup_host} 2>/dev/null"],
                        capture_output=True, text=True, timeout=10
                    )
                    lookup_result = result.stdout.strip() or f"No DNS result for {lookup_host}"
                else:
                    import socket
                    lookup_result = socket.gethostbyname(lookup_host)

            else:
                lookup_result = "DNS lookup not configured."
        except Exception as e:
            lookup_result = f"Lookup error: {str(e)}"
    return render_template("ddns.html", lines=lines, lookup_host=lookup_host,
                           lookup_result=lookup_result, log_status=log_status,
                           log_message=log_message, ddns_log=DDNS_LOG,
                           dns_provider=cfg.get("ddns", "dns_provider", fallback="technitium"))

# ─────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────
@app.route("/audit")
@login_required
@admin_required
def audit_log():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    search = sanitize_search(request.args.get("search", "").strip())
    per_page = 50
    logs = []
    total = 0
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            where = []
            params = []
            if search:
                where.append("(username LIKE %s OR action LIKE %s OR entity LIKE %s OR details LIKE %s)")
                s = f"%{search}%"
                params += [s, s, s, s]
            where_str = " WHERE " + " AND ".join(where) if where else ""
            cur.execute(f"SELECT COUNT(*) as cnt FROM audit_log{where_str}", params)
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute(f"SELECT * FROM audit_log{where_str} ORDER BY created_at DESC LIMIT {per_page} OFFSET {offset}", params)
            logs = cur.fetchall()
        db.close()
    except Exception as e:
        flash(f"Could not load audit log: {str(e)}", "error")
    pages = max(1, (total + per_page - 1) // per_page)
    return render_template("audit.html", logs=logs, page=page, pages=pages,
                           total=total, search=search)

# ─────────────────────────────────────────
# About
# ─────────────────────────────────────────
@app.route("/about")
@login_required
def about():
    kea_up = False
    kea_version = ""
    lease_counts = {}
    try:
        ver_result = kea_command("version-get")
        if ver_result.get("result") == 0:
            kea_up = True
            kea_version = ver_result.get("arguments", {}).get("extended", ver_result.get("text", ""))
            kea_version = kea_version.splitlines()[0] if kea_version else ""
    except Exception:
        pass
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            for sid in SUBNET_MAP:
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (sid,))
                lease_counts[sid] = cur.fetchone()["cnt"]
        db.close()
    except Exception:
        pass
    return render_template("about.html", jen_version=JEN_VERSION, kea_version=kea_version,
                           kea_up=kea_up, https_port=HTTPS_PORT, subnet_map=SUBNET_MAP,
                           lease_counts=lease_counts)

# ─────────────────────────────────────────
@app.route("/settings")
@login_required
@admin_required
def settings():
    return redirect(url_for("settings_system"))

@app.route("/settings/system")
@login_required
@admin_required
def settings_system():
    cert_info = {}
    if ssl_configured():
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", SSL_COMBINED if os.path.exists(SSL_COMBINED) else SSL_CERT,
                 "-noout", "-subject", "-enddate", "-issuer"],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                if line.startswith("subject="): cert_info["subject"] = line.replace("subject=", "").strip()
                elif line.startswith("notAfter="): cert_info["expires"] = line.replace("notAfter=", "").strip()
                elif line.startswith("issuer="): cert_info["issuer"] = line.replace("issuer=", "").strip()
        except Exception as e:
            cert_info["error"] = str(e)

    ssh_pub_key = ""
    if os.path.exists(SSH_KEY_PATH + ".pub"):
        try:
            with open(SSH_KEY_PATH + ".pub") as f:
                ssh_pub_key = f.read().strip()
        except Exception:
            pass

    telegram_settings = {
        "enabled": get_global_setting("telegram_enabled", "false"),
        "token": get_global_setting("telegram_token", ""),
        "chat_id": get_global_setting("telegram_chat_id", ""),
        "alert_kea_down": get_global_setting("alert_kea_down", "true"),
        "alert_new_lease": get_global_setting("alert_new_lease", "false"),
        "alert_utilization": get_global_setting("alert_utilization", "true"),
        "alert_threshold_pct": get_global_setting("alert_threshold_pct", "80"),
    }
    session_settings = {
        "timeout": get_global_setting("session_timeout_minutes", "60"),
        "enabled": get_global_setting("session_timeout_enabled", "true"),
    }
    rl_settings = {
        "max_attempts": get_global_setting("rl_max_attempts", "10"),
        "lockout_minutes": get_global_setting("rl_lockout_minutes", "15"),
        "mode": get_global_setting("rl_mode", "both"),
    }

    # Get current lockout counts for admin visibility
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(DISTINCT ip_address) as cnt FROM login_attempts WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)")
            rl_active_ips = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM login_attempts WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)")
            rl_attempts_1h = cur.fetchone()["cnt"]
        db.close()
    except Exception:
        rl_active_ips = 0
        rl_attempts_1h = 0

    # Get Kea version
    kea_version = ""
    try:
        ver_result = kea_command("version-get")
        if ver_result.get("result") == 0:
            kea_version = ver_result.get("arguments", {}).get("extended", ver_result.get("text", ""))
            kea_version = kea_version.splitlines()[0] if kea_version else ""
    except Exception:
        pass

    mfa_mode = get_mfa_mode()
    nav_logo_url = None
    for ext in ("png", "svg", "jpg", "jpeg", "webp"):
        if os.path.exists(f"{NAV_LOGO_PATH}.{ext}"):
            nav_logo_url = f"/static/nav_logo.{ext}?v={int(os.path.getmtime(f'{NAV_LOGO_PATH}.{ext}'))}"
            break
    branding = {
        "nav_logo": nav_logo_url,
        "nav_color": get_global_setting("branding_nav_color", ""),
    }
    return render_template("settings_system.html",
                           ssl_configured=ssl_configured(), cert_info=cert_info,
                           has_favicon=os.path.exists(FAVICON_PATH),
                           https_port=HTTPS_PORT, ssh_pub_key=ssh_pub_key,
                           ssh_configured=bool(ssh_pub_key),
                           kea_ssh_host=KEA_SSH_HOST, kea_ssh_user=KEA_SSH_USER,
                           telegram=telegram_settings, session=session_settings,
                           rl=rl_settings, rl_active_ips=rl_active_ips,
                           rl_attempts_1h=rl_attempts_1h,
                           jen_version=JEN_VERSION,
                           kea_version=kea_version,
                           mfa_mode=mfa_mode,
                           branding=branding)

@app.route("/settings/system/save-mfa-mode", methods=["POST"])
@login_required
@admin_required
def save_mfa_mode():
    mode = request.form.get("mfa_mode", "off")
    if mode not in ("off", "optional", "required_admins", "required_all"):
        flash("Invalid MFA mode.", "error")
        return redirect(url_for("settings_system"))
    set_global_setting("mfa_mode", mode)
    labels = {"off": "Off", "optional": "Optional", "required_admins": "Required for Admins", "required_all": "Required for All"}
    flash(f"MFA policy set to: {labels.get(mode, mode)}", "success")
    audit("SAVE_MFA_MODE", "settings", f"mode={mode} by {current_user.username}")
    return redirect(url_for("settings_system"))

@app.route("/settings/alerts")
@login_required
@admin_required
def settings_alerts():
    import json
    channels = []
    templates = {}
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM alert_channels ORDER BY channel_type, channel_name")
            channels = cur.fetchall()
            # Parse JSON fields
            for ch in channels:
                if isinstance(ch.get("config"), str):
                    try: ch["config"] = json.loads(ch["config"])
                    except (json.JSONDecodeError, ValueError): ch["config"] = {}
                if isinstance(ch.get("alert_types"), str):
                    try: ch["alert_types"] = json.loads(ch["alert_types"])
                    except (json.JSONDecodeError, ValueError): ch["alert_types"] = []
            cur.execute("SELECT alert_type, template_text FROM alert_templates")
            for row in cur.fetchall():
                templates[row["alert_type"]] = row["template_text"]
        db.close()
    except Exception as e:
        flash(f"Error loading alert settings: {e}", "error")
    summary_time = get_global_setting("daily_summary_time", "07:00")
    pool_exhaustion_free = get_global_setting("pool_exhaustion_free", "5")
    threshold_pct = get_global_setting("alert_threshold_pct", "80")
    return render_template("settings_alerts.html",
                           channels=channels, templates=templates,
                           default_templates=DEFAULT_TEMPLATES,
                           alert_type_labels=ALERT_TYPE_LABELS,
                           summary_time=summary_time,
                           pool_exhaustion_free=pool_exhaustion_free,
                           threshold_pct=threshold_pct)

@app.route("/settings/alerts/save-channel", methods=["POST"])
@login_required
@admin_required
def save_alert_channel():
    import json
    channel_id = request.form.get("channel_id", "").strip()
    channel_type = request.form.get("channel_type", "").strip()
    channel_name = request.form.get("channel_name", "").strip()[:100]
    enabled = 1 if request.form.get("enabled") else 0
    alert_types = request.form.getlist("alert_types[]")

    if channel_type not in ("telegram", "email", "slack", "webhook", "ntfy", "discord"):
        flash("Invalid channel type.", "error")
        return redirect(url_for("settings_alerts"))
    if not channel_name:
        flash("Channel name is required.", "error")
        return redirect(url_for("settings_alerts"))

    # Build config based on type
    config = {}
    if channel_type == "telegram":
        config = {
            "token": request.form.get("token", "").strip(),
            "chat_id": request.form.get("chat_id", "").strip(),
        }
    elif channel_type == "email":
        config = {
            "smtp_host": request.form.get("smtp_host", "").strip(),
            "smtp_port": request.form.get("smtp_port", "587").strip(),
            "smtp_user": request.form.get("smtp_user", "").strip(),
            "smtp_pass": request.form.get("smtp_pass", "").strip(),
            "from_addr": request.form.get("from_addr", "").strip(),
            "to_addr": request.form.get("to_addr", "").strip(),
            "use_tls": "true" if request.form.get("use_tls") else "false",
        }
    elif channel_type == "slack":
        config = {"webhook_url": request.form.get("slack_webhook", "").strip()}
    elif channel_type == "webhook":
        config = {
            "webhook_url": request.form.get("webhook_url", "").strip(),
            "payload_type": request.form.get("payload_type", "json").strip(),
            "header_name": request.form.get("header_name", "").strip(),
            "header_value": request.form.get("header_value", "").strip(),
        }
    elif channel_type == "ntfy":
        config = {
            "url": request.form.get("ntfy_url", "https://ntfy.sh").strip(),
            "topic": request.form.get("ntfy_topic", "").strip(),
            "token": request.form.get("ntfy_token", "").strip(),
            "priority": request.form.get("ntfy_priority", "default").strip(),
        }
    elif channel_type == "discord":
        config = {
            "webhook_url": request.form.get("discord_webhook", "").strip(),
        }

    # Don't overwrite password if blank
    if channel_id and channel_type == "email" and not config["smtp_pass"]:
        try:
            db = get_jen_db()
            with db.cursor() as cur:
                cur.execute("SELECT config FROM alert_channels WHERE id=%s", (channel_id,))
                row = cur.fetchone()
                if row:
                    existing = json.loads(row["config"]) if isinstance(row["config"], str) else row["config"]
                    config["smtp_pass"] = existing.get("smtp_pass", "")
            db.close()
        except Exception:
            pass

    try:
        db = get_jen_db()
        with db.cursor() as cur:
            if channel_id:
                cur.execute("""
                    UPDATE alert_channels SET channel_name=%s, enabled=%s, config=%s, alert_types=%s
                    WHERE id=%s
                """, (channel_name, enabled, json.dumps(config), json.dumps(alert_types), channel_id))
            else:
                cur.execute("""
                    INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types)
                    VALUES (%s, %s, %s, %s, %s)
                """, (channel_type, channel_name, enabled, json.dumps(config), json.dumps(alert_types)))
        db.commit()
        db.close()
        flash(f"Alert channel '{channel_name}' saved.", "success")
        audit("SAVE_ALERT_CHANNEL", channel_name, f"type={channel_type} enabled={enabled}")
    except Exception as e:
        flash(f"Error saving channel: {str(e)}", "error")
    return redirect(url_for("settings_alerts"))

@app.route("/settings/alerts/delete-channel/<int:channel_id>", methods=["POST"])
@login_required
@admin_required
def delete_alert_channel(channel_id):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT channel_name FROM alert_channels WHERE id=%s", (channel_id,))
            row = cur.fetchone()
            cur.execute("DELETE FROM alert_channels WHERE id=%s", (channel_id,))
        db.commit()
        db.close()
        flash(f"Alert channel deleted.", "success")
        audit("DELETE_ALERT_CHANNEL", str(channel_id), "")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("settings_alerts"))

@app.route("/settings/alerts/test-channel/<int:channel_id>", methods=["POST"])
@login_required
@admin_required
def test_alert_channel(channel_id):
    import json
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM alert_channels WHERE id=%s", (channel_id,))
            channel = cur.fetchone()
        db.close()
        if not channel:
            flash("Channel not found.", "error")
            return redirect(url_for("settings_alerts"))
        config = json.loads(channel["config"]) if isinstance(channel["config"], str) else channel["config"]
        ctype = channel["channel_type"]
        test_msg = f"🔔 <b>Jen Test</b>\nTest message from channel: {channel['channel_name']}"
        if ctype == "telegram":
            ok = _send_telegram_channel(test_msg, config)
        elif ctype == "email":
            ok = _send_email_channel(test_msg, "test", config)
        elif ctype == "slack":
            ok = _send_slack_channel(test_msg, config)
        elif ctype == "webhook":
            ok = _send_webhook_channel(test_msg, "test", config)
        elif ctype == "ntfy":
            ok = _send_ntfy_channel(test_msg, config)
        elif ctype == "discord":
            ok = _send_discord_channel(test_msg, config)
        else:
            ok = False
        if ok:
            flash(f"Test message sent successfully to '{channel['channel_name']}'.", "success")
        else:
            flash(f"Test failed for '{channel['channel_name']}'.", "error")
    except Exception as e:
        flash(f"Test error: {str(e)}", "error")
    return redirect(url_for("settings_alerts"))

@app.route("/settings/alerts/save-template", methods=["POST"])
@login_required
@admin_required
def save_alert_template():
    alert_type = request.form.get("alert_type", "").strip()
    template_text = request.form.get("template_text", "").strip()
    if alert_type not in DEFAULT_TEMPLATES:
        flash("Invalid alert type.", "error")
        return redirect(url_for("settings_alerts"))
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO alert_templates (alert_type, template_text) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE template_text=%s, updated_at=NOW()
            """, (alert_type, template_text, template_text))
        db.commit()
        db.close()
        flash(f"Template for '{ALERT_TYPE_LABELS.get(alert_type, alert_type)}' saved.", "success")
        audit("SAVE_ALERT_TEMPLATE", alert_type, "Template updated")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("settings_alerts"))

@app.route("/settings/alerts/reset-template", methods=["POST"])
@login_required
@admin_required
def reset_alert_template():
    alert_type = request.form.get("alert_type", "").strip()
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM alert_templates WHERE alert_type=%s", (alert_type,))
        db.commit()
        db.close()
        flash(f"Template reset to default.", "success")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("settings_alerts"))

@app.route("/settings/alerts/save-global", methods=["POST"])
@login_required
@admin_required
def save_alert_global():
    summary_time = request.form.get("summary_time", "07:00").strip()
    pool_free = request.form.get("pool_exhaustion_free", "5").strip()
    threshold = request.form.get("alert_threshold_pct", "80").strip()
    if not pool_free.isdigit() or int(pool_free) < 1:
        flash("Pool exhaustion threshold must be a positive number.", "error")
        return redirect(url_for("settings_alerts"))
    if not threshold.isdigit() or not (1 <= int(threshold) <= 100):
        flash("Utilization threshold must be between 1 and 100.", "error")
        return redirect(url_for("settings_alerts"))
    set_global_setting("daily_summary_time", summary_time)
    set_global_setting("pool_exhaustion_free", pool_free)
    set_global_setting("alert_threshold_pct", threshold)
    flash("Global alert settings saved.", "success")
    return redirect(url_for("settings_alerts"))

@app.route("/settings/infrastructure")
@login_required
@admin_required
def settings_infrastructure():
    kea_up = kea_is_up()
    ssh_pub_key = ""
    if os.path.exists(SSH_KEY_PATH + ".pub"):
        try:
            with open(SSH_KEY_PATH + ".pub") as f:
                ssh_pub_key = f.read().strip()
        except Exception:
            pass
    # Load extra servers
    extra_servers = []
    n = 2
    while cfg.has_section(f"kea_server_{n}"):
        sec = f"kea_server_{n}"
        extra_servers.append({
            "id": n,
            "name": cfg.get(sec, "name", fallback=f"Kea Server {n}"),
            "api_url": cfg.get(sec, "api_url", fallback=""),
            "api_user": cfg.get(sec, "api_user", fallback=""),
            "ssh_host": cfg.get(sec, "ssh_host", fallback=""),
            "ssh_user": cfg.get(sec, "ssh_user", fallback=""),
            "kea_conf": cfg.get(sec, "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
            "role": cfg.get(sec, "role", fallback="standby"),
        })
        n += 1

    infra = {
        "kea_api_url": cfg.get("kea", "api_url", fallback=""),
        "kea_api_user": cfg.get("kea", "api_user", fallback=""),
        "kea_api_pass": cfg.get("kea", "api_pass", fallback=""),
        "kea_db_host": cfg.get("kea_db", "host", fallback=""),
        "kea_db_user": cfg.get("kea_db", "user", fallback=""),
        "kea_db_name": cfg.get("kea_db", "database", fallback="kea"),
        "jen_db_host": cfg.get("jen_db", "host", fallback=""),
        "jen_db_user": cfg.get("jen_db", "user", fallback=""),
        "jen_db_name": cfg.get("jen_db", "database", fallback="jen"),
        "ssh_host": cfg.get("kea_ssh", "host", fallback=""),
        "ssh_user": cfg.get("kea_ssh", "user", fallback=""),
        "kea_conf": cfg.get("kea_ssh", "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
        "ddns_log": cfg.get("ddns", "log_path", fallback=""),
        "ddns_url": cfg.get("ddns", "api_url", fallback=""),
        "ddns_user": cfg.get("ddns", "api_user", fallback=""),
        "ddns_zone": cfg.get("ddns", "forward_zone", fallback=""),
        "dns_provider": cfg.get("ddns", "dns_provider", fallback="technitium"),
        "ha_mode": cfg.get("kea", "ha_mode", fallback=""),
        "server_name": cfg.get("kea", "name", fallback="Kea Server 1"),
        "subnets": SUBNET_MAP,
        "extra_servers": extra_servers,
    }
    restart_pending = get_global_setting("restart_pending", "false") == "true"
    return render_template("settings_infrastructure.html", infra=infra, kea_up=kea_up,
                           ssh_pub_key=ssh_pub_key, ssh_configured=bool(ssh_pub_key),
                           restart_pending=restart_pending)

@app.route("/settings/infrastructure/save-kea", methods=["POST"])
@login_required
@admin_required
def save_infra_kea():
    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_pass = request.form.get("api_pass", "").strip()
    if not api_url:
        flash("API URL is required.", "error")
        return redirect(url_for("settings_infrastructure"))
    global cfg, KEA_API_URL, KEA_API_USER, KEA_API_PASS
    write_config_value("kea", "api_url", api_url)
    write_config_value("kea", "api_user", api_user)
    if api_pass:
        write_config_value("kea", "api_pass", api_pass)
    cfg = load_config()
    KEA_API_URL = cfg.get("kea", "api_url")
    KEA_API_USER = cfg.get("kea", "api_user")
    KEA_API_PASS = cfg.get("kea", "api_pass")
    set_global_setting("restart_pending", "true")
    flash("Kea API settings saved. Restart Jen to apply.", "success")
    audit("SAVE_INFRA", "kea_api", f"url={api_url} user={api_user}")
    return redirect(url_for("settings_infrastructure"))

@app.route("/settings/infrastructure/save-kea-db", methods=["POST"])
@login_required
@admin_required
def save_infra_kea_db():
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "").strip()
    database = request.form.get("database", "").strip()
    if not host or not user or not database:
        flash("Host, username, and database name are required.", "error")
        return redirect(url_for("settings_infrastructure"))
    write_config_value("kea_db", "host", host)
    write_config_value("kea_db", "user", user)
    if password:
        write_config_value("kea_db", "password", password)
    write_config_value("kea_db", "database", database)
    set_global_setting("restart_pending", "true")
    flash("Kea database settings saved. Restart Jen to apply.", "success")
    audit("SAVE_INFRA", "kea_db", f"host={host}")
    return redirect(url_for("settings_infrastructure"))

@app.route("/settings/infrastructure/save-jen-db", methods=["POST"])
@login_required
@admin_required
def save_infra_jen_db():
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "").strip()
    database = request.form.get("database", "").strip()
    if not host or not user or not database:
        flash("Host, username, and database name are required.", "error")
        return redirect(url_for("settings_infrastructure"))
    write_config_value("jen_db", "host", host)
    write_config_value("jen_db", "user", user)
    if password:
        write_config_value("jen_db", "password", password)
    write_config_value("jen_db", "database", database)
    set_global_setting("restart_pending", "true")
    flash("Jen database settings saved. Restart Jen to apply.", "success")
    audit("SAVE_INFRA", "jen_db", f"host={host}")
    return redirect(url_for("settings_infrastructure"))

@app.route("/settings/infrastructure/save-ssh", methods=["POST"])
@login_required
@admin_required
def save_infra_ssh():
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    kea_conf = request.form.get("kea_conf", "").strip()
    write_config_value("kea_ssh", "host", host)
    write_config_value("kea_ssh", "user", user)
    if kea_conf:
        write_config_value("kea_ssh", "kea_conf", kea_conf)
    set_global_setting("restart_pending", "true")
    flash("SSH settings saved. Restart Jen to apply.", "success")
    audit("SAVE_INFRA", "ssh", f"host={host} user={user}")
    return redirect(url_for("settings_infrastructure"))

@app.route("/settings/infrastructure/save-subnets", methods=["POST"])
@login_required
@admin_required
def save_infra_subnets():
    ids = request.form.getlist("subnet_id[]")
    names = request.form.getlist("subnet_name[]")
    cidrs = request.form.getlist("subnet_cidr[]")
    errors = []
    new_subnets = {}
    for sid, name, cidr in zip(ids, names, cidrs):
        sid = sid.strip()
        name = name.strip()
        cidr = cidr.strip()
        if not sid or not name or not cidr:
            continue
        if not sid.isdigit():
            errors.append(f"Invalid subnet ID: {sid}")
            continue
        if not valid_cidr(cidr):
            errors.append(f"Invalid CIDR for subnet {sid}: {cidr}")
            continue
        new_subnets[int(sid)] = {"name": name, "cidr": cidr}
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("settings_infrastructure"))
    if not new_subnets:
        flash("At least one subnet is required.", "error")
        return redirect(url_for("settings_infrastructure"))
    write_subnets_config(new_subnets)
    global SUBNET_MAP
    SUBNET_MAP = new_subnets
    flash("Subnet map updated successfully.", "success")
    audit("SAVE_INFRA", "subnets", f"{len(new_subnets)} subnets saved")
    return redirect(url_for("settings_infrastructure"))

@app.route("/settings/infrastructure/save-extra-servers", methods=["POST"])
@login_required
@admin_required
def save_extra_servers():
    global cfg, KEA_SERVERS
    names = request.form.getlist("extra_name[]")
    roles = request.form.getlist("extra_role[]")
    api_urls = request.form.getlist("extra_api_url[]")
    api_users = request.form.getlist("extra_api_user[]")
    api_passes = request.form.getlist("extra_api_pass[]")
    ssh_hosts = request.form.getlist("extra_ssh_host[]")
    ssh_users = request.form.getlist("extra_ssh_user[]")
    kea_confs = request.form.getlist("extra_kea_conf[]")

    # Remove all existing extra server sections
    n = 2
    while cfg.has_section(f"kea_server_{n}"):
        cfg.remove_section(f"kea_server_{n}")
        n += 1

    # Add new ones
    for i, (name, role, api_url, api_user, api_pass, ssh_host, ssh_user, kea_conf) in enumerate(
        zip(names, roles, api_urls, api_users, api_passes, ssh_hosts, ssh_users, kea_confs), start=2
    ):
        if not api_url.strip():
            continue
        sec = f"kea_server_{i}"
        cfg.add_section(sec)
        cfg.set(sec, "name", name.strip() or f"Kea Server {i}")
        cfg.set(sec, "role", role.strip() or "standby")
        cfg.set(sec, "api_url", api_url.strip())
        cfg.set(sec, "api_user", api_user.strip())
        if api_pass.strip():
            cfg.set(sec, "api_pass", api_pass.strip())
        else:
            # Try to preserve existing password
            try:
                existing_pass = cfg.get(sec, "api_pass", fallback=KEA_API_PASS)
                cfg.set(sec, "api_pass", existing_pass)
            except Exception:
                cfg.set(sec, "api_pass", KEA_API_PASS)
        cfg.set(sec, "ssh_host", ssh_host.strip())
        cfg.set(sec, "ssh_user", ssh_user.strip())
        cfg.set(sec, "kea_conf", kea_conf.strip() or "/etc/kea/kea-dhcp4.conf")

    with open(CONFIG_FILE, 'w') as f:
        cfg.write(f)

    # Reload server list
    KEA_SERVERS = load_kea_servers()
    count = len(KEA_SERVERS) - 1
    flash(f"Additional servers saved — {count} extra server(s) configured.", "success")
    set_global_setting("restart_pending", "true")
    audit("SAVE_INFRA", "extra_servers", f"{count} additional servers configured")
    return redirect(url_for("settings_infrastructure"))

@app.route("/settings/infrastructure/save-ddns", methods=["POST"])
@login_required
@admin_required
def save_infra_ddns():
    log_path = request.form.get("log_path", "").strip()
    dns_provider = request.form.get("dns_provider", "technitium").strip()
    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_token = request.form.get("api_token", "").strip()
    forward_zone = request.form.get("forward_zone", "").strip()
    if log_path:
        write_config_value("ddns", "log_path", log_path)
        global DDNS_LOG
        DDNS_LOG = log_path
    write_config_value("ddns", "dns_provider", dns_provider)
    if api_url:
        write_config_value("ddns", "api_url", api_url)
    if api_user:
        write_config_value("ddns", "api_user", api_user)
    if api_token:
        write_config_value("ddns", "api_token", api_token)
    if forward_zone:
        write_config_value("ddns", "forward_zone", forward_zone)
    flash("DDNS settings saved.", "success")
    audit("SAVE_INFRA", "ddns", f"log={log_path} provider={dns_provider}")
    return redirect(url_for("settings_infrastructure"))

@app.route("/settings/infrastructure/save-ha", methods=["POST"])
@login_required
@admin_required
def save_ha_settings():
    """Save HA mode for primary Kea server."""
    global cfg, KEA_SERVERS
    ha_mode = request.form.get("ha_mode", "").strip()
    server_name = request.form.get("server_name", "").strip()
    if ha_mode in ("hot-standby", "load-balancing", "passive-backup", ""):
        write_config_value("kea", "ha_mode", ha_mode)
    if server_name:
        write_config_value("kea", "name", server_name)
        # Reload server list
        KEA_SERVERS = load_kea_servers()
    flash("HA settings saved.", "success")
    audit("SAVE_INFRA", "ha_settings", f"mode={ha_mode}")
    return redirect(url_for("settings_infrastructure"))

@app.route("/settings/infrastructure/restart", methods=["POST"])
@login_required
@admin_required
def restart_jen():
    flash("Jen is restarting...", "success")
    set_global_setting("restart_pending", "false")
    audit("RESTART", "jen", "Manual restart triggered from Infrastructure settings")
    def do_restart():
        import time
        time.sleep(2)
        subprocess.run(["/usr/bin/systemctl", "restart", "jen"])
    threading.Thread(target=do_restart, daemon=True).start()
    return redirect(url_for("settings_infrastructure"))

@app.route("/settings/generate-ssh-key", methods=["POST"])
@login_required
@admin_required
def generate_ssh_key():
    os.makedirs("/etc/jen/ssh", exist_ok=True)
    try:
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", SSH_KEY_PATH, "-N", "", "-C", "jen@your-jen-server"],
            capture_output=True, check=True
        )
        os.chmod(SSH_KEY_PATH, 0o600)
        subprocess.run(["chown", "www-data:www-data", SSH_KEY_PATH, SSH_KEY_PATH + ".pub"], capture_output=True)
        with open(SSH_KEY_PATH + ".pub") as f:
            pub_key = f.read().strip()
        flash(f"SSH key generated. Add this public key to your-kea-server:\n{pub_key}", "success")
        audit("GENERATE_SSH_KEY", "settings", "SSH key pair generated")
    except subprocess.CalledProcessError as e:
        flash(f"Failed to generate SSH key: {e.stderr.decode() if e.stderr else str(e)}", "error")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("settings"))

@app.route("/settings/save-telegram", methods=["POST"])
@login_required
@admin_required
def save_telegram():
    token = request.form.get("token", "").strip()
    chat_id = request.form.get("chat_id", "").strip()
    threshold = request.form.get("threshold_pct", "80").strip()

    if not threshold.isdigit() or not (1 <= int(threshold) <= 100):
        flash("Utilization threshold must be between 1 and 100.", "error")
        return redirect(url_for("settings"))

    settings_map = {
        "telegram_enabled": "true" if request.form.get("enabled") else "false",
        "telegram_token": token,
        "telegram_chat_id": chat_id,
        "alert_kea_down": "true" if request.form.get("alert_kea_down") else "false",
        "alert_new_lease": "true" if request.form.get("alert_new_lease") else "false",
        "alert_utilization": "true" if request.form.get("alert_utilization") else "false",
        "alert_threshold_pct": threshold,
    }
    for k, v in settings_map.items():
        set_global_setting(k, v)
    flash("Telegram settings saved.", "success")
    audit("SAVE_SETTINGS", "telegram", "Telegram settings updated")
    return redirect(url_for("settings"))

@app.route("/settings/test-telegram", methods=["POST"])
@login_required
@admin_required
def test_telegram():
    token = get_global_setting("telegram_token")
    chat_id = get_global_setting("telegram_chat_id")
    if not token or not chat_id:
        flash("Telegram not configured — enter a token and chat ID first.", "error")
        return redirect(url_for("settings"))
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": "🔔 <b>Jen Test</b>\nTelegram alerts are working correctly!", "parse_mode": "HTML"},
            timeout=10
        )
        data = resp.json()
        if data.get("ok"):
            flash("Test message sent successfully.", "success")
        else:
            error_desc = data.get("description", "Unknown error")
            error_code = data.get("error_code", "")
            flash(f"Telegram error {error_code}: {error_desc}", "error")
    except requests.exceptions.ConnectionError:
        flash("Could not connect to Telegram API. Check your internet connection.", "error")
    except requests.exceptions.Timeout:
        flash("Telegram API request timed out.", "error")
    except Exception as e:
        flash(f"Unexpected error: {str(e)}", "error")
    return redirect(url_for("settings"))

@app.route("/settings/save-session", methods=["POST"])
@login_required
@admin_required
def save_session_settings():
    timeout = request.form.get("timeout_minutes", "60").strip()
    enabled = request.form.get("timeout_enabled", "true").strip()
    if enabled not in ("true", "false"):
        enabled = "true"

    if not timeout.isdigit() or not (0 <= int(timeout) <= 1440):
        flash("Session timeout must be between 0 and 1440 minutes (0 = never).", "error")
        return redirect(url_for("settings"))

    set_global_setting("session_timeout_minutes", timeout)
    set_global_setting("session_timeout_enabled", enabled)

    if enabled == "false":
        flash("Session timeout disabled — sessions will not expire.", "success")
    elif int(timeout) == 0:
        flash("Session timeout enabled — sessions will never expire.", "success")
    else:
        flash(f"Session timeout set to {timeout} minutes.", "success")
    audit("SAVE_SETTINGS", "session", f"enabled={enabled} timeout={timeout}min")
    return redirect(url_for("settings"))

@app.route("/settings/save-rate-limit", methods=["POST"])
@login_required
@admin_required
def save_rate_limit():
    max_attempts = request.form.get("max_attempts", "10").strip()
    lockout_minutes = request.form.get("lockout_minutes", "15").strip()
    mode = request.form.get("mode", "both").strip()

    if not max_attempts.isdigit() or int(max_attempts) < 0:
        flash("Max attempts must be 0 or a positive number.", "error")
        return redirect(url_for("settings"))
    if not lockout_minutes.isdigit() or int(lockout_minutes) < 0:
        flash("Lockout duration must be 0 or a positive number.", "error")
        return redirect(url_for("settings"))
    if mode not in ("ip", "username", "both", "off"):
        flash("Invalid lockout mode.", "error")
        return redirect(url_for("settings"))

    set_global_setting("rl_max_attempts", max_attempts)
    set_global_setting("rl_lockout_minutes", lockout_minutes)
    set_global_setting("rl_mode", mode)
    flash("Rate limiting settings saved.", "success")
    audit("SAVE_SETTINGS", "rate_limit", f"max={max_attempts} lockout={lockout_minutes}min mode={mode}")
    return redirect(url_for("settings"))

@app.route("/settings/clear-lockouts", methods=["POST"])
@login_required
@admin_required
def clear_lockouts():
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM login_attempts")
        db.commit()
        db.close()
        flash("All login attempt records cleared.", "success")
        audit("CLEAR_LOCKOUTS", "settings", "All login attempts cleared")
    except Exception as e:
        flash(f"Error clearing lockouts: {str(e)}", "error")
    return redirect(url_for("settings"))

@app.route("/settings/upload-cert", methods=["POST"])
@login_required
@admin_required
def upload_cert():
    cert_file = request.files.get("certificate")
    key_file = request.files.get("private_key")
    ca_file = request.files.get("ca_bundle")
    if not cert_file or not key_file:
        flash("Certificate and private key are required.", "error")
        return redirect(url_for("settings"))
    os.makedirs("/etc/jen/ssl", exist_ok=True)
    try:
        cert_data = cert_file.read().decode("utf-8")
        key_data = key_file.read().decode("utf-8")
        if "BEGIN CERTIFICATE" not in cert_data:
            flash("Invalid certificate file — does not appear to be a PEM certificate.", "error")
            return redirect(url_for("settings"))
        if "BEGIN" not in key_data or "PRIVATE KEY" not in key_data:
            flash("Invalid private key file.", "error")
            return redirect(url_for("settings"))
        with open(SSL_CERT, "w") as f: f.write(cert_data)
        with open(SSL_KEY, "w") as f: f.write(key_data)
        if ca_file and ca_file.filename:
            ca_data = ca_file.read().decode("utf-8")
            with open(SSL_CA, "w") as f: f.write(ca_data)
            with open(SSL_COMBINED, "w") as f:
                f.write(cert_data)
                if not cert_data.endswith("\n"): f.write("\n")
                f.write(ca_data)
        else:
            with open(SSL_COMBINED, "w") as f: f.write(cert_data)
        os.chmod(SSL_KEY, 0o640)
        os.chmod(SSL_CERT, 0o644)
        os.chmod(SSL_COMBINED, 0o644)
        flash("Certificate uploaded. Jen is restarting...", "success")
        audit("UPLOAD_CERT", "settings", "SSL certificate uploaded")
        def restart():
            import time; time.sleep(2)
            subprocess.run(["/usr/bin/systemctl", "restart", "jen"])
        threading.Thread(target=restart, daemon=True).start()
    except UnicodeDecodeError:
        flash("Certificate files must be PEM format (text), not DER (binary).", "error")
    except Exception as e:
        flash(f"Error uploading certificate: {str(e)}", "error")
    return redirect(url_for("settings"))

@app.route("/settings/remove-cert", methods=["POST"])
@login_required
@admin_required
def remove_cert():
    for f in [SSL_CERT, SSL_KEY, SSL_CA, SSL_COMBINED]:
        if os.path.exists(f): os.remove(f)
    flash("Certificate removed. Restarting in HTTP mode...", "success")
    def restart():
        import time; time.sleep(2)
        subprocess.run(["/usr/bin/systemctl", "restart", "jen"])
    threading.Thread(target=restart, daemon=True).start()
    return redirect(url_for("settings"))

@app.route("/settings/upload-favicon", methods=["POST"])
@login_required
@admin_required
def upload_favicon():
    favicon_file = request.files.get("favicon")
    if not favicon_file or not favicon_file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("settings"))
    if not favicon_file.filename.lower().endswith((".ico", ".png")):
        flash("Favicon must be a .ico or .png file.", "error")
        return redirect(url_for("settings"))
    os.makedirs(STATIC_DIR, exist_ok=True)
    try:
        favicon_file.save(FAVICON_PATH)
        flash("Favicon updated.", "success")
    except Exception as e:
        flash(f"Error saving favicon: {str(e)}", "error")
    return redirect(url_for("settings"))

@app.route("/settings/remove-favicon", methods=["POST"])
@login_required
@admin_required
def remove_favicon():
    if os.path.exists(FAVICON_PATH): os.remove(FAVICON_PATH)
    flash("Favicon removed.", "success")
    return redirect(url_for("settings"))

@app.route("/settings/icons")
@login_required
@admin_required
def settings_icons():
    """Custom brand icon management page."""
    bundled = []
    for f in sorted(os.listdir(ICONS_BUNDLED_DIR)):
        if f.endswith(".svg"):
            name = f.replace(".svg", "")
            custom_override = os.path.exists(f"{ICONS_CUSTOM_DIR}/{f}")
            bundled.append({"name": name, "file": f, "custom_override": custom_override})
    custom = []
    for f in sorted(os.listdir(ICONS_CUSTOM_DIR)):
        if f.endswith(".svg"):
            custom.append({"name": f.replace(".svg", ""), "file": f})
    return render_template("settings_icons.html", bundled=bundled, custom=custom)

@app.route("/settings/icons/upload", methods=["POST"])
@login_required
@admin_required
def upload_custom_icon():
    svg_file = request.files.get("icon")
    icon_name = request.form.get("icon_name", "").strip().lower()
    if not svg_file or not icon_name:
        flash("Icon file and name are required.", "error")
        return redirect(url_for("settings_icons"))
    if not icon_name.replace("-", "").replace("_", "").isalnum():
        flash("Icon name must be alphanumeric (hyphens/underscores allowed).", "error")
        return redirect(url_for("settings_icons"))
    if not svg_file.filename.endswith(".svg"):
        flash("Only SVG files are accepted.", "error")
        return redirect(url_for("settings_icons"))
    svg_file.seek(0, 2)
    size = svg_file.tell()
    svg_file.seek(0)
    if size > 100 * 1024:
        flash("SVG file must be under 100KB.", "error")
        return redirect(url_for("settings_icons"))
    os.makedirs(ICONS_CUSTOM_DIR, exist_ok=True)
    dest = f"{ICONS_CUSTOM_DIR}/{icon_name}.svg"
    svg_file.save(dest)
    # Update MANUFACTURER_ICON_MAP if name matches a known manufacturer
    audit("UPLOAD_ICON", "settings", f"Custom icon '{icon_name}.svg' uploaded by {current_user.username}")
    flash(f"Icon '{icon_name}.svg' uploaded. It will be used for any manufacturer mapped to '{icon_name}'.", "success")
    return redirect(url_for("settings_icons"))

@app.route("/settings/icons/delete/<name>", methods=["POST"])
@login_required
@admin_required
def delete_custom_icon(name):
    path = f"{ICONS_CUSTOM_DIR}/{name}.svg"
    if os.path.exists(path):
        os.remove(path)
        audit("DELETE_ICON", "settings", f"Custom icon '{name}.svg' deleted by {current_user.username}")
        flash(f"Custom icon '{name}.svg' removed.", "success")
    else:
        flash("Icon not found.", "error")
    return redirect(url_for("settings_icons"))
@login_required
@admin_required
def upload_nav_logo():
    logo_file = request.files.get("logo")
    if not logo_file or not logo_file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("settings_system"))
    ext = logo_file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ("png", "svg", "jpg", "jpeg", "webp"):
        flash("Logo must be PNG, SVG, JPG, or WebP.", "error")
        return redirect(url_for("settings_system"))
    logo_file.seek(0, 2)
    size = logo_file.tell()
    logo_file.seek(0)
    if size > 200 * 1024:
        flash("Logo file must be under 200KB.", "error")
        return redirect(url_for("settings_system"))
    # Remove any existing logo files
    for old_ext in ("png", "svg", "jpg", "jpeg", "webp"):
        old = f"{NAV_LOGO_PATH}.{old_ext}"
        if os.path.exists(old): os.remove(old)
    os.makedirs(STATIC_DIR, exist_ok=True)
    try:
        logo_file.save(f"{NAV_LOGO_PATH}.{ext}")
        audit("BRANDING", "settings", f"Nav logo uploaded by {current_user.username}")
        flash("Nav logo updated.", "success")
    except Exception as e:
        flash(f"Error saving logo: {str(e)}", "error")
    return redirect(url_for("settings_system"))

@app.route("/settings/remove-nav-logo", methods=["POST"])
@login_required
@admin_required
def remove_nav_logo():
    for ext in ("png", "svg", "jpg", "jpeg", "webp"):
        f = f"{NAV_LOGO_PATH}.{ext}"
        if os.path.exists(f): os.remove(f)
    audit("BRANDING", "settings", f"Nav logo removed by {current_user.username}")
    flash("Nav logo removed.", "success")
    return redirect(url_for("settings_system"))

@app.route("/settings/save-nav-color", methods=["POST"])
@login_required
@admin_required
def save_nav_color():
    # Accept value from either the color picker or the text field
    color = request.form.get("nav_color_hex", "").strip() or request.form.get("nav_color", "").strip()
    # Validate — must be empty or a valid hex color
    import re
    if color and not re.match(r'^#[0-9a-fA-F]{3,6}$', color):
        flash("Invalid color value. Use a hex code like #1a1a2a.", "error")
        return redirect(url_for("settings_system"))
    set_global_setting("branding_nav_color", color)
    audit("BRANDING", "settings", f"Nav color set to '{color}' by {current_user.username}")
    flash("Nav bar color updated." if color else "Nav bar color reset to default.", "success")
    return redirect(url_for("settings_system"))

# ─────────────────────────────────────────
# Saved Searches
# ─────────────────────────────────────────
@app.route("/saved-searches", methods=["GET"])
@login_required
def saved_searches():
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM saved_searches WHERE user_id=%s ORDER BY created_at DESC", (current_user.id,))
            searches = cur.fetchall()
        db.close()
    except Exception:
        searches = []
    return render_template("saved_searches.html", searches=searches)

@app.route("/saved-searches/save", methods=["POST"])
@login_required
def save_search():
    name = request.form.get("name", "").strip()[:100]
    page = request.form.get("page", "").strip()[:50]
    params = request.form.get("params", "").strip()[:1000]
    if not name or not page:
        return jsonify({"error": "Name and page required"}), 400
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            # Max 20 saved searches per user
            cur.execute("SELECT COUNT(*) as cnt FROM saved_searches WHERE user_id=%s", (current_user.id,))
            if cur.fetchone()["cnt"] >= 20:
                cur.execute("""DELETE FROM saved_searches WHERE user_id=%s
                               ORDER BY created_at ASC LIMIT 1""", (current_user.id,))
            cur.execute("INSERT INTO saved_searches (user_id, name, page, params) VALUES (%s,%s,%s,%s)",
                        (current_user.id, name, page, params))
        db.commit()
        db.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/saved-searches/delete/<int:search_id>", methods=["POST"])
@login_required
def delete_saved_search(search_id):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM saved_searches WHERE id=%s AND user_id=%s", (search_id, current_user.id))
        db.commit()
        db.close()
    except Exception:
        pass
    return redirect(url_for("saved_searches"))

@app.route("/api/saved-searches")
@login_required
def api_saved_searches():
    page = request.args.get("page", "")
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            if page:
                cur.execute("SELECT * FROM saved_searches WHERE user_id=%s AND page=%s ORDER BY name", (current_user.id, page))
            else:
                cur.execute("SELECT * FROM saved_searches WHERE user_id=%s ORDER BY name", (current_user.id,))
            searches = cur.fetchall()
        db.close()
        return jsonify([dict(s) for s in searches])
    except Exception as e:
        return jsonify([])

# ─────────────────────────────────────────
# Dashboard Preferences
# ─────────────────────────────────────────
@app.route("/api/dashboard/save-prefs", methods=["POST"])
@login_required
def save_dashboard_prefs():
    import json
    widgets = request.json.get("widgets", ["subnet_stats", "recent_leases"])
    valid = {"subnet_stats", "recent_leases", "top_devices", "alert_summary", "server_status"}
    widgets = [w for w in widgets if w in valid]
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("""INSERT INTO dashboard_prefs (user_id, widgets)
                           VALUES (%s, %s)
                           ON DUPLICATE KEY UPDATE widgets=%s, updated_at=NOW()""",
                        (current_user.id, json.dumps(widgets), json.dumps(widgets)))
        db.commit()
        db.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/dashboard/get-prefs")
@login_required
def get_dashboard_prefs():
    import json
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT widgets FROM dashboard_prefs WHERE user_id=%s", (current_user.id,))
            row = cur.fetchone()
        db.close()
        widgets = json.loads(row["widgets"]) if row else ["subnet_stats", "recent_leases"]
        return jsonify({"widgets": widgets})
    except Exception:
        return jsonify({"widgets": ["subnet_stats", "recent_leases"]})

# ─────────────────────────────────────────
# Global Search
# ─────────────────────────────────────────
@app.route("/search")
@login_required
def global_search():
    q = sanitize_search(request.args.get("q", "").strip())
    results = {"leases": [], "reservations": [], "devices": []}
    if len(q) >= 2:
        try:
            kea_db = get_kea_db()
            jen_db = get_jen_db()
            s = f"%{q}%"
            s_mac = s.replace(":", "")

            # Search leases
            with kea_db.cursor() as cur:
                cur.execute("""
                    SELECT inet_ntoa(l.address) AS ip,
                           l.hostname,
                           HEX(l.hwaddr) AS mac_hex,
                           l.subnet_id,
                           l.expire, l.state
                    FROM lease4 l
                    WHERE inet_ntoa(l.address) LIKE %s
                       OR l.hostname LIKE %s
                       OR HEX(l.hwaddr) LIKE %s
                    LIMIT 20
                """, (s, s, s_mac))
                for row in cur.fetchall():
                    mac = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                    results["leases"].append({
                        "ip": row["ip"], "hostname": row["hostname"] or "",
                        "mac": mac, "subnet_id": row["subnet_id"]
                    })

            # Search reservations
            with kea_db.cursor() as cur:
                cur.execute("""
                    SELECT inet_ntoa(h.ipv4_address) AS ip,
                           h.hostname,
                           HEX(h.dhcp_identifier) AS mac_hex,
                           h.dhcp4_subnet_id AS subnet_id
                    FROM hosts h
                    WHERE h.dhcp4_subnet_id > 0
                      AND (inet_ntoa(h.ipv4_address) LIKE %s
                           OR h.hostname LIKE %s
                           OR HEX(h.dhcp_identifier) LIKE %s)
                    LIMIT 20
                """, (s, s, s_mac))
                for row in cur.fetchall():
                    mac = ":".join(row["mac_hex"][i:i+2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                    results["reservations"].append({
                        "ip": row["ip"], "hostname": row["hostname"] or "",
                        "mac": mac, "subnet_id": row["subnet_id"]
                    })

            # Search devices
            with jen_db.cursor() as cur:
                cur.execute("""
                    SELECT mac, last_ip, name, owner, notes
                    FROM devices
                    WHERE mac LIKE %s OR last_ip LIKE %s
                       OR name LIKE %s OR owner LIKE %s
                    LIMIT 20
                """, (s, s, s, s))
                results["devices"] = cur.fetchall()

            kea_db.close()
            jen_db.close()
        except Exception as e:
            flash(f"Search error: {str(e)}", "error")

    total = sum(len(v) for v in results.values())
    return render_template("search_results.html",
                           q=q, results=results, total=total,
                           subnet_map=SUBNET_MAP,
                           subnet_names=SUBNET_NAMES)

# ─────────────────────────────────────────
# MFA Routes
# ─────────────────────────────────────────
@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    # At this point the user has passed password auth but is not yet logged in.
    # Their user ID is held in the session under mfa_pending_user_id.
    pending_id = session.get("mfa_pending_user_id")
    pending_username = session.get("mfa_pending_username", "unknown")
    if not pending_id:
        # No pending MFA — if already fully logged in, go to dashboard; else back to login
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        # Try backup code first (8 hex chars without dash, or with dash stripped)
        clean_code = code.replace("-", "").upper()
        if verify_backup_code(pending_id, clean_code):
            user = load_user(pending_id)
            if user:
                login_user(user)
                session["last_active"] = datetime.now(timezone.utc).isoformat()
                session.pop("mfa_pending_user_id", None)
                session.pop("mfa_pending_username", None)
                next_url = session.pop("mfa_next", url_for("dashboard"))
                audit("MFA_BACKUP_CODE", "auth", pending_username)
                return redirect(next_url)
        # Try TOTP
        if verify_totp(pending_id, code):
            user = load_user(pending_id)
            if user:
                login_user(user)
                session["last_active"] = datetime.now(timezone.utc).isoformat()
                session.pop("mfa_pending_user_id", None)
                session.pop("mfa_pending_username", None)
                remember = request.form.get("remember_device")
                next_url = session.pop("mfa_next", url_for("dashboard"))
                if remember:
                    days = int(request.form.get("remember_days", 30))
                    device_name = request.user_agent.string[:100] if request.user_agent else "Unknown"
                    token = create_trusted_device_token(pending_id, days, device_name)
                    resp = redirect(next_url)
                    resp.set_cookie("jen_trusted", token, max_age=days*86400, httponly=True, samesite="Lax")
                    audit("MFA_VERIFY", "auth", f"{pending_username} trusted={days}d")
                    return resp
                audit("MFA_VERIFY", "auth", pending_username)
                return redirect(next_url)
        flash("Invalid code. Please try again.", "error")
        audit("MFA_FAILED", "auth", pending_username)
    has_totp = user_has_mfa(pending_id) if pending_id else False
    return render_template("mfa_challenge.html", username=pending_username, has_totp=has_totp)

@app.route("/mfa/enroll", methods=["GET", "POST"])
@login_required
def mfa_enroll():
    import pyotp, qrcode, io as _io, base64
    if request.method == "POST":
        action = request.form.get("action")
        if action == "enroll":
            secret = request.form.get("secret", "").strip()
            code = request.form.get("code", "").strip()
            device_name = request.form.get("device_name", "Authenticator").strip()[:100] or "Authenticator"
            if not secret or not code:
                flash("Missing secret or code.", "error")
                return redirect(url_for("mfa_enroll"))
            totp = pyotp.TOTP(secret)
            if not totp.verify(code, valid_window=1):
                flash("Invalid verification code. Please try again.", "error")
                return redirect(url_for("mfa_enroll"))
            try:
                db = get_jen_db()
                with db.cursor() as cur:
                    cur.execute("""INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled)
                                   VALUES (%s, 'totp', %s, %s, 1)""",
                                (current_user.id, secret, device_name))
                db.commit()
                # Generate backup codes
                codes = generate_backup_codes(current_user.id)
                db.close()
                audit("MFA_ENROLL", "auth", f"{current_user.username} device={device_name}")
                flash("Authenticator enrolled successfully!", "success")
                return render_template("mfa_backup_codes.html", codes=codes)
            except Exception as e:
                flash(f"Enrollment error: {str(e)}", "error")
                return redirect(url_for("mfa_enroll"))
        elif action in ("remove", "remove_totp"):
            method_id = request.form.get("method_id") or request.form.get("mfa_id")
            try:
                db = get_jen_db()
                with db.cursor() as cur:
                    cur.execute("DELETE FROM mfa_methods WHERE id=%s AND user_id=%s", (method_id, current_user.id))
                db.commit(); db.close()
                audit("MFA_REMOVE", "auth", f"{current_user.username} method_id={method_id}")
                flash("Authenticator removed.", "success")
            except Exception as e:
                flash(f"Error: {str(e)}", "error")
            return redirect(url_for("mfa_enroll"))
        elif action == "new_backup_codes":
            codes = generate_backup_codes(current_user.id)
            audit("MFA_NEW_BACKUP", "auth", current_user.username)
            return render_template("mfa_backup_codes.html", codes=codes)
    # GET - show enrollment page
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.username, issuer_name="Jen DHCP")
    qr = qrcode.make(uri)
    buf = _io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, name, created_at, last_used FROM mfa_methods WHERE user_id=%s AND method_type='totp' AND enabled=1", (current_user.id,))
            methods = cur.fetchall()
            cur.execute("SELECT COUNT(*) as cnt FROM mfa_backup_codes WHERE user_id=%s AND used=0", (current_user.id,))
            backup_count = cur.fetchone()["cnt"]
        db.close()
    except Exception as e:
        logger.error(f"mfa_enroll fetch error: {e}")
        methods = []; backup_count = 0
    return render_template("mfa_enroll.html", secret=secret, qr_b64=qr_b64,
                           totp_methods=methods, passkeys=[], backup_count=backup_count)

@app.route("/mfa/regenerate-backup-codes", methods=["POST"])
@login_required
def regenerate_backup_codes():
    codes = generate_backup_codes(current_user.id)
    audit("MFA_NEW_BACKUP", "auth", current_user.username)
    return render_template("mfa_backup_codes.html", codes=codes)

@app.route("/mfa/trusted-devices")
@login_required
def mfa_trusted_devices():
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("""SELECT id, device_name, created_at, expires_at, last_used
                           FROM mfa_trusted_devices WHERE user_id=%s
                           ORDER BY created_at DESC""", (current_user.id,))
            devices = cur.fetchall()
        db.close()
    except Exception:
        devices = []
    return render_template("mfa_trusted_devices.html", devices=devices)

@app.route("/mfa/trusted-devices/remove/<int:device_id>", methods=["POST"])
@app.route("/mfa/revoke-device/<int:device_id>", methods=["POST"])
@login_required
def remove_trusted_device(device_id):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_trusted_devices WHERE id=%s AND user_id=%s", (device_id, current_user.id))
        db.commit(); db.close()
        flash("Trusted device removed.", "success")
        audit("REMOVE_TRUSTED_DEVICE", "auth", f"device_id={device_id}")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("mfa_trusted_devices"))

@app.route("/mfa/revoke-all-devices", methods=["POST"])
@login_required
def revoke_all_trusted_devices():
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_trusted_devices WHERE user_id=%s", (current_user.id,))
            deleted = cur.rowcount
        db.commit(); db.close()
        flash(f"All {deleted} trusted device(s) revoked.", "success")
        audit("REVOKE_ALL_TRUSTED_DEVICES", "auth", current_user.username)
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("mfa_trusted_devices"))

@app.route("/mfa/admin-reset/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def admin_reset_mfa(user_id):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_methods WHERE user_id=%s", (user_id,))
            cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=%s", (user_id,))
            cur.execute("DELETE FROM mfa_trusted_devices WHERE user_id=%s", (user_id,))
        db.commit(); db.close()
        flash(f"MFA reset for user ID {user_id}.", "success")
        audit("ADMIN_RESET_MFA", str(user_id), f"Reset by {current_user.username}")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("users"))

# ─────────────────────────────────────────
# User Profile
# ─────────────────────────────────────────
@app.route("/profile")
@login_required
def user_profile():
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, username, role, session_timeout, created_at FROM users WHERE id=%s",
                       (current_user.id,))
            user_data = cur.fetchone()
            cur.execute("SELECT COUNT(*) as cnt FROM mfa_methods WHERE user_id=%s AND enabled=1",
                       (current_user.id,))
            totp_count = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM webauthn_credentials WHERE user_id=%s",
                       (current_user.id,))
            passkey_count = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM mfa_backup_codes WHERE user_id=%s AND used=0",
                       (current_user.id,))
            backup_count = cur.fetchone()["cnt"]
            cur.execute("""
                SELECT COUNT(*) as cnt FROM mfa_trusted_devices
                WHERE user_id=%s AND (expires_at IS NULL OR expires_at > NOW())
            """, (current_user.id,))
            trusted_count = cur.fetchone()["cnt"]
        db.close()
    except Exception as e:
        flash(f"Error loading profile: {str(e)}", "error")
        user_data = None
        totp_count = passkey_count = backup_count = trusted_count = 0
    return render_template("user_profile.html",
                           user_data=user_data,
                           totp_count=totp_count,
                           passkey_count=passkey_count,
                           backup_count=backup_count,
                           device_count=trusted_count,
                           mfa_enrolled=(totp_count + passkey_count) > 0)

# ─────────────────────────────────────────
# Users
# ─────────────────────────────────────────
@app.route("/users")
@login_required
@admin_required
def users():
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, username, role, session_timeout, created_at FROM users ORDER BY username")
            all_users = cur.fetchall()
            # Add MFA status
            for u in all_users:
                cur.execute("""
                    SELECT
                        (SELECT COUNT(*) FROM mfa_methods WHERE user_id=%s AND enabled=1) +
                        (SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=%s) as mfa_count
                """, (u["id"], u["id"]))
                u["mfa_enrolled"] = cur.fetchone()["mfa_count"] > 0
        db.close()
    except Exception as e:
        flash(f"Could not load users: {str(e)}", "error")
        all_users = []
    global_timeout = get_global_setting("session_timeout_minutes", "60")
    mfa_mode = get_mfa_mode()
    return render_template("users.html", users=all_users, global_timeout=global_timeout, mfa_mode=mfa_mode)

@app.route("/users/add", methods=["POST"])
@login_required
@admin_required
def add_user():
    username = request.form.get("username", "").strip()[:100]
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")

    if not username:
        flash("Username is required.", "error")
        return redirect(url_for("users"))
    if not re.match(r'^[a-zA-Z0-9_\-\.]{1,100}$', username):
        flash("Username may only contain letters, numbers, underscores, hyphens, and dots.", "error")
        return redirect(url_for("users"))
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("users"))
    if role not in ("admin", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for("users"))

    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                        (username, hash_password(password), role))
        db.commit()
        db.close()
        flash(f"User '{username}' created.", "success")
        audit("ADD_USER", username, f"Role={role}")
    except pymysql.IntegrityError:
        flash(f"Username '{username}' already exists.", "error")
    except Exception as e:
        flash(f"Error creating user: {str(e)}", "error")
    return redirect(url_for("users"))

@app.route("/users/delete/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("users"))
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT username FROM users WHERE id=%s", (user_id,))
            row = cur.fetchone()
            if not row:
                flash("User not found.", "error")
                db.close()
                return redirect(url_for("users"))
            cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        db.commit()
        db.close()
        flash(f"User '{row['username']}' deleted.", "success")
        audit("DELETE_USER", row["username"], "User deleted")
    except Exception as e:
        flash(f"Error deleting user: {str(e)}", "error")
    return redirect(url_for("users"))

@app.route("/users/upload-avatar", methods=["POST"])
@login_required
def upload_avatar():
    import base64, re
    data_url = request.form.get("avatar_data_url", "").strip()
    if data_url and data_url.startswith("data:image/"):
        # Validate it's a reasonable size (max ~200KB base64)
        if len(data_url) > 280000:
            flash("Image too large. Please use an image under 200KB.", "error")
            return redirect(url_for("user_profile"))
        # Validate format
        if not re.match(r'^data:image/(jpeg|png|gif|webp);base64,[A-Za-z0-9+/=]+$', data_url):
            flash("Invalid image format.", "error")
            return redirect(url_for("user_profile"))
        try:
            db = get_jen_db()
            with db.cursor() as cur:
                cur.execute("UPDATE users SET avatar_url=%s WHERE id=%s", (data_url, current_user.id))
            db.commit()
            db.close()
            flash("Profile picture updated.", "success")
            audit("UPDATE_AVATAR", "user", current_user.username)
        except Exception as e:
            flash(f"Error saving avatar: {str(e)}", "error")
    elif data_url == "":
        # Remove avatar
        try:
            db = get_jen_db()
            with db.cursor() as cur:
                cur.execute("UPDATE users SET avatar_url=NULL WHERE id=%s", (current_user.id,))
            db.commit()
            db.close()
            flash("Profile picture removed.", "success")
        except Exception as e:
            flash(f"Error removing avatar: {str(e)}", "error")
    return redirect(url_for("user_profile"))

@app.route("/users/change-password", methods=["POST"])
@login_required
def change_password():
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")

    if new_pw != confirm_pw:
        flash("New passwords do not match.", "error")
        return redirect(url_for("users"))
    if len(new_pw) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for("users"))

    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, password FROM users WHERE id=%s",
                        (current_user.id,))
            row = cur.fetchone()
            if not row or not verify_password(row["password"], current_pw):
                flash("Current password is incorrect.", "error")
                db.close()
                return redirect(url_for("users"))
            cur.execute("UPDATE users SET password=%s WHERE id=%s",
                        (hash_password(new_pw), current_user.id))
        db.commit()
        db.close()
        flash("Password changed successfully.", "success")
        audit("CHANGE_PASSWORD", current_user.username, "Password changed")
    except Exception as e:
        flash(f"Error changing password: {str(e)}", "error")
    return redirect(url_for("users"))

@app.route("/users/set-timeout/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def set_user_timeout(user_id):
    timeout = request.form.get("timeout", "").strip()
    if timeout and (not timeout.isdigit() or not (1 <= int(timeout) <= 1440)):
        flash("Timeout must be between 1 and 1440 minutes, or blank for global default.", "error")
        return redirect(url_for("users"))
    timeout_val = int(timeout) if timeout.isdigit() else None
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("UPDATE users SET session_timeout=%s WHERE id=%s", (timeout_val, user_id))
        db.commit()
        db.close()
        flash("Session timeout updated.", "success")
    except Exception as e:
        flash(f"Error updating timeout: {str(e)}", "error")
    return redirect(url_for("users"))

# ─────────────────────────────────────────
# Devices
# ─────────────────────────────────────────
@app.route("/devices")
@login_required
def devices():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    search = sanitize_search(request.args.get("search", "").strip())
    show_stale = request.args.get("stale", "0") == "1"
    type_filter = request.args.get("type", "").strip()
    subnet_filter = request.args.get("subnet", "all")
    sort = request.args.get("sort", "last_seen")
    direction = request.args.get("dir", "desc")
    if direction not in ("asc", "desc"):
        direction = "desc"
    sort_map = {
        "mac": "d.mac",
        "device_name": "d.device_name",
        "owner": "d.owner",
        "last_ip": "d.last_ip",
        "hostname": "d.last_hostname",
        "subnet": "d.last_subnet_id",
        "first_seen": "d.first_seen",
        "last_seen": "d.last_seen",
        "status": "d.last_seen",
    }
    sort_col = sort_map.get(sort, "d.last_seen")
    per_page = 50
    stale_days = int(get_global_setting("stale_device_days", "30"))

    devices_list = []
    total = 0
    try:
        db = get_jen_db()
        kdb = get_kea_db()
        with db.cursor() as cur:
            where = []
            params = []
            if search:
                where.append("(d.mac LIKE %s OR d.device_name LIKE %s OR d.owner LIKE %s OR d.last_ip LIKE %s OR d.last_hostname LIKE %s)")
                s = f"%{search}%"
                params += [s, s, s, s, s]
            if show_stale:
                where.append(f"d.last_seen < DATE_SUB(NOW(), INTERVAL {stale_days} DAY)")
            if type_filter:
                where.append("d.device_type=%s")
                params.append(type_filter)
            if subnet_filter != "all":
                try:
                    where.append("d.last_subnet_id=%s")
                    params.append(int(subnet_filter))
                except ValueError:
                    subnet_filter = "all"
            where_str = " AND ".join(where) if where else "1=1"

            cur.execute(f"SELECT COUNT(*) as cnt FROM devices d WHERE {where_str}", params)
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT d.id, d.mac, d.device_name, d.owner, d.notes,
                       d.first_seen, d.last_seen, d.last_ip, d.last_hostname, d.last_subnet_id,
                       COALESCE(d.manufacturer_override, d.manufacturer) AS manufacturer,
                       COALESCE(d.device_type_override, d.device_type) AS device_type,
                       COALESCE(d.device_icon_override, d.device_icon) AS device_icon,
                       d.manufacturer_override IS NOT NULL AS is_manual,
                       d.device_type_override AS type_override_key,
                       d.device_icon_override AS icon_override_key,
                       DATEDIFF(NOW(), d.last_seen) as days_since_seen
                FROM devices d
                WHERE {where_str}
                ORDER BY {sort_col} {direction}
                LIMIT {per_page} OFFSET {offset}
            """, params)
            rows = cur.fetchall()

            # Check which MACs have reservations
            with kdb.cursor() as kcur:
                for row in rows:
                    mac_hex = row["mac"].replace(":", "")
                    kcur.execute("SELECT host_id, inet_ntoa(ipv4_address) AS ip FROM hosts WHERE HEX(dhcp_identifier)=%s", (mac_hex,))
                    res = kcur.fetchone()
                    row["has_reservation"] = bool(res)
                    row["reservation_ip"] = res["ip"] if res else None
                    row["subnet_name"] = SUBNET_MAP.get(row["last_subnet_id"], {}).get("name", "") if row["last_subnet_id"] else ""
                    row["is_stale"] = row["days_since_seen"] >= stale_days
                    devices_list.append(row)
        db.close()
        kdb.close()
    except Exception as e:
        logger.error(f"Devices error: {e}")
        flash(f"Could not load device inventory: {str(e)}", "error")

    pages = max(1, (total + per_page - 1) // per_page)
    bundled_icons = sorted([f.replace(".svg","") for f in os.listdir(ICONS_BUNDLED_DIR) if f.endswith(".svg")]) if os.path.exists(ICONS_BUNDLED_DIR) else []
    custom_icons = sorted([f.replace(".svg","") for f in os.listdir(ICONS_CUSTOM_DIR) if f.endswith(".svg")]) if os.path.exists(ICONS_CUSTOM_DIR) else []
    return render_template("devices.html", devices=devices_list, page=page, pages=pages,
                           total=total, search=search, show_stale=show_stale,
                           stale_days=stale_days, subnet_map=SUBNET_MAP,
                           sort=sort, direction=direction,
                           type_filter=type_filter, subnet_filter=subnet_filter,
                           device_type_display=DEVICE_TYPE_DISPLAY,
                           get_manufacturer_icon_url=get_manufacturer_icon_url,
                           bundled_icons=bundled_icons, custom_icons=custom_icons)

@app.route("/devices/edit/<int:device_id>", methods=["POST"])
@login_required
@admin_required
def edit_device(device_id):
    device_name = request.form.get("device_name", "").strip()[:200]
    owner = request.form.get("owner", "").strip()[:200]
    notes = request.form.get("notes", "").strip()[:1000]
    type_override = request.form.get("type_override", "").strip()
    icon_override = request.form.get("icon_override", "").strip()  # icon name without .svg
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            if type_override == "auto" or type_override == "":
                # Clear manual override (but keep icon override if set)
                if icon_override:
                    cur.execute("""UPDATE devices SET device_name=%s, owner=%s, notes=%s,
                                   manufacturer_override=NULL, device_type_override=NULL,
                                   device_icon_override=%s
                                   WHERE id=%s""",
                                (device_name or None, owner or None, notes or None,
                                 icon_override, device_id))
                else:
                    cur.execute("""UPDATE devices SET device_name=%s, owner=%s, notes=%s,
                                   manufacturer_override=NULL, device_type_override=NULL, device_icon_override=NULL
                                   WHERE id=%s""",
                                (device_name or None, owner or None, notes or None, device_id))
                override_info = None
            elif type_override in DEVICE_TYPE_DISPLAY:
                type_label, _ = DEVICE_TYPE_DISPLAY[type_override]
                type_icon_map = {
                    "apple": ("Apple", "🍎"), "android": ("Android", "📱"),
                    "windows": ("Windows", "🖥️"), "linux": ("Linux", "🐧"),
                    "amazon": ("Amazon", "📦"), "iot": ("IoT Device", "🔌"),
                    "tv": ("Smart TV", "📺"), "printer": ("Printer", "🖨️"),
                    "nas": ("NAS", "🗄️"), "network": ("Network Device", "🌐"),
                    "gaming": ("Gaming", "🎮"), "raspberry_pi": ("Raspberry Pi", "🥧"),
                    "google": ("Google", "🔍"), "pc": ("PC", "🖥️"),
                    "unknown": ("Unknown", "❓"),
                }
                mfr_override, icon_default = type_icon_map.get(type_override, (type_label, "❓"))
                # Use explicit icon override if set, otherwise default for type
                final_icon = icon_override if icon_override else icon_default
                cur.execute("""UPDATE devices SET device_name=%s, owner=%s, notes=%s,
                               manufacturer_override=%s, device_type_override=%s, device_icon_override=%s
                               WHERE id=%s""",
                            (device_name or None, owner or None, notes or None,
                             mfr_override, type_override, final_icon, device_id))
                override_info = {"manufacturer": mfr_override, "device_type": type_override, "device_icon": final_icon}
            else:
                cur.execute("UPDATE devices SET device_name=%s, owner=%s, notes=%s WHERE id=%s",
                            (device_name or None, owner or None, notes or None, device_id))
                override_info = None
        db.commit()
        db.close()
        return jsonify({"ok": True, "override": override_info})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/devices/delete/<int:device_id>", methods=["POST"])
@login_required
@admin_required
def delete_device(device_id):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM devices WHERE id=%s", (device_id,))
        db.commit()
        db.close()
        flash("Device removed from inventory.", "success")
        audit("DELETE_DEVICE", str(device_id), "Removed from device inventory")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    return redirect(url_for("devices"))

@app.route("/devices/settings", methods=["POST"])
@login_required
@admin_required
def save_device_settings():
    stale_days = request.form.get("stale_days", "30").strip()
    if not stale_days.isdigit() or not (1 <= int(stale_days) <= 365):
        flash("Stale threshold must be between 1 and 365 days.", "error")
        return redirect(url_for("devices"))
    set_global_setting("stale_device_days", stale_days)
    flash(f"Stale device threshold set to {stale_days} days.", "success")
    return redirect(url_for("devices"))

# ─────────────────────────────────────────
# Reservations — bulk actions + stale detection
# ─────────────────────────────────────────
@app.route("/reservations/bulk-delete", methods=["POST"])
@login_required
@admin_required
def bulk_delete_reservations():
    host_ids = request.form.getlist("host_ids[]")
    if not host_ids:
        flash("No reservations selected.", "error")
        return redirect(url_for("reservations"))

    deleted = 0
    errors = 0
    try:
        db = get_kea_db()
        jdb = get_jen_db()
        with db.cursor() as cur:
            for host_id in host_ids:
                try:
                    host_id = int(host_id)
                    cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, dhcp_identifier, dhcp4_subnet_id FROM hosts WHERE host_id=%s", (host_id,))
                    host = cur.fetchone()
                    if host:
                        mac = format_mac(host["dhcp_identifier"])
                        result = kea_command("reservation-del", arguments={
                            "subnet-id": host["dhcp4_subnet_id"],
                            "identifier-type": "hw-address", "identifier": mac
                        })
                        if result.get("result") == 0:
                            with jdb.cursor() as jcur:
                                jcur.execute("DELETE FROM reservation_notes WHERE host_id=%s", (host_id,))
                            deleted += 1
                        else:
                            errors += 1
                except Exception:
                    errors += 1
        db.close()
        jdb.commit()
        jdb.close()
    except Exception as e:
        flash(f"Bulk delete error: {str(e)}", "error")
        return redirect(url_for("reservations"))

    flash(f"Deleted {deleted} reservation(s)." + (f" {errors} failed." if errors else ""), 
          "success" if errors == 0 else "warning")
    audit("BULK_DELETE_RESERVATIONS", "reservations", f"Deleted={deleted} Errors={errors}")
    return redirect(url_for("reservations"))

@app.route("/reservations/bulk-export", methods=["POST"])
@login_required
def bulk_export_reservations():
    host_ids = request.form.getlist("host_ids[]")
    if not host_ids:
        flash("No reservations selected.", "error")
        return redirect(url_for("reservations"))
    try:
        db = get_kea_db()
        jdb = get_jen_db()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ip", "mac", "hostname", "subnet_id", "subnet_name", "dns_override", "notes"])
        with db.cursor() as cur:
            for host_id in host_ids:
                try:
                    host_id = int(host_id)
                    cur.execute("""
                        SELECT h.host_id, inet_ntoa(h.ipv4_address) AS ip,
                               h.dhcp_identifier, h.hostname, h.dhcp4_subnet_id
                        FROM hosts h WHERE h.host_id=%s
                    """, (host_id,))
                    row = cur.fetchone()
                    if row:
                        mac = format_mac(row["dhcp_identifier"])
                        cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (host_id,))
                        dns_row = cur.fetchone()
                        dns = dns_row["formatted_value"] if dns_row and dns_row["formatted_value"] else ""
                        with jdb.cursor() as jcur:
                            jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (host_id,))
                            note_row = jcur.fetchone()
                            notes = note_row["notes"] if note_row else ""
                        subnet_name = SUBNET_MAP.get(row["dhcp4_subnet_id"], {}).get("name", "")
                        writer.writerow([row["ip"], mac, row["hostname"] or "", row["dhcp4_subnet_id"],
                                         subnet_name, dns, notes])
                except Exception:
                    pass
        db.close()
        jdb.close()
        output.seek(0)
        audit("BULK_EXPORT_RESERVATIONS", "reservations", f"Exported {len(host_ids)} selected")
        return Response(output.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=reservations_selected.csv"})
    except Exception as e:
        flash(f"Export error: {str(e)}", "error")
        return redirect(url_for("reservations"))

# ─────────────────────────────────────────
# Subnet notes
# ─────────────────────────────────────────
@app.route("/subnets/save-note", methods=["POST"])
@login_required
@admin_required
def save_subnet_note():
    try:
        subnet_id = int(request.form.get("subnet_id"))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Invalid subnet ID"})
    notes = request.form.get("notes", "").strip()[:1000]
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO subnet_notes (subnet_id, notes) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE notes=%s, updated_at=NOW()
            """, (subnet_id, notes, notes))
        db.commit()
        db.close()
        audit("SAVE_SUBNET_NOTE", str(subnet_id), f"Note updated")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ─────────────────────────────────────────
# HA / Multi-server Status
# ─────────────────────────────────────────
@app.route("/servers")
@login_required
def servers():
    statuses = get_all_server_status()
    # Get version info for each server
    for s in statuses:
        if s["up"]:
            ver = kea_command("version-get", server=s["server"])
            s["version"] = ver.get("arguments", {}).get("extended", ver.get("text", ""))
            s["version"] = s["version"].splitlines()[0] if s["version"] else ""
            # Get lease stats per server
            stats_result = kea_command("stat-lease4-get", server=s["server"])
            s["lease_stats"] = stats_result.get("arguments", {}).get("result-set", {}) if stats_result.get("result") == 0 else {}
        else:
            s["version"] = ""
            s["lease_stats"] = {}
    single_server = len(KEA_SERVERS) == 1
    ha_mode = cfg.get("kea", "ha_mode", fallback="")
    return render_template("servers.html", statuses=statuses,
                           single_server=single_server,
                           ha_mode=ha_mode,
                           subnet_map=SUBNET_MAP)

@app.route("/servers/restart/<int:server_id>", methods=["POST"])
@login_required
@admin_required
def restart_kea_server(server_id):
    server = next((s for s in KEA_SERVERS if s["id"] == server_id), None)
    if not server:
        flash("Server not found.", "error")
        return redirect(url_for("servers"))
    if not server["ssh_host"]:
        flash("SSH not configured for this server.", "error")
        return redirect(url_for("servers"))
    SSH_OPTS = ["-i", SSH_KEY_PATH, "-o", "StrictHostKeyChecking=no",
                "-o", f"UserKnownHostsFile=/etc/jen/ssh/known_hosts"]
    try:
        result = subprocess.run(
            ["ssh"] + SSH_OPTS + [f"{server['ssh_user']}@{server['ssh_host']}",
             "sudo systemctl restart isc-kea-dhcp4-server"],
            capture_output=True, timeout=15
        )
        if result.returncode == 0:
            flash(f"Kea restarted on {server['name']}.", "success")
            audit("RESTART_KEA", server["name"], f"Remote restart via SSH")
        else:
            flash(f"Restart failed on {server['name']}: {result.stderr.decode()}", "error")
    except Exception as e:
        flash(f"SSH error: {str(e)}", "error")
    return redirect(url_for("servers"))

# ─────────────────────────────────────────
# Reports
# ─────────────────────────────────────────
@app.route("/reports")
@login_required
def reports():
    days = request.args.get("days", "7")
    try:
        days = max(1, min(int(days), 90))
    except ValueError:
        days = 7

    history = {}
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            for subnet_id, info in SUBNET_MAP.items():
                cur.execute("""
                    SELECT
                        DATE_FORMAT(snapshot_time, '%%Y-%%m-%%d %%H:%%i') as ts,
                        active_leases, dynamic_leases, reserved_leases, pool_size
                    FROM lease_history
                    WHERE subnet_id=%s
                    AND snapshot_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
                    ORDER BY snapshot_time ASC
                """, (subnet_id, days))
                rows = cur.fetchall()
                history[subnet_id] = {
                    "name": info["name"],
                    "cidr": info["cidr"],
                    "data": rows
                }
        db.close()
    except Exception as e:
        logger.error(f"Reports error: {e}")
        flash(f"Could not load history data: {str(e)}", "error")

    # Summary stats
    summary = {}
    try:
        db = get_kea_db()
        jdb = get_jen_db()
        with db.cursor() as cur:
            with jdb.cursor() as jcur:
                for subnet_id, info in SUBNET_MAP.items():
                    cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                    active = cur.fetchone()["cnt"]
                    jcur.execute("""
                        SELECT active_leases, pool_size, snapshot_time
                        FROM lease_history WHERE subnet_id=%s
                        ORDER BY snapshot_time DESC LIMIT 1
                    """, (subnet_id,))
                    last = jcur.fetchone()
                    jcur.execute("""
                        SELECT MAX(active_leases) as peak FROM lease_history
                        WHERE subnet_id=%s AND snapshot_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
                    """, (subnet_id, days))
                    peak = jcur.fetchone()
                    summary[subnet_id] = {
                        "name": info["name"],
                        "cidr": info["cidr"],
                        "current": active,
                        "pool_size": last["pool_size"] if last else 0,
                        "peak": peak["peak"] if peak and peak["peak"] else active,
                    }
        db.close()
        jdb.close()
    except Exception as e:
        logger.error(f"Reports summary error: {e}")

    snapshot_interval = get_global_setting("snapshot_interval_minutes", "30")
    retention_days = get_global_setting("history_retention_days", "90")
    data_points = sum(len(h["data"]) for h in history.values())

    return render_template("reports.html",
                           history=history, summary=summary, days=days,
                           subnet_map=SUBNET_MAP, data_points=data_points,
                           snapshot_interval=snapshot_interval,
                           retention_days=retention_days)

@app.route("/reports/settings", methods=["POST"])
@login_required
@admin_required
def save_report_settings():
    interval = request.form.get("snapshot_interval", "30").strip()
    retention = request.form.get("retention_days", "90").strip()
    if not interval.isdigit() or not (5 <= int(interval) <= 1440):
        flash("Snapshot interval must be between 5 and 1440 minutes.", "error")
        return redirect(url_for("reports"))
    if not retention.isdigit() or not (1 <= int(retention) <= 365):
        flash("Retention must be between 1 and 365 days.", "error")
        return redirect(url_for("reports"))
    set_global_setting("snapshot_interval_minutes", interval)
    set_global_setting("history_retention_days", retention)
    flash(f"Report settings saved — snapshots every {interval} minutes, kept for {retention} days.", "success")
    audit("SAVE_SETTINGS", "reports", f"interval={interval}min retention={retention}days")
    return redirect(url_for("reports"))

# ─────────────────────────────────────────
# API
# ─────────────────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    try:
        db = get_kea_db()
        stats = {}
        with db.cursor() as cur:
            for subnet_id, info in SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                active = cur.fetchone()["cnt"]
                cur.execute("""
                    SELECT COUNT(*) as cnt FROM lease4 l
                    LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                        AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
                    WHERE l.state=0 AND l.subnet_id=%s AND h.host_id IS NULL
                """, (subnet_id,))
                dynamic = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (subnet_id,))
                reservations = cur.fetchone()["cnt"]
                stats[str(subnet_id)] = {
                    "active": active,
                    "dynamic": dynamic,
                    "reservations": reservations,
                    "name": info["name"],
                    "cidr": info["cidr"],
                }
        db.close()
        # Get pool sizes from Kea config
        pool_sizes = {}
        result = kea_command("config-get", server=get_active_kea_server())
        if result.get("result") == 0:
            for s in result["arguments"]["Dhcp4"].get("subnet4", []):
                for pool in s.get("pools", []):
                    p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                    if "-" in p:
                        start, end = [x.strip() for x in p.split("-")]
                        pool_sizes[str(s["id"])] = ip_to_int(end) - ip_to_int(start) + 1
        # Get Kea version
        kea_up = False
        kea_version = ""
        ver_result = kea_command("version-get")
        if ver_result.get("result") == 0:
            kea_up = True
            kea_version = ver_result.get("arguments", {}).get("extended", ver_result.get("text", ""))
            kea_version = kea_version.splitlines()[0] if kea_version else ""
        server_statuses = [{
            "id": s["id"], "name": s["name"], "up": kea_is_up(server=s), "role": s["role"]
        } for s in KEA_SERVERS]
        return jsonify({
            "subnets": stats,
            "pool_sizes": pool_sizes,
            "kea_up": any(s["up"] for s in server_statuses),
            "kea_version": kea_version,
            "servers": server_statuses,
        })
    except Exception as e:
        return jsonify({"subnets": {}, "pool_sizes": {}, "kea_up": False, "error": str(e)})

@app.route("/metrics")
def prometheus_metrics():
    lines = []
    lines.append("# HELP jen_subnet_active_leases Number of active leases per subnet")
    lines.append("# TYPE jen_subnet_active_leases gauge")
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            for subnet_id, info in SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (subnet_id,))
                cnt = cur.fetchone()["cnt"]
                lines.append(f'jen_subnet_active_leases{{subnet="{info["name"]}",cidr="{info["cidr"]}"}} {cnt}')
        db.close()
    except Exception:
        pass
    lines.append("# HELP jen_kea_up Whether Kea DHCP is reachable")
    lines.append("# TYPE jen_kea_up gauge")
    lines.append(f"jen_kea_up {1 if kea_is_up() else 0}")
    return Response("\n".join(lines) + "\n", mimetype="text/plain")

# ─────────────────────────────────────────
# REST API v1
# ─────────────────────────────────────────

def _api_auth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    raw_key = auth[7:].strip()
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, name FROM api_keys WHERE key_hash=%s AND active=1", (key_hash,))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE api_keys SET last_used=NOW() WHERE id=%s", (row["id"],))
                db.commit()
        db.close()
        return row
    except Exception:
        return None

def api_error(message, code=400):
    return jsonify({"error": message}), code

def api_ok(data):
    return jsonify(data)

@app.route("/api/v1/health")
def api_v1_health():
    kea_up = kea_is_up()
    kea_version = ""
    try:
        ver = kea_command("version-get")
        if ver.get("result") == 0:
            kea_version = ver.get("arguments", {}).get("extended", ver.get("text", ""))
            kea_version = kea_version.splitlines()[0] if kea_version else ""
    except Exception:
        pass
    return api_ok({"jen_version": JEN_VERSION, "kea_up": kea_up, "kea_version": kea_version, "subnets": len(SUBNET_MAP)})

@app.route("/api/v1/subnets")
def api_v1_subnets():
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    result = []
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            for sid, info in SUBNET_MAP.items():
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (sid,))
                active = cur.fetchone()["cnt"]
                cur.execute("SELECT COUNT(*) as cnt FROM hosts WHERE dhcp4_subnet_id=%s", (sid,))
                reserved = cur.fetchone()["cnt"]
                result.append({"id": sid, "name": info["name"], "cidr": info["cidr"],
                                "active_leases": active, "reservations": reserved,
                                "pool_size": 0, "pools": [], "utilization_pct": 0})
        db.close()
        try:
            cfg_result = kea_command("config-get", server=get_active_kea_server())
            if cfg_result.get("result") == 0:
                for s in cfg_result["arguments"]["Dhcp4"].get("subnet4", []):
                    for r in result:
                        if r["id"] == s["id"]:
                            pool_size = 0
                            pools = []
                            for p in s.get("pools", []):
                                ps = p.get("pool", "") if isinstance(p, dict) else str(p)
                                if "-" in ps:
                                    start, end = [x.strip() for x in ps.split("-")]
                                    pool_size += ip_to_int(end) - ip_to_int(start) + 1
                                    pools.append(ps)
                            r["pool_size"] = pool_size
                            r["pools"] = pools
                            r["utilization_pct"] = round(r["active_leases"] / pool_size * 100, 1) if pool_size > 0 else 0
        except Exception:
            pass
    except Exception as e:
        return api_error(str(e), 500)
    return api_ok({"subnets": result, "count": len(result)})

@app.route("/api/v1/leases")
def api_v1_leases():
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    subnet = request.args.get("subnet", "")
    mac = request.args.get("mac", "").lower().replace(":", "").replace("-", "")
    hostname = request.args.get("hostname", "")
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
    except ValueError:
        limit = 200
    result = []
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            where = ["l.state=0", "l.expire > NOW()"]
            params = []
            if subnet:
                sid = next((k for k, v in SUBNET_MAP.items() if v["name"].lower() == subnet.lower() or str(k) == subnet), None)
                if sid:
                    where.append("l.subnet_id=%s")
                    params.append(sid)
            if mac:
                where.append("HEX(l.hwaddr) LIKE %s")
                params.append("%" + mac + "%")
            if hostname:
                where.append("l.hostname LIKE %s")
                params.append("%" + hostname + "%")
            cur.execute(
                "SELECT inet_ntoa(l.address) AS ip, l.hostname, HEX(l.hwaddr) AS mac_hex, l.subnet_id, "
                "(l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained, "
                "l.expire AS expires, l.valid_lifetime "
                "FROM lease4 l WHERE " + " AND ".join(where) + " ORDER BY l.expire DESC LIMIT %s",
                params + [limit]
            )
            for row in cur.fetchall():
                mf = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)).lower() if row["mac_hex"] else ""
                si = SUBNET_MAP.get(row["subnet_id"], {})
                result.append({"ip": row["ip"], "mac": mf, "hostname": row["hostname"] or "",
                                "subnet_id": row["subnet_id"], "subnet_name": si.get("name",""),
                                "obtained": row["obtained"].isoformat() if row["obtained"] else None,
                                "expires": row["expires"].isoformat() if row["expires"] else None,
                                "valid_lifetime": row["valid_lifetime"]})
        db.close()
        di = get_device_info_map([r["mac"] for r in result if r["mac"]])
        for r in result:
            info = di.get(r["mac"], {})
            r["manufacturer"] = info.get("manufacturer", "")
            r["device_type"] = info.get("device_type", "unknown")
    except Exception as e:
        return api_error(str(e), 500)
    return api_ok({"leases": result, "count": len(result)})

@app.route("/api/v1/leases/<mac>")
def api_v1_lease_by_mac(mac):
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    mac_clean = mac.lower().replace(":", "").replace("-", "")
    if len(mac_clean) != 12:
        return api_error("Invalid MAC address format.", 400)
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(l.address) AS ip, l.hostname, HEX(l.hwaddr) AS mac_hex, l.subnet_id, "
                "(l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained, "
                "l.expire AS expires, l.valid_lifetime, l.state "
                "FROM lease4 l WHERE HEX(l.hwaddr)=%s ORDER BY l.expire DESC LIMIT 1",
                (mac_clean.upper(),)
            )
            row = cur.fetchone()
        db.close()
        if not row:
            return api_error("No lease found for this MAC address.", 404)
        mf = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)).lower() if row["mac_hex"] else ""
        si = SUBNET_MAP.get(row["subnet_id"], {})
        active = row["state"] == 0 and row["expires"] and row["expires"] > datetime.now()
        return api_ok({"ip": row["ip"], "mac": mf, "hostname": row["hostname"] or "",
                        "subnet_id": row["subnet_id"], "subnet_name": si.get("name",""),
                        "obtained": row["obtained"].isoformat() if row["obtained"] else None,
                        "expires": row["expires"].isoformat() if row["expires"] else None,
                        "valid_lifetime": row["valid_lifetime"], "active": active})
    except Exception as e:
        return api_error(str(e), 500)

@app.route("/api/v1/devices")
def api_v1_devices_endpoint():
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    mac = request.args.get("mac", "").lower().replace(":", "").replace("-", "")
    name = request.args.get("name", "")
    subnet = request.args.get("subnet", "")
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
    except ValueError:
        limit = 200
    result = []
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            where = ["1=1"]
            params = []
            if mac:
                where.append("REPLACE(d.mac, ':', '') LIKE %s")
                params.append("%" + mac + "%")
            if name:
                where.append("(d.device_name LIKE %s OR d.last_hostname LIKE %s)")
                params += ["%" + name + "%", "%" + name + "%"]
            if subnet:
                sid = next((k for k, v in SUBNET_MAP.items() if v["name"].lower() == subnet.lower() or str(k) == subnet), None)
                if sid:
                    where.append("d.last_subnet_id=%s")
                    params.append(sid)
            cur.execute(
                "SELECT d.mac, d.device_name, d.owner, d.last_ip, d.last_hostname, "
                "d.last_subnet_id, d.first_seen, d.last_seen, "
                "DATEDIFF(NOW(), d.last_seen) as days_inactive "
                "FROM devices d WHERE " + " AND ".join(where) + " ORDER BY d.last_seen DESC LIMIT %s",
                params + [limit]
            )
            for row in cur.fetchall():
                si = SUBNET_MAP.get(row["last_subnet_id"], {})
                result.append({"mac": row["mac"], "device_name": row["device_name"] or "",
                                "owner": row["owner"] or "", "last_ip": row["last_ip"] or "",
                                "last_hostname": row["last_hostname"] or "",
                                "subnet_name": si.get("name",""),
                                "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
                                "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
                                "days_inactive": row["days_inactive"]})
        db.close()
    except Exception as e:
        return api_error(str(e), 500)
    return api_ok({"devices": result, "count": len(result)})

@app.route("/api/v1/devices/<mac>")
def api_v1_device_by_mac(mac):
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    mac_fmt = mac.lower().replace("-", ":")
    try:
        db = get_jen_db()
        kdb = get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM devices WHERE mac=%s", (mac_fmt,))
            row = cur.fetchone()
        if not row:
            db.close(); kdb.close()
            return api_error("Device not found.", 404)
        mac_clean = mac_fmt.replace(":", "").upper()
        with kdb.cursor() as kcur:
            kcur.execute(
                "SELECT inet_ntoa(address) AS ip, hostname, state, "
                "(expire - INTERVAL valid_lifetime SECOND) AS obtained, expire AS expires "
                "FROM lease4 WHERE HEX(hwaddr)=%s ORDER BY expire DESC LIMIT 1",
                (mac_clean,)
            )
            lease = kcur.fetchone()
        db.close(); kdb.close()
        si = SUBNET_MAP.get(row["last_subnet_id"], {})
        result = {"mac": row["mac"], "device_name": row["device_name"] or "",
                  "owner": row["owner"] or "", "last_ip": row["last_ip"] or "",
                  "last_hostname": row["last_hostname"] or "", "subnet_name": si.get("name",""),
                  "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
                  "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
                  "online": False, "current_lease": None}
        if lease and lease["state"] == 0 and lease["expires"] and lease["expires"] > datetime.now():
            result["online"] = True
            result["current_lease"] = {"ip": lease["ip"], "hostname": lease["hostname"] or "",
                                        "obtained": lease["obtained"].isoformat() if lease["obtained"] else None,
                                        "expires": lease["expires"].isoformat() if lease["expires"] else None}
        return api_ok(result)
    except Exception as e:
        return api_error(str(e), 500)

@app.route("/api/v1/reservations")
def api_v1_reservations():
    if not _api_auth():
        return api_error("Invalid or missing API key.", 401)
    subnet = request.args.get("subnet", "")
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
    except ValueError:
        limit = 200
    result = []
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            where = ["dhcp4_subnet_id > 0"]
            params = []
            if subnet:
                sid = next((k for k, v in SUBNET_MAP.items() if v["name"].lower() == subnet.lower() or str(k) == subnet), None)
                if sid:
                    where.append("dhcp4_subnet_id=%s")
                    params.append(sid)
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) AS ip, hostname, "
                "HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id "
                "FROM hosts WHERE " + " AND ".join(where) + " ORDER BY ipv4_address LIMIT %s",
                params + [limit]
            )
            for row in cur.fetchall():
                mf = ":".join(row["mac_hex"][i:i+2] for i in range(0,12,2)).lower() if row["mac_hex"] else ""
                si = SUBNET_MAP.get(row["subnet_id"], {})
                result.append({"ip": row["ip"], "mac": mf, "hostname": row["hostname"] or "",
                                "subnet_id": row["subnet_id"], "subnet_name": si.get("name","")})
        db.close()
    except Exception as e:
        return api_error(str(e), 500)
    return api_ok({"reservations": result, "count": len(result)})

# ─────────────────────────────────────────
# API Key Management
# ─────────────────────────────────────────

@app.route("/settings/api-keys")
@login_required
@admin_required
def api_keys():
    keys = []
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT k.id, k.name, k.key_prefix, k.created_at, k.last_used, k.active, "
                "u.username as created_by_name "
                "FROM api_keys k LEFT JOIN users u ON u.id = k.created_by "
                "ORDER BY k.created_at DESC"
            )
            keys = cur.fetchall()
        db.close()
    except Exception as e:
        flash(f"Could not load API keys: {str(e)}", "error")
    return render_template("api_keys.html", keys=keys)

@app.route("/settings/api-keys/create", methods=["POST"])
@login_required
@admin_required
def api_keys_create():
    import secrets as _secrets
    name = request.form.get("name", "").strip()[:100]
    if not name:
        flash("Key name is required.", "error")
        return redirect(url_for("api_keys"))
    raw_key = "jen_" + _secrets.token_hex(24)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:8]
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("INSERT INTO api_keys (name, key_hash, key_prefix, created_by) VALUES (%s,%s,%s,%s)",
                        (name, key_hash, key_prefix, current_user.id))
        db.commit(); db.close()
        audit("API_KEY_CREATE", "api_keys", f"Key '{name}' created by {current_user.username}")
        session["new_api_key"] = raw_key
        session["new_api_key_name"] = name
        flash("API key created. Copy it now — it won't be shown again.", "success")
    except Exception as e:
        flash(f"Error creating key: {str(e)}", "error")
    return redirect(url_for("api_keys"))

@app.route("/settings/api-keys/revoke/<int:key_id>", methods=["POST"])
@login_required
@admin_required
def api_keys_revoke(key_id):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT name FROM api_keys WHERE id=%s", (key_id,))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE api_keys SET active=0 WHERE id=%s", (key_id,))
                db.commit()
                audit("API_KEY_REVOKE", "api_keys", f"Key '{row['name']}' revoked by {current_user.username}")
                flash(f"API key '{row['name']}' revoked.", "success")
        db.close()
    except Exception as e:
        flash(f"Error revoking key: {str(e)}", "error")
    return redirect(url_for("api_keys"))

@app.route("/settings/api-keys/delete/<int:key_id>", methods=["POST"])
@login_required
@admin_required
def api_keys_delete(key_id):
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT name FROM api_keys WHERE id=%s", (key_id,))
            row = cur.fetchone()
            if row:
                cur.execute("DELETE FROM api_keys WHERE id=%s", (key_id,))
                db.commit()
                audit("API_KEY_DELETE", "api_keys", f"Key '{row['name']}' deleted by {current_user.username}")
                flash(f"API key '{row['name']}' deleted.", "success")
        db.close()
    except Exception as e:
        flash(f"Error deleting key: {str(e)}", "error")
    return redirect(url_for("api_keys"))

@app.route("/settings/api-docs")
@login_required
def api_docs():
    keys = []
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, name, key_prefix FROM api_keys WHERE active=1 ORDER BY created_at DESC LIMIT 10")
            keys = cur.fetchall()
        db.close()
    except Exception:
        pass
    base_url = request.host_url.rstrip("/")
    return render_template("api_docs.html", keys=keys, base_url=base_url)

# ─────────────────────────────────────────
# Run
# ─────────────────────────────────────────
if __name__ == "__main__":
    init_jen_db()
    threading.Thread(target=check_alerts, daemon=True).start()

    if ssl_configured():
        print(f"SSL configured — HTTPS:{HTTPS_PORT} HTTP redirect:{HTTP_PORT}")
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(SSL_COMBINED if os.path.exists(SSL_COMBINED) else SSL_CERT, SSL_KEY)
        https_server = make_server("0.0.0.0", HTTPS_PORT, app, ssl_context=ssl_ctx)
        http_app = Flask("http_redirect")
        @http_app.route("/", defaults={"path": ""})
        @http_app.route("/<path:path>")
        def http_redirect(path):
            host = request.host.split(":")[0]
            return redirect(f"https://{host}:{HTTPS_PORT}/{path}", code=301)
        http_server = make_server("0.0.0.0", HTTP_PORT, http_app)
        t1 = threading.Thread(target=https_server.serve_forever, daemon=True)
        t2 = threading.Thread(target=http_server.serve_forever, daemon=True)
        t1.start(); t2.start(); t1.join()
    else:
        print(f"HTTP only — port {HTTP_PORT}")
        app.run(host="0.0.0.0", port=HTTP_PORT, debug=False)
