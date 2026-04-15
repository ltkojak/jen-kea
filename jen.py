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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

JEN_VERSION = "1.5.1"

# ─────────────────────────────────────────
# App setup
# ─────────────────────────────────────────
app = Flask(__name__, static_folder="/opt/jen/static")
app.secret_key = os.urandom(24).hex()

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
SSH_KEY_PATH = cfg.get("kea_ssh", "key_path", fallback="/etc/jen/ssh/jen_rsa")
DDNS_LOG     = cfg.get("ddns", "log_path", fallback="/var/log/kea/kea-ddns-technitium.log")

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
            cur.execute("SELECT COUNT(*) as cnt FROM users")
            if cur.fetchone()["cnt"] == 0:
                cur.execute(
                    "INSERT INTO users (username, password, role) VALUES (%s, %s, 'admin')",
                    ("admin", hash_password("admin"))
                )
                print("Created default admin user: admin / admin")
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
    return hashlib.sha256(p.encode()).hexdigest()

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
def kea_command(command, service="dhcp4", arguments=None):
    payload = {"command": command, "service": [service]}
    if arguments:
        payload["arguments"] = arguments
    try:
        resp = requests.post(KEA_API_URL, json=payload,
                             auth=(KEA_API_USER, KEA_API_PASS), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data[0] if isinstance(data, list) else data
    except requests.exceptions.ConnectionError:
        return {"result": 1, "text": "Cannot connect to Kea API. Is Kea running?"}
    except requests.exceptions.Timeout:
        return {"result": 1, "text": "Kea API request timed out."}
    except Exception as e:
        return {"result": 1, "text": str(e)}

def kea_is_up():
    result = kea_command("version-get")
    return result.get("result") == 0

def format_mac(raw_bytes):
    if not raw_bytes:
        return ""
    return ":".join(f"{b:02x}" for b in raw_bytes)

# ─────────────────────────────────────────
# Telegram
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
    "kea_down":           "🚨 <b>Kea Alert</b>\nKea DHCP server is <b>DOWN</b>!",
    "kea_up":             "✅ <b>Kea Alert</b>\nKea DHCP server is back <b>UP</b>.",
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

def take_lease_snapshot():
    """Record current lease counts for all subnets."""
    try:
        retention_days = int(get_global_setting("history_retention_days", "90"))
        kdb = get_kea_db()
        jdb = get_jen_db()

        # Get pool sizes from Kea config
        pool_sizes = {}
        result = kea_command("config-get")
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

    while True:
        try:
            kea_up = kea_is_up()

            # ── Kea up/down ──
            if not kea_up and last_kea_status:
                send_alert("kea_down")
            elif kea_up and not last_kea_status:
                send_alert("kea_up")
            last_kea_status = kea_up

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
                                    jcur.execute("""
                                        INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, last_seen)
                                        VALUES (%s, %s, %s, %s, NOW())
                                        ON DUPLICATE KEY UPDATE
                                            last_ip=%s, last_hostname=%s,
                                            last_subnet_id=%s, last_seen=NOW()
                                    """, (mac, row["ip"], row["hostname"], row["subnet_id"],
                                          row["ip"], row["hostname"], row["subnet_id"]))
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
                        kea_cfg = kea_command("config-get")
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
            return render_template("login.html", jen_version=JEN_VERSION)

        # Check rate limit
        locked, remaining = is_locked_out(ip, username)
        if locked:
            if remaining >= 999:
                flash("Account is locked. Contact an administrator.", "error")
            else:
                flash(f"Too many failed attempts. Try again in {remaining} minute(s).", "error")
            return render_template("login.html", jen_version=JEN_VERSION)

        try:
            db = get_jen_db()
            with db.cursor() as cur:
                cur.execute(
                    "SELECT id, username, role, session_timeout FROM users WHERE username=%s AND password=%s",
                    (username, hash_password(password))
                )
                row = cur.fetchone()
            db.close()
        except Exception as e:
            logger.error(f"Login DB error: {e}")
            flash("Database error. Please try again.", "error")
            return render_template("login.html", jen_version=JEN_VERSION)

        if row:
            clear_login_attempts(ip, username)
            user = User(row["id"], row["username"], row["role"], row["session_timeout"])
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

    return render_template("login.html", jen_version=JEN_VERSION)

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
    hours = request.args.get("hours", "0.5")
    try:
        hours_val = float(hours)
        if hours_val <= 0 or hours_val > 168:
            hours_val = 0.5
    except ValueError:
        hours_val = 0.5
    minutes_val = int(hours_val * 60)

    stats = {}
    try:
        db = get_kea_db()
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
                stats[subnet_id] = {
                    "name": info["name"], "cidr": info["cidr"],
                    "active": active, "dynamic": dynamic, "reservations": reservations,
                }
        db.close()
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        flash("Could not load subnet statistics. Check Kea database connection.", "error")

    recent = []
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute(f"""
                SELECT inet_ntoa(l.address) AS ip, l.hwaddr,
                       IFNULL(l.hostname,'') AS hostname,
                       l.subnet_id, l.expire, l.valid_lifetime,
                       DATE_SUB(l.expire, INTERVAL l.valid_lifetime SECOND) AS obtained
                FROM lease4 l
                LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                    AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
                WHERE l.state=0 AND h.host_id IS NULL
                AND DATE_SUB(l.expire, INTERVAL l.valid_lifetime SECOND) >= DATE_SUB(NOW(), INTERVAL %s MINUTE)
                ORDER BY obtained DESC LIMIT 50
            """, (minutes_val,))
            for row in cur.fetchall():
                row["mac"] = format_mac(row["hwaddr"])
                row["subnet_name"] = SUBNET_MAP.get(row["subnet_id"], {}).get("name", "Unknown")
                recent.append(row)
        db.close()
    except Exception as e:
        logger.error(f"Dashboard recent leases error: {e}")

    kea_up = kea_is_up()
    # Get pool sizes for utilization bars
    pool_sizes = {}
    try:
        result = kea_command("config-get")
        if result.get("result") == 0:
            for s in result["arguments"]["Dhcp4"].get("subnet4", []):
                for pool in s.get("pools", []):
                    p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                    if "-" in p:
                        start, end = [x.strip() for x in p.split("-")]
                        pool_sizes[str(s["id"])] = ip_to_int(end) - ip_to_int(start) + 1
    except Exception:
        pass
    return render_template("dashboard.html", stats=stats, recent=recent,
                           kea_up=kea_up, hours=str(hours_val), subnet_map=SUBNET_MAP,
                           pool_sizes=pool_sizes)

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
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 50

    # Validate subnet filter
    if subnet_filter != "all":
        try:
            subnet_filter_int = int(subnet_filter)
            if subnet_filter_int not in SUBNET_MAP:
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
            if show_expired:
                where.append("l.state=1")
            else:
                where.append("l.state=0")
                where.append("h.host_id IS NULL")
            if subnet_filter != "all":
                where.append("l.subnet_id=%s")
                params.append(int(subnet_filter))
            if minutes and minutes.isdigit() and 0 < int(minutes) <= 10080:
                where.append("DATE_SUB(l.expire, INTERVAL l.valid_lifetime SECOND) >= DATE_SUB(NOW(), INTERVAL %s MINUTE)")
                params.append(int(minutes))
            if search:
                where.append("(inet_ntoa(l.address) LIKE %s OR l.hostname LIKE %s OR HEX(l.hwaddr) LIKE %s)")
                s = f"%{search}%"
                params += [s, s, s.replace(":", "")]

            join = "" if show_expired else """
                LEFT JOIN hosts h ON h.dhcp4_subnet_id=l.subnet_id
                    AND h.dhcp_identifier=l.hwaddr AND h.dhcp_identifier_type=0
            """
            where_str = " AND ".join(where) if where else "1=1"

            cur.execute(f"SELECT COUNT(*) as cnt FROM lease4 l {join} WHERE {where_str}", params)
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT inet_ntoa(l.address) AS ip, l.hwaddr,
                       IFNULL(l.hostname,'') AS hostname,
                       l.subnet_id, l.expire, l.valid_lifetime, l.state,
                       DATE_SUB(l.expire, INTERVAL l.valid_lifetime SECOND) AS obtained
                FROM lease4 l {join}
                WHERE {where_str}
                ORDER BY l.subnet_id, l.address
                LIMIT {per_page} OFFSET {offset}
            """, params)
            for row in cur.fetchall():
                row["mac"] = format_mac(row["hwaddr"])
                row["subnet_name"] = SUBNET_MAP.get(row["subnet_id"], {}).get("name", "Unknown")
                leases_list.append(row)
        db.close()
    except Exception as e:
        logger.error(f"Leases error: {e}")
        flash("Could not load leases. Check Kea database connection.", "error")

    pages = max(1, (total + per_page - 1) // per_page)
    return render_template("leases.html", leases=leases_list,
                           subnet_filter=subnet_filter, minutes=minutes,
                           search=search, show_expired=show_expired,
                           subnet_map=SUBNET_MAP, page=page, pages=pages, total=total)

@app.route("/leases/release", methods=["POST"])
@login_required
@admin_required
def release_lease():
    ip = request.form.get("ip", "").strip()
    if not valid_ip(ip):
        flash("Invalid IP address.", "error")
        return redirect(url_for("leases"))
    result = kea_command("lease4-del", arguments={"ip-address": ip})
    if result.get("result") == 0:
        flash(f"Lease for {ip} released.", "success")
        audit("RELEASE_LEASE", ip, f"Lease released for {ip}")
    else:
        flash(f"Failed to release lease: {result.get('text')}", "error")
    return redirect(url_for("leases"))

@app.route("/leases/delete-stale", methods=["POST"])
@login_required
@admin_required
def delete_stale_leases():
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE state=1 AND expire < NOW()")
            deleted = cur.rowcount
        db.commit()
        db.close()
        flash(f"Deleted {deleted} stale lease(s).", "success")
        audit("DELETE_STALE", "leases", f"Deleted {deleted} stale leases")
    except Exception as e:
        flash(f"Error deleting stale leases: {str(e)}", "error")
    return redirect(url_for("leases"))

@app.route("/leases/make-reservation", methods=["POST"])
@login_required
@admin_required
def make_reservation():
    ip = request.form.get("ip", "").strip()
    mac = request.form.get("mac", "").strip().lower()
    hostname = request.form.get("hostname", "").strip()[:253]
    dns_override = request.form.get("dns_override", "").strip()

    errors = []
    if not valid_ip(ip):
        errors.append(f"Invalid IP address: {ip}")
    if not valid_mac(mac):
        errors.append(f"Invalid MAC address: {mac}")
    if hostname and not valid_hostname(hostname):
        errors.append(f"Invalid hostname: {hostname}")
    if dns_override and not valid_dns(dns_override):
        errors.append(f"Invalid DNS override (must be comma-separated IPs): {dns_override}")
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("leases"))

    try:
        subnet_id = int(request.form.get("subnet_id"))
    except (ValueError, TypeError):
        flash("Invalid subnet ID.", "error")
        return redirect(url_for("leases"))

    # Duplicate check
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s", (ip,))
            if cur.fetchone():
                flash(f"A reservation for {ip} already exists.", "error")
                db.close()
                return redirect(url_for("leases"))
            mac_hex = mac.replace(":", "")
            cur.execute("SELECT host_id FROM hosts WHERE HEX(dhcp_identifier)=%s AND dhcp4_subnet_id=%s", (mac_hex, subnet_id))
            if cur.fetchone():
                flash(f"A reservation for MAC {mac} already exists in this subnet.", "error")
                db.close()
                return redirect(url_for("leases"))
        db.close()
    except Exception as e:
        flash(f"Database error during duplicate check: {str(e)}", "error")
        return redirect(url_for("leases"))

    result = kea_command("reservation-add", arguments={
        "reservation": {
            "subnet-id": subnet_id, "hw-address": mac,
            "ip-address": ip, "hostname": hostname,
            **({"option-data": [{"name": "domain-name-servers", "data": dns_override}]} if dns_override else {})
        }
    })
    if result.get("result") == 0:
        flash(f"Reservation created for {ip}.", "success")
        audit("ADD_RESERVATION", ip, f"MAC={mac} hostname={hostname}")
    else:
        flash(f"Failed to create reservation: {result.get('text')}", "error")
    return redirect(url_for("leases"))

# ─────────────────────────────────────────
# IP Map
# ─────────────────────────────────────────
@app.route("/ipmap")
@login_required
def ipmap():
    default_subnet = list(SUBNET_MAP.keys())[0] if SUBNET_MAP else 1
    try:
        subnet_id = int(request.args.get("subnet", default_subnet))
        if subnet_id not in SUBNET_MAP:
            subnet_id = default_subnet
    except ValueError:
        subnet_id = default_subnet

    used = {}
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT inet_ntoa(address) AS ip, hostname, 'dynamic' AS type
                FROM lease4 WHERE state=0 AND subnet_id=%s
            """, (subnet_id,))
            for row in cur.fetchall():
                used[row["ip"]] = {"hostname": row["hostname"], "type": "dynamic"}
            cur.execute("""
                SELECT inet_ntoa(ipv4_address) AS ip, hostname, 'reserved' AS type
                FROM hosts WHERE dhcp4_subnet_id=%s
            """, (subnet_id,))
            for row in cur.fetchall():
                used[row["ip"]] = {"hostname": row["hostname"], "type": "reserved"}
        db.close()
    except Exception as e:
        logger.error(f"IP map error: {e}")
        flash("Could not load IP map data.", "error")

    pool_start = pool_end = None
    try:
        result = kea_command("config-get")
        if result.get("result") == 0:
            for s in result["arguments"]["Dhcp4"].get("subnet4", []):
                if s["id"] == subnet_id:
                    for pool in s.get("pools", []):
                        p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                        if "-" in p:
                            pool_start, pool_end = [x.strip() for x in p.split("-")]
                            break
    except Exception as e:
        logger.error(f"IP map pool fetch error: {e}")

    return render_template("ipmap.html", used=used, subnet_id=subnet_id,
                           subnet_map=SUBNET_MAP, pool_start=pool_start, pool_end=pool_end)

# ─────────────────────────────────────────
# Reservations
# ─────────────────────────────────────────
@app.route("/reservations")
@login_required
def reservations():
    subnet_filter = request.args.get("subnet", "all")
    search = sanitize_search(request.args.get("search", "").strip())
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
                       h.dhcp_identifier, h.hostname, h.dhcp4_subnet_id
                FROM hosts h WHERE {' AND '.join(where)}
                ORDER BY h.dhcp4_subnet_id, h.ipv4_address
                LIMIT {per_page} OFFSET {offset}
            """, params)
            for row in cur.fetchall():
                row["mac"] = format_mac(row["dhcp_identifier"])
                row["subnet_name"] = SUBNET_MAP.get(row["dhcp4_subnet_id"], {}).get("name", "Unknown")
                cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (row["host_id"],))
                dns_row = cur.fetchone()
                row["dns_override"] = dns_row["formatted_value"] if dns_row and dns_row["formatted_value"] else ""
                with jen_db.cursor() as jcur:
                    jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (row["host_id"],))
                    note_row = jcur.fetchone()
                    row["notes"] = note_row["notes"] if note_row else ""
                hosts.append(row)
        kea_db.close()
        jen_db.close()
    except Exception as e:
        logger.error(f"Reservations error: {e}")
        flash("Could not load reservations. Check database connection.", "error")

    pages = max(1, (total + per_page - 1) // per_page)
    stale_days = int(get_global_setting("stale_device_days", "30"))
    # Get stale MACs from device inventory
    stale_macs = set()
    try:
        jdb = get_jen_db()
        with jdb.cursor() as jcur:
            jcur.execute(f"SELECT mac FROM devices WHERE last_seen < DATE_SUB(NOW(), INTERVAL {stale_days} DAY)")
            stale_macs = {row["mac"] for row in jcur.fetchall()}
        jdb.close()
    except Exception:
        pass
    for host in hosts:
        host["is_stale"] = host["mac"] in stale_macs
    return render_template("reservations.html", hosts=hosts,
                           subnet_filter=subnet_filter, search=search,
                           subnet_map=SUBNET_MAP, page=page, pages=pages, total=total,
                           stale_days=stale_days)

@app.route("/reservations/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_reservation():
    if request.method == "POST":
        mac = request.form.get("mac", "").strip().lower()
        ip = request.form.get("ip", "").strip()
        hostname = request.form.get("hostname", "").strip()[:253]
        dns_override = request.form.get("dns_override", "").strip()
        notes = request.form.get("notes", "").strip()[:1000]

        try:
            subnet_id = int(request.form.get("subnet_id"))
            if subnet_id not in SUBNET_MAP:
                flash("Invalid subnet selected.", "error")
                return render_template("add_reservation.html", subnet_map=SUBNET_MAP)
        except (ValueError, TypeError):
            flash("Invalid subnet.", "error")
            return render_template("add_reservation.html", subnet_map=SUBNET_MAP)

        errors = []
        if not valid_ip(ip):
            errors.append(f"Invalid IP address: {ip}")
        if not valid_mac(mac):
            errors.append(f"Invalid MAC address format. Expected: aa:bb:cc:dd:ee:ff")
        if hostname and not valid_hostname(hostname):
            errors.append(f"Invalid hostname: {hostname}")
        if dns_override and not valid_dns(dns_override):
            errors.append(f"Invalid DNS override — must be comma-separated IP addresses.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("add_reservation.html", subnet_map=SUBNET_MAP)

        # Verify IP is in the correct subnet
        try:
            network = ipaddress.ip_network(SUBNET_MAP[subnet_id]["cidr"], strict=False)
            if ipaddress.ip_address(ip) not in network:
                flash(f"IP {ip} is not within subnet {SUBNET_MAP[subnet_id]['cidr']}.", "error")
                return render_template("add_reservation.html", subnet_map=SUBNET_MAP)
        except Exception:
            pass

        # Duplicate check
        try:
            db = get_kea_db()
            with db.cursor() as cur:
                cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s", (ip,))
                if cur.fetchone():
                    flash(f"A reservation for IP {ip} already exists.", "error")
                    db.close()
                    return render_template("add_reservation.html", subnet_map=SUBNET_MAP)
                mac_hex = mac.replace(":", "")
                cur.execute("SELECT host_id FROM hosts WHERE HEX(dhcp_identifier)=%s AND dhcp4_subnet_id=%s", (mac_hex, subnet_id))
                if cur.fetchone():
                    flash(f"A reservation for MAC {mac} already exists in this subnet.", "error")
                    db.close()
                    return render_template("add_reservation.html", subnet_map=SUBNET_MAP)
            db.close()
        except Exception as e:
            flash(f"Database error during duplicate check: {str(e)}", "error")
            return render_template("add_reservation.html", subnet_map=SUBNET_MAP)

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
                        hrow = cur.fetchone()
                        if hrow:
                            jdb = get_jen_db()
                            with jdb.cursor() as jcur:
                                jcur.execute("INSERT INTO reservation_notes (host_id, notes) VALUES (%s, %s) ON DUPLICATE KEY UPDATE notes=%s",
                                             (hrow["host_id"], notes, notes))
                            jdb.commit()
                            jdb.close()
                    db.close()
                except Exception as e:
                    logger.error(f"Failed to save notes: {e}")
            flash(f"Reservation added for {ip}.", "success")
            audit("ADD_RESERVATION", ip, f"MAC={mac} hostname={hostname}")
            subnet_name = SUBNET_MAP.get(subnet_id, {}).get("name", f"Subnet {subnet_id}")
            send_alert("reservation_added", ip=ip, mac=mac,
                      hostname=hostname or "(none)", subnet=subnet_name)
            return redirect(url_for("reservations"))
        else:
            flash(f"Kea error: {result.get('text')}", "error")

    return render_template("add_reservation.html", subnet_map=SUBNET_MAP)

@app.route("/reservations/edit/<int:host_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_reservation(host_id):
    try:
        kea_db = get_kea_db()
        jen_db = get_jen_db()
        with kea_db.cursor() as cur:
            cur.execute("""
                SELECT host_id, inet_ntoa(ipv4_address) AS ip,
                       dhcp_identifier, hostname, dhcp4_subnet_id
                FROM hosts WHERE host_id=%s
            """, (host_id,))
            host = cur.fetchone()
            if not host:
                flash("Reservation not found.", "error")
                return redirect(url_for("reservations"))
            host["mac"] = format_mac(host["dhcp_identifier"])
            cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (host_id,))
            dns_row = cur.fetchone()
            host["dns_override"] = dns_row["formatted_value"] if dns_row and dns_row["formatted_value"] else ""
        with jen_db.cursor() as jcur:
            jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (host_id,))
            note_row = jcur.fetchone()
            host["notes"] = note_row["notes"] if note_row else ""
        kea_db.close()
        jen_db.close()
    except Exception as e:
        flash(f"Error loading reservation: {str(e)}", "error")
        return redirect(url_for("reservations"))

    if request.method == "POST":
        new_hostname = request.form.get("hostname", "").strip()[:253]
        new_dns = request.form.get("dns_override", "").strip()
        new_notes = request.form.get("notes", "").strip()[:1000]

        errors = []
        if new_hostname and not valid_hostname(new_hostname):
            errors.append(f"Invalid hostname: {new_hostname}")
        if new_dns and not valid_dns(new_dns):
            errors.append("Invalid DNS override — must be comma-separated IP addresses.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("edit_reservation.html", host=host, subnet_map=SUBNET_MAP)

        kea_command("reservation-del", arguments={
            "subnet-id": host["dhcp4_subnet_id"],
            "identifier-type": "hw-address", "identifier": host["mac"]
        })
        res = {"subnet-id": host["dhcp4_subnet_id"], "hw-address": host["mac"],
               "ip-address": host["ip"], "hostname": new_hostname}
        if new_dns:
            res["option-data"] = [{"name": "domain-name-servers", "data": new_dns}]

        add_result = kea_command("reservation-add", arguments={"reservation": res})
        if add_result.get("result") == 0:
            try:
                jdb = get_jen_db()
                with jdb.cursor() as jcur:
                    jcur.execute("INSERT INTO reservation_notes (host_id, notes) VALUES (%s, %s) ON DUPLICATE KEY UPDATE notes=%s",
                                 (host_id, new_notes, new_notes))
                jdb.commit()
                jdb.close()
            except Exception as e:
                logger.error(f"Failed to save notes: {e}")
            flash(f"Reservation updated for {host['ip']}.", "success")
            audit("EDIT_RESERVATION", host["ip"], f"hostname={new_hostname}")
            return redirect(url_for("reservations"))
        else:
            flash(f"Kea error: {add_result.get('text')}", "error")

    return render_template("edit_reservation.html", host=host, subnet_map=SUBNET_MAP)

@app.route("/reservations/delete/<int:host_id>", methods=["POST"])
@login_required
@admin_required
def delete_reservation(host_id):
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            cur.execute("SELECT inet_ntoa(ipv4_address) AS ip, dhcp_identifier, dhcp4_subnet_id FROM hosts WHERE host_id=%s", (host_id,))
            host = cur.fetchone()
        db.close()
    except Exception as e:
        flash(f"Database error: {str(e)}", "error")
        return redirect(url_for("reservations"))

    if not host:
        flash("Reservation not found.", "error")
        return redirect(url_for("reservations"))

    mac = format_mac(host["dhcp_identifier"])
    result = kea_command("reservation-del", arguments={
        "subnet-id": host["dhcp4_subnet_id"],
        "identifier-type": "hw-address", "identifier": mac
    })
    if result.get("result") == 0:
        try:
            jdb = get_jen_db()
            with jdb.cursor() as jcur:
                jcur.execute("DELETE FROM reservation_notes WHERE host_id=%s", (host_id,))
            jdb.commit()
            jdb.close()
        except Exception:
            pass
        flash(f"Reservation for {host['ip']} deleted.", "success")
        audit("DELETE_RESERVATION", host["ip"], f"MAC={mac}")
        subnet_name = SUBNET_MAP.get(host["dhcp4_subnet_id"], {}).get("name", f"Subnet {host['dhcp4_subnet_id']}")
        send_alert("reservation_deleted", ip=host["ip"], mac=mac, subnet=subnet_name)
    else:
        flash(f"Kea error: {result.get('text')}", "error")
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
            cur.execute("""
                SELECT h.host_id, inet_ntoa(h.ipv4_address) AS ip,
                       h.dhcp_identifier, h.hostname, h.dhcp4_subnet_id
                FROM hosts h WHERE h.dhcp4_subnet_id > 0
                ORDER BY h.dhcp4_subnet_id, h.ipv4_address
            """)
            for row in cur.fetchall():
                mac = format_mac(row["dhcp_identifier"])
                cur.execute("SELECT formatted_value FROM dhcp4_options WHERE host_id=%s AND code=6", (row["host_id"],))
                dns_row = cur.fetchone()
                dns = dns_row["formatted_value"] if dns_row and dns_row["formatted_value"] else ""
                with jdb.cursor() as jcur:
                    jcur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (row["host_id"],))
                    note_row = jcur.fetchone()
                    notes = note_row["notes"] if note_row else ""
                subnet_name = SUBNET_MAP.get(row["dhcp4_subnet_id"], {}).get("name", "")
                writer.writerow([row["ip"], mac, row["hostname"] or "", row["dhcp4_subnet_id"], subnet_name, dns, notes])
        db.close()
        jdb.close()
        output.seek(0)
        audit("EXPORT_RESERVATIONS", "reservations", "CSV export")
        return Response(output.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=reservations.csv"})
    except Exception as e:
        flash(f"Export failed: {str(e)}", "error")
        return redirect(url_for("reservations"))

@app.route("/reservations/import", methods=["POST"])
@login_required
@admin_required
def import_reservations():
    f = request.files.get("csv_file")
    if not f or not f.filename.endswith(".csv"):
        flash("Please select a valid .csv file.", "error")
        return redirect(url_for("reservations"))

    added = skipped = errors = 0
    error_details = []

    try:
        reader = csv.DictReader(io.StringIO(f.read().decode("utf-8")))
        required_cols = {"ip", "mac", "subnet_id"}
        if not reader.fieldnames or not required_cols.issubset(set(reader.fieldnames)):
            flash(f"CSV missing required columns: {required_cols}", "error")
            return redirect(url_for("reservations"))

        for i, row in enumerate(reader, 1):
            try:
                ip = row.get("ip", "").strip()
                mac = row.get("mac", "").strip().lower()
                hostname = row.get("hostname", "").strip()[:253]
                dns_override = row.get("dns_override", "").strip()
                notes = row.get("notes", "").strip()[:1000]

                try:
                    subnet_id = int(row.get("subnet_id", 1))
                except ValueError:
                    error_details.append(f"Row {i}: Invalid subnet_id")
                    errors += 1
                    continue

                row_errors = []
                if not valid_ip(ip): row_errors.append(f"invalid IP '{ip}'")
                if not valid_mac(mac): row_errors.append(f"invalid MAC '{mac}'")
                if hostname and not valid_hostname(hostname): row_errors.append(f"invalid hostname '{hostname}'")
                if dns_override and not valid_dns(dns_override): row_errors.append(f"invalid DNS '{dns_override}'")
                if row_errors:
                    error_details.append(f"Row {i}: {', '.join(row_errors)}")
                    errors += 1
                    continue

                # Duplicate check
                db = get_kea_db()
                with db.cursor() as cur:
                    cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s", (ip,))
                    if cur.fetchone():
                        skipped += 1
                        db.close()
                        continue
                db.close()

                res = {"subnet-id": subnet_id, "hw-address": mac, "ip-address": ip, "hostname": hostname}
                if dns_override:
                    res["option-data"] = [{"name": "domain-name-servers", "data": dns_override}]

                result = kea_command("reservation-add", arguments={"reservation": res})
                if result.get("result") == 0:
                    added += 1
                    if notes:
                        try:
                            db = get_kea_db()
                            with db.cursor() as cur:
                                cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s", (ip,))
                                hrow = cur.fetchone()
                                if hrow:
                                    jdb = get_jen_db()
                                    with jdb.cursor() as jcur:
                                        jcur.execute("INSERT INTO reservation_notes (host_id, notes) VALUES (%s,%s) ON DUPLICATE KEY UPDATE notes=%s",
                                                     (hrow["host_id"], notes, notes))
                                    jdb.commit()
                                    jdb.close()
                            db.close()
                        except Exception:
                            pass
                else:
                    error_details.append(f"Row {i}: Kea error — {result.get('text')}")
                    errors += 1
            except Exception as e:
                error_details.append(f"Row {i}: {str(e)}")
                errors += 1

    except Exception as e:
        flash(f"Import failed: {str(e)}", "error")
        return redirect(url_for("reservations"))

    msg = f"Import complete: {added} added, {skipped} skipped (duplicates), {errors} errors."
    flash(msg, "success" if errors == 0 else "warning")
    if error_details:
        for detail in error_details[:5]:  # show first 5 errors
            flash(detail, "error")
        if len(error_details) > 5:
            flash(f"...and {len(error_details)-5} more errors. Check your CSV file.", "error")
    audit("IMPORT_RESERVATIONS", "reservations", f"Added={added} Skipped={skipped} Errors={errors}")
    return redirect(url_for("reservations"))

# ─────────────────────────────────────────
# Subnets
# ─────────────────────────────────────────
@app.route("/subnets")
@login_required
def subnets():
    subnet_data = []
    try:
        result = kea_command("config-get")
        if result.get("result") == 0:
            cfg_data = result.get("arguments", {}).get("Dhcp4", {})
            for s in cfg_data.get("subnet4", []):
                subnet_data.append({
                    "id": s.get("id"), "subnet": s.get("subnet"),
                    "pools": [p.get("pool", "") if isinstance(p, dict) else str(p) for p in s.get("pools", []) if p],
                    "valid_lifetime": s.get("valid-lifetime"),
                    "renew_timer": s.get("renew-timer"),
                    "rebind_timer": s.get("rebind-timer"),
                    "options": s.get("option-data", []),
                    "name": SUBNET_MAP.get(s.get("id"), {}).get("name", f"Subnet {s.get('id')}"),
                })
        elif result.get("result") == 1:
            flash(f"Could not load subnet config from Kea: {result.get('text')}", "error")
    except Exception as e:
        flash(f"Error fetching subnet configuration: {str(e)}", "error")

    ssh_ready = os.path.exists(SSH_KEY_PATH) and bool(KEA_SSH_HOST)
    # Load subnet notes
    subnet_notes = {}
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT subnet_id, notes FROM subnet_notes")
            for row in cur.fetchall():
                subnet_notes[row["subnet_id"]] = row["notes"]
        db.close()
    except Exception:
        pass
    return render_template("subnets.html", subnets=subnet_data, ssh_ready=ssh_ready,
                           subnet_notes=subnet_notes)

@app.route("/subnets/edit/<int:subnet_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_subnet(subnet_id):
    if not os.path.exists(SSH_KEY_PATH) or not KEA_SSH_HOST:
        flash("SSH not configured. Set up SSH keys in Settings first.", "error")
        return redirect(url_for("subnets"))

    subnet = None
    try:
        result = kea_command("config-get")
        if result.get("result") == 0:
            for s in result["arguments"]["Dhcp4"].get("subnet4", []):
                if s["id"] == subnet_id:
                    subnet = s
                    subnet["name"] = SUBNET_MAP.get(subnet_id, {}).get("name", f"Subnet {subnet_id}")
                    subnet["pools"] = [p.get("pool", "") if isinstance(p, dict) else str(p) for p in s.get("pools", []) if p]
                    break
    except Exception as e:
        flash(f"Error fetching subnet config: {str(e)}", "error")
        return redirect(url_for("subnets"))

    if not subnet:
        flash("Subnet not found.", "error")
        return redirect(url_for("subnets"))

    if request.method == "POST":
        new_pool   = request.form.get("pool", "").strip()
        new_valid  = request.form.get("valid_lifetime", "").strip()
        new_renew  = request.form.get("renew_timer", "").strip()
        new_rebind = request.form.get("rebind_timer", "").strip()
        new_routers = request.form.get("routers", "").strip()
        new_dns    = request.form.get("dns_servers", "").strip()

        errors = []
        if new_pool and not valid_pool(new_pool):
            errors.append("Invalid pool format. Use: x.x.x.x-y.y.y.y")
        if new_valid and not valid_positive_int(new_valid):
            errors.append("Valid lifetime must be a positive integer (seconds).")
        if new_renew and not valid_positive_int(new_renew):
            errors.append("Renew timer must be a positive integer (seconds).")
        if new_rebind and not valid_positive_int(new_rebind):
            errors.append("Rebind timer must be a positive integer (seconds).")
        if new_routers and not valid_ip(new_routers):
            errors.append(f"Invalid router IP: {new_routers}")
        if new_dns and not valid_dns(new_dns):
            errors.append("Invalid DNS servers — must be comma-separated IP addresses.")
        if new_valid and new_renew:
            if int(new_renew) >= int(new_valid):
                errors.append("Renew timer must be less than valid lifetime.")
        if new_valid and new_rebind:
            if int(new_rebind) >= int(new_valid):
                errors.append("Rebind timer must be less than valid lifetime.")
        if new_renew and new_rebind:
            if int(new_renew) >= int(new_rebind):
                errors.append("Renew timer must be less than rebind timer.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("edit_subnet.html", subnet=subnet, subnet_map=SUBNET_MAP)

        update_script = f"""
import json, subprocess, os
with open('{KEA_CONF}') as f:
    cfg = json.load(f)
for s in cfg['Dhcp4']['subnet4']:
    if s['id'] == {subnet_id}:
        if '{new_pool}':
            s['pools'] = [{{'option-data': [], 'pool': '{new_pool}'}}]
        if '{new_valid}'.isdigit():
            s['valid-lifetime'] = int('{new_valid}')
            s['max-valid-lifetime'] = int('{new_valid}')
            s['min-valid-lifetime'] = int('{new_valid}')
        if '{new_renew}'.isdigit():
            s['renew-timer'] = int('{new_renew}')
        if '{new_rebind}'.isdigit():
            s['rebind-timer'] = int('{new_rebind}')
        for opt in s.get('option-data', []):
            if opt.get('name') == 'routers' and '{new_routers}':
                opt['data'] = '{new_routers}'
            if opt.get('name') == 'domain-name-servers' and '{new_dns}':
                opt['data'] = '{new_dns}'
import json as _json
new_content = _json.dumps(cfg, indent=2)
subprocess.run(['sudo', 'cp', '{KEA_CONF}', '{KEA_CONF}.bak'], check=True)
proc = subprocess.run(['sudo', 'tee', '{KEA_CONF}'], input=new_content, capture_output=True, text=True, check=True)
print('OK')
"""
        SSH_OPTS = [
            "-i", SSH_KEY_PATH,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/etc/jen/ssh/known_hosts",
        ]
        try:
            import base64
            script_b64 = base64.b64encode(update_script.strip().encode()).decode()
            decode_cmd = f"echo {script_b64} | base64 -d > /tmp/jen_subnet_update.py && sudo python3 /tmp/jen_subnet_update.py && rm /tmp/jen_subnet_update.py"
            result = subprocess.run(
                ["ssh"] + SSH_OPTS + [f"{KEA_SSH_USER}@{KEA_SSH_HOST}", decode_cmd],
                capture_output=True, text=True, timeout=30
            )
            if "OK" in result.stdout:
                val = subprocess.run(
                    ["ssh"] + SSH_OPTS + [f"{KEA_SSH_USER}@{KEA_SSH_HOST}",
                     f"sudo kea-dhcp4 -t {KEA_CONF} 2>&1 | tail -5"],
                    capture_output=True, text=True, timeout=30
                )
                if "error" not in val.stdout.lower() and "fatal" not in val.stdout.lower():
                    subprocess.run(
                        ["ssh"] + SSH_OPTS + [f"{KEA_SSH_USER}@{KEA_SSH_HOST}",
                         "sudo systemctl restart isc-kea-dhcp4-server"],
                        capture_output=True, timeout=30
                    )
                    flash(f"Subnet {subnet['name']} updated successfully.", "success")
                    audit("EDIT_SUBNET", str(subnet_id), f"pool={new_pool} valid_lifetime={new_valid}")
                    send_alert("kea_config_changed", subnet=subnet["name"],
                              details=f"pool={new_pool or 'unchanged'} valid_lifetime={new_valid or 'unchanged'}")
                else:
                    subprocess.run(
                        ["ssh"] + SSH_OPTS + [f"{KEA_SSH_USER}@{KEA_SSH_HOST}",
                         f"sudo cp {KEA_CONF}.bak {KEA_CONF}"],
                        capture_output=True, timeout=30
                    )
                    flash(f"Config validation failed — changes rolled back.", "error")
            else:
                flash(f"Failed to update config: {result.stderr or result.stdout}", "error")
        except subprocess.TimeoutExpired:
            flash("SSH connection timed out. Check that your-kea-server is reachable.", "error")
        except Exception as e:
            flash(f"SSH error: {str(e)}", "error")

        return redirect(url_for("subnets"))

    return render_template("edit_subnet.html", subnet=subnet, subnet_map=SUBNET_MAP)

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
    per_page = 50
    logs = []
    total = 0
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM audit_log")
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT %s OFFSET %s", (per_page, offset))
            logs = cur.fetchall()
        db.close()
    except Exception as e:
        flash(f"Could not load audit log: {str(e)}", "error")
    pages = max(1, (total + per_page - 1) // per_page)
    return render_template("audit.html", logs=logs, page=page, pages=pages, total=total)

# ─────────────────────────────────────────
# DDNS
# ─────────────────────────────────────────
@app.route("/ddns")
@login_required
def ddns():
    lines = []
    log_status = "ok"
    log_message = ""

    # If SSH is configured, read the log from the Kea server via SSH
    # (the log file lives on the Kea server, not the Jen server)
    if KEA_SSH_HOST and os.path.exists(SSH_KEY_PATH):
        SSH_OPTS = [
            "-i", SSH_KEY_PATH,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/etc/jen/ssh/known_hosts",
        ]
        try:
            result = subprocess.run(
                ["ssh"] + SSH_OPTS + [f"{KEA_SSH_USER}@{KEA_SSH_HOST}",
                 f"sudo tail -200 {DDNS_LOG} 2>/dev/null || echo __NOTFOUND__"],
                capture_output=True, text=True, timeout=10
            )
            raw = result.stdout.strip()
            if "__NOTFOUND__" in raw or not raw:
                log_status = "missing"
                log_message = f"Log file not found on Kea server: {DDNS_LOG}"
            else:
                all_lines = raw.splitlines()
                lines = list(reversed(all_lines))
                if not lines:
                    log_status = "empty"
                    log_message = "Log file exists but contains no entries yet."
        except subprocess.TimeoutExpired:
            log_status = "error"
            log_message = "SSH connection to Kea server timed out."
        except Exception as e:
            log_status = "error"
            log_message = f"SSH error reading log: {str(e)}"
    else:
        # Fall back to reading locally (only works if Jen and Kea are on same server)
        try:
            with open(DDNS_LOG, "r") as f:
                all_lines = f.readlines()
                lines = list(reversed(all_lines[-200:]))
            if not lines:
                log_status = "empty"
                log_message = "Log file exists but contains no entries yet."
        except FileNotFoundError:
            log_status = "missing"
            log_message = f"Log file not found: {DDNS_LOG} — SSH not configured, falling back to local read."
        except PermissionError:
            log_status = "error"
            log_message = f"Permission denied reading {DDNS_LOG}."
        except Exception as e:
            log_status = "error"
            log_message = f"Could not read log: {str(e)}"

    lookup_result = None
    lookup_host = request.args.get("lookup", "").strip()[:253]
    if lookup_host:
        technitium_url = cfg.get("ddns", "api_url", fallback="")
        technitium_token = cfg.get("ddns", "api_token", fallback="")
        forward_zone = cfg.get("ddns", "forward_zone", fallback="")
        if technitium_url and technitium_token:
            try:
                resp = requests.get(
                    f"{technitium_url}/zones/records/get",
                    params={"token": technitium_token, "domain": lookup_host,
                            "zone": forward_zone, "listZone": "false"},
                    timeout=10, verify=False
                )
                data = resp.json()
                if data.get("status") == "ok":
                    lookup_result = data.get("response", {}).get("records", [])
                else:
                    lookup_result = f"API error: {data.get('errorMessage', 'Unknown error')}"
            except requests.exceptions.ConnectionError:
                lookup_result = "Cannot connect to Technitium DNS server."
            except Exception as e:
                lookup_result = str(e)
        else:
            lookup_result = "DDNS API not configured. Set api_url and api_token in [ddns] config section."

    return render_template("ddns.html", lines=lines, lookup_host=lookup_host,
                           lookup_result=lookup_result, log_status=log_status,
                           log_message=log_message, ddns_log=DDNS_LOG)

# ─────────────────────────────────────────
# Settings
# ─────────────────────────────────────────
# ─────────────────────────────────────────
# About
# ─────────────────────────────────────────
@app.route("/about")
@login_required
def about():
    kea_up = False
    kea_version = ""
    try:
        ver_result = kea_command("version-get")
        if ver_result.get("result") == 0:
            kea_up = True
            kea_version = ver_result.get("arguments", {}).get("extended", ver_result.get("text", ""))
            kea_version = kea_version.splitlines()[0] if kea_version else ""
    except Exception:
        pass
    lease_counts = {}
    try:
        db = get_kea_db()
        with db.cursor() as cur:
            for sid in SUBNET_MAP:
                cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (sid,))
                lease_counts[sid] = cur.fetchone()["cnt"]
        db.close()
    except Exception:
        pass
    return render_template("about.html",
                           jen_version=JEN_VERSION, kea_version=kea_version,
                           kea_up=kea_up, http_port=HTTP_PORT, https_port=HTTPS_PORT,
                           ssl_on=ssl_configured(), kea_ssh_host=KEA_SSH_HOST,
                           subnet_map=SUBNET_MAP, lease_counts=lease_counts)

# ─────────────────────────────────────────
# Settings — System
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
                           kea_version=kea_version)

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
                    except: ch["config"] = {}
                if isinstance(ch.get("alert_types"), str):
                    try: ch["alert_types"] = json.loads(ch["alert_types"])
                    except: ch["alert_types"] = []
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

    if channel_type not in ("telegram", "email", "slack", "webhook"):
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
        "ddns_zone": cfg.get("ddns", "forward_zone", fallback=""),
        "subnets": SUBNET_MAP,
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

@app.route("/settings/infrastructure/save-ddns", methods=["POST"])
@login_required
@admin_required
def save_infra_ddns():
    log_path = request.form.get("log_path", "").strip()
    api_url = request.form.get("api_url", "").strip()
    api_token = request.form.get("api_token", "").strip()
    forward_zone = request.form.get("forward_zone", "").strip()
    if log_path:
        write_config_value("ddns", "log_path", log_path)
        global DDNS_LOG
        DDNS_LOG = log_path
    if api_url:
        write_config_value("ddns", "api_url", api_url)
    if api_token:
        write_config_value("ddns", "api_token", api_token)
    if forward_zone:
        write_config_value("ddns", "forward_zone", forward_zone)
    flash("DDNS settings saved.", "success")
    audit("SAVE_INFRA", "ddns", f"log={log_path}")
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
        db.close()
    except Exception as e:
        flash(f"Could not load users: {str(e)}", "error")
        all_users = []
    global_timeout = get_global_setting("session_timeout_minutes", "60")
    return render_template("users.html", users=all_users, global_timeout=global_timeout)

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
            cur.execute("SELECT id FROM users WHERE id=%s AND password=%s",
                        (current_user.id, hash_password(current_pw)))
            if not cur.fetchone():
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
            where_str = " AND ".join(where) if where else "1=1"

            cur.execute(f"SELECT COUNT(*) as cnt FROM devices d WHERE {where_str}", params)
            total = cur.fetchone()["cnt"]
            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT d.id, d.mac, d.device_name, d.owner, d.notes,
                       d.first_seen, d.last_seen, d.last_ip, d.last_hostname, d.last_subnet_id,
                       DATEDIFF(NOW(), d.last_seen) as days_since_seen
                FROM devices d
                WHERE {where_str}
                ORDER BY d.last_seen DESC
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
    return render_template("devices.html", devices=devices_list, page=page, pages=pages,
                           total=total, search=search, show_stale=show_stale,
                           stale_days=stale_days, subnet_map=SUBNET_MAP)

@app.route("/devices/edit/<int:device_id>", methods=["POST"])
@login_required
@admin_required
def edit_device(device_id):
    device_name = request.form.get("device_name", "").strip()[:200]
    owner = request.form.get("owner", "").strip()[:200]
    notes = request.form.get("notes", "").strip()[:1000]
    try:
        db = get_jen_db()
        with db.cursor() as cur:
            cur.execute("UPDATE devices SET device_name=%s, owner=%s, notes=%s WHERE id=%s",
                        (device_name or None, owner or None, notes or None, device_id))
        db.commit()
        db.close()
        return jsonify({"ok": True})
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
        result = kea_command("config-get")
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
        return jsonify({
            "subnets": stats,
            "pool_sizes": pool_sizes,
            "kea_up": kea_up,
            "kea_version": kea_version,
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
