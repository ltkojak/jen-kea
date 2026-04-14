#!/usr/bin/env python3
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

JEN_VERSION = "1.1.0"

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

def ip_to_int(ip):
    parts = ip.strip().split(".")
    return sum(int(x) << (8*(3-i)) for i, x in enumerate(parts))

def check_alerts():
    import time
    last_kea_status = True
    last_seen_leases = set()
    first_run = True
    while True:
        try:
            alerts_enabled = get_global_setting("telegram_enabled", "false") == "true"
            kea_up = kea_is_up()
            if alerts_enabled and get_global_setting("alert_kea_down", "true") == "true":
                if not kea_up and last_kea_status:
                    send_telegram("🚨 <b>Jen Alert</b>\nKea DHCP server is <b>DOWN</b>!")
                elif kea_up and not last_kea_status:
                    send_telegram("✅ <b>Jen Alert</b>\nKea DHCP server is back <b>UP</b>.")
            last_kea_status = kea_up

            if kea_up:
                db = get_kea_db()
                try:
                    with db.cursor() as cur:
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

                        if alerts_enabled and get_global_setting("alert_new_lease", "false") == "true":
                            for row in new_lease_rows:
                                mac = format_mac(row["hwaddr"])
                                subnet_name = SUBNET_MAP.get(row["subnet_id"], {}).get("name", f"Subnet {row['subnet_id']}")
                                send_telegram(
                                    f"🆕 <b>New DHCP Lease</b>\n"
                                    f"IP: <code>{row['ip']}</code>\n"
                                    f"MAC: <code>{mac}</code>\n"
                                    f"Hostname: <code>{row['hostname'] or '(none)'}</code>\n"
                                    f"Subnet: <b>{subnet_name}</b>"
                                )
                        last_seen_leases = current_leases
                        first_run = False

                        if alerts_enabled and get_global_setting("alert_utilization", "true") == "true":
                            threshold = int(get_global_setting("alert_threshold_pct", "80"))
                            result = kea_command("config-get")
                            if result.get("result") == 0:
                                for s in result["arguments"]["Dhcp4"].get("subnet4", []):
                                    sid = s["id"]
                                    if sid not in SUBNET_MAP:
                                        continue
                                    cur.execute("SELECT COUNT(*) as cnt FROM lease4 WHERE state=0 AND subnet_id=%s", (sid,))
                                    active = cur.fetchone()["cnt"]
                                    for pool in s.get("pools", []):
                                        p = pool.get("pool", "") if isinstance(pool, dict) else str(pool)
                                        if "-" in p:
                                            start, end = [x.strip() for x in p.split("-")]
                                            pool_size = ip_to_int(end) - ip_to_int(start) + 1
                                            pct = (active / pool_size * 100) if pool_size > 0 else 0
                                            if pct >= threshold:
                                                info = SUBNET_MAP[sid]
                                                send_telegram(
                                                    f"⚠️ <b>Utilization Alert</b>\n"
                                                    f"Subnet <b>{info['name']} ({info['cidr']})</b>\n"
                                                    f"Usage: <b>{pct:.0f}%</b> ({active}/{pool_size} addresses)"
                                                )
                finally:
                    db.close()
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
    return render_template("reservations.html", hosts=hosts,
                           subnet_filter=subnet_filter, search=search,
                           subnet_map=SUBNET_MAP, page=page, pages=pages, total=total)

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
    return render_template("subnets.html", subnets=subnet_data, ssh_ready=ssh_ready)

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
    try:
        with open(DDNS_LOG, "r") as f:
            all_lines = f.readlines()
            lines = list(reversed(all_lines[-200:]))
        if not lines:
            log_status = "empty"
            log_message = "Log file exists but contains no entries yet."
    except FileNotFoundError:
        log_status = "missing"
        log_message = f"Log file not found: {DDNS_LOG} — Check the log_path setting in jen.config [ddns] section."
    except PermissionError:
        log_status = "error"
        log_message = f"Permission denied reading {DDNS_LOG} — the www-data user may not have read access."
    except Exception as e:
        log_status = "error"
        log_message = f"Could not read DDNS log: {str(e)}"

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
@app.route("/settings")
@login_required
@admin_required
def settings():
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

    return render_template("settings.html",
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
