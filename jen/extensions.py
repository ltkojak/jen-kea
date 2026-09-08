"""
jen/extensions.py
─────────────────
Shared application state. All modules import from here to avoid
circular imports.

As of v4.0.0, all config-derived globals in this module are assigned
EXCLUSIVELY by AppConfig.apply() in jen/config.py — the single source
of truth for configuration. No other code may assign them. To change
configuration at runtime, use app_config.write_value() /
write_values() / write_subnets() / mutate(), all of which write to
disk and re-derive these globals atomically, so the on-disk file and
in-memory state can never diverge.

CPython module objects are singletons — any module that does
    from jen import extensions
    print(extensions.KEA_SERVERS)
sees the current values immediately after any reload.

(The test suite is the one sanctioned exception: tests/conftest.py
patches these globals directly to point at the jen_test database.)
"""

import configparser
import os

# ── Install root (v5.3.3) ───────────────────────────────────────────────────
# Every path below that lives under the application's install directory
# (as opposed to /etc/jen, which is the separate CONFIGURATION directory
# convention and is deliberately untouched by this) is derived from this
# one constant instead of hardcoding "/opt/jen" repeatedly — a third-party
# review correctly pointed out that a hardcoded absolute path here makes a
# local clone-and-run hostile (nothing under /opt/jen exists outside a real
# install) and forces CI to work around it with a symlink. Defaults to
# /opt/jen, so every existing production install's behavior is completely
# unchanged; set JEN_ROOT to override for local development or a
# CI checkout that isn't (and shouldn't need to be) installed to
# /opt/jen at all.
JEN_ROOT = os.environ.get("JEN_ROOT", "/opt/jen")

# ── Config ──────────────────────────────────────────────────────────────────
cfg: configparser.ConfigParser = None   # loaded by app factory

# ── Kea connection constants ─────────────────────────────────────────────────
KEA_API_URL:  str = ""
KEA_API_USER: str = ""
KEA_API_PASS: str = ""

KEA_DB_HOST: str = ""
KEA_DB_USER: str = ""
KEA_DB_PASS: str = ""
KEA_DB_NAME: str = "kea"
KEA_DB_SSL_CA: str = ""   # v4.4.5 — path to CA cert; empty = plaintext (unchanged default)

JEN_DB_HOST: str = ""
JEN_DB_USER: str = ""
JEN_DB_PASS: str = ""
JEN_DB_NAME: str = "jen"
JEN_DB_SSL_CA: str = ""  # v4.4.5 — same idea, independent of KEA_DB_SSL_CA
                          # since jen_db and kea_db can live on different hosts

HTTP_PORT:  int = 5050
HTTPS_PORT: int = 8443

# v5.5.0 — worker thread count for the gunicorn server (run.py launches
# `gunicorn --workers 1 --threads N`). One worker keeps the background
# scheduler + alert loop a single-process concern; threads carry the
# I/O-bound concurrency (DB, Kea API, SSH). Configurable via
# [server] threads in jen.config and Settings → Infrastructure.
WORKER_THREADS: int = 8

KEA_SSH_HOST: str = ""
KEA_SSH_USER: str = ""
KEA_CONF:     str = "/etc/kea/kea-dhcp4.conf"

# ── IPv6 (v5.0, Phase 1) ──────────────────────────────────────────────────────
# All [kea6]/[kea6_db] values are optional and fall back to their v4
# counterpart when absent — matching Kea's own common deployment pattern of
# one Control Agent proxying to both kea-dhcp4 and kea-dhcp6 (see
# jen/services/kea6.py). None of this is read unless the ipv6_enabled global
# setting (settings table, NOT this config — see get_global_setting) is
# true; a v4-only install with no [kea6] section at all sees these stay
# identical to their v4 equivalents but they are simply never used.
KEA6_API_URL:  str = ""
KEA6_API_USER: str = ""
KEA6_API_PASS: str = ""

KEA6_DB_HOST: str = ""
KEA6_DB_USER: str = ""
KEA6_DB_PASS: str = ""
KEA6_DB_NAME: str = ""
KEA6_DB_SSL_CA: str = ""

# ── Runtime state ────────────────────────────────────────────────────────────
KEA_SERVERS: list = []          # list of server dicts loaded from config
SUBNET_MAP:  dict = {}          # {subnet_id: {"name": str, "cidr": str}}
SUBNET6_MAP: dict = {}          # {subnet_id: {"name": str, "cidr": str}} — v5.0
                                 # Kea's own v6 subnet-ID numbering space,
                                 # does NOT overlap SUBNET_MAP's v4 IDs.
DDNS_LOG:    str  = "/var/log/kea/kea-ddns.log"

# ── Active server cache (TTL 10s) ────────────────────────────────────────────
_active_server_cache: dict = {"server": None, "ts": 0}

# ── File paths ───────────────────────────────────────────────────────────────
CONFIG_FILE   = "/etc/jen/jen.config"
# v5.4.0 — Fernet key for encrypting MFA (TOTP) secrets at rest. Lives
# under /etc/jen (the config/secrets dir, preserved across upgrades),
# NOT in the database it protects. Plain module constant like the paths
# above — the test suite repoints it the same way it repoints CONFIG_FILE.
# jen/services/crypto.py falls back to $JEN_ROOT/.mfa_key when this path
# isn't writable, mirroring _load_secret_key()'s two-candidate approach.
MFA_KEY_PATH  = "/etc/jen/mfa_key"
SSL_CERT      = "/etc/jen/ssl/certificate.crt"
SSL_KEY       = "/etc/jen/ssl/private.key"
SSL_CA        = "/etc/jen/ssl/ca_bundle.crt"
SSL_COMBINED  = "/etc/jen/ssl/combined.crt"
FAVICON_PATH  = os.path.join(JEN_ROOT, "static", "favicon.ico")
STATIC_DIR    = os.path.join(JEN_ROOT, "static")
TEMPLATE_DIR  = os.path.join(JEN_ROOT, "templates")
ICONS_BUNDLED_DIR = os.path.join(JEN_ROOT, "static", "icons", "brands")
ICONS_CUSTOM_DIR  = os.path.join(JEN_ROOT, "static", "icons", "custom")
NAV_LOGO_PATH = os.path.join(JEN_ROOT, "static", "nav_logo")

# Plugin system
PLUGIN_DIR     = os.path.join(JEN_ROOT, "plugins")          # installed plugin directories
PLUGIN_REGISTRY_URL = "https://raw.githubusercontent.com/ltkojak/jen-kea/main/plugins/registry.json"
SSH_KEY_PATH  = "/etc/jen/ssh/jen_rsa"
SSH_KNOWN_HOSTS = "/etc/jen/ssh/known_hosts"
