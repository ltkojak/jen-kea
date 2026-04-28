"""
jen/extensions.py
─────────────────
Shared application state. All modules import from here to avoid
circular imports. The app factory (jen/__init__.py) initialises
these at startup; runtime mutations (e.g. reloading KEA_SERVERS
after a settings save) also go through this module.

CPython module objects are singletons — any module that does
    from jen import extensions
    extensions.KEA_SERVERS = new_value
will have that change visible to every other importer immediately.
"""

import configparser

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

JEN_DB_HOST: str = ""
JEN_DB_USER: str = ""
JEN_DB_PASS: str = ""
JEN_DB_NAME: str = "jen"

HTTP_PORT:  int = 5050
HTTPS_PORT: int = 8443

KEA_SSH_HOST: str = ""
KEA_SSH_USER: str = ""
KEA_SSH_KEY:  str = "/etc/jen/ssh/jen_rsa"
KEA_CONF:     str = "/etc/kea/kea-dhcp4.conf"

# ── Runtime state ────────────────────────────────────────────────────────────
KEA_SERVERS: list = []          # list of server dicts loaded from config
SUBNET_MAP:  dict = {}          # {subnet_id: {"name": str, "cidr": str}}
DDNS_LOG:    str  = "/var/log/kea/kea-ddns.log"

# ── Active server cache (TTL 10s) ────────────────────────────────────────────
_active_server_cache: dict = {"server": None, "ts": 0}

# ── File paths ───────────────────────────────────────────────────────────────
CONFIG_FILE   = "/etc/jen/jen.config"
SSL_CERT      = "/etc/jen/ssl/certificate.crt"
SSL_KEY       = "/etc/jen/ssl/private.key"
SSL_CA        = "/etc/jen/ssl/ca_bundle.crt"
SSL_COMBINED  = "/etc/jen/ssl/combined.crt"
FAVICON_PATH  = "/opt/jen/static/favicon.ico"
STATIC_DIR    = "/opt/jen/static"
ICONS_BUNDLED_DIR = "/opt/jen/static/icons/brands"
ICONS_CUSTOM_DIR  = "/opt/jen/static/icons/custom"
NAV_LOGO_PATH = "/opt/jen/static/nav_logo"
SSH_KEY_PATH  = "/etc/jen/ssh/jen_rsa"
