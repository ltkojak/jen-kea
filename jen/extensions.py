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

KEA_SSH_HOST: str = ""
KEA_SSH_USER: str = ""
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

# Plugin system
PLUGIN_DIR     = "/opt/jen/plugins"          # installed plugin directories
PLUGIN_REGISTRY_URL = "https://raw.githubusercontent.com/ltkojak/jen-kea/main/plugins/registry.json"
SSH_KEY_PATH  = "/etc/jen/ssh/jen_rsa"
SSH_KNOWN_HOSTS = "/etc/jen/ssh/known_hosts"
