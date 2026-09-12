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
# install) and forces CI to work around it with a symlink. `JEN_ROOT`
# env override wins (local development, CI). Otherwise: the versioned
# layout's `/opt/jen/current/app` (v5.14.0) if it exists, else the flat
# `/opt/jen` (pre-5.14, Docker, and the one transitional boot). The
# `current` symlink is flipped atomically by the updater / install.sh,
# so this is a stable path to read at startup.
JEN_ROOT = os.environ.get("JEN_ROOT") or (
    "/opt/jen/current/app" if os.path.isdir("/opt/jen/current/app") else "/opt/jen"
)

# ── Config ──────────────────────────────────────────────────────────────────
cfg: configparser.ConfigParser = None  # loaded by app factory

# ── Kea connection constants ─────────────────────────────────────────────────
KEA_API_URL: str = ""
KEA_API_USER: str = ""
KEA_API_PASS: str = ""

# v5.10.0 — Kea removed the Control Agent (deprecated in 3.0, gone in 3.2).
# connection_mode = "ca" | "direct":
#   ca     — one endpoint (KEA_API_URL) is a kea-ctrl-agent that routes
#            commands to kea-dhcp4/kea-dhcp6 by the JSON "service" field.
#            The default, and byte-identical to every release before 5.10.0.
#   direct — talk straight to each daemon's own HTTP control socket. dhcp4
#            commands go to KEA_API_URL (the kea-dhcp4 socket), dhcp6
#            commands to KEA6_API_URL (the kea-dhcp6 socket) with NO
#            fallback, and the "service" field is omitted from the payload.
# KEA_API_CA / KEA_API_TLS_VERIFY only matter for an https:// socket URL:
# a CA-bundle path pins verification to that CA, else the boolean toggle
# (default True — the same as requests' own default).
# KEA_API_CLIENT_CERT / KEA_API_CLIENT_KEY (v5.10.2): a client-cert PEM +
# key on the Jen host, passed to requests as its `cert=(cert, key)` pair.
# Kea's per-daemon https control socket defaults cert-required=true
# (mutual TLS), so without this an https:// endpoint refuses the
# handshake. Both or neither.
KEA_CONNECTION_MODE: str = "ca"
KEA_API_CA: str = ""
KEA_API_TLS_VERIFY: bool = True
KEA_API_CLIENT_CERT: str = ""
KEA_API_CLIENT_KEY: str = ""

KEA_DB_HOST: str = ""
KEA_DB_USER: str = ""
KEA_DB_PASS: str = ""
KEA_DB_NAME: str = "kea"
KEA_DB_SSL_CA: str = ""  # v4.4.5 — path to CA cert; empty = plaintext (unchanged default)

JEN_DB_HOST: str = ""
JEN_DB_USER: str = ""
JEN_DB_PASS: str = ""
JEN_DB_NAME: str = "jen"
JEN_DB_SSL_CA: str = ""  # v4.4.5 — same idea, independent of KEA_DB_SSL_CA
# since jen_db and kea_db can live on different hosts

HTTP_PORT: int = 5050
HTTPS_PORT: int = 8443

# v5.5.0 — worker thread count for the gunicorn server (run.py launches
# `gunicorn --workers 1 --threads N`). One worker keeps the background
# scheduler + alert loop a single-process concern; threads carry the
# I/O-bound concurrency (DB, Kea API, SSH). Configurable via
# [server] threads in jen.config and Settings → System.
WORKER_THREADS: int = 8

# v5.17.0 (Q6 6D) — reverse-proxy trust. List of ipaddress network objects
# parsed from [server] trusted_proxies; empty (the default) = no proxy,
# XFF/XFP headers are ignored and TrustedProxyMiddleware isn't installed.
TRUSTED_PROXIES: list = []

KEA_SSH_HOST: str = ""
KEA_SSH_USER: str = ""
KEA_CONF: str = "/etc/kea/kea-dhcp4.conf"

# ── IPv6 (v5.0, Phase 1) ──────────────────────────────────────────────────────
# All [kea6]/[kea6_db] values are optional and fall back to their v4
# counterpart when absent — matching Kea's own common deployment pattern of
# one Control Agent proxying to both kea-dhcp4 and kea-dhcp6 (see
# jen/services/kea6.py). None of this is read unless the ipv6_enabled global
# setting (settings table, NOT this config — see get_global_setting) is
# true; a v4-only install with no [kea6] section at all sees these stay
# identical to their v4 equivalents but they are simply never used.
KEA6_API_URL: str = ""
KEA6_API_USER: str = ""
KEA6_API_PASS: str = ""

KEA6_DB_HOST: str = ""
KEA6_DB_USER: str = ""
KEA6_DB_PASS: str = ""
KEA6_DB_NAME: str = ""
KEA6_DB_SSL_CA: str = ""

# ── D2 / kea-dhcp-ddns control socket (v5.23.0, Q19) ──────────────────────────
# Optional [d2] section — only matters in `direct` connection mode, where
# the Control Agent isn't there to route a "service": ["d2"] command
# anywhere. In `ca` mode api_url falls back to [kea] api_url at config-apply
# time (same fallback jen/config.py already does for [kea6]), since one CA
# proxies D2 too. api_user/api_pass always fall back to [kea]'s. Applies to
# the PRIMARY server only — each [kea_server_N] sets its own api_d2_url /
# api_d2_user / api_d2_pass (see AppConfig.derive_kea_servers).
D2_API_URL: str = ""
D2_API_USER: str = ""
D2_API_PASS: str = ""

# ── OIDC single sign-on (v5.25.0, Q21) ────────────────────────────────────────
# Optional [oidc] section, entirely backward-compatible — every field below
# defaults to off/blank, so an install with no [oidc] section behaves exactly
# as before. See jen/services/oidc.py for the login flow and the linking
# rules (match ONLY on (auth_provider='oidc', external_id), never username
# or email).
OIDC_ENABLED: bool = False
OIDC_ISSUER: str = ""
OIDC_CLIENT_ID: str = ""
OIDC_CLIENT_SECRET: str = ""
OIDC_SCOPES: str = "openid profile email"
OIDC_USERNAME_CLAIM: str = "preferred_username"
OIDC_ROLE_CLAIM: str = "groups"
# "<role>=<claim-value>[,<claim-value>...];..." — see oidc.parse_role_map().
OIDC_ROLE_MAP: str = "superadmin=jen-superadmin;admin=jen-admin;viewer=jen-viewer"
OIDC_DEFAULT_ROLE: str = "viewer"  # or "none" — denies a user with no mapped group
OIDC_AUTO_CREATE: bool = True
OIDC_BUTTON_LABEL: str = "Sign in with SSO"
OIDC_REDIRECT_URI: str = ""  # blank = derive from url_for(..., _external=True)
OIDC_LOCAL_LOGIN: bool = True  # false hides the password form (escape hatch: /login?local=1)

# ── Runtime state ────────────────────────────────────────────────────────────
KEA_SERVERS: list = []  # list of server dicts loaded from config
SUBNET_MAP: dict = {}  # {subnet_id: {"name": str, "cidr": str}}
SUBNET6_MAP: dict = {}  # {subnet_id: {"name": str, "cidr": str}} — v5.0
# Kea's own v6 subnet-ID numbering space,
# does NOT overlap SUBNET_MAP's v4 IDs.
DDNS_LOG: str = "/var/log/kea/kea-ddns.log"

# ── Active server cache (TTL 10s) ────────────────────────────────────────────
_active_server_cache: dict = {"server": None, "ts": 0}

# ── File paths ───────────────────────────────────────────────────────────────
CONFIG_FILE = "/etc/jen/jen.config"
# v5.4.0 — Fernet key for encrypting MFA (TOTP) secrets at rest. Lives
# under /etc/jen (the config/secrets dir, preserved across upgrades),
# NOT in the database it protects. Plain module constant like the paths
# above — the test suite repoints it the same way it repoints CONFIG_FILE.
# jen/services/crypto.py falls back to $JEN_ROOT/.mfa_key when this path
# isn't writable, mirroring _load_secret_key()'s two-candidate approach.
MFA_KEY_PATH = "/etc/jen/mfa_key"
SSL_CERT = "/etc/jen/ssl/certificate.crt"
SSL_KEY = "/etc/jen/ssl/private.key"
SSL_CA = "/etc/jen/ssl/ca_bundle.crt"
SSL_COMBINED = "/etc/jen/ssl/combined.crt"
STATIC_DIR = os.path.join(JEN_ROOT, "static")
TEMPLATE_DIR = os.path.join(JEN_ROOT, "templates")
ICONS_BUNDLED_DIR = os.path.join(JEN_ROOT, "static", "icons", "brands")

# ── User-writable content (v5.13.0) ─────────────────────────────────────────
# Everything a running Jen writes — uploaded brand icons, the nav logo, a
# custom favicon, DB backups, registry-installed plugins, plugin enable
# markers, and the secret-key / MFA-key fallbacks — lives HERE, outside the
# application tree. /opt/jen is reinstalled from the release tarball on every
# upgrade and (as of 5.13.0) is root-owned and read-only to the service
# user; CONTENT_DIR is service-user-owned and never touched by an upgrade.
#   JEN_CONTENT_DIR env override → that
#   else JEN_ROOT set (a dev / CI checkout) → $JEN_ROOT/var
#   else → /var/lib/jen
CONTENT_DIR = os.environ.get("JEN_CONTENT_DIR") or (
    os.path.join(JEN_ROOT, "var") if "JEN_ROOT" in os.environ else "/var/lib/jen"
)
CONTENT_ICONS_DIR = os.path.join(CONTENT_DIR, "icons")
CONTENT_BRANDING_DIR = os.path.join(CONTENT_DIR, "branding")
CONTENT_BACKUP_DIR = os.path.join(CONTENT_DIR, "backups")
CONTENT_PLUGIN_DIR = os.path.join(CONTENT_DIR, "plugins")
CONTENT_PLUGINS_ENABLED_DIR = os.path.join(CONTENT_DIR, "plugins-enabled")
CONTENT_KEYS_DIR = os.path.join(CONTENT_DIR, "keys")

# The shipped default favicon (release-owned, always present); an uploaded
# override lands at FAVICON_PATH under CONTENT_DIR. The /favicon.ico route
# prefers the override, then the default.
FAVICON_DEFAULT_PATH = os.path.join(JEN_ROOT, "static", "favicon.ico")
FAVICON_PATH = os.path.join(CONTENT_BRANDING_DIR, "favicon.ico")
# sha256 of the shipped static/favicon.ico — the app-side legacy migration
# uses it to tell "operator customized the favicon" from "still the default".
# Regenerate when static/favicon.ico changes (test_content_layout guards it).
SHIPPED_FAVICON_SHA256 = "48dd30fb607fe4e17f3c32662f2221d3d0eda1639bd09bc1d5c78524aebadb30"

# Names kept so tests that monkeypatch them by name keep working; the values
# now point into CONTENT_DIR.
ICONS_CUSTOM_DIR = CONTENT_ICONS_DIR
NAV_LOGO_PATH = os.path.join(CONTENT_BRANDING_DIR, "nav_logo")

# ── Plugin system ───────────────────────────────────────────────────────────
PLUGIN_DIR = CONTENT_PLUGIN_DIR  # registry-installed plugins (writable)
PLUGIN_DIR_BUNDLED = os.path.join(JEN_ROOT, "plugins")  # shipped, read-only
PLUGIN_REGISTRY_URL = "https://raw.githubusercontent.com/ltkojak/jen-kea/main/plugins/registry.json"
SSH_KEY_PATH = "/etc/jen/ssh/jen_rsa"
SSH_KNOWN_HOSTS = "/etc/jen/ssh/known_hosts"
