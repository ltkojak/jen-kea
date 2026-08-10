"""
jen/config.py
─────────────
Single source of truth for jen.config: loading, validation, writing,
and derivation of all runtime configuration values.

Architecture (v4.0.0)
─────────────────────
The AppConfig class owns the entire config lifecycle. The module-level
globals in jen/extensions.py remain the read surface for the rest of
the application (so call sites stay simple), but they are written
ONLY by AppConfig.apply() — no other code may assign them.

Every write method reloads from disk and re-derives all values, so
the on-disk file, the parsed ConfigParser, and the derived globals
can never diverge. This eliminates the stale-config bug class fixed
piecemeal in v3.8.1.

The config file path is read dynamically from extensions.CONFIG_FILE
on every operation (never cached) so the test suite can repoint it.

Module-level functions (load_config, init_extensions_from_config,
write_config_value, write_subnets_config, load_kea_servers,
load_subnet_map) are preserved as thin wrappers for backward
compatibility with existing callers and plugins.
"""

import configparser
import ipaddress
import logging
import os

from jen import extensions

logger = logging.getLogger(__name__)


class AppConfig:
    """Owns loading, writing, and derivation of jen.config."""

    # ── Path (dynamic — tests repoint extensions.CONFIG_FILE) ────────────

    @property
    def path(self) -> str:
        return extensions.CONFIG_FILE

    # ── Loading ──────────────────────────────────────────────────────────

    def load(self) -> configparser.ConfigParser:
        """Read and validate jen.config. Raises on missing required values."""
        # interpolation=None (v4.4.8): DB/API passwords can legitimately
        # contain a literal '%' character. With default BasicInterpolation
        # enabled, configparser treats '%' specially and raises
        # InterpolationSyntaxError reading such a value back — Jen doesn't
        # use interpolation anywhere in its own config, so there's no
        # downside to disabling it outright.
        cfg = configparser.ConfigParser(interpolation=None)
        if not os.path.exists(self.path):
            raise FileNotFoundError(
                f"Config file not found: {self.path}\n"
                f"Copy jen.config.example to {self.path} and fill in your values."
            )
        cfg.read(self.path)
        required = [
            ("kea",    "api_url"), ("kea",    "api_user"), ("kea",    "api_pass"),
            ("kea_db", "host"),    ("kea_db", "user"),    ("kea_db", "password"),
            ("jen_db", "host"),    ("jen_db", "user"),    ("jen_db", "password"),
        ]
        missing = [(s, k) for s, k in required
                   if not cfg.has_option(s, k) or not cfg.get(s, k).strip()]
        if missing:
            raise ValueError(f"Missing required config values: {missing}")
        return cfg

    # ── Derivation ───────────────────────────────────────────────────────

    def apply(self, cfg: configparser.ConfigParser) -> None:
        """
        Populate all extensions globals from a loaded ConfigParser.
        This is the ONLY place extensions config globals are assigned.
        """
        extensions.cfg = cfg

        extensions.KEA_API_URL  = cfg.get("kea", "api_url")
        extensions.KEA_API_USER = cfg.get("kea", "api_user")
        extensions.KEA_API_PASS = cfg.get("kea", "api_pass")

        extensions.KEA_DB_HOST = cfg.get("kea_db", "host")
        extensions.KEA_DB_USER = cfg.get("kea_db", "user")
        extensions.KEA_DB_PASS = cfg.get("kea_db", "password")
        extensions.KEA_DB_NAME = cfg.get("kea_db", "database", fallback="kea")
        extensions.KEA_DB_SSL_CA = cfg.get("kea_db", "ssl_ca", fallback="")

        extensions.JEN_DB_HOST = cfg.get("jen_db", "host")
        extensions.JEN_DB_USER = cfg.get("jen_db", "user")
        extensions.JEN_DB_PASS = cfg.get("jen_db", "password")
        extensions.JEN_DB_NAME = cfg.get("jen_db", "database", fallback="jen")
        extensions.JEN_DB_SSL_CA = cfg.get("jen_db", "ssl_ca", fallback="")

        extensions.HTTP_PORT  = cfg.getint("server", "http_port",  fallback=5050)
        extensions.HTTPS_PORT = cfg.getint("server", "https_port", fallback=8443)

        extensions.KEA_SSH_HOST = cfg.get("kea_ssh", "host",     fallback="")
        extensions.KEA_SSH_USER = cfg.get("kea_ssh", "user",     fallback="")
        extensions.KEA_SSH_KEY  = cfg.get("kea_ssh", "key_path", fallback="/etc/jen/ssh/jen_rsa")
        extensions.KEA_CONF     = cfg.get("kea_ssh", "kea_conf", fallback="/etc/kea/kea-dhcp4.conf")
        extensions.SSH_KEY_PATH = extensions.KEA_SSH_KEY

        extensions.DDNS_LOG = cfg.get("ddns", "log_path", fallback="/var/log/kea/kea-ddns.log")

        extensions.KEA_SERVERS = self.derive_kea_servers(cfg)
        extensions.SUBNET_MAP  = self.derive_subnet_map(cfg)

    def reload(self) -> configparser.ConfigParser:
        """Load from disk and re-derive everything. The single choke point."""
        cfg = self.load()
        self.apply(cfg)
        return cfg

    # ── Writing (every write reloads so memory always matches disk) ──────

    def _read_parser(self) -> configparser.ConfigParser:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(self.path)
        return parser

    def _write_parser(self, parser: configparser.ConfigParser) -> None:
        with open(self.path, "w") as f:
            parser.write(f)

    def write_value(self, section: str, key: str, value: str,
                    reload: bool = True) -> None:
        """Update a single value on disk, then reload."""
        parser = self._read_parser()
        if not parser.has_section(section):
            parser.add_section(section)
        parser.set(section, key, value)
        self._write_parser(parser)
        if reload:
            self.reload()

    def write_values(self, items, reload: bool = True) -> None:
        """Update multiple (section, key, value) tuples in one write+reload."""
        parser = self._read_parser()
        for section, key, value in items:
            if not parser.has_section(section):
                parser.add_section(section)
            parser.set(section, key, value)
        self._write_parser(parser)
        if reload:
            self.reload()

    def write_subnets(self, subnet_dict: dict, reload: bool = True) -> None:
        """Rewrite the [subnets] section entirely, then reload."""
        parser = self._read_parser()
        if parser.has_section("subnets"):
            parser.remove_section("subnets")
        parser.add_section("subnets")
        for sid, info in subnet_dict.items():
            parser.set("subnets", str(sid), f"{info['name']}, {info['cidr']}")
        self._write_parser(parser)
        if reload:
            self.reload()

    def mutate(self, fn, reload: bool = True) -> None:
        """
        Arbitrary structured edit: load the parser from disk, pass it to
        fn(parser) for mutation, write it back, reload. Used for edits
        that add/remove whole sections (e.g. extra Kea servers).
        """
        parser = self._read_parser()
        fn(parser)
        self._write_parser(parser)
        if reload:
            self.reload()

    # ── Derived structures ───────────────────────────────────────────────

    @staticmethod
    def derive_kea_servers(cfg: configparser.ConfigParser) -> list:
        """Return list of server dicts from config."""
        primary_user = cfg.get("kea", "api_user")
        primary_pass = cfg.get("kea", "api_pass")
        servers = [{
            "id":       1,
            "name":     cfg.get("kea", "name",     fallback="Kea Server 1"),
            "api_url":  cfg.get("kea", "api_url"),
            "api_user": primary_user,
            "api_pass": primary_pass,
            "ssh_host": cfg.get("kea_ssh", "host",     fallback=""),
            "ssh_user": cfg.get("kea_ssh", "user",     fallback=""),
            "ssh_key":  cfg.get("kea_ssh", "key_path", fallback="/etc/jen/ssh/jen_rsa"),
            "kea_conf": cfg.get("kea_ssh", "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
            "role":     cfg.get("kea", "role", fallback="primary"),
        }]
        n = 2
        while cfg.has_section(f"kea_server_{n}"):
            sec = f"kea_server_{n}"
            servers.append({
                "id":       n,
                "name":     cfg.get(sec, "name",     fallback=f"Kea Server {n}"),
                "api_url":  cfg.get(sec, "api_url",  fallback=""),
                "api_user": cfg.get(sec, "api_user", fallback=primary_user),
                "api_pass": cfg.get(sec, "api_pass", fallback=primary_pass),
                "ssh_host": cfg.get(sec, "ssh_host", fallback=""),
                "ssh_user": cfg.get(sec, "ssh_user", fallback=""),
                "ssh_key":  cfg.get(sec, "ssh_key",  fallback="/etc/jen/ssh/jen_rsa"),
                "kea_conf": cfg.get(sec, "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
                "role":     cfg.get(sec, "role",     fallback="standby"),
            })
            n += 1
        return servers

    @staticmethod
    def derive_subnet_map(cfg: configparser.ConfigParser) -> dict:
        """Parse [subnets] section into {int_id: {"name": str, "cidr": str}}."""
        subnet_map = {}
        if not cfg.has_section("subnets"):
            logger.warning("No [subnets] section found in config.")
            return subnet_map
        for key, val in cfg.items("subnets"):
            try:
                parts = [p.strip() for p in val.split(",")]
                if len(parts) != 2:
                    logger.warning(f"Skipping malformed subnet '{key}': expected 'Name, CIDR'")
                    continue
                name, cidr = parts
                ipaddress.ip_network(cidr, strict=False)
                subnet_map[int(key)] = {"name": name, "cidr": cidr}
            except ValueError as e:
                logger.warning(f"Skipping invalid subnet '{key} = {val}': {e}")
        if not subnet_map:
            logger.warning("No valid subnets found in [subnets] config section.")
        return subnet_map


# ── Singleton ─────────────────────────────────────────────────────────────────

app_config = AppConfig()


# ── Backward-compatible wrappers ─────────────────────────────────────────────
# Existing callers and plugins import these names; they delegate to app_config.

def load_config() -> configparser.ConfigParser:
    return app_config.load()


def init_extensions_from_config(cfg: configparser.ConfigParser) -> None:
    app_config.apply(cfg)


def write_config_value(section: str, key: str, value: str) -> None:
    app_config.write_value(section, key, value)


def write_subnets_config(subnet_dict: dict) -> None:
    app_config.write_subnets(subnet_dict)


def load_kea_servers(cfg: configparser.ConfigParser) -> list:
    return AppConfig.derive_kea_servers(cfg)


def load_subnet_map(cfg: configparser.ConfigParser) -> dict:
    return AppConfig.derive_subnet_map(cfg)


def ssl_configured() -> bool:
    """Return True if SSL certificate files are all present."""
    return all(os.path.exists(p) for p in [
        extensions.SSL_CERT, extensions.SSL_KEY, extensions.SSL_COMBINED
    ])
