"""
jen/config.py
─────────────
Configuration loading, writing, and subnet map parsing.
All functions read/write jen/extensions.py state so callers
don't need to manage globals directly.
"""

import configparser
import ipaddress
import logging
import os

from jen import extensions

logger = logging.getLogger(__name__)


def load_config() -> configparser.ConfigParser:
    """Load and validate jen.config. Raises on missing required values."""
    cfg = configparser.ConfigParser()
    if not os.path.exists(extensions.CONFIG_FILE):
        raise FileNotFoundError(
            f"Config file not found: {extensions.CONFIG_FILE}\n"
            f"Copy jen.config.example to {extensions.CONFIG_FILE} and fill in your values."
        )
    cfg.read(extensions.CONFIG_FILE)
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


def init_extensions_from_config(cfg: configparser.ConfigParser) -> None:
    """
    Populate all extensions globals from a loaded ConfigParser.
    Called once by the app factory and again after settings saves
    that require a reload (e.g. save_extra_servers).
    """
    extensions.cfg = cfg

    extensions.KEA_API_URL  = cfg.get("kea", "api_url")
    extensions.KEA_API_USER = cfg.get("kea", "api_user")
    extensions.KEA_API_PASS = cfg.get("kea", "api_pass")

    extensions.KEA_DB_HOST = cfg.get("kea_db", "host")
    extensions.KEA_DB_USER = cfg.get("kea_db", "user")
    extensions.KEA_DB_PASS = cfg.get("kea_db", "password")
    extensions.KEA_DB_NAME = cfg.get("kea_db", "database", fallback="kea")

    extensions.JEN_DB_HOST = cfg.get("jen_db", "host")
    extensions.JEN_DB_USER = cfg.get("jen_db", "user")
    extensions.JEN_DB_PASS = cfg.get("jen_db", "password")
    extensions.JEN_DB_NAME = cfg.get("jen_db", "database", fallback="jen")

    extensions.HTTP_PORT  = cfg.getint("server", "http_port",  fallback=5050)
    extensions.HTTPS_PORT = cfg.getint("server", "https_port", fallback=8443)

    extensions.KEA_SSH_HOST = cfg.get("kea_ssh", "host",     fallback="")
    extensions.KEA_SSH_USER = cfg.get("kea_ssh", "user",     fallback="")
    extensions.KEA_SSH_KEY  = cfg.get("kea_ssh", "key_path", fallback="/etc/jen/ssh/jen_rsa")
    extensions.KEA_CONF     = cfg.get("kea_ssh", "kea_conf", fallback="/etc/kea/kea-dhcp4.conf")
    extensions.SSH_KEY_PATH = extensions.KEA_SSH_KEY

    extensions.DDNS_LOG = cfg.get("ddns", "log_path", fallback="/var/log/kea/kea-ddns.log")

    extensions.KEA_SERVERS = load_kea_servers(cfg)
    extensions.SUBNET_MAP  = load_subnet_map(cfg)


def load_kea_servers(cfg: configparser.ConfigParser) -> list:
    """Return list of server dicts from config."""
    servers = [{
        "id":       1,
        "name":     cfg.get("kea", "name",     fallback="Kea Server 1"),
        "api_url":  cfg.get("kea", "api_url"),
        "api_user": cfg.get("kea", "api_user"),
        "api_pass": cfg.get("kea", "api_pass"),
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
            "api_user": cfg.get(sec, "api_user", fallback=extensions.KEA_API_USER),
            "api_pass": cfg.get(sec, "api_pass", fallback=extensions.KEA_API_PASS),
            "ssh_host": cfg.get(sec, "ssh_host", fallback=""),
            "ssh_user": cfg.get(sec, "ssh_user", fallback=""),
            "ssh_key":  cfg.get(sec, "ssh_key",  fallback="/etc/jen/ssh/jen_rsa"),
            "kea_conf": cfg.get(sec, "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
            "role":     cfg.get(sec, "role",     fallback="standby"),
        })
        n += 1
    return servers


def load_subnet_map(cfg: configparser.ConfigParser) -> dict:
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


def write_config_value(section: str, key: str, value: str) -> None:
    """Update a single value in jen.config on disk."""
    parser = configparser.ConfigParser()
    parser.read(extensions.CONFIG_FILE)
    if not parser.has_section(section):
        parser.add_section(section)
    parser.set(section, key, value)
    with open(extensions.CONFIG_FILE, "w") as f:
        parser.write(f)


def write_subnets_config(subnet_dict: dict) -> None:
    """Rewrite the [subnets] section entirely."""
    parser = configparser.ConfigParser()
    parser.read(extensions.CONFIG_FILE)
    if parser.has_section("subnets"):
        parser.remove_section("subnets")
    parser.add_section("subnets")
    for sid, info in subnet_dict.items():
        parser.set("subnets", str(sid), f"{info['name']}, {info['cidr']}")
    with open(extensions.CONFIG_FILE, "w") as f:
        parser.write(f)


def ssl_configured() -> bool:
    """Return True if SSL certificate files are all present."""
    return all(os.path.exists(p) for p in [
        extensions.SSL_CERT, extensions.SSL_KEY, extensions.SSL_COMBINED
    ])
