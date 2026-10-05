"""
tests/kea_compat/kea_config.py
───────────────────────────────
Q50 — the one Kea configuration the real-Kea compatibility job boots each
Kea version with. Pure: builds a dict, prints JSON when run as a script
(`python -m tests.kea_compat.kea_config > kea-dhcp4.conf`).

Shape: one subnet (10.99.0.0/24, id 1, reached through a relay so no
interface has to match), MySQL lease and host backends on the job's
MariaDB, the two hooks Jen's reservation/lease paths need (host_cmds,
lease_cmds), and both control sockets — unix and http — that a current
Jen deployment can be pointed at (control-sockets is a list from Kea
2.7.2 on; the singular `control-socket` it replaces is gone in 3.x).
"""

import json
import os

HOOKS_DIR = "/usr/lib/kea/hooks"
API_USER = "jen"
API_PASS = "jen_api_pw"


def build(
    db_host="127.0.0.1",
    db_name="kea",
    db_user="kea",
    db_pass="kea_pw",
    http_port=8004,
    severity="INFO",
    debuglevel=None,
    probe=False,
    ddns=False,
) -> dict:
    """`severity`/`debuglevel` set the kea-dhcp4 logger (the log-level probe, Q135, boots one daemon per level);
    `probe=True` adds what that probe needs on top of the compat config: two client classes whose tests read the
    vendor and user class options, and `store-extended-info` so the relay-agent options reach the lease row.
    `ddns=True` (v5.68.0-beta.9, Q144) turns DNS updates on towards a kea-dhcp-ddns that is NOT running, so the daemon logs its own
    DHCP4_DDNS_REQUEST_SEND_FAILED line - the probe records what that line carries."""
    backend = {"type": "mysql", "host": db_host, "name": db_name, "user": db_user, "password": db_pass}
    cfg = {
        "Dhcp4": {
            # udp sockets + no hard failure when an interface can't be
            # opened: a CI runner's NICs are none of this job's business.
            "interfaces-config": {
                "interfaces": ["*"],
                "dhcp-socket-type": "udp",
                "service-sockets-require-all": False,
                "service-sockets-max-retries": 0,
            },
            "control-sockets": [
                {"socket-type": "unix", "socket-name": "/var/run/kea/kea4-ctrl.sock"},
                {
                    "socket-type": "http",
                    "socket-address": "127.0.0.1",
                    "socket-port": http_port,
                    # Kea 3.2+ refuses an http control socket with neither
                    # TLS nor authentication ("Unsecured HTTP control channel"); clear-text
                    # user/password are refused too, hence the two files
                    # (3.0 resolves them against `directory`, default /).
                    "authentication": {
                        "type": "basic",
                        "realm": "kea-compat",
                        "directory": "/etc/kea",
                        "clients": [{"user-file": "jen-api.user", "password-file": "jen-api.pw"}],
                    },
                },
            ],
            "lease-database": dict(backend),
            "hosts-database": dict(backend),
            "hooks-libraries": [
                # Kea 3.0+ ships its database backends as hooks: without
                # libdhcp_mysql the daemon has no "mysql" lease/host type.
                {"library": f"{HOOKS_DIR}/libdhcp_mysql.so"},
                {"library": f"{HOOKS_DIR}/libdhcp_lease_cmds.so"},
                {"library": f"{HOOKS_DIR}/libdhcp_host_cmds.so"},
            ],
            "valid-lifetime": 3600,
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.99.0.0/24",
                    "pools": [{"pool": "10.99.0.100 - 10.99.0.200"}],
                    "relay": {"ip-addresses": ["10.99.0.1"]},
                    "option-data": [{"name": "routers", "data": "10.99.0.1"}],
                }
            ],
            "loggers": [
                {
                    "name": "kea-dhcp4",
                    "output-options": [{"output": "stdout"}],
                    "severity": severity,
                    **({"debuglevel": debuglevel} if debuglevel is not None else {}),
                }
            ],
        }
    }
    if probe:
        dhcp4 = cfg["Dhcp4"]
        dhcp4["store-extended-info"] = True
        dhcp4["client-classes"] = [
            {"name": "jen-probe-vendor", "test": "substring(option[60].hex,0,9) == 'jen-probe'"},
            {"name": "jen-probe-user", "test": "option[77].hex == 0x086a656e2d75736572"},
        ]
    if ddns:
        dhcp4 = cfg["Dhcp4"]
        dhcp4["dhcp-ddns"] = {
            "enable-updates": True,
            "server-ip": "127.0.0.1",
            "server-port": 53001,
            "sender-ip": "127.0.0.1",
            "sender-port": 0,
            "max-queue-size": 1024,
            "ncr-protocol": "UDP",
            "ncr-format": "JSON",
        }
        dhcp4["ddns-send-updates"] = True
        dhcp4["ddns-override-client-update"] = True
        dhcp4["ddns-qualifying-suffix"] = "probe.example.org"
    return cfg


if __name__ == "__main__":
    print(
        json.dumps(
            build(
                db_host=os.environ.get("KEA_DB_HOST", "127.0.0.1"),
                db_pass=os.environ.get("KEA_DB_PASS", "kea_pw"),
            ),
            indent=2,
        )
    )
