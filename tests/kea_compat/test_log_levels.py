"""
tests/kea_compat/test_log_levels.py
────────────────────────────────────
v5.68.0-beta.2 (Q135) — what a REAL kea-dhcp4 writes about one client at each log level, and what it stores in the lease row.

Explain (jen/services/dhcp_explain.py) can only decide a class test that reads option 60, 77, 61, 12 or the relay agent's
sub-options if it is told those values; Q135 takes them from what Jen already has, and Kea's own log is the one place that
could name the rest. Whether it does, and at which level, was written down as "likely only the DHCP4_QUERY_DATA packet dump
at a high debuglevel" — a guess. This module measures it: for each of seven logger settings it boots a throwaway
kea-dhcp4 (same image, same database, `tests/kea_compat/kea_config.py` with `probe=True`), sends it one relayed DISCOVER and
one REQUEST for its own MAC carrying a vendor class, a user class, a client id, a hostname and a relay-agent option, and
records which message ids named the client and whether each input appears ANYWHERE in what the daemon logged, plus what the
lease row's `client_id`, `hostname` and `user_context` hold.

It runs in its own workflow step (`-m kea_log`, after the compatibility suite, which it must not share a daemon with: it
restarts the container). Findings go to $KEA_COMPAT_LOG_OUT (JSON) and the raw logs to $KEA_COMPAT_LOG_DIR, uploaded with the
rest of the job's results. The assertions are the ones the product depends on, pinned to what ISC writes on the version under
test; the JSON is the reference for everything else.
"""

import json
import os
import re
import socket
import struct
import subprocess
import time

import pytest

pytestmark = pytest.mark.kea_log

IMAGE = os.environ.get("KEA_COMPAT_IMAGE", "")
CONF_DIR = os.environ.get("KEA_COMPAT_CONF_DIR", "")
LOG_DIR = os.environ.get("KEA_COMPAT_LOG_DIR", "")
OUT = os.environ.get("KEA_COMPAT_LOG_OUT", "")

LEVELS = [
    ("INFO", None),
    ("DEBUG", 0),
    ("DEBUG", 15),
    ("DEBUG", 30),
    ("DEBUG", 45),
    ("DEBUG", 55),
    ("DEBUG", 99),
]

VENDOR = b"jen-probe-vendor"
USER_CLASS = b"jen-user"
HOSTNAME = b"probe-host"
CIRCUIT = b"eth0/1/7"
REMOTE = bytes.fromhex("0a0b0c0d0e0f")
REQUESTED = "10.99.0.150"
RELAY = "10.99.0.1"

# what to look for in the daemon's output: the text a human would grep for, and the hex a packet dump would carry
MARKERS = {
    "vendor_class": ["jen-probe-vendor", VENDOR.hex()],
    "user_class": ["jen-user", USER_CLASS.hex()],
    "hostname": ["probe-host"],
    "circuit_id": ["eth0/1/7", CIRCUIT.hex()],
    "remote_id": ["0a:0b:0c:0d:0e:0f", "0a0b0c0d0e0f"],
    "client_id": [],  # filled per MAC
}


def _mac_for(index: int) -> str:
    return f"02:50:00:00:01:{index:02x}"


def _packet(kind: int, xid: int, mac: str, requested: str = "", server: str = "") -> bytes:
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    header = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s4s",
        1,
        1,
        6,
        1,
        xid,
        0,
        0x8000,
        bytes(4),
        bytes(4),
        bytes(4),
        socket.inet_aton(RELAY),
        mac_bytes.ljust(16, b"\0"),
        bytes(64),
        bytes(128),
        b"\x63\x82\x53\x63",
    )

    def opt(code, data):
        return bytes([code, len(data)]) + data

    options = opt(53, bytes([kind])) + opt(61, b"\x01" + mac_bytes) + opt(12, HOSTNAME) + opt(60, VENDOR)
    options += opt(77, bytes([len(USER_CLASS)]) + USER_CLASS)
    options += opt(82, opt(1, CIRCUIT) + opt(2, REMOTE))
    options += opt(55, bytes([1, 3, 6, 15, 51, 54]))
    if requested:
        options += opt(50, socket.inet_aton(requested))
    if server:
        options += opt(54, socket.inet_aton(server))
    return header + options + b"\xff"


def _local_address() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))  # no packet leaves: connect() on UDP only picks the route
        return probe.getsockname()[0]
    finally:
        probe.close()


def _sh(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=120)


def _restart(severity, debuglevel):
    from tests.kea_compat import kea_config

    conf = kea_config.build(severity=severity, debuglevel=debuglevel, probe=True)
    with open(os.path.join(CONF_DIR, "kea-dhcp4.conf"), "w") as fh:
        json.dump(conf, fh, indent=2)
    _sh("docker", "rm", "-f", "kea", check=False)
    _sh(
        "docker",
        "run",
        "-d",
        "--name",
        "kea",
        "--network",
        "host",
        "--tmpfs",
        "/var/run/kea",
        "-e",
        "MARIADB_TLS_DISABLE_PEER_VERIFICATION=1",
        "-v",
        f"{CONF_DIR}:/etc/kea:ro",
        IMAGE,
    )
    import requests

    url = os.environ["KEA_COMPAT_URL"]
    auth = (os.environ.get("KEA_COMPAT_USER", ""), os.environ.get("KEA_COMPAT_PASS", ""))
    for _ in range(40):
        try:
            if requests.post(url, json={"command": "version-get"}, auth=auth, timeout=2).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise AssertionError("the probe daemon never answered: " + _sh("docker", "logs", "kea", check=False).stdout[-2000:])


def _db():
    import pymysql

    return pymysql.connect(
        host=os.environ["KEA_COMPAT_DB_HOST"],
        port=int(os.environ.get("KEA_COMPAT_DB_PORT", "3306")),
        user=os.environ["KEA_COMPAT_DB_USER"],
        password=os.environ["KEA_COMPAT_DB_PASS"],
        database=os.environ["KEA_COMPAT_DB_NAME"],
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def _probe(index: int, severity: str, debuglevel):
    mac = _mac_for(index)
    local = _local_address()
    with _db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE hwaddr=%s", (bytes.fromhex(mac.replace(":", "")),))
    _restart(severity, debuglevel)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 0))
        sock.sendto(_packet(1, 0x10000 + index, mac), (local, 67))
        time.sleep(2)
        sock.sendto(_packet(3, 0x20000 + index, mac, requested=REQUESTED, server=local), (local, 67))
        time.sleep(3)
    finally:
        sock.close()
    log = _sh("docker", "logs", "kea", check=False)
    text = log.stdout + log.stderr
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT inet_ntoa(address) AS ip, HEX(client_id) AS client_id, hostname, user_context, state "
            "FROM lease4 WHERE hwaddr=%s",
            (bytes.fromhex(mac.replace(":", "")),),
        )
        lease = cur.fetchone()
    return mac, local, text, lease


def _ids_naming(text: str, mac: str) -> dict:
    ids: dict[str, int] = {}
    for line in text.splitlines():
        m = re.search(r"\b(DHCP4_[A-Z0-9_]+)\b", line)
        if m and mac.lower() in line.lower():
            ids[m.group(1)] = ids.get(m.group(1), 0) + 1
    return ids


def _present(text: str, needles) -> bool:
    low = text.lower()
    return any(n.lower() in low for n in needles)


@pytest.fixture(scope="module")
def findings():
    if not (IMAGE and CONF_DIR):
        pytest.skip("KEA_COMPAT_IMAGE / KEA_COMPAT_CONF_DIR not set - the log-level probe runs only in kea-compat.yml")
    data = {"image": IMAGE, "levels": {}}
    yield data
    if OUT:
        with open(OUT, "w") as fh:
            json.dump(data, fh, indent=2)


@pytest.mark.parametrize("index,level", list(enumerate(LEVELS, start=1)), ids=[f"{s}-{d}" for s, d in LEVELS])
def test_what_kea_logs_and_stores_at_this_level(findings, index, level):
    severity, debuglevel = level
    mac, local, text, lease = _probe(index, severity, debuglevel)
    name = severity if debuglevel is None else f"{severity}-{debuglevel}"
    if LOG_DIR:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, f"kea-{name}.log"), "w") as fh:
            fh.write(text)
    cid_hex = ("01" + mac.replace(":", "")).lower()
    markers = dict(MARKERS, client_id=[cid_hex, "01:" + mac])
    present = {k: _present(text, v) for k, v in markers.items()}
    naming = [line for line in text.splitlines() if mac.lower() in line.lower()]
    findings["levels"][name] = {
        "local_address": local,
        "log_lines": len(text.splitlines()),
        "ids_naming_the_mac": _ids_naming(text, mac),
        "classes_lines": [line[:300] for line in text.splitlines() if "CLASS" in line and "DHCP4_" in line][:6],
        "inputs_anywhere_in_the_log": present,
        "first_lines_naming_the_mac": [line[:300] for line in naming[:10]],
        "lease_row": {k: (str(v) if v is not None else None) for k, v in (lease or {}).items()},
    }
    # the one thing every level must show for the product to work at all: the daemon took the packets and the lease exists
    assert lease is not None and lease["ip"], f"no lease was stored at {name}; the packets did not reach the daemon"
