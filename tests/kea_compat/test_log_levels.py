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
RUN_DIR = os.environ.get(
    "KEA_COMPAT_RUN_DIR", ""
)  # v5.68.0-beta.31 (Q168): the daemon's /var/run/kea, bind-mounted so the runner can reach its unix control socket
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
REQUESTED_BASE = 150  # one address per level (10.99.0.15N): a lease the previous level made would NAK this one
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


def _packet(
    kind: int,
    xid: int,
    mac: str,
    requested: str = "",
    server: str = "",
    user_class: str = "lp",
    circuit: bytes = CIRCUIT,
) -> bytes:
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
    if user_class == "lp":  # RFC 3004: each user class is length-prefixed (what Windows sends)
        options += opt(77, bytes([len(USER_CLASS)]) + USER_CLASS)
    elif user_class == "raw":  # the bare string (what dhclient's `send user-class` sends)
        options += opt(77, USER_CLASS)
    options += opt(82, opt(1, circuit) + opt(2, REMOTE))
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


def _restart(severity, debuglevel, ddns=False, forms=False):
    from tests.kea_compat import kea_config

    conf = kea_config.build(severity=severity, debuglevel=debuglevel, probe=True, ddns=ddns, forms=forms)
    with open(os.path.join(CONF_DIR, "kea-dhcp4.conf"), "w") as fh:
        json.dump(conf, fh, indent=2)
    _sh("docker", "rm", "-f", "kea", check=False)
    if RUN_DIR:  # a bind mount outlives the container (a tmpfs did not): the dead daemon's pid file would read as "already running" and its socket as a live one
        for name in os.listdir(RUN_DIR):
            os.unlink(os.path.join(RUN_DIR, name))
    _sh(
        "docker",
        "run",
        "-d",
        "--name",
        "kea",
        "--network",
        "host",
        *(("-v", f"{RUN_DIR}:/var/run/kea") if RUN_DIR else ("--tmpfs", "/var/run/kea")),
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
                if RUN_DIR:  # test-only: the runner connects as itself, the helper on a real host connects as root
                    _sh(
                        "docker",
                        "exec",
                        "-u",
                        "root",
                        "kea",
                        "chmod",
                        "666",
                        "/var/run/kea/kea4-ctrl.sock",
                        check=False,
                    )
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
        sock.sendto(
            _packet(3, 0x20000 + index, mac, requested=f"10.99.0.{REQUESTED_BASE + index}", server=local), (local, 67)
        )
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

    # ── what Jen's parsers (jen/services/kea_log_inputs.py) read from the REAL output, pinned per level ──────────────────
    from jen.services import kea_log_inputs as li

    lines = text.splitlines()
    cid = li.client_id_from_log(lines, mac)
    assert cid and cid["client_id"] == cid_hex_colon(mac), f"the client id is on every label, at {name} too: {cid}"

    classes = li.latest_classes(lines, mac)
    query = li.latest_query_data(lines, mac)
    level = -1 if debuglevel is None else debuglevel  # INFO and DEBUG 0 are below every threshold
    if level >= li.LEVEL_FOR_CLASSES:
        assert classes and li.vendor_class_from(classes["classes"]) == "jen-probe-vendor", (name, classes)
        assert "jen-probe-user" in classes["classes"], classes
    else:
        assert classes is None, f"a class list at {name}: {classes}"
    if level >= li.LEVEL_FOR_PACKET:
        assert query == {
            **query,
            "hostname": "probe-host",
            "vendor_class": "jen-probe-vendor",
            "user_class": "jen-user",
            "circuit_id": "eth0/1/7",
            "remote_id": "0a0b0c0d0e0f",
            "client_id": cid_hex_colon(mac),
        }, query
    else:
        assert query is None, f"a packet dump at {name}: {query}"

    # the lease row, at every level: client id, hostname, and the relay agent's options (store-extended-info)
    assert lease["client_id"].lower() == cid_hex, lease
    assert lease["hostname"] == "probe-host", lease
    assert li.relay_info_from_user_context(lease["user_context"]) == {
        "circuit_id": "eth0/1/7",
        "circuit_id_hex": "657468302f312f37",
        "remote_id": "0a0b0c0d0e0f",
    }, lease
    findings["levels"][name]["parsed"] = {"client_id": cid, "classes": classes, "query": query}


def cid_hex_colon(mac: str) -> str:
    return "01:" + mac


# ── Q138: does `config-reload` apply a new log level without a restart? ───────────────────────────────────────────


def _exchange(mac: str, requested: str, local: str, xid: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 0))
        sock.sendto(_packet(1, xid, mac), (local, 67))
        time.sleep(2)
        sock.sendto(_packet(3, xid + 1, mac, requested=requested, server=local), (local, 67))
        time.sleep(3)
    finally:
        sock.close()


def _daemon_log() -> list[str]:
    log = _sh("docker", "logs", "kea", check=False)
    return (log.stdout + log.stderr).splitlines()


def _status() -> dict:
    from jen.services import kea

    reply = kea.kea_command("status-get")
    args = reply.get("arguments") or {}
    return {
        "result": reply.get("result"),
        "pid": args.get("pid"),
        "uptime": args.get("uptime"),
        "reload": args.get("reload"),
    }


def _started_at() -> str:
    return _sh("docker", "inspect", "-f", "{{.State.StartedAt}}", "kea").stdout.strip()


def test_config_reload_applies_the_investigation_log_level_without_a_restart(findings):
    """v5.68.0-beta.3 (Q138, verify first) - Jen turns investigation logging on by writing the mutated config and asking the
    daemon to `config-reload` instead of restarting it. This records, per Kea version, what that really does: the reply, whether the
    process and the container survived, whether the new level takes effect and the lease survives, what `config-get` shows of the
    logger's user-context, what happens when the file is broken, and that putting the level back works the same way."""
    from jen.services import kea
    from jen.services import kea_config_edit as ed

    index = 30
    mac, local = _mac_for(index), _local_address()
    requested = f"10.99.0.{REQUESTED_BASE + index}"
    with _db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE hwaddr=%s", (bytes.fromhex(mac.replace(":", "")),))
    _restart("INFO", None)
    record = {}
    findings["config_reload"] = record
    conf_path = os.path.join(CONF_DIR, "kea-dhcp4.conf")

    listed = kea.kea_command("list-commands")
    record["lists_config_reload"] = "config-reload" in (listed.get("arguments") or [])
    before = {"status": _status(), "started_at": _started_at()}
    _exchange(mac, requested, local, 0x30000)
    first = _daemon_log()
    assert li_has(first, mac, "DHCP4_LEASE_ALLOC"), "the baseline exchange at INFO allocated a lease"
    assert not li_has(first, mac, "DHCP4_QUERY_DATA"), "INFO carries no packet dump"

    with open(conf_path) as fh:
        conf = json.load(fh)
    until = "2099-01-01T00:00:00+00:00"
    mutated, code = ed.set_investigation_logging(conf, until)
    assert code == "ok"
    with open(conf_path, "w") as fh:
        json.dump(mutated, fh, indent=2)
    reply = kea.kea_command("config-reload")
    record["reload_reply"] = {"result": reply.get("result"), "text": (reply.get("text") or "")[:200]}
    time.sleep(1)
    after = {"status": _status(), "started_at": _started_at()}
    record["process_survived"] = (
        before["status"]["pid"] is not None and before["status"]["pid"] == after["status"]["pid"]
    )
    record["container_survived"] = before["started_at"] == after["started_at"]
    record["status_before"], record["status_after"] = before["status"], after["status"]

    seen_before = len(_daemon_log())
    _exchange(mac, requested, local, 0x30010)
    second = _daemon_log()[seen_before:]
    record["packet_dump_after_reload"] = li_has(second, mac, "DHCP4_QUERY_DATA")
    record["classes_after_reload"] = li_has(second, mac, "DHCP4_CLASSES_ASSIGNED")
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT inet_ntoa(address) AS ip FROM lease4 WHERE hwaddr=%s AND state=0",
            (bytes.fromhex(mac.replace(":", "")),),
        )
        record["lease_survived"] = (cur.fetchone() or {}).get("ip") == requested
    shown = kea.kea_command("config-get").get("arguments", {}).get("Dhcp4", {}).get("loggers", [])
    entry = next((x for x in shown if x.get("name") == "kea-dhcp4"), {})
    record["config_get_logger"] = {k: entry.get(k) for k in ("severity", "debuglevel", "user-context")}
    # v5.68.0-beta.23 (Q158): Jen no longer believes the reload's reply - it READS the running logger. What Kea shows after the reload is what
    # `observe` must call "debug": DEBUG, debuglevel 55, and the jen-investigation marker in the logger's user-context.
    from jen.services import investigation_logging as inv

    restore_object = (ed.investigation_marker(mutated) or {}).get("restore")
    observed = {"restore": restore_object}
    record["observed_after_reload"] = {"state": inv.observe(None, observed), "seen": observed.get("seen")}

    # a broken file: the reload must be refused and the daemon must keep running on what it had
    with open(conf_path, "w") as fh:
        fh.write('{ "Dhcp4": { "this is": not json')
    broken = kea.kea_command("config-reload")
    record["broken_file_reply"] = {"result": broken.get("result"), "text": (broken.get("text") or "")[:200]}
    record["answers_after_broken_reload"] = kea.kea_command("version-get").get("result") == 0

    # putting it back is the same two steps
    restored, code = ed.clear_investigation_logging(mutated)
    assert code == "ok"
    with open(conf_path, "w") as fh:
        json.dump(restored, fh, indent=2)
    back = kea.kea_command("config-reload")
    record["restore_reply"] = {"result": back.get("result"), "text": (back.get("text") or "")[:200]}
    time.sleep(1)
    seen_before = len(_daemon_log())
    _exchange(mac, requested, local, 0x30020)
    record["packet_dump_after_restore"] = li_has(_daemon_log()[seen_before:], mac, "DHCP4_QUERY_DATA")
    record["process_survived_restore"] = _status()["pid"] == before["status"]["pid"]
    shown_after = kea.kea_command("config-get").get("arguments", {}).get("Dhcp4", {}).get("loggers", [])
    entry_after = next((x for x in shown_after if x.get("name") == "kea-dhcp4"), {})
    record["config_get_logger_after_restore"] = {
        k: entry_after.get(k) for k in ("severity", "debuglevel", "user-context")
    }
    restored_probe = {"restore": restore_object}
    record["observed_after_restore"] = {"state": inv.observe(None, restored_probe), "seen": restored_probe.get("seen")}

    assert reply.get("result") == 0, record
    assert record["process_survived"] and record["container_survived"], record
    assert record["packet_dump_after_reload"] and record["classes_after_reload"], record
    assert record["lease_survived"], record
    assert record["broken_file_reply"]["result"] != 0 and record["answers_after_broken_reload"], record
    assert back.get("result") == 0 and not record["packet_dump_after_restore"], record
    # the running daemon, read back (Q158): DEBUG 55 with the marker after the reload; no marker, not at DEBUG 55, and "restored" after the restore
    shown_logger = record["config_get_logger"]
    assert str(shown_logger["severity"]).upper() == "DEBUG" and shown_logger["debuglevel"] == 55, record
    assert "jen-investigation" in (shown_logger["user-context"] or {}), record
    assert record["observed_after_reload"]["state"] == "debug", record
    back_logger = record["config_get_logger_after_restore"]
    assert "jen-investigation" not in (back_logger["user-context"] or {}), record
    assert not (str(back_logger["severity"]).upper() == "DEBUG" and back_logger["debuglevel"] == 55), record
    assert record["observed_after_restore"]["state"] == "restored", record


# ── Q165: does SIGHUP re-read the config file (the self-restore's reload)? ──────────────────────────────────────────


def _hup(pid):
    return _sh("docker", "exec", "-u", "root", "kea", "kill", "-HUP", str(pid), check=False)


def _wait_for(predicate, seconds=8.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.5)
    return predicate()


def _logger_now() -> dict:
    from jen.services import kea

    shown = kea.kea_command("config-get").get("arguments", {}).get("Dhcp4", {}).get("loggers", [])
    entry = next((x for x in shown if x.get("name") == "kea-dhcp4"), {})
    return {k: entry.get(k) for k in ("severity", "debuglevel", "user-context")}


def test_sighup_reloads_the_logger(findings):
    """v5.68.0-beta.29 (Q165, verify first) - the Kea HOST puts the logger back by itself (jen-kea-helper `--self-restore`): it rewrites the config file and sends the
    unit's main process SIGHUP, with a restart only as the fallback. This records, per Kea version, whether SIGHUP re-reads the file - the new level shows in `config-get` with
    the process (pid) unchanged - and that putting the level back works the same way. A version that does NOT reload on SIGHUP is not a failure of the product: the helper restarts the unit when it is not active afterwards, and a version recorded here as not reloading would be named in the helper so it restarts at once - the record says which."""
    from jen.services import kea
    from jen.services import kea_config_edit as ed

    _restart("INFO", None)
    record = {}
    findings["sighup"] = record
    conf_path = os.path.join(CONF_DIR, "kea-dhcp4.conf")
    before = _status()
    record["pid_before"] = before["pid"]
    assert before["pid"], "status-get reports the daemon's pid"
    with open(conf_path) as fh:
        conf = json.load(fh)
    mutated, code = ed.set_investigation_logging(conf, "2099-01-01T00:00:00+00:00")
    assert code == "ok"
    with open(conf_path, "w") as fh:
        json.dump(mutated, fh, indent=2)
    sent = _hup(before["pid"])
    record["kill_returncode"] = sent.returncode
    reloaded = _wait_for(
        lambda: (
            "jen-investigation" in (_logger_now().get("user-context") or {}) and _logger_now().get("debuglevel") == 55
        )
    )
    after = _status()
    record["process_survived"] = after["pid"] == before["pid"]
    record["answers_after_hup"] = kea.kea_command("version-get").get("result") == 0
    record["reloads_on_hup"] = bool(reloaded)
    record["logger_after_hup"] = _logger_now()

    # putting it back the same way
    restored, code = ed.clear_investigation_logging(mutated)
    assert code == "ok"
    with open(conf_path, "w") as fh:
        json.dump(restored, fh, indent=2)
    _hup(after["pid"])
    back = _wait_for(lambda: "jen-investigation" not in (_logger_now().get("user-context") or {}))
    record["restore_reloads_on_hup"] = bool(back)
    record["logger_after_restore"] = _logger_now()
    record["process_survived_restore"] = _status()["pid"] == before["pid"]

    # what is asserted is what the product depends on: a HUP never kills the daemon, and when it does reload, the restore is exactly the inverse
    assert record["kill_returncode"] == 0, record
    assert record["process_survived"] and record["answers_after_hup"] and record["process_survived_restore"], record
    assert isinstance(record["reloads_on_hup"], bool)
    assert record["restore_reloads_on_hup"] == record["reloads_on_hup"], record
    if record["reloads_on_hup"]:
        shown = record["logger_after_hup"]
        assert str(shown["severity"]).upper() == "DEBUG" and shown["debuglevel"] == 55, record
        back_logger = record["logger_after_restore"]
        assert "jen-investigation" not in (back_logger["user-context"] or {}), record
        assert not (str(back_logger["severity"]).upper() == "DEBUG" and back_logger["debuglevel"] == 55), record
    print(
        f"SIGHUP RECORD {IMAGE}: reloads_on_hup={record['reloads_on_hup']} restore_reloads={record['restore_reloads_on_hup']} pid_kept={record['process_survived']}"
    )


def test_what_a_ddns_failure_line_carries(findings):
    """v5.68.0-beta.9 (Q144, verify first) - the Problems sweep attributes a DHCP4_DDNS_REQUEST_SEND_FAILED line to the client the
    log showed getting the address it names, preferring the same transaction. Whether that line carries a transaction id (or a client
    label) at INFO on 3.0 / 3.2 / 3.3 was not known: this turns DNS updates on towards a kea-dhcp-ddns that is not running, sends one
    exchange, and RECORDS what the failure line looks like and whether its allocation line has a tid. It asserts only that a lease was
    stored: the facts are the reference, and Jen's parser takes a tid when there is one and the nearest preceding allocation when not."""
    index = 40
    mac, local = _mac_for(index), _local_address()
    requested = f"10.99.0.{REQUESTED_BASE + index}"
    with _db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE hwaddr=%s", (bytes.fromhex(mac.replace(":", "")),))
    _restart("INFO", None, ddns=True)
    _exchange(mac, requested, local, 0x40000)
    lines = _daemon_log()
    ddns = [line for line in lines if "DDNS" in line]
    failed = [line for line in ddns if "DHCP4_DDNS_REQUEST_SEND_FAILED" in line]
    alloc = [line for line in lines if "DHCP4_LEASE_ALLOC" in line and mac.lower() in line.lower()]
    from jen.services import kea_log_trace as klt

    events = klt.problem_events(lines)
    findings["ddns_failed_line"] = {
        "reproduced": bool(failed),
        "ddns_lines": [line[:400] for line in ddns[:8]],
        "failed_lines": [line[:400] for line in failed[:3]],
        "failed_line_has_tid": any("tid=" in line for line in failed),
        "failed_line_has_client_label": any("hwtype=" in line for line in failed),
        "alloc_lines": [line[:300] for line in alloc[:2]],
        "alloc_line_has_tid": any("tid=" in line for line in alloc),
        "attributed_to_the_probe_client": [e["mac"] for e in events if e["kind"] == "ddns-failed"],
    }
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT inet_ntoa(address) AS ip FROM lease4 WHERE hwaddr=%s", (bytes.fromhex(mac.replace(":", "")),)
        )
        assert cur.fetchone(), "the probe's exchange stored a lease"
    if failed:
        assert [e["mac"] for e in events if e["kind"] == "ddns-failed"] == [mac], findings["ddns_failed_line"]


def _dump_rows(lines: list[str], mac: str) -> list[str]:
    """The rows of the DHCP4_QUERY_DATA dump for `mac` that matter here: option 77 and the relay agent's circuit id, as Kea printed them."""
    out, inside = [], False
    for line in lines:
        if "DHCP4_QUERY_DATA" in line and mac.lower() in line.lower():
            inside = True
            continue
        if inside and re.match(r"^\d{4}-\d{2}-\d{2} ", line):
            inside = False
        if inside and ("type=077" in line or re.match(r"^\s+type=001, ", line)):
            out.append(line.strip())
    return out


FORM_CASES = [
    # name, user class form on the wire, circuit id bytes
    ("lp-text-circuit", "lp", CIRCUIT),
    ("raw-text-circuit", "raw", CIRCUIT),
    ("lp-binary-circuit", "lp", bytes.fromhex("deadbeef")),
]


def test_which_option_77_and_circuit_id_forms_kea_matches(findings):
    """v5.68.0-beta.10 (Q145, verify first). Explain evaluated `option[77].hex == '<text>'` against the typed TEXT, and a binary circuit id
    as the ASCII of its hex, while real Kea compares BYTES: a length-prefixed client (Windows, RFC 3004) sends 08 'jen-user', a raw one
    sends 'jen-user', and a class test written for one does not match the other. This boots ONE daemon with a class per spelling
    (`forms=True`), sends a DISCOVER per case, and RECORDS which classes Kea assigned and what its packet dump printed for option 77 and
    the circuit id - on 3.0.3, 3.2.0 and 3.3.1. Record-only: what Jen pins is decided from these findings."""
    _restart("DEBUG", 55, forms=True)
    local = _local_address()
    from jen.services import kea_log_inputs as li

    record = {}
    findings["forms"] = record
    for offset, (name, form, circuit) in enumerate(FORM_CASES):
        mac = _mac_for(50 + offset)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", 0))
            sock.sendto(_packet(1, 0x50000 + offset, mac, user_class=form, circuit=circuit), (local, 67))
            time.sleep(2)
        finally:
            sock.close()
        lines = _daemon_log()
        tx = li.latest_transaction(lines, mac)
        assigned = [c for c in ((tx or {}).get("classes") or {}).get("classes", []) if c.startswith("q145-")]
        record[name] = {
            "wire_user_class": form,
            "wire_circuit_hex": circuit.hex(),
            "assigned_q145_classes": sorted(assigned),
            "dump_rows": _dump_rows(lines, mac),
            "parsed_query": (tx or {}).get("query"),
        }
        assert tx is not None, f"the daemon never logged an exchange for {name}"

    # ── builder, real Kea and Explain must agree about every class, for every client form ─────────────────────────────────────
    from jen.services import dhcp_explain as de
    from jen.services import explain_inputs as ei
    from tests.kea_compat import kea_config

    classes = {
        c["name"]: c["test"]
        for c in kea_config.build(probe=True, forms=True)["Dhcp4"]["client-classes"]
        if c["name"].startswith("q145-")
    }
    disagreements = []
    for offset, (name, _form, _circuit) in enumerate(FORM_CASES):
        mac = _mac_for(50 + offset)
        tx = li.latest_transaction(_daemon_log(), mac)
        client = ei.build(mac, log={"classes": tx["classes"], "query": tx["query"], "cid": tx["cid"]})["client"]
        kea_said = set(record[name]["assigned_q145_classes"])
        for cls, test in sorted(classes.items()):
            explained = de.evaluate(de.parse_expression(test), client, {}, set())
            if explained is not (cls in kea_said):
                disagreements.append(
                    {"case": name, "class": cls, "test": test, "kea": cls in kea_said, "explain": explained}
                )
    record["disagreements"] = disagreements

    # ── what real Kea matched, pinned (3.0.3, 3.2.0 and 3.3.1 gave identical answers when this was measured, Q145) ────────────────
    def assigned(case):
        return set(record[case]["assigned_q145_classes"])

    lp, raw, binary = assigned("lp-text-circuit"), assigned("raw-text-circuit"), assigned("lp-binary-circuit")
    # a LENGTH-PREFIXED client (08 'jen-user'): only the length-byte literal and the substring that skips the length byte match
    assert {"q145-u77-lp", "q145-u77-sub1", "q145-b-lp-eq", "q145-b-lp-sw"} <= lp
    assert not ({"q145-u77-text", "q145-u77-raw-hex", "q145-u77-sub0", "q145-b-plain-eq", "q145-b-plain-sw"} & lp)
    # a RAW client ('jen-user'): the string, its bare hex and the substring from 0 match - and nothing written for the length-prefixed form
    assert {"q145-u77-text", "q145-u77-raw-hex", "q145-u77-sub0", "q145-b-plain-eq", "q145-b-plain-sw"} <= raw
    assert not ({"q145-u77-lp", "q145-u77-sub1", "q145-b-lp-eq", "q145-b-lp-sw"} & raw)
    # a circuit id is compared as BYTES: eth0/1/7 matches its text and its hex, DE AD BE EF matches 0xdeadbeef and NOT any text
    assert {"q145-circuit-text", "q145-circuit-hex"} <= lp and "q145-circuit-bin" not in lp
    assert "q145-circuit-bin" in binary and not ({"q145-circuit-text", "q145-circuit-hex"} & binary)
    # what the dump prints for option 77: hex only when length-prefixed; hex then the quoted text when raw
    assert record["lp-text-circuit"]["dump_rows"][0].startswith("type=077, len=009: 08:6a:65:6e:2d:75:73:65:72")
    assert not record["lp-text-circuit"]["dump_rows"][0].rstrip().endswith("'")
    assert record["raw-text-circuit"]["dump_rows"][0].endswith("'jen-user'")
    assert not disagreements, f"Explain and real Kea disagree about: {disagreements}"


def li_has(lines, mac: str, message_id: str) -> bool:
    return any(message_id in line and mac.lower() in line.lower() for line in lines)


# ── Q167: what does Kea itself write when a SIGHUP reload starts, completes or fails? ─────────────────────────────────────────────────────────────────


def _dhcp4_ids(lines):
    """The DHCP4_* / DCTL_* message ids of `lines`, in order, each once."""
    seen = []
    for line in lines:
        for found in re.findall(r"\b((?:DHCP4|DCTL|CTRL_AGENT|COMMAND)_[A-Z0-9_]+)\b", line):
            if found not in seen:
                seen.append(found)
    return seen


def _hup_and_read(pid: int, text: str, seconds: float = 5.0):
    """Write `text` as the daemon's config file, send it SIGHUP and return the daemon's own log lines written meanwhile (what `docker logs` gained)."""
    conf_path = os.path.join(CONF_DIR, "kea-dhcp4.conf")
    before = len(_daemon_log())
    with open(conf_path, "w") as fh:
        fh.write(text)
    sent = _hup(pid)
    assert sent.returncode == 0, sent.stderr
    time.sleep(seconds)
    return _daemon_log()[before:]


def test_sighup_reload_log_lines(findings):
    """v5.68.0-beta.30 (Q167, verify first) - the Kea host puts the logger back and sends the daemon SIGHUP; "the unit is active" says nothing about whether Kea re-read the file, so
    the helper will look for Kea's OWN log lines past the offset it noted before the signal. Which ids does each supported Kea write when the reload (a) starts and applies at a
    DEBUG-55 logger, (b) is restored to INFO, (c) is restored to WARN (the original level decides whether the daemon's log shows the completion at all) and (d) is refused because
    the file is broken? This records them per image; the helper's constants and the assertions below are what it recorded."""
    from jen.services import kea_config_edit as ed

    _restart("INFO", None)
    record = findings.setdefault("sighup_log", {})
    conf_path = os.path.join(CONF_DIR, "kea-dhcp4.conf")
    with open(conf_path) as fh:
        base = json.load(fh)
    pid = _status()["pid"]
    assert pid, "status-get reports the daemon's pid"
    until = "2099-01-01T00:00:00+00:00"

    def dump(conf):
        return json.dumps(conf, indent=2)

    def logger_entry(conf):
        return next(x for x in conf["Dhcp4"]["loggers"] if x["name"] == "kea-dhcp4")

    scenarios = {}
    on, code = ed.set_investigation_logging(base, until)
    assert code == "ok"
    scenarios["debug_55_applied"] = _hup_and_read(pid, dump(on))
    scenarios["restored_to_info"] = _hup_and_read(pid, dump(base))

    warn_base = json.loads(dump(base))
    logger_entry(warn_base)["severity"] = "WARN"
    warn_on, code = ed.set_investigation_logging(warn_base, until)
    assert code == "ok"
    _hup_and_read(pid, dump(warn_on))
    scenarios["restored_to_warn"] = _hup_and_read(pid, dump(warn_base))

    broken = json.loads(dump(base))
    broken["Dhcp4"]["jen-no-such-parameter"] = 1
    scenarios["refused_broken_file"] = _hup_and_read(pid, dump(broken))
    record["process_survived"] = _status()["pid"] == pid
    _hup_and_read(pid, dump(base))  # leave a sane file and a sane daemon behind

    # a RESTART onto a broken file: the ids the daemon writes as it refuses to start (the helper's `_START_FAIL_IDS` must contain one)
    with open(conf_path, "w") as fh:
        fh.write(dump(broken))
    before = len(_daemon_log())
    _sh("docker", "restart", "kea", check=False)
    time.sleep(6)
    scenarios["restart_refused_broken_file"] = _daemon_log()[before:]

    for name, lines in scenarios.items():
        record[name] = {
            "ids": _dhcp4_ids(lines),
            "lines": [ln[-220:] for ln in lines if re.search(r"DHCP4_|DCTL_|COMMAND_", ln)][:10],
        }
    _restart(
        "INFO", None
    )  # leave a sane daemon behind (the process id changed: the survival check below was taken before the restart)
    print(
        f"RELOAD IDS {IMAGE}: "
        + json.dumps({k: v["ids"] for k, v in record.items() if isinstance(v, dict) and "ids" in v}, sort_keys=True)
    )
    assert record["process_survived"], f"a SIGHUP reload, even of a broken file, never kills the daemon: {record}"

    # what the helper looks for (jen-kea-helper build 16) is what Kea wrote, on every supported image
    import importlib.util
    import pathlib
    from importlib.machinery import SourceFileLoader

    loader = SourceFileLoader(
        "jen_kea_helper_probe", str(pathlib.Path(__file__).resolve().parents[2] / "jen-kea-helper")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    helper = importlib.util.module_from_spec(spec)
    loader.exec_module(helper)
    ids = {name: set(record[name]["ids"]) for name in scenarios}
    for name in ("debug_55_applied", "restored_to_info"):
        assert set(helper._RELOAD_OK_IDS) <= ids[name], (
            f"{name}: the completion id the helper waits for is missing: {record[name]}"
        )
    for name in ("debug_55_applied", "restored_to_info", "restored_to_warn"):
        assert set(helper._RELOAD_STARTED_IDS) <= ids[name], (
            f"{name}: the started id is always visible (the OLD logger writes it): {record[name]}"
        )
        assert not (set(helper._RELOAD_FAIL_IDS) & ids[name]), (
            f"{name}: a successful reload writes no failure id: {record[name]}"
        )
    assert set(helper._RELOAD_FAIL_IDS) & ids["refused_broken_file"], (
        f"a refused reload writes a failure id: {record['refused_broken_file']}"
    )
    assert set(helper._START_FAIL_IDS) & ids["restart_refused_broken_file"], (
        f"a start onto a broken file writes a start-failure id: {record['restart_refused_broken_file']}"
    )


# ── Q168: does the daemon's OWN control socket answer the question "what logger are you running"? ────────────────────────────────────────────────────


def _logger_from(reply):
    """{"present", "severity", "debuglevel", "marker"} of the kea-dhcp4 logger a `config-get` reply shows, or None when the reply is not a usable config-get."""
    if not isinstance(reply, dict) or reply.get("result") != 0:
        return None
    section = (reply.get("arguments") or {}).get("Dhcp4")
    if not isinstance(section, dict):
        return None
    loggers = section.get("loggers") or []
    entry = next((x for x in loggers if isinstance(x, dict) and x.get("name") == "kea-dhcp4"), None)
    if entry is None:
        return {
            "present": False,
            "severity": None,
            "debuglevel": None,
            "marker": None,
            "loggers": [x.get("name") for x in loggers if isinstance(x, dict)],
        }
    context = entry.get("user-context")
    marker = context.get("jen-investigation") if isinstance(context, dict) else None
    return {
        "present": True,
        "severity": entry.get("severity"),
        "debuglevel": entry.get("debuglevel"),
        "marker": marker if isinstance(marker, dict) else None,
    }


def _ask_raw_unix(path, command="config-get", wait=6.0):
    """(reply | None, seconds to answer, closed_by_the_daemon_after_the_reply). One command to the unix control socket, read until it parses."""
    started = time.monotonic()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(wait)
    try:
        s.connect(path)
        s.sendall(json.dumps({"command": command}).encode())
        buf = b""
        reply = None
        while time.monotonic() - started < wait:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            try:
                reply = json.loads(buf.decode())
                break
            except ValueError:
                continue
        took = time.monotonic() - started
        closed = None
        if reply is not None:
            s.settimeout(1.5)
            try:
                closed = s.recv(1) == b""
            except TimeoutError:
                closed = False
        return reply, took, closed
    except OSError:
        return None, time.monotonic() - started, None
    finally:
        s.close()


def _ask_raw_http(address, port, user, password, command="config-get", wait=6.0):
    import base64

    started = time.monotonic()
    try:
        s = socket.create_connection((address, port), timeout=wait)
    except OSError:
        return None, 0.0
    try:
        body = json.dumps({"command": command}).encode()
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        head = f"POST / HTTP/1.0\r\nHost: {address}\r\nContent-Type: application/json\r\nAuthorization: Basic {token}\r\nContent-Length: {len(body)}\r\n\r\n"
        s.sendall(head.encode() + body)
        buf = b""
        while time.monotonic() - started < wait:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        text = buf.partition(b"\r\n\r\n")[2]
        reply = json.loads(text.decode())
        return (reply[0] if isinstance(reply, list) and reply else reply), time.monotonic() - started
    except (OSError, ValueError):
        return None, time.monotonic() - started
    finally:
        s.close()


def _wait_logger(sock_path, predicate, seconds=8.0):
    deadline = time.monotonic() + seconds
    seen = None
    while time.monotonic() < deadline:
        reply, _took, _closed = _ask_raw_unix(sock_path)
        seen = _logger_from(reply)
        if seen is not None and predicate(seen):
            return seen
        time.sleep(0.4)
    return seen


def _load_helper():
    import importlib.util
    import pathlib
    from importlib.machinery import SourceFileLoader

    loader = SourceFileLoader(
        "jen_kea_helper_probe17", str(pathlib.Path(__file__).resolve().parents[2] / "jen-kea-helper")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_the_daemons_own_control_socket_answers_config_get(findings):
    """v5.68.0-beta.31 (Q168, verify first) - the Kea host will ask the RUNNING daemon, on its own unix (or local http) control socket, whether it runs the logger the restored file has: the
    one answer that does not depend on the log level, the API, the Control Agent or Jen. This records, per image, the reply's shape, whether the daemon closes the connection, how long it
    takes, what it shows after a SIGHUP onto the DEBUG-55 file, back at INFO, back at WARN (where the completion line is hidden from the log - the beta.30 P1 on a real daemon), and onto a
    file with NO kea-dhcp4 logger (does Kea list a default one? it decides how the host judges a restore of a logger Jen created); the http form answers the same."""
    if not RUN_DIR:
        pytest.skip("KEA_COMPAT_RUN_DIR not set - the daemon's /var/run/kea is not bind-mounted for the runner")
    from jen.services import kea_config_edit as ed

    _restart("INFO", None)
    record = findings.setdefault("control_socket", {})
    sock_path = os.path.join(RUN_DIR, "kea4-ctrl.sock")
    conf_path = os.path.join(CONF_DIR, "kea-dhcp4.conf")
    with open(conf_path) as fh:
        base = json.load(fh)
    pid = _status()["pid"]
    until = "2099-01-01T00:00:00+00:00"

    def dump(conf):
        return json.dumps(conf, indent=2)

    reply, took, closed = _ask_raw_unix(sock_path)
    assert reply is not None, (
        "the unix control socket answered nothing: is /var/run/kea bind-mounted and the socket mode 666?"
    )
    record["reply_shape"] = {
        "type": type(reply).__name__,
        "keys": sorted(reply) if isinstance(reply, dict) else None,
        "result": reply.get("result") if isinstance(reply, dict) else None,
        "arguments_keys": sorted((reply.get("arguments") or {}).keys()) if isinstance(reply, dict) else None,
    }
    record["seconds_to_answer"] = round(took, 3)
    record["closed_after_reply"] = closed
    assert isinstance(reply, dict) and reply.get("result") == 0 and _logger_from(reply) is not None, record

    http_reply, http_took = _ask_raw_http("127.0.0.1", 8004, "jen", "jen_api_pw")
    record["http_shape"] = {
        "type": type(http_reply).__name__,
        "result": http_reply.get("result") if isinstance(http_reply, dict) else None,
    }
    record["http_logger_at_info"] = _logger_from(http_reply)
    assert _logger_from(http_reply) is not None, (
        f"the plain local http socket answers config-get with the same shape: {record['http_shape']}"
    )

    # the helper's OWN functions, against the real daemon: the spec it builds from the config file, the question it asks, the way it reads the answer and the judgement it makes
    helper = _load_helper()
    spec_from_file = helper._control_socket(base)
    record["helper_spec_kind"] = spec_from_file[0] if spec_from_file else None
    assert spec_from_file is not None and spec_from_file[0] == "unix", (
        f"the helper finds the daemon's unix control socket in the config Jen authors: {spec_from_file}"
    )
    unix_spec = (
        "unix",
        sock_path,
    )  # the runner reaches the bind-mounted socket; the helper on a real host uses the file's own path as root
    http_spec = ("http", ("127.0.0.1", 8004, "jen", "jen_api_pw"))
    helper_checks = record.setdefault("helper_checks", {})

    def helper_judges(label, file_conf, expect_match):
        """The helper asks the running daemon on BOTH transports and compares with the logger of `file_conf` (None: a file without the logger)."""
        file_entry = helper._logger_entry(file_conf)
        seen = {kind: helper._daemon_logger_now(spec) for kind, spec in (("unix", unix_spec), ("http", http_spec))}
        verdicts = {kind: helper._daemon_matches(sn, file_entry) for kind, sn in seen.items()}
        helper_checks[label] = {"seen": seen, "match": verdicts, "file_entry_present": file_entry is not None}
        assert seen["unix"] is not None and seen["http"] is not None, helper_checks[label]
        assert seen["unix"] == seen["http"], f"{label}: the two transports disagree: {seen}"
        assert verdicts["unix"] is expect_match and verdicts["http"] is expect_match, helper_checks[label]

    rows = {}
    on, code = ed.set_investigation_logging(base, until)
    assert code == "ok"
    _hup_and_read(pid, dump(on), seconds=1.0)
    rows["debug_55"] = _wait_logger(sock_path, lambda s: s["marker"] is not None)
    helper_judges("debug_55_vs_the_restored_file", base, False)  # the daemon still runs DEBUG 55: never a match
    _hup_and_read(pid, dump(base), seconds=1.0)
    rows["restored_info"] = _wait_logger(
        sock_path, lambda s: s["marker"] is None and str(s["severity"]).upper() == "INFO"
    )
    helper_judges("restored_info", base, True)

    warn_base = json.loads(dump(base))
    next(x for x in warn_base["Dhcp4"]["loggers"] if x["name"] == "kea-dhcp4")["severity"] = "WARN"
    warn_on, code = ed.set_investigation_logging(warn_base, until)
    assert code == "ok"
    _hup_and_read(pid, dump(warn_on), seconds=1.0)
    before = len(_daemon_log())
    with open(conf_path, "w") as fh:
        fh.write(dump(warn_base))
    _hup(pid)
    rows["restored_warn"] = _wait_logger(
        sock_path, lambda s: s["marker"] is None and str(s["severity"]).upper() == "WARN"
    )
    helper_judges("restored_warn", warn_base, True)
    helper_judges(
        "restored_warn_vs_an_info_file", base, False
    )  # a daemon at WARN is not at the INFO the file would say
    time.sleep(2.0)
    warn_lines = _daemon_log()[before:]
    record["warn_log_ids"] = _dhcp4_ids(warn_lines)
    record["warn_row_completion_line_in_log"] = any("DHCP4_DYNAMIC_RECONFIGURATION_SUCCESS" in ln for ln in warn_lines)

    created = json.loads(dump(base))
    created["Dhcp4"].pop("loggers", None)
    _hup_and_read(pid, dump(on), seconds=1.0)
    _hup_and_read(pid, dump(created), seconds=3.0)
    reply, _took, _closed = _ask_raw_unix(sock_path)
    record["created_case_reply_loggers"] = ((reply or {}).get("arguments") or {}).get("Dhcp4", {}).get("loggers")
    rows["created_no_logger_in_file"] = _logger_from(reply)
    # a file the helper restored by REMOVING the logger Jen created: the daemon lists none, and that is a match; a daemon that still lists the investigation logger is not
    helper_judges("created_no_logger_in_file", created, True)

    _hup_and_read(pid, dump(base), seconds=2.0)  # a sane file and a sane daemon behind
    record["rows"] = rows
    record["process_survived"] = _status()["pid"] == pid
    print(f"CONTROL SOCKET {IMAGE}: " + json.dumps(record, sort_keys=True, default=str))

    assert record["process_survived"], record
    assert (
        rows["debug_55"]
        and rows["debug_55"]["marker"] is not None
        and str(rows["debug_55"]["severity"]).upper() == "DEBUG"
        and rows["debug_55"]["debuglevel"] == 55
    ), rows
    assert (
        rows["restored_info"]
        and rows["restored_info"]["marker"] is None
        and str(rows["restored_info"]["severity"]).upper() == "INFO"
    ), rows
    assert (
        rows["restored_warn"]
        and rows["restored_warn"]["marker"] is None
        and str(rows["restored_warn"]["severity"]).upper() == "WARN"
    ), rows
    assert record["warn_row_completion_line_in_log"] is False, (
        f"the P1 row on a real Kea: restored to WARN the completion line is NOT in the log, yet the socket shows the file's logger: {record['warn_log_ids']}"
    )
