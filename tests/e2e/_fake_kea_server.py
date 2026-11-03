"""
tests/e2e/_fake_kea_server.py
──────────────────────────────
v5.39.0 (Q40) — a stdlib http.server standing in for a Kea Control
Agent: enough of the handful of commands the e2e journeys actually
trigger (version-get, config-get, status-get, lease4-get-all,
stat-lease4-get, reservation-add) to keep every page that round-trips
through jen.services.kea.kea_command() from erroring out. No auth
check — a fake test double, not a security boundary.
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer


def build_dhcp4_config(
    subnets: dict,
    routers: dict,
    dns: dict | None = None,
    pool_range: dict | None = None,
    valid_lifetime: dict | None = None,
    client_classes: list | None = None,
) -> dict:
    """A Dhcp4 config dict shaped like a real config-get response, built
    from the same subnet dict conftest.py hands to `app_config.write_subnets`
    — one source of truth for "what subnets/routers/pools this e2e run has"
    instead of a second hard-coded copy that could silently drift from it.

    `subnets`: {id: {"name", "cidr"}} (name is unused here — Kea's own config
    has no subnet name). `routers`/`dns`: {id: "a.b.c.d"[,"a.b.c.d"]} — dns
    is optional per subnet. `pool_range`: {id: (low, high)}, default (100,
    200). `valid_lifetime`: {id: seconds} — a per-subnet override; a subnet
    not in it uses the top-level 3600 default only, unchanged. `client_classes`
    (Q209): [{"name", "test"}] written as the config's `client-classes`; None
    (the default dataset) leaves the config exactly as it was."""
    dns = dns or {}
    pool_range = pool_range or {}
    valid_lifetime = valid_lifetime or {}
    subnet4 = []
    for sid, info in subnets.items():
        base = info["cidr"].rsplit(".", 1)[0]
        lo, hi = pool_range.get(sid, (100, 200))
        option_data = [{"name": "routers", "data": routers[sid]}]
        if dns.get(sid):
            option_data.append({"name": "domain-name-servers", "data": dns[sid]})
        entry = {
            "id": sid,
            "subnet": info["cidr"],
            "pools": [{"pool": f"{base}.{lo} - {base}.{hi}"}],
            "option-data": option_data,
        }
        if sid in valid_lifetime:
            entry["valid-lifetime"] = valid_lifetime[sid]
        subnet4.append(entry)
    config = {
        "valid-lifetime": 3600,
        "renew-timer": 900,
        "rebind-timer": 1800,
        "subnet4": subnet4,
        "hooks-libraries": [],
    }
    if client_classes:
        config["client-classes"] = [dict(c) for c in client_classes]
    return config


TWO_SUBNET_DHCP4 = build_dhcp4_config(
    subnets={1: {"name": "Office", "cidr": "10.99.0.0/24"}, 2: {"name": "Guest", "cidr": "10.99.1.0/24"}},
    routers={1: "10.99.0.1", 2: "10.99.1.1"},
)

DEFAULT_RESPONSES = {
    "version-get": {"result": 0, "text": "2.6.1", "arguments": {"extended": "2.6.1"}},
    "config-get": {"result": 0, "arguments": {"Dhcp4": TWO_SUBNET_DHCP4}},
    "config-test": {"result": 0, "text": "configuration seems sane"},
    "config-set": {"result": 0, "text": "configuration applied"},
    "status-get": {"result": 0, "arguments": {"pid": 1234, "uptime": 3600, "reload": 0}},
    "statistic-get-all": {"result": 0, "arguments": {}},
    "lease4-get-all": {"result": 0, "arguments": {"leases": []}},
    "stat-lease4-get": {"result": 0, "arguments": {"result-set": {"columns": [], "rows": []}}},
    "reservation-add": {"result": 0, "text": "Host added."},
    "reservation-get-all": {"result": 0, "arguments": {"hosts": []}},
    "class-list": {"result": 0, "arguments": {"client-classes": []}},
}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        command = body.get("command", "")
        reply = dict(self.server.responses.get(command, {"result": 0, "text": "mocked", "arguments": {}}))
        payload = json.dumps([reply]).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        pass  # keep CI logs readable — every journey fires several commands


class FakeKeaServer:
    """One fake Control Agent for the whole session. `responses` merges
    over DEFAULT_RESPONSES; a test can override a single command for its
    own scope via `server.responses[cmd] = {...}` and restore it after.
    `dhcp4_config` swaps out config-get's Dhcp4 body — the demo dataset
    (tests/e2e/demo_data.py, JEN_E2E_DATASET=demo) builds its own from the
    same subnet dict it seeds the DB from, via build_dhcp4_config()."""

    def __init__(self, dhcp4_config: dict | None = None):
        self.responses = dict(DEFAULT_RESPONSES)
        if dhcp4_config is not None:
            self.responses["config-get"] = {"result": 0, "arguments": {"Dhcp4": dhcp4_config}}
        self._httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.responses = self.responses
        self.port = self._httpd.server_port
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()


# ── Q212: a fake Kea that HOLDS a configuration ───────────────────────────────────────────────────────────────────────────


def digest_of(cfg_section: dict, key: str = "Dhcp4") -> str:
    """A stand-in for Kea's digest: SHA-256 over canonical JSON of the held section. Jen never computes Kea's digest (it only compares two the daemon gave), so any stable function will do."""
    return hashlib.sha256(json.dumps({key: cfg_section}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class _StatefulHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            body = json.loads((self.rfile.read(length) if length else b"{}") or b"{}")
        except ValueError:
            body = {}
        fake = self.server.fake
        command = body.get("command", "")
        with fake.lock:
            fake.commands.append(command)
            if fake.stopped:
                self.connection.close()  # a daemon that stopped serving: no reply at all
                return
            hook = fake.hooks.get(command)
            if hook:
                hook(fake)  # a stranger's change (or a crash) injected at the exact moment this command arrives
            when = fake.hang.get(command)
            if when != "before":
                reply = fake._answer(command, body.get("arguments") or {})
            else:
                reply = None
        if when:
            time.sleep(fake.hang_seconds)
            if reply is None:  # "before": the command is never run
                return
        payload = json.dumps([reply]).encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except OSError:
            pass  # the client gave up (a hang past its wait); nothing to tell it

    def log_message(self, fmt, *args):
        pass


class StatefulKeaServer:
    """One fake kea-dhcp4 (or kea-dhcp6) that HOLDS a configuration, the way the real daemon does: `config-set` replaces it, `config-get` / `config-hash-get` answer it with a digest,
    `config-write` writes it to a held FILE, and a restart (`restart()`) reloads from that file - so an apply that forgot `config-write` is lost, exactly as on the real thing.
    Every command received is appended to `commands`. The switches, each settable per test:

        write_fails        Kea's own permission text: `config-write` answers result 1
        set_fails          Kea's refusal text: `config-set` answers result 1 (the old configuration keeps serving)
        set_fails_and_stops   ... and the daemon then stops answering at all (ISC: a fatal error can stop the server)
        hooks              {command: callable(fake)} run when that command arrives, before it is answered
        hang               {command: "before" | "after"}: the reply arrives after `hang_seconds`; "before" never runs the command, "after" runs it and then goes quiet
        no_service_key     `config-get` answers without the Dhcp4/Dhcp6 section (a Control Agent answering for itself)
        no_digest          `config-get` answers without a `hash`
        stopped            every request is dropped
    """

    def __init__(self, config: dict | None = None, *, key: str = "Dhcp4", version: str = "3.0.5"):
        self.key = key
        self.version = version
        self.lock = threading.RLock()
        self.running = copy.deepcopy(config if config is not None else TWO_SUBNET_DHCP4)
        self.file = copy.deepcopy(self.running)
        self.commands: list[str] = []
        self.write_fails = None
        self.set_fails = None
        self.set_fails_and_stops = False
        self.hang: dict = {}
        self.hooks: dict = {}
        self.hang_seconds = 1.0
        self.no_service_key = False
        self.no_digest = False
        self.stopped = False
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _StatefulHandler)
        self._httpd.daemon_threads = True
        self._httpd.fake = self
        self.port = self._httpd.server_port
        self.url = f"http://127.0.0.1:{self.port}/"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    # the daemon's own view
    def digest(self) -> str:
        return digest_of(self.running, self.key)

    def restart(self):
        """A daemon restart: it serves the FILE again (whatever was only `config-set` is gone)."""
        with self.lock:
            self.running = copy.deepcopy(self.file)
            self.stopped = False

    def set_running(self, section: dict):
        """A second client's `config-set` (a hand edit on the daemon), without going through the wire."""
        with self.lock:
            self.running = copy.deepcopy(section)

    def _answer(self, command: str, arguments: dict) -> dict:
        if command == "version-get":
            return {"result": 0, "text": self.version, "arguments": {"extended": self.version}}
        if command == "config-get":
            args = {} if self.no_service_key else {self.key: copy.deepcopy(self.running)}
            if not self.no_digest:
                args["hash"] = self.digest()
            return {"result": 0, "arguments": args}
        if command == "config-hash-get":
            return {"result": 0, "arguments": {"hash": self.digest()}}
        if command == "config-test":
            return {"result": 0, "text": "Configuration seems sane."}
        if command == "config-set":
            if self.set_fails:
                if self.set_fails_and_stops:
                    self.stopped = True
                return {"result": 1, "text": self.set_fails}
            if self.key not in arguments:
                return {"result": 1, "text": f"missing {self.key}"}
            self.running = copy.deepcopy(arguments[self.key])
            return {"result": 0, "text": "Configuration successful.", "arguments": {"hash": self.digest()}}
        if command == "config-write":
            if self.write_fails:
                return {"result": 1, "text": self.write_fails}
            self.file = copy.deepcopy(self.running)
            size = len(json.dumps(self.file))
            return {
                "result": 0,
                "text": "Configuration written",
                "arguments": {"filename": "/etc/kea/kea-dhcp4.conf", "size": size},
            }
        return {"result": 0, "text": "mocked", "arguments": {}}

    def start(self):
        self._thread.start()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()
