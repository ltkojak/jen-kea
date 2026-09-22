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

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def build_dhcp4_config(
    subnets: dict,
    routers: dict,
    dns: dict | None = None,
    pool_range: dict | None = None,
    valid_lifetime: dict | None = None,
) -> dict:
    """A Dhcp4 config dict shaped like a real config-get response, built
    from the same subnet dict conftest.py hands to `app_config.write_subnets`
    — one source of truth for "what subnets/routers/pools this e2e run has"
    instead of a second hard-coded copy that could silently drift from it.

    `subnets`: {id: {"name", "cidr"}} (name is unused here — Kea's own config
    has no subnet name). `routers`/`dns`: {id: "a.b.c.d"[,"a.b.c.d"]} — dns
    is optional per subnet. `pool_range`: {id: (low, high)}, default (100,
    200). `valid_lifetime`: {id: seconds} — a per-subnet override; a subnet
    not in it uses the top-level 3600 default only, unchanged."""
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
    return {
        "valid-lifetime": 3600,
        "renew-timer": 900,
        "rebind-timer": 1800,
        "subnet4": subnet4,
        "hooks-libraries": [],
    }


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
