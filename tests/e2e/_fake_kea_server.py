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

TWO_SUBNET_DHCP4 = {
    "valid-lifetime": 3600,
    "renew-timer": 900,
    "rebind-timer": 1800,
    "subnet4": [
        {
            "id": 1,
            "subnet": "10.99.0.0/24",
            "pools": [{"pool": "10.99.0.100 - 10.99.0.200"}],
            "option-data": [{"name": "routers", "data": "10.99.0.1"}],
        },
        {
            "id": 2,
            "subnet": "10.99.1.0/24",
            "pools": [{"pool": "10.99.1.100 - 10.99.1.200"}],
            "option-data": [{"name": "routers", "data": "10.99.1.1"}],
        },
    ],
    "hooks-libraries": [],
}

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
    own scope via `server.responses[cmd] = {...}` and restore it after."""

    def __init__(self):
        self.responses = dict(DEFAULT_RESPONSES)
        self._httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.responses = self.responses
        self.port = self._httpd.server_port
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()
