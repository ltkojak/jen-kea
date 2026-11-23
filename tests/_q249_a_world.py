"""
tests/_q249_a_world.py
──────────────────────
Q249 - one Kea host for the tests of the Kea logging card (`tests/test_q249_a.py`, `tests/e2e/test_q249_a.py`).

The daemon is the stateful fake Kea (`tests/e2e/_fake_kea_server.py::StatefulKeaServer`), a real HTTP server reached by the REAL `kea_command` - nothing of Jen's is faked on
that side. The host is `KeaHost.helper_call`, which stands in for `kea_host.helper_call` (the one function that runs a remote command): it holds the daemon's config FILE
(`daemon.file`), restarts the daemon from it, and answers `tail-log` the way the measured kea-dhcp4 3.0.5 behaves:

    writes_log=True    the daemon writes a line to every file its RUNNING logger names for every command it receives (COMMAND_RECEIVED), creating the file
    writes_log=False   Kea accepted the logger and writes nothing (a file the daemon may not write: `kea_log_probe.out`, row 7)

Nothing here knows what the product decides.
"""

import copy
import hashlib
import json

FILE_LOGGER = {"output": "/var/log/kea/kea-dhcp4.log", "flush": True, "maxsize": 10485760, "maxver": 4}
PACKAGED = {"output": "stdout", "pattern": "%-5p %m\n"}


def dhcp4(loggers="absent"):
    """A small Dhcp4 section; `loggers` is the list to carry (or "absent")."""
    section = {"valid-lifetime": 3600, "subnet4": [{"id": 1, "subnet": "10.1.0.0/24"}]}
    if loggers != "absent":
        section["loggers"] = copy.deepcopy(loggers)
    return section


def packaged_logger():
    return {"name": "kea-dhcp4", "output-options": [dict(PACKAGED)], "severity": "INFO", "debuglevel": 0}


def kea_writes_defaults(section):
    """What a real kea-dhcp4 answers on `config-get` after a `config-set`: every output carries `flush` and a `pattern` (empty for a file)."""
    out = copy.deepcopy(section)
    for entry in out.get("loggers") or []:
        for option in entry.get("output-options") or [] if isinstance(entry, dict) else []:
            option.setdefault("flush", True)
            option.setdefault("pattern", "")
    return out


def _sha(cfg) -> str:
    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()


class KeaHost:
    """The Kea host behind SSH for one daemon: `helper_call(server, op, payload)`."""

    def __init__(self, daemon):
        self.daemon = daemon
        self.writes_log = True
        self.existing = {}  # path -> lines a file already holds (and Kea is not adding to)
        self.calls = []
        self.missing = False  # the helper is not installed
        self.test_refusal = None  # Kea's own text from `kea-dhcp4 -t`
        self.apply_fails_from = None  # the N-th apply-config (1-based) and every later one fails
        self.applies = 0
        self.session = None  # an unresolved investigation session on the host: {"until": ..., "restore": ...}
        self.build = 22

    def ops(self):
        return [op for op, _payload in self.calls]

    def _file_outputs(self):
        out = []
        for entry in self.daemon.running.get("loggers") or []:
            if isinstance(entry, dict) and entry.get("name") == "kea-dhcp4":
                for option in entry.get("output-options") or []:
                    if isinstance(option, dict) and str(option.get("output", "")).startswith("/"):
                        out.append(option["output"])
        return out

    def log_lines(self, path):
        if self.writes_log and path in self._file_outputs():
            received = len(self.daemon.commands)
            return [
                f"2026-11-23 14:15:{n % 60:02d}.000 INFO  [kea-dhcp4.commands/8.1] COMMAND_RECEIVED Received command 'config-get' ({n})"
                for n in range(received)
            ]
        return self.existing.get(path)

    def helper_call(self, server, op, payload=None, timeout=60):
        from jen.services import kea_host

        payload = dict(payload or {})
        self.calls.append((op, payload))
        if self.missing:
            raise kea_host.HelperMissing("sudo: jen-kea-helper: command not found")
        envelope = {"helper_version": 7, "helper_build": self.build}
        if op == "version":
            return {"ok": True, "python": "3.12.0", **envelope}
        if op == "read-config":
            cfg = {"Dhcp4": copy.deepcopy(self.daemon.file)}
            return {"ok": True, "config": cfg, "sha256": _sha(cfg), **envelope}
        if op == "test-config":
            if self.test_refusal:
                return {"ok": False, "error": "testerror", "detail": self.test_refusal, **envelope}
            return {"ok": True, **envelope}
        if op == "apply-config":
            self.applies += 1
            if self.apply_fails_from is not None and self.applies >= self.apply_fails_from:
                return {"ok": False, "error": "write", "detail": "No space left on device", **envelope}
            current = {"Dhcp4": copy.deepcopy(self.daemon.file)}
            if payload.get("expect_sha256") not in (None, _sha(current)):
                return {"ok": False, "error": "conflict", "sha256": _sha(current), **envelope}
            self.daemon.file = copy.deepcopy(payload["config"]["Dhcp4"])
            return {"ok": True, "sha256": _sha(payload["config"]), **envelope}
        if op == "service":
            self.daemon.restart()
            if self.daemon.expand is not None:
                self.daemon.running = self.daemon.expand(self.daemon.running)
            return {"ok": True, "unit": "kea-dhcp4-server", "state": "active", **envelope}
        if op == "tail-log":
            lines = self.log_lines(payload.get("path"))
            if lines is None:
                return {"ok": False, "error": "missing", **envelope}
            return {"ok": True, "lines": lines[-int(payload.get("lines") or 200) :], **envelope}
        if op == "investigation-status":
            if self.session is None:
                return {"ok": True, "armed": False, **envelope}
            return {"ok": True, "armed": True, "restored_at": "", **copy.deepcopy(self.session), **envelope}
        raise AssertionError(f"KeaHost: the test did not expect the helper op {op!r}")


def file_server(daemon, **extra):
    """A server on File over SSH whose daemon is `daemon`."""
    return {
        "id": 1,
        "name": "kea-a",
        "api_url": daemon.url,
        "api_user": "",
        "api_pass": "",
        "ssh_host": "10.9.9.9",
        "ssh_user": "jen",
        "config_transport": "file",
        **extra,
    }
