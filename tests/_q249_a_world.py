"""
tests/_q249_a_world.py
──────────────────────
Q249 - one Kea host for the tests of the Kea logging card (`tests/test_q249_a.py`, `tests/e2e/test_q249_a.py`).

The daemon is the stateful fake Kea (`tests/e2e/_fake_kea_server.py::StatefulKeaServer`), a real HTTP server reached by the REAL `kea_command` - nothing of Jen's is faked on
that side. The host is `KeaHost.helper_call`, which stands in for `kea_host.helper_call` (the one function that runs a remote command): it holds the daemon's config FILE
(`daemon.file`), restarts the daemon from it, and answers `tail-log` from the log the daemon WROTE. Since Q252 the daemon writes when a command ARRIVES
(`StatefulKeaServer.on_command`), to the files its running logger names at that moment, what the measured kea-dhcp4 3.0.5 and 3.2.1 write:

    severity INFO, DEBUG    one line per command: `INFO  [kea-dhcp4.commands/<pid>.<tid>] COMMAND_RECEIVED Received command '<name>'`
    a refused config-test   (a section with a key Kea does not know) two WARN lines at WARN or lower, and at ERROR or lower
                            `ERROR [kea-dhcp4.dhcp4/<pid>.<tid>] DHCP4_PARSER_FAIL failed to create or run parser for configuration element <key>: ...`
    severity FATAL, NONE    nothing, whatever it is asked

    writes_log=False   Kea accepted the logger and may write NO file (`kea_log_probe.out`, row 7); `unwritable` names single files it may not write
    existing           path -> lines a file already holds: the file is there, whoever may write it
    journal            what the daemon wrote to stdout (an output with a `pattern` of its own is written without the bracket)

A file Kea may write is there (empty) as soon as its running logger names it: Kea creates it. Nothing here knows what the product decides.
"""

import copy
import hashlib
import json

PROOF_PREFIX = "jen-log-proof-"  # as the fake daemon has it (`tests/e2e/_fake_kea_server.py`): the name of the one thing Kea is asked that it does not know
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
        self.unwritable = set()  # (Q252) files Kea may not write while it writes the others
        self.existing = {}  # path -> lines a file already holds
        self.written = {}  # (Q252) path -> the lines the daemon wrote, in order
        self.journal = []  # (Q252) the lines the daemon wrote to stdout, in order
        self.clock = 0
        daemon.on_command = self.kea_received
        self.calls = []
        self.missing = False  # the helper is not installed
        self.test_refusal = None  # Kea's own text from `kea-dhcp4 -t`
        self.apply_fails_from = None  # the N-th apply-config (1-based) and every later one fails
        self.applies = 0
        self.session = None  # an unresolved investigation session on the host: {"until": ..., "restore": ...}
        self.build = 22

    def ops(self):
        return [op for op, _payload in self.calls]

    def _options(self):
        """The outputs of the running `kea-dhcp4` logger; a daemon with no such logger writes to stdout."""
        for entry in self.daemon.running.get("loggers") or []:
            if isinstance(entry, dict) and entry.get("name") == "kea-dhcp4":
                return [o for o in entry.get("output-options") or [] if isinstance(o, dict)] or [{"output": "stdout"}]
        return [{"output": "stdout"}]

    def _file_outputs(self):
        return [o["output"] for o in self._options() if str(o.get("output", "")).startswith("/")]

    def may_write(self, path):
        return self.writes_log and path not in self.unwritable

    def severity(self):
        entry = next(
            (
                e
                for e in self.daemon.running.get("loggers") or []
                if isinstance(e, dict) and e.get("name") == "kea-dhcp4"
            ),
            None,
        )
        return str((entry or {}).get("severity") or "INFO").strip().upper()

    def kea_line(self, level, part, message):
        self.clock += 1
        stamp = f"2026-11-25 14:{self.clock // 60 % 60:02d}:{self.clock % 60:02d}.{self.clock % 1000:03d}"
        return f"{stamp} {level:<5} [kea-dhcp4.{part}/{self.daemon.pid}.140262] {message}"

    _RANK = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3, "FATAL": 4, "NONE": 5}

    def _entry_of(self, name):
        return next(
            (e for e in self.daemon.running.get("loggers") or [] if isinstance(e, dict) and e.get("name") == name),
            None,
        )

    def _routes(self, part):
        """(severity, outputs) the logger `kea-dhcp4.<part>` writes with (Q253). With no entry of its own it is the `kea-dhcp4` logger's. An entry of its own gives
        it its own severity, and its own outputs when it names any (measured by Opus's pass on v7.2.1, rows BM3: `kea-dhcp4.commands` at WARN under INFO, and with a
        stdout output of its own, keeps COMMAND_RECEIVED out of the main logger's file; `kea-dhcp4.dhcp4` at FATAL, and with an output of its own, keeps
        DHCP4_PARSER_FAIL out of it). Where an entry with NO outputs writes was not measured; here it writes to the main logger's, and nothing the product decides
        reads that."""
        own = self._entry_of(f"kea-dhcp4.{part}")
        if own is None:
            return self.severity(), self._options()
        severity = str(own.get("severity") or "INFO").strip().upper()
        outputs = [o for o in own.get("output-options") or [] if isinstance(o, dict)]
        return severity, outputs or self._options()

    def kea_received(self, fake, command, arguments):
        """What kea-dhcp4 writes when a command arrives, with the loggers it runs at that moment (measured: Q252, `pass/q252/b/out/measure.*.json`)."""
        section = arguments.get(fake.key) if isinstance(arguments, dict) else None
        refused = (
            [k for k in section if isinstance(k, str) and k.startswith(PROOF_PREFIX)]
            if command == "config-test" and isinstance(section, dict)
            else []
        )
        candidates = [("INFO", "commands", f"COMMAND_RECEIVED Received command '{command}'")]
        if refused:
            key = refused[0]
            candidates += [
                (
                    "WARN",
                    "dhcpsrv",
                    "DHCPSRV_MT_DISABLED_QUEUE_CONTROL disabling dhcp queue control when multi-threading is enabled.",
                ),
                (
                    "WARN",
                    "dhcp4",
                    "DHCP4_RESERVATIONS_LOOKUP_FIRST_ENABLED Multi-threading is enabled and host reservations lookup is always performed first.",
                ),
                (
                    "ERROR",
                    "dhcp4",
                    f"DHCP4_PARSER_FAIL failed to create or run parser for configuration element {key}: unsupported global configuration parameter: {key} (<string>:1:102)",
                ),
            ]
        for level, part, message in candidates:
            severity, outputs = self._routes(part)
            if self._RANK[level] < self._RANK.get(severity, 1):
                continue
            line = self.kea_line(level, part, message)
            for option in outputs:
                output = str(option.get("output", ""))
                text = line
                if option.get(
                    "pattern"
                ):  # an output with a pattern of its own: no bracket (here the package's `%-5p %m`)
                    text = f"{line.split(' ', 3)[2]:<5} {line.split('] ', 1)[1]}"
                if output == "stdout":
                    self.journal.append(text)
                elif output.startswith("/") and self.may_write(output):
                    self.written.setdefault(output, []).append(text)

    def log_lines(self, path):
        """The file as the helper's read finds it: None when it is not there."""
        if path in self.existing or path in self.written:
            return list(self.existing.get(path) or []) + list(self.written.get(path) or [])
        if path in self._file_outputs() and self.may_write(path):
            return []  # Kea made it when its logger named it, and has written nothing yet
        return None

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
