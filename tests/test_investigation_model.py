"""
tests/test_investigation_model.py
─────────────────────────────────
v5.68.0-beta.28 (Q163) — the MODEL test of investigation logging: a seeded random walk over every operation and every fault of the service, with the invariants
stated ONCE and checked after EVERY step against the STORED record.

Why it exists. Six reviews in a row found a P1 that was a SEQUENCE nobody had named - a reload applied with its reply lost; a lost reply, then a silent API, then
a sweep; a damaged record then one unreadable server; a damaged record then zero servers; an SSH host changed while an entry exists. Every test in the suite is a
path test: it checks the sequence its Q named, and the reviewer composes the ones it did not. This test composes them.

The world is the one of tests/_investigation_world.py (the same fake daemon, a settings table in a dict) with three differences that make a sequence mean what it
would mean on a real network: the Kea hosts are PHYSICAL fakes keyed by their address (a server id can be pointed at a different Kea - the identity changes the
guard exists for), a real jen.config on disk is written through the REAL `AppConfig`, and the writes to the Kea config file go through the REAL change set and the
REAL `kea_host.apply_config` (only `helper_call`, the wire, is fake). The clock and the random source are the test's own: a failure prints the seed and the whole
step log, and `JEN_MODEL_SEED=<n> pytest --noconftest tests/test_investigation_model.py` replays exactly that walk.

    pytest --noconftest tests/test_investigation_model.py -q                 # 40 seeds x 400 steps (CI's)
    JEN_MODEL_SEEDS=500 pytest --noconftest tests/test_investigation_model.py -q
    JEN_MODEL_SEED=17 JEN_MODEL_STEPS=400 pytest --noconftest tests/test_investigation_model.py -q -k walk

v5.68.0-beta.29 (Q165): the Kea HOST is part of the world. Each physical fake carries the state file and the timer of jen-kea-helper build 15 (the fake restores a logger with
the helper's OWN `_restore_logger`), a `HostTimer` actor fires every fake's timer every 60 s of the walk's clock WITHOUT any call from Jen, and invariant I10 says what the
guarantee now is: a daemon the host was armed for is never at investigation DEBUG more than 120 s after its deadline - however the rest of the walk went: Jen's database
unavailable or garbage, an identity changed under the entry, or Jen not running at all (`jen_dead_from`).

Where it lives in the process (CLAUDE.md, "Test environment notes"): any change under jen/services/investigation_logging.py, jen/services/explain_context.py or the Kea
settings routes runs this file locally before the push, and a new operation, state or fault in those modules is added to the walk in the same commit.
"""

import configparser
import copy
import json
import os
import random
import time
from datetime import timedelta
from urllib.parse import urlparse

import pytest

from jen import extensions
from jen.config import AppConfig, ConfigChangeRefused, app_config
from jen.services import explain_context as ctx
from jen.services import investigation_logging as inv
from jen.services import kea_changeset as _changeset_mod
from jen.services import kea_config_edit as ed
from jen.services import kea_host
from tests._investigation_world import FUTURE, NOW, FakeKea, _cfg

pytest_plugins = ("tests._investigation_world",)

SEEDS = int(os.environ.get("JEN_MODEL_SEEDS", "40"))
STEPS = int(os.environ.get("JEN_MODEL_STEPS", "400"))
ONLY_SEED = os.environ.get("JEN_MODEL_SEED")

_REAL_APPLY_CHANGE = (
    _changeset_mod.apply_change
)  # the `world` fixture swaps in the fake daemon's; the walk wants the REAL change set
HOSTS = ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9")
IDENTITY_KEYS = ("api_url", "ssh_host", "ssh_user", "kea_conf")
DEFAULT_CONF = "/etc/kea/kea-dhcp4.conf"


class InvariantViolated(AssertionError):
    pass


# ── what the stored record, the fakes and the config on disk say, read independently of the code under test ─────────────────────────────────────


def _logger_of(cfg):
    section = (cfg or {}).get("Dhcp4") or {}
    return next((x for x in section.get("loggers") or [] if isinstance(x, dict) and x.get("name") == "kea-dhcp4"), None)


def at_debug(cfg) -> bool:
    """The kea-dhcp4 logger of `cfg` is at investigation DEBUG (severity DEBUG, debuglevel 55) AND carries Jen's marker."""
    entry = _logger_of(cfg)
    if not entry:
        return False
    context = entry.get("user-context")
    marker = context.get("jen-investigation") if isinstance(context, dict) else None
    return (
        str(entry.get("severity") or "").upper() == "DEBUG"
        and entry.get("debuglevel") == 55
        and isinstance(marker, dict)
    )


def has_marker(cfg) -> bool:
    entry = _logger_of(cfg)
    context = entry.get("user-context") if entry else None
    return isinstance(context, dict) and "jen-investigation" in context


def host_of(url) -> str:
    return urlparse(url or "").hostname or ""


class Walk:
    """One seeded walk. `run()` raises InvariantViolated (with the seed and the step log) at the first step that breaks an invariant."""

    OPS = {
        "turn_on": 14,
        "turn_off": 7,
        "sweep": 8,
        "sweep_full": 8,
        "job": 8,
        "forget": 3,
        "acknowledge": 2,
        "removal": 2,
        "identity": 7,
        "file_write": 6,
        "views": 3,
        "reload": 2,
        "idle": 3,
    }

    #: Q165: the HostTimer actor. False is the mutation check of I10 - the walk must go red without the host's timer.
    HOST_TIMER = True

    def __init__(self, seed, steps, world, tmp_path, monkeypatch, jen_dead_from=None):
        self.seed, self.steps = seed, steps
        self.jen_dead_from = (
            jen_dead_from  # from this step on Jen does NOTHING (no operation, no sweep): only the hosts' timers run
        )
        self.rng = random.Random(seed)
        self.world, self.tmp_path = world, tmp_path
        self.log: list[str] = []
        self.step_no = 0
        self.now = NOW
        self.went_back = False
        self.faults: list[tuple] = []  # (expires at step, undo callable, text)
        self.db_fail_budget = 0
        self.unavailable_until = -1
        self.violations_ok = None
        # bookkeeping the invariants read
        self.writes: list[tuple] = []  # (op, key, ok) for every write of the record or its damaged copy that Jen made
        self.applies: list[tuple] = []  # (op, host) for every Kea config write the wire carried
        self.marker_removals: list[tuple] = []  # (host, writer flag) every time the wire removed a marker from a file
        self.answered_get: set = set()  # hosts that answered a config-get during the current step
        self.i1_open = False
        self.born: dict = {}
        self.frozen: dict | None = None
        self.prev_entries: dict = {}
        self.prev_kind = "ok"
        self.prev_raw = ""
        self.op = ""
        self.exempt_i7 = False
        self._life: dict = {}
        self.active_knobs: set = set()
        self._call_marks: dict = {}
        self._seen_hosts: dict = {}
        self._seen_entries: dict = {}
        self._seen_kind = "ok"
        self.hand_removed: set = set()  # server ids a person removed from jen.config by hand: the identity baseline of an id starts over when it is added again
        self.last_turn_on = (None, True)
        self.prev_ident, self.prev_mode = {}, "ca"
        self._build(monkeypatch)
        self.prev_ident, self.prev_mode = self.identity()

    # ── the world ──────────────────────────────────────────────────────────────────────────────────────────────────────────

    def _build(self, monkeypatch):
        w = self.world
        rng = self.rng
        self.physical = {
            "10.0.0.1": FakeKea(_cfg([{"name": "kea-dhcp4", "severity": "INFO"}])),
            "10.0.0.2": FakeKea(_cfg()),
            "10.0.0.3": FakeKea(
                _cfg(
                    [
                        {
                            "name": "kea-dhcp4",
                            "output-options": [{"output": "/var/log/kea/kea-dhcp4.log"}],
                            "severity": "WARN",
                            "debuglevel": 0,
                        },
                        {"name": "kea-dhcp4.hosts", "severity": "INFO"},
                    ]
                )
            ),
            "10.0.0.9": FakeKea(_cfg()),
        }
        for host, fake in self.physical.items():
            fake.host = host
            fake.next_tick = NOW + timedelta(
                seconds=rng.randint(1, 60)
            )  # when this host's timer fires next (the timer is the host's own clock)
            if rng.random() < 0.35:
                fake.commands = ["version-get"]  # a daemon that answers and lacks config-reload
        self.original = {host: copy.deepcopy(f.file) for host, f in self.physical.items()}
        ini = configparser.ConfigParser(interpolation=None)
        ini["kea"] = {"name": "kea-a", "api_url": "http://10.0.0.1:8000", "api_user": "u", "api_pass": "p"}
        ini["kea_ssh"] = {"host": "10.0.0.1", "user": "jen", "kea_conf": DEFAULT_CONF}
        for n, host in ((2, "10.0.0.2"), (3, "10.0.0.3")):
            ini[f"kea_server_{n}"] = {
                "name": f"kea-{'abc'[n - 1]}",
                "api_url": f"http://{host}:8000",
                "ssh_host": host,
                "ssh_user": "jen",
                "kea_conf": DEFAULT_CONF,
            }
        ini["jen_db"] = {"host": "h", "user": "u", "password": "p"}
        self.path = self.tmp_path / "jen.config"
        with open(self.path, "w", encoding="utf-8") as f:
            ini.write(f)
        monkeypatch.setattr(extensions, "CONFIG_FILE", str(self.path))
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca", raising=False)
        monkeypatch.setattr(app_config, "reload", self.sync)
        self.sync()
        # the wire: every Kea call is answered by the PHYSICAL fake at the address the server names
        monkeypatch.setattr(inv._kea, "kea_command", self._kea_command)
        monkeypatch.setattr(kea_host, "service_action", self._service_action)
        monkeypatch.setattr(kea_host, "read_config_versioned", self._read_config)
        monkeypatch.setattr(kea_host, "helper_call", self._helper_call)
        monkeypatch.setattr(kea_host, "helper_build", self._host_build)
        monkeypatch.setattr(kea_host, "investigation_arm", self._host_arm)
        monkeypatch.setattr(kea_host, "investigation_disarm", self._host_disarm)
        monkeypatch.setattr(kea_host, "investigation_status", self._host_status)
        monkeypatch.setattr(kea_host, "test_config", lambda server, service, cfg, **kw: {"ok": True, "code": "ok"})
        monkeypatch.setattr(kea_host, "_record_from_resp", lambda *a, **k: None)
        monkeypatch.setattr(kea_host, "_record_revision_after_apply", lambda *a, **k: None)
        monkeypatch.setattr(kea_host, "_conf_path", lambda server, service: DEFAULT_CONF)
        monkeypatch.setattr(inv._changeset, "apply_change", _REAL_APPLY_CHANGE)
        monkeypatch.setattr(_changeset_mod._events, "emit", lambda *a, **k: None)
        monkeypatch.setattr(_changeset_mod, "record_outcome", lambda *a, **k: None)
        monkeypatch.setattr(inv, "_now", lambda: self.now)
        monkeypatch.setattr(inv, "OBSERVE_AFTER_RESTART_S", 0)
        # settings: the world's store, traced and with the database failures the walk injects
        real_set = (
            w.set_setting if hasattr(w, "set_setting") else None
        )  # (the world exposes the patched function through the module)
        from jen.models import user as usermod

        patched_set, patched_set_audit = usermod.set_global_setting, usermod.set_global_setting_and_audit

        def traced_set(key, value):
            ok = patched_set(key, value)
            if key in (inv.RECORD_KEY, inv.DAMAGED_KEY):
                self.writes.append((self.op, key, ok))
            return ok

        def traced_set_audit(key, value, action, entity, details=""):
            ok = patched_set_audit(key, value, action, entity, details)
            if key in (inv.RECORD_KEY, inv.DAMAGED_KEY):
                self.writes.append((self.op, key, ok))
            return ok

        monkeypatch.setattr(usermod, "set_global_setting", traced_set)
        monkeypatch.setattr(usermod, "set_global_setting_and_audit", traced_set_audit)
        w.db["fails"] = self._db_fails
        _ = real_set

    def _db_fails(self, value):
        if self.db_fail_budget > 0:
            self.db_fail_budget -= 1
            self.i1_open = True
            return True
        return False

    def sync(self):
        """The reload: the server list follows the file (new dicts for the same ids), the mode follows the file."""
        parser = app_config._read_parser()
        self.world.servers[:] = AppConfig.derive_kea_servers(parser, quiet=True)
        mode = parser.get("kea", "connection_mode", fallback="ca").strip().lower()
        extensions.KEA_CONNECTION_MODE = mode if mode in ("ca", "direct") else "ca"

    def api_fake(self, server):
        return self.physical.get(host_of((server or {}).get("api_url")))

    def ssh_fake(self, server):
        return self.physical.get((server or {}).get("ssh_host"))

    def _kea_command(self, command, server=None, **kw):
        fake = self.api_fake(server)
        if fake is None:
            return {"result": 1, "text": "no route to host"}
        reply = fake.kea_command(command)
        if command == "config-get" and reply.get("result") == 0:
            self.answered_get.add(fake.host)
        return reply

    def _service_action(self, server, service, action):
        fake = self.ssh_fake(server)
        if fake is None:
            return {"ok": False, "detail": "ssh: no route to host"}
        out = fake.service_action(server, service, action)
        if not out.get("ok"):
            fake._restart_failed = True
        else:
            fake._restart_failed = False
        return out

    def _read_config(self, server, service, *, errors=None):
        fake = self.ssh_fake(server)
        if fake is None:
            if errors is not None:
                errors.append("ssh: no route to host")
            return None, None
        return copy.deepcopy(fake.file), "sha"

    # the Kea host's investigation ops (build 15): answered by the physical fake at the server's SSH host, or "no route" when there is none
    _NO_ROUTE = {"ok": False, "code": "error", "detail": "ssh: no route to host"}

    def _host_build(self, server):
        fake = self.ssh_fake(server)
        if fake is None:
            return {"code": "unreachable", "version": None, "build": None, "detail": "ssh: no route to host"}
        return fake.helper_build_info(server)

    def _host_arm(self, server, until, restore, jen=None, log_path=""):
        fake = self.ssh_fake(server)
        return dict(self._NO_ROUTE) if fake is None else fake.investigation_arm(server, until, restore, jen, log_path)

    def _host_disarm(self, server):
        fake = self.ssh_fake(server)
        return dict(self._NO_ROUTE) if fake is None else fake.investigation_disarm(server)

    def _host_status(self, server):
        fake = self.ssh_fake(server)
        return dict(self._NO_ROUTE) if fake is None else fake.investigation_status(server)

    def _host_timers(self):
        """The HostTimer actor: every host's timer fires every 60 s of the walk's clock, at the moment it fires, whether or not Jen runs, is reachable or is right about
        anything (`jen-kea-helper --self-restore` reads only its own state file and the Kea config). Jen's clock is the host's clock, so the tick sees the time it fired at."""
        if not self.HOST_TIMER:
            return
        for host, fake in self.physical.items():
            while fake.next_tick <= self.now:
                at, kept = fake.next_tick, self.now
                self.now = at
                try:
                    result = fake.host_tick()
                finally:
                    self.now = kept
                if result is not None and not result[0]:
                    fake.last_failed_tick = at
                if result is not None:
                    self.say(
                        f"  host timer on {host} fired at {at.isoformat(timespec='seconds')}: restore ok={result[0]} how={result[1]}"
                    )
                fake.next_tick = at + timedelta(seconds=60)

    def _helper_call(self, server, op, payload=None, timeout=60):
        fake = self.ssh_fake(server)
        if fake is None:
            raise kea_host.HelperError("ssh: no route to host")
        assert op == "apply-config", op
        if fake.fail_writes_after is not None and fake.writes >= fake.fail_writes_after:
            return {"ok": False, "error": "write", "detail": "the helper could not write the file"}
        if getattr(fake, "rollback_fails", False) and getattr(fake, "_restart_failed", False):
            return {"ok": False, "error": "write", "detail": "the rollback could not be written"}
        before_marker = has_marker(fake.file)
        fake.file = copy.deepcopy(payload["config"])
        fake.writes += 1
        self.applies.append((self.op, fake.host))
        if before_marker and not has_marker(fake.file):
            self.marker_removals.append((fake.host, bool(getattr(kea_host._investigation_writer, "on", False))))
        return {"ok": True, "sha256": "applied"}

    # ── independent readings ─────────────────────────────────────────────────────────────────────────────────────────────────

    def raw_state(self):
        """("ok" | "damaged" | "unavailable", {sid: entry}) read from the settings dict, not from `_record()`."""
        if self.world.db.get("unavailable"):
            return "unavailable", {}
        raw = self.world.store.get(inv.RECORD_KEY, "")
        if raw == "":
            return "ok", {}
        try:
            data = json.loads(raw)
        except ValueError:
            return "damaged", {}
        if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
            return "damaged", {}
        if not all(inv._valid_entry(e) for e in data["servers"].values()):
            return "damaged", {}
        return "ok", {str(k): v for k, v in data["servers"].items()}

    def outstanding(self):
        kind, entries = self.raw_state()
        return kind, {sid: e for sid, e in entries.items() if not e.get("removed")}

    def identity(self):
        """{sid: (api_url, ssh_host, ssh_user, kea_conf)} and the mode, from the file on disk."""
        parser = app_config._read_parser()
        out = {}
        for s in AppConfig.derive_kea_servers(parser, quiet=True):
            out[str(s["id"])] = tuple(
                (str(s.get(k) or "").strip() or (DEFAULT_CONF if k == "kea_conf" else "")) for k in IDENTITY_KEYS
            )
        mode = parser.get("kea", "connection_mode", fallback="ca").strip().lower()
        return out, ("direct" if mode == "direct" else "ca")

    def audits(self, action):
        return len([a for a in self.world.store.get("_audit", []) if a[0] == action])

    def fail(self, name, detail):
        shown = int(os.environ.get("JEN_MODEL_LOG", "60"))
        tail = "\n".join(self.log[-shown:]) + "\n--- state at the failure ---\n" + self.state_dump()
        raise InvariantViolated(
            f"\n{name} violated at step {self.step_no} (seed {self.seed}, op {self.op!r}): {detail}\n"
            f"reproduce: JEN_MODEL_SEED={self.seed} JEN_MODEL_STEPS={self.steps} pytest --noconftest tests/test_investigation_model.py -q -k walk\n"
            f"--- the last {min(shown, len(self.log))} of {len(self.log)} log lines (JEN_MODEL_LOG=<n> shows more) ---\n{tail}"
        )

    def state_dump(self):
        ident, mode = self.identity()
        kind, entries = self.raw_state()
        lines = [f"mode={mode} record={kind}"]
        lines += [f"server {sid}: api={i[0]} ssh={i[1]} user={i[2]}" for sid, i in sorted(ident.items())]
        for sid, e in sorted(entries.items()):
            lines.append(
                f"entry {sid}: {e.get('name')} ssh={e.get('ssh_host')} file={e.get('file')} daemon={e.get('daemon')} pending={e.get('pending')} "
                f"removed={e.get('removed')} contradiction={e.get('contradiction')} tries={e.get('reload_tries')} restarted={e.get('restarted')}"
            )
        for host, f in self.physical.items():
            lines.append(
                f"kea {host}: loaded_debug={at_debug(f.loaded)} file_marker={has_marker(f.file)} reload={'config-reload' in f.commands} "
                f"restarts={f.calls.count('restart:dhcp4')} reloads={f.calls.count('config-reload')} faults="
                f"{[k for k in ('reload_applied_but_lost', 'api_silent', 'list_unreachable', 'reload_ignored', 'restart_ignored', 'rollback_fails') if getattr(f, k, False)]}"
                f"{'' if f.restart_ok else ' restart_ok=False'}{'' if not f.reload_result else ' reload_refused'} host_state="
                f"{None if f.helper_state is None else {k: f.helper_state[k] for k in ('until', 'restored_at', 'how', 'last_error')}} last calls: {f.calls[-10:]}"
            )
        return "\n".join(lines)

    def say(self, text):
        self.log.append(f"[{self.step_no:3d}] {text}")

    # ── the walk ───────────────────────────────────────────────────────────────────────────────────────────────────────────────

    def run(self):
        names = list(self.OPS)
        weights = [self.OPS[n] for n in names]
        for n in range(self.steps):
            self.step_no = n
            self._tick()
            self._host_timers()
            self.answered_get = set()
            self.writes.clear()
            self.applies.clear()
            self.marker_removals.clear()
            self.exempt_i7 = False
            self._faults()
            self.op = self.rng.choices(names, weights)[0]
            if self.jen_dead_from is not None and n >= self.jen_dead_from:
                self.op = "idle"  # Jen is not running: no sweep, no page, no scheduler job - the clock moves and the hosts' timers fire
            self.start_kind, self.start_entries = self.raw_state()
            self.start_counts = {h: self._counts(f) for h, f in self.physical.items()}
            self.start_audits = {
                a: self.audits(a)
                for a in (
                    "INVESTIGATION_LOGGING_RECORD_ACKNOWLEDGED",
                    "INVESTIGATION_LOGGING_REMOVAL_REFUSED",
                    "INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED",
                    "INVESTIGATION_LOGGING_FILE_WRITE_REFUSED",
                    "INVESTIGATION_LOGGING_FORGOTTEN",
                )
            }
            try:
                getattr(self, "op_" + self.op)()
            except InvariantViolated:
                raise
            except Exception as e:  # an operation must never raise: it is the page's route and the scheduler's job
                self.say(f"!! {self.op} RAISED {type(e).__name__}: {e}")
                import traceback

                self.log.append(traceback.format_exc())
                self.fail("no-raise", f"{self.op} raised {type(e).__name__}: {e}")
            self._invariants()

    def _counts(self, fake):
        return (fake.calls.count("restart:dhcp4"), fake.calls.count("config-reload"))

    def _tick(self):
        step = self.rng.randint(1, 120)
        if not self.went_back and self.rng.random() < 0.004:
            self.went_back = True
            step = -self.rng.randint(5, 900)  # the clock steps backwards once
            self.say(f"clock steps BACK {-step}s")
            for fake in self.physical.values():
                fake.next_tick += timedelta(
                    seconds=step
                )  # a systemd timer is MONOTONIC: it fires 60 s of elapsed time after the last run, whatever the wall clock was set to
        self.now = self.now + timedelta(seconds=step)

    # ── faults ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────

    def _faults(self):
        for fault in [f for f in self.faults if f[0] <= self.step_no]:
            fault[1]()
            self.faults.remove(fault)
            self.say(f"fault over: {fault[2]}")
        if self.unavailable_until == self.step_no:
            self.world.db["unavailable"] = False
            self.say("settings available again")
            self.unavailable_until = -1
        if self.rng.random() > 0.30:
            return
        # weighted toward the faults that composed the reviews' P1s: a restart that fails, a server removed by hand, a database that refuses, an unreadable record
        weights = {
            "restart_fails": 4,
            "hand_remove_server": 3,
            "db_fails": 3,
            "garbage": 2,
            "bad_entry": 2,
            "unavailable": 2,
            "reload_ignored": 2,
            "reload_refused": 2,
            "restart_ignored": 2,
            "host_down": 2,
            "host_restore_fails": 2,
            "hup_ignored": 2,
        }
        kinds = [
            "reload_applied_but_lost",
            "api_silent",
            "list_unreachable",
            "silent_gets",
            "reload_ignored",
            "reload_refused",
            "restart_ignored",
            "restart_fails",
            "fail_writes",
            "rollback_fails",
            "second",
            "db_fails",
            "unavailable",
            "garbage",
            "bad_entry",
            "hand_file",
            "hand_reload",
            "rebuild_servers",
            "hand_remove_server",
            "host_down",
            "host_restore_fails",
            "hup_ignored",
        ]
        kind = self.rng.choices(kinds, [weights.get(k, 1) for k in kinds])[0]
        getattr(self, "fault_" + kind)()

    def _timed(self, fake, attr, value, text):
        """Switch a knob of one fake for a few steps and put it back. One fault per knob at a time: two overlapping ones would each restore the OTHER's value."""
        if (fake.host, attr) in self.active_knobs:
            return
        self.active_knobs.add((fake.host, attr))
        old = getattr(fake, attr, None)
        setattr(fake, attr, value)
        duration = self.rng.randint(1, 10)

        def undo(f=fake, a=attr, o=old):
            setattr(f, a, o)
            self.active_knobs.discard((f.host, a))

        self.faults.append((self.step_no + duration, undo, f"{text} on {fake.host}"))
        self.say(f"FAULT {text} on {fake.host} for {duration} steps")

    def _fake(self):
        return self.physical[self.rng.choice(HOSTS)]

    def fault_reload_applied_but_lost(self):
        self._timed(self._fake(), "reload_applied_but_lost", True, "reload_applied_but_lost")

    def fault_api_silent(self):
        self._timed(self._fake(), "api_silent", True, "api_silent")

    def fault_list_unreachable(self):
        self._timed(self._fake(), "list_unreachable", True, "list_unreachable")

    def fault_silent_gets(self):
        self._timed(self._fake(), "silent_gets", self.rng.randint(1, 4), "silent_gets")

    def fault_reload_ignored(self):
        self._timed(self._fake(), "reload_ignored", True, "reload_ignored")

    def fault_reload_refused(self):
        fake = self._fake()
        self._timed(fake, "reload_result", 1, "reload refused")

    def fault_restart_ignored(self):
        self._timed(self._fake(), "restart_ignored", True, "restart_ignored")

    def fault_restart_fails(self):
        self._timed(self._fake(), "restart_ok", False, "restart_ok=False")

    def fault_fail_writes(self):
        fake = self._fake()
        self._timed(fake, "fail_writes_after", fake.writes + self.rng.randint(0, 2), "fail_writes_after")

    def fault_rollback_fails(self):
        self._timed(self._fake(), "rollback_fails", True, "rollback_fails")

    def fault_second(self):
        """The API answers for ANOTHER daemon - only for a Kea no entry is about (an entry made while it lies is the `contradiction` the code names)."""
        fake = self._fake()
        _kind, entries = self.raw_state()
        if any(e.get("ssh_host") == fake.host for e in entries.values()):
            return
        self.i1_open = True  # a Kea that is reloaded while the API lies cannot be SEEN at DEBUG: the first healthy full scan afterwards is what finds it
        other = self.physical[self.rng.choice([h for h in HOSTS if h != fake.host])]
        self._timed(fake, "second", copy.deepcopy(other.loaded), "second (API answers for another daemon)")

    def fault_host_down(self):
        """The helper cannot be asked (SSH to the host fails for its investigation ops): arm is refused, status and disarm do not answer. The host's TIMER does not need Jen to reach it."""
        self._timed(self._fake(), "host_down", True, "host_down (the helper does not answer)")

    def fault_host_restore_fails(self):
        self._timed(self._fake(), "host_restore_fails", True, "host_restore_fails (-t refuses the restored config)")

    def fault_hup_ignored(self):
        self._timed(self._fake(), "hup_ignored", True, "hup_ignored (the daemon does not re-read on SIGHUP)")

    def fault_db_fails(self):
        self.db_fail_budget = self.rng.randint(1, 4)
        self.say(f"FAULT the next {self.db_fail_budget} record write(s) fail")

    def fault_unavailable(self):
        self.world.db["unavailable"] = True
        self.unavailable_until = self.step_no + self.rng.randint(1, 5)
        self.say(f"FAULT settings unavailable until step {self.unavailable_until}")

    def fault_garbage(self):
        value = self.rng.choice(["{broken", "[]", '"x"', "null", '{"servers": []}', '{"servers": "no"}', "{}"])
        self.world.store[inv.RECORD_KEY] = value
        self.exempt_i7 = True
        self.say(f"FAULT the stored record replaced by {value!r}")

    def fault_bad_entry(self):
        kind, entries = self.raw_state()
        if kind != "ok":
            return
        bad = self.rng.choice(
            [
                {"name": "x"},
                {"name": "x", "until": "not-a-date", "file": "debug", "daemon": "debug"},
                {"name": "x", "until": NOW.isoformat(), "file": "debug", "daemon": "debug", "reload_tries": -3},
                {"name": "x", "until": NOW.isoformat(), "file": "debug", "daemon": "debug", "restore": {}},
                None,
            ]
        )
        data = {"servers": {**entries, str(self.rng.choice([2, 3, 7])): bad}}
        self.world.store[inv.RECORD_KEY] = json.dumps(data)
        self.exempt_i7 = True
        self.say("FAULT the stored record gets an entry with a bad field")

    def fault_hand_file(self):
        fake = self._fake()
        how = self.rng.choice(["marker_removed", "severity_changed", "loggers_deleted"])
        section = fake.file.setdefault("Dhcp4", {})
        entry = _logger_of(fake.file)
        if how == "marker_removed" and entry is not None:
            fake.file, _code = ed.clear_investigation_logging(fake.file)
        elif how == "severity_changed" and entry is not None:
            entry["severity"], entry["debuglevel"] = "INFO", 0
        elif how == "loggers_deleted":
            section.pop("loggers", None)
        self.say(f"FAULT a person hand-edited the FILE on {fake.host}: {how}")

    def fault_hand_reload(self):
        fake = self._fake()
        fake.loaded = copy.deepcopy(fake.file)
        self.say(f"FAULT a person reloaded {fake.host} by hand")

    def fault_rebuild_servers(self):
        self.sync()
        self.say("FAULT the server list rebuilt (new dicts, same ids)")

    def fault_hand_remove_server(self):
        """A person hand-edits jen.config and removes a server section (an additional server: the primary is `[kea]`), then Jen reloads. It bypasses every
        route - the removal guard cannot see it - and what the service must then do is flag the entry `removed` and say how to restore the Kea by hand."""
        extras = self._present_extras()
        if not extras:
            return
        gone = self.rng.choice(extras)
        parser = app_config._read_parser()
        parser.remove_section(f"kea_server_{gone['id']}")
        with open(self.path, "w", encoding="utf-8") as f:
            parser.write(f)
        self.sync()
        self.hand_removed.add(str(gone["id"]))
        self.born.pop(str(gone["id"]), None)
        self.say(f"FAULT a person removed server {gone['id']} from jen.config by hand and Jen reloaded")

    # ── operations ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

    def _pick_server(self):
        return self.rng.choice(self.world.servers) if self.world.servers else None

    def _started_damaged(self):
        return self.start_kind != "ok"

    def op_idle(self):
        self.say("idle")

    def op_reload(self):
        self.sync()
        self.say("reload: the server list follows the file")

    def op_turn_on(self):
        server = self._pick_server()
        if server is None:
            return
        minutes = self.rng.choice(inv.DURATIONS)
        sfake, afake = self.ssh_fake(server), self.api_fake(server)
        listed = bool(afake and "config-reload" in afake.commands and not afake.list_unreachable)
        restarts0 = sfake.calls.count("restart:dhcp4") if sfake else 0
        out = inv.turn_on(server, minutes, actor="walk")
        restarts = (sfake.calls.count("restart:dhcp4") if sfake else 0) - restarts0
        self.say(f"turn_on {server['id']} {minutes}m -> ok={out['ok']} {out['lines'][-1][:90] if out['lines'] else ''}")
        self.turn_on_listed = listed
        if out["ok"]:
            state = sfake.helper_state if sfake else None
            if (
                state is None
                or ed._parse_until(state["until"]) != ed._parse_until(out["until"])
                or state["restored_at"]
            ):
                self.fail(
                    "I10",
                    f"turn_on of {server['id']} succeeded and the Kea host is not armed for {out['until']}: {state}",
                )
        if listed and restarts:
            self.fail(
                "I3", f"turn_on of {server['id']} restarted the daemon {restarts}x although it lists config-reload"
            )
        if self._started_damaged() and (out["ok"] or self.applies):
            self.fail("I6/I9", f"turn_on succeeded or wrote to a Kea while the record was {self.start_kind}: {out}")
        self.last_turn_on = (server["id"], listed)
        self._life.pop(
            str(server["id"]), None
        )  # a person pressing Turn on writes a FRESH entry: its counters start over

    def op_turn_off(self):
        server = self._pick_server()
        if server is None:
            return
        out = inv.turn_off(server, actor="walk")
        self.say(f"turn_off {server['id']} -> ok={out['ok']} {out['lines'][-1][:90] if out['lines'] else ''}")
        if self._started_damaged() and (out["ok"] or self.applies or self.writes):
            self.fail(
                "I6/I9",
                f"turn_off acted while the record was {self.start_kind}: {out}, applies={self.applies}, writes={self.writes}",
            )

    def _sweep_checks(self, summary):
        if self.start_kind == "unavailable" and (self.writes or self.applies):
            self.fail("I9", f"a sweep wrote while the settings were unavailable: {self.writes} {self.applies}")
        if self.start_kind == "damaged":
            record_writes = [w for w in self.writes if w[1] == inv.RECORD_KEY]
            if len(record_writes) > 1:
                self.fail(
                    "I6",
                    f"a damaged record was written {len(record_writes)}x in one sweep (the recovery makes ONE final write): {self.writes}",
                )
            if self.applies:
                self.fail("I6", f"a sweep wrote to a Kea while the record was damaged: {self.applies}")
        if self.start_kind == "ok" and summary["adopted"]:
            pass

    def op_sweep(self):
        summary = inv.sweep(now=self.now)
        self.say(
            f"sweep -> restored={summary['restored']} adopted={summary['adopted']} errors={len(summary['errors'])}"
        )
        self._sweep_checks(summary)

    def op_sweep_full(self):
        summary = inv.sweep(now=self.now, full=True)
        self.say(
            f"sweep(full) -> restored={summary['restored']} adopted={summary['adopted']} errors={len(summary['errors'])}"
        )
        self._sweep_checks(summary)
        faulted = any(
            f.api_silent or f.list_unreachable or f.silent_gets or f.second is not None for f in self.physical.values()
        )
        wrote_badly = any(
            not ok for _op, _key, ok in self.writes
        )  # (a write the database refused this very scan is not a scan that took responsibility)
        if (
            self.start_kind != "unavailable"
            and not self.db_fail_budget
            and not faulted
            and not wrote_badly
            and not summary["errors"]
        ):
            self.i1_open = False  # a full scan with a healthy database and every Kea answering has had its chance to take responsibility

    def op_job(self):
        summary = inv.run_sweep_job()
        self.say(f"job -> restored={summary['restored']} adopted={summary['adopted']} errors={len(summary['errors'])}")
        self._sweep_checks(summary)

    def op_forget(self):
        kind, entries = self.raw_state()
        sids = list(entries) or [str(self.rng.choice([1, 2, 3]))]
        sid = self.rng.choice(sids)
        entry = entries.get(sid) or {}
        fixed = False
        host = entry.get("ssh_host")
        honest = all(
            f.second is None for f in self.physical.values()
        )  # (while an API answers for another daemon a person's "look" through it proves nothing)
        if (
            entry
            and host in self.physical
            and (entry.get("removed") or entry.get("contradiction") or not honest or self.rng.random() < 0.6)
        ):
            # a person who restores the Kea BY HAND (file and daemon) and then presses Forget. For a server Jen no longer has (`removed`) Jen cannot look, so
            # Forget there is exactly the person's word: the walk never gives it without having done the work
            fake = self.physical[host]
            fake.file, fake.loaded = copy.deepcopy(self.original[host]), copy.deepcopy(self.original[host])
            fixed = True
        out = inv.forget(sid, actor="walk")
        self.say(f"forget {sid} (by hand first: {fixed}) -> {out}")
        if out:
            self.exempt_i7 = True
            host = entry.get("ssh_host")
            if host in self.physical and at_debug(self.physical[host].loaded) and not entry.get("removed"):
                self.fail("I7", f"forget dropped the entry of {sid} while its Kea is at investigation DEBUG")
        if kind != "ok" and out:
            self.fail("I6", "forget succeeded on an unreadable record")
        rows = self.audits("INVESTIGATION_LOGGING_FORGOTTEN") - self.start_audits["INVESTIGATION_LOGGING_FORGOTTEN"]
        if rows != (1 if out else 0):
            self.fail("I5", f"forget returned {out} and wrote {rows} audit row(s)")

    def op_acknowledge(self):
        if any(at_debug(f.loaded) for f in self.physical.values()):
            self.say("acknowledge: skipped - a person checks every Kea by hand first, and one is at DEBUG")
            return
        all_subnets = self.rng.random() < 0.85
        raw_before = self.world.store.get(inv.RECORD_KEY, "")
        out = inv.acknowledge_damaged("alice", all_subnets=all_subnets)
        rows = (
            self.audits("INVESTIGATION_LOGGING_RECORD_ACKNOWLEDGED")
            - self.start_audits["INVESTIGATION_LOGGING_RECORD_ACKNOWLEDGED"]
        )
        self.say(f"acknowledge(all_subnets={all_subnets}) -> {out}")
        self.exempt_i7 = True
        if rows != (1 if out else 0):
            self.fail("I5", f"acknowledge_damaged returned {out} and wrote {rows} audit row(s)")
        if out:
            if self.world.store.get(inv.RECORD_KEY) != "" or (raw_before and not self.world.store.get(inv.DAMAGED_KEY)):
                self.fail(
                    "I5", "an acknowledged record was not replaced by the empty one, or the old value was not kept"
                )
        elif self.world.store.get(inv.RECORD_KEY, "") != raw_before:
            self.fail("I5", "a refused acknowledgement changed the record")
        if self.start_kind == "unavailable" and out:
            self.fail("I9", "an acknowledgement succeeded while the settings were unavailable")

    def _present_extras(self):
        return [s for s in AppConfig.derive_kea_servers(app_config._read_parser(), quiet=True) if s["id"] != 1]

    def op_removal(self):
        extras = self._present_extras()
        if not extras:
            return self.op_identity()
        server = self.rng.choice(extras)
        sid = server["id"]
        text = inv.removal_refusal([sid], actor="walk")
        rows = (
            self.audits("INVESTIGATION_LOGGING_REMOVAL_REFUSED")
            - self.start_audits["INVESTIGATION_LOGGING_REMOVAL_REFUSED"]
        )
        kind, outstanding = (
            self.raw_state()
        )  # (every entry blocks the removal - a `removed` one too: Jen still owes that Kea its restore)
        expected = kind != "ok" or str(sid) in outstanding
        self.say(f"removal of {sid}: refusal={'yes' if text else 'no'}")
        if bool(text) != expected:
            self.fail(
                "I6",
                f"removal_refusal said {'refuse' if text else 'ok'} for {sid}; the record ({kind}, entries {sorted(outstanding)}) says {'refuse' if expected else 'ok'}",
            )
        if rows != (1 if text else 0):
            self.fail(
                "I5", f"removal_refusal returned {'a sentence' if text else 'nothing'} and wrote {rows} audit row(s)"
            )
        if not text:
            before = self.path.read_bytes()
            try:
                app_config.mutate(lambda p, n=sid: p.remove_section(f"kea_server_{n}"))
            except ConfigChangeRefused as e:
                self.fail("I4", f"removal_refusal allowed removing {sid} and the config writer refused it: {e}")
            if self.path.read_bytes() == before:
                self.fail("walk", "the removal wrote nothing")
            self.say(f"  server {sid} removed from the config")

    def op_identity(self):
        known_before = {s.get("ssh_host") for s in self.world.servers}
        parser = app_config._read_parser()
        before, mode_before = self.identity()
        used = {s["ssh_host"] for s in AppConfig.derive_kea_servers(parser, quiet=True)}
        free = [h for h in HOSTS if h not in used]
        servers = AppConfig.derive_kea_servers(parser, quiet=True)
        target = self.rng.choice(servers)
        sid = target["id"]
        sec_kea, sec_ssh = ("kea", "kea_ssh") if sid == 1 else (f"kea_server_{sid}", f"kea_server_{sid}")
        kind = self.rng.choice(
            ["ssh_host", "ssh_user", "kea_conf", "api_url", "mode", "socket", "remove", "add", "credentials", "same"]
        )
        edits = []  # (section, key, value) - applied through the writer's own callable form

        def put(section, key, value):
            edits.append((section, key, value))

        if kind == "ssh_host" and free:
            # the server is MOVED to another Kea: its API and its SSH host change together (a Kea reached by two different addresses is a misconfiguration the
            # contradiction check names; this walk is about the changes an operator means to make)
            new_host = self.rng.choice(free)
            put(sec_ssh, "host" if sid == 1 else "ssh_host", new_host)
            put(sec_kea, "api_url", f"http://{new_host}:8000")
        elif kind == "ssh_user":
            put(sec_ssh, "user" if sid == 1 else "ssh_user", self.rng.choice(["jen", "kea", "ops"]))
        elif kind == "kea_conf":
            put(sec_ssh, "kea_conf", self.rng.choice([DEFAULT_CONF, "/opt/kea/kea-dhcp4.conf", ""]))
        elif kind == "api_url":
            put(sec_kea, "api_url", f"http://{host_of(target['api_url'])}:{self.rng.choice([8000, 8001, 8002])}")
        elif kind == "mode":
            put("kea", "connection_mode", self.rng.choice(["ca", "direct", "direct"]))
        elif kind == "socket":
            put("kea", "connection_mode", "direct")
            put(sec_kea, "api_url", f"http://{host_of(target['api_url'])}:8004")
        elif kind == "credentials":
            put(sec_kea, "api_pass", "new-" + str(self.step_no))
            put(sec_kea, "name", f"renamed-{self.step_no}")
        elif kind == "add":
            missing = [n for n in (2, 3) if n not in {s["id"] for s in servers}]
            if missing and free:
                n = missing[0]
                put(f"kea_server_{n}", "name", f"kea-{'abc'[n - 1]}")
                put(f"kea_server_{n}", "api_url", f"http://{free[0]}:8000")
                put(f"kea_server_{n}", "ssh_host", free[0])
                put(f"kea_server_{n}", "ssh_user", "jen")
        elif kind == "remove" and sid != 1:
            pass
        if not edits and kind != "remove":
            return self.say(f"identity {kind}: nothing to change")

        def change(p):
            if kind == "remove":
                if p.has_section(f"kea_server_{sid}"):
                    p.remove_section(f"kea_server_{sid}")
                return
            for section, key, value in edits:
                if not p.has_section(section):
                    p.add_section(section)
                p.set(section, key, value)

        # what an INDEPENDENT reading of the stored record says about this change
        probe = configparser.ConfigParser(interpolation=None)
        probe.read_dict({s: dict(parser.items(s)) for s in parser.sections()})
        change(probe)
        after_ids = {str(s["id"]): s for s in AppConfig.derive_kea_servers(probe, quiet=True)}
        after = {
            k: tuple((str(s.get(x) or "").strip() or (DEFAULT_CONF if x == "kea_conf" else "")) for x in IDENTITY_KEYS)
            for k, s in after_ids.items()
        }
        mode_after = probe.get("kea", "connection_mode", fallback="ca").strip().lower()
        mode_after = "direct" if mode_after == "direct" else "ca"
        touched = [k for k in before if k not in after or before[k] != after[k]]
        state, outstanding = self.outstanding()
        if state != "ok":
            expected = bool(touched) or mode_after != mode_before
        else:
            # (a server ADDED under the number of a live entry must name the Kea that entry is about: its recorded SSH host and config path)
            readded = any(
                k in outstanding
                and (
                    (outstanding[k].get("ssh_host") or after[k][1]) != after[k][1]
                    or (outstanding[k].get("kea_conf") or after[k][3]) != after[k][3]
                )
                for k in after
                if k not in before
            )
            expected = (
                (mode_after != mode_before and bool(outstanding)) or any(k in outstanding for k in touched) or readded
            )
        try:
            app_config.preflight_identity_change(change)
            preflight_refused = False
        except ConfigChangeRefused:
            preflight_refused = True
        file_before = self.path.read_bytes()
        refused = False
        try:
            app_config.mutate(change)
        except ConfigChangeRefused:
            refused = True
        rows = (
            self.audits("INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED")
            + self.audits("INVESTIGATION_LOGGING_REMOVAL_REFUSED")
            - self.start_audits["INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED"]
            - self.start_audits["INVESTIGATION_LOGGING_REMOVAL_REFUSED"]
        )
        self.say(
            f"identity {kind} on {sid}: preflight_refused={preflight_refused} refused={refused} expected={expected} audit_rows={rows}"
        )
        if preflight_refused != refused:
            self.fail(
                "I4",
                f"preflight said {'refuse' if preflight_refused else 'ok'} and the write {'refused' if refused else 'went through'}",
            )
        if refused != expected:
            self.fail(
                "I4",
                f"{kind} on server {sid}: the writer {'refused' if refused else 'allowed'} it; the record ({state}, entries {sorted(outstanding)}) "
                f"says it should be {'refused' if expected else 'allowed'}",
            )
        if refused and self.path.read_bytes() != file_before:
            self.fail("I4", "a refused change wrote the file")
        if refused and rows < 2:  # preflight + write each audit
            self.fail("I5", f"a refused identity change wrote {rows} audit rows (expected one per refusal)")
        if not refused and rows != 0:
            self.fail("I5", f"an allowed identity change wrote {rows} refusal audit rows")
        if state == "unavailable" and not refused and touched:
            self.fail("I9", "an identity change went through while the settings were unavailable")
        self.sync()
        if {s.get("ssh_host") for s in self.world.servers} - known_before:
            self.i1_open = True  # a Kea that no server reached has just come into scope: the next healthy full scan is what finds a marker nobody indexed

    def op_file_write(self):
        server = self._pick_server()
        if server is None or not server.get("ssh_host"):
            return
        fake = self.ssh_fake(server)
        if fake is None:
            return
        flavour = self.rng.choice(["without_marker", "keep_marker", "old_config"])
        if flavour == "without_marker":
            candidate, _code = ed.clear_investigation_logging(copy.deepcopy(fake.file))
        elif flavour == "keep_marker":
            candidate = copy.deepcopy(fake.file)
            candidate["Dhcp4"]["subnet4"] = [{"id": self.rng.randint(1, 9), "subnet": "10.1.0.0/24"}]
        else:
            candidate = copy.deepcopy(self.original[fake.host])
        state, everything = self.raw_state()
        sid_here = str(server["id"])

        def same_kea(e):
            conf = e.get("kea_conf") or ""
            return e.get("ssh_host") == server.get("ssh_host") and (
                not conf or conf == (server.get("kea_conf") or DEFAULT_CONF)
            )

        # (Q165, found by the walk) the entry is about a KEA: this server's own live entry, or one under another id that names the same SSH host and config path
        owed = [
            e
            for k, e in everything.items()
            if (k == sid_here and not e.get("removed")) or (k != sid_here and same_kea(e))
        ]
        entry = next((e for e in owed if e.get("file", "debug") == "debug"), None)
        carries = has_marker(candidate)
        # (Q165, edge 2) a candidate that carries a marker whose restore object or deadline is not the one the entry recorded is refused too - compared, not validated
        theirs = (_logger_of(candidate).get("user-context") or {}).get("jen-investigation") if carries else None
        differs = bool(
            entry
            and isinstance(theirs, dict)
            and not ed.validate_investigation_marker(candidate)
            and not entry.get("marker_invalid")
            and (
                ("restore" in entry and theirs.get("restore") != entry["restore"])
                or (
                    not entry.get("deadline_malformed")
                    and ed._parse_until(entry.get("until")) is not None
                    and ed._parse_until(theirs.get("until")) != ed._parse_until(entry.get("until"))
                )
            )
        )
        expected = state != "ok" or bool(entry and entry.get("file", "debug") == "debug" and (not carries or differs))
        res = kea_host.apply_config(
            server, "dhcp4", candidate, summary="walk", source=self.rng.choice(["jen", "restore"])
        )
        refused = res.get("code") == "investigation-on"
        rows = (
            self.audits("INVESTIGATION_LOGGING_FILE_WRITE_REFUSED")
            - self.start_audits["INVESTIGATION_LOGGING_FILE_WRITE_REFUSED"]
        )
        self.say(f"file_write {flavour} on {server['id']}: code={res.get('code')} expected_refusal={expected}")
        if refused != expected:
            self.fail(
                "I8",
                f"a non-investigation write ({flavour}) to server {server['id']} was {'refused' if refused else 'allowed'}; it should be {'refused' if expected else 'allowed'}",
            )
        if rows != (1 if refused else 0):
            self.fail("I5", f"a file write {'refused' if refused else 'allowed'} wrote {rows} audit row(s)")
        if refused and self.applies:
            self.fail("I8", "a refused write reached the wire")

    def op_views(self):
        from jen.services import health

        rows = inv.active(self.now)
        blocked = inv.blocking_removal([1, 2, 3])
        check = health._debug_logging_left_on({})
        kind, _entries = self.raw_state()
        self.say(f"views: {len(rows)} active, {len(blocked)} blocking, health={check.status}")
        if kind != "ok" and check.status != "fail":
            self.fail("I6", f"Health is {check.status} while the record is {kind}")
        if kind != "ok" and not blocked:
            self.fail("I6", "blocking_removal is empty while the record is unreadable")
        # every sentence a person reads is built from an entry, and must be buildable from ANY entry the service can write
        banner, status = inv.record_banner(), inv.recovery_status()
        if banner["damaged"] != (kind != "ok") or not isinstance(status["problems"], list):
            self.fail("I2", f"the Servers page banner says damaged={banner['damaged']} while the record is {kind}")
        for row in rows:
            for text in (
                inv.hand_text(row),
                inv.by_hand(row),
                inv.by_hand_damaged(row),
                inv.by_hand_daemon(row),
                inv.by_hand_running(row),
            ):
                if not isinstance(text, str) or not text:
                    self.fail("no-raise", f"a by-hand sentence for {row['name']} is empty")

    # ── invariants, after EVERY step ───────────────────────────────────────────────────────────────────────────────────────────

    def _narrate(self, kind, entries):
        """What changed this step, in the log: which Kea went to or from investigation DEBUG, which entries appeared or went, how the record's state moved."""
        seen = {h: (at_debug(f.loaded), has_marker(f.file)) for h, f in self.physical.items()}
        for host, now in seen.items():
            was = self._seen_hosts.get(host, (False, False))
            if now != was:
                self.say(f"  > kea {host}: running DEBUG {was[0]}->{now[0]}, file marker {was[1]}->{now[1]}")
        self._seen_hosts = seen
        for host, fake in self.physical.items():
            fresh = fake.calls[self._call_marks.get(host, 0) :]
            self._call_marks[host] = len(fake.calls)
            interesting = [c for c in fresh if c != "config-get" and c != "list-commands"]
            if interesting:
                self.say(f"  > {host} was asked: {interesting}")
        mine = {
            sid: (
                e.get("ssh_host"),
                e.get("file"),
                e.get("daemon"),
                bool(e.get("removed")),
                bool(e.get("contradiction")),
            )
            for sid, e in entries.items()
        }
        for sid in sorted(set(mine) | set(self._seen_entries)):
            if mine.get(sid) != self._seen_entries.get(sid):
                self.say(f"  > entry {sid}: {self._seen_entries.get(sid)} -> {mine.get(sid)}")
        self._seen_entries = mine
        if kind != self._seen_kind:
            self.say(f"  > record: {self._seen_kind} -> {kind}")
            self._seen_kind = kind

    def _invariants(self):
        kind, entries = self.raw_state()
        self._narrate(kind, entries)
        rec = inv._record()
        # I2 - the record is valid or damaged, and a damaged value is kept before anything overwrites it
        if bool(rec["damaged"] or rec.get("unavailable")) != (kind != "ok"):
            self.fail(
                "I2",
                f"_record() says damaged={rec['damaged']} unavailable={rec.get('unavailable')}; the stored value says {kind}",
            )
        raw = self.world.store.get(inv.RECORD_KEY, "")
        if (
            self.prev_kind == "damaged"
            and self.prev_raw
            and raw != self.prev_raw
            and not self.exempt_i7
            and not self.world.store.get(inv.DAMAGED_KEY)
        ):
            self.fail(
                "I2",
                f"a damaged record {self.prev_raw!r} was overwritten and its value was not kept in {inv.DAMAGED_KEY}",
            )
        # I9 - nothing is written while the settings cannot be read
        if kind == "unavailable" and self.start_kind == "unavailable" and (self.writes or self.applies):
            self.fail("I9", f"writes while the settings were unavailable: {self.writes} {self.applies}")
        # I8 - the marker leaves a file only inside investigation_writer()
        # ... on a Kea some entry is about. (A marker that NO entry knows - the record was rebuilt without the server, which then came into scope - is the
        # ten-minute scan's to find; until it does, a restore/import/authoring write could erase it. That window is named in ARCHITECTURE, not closed here.)
        owed = {
            e.get("ssh_host")
            for e in self.start_entries.values()
            if not e.get("removed") and e.get("file", "debug") == "debug"
        }
        for host, flag in self.marker_removals:
            if flag:
                continue
            if host in owed:
                self.fail(
                    "I8",
                    f"a non-investigation write (op {self.op}) removed the marker from {host}, which an entry says Jen owes a restore",
                )
            self.say(f"  > a non-investigation write removed a marker no entry knows from {host} (the scan's to find)")
        # I4 - identity is frozen while state is outstanding
        ident, mode = self.identity()
        for sid, entry in entries.items():
            if entry.get("removed"):
                self.born.pop(sid, None)
                continue
            if ident.get(sid) is None:
                continue  # an entry whose server is not in the config: nothing to hold the identity of
            born = self.born.setdefault(sid, {"ident": ident.get(sid), "mode": mode, "step": self.step_no})
            if ident.get(sid) != born["ident"] and ident.get(sid) is not None:
                self.fail(
                    "I4",
                    f"server {sid}'s identity {ident.get(sid)} differs from {born['ident']} when its entry was created (step {born['step']})",
                )
            if ident.get(sid) is not None and entry.get("ssh_host") != ident[sid][1]:
                self.fail(
                    "I4",
                    f"the entry for {sid} was recorded against {entry.get('ssh_host')} and the server now points at {ident[sid][1]}",
                )
        if kind == "ok":
            for sid in [s for s in self.born if s not in entries]:
                del self.born[sid]
        if kind != "ok":
            if self.frozen is None:
                self.frozen = (self.prev_ident, self.prev_mode)
            for sid, was in self.frozen[0].items():
                if ident.get(sid) is not None and ident.get(sid) != was and sid not in self.hand_removed:
                    self.fail(
                        "I4", f"server {sid}'s identity changed while the record was {kind}: {was} -> {ident.get(sid)}"
                    )
            if mode != self.frozen[1]:
                self.fail("I4", f"the connection mode changed while the record was {kind}")
        else:
            self.frozen = None
        self.prev_ident, self.prev_mode = ident, mode
        # I7 - an entry that disappears means a daemon that was seen restored
        if kind == "ok" and self.prev_kind == "ok" and not self.exempt_i7:
            for sid, was in self.prev_entries.items():
                if sid in entries:
                    continue
                host = was.get("ssh_host")
                fake = self.physical.get(host)
                if fake is None:
                    continue
                if at_debug(fake.loaded):
                    self.fail(
                        "I7",
                        f"the entry for server {sid} ({host}) was dropped while that Kea is at investigation DEBUG",
                    )
                if host not in self.answered_get and self.op not in ("forget",):
                    self.fail(
                        "I7",
                        f"the entry for server {sid} ({host}) was dropped in a step in which that Kea answered no config-get (op {self.op})",
                    )
        # I1 - no DEBUG without responsibility
        if kind == "ok" and not self.i1_open:
            known_hosts = {s.get("ssh_host") for s in self.world.servers}
            for host, fake in self.physical.items():
                if not at_debug(fake.loaded):
                    continue
                mine = [e for e in entries.values() if e.get("ssh_host") == host]
                if not mine and host not in known_hosts:
                    continue  # a Kea no server of Jen's reaches any more: a rebuilt record cannot find what it was never told about (the old value is kept)
                if not mine:
                    self.fail(
                        "I1",
                        f"the Kea at {host} runs investigation DEBUG and no stored entry is responsible for it (entries: {sorted(entries)})",
                    )
                flagged = [e for e in mine if e.get("removed") or e.get("contradiction")]
                if flagged and len(flagged) == len(mine):
                    from jen.services import health

                    check = health._debug_logging_left_on({})
                    if check.status != "fail" or not any(e["name"] in check.detail for e in flagged):
                        self.fail(
                            "I1",
                            f"{host} is at DEBUG under a removed/contradiction entry and Health does not fail naming it: {check.status} {check.detail[:200]}",
                        )
        # I3 - the daemon step is bounded
        self._i3(entries, kind)
        # I10 - DEBUG never outlives its deadline (v5.68.0-beta.29, Q165)
        self._i10()
        self.prev_entries = entries if kind == "ok" else {}
        self.prev_kind, self.prev_raw = kind, raw

    I10_GRACE_S = 120  # the host's timer fires every 60 s; this is the allowance past the deadline

    def _i10(self):
        """I10 - DEBUG never outlives its deadline. A daemon whose RUNNING config is at investigation DEBUG with the marker, for a session the Kea host was armed for, is
        restored within `I10_GRACE_S` of the marker's own `until` - read from the daemon, not from Jen's record - whatever happened to Jen: its database unavailable or
        holding garbage, an identity changed under the entry, no sweep at all. The one thing that excuses a late restore is the host itself failing (its `-t` refuses the
        restored config, the daemon ignores SIGHUP and cannot be restarted), and then the host's state file must SAY so (`last_error`): a failure is reported, never silent."""
        for host, fake in self.physical.items():
            if not at_debug(fake.loaded):
                continue
            context = _logger_of(fake.loaded).get("user-context") or {}
            due = ed._parse_until((context.get("jen-investigation") or {}).get("until"))
            state = fake.helper_state
            if due is None or state is None or ed._parse_until(state["until"]) != due:
                continue  # a session the host was never armed for: the host has no promise to keep
            late = (self.now - due).total_seconds()
            if late <= self.I10_GRACE_S:
                continue
            failing = fake.host_restore_fails or (
                (fake.reload_ignored or fake.hup_ignored) and (state["restarts"] >= 1 or not fake.restart_ok)
            )
            retrying = getattr(fake, "last_failed_tick", None)
            retrying = (
                retrying is not None and (self.now - retrying).total_seconds() <= self.I10_GRACE_S
            )  # (the fault just ended: the next tick retries)
            if (failing or retrying) and state["last_error"] and not state["restored_at"]:
                continue
            self.fail(
                "I10",
                f"the Kea at {host} is still at investigation DEBUG {late:.0f} s after its deadline {due.isoformat()}; the host's state: {state}, host timer running: "
                f"{fake.timer_running and self.HOST_TIMER}",
            )

    def _new_life(self, entry):
        return {"host": entry.get("ssh_host"), "auto_restarts": 0, "auto_reloads": 0}

    def _i3(self, entries, kind):
        """The daemon step is bounded. What the AUTOMATIC operations (the sweep and the scheduler job) ask of one daemon during one entry's lifetime: at most
        ONE restore attempt (a failed one is two restart calls: the restart and the change set's rollback restart) and at most RELOAD_TRIES reloads - "Jen keeps trying every minute" is for a person to read, never a restart a minute. A person pressing Turn on
        or Turn off is not counted (each press is the person's act); a turn-on of a daemon that lists config-reload never restarts it (checked in `op_turn_on`)."""
        if kind != "ok":
            return
        for sid in [s for s in self._life if s not in entries]:
            del self._life[sid]
        for sid, entry in entries.items():
            life = self._life.setdefault(sid, self._new_life(entry))
            fake = self.physical.get(life["host"])
            if any(not ok for _op, _key, ok in self.writes):
                life["db_failed"] = (
                    True  # the bound is read from the STORED entry: an attempt the database did not record is not counted by the next one
                )
            if fake is None or life.get("db_failed") or self.op not in ("sweep", "sweep_full", "job"):
                continue
            now = self._counts(fake)
            then = self.start_counts[life["host"]]
            life["auto_restarts"] += now[0] - then[0]
            life["auto_reloads"] += now[1] - then[1]
            if life["auto_restarts"] > 2:
                self.fail(
                    "I3",
                    f"server {sid} ({life['host']}): the sweep restarted the daemon {life['auto_restarts']}x for one entry (allowed 2: one restore attempt and, when it fails, the change set's rollback restart)",
                )
            if life["auto_reloads"] > inv.RELOAD_TRIES:
                self.fail(
                    "I3",
                    f"server {sid} ({life['host']}): the sweep asked for {life['auto_reloads']} config-reloads for one entry (allowed {inv.RELOAD_TRIES})",
                )


@pytest.fixture
def walk_world(world, monkeypatch, tmp_path):
    return lambda seed, steps, **kw: Walk(seed, steps, world, tmp_path, monkeypatch, **kw)


def _seeds():
    if ONLY_SEED is not None:
        return [int(ONLY_SEED)]
    return list(range(SEEDS))


_WALK_CLOCK = {"seconds": 0.0, "seeds": 0}


class TestTheWalk:
    @pytest.mark.parametrize("seed", _seeds())
    def test_walk(self, seed, walk_world):
        started = time.monotonic()
        walk_world(seed, STEPS).run()
        _WALK_CLOCK["seconds"] += time.monotonic() - started
        _WALK_CLOCK["seeds"] += 1

    def test_the_walk_fits_its_budget(self):
        """CI runs 40 seeds x 400 steps and the budget is 60 s (drop steps before seeds if it grows): the elapsed time of the walks above, printed so a slow
        creep shows in the log. The assertion has a 2x margin for a slow runner and only applies to the default scale."""
        print(
            f"MODEL WALK: {_WALK_CLOCK['seeds']} seeds x {STEPS} steps in {_WALK_CLOCK['seconds']:.1f} s (budget 60 s)"
        )
        if _WALK_CLOCK["seeds"] == 40 and STEPS == 400:
            assert _WALK_CLOCK["seconds"] < 120, f"the walk took {_WALK_CLOCK['seconds']:.0f} s"

    #: Every public function of the service, and how the walk reaches it: an operation (`op_<name>` mentions it) or the reason it is reached only through another.
    COVERAGE = {
        "active": "op:views",
        "hand_text": "op:views",
        "daemon_logger": "through observe, which every turn_on, turn_off and sweep calls",
        "observe": "through turn_on / turn_off / sweep",
        "observe_from": "through the damaged-record recovery (sweep while damaged)",
        "turn_on": "op:turn_on",
        "turn_off": "op:turn_off",
        "helper_gate": "through turn_on (the build check before anything is written)",
        "blocking_removal": "op:views",
        "removal_refusal": "op:removal",
        "identity_guard": "through the config writer: op:identity (preflight_identity_change and mutate)",
        "endpoint_change_refusal": "the same engine as the writer's guard; driven by tests/test_investigation_logging.py::TestAnEndpointChangeKeepsTheServerIdentity",
        "file_write_refusal": "through kea_host.apply_config: op:file_write",
        "forget": "op:forget",
        "marker_invalid_text": "through the sweep's full scan and the restore of a damaged marker",
        "by_hand_damaged": "op:views",
        "by_hand": "op:views",
        "by_hand_daemon": "op:views",
        "by_hand_running": "op:views",
        "record_banner": "op:views",
        "recovery_status": "op:views",
        "acknowledge_damaged": "op:acknowledge",
        "sweep": "op:sweep",
        "run_sweep_job": "op:job",
    }

    def test_every_public_function_of_the_service_is_reached_by_the_walk_or_says_how(self):
        import ast
        import inspect
        import pathlib

        tree = ast.parse((pathlib.Path(inv.__file__)).read_text(encoding="utf-8"))
        public = {n.name for n in tree.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")}
        print(f"PUBLIC FUNCTIONS of investigation_logging.py ({len(public)}): {', '.join(sorted(public))}")
        missing = public - set(self.COVERAGE)
        assert not missing, (
            f"new public functions the walk does not know about - add an operation or say how it is reached: {sorted(missing)}"
        )
        stale = set(self.COVERAGE) - public
        assert not stale, f"coverage entries for functions that no longer exist: {sorted(stale)}"
        walk_source = inspect.getsource(Walk)
        for name, how in self.COVERAGE.items():
            if how.startswith("op:"):
                op = how[3:].split()[0]
                assert f"def op_{op}(" in walk_source, f"{name}: the walk has no operation {op!r}"
                body = inspect.getsource(getattr(Walk, f"op_{op}"))
                assert name in body or name in (
                    "hand_text",
                    "by_hand",
                    "by_hand_damaged",
                    "by_hand_daemon",
                    "by_hand_running",
                    "identity_guard",
                    "file_write_refusal",
                ), f"{name}: op_{op} does not call it"


class TestTheKeaHostKeepsTheDeadline:
    """I10 (v5.68.0-beta.29, Q165): a daemon the Kea host was armed for is never at investigation DEBUG more than 120 s past its deadline - with Jen alive, or not running at all.
    The mutation check is the first test: take the HostTimer actor away and the same walks go red. (In a probe of 30 seeds, 21 went red without the timer; the ten named here all did.)"""

    STEPS = 400
    RED_WITHOUT_THE_TIMER = list(range(10))

    @pytest.mark.parametrize("seed", RED_WITHOUT_THE_TIMER)
    def test_i10_is_red_when_the_hosts_timer_is_taken_away(self, seed, walk_world, monkeypatch):
        monkeypatch.setattr(Walk, "HOST_TIMER", False)
        with pytest.raises(InvariantViolated) as red:
            walk_world(seed, self.STEPS, jen_dead_from=self.STEPS // 3).run()
        assert "I10 violated" in str(red.value)

    @pytest.mark.parametrize("seed", RED_WITHOUT_THE_TIMER + list(range(10, 24)))
    def test_with_jen_stopped_after_a_third_of_the_walk_every_session_is_still_restored(self, seed, walk_world):
        walk_world(seed, self.STEPS, jen_dead_from=self.STEPS // 3).run()

    def test_the_grace_is_two_timer_periods_not_a_loophole(self):
        assert Walk.I10_GRACE_S == 120 and Walk.HOST_TIMER is True


class TestSeedsThatCaughtARealDefect:
    """A seed that failed during development stays as a fixed regression (Q163 self-check c). Under the harness as shipped these four are the walks that go red
    when the fix of a defect the walk found is taken out again (the mutation check): 13 and 165 when the restore's one restart is unbounded, 24 and 98 when
    an entry is acted on through whichever server now has its id. 98 and 165 lie outside the 40 seeds CI runs, which is why they are named here."""

    @pytest.mark.parametrize("seed", [13, 24, 98, 165])
    def test_the_walk_that_found_it_stays_green(self, seed, walk_world):
        walk_world(seed, STEPS).run()


# ── the Explain walk (E1): the log evidence of ONE request is one coherent snapshot, however the configuration moves under it ─────────────────────


def _log_head(ts, level, msg_id, mac, cid, tid):
    return f"2026-10-04 {ts} {level:<5} [kea-dhcp4.test/1.1] {msg_id} [hwtype=1 {mac}], cid=[{cid}], tid={tid}"


def _exchange_lines(mac, host, complete=True, stale=False):
    """One client's exchange as host `host`'s log shows it. Everything that names the host - the class list, the packet dump's hostname, the client id, the
    tid - carries it, so a view assembled from two servers' lines is visible in the view itself."""
    n = host.rsplit(".", 1)[-1]
    tid, cid = f"0x{int(n):x}", f"01:aa:bb:cc:dd:{int(n):02x}"
    at = "10:00:00.110" if not stale else "09:00:00.110"
    lines = [
        _log_head(at, "INFO", "DHCP4_PACKET_RECEIVED", mac, cid, tid)
        + ": DHCPREQUEST (type 3) received from 0.0.0.0 to 255.255.255.255"
    ]
    if complete:
        lines.append(
            _log_head(at, "DEBUG", "DHCP4_CLASSES_ASSIGNED", mac, cid, tid)
            + f": client packet has been assigned on DHCPREQUEST message to the following classes: ALL, SRV-{host}"
        )
        lines += [
            _log_head(at, "DEBUG", "DHCP4_QUERY_DATA", mac, cid, tid)
            + ", packet details: local_address=10.1.0.218:67,",
            "msg_type=DHCPREQUEST (3), trans_id=0x1,",
            "options:",
            f'  type=012, len={len(host) + 5:03d}: "host-{host}" (string)',
        ]
    return lines, tid, cid


class ExplainWalk:
    """A seeded walk over `explain_context.read_log`: servers come, go and move between hosts; each host's log answers well, fails in one of four ways, or hangs
    past the budget; and the configuration is RELOADED (new dicts, same ids, possibly different hosts or names) from inside a tail - while `read_log` is in the
    middle of its request. After every request, E1: the view's server, its class list, its packet hostname, its client id and its tid all come from ONE host and
    that host is the one the SNAPSHOT of the request named for that server id; every server whose read failed or hung is named, and no healthy one is."""

    MAC = "aa:bb:cc:dd:ee:01"

    def __init__(self, seed, steps, monkeypatch):
        import threading

        self.seed, self.steps = seed, steps
        self.rng = random.Random(seed)
        self.log: list[str] = []
        self.gate = threading.Event()
        self.lock = threading.Lock()
        self.inflight = 0
        self.mode: dict = {}
        self.reload_plan = None
        self.step_no = 0
        self.gen = 0
        self._build(monkeypatch)

    def _build(self, monkeypatch):
        from jen.services import log_tail

        ctx.clear_log_cache()
        log_tail.clear()
        monkeypatch.setattr(ctx, "EVIDENCE_BUDGET_S", 0.3)
        monkeypatch.setattr(ctx, "HA_PROBE_BUDGET_S", 0.2)
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: None)
        monkeypatch.setattr("jen.services.config_revisions.latest", lambda server_id, service: None)
        monkeypatch.setattr("jen.services.kea_host.tail_log", self._tail)
        monkeypatch.setattr("jen.services.kea_ha.ha_status", self._ha)
        self.hosts = [f"10.0.0.{n}" for n in range(1, 7)]
        count = self.rng.randint(1, 4)
        chosen = self.rng.sample(self.hosts, count)
        self.servers = [self._server(i + 1, h) for i, h in enumerate(chosen)]
        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(s) for s in self.servers])
        self.monkeypatch = monkeypatch
        real_pool = ctx._pool

        def pool(ssh_servers=0):
            # the first thing `read_log` does AFTER it took its snapshot of the configuration is hand the tails to the pool - on the request's own thread, so a reload
            # here is exactly "the configuration changed in the middle of a request", deterministically (a reload from a pool thread races the code that reads it)
            if self.reload_plan == "pool":
                self.reload_plan = None
                self._reload()
            return real_pool(ssh_servers)

        monkeypatch.setattr(ctx, "_pool", pool)

    def _server(self, sid, host):
        self.gen += 1
        return {"id": sid, "name": f"kea-{sid}-g{self.gen}", "ssh_host": host}

    def _ha(self, server):
        pick = self.rng.random()
        if pick < 0.3:
            return None
        return {
            "local": {"role": "primary", "scopes": ["server1"] if pick < 0.6 else [], "state": "hot-standby"},
            "remote": {},
        }

    def _reload(self):
        """Replace the loaded configuration - a new list of new dicts, ids kept, hosts and names possibly changed, a server possibly gone or added."""
        current = [dict(s) for s in extensions.KEA_SERVERS]
        kind = self.rng.choice(["rebuild", "move", "rename", "drop", "add"])
        if kind == "move" and current:
            s = self.rng.choice(current)
            free = [h for h in self.hosts if h not in {x["ssh_host"] for x in current}]
            if free:
                s["ssh_host"] = self.rng.choice(free)
        elif kind == "rename" and current:
            self.rng.choice(current)["name"] += "-renamed"
        elif kind == "drop" and len(current) > 1:
            current.pop(self.rng.randrange(len(current)))
        elif kind == "add":
            free = [h for h in self.hosts if h not in {x["ssh_host"] for x in current}]
            if free:
                current.append(self._server(max([s["id"] for s in current] + [0]) + 1, free[0]))
        self.say(f"  RELOAD ({kind}) while the request is in flight: {[(s['id'], s['ssh_host']) for s in current]}")
        extensions.KEA_SERVERS = current

    def _tail(self, server, path, lines, timeout=None, helper_only=False):
        with self.lock:
            self.inflight += 1
            plan = self.reload_plan == "tail"
            if plan:
                self.reload_plan = None
        try:
            if plan:
                self._reload()
            host = server.get("ssh_host")
            mode = self.mode.get(host, "ok")
            if mode == "hang":
                self.gate.wait(10)
                return {"ok": False, "code": "error", "detail": "released"}
            if mode == "ok":
                body, _tid, _cid = _exchange_lines(self.MAC, host, complete=self.complete.get(host, True))
                return {"ok": True, "code": "ok", "lines": body}
            if mode == "no-exchange":
                return {"ok": True, "code": "ok", "lines": []}
            if mode == "no-helper":
                return {"ok": False, "code": "no-helper", "detail": "not installed"}
            if mode == "missing":
                return {"ok": False, "code": "missing", "detail": "no log"}
            if mode == "transport":
                return {"ok": False, "code": "error", "detail": "ssh refused", "transport": True}
            return {"ok": False, "code": "error", "detail": "read failed"}
        finally:
            with self.lock:
                self.inflight -= 1

    def say(self, text):
        self.log.append(f"[{self.step_no:3d}] {text}")

    def fail(self, name, detail):
        raise InvariantViolated(
            f"\n{name} violated at step {self.step_no} (explain seed {self.seed}): {detail}\n"
            f"reproduce: JEN_MODEL_SEED={self.seed} pytest --noconftest tests/test_investigation_model.py -q -k explain\n--- log ---\n"
            + "\n".join(self.log[-40:])
        )

    def run(self):
        for n in range(self.steps):
            self.step_no = n
            ctx.clear_log_cache()
            from jen.services import log_tail

            log_tail.clear()
            self.gate.clear()
            snap = {s["id"]: dict(s) for s in extensions.KEA_SERVERS}
            self.mode = {}
            self.complete = {}
            for host in self.hosts:
                roll = self.rng.random()
                self.mode[host] = (
                    "ok"
                    if roll < 0.55
                    else "no-exchange"
                    if roll < 0.65
                    else "error"
                    if roll < 0.75
                    else "no-helper"
                    if roll < 0.82
                    else "missing"
                    if roll < 0.9
                    else "transport"
                    if roll < 0.99
                    else "hang"
                )
                self.complete[host] = self.rng.random() < 0.8
            self.reload_plan = self.rng.choice([None, "pool", "pool", "tail"])
            self.say(
                f"request: {sorted((i, s['ssh_host'], self.mode[s['ssh_host']]) for i, s in snap.items())} reload_planned={self.reload_plan}"
            )
            view = ctx.read_log(self.MAC, allowed=True)
            self.gate.set()
            deadline = time.monotonic() + 5
            while self.inflight and time.monotonic() < deadline:
                time.sleep(0.002)
            self._e1(view, snap)

    def _e1(self, view, snap):
        by_host = {s["ssh_host"]: s for s in snap.values()}
        failed = {
            s["name"]
            for s in snap.values()
            if self.mode[s["ssh_host"]] in ("error", "no-helper", "missing", "transport")
        }
        slow = {s["name"] for s in snap.values() if self.mode[s["ssh_host"]] == "hang"}
        named_failed = {f["server"] for f in view.get("read_failures", [])}
        named_slow = set(view.get("not_checked", []))
        if not failed <= named_failed:
            self.fail(
                "E1", f"servers whose read failed are not named: missing {sorted(failed - named_failed)}; view {view}"
            )
        if not slow <= named_slow:
            self.fail(
                "E1",
                f"servers that did not answer in time are not named: missing {sorted(slow - named_slow)}; view {view}",
            )
        healthy = {s["name"] for s in snap.values() if self.mode[s["ssh_host"]] in ("ok", "no-exchange")}
        if (named_failed | named_slow) & healthy:
            self.fail(
                "E1", f"a server that answered is named as failed: {sorted((named_failed | named_slow) & healthy)}"
            )
        tx = view.get("transaction")
        if not tx:
            return
        server = view.get("server") or {}
        mine = snap.get(server.get("id"))
        if mine is None:
            self.fail("E1", f"the view names server {server} which the request's snapshot does not have")
        host = mine["ssh_host"]
        if server.get("name") != mine["name"]:
            self.fail(
                "E1",
                f"the view names {server.get('name')!r}; the snapshot's name for server {server['id']} is {mine['name']!r}",
            )
        _lines, tid, cid = _exchange_lines(self.MAC, host)
        if tx["tid"] != tid:
            self.fail(
                "E1",
                f"the view's transaction {tx['tid']} is not the one host {host} logged ({tid}): a view from two servers",
            )
        if view.get("classes") and f"SRV-{host}" not in view["classes"]["classes"]:
            self.fail("E1", f"the class list {view['classes']['classes']} is not host {host}'s")
        if view.get("query") and view["query"].get("hostname") != f"host-{host}":
            self.fail("E1", f"the packet's hostname {view['query'].get('hostname')!r} is not host {host}'s")
        if view.get("cid") and view["cid"].get("client_id") != cid:
            self.fail("E1", f"the client id {view['cid']} is not host {host}'s ({cid})")
        _ = by_host


@pytest.fixture
def explain_world(monkeypatch):
    holder = {}

    def make(seed, steps):
        w = ExplainWalk(seed, steps, monkeypatch)
        holder["w"] = w
        return w

    yield make
    w = holder.get("w")
    if w is not None:
        w.gate.set()
        deadline = time.monotonic() + 5
        while w.inflight and time.monotonic() < deadline:
            time.sleep(0.002)
    ctx.clear_log_cache()
    from jen.services import log_tail

    log_tail.clear()


EXPLAIN_SEEDS = int(os.environ.get("JEN_MODEL_EXPLAIN_SEEDS", "16"))
EXPLAIN_STEPS = int(os.environ.get("JEN_MODEL_EXPLAIN_STEPS", "50"))


class TestTheExplainWalk:
    @pytest.mark.parametrize("seed", [int(ONLY_SEED)] if ONLY_SEED is not None else list(range(EXPLAIN_SEEDS)))
    def test_explain_walk(self, seed, explain_world):
        explain_world(seed, EXPLAIN_STEPS).run()


# ── the six reviews, as sequences: what the walk would have caught ────────────────────────────────────────────────────────────────────────────────


class TestTheWalkWouldHaveCaught:
    """Six reviews in a row found a P1 that was a SEQUENCE. Each is written here as the hand sequence that composes it, asserting the INVARIANT it broke
    (named in the docstring). Each was RUN against the release it was found in (a git worktree of the tag, this class copied in) and FAILED there; the
    report lists which. They pass on this code."""

    @staticmethod
    def _on_at_debug(fake):
        return at_debug(fake.loaded)

    def test_beta21_a_failed_reload_is_never_followed_by_a_restart__I3(self, world):
        """beta.21 (Q156): `list-commands` answered, `config-reload` failed, and the NEXT call to the same API failing made turn-on restart kea-dhcp4 over SSH.
        I3: turning logging ON never restarts a daemon that lists config-reload."""
        kea = world.daemons[1]
        kea.reload_result = 1
        out = inv.turn_on(world.servers[0], 5, actor="alice")
        assert out["ok"] is False
        assert kea.calls.count("restart:dhcp4") == 0, (
            f"turn-on restarted a daemon that lists config-reload: {kea.calls}"
        )
        assert not has_marker(kea.file) and not inv.active(), (
            "the file is back and there is no entry for a change that never happened"
        )

    def test_beta22_a_reload_that_applied_with_its_reply_lost_leaves_an_entry__I1(self, world):
        """beta.22 (Q157): Kea APPLIED the reload and the reply was lost; Jen called it a failure, put the file back and dropped the entry - the daemon stayed at
        DEBUG 55 with nothing that knew. I1: a Kea running investigation DEBUG always has a stored entry responsible for it."""
        kea = world.daemons[1]
        kea.reload_applied_but_lost = True
        inv.turn_on(world.servers[0], 5, actor="alice")
        assert self._on_at_debug(kea), "the lost-reply reload took effect"
        entries = _stored_servers(world)
        assert "1" in entries, "I1: the daemon is at DEBUG and no stored entry is responsible for it"
        kea.reload_applied_but_lost = False
        out = inv.sweep(now=NOW + timedelta(minutes=10))
        assert out["restored"] == ["kea-a"] and not self._on_at_debug(kea) and not inv.active()
        assert kea.calls.count("restart:dhcp4") == 0, "and finishing it never needed a restart"

    @pytest.mark.usefixtures("legacy_entries")
    def test_beta23_a_daemon_that_ignores_reloads_and_restarts_is_not_asked_every_minute__I3(self, world):
        """beta.23 (Q158, before its fixup): the file was restored, the daemon ignored both a reload and a restart and stayed at DEBUG 55 - and the sweep asked
        again every minute, for ever. I3: the daemon step is bounded (RELOAD_TRIES reloads, ONE restart per entry), then a person is told."""
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.reload_ignored = kea.restart_ignored = True
        before = (kea.calls.count("config-reload"), kea.calls.count("restart:dhcp4"))
        inv.turn_off(world.servers[0])
        for minute in range(1, 16):
            inv.sweep(now=NOW + timedelta(minutes=10 + minute))
        reloads = kea.calls.count("config-reload") - before[0]
        restarts = kea.calls.count("restart:dhcp4") - before[1]
        assert restarts <= 1, f"{restarts} restarts of a daemon that ignores them"
        assert reloads <= getattr(inv, "RELOAD_TRIES", 3) + 1, f"{reloads} reloads"
        assert self._on_at_debug(kea) and inv.active()[0]["needs_hand"], (
            "and the entry stays, saying a person has to act"
        )

    def test_beta24_a_damaged_record_is_not_rebuilt_from_the_servers_that_could_be_read__I1_I2(self, world):
        """beta.24 (Q159): the rebuild adopted what it found as it found it, and the first write cleared the damage - one adopted server plus one unreadable
        server left a healthy record with ONE entry while the unreadable one might be at DEBUG 55; and a clean file whose daemon could not be read counted as
        examined. I2 + I1: the record stays unreadable until every server's file AND daemon were examined, then ONE write stores everything."""
        damaged = "{this was the record"
        world.store[inv.RECORD_KEY] = damaged
        a, b = world.daemons[1], world.daemons[2]
        cfg, _ = ed.set_investigation_logging(a.file, FUTURE)
        a.file = a.loaded = cfg  # server A is at DEBUG with the marker in its file
        real = inv._host.read_config_versioned

        def b_unreadable(server, service):
            if server["id"] == 2:
                raise OSError("no route to host")
            return real(server, service)

        inv._host.read_config_versioned = b_unreadable
        try:
            out = inv.sweep(now=NOW, full=True)
        finally:
            inv._host.read_config_versioned = real
        assert world.store[inv.RECORD_KEY] == damaged, "nothing was written: server B could not be examined"
        assert inv._record()["damaged"] is True and out["errors"]
        b.api_silent = True  # B readable again, but its daemon cannot be seen: not examined either
        inv.sweep(now=NOW + timedelta(minutes=1), full=True)
        assert world.store[inv.RECORD_KEY] == damaged, "a daemon that could not be read is not an examined one"
        b.api_silent = False
        inv.sweep(now=NOW + timedelta(minutes=2), full=True)
        assert inv._record()["damaged"] is False and "1" in _stored_servers(world), (
            "now every server was examined: ONE write stores what was found"
        )

    def test_beta25_a_server_cannot_be_removed_while_the_record_is_unreadable_and_zero_servers_is_not_a_clean_bill__I6_I1(
        self, world
    ):
        """beta.25 (Q160): `blocking_removal` read the damaged record's EMPTY server map and let a server that might be at DEBUG 55 be removed; and with no
        SSH server at all the rebuild examined nothing and wrote an empty healthy record. I6: an unreadable record refuses removal. I1: 'nothing examined' is
        never 'nothing found'."""
        damaged = "{broken"
        world.store[inv.RECORD_KEY] = damaged
        assert inv.removal_refusal([2]) != "", (
            "I6: removal was allowed while the record cannot say whether the server is at DEBUG"
        )
        world.servers.clear()
        inv.sweep(now=NOW, full=True)
        assert world.store[inv.RECORD_KEY] == damaged and inv._record()["damaged"] is True, (
            "I1: zero servers examined is not a healthy empty record"
        )

    def test_beta26_a_server_with_an_entry_keeps_its_identity_and_the_recovery_writes_only_what_it_can_read__I4_I2_I5(
        self, world, tmp_path, monkeypatch
    ):
        """beta.26 (Q161): (I4) the same server id pointed at a different SSH host passed the removal guard, so every later restore went to a different Kea;
        (I2) a rebuilt entry whose deadline did not parse was written and then read back as damaged, for ever; (I5) the acknowledgement of an unreadable
        record and its audit row were two commits, so the record could be replaced with no durable note of who said so."""
        import jen.config as jconfig

        ini = configparser.ConfigParser(interpolation=None)
        ini["kea"] = {"api_url": "http://10.0.0.1:8000", "api_user": "u", "api_pass": "p"}
        ini["kea_ssh"] = {"host": "10.0.0.1", "user": "jen"}
        ini["jen_db"] = {"host": "h", "user": "u", "password": "p"}
        path = tmp_path / "jen.config"
        with open(path, "w", encoding="utf-8") as f:
            ini.write(f)
        monkeypatch.setattr(extensions, "CONFIG_FILE", str(path))
        monkeypatch.setattr(app_config, "reload", lambda: None)
        assert inv.turn_on(world.servers[0], 5)["ok"]
        refused = getattr(jconfig, "ConfigChangeRefused", ())
        try:
            app_config.write_values([("kea_ssh", "host", "10.9.9.9")])
            wrote = True
        except refused:
            wrote = False
        assert wrote is False, "I4: the SSH host of a server with an entry was pointed at a different Kea"
        assert inv.turn_off(world.servers[0])["ok"]
        # (I2) a marker whose deadline is not a date, in a server's file, with the record unreadable
        world.store[inv.RECORD_KEY] = "{broken"
        cfg, _ = ed.set_investigation_logging(world.daemons[2].file, FUTURE)
        next(x for x in cfg["Dhcp4"]["loggers"] if x["name"] == "kea-dhcp4")["user-context"]["jen-investigation"][
            "until"
        ] = "not-a-date"
        world.daemons[2].file = world.daemons[2].loaded = cfg
        inv.sweep(now=NOW, full=True)
        inv.sweep(now=NOW + timedelta(minutes=1), full=True)
        assert inv._record()["damaged"] is False, "I2: the recovery wrote an entry its own reader rejects"
        # (I5) an acknowledgement whose audit row cannot be written does not replace the record
        world.store[inv.RECORD_KEY] = "{broken again"
        world.servers.clear()
        inv.sweep(now=NOW + timedelta(minutes=2), full=True)
        world.db["audit_fails"] = True
        done = inv.acknowledge_damaged("alice", all_subnets=True) if hasattr(inv, "acknowledge_damaged") else False
        assert not done and world.store[inv.RECORD_KEY] == "{broken again", (
            "I5: the record was replaced and the decision is on no record"
        )


def _stored_servers(world):
    raw = world.store.get(inv.RECORD_KEY, "")
    if not raw:
        return {}
    try:
        return json.loads(raw).get("servers", {})
    except ValueError:
        return {}


# ── what the walk found on this code (v5.68.0-beta.28), each pinned as the sequence that exposed it ───────────────────────────────────────────────


class TestWhatTheWalkFound:
    """The first 500-seed run of the walk over beta.27 + Q164 found two defects in code nobody had touched in this Q. Each is the failing sequence, named."""

    @pytest.mark.usefixtures("legacy_entries")
    def test_a_restore_restart_that_fails_is_spent_once__seed_449_and_ten_more(self, world):
        """I3. A daemon with no `config-reload` is restored by a RESTART folded into the change set; a restart that fails is rolled back (the marker is
        written back, the daemon restarted AGAIN) and the entry stays due - and the sweep did the same every minute: two restarts a minute of a production
        daemon whose unit will not start. The restore's restart is now spent once per entry, whether or not it worked (as `_daemon_phase` always did); the
        file is then restored WITHOUT a restart and the entry says a person has to act."""
        kea = world.daemons[1]
        kea.commands = ["version-get"]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.restart_ok = False  # the unit will not start
        attempts = lambda: [c for c in kea.calls if c.startswith("apply(restart=True)")]  # noqa: E731
        before = len(attempts())
        inv.sweep(now=NOW + timedelta(minutes=6))
        assert len(attempts()) == before + 1, "the first sweep tries the restore once, with its restart"
        stored = _stored_servers(world)["1"]
        assert stored["restore_restarted"] is True and has_marker(kea.file), (
            "the attempt was rolled back; the entry remembers it was spent"
        )
        for minute in range(7, 14):
            inv.sweep(now=NOW + timedelta(minutes=minute))
        assert len(attempts()) == before + 1, "no later sweep restarts the daemon again"
        assert not has_marker(kea.file) and at_debug(kea.loaded), (
            "the file was restored without a restart; the running daemon is still at DEBUG"
        )
        (row,) = inv.active(NOW + timedelta(minutes=13))
        assert row["file"] == "restored" and row["needs_hand"], "and the row says a person has to restore it by hand"

    def test_a_person_pressing_turn_off_is_never_held_back_by_that_bound(self, world):
        kea = world.daemons[1]
        kea.commands = ["version-get"]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        kea.restart_ok = False
        inv.sweep(now=NOW + timedelta(minutes=6))
        kea.restart_ok = True
        out = inv.turn_off(world.servers[0])
        assert out["ok"] is True and not at_debug(kea.loaded) and not inv.active(), (
            "the person's own act restarts the daemon, as it always did"
        )

    def test_a_server_id_that_now_names_another_kea_is_not_restored_through_it__seed_32(self, world):
        """I7/I1. A server removed by hand-editing jen.config and the next one added are given the same id (the next free one is often the same number). The
        entry for the first Kea was then restored THROUGH the second server: no marker there, so it was 'seen restored' and the entry dropped - while the first
        Kea stayed at DEBUG 55. An entry is about the Kea it was made for (its SSH host and config path); a different one leaves it orphaned, said so."""
        kea = world.daemons[1]
        assert inv.turn_on(world.servers[0], 5)["ok"]
        world.servers[0] = {"id": 1, "name": "kea-new", "ssh_host": "10.0.0.9"}  # id 1 now names a different Kea
        calls = list(kea.calls)
        out = inv.sweep(now=NOW + timedelta(minutes=30), full=True)
        assert kea.calls == calls, f"the sweep reached through the new server: {kea.calls[len(calls) :]}"
        assert out["restored"] == [] and at_debug(kea.loaded)
        stored = _stored_servers(world)["1"]
        assert stored["removed"] is True and stored["ssh_host"] == "10.0.0.1", (
            "the entry stays, about the Kea it was made for, saying so"
        )
        assert "now names 10.0.0.9" in stored["error"] and "10.0.0.1" in stored["error"]
        orphaned = [a for a in world.store["_audit"] if a[0] == "INVESTIGATION_LOGGING_ORPHANED"]
        assert len(orphaned) == 1 and "another Kea" in orphaned[0][2]
        assert (
            inv.sweep(now=NOW + timedelta(minutes=31), full=True)["restored"] == []
            and len([a for a in world.store["_audit"] if a[0] == "INVESTIGATION_LOGGING_ORPHANED"]) == 1
        ), "and it is not audited again every minute"

    def test_a_server_that_comes_back_resumes_its_entry_and_is_protected_again__seed_38(self, world):
        """I4/I8. The sweep flags an entry `removed` when its server is gone and never cleared the flag when the same server came back; the identity guard and
        the file guard both exclude `removed` entries, so a server with DEBUG running was unprotected until the entry happened to fall due."""
        kea = world.daemons[1]
        server = world.servers[0]
        assert inv.turn_on(server, 15)["ok"]
        world.servers.pop(0)
        inv.sweep(now=NOW + timedelta(minutes=1))
        assert _stored_servers(world)["1"]["removed"] is True
        world.servers.insert(0, server)  # the same Kea, back
        inv.sweep(now=NOW + timedelta(minutes=2))
        stored = _stored_servers(world)["1"]
        assert "removed" not in stored and "error" not in stored, "the entry is live again"
        assert [a for a in world.store["_audit"] if a[0] == "INVESTIGATION_LOGGING_RESUMED"]
        assert "turn it off from Servers first" in inv.endpoint_change_refusal(1, {"ssh_host": "10.9.9.9"}), (
            "and the identity guard protects it again"
        )
        candidate, _code = ed.clear_investigation_logging(copy.deepcopy(kea.file))
        assert "would remove the marker" in inv.file_write_refusal(server, candidate), "and so does the file guard"
        assert at_debug(kea.loaded)

    def test_a_server_id_re_pointed_at_another_kea_is_refused_everywhere_an_entry_would_be_lost__seed_165(self, world):
        """I4/I1. The same hand-removal and re-add, BEFORE any sweep has flagged the entry: the guard let the addition through (an addition is not a change of
        anything it compares), and Turn off or Turn on pressed for the new server acted on the entry through the wrong Kea - the first found nothing to put back and
        dropped it, the second wrote a fresh entry over it - while the first Kea stayed at DEBUG 55. An added server number must name the Kea a live entry is about,
        and turn-on and turn-off refuse a server the entry is not about."""
        kea = world.daemons[2]
        assert inv.turn_on(world.servers[1], 5)["ok"] and at_debug(kea.loaded)

        def ident(host):
            return {
                "api_url": f"http://{host}:8000",
                "ssh_host": host,
                "ssh_user": "jen",
                "kea_conf": "/etc/kea/kea-dhcp4.conf",
            }

        before = {"1": ident("10.0.0.1"), "__mode__": "ca"}
        assert inv.identity_guard(before, {**before, "2": ident("10.0.0.9")}) != "", (
            "a DIFFERENT Kea under the number of a live entry is refused"
        )
        assert inv.identity_guard(before, {**before, "2": ident("10.0.0.2")}) == "", "the same Kea is fine"
        new_server = {"id": 2, "name": "kea-new", "ssh_host": "10.0.0.9"}
        world.servers[1] = new_server
        calls = list(kea.calls)
        off = inv.turn_off(new_server)
        on = inv.turn_on(new_server, 15)
        assert (
            off["ok"] is False
            and on["ok"] is False
            and "10.0.0.2" in off["lines"][0]
            and "new server a new number" in on["lines"][0]
        )
        assert kea.calls == calls and at_debug(kea.loaded), "nothing was sent anywhere"
        stored = _stored_servers(world)["2"]
        assert stored["ssh_host"] == "10.0.0.2" and "removed" not in stored, (
            "the entry is untouched, still about the Kea it was made for"
        )

    def test_turn_on_does_not_replace_an_unfinished_restore__seed_486(self, world):
        """I7/I1. An entry flagged `contradiction` (the API answers for another Kea than SSH edits) was REPLACED by a fresh one when Turn on was pressed again; the
        fresh entry was judged by the same lying observation, found 'restored' and dropped - while the real Kea ran DEBUG 55. An unfinished restore, a contradiction
        and a damaged marker are finished (or forgotten) before logging is turned on again."""
        kea = world.daemons[1]
        kea.second = copy.deepcopy(kea.loaded)  # the API answers for a different daemon, which is at the original level
        out = inv.turn_on(world.servers[0], 5)
        assert out["ok"] is False and _stored_servers(world)["1"]["contradiction"] is True
        again = inv.turn_on(world.servers[0], 5)
        assert again["ok"] is False and "not finished" in again["lines"][0]
        stored = _stored_servers(world)
        assert stored["1"]["contradiction"] is True, "the entry is still there, still a contradiction"
        assert at_debug(kea.loaded), "and the real Kea is still at DEBUG"
