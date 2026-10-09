"""
tests/_investigation_world.py
─────────────────────────────
The fake Kea host and the `world` fixture of tests/test_investigation_logging.py, in one place so the other files that drive the investigation-logging
service (tests/test_identity_guard.py, tests/test_investigation_model.py) use the SAME fake rather than a copy that drifts. Moved here unchanged in
v5.68.0-beta.28 (Q164); `pytest --noconftest` runs everything built on it.

NAMING: a fixture here must never share a name with one of tests/conftest.py's (`db`, `client`, `app`, ...): the conftest teardown would then be handed this
fixture's value (the beta.27 CI failure). The only fixture is `world`.
"""

import copy
import importlib.util
import pathlib
from datetime import datetime, timedelta, timezone
from importlib.machinery import SourceFileLoader

import pytest

from jen.services import investigation_logging as inv
from jen.services.kea_changeset import ChangeSetResult

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
FUTURE = (NOW + timedelta(minutes=10)).isoformat()
PAST = (NOW - timedelta(minutes=3)).isoformat()


_helper_module = None


def helper():
    """jen-kea-helper itself, loaded once: the fake host below restores a logger with the helper's OWN routine (`_restore_logger`), not a copy of it."""
    global _helper_module
    if _helper_module is None:
        path = pathlib.Path(__file__).resolve().parent.parent / "jen-kea-helper"
        loader = SourceFileLoader("jen_kea_helper_world", str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        _helper_module = importlib.util.module_from_spec(spec)
        loader.exec_module(_helper_module)
    return _helper_module


def _cfg(loggers="absent"):
    section = {"valid-lifetime": 3600, "subnet4": []}
    if loggers != "absent":
        section["loggers"] = loggers
    return {"Dhcp4": section}


class FakeKea:
    """One server's config file and daemon. `commands` is what `list-commands` answers; `reload` what config-reload returns."""

    def __init__(self, cfg, commands=("config-reload", "version-get"), reload_result=0, restart_ok=True):
        self.file = copy.deepcopy(cfg)
        self.commands, self.reload_result, self.restart_ok = list(commands), reload_result, restart_ok
        self.calls = []
        self.writes = 0
        self.loaded = copy.deepcopy(
            cfg
        )  # what the RUNNING daemon is configured with: only a reload or a restart moves it
        self.fail_writes_after = None  # once this many writes have worked, every further change set fails
        self.rollback_fails = False  # a failed restart cannot be rolled back either
        self.list_unreachable = False  # the Control Agent does not answer (list-commands AND config-get)
        self.reload_applied_but_lost = False  # config-reload takes effect and its reply is lost (result 1)
        self.api_silent = False  # config-get never answers
        self.silent_gets = 0  # ... or the first N config-gets do not
        self.reload_ignored = False  # config-reload answers 0 and the daemon does not move
        self.restart_ignored = False  # the restart succeeds and the daemon does not move
        self.second = None  # config-get answers from ANOTHER daemon (api_url and ssh_host are not the same Kea)
        # v5.68.0-beta.29 (Q165): the Kea HOST - jen-kea-helper build 15 with its state file and its timer. `host_down` is a host Jen cannot reach over SSH at all.
        self.build = 16
        self.helper_code = "ok"  # "missing" | "unreachable" | "error": what `helper_build` answers
        self.timer = "systemd"  # what `investigation-arm` reports ("none" = a host that cannot run the timer)
        self.arm_fails = None  # a detail string: `investigation-arm` answers not-ok with it
        self.host_down = False
        self.host_restore_fails = (
            False  # the host's restore routine fails (its `-t` refuses, or the file cannot be written)
        )
        self.hup_ignored = (
            False  # the daemon does not re-read its config on SIGHUP (the host then falls back to ONE restart)
        )
        self.helper_state = (
            None  # the host's state file: {"until", "restore", "restored_at", "how", "last_error", "restarts", "jen"}
        )
        self.timer_running = True  # False: the host's timer never fires (the walk's "no HostTimer" case)

    def kea_command(self, command, **kw):
        self.calls.append(command)
        if command == "list-commands":
            if getattr(
                self, "list_unreachable", False
            ):  # the Control Agent did not answer: kea_command's connection-failure reply
                return {"result": 1, "text": "connection refused"}
            return {"result": 0, "arguments": self.commands}
        if command == "config-reload":
            if self.reload_ignored:
                return {"result": 0, "text": "reloaded"}
            if self.reload_applied_but_lost:
                # v5.68.0-beta.23 (Q158): Kea APPLIED the reload and the HTTP reply never arrived - the daemon moved, the caller is told it failed
                self.loaded = copy.deepcopy(self.file)
                return {"result": 1, "text": "timed out after 10 s"}
            if not self.reload_result:
                self.loaded = copy.deepcopy(self.file)
            if self.reload_result:
                return {"result": self.reload_result, "text": getattr(self, "reload_text", "reload refused")}
            return {"result": 0, "text": "reloaded"}
        if command == "config-get":
            # the RUNNING daemon's configuration (`loaded`), never the file; `api_silent` is a Control Agent that does not answer at all
            if (
                self.api_silent or self.list_unreachable or self.silent_gets > 0
            ):  # a Control Agent that is down answers neither command
                self.silent_gets = max(0, self.silent_gets - 1)
                return {"result": 1, "text": "connection refused"}
            if self.second is not None:
                return {"result": 0, "arguments": copy.deepcopy(self.second)}
            return {"result": 0, "arguments": copy.deepcopy(self.loaded)}
        return {"result": 0}

    def service_action(self, server, service, action):
        self.calls.append(f"{action}:{service}")
        if self.restart_ok:
            if not self.restart_ignored:
                self.loaded = copy.deepcopy(self.file)
            self.list_unreachable = False  # the restarted daemon answers on its control socket again
        return {"ok": self.restart_ok, "detail": "" if self.restart_ok else "unit failed"}

    def apply_change(self, service, mutate_fn, summary, **kw):
        after, code = mutate_fn(self.file)
        skip = kw.get("skip_codes", ("notfound", "nochange"))
        assert kw["servers"] and len(kw["servers"]) == 1, "always exactly one target"
        self.calls.append(f"apply(restart={kw.get('restart', True)}):{summary}")
        if code in skip:
            return ChangeSetResult("nothing", code, [("success", f"ℹ️ {code}")])
        if code != "ok":
            return ChangeSetResult("aborted", code, [("error", f"❌ {kw['code_messages'].get(code, code)}")])
        if self.fail_writes_after is not None and self.writes >= self.fail_writes_after:
            return ChangeSetResult("rolled_back", "error", [("error", "❌ the change could not be applied")])
        before = self.file
        self.file = after
        self.writes += 1
        if kw.get("restart", True):  # the real change set restarts the daemon inside apply_change
            if self.restart_ok:
                if not self.restart_ignored:
                    self.loaded = copy.deepcopy(self.file)
                self.list_unreachable = False  # the restarted daemon answers on its control socket again
            else:
                self.file = after if self.rollback_fails else before
                status = "rollback_failed" if self.rollback_fails else "rolled_back"
                return ChangeSetResult(status, "restart-failed", [("error", "❌ the daemon did not restart")])
        return ChangeSetResult("ok", "ok", [("success", f"✅ {summary}")])

    def read_config_versioned(self, server, service):
        return copy.deepcopy(self.file), "sha"

    # ── the Kea host (jen-kea-helper build 15) ─────────────────────────────────────────────────────────────────────

    def _host_error(self):
        return {"ok": False, "code": "error", "detail": "ssh: connection refused"}

    def _too_old(self):
        return {
            "ok": False,
            "code": "old",
            "detail": "the Kea host helper on this host is older than build 16 - press Update helper",
        }

    def helper_build_info(self, server):
        if self.host_down:
            return {"code": "unreachable", "version": None, "build": None, "detail": "ssh: connection refused"}
        if self.helper_code != "ok":
            return {"code": self.helper_code, "version": None, "build": None, "detail": self.helper_code}
        return {"code": "ok", "version": 7, "build": self.build, "detail": ""}

    def investigation_arm(self, server, until, restore, jen=None, log_path=""):
        self.calls.append("host:arm")
        if self.host_down:
            return self._host_error()
        if self.build < 16:
            return self._too_old()
        if self.arm_fails:
            return {"ok": False, "code": "error", "detail": self.arm_fails}
        self.helper_state = {
            "until": until,
            "restore": copy.deepcopy(restore),
            "restored_at": None,
            "how": None,
            "last_error": None,
            "restarts": 0,
            "jen": jen or {},
        }
        return {
            "ok": True,
            "code": "ok",
            "timer": self.timer,
            "until": until,
            "detail": "" if self.timer == "systemd" else "no systemd here",
        }

    def investigation_status(self, server):
        self.calls.append("host:status")
        if self.host_down:
            return self._host_error()
        if self.build < 16:
            return self._too_old()
        st = self.helper_state
        if st is None:
            return {"ok": True, "code": "ok", "armed": False}
        return {"ok": True, "code": "ok", "armed": not st["restored_at"], **copy.deepcopy(st)}

    def _hup_or_restart(self, st):
        if not (self.reload_ignored or self.hup_ignored):
            self.loaded = copy.deepcopy(self.file)
            return "reload", None
        if st["restarts"] >= 1:
            return (
                None,
                "the daemon did not stay active after the reload and it was already restarted once for this state: not restarting again",
            )
        st["restarts"] += 1
        if not self.restart_ok:
            return None, "systemctl restart kea-dhcp4-server failed"
        self.loaded = copy.deepcopy(
            self.file
        )  # a real restart re-reads the file (`restart_ignored` models an API that answers for a different daemon)
        self.list_unreachable = False
        return "restart", None

    def host_restore(self):
        """The helper's restore routine (shared by disarm, the timer and boot): (ok, how, detail). The logger is put back from the STATE's `restore`, by the helper's
        own `_restore_logger`; the daemon is told by SIGHUP, with ONE restart as the fallback."""
        st = self.helper_state
        if self.host_restore_fails:
            st["last_error"] = "kea-dhcp4 -t refused the restored config"
            return False, None, st["last_error"]
        new, code = helper()._restore_logger(self.file, st["restore"])
        if code == "ok":
            self.file = new
        how, error = self._hup_or_restart(st)
        if error:
            st["last_error"] = error
            return False, None, error
        st.update(restored_at=inv._now().isoformat(timespec="seconds"), how=how, last_error=None)
        return True, how, ""

    def investigation_disarm(self, server):
        self.calls.append("host:disarm")
        if self.host_down:
            return self._host_error()
        if self.build < 16:
            return self._too_old()
        st = self.helper_state
        if st is None:
            return {"ok": True, "code": "ok", "restored": False, "how": "nothing", "detail": "not armed"}
        if st["restored_at"]:
            return {
                "ok": True,
                "code": "ok",
                "restored": False,
                "how": st["how"] or "nothing",
                "detail": "already restored",
            }
        ok, how, detail = self.host_restore()
        if not ok:
            return {"ok": False, "code": "error", "detail": detail}
        return {"ok": True, "code": "ok", "restored": True, "how": how, "detail": ""}

    def host_tick(self):
        """The host's timer firing (`jen-kea-helper --self-restore`): restores when an armed state's `until` has passed. Needs nothing of Jen."""
        st = self.helper_state
        if not self.timer_running or st is None or st["restored_at"]:
            return None
        due = inv._edit._parse_until(st["until"])
        if due is not None and due > inv._now():
            return None
        return self.host_restore()


@pytest.fixture
def world(monkeypatch):
    """Servers 1 and 2, each its own FakeKea; settings in a dict; the clock fixed."""
    from jen import extensions

    store = {}
    db = {
        "fails": None
    }  # a predicate on the investigation record being written: True = the Jen database does not take THIS write

    def set_setting(key, value):
        if db.get("unavailable"):
            return False
        if key == inv.RECORD_KEY and db["fails"] is not None and db["fails"](value):
            return (
                False  # what jen.models.user.set_global_setting answers when the write did not happen (v5.68.0-beta.22)
            )
        store[key] = value
        return True

    # `unavailable` (Q164): the settings table cannot be read at all - `get_global_setting` answers its default and `settings_ever_loaded` says it never read
    monkeypatch.setattr(
        "jen.models.user.get_global_setting", lambda k, d="": d if db.get("unavailable") else store.get(k, d)
    )
    monkeypatch.setattr("jen.models.user.settings_ever_loaded", lambda: not db.get("unavailable"), raising=False)
    monkeypatch.setattr("jen.models.user.set_global_setting", set_setting)

    def set_and_audit(key, value, action, entity, details=""):
        # the real one is ONE transaction: both rows or neither (v5.68.0-beta.27, Q162, item 3)
        if db.get("unavailable"):
            return False
        if key == inv.RECORD_KEY and db["fails"] is not None and db["fails"](value):
            return False
        if db.get("audit_fails"):
            return False
        store[key] = value
        store.setdefault("_audit", []).append((action, entity, details))
        return True

    # (`raising=False`: tests/test_investigation_model.py runs its historical sequences against the releases they were found in, which lack some of these names)
    monkeypatch.setattr("jen.models.user.set_global_setting_and_audit", set_and_audit, raising=False)
    monkeypatch.setattr(inv, "_sleep", lambda seconds: None, raising=False)

    def audit(*a, **k):
        if db.get("audit_fails"):
            raise RuntimeError("the audit row could not be written")
        store.setdefault("_audit", []).append(a)

    monkeypatch.setattr("jen.models.user.audit", audit)
    servers = [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.1"}, {"id": 2, "name": "kea-b", "ssh_host": "10.0.0.2"}]
    monkeypatch.setattr(extensions, "KEA_SERVERS", servers)
    daemons = {1: FakeKea(_cfg([{"name": "kea-dhcp4", "severity": "INFO"}])), 2: FakeKea(_cfg())}

    def pick(server):
        return daemons[server["id"]]

    monkeypatch.setattr(inv._kea, "kea_command", lambda command, server=None, **kw: pick(server).kea_command(command))
    monkeypatch.setattr(
        inv._host,
        "service_action",
        lambda server, service, action: pick(server).service_action(server, service, action),
    )
    monkeypatch.setattr(
        inv._host, "read_config_versioned", lambda server, service: pick(server).read_config_versioned(server, service)
    )
    monkeypatch.setattr(inv._host, "helper_build", lambda server: pick(server).helper_build_info(server))
    monkeypatch.setattr(
        inv._host,
        "investigation_arm",
        lambda server, until, restore, jen=None, log_path="": pick(server).investigation_arm(
            server, until, restore, jen, log_path
        ),
    )
    monkeypatch.setattr(inv._host, "investigation_disarm", lambda server: pick(server).investigation_disarm(server))
    monkeypatch.setattr(inv._host, "investigation_status", lambda server: pick(server).investigation_status(server))

    def fake_apply(service, mutate_fn, summary, **kw):
        return pick(kw["servers"][0]).apply_change(service, mutate_fn, summary, **kw)

    monkeypatch.setattr(inv._changeset, "apply_change", fake_apply)
    monkeypatch.setattr(inv, "_now", lambda: NOW)
    inv._runs["n"] = 0
    if hasattr(inv, "_recovery_status"):
        inv._recovery_status.update(
            at="", problems=[], rebuilt=None
        )  # module state: one test's rebuild attempt is not the next one's
    if hasattr(inv, "_legacy_logged"):
        inv._legacy_logged.clear()
    return type("World", (), {"store": store, "servers": servers, "daemons": daemons, "db": db})


@pytest.fixture
def legacy_entries(world, monkeypatch):
    """Entries as beta.28 wrote them: nothing behind them on the Kea host (no state file, no timer), so Jen's own file-writing restore is the only one there is
    (v5.68.0-beta.29, Q165). That path is still the one for an entry made before build 15, and the fallback when the host cannot restore; the tests of its state
    machine run under this fixture, and the host's own restore has its own classes (TestTheKeaHostOwnsTheRestore)."""
    monkeypatch.setattr(inv, "_arm_host", lambda server, entry, until: (True, [], False))
    monkeypatch.setattr(inv, "_host_phase", lambda known, record, now: set())
    return world
