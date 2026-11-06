"""v7.0.0-beta.7 (Q221, AE8, AE9 and AE10; CFG-007) - the write gate is a READ, and the file is judged live in the write path.

7.0.0-beta.5 (Q219 E1) asked the live proof from inside `kea_api_config.probe_gate` when a stored result said the file was not the daemon's. Every page derives the Live API badge from that function
(`capabilities.config_inputs`, `capabilities.write_gate_for`, the Write mode card), so a page a viewer can load made an SSH read and a `config-get` per server and WROTE the stored result - and the
nav pill's Health run did the same. The re-read is the write path's (`refresh_if_stale`, asked before the gate by the change set's Plan and by `apply`), a refusal by the live proof is recorded
there, and the gate itself is a settings read and pure rules. The first class is the property as source (the whole call graph under the gate); the rest execute it."""

import ast
import pathlib

import pytest

from jen.services import kea_api_config as api
from tests.test_kea_consent import GOOD

ROOT = pathlib.Path(__file__).resolve().parent.parent
API_SRC = ROOT / "jen/services/kea_api_config.py"

#: every function of the module that asks Kea, asks a host or writes a record - none may be reachable from the gate
REMOTE = {
    "_cmd",
    "_get",
    "hash",
    "read",
    "test",
    "file_proof",
    "_ask_the_file",
    "write_file",
    "_send_write",
    "_write_with_retries",
    "probe",
    "refresh_probe",
    "refresh_if_stale",
    "store_probe",
    "remember_refusal",
    "clear_refusal",
    "apply",
    "revert",
    "settle_pending",
    "_reconcile_pending",
    "pending_block",
    "pending_note",
    "compare",
    "defaults_for",
    "daemon_version",
    "record_rendering_after_write",
    "_capture",
}
#: the module aliases whose every call is a remote read, a remote write or the revision store
REMOTE_MODULES = {"_host", "_kea", "_rev", "_inv"}

SSH = {"id": 5, "name": "kea-e", "api_url": "http://127.0.0.1:9/", "ssh_host": "10.0.0.9", "config_transport": "api"}
NO_SSH = {"id": 6, "name": "kea-f", "api_url": "http://127.0.0.1:9/", "config_transport": "api"}


def _functions(path):
    return {n.name: n for n in ast.parse(path.read_text(encoding="utf-8")).body if isinstance(n, ast.FunctionDef)}


def _reach(path, start):
    """(the module's own functions reachable from `start`, every `alias.name(...)` call made by any of them)."""
    funcs = _functions(path)
    assert start in funcs, start
    seen, todo, attrs = set(), [start], set()
    while todo:
        name = todo.pop()
        if name in seen or name not in funcs:
            continue
        seen.add(name)
        for node in ast.walk(funcs[name]):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if isinstance(f, ast.Name):
                todo.append(f.id)
            elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                attrs.add(f"{f.value.id}.{f.attr}")
    return seen, attrs


class TestTheGateReachesNothingRemote:
    @pytest.mark.parametrize(
        "start", ["probe_gate", "stored_probe", "refusal_sentence", "consent_gap", "consents_called_for"]
    )
    def test_no_function_under_it_asks_kea_a_host_or_the_store(self, start):
        seen, attrs = _reach(API_SRC, start)
        assert seen & REMOTE == set(), sorted(seen & REMOTE)
        assert {a for a in attrs if a.split(".")[0] in REMOTE_MODULES} == set()

    def test_the_walk_sees_a_remote_call_when_there_is_one(self):
        """The control: the same walk from the write path's own refresh finds the probe and the store, so an empty answer above is a finding and not a blind walk."""
        seen, _attrs = _reach(API_SRC, "refresh_if_stale")
        assert {"refresh_probe", "probe", "store_probe", "_get", "file_proof"} <= seen

    def test_the_live_reproof_is_gone_from_the_module(self):
        assert "_reprove" not in API_SRC.read_text(encoding="utf-8")

    @pytest.mark.parametrize("name", ["write_gate_for", "config_inputs"])
    def test_capabilities_reads_the_gate_through_three_pure_names(self, name):
        _seen, attrs = _reach(ROOT / "jen/services/capabilities.py", name)
        asked = {a.split(".")[1] for a in attrs if a.startswith("_api.")}
        assert asked <= {"declared_transport", "stored_probe", "probe_gate"}, asked
        assert "probe_gate" in asked


def _stored(**over):
    now = api._now_iso()
    out = {
        **GOOD,
        "at": now,
        "consented_at": now,
        "consents": ["consent_rendering"],
        "bound": api._bound(SSH),
        "tls": False,
    }
    out.update(over)
    return out


@pytest.fixture
def tripwires(monkeypatch):
    """Anything remote, or a write of the stored result, fails the test that reaches it."""

    def trip(name):
        def fail(*a, **k):
            raise AssertionError(f"the gate reached {name}")

        return fail

    monkeypatch.setattr(api, "_cmd", trip("_cmd"))
    monkeypatch.setattr(api, "store_probe", trip("store_probe"))
    monkeypatch.setattr(api._host, "read_config_proof", trip("read_config_proof"))
    monkeypatch.setattr(api._host, "read_config_versioned", trip("read_config_versioned"))
    monkeypatch.setattr(api._rev, "pending", trip("config_revisions.pending"))


class TestTheGateAnswersFromTheStoredResult:
    def test_a_stored_no_refuses_and_nothing_is_asked_or_written(self, monkeypatch, tripwires):
        monkeypatch.setattr(api, "stored_probe", lambda sid: _stored(agree=False))
        gate = api.probe_gate(SSH)
        assert "the file on the host carries a configuration the daemon is not running" in gate

    def test_a_stored_yes_is_open_and_nothing_is_asked_or_written(self, monkeypatch, tripwires):
        monkeypatch.setattr(api, "stored_probe", lambda sid: _stored())
        assert api.probe_gate(SSH) == ""

    def test_capabilities_for_a_viewers_page_asks_nothing(self, monkeypatch, tripwires):
        from jen.services import capabilities

        monkeypatch.setattr(api, "stored_probe", lambda sid: _stored(agree=False))
        caps = capabilities.write_gate_for(SSH)
        assert caps.transport_blocked and "not running" in caps.transport_why()


class TestTheWritePathRefreshesBeforeItAsks:
    """Q219 E1, kept: a hand edit the operator restarted Kea over must not keep refusing changes on the fact stored before the restart."""

    DAY_OLD = "2020-01-01T00:00:00+00:00"

    @pytest.mark.parametrize(
        ("server", "stored", "refreshed"),
        [
            (SSH, None, False),  # never checked: nothing to refresh, the gate names the check
            (SSH, {"agree": True}, False),  # fresh and it said yes
            (SSH, {"agree": False}, True),  # it said no: asked again before the gate
            (NO_SSH, {"agree": False}, False),  # no SSH host, no file to ask about
            (SSH, {"agree": True, "at": DAY_OLD}, True),  # older than a day
            (NO_SSH, {"agree": None, "at": DAY_OLD}, True),
            (SSH, {"agree": None}, False),  # unknown is not "no": the gate says the host's facts could not be read
        ],
    )
    def test_when_the_facts_are_read_again(self, monkeypatch, server, stored, refreshed):
        calls = []
        monkeypatch.setattr(api, "stored_probe", lambda sid: None if stored is None else _stored(**stored))
        monkeypatch.setattr(api, "refresh_probe", lambda srv, service="dhcp4": calls.append(srv["id"]) or True)
        assert api.refresh_if_stale(server) is refreshed
        assert calls == ([server["id"]] if refreshed else [])

    def test_a_restart_since_the_check_opens_the_gate_for_the_next_change(self, monkeypatch):
        """The composition: the stored result says no, the refresh re-reads the facts (here: the daemon has loaded the file since), and the gate that refused now answers ""."""
        box = {"facts": _stored(agree=False)}
        monkeypatch.setattr(api, "stored_probe", lambda sid: dict(box["facts"]))
        monkeypatch.setattr(
            api, "refresh_probe", lambda srv, service="dhcp4": box.update(facts=_stored(agree=True)) or True
        )
        assert api.probe_gate(SSH) != ""
        assert api.refresh_if_stale(SSH) is True
        assert api.probe_gate(SSH) == ""

    def test_apply_refreshes_before_it_asks_the_gate(self, monkeypatch):
        """A caller with no Plan (a restore, an import) goes through `apply`: the refresh is asked first, then the gate, and a closed gate sends nothing."""
        order = []
        monkeypatch.setattr(api._host, "guard_kea_write", lambda *a, **k: "")
        monkeypatch.setattr("jen.services.investigation_logging.restore_window", lambda server, now=None: "")
        monkeypatch.setattr(api, "refresh_if_stale", lambda srv, service="dhcp4": order.append("refresh") or False)
        monkeypatch.setattr(api, "probe_gate", lambda srv, source="jen": order.append("gate") or "the gate is closed")
        monkeypatch.setattr(api, "_cmd", lambda *a, **k: order.append("sent") or {})
        result = api.apply(SSH, "dhcp4", {"Dhcp4": {}}, "digest", "a change")
        assert result["ok"] is False and result["code"] == "guard" and result["detail"] == "the gate is closed"
        assert order == ["refresh", "gate"]

    def test_the_plan_refreshes_before_the_gate_and_the_live_proof_follows_both(self):
        """As source, in `kea_changeset._run_change_unlocked`: `refresh_if_stale`, then `probe_gate`, then the live proof (`_unloaded_edit`) - the order the Plan asks them in."""
        src = (ROOT / "jen/services/kea_changeset.py").read_text(encoding="utf-8")
        fn = _functions(ROOT / "jen/services/kea_changeset.py")["_run_change_unlocked"]
        body = ast.get_source_segment(src, fn)
        assert 0 < body.index("_api.refresh_if_stale(") < body.index("_api.probe_gate(") < body.index("_unloaded_edit(")


class TestHealthSaysWhatItKnowsAndWhen:
    def test_the_ok_sentence_names_the_last_check_and_the_proof_before_every_change(self):
        src = (ROOT / "jen/services/health.py").read_text(encoding="utf-8")
        assert (
            "every gate was open at each server's last check; the file on the host is proved again before every change"
            in src
        )
        assert 'every gate open"' not in src
