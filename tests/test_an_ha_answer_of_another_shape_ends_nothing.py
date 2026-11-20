"""
tests/test_an_ha_answer_of_another_shape_ends_nothing.py
────────────────────────────────────────────────────────
Q244 (BB1 of the pass on v7.1.0-beta.11; AZ12's second half).

Q242 made `alerts.heartbeat_state` read an `ha-heartbeat` answer of any shape. Three more readers took `(answer.get("arguments") or {}).get(...)`:
`kea.get_active_kea_server`, `kea.get_all_server_status` and the dashboard. With `arguments` a list, a string or a number that raised `AttributeError`,
and `get_active_kea_server` is called from inside the alert cycle's one `try`: utilization, stale reservations, drift, the snapshot, the daily summary and
the certificate conditions did not run on that pass.

Only the network is in the test's hands: what `kea_command` and `kea_is_up` answer. No real Kea sends these shapes; a proxy or a daemon of another make can.
"""

import pathlib

import pytest

from jen import extensions
from jen.services import kea

ROOT = pathlib.Path(__file__).resolve().parent.parent
ODD = [[], ["hot-standby"], "hot-standby", 7, 1.5, True]
NOT_TEXT = [v for v in ODD if not isinstance(v, str)]
SERVERS = [
    {"id": 1, "name": "one", "role": "primary", "api_url": "http://192.0.2.1:8000"},
    {"id": 2, "name": "two", "role": "standby", "api_url": "http://192.0.2.2:8000"},
]


class TestTheTwoReaders:
    def test_arguments_that_are_an_object_are_returned(self):
        assert kea.ha_arguments({"result": 0, "arguments": {"state": "hot-standby"}}) == {"state": "hot-standby"}

    def test_a_result_that_is_not_0_is_no_answer(self):
        assert kea.ha_arguments({"result": 2, "text": "'ha-heartbeat' command not supported."}) is None
        assert kea.ha_arguments({"result": 1, "arguments": {"state": "hot-standby"}}) is None

    @pytest.mark.parametrize("answer", [None, [], "x", 3, [{"result": 0}]])
    def test_an_answer_that_is_not_an_object_is_no_answer(self, answer):
        assert kea.ha_arguments(answer) is None

    @pytest.mark.parametrize("odd", [*ODD, None])
    def test_arguments_of_another_shape_are_an_object_with_nothing_in_it(self, odd):
        assert kea.ha_arguments({"result": 0, "arguments": odd}) == {}
        assert kea.ha_arguments({"result": 0}) == {}

    @pytest.mark.parametrize("odd", [*NOT_TEXT, {"a": 1}, None])
    def test_a_state_that_is_not_text_is_the_default(self, odd):
        assert kea.ha_text({"state": odd}, "state", "unknown") == "unknown"
        assert kea.ha_text({}, "state") == ""
        assert kea.ha_text({"state": "partner-down"}, "state") == "partner-down"


@pytest.fixture
def pair(monkeypatch):
    """Two configured servers, both up; the test says what `ha-heartbeat` answers."""
    answers = {}
    monkeypatch.setattr(extensions, "KEA_SERVERS", SERVERS)
    monkeypatch.setattr(extensions, "_active_server_cache", {"server": None, "ts": 0})
    monkeypatch.setattr(kea, "kea_is_up", lambda server=None: True)
    monkeypatch.setattr(kea, "probe_kea_health", lambda server: {"up": True, "version": "3.0.1"})

    def command(name, server=None, **kw):
        assert name == "ha-heartbeat", name
        return answers["heartbeat"]

    monkeypatch.setattr(kea, "kea_command", command)
    return answers


class TestTheActiveServer:
    @pytest.mark.parametrize("odd", ODD)
    def test_arguments_of_another_shape_do_not_raise(self, pair, odd):
        """v7.2.0-beta.1 raises AttributeError here, inside `check_alerts`' one `try`."""
        pair["heartbeat"] = {"result": 0, "arguments": odd}
        assert kea.get_active_kea_server() == SERVERS[0], "no state was read, so it is the first reachable server"

    @pytest.mark.parametrize("odd", NOT_TEXT)
    def test_a_state_of_another_shape_is_no_state(self, pair, odd):
        pair["heartbeat"] = {"result": 0, "arguments": {"state": odd}}
        assert kea.get_active_kea_server() == SERVERS[0]

    def test_a_real_answer_still_chooses_the_primary(self, pair):
        pair["heartbeat"] = {"result": 0, "arguments": {"state": "hot-standby", "date-time": "x"}}
        assert kea.get_active_kea_server() == SERVERS[0]


class TestTheStatusList:
    @pytest.mark.parametrize("odd", ODD)
    def test_arguments_of_another_shape_do_not_raise(self, pair, odd):
        pair["heartbeat"] = {"result": 0, "arguments": odd}
        rows = kea.get_all_server_status()
        assert [(r["up"], r["ha_state"], r["ha_partner"]) for r in rows] == [(True, "unknown", "")] * 2

    def test_a_state_that_is_a_list_is_not_shown_as_a_state(self, pair):
        pair["heartbeat"] = {"result": 0, "arguments": {"state": ["hot-standby"], "partner-state": {"x": 1}}}
        assert [(r["ha_state"], r["ha_partner"]) for r in kea.get_all_server_status()] == [("unknown", "")] * 2

    def test_a_real_answer_is_shown(self, pair):
        pair["heartbeat"] = {"result": 0, "arguments": {"state": "hot-standby", "partner-state": "hot-standby"}}
        assert [(r["ha_state"], r["ha_partner"]) for r in kea.get_all_server_status()] == [
            ("hot-standby", "hot-standby")
        ] * 2

    def test_a_daemon_without_ha_has_no_state(self, pair):
        pair["heartbeat"] = {"result": 2, "text": "'ha-heartbeat' command not supported."}
        assert [r["ha_state"] for r in kea.get_all_server_status()] == [None, None]


class TestNoReaderOfAHeartbeatTakesItsArgumentsUnread:
    def test_over_the_whole_tree(self):
        """Every `kea_command("ha-heartbeat"` under `jen/` and `plugins/` is read by `ha_arguments` or by `alerts.heartbeat_state`, in the same statement
        or the next one: a fourth reader that takes `.get("arguments")` itself fails here."""
        bad = []
        for base in ("jen", "plugins"):
            for path in sorted((ROOT / base).rglob("*.py")):
                lines = path.read_text(encoding="utf-8").splitlines()
                for at, line in enumerate(lines):
                    if '"ha-heartbeat"' not in line or "kea_command" not in "".join(lines[max(0, at - 2) : at + 1]):
                        continue
                    near = "\n".join(lines[max(0, at - 3) : at + 3])
                    if "ha_arguments(" not in near and "heartbeat_state(" not in near:
                        bad.append(f"{path.relative_to(ROOT).as_posix()}:{at + 1}")
        assert bad == []

    def test_the_sweep_finds_the_three_it_was_written_for(self):
        text = (ROOT / "jen" / "services" / "kea.py").read_text(encoding="utf-8")
        assert text.count('ha_arguments(kea_command("ha-heartbeat", server=server))') == 2
        assert "__kea.ha_arguments(" in (ROOT / "jen" / "routes" / "dashboard.py").read_text(encoding="utf-8")
