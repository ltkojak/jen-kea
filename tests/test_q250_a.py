"""
tests/test_q250_a.py
────────────────────
Q250 - the Kea logging card after the executing pass on v7.2.0-beta.7 (INV-017: a change of Kea's log output is proven by the log itself or put back).

    TestOneChangeAtATime        the server is held from the change's first read to its last write, by the card AND by a turn-on of investigation logging; neither waits
    TestTheProofIsKeasOwnLine   a line another writer of the file added proves nothing
    TestAboveInfo               at WARN and ERROR Kea is asked for a line (Q252); at FATAL a file Kea created is the proof and the file it already wrote to stands
    TestNoWritePath             a server Jen has no way to change gets no form and a refusal that says why
    TestTheAuditRow             a change Kea ran for the seconds of the proof is in the audit log
    TestTheDoctor               an empty `pattern` is Kea's default, the dated one
    TestTheReadersFollow        the readers' remembered log path is forgotten when the output changes

The world is `tests/test_q249_a.py`'s: a stateful fake Kea reached over real HTTP by the real `kea_command`, and `tests/_q249_a_world.py::KeaHost` standing in for
`kea_host.helper_call`. The real kea-dhcp4 run of the same rows is `pass/q250/a/` (the ledger of the Q250 entry names its output).
"""

import ast
import copy
import pathlib
import threading

import pytest

from jen import extensions
from jen.services import config_doctor as doctor
from jen.services import investigation_logging as inv
from jen.services import kea_host, log_tail
from jen.services import kea_log_trace as klt
from tests._q249_a_world import FILE_LOGGER, PACKAGED, KeaHost, dhcp4, file_server, kea_writes_defaults, packaged_logger
from tests.e2e._fake_kea_server import StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
SID = 250  # a server id no other test file uses: this file's config-history rows are its own, and it removes them
LOG = "/var/log/kea/kea-dhcp4.log"
OTHER = "/var/log/kea/second.log"
MB10 = 10 * 1024 * 1024
URL = f"/settings/infrastructure/kea-logging/{SID}"


@pytest.fixture
def daemon():
    d = StatefulKeaServer(dhcp4([packaged_logger()]))
    d.expand = kea_writes_defaults
    d.running = kea_writes_defaults(d.running)
    d.start()
    yield d
    d.stop()


@pytest.fixture
def host(monkeypatch, daemon):
    h = KeaHost(daemon)
    monkeypatch.setattr(kea_host, "helper_call", h.helper_call)
    return h


@pytest.fixture
def server(monkeypatch, daemon, host, db):
    s = file_server(daemon, id=SID)
    monkeypatch.setattr(extensions, "KEA_SERVERS", [s])
    yield s
    klt.release_log_output(s)
    with db.cursor() as cur:
        cur.execute("DELETE FROM kea_config_revisions WHERE server_id=%s", (SID,))
    db.commit()


def flashes(client):
    with client.session_transaction() as sess:
        return list(sess.get("_flashes", []))


def post(client, **form):
    form.setdefault("log_file", LOG)
    form.setdefault("rotate_mb", "10")
    form.setdefault("old_files", "4")
    return client.post(URL, data=form)


def running_options(daemon):
    entry = next((x for x in daemon.running.get("loggers") or [] if x.get("name") == "kea-dhcp4"), None)
    return [
        {k: v for k, v in o.items() if not (k == "flush" or (k == "pattern" and v == ""))}
        for o in (entry or {}).get("output-options", [])
    ]


def audit_rows(db, action="KEA_LOG_OUTPUT"):
    db.commit()
    with db.cursor() as cur:
        cur.execute("SELECT details FROM audit_log WHERE action=%s ORDER BY id", (action,))
        return [row["details"] if isinstance(row, dict) else row[0] for row in cur.fetchall()]


def at(daemon, severity):
    daemon.file["loggers"][0]["severity"] = severity
    daemon.running["loggers"][0]["severity"] = severity


BUSY = (
    "The logging of kea-a is being changed right now (Settings → Kea → Kea logging, or investigation logging being turned on). "
    "Nothing was changed; try again in a few seconds."
)


class TestOneChangeAtATime:
    def test_the_hold_is_taken_once_and_given_back(self, server):
        assert klt.hold_log_output(server) is True
        assert klt.hold_log_output(server) is False
        assert klt.hold_log_output({"id": SID + 1}) is True  # another server is not held by it
        klt.release_log_output({"id": SID + 1})
        klt.release_log_output(server)
        assert klt.hold_log_output(server) is True

    def test_a_second_save_inside_the_first_ones_proof_window_is_refused_and_sends_nothing(
        self, server, daemon, host, monkeypatch
    ):
        """The pass's sequence: a save to a file Kea may not write is between its write and its put-back when a second save of the same server arrives."""
        host.writes_log = False
        inside, go_on, second = threading.Event(), threading.Event(), {}
        first_thread = {}

        def proof_sleep(_seconds):
            if threading.get_ident() == first_thread.get("id"):
                inside.set()
                assert go_on.wait(30)

        monkeypatch.setattr(klt, "_proof_sleep", proof_sleep)

        def first():
            first_thread["id"] = threading.get_ident()
            first_thread["out"] = klt.change_log_output(server, "file", LOG, MB10, 4)

        t = threading.Thread(target=first)
        t.start()
        assert inside.wait(30)
        sets_before, calls_before = daemon.commands.count("config-set"), len(host.calls)
        second = klt.change_log_output(server, "file", OTHER, MB10, 4)
        assert (second["ok"], second["code"], second["lines"]) == (False, "busy", [BUSY])
        assert daemon.commands.count("config-set") == sets_before and len(host.calls) == calls_before
        go_on.set()
        t.join(60)
        assert first_thread["out"]["code"] == "put-back"
        assert running_options(daemon) == [PACKAGED]  # what Kea ran before either save
        assert klt.hold_log_output(server) is True  # ... and the hold was given back

    def test_the_route_says_busy_and_writes_no_audit_row(self, logged_in_client, server, daemon, host, db):
        assert klt.hold_log_output(server)
        post(logged_in_client, output="file")
        assert flashes(logged_in_client) == [("error", BUSY)]
        assert host.calls == [] and audit_rows(db) == []

    def test_investigation_logging_is_not_turned_on_while_the_card_holds_the_server(self, server, daemon, host):
        assert klt.hold_log_output(server)
        out = inv.turn_on(server, 5, actor="alice")
        assert out == {"ok": False, "mode": "", "lines": [BUSY], "until": ""}
        assert host.calls == [] and "config-set" not in daemon.commands
        assert klt.hold_log_output(server) is False  # the refused turn-on did not give back a hold that was not its own

    def test_a_turn_on_gives_the_hold_back_however_it_ends(self, server, monkeypatch):
        monkeypatch.setattr(inv, "enabled", lambda: False)
        assert inv.turn_on(server, 5)["ok"] is False  # refused for its own reason, after taking the hold
        assert klt.hold_log_output(server) is True
        klt.release_log_output(server)

        def boom():
            raise RuntimeError("x")

        monkeypatch.setattr(inv, "enabled", boom)
        with pytest.raises(RuntimeError):
            inv.turn_on(server, 5)
        assert klt.hold_log_output(server) is True

    def test_a_change_gives_the_hold_back_when_it_raises(self, server, monkeypatch):
        def boom(_server, timeout=10):
            raise RuntimeError("x")

        monkeypatch.setattr(klt, "running_logger_config", boom)
        with pytest.raises(RuntimeError):
            klt.change_log_output(server, "journal")
        assert klt.hold_log_output(server) is True

    def test_only_the_change_and_the_turn_on_take_the_hold__whole_tree(self):
        """Turning logging OFF, the sweep, Forget and the Kea host's restore are never held back: the hold is taken in exactly two functions of the tree."""
        takers = set()
        for path in sorted((ROOT / "jen").rglob("*.py")) + sorted((ROOT / "plugins").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
                for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
                    name = getattr(call.func, "attr", getattr(call.func, "id", ""))
                    if name == "hold_log_output":
                        takers.add(f"{path.relative_to(ROOT).as_posix()}::{fn.name}")
        assert takers == {
            "jen/services/kea_log_trace.py::change_log_output",
            "jen/services/investigation_logging.py::_holds_the_logger",
            "jen/services/investigation_logging.py::held",
        }, takers

    def test_turn_on_is_the_only_function_the_hold_wraps(self):
        tree = ast.parse((ROOT / "jen/services/investigation_logging.py").read_text(encoding="utf-8"))
        wrapped = [
            fn.name
            for fn in tree.body
            if isinstance(fn, ast.FunctionDef)
            and any(getattr(d, "id", "") == "_holds_the_logger" for d in fn.decorator_list)
        ]
        assert wrapped == ["turn_on"]


class TestTheProofIsKeasOwnLine:
    def test_a_file_another_process_appends_to_is_not_proof_and_the_change_is_put_back(
        self, server, daemon, host, monkeypatch
    ):
        host.writes_log = False  # kea-dhcp4 may not write the file ...
        reads = {"n": 0}

        def log_lines(path):  # ... and something else appends to it between every read
            reads["n"] += 1
            return [f"04:10:{n:02d} another-daemon line {n}" for n in range(reads["n"])]

        monkeypatch.setattr(host, "log_lines", log_lines)
        before_file = copy.deepcopy(daemon.file)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert daemon.file == before_file and running_options(daemon) == [PACKAGED]


class TestAboveInfo:
    def test_a_new_output_on_a_file_that_was_already_there_is_put_back_and_says_what_to_do(
        self, logged_in_client, server, daemon, host, db
    ):
        at(daemon, "WARN")
        host.writes_log = False  # the pass's world: root's file, mode 0600, and Kea logs nowhere
        host.existing[LOG] = []
        before_file = copy.deepcopy(daemon.file)
        post(logged_in_client, output="file")
        assert (
            flashes(logged_in_client)
            == [
                (
                    "error",
                    f"Kea accepted the change on kea-a but Jen could not prove that it writes to {LOG}, so the previous logging was put back. "
                    f"Jen asked kea-dhcp4 on kea-a to write a line to {LOG} and did not find it there in the seconds it watched. Check that the file is writable by the "
                    "account kea-dhcp4 runs as, and that nothing moved or replaced it meanwhile.",  # (Q252) at WARN Kea is asked for a line: the cause is what Jen did and read
                )
            ]
        )
        assert daemon.file == before_file and running_options(daemon) == [PACKAGED]
        assert audit_rows(db) == [
            f"kea-a: the system journal (stdout) -> the file {LOG} was accepted by Kea, not proven, and put back"
        ]

    def test_the_advice_is_satisfiable_a_name_that_does_not_exist_is_created_and_stands(self, server, daemon, host):
        at(
            daemon, "FATAL"
        )  # (Q252) at WARN and ERROR Kea is asked for a line; FATAL and NONE are where the file Kea created is the proof
        out = klt.change_log_output(server, "file", OTHER, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "created"), out
        assert out["lines"][-1] == (
            f"Kea created {OTHER} on kea-a. Its severity is FATAL, so it has written no line yet; the file fills when Kea next logs at that level."
        )

    def test_a_file_kea_could_not_create_is_put_back(self, server, daemon, host):
        at(daemon, "WARN")
        host.writes_log = False  # nothing was there before, nothing is there after
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back")
        assert out["lines"] == [  # (Q252) at WARN Kea is asked: the cause is the line that did not arrive
            f"Kea accepted the change on kea-a but Jen could not prove that it writes to {LOG}, so the previous logging was put back. "
            f"Jen asked kea-dhcp4 on kea-a to write a line to {LOG} and did not find it there in the seconds it watched. Check that the file is writable by the "
            "account kea-dhcp4 runs as, and that nothing moved or replaced it meanwhile."
        ]

    def test_the_file_the_logger_already_wrote_to_stands_unchecked(self, server, daemon, host):
        """file -> the journal and the SAME file: nothing about the file is new, so there is nothing to prove and nothing to put back."""
        entry = {"name": "kea-dhcp4", "output-options": [dict(FILE_LOGGER)], "severity": "FATAL", "debuglevel": 0}
        daemon.file = dhcp4([entry])
        daemon.running = kea_writes_defaults(dhcp4([entry]))
        host.existing[LOG] = []
        out = klt.change_log_output(server, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"], out["level"]) == (True, "unchecked", "warning"), out
        assert out["lines"][
            -1
        ] == (  # (Q251) the sentence names the evidence, and the change set's own lines come before it
            f"Kea accepted the change on kea-a. Its severity is FATAL, so it wrote no line Jen could check; {LOG} is a file its logger already named, and this change takes no output away."
        )
        assert out["note"] == " (not checked: severity FATAL)"
        assert host.ops().count("apply-config") == 1


NO_WRITE = (
    "Jen has no way to change kea-a: its write mode is Read-only, or it is File over SSH and no SSH is configured. "
    "Choose how changes reach it in the Write mode card on this page first."
)


class TestNoWritePath:
    @pytest.mark.parametrize("change", [{"config_transport": "off"}, {"ssh_host": ""}])
    def test_the_card_draws_no_form_and_says_why(self, logged_in_client, server, daemon, change):
        server.update(change)
        card = klt.log_output_card(server)
        assert card["readable"] is True and card["can_change"] is False and card["no_write_path"] == NO_WRITE
        html = logged_in_client.get("/settings/kea").get_data(as_text=True).split('id="kea-logging"')[1]
        html = html.split("<!-- Servers & HA -->")[0]
        assert NO_WRITE in html and "data-kl-no-write-path" in html
        assert "Save Kea Logging" not in html and URL not in html
        assert "Kea writes its log to" in html  # what the daemon says is still shown

    @pytest.mark.parametrize("change", [{"config_transport": "off"}, {"ssh_host": ""}])
    @pytest.mark.parametrize("choice", ["journal", "file", "both"])
    def test_a_post_is_refused_with_the_reason_and_nothing_is_sent(
        self, logged_in_client, server, daemon, host, db, change, choice
    ):
        server.update(change)
        post(logged_in_client, output=choice)
        assert flashes(logged_in_client) == [("error", NO_WRITE + " Nothing was changed.")]
        assert host.calls == [] and daemon.commands == [] and audit_rows(db) == []

    def test_a_server_with_a_write_path_keeps_its_form(self, logged_in_client, server):
        assert klt.log_output_card(server)["can_change"] is True
        html = logged_in_client.get("/settings/kea").get_data(as_text=True)
        assert URL in html and "data-kl-no-write-path" not in html

    def test_a_live_api_server_with_no_ssh_keeps_the_journal_choice_and_is_told_about_the_file(
        self, server, daemon, host
    ):
        server.update({"config_transport": "api", "ssh_host": ""})
        assert klt.log_output_card(server)["can_change"] is True
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["code"], out["lines"]) == ("no-ssh", [klt.no_ssh_sentence("kea-a")])


class TestTheAuditRow:
    def test_a_put_back_is_audited_and_a_refusal_before_the_write_is_not(
        self, logged_in_client, server, daemon, host, db
    ):
        host.writes_log = False
        post(logged_in_client, output="both")
        assert audit_rows(db) == [
            f"kea-a: the system journal (stdout) -> the system journal and the file {LOG} was accepted by Kea, not proven, and put back"
        ]
        post(logged_in_client, output="journal")  # nothing to change: no row
        assert len(audit_rows(db)) == 1


class TestTheDoctor:
    def _ids(self, option):
        cfg = dhcp4([{"name": "kea-dhcp4", "output-options": [option], "severity": "INFO"}])
        return [f["id"] for f in doctor.diagnose(cfg, hosts=[])]

    def test_what_kea_writes_back_for_its_default_pattern_is_not_a_missing_timestamp(self):
        written_back = kea_writes_defaults(dhcp4([{"name": "kea-dhcp4", "output-options": [dict(FILE_LOGGER)]}]))
        assert written_back["loggers"][0]["output-options"][0]["pattern"] == ""
        assert "logger-pattern-no-timestamp" not in [f["id"] for f in doctor.diagnose(written_back, hosts=[])]
        assert "logger-pattern-no-timestamp" not in self._ids({"output": LOG, "pattern": ""})

    def test_a_pattern_that_really_has_no_date_is_still_named(self):
        assert "logger-pattern-no-timestamp" in self._ids({"output": LOG, "pattern": "%-5p %m\n"})
        assert "logger-pattern-no-timestamp" not in self._ids({"output": LOG})

    def test_the_note_says_whose_card_it_is(self):
        note = next(f for f in doctor.diagnose(dhcp4([packaged_logger()]), hosts=[]) if f["id"] == "logger-no-file")
        assert "A superadmin can choose a file under Settings → Kea → Kea logging; or paste this into" in note["detail"]


class TestTheReadersFollow:
    @pytest.fixture
    def clears(self, monkeypatch):
        seen = {"n": 0}
        real = log_tail.clear

        def clear():
            seen["n"] += 1
            real()

        monkeypatch.setattr(log_tail, "clear", clear)
        return seen

    def test_a_change_that_stands_forgets_the_remembered_path(self, server, daemon, host, clears):
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["code"] == "ok"
        assert clears["n"] == 1

    def test_a_put_back_forgets_it_again(self, server, daemon, host, clears):
        host.writes_log = False
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["code"] == "put-back"
        assert clears["n"] == 2

    def test_a_refusal_before_the_write_forgets_nothing(self, server, daemon, host, clears):
        assert klt.change_log_output(server, "journal")["code"] == "nochange"
        assert klt.change_log_output(server, "syslog")["code"] == "bad-choice"
        assert clears["n"] == 0
