"""
tests/test_q253.py
──────────────────
Q253 (7.2.2) - what Opus's pass on v7.2.1 found in the proof of a change of Kea's log output (`kea_log_trace.change_log_output`, INV-017). Two were NEW in 7.2.1:

    BM1  a busy server      Jen read the last 60 lines of the file; a server writing more than that between the ask and the read pushed the asked line out of
                            them on every try, and a working change was put back. It reads the most the Kea host's helper returns now (1000).
    BM3  a logger entry     `kea-dhcp4.commands` or `kea-dhcp4.dhcp4` with an entry of its own (another severity, other outputs) kept the asked line out of the
         of its own         file. The line asked for is chosen from the configuration now (`kea_config_edit.logger_proof_ask`); with both, no line is asked
                            for and the change goes the way FATAL and NONE go.
    BM9  the record         at FATAL and NONE the `unchecked` answer recorded a read of the log without looking at the read it made.
    BM10 the sentences      a daemon that stopped was told "check that the file is writable"; a put-back that found nothing to change said "was put back";
                            the change set's line ran into the next sentence.
    BM2  what is assumed    with the journal kept, the asked line is in the journal too. INV-017 says so (it said the opposite).

The world is `tests/_q249_a_world.py`: a stateful fake Kea reached over real HTTP by the REAL `kea_command`, and `KeaHost.helper_call` for the helper. Nothing of
`kea_log_trace` is faked. The same rows against a real kea-dhcp4 3.0.5 and 3.2.1 are `pass/q253/realkea/` (the ledger of the entry carries what they showed).
"""

import copy
import pathlib
import re

import pytest

from jen import extensions
from jen.services import client_problems as problems
from jen.services import kea_config_edit as edit
from jen.services import kea_host
from jen.services import kea_log_trace as klt
from tests._q249_a_world import FILE_LOGGER, PACKAGED, KeaHost, dhcp4, file_server, kea_writes_defaults
from tests.e2e._fake_kea_server import StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
SID = 253  # a server id no other test file uses
LOG = "/var/log/kea/kea-dhcp4.log"
MB10 = 10 * 1024 * 1024
URL = f"/settings/infrastructure/kea-logging/{SID}"
COMMANDS = "kea-dhcp4.commands"
DHCP4 = "kea-dhcp4.dhcp4"
OWN = "The loggers kea-dhcp4.commands and kea-dhcp4.dhcp4 each have an entry of their own in its configuration"
OWN_AT_WARN = "Its severity is WARN and the logger kea-dhcp4.dhcp4 has an entry of its own in its configuration"
UNPROVEN = f"Kea accepted the change on kea-a but Jen could not prove that it writes to {LOG}"
NOT_FOUND = (
    f"Jen asked kea-dhcp4 on kea-a to write a line to {LOG} and did not find that line in the last 1000 lines of the file, on any of 5 reads. "
    "Check that the file is writable by the account kea-dhcp4 runs as, and that nothing moved or replaced it meanwhile. "
    "A server that logs more lines than that between the ask and the read gives the same result."
)
NO_ANSWER = (
    f"Jen asked kea-dhcp4 on kea-a to write a line to {LOG} and kea-dhcp4 did not answer on any of 5 tries, so nothing could be proven. "
    "See the Kea Servers page."
)


def entry(name="kea-dhcp4", severity="INFO", options=None):
    out = {"name": name, "severity": severity, "debuglevel": 0}
    if options is not None:
        out["output-options"] = copy.deepcopy(options)
    return out


def loggers_on(daemon, *entries):
    daemon.file = dhcp4(list(entries))
    daemon.running = kea_writes_defaults(dhcp4(list(entries)))


@pytest.fixture
def daemon():
    d = StatefulKeaServer(dhcp4([entry(options=[dict(PACKAGED)])]))
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


def _forget(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM settings WHERE setting_key LIKE %s", (f"client_problems_%:{SID}",))
        cur.execute("DELETE FROM kea_config_revisions WHERE server_id=%s", (SID,))
    db.commit()


@pytest.fixture
def server(monkeypatch, daemon, host, db):
    s = file_server(daemon, id=SID)
    monkeypatch.setattr(extensions, "KEA_SERVERS", [s])
    _forget(db)
    yield s
    klt.release_log_output(s)
    _forget(db)


@pytest.fixture(autouse=True)
def no_wait(monkeypatch):
    monkeypatch.setattr(klt, "_proof_sleep", lambda seconds: None)


def asked(daemon):
    """What the proof sent, in order: "command" for the command Kea does not know, "config-test" for the configuration test Kea refuses."""
    out = []
    for command, arguments in daemon.received:
        if command.startswith(klt.PROOF_PREFIX):
            out.append("command")
        elif command == "config-test" and any(k.startswith(klt.PROOF_PREFIX) for k in arguments.get("Dhcp4") or {}):
            out.append("config-test")
    return out


def running_outputs(daemon):
    main = next((x for x in daemon.running.get("loggers") or [] if x.get("name") == "kea-dhcp4"), None)
    return [o["output"] for o in (main or {}).get("output-options", [])]


def record(db, server):
    db.commit()
    return problems.read_status([server])["servers"][0]


def seed_blind(db):
    """The sweep's record of a server whose log it cannot find: what Health and the dashboard's banner read."""
    with db.cursor() as cur:
        for key, value in (("miss", "7"), ("err", "missing"), ("path", LOG)):
            cur.execute(
                "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
                (f"client_problems_{key}:{SID}", value),
            )
    db.commit()


class TestWhichLineIsAskedFor:
    """`kea_config_edit.logger_proof_ask`: pure."""

    @pytest.mark.parametrize(
        "severity, others, want",
        [
            ("INFO", [], "command"),
            ("DEBUG", [], "command"),
            ("debug", [], "command"),
            ("WARN", [], "config-test"),
            ("ERROR", [], "config-test"),
            ("FATAL", [], "none"),
            ("NONE", [], "none"),
            (
                "INFO",
                [COMMANDS],
                "config-test",
            ),  # the commands logger may send its line elsewhere: ask through the other one
            ("DEBUG", [COMMANDS], "config-test"),
            ("INFO", [DHCP4], "command"),
            ("INFO", [COMMANDS, DHCP4], "none"),
            ("WARN", [COMMANDS], "config-test"),
            ("WARN", [DHCP4], "none"),
            ("ERROR", [DHCP4], "none"),
            ("FATAL", [COMMANDS, DHCP4], "none"),
            (
                "INFO",
                ["kea-dhcp4.leases", "kea-dhcp4.packets"],
                "command",
            ),  # an entry for a logger Jen does not ask through changes nothing
        ],
    )
    def test_from_the_severity_and_the_entries(self, severity, others, want):
        cfg = {"Dhcp4": dhcp4([entry(severity=severity)] + [entry(name=n, severity="DEBUG") for n in others])}
        assert edit.logger_proof_ask(cfg) == want
        assert want in edit.LOGGER_PROOF_ASKS

    def test_an_entry_of_its_own_counts_whatever_it_holds(self):
        """Jen does not model what such an entry does: the name is enough (an entry with the same severity and no outputs chooses the other line too)."""
        cfg = {"Dhcp4": dhcp4([entry(), {"name": COMMANDS}])}
        assert edit.logger_proof_ask(cfg) == "config-test"

    @pytest.mark.parametrize("cfg", [{}, None, {"Dhcp4": {}}, {"Dhcp4": dhcp4()}, {"Dhcp4": {"loggers": "x"}}])
    def test_a_configuration_with_no_logger_is_kea_at_info(self, cfg):
        assert edit.logger_proof_ask(cfg) == "command"

    def test_the_names_are_the_ones_kea_was_measured_to_write_with(self):
        assert edit.LOGGER_PROOF_PARTS == {"command": COMMANDS, "config-test": DHCP4}
        assert edit.LOGGER_PROOF_ASKS == ("command", "config-test", "none")

    def test_the_card_reads_it_in_one_place(self):
        """The choice is `change_log_output`'s only: one call in the product, and the severity alone no longer decides whether Kea is asked."""
        calls = []
        for path in sorted((ROOT / "jen").rglob("*.py")) + sorted((ROOT / "plugins").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            calls += [
                (path.name, n) for n in range(text.count("logger_proof_ask(")) if path.name != "kea_config_edit.py"
            ]
        assert calls == [("kea_log_trace.py", 0)], calls
        source = (ROOT / "jen/services/kea_log_trace.py").read_text(encoding="utf-8")
        assert 'if severity in ("", "WARN", "ERROR"):' not in source


class TestALoggerWithAnEntryOfItsOwn:
    """BM3. On 7.2.1 the first four were put back, with "check that the file is writable"."""

    @pytest.mark.parametrize(
        "own",
        [
            entry(name=COMMANDS, severity="WARN"),
            entry(name=COMMANDS, severity="INFO", options=[{"output": "stdout"}]),
            entry(name=COMMANDS, severity="FATAL", options=[{"output": "/var/log/kea/commands.log"}]),
        ],
    )
    def test_the_commands_logger_has_one_and_the_other_line_is_asked_for(self, server, daemon, host, own):
        loggers_on(daemon, entry(options=[dict(PACKAGED)]), own)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out
        assert out["lines"][-1] == f"Kea is writing to {LOG} on kea-a."
        assert asked(daemon) == ["config-test"]
        assert running_outputs(daemon) == [LOG]

    def test_the_dhcp4_logger_has_one_and_the_command_is_asked_for(self, server, daemon, host):
        loggers_on(daemon, entry(options=[dict(PACKAGED)]), entry(name=DHCP4, severity="FATAL"))
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out
        assert asked(daemon) == ["command"]

    def test_the_line_asked_for_through_a_logger_with_an_entry_would_not_have_arrived(self, server, daemon, host):
        """The control inside the world: the line 7.2.1 asked for is not in the file, and the one this release asks for is."""
        loggers_on(daemon, entry(options=[dict(PACKAGED)]), entry(name=COMMANDS, severity="WARN"))
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["ok"] is True
        assert klt._ask_for_a_line(server, klt.PROOF_PREFIX + "c0" * 16, "command") is True
        written = host.written[LOG]
        assert not any("COMMAND_RECEIVED" in line for line in written)
        assert any("DHCP4_PARSER_FAIL" in line for line in written)

    @pytest.mark.parametrize("severity", ["INFO", "WARN"])
    def test_both_have_one_and_a_new_file_stands_on_kea_having_made_it(self, server, daemon, host, severity):
        others = [entry(name=DHCP4, severity="ERROR")] + ([entry(name=COMMANDS)] if severity == "INFO" else [])
        loggers_on(daemon, entry(severity=severity, options=[dict(PACKAGED)]), *others)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"], out["level"]) == (True, "created", "success"), out
        why = OWN if severity == "INFO" else OWN_AT_WARN  # the words say which logger it was (found on the real Kea)
        assert out["lines"][-1] == (
            f"Kea created {LOG} on kea-a. {why}, so there was no line Jen could ask for; the file fills as Kea logs."
        )
        assert out["note"] == " (proven by the file Kea created: a logger entry of its own)"
        assert asked(daemon) == []

    def test_both_have_one_and_a_file_that_was_there_is_put_back(self, server, daemon, host):
        loggers_on(daemon, entry(options=[dict(PACKAGED)]), entry(name=COMMANDS), entry(name=DHCP4))
        host.existing[LOG] = []
        before = copy.deepcopy(daemon.file)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"] == [
            f"{UNPROVEN}, so the previous logging was put back. {OWN}, so there is no line Jen can ask kea-dhcp4 to write, and {LOG} was already there, "
            "so Jen could not tell whether kea-dhcp4 may write it. Choose a file name that does not exist yet (Kea creates it, and that is the proof)."
        ]
        assert asked(daemon) == [] and daemon.file == before and running_outputs(daemon) == ["stdout"]

    def test_both_have_one_and_a_named_file_that_loses_no_output_stands_unchecked(self, server, daemon, host):
        loggers_on(daemon, entry(options=[dict(FILE_LOGGER)]), entry(name=COMMANDS), entry(name=DHCP4))
        host.existing[LOG] = []
        out = klt.change_log_output(server, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"], out["level"]) == (True, "unchecked", "warning"), out
        assert out["lines"][-1] == (
            f"Kea accepted the change on kea-a. {OWN}, so there was no line Jen could ask for and check; {LOG} is a file its logger already named, "
            "and this change takes no output away."
        )
        assert out["note"] == " (not checked: a logger entry of its own)"

    def test_the_entries_of_their_own_are_left_as_they_were(self, server, daemon, host):
        own = entry(name=COMMANDS, severity="WARN", options=[{"output": "stdout"}])
        loggers_on(daemon, entry(options=[dict(PACKAGED)]), own)
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["ok"] is True
        assert [x for x in daemon.file["loggers"] if x["name"] == COMMANDS] == [own]


class TestABusyServer:
    """BM1. The server's own lines land between the ask and the read."""

    @staticmethod
    def busy(daemon, host, lines):
        real = host.kea_received

        def and_logs_its_own(fake, command, arguments):
            real(fake, command, arguments)
            if LOG in host.written:
                host.written[LOG].extend(
                    host.kea_line("INFO", "commands", "COMMAND_RECEIVED Received command 'status-get'")
                    for _ in range(lines)
                )

        daemon.on_command = and_logs_its_own

    @pytest.mark.parametrize("lines", [59, 60, 500, 999])
    def test_the_asked_line_is_still_in_what_jen_reads(self, server, daemon, host, lines):
        """60 and more were put back on 7.2.1 (`LOG_OUTPUT_TAIL = 60`)."""
        self.busy(daemon, host, lines)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out
        assert asked(daemon) == ["command"]

    def test_every_read_of_the_proof_asks_for_the_helpers_most(self, server, daemon, host):
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["ok"] is True
        assert [p["lines"] for op, p in host.calls if op == "tail-log"] == [1000, 1000]

    def test_the_helper_returns_that_many(self):
        """One number in two files: the helper caps what `tail-log` returns, and the proof reads exactly that much."""
        helper = (ROOT / "jen-kea-helper").read_text(encoding="utf-8")
        (cap,) = re.findall(r"lines = max\(1, min\(lines, (\d+)\)\)", helper)
        assert int(cap) == klt.LOG_OUTPUT_TAIL == 1000

    def test_past_what_the_helper_returns_it_is_put_back_and_the_sentence_says_what_jen_read(
        self, server, daemon, host
    ):
        self.busy(daemon, host, 1000)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"] == [f"{UNPROVEN}, so the previous logging was put back. {NOT_FOUND}"]
        assert len(asked(daemon)) == klt.LOG_OUTPUT_TRIES
        assert running_outputs(daemon) == ["stdout"]


class TestTheRecordOfARead:
    """BM9."""

    def test_unchecked_with_the_file_there_records_the_read(self, server, daemon, host, db):
        loggers_on(daemon, entry(severity="FATAL", options=[dict(FILE_LOGGER)]))
        host.existing[LOG] = []
        seed_blind(db)
        out = klt.change_log_output(server, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "unchecked"), out
        assert record(db, server)["misses"] == 0

    def test_unchecked_with_the_file_not_there_records_nothing(self, server, daemon, host, db):
        """The logger names the file, Kea may not write it and it is not there: the change stands unchecked (it takes nothing away) and the sweep's record of a
        log it cannot find stays as the sweep left it."""
        loggers_on(daemon, entry(severity="FATAL", options=[dict(FILE_LOGGER)]))
        host.writes_log = False
        seed_blind(db)
        before = record(db, server)
        out = klt.change_log_output(server, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "unchecked"), out
        assert record(db, server) == before and before["misses"] == 7


class TestTheSentences:
    """BM10."""

    def test_a_daemon_that_stops_answering_is_not_told_to_check_the_file(self, server, daemon, host):
        real = host.helper_call

        def and_then_it_is_gone(srv, op, payload=None, timeout=60):
            out = real(srv, op, payload, timeout)
            if op == "service":
                daemon.stopped = True  # restarted with the new logger, and it answers nothing after that
            return out

        kea_host.helper_call = and_then_it_is_gone  # the fixture's monkeypatch puts the real one back
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"] == [f"{UNPROVEN}, so the previous logging was put back. {NO_ANSWER}"]
        assert "writable" not in out["lines"][0]

    def test_one_answer_is_enough_to_say_the_line_was_not_found(self, server, daemon, host):
        host.writes_log = False
        real = host.kea_received

        def answers_once(fake, command, arguments):
            real(fake, command, arguments)
            if command.startswith(klt.PROOF_PREFIX):
                fake.stopped = True

        daemon.on_command = answers_once
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert out["code"] in ("put-back", "put-back-failed"), out
        assert NOT_FOUND in out["lines"][0] and NO_ANSWER not in out["lines"][0]

    def test_a_put_back_that_found_the_previous_logging_in_place_says_so(self, server, daemon, host, monkeypatch):
        host.writes_log = False
        before_file, before_running = copy.deepcopy(daemon.file), copy.deepcopy(daemon.running)

        def someone_restores_it(seconds):
            daemon.file, daemon.running = copy.deepcopy(before_file), copy.deepcopy(before_running)

        monkeypatch.setattr(klt, "_proof_sleep", someone_restores_it)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"] == [
            f"{UNPROVEN}. The previous logging was already in place when Jen went to put it back. {NOT_FOUND}"
        ]
        assert "was put back" not in out["lines"][0]

    @pytest.mark.parametrize(
        "text, want",
        [("a line", "a line."), ("a line.", "a line."), ("is it?", "is it?"), ("a line  ", "a line."), ("", "")],
    )
    def test_a_line_of_the_change_set_ends_as_a_sentence(self, text, want):
        assert klt._as_sentence(text) == want

    def test_the_put_back_that_fails_runs_no_two_sentences_together(self, server, daemon, host):
        host.writes_log = False
        host.apply_fails_from = 2  # the change is written; the put-back is not
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert out["code"] == "put-back-failed", out
        (said,) = out["lines"]
        assert not re.search(r"[^.!?:] (kea-a now writes|Jen could not ask|Jen asked)", said), said
        assert said.endswith(f" kea-a now writes its log to the file {LOG}. {NOT_FOUND} Then choose again.")

    def test_no_sentence_names_seconds_jen_did_not_count(self):
        source = (ROOT / "jen/services/kea_log_trace.py").read_text(encoding="utf-8")
        assert "in the seconds it watched" not in source


class TestWhatTheRegistryAssumes:
    """BM2: INV-017 said a line a forwarder copied from the journal proves nothing. With the journal KEPT that is untrue, and the registry says what is true."""

    def test_inv_017_states_the_journal_case(self):
        text = (ROOT / "docs/SAFETY_INVARIANTS.md").read_text(encoding="utf-8")
        inv = (
            text[text.index("### INV-017") : text.index("### INV-018")]
            if "### INV-018" in text
            else text[text.index("### INV-017") :]
        )
        assert "a line a forwarder copied from the journal" not in inv
        assert (
            "when the change keeps the journal beside the file, the line Jen asks for is written to the journal too"
            in " ".join(inv.split())
        )

    def test_with_the_journal_kept_a_rewritten_copy_of_the_asked_line_proves(self, server, daemon, host, monkeypatch):
        """The limit INV-017 states, as the world can model it: Kea may not write the file, the change keeps the journal, and a program rewrites every journal line
        into Kea's default shape and appends it to the file. Kea still logs to the journal. (Measured on kea-dhcp4 3.0.5 and 3.2.1: BM2 of the pass on v7.2.1.)"""
        host.writes_log = False
        host.existing[LOG] = []

        def rewritten(path):
            """The journal output this card writes has the package's pattern, `LEVEL message` with no date and no bracket: the program puts them back."""
            out = []
            for n, line in enumerate(host.journal):
                level, message = line[:5].strip(), line[6:]
                part = "commands" if message.startswith("COMMAND_RECEIVED") else "dhcp4"
                out.append(
                    f"2026-11-27 10:00:{n % 60:02d}.000 {level:<5} [kea-dhcp4.{part}/{daemon.pid}.140] {message}"
                )
            return out

        monkeypatch.setattr(host, "log_lines", rewritten)
        out = klt.change_log_output(server, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out
        assert "stdout" in running_outputs(daemon)  # Kea is not logging nowhere
        assert LOG not in host.written  # and wrote nothing to the file

    def test_with_the_journal_dropped_the_same_program_proves_nothing(self, server, daemon, host, monkeypatch):
        loggers_on(daemon, entry(options=[{"output": "stdout"}]))
        host.writes_log = False
        host.existing[LOG] = []
        monkeypatch.setattr(host, "log_lines", lambda path: list(host.journal))
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert running_outputs(daemon) == ["stdout"]


class TestThroughTheCard:
    """The route, the flash and the audit row of the two NEW results."""

    def post(self, client, **form):
        form.setdefault("log_file", LOG)
        form.setdefault("rotate_mb", "10")
        form.setdefault("old_files", "4")
        return client.post(URL, data=form)

    def flashes(self, client):
        with client.session_transaction() as sess:
            return list(sess.get("_flashes", []))

    def audit(self, db):
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT details FROM audit_log WHERE action='KEA_LOG_OUTPUT' ORDER BY id")
            return [row["details"] if isinstance(row, dict) else row[0] for row in cur.fetchall()]

    def test_a_logger_entry_of_its_own_and_the_change_stands(self, logged_in_client, server, daemon, host, db):
        loggers_on(daemon, entry(options=[dict(PACKAGED)]), entry(name=COMMANDS, severity="WARN"))
        self.post(logged_in_client, output="file")
        assert self.flashes(logged_in_client)[-1] == ("success", f"Kea is writing to {LOG} on kea-a.")
        assert self.audit(db) == [f"kea-a: the system journal (stdout) -> the file {LOG}"]

    def test_both_entries_and_the_note_is_in_the_audit_row(self, logged_in_client, server, daemon, host, db):
        loggers_on(daemon, entry(options=[dict(PACKAGED)]), entry(name=COMMANDS), entry(name=DHCP4))
        self.post(logged_in_client, output="file")
        assert self.audit(db) == [
            f"kea-a: the system journal (stdout) -> the file {LOG} (proven by the file Kea created: a logger entry of its own)"
        ]
