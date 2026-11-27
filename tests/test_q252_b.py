"""
tests/test_q252_b.py
────────────────────
Q252 - the proof of a change of Kea's log output (INV-017) is a line that carries a value Jen sent to the running daemon AFTER the change. Four passes in a row found
a writer that satisfied "who wrote this line?" (a plain writer, an imitation, a forwarder of kea-dhcp4's own journal, a writer that reads the process id); a file
cannot answer that. It can answer "did the line Jen asked for arrive?".

    TestTheLineThatProves          the two message shapes, and everything that is not one of them
    TestWhatIsAsked                the value, and what is sent at each severity
    TestAskedAtInfoAndDebug        proven by `COMMAND_RECEIVED Received command '<value>'`; a forwarder of the journal proves nothing once the journal is dropped
    TestAskedAtWarnAndError        proven by the one ERROR line of a `config-test` Kea refuses; a file the logger named and Kea cannot write is put back
    TestFatalAndNone               Kea cannot be asked: a file Kea created, or a named file that lost no output; anything else is put back
    TestStatusGetIsNeverAsked      the process id is no part of the proof any more
    TestTheSentences               what a put-back says: what Jen did and read, never what Kea did; a daemon that did not answer is not said to write anywhere
    TestOverTheDaemonsOwnApi       the same proof on a Live API server

The world is `tests/_q249_a_world.py`: a stateful fake Kea reached over real HTTP by the REAL `kea_command`, which writes its log when a command arrives exactly as
kea-dhcp4 3.0.5 and 3.2.1 were measured to (`pass/q252/b/out/measure.*.json`), and `KeaHost.helper_call` for the helper's log read. Nothing of `kea_log_trace` is
faked. The same rows against a real kea-dhcp4 on both transports and both versions are `pass/q252/b/test_q252_realkea.py`.
"""

import ast
import copy
import pathlib

import pytest

from jen import extensions
from jen.services import kea_changeset as changeset
from jen.services import kea_host
from jen.services import kea_log_trace as klt
from tests._q249_a_world import FILE_LOGGER, PACKAGED, KeaHost, dhcp4, file_server, kea_writes_defaults, packaged_logger
from tests.e2e._fake_kea_server import StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
SID = 252  # a server id no other test file uses
LOG = "/var/log/kea/kea-dhcp4.log"
OTHER = "/var/log/kea/second.log"
MB10 = 10 * 1024 * 1024
URL = f"/settings/infrastructure/kea-logging/{SID}"
V = "jen-log-proof-" + "0f" * 16
W = "jen-log-proof-" + "a1" * 16
HEAD = "2026-11-25 14:17:56.621"
BOTH = [dict(PACKAGED), dict(FILE_LOGGER)]


def received(value=V, pid=81):
    return f"{HEAD} INFO  [kea-dhcp4.commands/{pid}.133455821575488] COMMAND_RECEIVED Received command '{value}'"


def refused(value=V, pid=81):
    return (
        f"{HEAD} ERROR [kea-dhcp4.dhcp4/{pid}.133455821575488] DHCP4_PARSER_FAIL failed to create or run parser for configuration element {value}: "
        f"unsupported global configuration parameter: {value} (<string>:1:102)"
    )


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
    """The second between two tries (`_proof_sleep`, "a name the tests replace"); a test that needs the moment replaces it again."""
    monkeypatch.setattr(klt, "_proof_sleep", lambda seconds: None)


def flashes(client):
    with client.session_transaction() as sess:
        return list(sess.get("_flashes", []))


def post(client, **form):
    form.setdefault("log_file", LOG)
    form.setdefault("rotate_mb", "10")
    form.setdefault("old_files", "4")
    return client.post(URL, data=form)


def running_outputs(daemon):
    entry = next((x for x in daemon.running.get("loggers") or [] if x.get("name") == "kea-dhcp4"), None)
    return [o["output"] for o in (entry or {}).get("output-options", [])]


def audit_rows(db, action="KEA_LOG_OUTPUT"):
    db.commit()
    with db.cursor() as cur:
        cur.execute("SELECT details FROM audit_log WHERE action=%s ORDER BY id", (action,))
        return [row["details"] if isinstance(row, dict) else row[0] for row in cur.fetchall()]


def logger_on(daemon, options, severity="INFO"):
    entry = {"name": "kea-dhcp4", "output-options": copy.deepcopy(options), "severity": severity, "debuglevel": 0}
    daemon.file = dhcp4([entry])
    daemon.running = kea_writes_defaults(dhcp4([entry]))


def at(daemon, severity):
    daemon.file["loggers"][0]["severity"] = severity
    daemon.running["loggers"][0]["severity"] = severity


def asked(daemon):
    """What the proof sent, in order: `("command", <value>)` for the command Kea does not know, `("config-test", <value>)` for the configuration test Kea refuses."""
    out = []
    for command, arguments in daemon.received:
        if command.startswith(klt.PROOF_PREFIX):
            out.append(("command", command))
        elif command == "config-test":
            out.extend(("config-test", k) for k in (arguments.get("Dhcp4") or {}) if k.startswith(klt.PROOF_PREFIX))
    return out


def unproven(path=LOG):
    return f"Kea accepted the change on kea-a but Jen could not prove that it writes to {path}"


def not_found(path=LOG):
    return (
        f"Jen asked kea-dhcp4 on kea-a to write a line to {path} and did not find that line in the last 1000 lines of the file, on any of 5 reads. Check that the file is writable by the "
        "account kea-dhcp4 runs as, and that nothing moved or replaced it meanwhile. A server that logs more lines than that between the ask and the read gives the same result."
    )


def already_there(severity, path=LOG):
    return (
        f"Its severity is {severity}, so there is no line Jen can ask kea-dhcp4 to write, and {path} was already there, so Jen could not tell whether kea-dhcp4 "
        "may write it. Choose a file name that does not exist yet (Kea creates it, and that is the proof), or set the severity to ERROR or lower first."
    )


def not_created(severity, path=LOG):
    return (
        f"Its severity is {severity}, so there is no line Jen can ask kea-dhcp4 to write, and {path} was not created, so Jen could not tell whether kea-dhcp4 "
        "may write there."
    )


class TestTheLineThatProves:
    @pytest.mark.parametrize(
        "line, want",
        [
            (received(), True),
            (refused(), True),
            (received() + "\n", True),  # the line end is no part of the line
            (received() + "\r\n", True),
            (received(pid=1), True),  # whose process wrote it is not asked: the value is the proof
            (f"{HEAD} INFO  [kea-dhcp4.commands/81] COMMAND_RECEIVED Received command '{V}'", True),  # no thread id
            # an imitation: the value outside Kea's shape (`echo`)
            (f"COMMAND_RECEIVED Received command '{V}'", False),
            (f"INFO  [kea-dhcp4.commands/81.1] COMMAND_RECEIVED Received command '{V}'", False),
            (f"x {received()}", False),
            (
                f"{HEAD} INFO  COMMAND_RECEIVED Received command '{V}'",
                False,
            ),  # the package's stdout pattern has no bracket
            (f"{HEAD} INFO  [kea-dhcp6.commands/81.1] COMMAND_RECEIVED Received command '{V}'", False),
            (f"{HEAD} INFO  [another.commands/81.1] COMMAND_RECEIVED Received command '{V}'", False),
            (V, False),
            # Kea's shape with ANOTHER value, and without one
            (received(W), False),
            (refused(W), False),
            (received("status-get"), False),
            (received("config-get"), False),
            (f"{HEAD} INFO  [kea-dhcp4.dhcp4/81.1] DHCP4_STARTED Kea DHCPv4 server version 3.0.5 started", False),
            # the value inside a longer command name, or with words after it
            (received(V + "0"), False),
            (received("x" + V), False),
            (received() + " again", False),
            # the value in a message that is neither of the two
            (f"{HEAD} INFO  [kea-dhcp4.commands/81.1] COMMAND_RECEIVED Received command 'config-test' {V}", False),
            (f"{HEAD} ERROR [kea-dhcp4.dhcp4/81.1] DHCP4_CONFIG_LOAD_FAIL configuration error: {V}", False),
            (f"{HEAD} ERROR [kea-dhcp4.dhcp4/81.1] x DHCP4_PARSER_FAIL {V}", False),
            ("", False),
            (None, False),
        ],
    )
    def test_what_is_the_line_jen_asked_for(self, line, want):
        assert klt._kea_wrote([line], V) is want

    def test_any_line_of_the_tail_may_be_the_one(self):
        noise = [received("config-get"), "junk", received(W)]
        assert klt._kea_wrote(noise + [refused()] + noise, V) is True
        assert klt._kea_wrote(noise, V) is False
        assert klt._kea_wrote([], V) is False

    def test_no_value_proves_nothing(self):
        assert klt._kea_wrote([refused(), received()], "") is False

    def test_the_whole_line_is_matched(self):
        assert klt._KEA_LINE.pattern.startswith("^") and klt._KEA_LINE.pattern.endswith("$")
        assert klt._KEA_LINE.fullmatch(received()).group(1) == f"COMMAND_RECEIVED Received command '{V}'"

    def test_the_tail_is_the_most_the_helper_returns(self):
        """(Q253) 60 until 7.2.1: a server writing about 150 lines a second pushed the asked line out of what Jen read, every time."""
        assert klt.LOG_OUTPUT_TAIL == 1000

    def test_the_process_id_proof_is_gone__whole_tree(self):
        """Q251's proof asked whose process wrote a line. Its four names are in no file of the product."""
        gone = ("_daemon_pid", "_line_pid", "_kea_wrote_before")
        for name in gone:
            assert not hasattr(klt, name), name
        for path in sorted((ROOT / "jen").rglob("*.py")) + sorted((ROOT / "plugins").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for name in gone:
                assert name not in text, (path.name, name)
        tree = ast.parse((ROOT / "jen/services/kea_log_trace.py").read_text(encoding="utf-8"))
        imported = {a.name for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
        assert "Counter" not in imported and "secrets" not in imported  # `secrets` is imported inside `_proof_value`


class TestWhatIsAsked:
    def test_the_value_is_new_every_time_and_says_whose_it_is(self):
        a, b = klt._proof_value(), klt._proof_value()
        assert a != b and a.startswith(klt.PROOF_PREFIX) and klt.PROOF_PREFIX == "jen-log-proof-"
        assert len(a) == len(klt.PROOF_PREFIX) + 32 and int(a[len(klt.PROOF_PREFIX) :], 16) >= 0

    @pytest.mark.parametrize("ask", ["command", "config-test"])
    def test_what_goes_to_the_daemon(self, server, daemon, ask):
        assert klt._ask_for_a_line(server, V, ask) is True  # (Q253) the daemon answered
        if ask == "config-test":
            assert daemon.received == [("config-test", {"Dhcp4": {V: 1}})]
        else:
            assert daemon.received == [(V, {})]

    @pytest.mark.parametrize("ask", ["command", "config-test"])
    def test_a_daemon_that_does_not_answer_raises_nothing(self, server, daemon, ask):
        daemon.stopped = True
        assert klt._ask_for_a_line(server, V, ask) is False  # (Q253) and says so

    def test_the_fake_answers_as_the_real_daemon_was_measured(self, server, daemon):
        """`pass/q252/b/out/measure.*.json`: `result 2` for the command, `result 1` for the configuration test, and the running configuration is what it was."""
        from jen.services import kea

        digest = daemon.digest()
        assert kea.kea_command(V, server=server) == {"result": 2, "text": f"'{V}' command not supported."}
        reply = kea.kea_command("config-test", arguments={"Dhcp4": {V: 1}}, server=server)
        assert reply == {"result": 1, "text": f"unsupported global configuration parameter: {V} (<string>:1:102)"}
        assert daemon.digest() == digest


class TestAskedAtInfoAndDebug:
    @pytest.mark.parametrize("severity", ["INFO", "DEBUG"])
    def test_proven_on_the_first_try_by_the_line_that_carries_the_value(self, server, daemon, host, severity):
        at(daemon, severity)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"], out["level"]) == (True, "ok", "success"), out
        assert out["lines"][-1] == f"Kea is writing to {LOG} on kea-a."
        (ask,) = asked(daemon)
        assert ask[0] == "command" and received(ask[1], daemon.pid).split("] ", 1)[1] in [
            line.split("] ", 1)[1] for line in host.written[LOG]
        ]

    def test_one_value_for_the_change_asked_again_on_every_try(self, server, daemon, host, monkeypatch):
        host.writes_log = False
        naps = []

        def nap(seconds):
            naps.append(seconds)
            if len(naps) == 2:
                host.writes_log = True  # the file becomes writable while Jen watches

        monkeypatch.setattr(klt, "_proof_sleep", nap)
        host.existing[LOG] = []
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out
        asks = asked(daemon)
        assert len(asks) == 3 and len({value for _kind, value in asks}) == 1 and naps == [1, 1]

    def test_every_try_fails_and_it_is_put_back_after_five_asks(self, server, daemon, host):
        host.writes_log = False
        before_file = copy.deepcopy(daemon.file)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert len(asked(daemon)) == klt.LOG_OUTPUT_TRIES == 5
        assert host.ops().count("tail-log") == 1 + klt.LOG_OUTPUT_TRIES
        assert daemon.file == before_file and running_outputs(daemon) == ["stdout"]

    def test_a_forwarder_of_the_journal_into_a_file_kea_cannot_write_is_put_back(
        self, server, daemon, host, monkeypatch
    ):
        """BL1 as the fake can model it: a root 0600 file, and a unit that appends everything kea-dhcp4 writes to its journal - its lines from before the change, the
        lines of the change itself and its startup lines, all in Kea's own shape with the daemon's own process id. The change DROPS the journal, so the line Jen asks
        for is written nowhere and there is nothing to copy."""
        logger_on(
            daemon, [{"output": "stdout"}]
        )  # the bracketed stdout pattern: the journal's lines are whole Kea lines
        host.writes_log = False
        host.existing[LOG] = []
        startup = [
            f"{HEAD} INFO  [kea-dhcp4.dhcp4/{daemon.pid + 1}.140] DHCP4_STARTING Kea DHCPv4 server version 3.0.5 (stable) starting",
            f"{HEAD} INFO  [kea-dhcp4.commands/{daemon.pid + 1}.140] COMMAND_RECEIVED Received command 'status-get'",
        ]
        monkeypatch.setattr(host, "log_lines", lambda path: list(host.journal) + startup)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"] == [f"{unproven()}, so the previous logging was put back. {not_found()}"]
        assert any("COMMAND_RECEIVED" in line and klt._KEA_LINE.fullmatch(line) for line in host.journal)
        assert running_outputs(daemon) == ["stdout"]  # Kea is back on the journal

    @pytest.mark.parametrize("stdout", [{"output": "stdout"}, dict(PACKAGED)])
    def test_the_same_forwarder_with_the_journal_kept_is_put_back_too(self, server, daemon, host, monkeypatch, stdout):
        """With `both` Kea keeps the journal, and the line Jen asks for IS written there - with the pattern the card itself writes for the journal output, the
        package's `%-5p %m`, which has no bracket. The forwarder's copy is not a whole line of Kea's default shape, so it proves nothing (the reason `_KEA_LINE` is
        matched from the first character to the last)."""
        logger_on(daemon, [stdout])
        host.writes_log = False
        host.existing[LOG] = []
        monkeypatch.setattr(host, "log_lines", lambda path: list(host.journal))
        out = klt.change_log_output(server, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        carried = [line for line in host.journal if klt.PROOF_PREFIX in line]
        assert len(carried) == klt.LOG_OUTPUT_TRIES and all(
            line.startswith("INFO  COMMAND_RECEIVED ") for line in carried
        )

    @pytest.mark.parametrize(
        "shape",
        [
            "{head} INFO  [kea-dhcp4.commands/{pid}.140000] COMMAND_RECEIVED Received command 'status-get'",  # BL16: the right process id
            "{head} INFO  [kea-dhcp4.commands/999.1] COMMAND_RECEIVED Received command 'config-get'",
            "kea-dhcp4 says hello",
        ],
    )
    def test_a_writer_that_imitates_kea_is_put_back(self, server, daemon, host, monkeypatch, shape):
        host.writes_log = False
        reads = {"n": 0}

        def log_lines(path):
            reads["n"] += 1
            return [shape.format(head=HEAD, pid=daemon.pid) for _n in range(reads["n"])]

        monkeypatch.setattr(host, "log_lines", log_lines)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out


class TestAskedAtWarnAndError:
    @pytest.mark.parametrize("severity", ["WARN", "ERROR", "warn", "Error"])
    def test_proven_by_the_error_line_and_the_unknown_command_is_not_what_was_sent(
        self, server, daemon, host, severity
    ):
        at(daemon, severity)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"], out["level"]) == (True, "ok", "success"), out
        assert out["lines"][-1] == f"Kea is writing to {LOG} on kea-a." and "note" not in out
        ((kind, value),) = asked(daemon)
        assert kind == "config-test"
        assert not [c for c in daemon.commands if c.startswith(klt.PROOF_PREFIX)]
        proof = [line for line in host.written[LOG] if value in line]
        assert len(proof) == 1 and " ERROR [kea-dhcp4.dhcp4/" in proof[0] and "DHCP4_PARSER_FAIL " in proof[0]
        assert not [
            line for line in host.written[LOG] if "COMMAND_RECEIVED" in line
        ]  # at WARN a command writes no line

    def test_the_refused_test_changes_nothing_in_the_daemon(self, server, daemon, host):
        at(daemon, "ERROR")
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["ok"] is True
        position = max(i for i, (c, _a) in enumerate(daemon.received) if c == "config-test")
        assert "config-set" not in [c for c, _a in daemon.received[position:]]
        assert not [k for k in daemon.running if k.startswith(klt.PROOF_PREFIX)]
        assert not [k for k in daemon.file if k.startswith(klt.PROOF_PREFIX)]

    @pytest.mark.parametrize("severity", ["WARN", "ERROR"])
    @pytest.mark.parametrize(
        "holds",
        [
            [],  # BK2: root's empty file
            [received("config-get", 3)],  # BL2 w2: lines kea-dhcp4 itself wrote before the file was taken from it
            [
                f"{HEAD} INFO  [kea-dhcp4.commands/999.1] COMMAND_RECEIVED copied line"
            ],  # BL2 w6: one line of the shape, from `echo`
        ],
    )
    def test_a_file_the_logger_names_and_kea_cannot_write_is_put_back(
        self, logged_in_client, server, daemon, host, db, severity, holds
    ):
        """The journal and a file Kea cannot write, changed to the file alone. Through Q251 this stood "unchecked" on a line of Kea's shape in the file, and Kea
        logged nowhere."""
        logger_on(daemon, BOTH, severity)
        host.unwritable = {LOG}
        host.existing[LOG] = list(holds)
        before_file = copy.deepcopy(daemon.file)
        post(logged_in_client, output="file")
        assert flashes(logged_in_client) == [
            ("error", f"{unproven()}, so the previous logging was put back. {not_found()}")
        ]
        assert daemon.file == before_file and running_outputs(daemon) == ["stdout", LOG]
        assert len(asked(daemon)) == klt.LOG_OUTPUT_TRIES and {kind for kind, _v in asked(daemon)} == {"config-test"}
        assert audit_rows(db) == [
            f"kea-a: the system journal and the file {LOG} -> the file {LOG} was accepted by Kea, not proven, and put back"
        ]

    @pytest.mark.parametrize("severity", ["WARN", "ERROR"])
    def test_there_is_no_unchecked_and_no_created_at_these_severities(self, server, daemon, host, severity):
        """What Q250 and Q251 let stand without a line: a named file that lost no output, and a file Kea created. Kea can be asked now, so both are asked."""
        logger_on(daemon, [dict(FILE_LOGGER)], severity)
        out = klt.change_log_output(server, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out
        logger_on(daemon, [dict(FILE_LOGGER)], severity)
        host.unwritable = {LOG}
        host.existing[LOG] = []
        out = klt.change_log_output(server, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out  # named, nothing taken away, and still asked
        logger_on(daemon, [dict(PACKAGED)], severity)
        host.unwritable = set()
        out = klt.change_log_output(server, "file", OTHER, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out  # a new name: created AND written

    def test_a_file_with_a_pattern_of_its_own_is_proven_at_error(self, server, daemon, host):
        """BL3: the journal and a file Kea writes with a `pattern` (no bracket), at ERROR, changed to the file alone. Q251 put it back with a false cause. The card's own
        output carries no pattern, so the line Kea is asked for arrives in the default shape."""
        patterned = {"output": LOG, "pattern": "%d %-5p %m\n"}
        logger_on(daemon, [dict(PACKAGED), patterned], "ERROR")
        host.existing[LOG] = ["2026-11-25 14:00:00 ERROR DHCP4_PACKET_SEND_FAIL an older line with no bracket"]
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out


class TestFatalAndNone:
    @pytest.mark.parametrize("severity", ["FATAL", "NONE", "fatal"])
    def test_a_named_file_that_loses_no_output_stands_unchecked(self, server, daemon, host, severity):
        logger_on(daemon, [dict(FILE_LOGGER)], severity)
        host.existing[LOG] = []
        out = klt.change_log_output(server, "both", LOG, MB10, 4)  # the journal is added beside the file
        assert (out["ok"], out["code"], out["level"]) == (True, "unchecked", "warning"), out
        assert out["lines"][-1] == (
            f"Kea accepted the change on kea-a. Its severity is {severity.upper()}, so it wrote no line Jen could check; {LOG} is a file its logger already "
            "named, and this change takes no output away."
        )
        assert out["note"] == f" (not checked: severity {severity.upper()})"
        out = klt.change_log_output(server, "both", LOG, 2 * MB10, 4)  # a changed rotation on the same outputs
        assert (out["ok"], out["code"]) == (True, "unchecked"), out
        assert asked(daemon) == []

    @pytest.mark.parametrize(
        "severity, tail",
        [
            ("FATAL", "the file fills when Kea next logs at that level."),
            ("NONE", "the file stays empty until the severity is changed."),
        ],
    )
    def test_a_file_kea_created_stands(self, server, daemon, host, severity, tail):
        at(daemon, severity)
        out = klt.change_log_output(server, "file", OTHER, MB10, 4)
        assert (out["ok"], out["code"], out["level"]) == (True, "created", "success"), out
        assert (
            out["lines"][-1]
            == f"Kea created {OTHER} on kea-a. Its severity is {severity}, so it has written no line yet; {tail}"
        )
        assert out["note"] == f" (proven by the file Kea created: severity {severity})"
        assert asked(daemon) == []

    @pytest.mark.parametrize("severity", ["FATAL", "NONE"])
    def test_a_file_that_was_there_is_put_back_and_the_cause_names_two_ways_on(self, server, daemon, host, severity):
        at(daemon, severity)
        host.existing[LOG] = []
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"] == [f"{unproven()}, so the previous logging was put back. {already_there(severity)}"]
        assert asked(daemon) == []

    @pytest.mark.parametrize("severity", ["FATAL", "NONE"])
    def test_a_file_kea_did_not_create_is_put_back(self, server, daemon, host, severity):
        at(daemon, severity)
        host.writes_log = False
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"] == [f"{unproven()}, so the previous logging was put back. {not_created(severity)}"]

    @pytest.mark.parametrize("severity", ["FATAL", "NONE"])
    @pytest.mark.parametrize("writable", [True, False])
    def test_a_named_file_that_would_be_all_that_is_left_is_put_back_whatever_it_holds(
        self, server, daemon, host, severity, writable
    ):
        """The branch "already holds lines kea-dhcp4 wrote before this change" is gone (BL2): a line of the shape can be anyone's. So the journal and a file, changed
        to the file alone, is put back at FATAL and NONE also when Kea really writes the file - an over-refusal by decision; the cause says how to get there."""
        logger_on(daemon, BOTH, severity)
        if not writable:
            host.unwritable = {LOG}
        host.existing[LOG] = [received("config-get", 3), refused(W, 3)]
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"] == [f"{unproven()}, so the previous logging was put back. {already_there(severity)}"]
        assert running_outputs(daemon) == ["stdout", LOG] and asked(daemon) == []

    def test_only_a_result_that_stands_is_a_read_of_the_log(self, server, daemon, host, monkeypatch):
        seen = []
        monkeypatch.setattr(klt, "_record_read", lambda server, path: seen.append(path))
        at(daemon, "NONE")
        assert klt.change_log_output(server, "file", OTHER, MB10, 4)["code"] == "created"
        assert klt.change_log_output(server, "both", OTHER, MB10, 4)["code"] == "unchecked"
        host.existing[LOG] = []
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["code"] == "put-back"
        at(daemon, "WARN")
        assert klt.change_log_output(server, "file", OTHER, MB10, 4)["code"] == "ok"
        host.unwritable = {LOG}
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["code"] == "put-back"
        assert seen == [OTHER, OTHER, OTHER]


class TestStatusGetIsNeverAsked:
    @pytest.mark.parametrize("severity", ["INFO", "DEBUG", "WARN", "ERROR", "FATAL", "NONE"])
    @pytest.mark.parametrize("writable", [True, False])
    def test_no_world_sends_it(self, server, daemon, host, severity, writable):
        """BL9: a `status-get` that failed, answered no process id or one that is not a number put a working change back. The proof does not ask it."""
        at(daemon, severity)
        host.writes_log = writable
        out = klt.change_log_output(server, "file", OTHER, MB10, 4)
        assert "status-get" not in daemon.commands
        assert out["ok"] is writable, out


class TestTheSentences:
    def test_asked_and_not_found(self, logged_in_client, server, daemon, host, db):
        host.writes_log = False
        post(logged_in_client, output="file")
        assert flashes(logged_in_client) == [
            (
                "error",
                f"Kea accepted the change on kea-a but Jen could not prove that it writes to {LOG}, so the previous logging was put back. "
                f"Jen asked kea-dhcp4 on kea-a to write a line to {LOG} and did not find that line in the last 1000 lines of the file, on any of 5 reads. Check that the file is writable by the "
                "account kea-dhcp4 runs as, and that nothing moved or replaced it meanwhile. A server that logs more lines than that between the ask and the read gives the same result.",
            )
        ]
        assert audit_rows(db) == [
            f"kea-a: the system journal (stdout) -> the file {LOG} was accepted by Kea, not proven, and put back"
        ]

    def test_fatal_the_file_was_already_there(self, server, daemon, host):
        at(daemon, "FATAL")
        host.existing[LOG] = []
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["lines"] == [
            f"Kea accepted the change on kea-a but Jen could not prove that it writes to {LOG}, so the previous logging was put back. "
            f"Its severity is FATAL, so there is no line Jen can ask kea-dhcp4 to write, and {LOG} was already there, so Jen could not tell whether kea-dhcp4 may "
            "write it. Choose a file name that does not exist yet (Kea creates it, and that is the proof), or set the severity to ERROR or lower first."
        ]

    def test_none_the_file_was_not_created(self, server, daemon, host):
        at(daemon, "NONE")
        host.writes_log = False
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["lines"] == [
            f"Kea accepted the change on kea-a but Jen could not prove that it writes to {LOG}, so the previous logging was put back. "
            f"Its severity is NONE, so there is no line Jen can ask kea-dhcp4 to write, and {LOG} was not created, so Jen could not tell whether kea-dhcp4 may "
            "write there."
        ]

    def test_no_sentence_says_what_kea_did(self, server, daemon, host):
        """BL3, BL9, BL14: "wrote nothing", "added no line of its own", "without a line kea-dhcp4 wrote" were said of files Kea had written 21 to 48 lines to."""
        source = (ROOT / "jen/services/kea_log_trace.py").read_text(encoding="utf-8")
        for old in (
            "but wrote nothing to",
            "added no line of its own",
            "without a line kea-dhcp4 wrote",
            "already holds lines kea-dhcp4 wrote",
            "so Kea writes ",
            "something Jen could not read",
        ):
            assert old not in source, old

    def test_the_put_back_fails_and_the_daemon_says_what_it_runs(self, logged_in_client, server, daemon, host, db):
        host.writes_log = False
        host.apply_fails_from = 2  # the change is written; the put-back is not
        post(logged_in_client, output="file")
        ((level, said),) = flashes(logged_in_client)
        assert level == "error"
        assert said.startswith(
            f"Kea accepted the change on kea-a but Jen could not prove that it writes to {LOG}, and putting the previous logging back failed: "
        )
        assert "No space left on device" in said
        assert said.endswith(f" kea-a now writes its log to the file {LOG}. {not_found()} Then choose again.")
        assert audit_rows(db) == [
            f"kea-a: the system journal (stdout) -> the file {LOG} (the change was not proven and could not be put back)"
        ]

    def test_the_put_back_fails_and_the_daemon_does_not_answer(self, logged_in_client, server, daemon, host, db):
        """BL10: "now writes its log to something Jen could not read" was said of a daemon that was stopped."""
        host.writes_log = False
        host.apply_fails_from = 2
        real = host.kea_received

        def stops_when_asked(fake, command, arguments):
            real(fake, command, arguments)
            if command.startswith(klt.PROOF_PREFIX):
                fake.stopped = True  # it answers this one, and nothing after it

        daemon.on_command = stops_when_asked
        post(logged_in_client, output="file")
        ((_level, said),) = flashes(logged_in_client)
        assert said.endswith(
            f" Jen could not ask kea-a what it writes to now: kea-dhcp4 did not answer. {not_found()} Then choose again."
        )
        assert "now writes its log to" not in said
        assert audit_rows(db) == [
            "kea-a: the system journal (stdout) -> not known (kea-dhcp4 did not answer) (the change was not proven and could not be put back)"
        ]

    @pytest.mark.parametrize("answers", [True, False])
    def test_a_change_set_that_could_not_undo_itself(
        self, logged_in_client, server, daemon, host, db, monkeypatch, answers
    ):
        """The change set's own end `rollback_failed` is made by the stand-in (the outermost thing, as in `tests/test_q251_a.py`); the card around it is real."""
        real = changeset.apply_change

        def apply_change(service, mutate, description, **kw):
            daemon.running = kea_writes_defaults(mutate({"Dhcp4": copy.deepcopy(daemon.running)})[0]["Dhcp4"])
            daemon.stopped = not answers
            return changeset.ChangeSetResult(
                status="rollback_failed",
                last_code="",
                lines=[("error", "kea-a: the restart failed and the previous configuration could not be put back.")],
            )

        monkeypatch.setattr(changeset, "apply_change", apply_change)
        post(logged_in_client, output="file")
        monkeypatch.setattr(changeset, "apply_change", real)
        got = flashes(logged_in_client)
        now_sentence, now = (
            (f"kea-a now writes its log to the file {LOG}.", f"the file {LOG}")
            if answers
            else (
                "Jen could not ask kea-a what it writes to now: kea-dhcp4 did not answer.",
                "not known (kea-dhcp4 did not answer)",
            )
        )
        assert got[-1] == (
            "error",
            f"The change on kea-a failed part way and could not be undone, so nothing was proven. {now_sentence} See the Kea Servers page, then choose again.",
        )
        assert audit_rows(db) == [
            f"kea-a: the system journal (stdout) -> {now} (the change failed part way, was not proven and could not be undone)"
        ]
        assert asked(daemon) == []  # nothing was asked of a change that did not go through


class TestOverTheDaemonsOwnApi:
    @pytest.fixture
    def api(self, monkeypatch, daemon, host):
        from tests import _kea_api_world as world

        store = world.install_store(monkeypatch)
        world.install_probes(monkeypatch)
        server = {"id": SID, "name": "kea-a", "api_url": daemon.url, "config_transport": "api", "ssh_host": "10.9.9.9"}
        daemon.file = copy.deepcopy(daemon.running)
        self.clock = world.host_reads_the_fakes_file(monkeypatch, daemon, store, server_id=SID)["clock"]
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        return server

    def _loaded(self, daemon, severity):
        daemon.running["loggers"][0]["severity"] = severity
        daemon.file = copy.deepcopy(daemon.running)
        self.clock.seen_sha = self.clock._sha()
        self.clock.mtime = self.clock.loaded_at - 100

    @pytest.mark.parametrize("severity", ["INFO", "WARN", "ERROR"])
    def test_proven_live_with_no_restart(self, api, daemon, host, severity):
        self._loaded(daemon, severity)
        out = klt.change_log_output(api, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out
        assert "service" not in host.ops() and daemon.commands.count("config-set") == 1
        ((kind, _value),) = asked(daemon)
        assert kind == ("command" if severity == "INFO" else "config-test")
        assert "status-get" not in daemon.commands

    @pytest.mark.parametrize("severity", ["INFO", "ERROR"])
    def test_a_file_kea_cannot_write_is_put_back_live(self, api, daemon, host, severity):
        self._loaded(daemon, severity)
        host.writes_log = False
        out = klt.change_log_output(api, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert running_outputs(daemon) == ["stdout"] and daemon.commands.count("config-set") == 2

    def test_fatal_a_new_file_is_created_live(self, api, daemon, host):
        self._loaded(daemon, "FATAL")
        out = klt.change_log_output(api, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "created"), out
        assert asked(daemon) == [] and daemon.commands.count("config-set") == 1
