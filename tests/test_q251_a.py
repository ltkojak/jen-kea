"""
tests/test_q251_a.py
────────────────────
Q251 - the Kea logging card after the executing pass on v7.2.0-beta.8 (INV-017), the Problems sweep's record after a proven change, and three things the maintainer
read on the pages.

    TestTheProofIsThisDaemonsLine     a line proves a change only when it has Kea's shape AND the process id the running daemon answered (BK3)
    TestTheNameAloneIsNotEvidence     above INFO, a file the logger names stands only when it holds lines kea-dhcp4 wrote (BK2); the flash keeps its lines (BK16)
    TestSeverityNone                  NONE is a severity at which Kea writes nothing (BK14)
    TestThePutBackSaysWhatJenSaw      the put-back's cause is what was observed, not one guess (BK15)
    TestAChangeThatCouldNotUndoItself a change set that ends `rollback_failed` is in the audit log (BK8)
    TestAProvenChangeIsARead          the sweep's record follows a change that stands, at once (BK5); a change that does not stand leaves it
    TestTheFirstSweep                 the sweep's first run is seconds after the start, not one interval (BK5)
    TestTheLabels                     the card's three choices in one shape, and why one would choose both
    TestTheLogPathField               the SSH card's "Kea log path" is a field only while a server needs it
    TestTheFixLink                    Health's Fix link is two words; the hint is a sentence of the row

The world is `tests/_q249_a_world.py` (a stateful fake Kea over real HTTP and `KeaHost` for `kea_host.helper_call`). The same rows against a real kea-dhcp4 are
`pass/q251/a/` (the ledger of the Q251 entry names the output).
"""

import copy
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from jen import extensions
from jen.services import client_problems as problems
from jen.services import health, kea_host
from jen.services import kea_changeset as changeset
from jen.services import kea_config_edit as edit
from jen.services import kea_log_trace as klt
from jen.services import scheduler as sched
from tests._q249_a_world import FILE_LOGGER, PACKAGED, KeaHost, dhcp4, file_server, kea_writes_defaults, packaged_logger
from tests.e2e._fake_kea_server import StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
SID = 251  # a server id no other test file uses
LOG = "/var/log/kea/kea-dhcp4.log"
OTHER = "/var/log/kea/second.log"
MB10 = 10 * 1024 * 1024
URL = f"/settings/infrastructure/kea-logging/{SID}"


def kea_line(pid, n=0, level="INFO"):
    return f"2026-11-24 02:18:{n % 60:02d}.273 {level:<5} [kea-dhcp4.commands/{pid}.140] COMMAND_RECEIVED Received command 'status-get'"


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


def _forget_sweep(db):
    with db.cursor() as cur:
        cur.execute(
            "DELETE FROM settings WHERE setting_key=%s", (problems._SWEPT_KEY,)
        )  # as a database no sweep has run on: what the files beside this one expect
        cur.execute("DELETE FROM settings WHERE setting_key LIKE %s", (f"client_problems_%:{SID}",))
        cur.execute("DELETE FROM kea_config_revisions WHERE server_id=%s", (SID,))
    db.commit()


@pytest.fixture
def server(monkeypatch, daemon, host, db):
    s = file_server(daemon, id=SID)
    monkeypatch.setattr(extensions, "KEA_SERVERS", [s])
    _forget_sweep(db)
    yield s
    klt.release_log_output(s)
    _forget_sweep(db)


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


def logger_on(daemon, options, severity="INFO"):
    entry = {"name": "kea-dhcp4", "output-options": copy.deepcopy(options), "severity": severity, "debuglevel": 0}
    daemon.file = dhcp4([entry])
    daemon.running = kea_writes_defaults(dhcp4([entry]))


def seed_blind(db, misses=7):
    """The sweep's record of a server whose log file is missing, as seven sweeps would have left it (the last of them just now)."""
    problems._note_swept(problems._now())
    with db.cursor() as cur:
        for key, value in (("miss", str(misses)), ("err", "missing"), ("path", LOG)):
            cur.execute(
                "INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
                (f"client_problems_{key}:{SID}", value),
            )
    db.commit()


def sweep_record(db, server):
    db.commit()
    return problems.read_status([server])["servers"][0]


class TestTheProofIsThisDaemonsLine:
    @pytest.mark.parametrize(
        "line, want",
        [
            (kea_line(81), 81),
            (
                "2026-11-24 02:18:41.273 WARN  [kea-dhcp4.dhcpsrv/4012.139822] DHCPSRV_MT_DISABLED_QUEUE_CONTROL ...",
                4012,
            ),
            ("2026-11-24 02:18:41.273 INFO  [kea-dhcp4/7.0x7f2a] a line of the root logger", 7),
            ("2026-11-24 02:18:41.273 INFO  [kea-dhcp4.commands/81] no thread id", 81),
            ("04:10:11 another-daemon says kea-dhcp4 is fine", None),
            ("2026-11-24 02:18:41.273 INFO  [kea-dhcp6.commands/81.140] the other daemon", None),
            ("2026-11-24 02:18:41.273 INFO  [kea-dhcp4.commands/x.140] no process id", None),
            ("", None),
            (None, None),
        ],
    )
    def test_the_process_id_of_a_line(self, line, want):
        assert klt._line_pid(line) == want

    @pytest.mark.parametrize(
        "before, tail, pid, want",
        [
            ([], [kea_line(81)], 81, True),
            ([], [kea_line(81)], 82, False),  # a second kea-dhcp4's real line
            ([], [kea_line(81)], None, False),  # the daemon did not say who it is: nothing proves
            ([kea_line(81)], [kea_line(81)], 81, False),  # the tail did not move
            ([kea_line(81)], [kea_line(81), kea_line(81, 1)], 81, True),
            ([], ["2026-11-24 02:18:41 INFO kea-dhcp4 imitation line"], 81, False),
            ([], ["x [kea-dhcp4.commands/999.1] an imitation with a made-up process"], 81, False),
            ([kea_line(81), kea_line(81)], [kea_line(81)], 81, False),
            ([], [], 81, False),
        ],
    )
    def test_what_counts_as_a_line_this_daemon_added(self, before, tail, pid, want):
        assert klt._kea_wrote(tail, before, pid) is want

    def test_the_daemons_process_id_is_its_own_answer(self, server, daemon):
        assert klt._daemon_pid(server) == daemon.pid == 8
        daemon.pid = "8"  # an answer that is not a number is no answer
        assert klt._daemon_pid(server) is None
        daemon.pid = True
        assert klt._daemon_pid(server) is None
        daemon.pid = 0
        assert klt._daemon_pid(server) is None

    def test_a_change_the_daemon_itself_writes_is_proven(self, server, daemon, host):
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out
        assert out["lines"][-1] == f"Kea is writing to {LOG} on kea-a."
        assert "status-get" in daemon.commands, "the proof's harmless command is the one whose answer names the process"

    def test_the_lines_of_a_second_kea_dhcp4_prove_nothing_and_the_change_is_put_back(self, server, daemon, host):
        """The pass's world (b): the file fills with REAL kea-dhcp4 lines, written by another daemon; this one may not write it."""
        host.line_pid = 4999
        before_file = copy.deepcopy(daemon.file)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert daemon.file == before_file and running_options(daemon) == [PACKAGED]

    def test_a_line_that_only_names_the_daemon_proves_nothing(self, server, daemon, host, monkeypatch):
        """The pass's world (a): something appends lines that contain the logger's name between every read."""
        host.writes_log = False
        reads = {"n": 0}

        def log_lines(path):
            reads["n"] += 1
            return [f"2026-11-24 04:10:{n:02d}.000 INFO  kea-dhcp4.commands imitation {n}" for n in range(reads["n"])]

        monkeypatch.setattr(host, "log_lines", log_lines)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert running_options(daemon) == [PACKAGED]

    def test_a_daemon_that_does_not_say_who_it_is_is_put_back(self, server, daemon, host, monkeypatch):
        monkeypatch.setattr(klt, "_daemon_pid", lambda server: None)
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out


class TestTheNameAloneIsNotEvidence:
    BOTH = [dict(PACKAGED), dict(FILE_LOGGER)]

    def test_a_file_the_logger_names_and_kea_never_wrote_is_put_back(self, logged_in_client, server, daemon, host, db):
        """BK2: the journal and a file kea-dhcp4 cannot write, at WARN, changed to the file alone: before this Q it stood "unchecked" and Kea logged nowhere."""
        logger_on(daemon, self.BOTH, "WARN")
        host.writes_log = False
        host.existing[LOG] = []  # root's file: there, and no line of Kea's in it
        before_file = copy.deepcopy(daemon.file)
        post(logged_in_client, output="file")
        assert flashes(logged_in_client) == [
            (
                "error",
                f"Kea accepted the change but wrote nothing to {LOG} on kea-a, so the previous logging was put back. Its severity is WARN, so Kea writes few lines, "
                f"and {LOG} was already there without a line kea-dhcp4 wrote, so Jen could not tell whether kea-dhcp4 may write it. "
                "Choose a file name that does not exist yet: Kea creates it, and that is the proof.",
            )
        ]
        assert daemon.file == before_file
        assert [o["output"] for o in running_options(daemon)] == ["stdout", LOG]
        assert audit_rows(db) == [
            f"kea-a: the system journal and the file {LOG} -> the file {LOG} was accepted by Kea, not proven, and put back"
        ]

    def test_a_change_that_takes_no_output_away_stands_on_the_name(self, server, daemon, host):
        """The file alone, then the journal added beside it (and a rotation size changed on the same file): Kea writes everywhere it wrote before, so an empty
        file the logger already named is no reason to put anything back - the world Kea leaves after it CREATED a file at ERROR."""
        logger_on(daemon, [dict(FILE_LOGGER)], "ERROR")
        host.quiet = True
        host.existing[LOG] = []
        out = klt.change_log_output(server, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "unchecked"), out
        assert out["lines"][-1] == (
            f"Kea accepted the change on kea-a. Its severity is ERROR, so it wrote no line Jen could check; {LOG} is a file its logger already named, "
            "and this change takes no output away."
        )
        out = klt.change_log_output(server, "both", LOG, 2 * MB10, 4)
        assert (out["ok"], out["code"]) == (True, "unchecked"), out

    def test_lines_of_some_writer_that_is_not_kea_are_not_evidence_either(self, server, daemon, host):
        logger_on(daemon, self.BOTH, "ERROR")
        host.writes_log = False
        host.existing[LOG] = ["logrotate: created", "a line with kea-dhcp4 in it"]
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out

    def test_a_file_that_holds_keas_own_lines_stands_unchecked_and_keeps_the_change_sets_lines(
        self, server, daemon, host
    ):
        logger_on(daemon, self.BOTH, "WARN")
        host.quiet = True
        host.existing[LOG] = [kea_line(3, level="WARN")]  # written before a restart: the process id is an older one
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"], out["level"]) == (True, "unchecked", "warning"), out
        assert out["lines"][-1] == (
            f"Kea accepted the change on kea-a. Its severity is WARN, so it wrote no line Jen could check; {LOG} already holds lines kea-dhcp4 wrote before this change."
        )
        assert len(out["lines"]) > 1 and any("Kea logging" in line for line in out["lines"][:-1]), out["lines"]  # BK16
        assert out["note"] == " (not checked: severity WARN)"


class TestSeverityNone:
    def test_none_is_a_severity_above_info(self):
        assert "NONE" in edit.LOGGER_SEVERITIES_ABOVE_INFO
        cfg = {"Dhcp4": dhcp4([{"name": "kea-dhcp4", "severity": "none", "output-options": [dict(PACKAGED)]}])}
        assert edit.logger_severity_above_info(cfg) == "NONE"

    def test_a_new_name_is_created_and_the_sentence_does_not_promise_lines(self, server, daemon, host):
        at(daemon, "NONE")
        host.quiet = True
        out = klt.change_log_output(server, "file", OTHER, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "created"), out
        assert out["lines"][-1] == (
            f"Kea created {OTHER} on kea-a. Its severity is NONE, so it has written no line yet; the file stays empty until the severity is changed."
        )

    def test_a_file_that_was_there_is_put_back_for_the_true_reason(self, server, daemon, host):
        at(daemon, "NONE")
        host.quiet = True
        host.existing[LOG] = []
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"] == [
            f"Kea accepted the change but wrote nothing to {LOG} on kea-a, so the previous logging was put back. Its severity is NONE, so Kea writes nothing, "
            f"and {LOG} was already there, so Jen could not tell whether kea-dhcp4 may write it. Choose a file name that does not exist yet: Kea creates it, "
            "and that is the proof."
        ]


class TestThePutBackSaysWhatJenSaw:
    def test_at_info_the_cause_is_what_was_observed(self, server, daemon, host):
        host.writes_log = False
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"] == [
            f"Kea accepted the change but wrote nothing to {LOG} on kea-a, so the previous logging was put back. "
            f"The running kea-dhcp4 added no line of its own to {LOG} in the seconds Jen watched. Check that the file is writable by the account "
            "kea-dhcp4 runs as, and that nothing moved or replaced it meanwhile."
        ]

    def test_above_info_a_file_kea_could_not_create_says_so(self, server, daemon, host):
        at(daemon, "WARN")
        host.writes_log = False
        out = klt.change_log_output(server, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert out["lines"][0].endswith(
            f"Its severity is WARN, and {LOG} was not created, so Jen could not tell whether kea-dhcp4 may write there."
        )


class TestAChangeThatCouldNotUndoItself:
    def test_the_card_says_what_kea_runs_and_the_audit_log_has_the_row(
        self, logged_in_client, server, daemon, host, db, monkeypatch
    ):
        """BK8. The change set's own end `rollback_failed` is made by the stand-in below (the outermost thing: the transaction itself is `kea_changeset`'s and has its
        own tests); everything of the card around it is real."""
        real = changeset.apply_change

        def apply_change(service, mutate, description, **kw):
            daemon.running = kea_writes_defaults(mutate({"Dhcp4": copy.deepcopy(daemon.running)})[0]["Dhcp4"])
            return changeset.ChangeSetResult(
                status="rollback_failed",
                last_code="",
                lines=[("error", "kea-a: the restart failed and the previous configuration could not be put back.")],
            )

        monkeypatch.setattr(changeset, "apply_change", apply_change)
        post(logged_in_client, output="file")
        monkeypatch.setattr(changeset, "apply_change", real)
        got = flashes(logged_in_client)
        assert [level for level, _text in got] == ["error", "error"]
        assert got[0][1] == "kea-a: the restart failed and the previous configuration could not be put back."
        assert got[1][1] == (
            f"The change on kea-a failed part way and could not be undone, so nothing was proven. kea-a now writes its log to the file {LOG}. "
            "See the Kea Servers page, then choose again."
        )
        assert audit_rows(db) == [
            f"kea-a: the system journal (stdout) -> the file {LOG} (the change failed part way, was not proven and could not be undone)"
        ]

    def test_a_change_set_that_only_refused_writes_no_row(self, logged_in_client, server, daemon, host, db):
        host.apply_fails_from = 1
        post(logged_in_client, output="file")
        assert audit_rows(db) == []
        assert running_options(daemon) == [PACKAGED]


class TestAProvenChangeIsARead:
    def test_the_sweeps_record_follows_a_proven_change_at_once(self, logged_in_client, server, daemon, host, db):
        """The maintainer's banner: seven sweeps found no file, the card's change is proven by reading that file, and the row stayed red until the next sweep."""
        seed_blind(db)
        before = sweep_record(db, server)
        assert (before["misses"], before["last_error"], before["last_read"]) == (7, "missing", None)
        assert health._problems_sweep({}).status == "fail"
        post(logged_in_client, output="both")
        assert flashes(logged_in_client)[-1] == ("success", f"Kea is writing to {LOG} on kea-a.")
        after = sweep_record(db, server)
        assert (after["misses"], after["last_error"], after["last_path"]) == (0, "", LOG)
        assert after["last_read"] is not None
        assert health._problems_sweep({}).status != "fail"

    def test_a_file_kea_created_above_info_is_a_read_too(self, server, daemon, host, db):
        seed_blind(db)
        at(daemon, "ERROR")
        host.quiet = True
        assert klt.change_log_output(server, "file", OTHER, MB10, 4)["code"] == "created"
        after = sweep_record(db, server)
        assert (after["misses"], after["last_error"], after["last_path"]) == (0, "", OTHER)

    def test_a_change_that_was_put_back_leaves_the_record(self, server, daemon, host, db):
        seed_blind(db)
        host.writes_log = False
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["code"] == "put-back"
        after = sweep_record(db, server)
        assert (after["misses"], after["last_error"], after["last_read"]) == (7, "missing", None)

    def test_a_change_to_the_journal_leaves_the_record(self, server, daemon, host, db):
        logger_on(daemon, [dict(FILE_LOGGER)])
        seed_blind(db, misses=2)
        assert klt.change_log_output(server, "journal")["ok"] is True
        assert sweep_record(db, server)["misses"] == 2

    def test_only_the_read_is_recorded(self, server, db):
        """`note_read` writes what a sweep's good read writes and nothing of the sweep's own progress."""
        seed_blind(db)
        problems.note_read(server, LOG)
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT setting_key FROM settings WHERE setting_key LIKE %s", (f"client_problems_%:{SID}",))
            keys = sorted((r["setting_key"] if isinstance(r, dict) else r[0]) for r in cur.fetchall())
        assert keys == [f"client_problems_{k}:{SID}" for k in ("err", "miss", "path", "read")]

    def test_a_server_with_no_ssh_has_no_record_to_correct(self, server, db):
        problems.note_read({**server, "ssh_host": ""}, LOG)
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM settings WHERE setting_key LIKE %s", (f"client_problems_%:{SID}",))
            row = cur.fetchone()
        assert (row["n"] if isinstance(row, dict) else row[0]) == 0


class TestTheFirstSweep:
    def test_the_first_sweep_is_seconds_after_the_start(self, app, monkeypatch):
        for name in (
            "_run_backup_job",
            "_run_audit_cleanup",
            "_run_investigation_sweep",
            "_run_client_problems_sweep",
            "_run_probe_refresh",
        ):
            monkeypatch.setattr(sched, name, lambda app: None)
        monkeypatch.setattr(sched, "_scheduler", None)
        monkeypatch.setattr(sched, "_start_error", "")
        started = datetime.now(timezone.utc)
        sched.start_scheduler(app)
        try:
            job = sched._scheduler.get_job("jen_client_problems_sweep")
            first = job.next_run_time.astimezone(timezone.utc)
            assert timedelta(0) < first - started <= timedelta(seconds=sched.FIRST_PROBLEMS_SWEEP_S + 5)
            assert job.trigger.interval == timedelta(minutes=5)
            # the sweeps beside it keep their own first run: one interval after the start
            minute = sched._scheduler.get_job("jen_investigation_sweep").next_run_time.astimezone(timezone.utc)
            assert timedelta(seconds=50) < minute - started <= timedelta(seconds=65)
        finally:
            sched._scheduler.shutdown(wait=False)

    def test_the_wait_is_shorter_than_one_interval_and_long_enough_to_start(self):
        assert 15 <= sched.FIRST_PROBLEMS_SWEEP_S <= 120


class TestTheLabels:
    def test_the_three_choices_have_one_shape_and_both_says_why(self, logged_in_client, server):
        html = logged_in_client.get("/settings/kea").get_data(as_text=True)
        assert "<strong>Logging to the system journal (Kea's default, not readable by Jen)</strong>" in html
        assert "<strong>Logging to file (Readable by Jen)</strong>" in html
        assert "<strong>Logging to the system journal and to file (Readable by Jen)</strong>" in html
        assert (
            "Both of the above. Choose this when journalctl, or something that collects the journal, should keep seeing Kea's log while Jen reads the file."
            in html
        )
        assert "A file Jen can read" not in html and "<strong>The system journal and a file</strong>" not in html

    def test_no_file_under_templates_or_docs_keeps_an_old_label(self):
        for folder, pattern in (("templates", "*.html"), ("docs", "*.md")):
            for path in sorted((ROOT / folder).glob(pattern)):
                if path.name == "upgrading.md":
                    continue  # it names the old label once, to say what it became
                text = path.read_text(encoding="utf-8")
                assert "A file Jen can read" not in text, path.name


class TestTheLogPathField:
    @pytest.mark.parametrize(
        "cards, want",
        [
            ([], True),
            ([{"has_ssh": True, "readable": True, "reads_from": "from Kea's logger"}], False),
            ([{"has_ssh": True, "readable": True, "reads_from": "from the Kea Log Path setting"}], True),
            ([{"has_ssh": True, "readable": True, "reads_from": ""}], True),
            ([{"has_ssh": True, "readable": False}], True),
            ([{"has_ssh": False, "readable": True, "reads_from": ""}], True),  # nobody reads a log: the field stays
            (
                [
                    {"has_ssh": True, "readable": True, "reads_from": "from Kea's logger"},
                    {"has_ssh": False, "readable": True, "reads_from": ""},
                ],
                False,
            ),
            (
                [
                    {"has_ssh": True, "readable": True, "reads_from": "from Kea's logger"},
                    {"has_ssh": True, "readable": True, "reads_from": ""},
                ],
                True,
            ),
        ],
    )
    def test_when_the_field_is_needed(self, cards, want):
        assert klt.log_path_field_needed(cards) is want

    def test_the_words_the_card_and_the_rule_share(self, server, daemon, host):
        logger_on(daemon, [dict(FILE_LOGGER)])
        card = klt.log_output_card(server)
        assert card["reads_from"] == "from Kea's logger" and klt.log_path_field_needed([card]) is False

    def test_a_logger_that_names_its_file_takes_the_field_away_and_keeps_the_stored_value(
        self, logged_in_client, server, daemon, host, monkeypatch
    ):
        logger_on(daemon, [dict(FILE_LOGGER)])
        monkeypatch.setattr(
            extensions.cfg, "get", _cfg_get(extensions.cfg.get, {("kea", "dhcp4_log_path"): "/var/log/kea/old.log"})
        )
        html = logged_in_client.get("/settings/kea").get_data(as_text=True)
        assert 'id="f-dhcp4_log_path"' not in html
        assert '<input type="hidden" name="dhcp4_log_path" value="/var/log/kea/old.log">' in html
        assert 'Not needed: Kea names the file itself. See <a href="#kea-logging">Kea logging</a> on this page.' in html

    def test_a_logger_on_the_journal_keeps_the_field(self, logged_in_client, server, daemon, host):
        html = logged_in_client.get("/settings/kea").get_data(as_text=True)
        assert 'id="f-dhcp4_log_path"' in html and "data-log-path-from-kea" not in html


def _cfg_get(real, values):
    def get(section, option, *args, **kw):
        if (section, option) in values:
            return values[(section, option)]
        return real(section, option, *args, **kw)

    return get


class TestTheFixLink:
    def _html(self, app, check):
        from flask import render_template

        with app.test_request_context("/health-center"):
            return render_template(
                "_health_checks.html",
                grouped=[("kea", "Kea", [check])],
                group_banners={},
                summary={"ok": 0, "warn": 0, "fail": 1, "skip": 0},
                checked_at=datetime.now(timezone.utc),
            )

    def test_the_link_is_two_words_and_the_hint_is_a_sentence_of_the_row(self, app):
        hint = (
            "A superadmin can choose a file under Settings → Kea → Kea logging; the sweep retries every five minutes."
        )
        c = health.Check(
            "problems_sweep", "Problems inbox sweep", "kea", "fail", "blind", hint, "/settings/kea#kea-logging"
        )
        html = self._html(app, c)
        assert '<a class="hc-fix" href="/settings/kea#kea-logging">Fix &rarr;</a>' in html
        assert f'<div class="hc-hint">{hint}</div>' in html
        assert html.count(hint) == 1

    def test_a_row_with_no_link_draws_no_hint_line(self, app):
        c = health.Check("problems_sweep", "Problems inbox sweep", "kea", "fail", "blind", "a hint", "")
        html = self._html(app, c)
        assert "hc-fix" not in html and "hc-hint" not in html

    def test_a_passing_row_draws_neither(self, app):
        c = health.Check("problems_sweep", "Problems inbox sweep", "kea", "ok", "fine", "a hint", "/settings/kea")
        html = self._html(app, c)
        assert "hc-fix" not in html and "hc-hint" not in html
