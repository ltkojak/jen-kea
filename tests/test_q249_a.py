"""
tests/test_q249_a.py
────────────────────
Q249 - the Kea logging card (Settings → Kea → Kea logging): the card READS where each running kea-dhcp4 writes its log and one form per server changes it to the journal, a file
Jen can read, or both.

    TestThePureEdit        `kea_config_edit.set_logger_output` / `describe_logger_output` over every starting shape
    TestTheCard            what the page prints, from the daemon's own answer
    TestTheRouteRefuses    who may post, and every refusal made before anything is sent
    TestTheProof           INV-017 in four worlds: proven; accepted and silent, so put back; Kea refuses; the put-back fails
    TestHealthAndDoctor    the sweep row and the Doctor point at the card

The daemon is a stateful fake Kea reached over real HTTP by the real `kea_command`; the Kea host is `tests/_q249_a_world.py::KeaHost`, standing in for `kea_host.helper_call` (the
function that runs the remote command). Nothing between those two edges is replaced: the change set, its preflight, the config history and the revert are the product's own.
"""

import copy
import json

import pytest

from jen import extensions
from jen.services import config_doctor as doctor
from jen.services import kea_config_edit as edit
from jen.services import kea_host
from jen.services import kea_log_trace as klt
from tests._q249_a_world import FILE_LOGGER, PACKAGED, KeaHost, dhcp4, file_server, kea_writes_defaults, packaged_logger
from tests.conftest import restricted_client
from tests.e2e._fake_kea_server import StatefulKeaServer

SID = 249  # a server id no other test file uses: this file's config-history rows are its own, and it removes them
LOG = "/var/log/kea/kea-dhcp4.log"
MB10 = 10 * 1024 * 1024
URL = f"/settings/infrastructure/kea-logging/{SID}"

MARKER = {"jen-investigation": {"until": "2026-11-23T15:00:00+00:00", "restore": {"severity": "INFO", "debuglevel": 0}}}


def cfg_of(loggers="absent"):
    return {"Dhcp4": dhcp4(loggers)}


def logger_of(cfg):
    return next(x for x in cfg["Dhcp4"]["loggers"] if x.get("name") == "kea-dhcp4")


SHAPES = {
    "no logger": cfg_of(),
    "packaged stdout": cfg_of([packaged_logger()]),
    "a file": cfg_of(
        [{"name": "kea-dhcp4", "output-options": [dict(FILE_LOGGER)], "severity": "WARN", "debuglevel": 0}]
    ),
    "two files": cfg_of(
        [
            {
                "name": "kea-dhcp4",
                "output-options": [{"output": "/var/log/kea/a.log"}, {"output": "/var/log/kea/b.log"}],
                "severity": "INFO",
            }
        ]
    ),
    "syslog": cfg_of([{"name": "kea-dhcp4", "output-options": [{"output": "syslog"}], "severity": "INFO"}]),
    "a marker": cfg_of(
        [
            {
                "name": "kea-dhcp4",
                "output-options": [dict(PACKAGED)],
                "severity": "DEBUG",
                "debuglevel": 55,
                "user-context": copy.deepcopy(MARKER),
            }
        ]
    ),
    "a damaged marker": cfg_of(
        [{"name": "kea-dhcp4", "output-options": [dict(PACKAGED)], "user-context": {"jen-investigation": "oops"}}]
    ),
    "loggers not a list": {"Dhcp4": {"loggers": {"name": "kea-dhcp4"}}},
}


class TestThePureEdit:
    @pytest.mark.parametrize(
        ("shape", "choice", "code"),
        [
            ("no logger", "journal", "nochange"),  # a config with no logger already logs to stdout
            ("no logger", "file", "ok"),
            ("no logger", "both", "ok"),
            ("packaged stdout", "journal", "nochange"),
            ("packaged stdout", "file", "ok"),
            ("packaged stdout", "both", "ok"),
            ("a file", "journal", "ok"),
            ("a file", "file", "nochange"),
            ("a file", "both", "ok"),
            ("two files", "journal", "ok"),
            ("two files", "file", "ok"),
            ("syslog", "journal", "ok"),
            ("syslog", "both", "ok"),
            ("a marker", "journal", "investigation"),
            ("a marker", "file", "investigation"),
            ("a damaged marker", "file", "investigation"),
            ("a damaged marker", "journal", "investigation"),
            ("loggers not a list", "file", "unsupported"),
            ("loggers not a list", "journal", "unsupported"),
        ],
    )
    def test_every_starting_shape(self, shape, choice, code):
        before = copy.deepcopy(SHAPES[shape])
        after, got = edit.set_logger_output(SHAPES[shape], choice, LOG, MB10, 4)
        assert got == code
        assert SHAPES[shape] == before  # the config given is never touched: the answer is a copy
        if code != "ok":
            assert after == before
            return
        wanted = {
            "journal": [PACKAGED],
            "file": [FILE_LOGGER],
            "both": [PACKAGED, FILE_LOGGER],
        }[choice]
        assert logger_of(after)["output-options"] == wanted
        # nothing but the kea-dhcp4 logger's output-options moved
        stripped_after, stripped_before = copy.deepcopy(after), copy.deepcopy(before)
        if "loggers" in stripped_before["Dhcp4"]:
            logger_of(stripped_after).pop("output-options")
            logger_of(stripped_before).pop("output-options")
            assert stripped_after == stripped_before

    def test_what_each_choice_stores_exactly(self):
        assert edit.logger_output_options("journal", "", 0, 0) == [{"output": "stdout", "pattern": "%-5p %m\n"}]
        assert edit.logger_output_options("file", "/var/log/kea/x.log", 1048576, 2) == [
            {"output": "/var/log/kea/x.log", "flush": True, "maxsize": 1048576, "maxver": 2}
        ]
        assert edit.logger_output_options("both", LOG, MB10, 4) == [PACKAGED, FILE_LOGGER]

    def test_the_entry_is_created_only_when_there_is_none_and_only_for_a_file(self):
        after, code = edit.set_logger_output(cfg_of(), "file", LOG, MB10, 4)
        assert code == "ok"
        assert after["Dhcp4"]["loggers"] == [
            {"name": "kea-dhcp4", "output-options": [FILE_LOGGER], "severity": "INFO", "debuglevel": 0}
        ]
        after, code = edit.set_logger_output(
            cfg_of([{"name": "kea-dhcp4.hosts", "severity": "DEBUG"}]), "both", LOG, MB10, 4
        )
        assert code == "ok" and [x["name"] for x in after["Dhcp4"]["loggers"]] == ["kea-dhcp4.hosts", "kea-dhcp4"]

    def test_severity_debuglevel_and_user_context_of_an_entry_are_never_touched(self):
        start = cfg_of(
            [
                {
                    "name": "kea-dhcp4",
                    "output-options": [dict(PACKAGED)],
                    "severity": "WARN",
                    "debuglevel": 7,
                    "user-context": {"note": "mine"},
                }
            ]
        )
        after, code = edit.set_logger_output(start, "file", LOG, MB10, 4)
        entry = logger_of(after)
        assert code == "ok" and (entry["severity"], entry["debuglevel"], entry["user-context"]) == (
            "WARN",
            7,
            {"note": "mine"},
        )

    def test_what_the_daemon_answers_with_its_defaults_written_out_is_the_same_choice(self):
        running = {
            "Dhcp4": kea_writes_defaults(
                dhcp4([{"name": "kea-dhcp4", "output-options": [dict(PACKAGED), dict(FILE_LOGGER)]}])
            )
        }
        assert logger_of(running)["output-options"][1]["pattern"] == ""  # as kea-dhcp4 3.0.5 answered
        assert edit.describe_logger_output(running)["choice"] == "both"
        assert edit.set_logger_output(running, "both", LOG, MB10, 4)[1] == "nochange"
        assert edit.set_logger_output(running, "both", LOG, MB10, 5)[1] == "ok"  # another number is a change

    @pytest.mark.parametrize(
        ("shape", "choice", "present", "words"),
        [
            ("no logger", "none", False, "the system journal (stdout)"),
            ("packaged stdout", "journal", True, "the system journal (stdout)"),
            ("a file", "file", True, f"the file {LOG}"),
            ("two files", "custom", True, "/var/log/kea/a.log, /var/log/kea/b.log"),
            ("syslog", "custom", True, "syslog"),
            ("loggers not a list", "none", False, "the system journal (stdout)"),
        ],
    )
    def test_describe(self, shape, choice, present, words):
        described = edit.describe_logger_output(SHAPES[shape])
        assert set(described) == {"present", "options", "choice", "file", "maxsize", "maxver"}
        assert (described["choice"], described["present"]) == (choice, present)
        assert edit.logger_output_words(described) == words

    def test_describe_gives_the_file_and_its_rotation(self):
        described = edit.describe_logger_output(SHAPES["a file"])
        assert (described["file"], described["maxsize"], described["maxver"]) == (LOG, MB10, 4)
        both = edit.describe_logger_output(cfg_of([{"name": "kea-dhcp4", "output-options": [PACKAGED, FILE_LOGGER]}]))
        assert both["choice"] == "both" and both["file"] == LOG
        assert edit.logger_output_words(both) == f"the system journal and the file {LOG}"

    def test_a_custom_pattern_on_a_file_and_stderr_are_custom(self):
        patterned = cfg_of([{"name": "kea-dhcp4", "output-options": [{"output": LOG, "pattern": "%m\n"}]}])
        assert edit.describe_logger_output(patterned)["choice"] == "custom"
        stderr = cfg_of([{"name": "kea-dhcp4", "output-options": [{"output": "stderr"}]}])
        assert edit.describe_logger_output(stderr)["choice"] == "custom"
        assert edit.logger_output_words(edit.describe_logger_output(stderr)) == "stderr"

    @pytest.mark.parametrize("shape", ["no logger", "packaged stdout", "a file", "two files", "syslog"])
    @pytest.mark.parametrize("choice", ["journal", "file", "both"])
    def test_the_snapshot_puts_the_output_back_exactly(self, shape, choice):
        start = SHAPES[shape]
        snapshot = edit.logger_output_snapshot(start)
        changed, code = edit.set_logger_output(start, choice, "/var/log/kea/other.log", 2097152, 9)
        back, back_code = edit.restore_logger_output(changed, snapshot)
        assert back == start
        assert back_code == ("ok" if code == "ok" else "nochange")

    @pytest.mark.parametrize(
        ("severity", "want"),
        [
            ("WARN", "WARN"),
            ("warn", "WARN"),
            (" Error ", "ERROR"),
            ("FATAL", "FATAL"),
            ("INFO", ""),
            ("DEBUG", ""),
            ("", ""),
            (None, ""),
            (7, ""),
            ("NONE", ""),
        ],
    )
    def test_which_severities_write_no_line_for_a_command(self, severity, want):
        entry = {"name": "kea-dhcp4"}
        if severity is not None:
            entry["severity"] = severity
        assert edit.logger_severity_above_info(cfg_of([entry])) == want
        assert edit.logger_severity_above_info(cfg_of()) == ""

    def test_the_doctor_block_is_the_cards_default_file(self):
        assert doctor.LOGGER_FILE == edit.LOGGER_OUTPUT_FILE_DEFAULT["output"] == LOG
        assert json.loads("{" + doctor.LOGGER_OUTPUT_JSON + "}") == {
            "output-options": [edit.LOGGER_OUTPUT_FILE_DEFAULT]
        }
        assert edit.logger_output_options("file", LOG, MB10, 4) == [edit.LOGGER_OUTPUT_FILE_DEFAULT]
        assert edit.logger_output_options("journal", "", 0, 0) == [edit.LOGGER_OUTPUT_JOURNAL]


# ── a Kea host and its daemon ────────────────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def daemon():
    d = StatefulKeaServer(dhcp4([packaged_logger()]))
    d.expand = kea_writes_defaults
    d.running = kea_writes_defaults(
        d.running
    )  # the running daemon answers with its defaults written out; its file does not carry them
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
    with db.cursor() as cur:
        cur.execute("DELETE FROM kea_config_revisions WHERE server_id=%s", (SID,))
    db.commit()


def flashes(client):
    with client.session_transaction() as sess:
        return [text for _category, text in sess.get("_flashes", [])]


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


def file_options(daemon):
    entry = next((x for x in daemon.file.get("loggers") or [] if x.get("name") == "kea-dhcp4"), None)
    return (entry or {}).get("output-options")


def audit_rows(db, action="KEA_LOG_OUTPUT"):
    db.commit()
    with db.cursor() as cur:
        cur.execute("SELECT details FROM audit_log WHERE action=%s ORDER BY id", (action,))
        return [row["details"] if isinstance(row, dict) else row[0] for row in cur.fetchall()]


class TestTheCard:
    def test_the_card_prints_what_the_running_daemon_says(self, logged_in_client, server, daemon):
        html = logged_in_client.get("/settings/kea").get_data(as_text=True)
        assert 'id="kea-logging"' in html and "Kea logging</span>" in html
        card = html.split('id="kea-logging"')[1].split("<!-- Servers & HA -->")[0]
        assert "the system journal (stdout)" in card.split("data-kl-writes>")[1].split("</dd>")[0]
        assert (
            "nothing: there is no file Jen may read" not in card
        )  # the Kea Log Path setting's default is a file Jen may read
        assert "from the Kea Log Path setting" in card
        assert 'value="journal" checked' in card and 'value="file" checked' not in card
        assert (
            f'value="{LOG}"' in card and 'name="rotate_mb" value="10"' in card and 'name="old_files" value="4"' in card
        )
        assert (
            'data-confirm="Change where kea-a writes its log? Kea is restarted to apply it."' in card
        )  # File over SSH
        assert 'data-confirm-label="Change Logging"' in card and "Save Kea Logging" in card
        assert 'name="csrf_token"' in card and f'action="{URL}"' in card

    def test_it_follows_the_ssh_card_and_is_on_the_pages_line(self, logged_in_client, server):
        html = logged_in_client.get("/settings/kea").get_data(as_text=True)
        assert html.index('id="kea-ssh"') < html.index('id="kea-logging"') < html.index('id="kea-servers"')
        jump = html.split('class="page-jump"')[1].split("</nav>")[0]
        assert jump.index('href="#kea-ssh"') < jump.index('href="#kea-logging"') < jump.index('href="#kea-servers"')
        assert '<a href="#kea-logging">Kea logging</a>' in jump

    def test_a_file_the_daemon_writes_fills_the_fields_and_is_what_jen_reads(self, logged_in_client, server, daemon):
        daemon.running = kea_writes_defaults(
            dhcp4(
                [
                    {
                        "name": "kea-dhcp4",
                        "output-options": [
                            {"output": "/var/log/kea/dhcp4.log", "maxsize": 5 * 1024 * 1024, "maxver": 7}
                        ],
                        "severity": "WARN",
                    }
                ]
            )
        )
        card = logged_in_client.get("/settings/kea").get_data(as_text=True).split('id="kea-logging"')[1]
        card = card.split("<!-- Servers & HA -->")[0]
        assert "the file /var/log/kea/dhcp4.log" in card
        assert "/var/log/kea/dhcp4.log</span> (from Kea&#39;s logger)" in card
        assert 'value="file" checked' in card and 'value="/var/log/kea/dhcp4.log"' in card
        assert 'name="rotate_mb" value="5"' in card and 'name="old_files" value="7"' in card
        assert "WARN" in card.split("data-kl-severity>")[1].split("</dd>")[0]

    def test_outputs_the_choices_do_not_describe_are_shown_as_given_and_the_confirm_says_they_go(
        self, logged_in_client, server, daemon
    ):
        daemon.running = dhcp4([{"name": "kea-dhcp4", "output-options": [{"output": "syslog"}, {"output": "stderr"}]}])
        card = logged_in_client.get("/settings/kea").get_data(as_text=True).split('id="kea-logging"')[1]
        card = card.split("<!-- Servers & HA -->")[0]
        assert "syslog, stderr" in card.split("data-kl-writes>")[1].split("</dd>")[0]
        assert "Kea is restarted to apply it. The outputs it has now are replaced." in card
        assert " checked" not in card  # none of the three is what it runs

    def test_a_marker_reads_investigation_logging_is_on(self, logged_in_client, server, daemon):
        daemon.running = SHAPES["a marker"]["Dhcp4"]
        card = logged_in_client.get("/settings/kea").get_data(as_text=True).split('id="kea-logging"')[1]
        severity = card.split("data-kl-severity>")[1].split("</dd>")[0]
        assert "DEBUG (debuglevel 55)" in severity and "(investigation logging is on)" in severity

    def test_a_daemon_that_cannot_be_read_gets_the_reason_and_no_form(self, logged_in_client, server, daemon):
        daemon.no_service_key = True
        card = logged_in_client.get("/settings/kea").get_data(as_text=True).split('id="kea-logging"')[1]
        card = card.split("<!-- Servers & HA -->")[0]
        assert "Kea's configuration could not be read: the answer carries no Dhcp4 configuration" in card
        assert "Save Kea Logging" not in card and URL not in card

    def test_an_admin_is_shown_no_card_and_no_link_to_it(self, client, db, server):
        restricted_client(client, db, None, role="admin", username="q249admin")
        html = client.get("/settings/kea").get_data(as_text=True)
        assert 'id="kea-logging"' not in html and "#kea-logging" not in html and "Save Kea Logging" not in html


class TestTheRouteRefuses:
    @pytest.mark.parametrize("role", ["viewer", "admin"])
    def test_a_viewer_and_an_admin_are_refused(self, client, db, server, daemon, host, role):
        restricted_client(client, db, None, role=role, username=f"q249{role}")
        sent = len(daemon.commands)
        response = post(client, output="file")
        assert response.status_code in (302, 403)
        assert len(daemon.commands) == sent and host.calls == []
        assert audit_rows(db) == []

    def test_without_a_recent_password_it_is_answered_as_its_siblings_are_and_nothing_is_sent(
        self, logged_in_client, server, daemon, host, db
    ):
        from datetime import datetime, timedelta, timezone

        with logged_in_client.session_transaction() as sess:
            sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        response = post(logged_in_client, output="file")
        assert response.status_code == 302 and "reauth" in response.headers["Location"]
        assert daemon.commands == [] and host.calls == [] and audit_rows(db) == []

    def test_the_sentence_names_the_page_whose_template_draws_the_controls(self):
        import pathlib

        page = pathlib.Path("templates/servers.html").read_text(encoding="utf-8")
        assert "{% block title %}Kea Servers{% endblock %}" in page
        assert "investigation_controls(s.server" in page  # Turn it off
        assert 'action="/servers/investigation-logging/forget/' in page  # resolve: Forget
        assert 'action="/servers/investigation-logging/acknowledge-damaged"' in page  # resolve: acknowledge
        assert "resolve it on the Kea Servers page first" in klt.investigation_sentence("x")

    def test_a_server_that_is_not_configured(self, logged_in_client, server):
        response = logged_in_client.post("/settings/infrastructure/kea-logging/777", data={"output": "journal"})
        assert response.status_code == 302 and flashes(logged_in_client) == ["That server is not configured."]

    def test_a_marker_in_the_running_config_refuses_before_anything_is_sent(
        self, logged_in_client, server, daemon, host, db
    ):
        daemon.running = SHAPES["a marker"]["Dhcp4"]
        post(logged_in_client, output="file")
        assert flashes(logged_in_client) == [
            "Investigation logging is on for kea-a (or its last session is not resolved). Turn it off or resolve it on the Kea Servers page first; a restore "
            "would undo this change."
        ]
        assert not {"apply-config", "test-config", "service"} & set(host.ops())
        assert "config-set" not in daemon.commands and audit_rows(db) == []

    def test_a_damaged_marker_refuses_too(self, logged_in_client, server, daemon, host):
        daemon.running = SHAPES["a damaged marker"]["Dhcp4"]
        post(logged_in_client, output="journal")
        assert flashes(logged_in_client)[0].startswith("Investigation logging is on for kea-a")
        assert "apply-config" not in host.ops()

    def test_a_marker_only_the_file_carries_refuses_too(self, logged_in_client, server, daemon, host):
        daemon.file = copy.deepcopy(SHAPES["a marker"]["Dhcp4"])  # written, and the daemon has not loaded it
        post(logged_in_client, output="file")
        assert flashes(logged_in_client)[0].startswith("Investigation logging is on for kea-a")
        assert "apply-config" not in host.ops() and "service" not in host.ops()

    def test_jens_own_record_of_a_session_refuses(self, logged_in_client, server, host):
        from jen.models.user import set_global_setting
        from jen.services import investigation_logging as inv

        entry = {
            "name": "kea-a",
            "until": "2026-11-23T15:00:00+00:00",
            "ssh_host": server["ssh_host"],
            "file": "restored",
            "daemon": "debug",
            "pending": "reload",
        }
        set_global_setting(inv.RECORD_KEY, json.dumps({"servers": {str(SID): entry}}))
        assert inv.blocking_removal([SID])  # the record reads as a session that is not finished
        post(logged_in_client, output="journal", log_file="")
        assert flashes(logged_in_client)[0].startswith("Investigation logging is on for kea-a")
        assert "apply-config" not in host.ops()

    def test_a_session_the_kea_host_holds_refuses(self, logged_in_client, server, daemon, host):
        daemon.running = kea_writes_defaults(dhcp4([{"name": "kea-dhcp4", "output-options": [dict(FILE_LOGGER)]}]))
        host.session = {
            "until": "2026-11-23T15:00:00+00:00",
            "restore": {"created": True},
            "armed_at": "2026-11-23T14:00:00+00:00",
        }
        post(logged_in_client, output="journal")
        assert flashes(logged_in_client)[0].startswith("Investigation logging is on for kea-a")
        assert "investigation-status" in host.ops() and "apply-config" not in host.ops()

    def test_a_file_choice_without_ssh_is_refused(self, logged_in_client, server, daemon, host):
        server["ssh_host"] = ""
        server["config_transport"] = (
            "api"  # (Q250) on File over SSH a server with no SSH has no write path at all, and is told that first
        )
        post(logged_in_client, output="file")
        assert flashes(logged_in_client) == [
            "Jen reads Kea's log over SSH, and kea-a has no SSH configured (or no helper). Set that up first; without it a file would be written that Jen cannot read."
        ]
        assert host.calls == [] and "config-set" not in daemon.commands

    def test_a_file_choice_without_the_helper_is_refused(self, logged_in_client, server, daemon, host):
        host.missing = True
        post(logged_in_client, output="both")
        # (the first line is the product's standing note that this host has no helper; the refusal follows it)
        assert flashes(logged_in_client)[-1].startswith(
            "Jen reads Kea's log over SSH, and kea-a has no SSH configured (or no helper)."
        )
        assert "apply-config" not in host.ops()

    @pytest.mark.parametrize(
        "path",
        [
            "/tmp/kea.log",
            "/var/log/kea.log",
            "/var/log/kea/sub/x.log",
            "/var/log/kea/../x.log",
            "/var/log/kea/x.txt",
            "kea.log",
            "",
            "/var/log/kea/a b.log",
        ],
    )
    def test_a_bad_path_is_refused_under_its_field(self, logged_in_client, server, daemon, host, path):
        post(logged_in_client, output="file", log_file=path)
        with logged_in_client.session_transaction() as sess:
            errors = sess.get("field_errors")
        assert errors and errors[0][0] == f"log_file_{SID}" and "directly in /var/log/kea" in errors[0][1]
        assert host.calls == [] and daemon.commands == []

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("rotate_mb", "0"),
            ("rotate_mb", "1025"),
            ("rotate_mb", "1.5"),
            ("rotate_mb", ""),
            ("rotate_mb", "-3"),
            ("old_files", "0"),
            ("old_files", "51"),
            ("old_files", "x"),
        ],
    )
    def test_a_bad_number_is_refused_under_its_field(self, logged_in_client, server, daemon, host, field, value):
        post(logged_in_client, output="both", **{field: value})
        with logged_in_client.session_transaction() as sess:
            errors = sess.get("field_errors")
        assert errors and errors[0][0] == f"{field}_{SID}" and "whole number" in errors[0][1]
        assert host.calls == [] and daemon.commands == []

    def test_a_choice_that_is_not_one_of_the_three(self, logged_in_client, server, daemon, host):
        post(logged_in_client, output="syslog")
        assert flashes(logged_in_client) == ["Choose where Kea writes its log."]
        assert host.calls == [] and daemon.commands == []

    def test_nothing_to_change_writes_nothing(self, logged_in_client, server, daemon, host, db):
        post(logged_in_client, output="journal")
        assert flashes(logged_in_client) == ["Nothing to change."]
        assert daemon.commands == ["config-get"] and "apply-config" not in host.ops() and "service" not in host.ops()
        assert audit_rows(db) == []

    def test_the_journal_choice_needs_no_ssh_read_and_no_proof(self, logged_in_client, server, daemon, host, db):
        daemon.file = dhcp4([{"name": "kea-dhcp4", "output-options": [dict(FILE_LOGGER)], "severity": "INFO"}])
        daemon.running = kea_writes_defaults(daemon.file)
        post(logged_in_client, output="journal")
        assert "tail-log" not in host.ops()
        assert file_options(daemon) == [PACKAGED] and running_options(daemon) == [PACKAGED]
        assert audit_rows(db) == [f"kea-a: the file {LOG} -> the system journal (stdout)"]


class TestTheProof:
    """INV-017: a change of Kea's log output is proven by the log itself or put back."""

    def test_proven_kea_writes_the_file_and_the_change_stands(self, logged_in_client, server, daemon, host, db):
        post(logged_in_client, output="file")
        said = flashes(logged_in_client)
        assert said[-1] == f"Kea is writing to {LOG} on kea-a."
        assert file_options(daemon) == [FILE_LOGGER] and running_options(daemon) == [
            {k: v for k, v in FILE_LOGGER.items() if k != "flush"}
        ]
        ops = host.ops()
        assert (
            ops.index("tail-log")
            < ops.index("apply-config")
            < ops.index("service")
            < len(ops) - 1 - ops[::-1].index("tail-log")
        )
        assert audit_rows(db) == [f"kea-a: the system journal (stdout) -> the file {LOG}"]
        # the entry's level was left alone
        entry = next(x for x in daemon.file["loggers"] if x["name"] == "kea-dhcp4")
        assert (entry["severity"], entry["debuglevel"]) == ("INFO", 0)

    def test_proven_for_the_journal_and_a_file(self, logged_in_client, server, daemon, host, db):
        post(logged_in_client, output="both", log_file="/var/log/kea/dhcp4.log", rotate_mb="2", old_files="9")
        wanted = [PACKAGED, {"output": "/var/log/kea/dhcp4.log", "flush": True, "maxsize": 2097152, "maxver": 9}]
        assert file_options(daemon) == wanted
        assert audit_rows(db) == [
            "kea-a: the system journal (stdout) -> the system journal and the file /var/log/kea/dhcp4.log"
        ]

    def test_accepted_and_silent_the_previous_logging_is_put_back(self, logged_in_client, server, daemon, host, db):
        host.writes_log = (
            False  # Kea said "Configuration successful." and logs nothing anywhere (kea_log_probe.out, row 7)
        )
        before_file = copy.deepcopy(daemon.file)
        post(logged_in_client, output="file")
        assert flashes(logged_in_client) == [
            f"Kea accepted the change but wrote nothing to {LOG} on kea-a, so the previous logging was put back. "
            f"Check that {LOG} is writable by the account kea-dhcp4 runs as."
        ]
        assert daemon.file == before_file and running_options(daemon) == [PACKAGED]
        assert host.ops().count("apply-config") == 2 and host.ops().count("service") == 2
        assert host.ops().count("tail-log") == 1 + klt.LOG_OUTPUT_TRIES
        # (Q250) Kea ran the new output for the seconds of the proof: the audit log says so
        assert audit_rows(db) == [
            f"kea-a: the system journal (stdout) -> the file {LOG} was accepted by Kea, not proven, and put back"
        ]

    def test_a_file_that_is_there_and_does_not_grow_is_not_a_proof(self, logged_in_client, server, daemon, host):
        host.writes_log = False
        host.existing[LOG] = ["2026-11-01 00:00:00.000 INFO  [kea-dhcp4.dhcp4/1.1] DHCP4_STARTED an old line"]
        before_file = copy.deepcopy(daemon.file)
        post(logged_in_client, output="both")
        assert flashes(logged_in_client)[0].startswith("Kea accepted the change but wrote nothing to")
        assert daemon.file == before_file

    def test_the_put_back_removes_an_entry_the_change_created(self, logged_in_client, server, daemon, host):
        daemon.file = dhcp4()  # no loggers at all
        daemon.running = dhcp4()
        host.writes_log = False
        post(logged_in_client, output="file")
        assert flashes(logged_in_client)[0].startswith("Kea accepted the change but wrote nothing to")
        assert daemon.file == dhcp4() and "loggers" not in daemon.running or daemon.running.get("loggers") == []

    def test_kea_refuses_and_its_own_text_is_shown(self, logged_in_client, server, daemon, host, db):
        host.test_refusal = (
            "invalid path in `output`: invalid path specified: '/var/log', supported path is '/var/log/kea'"
        )
        before_file = copy.deepcopy(daemon.file)
        post(logged_in_client, output="file")
        said = " ".join(flashes(logged_in_client))
        assert "supported path is '/var/log/kea'" in said and "kea-a" in said
        assert daemon.file == before_file and "apply-config" not in host.ops() and "service" not in host.ops()
        assert audit_rows(db) == []

    def test_the_put_back_fails_and_jen_says_what_the_daemon_runs_now(self, logged_in_client, server, daemon, host, db):
        host.writes_log = False
        host.apply_fails_from = 2  # the change is written; the put-back is not
        post(logged_in_client, output="file")
        said = flashes(logged_in_client)
        assert len(said) == 1
        assert said[0].startswith(
            f"Kea accepted the change but wrote nothing to {LOG} on kea-a, and putting the previous logging back failed: "
        )
        assert "No space left on device" in said[0]
        assert f"kea-a now writes its log to the file {LOG}." in said[0]
        assert file_options(daemon) == [FILE_LOGGER]  # what stands is what Jen said stands
        assert audit_rows(db) == [
            f"kea-a: the system journal (stdout) -> the file {LOG} (the change was not proven and could not be put back)"
        ]

    # (Q250) above INFO the proof is the file Kea CREATED; `tests/test_q250_a.py::TestAboveInfo` holds the other two worlds (a file that was already there, and the file
    # the logger already wrote to)
    CREATED = "Kea created /var/log/kea/kea-dhcp4.log on kea-a. Its severity is WARN, so it has written no line yet; the file fills when Kea next logs at that level."

    def _at(self, daemon, severity):
        daemon.file["loggers"][0]["severity"] = severity
        daemon.running["loggers"][0]["severity"] = severity

    def test_a_logger_above_info_is_not_judged_by_a_tail_that_did_not_move(
        self, logged_in_client, server, daemon, host, db
    ):
        self._at(daemon, "WARN")
        host.quiet = True  # at WARN a command writes no line: the tail does not move, and that is not evidence. Kea made the file, and that is
        post(logged_in_client, output="file")
        with logged_in_client.session_transaction() as sess:
            said = list(sess.get("_flashes", []))
        assert said[-1] == ("success", self.CREATED)
        assert file_options(daemon) == [FILE_LOGGER]  # the change stands
        assert host.ops().count("apply-config") == 1 and host.ops().count("service") == 1  # nothing was put back
        assert audit_rows(db) == [
            f"kea-a: the system journal (stdout) -> the file {LOG} (proven by the file Kea created: severity WARN)"
        ]

    @pytest.mark.parametrize("severity", ["warn", "Error", "FATAL"])
    def test_the_severity_is_compared_without_case(self, server, daemon, host, severity):
        self._at(daemon, severity)
        host.quiet = True
        out = klt.change_log_output(server, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"], out["level"]) == (True, "created", "success")
        assert (
            f"Its severity is {severity.upper()}," in out["lines"][-1]
            and out["note"] == f" (proven by the file Kea created: severity {severity.upper()})"
        )

    def test_a_logger_above_info_whose_file_did_move_is_the_ordinary_proven_case(
        self, logged_in_client, server, daemon, host, db
    ):
        self._at(daemon, "WARN")
        post(logged_in_client, output="file")
        assert flashes(logged_in_client)[-1] == f"Kea is writing to {LOG} on kea-a."
        assert audit_rows(db) == [f"kea-a: the system journal (stdout) -> the file {LOG}"]

    @pytest.mark.parametrize("severity", ["INFO", "DEBUG", "", "TRACE"])
    def test_info_or_lower_and_anything_else_is_still_put_back(self, server, daemon, host, severity):
        self._at(daemon, severity)
        host.writes_log = False
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["code"] == "put-back"

    def test_the_service_function_reports_each_world_by_code(self, server, daemon, host):
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["code"] == "ok"
        assert klt.change_log_output(server, "file", LOG, MB10, 4)["code"] == "nochange"
        host.writes_log = False
        out = klt.change_log_output(server, "both", "/var/log/kea/second.log", MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back")
        assert file_options(daemon) == [FILE_LOGGER]  # back on the file that was proven


class TestHealthAndDoctor:
    def test_the_doctor_note_points_at_the_card(self):
        note = next(f for f in doctor.diagnose(dhcp4([packaged_logger()]), hosts=[]) if f["id"] == "logger-no-file")
        assert note["fix_url"] == "/settings/kea#kea-logging"
        assert (
            "A superadmin can choose a file under Settings → Kea → Kea logging; or paste this into that logger's entry"
            in note["detail"]
        )
        assert doctor.LOGGER_OUTPUT_JSON in note["detail"]  # the paste line stays for a server Jen cannot write to

    def test_the_sweep_row_points_at_the_card(self, db, monkeypatch):
        from jen.services import client_problems as cp
        from jen.services import health

        servers = [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.1"}]
        monkeypatch.setattr(extensions, "KEA_SERVERS", servers)
        monkeypatch.setattr(
            cp,
            "read_status",
            lambda s: {
                "swept_at": cp._now(),
                "servers": [
                    {
                        "id": 1,
                        "name": "kea-a",
                        "misses": 13495,
                        "last_read": None,
                        "last_error": "missing",
                        "last_path": LOG,
                    }
                ],
            },
        )
        row = health._problems_sweep({})
        assert row.status == "fail" and row.fix_url == "/settings/kea#kea-logging"
        # (Q250) the sentence says who can choose a file and names the card each answer is on; the link is a superadmin's (tests/test_q250_b.py)
        assert (
            "; a superadmin can choose a file under Settings → Kea → Kea logging, or set the Kea log path under Settings → Kea → SSH if Kea already writes one (13495 sweeps without a read, last read never)"
            in row.detail
        )
        assert row.fix_hint == (
            "A superadmin can choose a file under Settings → Kea → Kea logging, or set the Kea log path under Settings → Kea → SSH if Kea already writes one; the sweep retries every five minutes."
        )
        assert health._problems_sweep({"role": "admin"}).fix_url == ""


class TestOverTheDaemonsOwnApi:
    """The same card on a server whose write mode is Live API: `config-test`, `config-set` and `config-write` to the stateful fake over real HTTP, no restart. Jen's own record
    of changes and of the readiness check is the in-memory one the API tests share (`tests/_kea_api_world.py`), and the host's file is the fake daemon's own file."""

    @pytest.fixture
    def api(self, monkeypatch, daemon, host):
        from tests import _kea_api_world as world

        store = world.install_store(monkeypatch)
        world.install_probes(monkeypatch)
        server = {"id": SID, "name": "kea-a", "api_url": daemon.url, "config_transport": "api", "ssh_host": "10.9.9.9"}
        daemon.file = copy.deepcopy(
            daemon.running
        )  # the file is Kea's own rendering of what runs, as after a switch to Live API
        self.clock = world.host_reads_the_fakes_file(monkeypatch, daemon, store, server_id=SID)["clock"]
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        return server

    def test_a_file_is_set_live_proven_and_written_with_no_restart(self, api, daemon, host):
        out = klt.change_log_output(api, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (True, "ok"), out
        assert {"config-test", "config-set", "config-write"} <= set(daemon.commands)
        assert "service" not in host.ops() and "apply-config" not in host.ops()
        assert running_options(daemon) == [{k: v for k, v in FILE_LOGGER.items() if k != "flush"}]
        assert out["lines"][-1] == f"Kea is writing to {LOG} on kea-a."

    def test_accepted_and_silent_is_put_back_over_the_api(self, api, daemon, host):
        host.writes_log = False
        out = klt.change_log_output(api, "both", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "put-back"), out
        assert running_options(daemon) == [PACKAGED]
        assert daemon.commands.count("config-set") == 2 and "service" not in host.ops()

    def test_keas_own_refusal_of_the_set_is_shown_with_its_text(self, api, daemon, host):
        daemon.set_fails = (
            "invalid path in `output`: invalid path specified: '/var/log', supported path is '/var/log/kea'"
        )
        out = klt.change_log_output(api, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"]) == (False, "refused")
        assert "supported path is '/var/log/kea'" in " ".join(out["lines"])
        assert running_options(daemon) == [PACKAGED]

    def test_a_logger_above_info_is_not_put_back_over_the_api(self, api, daemon, host):
        daemon.running["loggers"][0]["severity"] = "ERROR"
        daemon.file = copy.deepcopy(daemon.running)
        # the file with that severity is one the daemon loaded: written before its last load (as `ProofWorld.loaded_file` sets the host's clock)
        self.clock.seen_sha = self.clock._sha()
        self.clock.mtime = self.clock.loaded_at - 100
        host.quiet = True
        out = klt.change_log_output(api, "file", LOG, MB10, 4)
        assert (out["ok"], out["code"], out["level"]) == (True, "created", "success"), out
        assert (
            "Its severity is ERROR," in out["lines"][-1]
            and out["note"] == " (proven by the file Kea created: severity ERROR)"
        )
        assert daemon.commands.count("config-set") == 1  # nothing was put back
        assert running_options(daemon) == [{k: v for k, v in FILE_LOGGER.items() if k != "flush"}]

    def test_the_confirm_says_what_happens_on_each_write_mode(self, api, daemon, host):
        assert klt.log_output_card(api)["confirm"] == "Change where kea-a writes its log? Kea applies it at once."
        on_file = {**api, "config_transport": "file"}
        assert (
            klt.log_output_card(on_file)["confirm"]
            == "Change where kea-a writes its log? Kea is restarted to apply it."
        )

    def test_the_journal_choice_needs_no_ssh_at_all(self, api, daemon, host):
        api["ssh_host"] = ""
        daemon.running = kea_writes_defaults(dhcp4([{"name": "kea-dhcp4", "output-options": [dict(FILE_LOGGER)]}]))
        out = klt.change_log_output(api, "journal")
        assert (out["ok"], out["code"]) == (True, "ok"), out
        assert host.calls == [] and running_options(daemon) == [PACKAGED]
