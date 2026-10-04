"""
tests/test_install_database.py
──────────────────────────────
v5.67.0-beta.18 (Q132) — the installer on a machine with no database, and the install log.

The maintainer's first fresh install (a new Ubuntu 24.04 box, no database server on it) answered the Jen-database
prompt with the defaults, got "could not reach", chose `c) Continue without it — I will finish in Jen`, and the shell
prompt came back: `_blank_if_placeholder` ended in a bare `[[ ]] && ...` that is FALSE for a real host, which under
`set -euo pipefail` exited the whole script silently — and, had it not, "finish in Jen" is a promise Jen cannot keep
(create_app() runs the migrations against [jen_db] before it serves anything, so the service crash-loops every five
seconds). Run through a real bash with the same sourced-copy technique tests/test_layout.py uses; the install CI job is
what runs the whole script. Self-skips on Windows (POSIX shell semantics).
"""

import pathlib
import platform
import re
import stat
import textwrap

import pytest

from tests.test_layout import _run

pytestmark = pytest.mark.skipif(platform.system() == "Windows", reason="POSIX shell semantics required")

ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALL = ROOT / "install.sh"
UNINSTALL = ROOT / "uninstall.sh"


def _text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _functions(text):
    """{name: [lines of its body]} for every top-level `name() {` ... `}` in a script."""
    out, name, body = {}, None, []
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", line)
        if m and name is None:
            name, body = m.group(1), []
            if line.rstrip().endswith("}"):  # a one-line function
                out[name] = [line]
                name = None
            continue
        if name is not None:
            if line == "}":
                out[name] = body
                name = None
            else:
                body.append(line)
    return out


def _last_statement(body):
    for line in reversed(body):
        s = line.strip()
        if s and not s.startswith("#"):
            return s
    return ""


BARE_TEST_LIST = re.compile(r"^\[\[ .* \]\] +&& +[^|]*$")


class TestBlankIfPlaceholder:
    def test_it_ends_in_return_zero(self):
        body = _functions(_text(INSTALL))["_blank_if_placeholder"]
        assert _last_statement(body).startswith("return 0")

    def test_a_real_host_does_not_exit_the_shell_under_set_e(self, tmp_path):
        """The reported bug: with a value that is NOT the placeholder the test is false and the `&&` list returned 1."""
        r = _run(
            tmp_path,
            textwrap.dedent("""
                set -e
                V=localhost
                _blank_if_placeholder V "YOUR-KEA-SERVER"
                echo "survived [$V]"
            """),
        )
        assert r.returncode == 0 and "survived [localhost]" in r.stdout, r.stdout + r.stderr

    def test_the_placeholder_is_still_blanked(self, tmp_path):
        r = _run(
            tmp_path,
            textwrap.dedent("""
                set -e
                V="YOUR-KEA-SERVER"
                _blank_if_placeholder V "YOUR-KEA-SERVER"
                echo "survived [$V]"
            """),
        )
        assert r.returncode == 0 and "survived []" in r.stdout, r.stdout + r.stderr


class TestNoFunctionEndsInABareTestList:
    """A function whose LAST statement is `[[ ... ]] && ...` returns 1 when the test is false, and under `set -e` a bare
    call of it exits the script with no message. The scan names any function (in either installer script) that ends that
    way without a `return` after it, so the class of bug cannot come back."""

    @pytest.mark.parametrize("script", [INSTALL, UNINSTALL], ids=["install.sh", "uninstall.sh"])
    def test_none_does(self, script):
        offenders = [
            name for name, body in _functions(_text(script)).items() if BARE_TEST_LIST.match(_last_statement(body))
        ]
        assert not offenders, (
            f"{script.name}: {offenders} end in a bare `[[ ]] && ...` — add `return 0` after it "
            "(a false test would be the function's status, fatal under set -e)"
        )

    def test_the_scan_finds_the_old_shape_and_ignores_the_fixed_one(self):
        old = _functions('f() {\n    local x=1\n    [[ "$x" == "2" ]] && x=""\n}\n')
        fixed = _functions('f() {\n    local x=1\n    [[ "$x" == "2" ]] && x=""\n    return 0\n}\n')
        assert BARE_TEST_LIST.match(_last_statement(old["f"]))
        assert not BARE_TEST_LIST.match(_last_statement(fixed["f"]))
        withor = _functions("f() {\n    [[ -d /x ]] && echo yes || echo no\n}\n")
        assert not BARE_TEST_LIST.match(_last_statement(withor["f"])), "`|| ...` makes the list end truthy"


class TestTheJenDatabaseFailureChoice:
    def _choice(self, tmp_path, required, unattended=True, host="localhost"):
        script = textwrap.dedent(f"""
            MODE_UNATTENDED={"true" if unattended else "false"}
            HAVE_TTY=false
            _jen_db_can_self_create() {{ return 1; }}
            _connection_failure_choice "Jen database" "jen@{host}/jen" {required}
            echo "choice=[$_RETRY_ACTION]"
        """)
        return _run(tmp_path, script)

    def test_non_interactive_and_required_is_fatal_with_a_reason_not_a_silent_continue(self, tmp_path):
        r = self._choice(tmp_path, "required")
        out = r.stdout + r.stderr
        assert r.returncode != 0 and "choice=" not in out, out
        assert "Could not reach Jen database (jen@localhost/jen)" in out
        assert "Jen does not start without it" in out and "restart every 5 seconds" in out

    def test_the_hint_depends_on_whether_a_local_database_can_create_it(self, tmp_path):
        r = _run(
            tmp_path,
            textwrap.dedent("""
                MODE_UNATTENDED=true; HAVE_TTY=false
                _jen_db_can_self_create() { return 0; }
                _connection_failure_choice "Jen database" "jen@localhost/jen" required
            """),
        )
        assert "accepts root over its socket" in r.stdout and r.returncode != 0
        r = self._choice(tmp_path, "required", host="db.example.net")
        assert "No usable database answered at db.example.net" in r.stdout

    def test_non_interactive_and_optional_still_warns_and_continues(self, tmp_path):
        r = self._choice(tmp_path, "")
        assert r.returncode == 0 and "choice=[continue]" in r.stdout, r.stdout + r.stderr
        assert "continuing; configure it later in Jen" in r.stdout

    def test_the_interactive_menu_for_the_jen_database_has_no_continue(self):
        body = "\n".join(_functions(_text(INSTALL))["_connection_failure_choice"])
        required_branch = body.split('if [[ "$required" == "required" ]]; then\n            [[ "$offer_local"', 1)[
            1
        ].split("else", 1)[0]
        assert "Quit — Jen cannot start without its own database" in required_branch
        assert "Continue without it" not in required_branch
        assert "Continue without it — I will finish in Jen" in body.split(required_branch, 1)[1], (
            "an optional menu keeps c)"
        )

    def test_the_jen_database_prompt_passes_required_and_has_no_continue_case(self):
        body = "\n".join(_functions(_text(INSTALL))["_configure_jen_db"])
        assert '"${JEN_DB_USER}@${JEN_DB_HOST}/${JEN_DB_NAME}" required' in body
        assert "continue)" not in body and "quit)" in body

    def test_the_kea_sections_do_not_use_the_menu_at_all(self):
        fns = _functions(_text(INSTALL))
        for name in ("_configure_kea_api", "_configure_kea_db"):
            assert "_connection_failure_choice" not in "\n".join(fns[name]), name


class TestStartServiceNamesTheLikelyCause:
    def _start(self, tmp_path, config_text):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        for name, body in {
            "systemctl": 'case "$1" in is-active) exit 3 ;; *) exit 0 ;; esac',
            "journalctl": "echo journal-line",
            "sleep": "exit 0",
        }.items():
            p = bindir / name
            p.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
            p.chmod(p.stat().st_mode | stat.S_IEXEC)
        cfg = tmp_path / "jen.config"
        cfg.write_text(config_text, encoding="utf-8")
        return _run(
            tmp_path,
            textwrap.dedent(f"""
                export PATH="{bindir}:$PATH"
                INSTALL_LOG="{tmp_path}/install.log"
                IS_UPGRADE=false; MODE_REPAIR=false
                CONFIG_FILE="{cfg}"
                set -e
                start_service
            """),
        )

    def test_a_failed_start_with_a_jen_db_section_names_the_database(self, tmp_path):
        r = self._start(tmp_path, "[jen_db]\nhost = localhost\n")
        out = r.stdout + r.stderr
        assert r.returncode != 0 and "Jen service failed to start" in out
        assert "likeliest cause is Jen's own database" in out and "[jen_db] answers" in out

    def test_without_the_section_it_does_not_guess(self, tmp_path):
        r = self._start(tmp_path, "[server]\nhttp_port = 5050\n")
        assert r.returncode != 0 and "likeliest cause" not in r.stdout + r.stderr

    def test_the_systemctl_calls_are_logged(self, tmp_path):
        self._start(tmp_path, "[jen_db]\n")
        log = (tmp_path / "install.log").read_text(encoding="utf-8")
        assert "systemctl daemon-reload" in log and "systemctl enable jen" in log and "systemctl start jen" in log


class TestTheInstallLog:
    def test_init_creates_a_private_file_with_a_dated_header_and_appends_per_run(self, tmp_path):
        log = tmp_path / "var" / "log" / "jen-install.log"
        r = _run(
            tmp_path,
            f'INSTALL_LOG="{log}"\n_init_install_log\n_init_install_log\necho "log=[$INSTALL_LOG]"',
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert stat.S_IMODE(log.stat().st_mode) == 0o600
        text = log.read_text(encoding="utf-8")
        assert text.count("══ Jen installer ") == 2, "one header per run, appended"
        assert re.search(r"══ Jen installer \S+ — \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", text)

    def test_an_unwritable_log_degrades_to_dev_null_with_a_warning(self, tmp_path):
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        r = _run(tmp_path, f'INSTALL_LOG="{blocker}/jen-install.log"\n_init_install_log\necho "log=[$INSTALL_LOG]"')
        assert "log=[/dev/null]" in r.stdout and "will not be kept" in r.stdout

    def test_a_logged_command_writes_stdout_and_stderr_and_returns_its_own_status(self, tmp_path):
        log = tmp_path / "i.log"
        r = _run(
            tmp_path,
            textwrap.dedent(f"""
                INSTALL_LOG="{log}"
                _run_logged "good" sh -c 'echo to-out; echo to-err >&2'
                echo "rc1=$?"
                _run_logged "bad" sh -c 'echo failing >&2; exit 7' || echo "rc2=$?"
            """),
        )
        assert "rc1=0" in r.stdout and "rc2=7" in r.stdout, r.stdout + r.stderr
        assert "to-out" not in r.stdout and "to-err" not in r.stdout + r.stderr, "nothing reaches the screen"
        text = log.read_text(encoding="utf-8")
        assert "to-out" in text and "to-err" in text and "failing" in text
        assert "── " in text and "good" in text and "$ sh -c" in text, "a header names the step and its argv"

    def test_the_noargs_variant_never_records_the_argv(self, tmp_path):
        log = tmp_path / "i.log"
        r = _run(
            tmp_path,
            f'INSTALL_LOG="{log}"\nprintf "SECRET-SQL" | _run_logged_noargs "mysql step" cat -- /dev/stdin\n',
        )
        assert r.returncode == 0
        text = log.read_text(encoding="utf-8")
        assert "mysql step" in text and "$ cat" not in text

    def test_mysql_calls_never_put_the_password_in_the_log_header(self, tmp_path):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        p = bindir / "mysql"
        p.write_text("#!/bin/sh\necho 'ERROR 2002 (HY000): Can not connect' >&2\nexit 1\n", encoding="utf-8")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
        log = tmp_path / "i.log"
        r = _run(
            tmp_path,
            f'export PATH="{bindir}:$PATH"\nINSTALL_LOG="{log}"\ntest_mysql db.example jen "hunter2-pass" jen || echo "rc=$?"',
        )
        text = log.read_text(encoding="utf-8")
        assert "rc=1" in r.stdout and "hunter2-pass" not in text and "ERROR 2002" in text
        assert "mysql connection test jen@db.example/jen" in text

    def test_the_tail_prints_the_last_twenty_lines_and_the_path(self, tmp_path):
        log = tmp_path / "i.log"
        log.write_text("".join(f"line {i}\n" for i in range(1, 41)), encoding="utf-8")
        r = _run(tmp_path, f'INSTALL_LOG="{log}"\n_install_log_tail')
        out = r.stdout
        assert f"The last 20 lines of {log}" in out
        assert "line 21" in out and "line 40" in out and "line 20" not in out

    def test_the_tail_is_silent_when_there_is_no_log(self, tmp_path):
        r = _run(tmp_path, "INSTALL_LOG=/dev/null\n_install_log_tail\necho done")
        assert r.stdout.strip() == "done"


class TestAptNoLongerFloodsTheScreen:
    def _deps(self, tmp_path, apt_body):
        bindir = tmp_path / "bin"
        bindir.mkdir()
        stubs = {
            "apt-get": apt_body,
            "pip3": "exit 0",
            "mysql": "exit 0",
            "ssh-keygen": "exit 0",
            "curl": "exit 0",
            "openssl": "exit 0",
        }
        for name, body in stubs.items():
            p = bindir / name
            p.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
            p.chmod(p.stat().st_mode | stat.S_IEXEC)
        log = tmp_path / "i.log"
        return log, _run(
            tmp_path,
            textwrap.dedent(f"""
                export PATH="{bindir}:$PATH"
                INSTALL_LOG="{log}"
                IS_UPGRADE=false
                MODE_UNATTENDED=true
                set -e
                # force a package to be 'missing' so apt-get install runs
                command() {{ if [[ "$1" == "-v" && "$2" == "curl" ]]; then return 1; fi; builtin command "$@"; }}
                install_dependencies
                echo FINISHED
            """),
        )

    def test_the_dpkg_noise_goes_to_the_log_not_the_screen(self, tmp_path):
        log, r = self._deps(
            tmp_path,
            'echo "Selecting previously unselected package curl"; echo "Setting up curl"; echo "env=$DEBIAN_FRONTEND/$NEEDRESTART_MODE"',
        )
        assert r.returncode == 0 and "FINISHED" in r.stdout, r.stdout + r.stderr
        assert "Selecting previously unselected" not in r.stdout + r.stderr
        text = log.read_text(encoding="utf-8")
        assert "Selecting previously unselected package curl" in text
        assert "env=noninteractive/l" in text, "debconf and needrestart are told not to prompt or print"
        assert "apt-get install curl" in text and "apt-get update" in text

    def test_a_failing_apt_prints_the_error_it_used_to_discard_and_stops(self, tmp_path):
        log, r = self._deps(tmp_path, 'echo "E: Unable to locate package curl" >&2; exit 100')
        out = r.stdout + r.stderr
        assert r.returncode != 0 and "FINISHED" not in out
        assert "E: Unable to locate package curl" in out, "the last lines of the log are printed"
        assert str(log) in out and "failed" in out


class TestSourceGuards:
    def test_no_apt_or_pip_call_throws_its_output_away(self):
        text = _text(INSTALL)
        for line in text.splitlines():
            code = line.split("#", 1)[0]
            if re.search(r"\bapt-get\b|-m pip install", code):
                assert "2>/dev/null" not in code and ">/dev/null" not in code, line
        assert "apt-get install -y -qq" not in text

    def test_apt_runs_with_the_prompt_and_epilogue_switched_off(self):
        assert "env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get" in _text(INSTALL)

    def test_the_log_is_opened_before_the_answers_file_and_named_in_the_summary(self):
        text = _text(INSTALL)
        main = text[text.index("\nmain() {") :]
        assert main.index("_init_install_log") < main.index("_load_answers_file")
        assert 'INSTALL_LOG="/var/log/jen-install.log"' in text
        assert "Install:  ${INSTALL_LOG}" in text


class TestTheCiProvesTheFailurePath:
    def test_the_install_job_has_a_step_that_expects_a_loud_non_zero_exit(self):
        wf = _text(ROOT / ".github" / "workflows" / "tests.yml")
        step = wf.split("A Jen database that does not answer stops an unattended install", 1)[1].split("- name:", 1)[0]
        assert "answers-unreachable.env" in step and "[[ $rc -ne 0 ]]" in step
        assert "CREATE DATABASE" in step and "Jen does not start without it" in step
        assert "! systemctl" not in step, "a negated command is ignored by errexit and would assert nothing"


def _stubs(tmp_path, bodies):
    """A directory of tiny `sh` stubs, returned as a bash `export PATH=...` line."""
    bindir = tmp_path / "stubs"
    bindir.mkdir(exist_ok=True)
    for name, body in bodies.items():
        p = bindir / name
        p.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return f'export PATH="{bindir}:$PATH"'


class TestInstallingMariaDbHereOnRequest:
    """v5.67.0-beta.18 (Q132, item c) — a local database on request. Opt-in only (the operator's y, or
    JEN_DB_INSTALL_LOCAL=yes with no one to ask), local host only, never silently, and Jen never removes it."""

    @pytest.mark.parametrize(
        "value,expected",
        [("yes", 0), ("YES", 0), ("y", 0), ("true", 0), ("1", 0), ("no", 1), ("", 1), ("maybe", 1)],
    )
    def test_the_opt_in_values(self, tmp_path, value, expected):
        r = _run(
            tmp_path,
            f'ANSWERS[JEN_DB_INSTALL_LOCAL]="{value}"\n_jen_db_install_local_opted_in && echo rc=0 || echo rc=1',
        )
        assert f"rc={expected}" in r.stdout, r.stdout + r.stderr

    def test_the_opt_in_is_also_read_from_the_environment_and_absent_means_no(self, tmp_path):
        r = _run(tmp_path, "JEN_DB_INSTALL_LOCAL=yes\n_jen_db_install_local_opted_in && echo rc=0 || echo rc=1")
        assert "rc=0" in r.stdout
        r = _run(tmp_path, "unset JEN_DB_INSTALL_LOCAL\n_jen_db_install_local_opted_in && echo rc=0 || echo rc=1")
        assert "rc=1" in r.stdout

    @pytest.mark.parametrize(
        "host,local",
        [
            ("localhost", 0),
            ("127.0.0.1", 0),
            ("::1", 0),
            ("db.example.net", 1),
            ("10.0.0.5", 1),
            ("127.0.0.2", 1),
            ("", 1),
        ],
    )
    def test_what_counts_as_local(self, tmp_path, host, local):
        r = _run(tmp_path, f'_is_local_host "{host}" && echo rc=0 || echo rc=1')
        assert f"rc={local}" in r.stdout

    def _offer(self, tmp_path, host, answers="", can_self_create=False, apt_ok=True, mysql_ok=True):
        apt_tail = "exit 0" if apt_ok else 'echo "E: broken" >&2; exit 100'
        mysql_tail = "exit 0" if mysql_ok else "echo 'ERROR 2002' >&2; exit 1"
        path = _stubs(
            tmp_path,
            {
                "apt-get": 'echo "apt-get $*" >> "$STUB_CALLS"; ' + apt_tail,
                "dpkg": "exit 1",  # mariadb-server is not installed
                "systemctl": 'echo "systemctl $*" >> "$STUB_CALLS"; touch "$STUB_STARTED"; exit 0',
                # no server answers until `systemctl enable --now` has run (the stub marks it started)
                "mysql": '[ -f "$STUB_STARTED" ] || exit 1; cat >> "$STUB_SQL"; ' + mysql_tail,
                "sleep": "exit 0",
                "seq": "echo 1",
            },
        )
        calls, sql = tmp_path / "calls", tmp_path / "sql"
        calls.write_text("", encoding="utf-8")
        sql.write_text("", encoding="utf-8")
        log = tmp_path / "i.log"
        override = "_jen_db_can_self_create() { return 0; }" if can_self_create else ""
        if can_self_create:
            (tmp_path / "started").write_text("", encoding="utf-8")  # a server already runs
        r = _run(
            tmp_path,
            textwrap.dedent(f"""
                {path}
                export STUB_CALLS="{calls}" STUB_SQL="{sql}" STUB_STARTED="{tmp_path}/started"
                INSTALL_LOG="{log}"
                MODE_UNATTENDED=true; HAVE_TTY=false
                JEN_DB_HOST="{host}"; JEN_DB_NAME=jen; JEN_DB_USER=jen; JEN_DB_PASS="pa'ss"
                {answers}
                {override}
                _jen_db_offer_create && echo "offer-rc=0" || echo "offer-rc=1"
            """),
        )
        return r, calls.read_text(encoding="utf-8"), sql.read_text(encoding="utf-8"), log

    def test_unattended_without_the_opt_in_never_installs_and_shows_the_sql(self, tmp_path):
        r, calls, sql, _log = self._offer(tmp_path, "localhost")
        assert "offer-rc=1" in r.stdout and "CREATE DATABASE `jen`" in r.stdout
        assert calls == "" and sql == "", "nothing was installed, started or created"

    def test_unattended_with_the_opt_in_installs_starts_and_creates(self, tmp_path):
        r, calls, sql, log = self._offer(tmp_path, "127.0.0.1", answers='ANSWERS[JEN_DB_INSTALL_LOCAL]="yes"')
        assert "offer-rc=0" in r.stdout, r.stdout + r.stderr
        assert "apt-get install -y mariadb-server" in calls
        assert "systemctl enable --now mariadb" in calls
        assert "CREATE DATABASE IF NOT EXISTS `jen`" in sql and "IDENTIFIED BY 'pa''ss'" in sql, "quoted by _sql_quote"
        text = log.read_text(encoding="utf-8")
        assert "apt-get install mariadb-server" in text
        assert "pa''ss" not in text and "IDENTIFIED BY" not in text, "the password never reaches the log"

    def test_a_remote_host_is_never_installed_for_even_with_the_opt_in(self, tmp_path):
        r, calls, sql, _log = self._offer(tmp_path, "db.example.net", answers='ANSWERS[JEN_DB_INSTALL_LOCAL]="yes"')
        assert "offer-rc=1" in r.stdout and "CREATE DATABASE `jen`" in r.stdout
        assert calls == "" and sql == ""

    def test_an_installed_but_stopped_server_is_started_not_reinstalled(self, tmp_path):
        path = _stubs(
            tmp_path,
            {
                "dpkg": "exit 0",  # mariadb-server IS installed
                "apt-get": 'echo "apt-get $*" >> "$STUB_CALLS"; exit 0',
                "systemctl": 'echo "systemctl $*" >> "$STUB_CALLS"; exit 0',
                "mysql": "exit 0",
                "sleep": "exit 0",
                "seq": "echo 1",
            },
        )
        calls = tmp_path / "calls"
        calls.write_text("", encoding="utf-8")
        r = _run(
            tmp_path,
            f'{path}\nexport STUB_CALLS="{calls}"\nINSTALL_LOG="{tmp_path}/i.log"\n_jen_db_install_local && echo rc=0 || echo rc=1',
        )
        text = calls.read_text(encoding="utf-8")
        assert "rc=0" in r.stdout and "already installed" in r.stdout, r.stdout + r.stderr
        assert "apt-get" not in text and "systemctl enable --now mariadb" in text

    def test_a_server_that_already_lets_root_in_is_not_installed_but_the_database_is_created(self, tmp_path):
        r, calls, sql, _log = self._offer(
            tmp_path, "localhost", answers='ANSWERS[JEN_DB_INSTALL_LOCAL]="yes"', can_self_create=True
        )
        assert "offer-rc=0" in r.stdout
        assert "apt-get" not in calls and "CREATE USER IF NOT EXISTS 'jen'@'%'" in sql

    def test_a_failed_apt_falls_back_to_the_sql_with_the_error_shown(self, tmp_path):
        r, calls, sql, _log = self._offer(
            tmp_path, "localhost", answers='ANSWERS[JEN_DB_INSTALL_LOCAL]="yes"', apt_ok=False
        )
        out = r.stdout + r.stderr
        assert "offer-rc=1" in out and "E: broken" in out and "falling back to the SQL" in out
        assert "CREATE DATABASE `jen`" in out and sql == ""

    def test_a_server_that_never_answers_is_reported_after_the_wait(self, tmp_path):
        r, calls, sql, _log = self._offer(
            tmp_path, "localhost", answers='ANSWERS[JEN_DB_INSTALL_LOCAL]="yes"', mysql_ok=False
        )
        out = r.stdout + r.stderr
        assert "offer-rc=1" in out and "did not accept a root-socket connection within 30 seconds" in out

    def test_the_menu_offers_install_only_for_a_local_database(self):
        body = "\n".join(_functions(_text(INSTALL))["_connection_failure_choice"])
        assert 'if [[ "$required" == "required" ]] && _is_local_host "$_h"; then offer_local=true; fi' in body
        assert (
            '[[ "$offer_local" == "true" ]] && echo -e "    ${B}i)${NC}  Install MariaDB on this machine and create '
            'the database now"' in body
        )
        assert 'i) if [[ "$offer_local" == "true" ]]; then _RETRY_ACTION="install"' in body

    def test_the_prompt_defaults_to_no_so_nothing_is_installed_by_pressing_enter(self):
        body = "\n".join(_functions(_text(INSTALL))["_jen_db_offer_create"])
        assert 'prompt_yn "Install MariaDB on this machine and create the database now?" "n"' in body

    def test_the_section_opens_with_the_one_sentence(self):
        body = "\n".join(_functions(_text(INSTALL))["_configure_jen_db"])
        assert (
            "Jen needs its own MariaDB/MySQL database. If this machine has none, the installer can install MariaDB "
            "here and create it." in body
        )

    def test_the_unattended_hint_names_the_opt_in_for_a_local_host(self, tmp_path):
        r = _run(
            tmp_path,
            textwrap.dedent("""
                MODE_UNATTENDED=true; HAVE_TTY=false
                _jen_db_can_self_create() { return 1; }
                _connection_failure_choice "Jen database" "jen@localhost/jen" required
            """),
        )
        assert "JEN_DB_INSTALL_LOCAL=yes" in r.stdout and r.returncode != 0


class TestUninstallLeavesTheDatabaseAlone:
    def test_it_says_so_and_never_touches_mariadb(self):
        text = _text(UNINSTALL)
        assert "no level below removes them" in text and "No level removes MariaDB or Jen's database" in text
        for code in (line.split("#", 1)[0] for line in text.splitlines()):
            assert not re.search(r"apt(-get)?\s+(remove|purge|autoremove)", code), code
            assert not re.search(r"systemctl\s+(stop|disable|mask)\s+(mariadb|mysql)", code), code
            assert not re.search(r"DROP\s+(DATABASE|USER)", code, re.I), code


class TestTheCiLeavesNoDatabaseServerUntilTheInstallerMakesOne:
    def _job(self):
        wf = _text(ROOT / ".github" / "workflows" / "tests.yml")
        job = wf.split("\n  install-local-db:\n", 1)[1]
        return job.split("\n  # v5.67.0-beta.10 (Q122)", 1)[0]

    def test_the_leg_has_no_service_container_and_takes_the_opt_in(self):
        job = self._job()
        assert "services:" not in job, "every other install leg gets a MariaDB container; this one must have none"
        assert "JEN_DB_INSTALL_LOCAL=yes" in job and "JEN_DB_HOST=127.0.0.1" in job
        assert "runs-on: ubuntu-24.04" in job

    def test_it_proves_the_install_the_database_the_log_and_the_uninstall(self):
        job = self._job()
        for needle in (
            "dpkg -s mariadb-server",
            "systemctl is-active --quiet mariadb",
            "information_schema.schemata WHERE schema_name='jen'",
            "/var/log/jen-install.log",
            "600 root:root",
            "Selecting previously unselected package",
            "printf 'y\\n3\\nDELETE\\n' | sudo ./uninstall.sh",
        ):
            assert needle in job, needle

    def test_it_starts_from_a_box_with_no_database_server_or_client(self):
        job = self._job()
        assert "apt-get purge" in job and "ss -ltnH 'sport = :3306'" in job and "command -v mysql" in job
