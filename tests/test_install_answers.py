"""
tests/test_install_answers.py
──────────────────────────────
v5.67.0-beta.9 (Q121, item h) — install.sh's answers-file parser, SQL quoting
and required-value rule, run through a real bash (the same sourced-copy
technique tests/test_layout.py uses; the install CI job is what runs the whole
script).
"""

import pathlib
import platform
import textwrap

import pytest

from tests.test_layout import _run

pytestmark = pytest.mark.skipif(platform.system() == "Windows", reason="POSIX shell semantics required")


def _parse(tmp_path: pathlib.Path, text: str, keys: list[str]) -> dict:
    f = tmp_path / "answers.env"
    f.write_text(text, encoding="utf-8", newline="")
    f.chmod(0o600)
    probe = "\n".join(f"printf '%s=[%s]\\n' {k} \"${{ANSWERS[{k}]-UNSET}}\"" for k in keys)
    r = _run(tmp_path, f'_load_answers_file "{f}"\n{probe}')
    assert r.returncode == 0, r.stdout + r.stderr
    out = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition("=")
        out[k] = v[1:-1]
    return out


class TestAnswersParser:
    def test_plain_key_value(self, tmp_path):
        assert _parse(tmp_path, "JEN_DB_HOST=127.0.0.1\n", ["JEN_DB_HOST"]) == {"JEN_DB_HOST": "127.0.0.1"}

    def test_spaces_around_the_equals_do_not_become_part_of_the_value(self, tmp_path):
        got = _parse(tmp_path, "JEN_DB_PASS = secret\nJEN_DB_USER   =   jen   \n", ["JEN_DB_PASS", "JEN_DB_USER"])
        assert got == {"JEN_DB_PASS": "secret", "JEN_DB_USER": "jen"}

    @pytest.mark.parametrize("quote", ['"', "'"])
    def test_one_matching_pair_of_quotes_is_stripped(self, tmp_path, quote):
        got = _parse(tmp_path, f"JEN_DB_PASS={quote}p a ss{quote}\n", ["JEN_DB_PASS"])
        assert got == {"JEN_DB_PASS": "p a ss"}

    def test_quotes_inside_a_value_and_a_lone_quote_are_kept(self, tmp_path):
        got = _parse(
            tmp_path,
            'A=it\'s\nB="a"b"\nC="\nD=\'x\n',
            ["A", "B", "C", "D"],
        )
        assert got == {"A": "it's", "B": 'a"b', "C": '"', "D": "'x"}

    def test_trailing_whitespace_inside_quotes_is_preserved(self, tmp_path):
        assert _parse(tmp_path, 'JEN_DB_PASS="pass "\n', ["JEN_DB_PASS"]) == {"JEN_DB_PASS": "pass "}

    def test_export_lines_are_accepted(self, tmp_path):
        got = _parse(
            tmp_path, "export JEN_DB_USER=jen\nexport   JEN_DB_NAME = 'jen_db'\n", ["JEN_DB_USER", "JEN_DB_NAME"]
        )
        assert got == {"JEN_DB_USER": "jen", "JEN_DB_NAME": "jen_db"}

    def test_indented_lines_comments_blanks_and_crlf(self, tmp_path):
        text = "# a comment\r\n\r\n   JEN_DB_HOST=db\r\n  # indented comment\r\nJEN_HTTP_PORT=5050\r\n"
        assert _parse(tmp_path, text, ["JEN_DB_HOST", "JEN_HTTP_PORT"]) == {
            "JEN_DB_HOST": "db",
            "JEN_HTTP_PORT": "5050",
        }

    def test_an_empty_value_is_set_not_absent(self, tmp_path):
        """JEN_DB_PASS= means "an empty password, on purpose" — distinct from not giving one."""
        assert _parse(tmp_path, 'JEN_DB_PASS=\nJEN_X=""\n', ["JEN_DB_PASS", "JEN_X", "JEN_Y"]) == {
            "JEN_DB_PASS": "",
            "JEN_X": "",
            "JEN_Y": "UNSET",
        }

    def test_nothing_in_a_value_is_ever_executed(self, tmp_path):
        marker = tmp_path / "pwned"
        text = f"JEN_DB_PASS=$(touch {marker})\nJEN_DB_USER=`touch {marker}`\nJEN_X=a;touch {marker}\n"
        got = _parse(tmp_path, text, ["JEN_DB_PASS", "JEN_DB_USER", "JEN_X"])
        assert not marker.exists()
        assert got["JEN_DB_PASS"] == f"$(touch {marker})"

    def test_a_value_may_contain_an_equals_sign(self, tmp_path):
        assert _parse(tmp_path, "JEN_DB_PASS=a=b=c\n", ["JEN_DB_PASS"]) == {"JEN_DB_PASS": "a=b=c"}


class TestSqlQuote:
    def _q(self, tmp_path, value):
        script = textwrap.dedent(f"""
            _sql_quote {__import__("shlex").quote(value)}
        """)
        r = _run(tmp_path, script)
        assert r.returncode == 0, r.stdout + r.stderr
        return r.stdout

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("plain", "'plain'"),
            ("it's", "'it''s'"),
            ("a\\b", "'a\\\\b'"),
            ("'; DROP DATABASE jen; --", "'''; DROP DATABASE jen; --'"),
            ("", "''"),
        ],
    )
    def test_quoting(self, tmp_path, value, expected):
        assert self._q(tmp_path, value) == expected


class TestRequiredValue:
    def test_a_missing_required_secret_is_fatal_and_names_the_variable(self, tmp_path):
        r = _run(
            tmp_path, 'HAVE_TTY=false; MODE_UNATTENDED=true; _ask_secret JEN_Q121_NO_SUCH_SECRET "Password" required'
        )
        assert r.returncode != 0
        assert "JEN_Q121_NO_SUCH_SECRET" in r.stdout

    def test_an_explicitly_empty_value_satisfies_it(self, tmp_path):
        r = _run(
            tmp_path,
            'HAVE_TTY=false; ANSWERS[JEN_DB_PASS]=""; v=$(_ask_secret JEN_DB_PASS "Password" required); echo "[$v]"',
        )
        assert r.returncode == 0 and r.stdout.strip() == "[]"

    def test_the_jen_database_password_is_the_one_asked_as_required(self):
        text = (pathlib.Path(__file__).resolve().parent.parent / "install.sh").read_text(encoding="utf-8")
        assert '_ask_secret "JEN_DB_PASS" "Password" required' in text

    def test_optional_secrets_stay_optional(self, tmp_path):
        r = _run(tmp_path, 'HAVE_TTY=false; v=$(_ask_secret JEN_OTHER "Password"); echo "[$v]"')
        assert r.returncode == 0 and r.stdout.strip() == "[]"


class TestPreUpgradeBackup:
    """v5.67.0-beta.9 (Q121, item g) — the summary says what was and was not written. `runuser` is stubbed with a
    shell function that prints what the python snippet would, so this tests the reporting and the return code;
    the snippet itself is the app's own primitives, exercised for real by the install CI job's upgrade leg."""

    def _run_backup(self, tmp_path, stub_output: str, stub_rc: int = 0):
        stub = f"runuser() {{ printf '%s\n' {__import__('shlex').quote(stub_output)}; return {stub_rc}; }}"
        return _run(
            tmp_path,
            f"""
            set +e
            {stub}
            MODE_UNATTENDED=true
            _preupgrade_backup; echo "RC=$?"
            """,
        )

    def test_a_written_backup_is_reported_with_its_path_and_what_it_leaves_out(self, tmp_path):
        r = self._run_backup(tmp_path, "JEN_BACKUP_OK /var/lib/jen/backups/jen-pre-upgrade-1-2.json.gz")
        assert "RC=0" in r.stdout
        assert "/var/lib/jen/backups/jen-pre-upgrade-1-2.json.gz" in r.stdout
        assert "Kea's own database" in r.stdout and "Not included" in r.stdout

    def test_a_failed_backup_says_nothing_was_written_and_returns_nonzero(self, tmp_path):
        r = self._run_backup(tmp_path, 'JEN_BACKUP_FAILED OperationalError: (2003, "Can\'t connect")', stub_rc=1)
        assert "RC=1" in r.stdout
        assert "NO backup was written" in r.stdout and "OperationalError" in r.stdout
        assert "saved" not in r.stdout.lower().replace("not saved", "")

    def test_an_install_without_the_primitive_says_so(self, tmp_path):
        r = self._run_backup(
            tmp_path, "JEN_BACKUP_UNAVAILABLE ImportError: cannot import name 'publish_backup'", stub_rc=3
        )
        assert "RC=1" in r.stdout
        assert "predates the backup tool" in r.stdout and "publish_backup" in r.stdout

    def test_no_result_at_all_is_a_failure_not_a_success(self, tmp_path):
        r = self._run_backup(tmp_path, "Traceback (most recent call last): boom", stub_rc=1)
        assert "RC=1" in r.stdout and "NO backup was written" in r.stdout
        assert "boom" in r.stdout

    def test_the_old_implementation_is_gone(self):
        raw = (pathlib.Path(__file__).resolve().parent.parent / "install.sh").read_text(encoding="utf-8")
        # code only, not the comments that explain the change
        text = chr(10).join(ln for ln in raw.splitlines() if not ln.lstrip().startswith("#"))
        for gone in ("/tmp/jen_backup_err", "fetchall()", "Pre-upgrade backups saved", "configparser.ConfigParser()"):
            assert gone not in text, gone
        for there in ("publish_backup", "write_jen_export", "_write_meta_sidecar", 'runuser -u "$JEN_USER"'):
            assert there in text, there
