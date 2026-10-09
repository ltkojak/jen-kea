"""
tests/test_install_endpoint_guard.py
────────────────────────────────────
v5.68.0-beta.29 (Q165, edge 1) - `install.sh --configure` rewrites jen.config from OUTSIDE the running Jen, so none of Jen's own identity guards can see it. The installer's own
guard, `_guard_endpoint_changes`, needs no database and no running Jen: it compares the LIVE file with the merged text (`tools/config_merge.py --identity-diff`) and refuses a
change to which Kea Jen reaches unless the operator said `--change-endpoints`. Run through a real bash, the way tests/test_install_answers.py runs the answers parser (the install CI
job runs the whole script).
"""

import pathlib
import platform
import re
import shlex
import sys

import pytest

from tests.test_layout import _run

pytestmark = pytest.mark.skipif(platform.system() == "Windows", reason="POSIX shell semantics required")

ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")

LIVE = """[kea]
api_url = http://1.1.1.1:8000
connection_mode = ca

[kea_ssh]
host = kea-a.lan
user = jen

[jen_db]
password = old
"""


def _guard(tmp_path, merged: str, *, flag: bool, live_exists: bool = True):
    live = tmp_path / "jen.config"
    if live_exists:
        live.write_text(LIVE, encoding="utf-8")
    text = tmp_path / "merged.ini"
    text.write_text(merged, encoding="utf-8")
    return _run(
        tmp_path,
        f"""
        SCRIPT_DIR={shlex.quote(str(ROOT))}
        PYBIN_FOR_LAYOUT={shlex.quote(sys.executable)}
        MODE_CHANGE_ENDPOINTS={"true" if flag else "false"}
        _guard_endpoint_changes {shlex.quote(str(live))} "$(cat {shlex.quote(str(text))})"
        echo "GUARD-PASSED"
        """,
    )


class TestTheInstallerRefusesAnEndpointChangeWithoutTheFlag:
    def test_nothing_changed_goes_through(self, tmp_path):
        r = _guard(tmp_path, LIVE, flag=False)
        assert r.returncode == 0 and "GUARD-PASSED" in r.stdout and "change which Kea" not in r.stdout

    def test_a_credential_change_is_not_an_endpoint_change(self, tmp_path):
        r = _guard(tmp_path, LIVE.replace("password = old", "password = new"), flag=False)
        assert r.returncode == 0 and "GUARD-PASSED" in r.stdout

    @pytest.mark.parametrize(
        "old,new,line",
        [
            ("host = kea-a.lan", "host = kea-b.lan", "[kea_ssh] host: kea-a.lan -> kea-b.lan"),
            ("connection_mode = ca", "connection_mode = direct", "[kea] connection_mode: ca -> direct"),
            (
                "api_url = http://1.1.1.1:8000",
                "api_url = http://2.2.2.2:8000",
                "[kea] api_url: http://1.1.1.1:8000 -> http://2.2.2.2:8000",
            ),
        ],
    )
    def test_a_changed_endpoint_is_listed_and_refused(self, tmp_path, old, new, line):
        r = _guard(tmp_path, LIVE.replace(old, new), flag=False)
        assert r.returncode != 0 and "GUARD-PASSED" not in r.stdout
        assert line in r.stdout and "--change-endpoints" in r.stdout and "Nothing was written" in r.stdout

    def test_with_the_flag_it_goes_ahead_and_still_lists_what_changes(self, tmp_path):
        r = _guard(tmp_path, LIVE.replace("host = kea-a.lan", "host = kea-b.lan"), flag=True)
        assert r.returncode == 0 and "GUARD-PASSED" in r.stdout
        assert "[kea_ssh] host: kea-a.lan -> kea-b.lan" in r.stdout and "restores itself" in r.stdout

    def test_there_is_nothing_to_compare_on_a_fresh_install(self, tmp_path):
        r = _guard(tmp_path, LIVE, flag=False, live_exists=False)
        assert r.returncode == 0 and "GUARD-PASSED" in r.stdout


class TestTheGuardIsWired:
    def test_write_config_runs_it_after_the_merge_and_before_the_write(self):
        body = INSTALL[INSTALL.index("write_config() {") :]
        merge = body.index("config_merge.py")
        guard = body.index('_guard_endpoint_changes "$CONFIG_FILE" "$final_text"')
        write = body.index('_private_write "$CONFIG_FILE"')
        assert merge < guard < write

    def test_the_flag_defaults_off_and_is_read_only_from_the_command_line(self):
        assert re.search(r"^MODE_CHANGE_ENDPOINTS=false", INSTALL, re.M)
        assert len(re.findall(r"MODE_CHANGE_ENDPOINTS=true", INSTALL)) == 1
        assert "--change-endpoints) MODE_CHANGE_ENDPOINTS=true" in INSTALL
