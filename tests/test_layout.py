"""
tests/test_layout.py
─────────────────────
v5.67.0 (Q114) — install.sh's layout-resolution functions.

v5.67.0-beta.5 (Q117) — a ChatGPT review of 5.67.0-beta.3 found install.sh's
own bash copy of the validation rules had already drifted from
jen-update-root.py's Python copy (the bash side's forbidden-prefix list let
`--config-dir /etc` through, which install_files() then recursively
chown'd/chmod'd). The fix was to delete the bash copy entirely:
_resolve_layout_dirs now just builds `--for install|upgrade [--app-dir ...]`
arguments, calls `jen-update-root.py --check-layout` (the ONE
implementation — see that module's own "── --check-layout" section), and
either adopts its printed `key=value` paths or fatal()s with its refusal
verbatim.

This file tests that bash GLUE only — argument-building, output-parsing,
and refusal pass-through — against a stubbed `_layout_checker` (a copy of
install.sh with the trailing `main "$@"` call stripped, sourced into a
real bash process, the same technique used to debug Q113's install.sh
bugs). The validation RULES themselves (path grammar, shared-root
refusal, nesting, ancestor ownership, the marker/recognize-by-content
contract) are tested against the real implementation, against real temp
dirs, in tests/test_jen_update_root.py — a pytest tmp_path's own ancestors
are never root-owned on ordinary CI, so exercising those rules for real
needs the bypass techniques that file already established for the
Python side (the same approach tests/test_kea_helper.py uses for
jen-kea-helper's own analogous _bin_dir_ok).
"""

import pathlib
import platform
import shlex
import subprocess
import textwrap

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_INSTALL_SH = _ROOT / "install.sh"
_UNINSTALL_SH = _ROOT / "uninstall.sh"

pytestmark = pytest.mark.skipif(platform.system() == "Windows", reason="POSIX shell semantics required")


def _sourceable(tmp_path: pathlib.Path, prelude: str = "") -> pathlib.Path:
    """A copy of install.sh with the trailing `main "$@"` call and signal
    traps stripped, so sourcing it defines every function/variable without
    running the installer.

    install.sh calls `_resolve_layout_dirs` itself at top level (not from
    main()) — the rest of the script needs INSTALL_DIR/CONFIG_DIR/
    CONTENT_DIR to build SERVICE_FILE/CONFIG_FILE/RELEASES_DIR/etc., all
    computed before main() ever runs. That means a `_layout_checker`
    override only takes effect for this auto-call if it's spliced in
    BEFORE that one line, not appended after `source` returns — any given
    test's `prelude` (its _layout_checker stub) is inserted right there.
    """
    text = _INSTALL_SH.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not line.startswith("trap ") and line.strip() != 'main "$@"']
    call_line = lines.index("_resolve_layout_dirs")
    if prelude:
        lines[call_line:call_line] = prelude.splitlines()
    out = tmp_path / "install_lib.sh"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


# A minimal _layout_checker override for tests that don't care what it
# returns — just enough that install.sh's own top-level auto-call to
# _resolve_layout_dirs (see _sourceable's docstring) succeeds quietly
# during `source`, rather than trying to exec a jen-update-root.py that
# was never copied into tmp_path alongside the stripped install.sh.
_NOOP_CHECKER = (
    "_layout_checker() { printf 'app_dir=/opt/jen\\nconfig_dir=/etc/jen\\ndata_dir=/var/lib/jen\\n'; return 0; }\n"
)


def _run(tmp_path: pathlib.Path, script: str, prelude: str = _NOOP_CHECKER) -> subprocess.CompletedProcess:
    lib = _sourceable(tmp_path, prelude=prelude)
    full = textwrap.dedent(f"""
        set -uo pipefail
        source "{lib}" >/dev/null 2>&1
        {script}
    """)
    return subprocess.run(["bash", "-c", full], capture_output=True, text=True)


def _checker_stub(probe: pathlib.Path, stdout: str, rc: int = 0) -> str:
    """A _layout_checker override that (1) records its own argv to `probe`,
    one argument per line, and (2) prints `stdout` and exits `rc` —
    isolating _resolve_layout_dirs's own argument-building and key=value
    parsing from the real Python validator it would otherwise call. Must
    be installed via `_run`'s `prelude` (see `_sourceable`), not appended
    to `script`: install.sh's own top-level `_resolve_layout_dirs` call
    runs during `source`, before any override a test script adds
    afterward could ever take effect.

    The FIRST call the stub ever sees is always that top-level auto-call
    (today's defaults — no test has set OPT_APP_DIR/LAYOUT_FILE yet at
    that point) and is always answered with a harmless canned success, so
    `source` itself never fails; the scenario each test actually means to
    exercise is the SECOND call, made explicitly by `script` after it sets
    up whatever OPT_*/LAYOUT_FILE state the test is about, and that is
    the one whose argv is recorded and whose configured stdout/rc apply.
    A FILE (not a shell variable) tracks which call this is: every call
    goes through `out=$(_layout_checker ...)`, and `$(...)` always forks a
    subshell, so a variable assignment inside the function body is lost
    the instant that subshell exits — only filesystem state survives it."""
    seen_marker = probe.with_name(probe.name + ".seen")
    return (
        "_layout_checker() {\n"
        f"    if [[ ! -e {shlex.quote(str(seen_marker))} ]]; then\n"
        f"        : > {shlex.quote(str(seen_marker))}\n"
        "        printf 'app_dir=/opt/jen\\nconfig_dir=/etc/jen\\ndata_dir=/var/lib/jen\\n'\n"
        "        return 0\n"
        "    fi\n"
        f"    printf '%s\\n' \"$@\" > {shlex.quote(str(probe))}\n"
        f"    printf '%s' {shlex.quote(stdout)}\n"
        f"    return {rc}\n"
        "}\n"
    )


class TestFreshInstallGlue:
    """No $LAYOUT_FILE on disk — _resolve_layout_dirs must call the
    checker with --for install and today's resolved candidate paths
    (defaults, or any --app-dir/--config-dir/--data-dir /
    JEN_*_DIR override), then adopt its printed app_dir/config_dir/
    data_dir verbatim."""

    def test_calls_checker_with_for_install_and_default_candidates(self, tmp_path):
        probe = tmp_path / "argv.txt"
        stdout = "app_dir=/opt/jen\nconfig_dir=/etc/jen\ndata_dir=/var/lib/jen\n"
        r = _run(
            tmp_path,
            """
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
            prelude=_checker_stub(probe, stdout),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "/opt/jen|/etc/jen|/var/lib/jen"
        assert probe.read_text(encoding="utf-8").split() == [
            "--for",
            "install",
            "--app-dir",
            "/opt/jen",
            "--config-dir",
            "/etc/jen",
            "--data-dir",
            "/var/lib/jen",
        ]

    def test_custom_dirs_are_passed_through_to_the_checker(self, tmp_path):
        probe = tmp_path / "argv.txt"
        stdout = "app_dir=/srv/jen/app\nconfig_dir=/srv/jen/etc\ndata_dir=/srv/jen/data\n"
        r = _run(
            tmp_path,
            """
            OPT_APP_DIR="/srv/jen/app"; OPT_CONFIG_DIR="/srv/jen/etc"; OPT_DATA_DIR="/srv/jen/data"
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
            prelude=_checker_stub(probe, stdout),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "/srv/jen/app|/srv/jen/etc|/srv/jen/data"
        assert probe.read_text(encoding="utf-8").split() == [
            "--for",
            "install",
            "--app-dir",
            "/srv/jen/app",
            "--config-dir",
            "/srv/jen/etc",
            "--data-dir",
            "/srv/jen/data",
        ]

    def test_only_app_dir_set_others_stay_default(self, tmp_path):
        probe = tmp_path / "argv.txt"
        stdout = "app_dir=/srv/jen\nconfig_dir=/etc/jen\ndata_dir=/var/lib/jen\n"
        r = _run(
            tmp_path,
            """
            OPT_APP_DIR="/srv/jen"
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
            prelude=_checker_stub(probe, stdout),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "/srv/jen|/etc/jen|/var/lib/jen"
        assert probe.read_text(encoding="utf-8").split() == [
            "--for",
            "install",
            "--app-dir",
            "/srv/jen",
            "--config-dir",
            "/etc/jen",
            "--data-dir",
            "/var/lib/jen",
        ]

    def test_checker_refusal_is_fatal_verbatim(self, tmp_path):
        probe = tmp_path / "argv.txt"
        msg = "config_dir must be a dedicated directory, not a shared system path: /etc"
        r = _run(tmp_path, "_resolve_layout_dirs", prelude=_checker_stub(probe, msg, rc=1))
        assert r.returncode != 0
        assert "must be a dedicated directory" in r.stdout

    def test_existing_app_dir_with_no_layout_file_is_treated_as_an_upgrade(self, tmp_path):
        # A pre-Q114 box: no $LAYOUT_FILE yet, but a real, already-
        # populated app_dir. check_layout's own "install" mode requires
        # absent/empty/marked (a fresh-install-only rule) — sending that
        # mode here would refuse this box's very first run under Q117.
        # _resolve_layout_dirs must detect the existing directory and
        # call the checker with --for upgrade instead.
        app_dir = tmp_path / "opt-jen"
        app_dir.mkdir()
        (app_dir / "run.py").write_text("# a real pre-Q114 install\n")
        probe = tmp_path / "argv.txt"
        stdout = f"app_dir={app_dir}\nconfig_dir=/etc/jen\ndata_dir=/var/lib/jen\n"
        r = _run(
            tmp_path,
            f"""
            OPT_APP_DIR="{app_dir}"
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
            prelude=_checker_stub(probe, stdout),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == f"{app_dir}|/etc/jen|/var/lib/jen"
        assert probe.read_text(encoding="utf-8").split() == ["--for", "upgrade", "--app-dir", str(app_dir)]

    def test_nonexistent_app_dir_with_no_layout_file_stays_install_mode(self, tmp_path):
        app_dir = tmp_path / "does-not-exist-yet"
        probe = tmp_path / "argv.txt"
        stdout = f"app_dir={app_dir}\nconfig_dir=/etc/jen\ndata_dir=/var/lib/jen\n"
        r = _run(
            tmp_path,
            f"""
            OPT_APP_DIR="{app_dir}"
            _resolve_layout_dirs
            """,
            prelude=_checker_stub(probe, stdout),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert probe.read_text(encoding="utf-8").split()[:2] == ["--for", "install"]


class TestUpgradeGlue:
    """An existing $LAYOUT_FILE — _resolve_layout_dirs must call the
    checker with --for upgrade, forwarding only the flags actually given
    (an upgrade with no flags passes none at all; the checker itself reads
    the existing file), and the disagreement refusal (now entirely the
    checker's own job) passes through unchanged."""

    def _write_layout(self, tmp_path):
        layout = tmp_path / "jen-layout.conf"
        layout.write_text(
            "[layout]\napp_dir = /srv/jen/app\nconfig_dir = /srv/jen/etc\ndata_dir = /srv/jen/data\n", encoding="utf-8"
        )
        return layout

    def test_existing_layout_calls_checker_with_for_upgrade_and_no_flags_by_default(self, tmp_path):
        layout = self._write_layout(tmp_path)
        probe = tmp_path / "argv.txt"
        stdout = "app_dir=/srv/jen/app\nconfig_dir=/srv/jen/etc\ndata_dir=/srv/jen/data\n"
        r = _run(
            tmp_path,
            f"""
            LAYOUT_FILE="{layout}"
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
            prelude=_checker_stub(probe, stdout),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "/srv/jen/app|/srv/jen/etc|/srv/jen/data"
        assert probe.read_text(encoding="utf-8").split() == ["--for", "upgrade"]

    def test_explicit_flags_are_forwarded_to_the_checker_on_upgrade(self, tmp_path):
        layout = self._write_layout(tmp_path)
        probe = tmp_path / "argv.txt"
        stdout = "app_dir=/srv/jen/app\nconfig_dir=/srv/jen/etc\ndata_dir=/srv/jen/data\n"
        r = _run(
            tmp_path,
            f"""
            LAYOUT_FILE="{layout}"
            OPT_APP_DIR="/srv/jen/app"
            _resolve_layout_dirs
            """,
            prelude=_checker_stub(probe, stdout),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert probe.read_text(encoding="utf-8").split() == ["--for", "upgrade", "--app-dir", "/srv/jen/app"]

    def test_disagreeing_flag_refusal_is_fatal_verbatim(self, tmp_path):
        # The disagreement check itself now lives entirely in
        # check_layout() (Python, see tests/test_jen_update_root.py) —
        # this only proves the bash side passes the refusal through
        # unchanged rather than re-deriving or swallowing it.
        layout = self._write_layout(tmp_path)
        probe = tmp_path / "argv.txt"
        msg = "This install's app_dir is already /srv/jen/app — relocating an existing install is a runbook (docs/runbooks.md), not a flag."
        r = _run(
            tmp_path,
            f"""
            LAYOUT_FILE="{layout}"
            OPT_APP_DIR="/somewhere/else"
            _resolve_layout_dirs
            """,
            prelude=_checker_stub(probe, msg, rc=1),
        )
        assert r.returncode != 0
        assert "runbook" in r.stdout


class TestLayoutKv:
    def test_parses_a_value_from_multiple_lines(self, tmp_path):
        r = _run(tmp_path, "_layout_kv \"$(printf 'app_dir=/opt/jen\\nconfig_dir=/etc/jen\\n')\" config_dir")
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "/etc/jen"


class TestNoDuplicateValidationLogic:
    """v5.67.0-beta.5 (Q117) — the whole point of ONE implementation is
    that there's exactly one; a second bash copy (even a partial one)
    could silently drift again, the way the old forbidden-prefix list
    already had by the time ChatGPT reviewed 5.67.0-beta.3."""

    def test_install_sh_has_no_forbidden_prefix_list(self):
        text = _INSTALL_SH.read_text(encoding="utf-8")
        assert "_LAYOUT_FORBIDDEN_PREFIXES" not in text

    def test_install_sh_has_no_stat_based_layout_ownership_check(self):
        text = _INSTALL_SH.read_text(encoding="utf-8")
        assert "_layout_parents_root_owned" not in text
        assert "_layout_app_dir_not_preplanted" not in text
        assert "_validate_layout_file_or_fatal" not in text

    def test_uninstall_sh_has_no_own_layout_trust_logic(self):
        text = _UNINSTALL_SH.read_text(encoding="utf-8")
        assert "_layout_get" not in text
