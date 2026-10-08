"""
tests/test_layout.py
─────────────────────
v5.67.0 (Q114) — install.sh's layout-resolution functions.

v5.67.0-beta.5 (Q117) — a ChatGPT review of 5.67.0-beta.3 found install.sh's
own bash copy of the validation rules had already drifted from
jen-update-root.py's Python copy (the bash side's forbidden-prefix list let
`--config-dir /etc` through, which install_files() then recursively
chown'd/chmod'd). The fix was to delete the bash copy entirely:
_resolve_layout_dirs now just builds `--for auto [--app-dir ...]` (v5.67.0-beta.9, Q121; it was install|upgrade)
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
import re
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

    v5.67.0-beta.9 (Q121) — install.sh no longer calls `_resolve_layout_dirs`
    at top level (main() does, after the flags, the answers file and root), so
    sourcing defines everything and runs nothing. A test's `prelude` (its
    `_layout_checker` stub) is appended AFTER the definitions it replaces.
    """
    text = _INSTALL_SH.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not line.startswith("trap ") and line.strip() != 'main "$@"']
    out = tmp_path / "install_lib.sh"
    out.write_text("\n".join(lines) + "\n" + prelude + "\n", encoding="utf-8")
    return out


def _run(tmp_path: pathlib.Path, script: str, prelude: str = "") -> subprocess.CompletedProcess:
    lib = _sourceable(tmp_path, prelude=prelude)
    full = textwrap.dedent(f"""
        set -uo pipefail
        source "{lib}" >/dev/null 2>&1
        {script}
    """)
    return subprocess.run(["bash", "-c", full], capture_output=True, text=True)


def _checker_stub(probe: pathlib.Path, stdout: str, rc: int = 0) -> str:
    """A `_layout_checker` override that (1) records its own argv to `probe`,
    one argument per line, and (2) prints `stdout` and exits `rc` — isolating
    _resolve_layout_dirs's own argument-building and key=value parsing from
    the real Python validator it would otherwise call."""
    return (
        "_layout_checker() {\n"
        f"    printf '%s\\n' \"$@\" > {shlex.quote(str(probe))}\n"
        f"    printf '%s' {shlex.quote(stdout)}\n"
        f"    return {rc}\n"
        "}\n"
    )


_INSTALL_OUT = "mode=install\napp_dir=/opt/jen\nconfig_dir=/etc/jen\ndata_dir=/var/lib/jen\n"


class TestResolveGlue:
    """_resolve_layout_dirs hands the checker `--for auto` plus only the
    directories actually asked for (--app-dir/--config-dir/--data-dir, or
    JEN_APP_DIR/JEN_CONFIG_DIR/JEN_DATA_DIR from the answers file or the
    environment), then adopts what the checker prints — the three paths AND
    the install-versus-upgrade decision (v5.67.0-beta.9, Q121, item b: that
    decision is the checker's, by marker-or-content, never `[[ -d ]]`)."""

    def test_no_flags_means_no_directory_arguments(self, tmp_path):
        probe = tmp_path / "argv.txt"
        r = _run(
            tmp_path,
            """
            _resolve_layout_dirs
            echo "$LAYOUT_MODE|$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
            prelude=_checker_stub(probe, _INSTALL_OUT),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "install|/opt/jen|/etc/jen|/var/lib/jen"
        assert probe.read_text(encoding="utf-8").split() == ["--for", "auto"]

    def test_flags_are_forwarded(self, tmp_path):
        probe = tmp_path / "argv.txt"
        out = "mode=install\napp_dir=/srv/jen/app\nconfig_dir=/srv/jen/etc\ndata_dir=/srv/jen/data\n"
        r = _run(
            tmp_path,
            """
            OPT_APP_DIR="/srv/jen/app"; OPT_CONFIG_DIR="/srv/jen/etc"; OPT_DATA_DIR="/srv/jen/data"
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
            prelude=_checker_stub(probe, out),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "/srv/jen/app|/srv/jen/etc|/srv/jen/data"
        assert probe.read_text(encoding="utf-8").split() == [
            "--for",
            "auto",
            "--app-dir",
            "/srv/jen/app",
            "--config-dir",
            "/srv/jen/etc",
            "--data-dir",
            "/srv/jen/data",
        ]

    def test_only_the_directories_asked_for_are_forwarded(self, tmp_path):
        probe = tmp_path / "argv.txt"
        out = "mode=install\napp_dir=/srv/jen\nconfig_dir=/etc/jen\ndata_dir=/var/lib/jen\n"
        r = _run(
            tmp_path,
            """
            OPT_APP_DIR="/srv/jen"
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
            prelude=_checker_stub(probe, out),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "/srv/jen|/etc/jen|/var/lib/jen"
        assert probe.read_text(encoding="utf-8").split() == ["--for", "auto", "--app-dir", "/srv/jen"]

    def test_layout_keys_from_the_answers_file_count(self, tmp_path):
        """Item a — JEN_APP_DIR in --answers used to be ignored: the layout was resolved at top level, before
        the answers file was read, so the install went to the defaults and recorded them."""
        probe = tmp_path / "argv.txt"
        out = "mode=install\napp_dir=/srv/jen/app\nconfig_dir=/srv/jen/etc\ndata_dir=/srv/jen/data\n"
        r = _run(
            tmp_path,
            """
            ANSWERS[JEN_APP_DIR]=/srv/jen/app
            ANSWERS[JEN_CONFIG_DIR]=/srv/jen/etc
            ANSWERS[JEN_DATA_DIR]=/srv/jen/data
            _resolve_layout_dirs
            echo "$INSTALL_DIR"
            """,
            prelude=_checker_stub(probe, out),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "/srv/jen/app"
        assert probe.read_text(encoding="utf-8").split() == [
            "--for",
            "auto",
            "--app-dir",
            "/srv/jen/app",
            "--config-dir",
            "/srv/jen/etc",
            "--data-dir",
            "/srv/jen/data",
        ]

    def test_layout_keys_from_the_environment_count_and_a_flag_beats_them(self, tmp_path):
        probe = tmp_path / "argv.txt"
        r = _run(
            tmp_path,
            """
            JEN_APP_DIR=/from/env
            OPT_APP_DIR=/from/flag
            _resolve_layout_dirs
            """,
            prelude=_checker_stub(
                probe, "mode=install\napp_dir=/from/flag\nconfig_dir=/etc/jen\ndata_dir=/var/lib/jen\n"
            ),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert probe.read_text(encoding="utf-8").split() == ["--for", "auto", "--app-dir", "/from/flag"]

    def test_the_mode_is_the_checkers_answer_not_whether_the_directory_exists(self, tmp_path):
        """Item b — a pre-created EMPTY app dir is an install (the checker says so); the old
        `[[ -d "$INSTALL_DIR" ]]` called it an upgrade and refused to "relocate" it."""
        app_dir = tmp_path / "pre-created-empty"
        app_dir.mkdir()
        probe = tmp_path / "argv.txt"
        out = f"mode=install\napp_dir={app_dir}\nconfig_dir=/etc/jen\ndata_dir=/var/lib/jen\n"
        r = _run(
            tmp_path,
            f"""
            OPT_APP_DIR="{app_dir}"
            _resolve_layout_dirs
            echo "$LAYOUT_MODE"
            """,
            prelude=_checker_stub(probe, out),
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "install"

    def test_an_upgrade_answer_is_adopted(self, tmp_path):
        probe = tmp_path / "argv.txt"
        out = "mode=upgrade\napp_dir=/srv/jen/app\nconfig_dir=/srv/jen/etc\ndata_dir=/srv/jen/data\n"
        r = _run(tmp_path, '_resolve_layout_dirs; echo "$LAYOUT_MODE"', prelude=_checker_stub(probe, out))
        assert r.stdout.strip() == "upgrade"

    def test_checker_refusal_is_fatal_verbatim(self, tmp_path):
        probe = tmp_path / "argv.txt"
        msg = "config_dir must be a dedicated directory, not a shared system path: /etc"
        r = _run(tmp_path, "_resolve_layout_dirs", prelude=_checker_stub(probe, msg, rc=1))
        assert r.returncode != 0
        assert "must be a dedicated directory" in r.stdout

    def test_disagreeing_flag_refusal_is_fatal_verbatim(self, tmp_path):
        # The disagreement check itself lives entirely in check_layout()
        # (Python, tests/test_jen_update_root.py) — this only proves the bash
        # side passes the refusal through unchanged.
        probe = tmp_path / "argv.txt"
        msg = "This install's app_dir is already /srv/jen/app — relocating an existing install is a runbook (docs/runbooks.md), not a flag."
        r = _run(
            tmp_path,
            """
            OPT_APP_DIR="/somewhere/else"
            _resolve_layout_dirs
            """,
            prelude=_checker_stub(probe, msg, rc=1),
        )
        assert r.returncode != 0
        assert "runbook" in r.stdout

    def test_an_incomplete_answer_is_fatal_not_a_half_resolved_layout(self, tmp_path):
        probe = tmp_path / "argv.txt"
        r = _run(tmp_path, "_resolve_layout_dirs", prelude=_checker_stub(probe, "mode=install\napp_dir=/opt/jen\n"))
        assert r.returncode != 0
        assert "did not return all three" in r.stdout


class TestPathsFollowTheLayout:
    def test_the_defaults_are_defined_before_anything_resolves(self, tmp_path):
        """--docker never resolves a layout, so every derived variable must already exist."""
        r = _run(tmp_path, 'echo "$INSTALL_DIR|$CONFIG_FILE|$RELEASES_DIR|$APP_DIR|$ROOT_ROLLBACK_DIR"')
        out = r.stdout.strip()
        assert out.startswith("/opt/jen|/etc/jen/jen.config|/opt/jen/releases|/opt/jen/releases/")
        assert out.endswith("/app|/opt/jen/.rollback")

    def test_set_paths_rederives_everything_from_the_resolved_dirs(self, tmp_path):
        r = _run(
            tmp_path,
            """
            INSTALL_DIR=/srv/jen/app; CONFIG_DIR=/srv/jen/etc; CONTENT_DIR=/srv/jen/data
            _set_paths
            echo "$CONFIG_FILE|$CONFIG_BACKUP_DIR|$RELEASES_DIR|$CURRENT_LINK|$ROOT_ROLLBACK_DIR"
            """,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == (
            "/srv/jen/etc/jen.config|/srv/jen/app/.rollback/config|/srv/jen/app/releases|/srv/jen/app/current|/srv/jen/app/.rollback"
        )

    def test_set_paths_returns_zero_even_when_no_venv_exists(self, tmp_path):
        """Its last statement is a bare `[[ -x ... ]] && ...`; false would otherwise be the status, and
        install.sh runs under set -e."""
        r = _run(tmp_path, "set -e; INSTALL_DIR=/nonexistent/jen; _set_paths; echo survived")
        assert r.stdout.strip() == "survived"


class TestMainOrdersTheSteps:
    """v5.67.0-beta.9 (Q121, items a/h) — the layout is resolved in main(), in a fixed order: root, umask,
    the answers file, then the layout (not for --docker). Read from the source, since main() itself cannot
    be run without a root, a systemd and a real install."""

    def _main(self) -> str:
        text = _INSTALL_SH.read_text(encoding="utf-8")
        start = text.index("\nmain() {")
        return text[start : text.index("\n}\n", start)]

    def test_nothing_resolves_a_layout_at_top_level_any_more(self):
        text = _INSTALL_SH.read_text(encoding="utf-8")
        top_level_calls = [ln for ln in text.splitlines() if ln.strip() == "_resolve_layout_dirs"]
        assert len(top_level_calls) == 1, "only main()'s own (indented) call remains"
        assert top_level_calls[0].startswith("        "), "and it is indented inside main(), not a top-level statement"

    def test_order_root_umask_answers_layout(self):
        body = self._main()
        order = [body.index(s) for s in ("require_root", "umask 022", "_load_answers_file", "_resolve_layout_dirs")]
        assert order == sorted(order), order

    def test_docker_skips_the_layout(self):
        body = self._main()
        guard = body.index('if [[ "$MODE_DOCKER" != "true" ]]; then')
        assert guard < body.index("_resolve_layout_dirs") < body.index("_set_paths")

    def test_the_answers_file_is_loaded_once_and_only_in_main(self):
        text = _INSTALL_SH.read_text(encoding="utf-8")
        assert text.count('_load_answers_file "$ANSWERS_FILE"') == 1


class TestLayoutKv:
    def test_parses_a_value_from_multiple_lines(self, tmp_path):
        r = _run(tmp_path, "_layout_kv \"$(printf 'app_dir=/opt/jen\\nconfig_dir=/etc/jen\\n')\" config_dir")
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "/etc/jen"


class TestUninstallPicksTheRightChecker:
    """v5.67.0-beta.9 (Q121, item d). uninstall.sh needs root, so its behaviour is proved by the install CI job
    (a 5.66-style updater stub installed, the uninstall run from the tarball); this is the source half: the copy
    beside the script comes first, the installed copy only if it answers `--check-layout --help`, and level 3
    removes the updater and both oneshot units."""

    # the level-3 block's first two lines, joined with a real newline
    _LEVEL3 = 'if [[ "$REMOVAL_LEVEL" == "3" ]]; then' + chr(10) + "    rm -rf"

    def _text(self) -> str:
        return _UNINSTALL_SH.read_text(encoding="utf-8")

    def test_the_copy_beside_the_script_is_preferred(self):
        text = self._text()
        beside = text.index('if [[ -f "$SCRIPT_DIR/jen-update-root.py" ]]')
        installed = text.index('elif [[ -f "$INSTALLED_UPDATER" ]]')
        assert beside < installed < text.index("--check-layout --for uninstall 2>&1")

    def test_the_installed_copy_must_answer_help(self):
        text = self._text()
        assert '"$INSTALLED_UPDATER" --check-layout --help' in text

    def test_a_stale_installed_copy_with_nothing_beside_is_a_clear_refusal(self):
        text = self._text()
        assert "predates --check-layout" in text and "run uninstall.sh from the extracted release tarball" in text

    def test_level_3_removes_the_updater_and_both_units(self):
        text = self._text()
        level3 = text[text.index(self._LEVEL3) :]
        for needle in ("jen-update.service", "jen-plugin-install.service", '"$INSTALLED_UPDATER"'):
            assert needle in level3, needle
        assert "daemon-reload" in level3

    def test_levels_1_and_2_do_not_touch_the_updater(self):
        text = self._text()
        before_level3 = text[: text.index(self._LEVEL3)]
        assert 'rm -f "$INSTALLED_UPDATER"' not in before_level3


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


class TestNoHardcodedLayoutLiteralsOutsideAllowedSpots:
    """v5.67.0-beta.5 (Q117, item d) — a relocated install must never see
    a literal /opt/jen, /etc/jen or /var/lib/jen leak into its own
    generated artifacts or operator-facing messages: ChatGPT's review
    found install.sh's [kea_ssh] key_path and its SSL-summary check, plus
    three jen-update-root.py log lines, hardcoding one of these
    regardless of where the install actually lives (the app's own
    relocation-aware fallback — jen/extensions.py's CONFIG_DIR/
    SSH_KEY_PATH — got silently overridden by the literal). The install
    CI job's relocated leg (.github/workflows/tests.yml) is the
    behavioral half of this regression: it greps the actually-generated
    jen.config, the rendered unit and the install run's own printed
    summary for these three strings. This is the source half: every line
    in install.sh/uninstall.sh containing one is either a comment, one of
    the three default-assignment lines (`VAR="${x:-/opt/jen}"` or a bare
    `VAR="/opt/jen"`), inside install.sh's own --help text, or a
    reference to /etc/jen-layout.conf (a fixed sibling path that is never
    itself relocatable, regardless of where app_dir/config_dir/data_dir
    move to)."""

    # (?<![\w/]) — a real standalone reference, not a substring inside a
    # larger path (the behavioral CI check needs the same guard: the
    # relocated leg's own --config-dir /srv/jen/etc makes the generated
    # config's own path /srv/jen/etc/jen.config, which otherwise
    # self-matches "/etc/jen" in its middle).
    _LITERAL_RE = re.compile(r"(?<![\w/])/etc/jen(?!-layout\.conf)|(?<![\w/])/opt/jen|(?<![\w/])/var/lib/jen")
    _ASSIGNMENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*="')

    def _violations(self, path: pathlib.Path) -> list:
        violations = []
        in_help = False
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped == "cat << 'HELPEOF'":
                in_help = True
                continue
            if stripped == "HELPEOF":
                in_help = False
                continue
            if in_help or stripped.startswith("#"):
                continue
            if not self._LITERAL_RE.search(line):
                continue
            if self._ASSIGNMENT_RE.match(stripped):
                continue
            violations.append((lineno, line))
        return violations

    def test_install_sh_has_no_stray_literal(self):
        violations = self._violations(_INSTALL_SH)
        assert violations == [], violations

    def test_uninstall_sh_has_no_stray_literal(self):
        violations = self._violations(_UNINSTALL_SH)
        assert violations == [], violations
