"""
tests/test_layout.py
─────────────────────
v5.67.0 (Q114) — install.sh's layout-resolution functions
(_resolve_layout_dirs and friends), exercised for real rather than by
source-text scanning: a stripped copy of install.sh (the trailing
`main "$@"` invocation and signal traps removed, the same technique used
to debug Q113's install.sh bugs) is sourced into a real bash process and
the functions are called directly, the way jen-update-root.py's own
updater-harness tests already run its real functions against real temp
dirs rather than a hand-retyped mock.

_layout_parents_root_owned's ownership walk needs to run as real root
against a real POSIX filesystem to mean anything — skipped here and
exercised for real by the `install` CI job (tests.yml), which does run
install.sh as root on a real Ubuntu runner.
"""

import os
import pathlib
import platform
import subprocess
import textwrap

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_INSTALL_SH = _ROOT / "install.sh"

pytestmark = pytest.mark.skipif(platform.system() == "Windows", reason="POSIX filesystem semantics required")


def _sourceable(tmp_path: pathlib.Path) -> pathlib.Path:
    """A copy of install.sh with the trailing `main "$@"` call and signal
    traps stripped, so sourcing it defines every function/variable without
    running the installer."""
    text = _INSTALL_SH.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not line.startswith("trap ") and line.strip() != 'main "$@"']
    out = tmp_path / "install_lib.sh"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def _run(tmp_path: pathlib.Path, script: str) -> subprocess.CompletedProcess:
    lib = _sourceable(tmp_path)
    full = textwrap.dedent(f"""
        set -uo pipefail
        source "{lib}" >/dev/null 2>&1
        {script}
    """)
    return subprocess.run(["bash", "-c", full], capture_output=True, text=True)


class TestDefaultResolution:
    def test_no_flags_no_layout_file_is_todays_defaults(self, tmp_path):
        r = _run(
            tmp_path,
            'echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"',
        )
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == "/opt/jen|/etc/jen|/var/lib/jen"


class TestExplicitFlags:
    def test_custom_dirs_are_adopted(self, tmp_path):
        r = _run(
            tmp_path,
            """
            OPT_APP_DIR="/srv/jen/app"; OPT_CONFIG_DIR="/srv/jen/etc"; OPT_DATA_DIR="/srv/jen/data"
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
        )
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == "/srv/jen/app|/srv/jen/etc|/srv/jen/data"

    def test_only_app_dir_set_others_stay_default(self, tmp_path):
        r = _run(
            tmp_path,
            """
            OPT_APP_DIR="/srv/jen"
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
        )
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == "/srv/jen|/etc/jen|/var/lib/jen"


class TestValidationTable:
    @pytest.mark.parametrize(
        "path,expect_in_error",
        [
            ("opt/jen", "absolute"),
            ("/", "cannot be /"),
            ("/opt/../etc/jen2", ".."),
            ("/tmp/jen", "/tmp"),
            ("/run/jen", "/run"),
            ("/proc/jen", "/proc"),
            ("/sys/jen", "/sys"),
            ("/dev/jen", "/dev"),
            ("/home/jen", "/home"),
        ],
    )
    def test_app_dir_rejections(self, tmp_path, path, expect_in_error):
        r = _run(
            tmp_path,
            f"""
            OPT_APP_DIR="{path}"
            _resolve_layout_dirs
            """,
        )
        assert r.returncode != 0
        assert expect_in_error in r.stdout, r.stdout

    def test_nested_data_under_app_is_rejected(self, tmp_path):
        r = _run(
            tmp_path,
            """
            OPT_APP_DIR="/srv/jen"; OPT_DATA_DIR="/srv/jen/data"
            _resolve_layout_dirs
            """,
        )
        assert r.returncode != 0
        assert "nested" in r.stdout

    def test_nested_config_under_app_is_rejected(self, tmp_path):
        r = _run(
            tmp_path,
            """
            OPT_APP_DIR="/srv/jen"; OPT_CONFIG_DIR="/srv/jen/etc"
            _resolve_layout_dirs
            """,
        )
        assert r.returncode != 0
        assert "nested" in r.stdout

    def test_siblings_are_not_nested(self, tmp_path):
        r = _run(
            tmp_path,
            """
            OPT_APP_DIR="/srv/jen-app"; OPT_CONFIG_DIR="/srv/jen-etc"; OPT_DATA_DIR="/srv/jen-data"
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.strip() == "/srv/jen-app|/srv/jen-etc|/srv/jen-data"


class TestExistingLayoutFile:
    def _write_layout(self, tmp_path, app="/srv/jen/app", config="/srv/jen/etc", data="/srv/jen/data"):
        layout = tmp_path / "jen-layout.conf"
        layout.write_text(
            f"[layout]\napp_dir = {app}\nconfig_dir = {config}\ndata_dir = {data}\n",
            encoding="utf-8",
        )
        os.chmod(layout, 0o644)
        return layout

    def test_existing_layout_is_adopted_with_no_flags(self, tmp_path):
        layout = self._write_layout(tmp_path)
        r = _run(
            tmp_path,
            f"""
            LAYOUT_FILE="{layout}"
            _resolve_layout_dirs
            echo "$INSTALL_DIR|$CONFIG_DIR|$CONTENT_DIR"
            """,
        )
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == "/srv/jen/app|/srv/jen/etc|/srv/jen/data"

    def test_disagreeing_flag_is_refused(self, tmp_path):
        layout = self._write_layout(tmp_path)
        r = _run(
            tmp_path,
            f"""
            LAYOUT_FILE="{layout}"
            OPT_APP_DIR="/somewhere/else"
            _resolve_layout_dirs
            """,
        )
        assert r.returncode != 0
        assert "runbook" in r.stdout

    def test_agreeing_flag_is_accepted(self, tmp_path):
        layout = self._write_layout(tmp_path)
        r = _run(
            tmp_path,
            f"""
            LAYOUT_FILE="{layout}"
            OPT_APP_DIR="/srv/jen/app"
            _resolve_layout_dirs
            echo "$INSTALL_DIR"
            """,
        )
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == "/srv/jen/app"

    @pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="requires real root to prove ownership refusal")
    def test_non_root_owned_layout_file_is_refused(self, tmp_path):
        layout = self._write_layout(tmp_path)
        os.chown(layout, 1000, 1000)
        r = _run(tmp_path, f'LAYOUT_FILE="{layout}"\n_resolve_layout_dirs')
        assert r.returncode != 0
        assert "owned by root" in r.stdout

    def test_group_writable_layout_file_is_refused(self, tmp_path):
        layout = self._write_layout(tmp_path)
        os.chmod(layout, 0o664)
        r = _run(tmp_path, f'LAYOUT_FILE="{layout}"\n_resolve_layout_dirs')
        assert r.returncode != 0
        assert "writable by group or other" in r.stdout

    def test_symlinked_layout_file_is_refused(self, tmp_path):
        real = self._write_layout(tmp_path)
        link = tmp_path / "jen-layout-link.conf"
        link.symlink_to(real)
        r = _run(tmp_path, f'LAYOUT_FILE="{link}"\n_resolve_layout_dirs')
        assert r.returncode != 0
        assert "symlink" in r.stdout


class TestLayoutFileGet:
    def test_parses_values_with_surrounding_whitespace(self, tmp_path):
        layout = tmp_path / "jen-layout.conf"
        layout.write_text("[layout]\napp_dir =   /opt/jen  \nconfig_dir=/etc/jen\n", encoding="utf-8")
        r = _run(tmp_path, f'_layout_file_get "{layout}" app_dir')
        assert r.stdout == "/opt/jen"
        r = _run(tmp_path, f'_layout_file_get "{layout}" config_dir')
        assert r.stdout == "/etc/jen"
