"""
tests/test_venv_isolation.py
────────────────────────────
v5.8.0 — bare-metal Jen runs its Python dependencies from /opt/jen/venv
instead of system site-packages (no more `pip --break-system-packages`).
run.py re-execs into the venv interpreter; install.sh builds and
maintains the venv; jen.service deliberately stays on system python3 so
the unit never changes and a pre-venv install can't be stranded.
"""

import os
import pathlib
import re
import subprocess
import sys
import venv

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
RUN_PY = (REPO / "run.py").read_text(encoding="utf-8")
INSTALL_SH = (REPO / "install.sh").read_text(encoding="utf-8")
SERVICE = (REPO / "jen.service").read_text(encoding="utf-8")


class TestRunPyReExec:
    def test_guard_uses_sys_prefix_not_realpath(self):
        # v5.8.0 shipped with a realpath(executable) comparison, which is
        # always equal on POSIX (venv bin/python symlink-chains to the base
        # interpreter) → re-exec never fired. sys.prefix is the right check.
        assert "os.path.abspath(sys.prefix) == os.path.abspath(venv_dir)" in RUN_PY
        assert "os.path.realpath" not in RUN_PY, "the realpath comparison was the bug"
        assert 'os.environ.get("JEN_NO_VENV_REEXEC") == "1"' in RUN_PY
        assert "except OSError:" in RUN_PY  # broken venv must not be fatal

    def test_reexec_runs_before_any_jen_import(self):
        assert RUN_PY.index("_venv_reexec_target") < RUN_PY.index("from jen import JEN_VERSION")

    def test_run_py_imports_cleanly_here(self):
        import run

        assert hasattr(run, "gunicorn_argv")

    def test_target_is_none_when_no_venv(self, tmp_path):
        import run

        assert run._venv_reexec_target(str(tmp_path / "nope")) is None

    # run.py's re-exec is bare-metal-Linux-only by design (it hardcodes the
    # POSIX bin/python layout; Docker and dev never reach it). The
    # behavioural tests below build a real venv and only run on POSIX.
    @pytest.mark.skipif(os.name == "nt", reason="POSIX bin/python venv layout")
    def test_target_is_none_when_opted_out(self, tmp_path, monkeypatch):
        import run

        v = tmp_path / "venv"
        venv.create(v, with_pip=False)
        monkeypatch.setenv("JEN_NO_VENV_REEXEC", "1")
        assert run._venv_reexec_target(str(v)) is None

    @pytest.mark.skipif(os.name == "nt", reason="POSIX bin/python venv layout")
    def test_target_is_the_venv_python_when_running_outside_it(self, tmp_path):
        """The v5.8.0 bug: this returned None because realpath of the
        venv's bin/python equals realpath of the base interpreter. It must
        return the venv python whenever we're not already running it."""
        import run

        v = tmp_path / "venv"
        venv.create(v, with_pip=False, symlinks=True)
        out = run._venv_reexec_target(str(v))
        assert out == str(v / "bin" / "python")

    @pytest.mark.skipif(os.name == "nt", reason="POSIX bin/python venv layout")
    def test_end_to_end_reexec_actually_switches_interpreter(self, tmp_path):
        """Build a real venv, point a stub run.py guard at it, run it with
        the base interpreter, and prove the process re-execs."""
        v = tmp_path / "venv"
        venv.create(v, with_pip=False, symlinks=True)
        vpy = str(v / "bin" / "python")
        stub = tmp_path / "stub.py"
        guard = RUN_PY[RUN_PY.index("import os") : RUN_PY.index("import logging")]
        guard = guard.replace('_VENV_DIR = "/opt/jen/venv"', f"_VENV_DIR = {str(v)!r}")
        stub.write_text(guard + "\nimport sys; print(sys.executable)\n", encoding="utf-8")
        r = subprocess.run([sys.executable, str(stub)], capture_output=True, text=True, check=True)
        assert r.stdout.strip() == vpy, f"expected re-exec into {vpy}, ran as {r.stdout.strip()}"


class TestInstallShVenv:
    def test_setup_venv_function_exists(self):
        assert "setup_venv()" in INSTALL_SH

    def test_creates_venv_at_opt_jen_venv(self):
        assert "python3 -m venv" in INSTALL_SH
        assert "/opt/jen/venv" in INSTALL_SH or '"$VENV_DIR"' in INSTALL_SH

    def test_installs_requirements_into_the_venv_not_system(self):
        assert '"$VENV_PY" -m pip install -q -r "$req_file"' in INSTALL_SH
        # the old system-wide break-system-packages install is gone
        assert "pip3 install -q -r" not in INSTALL_SH

    def test_pulls_python3_venv_apt_package_when_missing(self):
        assert "python3-venv" in INSTALL_SH

    def test_venv_is_left_root_owned_not_writable_by_the_service(self):
        # A www-data-writable venv is a persistence foothold — install.sh
        # and the root updater own it, the service only reads/executes it.
        assert 'chown -R root:root "$VENV_DIR"' in INSTALL_SH
        assert 'chown -R "$JEN_USER:$JEN_USER" "$VENV_DIR"' not in INSTALL_SH

    def test_setup_venv_runs_in_install_and_repair_flows(self):
        # both the standard main() flow and --repair call it (the def
        # itself is `setup_venv()` with parens, so it's not counted here)
        calls = re.findall(r"^\s+setup_venv\s*$", INSTALL_SH, re.M)
        assert len(calls) >= 2, f"expected setup_venv called in ≥2 flows, found {len(calls)}"


class TestServiceFileUnchanged:
    def test_execstart_still_system_python(self):
        assert "ExecStart=/usr/bin/python3 /opt/jen/run.py" in SERVICE

    def test_comment_explains_the_venv_reexec_choice(self):
        assert "re-execs into the venv" in SERVICE


class TestVenvMigrationBanner:
    """v5.8.1 — surface a bare-metal install running without its venv."""

    def test_not_flagged_in_a_dev_checkout(self):
        import jen

        # JEN_ROOT is set for the test suite → dev/CI → never flagged
        assert jen._venv_migration_incomplete() is False

    def test_not_flagged_when_running_inside_a_venv(self, monkeypatch):
        import jen

        monkeypatch.setattr(sys, "base_prefix", sys.prefix + "-other")
        assert jen._venv_migration_incomplete() is False

    def test_flagged_for_a_bare_metal_install_with_no_venv(self, monkeypatch):
        import jen

        monkeypatch.setattr(sys, "base_prefix", sys.prefix)  # not in a venv
        monkeypatch.delenv("JEN_ROOT", raising=False)
        monkeypatch.setattr(jen.os.path, "exists", lambda p: p == "/opt/jen/run.py")
        monkeypatch.setattr(jen.os.path, "isfile", lambda p: p == "/opt/jen/run.py")
        assert jen._venv_migration_incomplete() is True

    def test_base_html_has_the_banner(self):
        base = (REPO / "templates" / "base.html").read_text(encoding="utf-8")
        assert "venv_migration_incomplete" in base
        assert "install.sh --repair" in base


class TestJenConfigOwnership:
    """v5.10.4 — jen.config is rewritten by the running service on every
    Settings save, so it must be owned by the service user. Fresh
    installs 5.9.0–5.10.3 chowned it root:www-data in write_config, which
    runs AFTER install_files' `chown -R www-data`, so every save failed
    with EACCES until the next `install.sh --upgrade`."""

    def test_config_file_is_chowned_to_the_service_user_not_root(self):
        assert 'chown "$JEN_USER:$JEN_USER" "$CONFIG_FILE"' in INSTALL_SH
        assert 'chown root:www-data "$CONFIG_FILE"' not in INSTALL_SH


class TestKeaHelperPackaged:
    """v5.11.0 — jen-kea-helper ships beside the app on the Jen host."""

    def test_install_sh_copies_the_helper(self):
        assert 'cp "$SCRIPT_DIR/jen-kea-helper" "$INSTALL_DIR/jen-kea-helper"' in INSTALL_SH
