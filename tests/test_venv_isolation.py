"""
tests/test_venv_isolation.py
────────────────────────────
v5.8.0 — bare-metal Jen runs its Python dependencies from /opt/jen/venv
instead of system site-packages (no more `pip --break-system-packages`).
run.py re-execs into the venv interpreter; install.sh builds and
maintains the venv; jen.service deliberately stays on system python3 so
the unit never changes and a pre-venv install can't be stranded.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
RUN_PY = (REPO / "run.py").read_text(encoding="utf-8")
INSTALL_SH = (REPO / "install.sh").read_text(encoding="utf-8")
SERVICE = (REPO / "jen.service").read_text(encoding="utf-8")


class TestRunPyReExec:
    def test_reexec_block_present_and_guarded(self):
        assert '_VENV_PYTHON = "/opt/jen/venv/bin/python"' in RUN_PY
        # must not loop: skip the exec when we're already that interpreter
        assert "os.path.realpath(sys.executable) != os.path.realpath(_VENV_PYTHON)" in RUN_PY
        # opt-out hatch
        assert 'os.environ.get("JEN_NO_VENV_REEXEC") != "1"' in RUN_PY
        # a broken venv must not be fatal
        assert "except OSError:" in RUN_PY

    def test_reexec_runs_before_any_jen_import(self):
        reexec_at = RUN_PY.index("_VENV_PYTHON =")
        first_jen_import = RUN_PY.index("from jen import JEN_VERSION")
        assert reexec_at < first_jen_import, "venv re-exec must precede the first dependency import"

    def test_run_py_imports_cleanly_here(self):
        # No /opt/jen/venv on the test box → the guard is a no-op and the
        # module imports normally (also exercised by test_run_launcher).
        import run

        assert hasattr(run, "gunicorn_argv")


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

    def test_venv_is_chowned_to_service_user(self):
        assert 'chown -R "$JEN_USER:$JEN_USER" "$VENV_DIR"' in INSTALL_SH

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
