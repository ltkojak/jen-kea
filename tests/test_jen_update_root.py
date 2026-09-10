"""
tests/test_jen_update_root.py
─────────────────────────────
v5.2.6 — tests for jen-update-root.py, the root-owned script that now
performs the entire download → verify → extract → install pipeline
that used to live inside the self_update() Flask route (see
tests/test_self_update.py for why that mattered: the old design let
www-data — the exact account permitted to write
/tmp/jen_update_install.sh — write and then sudo-execute that file as
root, bypassing every check the Flask route performed).

jen-update-root.py is a standalone script, not part of the jen/
package (deliberately — it must live outside every directory www-data
can write to, which rules out putting it inside jen/ at all). It's
loaded here via importlib against its file path, since a filename
containing hyphens isn't a valid Python module name for a normal
import statement.

These tests focus on install_extracted_files() and
verify_release_checksum() — the two pieces with real logic worth
testing directly. main() itself (the network-facing orchestration) is
intentionally not unit-tested in detail here the same way the old
Flask-based tests mocked requests/subprocess extensively; the pieces
that matter for correctness (file installation, checksum verification)
are covered as pure/near-pure functions instead, which is more
directly verifiable than mocking urllib at multiple call sites.
"""

import importlib.util
import json
import os
import pathlib
from unittest.mock import MagicMock, patch

import pytest

_SCRIPT_PATH = pathlib.Path(__file__).resolve().parent.parent / "jen-update-root.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("jen_update_root", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def jen_update_root():
    if not _SCRIPT_PATH.exists():
        pytest.skip("jen-update-root.py not found at expected repo-root path")
    return _load_module()


class TestScriptExistsWithCorrectShape:
    """Basic structural checks — mirrors the discipline already
    established for other shipped, non-package scripts in this repo
    (e.g. tests/test_htmx_vendoring.py verifying a vendored asset is
    real, not just present)."""

    def test_script_exists_at_repo_root(self):
        assert _SCRIPT_PATH.exists(), "jen-update-root.py must exist at the repo root"

    def test_script_is_valid_python(self):
        import ast

        ast.parse(_SCRIPT_PATH.read_text())

    def test_script_never_accepts_command_line_arguments(self):
        """Core security property: this script must read NO input from
        its caller (www-data, via the systemd unit) at all — it always
        re-derives everything from GitHub itself. A future change that
        starts parsing sys.argv here would reintroduce exactly the kind
        of attacker-controllable-input channel this whole rewrite
        exists to eliminate."""
        content = _SCRIPT_PATH.read_text()
        assert "sys.argv" not in content
        assert "argparse" not in content


class TestVerifyReleaseChecksum:
    def test_matching_checksum_returns_true(self, jen_update_root):
        checksum_text = "abc123def456  jen-v5.2.6.tar.gz\n"
        assert jen_update_root.verify_release_checksum("jen-v5.2.6.tar.gz", "abc123def456", checksum_text) is True

    def test_mismatched_checksum_returns_false(self, jen_update_root):
        checksum_text = "abc123def456  jen-v5.2.6.tar.gz\n"
        assert jen_update_root.verify_release_checksum("jen-v5.2.6.tar.gz", "wronghash000", checksum_text) is False

    def test_missing_entry_for_this_tarball_returns_false(self, jen_update_root):
        """A checksum file that exists but doesn't mention this exact
        tarball must fail closed, not pass through unverified."""
        checksum_text = "abc123def456  some-other-file.tar.gz\n"
        assert jen_update_root.verify_release_checksum("jen-v5.2.6.tar.gz", "abc123def456", checksum_text) is False

    def test_empty_checksum_file_returns_false(self, jen_update_root):
        assert jen_update_root.verify_release_checksum("jen-v5.2.6.tar.gz", "abc123def456", "") is False

    def test_case_insensitive_hash_comparison(self, jen_update_root):
        checksum_text = "ABC123DEF456  jen-v5.2.6.tar.gz\n"
        assert jen_update_root.verify_release_checksum("jen-v5.2.6.tar.gz", "abc123def456", checksum_text) is True

    def test_malformed_lines_are_skipped_not_fatal(self, jen_update_root):
        checksum_text = "this line is malformed\nabc123def456  jen-v5.2.6.tar.gz\n"
        assert jen_update_root.verify_release_checksum("jen-v5.2.6.tar.gz", "abc123def456", checksum_text) is True


class TestInstallExtractedFiles:
    """Mirrors the exact scenarios the old (now-removed)
    TestSelfUpdateCopiesRunPy / TestSelfUpdateCopiesStaticAssets /
    TestSelfUpdatePreservesCustomFavicon / TestSelfUpdateCopiesChangelog
    classes covered, against install_extracted_files() directly instead
    of a generated shell script — this function performs real file
    operations against real temp directories, not string-matching on
    shell commands."""

    def _make_extracted_dir(self, tmp_path, with_static=True, with_service=True, with_sudoers=True, with_plugins=False):
        extracted = tmp_path / "extracted"
        (extracted / "jen").mkdir(parents=True)
        (extracted / "jen" / "__init__.py").write_text('JEN_VERSION = "5.2.6"\n')
        (extracted / "run.py").write_text("# fake run.py\n")
        (extracted / "CHANGELOG.md").write_text("# Changelog\n\n## [5.2.6] - 2026-01-01\n\nFake.\n")
        (extracted / "requirements.txt").write_text("flask>=3.1.3\n")
        (extracted / "templates").mkdir()
        (extracted / "templates" / "index.html").write_text("<html></html>\n")
        if with_static:
            (extracted / "static" / "js").mkdir(parents=True)
            (extracted / "static" / "favicon.ico").write_bytes(b"SHIPPED-DEFAULT-FAVICON")
            (extracted / "static" / "js" / "htmx.min.js").write_text("// fake htmx\n")
        if with_plugins:
            (extracted / "plugins" / "ipam").mkdir(parents=True)
            (extracted / "plugins" / "ipam" / "manifest.json").write_text('{"id":"ipam"}')
        if with_service:
            (extracted / "jen.service").write_text("[Unit]\nDescription=fake\n")
        if with_sudoers:
            (extracted / "jen-sudoers").write_text("www-data ALL=(root) NOPASSWD: /usr/bin/systemctl restart jen\n")
        return extracted

    def test_jen_package_and_run_py_installed(self, jen_update_root, tmp_path):
        extracted = self._make_extracted_dir(tmp_path, with_static=False, with_service=False, with_sudoers=False)
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        assert (install_dir / "jen" / "__init__.py").read_text() == 'JEN_VERSION = "5.2.6"\n'
        assert (install_dir / "run.py").read_text() == "# fake run.py\n"

    def test_changelog_installed(self, jen_update_root, tmp_path):
        """v5.2.5's fix, now living in this script instead — confirms
        it carried over correctly during the rewrite."""
        extracted = self._make_extracted_dir(tmp_path, with_static=False, with_service=False, with_sudoers=False)
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        assert "5.2.6" in (install_dir / "CHANGELOG.md").read_text()

    def test_requirements_txt_installed(self, jen_update_root, tmp_path):
        """v5.4.1 — requirements.txt travels with the release so the
        installed copy at /opt/jen stays current."""
        extracted = self._make_extracted_dir(tmp_path, with_static=False, with_service=False, with_sudoers=False)
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        assert (install_dir / "requirements.txt").read_text() == "flask>=3.1.3\n"

    def test_templates_replaced_wholesale(self, jen_update_root, tmp_path):
        extracted = self._make_extracted_dir(tmp_path, with_static=False, with_service=False, with_sudoers=False)
        install_dir = tmp_path / "install"
        (install_dir / "templates").mkdir(parents=True)
        (install_dir / "templates" / "stale.html").write_text("old\n")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        assert (install_dir / "templates" / "index.html").exists()
        assert not (install_dir / "templates" / "stale.html").exists()

    def test_static_replaced_wholesale(self, jen_update_root, tmp_path):
        """v5.13.0 — static/ is release-owned now (a custom favicon and
        uploaded icons/logos moved to CONTENT_DIR). rmtree + recopy, so a
        stale file goes and the shipped favicon always wins."""
        extracted = self._make_extracted_dir(tmp_path, with_service=False, with_sudoers=False)
        install_dir = tmp_path / "install"
        (install_dir / "static").mkdir(parents=True)
        (install_dir / "static" / "favicon.ico").write_bytes(b"OLD-CUSTOM-FAVICON")
        (install_dir / "static" / "stale.js").write_text("old\n")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        assert (install_dir / "static" / "favicon.ico").read_bytes() == b"SHIPPED-DEFAULT-FAVICON"
        assert not (install_dir / "static" / "stale.js").exists()
        assert (install_dir / "static" / "js" / "htmx.min.js").exists()

    def test_bundled_plugins_replaced_wholesale(self, jen_update_root, tmp_path):
        extracted = self._make_extracted_dir(
            tmp_path, with_static=False, with_service=False, with_sudoers=False, with_plugins=True
        )
        install_dir = tmp_path / "install"
        (install_dir / "plugins" / "stale-plugin").mkdir(parents=True)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        assert (install_dir / "plugins" / "ipam" / "manifest.json").exists()
        assert not (install_dir / "plugins" / "stale-plugin").exists()

    def test_app_tree_is_chowned_root_not_www_data(self, jen_update_root, tmp_path):
        extracted = self._make_extracted_dir(tmp_path, with_service=False, with_sudoers=False)
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        calls = []
        with patch("subprocess.run", side_effect=lambda cmd, **kw: calls.append(cmd) or MagicMock(returncode=0)):
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        chowns = [c for c in calls if c and c[0] == "/bin/chown"]
        assert chowns and all("www-data:www-data" not in c for c in chowns)
        assert any(c[:3] == ["/bin/chown", "-R", "root:root"] for c in chowns)

    def test_valid_sudoers_installed_after_visudo_check_passes(self, jen_update_root, tmp_path):
        extracted = self._make_extracted_dir(tmp_path, with_static=False, with_service=False)
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[0] == "/usr/sbin/visudo":
                return MagicMock(returncode=0, stderr="")
            return MagicMock(returncode=0)

        with patch("shutil.copy2") as mock_copy2, patch("os.chmod"), patch("subprocess.run", side_effect=fake_run):
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))

        visudo_calls = [c for c in calls if c[0] == "/usr/sbin/visudo"]
        assert len(visudo_calls) == 1
        sudoers_copy_calls = [c for c in mock_copy2.call_args_list if "jen-sudoers" in str(c)]
        assert len(sudoers_copy_calls) == 1, (
            "sudoers file must be copied to /etc/sudoers.d/jen after passing validation"
        )

    def test_invalid_sudoers_never_installed(self, jen_update_root, tmp_path):
        """A malformed sudoers file must never be installed, or it can
        lock out all sudo access on the box entirely."""
        extracted = self._make_extracted_dir(tmp_path, with_static=False, with_service=False)
        install_dir = tmp_path / "install"
        install_dir.mkdir()

        def fake_run(cmd, **kwargs):
            if cmd[0] == "/usr/sbin/visudo":
                return MagicMock(returncode=1, stderr="syntax error near line 1")
            return MagicMock(returncode=0)

        with patch("shutil.copy2") as mock_copy2, patch("os.chmod"), patch("subprocess.run", side_effect=fake_run):
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))

        sudoers_copy_calls = [c for c in mock_copy2.call_args_list if "sudoers.d/jen" in str(c)]
        assert len(sudoers_copy_calls) == 0, "a sudoers file that failed visudo -c must never be installed"

    def test_service_file_triggers_daemon_reload(self, jen_update_root, tmp_path):
        extracted = self._make_extracted_dir(tmp_path, with_static=False, with_sudoers=False)
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return MagicMock(returncode=0, stderr="")

        with patch("shutil.copy2"), patch("subprocess.run", side_effect=fake_run):
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))

        assert ["/usr/bin/systemctl", "daemon-reload"] in calls

    def test_missing_optional_files_do_not_crash(self, jen_update_root, tmp_path):
        """An older/malformed tarball missing static/, jen.service, or
        jen-sudoers shouldn't crash installation of everything else."""
        extracted = self._make_extracted_dir(tmp_path, with_static=False, with_service=False, with_sudoers=False)
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        assert (install_dir / "run.py").exists()

    def test_jen_kea_helper_installed_when_present(self, jen_update_root, tmp_path):
        """v5.11.0 — jen-kea-helper travels with the release so the
        installed copy Jen pushes to Kea hosts stays current."""
        extracted = self._make_extracted_dir(tmp_path, with_static=False, with_service=False, with_sudoers=False)
        (extracted / "jen-kea-helper").write_text("#!/usr/bin/env python3\nHELPER_VERSION = 1\n")
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        assert "HELPER_VERSION = 1" in (install_dir / "jen-kea-helper").read_text()


class TestKeaHelperRollback:
    """v5.11.0 — jen-kea-helper is in _ROLLBACK_ITEMS so a failed update
    restores the previous copy (a helper version drift between Jen and
    the box's installed helper would otherwise be silent)."""

    def test_helper_is_a_rollback_item(self, jen_update_root):
        assert "jen-kea-helper" in jen_update_root._ROLLBACK_ITEMS

    def test_snapshot_then_restore_round_trips_the_helper(self, jen_update_root, tmp_path):
        install = tmp_path / "opt-jen"
        (install / "jen").mkdir(parents=True)
        (install / "jen" / "x.py").write_text("1\n")
        (install / "jen-kea-helper").write_text("HELPER_VERSION = 1\n")
        snap = tmp_path / "snap"
        jen_update_root.snapshot_install(str(snap), install_dir=str(install))
        (install / "jen-kea-helper").write_text("HELPER_VERSION = 2  # bad update\n")
        with patch("subprocess.run"):
            jen_update_root.restore_snapshot(str(snap), install_dir=str(install))
        assert (install / "jen-kea-helper").read_text() == "HELPER_VERSION = 1\n"


class TestInstallPythonDependencies:
    """v5.8.0 — the flow pip-installs the *staged* requirements.txt into
    the venv, and a failure ABORTS the update (returns False) rather than
    the pre-5.8.0 log-a-warning-and-restart behaviour."""

    def test_runs_pip_install_against_the_given_requirements(self, jen_update_root, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("gunicorn>=26.0.0\n")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            ok = jen_update_root.install_python_dependencies(str(req), "/opt/jen/venv/bin/python")
        assert ok is True
        joined = " ".join(str(c) for c in mock_run.call_args_list)
        assert "pip" in joined and "install" in joined
        assert str(req) in joined

    def test_venv_python_does_not_get_break_system_packages(self, jen_update_root, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=3.1\n")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            jen_update_root.install_python_dependencies(str(req), "/opt/jen/venv/bin/python")
        joined = " ".join(str(c) for c in mock_run.call_args_list)
        assert "--break-system-packages" not in joined

    def test_system_python_gets_break_system_packages(self, jen_update_root, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=3.1\n")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            jen_update_root.install_python_dependencies(str(req), jen_update_root.SYSTEM_PYTHON)
        joined = " ".join(str(c) for c in mock_run.call_args_list)
        assert "--break-system-packages" in joined

    def test_missing_requirements_file_is_a_no_op_success(self, jen_update_root, tmp_path):
        with patch("subprocess.run") as mock_run:
            ok = jen_update_root.install_python_dependencies(str(tmp_path / "nope.txt"), "/x/python")
        mock_run.assert_not_called()
        assert ok is True

    def test_pip_failure_returns_false_and_does_not_raise(self, jen_update_root, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("gunicorn>=26.0.0\n")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="boom", stdout="")
            ok = jen_update_root.install_python_dependencies(str(req), "/opt/jen/venv/bin/python")
        assert ok is False


class TestVenvUsable:
    def test_needs_a_working_pip_not_just_a_runnable_python(self, jen_update_root):
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            rc = 0 if argv[1:] == ["-c", ""] else 1  # python runs, pip --version fails
            return MagicMock(returncode=rc)

        with patch("subprocess.run", side_effect=fake_run):
            assert jen_update_root._venv_usable("/x/venv/bin/python") is False
        assert any("pip" in a for a in calls[-1])


class TestEnsureVenv:
    def test_returns_existing_usable_venv_without_rebuilding(self, jen_update_root, tmp_path):
        venv = tmp_path / "venv"
        (venv / "bin").mkdir(parents=True)
        (venv / "bin" / "python").write_text("")
        with (
            patch.object(jen_update_root, "_venv_usable", return_value=True),
            patch.object(jen_update_root, "_try_build_venv") as build,
        ):
            out = jen_update_root.ensure_venv(str(venv))
        assert out == str(venv / "bin" / "python")
        build.assert_not_called()

    def test_builds_the_venv_when_missing(self, jen_update_root, tmp_path):
        venv = tmp_path / "venv"
        with (
            patch.object(jen_update_root, "_venv_usable", return_value=False),
            patch.object(jen_update_root, "_try_build_venv", return_value=True) as build,
        ):
            out = jen_update_root.ensure_venv(str(venv))
        assert out == str(venv / "bin" / "python")
        build.assert_called_once()

    def test_apt_installs_python3_venv_and_retries_then_succeeds(self, jen_update_root, tmp_path):
        venv = tmp_path / "venv"
        build_results = iter([False, True])  # first build fails, retry after apt succeeds
        apt_calls = []

        def fake_run(argv, **kw):
            if "apt-get" in argv[0]:
                apt_calls.append(argv)
            return MagicMock(returncode=0)

        with (
            patch.object(jen_update_root, "_venv_usable", return_value=False),
            patch.object(jen_update_root, "_try_build_venv", side_effect=lambda _d: next(build_results)),
            patch("subprocess.run", side_effect=fake_run),
        ):
            out = jen_update_root.ensure_venv(str(venv))
        assert out == str(venv / "bin" / "python")
        assert apt_calls and "python3-venv" in apt_calls[0]

    def test_apt_get_update_then_one_more_retry_when_install_first_fails(self, jen_update_root, tmp_path):
        """v5.8.3 — a box old enough to be missing python3-venv often has
        stale indices too, so `apt-get install` fails once, `apt-get
        update` runs, and the install is retried a final time."""
        venv = tmp_path / "venv"
        runs = iter(
            [
                MagicMock(returncode=1, stderr="Unable to locate package python3-venv", stdout=""),  # install #1
                MagicMock(returncode=0, stderr="", stdout=""),  # apt-get update
                MagicMock(returncode=0, stderr="", stdout=""),  # install #2
            ]
        )
        seen = []

        def fake_run(argv, **kw):
            seen.append(" ".join(argv))
            return next(runs)

        with (
            patch.object(jen_update_root, "_venv_usable", return_value=False),
            patch.object(jen_update_root, "_try_build_venv", side_effect=[False, True]),
            patch("subprocess.run", side_effect=fake_run),
        ):
            out = jen_update_root.ensure_venv(str(venv))
        assert out == str(venv / "bin" / "python")
        assert any("apt-get update" in c for c in seen), seen

    def test_returns_none_when_even_apt_and_retry_fail(self, jen_update_root, tmp_path):
        with (
            patch.object(jen_update_root, "_venv_usable", return_value=False),
            patch.object(jen_update_root, "_try_build_venv", return_value=False),
            patch("subprocess.run", return_value=MagicMock(returncode=1, stderr="nope", stdout="")),
        ):
            assert jen_update_root.ensure_venv(str(tmp_path / "venv")) is None

    def test_updater_keeps_the_venv_root_owned(self):
        # The venv must stay root-owned — a www-data-writable venv is a
        # persistence foothold (module docstring / ARCHITECTURE §6).
        src = _SCRIPT_PATH.read_text()
        venv_chowns = [ln for ln in src.splitlines() if "chown" in ln and "VENV_DIR" in ln]
        assert venv_chowns, "expected the updater to assert venv ownership"
        assert all("root:root" in ln for ln in venv_chowns)
        assert not any("www-data" in ln for ln in venv_chowns)


class TestValidateStagedRelease:
    def _staged(self, tmp_path):
        root = tmp_path / "staged"
        (root / "jen").mkdir(parents=True)
        (root / "jen" / "__init__.py").write_text('JEN_VERSION = "9.9.9"\n')
        return root

    def test_true_when_compile_and_import_both_succeed(self, jen_update_root, tmp_path):
        root = self._staged(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            assert jen_update_root.validate_staged_release(str(root), "/x/python") is True

    def test_false_when_compile_fails(self, jen_update_root, tmp_path):
        root = self._staged(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="SyntaxError", stderr="")
            assert jen_update_root.validate_staged_release(str(root), "/x/python") is False

    def test_false_when_import_fails(self, jen_update_root, tmp_path):
        root = self._staged(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),  # compileall ok
                MagicMock(returncode=1, stdout="", stderr="ModuleNotFoundError: newdep"),  # import fails
            ]
            assert jen_update_root.validate_staged_release(str(root), "/x/python") is False


class TestSnapshotRollback:
    def test_snapshot_then_restore_round_trips_replaced_items(self, jen_update_root, tmp_path):
        install = tmp_path / "opt-jen"
        (install / "jen").mkdir(parents=True)
        (install / "jen" / "app.py").write_text("v1\n")
        (install / "run.py").write_text("run-v1\n")
        (install / "static").mkdir()
        (install / "static" / "favicon.ico").write_text("v1-icon\n")
        (install / "plugins" / "ipam").mkdir(parents=True)
        (install / "plugins" / "ipam" / "manifest.json").write_text("v1\n")

        snap = tmp_path / "snap"
        jen_update_root.snapshot_install(str(snap), install_dir=str(install))

        # simulate a bad update overwriting the tree
        (install / "jen" / "app.py").write_text("v2-broken\n")
        (install / "run.py").write_text("run-v2-broken\n")
        (install / "static" / "favicon.ico").write_text("v2-icon\n")
        (install / "plugins" / "ipam" / "manifest.json").write_text("v2\n")

        with patch("subprocess.run"):
            jen_update_root.restore_snapshot(str(snap), install_dir=str(install))

        assert (install / "jen" / "app.py").read_text() == "v1\n"
        assert (install / "run.py").read_text() == "run-v1\n"
        # v5.13.0 — static/ and plugins/ are release-owned rollback items now
        assert (install / "static" / "favicon.ico").read_text() == "v1-icon\n"
        assert (install / "plugins" / "ipam" / "manifest.json").read_text() == "v1\n"

    def test_static_and_plugins_are_rollback_items(self, jen_update_root):
        assert "static" in jen_update_root._ROLLBACK_ITEMS
        assert "plugins" in jen_update_root._ROLLBACK_ITEMS

    def test_restore_restarts_jen(self, jen_update_root, tmp_path):
        install = tmp_path / "opt-jen"
        (install / "jen").mkdir(parents=True)
        (install / "jen" / "x.py").write_text("1\n")
        snap = tmp_path / "snap"
        jen_update_root.snapshot_install(str(snap), install_dir=str(install))
        with patch("subprocess.run") as mock_run:
            jen_update_root.restore_snapshot(str(snap), install_dir=str(install))
        calls = [" ".join(map(str, c.args[0])) for c in mock_run.call_args_list]
        assert any("systemctl restart jen" in c for c in calls)

    def test_restore_chowns_root_not_www_data(self, jen_update_root, tmp_path):
        install = tmp_path / "opt-jen"
        (install / "jen").mkdir(parents=True)
        snap = tmp_path / "snap"
        jen_update_root.snapshot_install(str(snap), install_dir=str(install))
        with patch("subprocess.run") as mock_run:
            jen_update_root.restore_snapshot(str(snap), install_dir=str(install))
        chowns = [c.args[0] for c in mock_run.call_args_list if c.args[0][0] == "/bin/chown"]
        assert chowns and all("www-data:www-data" not in c for c in chowns)


class TestMigrateUserContent:
    """v5.13.0 — MOVE pre-5.13 content from the /opt/jen tree into /var/lib/jen."""

    def _tree(self, tmp_path):
        install = tmp_path / "opt-jen"
        content = tmp_path / "var-lib-jen"
        extracted = tmp_path / "extracted"
        (install / "static" / "icons" / "custom").mkdir(parents=True)
        (extracted / "static").mkdir(parents=True)
        (extracted / "static" / "favicon.ico").write_bytes(b"SHIPPED-DEFAULT")
        return install, content, extracted

    def _run(self, jen_update_root, install, content, extracted):
        with patch("subprocess.run"):
            jen_update_root.migrate_user_content(str(install), str(content), str(extracted))

    def test_moves_icons_navlogo_backups_keys(self, jen_update_root, tmp_path):
        install, content, extracted = self._tree(tmp_path)
        (install / "static" / "icons" / "custom" / "acme.svg").write_text("<svg/>")
        (install / "static" / "nav_logo.png").write_bytes(b"png")
        (install / "backups").mkdir()
        (install / "backups" / "jen.json.gz").write_bytes(b"gz")
        (install / ".secret_key").write_text("k" * 40)
        self._run(jen_update_root, install, content, extracted)
        assert (content / "icons" / "acme.svg").exists()
        assert not (install / "static" / "icons" / "custom" / "acme.svg").exists()  # MOVED
        assert (content / "branding" / "nav_logo.png").exists()
        assert (content / "backups" / "jen.json.gz").exists()
        assert (content / "keys" / ".secret_key").read_text() == "k" * 40

    def test_favicon_only_when_differs_from_shipped(self, jen_update_root, tmp_path):
        install, content, extracted = self._tree(tmp_path)
        (install / "static" / "favicon.ico").write_bytes(b"SHIPPED-DEFAULT")  # identical
        self._run(jen_update_root, install, content, extracted)
        assert not (content / "branding" / "favicon.ico").exists()
        (install / "static" / "favicon.ico").write_bytes(b"a-real-custom-favicon")
        self._run(jen_update_root, install, content, extracted)
        assert (content / "branding" / "favicon.ico").read_bytes() == b"a-real-custom-favicon"

    def test_plugins_split_shipped_vs_installed(self, jen_update_root, tmp_path):
        install, content, extracted = self._tree(tmp_path)
        (install / "plugins" / "ipam").mkdir(parents=True)
        (install / "plugins" / "ipam" / ".enabled").write_text("")
        (install / "plugins" / "thirdparty").mkdir()
        (install / "plugins" / "thirdparty" / "manifest.json").write_text('{"id":"thirdparty"}')
        (install / "plugins" / "thirdparty" / ".enabled").write_text("")
        self._run(jen_update_root, install, content, extracted)
        assert (content / "plugins-enabled" / "ipam").exists()  # bundled marker moved
        assert (content / "plugins-enabled" / "thirdparty").exists()
        assert (content / "plugins" / "thirdparty" / "manifest.json").exists()  # non-shipped dir moved
        assert not (content / "plugins" / "ipam").exists()  # shipped dir NOT moved

    def test_idempotent(self, jen_update_root, tmp_path):
        install, content, extracted = self._tree(tmp_path)
        (install / "static" / "icons" / "custom" / "acme.svg").write_text("<svg/>")
        self._run(jen_update_root, install, content, extracted)
        self._run(jen_update_root, install, content, extracted)  # no error
        assert (content / "icons" / "acme.svg").exists()

    def test_main_calls_migrate_before_install(self):
        src = _SCRIPT_PATH.read_text()
        # the CALL sites (upper-case args), not the `def` line
        assert src.index("migrate_user_content(INSTALL_DIR, CONTENT_DIR, extracted)") < src.index(
            "install_extracted_files(extracted, INSTALL_DIR)"
        )

    def test_snapshot_and_restore_cover_the_external_unit_files(self, jen_update_root, tmp_path):
        install = tmp_path / "opt-jen"
        (install / "jen").mkdir(parents=True)
        (install / "jen" / "x.py").write_text("1\n")
        unit = tmp_path / "jen.service"
        unit.write_text("[Service]\nExecStart=good\n")
        sudoers = tmp_path / "sudoers-jen"
        sudoers.write_text("www-data ALL=(root) NOPASSWD: /usr/bin/systemctl restart jen\n")
        snap = tmp_path / "snap"
        with patch.dict(
            jen_update_root._EXTERNAL_ITEMS,
            {str(unit): "jen.service", str(sudoers): "sudoers-jen"},
            clear=True,
        ):
            jen_update_root.snapshot_install(str(snap), install_dir=str(install))
            # a bad update wrecks the unit
            unit.write_text("[Service]\nExecStart=BROKEN\n")
            sudoers.write_text("garbage\n")
            with patch("subprocess.run") as mock_run:
                jen_update_root.restore_snapshot(str(snap), install_dir=str(install))
        assert unit.read_text() == "[Service]\nExecStart=good\n"
        assert "restart jen" in sudoers.read_text()
        calls = [" ".join(map(str, c.args[0])) for c in mock_run.call_args_list]
        assert any("daemon-reload" in c for c in calls), "a restored .service needs daemon-reload"

    def test_main_rolls_back_on_an_exception_during_the_swap(self, jen_update_root):
        """v5.8.1 — the file swap + restart must be inside a try/except
        that restores the snapshot, not just a post-restart health check."""
        import inspect

        src = inspect.getsource(jen_update_root.main)
        # the region from the snapshot to the success return
        region = src[src.index("snapshot_install(snapshot_dir)") : src.rindex("return 0")]
        assert "try:" in region
        assert "except Exception" in region
        assert "restore_snapshot(snapshot_dir)" in region
        # install_extracted_files must be INSIDE that try (before the except)
        assert region.index("install_extracted_files(extracted") < region.index("except Exception")

    @pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs a privilege on Windows")
    def test_snapshot_copies_a_dangling_symlink_instead_of_dying(self, jen_update_root, tmp_path):
        """v5.8.4 — bigben had a stray `/opt/jen/templates/templates -> (gone)`
        from some ancient install. copytree(symlinks=False) followed it,
        raised ENOENT, and every in-app update died at the snapshot step —
        before the swap, so the box just stayed on the old version."""
        install = tmp_path / "opt-jen"
        (install / "templates").mkdir(parents=True)
        (install / "templates" / "index.html").write_text("ok\n")
        os.symlink(str(tmp_path / "does-not-exist"), str(install / "templates" / "templates"))

        snap = tmp_path / "snap"
        jen_update_root.snapshot_install(str(snap), install_dir=str(install))

        assert (snap / "templates" / "index.html").read_text() == "ok\n"
        assert os.path.islink(snap / "templates" / "templates")  # copied as a link, not followed

    def test_main_aborts_cleanly_when_the_snapshot_itself_fails(self, jen_update_root):
        """A snapshot failure happens before anything is touched, so it must
        log + return 1, not traceback — and must NOT use `except Exception`
        (the rollback-region test above slices on that string)."""
        import inspect

        src = inspect.getsource(jen_update_root.main)
        i = src.index("snapshot_install(snapshot_dir)")
        after = src[i : i + 600]
        assert "except (OSError, shutil.Error)" in after
        assert "/opt/jen untouched" in after
        assert "return 1" in after

    def test_prunes_stale_rollback_dirs_at_start(self, jen_update_root, tmp_path):
        """v5.9.0 — bigben had four `.rollback-*` dirs from failed 5.8.2
        attempts. Anything from an earlier run is stale once a new one
        starts."""
        install = tmp_path / "opt-jen"
        install.mkdir()
        for ts in ("1", "2", "3"):
            (install / f".rollback-{ts}").mkdir()
            (install / f".rollback-{ts}" / "x").write_text("x")
        (install / "jen").mkdir()
        # v5.9.1 — the newest snapshot survives, and so does anything the
        # CRITICAL path marked .keep (it may be the only intact copy of the
        # previous release). Everything else goes.
        (install / ".rollback-2" / jen_update_root.KEEP_MARKER).write_text("kept")
        assert jen_update_root._prune_stale_snapshots(str(install)) == 1
        left = sorted(p.name for p in install.iterdir() if p.name.startswith(".rollback-"))
        assert left == [".rollback-2", ".rollback-3"]
        assert (install / "jen").exists()

    def test_critical_path_marks_its_snapshot_keep(self, jen_update_root):
        import inspect

        src = inspect.getsource(jen_update_root.main)
        i = src.index("CRITICAL: rollback restart also unhealthy")
        assert "KEEP_MARKER" in src[i - 600 : i]

    def test_main_baselines_the_probe_before_the_snapshot(self, jen_update_root):
        """v5.9.0 — a probe that can't see the currently-running Jen must
        abort BEFORE the swap (nothing to roll back), not install and then
        roll a good release back on a false negative."""
        import inspect

        src = inspect.getsource(jen_update_root.main)
        i_validate = src.index("validate_staged_release(extracted")
        i_probe = src.index("_probe_once(_local_opener(), probe_url)")
        i_snapshot = src.index("snapshot_install(snapshot_dir)")
        assert i_validate < i_probe < i_snapshot
        after = src[i_probe : i_probe + 700]
        assert "/opt/jen untouched" in after and "return 1" in after

    def test_probe_once_treats_redirect_as_alive(self, jen_update_root):
        port, stop = _serve(_AppLike.handler())
        try:
            assert jen_update_root._probe_once(jen_update_root._local_opener(), f"http://127.0.0.1:{port}/") is True
        finally:
            stop()
        assert jen_update_root._probe_once(jen_update_root._local_opener(), "http://127.0.0.1:5999/") is False

    def test_main_exits_zero_without_downloading_when_already_current(self, jen_update_root):
        with (
            patch.object(jen_update_root, "fetch_json", return_value={"tag_name": "v9.9.9", "assets": []}),
            patch.object(jen_update_root, "_installed_version", return_value="9.9.9"),
            patch.object(jen_update_root, "fetch_bytes_with_sha256") as download,
        ):
            assert jen_update_root.main() == 0
        download.assert_not_called()


def _self_signed_cert(tmp_path, cn="jen.example.com"):
    """A throwaway cert whose CN is deliberately NOT 127.0.0.1 — the whole
    point of the v5.8.3 fix is that the updater's loopback probe still
    works against a cert like this."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    crt = tmp_path / "certificate.crt"
    keyf = tmp_path / "private.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyf.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(crt), str(keyf)


def _serve(handler_cls, certfile=None, keyfile=None):
    """Start a throwaway localhost HTTP(S) server on an ephemeral port.
    Returns (port, stop_fn)."""
    import http.server
    import ssl as _ssl
    import threading

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    if certfile:
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv.server_address[1], srv.shutdown


class _AppLike:
    """GET / -> 302 to /login (like Jen unauthenticated); /api/v1/health -> JSON."""

    version = "5.8.3"

    @classmethod
    def handler(cls):
        import http.server

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                if self.path.startswith("/api/v1/health"):
                    body = json.dumps({"jen_version": cls.version, "kea_up": True}).encode()
                    self.send_response(200)
                else:
                    body = b"go to login\n"
                    self.send_response(302)
                    self.send_header("Location", "/login")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        return H


class TestServiceHealthy:
    def test_false_when_unit_never_active(self, jen_update_root):
        with (
            patch("subprocess.run", return_value=MagicMock(returncode=1)),
            patch("time.sleep"),
        ):
            assert jen_update_root.service_healthy(timeout=0.01) is False

    def test_http_302_to_login_counts_as_healthy(self, jen_update_root, monkeypatch):
        """A real 302 — not a mocked HTTPError. urllib would normally follow
        it; the probe must NOT, and must read the 302 as proof-of-life."""
        port, stop = _serve(_AppLike.handler())
        try:
            monkeypatch.setattr(jen_update_root, "_ssl_enabled", lambda: False)
            monkeypatch.setattr(jen_update_root, "_server_cfg", lambda k, f: port if k == "http_port" else f)
            with patch("subprocess.run", return_value=MagicMock(returncode=0)), patch("time.sleep"):
                assert jen_update_root.service_healthy(timeout=5) is True
        finally:
            stop()

    def test_ssl_install_probes_https_port_and_ignores_a_wrong_cn_cert(self, jen_update_root, tmp_path, monkeypatch):
        """THE v5.8.3 regression test. 5.8.2 hit the plain-HTTP port, let
        urllib follow jen/httpredirect.py's 301 to https://<hostname>, and
        died on cert validation — rolling back a healthy HTTPS upgrade.
        Here the HTTPS server uses a cert for `jen.example.com`; the probe
        connects to 127.0.0.1 and must still succeed."""
        crt, key = _self_signed_cert(tmp_path)
        https_port, stop_https = _serve(_AppLike.handler(), certfile=crt, keyfile=key)

        # a real jen/httpredirect.py listener on the "HTTP" port — if the
        # probe touched this one and followed the redirect it would fail.
        from jen.httpredirect import make_server

        redir = make_server(0, https_port)
        import threading

        threading.Thread(target=redir.serve_forever, daemon=True).start()
        try:
            monkeypatch.setattr(jen_update_root, "_ssl_enabled", lambda: True)
            monkeypatch.setattr(
                jen_update_root,
                "_server_cfg",
                lambda k, f: https_port if k == "https_port" else (redir.server_address[1] if k == "http_port" else f),
            )
            with patch("subprocess.run", return_value=MagicMock(returncode=0)), patch("time.sleep"):
                assert jen_update_root.service_healthy(timeout=5) is True
        finally:
            stop_https()
            redir.shutdown()

    def test_default_timeout_is_read_from_jen_config(self, jen_update_root, tmp_path, monkeypatch):
        cfg = tmp_path / "jen.config"
        cfg.write_text("[server]\nupdate_health_timeout = 7\n")
        monkeypatch.setattr(jen_update_root, "CONFIG_FILE", str(cfg))
        assert jen_update_root._server_cfg("update_health_timeout", 90) == 7

    def test_default_timeout_falls_back_to_90_when_unset(self, jen_update_root, tmp_path, monkeypatch):
        cfg = tmp_path / "jen.config"
        cfg.write_text("[server]\nhttp_port = 5050\n")
        monkeypatch.setattr(jen_update_root, "CONFIG_FILE", str(cfg))
        assert jen_update_root._server_cfg("update_health_timeout", 90) == 90


class TestLocalBaseUrl:
    def test_plain_http_when_no_certs(self, jen_update_root, monkeypatch):
        monkeypatch.setattr(jen_update_root, "_ssl_enabled", lambda: False)
        monkeypatch.setattr(jen_update_root, "_server_cfg", lambda k, f: 5050 if k == "http_port" else f)
        assert jen_update_root._local_base_url() == "http://127.0.0.1:5050"

    def test_https_port_when_certs_present(self, jen_update_root, monkeypatch):
        monkeypatch.setattr(jen_update_root, "_ssl_enabled", lambda: True)
        monkeypatch.setattr(jen_update_root, "_server_cfg", lambda k, f: 8443 if k == "https_port" else f)
        assert jen_update_root._local_base_url() == "https://127.0.0.1:8443"

    def test_ssl_enabled_keys_on_both_cert_and_key(self, jen_update_root, tmp_path, monkeypatch):
        crt = tmp_path / "certificate.crt"
        monkeypatch.setattr(jen_update_root, "SSL_CERT", str(crt))
        monkeypatch.setattr(jen_update_root, "SSL_KEY", str(tmp_path / "private.key"))
        assert jen_update_root._ssl_enabled() is False
        crt.write_text("x")
        assert jen_update_root._ssl_enabled() is False  # key still missing
        (tmp_path / "private.key").write_text("x")
        assert jen_update_root._ssl_enabled() is True


class TestRunningVersion:
    """v5.8.2 — the post-restart check queries the running process, not
    just the string we just wrote to disk. v5.8.3 — over the app's real
    (HTTPS) port, tolerating a loopback cert mismatch."""

    def test_reads_version_over_https_with_a_wrong_cn_cert(self, jen_update_root, tmp_path, monkeypatch):
        crt, key = _self_signed_cert(tmp_path)
        _AppLike.version = "5.8.3"
        port, stop = _serve(_AppLike.handler(), certfile=crt, keyfile=key)
        try:
            monkeypatch.setattr(jen_update_root, "_ssl_enabled", lambda: True)
            monkeypatch.setattr(jen_update_root, "_server_cfg", lambda k, f: port if k == "https_port" else f)
            assert jen_update_root._running_version() == "5.8.3"
        finally:
            stop()

    def test_returns_none_when_endpoint_is_unreachable(self, jen_update_root, monkeypatch):
        monkeypatch.setattr(jen_update_root, "_ssl_enabled", lambda: False)
        # nothing listening on this port
        monkeypatch.setattr(jen_update_root, "_server_cfg", lambda k, f: 5999 if k == "http_port" else f)
        assert jen_update_root._running_version() is None

    def test_returns_none_on_non_json_body(self, jen_update_root, monkeypatch):
        import http.server

        class Html(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                body = b"<html>not json</html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        port, stop = _serve(Html)
        try:
            monkeypatch.setattr(jen_update_root, "_ssl_enabled", lambda: False)
            monkeypatch.setattr(jen_update_root, "_server_cfg", lambda k, f: port if k == "http_port" else f)
            assert jen_update_root._running_version() is None
        finally:
            stop()


class TestMainPostRestartChecks:
    """v5.8.2 — main() byte-compiles the installed tree with the venv
    interpreter and confirms the running version before declaring success,
    both inside the rollback try/except."""

    def test_swap_region_compiles_installed_tree_and_confirms_version(self, jen_update_root):
        import inspect

        src = inspect.getsource(jen_update_root.main)
        region = src[src.index("snapshot_install(snapshot_dir)") : src.rindex("return 0")]
        # v5.13.0 — the installed tree is jen/ + plugins/ (both now
        # release-owned); compileall runs over whichever exist.
        assert 'os.path.join(INSTALL_DIR, d) for d in ("jen", "plugins")' in region
        assert 'compileall", "-q", *_compile_targets' in region
        assert "_confirm_running_version(version)" in region
        assert region.index("compileall") < region.index("except Exception")
        assert region.index("_confirm_running_version(version)") < region.index("except Exception")
        # v5.9.1 — the on-disk string is never accepted as "confirmed running"
        assert "_installed_version(), " not in region

    def test_confirm_running_version_retries_then_accepts(self, jen_update_root):
        with (
            patch.object(jen_update_root, "_running_version", side_effect=[None, None, "9.9.9"]),
            patch("time.sleep") as slp,
        ):
            assert jen_update_root._confirm_running_version("9.9.9", attempts=5, delay=3) == "9.9.9"
        assert slp.call_count == 2

    def test_confirm_running_version_fails_instead_of_trusting_disk(self, jen_update_root):
        with (
            patch.object(jen_update_root, "_running_version", return_value=None),
            patch.object(jen_update_root, "_installed_version", return_value="9.9.9"),
            patch("time.sleep"),
            pytest.raises(RuntimeError, match="only\\s+proves the files were copied"),
        ):
            jen_update_root._confirm_running_version("9.9.9", attempts=3, delay=0)

    def test_confirm_running_version_mismatch_fails_immediately(self, jen_update_root):
        with (
            patch.object(jen_update_root, "_running_version", return_value="1.0.0"),
            patch("time.sleep") as slp,
            pytest.raises(RuntimeError, match="mismatch"),
        ):
            jen_update_root._confirm_running_version("9.9.9")
        slp.assert_not_called()


class TestInstallSelfUpdateFiles:
    """
    v5.3.3 — regression tests for the gap a third-party review found in
    the v5.2.6 redesign: install_extracted_files() installed the
    application but never a new copy of this script or of
    jen-update.service, so a fix to the updater itself could never
    reach a running instance via the in-app update button.

    os.chown is the only thing mocked here — it genuinely requires
    root to change ownership to uid/gid 0, which a CI test runner
    doesn't have. Everything else (file writes, chmod, os.replace) runs
    for real against tmp_path, so these tests verify actual resulting
    file content and mode, not just that a function was called with
    the right-looking arguments.
    """

    def _make_extracted_dir_with_self_update_files(
        self, tmp_path, script_content=b"# fake v2 updater\n", service_content=b"[Unit]\nDescription=fake v2\n"
    ):
        extracted = tmp_path / "extracted"
        extracted.mkdir(exist_ok=True)
        (extracted / "jen-update-root.py").write_bytes(script_content)
        (extracted / "jen-update.service").write_bytes(service_content)
        return extracted

    def test_installs_new_script_content(self, jen_update_root, tmp_path):
        extracted = self._make_extracted_dir_with_self_update_files(tmp_path)
        dest_dir = tmp_path / "sbin"
        dest_dir.mkdir()
        self_install_path = dest_dir / "jen-update-root.py"
        with patch("os.chown"), patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_self_update_files(
                str(extracted),
                self_install_path=str(self_install_path),
                update_service_path=str(tmp_path / "jen-update.service"),
            )
        assert self_install_path.read_bytes() == b"# fake v2 updater\n"

    def test_installed_script_is_root_owned_and_mode_0700(self, jen_update_root, tmp_path):
        """The specific regression a third-party review asked for
        directly: 'A verified release containing a newer root updater
        installs it root-owned and non-writable by www-data.'"""
        extracted = self._make_extracted_dir_with_self_update_files(tmp_path)
        dest_dir = tmp_path / "sbin"
        dest_dir.mkdir()
        self_install_path = dest_dir / "jen-update-root.py"
        with patch("os.chown") as mock_chown, patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_self_update_files(
                str(extracted),
                self_install_path=str(self_install_path),
                update_service_path=str(tmp_path / "jen-update.service"),
            )
        # os.chown targets the TEMP file (before the atomic rename to
        # self_install_path), not self_install_path itself — filter by
        # the script's distinct temp-file prefix to isolate its chown
        # call from the service file's separate one.
        script_chown_calls = [c for c in mock_chown.call_args_list if ".jen-update-root-" in c[0][0]]
        assert len(script_chown_calls) == 1
        _, uid, gid = script_chown_calls[0][0]
        assert uid == 0 and gid == 0
        # Mode is checked for real, against the actual installed file —
        # os.chmod doesn't require root, only ownership of the file,
        # which the test process has since it just created it.
        mode = os.stat(self_install_path).st_mode & 0o777
        assert mode == 0o700, f"expected mode 0o700 (root-only, unreadable/unwritable by www-data), got {oct(mode)}"

    def test_installs_new_service_content_and_reloads_daemon(self, jen_update_root, tmp_path):
        extracted = self._make_extracted_dir_with_self_update_files(tmp_path)
        (tmp_path / "sbin").mkdir()
        update_service_path = tmp_path / "jen-update.service"
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return MagicMock(returncode=0)

        with patch("os.chown"), patch("subprocess.run", side_effect=fake_run):
            jen_update_root.install_self_update_files(
                str(extracted),
                self_install_path=str(tmp_path / "sbin" / "jen-update-root.py"),
                update_service_path=str(update_service_path),
            )
        assert update_service_path.read_bytes() == b"[Unit]\nDescription=fake v2\n"
        assert ["/usr/bin/systemctl", "daemon-reload"] in calls

    def test_service_file_mode_is_0644_not_owner_only(self, jen_update_root, tmp_path):
        """A systemd unit file needs to be world-readable (systemd
        itself reads it as root, but 0644 is the conventional,
        expected mode for unit files) — unlike the script itself,
        which is deliberately 0700 since it's the thing www-data must
        never be able to read or modify."""
        extracted = self._make_extracted_dir_with_self_update_files(tmp_path)
        (tmp_path / "sbin").mkdir()
        update_service_path = tmp_path / "jen-update.service"
        with patch("os.chown"), patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_self_update_files(
                str(extracted),
                self_install_path=str(tmp_path / "sbin" / "jen-update-root.py"),
                update_service_path=str(update_service_path),
            )
        mode = os.stat(update_service_path).st_mode & 0o777
        assert mode == 0o644

    def test_uses_atomic_replace_not_in_place_overwrite(self, jen_update_root, tmp_path):
        """Confirms the actual safety property, not just that the file
        ends up with the right content: os.replace must be the
        mechanism, not shutil.copy2 (which would overwrite the
        destination's existing inode in place rather than atomically
        swapping in a fully-written replacement)."""
        extracted = self._make_extracted_dir_with_self_update_files(tmp_path)
        self_install_path = tmp_path / "sbin" / "jen-update-root.py"
        self_install_path.parent.mkdir()
        self_install_path.write_bytes(b"# old v1 updater\n")

        with (
            patch("os.chown"),
            patch("subprocess.run") as mock_run,
            patch("os.replace", side_effect=os.replace) as mock_replace,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_self_update_files(
                str(extracted),
                self_install_path=str(self_install_path),
                update_service_path=str(tmp_path / "jen-update.service"),
            )
        assert mock_replace.called, "expected os.replace to be used for the atomic swap"
        # And confirm the end result is still correct through the real
        # os.replace call (side_effect delegates to it for real).
        assert self_install_path.read_bytes() == b"# fake v2 updater\n"

    def test_missing_self_update_files_in_extracted_dir_does_not_crash(self, jen_update_root, tmp_path):
        """An older-shaped release, or one that genuinely doesn't touch
        the updater, shouldn't crash — this must be a no-op, not an
        error, when the extracted tarball simply doesn't contain these
        two files."""
        extracted = tmp_path / "extracted"
        extracted.mkdir()
        self_install_path = tmp_path / "sbin" / "jen-update-root.py"
        self_install_path.parent.mkdir()
        self_install_path.write_bytes(b"# untouched existing v1\n")
        update_service_path = tmp_path / "jen-update.service"

        with patch("os.chown"), patch("subprocess.run") as mock_run:
            jen_update_root.install_self_update_files(
                str(extracted),
                self_install_path=str(self_install_path),
                update_service_path=str(update_service_path),
            )
        assert self_install_path.read_bytes() == b"# untouched existing v1\n"
        assert not update_service_path.exists()
        mock_run.assert_not_called()

    def test_main_calls_install_self_update_files_after_install_extracted_files(self, jen_update_root):
        """Confirms main() actually wires this in — the whole point of
        this fix is useless if the new function exists but is never
        called from the real update flow."""
        import inspect

        main_source = inspect.getsource(jen_update_root.main)
        install_pos = main_source.find("install_extracted_files(")
        self_update_pos = main_source.find("install_self_update_files(")
        assert install_pos != -1, "main() no longer calls install_extracted_files()"
        assert self_update_pos != -1, "main() does not call install_self_update_files() at all"
        assert self_update_pos > install_pos, (
            "install_self_update_files() should run after the main application install"
        )
