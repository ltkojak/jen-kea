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
import os
import pathlib
import sys
from unittest.mock import patch, MagicMock

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
        assert jen_update_root.verify_release_checksum(
            "jen-v5.2.6.tar.gz", "abc123def456", checksum_text
        ) is True

    def test_mismatched_checksum_returns_false(self, jen_update_root):
        checksum_text = "abc123def456  jen-v5.2.6.tar.gz\n"
        assert jen_update_root.verify_release_checksum(
            "jen-v5.2.6.tar.gz", "wronghash000", checksum_text
        ) is False

    def test_missing_entry_for_this_tarball_returns_false(self, jen_update_root):
        """A checksum file that exists but doesn't mention this exact
        tarball must fail closed, not pass through unverified."""
        checksum_text = "abc123def456  some-other-file.tar.gz\n"
        assert jen_update_root.verify_release_checksum(
            "jen-v5.2.6.tar.gz", "abc123def456", checksum_text
        ) is False

    def test_empty_checksum_file_returns_false(self, jen_update_root):
        assert jen_update_root.verify_release_checksum(
            "jen-v5.2.6.tar.gz", "abc123def456", ""
        ) is False

    def test_case_insensitive_hash_comparison(self, jen_update_root):
        checksum_text = "ABC123DEF456  jen-v5.2.6.tar.gz\n"
        assert jen_update_root.verify_release_checksum(
            "jen-v5.2.6.tar.gz", "abc123def456", checksum_text
        ) is True

    def test_malformed_lines_are_skipped_not_fatal(self, jen_update_root):
        checksum_text = "this line is malformed\nabc123def456  jen-v5.2.6.tar.gz\n"
        assert jen_update_root.verify_release_checksum(
            "jen-v5.2.6.tar.gz", "abc123def456", checksum_text
        ) is True


class TestInstallExtractedFiles:
    """Mirrors the exact scenarios the old (now-removed)
    TestSelfUpdateCopiesRunPy / TestSelfUpdateCopiesStaticAssets /
    TestSelfUpdatePreservesCustomFavicon / TestSelfUpdateCopiesChangelog
    classes covered, against install_extracted_files() directly instead
    of a generated shell script — this function performs real file
    operations against real temp directories, not string-matching on
    shell commands."""

    def _make_extracted_dir(self, tmp_path, with_static=True, with_service=True, with_sudoers=True):
        extracted = tmp_path / "extracted"
        (extracted / "jen").mkdir(parents=True)
        (extracted / "jen" / "__init__.py").write_text('JEN_VERSION = "5.2.6"\n')
        (extracted / "run.py").write_text("# fake run.py\n")
        (extracted / "CHANGELOG.md").write_text("# Changelog\n\n## [5.2.6] - 2026-01-01\n\nFake.\n")
        (extracted / "templates").mkdir()
        (extracted / "templates" / "index.html").write_text("<html></html>\n")
        if with_static:
            (extracted / "static" / "js").mkdir(parents=True)
            (extracted / "static" / "favicon.ico").write_bytes(b"SHIPPED-DEFAULT-FAVICON")
            (extracted / "static" / "js" / "htmx.min.js").write_text("// fake htmx\n")
        if with_service:
            (extracted / "jen.service").write_text("[Unit]\nDescription=fake\n")
        if with_sudoers:
            (extracted / "jen-sudoers").write_text(
                "www-data ALL=(root) NOPASSWD: /usr/bin/systemctl restart jen\n"
            )
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

    def test_static_copy_preserves_existing_favicon(self, jen_update_root, tmp_path):
        """v5.1.8's fix, now living in this script — a real uploaded
        favicon must survive a static/ update, not get overwritten by
        the shipped default."""
        extracted = self._make_extracted_dir(tmp_path, with_service=False, with_sudoers=False)
        install_dir = tmp_path / "install"
        (install_dir / "static").mkdir(parents=True)
        (install_dir / "static" / "favicon.ico").write_bytes(b"MATTHEWS-CUSTOM-FAVICON")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        assert (install_dir / "static" / "favicon.ico").read_bytes() == b"MATTHEWS-CUSTOM-FAVICON"
        assert (install_dir / "static" / "js" / "htmx.min.js").exists()

    def test_static_copy_installs_shipped_favicon_when_none_exists(self, jen_update_root, tmp_path):
        extracted = self._make_extracted_dir(tmp_path, with_service=False, with_sudoers=False)
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))
        assert (install_dir / "static" / "favicon.ico").read_bytes() == b"SHIPPED-DEFAULT-FAVICON"

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

        with patch("shutil.copy2") as mock_copy2, patch("os.chmod"), \
             patch("subprocess.run", side_effect=fake_run):
            jen_update_root.install_extracted_files(str(extracted), str(install_dir))

        visudo_calls = [c for c in calls if c[0] == "/usr/sbin/visudo"]
        assert len(visudo_calls) == 1
        sudoers_copy_calls = [c for c in mock_copy2.call_args_list if "jen-sudoers" in str(c)]
        assert len(sudoers_copy_calls) == 1, "sudoers file must be copied to /etc/sudoers.d/jen after passing validation"

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

        with patch("shutil.copy2") as mock_copy2, patch("os.chmod"), \
             patch("subprocess.run", side_effect=fake_run):
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
