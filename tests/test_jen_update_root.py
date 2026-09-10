"""
tests/test_jen_update_root.py
─────────────────────────────
v5.2.6 — tests for jen-update-root.py, the root-owned script that
performs the entire download → verify → build → switch pipeline that
used to live inside the self_update() Flask route (see
tests/test_self_update.py for why that mattered).

v5.14.0 — the script builds a whole release under
`/opt/jen/releases/<X.Y.Z>/{app,venv}` and the "install" is an atomic
`os.replace()` of the `/opt/jen/current` symlink. The rollback is
flipping that link back — the previous release directory is never
touched. The first run on a still-flat box ("migration run") has no
`current` symlink yet: it snapshots the flat tree, builds the versioned
layout, and on success removes the flat leftovers.

jen-update-root.py is a standalone script, not part of the jen/ package
(it must live outside every directory www-data can write to). It's
loaded here via importlib against its file path.
"""

import importlib.util
import io
import json
import os
import pathlib
import tarfile
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
    def test_script_exists_at_repo_root(self):
        assert _SCRIPT_PATH.exists(), "jen-update-root.py must exist at the repo root"

    def test_script_is_valid_python(self):
        import ast

        ast.parse(_SCRIPT_PATH.read_text())

    def test_script_never_accepts_command_line_arguments(self):
        """Core security property: this script must read NO input from its
        caller (www-data, via the systemd unit) at all — it always
        re-derives everything from GitHub itself."""
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
        checksum_text = "abc123def456  some-other-file.tar.gz\n"
        assert jen_update_root.verify_release_checksum("jen-v5.2.6.tar.gz", "abc123def456", checksum_text) is False

    def test_empty_checksum_file_returns_false(self, jen_update_root):
        assert jen_update_root.verify_release_checksum("jen-v5.2.6.tar.gz", "abc123def456", "") is False

    def test_case_insensitive_hash_comparison(self, jen_update_root):
        checksum_text = "ABC123DEF456  jen-v5.2.6.tar.gz\n"
        assert jen_update_root.verify_release_checksum("jen-v5.2.6.tar.gz", "abc123def456", checksum_text) is True

    def test_malformed_lines_are_skipped_not_fatal(self, jen_update_root):
        checksum_text = "garbage line with no structure\nabc123def456  jen-v5.2.6.tar.gz\n"
        assert jen_update_root.verify_release_checksum("jen-v5.2.6.tar.gz", "abc123def456", checksum_text) is True


def _make_release_tarball(tmp_path, *, version="5.2.6", extra=None, slip=False):
    """A tar.gz shaped like a real GitHub release archive: every path
    under a top-level `jen/` component. `_extract_release()` strips that
    component. `slip=True` adds a member that tries to escape."""
    root = tmp_path / "src"
    (root / "jen" / "jen").mkdir(parents=True)
    (root / "jen" / "jen" / "__init__.py").write_text(f'JEN_VERSION = "{version}"\n')
    (root / "jen" / "run.py").write_text("# run.py\n")
    (root / "jen" / "requirements.txt").write_text("")
    (root / "jen" / "CHANGELOG.md").write_text(f"## [{version}] - 2026-01-01\n")
    (root / "jen" / "templates").mkdir()
    (root / "jen" / "templates" / "base.html").write_text("<html></html>\n")
    (root / "jen" / "static").mkdir()
    (root / "jen" / "static" / "favicon.ico").write_bytes(b"ICON")
    (root / "jen" / "plugins" / "ipam").mkdir(parents=True)
    (root / "jen" / "plugins" / "ipam" / "manifest.json").write_text('{"id":"ipam"}')
    (root / "jen" / "jen.service").write_text("[Service]\nExecStart=x\n")
    (root / "jen" / "jen-sudoers").write_text("www-data ALL=(root) NOPASSWD: /usr/bin/systemctl restart jen\n")
    (root / "jen" / "jen-update-root.py").write_text("# v2 updater\n")
    (root / "jen" / "jen-update.service").write_text("[Unit]\nDescription=x\n")
    (root / "jen" / "jen-kea-helper").write_text("HELPER_VERSION = 1\n")
    for rel, body in (extra or {}).items():
        p = root / "jen" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)

    tarball = tmp_path / f"jen-v{version}.tar.gz"
    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(root / "jen", arcname="jen")
        if slip:
            info = tarfile.TarInfo("jen/../escape.txt")
            data = b"nope\n"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo("jen/evil-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tf.addfile(link)
    return tarball


class TestExtractRelease:
    """v5.14.0 — extraction IS the install now (into releases/<ver>/app),
    stripping the leading `jen/` path component."""

    def test_strips_the_jen_prefix_and_lays_out_app(self, jen_update_root, tmp_path):
        tarball = _make_release_tarball(tmp_path)
        dest = tmp_path / "releases" / "5.2.6.staging" / "app"
        jen_update_root._extract_release(str(tarball), str(dest))
        assert (dest / "jen" / "__init__.py").read_text() == 'JEN_VERSION = "5.2.6"\n'
        assert (dest / "run.py").exists()
        assert (dest / "templates" / "base.html").exists()
        assert (dest / "static" / "favicon.ico").exists()
        assert (dest / "plugins" / "ipam" / "manifest.json").exists()
        assert (dest / "jen.service").exists()
        assert (dest / "jen-sudoers").exists()
        assert (dest / "jen-update-root.py").exists()
        # nothing left with a doubled prefix
        assert not (dest / "jen" / "jen").exists() or (dest / "jen" / "jen" / "__init__.py").exists() is False

    def test_tar_slip_members_are_filtered(self, jen_update_root, tmp_path):
        tarball = _make_release_tarball(tmp_path, slip=True)
        dest = tmp_path / "app"
        jen_update_root._extract_release(str(tarball), str(dest))
        assert not (tmp_path / "escape.txt").exists()
        assert not (dest / "evil-link").exists()  # symlink member rejected (not a plain file/dir)
        assert (dest / "run.py").exists()


class TestInstallExternalFiles:
    """v5.14.0 — the file install of the app tree IS the extraction +
    symlink flip; install_external_files() only handles the two files a
    release ships that live OUTSIDE the release directory: jen.service
    and jen-sudoers. (jen-update-root.py / jen-update.service are
    install_self_update_files()'s job.)"""

    def _app_dir(self, tmp_path, with_service=True, with_sudoers=True):
        app = tmp_path / "release" / "app"
        app.mkdir(parents=True)
        if with_service:
            (app / "jen.service").write_text("[Service]\nExecStart=x\n")
        if with_sudoers:
            (app / "jen-sudoers").write_text("www-data ALL=(root) NOPASSWD: /usr/bin/systemctl restart jen\n")
        return app

    def test_service_file_installed_and_daemon_reloaded(self, jen_update_root, tmp_path):
        app = self._app_dir(tmp_path, with_sudoers=False)
        calls = []
        with (
            patch("shutil.copy2") as copy2,
            patch("subprocess.run", side_effect=lambda c, **k: calls.append(c) or MagicMock(returncode=0)),
        ):
            jen_update_root.install_external_files(str(app))
        assert any("jen.service" in str(c) for c in copy2.call_args_list)
        assert ["/usr/bin/systemctl", "daemon-reload"] in calls

    def test_valid_sudoers_installed_after_visudo_passes(self, jen_update_root, tmp_path):
        app = self._app_dir(tmp_path, with_service=False)

        def fake_run(cmd, **kw):
            return MagicMock(returncode=0, stderr="")

        with patch("shutil.copy2") as copy2, patch("os.chmod"), patch("subprocess.run", side_effect=fake_run):
            jen_update_root.install_external_files(str(app))
        assert any("jen-sudoers" in str(c) and "sudoers.d/jen" in str(c) for c in copy2.call_args_list)

    def test_invalid_sudoers_never_installed(self, jen_update_root, tmp_path):
        app = self._app_dir(tmp_path, with_service=False)

        def fake_run(cmd, **kw):
            if cmd[0] == "/usr/sbin/visudo":
                return MagicMock(returncode=1, stderr="syntax error")
            return MagicMock(returncode=0)

        with patch("shutil.copy2") as copy2, patch("os.chmod"), patch("subprocess.run", side_effect=fake_run):
            jen_update_root.install_external_files(str(app))
        assert not any("sudoers.d/jen" in str(c) for c in copy2.call_args_list)

    def test_missing_files_are_a_no_op(self, jen_update_root, tmp_path):
        app = self._app_dir(tmp_path, with_service=False, with_sudoers=False)
        with patch("subprocess.run") as run:
            jen_update_root.install_external_files(str(app))
        run.assert_not_called()

    def test_does_not_touch_the_app_tree(self, jen_update_root, tmp_path):
        """The whole point of the versioned layout: no copy of jen/,
        templates/, static/ anywhere — those live under app/ already."""
        src = _SCRIPT_PATH.read_text()
        i = src.index("def install_external_files(")
        body = src[i : src.index("\ndef ", i + 1)]
        assert "copytree" not in body
        assert "shutil.rmtree" not in body


class TestInstallSelfUpdateFiles:
    """v5.3.3 — a release also carries a new copy of THIS script and of
    jen-update.service; both get installed (atomically, safe while this
    script is the one running). os.chown is mocked (needs real root)."""

    def _extracted(self, tmp_path, script=b"# v2 updater\n", service=b"[Unit]\nDescription=v2\n"):
        extracted = tmp_path / "app"
        extracted.mkdir(exist_ok=True)
        (extracted / "jen-update-root.py").write_bytes(script)
        (extracted / "jen-update.service").write_bytes(service)
        return extracted

    def test_installs_new_script_content(self, jen_update_root, tmp_path):
        extracted = self._extracted(tmp_path)
        dest = tmp_path / "sbin" / "jen-update-root.py"
        dest.parent.mkdir()
        with patch("os.chown"), patch("subprocess.run", return_value=MagicMock(returncode=0)):
            jen_update_root.install_self_update_files(
                str(extracted), self_install_path=str(dest), update_service_path=str(tmp_path / "jen-update.service")
            )
        assert dest.read_bytes() == b"# v2 updater\n"

    def test_installed_script_is_mode_0700(self, jen_update_root, tmp_path):
        extracted = self._extracted(tmp_path)
        dest = tmp_path / "sbin" / "jen-update-root.py"
        dest.parent.mkdir()
        with patch("os.chown") as chown, patch("subprocess.run", return_value=MagicMock(returncode=0)):
            jen_update_root.install_self_update_files(
                str(extracted), self_install_path=str(dest), update_service_path=str(tmp_path / "jen-update.service")
            )
        script_chowns = [c for c in chown.call_args_list if ".jen-update-root-" in c[0][0]]
        assert script_chowns and script_chowns[0][0][1:] == (0, 0)
        assert os.stat(dest).st_mode & 0o777 == 0o700

    def test_service_file_installed_mode_0644_and_daemon_reload(self, jen_update_root, tmp_path):
        extracted = self._extracted(tmp_path)
        (tmp_path / "sbin").mkdir()
        svc = tmp_path / "jen-update.service"
        calls = []
        with (
            patch("os.chown"),
            patch("subprocess.run", side_effect=lambda c, **k: calls.append(c) or MagicMock(returncode=0)),
        ):
            jen_update_root.install_self_update_files(
                str(extracted), self_install_path=str(tmp_path / "sbin" / "u.py"), update_service_path=str(svc)
            )
        assert svc.read_bytes() == b"[Unit]\nDescription=v2\n"
        assert os.stat(svc).st_mode & 0o777 == 0o644
        assert ["/usr/bin/systemctl", "daemon-reload"] in calls

    def test_uses_atomic_replace(self, jen_update_root, tmp_path):
        extracted = self._extracted(tmp_path)
        dest = tmp_path / "sbin" / "jen-update-root.py"
        dest.parent.mkdir()
        dest.write_bytes(b"# old\n")
        with (
            patch("os.chown"),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
            patch("os.replace", side_effect=os.replace) as repl,
        ):
            jen_update_root.install_self_update_files(
                str(extracted), self_install_path=str(dest), update_service_path=str(tmp_path / "svc")
            )
        assert repl.called
        assert dest.read_bytes() == b"# v2 updater\n"

    def test_missing_files_do_not_crash(self, jen_update_root, tmp_path):
        extracted = tmp_path / "app"
        extracted.mkdir()
        dest = tmp_path / "sbin" / "u.py"
        dest.parent.mkdir()
        dest.write_bytes(b"# untouched\n")
        with patch("os.chown"), patch("subprocess.run") as run:
            jen_update_root.install_self_update_files(
                str(extracted), self_install_path=str(dest), update_service_path=str(tmp_path / "svc")
            )
        assert dest.read_bytes() == b"# untouched\n"
        run.assert_not_called()

    def test_main_calls_it_after_install_external_files(self, jen_update_root):
        import inspect

        src = inspect.getsource(jen_update_root.main)
        assert src.index("install_external_files(") < src.index("install_self_update_files(")


class TestInstallPythonDependencies:
    def test_runs_pip_install_against_the_given_requirements(self, jen_update_root, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("gunicorn>=26.0.0\n")
        with patch("subprocess.run", return_value=MagicMock(returncode=0, stderr="")) as run:
            ok = jen_update_root.install_python_dependencies(str(req), "/opt/jen/releases/x/venv/bin/python")
        assert ok is True
        joined = " ".join(str(c) for c in run.call_args_list)
        assert "pip" in joined and "install" in joined and str(req) in joined

    def test_venv_python_does_not_get_break_system_packages(self, jen_update_root, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=3.1\n")
        with patch("subprocess.run", return_value=MagicMock(returncode=0, stderr="")) as run:
            jen_update_root.install_python_dependencies(str(req), "/opt/jen/releases/x/venv/bin/python")
        assert "--break-system-packages" not in " ".join(str(c) for c in run.call_args_list)

    def test_system_python_gets_break_system_packages(self, jen_update_root, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=3.1\n")
        with patch("subprocess.run", return_value=MagicMock(returncode=0, stderr="")) as run:
            jen_update_root.install_python_dependencies(str(req), jen_update_root.SYSTEM_PYTHON)
        assert "--break-system-packages" in " ".join(str(c) for c in run.call_args_list)

    def test_missing_requirements_file_is_a_no_op_success(self, jen_update_root, tmp_path):
        with patch("subprocess.run") as run:
            ok = jen_update_root.install_python_dependencies(str(tmp_path / "nope.txt"), "/x/python")
        run.assert_not_called()
        assert ok is True

    def test_pip_failure_returns_false_and_does_not_raise(self, jen_update_root, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("gunicorn>=26.0.0\n")
        with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr="boom", stdout="")):
            ok = jen_update_root.install_python_dependencies(str(req), "/opt/jen/releases/x/venv/bin/python")
        assert ok is False


class TestVenvUsable:
    def test_needs_a_working_pip_not_just_a_runnable_python(self, jen_update_root):
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            return MagicMock(returncode=0 if argv[1:] == ["-c", ""] else 1)

        with patch("subprocess.run", side_effect=fake_run):
            assert jen_update_root._venv_usable("/x/venv/bin/python") is False
        assert any("pip" in a for a in calls[-1])


class TestBuildReleaseVenv:
    """v5.14.0 — every update builds a fresh per-release venv. No 'is the
    existing one usable' shortcut (the path is brand new). Reuses the
    apt-get python3-venv recovery the pre-5.14 ensure_venv() had."""

    def test_returns_the_venv_python_on_success(self, jen_update_root, tmp_path):
        venv = tmp_path / "releases" / "x" / "venv"
        with patch.object(jen_update_root, "_try_build_venv", return_value=True) as build:
            out = jen_update_root._build_release_venv(str(venv))
        assert out == str(venv / "bin" / "python")
        build.assert_called_once()

    def test_returns_none_when_a_venv_cannot_be_built(self, jen_update_root, tmp_path):
        with (
            patch.object(jen_update_root, "_try_build_venv", return_value=False),
            patch("subprocess.run", return_value=MagicMock(returncode=1, stderr="nope", stdout="")),
        ):
            assert jen_update_root._build_release_venv(str(tmp_path / "venv")) is None

    def test_apt_installs_python3_venv_then_retries(self, jen_update_root, tmp_path):
        venv = tmp_path / "venv"
        apt_calls = []

        def fake_run(argv, **kw):
            if "apt-get" in argv[0]:
                apt_calls.append(argv)
            return MagicMock(returncode=0)

        with (
            patch.object(jen_update_root, "_try_build_venv", side_effect=[False, True]),
            patch("subprocess.run", side_effect=fake_run),
        ):
            out = jen_update_root._build_release_venv(str(venv))
        assert out == str(venv / "bin" / "python")
        assert apt_calls and "python3-venv" in apt_calls[0]

    def test_apt_get_update_then_one_more_retry(self, jen_update_root, tmp_path):
        venv = tmp_path / "venv"
        runs = iter(
            [
                MagicMock(returncode=1, stderr="Unable to locate package", stdout=""),  # install #1
                MagicMock(returncode=0, stderr="", stdout=""),  # apt-get update
                MagicMock(returncode=0, stderr="", stdout=""),  # install #2
            ]
        )
        seen = []

        def fake_run(argv, **kw):
            seen.append(" ".join(argv))
            return next(runs)

        with (
            patch.object(jen_update_root, "_try_build_venv", side_effect=[False, True]),
            patch("subprocess.run", side_effect=fake_run),
        ):
            out = jen_update_root._build_release_venv(str(venv))
        assert out == str(venv / "bin" / "python")
        assert any("apt-get update" in c for c in seen), seen

    def test_staging_tree_is_chowned_root_in_main(self, jen_update_root):
        """A www-data-writable app tree or venv is a persistence foothold
        (module docstring / ARCHITECTURE §6). The whole staging dir is
        chowned root:root before the switch."""
        import inspect

        src = inspect.getsource(jen_update_root.main)
        assert '"/bin/chown", "-R", "root:root", staging' in src
        # main() itself only ever chowns things to root:root — the one
        # www-data chown lives in migrate_user_content (CONTENT_DIR).
        assert '"root:root", staging' in src
        assert '"www-data:www-data", staging' not in src


class TestValidateStagedRelease:
    def _staged(self, tmp_path):
        root = tmp_path / "staged"
        (root / "jen").mkdir(parents=True)
        (root / "jen" / "__init__.py").write_text('JEN_VERSION = "9.9.9"\n')
        return root

    def test_true_when_compile_and_import_both_succeed(self, jen_update_root, tmp_path):
        root = self._staged(tmp_path)
        with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
            assert jen_update_root.validate_staged_release(str(root), "/x/python") is True

    def test_false_when_compile_fails(self, jen_update_root, tmp_path):
        root = self._staged(tmp_path)
        with patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="SyntaxError", stderr="")):
            assert jen_update_root.validate_staged_release(str(root), "/x/python") is False

    def test_false_when_import_fails(self, jen_update_root, tmp_path):
        root = self._staged(tmp_path)
        with patch("subprocess.run") as run:
            run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=1, stdout="", stderr="ModuleNotFoundError: newdep"),
            ]
            assert jen_update_root.validate_staged_release(str(root), "/x/python") is False


class TestSwitchCurrent:
    """v5.14.0 — the atomic install: os.replace() of the `current`
    symlink, RELATIVE target so /opt/jen can be bind-mounted."""

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need a privilege on Windows")
    def test_creates_a_relative_symlink_atomically(self, jen_update_root, tmp_path):
        (tmp_path / "releases" / "5.14.0").mkdir(parents=True)
        current = tmp_path / "current"
        jen_update_root._switch_current("5.14.0", current_link=str(current))
        assert os.path.islink(current)
        assert os.readlink(current) == os.path.join("releases", "5.14.0")

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need a privilege on Windows")
    def test_replaces_an_existing_link_without_a_gap(self, jen_update_root, tmp_path):
        (tmp_path / "releases" / "a").mkdir(parents=True)
        (tmp_path / "releases" / "b").mkdir(parents=True)
        current = tmp_path / "current"
        jen_update_root._switch_current("a", current_link=str(current))
        jen_update_root._switch_current("b", current_link=str(current))
        assert os.readlink(current) == os.path.join("releases", "b")
        assert not (tmp_path / "current.tmp").exists()

    def test_uses_os_replace_not_remove_then_symlink(self, jen_update_root):
        import inspect

        src = inspect.getsource(jen_update_root._switch_current)
        assert "os.replace(" in src
        assert "os.remove(current_link)" not in src


class TestInstalledVersion:
    def test_prefers_current_app_then_flat(self, jen_update_root, tmp_path, monkeypatch):
        current = tmp_path / "current"
        flat = tmp_path / "opt-jen"
        (flat / "jen").mkdir(parents=True)
        (flat / "jen" / "__init__.py").write_text('JEN_VERSION = "5.13.0"\n')
        monkeypatch.setattr(jen_update_root, "CURRENT_LINK", str(current))
        monkeypatch.setattr(jen_update_root, "INSTALL_DIR", str(flat))
        assert jen_update_root._installed_version() == "5.13.0"  # flat fallback

        (current / "app" / "jen").mkdir(parents=True)
        (current / "app" / "jen" / "__init__.py").write_text('JEN_VERSION = "5.14.0"\n')
        assert jen_update_root._installed_version() == "5.14.0"  # versioned wins

    def test_question_mark_when_neither_exists(self, jen_update_root, tmp_path, monkeypatch):
        monkeypatch.setattr(jen_update_root, "CURRENT_LINK", str(tmp_path / "current"))
        monkeypatch.setattr(jen_update_root, "INSTALL_DIR", str(tmp_path / "nope"))
        assert jen_update_root._installed_version() == "?"


class TestPruneOldReleases:
    def _layout(self, tmp_path):
        rel = tmp_path / "releases"
        rel.mkdir()
        return rel

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need a privilege on Windows")
    def test_keeps_current_plus_newest_other_plus_keep_marked(self, jen_update_root, tmp_path):
        rel = self._layout(tmp_path)
        for name in ("5.11.0", "5.12.0", "5.13.0", "5.14.0"):
            (rel / name).mkdir()
        (rel / "5.10.0").mkdir()
        (rel / "5.10.0" / jen_update_root.KEEP_MARKER).write_text("recover me")
        # make 5.14.0 newest, then 5.13.0, ...
        import time as _t

        for i, name in enumerate(("5.10.0", "5.11.0", "5.12.0", "5.13.0", "5.14.0")):
            os.utime(rel / name, (_t.time() + i, _t.time() + i))
        current = tmp_path / "current"
        os.symlink(os.path.join("releases", "5.14.0"), current)

        jen_update_root._prune_old_releases(
            releases_dir=str(rel), current_link=str(current), install_dir=str(tmp_path / "no-flat")
        )
        left = sorted(p.name for p in rel.iterdir())
        assert "5.14.0" in left  # current
        assert "5.13.0" in left  # newest other
        assert "5.10.0" in left  # .keep
        assert "5.11.0" not in left and "5.12.0" not in left

    def test_removes_failed_marked_and_old_staging(self, jen_update_root, tmp_path):
        rel = self._layout(tmp_path)
        (rel / "5.14.0").mkdir()
        (rel / "5.13.0").mkdir()
        (rel / "5.13.0" / ".failed").write_text("bad")
        staging_old = rel / "5.14.1.staging-1"
        staging_old.mkdir()
        os.utime(staging_old, (1_000_000, 1_000_000))  # ancient
        jen_update_root._prune_old_releases(
            releases_dir=str(rel), current_link=str(tmp_path / "current"), install_dir=str(tmp_path / "no-flat")
        )
        left = sorted(p.name for p in rel.iterdir())
        assert "5.13.0" not in left  # .failed
        assert "5.14.1.staging-1" not in left  # old staging
        assert "5.14.0" in left

    def test_also_sweeps_legacy_rollback_dirs_in_install_dir(self, jen_update_root, tmp_path):
        flat = tmp_path / "opt-jen"
        flat.mkdir()
        for ts in ("1", "2", "3"):
            (flat / f".rollback-{ts}").mkdir()
        (flat / ".rollback-2" / jen_update_root.KEEP_MARKER).write_text("kept")
        jen_update_root._prune_old_releases(
            releases_dir=str(tmp_path / "releases"), current_link=str(tmp_path / "current"), install_dir=str(flat)
        )
        left = sorted(p.name for p in flat.iterdir() if p.name.startswith(".rollback-"))
        assert left == [".rollback-2", ".rollback-3"]  # newest + .keep survive


class TestSnapshotRollbackMigrationRun:
    """snapshot_install()/restore_snapshot() survive as the MIGRATION
    run's rollback: a still-flat box that fails the switch to the
    versioned layout goes back to exactly the flat tree it started
    from."""

    def test_snapshot_then_restore_round_trips_flat_items(self, jen_update_root, tmp_path):
        install = tmp_path / "opt-jen"
        (install / "jen").mkdir(parents=True)
        (install / "jen" / "app.py").write_text("v1\n")
        (install / "run.py").write_text("run-v1\n")
        (install / "static").mkdir()
        (install / "static" / "favicon.ico").write_text("v1-icon\n")
        (install / "jen-kea-helper").write_text("HELPER_VERSION = 1\n")
        snap = tmp_path / "snap"
        jen_update_root.snapshot_install(str(snap), install_dir=str(install))

        (install / "jen" / "app.py").write_text("v2-broken\n")
        (install / "static" / "favicon.ico").write_text("v2\n")
        (install / "jen-kea-helper").write_text("HELPER_VERSION = 2\n")
        with patch("subprocess.run"):
            jen_update_root.restore_snapshot(
                str(snap), install_dir=str(install), current_link=str(tmp_path / "current")
            )
        assert (install / "jen" / "app.py").read_text() == "v1\n"
        assert (install / "static" / "favicon.ico").read_text() == "v1-icon\n"
        assert (install / "jen-kea-helper").read_text() == "HELPER_VERSION = 1\n"

    def test_restore_drops_a_half_made_current_symlink(self, jen_update_root, tmp_path):
        install = tmp_path / "opt-jen"
        (install / "jen").mkdir(parents=True)
        snap = tmp_path / "snap"
        jen_update_root.snapshot_install(str(snap), install_dir=str(install))
        current = tmp_path / "current"
        try:
            os.symlink(str(tmp_path / "whatever"), str(current))
        except (OSError, NotImplementedError):
            pytest.skip("symlinks need a privilege on Windows")
        with patch("subprocess.run"):
            jen_update_root.restore_snapshot(str(snap), install_dir=str(install), current_link=str(current))
        assert not os.path.lexists(current)

    def test_restore_restarts_jen_and_chowns_root(self, jen_update_root, tmp_path):
        install = tmp_path / "opt-jen"
        (install / "jen").mkdir(parents=True)
        snap = tmp_path / "snap"
        jen_update_root.snapshot_install(str(snap), install_dir=str(install))
        with patch("subprocess.run") as run:
            jen_update_root.restore_snapshot(
                str(snap), install_dir=str(install), current_link=str(tmp_path / "current")
            )
        calls = [" ".join(map(str, c.args[0])) for c in run.call_args_list]
        assert any("systemctl restart jen" in c for c in calls)
        chowns = [c.args[0] for c in run.call_args_list if c.args[0][0] == "/bin/chown"]
        assert chowns and all("www-data:www-data" not in c for c in chowns)

    def test_snapshot_covers_the_external_unit_files(self, jen_update_root, tmp_path):
        install = tmp_path / "opt-jen"
        (install / "jen").mkdir(parents=True)
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
            unit.write_text("[Service]\nExecStart=BROKEN\n")
            with patch("subprocess.run") as run:
                jen_update_root.restore_snapshot(
                    str(snap), install_dir=str(install), current_link=str(tmp_path / "current")
                )
        assert unit.read_text() == "[Service]\nExecStart=good\n"
        calls = [" ".join(map(str, c.args[0])) for c in run.call_args_list]
        assert any("daemon-reload" in c for c in calls)

    @pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs a privilege on Windows")
    def test_snapshot_copies_a_dangling_symlink_instead_of_dying(self, jen_update_root, tmp_path):
        """v5.8.4 — a stray `/opt/jen/templates/templates -> (gone)` used to
        make copytree raise ENOENT at the snapshot step."""
        install = tmp_path / "opt-jen"
        (install / "templates").mkdir(parents=True)
        (install / "templates" / "index.html").write_text("ok\n")
        os.symlink(str(tmp_path / "does-not-exist"), str(install / "templates" / "templates"))
        snap = tmp_path / "snap"
        jen_update_root.snapshot_install(str(snap), install_dir=str(install))
        assert (snap / "templates" / "index.html").read_text() == "ok\n"
        assert os.path.islink(snap / "templates" / "templates")

    def test_helper_and_static_and_plugins_are_flat_rollback_items(self, jen_update_root):
        for item in ("jen-kea-helper", "static", "plugins", "jen", "run.py"):
            assert item in jen_update_root._ROLLBACK_ITEMS
        assert "venv" in jen_update_root._FLAT_LEFTOVERS


class TestRemoveFlatLeftovers:
    def test_removes_the_flat_app_tree_and_venv(self, jen_update_root, tmp_path):
        flat = tmp_path / "opt-jen"
        (flat / "jen").mkdir(parents=True)
        (flat / "run.py").write_text("x\n")
        (flat / "static").mkdir()
        (flat / "venv" / "bin").mkdir(parents=True)
        (flat / "jen-kea-helper").write_text("x\n")
        (flat / "releases").mkdir()
        (flat / ".rollback-1").mkdir()
        jen_update_root._remove_flat_leftovers(install_dir=str(flat))
        assert not (flat / "jen").exists()
        assert not (flat / "run.py").exists()
        assert not (flat / "venv").exists()
        assert not (flat / "jen-kea-helper").exists()
        # left alone
        assert (flat / "releases").exists()
        assert (flat / ".rollback-1").exists()


class TestRollbackRelease:
    @pytest.mark.skipif(os.name == "nt", reason="symlinks need a privilege on Windows")
    def test_steady_state_flips_current_back_to_prev(self, jen_update_root, tmp_path, monkeypatch):
        rel = tmp_path / "releases"
        (rel / "5.13.0").mkdir(parents=True)
        (rel / "5.14.0" / "app").mkdir(parents=True)
        current = tmp_path / "current"
        os.symlink(os.path.join("releases", "5.14.0"), current)
        snap = tmp_path / "snap"
        (snap / "_ext").mkdir(parents=True)
        monkeypatch.setattr(jen_update_root, "CURRENT_LINK", str(current))
        monkeypatch.setattr(jen_update_root, "RELEASES_DIR", str(rel))
        monkeypatch.setattr(jen_update_root, "service_healthy", lambda *a, **k: True)
        with patch("subprocess.run"):
            jen_update_root._rollback_release(str(snap), "5.13.0", False, "5.14.0", str(rel / "5.14.0"))
        assert os.readlink(current) == os.path.join("releases", "5.13.0")
        assert (rel / "5.14.0" / ".failed").exists()

    def test_migration_run_calls_restore_snapshot(self, jen_update_root, tmp_path, monkeypatch):
        snap = tmp_path / "snap"
        (snap / "_ext").mkdir(parents=True)
        monkeypatch.setattr(jen_update_root, "service_healthy", lambda *a, **k: True)
        called = {}
        monkeypatch.setattr(jen_update_root, "restore_snapshot", lambda *a, **k: called.setdefault("yes", True))
        with patch("subprocess.run"):
            jen_update_root._rollback_release(str(snap), None, True, "5.14.0", str(tmp_path / "rel" / "5.14.0"))
        assert called.get("yes")

    def test_critical_path_keeps_recovery_artefacts(self, jen_update_root, tmp_path, monkeypatch):
        rel = tmp_path / "releases"
        (rel / "5.13.0").mkdir(parents=True)
        (rel / "5.14.0").mkdir()
        current = tmp_path / "current"
        snap = tmp_path / "snap"
        (snap / "_ext").mkdir(parents=True)
        monkeypatch.setattr(jen_update_root, "CURRENT_LINK", str(current))
        monkeypatch.setattr(jen_update_root, "RELEASES_DIR", str(rel))
        monkeypatch.setattr(jen_update_root, "service_healthy", lambda *a, **k: False)  # rollback restart unhealthy
        with patch("subprocess.run"):
            jen_update_root._rollback_release(str(snap), "5.13.0", False, "5.14.0", str(rel / "5.14.0"))
        assert (snap / jen_update_root.KEEP_MARKER).exists()
        assert (rel / "5.13.0" / jen_update_root.KEEP_MARKER).exists()


class TestMigrateUserContent:
    """v5.13.0 — MOVE pre-5.13 content from the /opt/jen tree into /var/lib/jen."""

    def _tree(self, tmp_path):
        install = tmp_path / "opt-jen"
        content = tmp_path / "var-lib-jen"
        extracted = tmp_path / "app"
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
        assert not (install / "static" / "icons" / "custom" / "acme.svg").exists()
        assert (content / "branding" / "nav_logo.png").exists()
        assert (content / "backups" / "jen.json.gz").exists()
        assert (content / "keys" / ".secret_key").read_text() == "k" * 40

    def test_favicon_only_when_differs_from_shipped(self, jen_update_root, tmp_path):
        install, content, extracted = self._tree(tmp_path)
        (install / "static" / "favicon.ico").write_bytes(b"SHIPPED-DEFAULT")
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
        assert (content / "plugins-enabled" / "ipam").exists()
        assert (content / "plugins-enabled" / "thirdparty").exists()
        assert (content / "plugins" / "thirdparty" / "manifest.json").exists()
        assert not (content / "plugins" / "ipam").exists()

    def test_idempotent(self, jen_update_root, tmp_path):
        install, content, extracted = self._tree(tmp_path)
        (install / "static" / "icons" / "custom" / "acme.svg").write_text("<svg/>")
        self._run(jen_update_root, install, content, extracted)
        self._run(jen_update_root, install, content, extracted)
        assert (content / "icons" / "acme.svg").exists()

    def test_main_calls_migrate_only_on_the_migration_run_before_the_rename(self):
        src = _SCRIPT_PATH.read_text()
        i_mig = src.index("migrate_user_content(INSTALL_DIR, CONTENT_DIR, staging_app)")
        i_rename = src.index("os.rename(staging, release_dir)")
        assert i_mig < i_rename
        # guarded by `if migration_run:`
        assert "if migration_run:\n                migrate_user_content(" in src


class TestMainSourceShape:
    """The update flow is orchestration over network I/O — verified here
    by inspecting main()'s source for the ordering guarantees that
    matter, the same way the pre-5.14 suite did."""

    def _main(self, jen_update_root):
        import inspect

        return inspect.getsource(jen_update_root.main)

    def test_prunes_before_touching_github(self, jen_update_root):
        src = self._main(jen_update_root)
        assert src.index("_prune_old_releases()") < src.index("fetch_json(")

    def test_builds_venv_and_validates_before_any_switch(self, jen_update_root):
        src = self._main(jen_update_root)
        i_venv = src.index("_build_release_venv(staging_venv)")
        i_deps = src.index("install_python_dependencies(")
        i_valid = src.index("validate_staged_release(staging_app")
        i_switch = src.index("_switch_current(version)")
        assert i_venv < i_deps < i_valid < i_switch

    def test_probe_baseline_is_before_the_snapshot_and_aborts_clean(self, jen_update_root):
        src = self._main(jen_update_root)
        i_probe = src.index("_probe_once(_local_opener(), probe_url)")
        i_snap = src.index("snapshot_install(snapshot_dir)")
        assert src.index("validate_staged_release(staging_app") < i_probe < i_snap
        after = src[i_probe : i_probe + 700]
        assert "Aborting before the switch" in after and "return 1" in after

    def test_snapshot_failure_aborts_without_except_exception(self, jen_update_root):
        src = self._main(jen_update_root)
        i = src.index("snapshot_install(snapshot_dir)")
        after = src[i : i + 600]
        assert "except (OSError, shutil.Error)" in after
        assert "/opt/jen untouched" in after and "return 1" in after

    def test_switch_region_is_inside_a_rollback_try_except(self, jen_update_root):
        src = self._main(jen_update_root)
        region = src[src.index("snapshot_install(snapshot_dir)") : src.rindex("return 0")]
        assert "try:" in region and "except Exception" in region
        assert "_rollback_release(snapshot_dir" in region
        for anchor in ("os.rename(staging, release_dir)", "_switch_current(version)", "install_external_files("):
            assert region.index(anchor) < region.index("except Exception")

    def test_compiles_staged_tree_with_the_release_interpreter(self, jen_update_root):
        src = self._main(jen_update_root)
        region = src[src.index("_build_release_venv") : src.index("validate_staged_release")]
        assert 'os.path.join(staging_app, d) for d in ("jen", "plugins")' in region
        assert 'compileall", "-q", *_compile_targets' in region

    def test_confirms_running_version_and_removes_flat_leftovers_on_migration_success(self, jen_update_root):
        src = self._main(jen_update_root)
        region = src[src.index("snapshot_install(snapshot_dir)") : src.rindex("return 0")]
        assert "_confirm_running_version(version)" in region
        assert region.index("_confirm_running_version(version)") < region.index("except Exception")
        assert "_remove_flat_leftovers()" in region
        assert "_installed_version(), " not in region

    def test_critical_path_marks_keep_in_rollback_release(self, jen_update_root):
        import inspect

        src = inspect.getsource(jen_update_root._rollback_release)
        i = src.index("CRITICAL: rollback restart also unhealthy")
        assert "KEEP_MARKER" in src[i - 800 : i]

    def test_exits_zero_without_downloading_when_already_current(self, jen_update_root):
        with (
            patch.object(jen_update_root, "fetch_json", return_value={"tag_name": "v9.9.9", "assets": []}),
            patch.object(jen_update_root, "_installed_version", return_value="9.9.9"),
            patch.object(jen_update_root, "_prune_old_releases"),
            patch.object(jen_update_root, "fetch_bytes_with_sha256") as download,
        ):
            assert jen_update_root.main() == 0
        download.assert_not_called()


def _self_signed_cert(tmp_path, cn="jen.example.com"):
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
        with patch("subprocess.run", return_value=MagicMock(returncode=1)), patch("time.sleep"):
            assert jen_update_root.service_healthy(timeout=0.01) is False

    def test_http_302_to_login_counts_as_healthy(self, jen_update_root, monkeypatch):
        port, stop = _serve(_AppLike.handler())
        try:
            monkeypatch.setattr(jen_update_root, "_ssl_enabled", lambda: False)
            monkeypatch.setattr(jen_update_root, "_server_cfg", lambda k, f: port if k == "http_port" else f)
            with patch("subprocess.run", return_value=MagicMock(returncode=0)), patch("time.sleep"):
                assert jen_update_root.service_healthy(timeout=5) is True
        finally:
            stop()

    def test_ssl_install_probes_https_port_and_ignores_a_wrong_cn_cert(self, jen_update_root, tmp_path, monkeypatch):
        crt, key = _self_signed_cert(tmp_path)
        https_port, stop_https = _serve(_AppLike.handler(), certfile=crt, keyfile=key)
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
        assert jen_update_root._ssl_enabled() is False
        (tmp_path / "private.key").write_text("x")
        assert jen_update_root._ssl_enabled() is True


class TestRunningVersion:
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


class TestConfirmRunningVersion:
    def test_retries_then_accepts(self, jen_update_root):
        with (
            patch.object(jen_update_root, "_running_version", side_effect=[None, None, "9.9.9"]),
            patch("time.sleep") as slp,
        ):
            assert jen_update_root._confirm_running_version("9.9.9", attempts=5, delay=3) == "9.9.9"
        assert slp.call_count == 2

    def test_fails_instead_of_trusting_disk(self, jen_update_root):
        with (
            patch.object(jen_update_root, "_running_version", return_value=None),
            patch.object(jen_update_root, "_installed_version", return_value="9.9.9"),
            patch("time.sleep"),
            pytest.raises(RuntimeError, match="only\\s+proves the files were copied"),
        ):
            jen_update_root._confirm_running_version("9.9.9", attempts=3, delay=0)

    def test_mismatch_fails_immediately(self, jen_update_root):
        with (
            patch.object(jen_update_root, "_running_version", return_value="1.0.0"),
            patch("time.sleep") as slp,
            pytest.raises(RuntimeError, match="mismatch"),
        ):
            jen_update_root._confirm_running_version("9.9.9")
        slp.assert_not_called()
