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

import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tarfile
import zipfile
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

    def test_script_never_accepts_free_form_command_line_arguments(self):
        """Core security property: this script reads NO free-form input
        from its caller (www-data, via a systemd unit) — it always
        re-derives everything from GitHub itself. v5.27.0 (Q23) carved
        out exactly ONE pinned exception: `sys.argv[1:] == ["--plugins"]`
        dispatches to the plugin-install flow, and that's safe only
        because jen-sudoers pins the entire invocation byte-for-byte —
        www-data can request that this script run with EXACTLY that one
        argv, never an attacker-chosen one. No general argument parser,
        and no other argv value is ever consulted."""
        content = _SCRIPT_PATH.read_text()
        assert "argparse" not in content
        assert 'sys.argv[1:] == ["--plugins"]' in content


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


class TestVerifyReleaseSignature:
    """v5.26.0 (Q22) — real ssh-keygen subprocess calls against a
    throwaway key generated fresh per test, never the production
    RELEASE_SIGNERS key. openssh-client (ssh-keygen) ships on every
    target OS this already assumes (CI runners, Jen hosts, this dev
    box) — no mocking needed or wanted for a security-relevant check
    like this."""

    @pytest.fixture
    def keypair(self, tmp_path):
        import subprocess as _subprocess

        key_path = tmp_path / "throwaway-key"
        _subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-C", "release@jen", "-f", str(key_path), "-N", "", "-q"],
            check=True,
        )
        pub_line = key_path.with_suffix(".pub").read_text().strip()
        # "<type> <base64> <comment>" -> "<comment> <type> <base64>",
        # the allowed-signers line shape verify_release_signature expects.
        parts = pub_line.split()
        signers_text = f"{parts[2]} {parts[0]} {parts[1]}"
        return str(key_path), signers_text

    def _sign(self, key_path, tmp_path, sums_text, namespace="jen-release"):
        import subprocess as _subprocess

        # write_bytes, not write_text: on Windows, text-mode writes
        # translate "\n" to "\r\n", so the bytes ssh-keygen actually
        # signs on disk would silently differ from `sums_text` as
        # verify_release_signature receives it — a real signature
        # mismatch, not a bug in the function under test.
        sums_path = tmp_path / "SHA256SUMS"
        sums_path.write_bytes(sums_text.encode())
        _subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", key_path, "-n", namespace, str(sums_path)],
            check=True,
            capture_output=True,
        )
        return sums_path.with_name(sums_path.name + ".sig").read_bytes()

    def test_valid_signature_verifies(self, jen_update_root, keypair, tmp_path):
        key_path, signers_text = keypair
        sums_text = "abc123def456  jen-v5.26.0.tar.gz\n"
        sig_bytes = self._sign(key_path, tmp_path, sums_text)
        assert jen_update_root.verify_release_signature(sums_text, sig_bytes, signers_text) is True

    def test_tampered_sums_fails(self, jen_update_root, keypair, tmp_path):
        key_path, signers_text = keypair
        sig_bytes = self._sign(key_path, tmp_path, "abc123def456  jen-v5.26.0.tar.gz\n")
        assert jen_update_root.verify_release_signature("tampered content\n", sig_bytes, signers_text) is False

    def test_wrong_namespace_fails(self, jen_update_root, keypair, tmp_path):
        key_path, signers_text = keypair
        sums_text = "abc123def456  jen-v5.26.0.tar.gz\n"
        sig_bytes = self._sign(key_path, tmp_path, sums_text, namespace="something-else")
        assert jen_update_root.verify_release_signature(sums_text, sig_bytes, signers_text) is False

    def test_unrelated_key_fails(self, jen_update_root, keypair, tmp_path):
        # Signed with a genuinely different key than the one named in
        # signers_text — not just a corrupted signature.
        _, signers_text = keypair
        import subprocess as _subprocess

        other_key = tmp_path / "other-key"
        _subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-C", "release@jen", "-f", str(other_key), "-N", "", "-q"],
            check=True,
        )
        sums_text = "abc123def456  jen-v5.26.0.tar.gz\n"
        sig_bytes = self._sign(str(other_key), tmp_path, sums_text)
        assert jen_update_root.verify_release_signature(sums_text, sig_bytes, signers_text) is False

    def test_garbage_signature_bytes_fails_not_raises(self, jen_update_root, keypair):
        _, signers_text = keypair
        assert jen_update_root.verify_release_signature("data\n", b"not a real signature", signers_text) is False

    def test_real_release_signers_constant_is_a_well_formed_allowed_signers_line(self, jen_update_root):
        parts = jen_update_root.RELEASE_SIGNERS.split()
        assert len(parts) == 3
        assert parts[0] == jen_update_root.RELEASE_SIGNATURE_IDENTITY
        assert parts[1] == "ssh-ed25519"


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

    def test_signature_is_verified_before_the_tarball_download(self, jen_update_root):
        """v5.26.0 (Q22) — the pinned test: a missing/invalid signature
        must abort before the (large) tarball download even starts."""
        src = self._main(jen_update_root)
        i_sig_check = src.index("verify_release_signature(")
        i_download = src.index("fetch_bytes_with_sha256(asset_url)")
        assert i_sig_check < i_download

    def test_missing_signature_asset_aborts(self, jen_update_root):
        src = self._main(jen_update_root)
        i_sig_url = src.index('sig_asset_url = ""')
        i_download = src.index("fetch_bytes_with_sha256(asset_url)")
        region = src[i_sig_url:i_download]
        assert "if not sig_asset_url:" in region
        assert "return 1" in region

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
            patch.object(jen_update_root.sys, "argv", ["jen-update-root.py"]),
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


# ── v5.27.0 (Q23) — root-owned plugin installs ──────────────────────────────


def _make_plugin_zip(plugin_id="test-plugin", bad_member=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"id": plugin_id, "name": "Test", "version": "1.0.0"}))
        zf.writestr(f"{plugin_id}/__init__.py", "# plugin code\n")
        if bad_member:
            zf.writestr(bad_member, "evil")
    return buf.getvalue()


def _serve_registry(entries, zips):
    """A real local http.server serving a fake plugins/registry.json
    (`entries`, a mutable list — mutate it in place after binding to
    fill in the real port) and, for any path containing a key of
    `zips`, that key's zip bytes at /raw/<key>/plugin.zip. Reuses this
    file's own `_serve()` helper — same httpd-over-real-sockets
    convention as TestServiceHealthy above, no mocked network I/O."""
    import http.server

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.endswith("/registry.json"):
                body = json.dumps(entries).encode()
                self.send_response(200)
            elif self.path.endswith("/plugin.zip"):
                body = next((data for key, data in zips.items() if key in self.path), None)
                if body is None:
                    body = b""
                    self.send_response(404)
                else:
                    self.send_response(200)
            else:
                body = b""
                self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return _serve(H)


class TestProcessPluginRequests:
    """A marker + a fake registry served from a real local http.server —
    no mocked network I/O, matching this file's own established
    convention (see TestServiceHealthy above). ROOT_PLUGIN_DIR and
    PLUGIN_REQUESTS_DIR are always injected as tmp_path subdirectories;
    this never touches the real /opt/jen/plugins-installed.

    v5.28.0 (Q24, A2) — result filenames are now `<id>.<action>.result`
    (was `<id>.result`); every assertion below was updated to match."""

    def test_happy_path_lands_root_owned_and_writes_ok(self, jen_update_root, tmp_path):
        zip_bytes = _make_plugin_zip("test-plugin")
        sha = hashlib.sha256(zip_bytes).hexdigest()
        entries = [{"id": "test-plugin", "download_url": "http://PLACEHOLDER/raw/v1.0.0", "sha256": sha}]
        port, stop = _serve_registry(entries, {"v1.0.0": zip_bytes})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/v1.0.0"
            requests_dir = tmp_path / "requests"
            root_dir = tmp_path / "root"
            requests_dir.mkdir()
            (requests_dir / "test-plugin.install").touch()

            rc = jen_update_root.process_plugin_requests(
                str(requests_dir), str(root_dir), f"http://127.0.0.1:{port}/registry.json"
            )
            assert rc == 0
            assert not (requests_dir / "test-plugin.install").exists()
            assert (requests_dir / "test-plugin.install.result").read_text().strip() == "ok"
            manifest = root_dir / "test-plugin" / "manifest.json"
            assert manifest.is_file()
            assert json.loads(manifest.read_text())["id"] == "test-plugin"

            # Mode bits are checked unconditionally; ownership only when
            # actually running as root (this dev/CI box mostly isn't).
            mode = os.stat(root_dir / "test-plugin").st_mode
            assert mode & 0o444 == 0o444, "not world-readable"
            assert mode & 0o022 == 0, "group/other-writable"
            if hasattr(os, "getuid") and os.getuid() == 0:
                assert os.stat(root_dir / "test-plugin").st_uid == 0
        finally:
            stop()

    def test_sha_mismatch_is_refused_nothing_extracted(self, jen_update_root, tmp_path):
        zip_bytes = _make_plugin_zip("bad-plugin")
        entries = [{"id": "bad-plugin", "download_url": "http://PLACEHOLDER/raw/v1.0.0", "sha256": "0" * 64}]
        port, stop = _serve_registry(entries, {"v1.0.0": zip_bytes})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/v1.0.0"
            requests_dir = tmp_path / "requests"
            root_dir = tmp_path / "root"
            requests_dir.mkdir()
            (requests_dir / "bad-plugin.install").touch()

            jen_update_root.process_plugin_requests(
                str(requests_dir), str(root_dir), f"http://127.0.0.1:{port}/registry.json"
            )
            result = (requests_dir / "bad-plugin.install.result").read_text().strip()
            assert result.startswith("error:")
            assert "checksum" in result.lower()
            assert not (root_dir / "bad-plugin").exists()
        finally:
            stop()

    def test_missing_sha256_is_refused(self, jen_update_root, tmp_path):
        entries = [{"id": "nosha-plugin", "download_url": "http://PLACEHOLDER/raw/v1.0.0"}]
        port, stop = _serve_registry(entries, {})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/v1.0.0"
            requests_dir = tmp_path / "requests"
            root_dir = tmp_path / "root"
            requests_dir.mkdir()
            (requests_dir / "nosha-plugin.install").touch()

            jen_update_root.process_plugin_requests(
                str(requests_dir), str(root_dir), f"http://127.0.0.1:{port}/registry.json"
            )
            result = (requests_dir / "nosha-plugin.install.result").read_text().strip()
            assert result.startswith("error:")
            assert "checksum" in result.lower()
        finally:
            stop()

    def test_untagged_download_url_is_refused(self, jen_update_root, tmp_path):
        zip_bytes = _make_plugin_zip("main-plugin")
        sha = hashlib.sha256(zip_bytes).hexdigest()
        entries = [{"id": "main-plugin", "download_url": "http://PLACEHOLDER/raw/main", "sha256": sha}]
        port, stop = _serve_registry(entries, {"main": zip_bytes})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/main"
            requests_dir = tmp_path / "requests"
            root_dir = tmp_path / "root"
            requests_dir.mkdir()
            (requests_dir / "main-plugin.install").touch()

            jen_update_root.process_plugin_requests(
                str(requests_dir), str(root_dir), f"http://127.0.0.1:{port}/registry.json"
            )
            result = (requests_dir / "main-plugin.install.result").read_text().strip()
            assert result.startswith("error:")
            assert "tag" in result.lower()
        finally:
            stop()

    def test_zip_slip_member_is_refused(self, jen_update_root, tmp_path):
        zip_bytes = _make_plugin_zip("slip-plugin", bad_member="../../escaped")
        sha = hashlib.sha256(zip_bytes).hexdigest()
        entries = [{"id": "slip-plugin", "download_url": "http://PLACEHOLDER/raw/v1.0.0", "sha256": sha}]
        port, stop = _serve_registry(entries, {"v1.0.0": zip_bytes})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/v1.0.0"
            requests_dir = tmp_path / "requests"
            root_dir = tmp_path / "root"
            requests_dir.mkdir()
            (requests_dir / "slip-plugin.install").touch()

            jen_update_root.process_plugin_requests(
                str(requests_dir), str(root_dir), f"http://127.0.0.1:{port}/registry.json"
            )
            result = (requests_dir / "slip-plugin.install.result").read_text().strip()
            assert result.startswith("error:")
            assert not (root_dir / "slip-plugin").exists()
            assert not (tmp_path.parent / "escaped").exists()
        finally:
            stop()

    def test_id_mismatch_between_marker_and_manifest_is_refused(self, jen_update_root, tmp_path):
        # The archive's manifest.json disagrees with the marker's own id
        # — same "trust nothing from the archive beyond what's checked"
        # rule install_plugin() already enforces in-process.
        zip_bytes = _make_plugin_zip("actual-id")
        sha = hashlib.sha256(zip_bytes).hexdigest()
        entries = [{"id": "claimed-id", "download_url": "http://PLACEHOLDER/raw/v1.0.0", "sha256": sha}]
        port, stop = _serve_registry(entries, {"v1.0.0": zip_bytes})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/v1.0.0"
            requests_dir = tmp_path / "requests"
            root_dir = tmp_path / "root"
            requests_dir.mkdir()
            (requests_dir / "claimed-id.install").touch()

            jen_update_root.process_plugin_requests(
                str(requests_dir), str(root_dir), f"http://127.0.0.1:{port}/registry.json"
            )
            result = (requests_dir / "claimed-id.install.result").read_text().strip()
            assert result.startswith("error:")
            assert "mismatch" in result.lower()
        finally:
            stop()

    def test_bad_id_in_marker_name_is_ignored_and_deleted(self, jen_update_root, tmp_path):
        requests_dir = tmp_path / "requests"
        root_dir = tmp_path / "root"
        requests_dir.mkdir()
        (requests_dir / "-bad-id-.install").touch()

        jen_update_root.process_plugin_requests(str(requests_dir), str(root_dir), "http://127.0.0.1:1/registry.json")
        assert not (requests_dir / "-bad-id-.install").exists()
        assert not (requests_dir / "-bad-id-.install.result").exists()

    def test_not_found_in_registry_is_refused(self, jen_update_root, tmp_path):
        entries = []
        port, stop = _serve_registry(entries, {})
        try:
            requests_dir = tmp_path / "requests"
            root_dir = tmp_path / "root"
            requests_dir.mkdir()
            (requests_dir / "ghost-plugin.install").touch()
            jen_update_root.process_plugin_requests(
                str(requests_dir), str(root_dir), f"http://127.0.0.1:{port}/registry.json"
            )
            result = (requests_dir / "ghost-plugin.install.result").read_text().strip()
            assert result.startswith("error:")
            assert "not found" in result.lower()
        finally:
            stop()

    def test_remove_marker_deletes_the_live_dir(self, jen_update_root, tmp_path):
        root_dir = tmp_path / "root"
        requests_dir = tmp_path / "requests"
        requests_dir.mkdir()
        plugin_dir = root_dir / "old-plugin"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "manifest.json").write_text("{}")
        (requests_dir / "old-plugin.remove").touch()

        jen_update_root.process_plugin_requests(str(requests_dir), str(root_dir), "http://127.0.0.1:1/registry.json")
        assert not plugin_dir.exists()
        assert (requests_dir / "old-plugin.remove.result").read_text().strip() == "ok"

    def test_no_requests_dir_is_a_quiet_no_op(self, jen_update_root, tmp_path):
        missing = tmp_path / "does-not-exist"
        assert (
            jen_update_root.process_plugin_requests(str(missing), str(tmp_path / "root"), "http://x/registry.json") == 0
        )

    def test_removes_a_superseded_writable_copy_on_successful_install(self, jen_update_root, tmp_path):
        """Reinstall-to-harden: once the root-owned copy lands, a stale
        writable copy under content_dir/plugins/<id> must not survive to
        still win discover_plugins()'s "later wins" precedence."""
        zip_bytes = _make_plugin_zip("harden-me")
        sha = hashlib.sha256(zip_bytes).hexdigest()
        entries = [{"id": "harden-me", "download_url": "http://PLACEHOLDER/raw/v1.0.0", "sha256": sha}]
        port, stop = _serve_registry(entries, {"v1.0.0": zip_bytes})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/v1.0.0"
            requests_dir = tmp_path / "requests"
            root_dir = tmp_path / "root"
            content_dir = tmp_path / "content"
            requests_dir.mkdir()
            writable_copy = content_dir / "plugins" / "harden-me"
            writable_copy.mkdir(parents=True)
            (writable_copy / "manifest.json").write_text(json.dumps({"id": "harden-me"}))
            (requests_dir / "harden-me.install").touch()

            result = jen_update_root._install_one_plugin(
                "harden-me", str(root_dir), f"http://127.0.0.1:{port}/registry.json", str(content_dir)
            )
            assert result == "ok"
            assert (root_dir / "harden-me" / "manifest.json").is_file()
            assert not writable_copy.exists(), "stale writable copy must be removed once root copy lands"
        finally:
            stop()

    def test_requires_jen_is_enforced_root_side(self, jen_update_root, tmp_path):
        """v5.28.0 (Q24, A3) — the in-process installer already refused a
        plugin whose requires_jen exceeds the running version; the root
        path skipped this entirely until now."""
        zip_bytes = _make_plugin_zip("needs-future-jen")
        # _make_plugin_zip doesn't take requires_jen — build the manifest
        # directly so it can carry one.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "manifest.json",
                json.dumps({"id": "needs-future-jen", "name": "Test", "version": "1.0.0", "requires_jen": "99.0.0"}),
            )
            zf.writestr("needs-future-jen/__init__.py", "# plugin\n")
        zip_bytes = buf.getvalue()
        sha = hashlib.sha256(zip_bytes).hexdigest()
        entries = [{"id": "needs-future-jen", "download_url": "http://PLACEHOLDER/raw/v1.0.0", "sha256": sha}]
        port, stop = _serve_registry(entries, {"v1.0.0": zip_bytes})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/v1.0.0"
            root_dir = tmp_path / "root"
            with patch.object(jen_update_root, "_installed_version", return_value="5.0.0"):
                result = jen_update_root._install_one_plugin(
                    "needs-future-jen", str(root_dir), f"http://127.0.0.1:{port}/registry.json", str(tmp_path)
                )
            assert result == "error: plugin requires Jen 99.0.0 (running 5.0.0)"
            assert not (root_dir / "needs-future-jen").exists()
        finally:
            stop()

    def test_requires_jen_check_is_skipped_when_installed_version_is_unknown(self, jen_update_root, tmp_path):
        """`_installed_version()` returns "?" when it can't find
        jen/__init__.py at all — a worse, unrelated problem than this
        plugin's compatibility. Must not block the install on a false
        "?" < anything comparison."""
        zip_bytes = _make_plugin_zip("needs-future-jen-2")
        sha = hashlib.sha256(zip_bytes).hexdigest()
        entries = [{"id": "needs-future-jen-2", "download_url": "http://PLACEHOLDER/raw/v1.0.0", "sha256": sha}]
        port, stop = _serve_registry(entries, {"v1.0.0": zip_bytes})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/v1.0.0"
            root_dir = tmp_path / "root"
            with patch.object(jen_update_root, "_installed_version", return_value="?"):
                result = jen_update_root._install_one_plugin(
                    "needs-future-jen-2", str(root_dir), f"http://127.0.0.1:{port}/registry.json", str(tmp_path)
                )
            assert result == "ok"
            assert (root_dir / "needs-future-jen-2" / "manifest.json").is_file()
        finally:
            stop()

    def test_crash_safe_swap_replaces_an_existing_install(self, jen_update_root, tmp_path):
        """v5.28.0 (Q24, A4) — the old copy is renamed aside, not
        deleted, before the new one is renamed in; the old copy is
        removed only after the swap succeeds."""
        root_dir = tmp_path / "root"
        existing = root_dir / "swap-me"
        existing.mkdir(parents=True)
        (existing / "manifest.json").write_text(json.dumps({"id": "swap-me", "version": "0.9.0"}))
        zip_bytes = _make_plugin_zip("swap-me")
        sha = hashlib.sha256(zip_bytes).hexdigest()
        entries = [{"id": "swap-me", "download_url": "http://PLACEHOLDER/raw/v1.0.0", "sha256": sha}]
        port, stop = _serve_registry(entries, {"v1.0.0": zip_bytes})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/v1.0.0"
            result = jen_update_root._install_one_plugin(
                "swap-me", str(root_dir), f"http://127.0.0.1:{port}/registry.json", str(tmp_path)
            )
            assert result == "ok"
            manifest = json.loads((root_dir / "swap-me" / "manifest.json").read_text())
            assert manifest["id"] == "swap-me"
            leftovers = [p.name for p in root_dir.iterdir() if ".old-" in p.name]
            assert leftovers == [], f"the renamed-aside old copy must be cleaned up on success: {leftovers}"
        finally:
            stop()

    def test_sweep_removes_stale_staging_and_old_directories(self, jen_update_root, tmp_path):
        """v5.28.0 (Q24, A4) — a crash between the two os.rename() calls
        in _install_one_plugin can leave a `<id>.staging-<ts>` or
        `<id>.old-<ts>` directory sitting next to the live one; the next
        --plugins run sweeps them before processing any marker."""
        requests_dir = tmp_path / "requests"
        root_dir = tmp_path / "root"
        requests_dir.mkdir()
        stale_staging = root_dir / "crashed.staging-1000000000"
        stale_old = root_dir / "crashed.old-1000000001"
        stale_staging.mkdir(parents=True)
        stale_old.mkdir(parents=True)
        (stale_old / "manifest.json").write_text("{}")

        jen_update_root.process_plugin_requests(str(requests_dir), str(root_dir), "http://127.0.0.1:1/registry.json")

        assert not stale_staging.exists()
        assert not stale_old.exists()

    def test_sweep_leaves_a_real_plugin_directory_alone(self, jen_update_root, tmp_path):
        """The sweep's name pattern must only match the exact
        `.staging-<digits>` / `.old-<digits>` suffix shape — a plugin id
        that happens to contain "old" or "staging" as a substring (not
        as that exact suffix) must never be mistaken for a leftover."""
        requests_dir = tmp_path / "requests"
        root_dir = tmp_path / "root"
        requests_dir.mkdir()
        real_plugin = root_dir / "my-old-plugin"
        real_plugin.mkdir(parents=True)
        (real_plugin / "manifest.json").write_text(json.dumps({"id": "my-old-plugin"}))

        jen_update_root._sweep_stale_plugin_dirs(str(root_dir))

        assert real_plugin.exists(), "a real plugin dir must never be swept just for containing 'old'"

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need elevated privileges on Windows")
    def test_a_symlinked_result_path_is_never_followed(self, jen_update_root, tmp_path):
        """v5.28.0 (Q24, A1) — the security finding: this runs as root
        inside a directory www-data owns. A symlink pre-planted at the
        exact result path must never be followed, or root would
        truncate/overwrite whatever it points at."""
        zip_bytes = _make_plugin_zip("sym-plugin")
        sha = hashlib.sha256(zip_bytes).hexdigest()
        entries = [{"id": "sym-plugin", "download_url": "http://PLACEHOLDER/raw/v1.0.0", "sha256": sha}]
        port, stop = _serve_registry(entries, {"v1.0.0": zip_bytes})
        try:
            entries[0]["download_url"] = f"http://127.0.0.1:{port}/raw/v1.0.0"
            requests_dir = tmp_path / "requests"
            root_dir = tmp_path / "root"
            requests_dir.mkdir()
            victim = tmp_path / "victim.txt"
            victim.write_text("PRECIOUS DATA")
            (requests_dir / "sym-plugin.install").touch()
            os.symlink(str(victim), str(requests_dir / "sym-plugin.install.result"))

            jen_update_root.process_plugin_requests(
                str(requests_dir), str(root_dir), f"http://127.0.0.1:{port}/registry.json"
            )

            assert victim.read_text() == "PRECIOUS DATA", "root must never write through the planted symlink"
        finally:
            stop()

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need elevated privileges on Windows")
    def test_requests_dir_itself_being_a_symlink_is_refused(self, jen_update_root, tmp_path):
        """v5.28.0 (Q24, A1) — requests_dir is lstat'd, not stat'd: a
        symlink there (parent /var/lib/jen is www-data-owned) fails the
        S_ISDIR check and the whole run refuses rather than following it
        into an attacker-chosen real directory."""
        real_dir = tmp_path / "real_requests"
        real_dir.mkdir()
        (real_dir / "ghost.install").touch()
        linked = tmp_path / "requests_link"
        os.symlink(str(real_dir), str(linked))
        root_dir = tmp_path / "root"

        rc = jen_update_root.process_plugin_requests(str(linked), str(root_dir), "http://127.0.0.1:1/registry.json")

        assert rc == 0
        assert (real_dir / "ghost.install").exists(), "nothing inside the symlinked dir should have been touched"

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need elevated privileges on Windows")
    def test_a_symlinked_marker_is_unlinked_not_followed(self, jen_update_root, tmp_path):
        """v5.28.0 (Q24, A1) — a marker path itself, not just the result
        path, must be lstat'd: a symlink named `<id>.install` pointing
        anywhere is unlinked (removing the symlink, never its target)
        rather than treated as a genuine marker."""
        requests_dir = tmp_path / "requests"
        root_dir = tmp_path / "root"
        requests_dir.mkdir()
        victim = tmp_path / "victim-marker-target"
        victim.mkdir()
        (victim / "manifest.json").write_text("{}")
        os.symlink(str(victim), str(requests_dir / "linked-plugin.install"))

        jen_update_root.process_plugin_requests(str(requests_dir), str(root_dir), "http://127.0.0.1:1/registry.json")

        assert not (requests_dir / "linked-plugin.install").exists(), "the symlink itself should be removed"
        assert victim.exists(), "the symlink's TARGET must never be touched"
        assert not (root_dir / "linked-plugin").exists()

    def test_a_directory_named_like_a_marker_is_left_alone(self, jen_update_root, tmp_path):
        """v5.28.0 (Q24, A1) — only a regular file is ever a marker; a
        directory shaped like one is inert, not a security concern, but
        must never be processed or deleted."""
        requests_dir = tmp_path / "requests"
        root_dir = tmp_path / "root"
        requests_dir.mkdir()
        (requests_dir / "dir-marker.install").mkdir()

        rc = jen_update_root.process_plugin_requests(
            str(requests_dir), str(root_dir), "http://127.0.0.1:1/registry.json"
        )

        assert rc == 0
        assert (requests_dir / "dir-marker.install").is_dir()

    def test_drain_loop_picks_up_a_marker_dropped_mid_run(self, jen_update_root, tmp_path):
        """v5.28.0 (Q24, A6) — jen-plugin-install.service is a oneshot; a
        `systemctl start` on an already-active oneshot is a no-op, so a
        request written while this run is already processing an earlier
        one must be picked up within the SAME invocation, not left
        queued until the next external trigger."""
        requests_dir = tmp_path / "requests"
        root_dir = tmp_path / "root"
        requests_dir.mkdir()
        (requests_dir / "first-plugin.install").touch()

        calls = []

        def fake_install(plugin_id, root_plugin_dir, registry_url, content_dir=jen_update_root.CONTENT_DIR):
            calls.append(plugin_id)
            if plugin_id == "first-plugin":
                (requests_dir / "second-plugin.install").touch()
            return "ok"

        with patch.object(jen_update_root, "_install_one_plugin", side_effect=fake_install):
            jen_update_root.process_plugin_requests(
                str(requests_dir), str(root_dir), "http://127.0.0.1:1/registry.json"
            )

        assert calls == ["first-plugin", "second-plugin"]
        assert (requests_dir / "second-plugin.install.result").read_text().strip() == "ok"

    def test_drain_loop_stops_early_when_nothing_can_be_resolved(self, jen_update_root, tmp_path):
        """A marker that can never be resolved on its own (a directory
        shaped like one) must not make the loop spin through every one
        of its passes — it should detect "no progress" and stop after
        one repeat, not max_passes."""
        requests_dir = tmp_path / "requests"
        root_dir = tmp_path / "root"
        requests_dir.mkdir()
        (requests_dir / "stuck.install").mkdir()

        listdir_calls = []
        real_listdir = os.listdir

        def counting_listdir(path):
            if str(path) == str(requests_dir):
                listdir_calls.append(1)
            return real_listdir(path)

        with patch.object(jen_update_root.os, "listdir", side_effect=counting_listdir):
            jen_update_root.process_plugin_requests(
                str(requests_dir), str(root_dir), "http://127.0.0.1:1/registry.json"
            )

        assert len(listdir_calls) <= 3, (
            f"drain loop should stop quickly on a stuck marker, made {len(listdir_calls)} passes"
        )


class TestPluginInstallServiceUnitAndSudoers:
    """v5.27.0 (Q23) — the second unit follows every installation path
    jen-update.service already does; this is the test_dependency_
    consistency.py-style check the pinned spec calls for, kept here
    since it's really about jen-update-root.py's own _EXTERNAL_ITEMS."""

    def test_unit_file_exists_at_repo_root(self):
        assert pathlib.Path("jen-plugin-install.service").is_file()

    def test_unit_is_a_zero_parameter_root_oneshot(self):
        text = pathlib.Path("jen-plugin-install.service").read_text()
        assert "Type=oneshot" in text
        assert "User=root" in text
        assert "ExecStart=/usr/bin/python3 /usr/local/sbin/jen-update-root.py --plugins" in text

    def test_listed_in_external_items(self, jen_update_root):
        assert jen_update_root.PLUGIN_INSTALL_SERVICE_PATH in jen_update_root._EXTERNAL_ITEMS
        assert (
            jen_update_root._EXTERNAL_ITEMS[jen_update_root.PLUGIN_INSTALL_SERVICE_PATH] == "jen-plugin-install.service"
        )

    def test_listed_in_install_sh(self):
        text = pathlib.Path("install.sh").read_text()
        assert "jen-plugin-install.service" in text

    def test_root_plugin_dir_is_not_a_flat_leftover(self, jen_update_root):
        """The Gotcha this session actually confirmed: /opt/jen/plugins
        (a _ROLLBACK_ITEMS / _FLAT_LEFTOVERS entry) is rmtree'd wholesale
        by _remove_flat_leftovers() after a migration run — a sibling
        /opt/jen/plugins-installed must never collide with that."""
        assert jen_update_root.ROOT_PLUGIN_DIR == "/opt/jen/plugins-installed"
        assert os.path.basename(jen_update_root.ROOT_PLUGIN_DIR) not in jen_update_root._FLAT_LEFTOVERS


class TestPruneOldReleasesLeavesPluginsInstalledAlone:
    def test_sibling_plugins_installed_dir_survives_a_prune(self, jen_update_root, tmp_path):
        install_dir = tmp_path / "opt-jen"
        releases_dir = install_dir / "releases"
        plugins_installed = install_dir / "plugins-installed"
        releases_dir.mkdir(parents=True)
        plugins_installed.mkdir()
        (plugins_installed / "some-plugin").mkdir()
        (plugins_installed / "some-plugin" / "manifest.json").write_text("{}")

        for name in ("5.1.0", "5.2.0", "5.3.0"):
            (releases_dir / name).mkdir()

        jen_update_root._prune_old_releases(
            releases_dir=str(releases_dir), current_link=str(install_dir / "current"), install_dir=str(install_dir)
        )

        assert (plugins_installed / "some-plugin" / "manifest.json").is_file(), (
            "_prune_old_releases must never touch a sibling plugins-installed/ directory"
        )


class TestArgvDispatch:
    """v5.27.0 (Q23) — main()'s one safe exception to "no caller input
    at all": --plugins, and only that exact single argument."""

    def test_plugins_flag_calls_process_plugin_requests(self, jen_update_root):
        with (
            patch.object(jen_update_root, "process_plugin_requests", return_value=0) as mock_process,
            patch.object(jen_update_root.sys, "argv", ["jen-update-root.py", "--plugins"]),
        ):
            rc = jen_update_root.main()
        assert rc == 0
        mock_process.assert_called_once_with()

    def test_any_other_argument_exits_2(self, jen_update_root):
        with patch.object(jen_update_root.sys, "argv", ["jen-update-root.py", "--bogus"]):
            rc = jen_update_root.main()
        assert rc == 2

    def test_multiple_arguments_including_plugins_is_still_refused(self, jen_update_root):
        """Exact match only — "--plugins extra" is not "--plugins"."""
        with patch.object(jen_update_root.sys, "argv", ["jen-update-root.py", "--plugins", "extra"]):
            rc = jen_update_root.main()
        assert rc == 2
