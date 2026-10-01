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
import re
import sys
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


class TestLoadLayout:
    """v5.67.0 (Q114) — load_layout() is the root-trusted source of
    app_dir/config_dir/data_dir. Mirrors install.sh's
    _resolve_layout_dirs/_layout_path_ok/_layout_not_nested/
    _validate_layout_file_or_fatal — tests/test_layout.py exercises the
    bash side of the same validation table.

    Every test that needs a "valid" file (passing _validate_layout_file's
    owner/group/mode check) needs real POSIX semantics: Windows' os.chmod
    can't clear the group/other-write bits os.stat then reports, so a
    freshly written file always reads back as mode 0o666 there. Skipped
    as a whole class rather than test-by-test — verified for real by the
    `install`/`pytest` CI jobs on real Ubuntu runners.

    Even on real POSIX, only the `install` CI job runs as root — the
    plain `pytest` job (this one) is a non-root user, so a file this
    test creates can never actually BE root-owned. Every test that
    doesn't mean to test the ownership check itself bypasses just that
    (`_bypass_ownership`), the same technique tests/test_layout.py uses
    on the bash side and tests/test_kea_helper.py already established
    for jen-kea-helper's own analogous _bin_dir_ok check."""

    pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX file permission bits required")

    def _write(self, path, app="/opt/jen", config="/etc/jen", data="/var/lib/jen"):
        path.write_text(f"[layout]\napp_dir = {app}\nconfig_dir = {config}\ndata_dir = {data}\n")
        os.chmod(path, 0o644)

    def _bypass_ownership(self, monkeypatch, jen_update_root, mode_check=False):
        """Replace _validate_layout_file with a version that skips the
        owner/group check a non-root test process could never pass —
        keeping the real mode check when mode_check=True (for the one
        test that needs it), a no-op otherwise."""
        real_mode_bits = 0o022

        def _patched(path):
            if os.path.islink(path):
                return f"{path} must be a regular file, not a symlink."
            if not os.path.isfile(path):
                return f"{path} exists but is not a regular file."
            if mode_check:
                st = os.stat(path)
                if st.st_mode & real_mode_bits:
                    return (
                        f"{path} is writable by group or other (mode {oct(st.st_mode & 0o777)}) — refusing to trust it."
                    )
            return None

        monkeypatch.setattr(jen_update_root, "_validate_layout_file", _patched)

    def test_absent_file_returns_historical_defaults(self, jen_update_root, tmp_path):
        missing = tmp_path / "does-not-exist" / "jen-layout.conf"
        assert jen_update_root.load_layout(str(missing)) == {
            "app_dir": "/opt/jen",
            "config_dir": "/etc/jen",
            "data_dir": "/var/lib/jen",
        }

    def test_present_and_valid_is_returned(self, jen_update_root, tmp_path, monkeypatch):
        self._bypass_ownership(monkeypatch, jen_update_root)
        layout = tmp_path / "jen-layout.conf"
        self._write(layout, app="/srv/jen/app", config="/srv/jen/etc", data="/srv/jen/data")
        result = jen_update_root.load_layout(str(layout))
        assert result == {"app_dir": "/srv/jen/app", "config_dir": "/srv/jen/etc", "data_dir": "/srv/jen/data"}

    @pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="requires real root to prove ownership refusal")
    def test_non_root_owned_file_raises(self, jen_update_root, tmp_path):
        layout = tmp_path / "jen-layout.conf"
        self._write(layout)
        os.chown(layout, 1000, 1000)
        with pytest.raises(RuntimeError, match="owned by root"):
            jen_update_root.load_layout(str(layout))

    def test_group_writable_file_raises(self, jen_update_root, tmp_path, monkeypatch):
        self._bypass_ownership(monkeypatch, jen_update_root, mode_check=True)
        layout = tmp_path / "jen-layout.conf"
        self._write(layout)
        os.chmod(layout, 0o664)
        with pytest.raises(RuntimeError, match="writable by group or other"):
            jen_update_root.load_layout(str(layout))

    def test_symlinked_file_raises(self, jen_update_root, tmp_path):
        # No bypass needed: the symlink check runs before the ownership
        # check, so this doesn't touch the part a non-root process fails.
        real = tmp_path / "real-layout.conf"
        self._write(real)
        link = tmp_path / "jen-layout.conf"
        link.symlink_to(real)
        with pytest.raises(RuntimeError, match="symlink"):
            jen_update_root.load_layout(str(link))

    def test_missing_key_raises(self, jen_update_root, tmp_path, monkeypatch):
        self._bypass_ownership(monkeypatch, jen_update_root)
        layout = tmp_path / "jen-layout.conf"
        layout.write_text("[layout]\napp_dir = /opt/jen\nconfig_dir = /etc/jen\n")
        os.chmod(layout, 0o644)
        with pytest.raises(RuntimeError, match="missing data_dir"):
            jen_update_root.load_layout(str(layout))

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
    def test_app_dir_rejections(self, jen_update_root, tmp_path, monkeypatch, path, expect_in_error):
        self._bypass_ownership(monkeypatch, jen_update_root)
        layout = tmp_path / "jen-layout.conf"
        self._write(layout, app=path)
        with pytest.raises(RuntimeError, match=re.escape(expect_in_error)):
            jen_update_root.load_layout(str(layout))

    def test_nested_data_under_app_raises(self, jen_update_root, tmp_path, monkeypatch):
        self._bypass_ownership(monkeypatch, jen_update_root)
        layout = tmp_path / "jen-layout.conf"
        self._write(layout, app="/srv/jen", data="/srv/jen/data")
        with pytest.raises(RuntimeError, match="nested"):
            jen_update_root.load_layout(str(layout))

    def test_siblings_are_not_nested(self, jen_update_root, tmp_path, monkeypatch):
        self._bypass_ownership(monkeypatch, jen_update_root)
        layout = tmp_path / "jen-layout.conf"
        self._write(layout, app="/srv/jen-app", config="/srv/jen-etc", data="/srv/jen-data")
        result = jen_update_root.load_layout(str(layout))
        assert result == {"app_dir": "/srv/jen-app", "config_dir": "/srv/jen-etc", "data_dir": "/srv/jen-data"}

    def test_module_level_constants_derive_from_the_layout(self, jen_update_root):
        # The module's own globals (computed once, at import time) must
        # agree with what a fresh load_layout() call for the same
        # (absent, in a normal test environment) file would produce.
        assert jen_update_root.LAYOUT_ERROR is None
        assert jen_update_root._layout["app_dir"] == jen_update_root.INSTALL_DIR
        assert jen_update_root._layout["data_dir"] == jen_update_root.CONTENT_DIR
        assert os.path.join(jen_update_root._layout["config_dir"], "jen.config") == jen_update_root.CONFIG_FILE


class TestLayoutPathOkSharedRootsAndGrammar:
    """v5.67.0-beta.5 (Q117) — _layout_path_ok's three new checks, added
    on top of the pre-existing absolute/not-"/"/no-".."/normalized/
    not-forbidden-prefix ones TestLoadLayout's parametrized rejections
    already cover.

    Skipped as a whole class on Windows for the same reason
    TestLoadLayout is: the pre-existing normalize check
    (os.path.normpath) runs before any of these new ones and rewrites a
    POSIX path to backslashes there, so even a "should be refused" case
    here would pass for the wrong reason. Verified for real by the
    `install`/`pytest` CI jobs on real Ubuntu runners."""

    pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX path semantics required")

    def test_shared_root_exact_match_is_refused(self, jen_update_root):
        for path in ("/etc", "/opt", "/usr/local", "/var/lib"):
            err = jen_update_root._layout_path_ok("config_dir", path)
            assert err is not None and "dedicated directory" in err, path

    def test_a_child_of_a_shared_root_is_fine(self, jen_update_root):
        for path in ("/etc/jen", "/opt/jen", "/usr/local/jen", "/var/lib/jen"):
            assert jen_update_root._layout_path_ok("config_dir", path) is None, path

    def test_grammar_refuses_shell_metacharacters(self, jen_update_root):
        for bad in ("/opt/jen app", "/opt/jen#1", "/opt/jen&x", "/opt/jen%n", "/opt/jen;x", "/opt/jen$x"):
            err = jen_update_root._layout_path_ok("app_dir", bad)
            assert err is not None, bad

    def test_grammar_accepts_dots_underscores_and_hyphens(self, jen_update_root):
        for good in ("/srv/jen-app", "/srv/jen_app.v2", "/srv/my.jen/app"):
            assert jen_update_root._layout_path_ok("app_dir", good) is None, good

    def test_overlong_path_is_refused(self, jen_update_root):
        path = "/srv/" + ("a" * 250)
        err = jen_update_root._layout_path_ok("app_dir", path)
        assert err is not None and "characters" in err


class TestLayoutMarker:
    """v5.67.0-beta.5 (Q117) — the .jen-directory marker: a plain "key =
    value" file (never sourced), root:root 0644. write_layout_marker's
    os.chown needs real root, so it's mocked here the same way
    TestInstallSelfUpdateFiles mocks it for install_self_update_files."""

    @pytest.mark.skipif(os.name != "posix", reason="os.chown requires POSIX")
    def test_write_then_read_round_trips(self, jen_update_root, tmp_path):
        with patch("os.chown"), patch("os.chmod"):
            jen_update_root.write_layout_marker(str(tmp_path), "app_dir", "5.67.0-beta.5")
        marker = jen_update_root._read_layout_marker(str(tmp_path))
        assert marker == {"role": "app_dir", "version": "5.67.0-beta.5"}

    def test_absent_marker_reads_as_none(self, jen_update_root, tmp_path):
        assert jen_update_root._read_layout_marker(str(tmp_path)) is None

    @pytest.mark.skipif(os.name != "posix", reason="symlink creation requires POSIX/elevated Windows privilege")
    def test_symlinked_marker_is_never_trusted(self, jen_update_root, tmp_path):
        real = tmp_path / "real-marker"
        real.write_text("role = app_dir\nversion = 1.0.0\n")
        d = tmp_path / "d"
        d.mkdir()
        (d / ".jen-directory").symlink_to(real)
        assert jen_update_root._read_layout_marker(str(d)) is None

    def test_marker_missing_role_key_reads_as_none(self, jen_update_root, tmp_path):
        (tmp_path / ".jen-directory").write_text("version = 1.0.0\n")
        assert jen_update_root._read_layout_marker(str(tmp_path)) is None


class TestRecognizedByContent:
    """v5.67.0-beta.5 (Q117) — retroactively recognizing a pre-Q117 Jen
    directory by the content each role's own install step already puts
    there, used only to stamp a marker on upgrade/uninstall, never to
    trust an unrelated directory."""

    def test_config_dir_recognized_by_jen_config(self, jen_update_root, tmp_path):
        (tmp_path / "jen.config").write_text("[jen_db]\n")
        assert jen_update_root._recognized_by_content(str(tmp_path), "config_dir") is True

    def test_app_dir_recognized_by_releases_subdir(self, jen_update_root, tmp_path):
        (tmp_path / "releases").mkdir()
        assert jen_update_root._recognized_by_content(str(tmp_path), "app_dir") is True

    def test_app_dir_recognized_by_flat_run_py(self, jen_update_root, tmp_path):
        (tmp_path / "run.py").write_text("# jen\n")
        assert jen_update_root._recognized_by_content(str(tmp_path), "app_dir") is True

    def test_data_dir_recognized_by_any_known_subdir(self, jen_update_root, tmp_path):
        (tmp_path / "backups").mkdir()
        assert jen_update_root._recognized_by_content(str(tmp_path), "data_dir") is True

    def test_empty_directory_is_not_recognized(self, jen_update_root, tmp_path):
        for role in ("app_dir", "config_dir", "data_dir"):
            assert jen_update_root._recognized_by_content(str(tmp_path), role) is False


class TestLayoutTargetOkForInstall:
    """v5.67.0-beta.5 (Q117) — a layout target for a FRESH install must be
    absent, an empty directory, or already carrying Jen's own marker."""

    def test_absent_path_is_fine(self, jen_update_root, tmp_path):
        assert jen_update_root._layout_target_ok_for_install("app_dir", str(tmp_path / "nope")) is None

    def test_empty_existing_directory_is_fine(self, jen_update_root, tmp_path):
        assert jen_update_root._layout_target_ok_for_install("app_dir", str(tmp_path)) is None

    @pytest.mark.skipif(os.name != "posix", reason="os.chown requires POSIX")
    def test_marked_directory_is_reused(self, jen_update_root, tmp_path):
        with patch("os.chown"), patch("os.chmod"):
            jen_update_root.write_layout_marker(str(tmp_path), "app_dir", "5.67.0-beta.5")
        assert jen_update_root._layout_target_ok_for_install("app_dir", str(tmp_path)) is None

    def test_nonempty_unmarked_directory_is_refused(self, jen_update_root, tmp_path):
        (tmp_path / "something").write_text("real content\n")
        err = jen_update_root._layout_target_ok_for_install("app_dir", str(tmp_path))
        assert err is not None and "does not carry Jen's own marker" in err

    @pytest.mark.skipif(os.name != "posix", reason="symlink creation requires POSIX/elevated Windows privilege")
    def test_symlink_is_refused(self, jen_update_root, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        err = jen_update_root._layout_target_ok_for_install("app_dir", str(link))
        assert err is not None and "symlink" in err

    def test_existing_plain_file_is_refused(self, jen_update_root, tmp_path):
        f = tmp_path / "a-file"
        f.write_text("x")
        err = jen_update_root._layout_target_ok_for_install("app_dir", str(f))
        assert err is not None and "not a directory" in err


class TestLayoutAncestorsOk:
    """v5.67.0-beta.5 (Q117) — every EXISTING ancestor of a layout path
    must be root-owned and not group/other-writable, full stop (no CI
    warn-only downgrade — that belongs in CI itself, via `chmod 755
    /opt`). The refusal cases run for real, without root: a pytest
    tmp_path's own ancestors are never root-owned on ordinary CI, which
    is exactly the condition this class tests. The success case needs
    real root to construct, so it's skipped otherwise."""

    def test_non_root_owned_ancestor_is_refused(self, jen_update_root, tmp_path):
        candidate = tmp_path / "nested" / "app"
        err = jen_update_root._layout_ancestors_ok("app_dir", str(candidate))
        assert err is not None
        assert "not root-owned" in err or "writable by group or other" in err

    @pytest.mark.skipif(os.name != "posix", reason="symlink creation requires POSIX/elevated Windows privilege")
    def test_symlinked_ancestor_is_refused(self, jen_update_root, tmp_path):
        real = tmp_path / "real-parent"
        real.mkdir()
        link = tmp_path / "linked-parent"
        link.symlink_to(real)
        candidate = link / "app"
        err = jen_update_root._layout_ancestors_ok("app_dir", str(candidate))
        assert err is not None and "symlink" in err

    def test_nonexistent_ancestor_chain_is_skipped(self, jen_update_root):
        # Every ancestor of this candidate is missing on any real
        # machine — none of them can be checked, so there's nothing to
        # refuse (the install step creates them fresh).
        err = jen_update_root._layout_ancestors_ok("app_dir", "/this-does-not-exist-anywhere/jen")
        assert err is None

    @pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="requires real root-owned ancestors")
    def test_root_owned_non_writable_ancestors_pass(self, jen_update_root, tmp_path):
        os.chmod(tmp_path, 0o755)
        os.chown(tmp_path, 0, 0)
        candidate = tmp_path / "app"
        assert jen_update_root._layout_ancestors_ok("app_dir", str(candidate)) is None


class TestLayoutAppdirItselfOk:
    """v5.67.0-beta.5 (Q117) — app_dir ITSELF (not just its ancestors)
    must be a real root-owned directory once it exists — config_dir/
    data_dir are intentionally www-data-owned, so this check is
    app_dir-only (docs/ARCHITECTURE.md §6.1)."""

    def test_absent_path_is_fine(self, jen_update_root, tmp_path):
        assert jen_update_root._layout_appdir_itself_ok(str(tmp_path / "nope")) is None

    @pytest.mark.skipif(os.name != "posix", reason="symlink creation requires POSIX/elevated Windows privilege")
    def test_symlink_is_refused(self, jen_update_root, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        err = jen_update_root._layout_appdir_itself_ok(str(link))
        assert err is not None and "symlink" in err

    def test_existing_plain_file_is_refused(self, jen_update_root, tmp_path):
        f = tmp_path / "a-file"
        f.write_text("x")
        err = jen_update_root._layout_appdir_itself_ok(str(f))
        assert err is not None and "not a directory" in err

    @pytest.mark.skipif(os.name != "posix", reason="os.geteuid requires POSIX")
    def test_non_root_owned_directory_is_refused(self, jen_update_root, tmp_path):
        # tmp_path is owned by whatever user is running pytest, never
        # root, on ordinary (non-root) CI — a real refusal, no mocking.
        err = jen_update_root._layout_appdir_itself_ok(str(tmp_path))
        if os.geteuid() == 0:
            pytest.skip("running as root — this directory really is root-owned here")
        assert err is not None and "not root-owned" in err


class TestCheckLayout:
    """v5.67.0-beta.5 (Q117) — check_layout() end to end. The ancestor/
    app_dir-ownership checks are bypassed here (monkeypatched to always
    pass) for every test that isn't specifically about ownership — the
    same technique TestLoadLayout's _bypass_ownership and
    tests/test_layout.py's own bash-side bypasses already use; a non-root
    CI process could never construct a real root-owned ancestor to test
    the success path against. The forbidden-prefix list is cleared too:
    pytest's own tmp_path lives under /tmp, one of those prefixes, so a
    real candidate directory built from it would be refused by THAT rule
    before ever reaching the marker/ancestor logic a given test means to
    exercise (caught the hard way — CI's own non-Windows pytest job, where
    tmp_path really does resolve to /tmp/...). Grammar and shared-root
    refusal have their own dedicated, filesystem-free tests in
    TestLayoutPathOkSharedRootsAndGrammar above."""

    # Every scenario here, even a refusal, goes through _layout_path_ok's
    # pre-existing normalize check first — on Windows that rewrites a
    # POSIX path to backslashes and fires before the thing a given test
    # means to exercise, the same reason TestLoadLayout skips as a whole
    # class. Real Linux (CI) is the arbiter.
    pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX path semantics required")

    @pytest.fixture(autouse=False)
    def _bypass_ownership(self, jen_update_root, monkeypatch):
        monkeypatch.setattr(jen_update_root, "_layout_ancestors_ok", lambda name, path: None)
        monkeypatch.setattr(jen_update_root, "_layout_appdir_itself_ok", lambda path: None)
        monkeypatch.setattr(jen_update_root, "_LAYOUT_FORBIDDEN_PREFIXES", ())

    def test_install_mode_without_explicit_paths_is_refused(self, jen_update_root):
        ok, result = jen_update_root.check_layout("install")
        assert not ok and "needs --app-dir" in result

    def test_install_mode_bad_grammar_is_refused(self, jen_update_root, _bypass_ownership):
        ok, result = jen_update_root.check_layout(
            "install", app_dir="/srv/jen app", config_dir="/etc/jen", data_dir="/var/lib/jen"
        )
        assert not ok

    def test_install_mode_nested_paths_refused(self, jen_update_root, _bypass_ownership):
        ok, result = jen_update_root.check_layout(
            "install", app_dir="/srv/jen", config_dir="/etc/jen", data_dir="/srv/jen/data"
        )
        assert not ok and "nested" in result

    def test_install_mode_success_returns_the_three_values(self, jen_update_root, _bypass_ownership, tmp_path):
        app = str(tmp_path / "app")
        config = str(tmp_path / "etc")
        data = str(tmp_path / "data")
        ok, result = jen_update_root.check_layout("install", app_dir=app, config_dir=config, data_dir=data)
        assert ok, result
        assert result == {"app_dir": app, "config_dir": config, "data_dir": data}

    def test_install_mode_refuses_a_nonempty_unmarked_target(self, jen_update_root, _bypass_ownership, tmp_path):
        app = tmp_path / "app"
        app.mkdir()
        (app / "unrelated").write_text("x")
        ok, result = jen_update_root.check_layout(
            "install", app_dir=str(app), config_dir=str(tmp_path / "etc"), data_dir=str(tmp_path / "data")
        )
        assert not ok and "does not carry Jen's own marker" in result

    def test_upgrade_mode_no_layout_file_uses_defaults(self, jen_update_root, _bypass_ownership, monkeypatch):
        monkeypatch.setattr(jen_update_root, "LAYOUT_FILE", "/does/not/exist/jen-layout.conf")
        ok, result = jen_update_root.check_layout("upgrade")
        assert ok, result
        assert result == dict(jen_update_root._DEFAULT_LAYOUT)

    def test_upgrade_mode_disagreeing_flag_is_refused(self, jen_update_root, _bypass_ownership, monkeypatch, tmp_path):
        layout_file = tmp_path / "jen-layout.conf"
        layout_file.write_text(
            "[layout]\napp_dir = /srv/jen/app\nconfig_dir = /srv/jen/etc\ndata_dir = /srv/jen/data\n"
        )
        monkeypatch.setattr(jen_update_root, "LAYOUT_FILE", str(layout_file))
        monkeypatch.setattr(jen_update_root, "_validate_layout_file", lambda p: None)
        ok, result = jen_update_root.check_layout("upgrade", app_dir="/somewhere/else")
        assert not ok and "runbook" in result

    def test_upgrade_mode_agreeing_flag_is_accepted(self, jen_update_root, _bypass_ownership, monkeypatch, tmp_path):
        layout_file = tmp_path / "jen-layout.conf"
        layout_file.write_text(
            "[layout]\napp_dir = /srv/jen/app\nconfig_dir = /srv/jen/etc\ndata_dir = /srv/jen/data\n"
        )
        monkeypatch.setattr(jen_update_root, "LAYOUT_FILE", str(layout_file))
        monkeypatch.setattr(jen_update_root, "_validate_layout_file", lambda p: None)
        ok, result = jen_update_root.check_layout("upgrade", app_dir="/srv/jen/app")
        assert ok, result
        assert result["app_dir"] == "/srv/jen/app"

    def test_upgrade_mode_stamps_a_marker_on_a_recognized_unmarked_directory(
        self, jen_update_root, _bypass_ownership, monkeypatch, tmp_path
    ):
        # No LAYOUT_FILE AND no explicit flags — the real shape of
        # install.sh's own call for a pre-Q114 box with no layout file
        # yet (_resolve_layout_dirs sends --for upgrade with no --app-dir/
        # etc unless the operator overrode them): _DEFAULT_LAYOUT is the
        # only source of truth, so it's patched to point at this test's
        # own tmp dirs rather than passing them as (dis)agreeing flags.
        app, config, data = tmp_path / "app", tmp_path / "etc", tmp_path / "data"
        app.mkdir()
        config.mkdir()
        data.mkdir()
        (app / "run.py").write_text("# jen\n")
        (config / "jen.config").write_text("[jen_db]\n")
        (data / "backups").mkdir()
        monkeypatch.setattr(jen_update_root, "LAYOUT_FILE", "/does/not/exist/jen-layout.conf")
        monkeypatch.setattr(
            jen_update_root, "_DEFAULT_LAYOUT", {"app_dir": str(app), "config_dir": str(config), "data_dir": str(data)}
        )
        with patch("os.chown"), patch("os.chmod"):
            ok, result = jen_update_root.check_layout("upgrade")
        assert ok, result
        assert jen_update_root._read_layout_marker(str(app)) is not None
        assert jen_update_root._read_layout_marker(str(config)) is not None
        assert jen_update_root._read_layout_marker(str(data)) is not None

    def test_upgrade_mode_tolerates_an_unrecognized_unmarked_directory(
        self, jen_update_root, _bypass_ownership, monkeypatch, tmp_path
    ):
        app, config, data = tmp_path / "app", tmp_path / "etc", tmp_path / "data"
        app.mkdir()
        config.mkdir()
        data.mkdir()
        (app / "unrelated-stuff").write_text("x")
        monkeypatch.setattr(jen_update_root, "LAYOUT_FILE", "/does/not/exist/jen-layout.conf")
        monkeypatch.setattr(
            jen_update_root, "_DEFAULT_LAYOUT", {"app_dir": str(app), "config_dir": str(config), "data_dir": str(data)}
        )
        ok, result = jen_update_root.check_layout("upgrade")
        assert ok, result
        assert jen_update_root._read_layout_marker(str(app)) is None

    def test_uninstall_mode_refuses_an_unrecognized_unmarked_directory(
        self, jen_update_root, _bypass_ownership, monkeypatch, tmp_path
    ):
        # No LAYOUT_FILE and no explicit flags — uninstall.sh's own real
        # call is always bare `--check-layout --for uninstall`, so
        # _DEFAULT_LAYOUT is the only source of truth here, same reasoning
        # as the upgrade-mode tests above.
        app, config, data = tmp_path / "app", tmp_path / "etc", tmp_path / "data"
        app.mkdir()
        config.mkdir()
        data.mkdir()
        (app / "unrelated-stuff").write_text("x")
        monkeypatch.setattr(jen_update_root, "LAYOUT_FILE", "/does/not/exist/jen-layout.conf")
        monkeypatch.setattr(
            jen_update_root, "_DEFAULT_LAYOUT", {"app_dir": str(app), "config_dir": str(config), "data_dir": str(data)}
        )
        ok, result = jen_update_root.check_layout("uninstall")
        assert not ok and "does not carry Jen's own marker" in result

    def test_uninstall_mode_stamps_a_marker_on_a_recognized_unmarked_directory(
        self, jen_update_root, _bypass_ownership, monkeypatch, tmp_path
    ):
        app, config, data = tmp_path / "app", tmp_path / "etc", tmp_path / "data"
        app.mkdir()
        config.mkdir()
        data.mkdir()
        (app / "releases").mkdir()
        (config / "jen.config").write_text("[jen_db]\n")
        (data / "icons").mkdir()
        monkeypatch.setattr(jen_update_root, "LAYOUT_FILE", "/does/not/exist/jen-layout.conf")
        monkeypatch.setattr(
            jen_update_root, "_DEFAULT_LAYOUT", {"app_dir": str(app), "config_dir": str(config), "data_dir": str(data)}
        )
        with patch("os.chown"), patch("os.chmod"):
            ok, result = jen_update_root.check_layout("uninstall")
        assert ok, result


class TestCheckLayoutCli:
    """v5.67.0-beta.5 (Q117) — the `--check-layout` argv surface itself:
    install.sh/uninstall.sh are the only callers (see the module comment
    above check_layout_cli), communicating over stdout/stderr + exit
    code, never Python objects."""

    def test_missing_for_is_refused(self, jen_update_root, capsys):
        rc = jen_update_root.check_layout_cli([])
        assert rc == 1
        assert "--for must be" in capsys.readouterr().err

    def test_invalid_for_value_is_refused(self, jen_update_root, capsys):
        rc = jen_update_root.check_layout_cli(["--for", "bogus"])
        assert rc == 1
        assert "--for must be" in capsys.readouterr().err

    def test_unrecognized_argument_is_refused(self, jen_update_root, capsys):
        rc = jen_update_root.check_layout_cli(["--for", "install", "--bogus", "x"])
        assert rc == 1
        assert "unrecognized argument" in capsys.readouterr().err

    def test_install_mode_missing_dirs_prints_refusal_to_stderr(self, jen_update_root, capsys):
        rc = jen_update_root.check_layout_cli(["--for", "install"])
        assert rc == 1
        assert "needs --app-dir" in capsys.readouterr().err

    @pytest.mark.skipif(os.name != "posix", reason="POSIX path semantics required (os.path.normpath)")
    def test_success_prints_key_value_lines(self, jen_update_root, capsys, monkeypatch, tmp_path):
        monkeypatch.setattr(jen_update_root, "_layout_ancestors_ok", lambda name, path: None)
        monkeypatch.setattr(jen_update_root, "_layout_appdir_itself_ok", lambda path: None)
        # tmp_path lives under /tmp, one of _LAYOUT_FORBIDDEN_PREFIXES —
        # cleared here for the same reason TestCheckLayout's own
        # _bypass_ownership fixture clears it.
        monkeypatch.setattr(jen_update_root, "_LAYOUT_FORBIDDEN_PREFIXES", ())
        app, config, data = str(tmp_path / "app"), str(tmp_path / "etc"), str(tmp_path / "data")
        rc = jen_update_root.check_layout_cli(
            ["--for", "install", "--app-dir", app, "--config-dir", config, "--data-dir", data]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert f"app_dir={app}" in out
        assert f"config_dir={config}" in out
        assert f"data_dir={data}" in out


class TestWriteLayoutMarkersCli:
    """v5.67.0-beta.5 (Q117) — install.sh's own `write_layout_markers`
    step calls this once the three directories genuinely exist."""

    def test_missing_arguments_is_refused(self, jen_update_root, capsys):
        rc = jen_update_root.write_layout_markers_cli(["--app-dir", "/a"])
        assert rc == 1
        assert "needs --app-dir" in capsys.readouterr().err

    def test_unrecognized_argument_is_refused(self, jen_update_root, capsys):
        rc = jen_update_root.write_layout_markers_cli(["--bogus", "x"])
        assert rc == 1
        assert "unrecognized argument" in capsys.readouterr().err

    @pytest.mark.skipif(os.name != "posix", reason="os.chown requires POSIX")
    def test_success_marks_all_three(self, jen_update_root, tmp_path):
        app, config, data = tmp_path / "app", tmp_path / "etc", tmp_path / "data"
        app.mkdir()
        config.mkdir()
        data.mkdir()
        with patch("os.chown"), patch("os.chmod"):
            rc = jen_update_root.write_layout_markers_cli(
                [
                    "--app-dir",
                    str(app),
                    "--config-dir",
                    str(config),
                    "--data-dir",
                    str(data),
                    "--version",
                    "5.67.0-beta.5",
                ]
            )
        assert rc == 0
        for d in (app, config, data):
            marker = jen_update_root._read_layout_marker(str(d))
            assert marker is not None and marker["version"] == "5.67.0-beta.5"

    @pytest.mark.skipif(os.name != "posix", reason="os.chown requires POSIX")
    def test_write_failure_is_reported_and_refused(self, jen_update_root, capsys, tmp_path):
        # app_dir doesn't exist — writing its marker file fails with
        # ENOENT, which must be reported, not crash the whole call.
        missing = tmp_path / "does-not-exist"
        config, data = tmp_path / "etc", tmp_path / "data"
        config.mkdir()
        data.mkdir()
        with patch("os.chown"), patch("os.chmod"):
            rc = jen_update_root.write_layout_markers_cli(
                ["--app-dir", str(missing), "--config-dir", str(config), "--data-dir", str(data), "--version", "1.0.0"]
            )
        assert rc == 1
        assert "could not be marked" in capsys.readouterr().err


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

    # ── v5.66.0 (Q103): the namespace parameter, reused for the helper's own signature ──

    def test_default_namespace_is_jen_release(self, jen_update_root, keypair, tmp_path):
        key_path, signers_text = keypair
        sums_text = "abc123def456  jen-v5.26.0.tar.gz\n"
        sig_bytes = self._sign(key_path, tmp_path, sums_text, namespace="jen-release")
        assert jen_update_root.verify_release_signature(sums_text, sig_bytes, signers_text) is True

    def test_explicit_helper_namespace_verifies_a_helper_signature(self, jen_update_root, keypair, tmp_path):
        key_path, signers_text = keypair
        sums_text = "HELPER_VERSION = 6\n"
        sig_bytes = self._sign(key_path, tmp_path, sums_text, namespace="jen-kea-helper")
        assert (
            jen_update_root.verify_release_signature(sums_text, sig_bytes, signers_text, namespace="jen-kea-helper")
            is True
        )

    def test_a_release_namespace_signature_is_not_accepted_as_a_helper_signature(
        self, jen_update_root, keypair, tmp_path
    ):
        """The whole point of the distinct namespace: signing under "jen-release" (what
        release.yml uses for SHA256SUMS) must never verify when the caller asks for
        "jen-kea-helper" instead, and vice versa (test_wrong_namespace_fails already covers
        the opposite direction generically)."""
        key_path, signers_text = keypair
        sums_text = "HELPER_VERSION = 6\n"
        sig_bytes = self._sign(key_path, tmp_path, sums_text, namespace="jen-release")
        assert (
            jen_update_root.verify_release_signature(sums_text, sig_bytes, signers_text, namespace="jen-kea-helper")
            is False
        )

    def test_bytes_message_is_never_re_decoded(self, jen_update_root, keypair, tmp_path):
        """A `bytes` message is passed straight to ssh-keygen, never round-tripped through str
        decode/encode first (which could silently alter it for non-UTF-8 content)."""
        key_path, signers_text = keypair
        raw = b"\x00\x01HELPER_VERSION = 6\xff\xfe"
        sig_bytes = self._sign_bytes(key_path, tmp_path, raw, namespace="jen-kea-helper")
        assert (
            jen_update_root.verify_release_signature(raw, sig_bytes, signers_text, namespace="jen-kea-helper") is True
        )

    def _sign_bytes(self, key_path, tmp_path, data, namespace):
        import subprocess as _subprocess

        p = tmp_path / "raw_candidate"
        p.write_bytes(data)
        _subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", key_path, "-n", namespace, str(p)],
            check=True,
            capture_output=True,
        )
        return p.with_name(p.name + ".sig").read_bytes()

    def test_helper_signature_namespace_constant_matches_the_helper_files_own(self, jen_update_root):
        """Byte-identical to jen-kea-helper's own _UPDATE_SIGNATURE_NAMESPACE — the same twin
        discipline as RELEASE_SIGNERS (see TestHelperUpdateSignatureTwins below)."""
        assert jen_update_root.HELPER_SIGNATURE_NAMESPACE == "jen-kea-helper"


class TestHelperUpdateSignatureTwins:
    """v5.66.0 (Q103) — RELEASE_SIGNERS and the update-signature namespace must be
    byte-identical between jen-update-root.py and jen-kea-helper: this script writes
    <release>/app/jen-kea-helper.sig using RELEASE_SIGNERS + "jen-kea-helper", and the helper
    later verifies an update against the SAME two values — any drift would mean a signature
    one side accepts, the other silently doesn't (or worse, vice versa)."""

    def _load_helper(self):
        # jen-kea-helper has no .py suffix (it installs as
        # /usr/local/sbin/jen-kea-helper), so spec_from_file_location can't infer a
        # loader — name one explicitly, the same way tests/test_kea_helper.py does.
        import importlib.util
        from importlib.machinery import SourceFileLoader

        path = pathlib.Path(__file__).resolve().parent.parent / "jen-kea-helper"
        loader = SourceFileLoader("jen_kea_helper_twin_check", str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def test_release_signers_is_byte_identical(self, jen_update_root):
        helper = self._load_helper()
        assert jen_update_root.RELEASE_SIGNERS == helper.RELEASE_SIGNERS

    def test_namespace_is_byte_identical(self, jen_update_root):
        helper = self._load_helper()
        assert jen_update_root.HELPER_SIGNATURE_NAMESPACE == helper._UPDATE_SIGNATURE_NAMESPACE


class TestFetchBytesBounded:
    """v5.66.0-beta.2 (Q104, item g) — fetch_bytes_bounded() is fetch_text()'s bytes-and-a-cap
    sibling, for small fixed-shape assets (a signature file) where an unbounded read would let
    a compromised or misconfigured host hand back arbitrarily large data for something that
    should never be more than a few hundred bytes. Mirrors kea_host.py's own bounded reads
    (both capped at the same 8 KiB, read as max_bytes + 1 so an exactly-oversize response is
    still caught rather than silently truncated and accepted)."""

    class _FakeResp:
        def __init__(self, data):
            self._data = data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return self._data[:n]

    def test_a_normal_response_is_returned_whole(self, jen_update_root, monkeypatch):
        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=15: self._FakeResp(b"a small signature"))
        assert jen_update_root.fetch_bytes_bounded("https://example/x.sig", 1024) == b"a small signature"

    def test_a_response_over_the_cap_raises(self, jen_update_root, monkeypatch):
        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=15: self._FakeResp(b"x" * 20))
        with pytest.raises(RuntimeError):
            jen_update_root.fetch_bytes_bounded("https://example/x.sig", 10)

    def test_a_response_exactly_at_the_cap_is_accepted(self, jen_update_root, monkeypatch):
        monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=15: self._FakeResp(b"x" * 10))
        assert jen_update_root.fetch_bytes_bounded("https://example/x.sig", 10) == b"x" * 10


class TestInstallKeaHelperSignature:
    """v5.66.0 (Q103) — jen-update-root.py's own side of getting the signature onto disk:
    fetch the jen-kea-helper.sig asset, verify it against the JUST-EXTRACTED helper's real
    bytes, write it next to the helper. Never fails the update either way."""

    @pytest.fixture
    def keypair(self, tmp_path):
        import subprocess as _subprocess

        key_path = tmp_path / "throwaway-key"
        _subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-C", "release@jen", "-f", str(key_path), "-N", "", "-q"],
            check=True,
        )
        pub_line = key_path.with_suffix(".pub").read_text().strip()
        parts = pub_line.split()
        signers_text = f"{parts[2]} {parts[0]} {parts[1]}"
        return str(key_path), signers_text

    def _sign_bytes(self, key_path, data, namespace, tmp_path):
        """Signs a COPY of `data` at a throwaway filename, never `<tmp_path>/jen-kea-helper.sig`
        itself — that's the exact path _install_kea_helper_signature writes its OWN output to,
        so signing directly onto the real helper file would make "the file exists" trivially
        true regardless of whether the function under test ever wrote it."""
        import subprocess as _subprocess

        signable = tmp_path / "to_sign"
        signable.write_bytes(data)
        _subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", key_path, "-n", namespace, str(signable)],
            check=True,
            capture_output=True,
        )
        return signable.with_name(signable.name + ".sig").read_bytes()

    def test_no_helper_file_is_a_silent_noop(self, jen_update_root, tmp_path):
        jen_update_root._install_kea_helper_signature(str(tmp_path), [])
        assert not (tmp_path / "jen-kea-helper.sig").exists()

    def test_no_sig_asset_published_is_a_silent_noop(self, jen_update_root, tmp_path):
        (tmp_path / "jen-kea-helper").write_text("HELPER_VERSION = 6\n")
        jen_update_root._install_kea_helper_signature(
            str(tmp_path), [{"name": "SHA256SUMS", "browser_download_url": "x"}]
        )
        assert not (tmp_path / "jen-kea-helper.sig").exists()

    def test_a_non_github_asset_url_is_refused(self, jen_update_root, tmp_path):
        (tmp_path / "jen-kea-helper").write_text("HELPER_VERSION = 6\n")
        assets = [{"name": "jen-kea-helper.sig", "browser_download_url": "https://evil.example/x.sig"}]
        jen_update_root._install_kea_helper_signature(str(tmp_path), assets)
        assert not (tmp_path / "jen-kea-helper.sig").exists()

    def test_verifying_signature_is_written_0644(self, jen_update_root, tmp_path, keypair, monkeypatch):
        key_path, signers_text = keypair
        monkeypatch.setattr(jen_update_root, "RELEASE_SIGNERS", signers_text)
        helper_bytes = b"HELPER_VERSION = 6\n# body\n"
        (tmp_path / "jen-kea-helper").write_bytes(helper_bytes)
        sig_bytes = self._sign_bytes(key_path, helper_bytes, "jen-kea-helper", tmp_path)

        good_url = f"{jen_update_root.GITHUB_ASSET_PREFIX}v6.0.0/jen-kea-helper.sig"
        monkeypatch.setattr(jen_update_root, "fetch_bytes_bounded", lambda url, max_bytes, timeout=15: sig_bytes)
        assets = [{"name": "jen-kea-helper.sig", "browser_download_url": good_url}]

        jen_update_root._install_kea_helper_signature(str(tmp_path), assets)
        sig_dest = tmp_path / "jen-kea-helper.sig"
        assert sig_dest.read_bytes() == sig_bytes
        if sys.platform != "win32":
            assert oct(sig_dest.stat().st_mode)[-3:] == "644"

    def test_a_signature_that_does_not_verify_is_not_written(self, jen_update_root, tmp_path, keypair, monkeypatch):
        key_path, signers_text = keypair
        monkeypatch.setattr(jen_update_root, "RELEASE_SIGNERS", signers_text)
        helper_bytes = b"HELPER_VERSION = 6\n# body\n"
        (tmp_path / "jen-kea-helper").write_bytes(helper_bytes)
        # signed under the WRONG namespace — verification must fail
        sig_bytes = self._sign_bytes(key_path, helper_bytes, "jen-release", tmp_path)

        good_url = f"{jen_update_root.GITHUB_ASSET_PREFIX}v6.0.0/jen-kea-helper.sig"
        monkeypatch.setattr(jen_update_root, "fetch_bytes_bounded", lambda url, max_bytes, timeout=15: sig_bytes)
        assets = [{"name": "jen-kea-helper.sig", "browser_download_url": good_url}]

        jen_update_root._install_kea_helper_signature(str(tmp_path), assets)
        assert not (tmp_path / "jen-kea-helper.sig").exists()

    def test_a_fetch_failure_does_not_raise(self, jen_update_root, tmp_path, monkeypatch):
        (tmp_path / "jen-kea-helper").write_text("HELPER_VERSION = 6\n")
        good_url = f"{jen_update_root.GITHUB_ASSET_PREFIX}v6.0.0/jen-kea-helper.sig"

        def _raise(url, max_bytes, timeout=15):
            raise OSError("network is down")

        monkeypatch.setattr(jen_update_root, "fetch_bytes_bounded", _raise)
        assets = [{"name": "jen-kea-helper.sig", "browser_download_url": good_url}]
        jen_update_root._install_kea_helper_signature(str(tmp_path), assets)  # must not raise
        assert not (tmp_path / "jen-kea-helper.sig").exists()

    def test_an_oversize_signature_is_rejected(self, jen_update_root, tmp_path, monkeypatch):
        """v5.66.0-beta.2 (Q104, item g) — fetch_bytes_bounded() itself raises past the cap;
        this confirms _install_kea_helper_signature actually uses it (a bound only matters if
        every caller of a fetch actually goes through it)."""
        (tmp_path / "jen-kea-helper").write_text("HELPER_VERSION = 6\n")
        good_url = f"{jen_update_root.GITHUB_ASSET_PREFIX}v6.0.0/jen-kea-helper.sig"

        def _oversize(url, max_bytes, timeout=15):
            raise RuntimeError(f"response exceeded {max_bytes} bytes")

        monkeypatch.setattr(jen_update_root, "fetch_bytes_bounded", _oversize)
        assets = [{"name": "jen-kea-helper.sig", "browser_download_url": good_url}]
        jen_update_root._install_kea_helper_signature(str(tmp_path), assets)  # must not raise
        assert not (tmp_path / "jen-kea-helper.sig").exists()


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
    (root / "jen" / "jen.service.template").write_text("[Service]\nExecStart=@@APP_DIR@@/x\n")
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
        assert (dest / "jen.service.template").exists()
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
    release ships that live OUTSIDE the release directory: the systemd
    unit and jen-sudoers. (jen-update-root.py / jen-update.service are
    install_self_update_files()'s job.)

    v5.67.0 (Q114) — the unit ships as jen.service.template
    (@@APP_DIR@@/@@CONFIG_DIR@@/@@DATA_DIR@@ placeholders) and is
    RENDERED, not shutil.copy2'd verbatim — see render_jen_service()."""

    def _app_dir(self, tmp_path, with_service=True, with_sudoers=True):
        app = tmp_path / "release" / "app"
        app.mkdir(parents=True)
        if with_service:
            (app / "jen.service.template").write_text(
                "[Service]\nExecStart=@@APP_DIR@@/current/venv/bin/python\n"
                "Environment=JEN_CONFIG_DIR=@@CONFIG_DIR@@\n"
                "Environment=JEN_CONTENT_DIR=@@DATA_DIR@@\n"
            )
        if with_sudoers:
            (app / "jen-sudoers").write_text("www-data ALL=(root) NOPASSWD: /usr/bin/systemctl restart jen\n")
        return app

    def test_render_jen_service_fills_every_placeholder(self, jen_update_root, tmp_path):
        app = self._app_dir(tmp_path, with_sudoers=False)
        out = tmp_path / "jen.service"
        jen_update_root.render_jen_service(
            str(app / "jen.service.template"),
            str(out),
            app_dir="/srv/jen",
            config_dir="/srv/etc",
            data_dir="/srv/data",
        )
        rendered = out.read_text()
        assert "ExecStart=/srv/jen/current/venv/bin/python" in rendered
        assert "Environment=JEN_CONFIG_DIR=/srv/etc" in rendered
        assert "Environment=JEN_CONTENT_DIR=/srv/data" in rendered
        assert "@@" not in rendered

    def test_install_external_files_renders_not_copies_the_unit(self, jen_update_root, tmp_path):
        app = self._app_dir(tmp_path, with_sudoers=False)
        calls = []
        with (
            patch.object(jen_update_root, "render_jen_service") as render_mock,
            patch("subprocess.run", side_effect=lambda c, **k: calls.append(c) or MagicMock(returncode=0)),
        ):
            jen_update_root.install_external_files(str(app))
        render_mock.assert_called_once_with(str(app / "jen.service.template"), "/etc/systemd/system/jen.service")
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

    def test_a_fresh_staging_dir_is_kept_but_named_in_the_log(self, jen_update_root, tmp_path, capsys):
        """v5.65.1 (Q90) - a crashed update leaves `<version>.staging-<ts>`; it stays for a day
        (a concurrent updater's must never be deleted) but the next run says it is there."""
        rel = self._layout(tmp_path)
        (rel / "5.14.0").mkdir()
        fresh = rel / "5.14.1.staging-1790301888"
        fresh.mkdir()
        removed = jen_update_root._prune_old_releases(
            releases_dir=str(rel), current_link=str(tmp_path / "current"), install_dir=str(tmp_path / "no-flat")
        )
        assert fresh.is_dir() and removed == 0
        out = capsys.readouterr().out
        assert "5.14.1.staging-1790301888" in out and "older than a day" in out

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
        # v5.32.0 (Q38): fetch_json now returns the release LIST and main()
        # picks per channel — a stable box ignores the newer beta here.
        listing = [
            {"tag_name": "v9.9.10-beta.1", "prerelease": True, "draft": False, "assets": []},
            {"tag_name": "v9.9.9", "prerelease": False, "draft": False, "assets": []},
        ]
        with (
            patch.object(jen_update_root, "fetch_json", return_value=listing),
            patch.object(jen_update_root, "_update_channel", return_value="stable"),
            patch.object(jen_update_root, "_installed_version", return_value="9.9.9"),
            patch.object(jen_update_root, "_prune_old_releases"),
            patch.object(jen_update_root, "fetch_bytes_with_sha256") as download,
            patch.object(jen_update_root.sys, "argv", ["jen-update-root.py"]),
        ):
            assert jen_update_root.main() == 0
        download.assert_not_called()

    def test_beta_channel_picks_the_prerelease_and_stable_channel_does_not(self, jen_update_root):
        """The root side's own channel decision — the web page only
        suggests; this unit re-derives "latest" and must agree. The beta
        release carries no assets on purpose: reaching "no valid release
        asset" proves main() picked it (and got past "already running"),
        without needing the whole download/verify chain stubbed."""
        listing = [
            {"tag_name": "v9.9.10-beta.1", "prerelease": True, "draft": False, "assets": []},
            {"tag_name": "v9.9.9", "prerelease": False, "draft": False, "assets": []},
        ]
        for channel, expect_rc, expect_log in (
            ("beta", 1, "no valid release asset"),
            ("stable", 0, "Already running v9.9.9"),
        ):
            logs = []
            with (
                patch.object(jen_update_root, "fetch_json", return_value=listing),
                patch.object(jen_update_root, "_update_channel", return_value=channel),
                patch.object(jen_update_root, "_installed_version", return_value="9.9.9"),
                patch.object(jen_update_root, "_prune_old_releases"),
                patch.object(jen_update_root, "log", side_effect=logs.append),
                patch.object(jen_update_root, "fetch_bytes_with_sha256") as download,
                patch.object(jen_update_root.sys, "argv", ["jen-update-root.py"]),
            ):
                assert jen_update_root.main() == expect_rc, (channel, logs)
            assert any(expect_log in m for m in logs), (channel, logs)
            download.assert_not_called()

    def test_no_usable_release_for_channel_is_an_error_not_an_install(self, jen_update_root):
        with (
            patch.object(jen_update_root, "fetch_json", return_value=[{"tag_name": "v9.9.9", "draft": True}]),
            patch.object(jen_update_root, "_update_channel", return_value="stable"),
            patch.object(jen_update_root, "_installed_version", return_value="1.0.0"),
            patch.object(jen_update_root, "_prune_old_releases"),
            patch.object(jen_update_root, "fetch_bytes_with_sha256") as download,
            patch.object(jen_update_root.sys, "argv", ["jen-update-root.py"]),
        ):
            assert jen_update_root.main() == 1
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

    def test_sweep_restores_the_newest_old_copy_when_live_is_missing(self, jen_update_root, tmp_path):
        """v5.28.1 (Q26, C2) — a crash in the exact window between the
        two os.rename() calls (live moved aside to `.old-<ts>`, staging
        never renamed into place) used to lose BOTH recovery copies:
        there is no live directory at that point, and the old sweep just
        deleted the `.old-<ts>` right along with the never-verified
        `.staging-<ts>`. Now the newest `.old-<ts>` is restored as live,
        and only the (never-verified-complete) staging copy is deleted."""
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        old_dir = root_dir / "ipam.old-1"
        staging_dir = root_dir / "ipam.staging-2"
        old_dir.mkdir()
        staging_dir.mkdir()
        (old_dir / "manifest.json").write_text(json.dumps({"id": "ipam", "version": "1.2.3"}))

        jen_update_root._sweep_stale_plugin_dirs(str(root_dir))

        assert not old_dir.exists()
        assert not staging_dir.exists()
        live_dir = root_dir / "ipam"
        assert live_dir.is_dir(), "the newest .old-<ts> must be restored as the live copy"
        assert json.loads((live_dir / "manifest.json").read_text())["version"] == "1.2.3"

    def test_sweep_deletes_both_leftovers_when_live_already_exists(self, jen_update_root, tmp_path):
        """Unchanged behavior: once the live copy exists, the swap
        already finished — every leftover for that id is simply stale."""
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        live_dir = root_dir / "ipam"
        live_dir.mkdir()
        (live_dir / "manifest.json").write_text(json.dumps({"id": "ipam", "version": "2.0.0"}))
        old_dir = root_dir / "ipam.old-1"
        staging_dir = root_dir / "ipam.staging-2"
        old_dir.mkdir()
        staging_dir.mkdir()

        jen_update_root._sweep_stale_plugin_dirs(str(root_dir))

        assert not old_dir.exists()
        assert not staging_dir.exists()
        assert live_dir.is_dir()
        assert json.loads((live_dir / "manifest.json").read_text())["version"] == "2.0.0"

    def test_sweep_deletes_only_staging_leftovers_when_nothing_to_restore(self, jen_update_root, tmp_path):
        """Only a staging leftover (no old, no live) means an interrupted
        FIRST-ever install — there is nothing to restore, so it's simply
        deleted."""
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        staging_dir = root_dir / "ipam.staging-2"
        staging_dir.mkdir()

        jen_update_root._sweep_stale_plugin_dirs(str(root_dir))

        assert not staging_dir.exists()
        assert not (root_dir / "ipam").exists()

    def test_sweep_restores_the_newest_of_two_old_copies_by_integer_timestamp(self, jen_update_root, tmp_path):
        """Timestamps must be compared as integers, not strings — sort by
        the parsed int so e.g. ts=9 doesn't outrank ts=10 lexically."""
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        older = root_dir / "ipam.old-9"
        newer = root_dir / "ipam.old-10"
        older.mkdir()
        newer.mkdir()
        (older / "manifest.json").write_text(json.dumps({"id": "ipam", "version": "older"}))
        (newer / "manifest.json").write_text(json.dumps({"id": "ipam", "version": "newer"}))

        jen_update_root._sweep_stale_plugin_dirs(str(root_dir))

        assert not older.exists()
        assert not newer.exists()
        live_dir = root_dir / "ipam"
        assert live_dir.is_dir()
        assert json.loads((live_dir / "manifest.json").read_text())["version"] == "newer"

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


class TestPluginDepsRequests:
    """v5.30.0 (Q30, A1) — the `.deps` marker: apt-install the packages a
    plugin's REGISTRY entry declares under os_packages, through the same
    root-run request processor as install/remove. The allowlist is the
    control: nothing a registry entry (or anything www-data can write)
    says can make this script install a package it didn't already agree
    to. apt itself is always patched here — no test ever runs it."""

    def _run(self, jen_update_root, tmp_path, entries, marker="nd.deps"):
        port, stop = _serve_registry(entries, {})
        try:
            requests_dir = tmp_path / "requests"
            root_dir = tmp_path / "root"
            requests_dir.mkdir()
            (requests_dir / marker).touch()
            calls = []

            class Proc:
                returncode, stdout, stderr = 0, "", ""

            def fake_run(argv, **kw):
                calls.append(list(argv))
                return Proc()

            with patch.object(jen_update_root.subprocess, "run", side_effect=fake_run):
                rc = jen_update_root.process_plugin_requests(
                    str(requests_dir), str(root_dir), f"http://127.0.0.1:{port}/registry.json"
                )
            return rc, requests_dir, calls
        finally:
            stop()

    def test_happy_path_installs_the_declared_allowlisted_packages(self, jen_update_root, tmp_path):
        entries = [{"id": "nd", "download_url": "http://x/raw/v1.0.0", "sha256": "a" * 64, "os_packages": ["nmap"]}]
        rc, requests_dir, calls = self._run(jen_update_root, tmp_path, entries)
        assert rc == 0
        assert not (requests_dir / "nd.deps").exists()
        assert (requests_dir / "nd.deps.result").read_text().strip() == "ok"
        assert calls == [["/usr/bin/apt-get", "install", "-y", "-qq", "nmap"]]

    def test_a_package_outside_the_allowlist_is_refused_before_apt(self, jen_update_root, tmp_path):
        entries = [{"id": "nd", "os_packages": ["nmap", "curl"]}]
        _rc, requests_dir, calls = self._run(jen_update_root, tmp_path, entries)
        result = (requests_dir / "nd.deps.result").read_text()
        assert result.startswith("error:") and "'curl'" in result and "allowlist" in result
        assert calls == []

    @pytest.mark.parametrize("bad", [["nmap; rm -rf /"], ["../x"], [42], ["-badflag"], ["Nmap"]])
    def test_a_malformed_package_name_is_refused(self, jen_update_root, tmp_path, bad):
        entries = [{"id": "nd", "os_packages": bad}]
        _rc, requests_dir, calls = self._run(jen_update_root, tmp_path, entries)
        assert (requests_dir / "nd.deps.result").read_text().startswith("error:")
        assert calls == []

    def test_no_os_packages_declared_is_an_error_not_an_install(self, jen_update_root, tmp_path):
        entries = [{"id": "nd", "download_url": "http://x/raw/v1.0.0", "sha256": "a" * 64}]
        _rc, requests_dir, calls = self._run(jen_update_root, tmp_path, entries)
        assert "no os_packages" in (requests_dir / "nd.deps.result").read_text()
        assert calls == []

    def test_unknown_plugin_is_an_error(self, jen_update_root, tmp_path):
        _rc, requests_dir, calls = self._run(jen_update_root, tmp_path, [{"id": "someone-else"}])
        assert "not found in registry" in (requests_dir / "nd.deps.result").read_text()
        assert calls == []

    def test_apt_failure_retries_after_an_update_then_reports(self, jen_update_root, tmp_path):
        entries = [{"id": "nd", "os_packages": ["nmap"]}]
        port, stop = _serve_registry(entries, {})
        try:
            requests_dir = tmp_path / "requests"
            requests_dir.mkdir()
            (requests_dir / "nd.deps").touch()
            calls = []

            class Fail:
                returncode, stdout, stderr = 100, "", "E: Unable to locate package nmap\n"

            def fake_run(argv, **kw):
                calls.append(list(argv))
                return Fail()

            with patch.object(jen_update_root.subprocess, "run", side_effect=fake_run):
                jen_update_root.process_plugin_requests(
                    str(requests_dir), str(tmp_path / "root"), f"http://127.0.0.1:{port}/registry.json"
                )
            assert [c[1] for c in calls] == ["install", "update", "install"]
            result = (requests_dir / "nd.deps.result").read_text()
            assert result.startswith("error: apt-get install failed") and "Unable to locate package" in result
        finally:
            stop()

    def test_the_marker_never_carries_the_package_list(self, jen_update_root, tmp_path):
        """A marker with contents is still just a marker — the packages
        come from the registry, and what www-data wrote is ignored."""
        entries = [{"id": "nd", "os_packages": ["nmap"]}]
        port, stop = _serve_registry(entries, {})
        try:
            requests_dir = tmp_path / "requests"
            requests_dir.mkdir()
            (requests_dir / "nd.deps").write_text("curl\nnetcat\n")
            calls = []

            class Proc:
                returncode, stdout, stderr = 0, "", ""

            with patch.object(
                jen_update_root.subprocess, "run", side_effect=lambda a, **k: (calls.append(list(a)), Proc())[1]
            ):
                jen_update_root.process_plugin_requests(
                    str(requests_dir), str(tmp_path / "root"), f"http://127.0.0.1:{port}/registry.json"
                )
            assert calls == [["/usr/bin/apt-get", "install", "-y", "-qq", "nmap"]]
        finally:
            stop()

    def test_allowlist_is_exactly_nmap_ping_and_snmp_today(self, jen_update_root):
        # v5.57.0 (Q73) — widened for the round-5 plugins (watchdog needs
        # ping, switch-port-locator needs snmp), same allowlist philosophy
        # as jen-kea-helper's op table: a registry entry can only ever ask
        # for a package this exact Jen version already agreed to install.
        assert frozenset({"nmap", "iputils-ping", "snmp"}) == jen_update_root._DEPS_ALLOWED_PACKAGES
