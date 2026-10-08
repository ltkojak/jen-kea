"""
tests/test_restore_private.py
─────────────────────────────
v5.68.0-beta.19 (Q154) - the recovery tool is no longer the one exempt writer. `jen/tools/restore.py` ran as root with `write_bytes` then `chmod`
(a previously absent SSL/SSH/MFA key born 0644 under the installer's umask 022), followed a symlink the service account had left at the live path,
truncated the live file if killed mid-write, and treated a failing `chown` as a printed warning. Every write now goes through `_restore_private`
(Q151's discipline: bounded by the restore root, no symlink component, O_EXCL 0600 unique temp, streamed, fsynced, `fchown` aborting, replace).
POSIX modes and symlinks: Linux CI; the tests never run as root, so ownership is the runner's own (a chown to oneself is allowed).
"""

import io
import os
import pathlib
import platform
import stat
import tarfile
import threading
import time

import pytest

from jen.tools import restore

pytestmark = pytest.mark.skipif(platform.system() == "Windows", reason="POSIX modes and symlinks")

ME = (os.getuid() if hasattr(os, "getuid") else 0, os.getgid() if hasattr(os, "getgid") else 0)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _no_temp_left(directory):
    return [p.name for p in pathlib.Path(directory).rglob(".*.tmp")] == []


class TestPlantedSymlinks:
    def test_a_symlink_at_the_live_config_is_refused_and_its_target_untouched(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        victim = tmp_path / "victim"
        victim.write_text("what the service account pointed the link at")
        os.symlink(victim, etc / "jen.config")
        with pytest.raises(restore.RestoreRefused, match="symlink"):
            restore._write_file(etc / "jen.config", b"[jen_db]\npassword = s3cret\n", 0o600, ME, etc)
        assert victim.read_text() == "what the service account pointed the link at"
        assert (etc / "jen.config").is_symlink() and _no_temp_left(etc)

    def test_a_symlink_at_a_key_under_ssl_is_refused(self, tmp_path):
        etc = tmp_path / "etc"
        (etc / "ssl").mkdir(parents=True)
        victim = tmp_path / "victim"
        victim.write_text("untouched")
        os.symlink(victim, etc / "ssl" / "server.key")
        with pytest.raises(restore.RestoreRefused):
            restore._write_file(etc / "ssl" / "server.key", b"-----BEGIN PRIVATE KEY-----", 0o600, ME, etc)
        assert victim.read_text() == "untouched"

    def test_a_symlinked_parent_directory_is_refused_and_nothing_lands_beyond_it(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        os.symlink(elsewhere, etc / "ssl")
        with pytest.raises(restore.RestoreRefused, match="symlink"):
            restore._write_file(etc / "ssl" / "server.key", b"key", 0o600, ME, etc)
        assert list(elsewhere.iterdir()) == []

    def test_a_path_outside_the_restore_root_is_refused(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        with pytest.raises(restore.RestoreRefused, match="not under"):
            restore._write_file(tmp_path / "outside" / "x", b"x", 0o600, ME, etc)
        with pytest.raises(restore.RestoreRefused, match="not under"):
            restore._write_file(etc / ".." / "outside" / "x", b"x", 0o600, ME, etc)
        assert not (tmp_path / "outside").exists()

    def test_the_content_copy_is_bounded_too(self, tmp_path):
        content = tmp_path / "content"
        content.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        os.symlink(elsewhere, content / "keys")
        src = tmp_path / "src"
        src.write_bytes(b"fallback key")
        with pytest.raises(restore.RestoreRefused):
            restore._copy_file(src, content / "keys" / "mfa_key", 0o600, ME, content)
        assert list(elsewhere.iterdir()) == []


class TestPrivateFromTheFirstByte:
    def test_a_previously_absent_key_is_born_0600_under_umask_022(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        old = os.umask(0o022)
        try:
            restore._write_file(etc / "ssl" / "server.key", b"-----BEGIN PRIVATE KEY-----", 0o600, ME, etc)
        finally:
            os.umask(old)
        assert _mode(etc / "ssl" / "server.key") == 0o600 and _no_temp_left(etc)

    def test_no_instant_has_it_group_or_other_readable(self, tmp_path, monkeypatch):
        """A directory watcher stats every entry in a tight loop while 40 restores run under umask 022 with a slow fsync (a 2 ms window between
        'written' and 'final mode')."""
        etc = tmp_path / "etc"
        etc.mkdir()
        real_fsync = os.fsync
        monkeypatch.setattr(os, "fsync", lambda fd: (time.sleep(0.002), real_fsync(fd))[1])
        seen, stop = set(), threading.Event()

        def watch():
            while not stop.is_set():
                try:
                    for entry in os.scandir(etc):
                        if entry.is_file(follow_symlinks=False):
                            seen.add(stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode))
                except (FileNotFoundError, OSError):
                    pass

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        old = os.umask(0o022)
        try:
            for i in range(40):
                restore._write_file(etc / "mfa_key", f"key-{i}".encode(), 0o600, ME, etc)
        finally:
            os.umask(old)
            stop.set()
            watcher.join(5)
        assert seen and seen <= {0o600}, f"modes seen: {sorted(oct(m) for m in seen)}"

    def test_the_final_mode_and_the_owner_are_applied_to_the_descriptor(self, tmp_path, monkeypatch):
        etc = tmp_path / "etc"
        etc.mkdir()
        chowned = []
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: chowned.append((uid, gid)))
        restore._write_file(etc / "jen.config", b"x", 0o640, (4242, 4343), etc)
        assert chowned == [(4242, 4343)] and _mode(etc / "jen.config") == 0o640


class TestAFailureLeavesTheLiveFileAlone:
    def test_a_failed_fchown_aborts_and_the_old_file_is_intact(self, tmp_path, monkeypatch):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "jen.config").write_text("OLD")

        def refuse(fd, uid, gid):
            raise PermissionError("operation not permitted")

        monkeypatch.setattr(os, "fchown", refuse)
        with pytest.raises(PermissionError):
            restore._write_file(etc / "jen.config", b"NEW", 0o600, (0, 0), etc)
        assert (etc / "jen.config").read_text() == "OLD" and _no_temp_left(etc)

    def test_a_copy_killed_mid_stream_leaves_the_live_file_old_and_no_temp(self, tmp_path):
        content = tmp_path / "content"
        content.mkdir()
        (content / "big.bin").write_bytes(b"OLD" * 10)

        class DiesHalfWay(io.RawIOBase):
            def __init__(self):
                self.sent = 0

            def read(self, n=-1):
                self.sent += 1
                if self.sent > 2:
                    raise OSError("killed")
                return b"x" * 1024

        with pytest.raises(OSError, match="killed"):
            restore._restore_private(content / "big.bin", DiesHalfWay(), 0o644, ME, content)
        assert (content / "big.bin").read_bytes() == b"OLD" * 10 and _no_temp_left(content)

    def test_a_failed_replace_removes_the_temp(self, tmp_path, monkeypatch):
        etc = tmp_path / "etc"
        etc.mkdir()
        monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(OSError, match="disk full"):
            restore._write_file(etc / "jen.config", b"x", 0o600, ME, etc)
        assert not (etc / "jen.config").exists() and _no_temp_left(etc)


def _tar(path, members):
    with tarfile.open(path, "w") as tf:
        for name, data, mode in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.uid, info.gid = ME
            tf.addfile(info, io.BytesIO(data))


class TestTheRollbackPathUsesTheSameWriter:
    def test_it_restores_the_snapshot_privately_and_never_follows_a_planted_link(self, tmp_path):
        root = tmp_path / "etc"
        root.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "precious").write_text("do not touch")
        os.symlink(elsewhere / "precious", root / "jen.config")  # a link planted since the snapshot
        _tar(
            tmp_path / "snap.tar",
            [("jen.config", b"[jen_db]\npassword = original\n", 0o600), ("ssl/server.key", b"KEY", 0o600)],
        )
        with pytest.raises(restore.RestoreRefused):
            restore._restore_tree(tmp_path / "snap.tar", root)
        assert (elsewhere / "precious").read_text() == "do not touch"

    def test_a_clean_rollback_restores_every_member_0600_and_removes_what_the_restore_added(self, tmp_path):
        root = tmp_path / "etc"
        (root / "ssl").mkdir(parents=True)
        (root / "ssl" / "added-by-the-restore.pem").write_text("new")
        (root / "jen.config").write_text("[jen_db]\npassword = changed-by-the-restore\n")
        os.chmod(root / "jen.config", 0o644)
        _tar(
            tmp_path / "snap.tar",
            [("jen.config", b"[jen_db]\npassword = original\n", 0o600), ("ssl/server.key", b"KEY", 0o600)],
        )
        old = os.umask(0o022)
        try:
            restore._restore_tree(tmp_path / "snap.tar", root)
        finally:
            os.umask(old)
        assert (root / "jen.config").read_text() == "[jen_db]\npassword = original\n"
        assert (root / "ssl" / "server.key").read_bytes() == b"KEY"
        assert not (root / "ssl" / "added-by-the-restore.pem").exists()
        assert _mode(root / "jen.config") == 0o600 and _mode(root / "ssl" / "server.key") == 0o600
        assert _no_temp_left(root)

    def test_a_rollback_chown_failure_is_loud_not_swallowed(self, tmp_path, monkeypatch):
        root = tmp_path / "etc"
        root.mkdir()
        _tar(tmp_path / "snap.tar", [("jen.config", b"x", 0o600)])
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: (_ for _ in ()).throw(PermissionError("nope")))
        with pytest.raises(PermissionError):
            restore._restore_tree(tmp_path / "snap.tar", root)
        assert not (root / "jen.config").exists()


class TestNoOtherWriterInTheTool:
    def test_restore_py_writes_files_only_through_restore_private(self):
        import ast

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "tools" / "restore.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(src)
        parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}

        def enclosing(node):
            while node in parents:
                node = parents[node]
                if isinstance(node, ast.FunctionDef):
                    return node.name
            return "<module>"

        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            mode = ""
            if name == "open" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            if name in ("write_bytes", "write_text") or (name == "open" and any(c in mode for c in "wax")):
                offenders.append(f"{enclosing(node)}: {ast.unparse(node)[:70]}")
        # safe_extract (bundle members into the 0700 scratch directory), _tar_tree (the pre-restore snapshot archive, inside the 0700 snapshot
        # directory) and the plain-text report are the reviewed exceptions
        assert {o.split(":")[0] for o in offenders} <= {"safe_extract", "_tar_tree", "_write_report"}, offenders

    def test_the_old_writers_are_off_the_private_files_allowlist(self):
        text = (pathlib.Path(__file__).resolve().parent / "test_private_files.py").read_text(encoding="utf-8")
        for name in ("_copy_file", "_restore_tree", "_write_file"):
            assert (
                f'("jen/tools/restore.py", "{name}")' not in text
                and f'"jen/tools/restore.py",\n        "{name}"' not in text
            )


class TestTheParentIsWalkedByDescriptors:
    """v5.68.0-beta.20 (Q155): the restore resolves no pathname after it was checked - every component below the restore root is opened
    `O_DIRECTORY | O_NOFOLLOW` relative to the previous descriptor and the temp, the rename and the fsync are relative to the last one."""

    def test_a_planted_symlink_parent_is_refused_and_nothing_is_created_or_written_beyond_it(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        os.symlink(outside, etc / "ssl")
        with pytest.raises(restore.RestoreRefused, match="symlink"):
            restore._write_file(etc / "ssl" / "sub" / "server.key", b"KEY", 0o600, ME, etc)
        assert list(outside.iterdir()) == []

    def test_a_parent_replaced_between_the_check_and_the_write_is_refused(self, tmp_path, monkeypatch):
        etc = tmp_path / "etc"
        (etc / "ssl").mkdir(parents=True)
        outside = tmp_path / "outside"
        outside.mkdir()
        real_fsync = os.fsync
        swapped = []

        def swap_then_fsync(fd):
            if not swapped:
                swapped.append(1)
                os.rename(etc / "ssl", etc / "ssl-moved")
                os.symlink(outside, etc / "ssl")
            return real_fsync(fd)

        monkeypatch.setattr(os, "fsync", swap_then_fsync)
        with pytest.raises(restore.RestoreRefused, match="replaced while"):
            restore._write_file(etc / "ssl" / "server.key", b"KEY", 0o600, ME, etc)
        assert list(outside.iterdir()) == []
        assert list((etc / "ssl-moved").iterdir()) == []

    def test_every_step_after_the_walk_is_relative_to_the_descriptor(self):
        import inspect

        source = inspect.getsource(restore._restore_private)
        for needle in ("dir_fd=dfd", "src_dir_fd=dfd", "dst_dir_fd=dfd"):
            assert needle in source
