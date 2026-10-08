"""
tests/test_private_write_tool.py - v5.68.0-beta.16 (Q151, item 1): tools/private_write.py, the writer the ROOT installer uses for `jen.config` and
its backup inside the service-writable config directory. Pure stdlib; POSIX file modes, so it skips on the Windows dev box and runs in CI.

The contract (see the tool's own docstring): refuse a symlink at the live path (and a symlink source); a unique O_EXCL 0600 temp in the same
directory; written and fsynced; the FINAL owner and mode applied to the open descriptor, a failing chown ABORTING (never swallowed); replaced
atomically; a failure leaves the previous file byte-for-byte intact and no temp file behind.
"""

import importlib.util
import io
import os
import pathlib
import stat
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")

TOOL = pathlib.Path(__file__).resolve().parent.parent / "tools" / "private_write.py"


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("private_write", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(*args, stdin=b""):
    return subprocess.run([sys.executable, str(TOOL), *args], input=stdin, capture_output=True)


class TestTheCommandLine:
    def test_writes_stdin_0600_and_replaces_an_existing_file(self, tmp_path):
        dest = tmp_path / "jen.config"
        dest.write_text("old")
        os.chmod(dest, 0o666)
        proc = _run(str(dest), stdin=b"[jen_db]\npassword = s3cret\n")
        assert proc.returncode == 0, proc.stderr
        assert dest.read_bytes() == b"[jen_db]\npassword = s3cret\n" and stat.S_IMODE(dest.stat().st_mode) == 0o600
        assert [p.name for p in tmp_path.iterdir()] == ["jen.config"]

    @pytest.mark.parametrize("umask", [0o000, 0o022, 0o077])
    def test_the_umask_never_loosens_it(self, tmp_path, umask):
        old = os.umask(umask)
        try:
            assert _run(str(tmp_path / "k"), stdin=b"x").returncode == 0
        finally:
            os.umask(old)
        assert stat.S_IMODE((tmp_path / "k").stat().st_mode) == 0o600

    def test_mode_and_owner_are_applied_to_the_file_before_the_rename(self, tmp_path):
        proc = _run(str(tmp_path / "k"), "--mode", "0640", "--owner", f"{os.getuid()}:{os.getgid()}", stdin=b"x")
        assert proc.returncode == 0, proc.stderr
        assert stat.S_IMODE((tmp_path / "k").stat().st_mode) == 0o640

    def test_copy_from_makes_a_private_copy(self, tmp_path):
        src = tmp_path / "jen.config"
        src.write_text("[jen_db]\npassword = s3cret\n")
        os.chmod(src, 0o644)
        proc = _run(str(tmp_path / "bak"), "--copy-from", str(src))
        assert proc.returncode == 0, proc.stderr
        assert (tmp_path / "bak").read_text() == src.read_text() and stat.S_IMODE(
            (tmp_path / "bak").stat().st_mode
        ) == 0o600

    @pytest.mark.parametrize("args", [["--mode", "9"], ["--owner", "nobody"], ["--owner", "1:x"]])
    def test_a_bad_argument_is_a_usage_error_and_writes_nothing(self, tmp_path, args):
        proc = _run(str(tmp_path / "k"), *args, stdin=b"x")
        assert proc.returncode == 2 and not (tmp_path / "k").exists()


class TestItRefusesToFollowOrReplaceALink:
    def test_a_symlink_at_the_live_path_is_refused_and_its_target_untouched(self, tmp_path):
        victim = tmp_path / "victim"
        victim.write_text("the target")
        os.symlink(victim, tmp_path / "jen.config")
        proc = _run(str(tmp_path / "jen.config"), stdin=b"[jen_db]\npassword = s3cret\n")
        assert proc.returncode == 3 and victim.read_text() == "the target"
        assert (tmp_path / "jen.config").is_symlink()
        assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".")] == []

    def test_a_directory_at_the_live_path_is_refused(self, tmp_path):
        (tmp_path / "jen.config").mkdir()
        assert _run(str(tmp_path / "jen.config"), stdin=b"x").returncode == 3

    def test_a_symlink_source_is_never_copied(self, tmp_path):
        secret = tmp_path / "other-secret"
        secret.write_text("not the config")
        os.symlink(secret, tmp_path / "jen.config")
        proc = _run(str(tmp_path / "bak"), "--copy-from", str(tmp_path / "jen.config"))
        assert proc.returncode == 3 and not (tmp_path / "bak").exists()

    def test_a_planted_symlink_at_the_backup_path_is_refused(self, tmp_path):
        """The service account plants `jen.config.<ts>.bak` as a link to a file root could overwrite: refused outright, the target untouched."""
        victim = tmp_path / "victim"
        victim.write_text("keep")
        src = tmp_path / "jen.config"
        src.write_text("[jen_db]\npassword = s3cret\n")
        os.symlink(victim, tmp_path / "bak")
        proc = _run(str(tmp_path / "bak"), "--copy-from", str(src))
        assert victim.read_text() == "keep"
        assert proc.returncode == 3, "a symlink at the destination is never replaced either"


class TestAFailedWriteLeavesNothingBehind:
    def _call(self, tool, dest, **kw):
        return tool.write_private(str(dest), b"new content", **kw)

    def test_a_failing_chown_aborts_before_the_replace(self, tool, tmp_path, monkeypatch):
        dest = tmp_path / "jen.config"
        dest.write_bytes(b"previous config")

        def refuse(fd, uid, gid):
            raise PermissionError(1, "Operation not permitted")

        monkeypatch.setattr(os, "fchown", refuse)
        with pytest.raises(PermissionError):
            self._call(tool, dest, owner=(0, 0))
        assert dest.read_bytes() == b"previous config", "byte-for-byte unchanged"
        assert [p.name for p in tmp_path.iterdir()] == ["jen.config"], "and no temp file"

    def test_a_failing_fsync_aborts_before_the_replace(self, tool, tmp_path, monkeypatch):
        dest = tmp_path / "jen.config"
        dest.write_bytes(b"previous config")

        def disk_full(fd):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(os, "fsync", disk_full)
        with pytest.raises(OSError):
            self._call(tool, dest)
        assert dest.read_bytes() == b"previous config" and [p.name for p in tmp_path.iterdir()] == ["jen.config"]

    def test_the_command_line_reports_a_failed_write_as_4(self, tool, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: (_ for _ in ()).throw(PermissionError(1, "no")))
        dest = tmp_path / "jen.config"
        dest.write_bytes(b"previous")
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"new")))
        assert tool.main([str(dest), "--owner", "0:0"]) == 4
        assert dest.read_bytes() == b"previous"

    def test_a_pre_planted_temp_name_is_skipped_never_opened(self, tool, tmp_path, monkeypatch):
        victim = tmp_path / "victim"
        victim.write_text("keep")
        names = iter(["aaaa", "bbbb"])
        monkeypatch.setattr(tool.secrets, "token_hex", lambda n: next(names))
        os.symlink(victim, tmp_path / ".k.aaaa.tmp")
        self._call(tool, tmp_path / "k")
        assert victim.read_text() == "keep" and (tmp_path / "k").read_bytes() == b"new content"


class TestTheConfigFileLock:
    """v5.68.0-beta.18 (Q153): `--lock PATH` holds the same exclusive advisory flock Jen's AppConfig writers take (`<config>.lock`) for the whole
    write, so the installer and the running service cannot both rewrite jen.config at once."""

    @staticmethod
    def _hold(path, seconds=1.5):
        import fcntl
        import threading
        import time

        ready = threading.Event()

        def run():
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            ready.set()
            time.sleep(seconds)
            os.close(fd)

        t = threading.Thread(target=run)
        t.start()
        ready.wait(5)
        return t

    def test_the_write_waits_for_a_held_lock_and_then_happens(self, tmp_path):
        import time

        lock = tmp_path / "jen.config.lock"
        holder = self._hold(str(lock), 1.2)
        started = time.monotonic()
        proc = _run(str(tmp_path / "jen.config"), "--lock", str(lock), stdin=b"[a]\nb = 1\n")
        waited = time.monotonic() - started
        holder.join()
        assert proc.returncode == 0, proc.stderr
        assert waited >= 0.9, f"it did not wait for the lock holder ({waited:.2f}s)"
        assert (tmp_path / "jen.config").read_bytes() == b"[a]\nb = 1\n"

    def test_the_lock_file_is_created_0600_and_the_write_holds_nothing_afterwards(self, tmp_path):
        import fcntl

        lock = tmp_path / "jen.config.lock"
        assert _run(str(tmp_path / "jen.config"), "--lock", str(lock), stdin=b"x").returncode == 0
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600
        fd = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def test_a_backup_copy_reads_the_live_file_inside_the_lock(self, tmp_path):
        """The copy is read AFTER the lock is taken: a writer that held it and changed the file is seen, never a stale read from before."""
        import threading
        import time

        live = tmp_path / "jen.config"
        live.write_text("before")
        lock = tmp_path / "jen.config.lock"
        holder = self._hold(str(lock), 1.0)
        threading.Timer(0.3, lambda: live.write_text("after")).start()  # the holder's save, while it holds the lock
        time.sleep(0.05)
        proc = _run(str(tmp_path / "bak"), "--copy-from", str(live), "--lock", str(lock))
        holder.join()
        assert proc.returncode == 0, proc.stderr
        assert (tmp_path / "bak").read_text() == "after"

    def test_a_symlink_lock_path_is_not_followed(self, tmp_path):
        victim = tmp_path / "victim"
        victim.write_text("untouched")
        os.symlink(victim, tmp_path / "jen.config.lock")
        proc = _run(str(tmp_path / "jen.config"), "--lock", str(tmp_path / "jen.config.lock"), stdin=b"x")
        assert proc.returncode == 6 and not (tmp_path / "jen.config").exists()
        assert victim.read_text() == "untouched"


class TestTheLockIsOneInodeNormalisedInPlace:
    """v5.68.0-beta.20 (Q155): `take_lock` opens the lock ONCE with O_NOFOLLOW and normalises THAT inode (fchown/fchmod, which keep an flock); it never
    renames a new file over the path - a lock is an inode, and two inodes are two locks. `--hold-lock` is the installer's side of the same primitive."""

    def test_an_existing_loose_lock_is_made_0600_in_place_the_inode_unchanged(self, tool, tmp_path):
        lock = tmp_path / "jen.config.lock"
        lock.write_text("")
        os.chmod(lock, 0o666)
        inode = lock.stat().st_ino
        fd = tool.take_lock(str(lock), owner=(os.getuid(), os.getgid()))
        os.close(fd)
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600 and lock.stat().st_ino == inode

    def test_a_chown_and_chmod_do_not_drop_a_held_flock(self, tool, tmp_path):
        """The holder keeps its flock across the normalisation another opener makes: the second take_lock waits (it is the same inode)."""
        import fcntl

        lock = tmp_path / "jen.config.lock"
        lock.write_text("")
        os.chmod(lock, 0o644)
        held = os.open(lock, os.O_RDWR)
        fcntl.flock(held, fcntl.LOCK_EX)
        try:
            with pytest.raises(TimeoutError, match="held by another process"):
                tool.take_lock(str(lock), owner=(os.getuid(), os.getgid()), wait_s=0.3)
            assert stat.S_IMODE(lock.stat().st_mode) == 0o600, "normalised in place while it was held"
            second = os.open(lock, os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)  # still the holder's lock: one inode
            finally:
                os.close(second)
        finally:
            os.close(held)

    def test_it_never_replaces_the_file(self, tool):
        import inspect

        source = inspect.getsource(tool.take_lock) + inspect.getsource(tool._normalise_lock)
        assert "os.replace" not in source and "os.rename" not in source and "os.unlink" not in source

    def test_a_hard_linked_lock_is_refused_and_never_chowned(self, tool, tmp_path):
        target = tmp_path / "somebody-elses-file"
        target.write_text("x")
        os.link(target, tmp_path / "jen.config.lock")
        with pytest.raises(tool.Refused, match="links"):
            tool.take_lock(str(tmp_path / "jen.config.lock"), owner=(os.getuid(), os.getgid()))

    def test_a_symlink_is_refused(self, tool, tmp_path):
        victim = tmp_path / "victim"
        victim.write_text("x")
        os.symlink(victim, tmp_path / "jen.config.lock")
        with pytest.raises(OSError):
            tool.take_lock(str(tmp_path / "jen.config.lock"))
        assert victim.read_text() == "x"

    def test_hold_lock_prints_locked_holds_until_stdin_closes_and_then_releases(self, tmp_path):
        import fcntl

        lock = tmp_path / "jen.config.lock"
        proc = subprocess.Popen(
            [sys.executable, str(TOOL), "--hold-lock", str(lock), "--owner", f"{os.getuid()}:{os.getgid()}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert proc.stdout.readline().strip() == "locked"
            fd = os.open(lock, os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        finally:
            proc.stdin.close()
            assert proc.wait(10) == 0
        fd = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released with the holder
        finally:
            os.close(fd)

    def test_hold_lock_on_a_symlink_exits_non_zero_and_touches_nothing(self, tmp_path):
        victim = tmp_path / "victim"
        victim.write_text("x")
        os.symlink(victim, tmp_path / "jen.config.lock")
        proc = _run("--hold-lock", str(tmp_path / "jen.config.lock"))
        assert proc.returncode == 6 and victim.read_text() == "x"


class TestATrustedRootIsWalkedByDescriptors:
    """v5.68.0-beta.20 (Q155): with `--trusted-root DIR` no pathname is re-resolved after it was checked. A symlink the service account planted at
    `$CONFIG_DIR/backups` was followed by root (the reviewer reproduced it with the shipped file)."""

    def test_a_file_is_written_into_directories_created_0700_below_the_root(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        proc = _run(str(root / "config" / "jen.config.1.bak"), "--trusted-root", str(root), stdin=b"secret")
        assert proc.returncode == 0, proc.stderr
        written = root / "config" / "jen.config.1.bak"
        assert written.read_bytes() == b"secret" and stat.S_IMODE(written.stat().st_mode) == 0o600
        assert stat.S_IMODE((root / "config").stat().st_mode) == 0o700

    def test_a_planted_symlink_component_is_refused_and_nothing_lands_or_is_created_beyond_it(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        os.symlink(outside, root / "backups")
        proc = _run(str(root / "backups" / "jen.config.1.bak"), "--trusted-root", str(root), stdin=b"secret")
        assert proc.returncode == 3, proc.stderr
        assert list(outside.iterdir()) == [], "something was written through the planted symlink"
        assert (root / "backups").is_symlink()

    def test_the_root_itself_may_be_reached_by_a_link(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        os.symlink(real, tmp_path / "etc-jen")
        proc = _run(str(tmp_path / "etc-jen" / "jen.config"), "--trusted-root", str(tmp_path / "etc-jen"), stdin=b"x")
        assert proc.returncode == 0, proc.stderr
        assert (real / "jen.config").read_bytes() == b"x"

    def test_a_destination_outside_the_root_is_refused(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        proc = _run(str(tmp_path / "elsewhere" / "k"), "--trusted-root", str(root), stdin=b"x")
        assert proc.returncode == 3 and not (tmp_path / "elsewhere").exists()

    def test_a_symlink_at_the_destination_is_refused_in_this_mode_too(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        victim = tmp_path / "victim"
        victim.write_text("untouched")
        os.symlink(victim, root / "jen.config")
        proc = _run(str(root / "jen.config"), "--trusted-root", str(root), stdin=b"x")
        assert proc.returncode == 3 and victim.read_text() == "untouched"

    def test_a_parent_replaced_between_the_check_and_the_write_is_refused(self, tool, tmp_path, monkeypatch):
        """The attacker swaps the parent for a symlink AFTER the walk validated it (the window is the fsync of the data): the write must not
        land beyond the link and must say so; the original directory keeps no half-written file."""
        root = tmp_path / "root"
        (root / "backups").mkdir(parents=True)
        outside = tmp_path / "outside"
        outside.mkdir()
        real_fsync = os.fsync
        swapped = []

        def swap_then_fsync(fd):
            if not swapped:
                swapped.append(1)
                os.rename(root / "backups", root / "backups-moved")
                os.symlink(outside, root / "backups")
            return real_fsync(fd)

        monkeypatch.setattr(os, "fsync", swap_then_fsync)
        with pytest.raises(tool.Refused, match="replaced while"):
            tool.write_private(str(root / "backups" / "jen.config.bak"), b"secret", 0o600, None, trusted_root=str(root))
        assert list(outside.iterdir()) == [], "the write landed beyond the symlink that replaced the parent"
        assert [p.name for p in (root / "backups-moved").iterdir()] == [], (
            "a temp or a half-written file was left behind"
        )

    def test_a_failure_leaves_the_old_file_and_no_temp(self, tool, tmp_path, monkeypatch):
        root = tmp_path / "root"
        root.mkdir()
        (root / "k").write_text("OLD")
        monkeypatch.setattr(os, "fchown", lambda *a: (_ for _ in ()).throw(PermissionError("no")))
        with pytest.raises(PermissionError):
            tool.write_private(str(root / "k"), b"NEW", 0o600, (0, 0), trusted_root=str(root))
        assert (root / "k").read_text() == "OLD" and sorted(p.name for p in root.iterdir()) == ["k"]
