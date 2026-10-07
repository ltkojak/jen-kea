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
