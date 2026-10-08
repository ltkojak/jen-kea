"""
tests/test_config_file_lock.py
──────────────────────────────
v5.68.0-beta.18 (Q153) - the config lock covers the INSTALLER too. `AppConfig._write_lock` serialises Jen's threads; `install.sh --configure` is
another process that runs an interactive wizard and rewrites jen.config with Jen running, so a Settings save made during it was overwritten by the
installer's older copy. Every writer now also takes an exclusive advisory `flock` on `<config>.lock` for its whole read-modify-replace, and the
installer and `tools/private_write.py` take the same one. Linux (flock is POSIX); no database needed.
"""

import os
import pathlib
import platform
import stat
import subprocess
import sys
import textwrap
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(platform.system() == "Windows", reason="advisory flock is POSIX")

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    from jen import extensions

    path = tmp_path / "jen.config"
    path.write_text("[jen_db]\nhost = h\nuser = u\npassword = p\n")
    monkeypatch.setattr(extensions, "CONFIG_FILE", str(path))
    return path


def _hold(path, seconds, ready):
    """Hold an exclusive flock on `<path>.lock` for `seconds` (like the installer's --configure does for its whole wizard)."""
    import fcntl

    fd = os.open(f"{path}.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    ready.set()
    time.sleep(seconds)
    os.close(fd)


def _present(path):
    import configparser

    parser = configparser.ConfigParser(interpolation=None)
    parser.read(str(path))
    return {(s, k) for s in parser.sections() for k in parser[s]}


class TestAnExternalProcessAndTheServiceDoNotLoseEachOthersWrites:
    ROUNDS = 60

    def test_an_in_process_writer_and_an_external_writer_at_once_both_survive(self, cfg):
        script = textwrap.dedent(
            f"""
            import sys
            sys.path.insert(0, {str(ROOT)!r})
            from jen import extensions
            extensions.CONFIG_FILE = {str(cfg)!r}
            from jen.config import AppConfig
            for i in range({self.ROUNDS}):
                AppConfig().write_value("ext", f"e{{i}}", str(i), reload=False)
            """
        )
        proc = subprocess.Popen([sys.executable, "-c", script], stderr=subprocess.PIPE, text=True)
        from jen.config import AppConfig

        for i in range(self.ROUNDS):
            AppConfig().write_value("proc", f"p{i}", str(i), reload=False)
        _out, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err
        expected = {("proc", f"p{i}") for i in range(self.ROUNDS)} | {("ext", f"e{i}") for i in range(self.ROUNDS)}
        assert expected <= _present(cfg), "a write made by one process was lost to the other"

    def test_without_the_file_lock_the_same_run_loses_writes(self, cfg, monkeypatch):
        """The test has power: with the file lock disabled in BOTH processes (and the in-process lock too) writes are lost."""
        script = textwrap.dedent(
            f"""
            import sys, time
            sys.path.insert(0, {str(ROOT)!r})
            from jen import extensions
            extensions.CONFIG_FILE = {str(cfg)!r}
            import jen.config as c
            c.fcntl = None
            c.AppConfig._write_lock = type("N", (), {{"__enter__": lambda s: s, "__exit__": lambda s, *a: False}})()
            real = c.AppConfig._write_parser
            def slow(self, parser):
                time.sleep(0.002)
                real(self, parser)
            c.AppConfig._write_parser = slow
            for i in range({self.ROUNDS}):
                c.AppConfig().write_value("ext", f"e{{i}}", str(i), reload=False)
            """
        )
        import jen.config as c

        monkeypatch.setattr(c, "fcntl", None)
        monkeypatch.setattr(
            c.AppConfig, "_write_lock", type("N", (), {"__enter__": lambda s: s, "__exit__": lambda s, *a: False})()
        )
        real = c.AppConfig._write_parser

        def slow(self, parser):
            time.sleep(0.002)
            real(self, parser)

        monkeypatch.setattr(c.AppConfig, "_write_parser", slow)
        proc = subprocess.Popen([sys.executable, "-c", script], stderr=subprocess.PIPE, text=True)
        for i in range(self.ROUNDS):
            c.AppConfig().write_value("proc", f"p{i}", str(i), reload=False)
        proc.communicate(timeout=120)
        expected = {("proc", f"p{i}") for i in range(self.ROUNDS)} | {("ext", f"e{i}") for i in range(self.ROUNDS)}
        assert not expected <= _present(cfg), "nothing was lost even without the locks - the test proves nothing"


class TestAHeldLockMakesAWriterWait:
    def test_a_save_waits_for_the_installer_and_lands_after_it(self, cfg):
        from jen.config import AppConfig

        ready = threading.Event()
        holder = threading.Thread(target=_hold, args=(cfg, 1.0, ready))
        holder.start()
        ready.wait(5)
        started = time.monotonic()
        AppConfig().write_value("settings", "saved_after", "1", reload=False)
        waited = time.monotonic() - started
        holder.join()
        assert waited >= 0.7, f"the save did not wait for the lock holder ({waited:.2f}s)"
        assert ("settings", "saved_after") in _present(cfg)

    def test_a_lock_that_does_not_come_free_is_an_error_that_names_the_cause_and_writes_nothing(self, cfg, monkeypatch):
        import jen.config as c

        monkeypatch.setattr(c, "FILE_LOCK_WAIT_S", 0.3)
        ready = threading.Event()
        holder = threading.Thread(target=_hold, args=(cfg, 1.0, ready))
        holder.start()
        ready.wait(5)
        before = cfg.read_text()
        with pytest.raises(c.ConfigFileLocked, match=r"held by another process"):
            c.AppConfig().write_value("settings", "never", "1", reload=False)
        holder.join()
        assert cfg.read_text() == before

    def test_the_lock_is_released_after_each_write(self, cfg):
        import fcntl

        from jen.config import AppConfig

        AppConfig().write_value("a", "b", "1", reload=False)
        fd = os.open(f"{cfg}.lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # would raise if the writer still held it
        finally:
            os.close(fd)

    def test_a_failing_write_releases_it_too(self, cfg):
        import fcntl

        from jen.config import AppConfig

        with pytest.raises(ValueError):
            AppConfig().mutate(lambda p: (_ for _ in ()).throw(ValueError("boom")), reload=False)
        fd = os.open(f"{cfg}.lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)


class TestTheLockFile:
    def test_it_is_created_private_beside_the_config(self, cfg):
        from jen.config import AppConfig

        AppConfig().write_value("a", "b", "1", reload=False)
        lock = pathlib.Path(f"{cfg}.lock")
        assert lock.exists() and stat.S_IMODE(lock.stat().st_mode) == 0o600

    def test_a_nested_writer_does_not_deadlock_on_its_own_threads_lock(self, cfg):
        """The RLock allows nesting (a callback of `mutate` may reach another writer through a service) - and the file lock is taken once per
        thread, not once per writer: a second descriptor in the same thread would queue behind the first forever."""
        import jen.config as c

        done = threading.Event()

        def go():
            with c.AppConfig._write_lock, c._file_lock(str(cfg)), c._file_lock(str(cfg)):
                done.set()

        t = threading.Thread(target=go, daemon=True)
        t.start()
        assert done.wait(5), "taking the file lock twice in one thread deadlocked"


class TestTheLockFailsClosed:
    """v5.68.0-beta.19 (Q154) made the lock fail closed; v5.68.0-beta.20 (Q155) removed the one thing that still let it be two locks. beta.19 repaired an
    unopenable lock by renaming a fresh private file OVER it, and `flock` locks an INODE: an installer holding the old inode and Jen locking the new
    one both "held" the lock. There is no repair now - a symlink is refused, an unopenable file refuses the save with the exact fix, and the inode is
    never replaced."""

    def test_a_symlink_is_refused_never_followed_and_nothing_is_written(self, cfg, tmp_path):
        import jen.config as c

        victim = tmp_path / "victim"
        victim.write_text("untouched")
        os.symlink(victim, f"{cfg}.lock")
        before = cfg.read_text()
        with pytest.raises(c.ConfigFileLocked, match=r"is a symlink.*chown"):
            c.AppConfig().write_value("a", "b", "1", reload=False)
        assert victim.read_text() == "untouched" and cfg.read_text() == before

    def test_the_repair_function_is_gone(self):
        """`_replace_lock_with_private_file` made a second inode under a held lock; nothing in the module may rename over the lock path again."""
        import inspect

        import jen.config as c

        assert not hasattr(c, "_replace_lock_with_private_file")
        source = inspect.getsource(c._open_lock) + inspect.getsource(c._file_lock)
        assert "os.replace" not in source and "os.rename" not in source and "os.unlink" not in source

    def test_a_lock_a_privileged_holder_owns_is_refused_and_its_inode_never_changes(self, cfg, monkeypatch):
        """A privileged stand-in (a child process - as the installer does - that holds the flock on inode A and then makes the file unopenable for this
        account, the state `chown root` + `chmod 600` leaves): AppConfig's save is REFUSED at once with the fix in the message, the lock file is still
        inode A, the config is unchanged for as long as the holder lives, and once the operator's fix (a chmod, in the same inode) is made the save
        goes through. beta.19 renamed a fresh file over the lock here: the holder kept inode A, Jen locked inode B, and both held 'the' lock."""
        import jen.config as c

        if os.geteuid() == 0:
            pytest.skip("root opens a mode-000 file")
        lock = pathlib.Path(f"{cfg}.lock")
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                textwrap.dedent(
                    f"""
                    import fcntl, os, sys
                    fd = os.open({str(lock)!r}, os.O_RDWR | os.O_CREAT, 0o600)
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    os.chmod({str(lock)!r}, 0o000)
                    print("held", flush=True)
                    sys.stdin.read()
                    """
                ),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert holder.stdout.readline().strip() == "held"
            inode_before = os.stat(lock).st_ino
            config_before = cfg.read_text()
            with pytest.raises(c.ConfigFileLocked) as err:
                c.AppConfig().write_value("a", "b", "1", reload=False)
            message = str(err.value)
            assert (
                str(lock) in message and "cannot be opened" in message and "chown" in message and "chmod 600" in message
            )
            assert os.stat(lock).st_ino == inode_before, "the lock file was replaced - a second inode under a held lock"
            assert cfg.read_text() == config_before
            assert sorted(p.name for p in lock.parent.iterdir() if "repair" in p.name or p.name.endswith(".tmp")) == []
            os.chmod(lock, 0o600)  # the operator's fix, on the same inode
            monkeypatch.setattr(c, "FILE_LOCK_WAIT_S", 0.3)
            started = time.monotonic()
            with pytest.raises(c.ConfigFileLocked, match=r"held by another process"):
                c.AppConfig().write_value("a", "b", "1", reload=False)  # opened (same inode), and WAITS on the holder
            assert 0.25 <= time.monotonic() - started < 5
            assert os.stat(lock).st_ino == inode_before and cfg.read_text() == config_before
        finally:
            holder.stdin.close()
            holder.wait(10)
        c.AppConfig().write_value("a", "b", "1", reload=False)  # the holder has exited: the save goes through
        assert ("a", "b") in _present(cfg) and os.stat(lock).st_ino == inode_before

    def test_a_mode_000_lock_is_refused_with_the_fix_and_works_once_chmodded(self, cfg):
        import jen.config as c

        if os.geteuid() == 0:
            pytest.skip("root opens a mode-000 file")
        lock = pathlib.Path(f"{cfg}.lock")
        lock.write_text("")
        os.chmod(lock, 0o000)
        inode = os.stat(lock).st_ino
        before = cfg.read_text()
        with pytest.raises(c.ConfigFileLocked, match=r"chown.*chmod 600"):
            c.AppConfig().write_value("a", "b", "1", reload=False)
        assert os.stat(lock).st_ino == inode and cfg.read_text() == before
        os.chmod(lock, 0o600)
        c.AppConfig().write_value("a", "b", "1", reload=False)
        assert ("a", "b") in _present(cfg) and os.stat(lock).st_ino == inode

    def test_a_lock_that_cannot_be_opened_for_another_reason_is_refused(self, cfg, monkeypatch):
        import jen.config as c

        lock = f"{cfg}.lock"
        real_open = os.open

        def disk_gone(path, flags, mode=0o777, **kw):
            if str(path) == lock:
                raise OSError(5, "Input/output error", lock)
            return real_open(path, flags, mode, **kw)

        monkeypatch.setattr(os, "open", disk_gone)
        with pytest.raises(c.ConfigFileLocked, match="cannot be opened"):
            c.AppConfig().write_value("a", "b", "1", reload=False)
