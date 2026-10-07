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

    def test_a_symlink_there_is_never_followed_and_the_save_still_works_unlocked(self, cfg, tmp_path, caplog):
        from jen.config import AppConfig

        victim = tmp_path / "victim"
        victim.write_text("untouched")
        os.symlink(victim, f"{cfg}.lock")
        AppConfig().write_value("a", "b", "1", reload=False)
        assert victim.read_text() == "untouched"
        assert ("a", "b") in _present(cfg)
        assert "unavailable" in caplog.text

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
