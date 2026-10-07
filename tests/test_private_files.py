"""
tests/test_private_files.py - v5.68.0-beta.15 (Q150, item F-b): a secret is private from its FIRST BYTE.

`jen.config` (every database password and API credential), the SSL private key and the Fernet key were each written with `open(tmp, "w")`
- the process umask, 0644 under systemd's default 0022 - and tightened with `chmod` afterwards. `jen/services/private_files.py` is the one
discipline (a unique O_EXCL 0600 temp in the target's directory, fsync, the final owner/mode applied to the DESCRIPTOR, os.replace); these
tests prove it three ways: the function itself, a DIRECTORY WATCHER that stats every entry in the directory in a tight loop while each
real writer runs (so a window of any width, not just one a test happens to look at, is seen), and source guards that keep the umask
in run.py and the unit and refuse a new bare write-mode open() that nobody reviewed.

The watcher and the mode tests need POSIX file modes, so they skip on the Windows dev box and run in CI.
"""

import ast
import os
import pathlib
import stat
import sys
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
posix = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX file modes")


# ── the function ─────────────────────────────────────────────────────────────


@posix
class TestWritePrivateFile:
    def test_bytes_and_str_end_with_the_mode_asked_for(self, tmp_path):
        from jen.services.private_files import write_private_file

        a, b = tmp_path / "a", tmp_path / "b"
        write_private_file(str(a), b"secret", 0o600)
        write_private_file(str(b), "secret é", 0o640)
        assert a.read_bytes() == b"secret" and stat.S_IMODE(a.stat().st_mode) == 0o600
        assert b.read_text(encoding="utf-8") == "secret é" and stat.S_IMODE(b.stat().st_mode) == 0o640

    @pytest.mark.parametrize("umask", [0o000, 0o022, 0o077])
    def test_the_umask_never_loosens_a_0600_file(self, tmp_path, umask):
        from jen.services.private_files import write_private_file

        old = os.umask(umask)
        try:
            write_private_file(str(tmp_path / "k"), b"x", 0o600)
        finally:
            os.umask(old)
        assert stat.S_IMODE((tmp_path / "k").stat().st_mode) == 0o600

    def test_it_replaces_an_existing_file_in_one_step_and_leaves_no_temp_behind(self, tmp_path):
        from jen.services.private_files import write_private_file

        target = tmp_path / "jen.config"
        target.write_text("old")
        os.chmod(target, 0o666)
        write_private_file(str(target), "new", 0o600)
        assert target.read_text() == "new" and stat.S_IMODE(target.stat().st_mode) == 0o600
        assert [p.name for p in tmp_path.iterdir()] == ["jen.config"]

    def test_a_planted_symlink_at_the_temp_name_is_never_written_through(self, tmp_path, monkeypatch):
        import jen.services.private_files as pf

        victim = tmp_path / "victim"
        victim.write_text("keep")
        names = iter(["aaaa", "bbbb"])
        monkeypatch.setattr(pf.secrets, "token_hex", lambda n: next(names))
        os.symlink(victim, tmp_path / ".k.aaaa.tmp")  # where the first attempt would have created its temp
        pf.write_private_file(str(tmp_path / "k"), b"secret", 0o600)
        assert victim.read_text() == "keep", "O_EXCL | O_NOFOLLOW: the pre-planted link is skipped, never followed"
        assert (tmp_path / "k").read_bytes() == b"secret"

    def test_a_failure_removes_the_temp_and_leaves_the_target_alone(self, tmp_path, monkeypatch):
        import jen.services.private_files as pf

        target = tmp_path / "k"
        target.write_text("old")

        def boom(src, dst):
            raise OSError("disk went away")

        monkeypatch.setattr(pf.os, "replace", boom)
        with pytest.raises(OSError):
            pf.write_private_file(str(target), b"new", 0o600)
        assert target.read_text() == "old" and [p.name for p in tmp_path.iterdir()] == ["k"]

    def test_the_temp_is_created_in_the_targets_own_directory(self, tmp_path, monkeypatch):
        import jen.services.private_files as pf

        seen = []
        real = pf.os.open
        monkeypatch.setattr(
            pf.os,
            "open",
            lambda path, flags, mode=0o777, **kw: seen.append((path, flags, mode)) or real(path, flags, mode, **kw),
        )
        pf.write_private_file(str(tmp_path / "k"), b"x", 0o640)
        path, flags, mode = seen[0]
        assert os.path.dirname(path) == str(tmp_path) and mode == 0o600
        assert flags & os.O_EXCL and flags & os.O_CREAT, "created exclusively: nothing pre-existing is ever opened"


# ── the directory watcher ────────────────────────────────────────────────────


class _Watcher(threading.Thread):
    """Stats every entry of `directory` in a tight loop and records each (name, mode, size-was-zero) it ever sees."""

    def __init__(self, directory):
        super().__init__(daemon=True)
        self.directory, self.stop, self.modes, self.samples = directory, threading.Event(), {}, 0

    def run(self):
        while not self.stop.is_set():
            try:
                with os.scandir(self.directory) as it:
                    for entry in it:
                        try:
                            mode = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
                        except FileNotFoundError:
                            continue
                        kind = "temp" if entry.name.startswith(".") and entry.name.endswith(".tmp") else entry.name
                        self.modes.setdefault(kind, set()).add(mode)
                        self.samples += 1
            except FileNotFoundError:
                pass

    def watch(self, work, rounds):
        self.start()
        try:
            for i in range(rounds):
                work(i)
        finally:
            self.stop.set()
            self.join(5)


def _say(request, line):
    """A line in the pytest run's own report (visible in CI without -s)."""
    reporter = request.config.pluginmanager.getplugin("terminalreporter")
    if reporter is not None:
        reporter.write_line("")
        reporter.write_line(line)


@posix
class TestEveryPrivateWriteIsPrivateAtEveryInstant:
    """Run each real writer 300 times under a tight directory watcher with umask 022 (so an `open()` would have produced 0644 and the
    watcher would see it). A file whose FINAL mode is 0600 must only ever be seen 0600; one whose final mode is 0640 is seen 0600 while
    it is being written and 0640 only after it is complete - never 0644/0666 at any instant."""

    ROUNDS = 300

    @pytest.fixture(autouse=True)
    def _umask_and_a_wide_window(self, monkeypatch):
        old = os.umask(0o022)
        real_fsync = os.fsync

        def slow_fsync(fd):
            time.sleep(
                0.001
            )  # a 1 ms window between "written" and "final mode": a watcher that polls can no longer miss the temp file
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", slow_fsync)
        yield
        os.umask(old)

    def _check(self, request, label, watcher, final):
        observed = {k: sorted(oct(m) for m in v) for k, v in sorted(watcher.modes.items())}
        _say(
            request,
            f"[private-write watcher] {label}: {watcher.samples} stats over {self.ROUNDS} writes; modes seen {observed}",
        )
        assert watcher.samples > 0, "the watcher never saw the directory at all"
        allowed = {0o600, final}
        for kind, modes in watcher.modes.items():
            assert modes <= allowed, f"{label}: {kind} was seen with mode(s) {sorted(oct(m) for m in modes - allowed)}"
        assert any(k == "temp" for k in watcher.modes) or final != 0o600, (
            f"{label}: the watcher never caught a temp file in flight - the test has no power"
        )

    def test_jen_config_is_0600_at_every_instant(self, tmp_path, monkeypatch, request):
        import configparser

        from jen import extensions
        from jen.config import AppConfig

        monkeypatch.setattr(extensions, "CONFIG_FILE", str(tmp_path / "jen.config"))
        parser = configparser.ConfigParser(interpolation=None)
        parser.add_section("jen_db")
        w = _Watcher(str(tmp_path))
        w.watch(
            lambda i: (parser.set("jen_db", "password", f"s3cret-{i}"), AppConfig()._write_parser(parser)), self.ROUNDS
        )
        self._check(request, "jen.config", w, 0o600)
        assert stat.S_IMODE((tmp_path / "jen.config").stat().st_mode) == 0o600

    def test_the_ssl_private_key_is_0600_while_written_and_0640_when_complete(self, tmp_path, request):
        from jen.services.certs import write_atomically

        w = _Watcher(str(tmp_path))
        w.watch(
            lambda i: write_atomically(str(tmp_path / "key.pem"), f"-----BEGIN PRIVATE KEY-----\n{i}\n", 0o640),
            self.ROUNDS,
        )
        self._check(request, "ssl/key.pem (final 0640)", w, 0o640)
        assert stat.S_IMODE((tmp_path / "key.pem").stat().st_mode) == 0o640

    def test_the_fernet_key_is_0600_at_every_instant(self, tmp_path, monkeypatch, request):
        from jen import extensions
        from jen.services import crypto

        monkeypatch.setattr(extensions, "CONFIG_DIR", str(tmp_path))
        monkeypatch.setattr(extensions, "CONTENT_KEYS_DIR", str(tmp_path / "keys"), raising=False)
        key = tmp_path / "mfa_key"
        monkeypatch.setattr(crypto, "_key_candidates", lambda: [str(key)])

        def work(i):
            if key.exists():
                key.unlink()
            assert crypto._load_or_create_key()

        w = _Watcher(str(tmp_path))
        w.watch(work, self.ROUNDS)
        self._check(request, "the Fernet key", w, 0o600)

    def test_the_flask_secret_key_is_0600_while_written_and_0640_when_complete(self, tmp_path, monkeypatch, request):
        import jen
        from jen import extensions

        monkeypatch.setattr(extensions, "CONFIG_DIR", str(tmp_path))
        monkeypatch.setattr(extensions, "CONTENT_KEYS_DIR", str(tmp_path / "keys"), raising=False)
        target = tmp_path / "secret_key"

        def work(i):
            if target.exists():
                target.unlink()
            assert jen._load_secret_key()

        w = _Watcher(str(tmp_path))
        w.watch(work, self.ROUNDS)
        self._check(request, "the Flask secret key (final 0640)", w, 0o640)


# ── the source rules ─────────────────────────────────────────────────────────


class TestTheUmaskIsSetWhereTheServiceStarts:
    def test_run_py_sets_the_umask_first_thing_in_main(self):
        tree = ast.parse((ROOT / "run.py").read_text(encoding="utf-8"))
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        first = main.body[0]
        assert (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Call)
            and ast.unparse(first.value.func) == "os.umask"
            and ast.literal_eval(first.value.args[0]) == 0o077
        ), "run.py main() must begin with os.umask(0o077): Docker and a hand-run server have no unit to set it"

    def test_the_unit_template_carries_umask_0077_in_the_service_section(self):
        text = (ROOT / "jen.service.template").read_text(encoding="utf-8")
        service = text.split("[Service]", 1)[1].split("[Install]", 1)[0]
        assert any(line.strip() == "UMask=0077" for line in service.splitlines())

    def test_the_root_updater_and_the_plugin_installer_units_are_not_given_it(self):
        for unit in ("jen-update.service", "jen-plugin-install.service"):
            assert "UMask" not in (ROOT / unit).read_text(encoding="utf-8"), (
                f"{unit} is a separate root unit: a 0077 umask would make every file the updater installs unreadable to the service user"
            )


# Every write-mode open() / os.fdopen() / Path.write_* in jen/, by (file, enclosing function) - each reviewed and WHY it is not a secret
# that needs the private-file writer. A new one fails here: write a secret with jen.services.private_files.write_private_file, or add
# the entry with its reason once someone has looked.
REVIEWED_WRITES = {
    ("jen/routes/database.py", "import_inspect"): "an uploaded export in a 0600 temp from os.open(0o600)",
    ("jen/routes/database.py", "recovery_bundle"): "the recovery bundle, created through os.open(..., 0o600)",
    ("jen/routes/settings/branding.py", "upload_custom_icon"): "a public logo/icon under static/",
    (
        "jen/routes/settings/security.py",
        "validate_cert_material",
    ): "a TemporaryDirectory (0700) used only to test-load a pair",
    ("jen/services/auth.py", "paramiko_load_known_hosts"): "known_hosts: public keys, opened for append to create it",
    ("jen/services/content.py", "ensure_content_dirs"): "a writability probe file with no content",
    ("jen/services/content.py", "migrate_legacy_content"): "an empty marker file",
    ("jen/services/dbexport.py", "publish_backup"): "created through os.open(..., 0o600), then fdopen'd",
    ("jen/services/dbexport.py", "_write_backup.write_fn"): "gzip stream onto an fd the caller created 0600",
    ("jen/services/dbexport.py", "write_jen_export"): "gzip stream; the path is chmod 0600 and the folder is 0700",
    ("jen/services/dbexport.py", "write_kea_export"): "gzip stream; the path is chmod 0600 and the folder is 0700",
    ("jen/services/plugins.py", "_write_plugin_request"): "a request marker for the root plugin installer: no secret",
    ("jen/services/plugins.py", "enable_plugin"): "a request marker: no secret",
    ("jen/services/recovery.py", "build_tar"): "an in-memory tar stream",
    ("jen/services/recovery.py", "build_stream"): "an in-memory tar stream",
    # v5.68.0-beta.19 (Q154): `_copy_file`, `_restore_tree` and `_write_file` are no longer here - they write through `_restore_private`
    ("jen/tools/restore.py", "_tar_tree"): "an in-memory/out-file tar stream of the restore snapshot",
    ("jen/tools/restore.py", "safe_extract"): "bundle members into the restore's own 0700 scratch directory",
    ("jen/tools/restore.py", "_write_report"): "a plain-text restore report",
    (
        "jen/services/kea_host.py",
        "verify_helper_signature",
    ): "the release signers file and a signature, in a temp dir: public",
}


def _writes_in(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def enclosing(node):
        names = []
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.append(node.name)
        return ".".join(reversed(names)) or "<module>"

    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else "")
        if name in ("open", "fdopen"):
            mode = node.args[1].value if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) else None
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = kw.value.value
            owner = ast.unparse(func.value) if isinstance(func, ast.Attribute) else ""
            if isinstance(mode, str) and any(c in mode for c in "wax") and owner not in ("tarfile", "gzip"):
                found.add(enclosing(node))
            elif isinstance(mode, str) and any(c in mode for c in "wax"):
                found.add(
                    enclosing(node)
                )  # gzip/tar writers are listed too: a stream onto a secret path would be a finding
        elif name in ("write_bytes", "write_text"):
            found.add(enclosing(node))
    return found


class TestNoUnreviewedWriteOfAFile:
    def test_every_write_mode_open_in_jen_is_reviewed_or_goes_through_the_private_writer(self):
        unreviewed = []
        for path in sorted((ROOT / "jen").rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            for function in sorted(_writes_in(path)):
                reviewed = (rel, function) in REVIEWED_WRITES
                if not reviewed:
                    unreviewed.append(f"{rel}::{function}")
        assert not unreviewed, (
            "a write-mode open() / write_bytes() nobody reviewed: write secrets with "
            f"jen.services.private_files.write_private_file, or add it to REVIEWED_WRITES with its reason: {unreviewed}"
        )

    def test_the_three_secret_writers_use_the_private_writer_and_nothing_else(self):
        for rel in ("jen/config.py", "jen/services/certs.py", "jen/services/crypto.py"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            assert "write_private_file" in text, rel
            assert not _writes_in(ROOT / rel), f"{rel} writes a file with a bare open()"
        init = (ROOT / "jen/__init__.py").read_text(encoding="utf-8")
        assert "write_private_file(key_file, key, 0o640)" in init
        assert "_load_secret_key" not in _writes_in(ROOT / "jen/__init__.py")
