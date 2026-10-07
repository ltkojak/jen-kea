"""
tests/test_installer_trust.py - v5.68.0-beta.16 (Q151, items F-2 and 1): what the ROOT installer writes and what it trusts.

`$CONFIG_DIR` is service-owned. (F-2) The upgrade snapshot of `run.py` and the `jen/` package used to be written to `$CONFIG_DIR/backups` and a
failed upgrade `cp`ed it back into `$INSTALL_DIR` as root: a compromised service account that planted a `run.py` there had it installed by root.
Q119 moved only the `ext.*` snapshot. The snapshots now live under `$ROOT_ROLLBACK_DIR`, and the rollback refuses one that is not root-owned, is a
symlink, or is not under that directory. (1) `write_config` wrote `jen.config` with `cat >` under umask 022 inside the service-writable directory:
created 0644, following a planted symlink, tightened only after every password was in it; it now goes through `tools/private_write.py`.

Real bash against install.sh's own functions (the same technique as tests/test_layout.py), Linux CI. The tests never run as root, so `chown` is a
no-op stub and `_root_owned` - the ownership decision, in its own function for exactly this reason - is overridden where a test needs a
"trusted" snapshot; a test that wants the real refusal leaves it alone (a runner-owned file is not root-owned).
"""

import os
import pathlib
import platform
import stat
import subprocess
import textwrap
import threading

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / "install.sh"

pytestmark = pytest.mark.skipif(platform.system() == "Windows", reason="POSIX shell semantics required")


def _lib(tmp_path):
    """install.sh without the trailing `main "$@"` and the signal traps, plus the tarball's tools/ beside it (SCRIPT_DIR is this directory)."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not line.startswith("trap ") and line.strip() != 'main "$@"']
    lib = tmp_path / "install_lib.sh"
    lib.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tools = tmp_path / "tools"
    tools.mkdir(exist_ok=True)
    (tools / "private_write.py").write_bytes((ROOT / "tools" / "private_write.py").read_bytes())
    return lib


def _bash(tmp_path, script, env=None):
    lib = _lib(tmp_path)
    full = textwrap.dedent(
        f"""
        set -uo pipefail
        source "{lib}" >/dev/null 2>&1
        T="{tmp_path}"
        INSTALL_DIR="$T/opt"; CONFIG_DIR="$T/etc"; CONTENT_DIR="$T/var"
        BACKUP_DIR="$CONFIG_DIR/backups"; ROOT_ROLLBACK_DIR="$INSTALL_DIR/.rollback"
        CURRENT_LINK="$INSTALL_DIR/current"; RELEASES_DIR="$INSTALL_DIR/releases"
        CONFIG_FILE="$CONFIG_DIR/jen.config"; JEN_VERSION=9.9.9; IS_UPGRADE=true
        chown() {{ :; }}
        _run_logged() {{ :; }}
        _restore_external_files() {{ :; }}
        systemctl() {{ :; }}
        {script}
        """
    )
    return subprocess.run(["bash", "-c", full], capture_output=True, text=True, env={**os.environ, **(env or {})})


def _flat_box(tmp_path):
    """A still-flat install: run.py and the jen/ package directly under $INSTALL_DIR."""
    opt = tmp_path / "opt"
    (opt / "jen").mkdir(parents=True)
    (opt / "run.py").write_text("print('the running version')\n")
    (opt / "jen" / "__init__.py").write_text("VERSION = 'old'\n")
    (tmp_path / "etc" / "backups").mkdir(parents=True)
    return opt


class TestTheUpgradeSnapshotIsRootsOwn:
    def test_run_py_and_the_package_are_snapshotted_under_root_rollback_dir_never_the_config_dir(self, tmp_path):
        opt = _flat_box(tmp_path)
        proc = _bash(tmp_path, 'backup_existing; echo "JEN=$ROLLBACK_JEN"; echo "PKG=$ROLLBACK_PKG"')
        assert proc.returncode == 0, proc.stdout + proc.stderr
        values = dict(line.split("=", 1) for line in proc.stdout.splitlines() if line.startswith(("JEN=", "PKG=")))
        rollback = opt / ".rollback"
        assert (
            values["JEN"].startswith(str(rollback))
            and pathlib.Path(values["JEN"]).read_text() == "print('the running version')\n"
        )
        assert values["PKG"].startswith(str(rollback)) and (pathlib.Path(values["PKG"]) / "__init__.py").exists()
        leftovers = [p.name for p in (tmp_path / "etc" / "backups").iterdir()]
        assert leftovers == [], (
            f"nothing of the code snapshot may sit in the service-writable backups directory: {leftovers}"
        )
        assert stat.S_IMODE(rollback.stat().st_mode) & 0o077 == 0, "go-rwx"

    def test_snapshots_a_pre_fix_install_left_in_the_config_dir_are_removed_but_the_config_backups_stay(self, tmp_path):
        _flat_box(tmp_path)
        backups = tmp_path / "etc" / "backups"
        (backups / "run.py.20260101_000000.bak").write_text("EVIL")
        (backups / "jen.20260101_000000.bak").mkdir()
        (backups / "jen.20260101_000000.bak" / "x.py").write_text("EVIL")
        (backups / "jen.config.20260101_000000.bak").write_text("[jen_db]\npassword = keep\n")
        proc = _bash(tmp_path, "backup_existing")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert sorted(p.name for p in backups.iterdir()) == ["jen.config.20260101_000000.bak"]

    def test_a_source_that_resolves_outside_the_install_dir_is_refused(self, tmp_path):
        _flat_box(tmp_path)
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "app").mkdir(parents=True)
        (elsewhere / "app" / "run.py").write_text("print('not ours')\n")
        os.symlink(elsewhere, tmp_path / "opt" / "current")  # `current/app` is where the versioned layout reads from
        proc = _bash(tmp_path, "backup_existing")
        assert proc.returncode != 0 and "outside" in (proc.stdout + proc.stderr)
        assert not (tmp_path / "opt" / ".rollback" / "run.py.x").exists()


class TestTheRollbackTrustsOnlyRootsSnapshot:
    def test_a_planted_run_py_in_the_config_dir_is_never_copied_into_the_app_tree(self, tmp_path):
        opt = _flat_box(tmp_path)
        planted = tmp_path / "etc" / "backups" / "run.py.20260101_000000.bak"
        planted.write_text("print('EVIL')\n")
        script = f"""
            _root_owned() {{ return 0; }}      # even a file that claims root ownership: the LOCATION is checked too
            ROLLBACK_JEN="{planted}"; ROLLBACK_PKG=""
            RELEASES_DIR="$T/no-releases"
            rollback
        """
        proc = _bash(tmp_path, script)
        assert (opt / "run.py").read_text() == "print('the running version')\n", proc.stdout + proc.stderr
        assert "refusing" in (proc.stdout + proc.stderr).lower()

    def test_a_failed_upgrade_restores_from_the_root_snapshot(self, tmp_path):
        opt = _flat_box(tmp_path)
        script = """
            backup_existing
            echo "the upgrade broke it" > "$INSTALL_DIR/run.py"; rm -rf "$INSTALL_DIR/jen"
            _root_owned() { return 0; }        # the test is not root; the snapshot is otherwise exactly what root made
            RELEASES_DIR="$T/no-releases"
            rollback
        """
        proc = _bash(tmp_path, script)
        assert (opt / "run.py").read_text() == "print('the running version')\n", proc.stdout + proc.stderr
        assert (opt / "jen" / "__init__.py").read_text() == "VERSION = 'old'\n"

    @pytest.mark.skipif(getattr(os, "geteuid", lambda: 1)() == 0, reason="as root the snapshot IS root-owned")
    def test_a_snapshot_that_is_not_root_owned_is_refused(self, tmp_path):
        opt = _flat_box(tmp_path)
        script = """
            backup_existing
            echo "broken" > "$INSTALL_DIR/run.py"
            RELEASES_DIR="$T/no-releases"
            rollback               # the real _root_owned: this runner's files are not owned by uid 0
        """
        proc = _bash(tmp_path, script)
        assert (opt / "run.py").read_text() == "broken\n", (
            "refused: the snapshot is not root-owned, so nothing is copied back"
        )
        assert "root-owned" in (proc.stdout + proc.stderr)

    def test_a_snapshot_that_is_a_symlink_is_refused(self, tmp_path):
        opt = _flat_box(tmp_path)
        victim = tmp_path / "victim.py"
        victim.write_text("print('EVIL')\n")
        (opt / ".rollback").mkdir()
        link = opt / ".rollback" / "run.py.20260101_000000"
        os.symlink(victim, link)
        script = f"""
            _root_owned() {{ return 0; }}
            ROLLBACK_JEN="{link}"; ROLLBACK_PKG=""
            RELEASES_DIR="$T/no-releases"
            rollback
        """
        proc = _bash(tmp_path, script)
        assert (opt / "run.py").read_text() == "print('the running version')\n", proc.stdout + proc.stderr

    def test_a_package_snapshot_containing_a_symlink_is_refused(self, tmp_path):
        opt = _flat_box(tmp_path)
        script = """
            backup_existing
            ln -s /etc/passwd "$ROLLBACK_PKG/planted"
            echo "broken" > "$INSTALL_DIR/jen/__init__.py"
            _root_owned() { return 0; }
            RELEASES_DIR="$T/no-releases"
            rollback
        """
        _bash(tmp_path, script)
        assert (opt / "jen" / "__init__.py").read_text() == "broken\n", "the package snapshot was not copied back"
        assert not (opt / "jen" / "planted").exists()


WRITE_CONFIG_ENV = """
    CONFIGURE=true; IS_UPGRADE=true; JEN_USER="$(id -un)"
    KEA_API_URL=http://kea:8000; KEA_API_USER=u; KEA_API_PASS='p@ss'
    KEA_DB_HOST=db; KEA_DB_USER=kea; KEA_DB_PASS='kea-secret'; KEA_DB_NAME=kea
    JEN_DB_HOST=db; JEN_DB_USER=jen; JEN_DB_PASS='jen-secret'; JEN_DB_NAME=jen
    HTTP_PORT=5050; HTTPS_PORT=8443; KEA_SSH_HOST=h; KEA_SSH_USER=s; KEA_CONF_PATH=/etc/kea/kea-dhcp4.conf
    SUBNET_LINES='1 = LAN, 10.0.0.0/24\\n'
    DDNS_LOG=/var/log/kea/ddns.log; DDNS_PROVIDER=none; DDNS_URL=; DDNS_TOKEN=; DDNS_ZONE=
    mkdir -p "$CONFIG_DIR"
"""


class TestWriteConfigIsPrivateFromItsFirstByte:
    def test_the_config_is_written_0600_owned_by_the_service_user_with_every_value(self, tmp_path):
        proc = _bash(tmp_path, "umask 022\n" + WRITE_CONFIG_ENV + "write_config")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        config = tmp_path / "etc" / "jen.config"
        assert stat.S_IMODE(config.stat().st_mode) == 0o600 and config.stat().st_uid == os.getuid()
        text = config.read_text()
        assert "password = jen-secret" in text and "api_pass = p@ss" in text and "1 = LAN, 10.0.0.0/24" in text
        assert [p.name for p in config.parent.iterdir() if p.name.startswith(".")] == [], "no temp file left behind"

    def test_an_existing_config_is_backed_up_0600_and_the_new_one_replaces_it(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "jen.config").write_text("[jen_db]\npassword = old-secret\n")
        os.chmod(etc / "jen.config", 0o644)
        proc = _bash(tmp_path, "umask 022\n" + WRITE_CONFIG_ENV + "write_config")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        (backup,) = list((etc / "backups").glob("jen.config.*.bak"))
        assert "old-secret" in backup.read_text() and stat.S_IMODE(backup.stat().st_mode) == 0o600
        assert "old-secret" not in (etc / "jen.config").read_text()

    def test_a_symlink_at_the_live_path_is_refused_and_its_target_untouched(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        victim = tmp_path / "victim"
        victim.write_text("the target the service account pointed the link at\n")
        os.symlink(victim, etc / "jen.config")
        proc = _bash(tmp_path, "umask 022\n" + WRITE_CONFIG_ENV + "write_config")
        assert proc.returncode != 0, "refused: the installer stops"
        assert victim.read_text() == "the target the service account pointed the link at\n"
        assert (etc / "jen.config").is_symlink()

    def test_umask_022_never_makes_it_group_or_other_readable_at_any_instant(self, tmp_path):
        """A directory watcher stats every entry in a tight loop while write_config runs 25 times under umask 022 with the writer made slow (a
        30 ms fsync), so the window between 'created' and 'final mode' is wide. `cat >` would be seen 0644."""
        etc = tmp_path / "etc"
        (etc / "backups").mkdir(parents=True)
        slow = tmp_path / "slowpython"
        slow.write_text(
            "#!/bin/sh\n"
            "exec python3 -c 'import os,sys,time,runpy\n"
            "real=os.fsync\n"
            "def slow(fd):\n"
            "    time.sleep(0.03); real(fd)\n"
            "os.fsync=slow\n"
            "script=sys.argv[1]; sys.argv=sys.argv[1:]\n"
            'runpy.run_path(script, run_name="__main__")\' "$@"\n'
        )
        slow.chmod(0o755)
        seen, samples, stop = {}, [0], threading.Event()

        def watch():
            while not stop.is_set():
                for directory in (etc, etc / "backups"):
                    try:
                        with os.scandir(directory) as it:
                            for entry in it:
                                try:
                                    mode = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
                                except FileNotFoundError:
                                    continue
                                kind = (
                                    "temp"
                                    if entry.name.startswith(".")
                                    else ("backup" if entry.name.endswith(".bak") else entry.name)
                                )
                                if entry.is_dir(follow_symlinks=False):
                                    continue
                                seen.setdefault(kind, set()).add(mode)
                                samples[0] += 1
                    except FileNotFoundError:
                        pass

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        try:
            script = (
                f'umask 022\nPYBIN_FOR_LAYOUT="{slow}"\n'
                + WRITE_CONFIG_ENV
                + "for i in $(seq 1 25); do write_config; sleep 0.01; done"
            )
            proc = _bash(tmp_path, script)
        finally:
            stop.set()
            watcher.join(5)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        observed = {k: sorted(oct(m) for m in v) for k, v in sorted(seen.items())}
        print(
            f"[installer private-write watcher] jen.config: {samples[0]} stats over 25 write_config runs; modes seen {observed}"
        )
        assert samples[0] > 0 and "temp" in seen, (
            "the watcher never caught a temp file in flight: the test has no power"
        )
        for kind, modes in seen.items():
            assert modes <= {0o600}, f"{kind} was seen with mode(s) {sorted(oct(m) for m in modes - {0o600})}"
