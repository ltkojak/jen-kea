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
import re
import stat
import subprocess
import sys
import textwrap
import threading
import time

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
    (tools / "config_merge.py").write_bytes((ROOT / "tools" / "config_merge.py").read_bytes())
    return lib


def _bash(tmp_path, script, env=None):
    lib = _lib(tmp_path)
    full = textwrap.dedent(
        f"""
        set -uo pipefail
        source "{lib}" >/dev/null 2>&1
        T="{tmp_path}"
        INSTALL_DIR="$T/opt"; CONFIG_DIR="$T/etc"; CONTENT_DIR="$T/var"
        ROOT_ROLLBACK_DIR="$INSTALL_DIR/.rollback"; CONFIG_BACKUP_DIR="$ROOT_ROLLBACK_DIR/config"
        CURRENT_LINK="$INSTALL_DIR/current"; RELEASES_DIR="$INSTALL_DIR/releases"
        CONFIG_FILE="$CONFIG_DIR/jen.config"; CONFIG_LOCK_FILE="$CONFIG_DIR/jen.config.lock"; JEN_VERSION=9.9.9; IS_UPGRADE=true
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

    def test_a_pre_fix_install_s_config_backups_directory_is_left_exactly_as_it_is(self, tmp_path):
        """v5.68.0-beta.20 (Q155): root no longer deletes anything under the service-owned $CONFIG_DIR - not even the leftovers of the old layout
        (two `rm -rf` ran there as root). Nothing references what is in it, root never reads it back, and nothing is created, changed or removed."""
        _flat_box(tmp_path)
        backups = tmp_path / "etc" / "backups"
        (backups / "run.py.20260101_000000.bak").write_text("EVIL")
        (backups / "jen.20260101_000000.bak").mkdir()
        (backups / "jen.20260101_000000.bak" / "x.py").write_text("EVIL")
        (backups / "ext.20260101_000000").mkdir()
        (backups / "jen.config.20260101_000000.bak").write_text("[jen_db]\npassword = keep\n")
        before = sorted(str(p.relative_to(backups)) for p in backups.rglob("*"))
        proc = _bash(tmp_path, "backup_existing")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert sorted(str(p.relative_to(backups)) for p in backups.rglob("*")) == before
        assert (backups / "run.py.20260101_000000.bak").read_text() == "EVIL"

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
        (backup,) = list((tmp_path / "opt" / ".rollback" / "config").glob("jen.config.*.bak"))
        assert "old-secret" in backup.read_text() and stat.S_IMODE(backup.stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "opt" / ".rollback" / "config").stat().st_mode) == 0o700
        assert not (etc / "backups").exists(), "no config backup is written under the service-owned config directory"
        assert "old-secret" not in (etc / "jen.config").read_text()

    def test_a_planted_backups_symlink_is_never_followed_or_deleted_through(self, tmp_path):
        """The reviewer's reproduction of beta.19: a symlink at $CONFIG_DIR/backups. The backup is root's own now, so nothing is written through
        it - and nothing is deleted through it either (the `rm -rf` cleanups under that tree are gone)."""
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "jen.config").write_text("[jen_db]\npassword = old-secret\n")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "ext.keep-me").write_text("must survive")
        os.symlink(outside, etc / "backups")
        proc = _bash(tmp_path, "umask 022\n" + WRITE_CONFIG_ENV + "write_config\nbackup_existing")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert sorted(p.name for p in outside.iterdir()) == ["ext.keep-me"], (
            "something was written (or deleted) through the symlink"
        )
        assert (etc / "backups").is_symlink()
        assert len(list((tmp_path / "opt" / ".rollback" / "config").glob("jen.config.*.bak"))) == 1

    def test_a_symlink_where_the_root_backup_directory_should_be_is_refused(self, tmp_path):
        """If `.rollback/config` is a symlink (it is root's directory, so only a bug or an attacker with root could have made it): the walk by
        directory descriptors refuses it and the installer stops - the backup is not made through it."""
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "jen.config").write_text("[jen_db]\npassword = old-secret\n")
        outside = tmp_path / "outside"
        outside.mkdir()
        (tmp_path / "opt" / ".rollback").mkdir(parents=True)
        os.symlink(outside, tmp_path / "opt" / ".rollback" / "config")
        proc = _bash(tmp_path, "umask 022\n" + WRITE_CONFIG_ENV + "write_config")
        assert proc.returncode != 0
        assert list(outside.iterdir()) == []
        assert "old-secret" in (etc / "jen.config").read_text(), (
            "the live config was replaced although its backup could not be made"
        )

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
        etc.mkdir(parents=True)
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
                for directory in (etc, tmp_path / "opt" / ".rollback" / "config"):
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


# ── v5.68.0-beta.18 (Q153): `--configure` holds the config lock and merges into the live file ─────────────────────────────────────────

LIVE_CONFIG = """[kea]
api_url = http://old:8000
api_user = u
api_pass = old-pass

[kea_db]
host = db
user = kea
password = kea-secret
database = kea

[jen_db]
host = db
user = jen
password = jen-secret
database = jen

[server]
http_port = 5050
https_port = 8443

[kea_ssh]
host = h
user = s
kea_conf = /etc/kea/kea-dhcp4.conf

[subnets]
1 = LAN, 10.0.0.0/24

[ddns]
log_path = /var/log/kea/ddns.log
dns_provider = none
api_url =
api_token =
forward_zone =

[oidc]
enabled = true
issuer = https://idp.example
"""

CONFIGURE_ENV = (
    WRITE_CONFIG_ENV.replace("KEA_API_PASS='p@ss'", "KEA_API_PASS='old-pass'").replace(
        "KEA_API_URL=http://kea:8000", "KEA_API_URL=http://old:8000"
    )
    + "MODE_CONFIGURE=true\n"
)


class TestConfigureHoldsTheLockAndMergesIntoTheLiveFile:
    def _live(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir(exist_ok=True)
        (etc / "jen.config").write_text(LIVE_CONFIG)
        (etc / "jen.config.lock").write_text("")
        os.chmod(etc / "jen.config.lock", 0o600)
        return etc

    def _save_meanwhile(self, etc):
        """What a Settings save made after `--configure` began does to the file (the same configparser rewrite jen/config.py does)."""
        return (
            "python3 - <<'PYEOF'\n"
            "import configparser\n"
            "p = configparser.ConfigParser(interpolation=None)\n"
            f"p.read('{etc}/jen.config')\n"
            "p.set('kea', 'api_url', 'http://saved-during-the-wizard:8000')\n"
            "p.set('server', 'http_port', '6000')\n"
            "p.set('oidc', 'issuer', 'https://idp2.example')\n"
            "p.add_section('kea6'); p.set('kea6', 'api_url', 'http://kea6:8006')\n"
            f"p.write(open('{etc}/jen.config', 'w'))\n"
            "PYEOF\n"
        )

    def test_a_value_saved_after_the_snapshot_is_still_there_after_write_config(self, tmp_path):
        etc = self._live(tmp_path)
        script = (
            CONFIGURE_ENV
            + 'CONFIG_SNAPSHOT_TEXT="$(cat "$CONFIG_FILE")"\n'
            + self._save_meanwhile(etc)
            + "write_config\n"
        )
        proc = _bash(tmp_path, "umask 022\n" + script)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        import configparser

        merged = configparser.ConfigParser(interpolation=None)
        merged.read(etc / "jen.config")
        assert merged.get("kea", "api_url") == "http://saved-during-the-wizard:8000", (
            "the wizard accepted the old default: the save wins"
        )
        assert merged.get("server", "http_port") == "6000"
        assert merged.get("oidc", "issuer") == "https://idp2.example", (
            "a section the wizard never asks about is kept, newest value"
        )
        assert merged.get("kea6", "api_url") == "http://kea6:8006", "...and so is one added meanwhile"
        assert merged.get("jen_db", "password") == "jen-secret"

    def test_a_value_the_operator_changed_in_the_wizard_wins(self, tmp_path):
        etc = self._live(tmp_path)
        script = (
            CONFIGURE_ENV
            + "KEA_DB_PASS='typed-in-the-wizard'\n"
            + 'CONFIG_SNAPSHOT_TEXT="$(cat "$CONFIG_FILE")"\n'
            + "write_config\n"
        )
        proc = _bash(tmp_path, "umask 022\n" + script)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        text = (etc / "jen.config").read_text()
        assert "typed-in-the-wizard" in text and "kea-secret" not in text
        assert "issuer = https://idp.example" in text, "the [oidc] section the wizard never writes was dropped"

    def test_the_result_is_still_private_and_the_backup_holds_the_live_file(self, tmp_path):
        etc = self._live(tmp_path)
        proc = _bash(
            tmp_path, "umask 022\n" + CONFIGURE_ENV + 'CONFIG_SNAPSHOT_TEXT="$(cat "$CONFIG_FILE")"\nwrite_config\n'
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        config = etc / "jen.config"
        assert stat.S_IMODE(config.stat().st_mode) == 0o600 and config.stat().st_uid == os.getuid()
        (backup,) = list((tmp_path / "opt" / ".rollback" / "config").glob("jen.config.*.bak"))
        assert "issuer = https://idp.example" in backup.read_text()

    def test_a_fresh_install_is_not_merged_with_anything(self, tmp_path):
        """Not --configure: write_config writes the wizard's file as it always did (and takes the lock for its own write)."""
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "jen.config").write_text("[oidc]\nenabled = true\n")
        proc = _bash(tmp_path, "umask 022\n" + WRITE_CONFIG_ENV + "write_config\n")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "[oidc]" not in (etc / "jen.config").read_text()

    def test_a_save_waits_while_the_wizard_holds_the_lock_and_lands_after_it(self, tmp_path):
        """--configure takes the lock before reading anything: Jen's own writer (the same flock) waits for the installer."""
        etc = self._live(tmp_path)
        lib = _lib(tmp_path)
        holder = subprocess.Popen(
            [
                "bash",
                "-c",
                textwrap.dedent(
                    f"""
                    set -uo pipefail
                    source "{lib}" >/dev/null 2>&1
                    CONFIG_DIR="{etc}"; CONFIG_FILE="{etc}/jen.config"; CONFIG_LOCK_FILE="{etc}/jen.config.lock"; JEN_USER="$(id -un)"
                    _config_lock_acquire
                    echo locked
                    sleep 2
                    _config_lock_release
                    echo released
                    """
                ),
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert holder.stdout.readline().strip() == "locked"
        script = (
            "import sys, time\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from jen import extensions\n"
            f"extensions.CONFIG_FILE = {str(etc / 'jen.config')!r}\n"
            "from jen.config import AppConfig\n"
            "t = time.monotonic()\n"
            "AppConfig().write_value('settings', 'saved', '1', reload=False)\n"
            "print(round(time.monotonic() - t, 2))\n"
        )
        started = time.monotonic()
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
        holder.wait(10)
        assert out.returncode == 0, out.stderr
        assert float(out.stdout.strip()) >= 1.0 and time.monotonic() - started >= 1.0, (
            "the save did not wait for the installer"
        )
        assert "saved = 1" in (etc / "jen.config").read_text()
        assert "issuer = https://idp.example" in (etc / "jen.config").read_text(), (
            "and it was applied to the file as it is"
        )

    def test_the_lock_helpers_refuse_a_symlink_and_never_create_a_root_owned_lock(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        victim = tmp_path / "victim"
        victim.write_text("x")
        os.symlink(victim, etc / "jen.config.lock")
        proc = _bash(tmp_path, 'JEN_USER="$(id -un)"; _config_lock_acquire; echo reached')
        assert proc.returncode != 0 and "reached" not in proc.stdout
        assert victim.read_text() == "x"


class TestFlockIsRequired:
    """v5.68.0-beta.19 (Q154): flock is a required dependency. Continuing without it let Jen's own saves be overwritten by the wizard - the thing the
    lock exists to prevent - so `--configure` refuses, and the preflight and the dependency installer know about it."""

    HIDE_FLOCK = (
        'command() { if [[ "${1:-}" == "-v" && "${2:-}" == "flock" ]]; then return 1; fi; builtin command "$@"; }\n'
        'JEN_USER="$(id -un)"; mkdir -p "$CONFIG_DIR"\n'
    )

    def test_configure_refuses_without_flock_and_says_how_to_fix_it(self, tmp_path):
        proc = _bash(tmp_path, self.HIDE_FLOCK + "_config_lock_acquire; echo reached")
        assert proc.returncode != 0 and "reached" not in proc.stdout
        assert "needs flock" in (proc.stdout + proc.stderr) and "util-linux" in (proc.stdout + proc.stderr)

    def test_the_preflight_checks_it_and_the_dependency_installer_would_install_it(self):
        text = INSTALL_SH.read_text(encoding="utf-8")
        assert 'command -v flock &>/dev/null && ok "flock"' in text
        assert "command -v flock       &>/dev/null || pkgs+=(util-linux)" in text

    def test_configure_mode_acquires_the_lock_before_it_reads_anything(self):
        text = INSTALL_SH.read_text(encoding="utf-8")
        body = text[text.index("_run_configure_mode() {") :].split(chr(10) + "}" + chr(10), 1)[0]
        calls = [ln.strip() for ln in body.splitlines() if not ln.strip().startswith("#")]
        assert calls.index("_config_lock_acquire") < calls.index("detect_existing") < calls.index("write_config")


class TestTheInstallerLocksTheSameInodeThroughTheOneOpen:
    """v5.68.0-beta.20 (Q155): `_config_lock_acquire` no longer tests `-L` and then `exec {fd}>>`s (a check-then-open) or `install`s a new file. The lock is
    opened ONCE by `tools/private_write.py --hold-lock` (`take_lock`: O_NOFOLLOW, the same inode normalised in place); a lock is an inode, and two
    inodes are two locks."""

    SCRIPT = (
        'set -uo pipefail\nsource "{lib}" >/dev/null 2>&1\n'
        'CONFIG_DIR="{etc}"; CONFIG_LOCK_FILE="{etc}/jen.config.lock"; JEN_USER="$(id -un)"\n'
        "{body}\n"
    )

    def _run(self, tmp_path, body):
        etc = tmp_path / "etc"
        etc.mkdir(exist_ok=True)
        script = self.SCRIPT.format(lib=_lib(tmp_path), etc=etc, body=body)
        return subprocess.Popen(["bash", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_an_existing_loose_lock_is_normalised_in_place_and_held_on_that_inode(self, tmp_path):
        import fcntl

        lock = tmp_path / "etc" / "jen.config.lock"
        lock.parent.mkdir()
        lock.write_text("")
        os.chmod(lock, 0o666)
        inode = lock.stat().st_ino
        proc = self._run(
            tmp_path,
            '_config_lock_acquire; echo "locked $(stat -c %i "$CONFIG_LOCK_FILE")"; sleep 2; _config_lock_release; echo released',
        )
        try:
            assert proc.stdout.readline().split() == ["locked", str(inode)], (
                "the installer locked a different file than the one that was there"
            )
            assert stat.S_IMODE(lock.stat().st_mode) == 0o600 and lock.stat().st_ino == inode
            fd = os.open(lock, os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # held by the installer's holder
            finally:
                os.close(fd)
        finally:
            proc.wait(15)
        fd = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released
        finally:
            os.close(fd)

    def test_a_save_in_the_other_process_waits_on_that_same_inode(self, tmp_path):
        """Jen's AppConfig opens the lock path; the installer's holder has the lock on the file at that path: one inode, so the save WAITS."""
        etc = tmp_path / "etc"
        etc.mkdir()
        (etc / "jen.config").write_text("[a]\nb = 1\n")
        proc = self._run(tmp_path, "_config_lock_acquire; echo locked; sleep 2; _config_lock_release")
        try:
            assert proc.stdout.readline().strip() == "locked"
            script = (
                "import sys, time\n"
                f"sys.path.insert(0, {str(ROOT)!r})\n"
                "from jen import extensions\n"
                f"extensions.CONFIG_FILE = {str(etc / 'jen.config')!r}\n"
                "from jen.config import AppConfig\n"
                "t = time.monotonic()\n"
                "AppConfig().write_value('settings', 'saved', '1', reload=False)\n"
                "print(round(time.monotonic() - t, 2))\n"
            )
            out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
            assert out.returncode == 0, out.stderr
            assert float(out.stdout.strip()) >= 1.0, "the save did not wait for the installer's lock"
        finally:
            proc.wait(15)

    def test_the_holder_goes_with_the_installer_when_it_is_killed(self, tmp_path):
        import fcntl
        import signal

        lock = tmp_path / "etc" / "jen.config.lock"
        proc = self._run(tmp_path, "_config_lock_acquire; echo locked; sleep 60")
        try:
            assert proc.stdout.readline().strip() == "locked"
            os.kill(proc.pid, signal.SIGKILL)  # no trap runs, nothing releases anything
            proc.wait(10)
        finally:
            if proc.poll() is None:
                proc.kill()
        deadline = time.monotonic() + 8
        while True:
            fd = os.open(lock, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise AssertionError("the lock holder outlived a killed installer") from None
                time.sleep(0.2)
            finally:
                os.close(fd)

    def test_a_hard_linked_lock_is_refused_and_the_other_name_is_not_chowned(self, tmp_path):
        etc = tmp_path / "etc"
        etc.mkdir()
        target = tmp_path / "root-file"
        target.write_text("x")
        os.link(target, etc / "jen.config.lock")
        os.chmod(target, 0o644)
        proc = self._run(tmp_path, "_config_lock_acquire; echo reached")
        out, err = proc.communicate(timeout=60)
        assert proc.returncode != 0 and "reached" not in out
        assert stat.S_IMODE(target.stat().st_mode) == 0o644, (
            "a file the installer was tricked into locking was re-moded"
        )

    def test_the_installer_no_longer_checks_then_opens_or_creates_a_second_file(self):
        text = INSTALL_SH.read_text(encoding="utf-8")
        body = text[text.index("_config_lock_acquire() {") : text.index("_config_lock_release() {")]
        code = "\n".join(ln.split("#", 1)[0] for ln in body.splitlines())
        assert '-L "$CONFIG_LOCK_FILE"' not in code and "exec {CONFIG_LOCK_FD}" not in code and "install -m" not in code
        assert "--hold-lock" in code

    def test_root_deletes_nothing_under_the_service_owned_trees(self):
        """`rm -rf "${BACKUP_DIR:?}"/...` ran as root under $CONFIG_DIR/backups. No recursive removal in install.sh may name $CONFIG_DIR, $CONTENT_DIR or a
        BACKUP_DIR (the $ROOT_ROLLBACK_DIR ones are root's own)."""
        text = INSTALL_SH.read_text(encoding="utf-8")
        offenders = [
            ln.strip()
            for ln in text.splitlines()
            if re.search(r"\brm\s+-[a-zA-Z]*[rR]", ln.split("#", 1)[0])
            and re.search(r"\$\{?(CONFIG_DIR|CONTENT_DIR|BACKUP_DIR|CONFIG_BACKUP_DIR)\b", ln.split("#", 1)[0])
        ]
        assert offenders == [], offenders
        assert "BACKUP_DIR:?" not in text.replace("CONFIG_BACKUP_DIR", "")
