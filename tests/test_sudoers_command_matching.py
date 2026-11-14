"""
tests/test_sudoers_command_matching.py
────────────────────────────────────────
v7.1.0-beta.3 (Q213) - zero sudoers on Jen's own box.

This file used to hold `jen-sudoers` and the three `sudo` call sites identical, argument by argument: sudo matches a
command literally, and a `--no-block` the rule did not carry broke every self-update from 5.2.6 to 5.2.9. The grant is
gone, so the test is now the opposite claim, over the WHOLE tree and never a file list:

  * no module under `jen/` or `plugins/` runs `sudo` for Jen's own box, except the one legacy call in
    `jen/services/privileged.py`, which is still the earlier grant's command byte for byte (a box updated in place
    uses it until its root script has installed the path units);
  * a restart is a signal to Jen's own master, never a command;
  * the trigger file the app writes, the path unit that watches it and the name the root script removes are ONE name;
  * root removes the trigger first, through a handle that follows no link, whatever the app left there;
  * the grant is removed only after systemd says both path units are active.

The remote `sudo` of the Kea-host engine (`kea_host.py`, `kea_authoring.py`) runs on ANOTHER machine through SSH, as a
shell string: it is not this file's subject and `tests/test_kea_host.py` guards it.
"""

import ast
import importlib.util
import os
import pathlib
import re
import signal
import stat
import sys

import pytest

from jen.services import privileged, runtime

ROOT = pathlib.Path(__file__).resolve().parents[1]
LINUX = sys.platform.startswith("linux")
needs_linux = pytest.mark.skipif(not LINUX, reason="directory handles and O_NOFOLLOW are the Linux behavior under test")


def _root_script():
    spec = importlib.util.spec_from_file_location("jen_update_root_q213", ROOT / "jen-update-root.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _argv_lists_that_start_with_sudo():
    """Every list literal in the product whose first element is a string naming `sudo`: `(file, [argv...])`."""
    found = []
    for base in ("jen", "plugins"):
        for path in sorted((ROOT / base).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.List) or not node.elts:
                    continue
                first = node.elts[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.endswith("sudo"):
                    argv = [e.value if isinstance(e, ast.Constant) else "<expr>" for e in node.elts]
                    found.append((path.relative_to(ROOT).as_posix(), argv))
    return found


# ── the whole tree ────────────────────────────────────────────────────────────────────────────────────────────


class TestNoSudoOnJensOwnBox:
    def test_the_only_local_sudo_argv_is_the_legacy_start(self):
        found = _argv_lists_that_start_with_sudo()
        assert [f for f, _argv in found] == ["jen/services/privileged.py"], found
        assert found[0][1] == ["/usr/bin/sudo", "/usr/bin/systemctl", "start", "--no-block", "<expr>"]

    def test_the_legacy_start_is_the_earlier_grants_command_byte_for_byte(self, monkeypatch):
        """The two lines `/etc/sudoers.d/jen` carried for the units. A box that still has the file has exactly these."""
        ran = []

        class Done:
            returncode, stderr = 0, ""

        monkeypatch.setattr(privileged.subprocess, "run", lambda argv, **kw: ran.append(argv) or Done())
        assert privileged._legacy_start("update") == (True, "sudo")
        assert privileged._legacy_start("plugins") == (True, "sudo")
        assert ran == [
            ["/usr/bin/sudo", "/usr/bin/systemctl", "start", "--no-block", "jen-update.service"],
            ["/usr/bin/sudo", "/usr/bin/systemctl", "start", "--no-block", "jen-plugin-install.service"],
        ]

    def test_no_release_ships_a_sudoers_file_and_no_installer_installs_one(self):
        assert not (ROOT / "jen-sudoers").exists()
        for script in ("install.sh", "jen-update-root.py"):
            text = (ROOT / script).read_text(encoding="utf-8")
            assert not re.search(r"cp[^\n]*jen-sudoers|copy2\([^\n]*sudoers", text), script
        assert "visudo" not in (ROOT / "jen-update-root.py").read_text(encoding="utf-8")

    def test_a_restart_is_a_signal_to_jens_own_master_under_systemd_too(self, monkeypatch):
        sent = []
        monkeypatch.setattr(runtime, "deployment", lambda: "systemd")
        monkeypatch.setattr(runtime.os, "kill", lambda pid, sig: sent.append((pid, sig)))
        monkeypatch.setattr(runtime.time, "sleep", lambda s: None)
        threads = []
        monkeypatch.setattr(
            runtime.threading, "Thread", lambda target, daemon: threads.append(target) or _Inline(target)
        )
        assert runtime.restart_service(delay=0) == "systemd"
        assert sent == [(os.getppid(), signal.SIGTERM)]
        assert "subprocess" not in (ROOT / "jen/services/runtime.py").read_text(encoding="utf-8")

    def test_the_unit_restarts_a_jen_that_stopped_itself(self):
        unit = (ROOT / "jen.service.template").read_text(encoding="utf-8")
        assert re.search(r"^Restart=always$", unit, re.M)


class _Inline:
    def __init__(self, target):
        self.target = target

    def start(self):
        self.target()


# ── one name in three places ──────────────────────────────────────────────────────────────────────────────────


class TestTheTriggerIsOneName:
    @pytest.mark.parametrize("kind", ["update", "plugins"])
    def test_the_app_the_path_unit_and_the_root_script_agree(self, kind):
        name, path_unit, service = privileged.TRIGGERS[kind]
        root = _root_script()
        assert root.TRIGGER_DIR == privileged.TRIGGER_DIR == "/run/jen"
        assert root.TRIGGER_FILES[kind] == name
        assert path_unit in root.TRIGGER_PATH_UNITS
        unit = (ROOT / path_unit).read_text(encoding="utf-8")
        assert re.findall(r"^PathExists=(.*)$", unit, re.M) == [privileged.trigger_path(kind).replace(os.sep, "/")]
        assert re.findall(r"^Unit=(.*)$", unit, re.M) == [service]
        assert re.search(r"^WantedBy=multi-user\.target$", unit, re.M)
        assert (ROOT / service).is_file()

    def test_jens_unit_owns_the_directory_the_triggers_live_in(self):
        unit = (ROOT / "jen.service.template").read_text(encoding="utf-8")
        for line in ("RuntimeDirectory=jen", "RuntimeDirectoryMode=0700", "RuntimeDirectoryPreserve=yes"):
            assert re.search(rf"^{line}$", unit, re.M), line

    def test_every_installer_handles_both_path_units(self):
        install = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        root = (ROOT / "jen-update-root.py").read_text(encoding="utf-8")
        for unit in ("jen-update.path", "jen-plugin-install.path"):
            assert f'"/etc/systemd/system/{unit}"' in install  # snapshotted, and put back by a rollback
            assert f'{unit}) dest="/etc/systemd/system/{unit}"' in install
            assert unit in uninstall
            assert f'"/etc/systemd/system/{unit}": "{unit}"' in root
        assert '--converge-triggers "$APP_DIR"' in install


# ── the app's half ────────────────────────────────────────────────────────────────────────────────────────────


class TestTheAppAsks:
    def test_a_watching_path_unit_gets_a_trigger_file_and_nothing_is_run(self, monkeypatch, tmp_path):
        monkeypatch.setattr(privileged, "TRIGGER_DIR", str(tmp_path))
        monkeypatch.setattr(privileged, "path_unit_active", lambda kind: True)
        monkeypatch.setattr(privileged, "_legacy_start", lambda kind: pytest.fail("sudo was run"))
        assert privileged.request("update") == (True, "path")
        assert privileged.request("plugins") == (True, "path")
        assert sorted(p.name for p in tmp_path.iterdir()) == ["plugins.request", "update.request"]
        assert all(p.stat().st_size == 0 for p in tmp_path.iterdir())

    def test_asking_twice_is_one_request(self, monkeypatch, tmp_path):
        monkeypatch.setattr(privileged, "TRIGGER_DIR", str(tmp_path))
        monkeypatch.setattr(privileged, "path_unit_active", lambda kind: True)
        assert privileged.request("update") == privileged.request("update") == (True, "path")
        assert [p.name for p in tmp_path.iterdir()] == ["update.request"]

    def test_a_directory_that_is_not_there_is_said(self, monkeypatch, tmp_path):
        monkeypatch.setattr(privileged, "TRIGGER_DIR", str(tmp_path / "absent"))
        monkeypatch.setattr(privileged, "path_unit_active", lambda kind: True)
        ok, why = privileged.request("update")
        assert ok is False and "could not write" in why

    @needs_linux
    def test_a_link_where_the_trigger_goes_is_not_followed(self, monkeypatch, tmp_path):
        target = tmp_path / "elsewhere"
        (tmp_path / "run").mkdir()
        os.symlink(target, tmp_path / "run" / "update.request")
        monkeypatch.setattr(privileged, "TRIGGER_DIR", str(tmp_path / "run"))
        monkeypatch.setattr(privileged, "path_unit_active", lambda kind: True)
        ok, _why = privileged.request("update")
        assert ok is False and not target.exists()

    def test_a_path_unit_that_is_not_watching_means_the_earlier_command(self, monkeypatch, tmp_path):
        monkeypatch.setattr(privileged, "TRIGGER_DIR", str(tmp_path))
        monkeypatch.setattr(privileged, "path_unit_active", lambda kind: False)
        monkeypatch.setattr(privileged, "_legacy_start", lambda kind: (True, "sudo"))
        assert privileged.request("plugins") == (True, "sudo")
        assert list(tmp_path.iterdir()) == []

    def test_an_unknown_request_is_an_error_not_a_default(self):
        with pytest.raises(ValueError):
            privileged.request("restart")

    @pytest.mark.parametrize(
        "raised", [FileNotFoundError("no systemctl"), privileged.subprocess.TimeoutExpired("systemctl", 5)]
    )
    def test_a_question_systemd_did_not_answer_is_not_watching(self, monkeypatch, raised):
        def boom(*a, **k):
            raise raised

        monkeypatch.setattr(privileged.subprocess, "run", boom)
        assert privileged.path_unit_active("update") is False

    def test_the_question_is_read_only(self, monkeypatch):
        asked = []

        class Done:
            returncode = 0

        monkeypatch.setattr(privileged.subprocess, "run", lambda argv, **kw: asked.append(argv) or Done())
        assert privileged.path_unit_active("update") is True
        assert asked == [["/usr/bin/systemctl", "is-active", "--quiet", "jen-update.path"]]

    @pytest.mark.parametrize(
        "deployment,active,legacy,said,ran",
        [
            ("docker", False, (True, "sudo"), "not-systemd", 0),
            ("dev", False, (True, "sudo"), "not-systemd", 0),
            ("systemd", True, (True, "sudo"), "watching", 0),
            ("systemd", False, (True, "sudo"), "asked", 1),
            ("systemd", False, (False, "sudo: a password is required"), "legacy-unavailable", 1),
        ],
    )
    def test_a_start_converges_once_and_only_where_it_can(self, monkeypatch, deployment, active, legacy, said, ran):
        calls = []
        monkeypatch.setattr(runtime, "deployment", lambda: deployment)
        monkeypatch.setattr(privileged, "path_unit_active", lambda kind: active)
        monkeypatch.setattr(privileged, "_legacy_start", lambda kind: calls.append(kind) or legacy)
        assert privileged.converge_at_startup() == said
        assert calls == ["plugins"] * ran

    def test_the_two_routes_ask_through_the_one_module(self):
        updates = (ROOT / "jen/routes/settings/updates.py").read_text(encoding="utf-8")
        plugins = (ROOT / "jen/services/plugins.py").read_text(encoding="utf-8")
        assert 'privileged.request("update")' in updates
        assert 'privileged.request("plugins")' in plugins


# ── root's half ───────────────────────────────────────────────────────────────────────────────────────────────


@needs_linux
class TestRootRemovesTheTriggerFirst:
    def _dir(self, tmp_path):
        d = tmp_path / "run-jen"
        d.mkdir()
        return d

    def test_a_file_is_removed(self, tmp_path):
        d = self._dir(tmp_path)
        (d / "update.request").touch()
        assert _root_script().consume_trigger("update", str(d)) == "removed"
        assert list(d.iterdir()) == []

    def test_a_link_is_removed_and_what_it_points_at_is_not_touched(self, tmp_path):
        d = self._dir(tmp_path)
        victim = tmp_path / "victim"
        victim.write_text("keep")
        os.symlink(victim, d / "update.request")
        assert _root_script().consume_trigger("update", str(d)) == "removed"
        assert list(d.iterdir()) == [] and victim.read_text() == "keep"

    def test_a_directory_is_removed_with_what_is_in_it(self, tmp_path):
        d = self._dir(tmp_path)
        (d / "plugins.request").mkdir()
        (d / "plugins.request" / "x").touch()
        assert _root_script().consume_trigger("plugins", str(d)) == "removed"
        assert list(d.iterdir()) == []

    def test_nothing_there_and_no_directory_are_said_apart(self, tmp_path):
        root = _root_script()
        assert root.consume_trigger("update", str(self._dir(tmp_path))) == "absent"
        assert root.consume_trigger("update", str(tmp_path / "nowhere")) == "no-dir"

    def test_a_directory_that_is_itself_a_link_is_not_entered(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        (real / "update.request").write_text("keep")
        os.symlink(real, tmp_path / "run-jen")
        assert _root_script().consume_trigger("update", str(tmp_path / "run-jen")) == "no-dir"
        assert (real / "update.request").read_text() == "keep"

    def test_only_the_asked_name_is_removed(self, tmp_path):
        d = self._dir(tmp_path)
        (d / "update.request").touch()
        (d / "plugins.request").touch()
        _root_script().consume_trigger("update", str(d))
        assert [p.name for p in d.iterdir()] == ["plugins.request"]


class TestTheTriggerGoesBeforeAnythingThatCanReturn:
    def test_main_removes_the_trigger_before_it_reads_the_layout(self):
        src = (ROOT / "jen-update-root.py").read_text(encoding="utf-8")
        main = src[src.index("\ndef main():") :]
        first_gate = main.index("if LAYOUT_ERROR:")
        assert main.index('consume_trigger("update")') < first_gate
        assert main.index('consume_trigger("plugins")') < first_gate
        # ... and the units converge only once the layout is trusted
        assert main.index('check_layout("update")') < main.index("    converge_triggers()\n")


class _Systemd:
    """`subprocess.run` as `converge_triggers` uses it: records every argv and answers `is-active` as told."""

    def __init__(self, active):
        self.active, self.ran = active, []

    def __call__(self, argv, **kw):
        self.ran.append(argv)

        class Done:
            returncode = 0 if (argv[1] != "is-active" or self.active) else 3

        return Done()


@needs_linux
class TestTheGrantGoesAfterItsReplacementWorks:
    def _box(self, tmp_path, monkeypatch, active, ships=True):
        root = _root_script()
        app, units = tmp_path / "app", tmp_path / "systemd"
        app.mkdir()
        units.mkdir()
        if ships:
            for unit in root.TRIGGER_PATH_UNITS:
                (app / unit).write_text((ROOT / unit).read_text(encoding="utf-8"))
        sudoers = tmp_path / "sudoers-jen"
        sudoers.write_text("www-data ALL=(root) NOPASSWD: /usr/bin/systemctl restart jen\n")
        systemd = _Systemd(active)
        monkeypatch.setattr(root.subprocess, "run", systemd)
        monkeypatch.setattr(root.os, "chown", lambda *a, **k: None)
        return root, app, units, sudoers, systemd

    def test_both_units_active_removes_the_grant(self, tmp_path, monkeypatch):
        root, app, units, sudoers, systemd = self._box(tmp_path, monkeypatch, active=True)
        assert root.converge_triggers(str(app), str(units), str(sudoers)) == "converged"
        assert not sudoers.exists()
        assert sorted(p.name for p in units.iterdir()) == ["jen-plugin-install.path", "jen-update.path"]
        assert all(stat.S_IMODE(p.stat().st_mode) == 0o644 for p in units.iterdir())
        verbs = [argv[1] for argv in systemd.ran]
        assert verbs.index("daemon-reload") < verbs.index("enable") < verbs.index("is-active")
        assert ["/usr/bin/systemctl", "enable", "--now", "jen-update.path"] in systemd.ran

    def test_a_unit_that_is_not_active_leaves_the_grant(self, tmp_path, monkeypatch):
        root, app, units, sudoers, _systemd = self._box(tmp_path, monkeypatch, active=False)
        assert root.converge_triggers(str(app), str(units), str(sudoers)) == "not-active"
        assert sudoers.exists()

    def test_a_release_that_ships_no_path_unit_changes_nothing(self, tmp_path, monkeypatch):
        root, app, units, sudoers, systemd = self._box(tmp_path, monkeypatch, active=True, ships=False)
        assert root.converge_triggers(str(app), str(units), str(sudoers)) == "no-units"
        assert sudoers.exists() and list(units.iterdir()) == [] and systemd.ran == []

    def test_a_second_run_reloads_nothing_and_says_watching(self, tmp_path, monkeypatch):
        root, app, units, sudoers, systemd = self._box(tmp_path, monkeypatch, active=True)
        root.converge_triggers(str(app), str(units), str(sudoers))
        systemd.ran.clear()
        assert root.converge_triggers(str(app), str(units), str(sudoers)) == "watching"
        assert "daemon-reload" not in [argv[1] for argv in systemd.ran]

    def test_systemd_failing_is_never_fatal_and_leaves_the_grant(self, tmp_path, monkeypatch):
        root, app, units, sudoers, _systemd = self._box(tmp_path, monkeypatch, active=True)

        def boom(argv, **kw):
            raise OSError("no systemctl here")

        monkeypatch.setattr(root.subprocess, "run", boom)
        assert root.converge_triggers(str(app), str(units), str(sudoers)) == "not-active"
        assert sudoers.exists()
