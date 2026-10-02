"""
tests/test_runtime.py
──────────────────────
v5.67.0-beta.6 (Q118) — jen.services.runtime.deployment() is the single
place that answers "systemd, Docker, or dev" — it replaces a JEN_ROOT-based
heuristic duplicated (inconsistently) across is_systemd_host(),
content_dir_incomplete(), and the venv-migration check, broken the moment
Q114's rendered systemd unit started setting JEN_ROOT on every production
install too. No DB/Flask needed — pure function, runs with --noconftest.
"""

import os
import pathlib
import re

from jen.services import runtime


def _patch_dockerenv(monkeypatch, present: bool):
    real_exists = os.path.exists

    def fake(path):
        if path == "/.dockerenv":
            return present
        return real_exists(path)

    monkeypatch.setattr(os.path, "exists", fake)


def _clear_signals(monkeypatch):
    monkeypatch.delenv("JEN_SERVICE_MANAGER", raising=False)
    monkeypatch.delenv("INVOCATION_ID", raising=False)


class TestDeployment:
    """Every permutation drives the real function through its actual
    inputs (env vars, /.dockerenv) — never by monkeypatching deployment()
    itself, which would just test the mock."""

    def test_dockerenv_present_is_docker(self, monkeypatch):
        _clear_signals(monkeypatch)
        _patch_dockerenv(monkeypatch, True)
        assert runtime.deployment() == "docker"

    def test_jen_service_manager_systemd_is_systemd(self, monkeypatch):
        _clear_signals(monkeypatch)
        _patch_dockerenv(monkeypatch, False)
        monkeypatch.setenv("JEN_SERVICE_MANAGER", "systemd")
        assert runtime.deployment() == "systemd"

    def test_invocation_id_alone_is_systemd(self, monkeypatch):
        """Covers a unit rendered before this release, or a hand-written
        one from docs/manual-install.md — neither carries the new
        Environment=JEN_SERVICE_MANAGER=systemd line, but systemd sets
        INVOCATION_ID for every unit it starts regardless."""
        _clear_signals(monkeypatch)
        _patch_dockerenv(monkeypatch, False)
        monkeypatch.setenv("INVOCATION_ID", "deadbeef")
        assert runtime.deployment() == "systemd"

    def test_an_unrecognized_jen_service_manager_value_is_not_systemd_alone(self, monkeypatch):
        _clear_signals(monkeypatch)
        _patch_dockerenv(monkeypatch, False)
        monkeypatch.setenv("JEN_SERVICE_MANAGER", "openrc")
        assert runtime.deployment() == "dev"

    def test_neither_signal_is_dev(self, monkeypatch):
        _clear_signals(monkeypatch)
        _patch_dockerenv(monkeypatch, False)
        assert runtime.deployment() == "dev"

    def test_dockerenv_wins_over_a_stray_systemd_signal(self, monkeypatch):
        """A container that happens to inherit INVOCATION_ID from its host
        (unusual, but not impossible) is still a container."""
        _clear_signals(monkeypatch)
        _patch_dockerenv(monkeypatch, True)
        monkeypatch.setenv("INVOCATION_ID", "deadbeef")
        assert runtime.deployment() == "docker"

    def test_jen_root_never_changes_the_answer(self, monkeypatch):
        """INVARIANT: the one thing this Q exists to fix — JEN_ROOT is a
        path default and must never be consulted here, set or not, and
        whatever shape it takes (including a relocated install's own
        .../current/app)."""
        _clear_signals(monkeypatch)
        _patch_dockerenv(monkeypatch, False)
        for jen_root in (None, "/opt/jen/current/app", "/home/dev/jen", "/srv/jen/app/current/app"):
            if jen_root is None:
                monkeypatch.delenv("JEN_ROOT", raising=False)
            else:
                monkeypatch.setenv("JEN_ROOT", jen_root)
            assert runtime.deployment() == "dev"

        monkeypatch.setenv("INVOCATION_ID", "deadbeef")
        for jen_root in (None, "/opt/jen/current/app", "/home/dev/jen"):
            if jen_root is None:
                monkeypatch.delenv("JEN_ROOT", raising=False)
            else:
                monkeypatch.setenv("JEN_ROOT", jen_root)
            assert runtime.deployment() == "systemd"


class TestIsSystemdHostDelegates:
    """plugins.is_systemd_host() is kept only as a one-line wrapper for the
    plugin API's own naming — this proves it actually delegates rather than
    carrying its own copy of the logic again."""

    def test_true_when_deployment_is_systemd(self, monkeypatch):
        from jen.services import plugins

        monkeypatch.setattr(plugins.runtime, "deployment", lambda: "systemd")
        assert plugins.is_systemd_host() is True

    def test_false_when_deployment_is_docker_or_dev(self, monkeypatch):
        from jen.services import plugins

        monkeypatch.setattr(plugins.runtime, "deployment", lambda: "docker")
        assert plugins.is_systemd_host() is False
        monkeypatch.setattr(plugins.runtime, "deployment", lambda: "dev")
        assert plugins.is_systemd_host() is False


class TestNoJenRootAsADeploymentCondition:
    """v5.67.0-beta.6 (Q118) — the exact bug class this release fixes:
    is_systemd_host()/content_dir_incomplete()/the venv-migration check
    each independently asked "is JEN_ROOT set" to answer "is this
    systemd" — broken the moment Q114 started setting JEN_ROOT on every
    production install too. Refuse the pattern anywhere it could come
    back, outside extensions.py (where JEN_ROOT is legitimately read as a
    PATH default) and runtime.py (where it is deliberately never read at
    all)."""

    _PATTERN = re.compile(r'["\']JEN_ROOT["\']\s+(?:not\s+)?in\s+os\.environ|os\.environ\.get\(\s*["\']JEN_ROOT["\']')
    _ALLOWED = {"extensions.py", "runtime.py"}

    def test_the_scanner_actually_finds_the_old_shapes(self):
        samples = [
            '"JEN_ROOT" in os.environ',
            "'JEN_ROOT' not in os.environ",
            'os.environ.get("JEN_ROOT")',
        ]
        for s in samples:
            assert self._PATTERN.search(s), s

    def test_no_jen_file_matches_outside_the_allowed_two(self):
        repo = pathlib.Path(__file__).resolve().parent.parent
        offenders = []
        for path in sorted((repo / "jen").rglob("*.py")):
            if path.name in self._ALLOWED:
                continue
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                if self._PATTERN.search(code):
                    offenders.append(f"{path.relative_to(repo)}:{lineno}: {line.strip()}")
        assert not offenders, (
            "JEN_ROOT is a path default, never a deployment condition — "
            "use jen.services.runtime.deployment() instead:\n" + "\n".join(offenders)
        )


class TestRestartService:
    """v5.67.0-beta.10 (Q122) — "Save & Restart", the port change and the certificate upload/removal each ran
    `sudo systemctl restart jen` unconditionally; in a container there is no sudo and no unit, the call failed
    inside a thread nobody watched, and the page said "Jen is restarting..." while nothing restarted. The one
    helper now picks the restart by deployment(). Each test drives the real function with delay=0 and a
    fake at the one process boundary (subprocess.run / os.kill), never by stubbing deployment()'s answer's
    consequences."""

    def _wait(self, event):
        assert event.wait(5), "the restart never ran"

    def test_systemd_runs_exactly_the_command_the_sudoers_file_grants(self, monkeypatch):
        import threading

        _clear_signals(monkeypatch)
        _patch_dockerenv(monkeypatch, False)
        monkeypatch.setenv("JEN_SERVICE_MANAGER", "systemd")
        done, calls = threading.Event(), []
        monkeypatch.setattr(runtime.subprocess, "run", lambda cmd, *a, **k: (calls.append(cmd), done.set()))
        assert runtime.restart_service(delay=0) == "systemd"
        self._wait(done)
        assert calls == [["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "jen"]]
        sudoers = (pathlib.Path(__file__).resolve().parent.parent / "jen-sudoers").read_text(encoding="utf-8")
        assert "NOPASSWD: /usr/bin/systemctl restart jen\n" in sudoers

    def test_docker_signals_the_gunicorn_master_and_never_shells_out(self, monkeypatch):
        import threading

        _clear_signals(monkeypatch)
        _patch_dockerenv(monkeypatch, True)
        done, sent = threading.Event(), []
        monkeypatch.setattr(runtime.os, "getppid", lambda: 4242)
        monkeypatch.setattr(runtime.os, "kill", lambda pid, sig: (sent.append((pid, sig)), done.set()))
        monkeypatch.setattr(
            runtime.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no sudo in a container"))
        )
        assert runtime.restart_service(delay=0) == "docker"
        self._wait(done)
        assert sent == [(4242, runtime.signal.SIGTERM)]

    def test_a_dev_checkout_restarts_nothing_and_says_so(self, monkeypatch):
        _clear_signals(monkeypatch)
        _patch_dockerenv(monkeypatch, False)
        monkeypatch.setattr(
            runtime.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run"))
        )
        monkeypatch.setattr(runtime.os, "kill", lambda *a: (_ for _ in ()).throw(AssertionError("must not signal")))
        assert runtime.restart_service(delay=0) == "none"
        assert "restart it yourself" in runtime.RESTART_BY_HAND

    def test_no_route_still_shells_out_to_systemctl_restart_itself(self):
        repo = pathlib.Path(__file__).resolve().parent.parent
        offenders = [
            str(p.relative_to(repo))
            for p in sorted((repo / "jen" / "routes").rglob("*.py"))
            if '"restart", "jen"' in p.read_text(encoding="utf-8")
        ]
        assert not offenders, f"{offenders}: use jen.services.runtime.restart_service()"

    def test_both_compose_files_restart_the_container_when_jen_stops_itself(self):
        repo = pathlib.Path(__file__).resolve().parent.parent
        for name in ("docker-compose.yml", "docker-compose.mysql.yml"):
            text = (repo / name).read_text(encoding="utf-8")
            jen_block = text.split("  jen:\n", 1)[1].split("\n  jen-mysql:", 1)[0]
            assert "restart: unless-stopped" in jen_block, name
