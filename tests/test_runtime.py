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
