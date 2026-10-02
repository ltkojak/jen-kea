"""
tests/test_install_python_env.py
──────────────────────────────────
v5.67.0-beta.9 (Q121, item e) — every Python process install.sh starts to run
Jen's own code exports the three layout variables TOGETHER: JEN_ROOT,
JEN_CONFIG_DIR and JEN_CONTENT_DIR.

Such a process has no systemd `Environment=` lines to inherit them from. With
JEN_ROOT alone, jen/extensions.py derives `CONFIG_DIR` as `$JEN_ROOT/etc`
(extensions.py:202-204): `--restore` and `--rollback` (which passed only
JEN_ROOT) printed a reload warning on every restore, ran their sizing pass and
their rollback snapshot against whatever database the BUNDLE's own config
named, and read a legacy writable plugin as "code is not installed here". The
other launches (_seed_jen_db, both verify_install snippets) already passed all
three; this is the test that makes the next one do the same.

Scope: inline `-c "..."` snippets that import the `jen` package (the shapes
tests/test_no_root_jen_imports.py already scans) and every `-m jen.<module>`
launch.
"""

import re

from tests.test_no_root_jen_imports import _CONTINUATION, _JEN_IMPORT_OR_DYNAMIC, INSTALL_SH, _inline_c_snippets

_REQUIRED = ("JEN_ROOT=", "JEN_CONFIG_DIR=", "JEN_CONTENT_DIR=")
_DASH_M_JEN = re.compile(r"-m\s+jen\.[\w.]+")


def _launches(source: str) -> list[tuple[str, str]]:
    """(kind, logical_line) for every launch of Jen's own code in `source`."""
    found = []
    for opening, body in _inline_c_snippets(source):
        if _JEN_IMPORT_OR_DYNAMIC.search(body):
            found.append(("inline -c snippet", opening))
    for line in _CONTINUATION.sub(" ", source).split("\n"):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _DASH_M_JEN.search(line):
            found.append(("-m jen.<module>", line))
    return found


class TestScannerSeesTheRealLaunches:
    def test_it_finds_the_launches_install_sh_makes_today(self):
        kinds = [k for k, _ in _launches(INSTALL_SH)]
        # _seed_jen_db, the two verify_install snippets, --restore, --rollback (and the pre-upgrade backup)
        assert kinds.count("inline -c snippet") >= 3
        assert kinds.count("-m jen.<module>") >= 2

    def test_a_hand_built_launch_missing_two_of_the_three_is_caught(self):
        sample = 'if ! (cd "$(app_pyroot)" && JEN_ROOT="$(app_pyroot)" "$RESTORE_PY" -m jen.tools.restore "$B"); then\n'
        ((kind, line),) = _launches(sample)
        assert kind == "-m jen.<module>"
        assert [r for r in _REQUIRED if r not in line] == ["JEN_CONFIG_DIR=", "JEN_CONTENT_DIR="]


class TestEveryLaunchExportsTheLayout:
    def test_install_sh(self):
        missing = []
        for kind, line in _launches(INSTALL_SH):
            absent = [r for r in _REQUIRED if r not in line]
            if absent:
                missing.append(f"{kind} lacks {absent}: {line.strip()[:140]}")
        assert missing == [], "\n".join(missing)
