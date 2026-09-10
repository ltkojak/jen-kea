"""
tests/test_no_shipped_symlinks.py
─────────────────────────────────
v5.11.0 — a tracked symlink under templates/ or static/ ships in every
`git archive` release tarball. `templates/templates` was a dangling
absolute symlink (`/home/claude/audit/jen/templates`, committed in
v4.4.10) that made a plain `tar xzf jen-vX.Y.Z.tar.gz` fail unless that
exact path happened to exist — and it broke the updater's snapshot on a
real box (fixed defensively in v5.8.4 with `symlinks=True`). Guard
against another one.
"""

import subprocess

SHIPPED_DIRS = ["templates", "static", "jen", "plugins"]


def _tracked_symlinks():
    out = subprocess.run(
        ["git", "ls-files", "-s", "--", *SHIPPED_DIRS],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    bad = []
    for line in out.splitlines():
        if not line.strip():
            continue
        mode, rest = line.split(" ", 1)
        if mode == "120000":  # git's mode for a symlink blob
            bad.append(rest.split("\t", 1)[-1])
    return bad


def test_no_tracked_symlinks_in_shipped_directories():
    bad = _tracked_symlinks()
    assert not bad, (
        f"tracked symlink(s) under a shipped directory: {bad}. These land in every "
        "release tarball and break a plain `tar xzf`. Replace with a real file or `git rm` it."
    )
