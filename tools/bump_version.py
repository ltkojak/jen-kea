#!/usr/bin/env python3
"""
tools/bump_version.py — move the six version spots together and prepend
a CHANGELOG entry, the way every release since 5.32.1-beta.1 was cut.

    py tools/bump_version.py 5.38.0-beta.1 5.39.0-beta.1 path/to/entry.md

`entry.md` starts with the new heading (`## [5.39.0-beta.1] - 2026-09-15`)
and ends with a blank line; it is inserted immediately before the
previous release's heading. The six spots (CLAUDE.md "Versioning"):
jen/__init__.py, install.sh, Dockerfile, docker-compose.yml,
docker-compose.mysql.yml, and the CHANGELOG heading. README is NOT a
spot. Refuses to run if any spot does not carry OLD exactly once, so a
half-bumped tree is never produced. Working copies may be CRLF; files
are rewritten with LF, which git's autocrlf normalises as usual.
"""

from __future__ import annotations

import pathlib
import re
import sys

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(-(beta|rc)\.\d+)?$")


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 2
    old, new, entry_path = argv[1], argv[2], pathlib.Path(argv[3])
    for v in (old, new):
        if not VERSION_RE.match(v):
            print(f"not a Jen version: {v!r} (X.Y.Z, X.Y.Z-beta.N or X.Y.Z-rc.N)")
            return 2
    root = pathlib.Path(__file__).resolve().parent.parent
    entry = entry_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if not entry.startswith(f"## [{new}]"):
        print(f"{entry_path} must start with '## [{new}]'")
        return 2
    if not entry.endswith("\n\n"):
        entry = entry.rstrip("\n") + "\n\n"

    spots = [
        ("jen/__init__.py", f'JEN_VERSION = "{old}"', f'JEN_VERSION = "{new}"'),
        ("install.sh", f'JEN_VERSION="{old}"', f'JEN_VERSION="{new}"'),
        ("Dockerfile", f'LABEL version="{old}"', f'LABEL version="{new}"'),
        ("docker-compose.yml", f"jen-dhcp:{old}", f"jen-dhcp:{new}"),
        ("docker-compose.mysql.yml", f"jen-dhcp:{old}", f"jen-dhcp:{new}"),
        ("CHANGELOG.md", f"## [{old}]", entry + f"## [{old}]"),
    ]
    texts = {}
    for rel, needle, _repl in spots:
        text = (root / rel).read_text(encoding="utf-8").replace("\r\n", "\n")
        n = text.count(needle)
        if n != 1:
            print(f"{rel}: expected exactly one {needle!r}, found {n} — nothing written")
            return 1
        texts[rel] = text
    for rel, needle, repl in spots:
        (root / rel).write_text(texts[rel].replace(needle, repl, 1), encoding="utf-8", newline="\n")
        print(f"{rel}: {old} -> {new}")
    print("bumped; now run: py -m pytest --noconftest tests/test_changelog.py -q")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
