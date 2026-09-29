"""
tests/test_doc_links.py
────────────────────────
v5.66.0-beta.4 (Q106) — two doc references were plain code spans, not links, until this Q:
docs/runbooks.md's own mentions of ARCHITECTURE.md and SECURITY.md, and SECURITY.md's mention
of docs/runbooks.md. Now that they're real relative Markdown links, this is what keeps every
relative link across the docs honest going forward — a rename or a typo that would otherwise
just 404 in a reader's browser fails here instead.

Every relative link (not http(s)/mailto, not a same-file anchor) in docs/*.md, README.md,
SECURITY.md and CONTRIBUTING.md must resolve to a real file in the tree; a `#anchor` suffix on
a link to another file is stripped before resolving (GitHub's heading-anchor slugs aren't
checked here, only that the FILE exists).
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC_FILES = sorted(ROOT.glob("docs/*.md")) + [ROOT / "README.md", ROOT / "SECURITY.md", ROOT / "CONTRIBUTING.md"]

_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def _relative_links():
    for path in DOC_FILES:
        text = path.read_text(encoding="utf-8")
        for m in _LINK_RE.finditer(text):
            target = m.group(1).strip()
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            rel = path.relative_to(ROOT).as_posix()
            yield pytest.param(path, target, id=f"{rel}:{target}")


LINKS = list(_relative_links())


class TestDocFilesExist:
    def test_every_doc_file_under_test_exists(self):
        # a guard against the glob/list above silently shrinking to nothing
        assert len(DOC_FILES) >= 10, DOC_FILES


@pytest.mark.parametrize("path,target", LINKS)
def test_relative_link_resolves_to_a_real_file(path, target):
    file_part = target.split("#", 1)[0]
    resolved = (path.parent / file_part).resolve()
    assert resolved.is_file(), (
        f"{path.relative_to(ROOT).as_posix()}: link target {target!r} does not resolve to a real file ({resolved})"
    )


def test_at_least_one_link_was_actually_collected():
    # a broken _LINK_RE or an empty DOC_FILES list would make every test above vacuously pass
    assert len(LINKS) > 20, len(LINKS)
