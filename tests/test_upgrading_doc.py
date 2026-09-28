"""
tests/test_upgrading_doc.py
────────────────────────────
v5.66.0-beta.3 (Q105 c) — docs/upgrading.md is a living page, one section per
operator-visible change since v5.56.3, meant to be kept current by every later
release commit (the round-3 recipe line: "a release commit updates
docs/upgrading.md when the CHANGELOG entry has an operator-visible item"). This
is the cheap "did you actually read them all" guard the spec calls for: every
CHANGELOG heading from 5.56.4 onward must appear in the page at least once. It
can't verify the PROSE is accurate — only that nothing was silently skipped.

Also covers docs/runbooks.md (Q105 b): it exists and is linked from the two
places an operator would actually go looking for it.
"""

import pathlib
import re

import pytest

from jen.version import parse_version

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_UPGRADING = _ROOT / "docs" / "upgrading.md"
_RUNBOOKS = _ROOT / "docs" / "runbooks.md"
_CHANGELOG = _ROOT / "CHANGELOG.md"
_ADMIN_GUIDE = _ROOT / "docs" / "admin-guide.md"
_SECURITY = _ROOT / "SECURITY.md"

_FLOOR = "5.56.4-beta.1"  # the oldest heading upgrading.md must cover — 5.56.3 itself is the baseline


def _changelog_versions_since_floor() -> list[str]:
    """Every `## [X.Y.Z...]` heading in CHANGELOG.md at or above the floor version,
    oldest CHANGELOG.md entry counted first being 5.56.4-beta.1 (5.56.3 itself, the
    stable floor everything is relative to, is deliberately excluded — the guard is
    about not skipping anything ADDED since, not about restating the floor)."""
    text = _CHANGELOG.read_text(encoding="utf-8")
    headings = re.findall(r"^## \[([^\]]+)\]", text, re.M)
    floor_rank = parse_version(_FLOOR)
    return [v for v in headings if parse_version(v) >= floor_rank]


class TestUpgradingDocExists:
    def test_file_exists(self):
        assert _UPGRADING.is_file()


class TestUpgradingDocCoversEveryVersionSinceTheFloor:
    def test_the_floor_itself_resolves_to_a_real_changelog_heading(self):
        # a canary against the floor constant itself going stale (e.g. a future
        # renumbering) — if 5.56.4-beta.1 ever stops being a real heading, this
        # test (not the coverage test below, which would just silently cover
        # less) is what should fail.
        text = _CHANGELOG.read_text(encoding="utf-8")
        assert f"## [{_FLOOR}]" in text

    def test_every_changelog_heading_since_5_56_4_is_mentioned(self):
        text = _UPGRADING.read_text(encoding="utf-8")
        versions = _changelog_versions_since_floor()
        assert versions, "no CHANGELOG headings found at or above the floor — the parser itself is broken"
        missing = [v for v in versions if v not in text]
        assert not missing, f"docs/upgrading.md never mentions: {missing}"


class TestUpgradingDocNeverTalksChannelsOrPromotion:
    """Q105 c: 'without channel or promotion language' — written for an operator
    coming from stable 5.56.3, never told what channel anything shipped on or
    that something is a step toward a future promotion. The version numbers
    themselves necessarily carry a literal '-beta.N' suffix (that's the numbering
    scheme, not a claim about channels) — this checks for the NARRATIVE phrases,
    not the numbers."""

    _BANNED_PHRASES = (
        "beta channel",
        "stable channel",
        "release candidate",
        "promote",
        "promotion",
        "promoted",
        "when this ships to stable",
        "once this is stable",
    )

    def test_no_channel_or_promotion_language(self):
        text = _UPGRADING.read_text(encoding="utf-8").lower()
        found = [p for p in self._BANNED_PHRASES if p in text]
        assert not found, f"docs/upgrading.md uses channel/promotion language: {found}"


class TestRunbooksDocExistsAndIsLinked:
    def test_file_exists(self):
        assert _RUNBOOKS.is_file()

    def test_four_numbered_runbooks_are_present(self):
        text = _RUNBOOKS.read_text(encoding="utf-8")
        for heading in (
            "Rotating the helper signing key",
            "wrong bytes",
            "Installing the Kea host helper by hand",
            "Restoring a JENREC2 recovery bundle",
        ):
            assert heading in text, f"missing runbook: {heading!r}"

    def test_linked_from_admin_guide(self):
        text = _ADMIN_GUIDE.read_text(encoding="utf-8")
        assert "runbooks.md" in text

    def test_linked_from_security_md(self):
        text = _SECURITY.read_text(encoding="utf-8")
        assert "runbooks.md" in text

    def test_upgrading_doc_is_also_linked_from_admin_guide(self):
        text = _ADMIN_GUIDE.read_text(encoding="utf-8")
        assert "upgrading.md" in text


@pytest.mark.parametrize("version", _changelog_versions_since_floor())
def test_each_version_individually_for_a_readable_failure(version):
    """The aggregate test above is what actually guards this; this parametrized
    twin exists only so a red run names the ONE missing version directly instead
    of a Python list repr buried in an assertion message."""
    text = _UPGRADING.read_text(encoding="utf-8")
    assert version in text
