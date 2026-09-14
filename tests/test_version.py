"""
tests/test_version.py
─────────────────────
v5.32.0 (Q38) — release channels. One parser for Jen's version grammar
(`X.Y.Z`, `X.Y.Z-beta.N`, `X.Y.Z-rc.N`), the channel-aware release
picker, and the guarantee that the root-privileged updater — which
can't import the jen package — carries a byte-identical copy of both.

DB-free: `python -m pytest --noconftest tests/test_version.py`.
"""

import pathlib
import re

import pytest

from jen import version

REPO = pathlib.Path(__file__).resolve().parent.parent
ROOT_SCRIPT = REPO / "jen-update-root.py"


class TestParseVersion:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("5.32.0", (5, 32, 0, 2, 0)),
            ("v5.32.0", (0, 0, 0, 0, 0)),  # callers strip the v; the parser doesn't guess
            ("5.32.0-beta.1", (5, 32, 0, 0, 1)),
            ("5.32.0-beta.12", (5, 32, 0, 0, 12)),
            ("5.32.0-rc.1", (5, 32, 0, 1, 1)),
            ("  5.32.0  ", (5, 32, 0, 2, 0)),
            ("5.32", (0, 0, 0, 0, 0)),
            ("5.32.0-alpha.1", (0, 0, 0, 0, 0)),
            ("5.32.0-beta", (0, 0, 0, 0, 0)),
            ("5.32.0-foo", (0, 0, 0, 0, 0)),
            ("?", (0, 0, 0, 0, 0)),
            ("", (0, 0, 0, 0, 0)),
            (None, (0, 0, 0, 0, 0)),
        ],
    )
    def test_parse(self, text, expected):
        assert version.parse_version(text) == expected

    def test_semver_ordering(self):
        ordered = ["5.31.3", "5.32.0-beta.1", "5.32.0-beta.2", "5.32.0-rc.1", "5.32.0", "5.32.1-beta.1", "5.32.1"]
        keys = [version.parse_version(v) for v in ordered]
        assert keys == sorted(keys)
        assert len(set(keys)) == len(keys)

    def test_numeric_drops_the_prerelease_part(self):
        assert version.numeric("5.32.0-beta.3") == (5, 32, 0)
        assert version.numeric("5.32.0") == (5, 32, 0)
        # The rule that matters for plugins: a beta of X.Y.Z satisfies X.Y.Z.
        assert version.numeric("5.32.0-beta.1") >= version.numeric("5.32.0")

    def test_is_prerelease(self):
        assert version.is_prerelease("5.32.0-beta.1")
        assert version.is_prerelease("5.32.0-rc.2")
        assert not version.is_prerelease("5.32.0")
        assert not version.is_prerelease("garbage")


def _rel(tag, prerelease=False, draft=False):
    return {"tag_name": tag, "prerelease": prerelease, "draft": draft, "html_url": f"https://x/{tag}"}


# GitHub lists by creation time — deliberately NOT in version order here.
LISTING = [
    _rel("v5.32.0-beta.2", prerelease=True),
    _rel("v5.31.3"),
    _rel("v5.33.0", draft=True),  # a draft is never offered, whatever its number
    _rel("v5.32.0-beta.1", prerelease=True),
    _rel("v5.32.0-rc.1", prerelease=True),
    _rel("v5.30.0"),
    _rel("v5.32.0-foo", prerelease=True),  # mistyped tag: unparsable, ignored
    _rel("nightly", prerelease=True),
]


class TestPickRelease:
    def test_stable_sees_only_final_releases(self):
        assert version.pick_release(LISTING, "stable")["tag_name"] == "v5.31.3"

    def test_beta_sees_the_newest_by_version_not_position(self):
        assert version.pick_release(LISTING, "beta")["tag_name"] == "v5.32.0-rc.1"

    def test_a_final_release_beats_its_own_prereleases_on_beta(self):
        listing = LISTING + [_rel("v5.32.0")]
        assert version.pick_release(listing, "beta")["tag_name"] == "v5.32.0"
        assert version.pick_release(listing, "stable")["tag_name"] == "v5.32.0"

    def test_unknown_channel_behaves_as_stable(self):
        assert version.pick_release(LISTING, "nightly")["tag_name"] == "v5.31.3"

    @pytest.mark.parametrize("listing", [[], None, [{"tag_name": "junk"}], [_rel("v9.9.9", draft=True)]])
    def test_nothing_usable_is_none(self, listing):
        assert version.pick_release(listing, "beta") is None
        assert version.pick_release(listing, "stable") is None

    def test_garbage_entries_are_skipped(self):
        assert version.pick_release(["nope", 3, None, _rel("v1.0.0")], "stable")["tag_name"] == "v1.0.0"


class TestRootScriptCarriesAnIdenticalCopy:
    """jen-update-root.py is pure stdlib and can't import jen.version, so
    it embeds the marked block verbatim. The comment saying "mirrors …
    exactly" used to be the only guard; this is the real one."""

    def _block(self, path):
        text = path.read_text(encoding="utf-8")
        m = re.search(r"# ── BEGIN shared-with-root ─.*?\n(.*?)# ── END shared-with-root ─", text, re.DOTALL)
        assert m, f"{path.name}: shared-with-root markers not found"
        return m.group(1)

    def test_blocks_are_byte_identical(self):
        assert self._block(REPO / "jen" / "version.py") == self._block(ROOT_SCRIPT)

    def test_root_script_uses_the_shared_parser(self):
        text = ROOT_SCRIPT.read_text(encoding="utf-8")
        assert "def parse_version(" in text and "def pick_release(" in text
        # The old three-int parser must not survive as a second opinion.
        assert 'int(x) for x in str(v).strip().split(".")[:3]' not in text


class TestEveryOtherParserDelegates:
    """No module may grow its own version arithmetic again."""

    def test_plugins_gate_on_the_numeric_triple(self):
        from jen.services import plugins

        assert plugins._parse_version("5.32.0-beta.1") == (5, 32, 0)
        assert plugins._parse_version("garbage") == (0, 0, 0)

    def test_changelog_sorts_prereleases_below_their_final(self):
        from jen.services.changelog import _version_sort_key

        keys = [_version_sort_key(v) for v in ("5.31.3", "5.32.0-beta.1", "5.32.0")]
        assert keys == sorted(keys)

    def test_no_ad_hoc_three_int_parsers_remain(self):
        offenders = []
        for path in sorted((REPO / "jen").rglob("*.py")):
            if path.name == "version.py":
                continue
            if 'split(".")[:3]' in path.read_text(encoding="utf-8"):
                offenders.append(path.as_posix())
        assert not offenders, f"version parsing outside jen/version.py: {offenders}"
