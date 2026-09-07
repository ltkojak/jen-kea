"""
tests/test_changelog.py
──────────────────────────
v5.2.1 — in-app "What's New" viewer. See jen/services/changelog.py's
module docstring for the full rationale: a small, purpose-built parser
for CHANGELOG.md's own consistent format, deliberately not a general
markdown library, since this is our own trusted file with a
constrained, fully-controlled structure.

Security note: even though CHANGELOG.md is our own file, not user
input, these tests still verify the HTML-escaping behavior explicitly
— the same "escape first, reintroduce only deliberate markup"
discipline established for DHCP hostnames in v5.1.15 applies here too,
as cheap insurance against a future changelog entry that happens to
contain a literal '<' or '&' (e.g., quoting an error message, a code
snippet, or an HTML attribute) rendering as a broken/injected tag
instead of literal text.
"""

import pathlib
import tempfile

from jen.services.changelog import parse_changelog, _inline_markdown_to_html


class TestInlineMarkdown:

    def test_bold(self):
        assert _inline_markdown_to_html("some **bold** text") == "some <strong>bold</strong> text"

    def test_italic(self):
        assert _inline_markdown_to_html("some *italic* text") == "some <em>italic</em> text"

    def test_code(self):
        assert _inline_markdown_to_html("run `git status` now") == "run <code>git status</code> now"

    def test_link(self):
        result = _inline_markdown_to_html("see [the docs](https://example.com/docs)")
        assert '<a href="https://example.com/docs" target="_blank" rel="noopener">the docs</a>' in result

    def test_bold_and_italic_together_do_not_interfere(self):
        result = _inline_markdown_to_html("**bold** and *italic* together")
        assert result == "<strong>bold</strong> and <em>italic</em> together"

    def test_raw_html_special_characters_are_escaped(self):
        """The actual security-relevant case: a changelog entry that
        quotes something containing '<', '>', or '&' must not produce
        a live tag or a broken attribute."""
        result = _inline_markdown_to_html("fixed `a < b` and `x & y`, plus <script>alert(1)</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result
        assert "&amp;" in result or "& y" not in result  # the raw & must be escaped somewhere

    def test_link_url_with_quote_is_escaped_in_attribute(self):
        """A malformed/unusual URL containing a quote must not break
        out of the href attribute — the quote must appear as the
        escaped entity, never as a literal unescaped double quote
        inside the attribute value."""
        result = _inline_markdown_to_html('[text](https://example.com/"onmouseover="alert(1))')
        assert 'href="https://example.com/&quot;onmouseover=&quot;alert(1"' in result

    def test_plain_text_with_no_markup_passes_through_unchanged_but_escaped(self):
        assert _inline_markdown_to_html("plain text, nothing special") == "plain text, nothing special"


class TestParseChangelog:

    def _write_changelog(self, tmp_path, content):
        p = tmp_path / "CHANGELOG.md"
        p.write_text(content, encoding="utf-8")
        return p

    def test_single_release_parsed_correctly(self, tmp_path):
        content = """# Changelog

## [1.2.3] - 2026-01-01

### A Fix

Some prose here.

- First bullet
- Second bullet with **bold**
"""
        path = self._write_changelog(tmp_path, content)
        releases = parse_changelog(path=path)
        assert len(releases) == 1
        assert releases[0]["version"] == "1.2.3"
        assert releases[0]["date"] == "2026-01-01"
        assert "<h4>A Fix</h4>" in releases[0]["html"]
        assert "<p>Some prose here.</p>" in releases[0]["html"]
        assert "<li>First bullet</li>" in releases[0]["html"]
        assert "<li>Second bullet with <strong>bold</strong></li>" in releases[0]["html"]

    def test_multiple_releases_parsed_in_order(self, tmp_path):
        content = """# Changelog

## [2.0.0] - 2026-02-01

### Newest

Newest content.

## [1.0.0] - 2026-01-01

### Oldest

Oldest content.
"""
        path = self._write_changelog(tmp_path, content)
        releases = parse_changelog(path=path)
        assert [r["version"] for r in releases] == ["2.0.0", "1.0.0"]
        assert "Newest content" in releases[0]["html"]
        assert "Oldest content" in releases[1]["html"]

    def test_limit_stops_after_n_releases(self, tmp_path):
        content = "# Changelog\n\n" + "".join(
            f"## [{i}.0.0] - 2026-01-0{i}\n\n### Entry {i}\n\nBody {i}.\n\n" for i in range(5, 0, -1)
        )
        path = self._write_changelog(tmp_path, content)
        releases = parse_changelog(path=path, limit=2)
        assert len(releases) == 2
        assert releases[0]["version"] == "5.0.0"
        assert releases[1]["version"] == "4.0.0"

    def test_no_limit_returns_all_releases(self, tmp_path):
        content = "# Changelog\n\n" + "".join(
            f"## [{i}.0.0] - 2026-01-0{i}\n\nBody {i}.\n\n" for i in range(1, 4)
        )
        path = self._write_changelog(tmp_path, content)
        releases = parse_changelog(path=path)
        assert len(releases) == 3

    def test_last_release_in_file_is_not_dropped(self, tmp_path):
        """Regression guard: the final release entry has no following
        '## [' header to trigger its own flush — must still be
        captured via the loop's natural completion, not silently lost."""
        content = "# Changelog\n\n## [1.0.0] - 2026-01-01\n\n### Only Entry\n\nOnly body.\n"
        path = self._write_changelog(tmp_path, content)
        releases = parse_changelog(path=path)
        assert len(releases) == 1
        assert "Only body" in releases[0]["html"]

    def test_multiline_bullet_continuation_joins_into_one_item(self, tmp_path):
        content = """# Changelog

## [1.0.0] - 2026-01-01

- This is a long bullet point that
  wraps onto a continuation line
- A second, separate bullet
"""
        path = self._write_changelog(tmp_path, content)
        releases = parse_changelog(path=path)
        html_out = releases[0]["html"]
        assert "This is a long bullet point that wraps onto a continuation line" in html_out
        assert html_out.count("<li>") == 2

    def test_missing_file_returns_empty_list_not_raises(self, tmp_path):
        assert parse_changelog(path=tmp_path / "does_not_exist.md") == []

    def test_default_path_reads_the_real_project_changelog(self):
        """No path override — confirms the default resolves to the
        actual CHANGELOG.md shipped with this codebase, not nothing."""
        releases = parse_changelog(limit=1)
        assert len(releases) == 1
        assert releases[0]["version"]
        assert releases[0]["date"]

    def test_html_injection_in_changelog_entry_is_neutralized(self, tmp_path):
        """Defense in depth: even though this is our own trusted file,
        confirm a stray '<script>' or unescaped '&' in an entry can't
        produce a live tag in the rendered output."""
        content = """# Changelog

## [1.0.0] - 2026-01-01

- Fixed handling of `<script>alert(1)</script>` in user input & similar
"""
        path = self._write_changelog(tmp_path, content)
        releases = parse_changelog(path=path)
        html_out = releases[0]["html"]
        assert "<script>alert(1)</script>" not in html_out
        assert "&lt;script&gt;" in html_out


class TestAboutPageChangelogSection:
    """No existing test coverage exercised /about at all before this
    feature — added here alongside the parser it depends on, rather
    than assuming the route works just because the parser's unit tests
    pass in isolation."""

    def test_about_page_loads_with_changelog_section(self, logged_in_client):
        resp = logged_in_client.get("/about")
        assert resp.status_code == 200
        assert b"What" in resp.data and b"New" in resp.data

    def test_about_page_renders_real_html_not_escaped_markup(self, logged_in_client):
        """Confirms the |safe usage in the template is actually
        rendering real tags from the changelog's HTML, not double-
        escaping them into visible '&lt;h4&gt;'-style text."""
        resp = logged_in_client.get("/about")
        assert b"&lt;h4&gt;" not in resp.data
        assert b"&lt;strong&gt;" not in resp.data
