"""
jen/services/changelog.py
────────────────────────────
v5.2.1 — in-app "What's New" viewer. Jen has always maintained a
genuinely good CHANGELOG.md, but nothing surfaced it in the app
itself — after an update there was no "here's what changed" anywhere
in the UI, which matters most for anyone other than whoever just did
the deploy (a future admin, or future-you six months from now).

This module reads and parses the ACTUAL CHANGELOG.md file shipped with
the running instance, rather than any separately-maintained or
hardcoded copy — the same "don't let two sources of truth drift apart"
principle behind config drift detection (v5.2.0) itself. Whatever this
shows always matches what's actually deployed.

Deliberately does NOT pull in a general markdown library. This parses
CHANGELOG.md specifically — a file with a small, consistent format we
fully control (release headers, subheadings, prose paragraphs, simple
bullet lists with **bold**, `code`, and [links](url)) — not arbitrary
third-party markdown. A general-purpose parser would be a new
dependency and a larger, harder-to-audit HTML-output surface for a
task this constrained. All text content is HTML-escaped before any
formatting markup is reintroduced, so nothing in the source file can
produce a live tag other than the ones this module deliberately adds.
"""

import html
import pathlib
import re

_RELEASE_HEADER_RE = re.compile(r"^## \[([^\]]+)\]\s*-\s*(.+)$")
_SUBHEADING_RE = re.compile(r"^### (.+)$")
_BULLET_RE = re.compile(r"^-\s+(.*)$")
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC_RE = re.compile(r"\*([^*]+)\*")
_CODE_RE = re.compile(r"`([^`]+)`")


def _inline_markdown_to_html(text: str) -> str:
    """Escape raw text first, then reintroduce only the specific inline
    constructs this changelog actually uses. Order matters: links
    before bold before italic, so an escaped bracket inside link text
    can't be mistaken for another pattern, and bold's ** is fully
    consumed before the italic pass looks for lone *."""
    escaped = html.escape(text, quote=False)
    escaped = _LINK_RE.sub(
        lambda m: (
            f'<a href="{html.escape(m.group(2), quote=True)}" '
            f'target="_blank" rel="noopener">{m.group(1)}</a>'
        ),
        escaped,
    )
    escaped = _BOLD_RE.sub(r"<strong>\1</strong>", escaped)
    escaped = _ITALIC_RE.sub(r"<em>\1</em>", escaped)
    escaped = _CODE_RE.sub(r"<code>\1</code>", escaped)
    return escaped


def _render_body(lines: list) -> str:
    """Convert one release's raw markdown body lines (subheadings,
    prose paragraphs, bullet lists, and their continuation lines) into
    a single HTML string."""
    parts = []
    bullets = []
    paragraph = []

    def flush_bullets():
        if bullets:
            items = "".join(f"<li>{_inline_markdown_to_html(b)}</li>" for b in bullets)
            parts.append(f"<ul>{items}</ul>")
            bullets.clear()

    def flush_paragraph():
        if paragraph:
            joined = " ".join(paragraph).strip()
            if joined:
                parts.append(f"<p>{_inline_markdown_to_html(joined)}</p>")
            paragraph.clear()

    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            flush_bullets()
            flush_paragraph()
            continue
        sub = _SUBHEADING_RE.match(line)
        if sub:
            flush_bullets()
            flush_paragraph()
            parts.append(f"<h4>{_inline_markdown_to_html(sub.group(1))}</h4>")
            continue
        bullet = _BULLET_RE.match(line)
        if bullet:
            flush_paragraph()
            bullets.append(bullet.group(1))
            continue
        # A continuation line (wrapped/indented text belonging to the
        # previous bullet or paragraph) — append to whichever buffer is
        # currently open rather than starting a new block.
        stripped = line.strip()
        if bullets:
            bullets[-1] = bullets[-1] + " " + stripped
        else:
            paragraph.append(stripped)

    flush_bullets()
    flush_paragraph()
    return "".join(parts)


def _version_sort_key(version: str) -> tuple:
    """
    Convert a version string like "5.2.2" into a tuple of ints for
    correct numeric sorting — plain string comparison gets this wrong
    (e.g. "5.2.10" sorts before "5.2.9" lexically, since "1" < "9").
    Falls back to (0,) for anything that doesn't parse as dot-separated
    integers (a stray non-numeric suffix, or an entirely malformed
    version string), so one bad entry can't crash sorting for the rest
    of the changelog — it just sorts as the oldest/lowest-priority
    entry instead.
    """
    parts = []
    for piece in version.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) if parts else (0,)


def parse_changelog(path=None, limit=None) -> list:
    """
    Parse CHANGELOG.md into a list of release entries, each a dict with
    "version", "date", and "html" (pre-rendered, already-safe HTML
    body). Reads the real file at the repo root by default. Entries are
    sorted newest-first by parsed semantic version.

    v5.2.3 — this used to trust the order release headers physically
    appear in the file (parsing top to bottom, stopping early once
    `limit` entries were found), on the assumption the file is always
    maintained newest-entry-first. That assumption broke in practice:
    reported as "What's New" showing old entries (a 3.x-series release)
    as if they were the newest, on the real deployed CHANGELOG.md —
    which has genuine multi-year history well before this feature
    existed (the file's own intro line references a separate "3.x
    line" with its own release-history docs this module has never had
    visibility into). Every test file used to verify this module's own
    logic behaved correctly, because trusting file order is only wrong
    if the file itself isn't strictly ordered that way — which
    apparently the real one, somewhere in its older history, isn't.

    Rather than track down the exact formatting quirk responsible in a
    file this module can't fully see, entries are now explicitly
    sorted by parsed version (see _version_sort_key) after parsing,
    instead of trusting file order at all. This is strictly more
    correct regardless of the file's actual order, and doesn't depend
    on ever fully explaining the original discrepancy. The tradeoff:
    this now always parses the entire file rather than stopping early
    once `limit` entries are found, since the correct newest entries
    can no longer be assumed to be the first ones encountered. A
    changelog is plain text, even a long one — this cost is
    negligible compared to the correctness it buys.

    limit: if given, only the `limit` most recent releases (by
    version, after sorting) are returned.

    Returns [] if the file can't be read for any reason — this is
    display-only content, never something that should break a page
    load if the file happens to be missing or unreadable.
    """
    if path is None:
        path = pathlib.Path(__file__).resolve().parent.parent.parent / "CHANGELOG.md"
    else:
        path = pathlib.Path(path)

    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return []

    releases = []
    current = None
    body_lines = []

    def flush():
        if current is not None:
            current["html"] = _render_body(body_lines)
            releases.append(current)

    for line in text.splitlines():
        m = _RELEASE_HEADER_RE.match(line)
        if m:
            flush()
            current = {"version": m.group(1), "date": m.group(2).strip()}
            body_lines = []
            continue
        if current is not None:
            body_lines.append(line)
    else:
        flush()

    releases.sort(key=lambda r: _version_sort_key(r["version"]), reverse=True)

    if limit is not None:
        releases = releases[:limit]

    return releases
