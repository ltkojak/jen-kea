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

# Q248 (V33) - what the About page leaves out of "What's New". The file's entries cite the rows of the reviews and passes they answer ("(BG1, BG6, BG7)", "(U5 to U15)",
# "(WOL-1 to WOL-4)", "(DEF-003)") and close with a paragraph of rows that were registered and not changed. A person reading About cannot look any of them up. The file
# is not edited: `whats_new()` leaves these out of what it renders, and `parse_changelog()` renders the file as it is.
#   a code:   one to six capitals, an optional hyphen, one to four digits ("U1", "BG27", "WOL-16", "DEF-003"). "RFC 5280" has a space, "v5.65.10" and "7.2.0-beta.4"
#             start otherwise, "Ubuntu 22.04" has small letters: none of them is one.
#   a group:  a pair of parentheses that holds at least one code. It goes WHOLE, words and all ("(V12, V13; additions 4, 5)", "(BG3; BG5 written down)"), with the
#             space before it (Q249, BI5: Q248 dropped a group only when it held codes and nothing else, and seventeen codes stayed behind "More"). A pair with no
#             code in it is kept.
#   kept:     names that only look like a code (a hash, a cipher, a curve, a protocol version, Kea's D2 daemon).
_TRACKING_CODE = r"[A-Z]{1,6}-?\d{1,4}"
_TRACKING_GROUP_RE = re.compile(r"[ \t]*\(([^()]*)\)")
_TRACKING_TOKEN_RE = re.compile(rf"(?<![A-Za-z0-9.-]){_TRACKING_CODE}(?![A-Za-z0-9]|[.-][A-Za-z0-9])")
_NOT_A_CODE_PREFIX = frozenset(
    {
        "RFC",
        "SHA",
        "MD",
        "AES",
        "RSA",
        "RS",
        "ES",
        "HS",
        "PS",
        "UTF",
        "HTTP",
        "TLS",
        "SSL",
        "IPV",
        "X",
        "CVE",
        "ISO",
        "HMAC",
    }
)
_NOT_A_CODE = frozenset({"D2", "P-256", "P-384", "P-521", "P256", "P384", "P521"})
_REGISTERED_RE = re.compile(r"^[\s*_]*Registered\b")


def _is_tracking_code(token: str) -> bool:
    return token not in _NOT_A_CODE and re.match(r"[A-Z]+", token).group(0) not in _NOT_A_CODE_PREFIX


def strip_tracking_codes(text: str) -> str:
    """`text` without the parenthesized groups that hold a tracking code (Q248, V33; Q249, BI5: the whole group, whatever else it holds). Everything else is
    returned as it was."""

    def _drop(m):
        tokens = _TRACKING_TOKEN_RE.findall(m.group(1))
        return "" if any(_is_tracking_code(t) for t in tokens) else m.group(0)

    return _TRACKING_GROUP_RE.sub(_drop, text)


def _inline_markdown_to_html(text: str) -> str:
    """Escape raw text first, then reintroduce only the specific inline
    constructs this changelog actually uses. Order matters: links
    before bold before italic, so an escaped bracket inside link text
    can't be mistaken for another pattern, and bold's ** is fully
    consumed before the italic pass looks for lone *."""
    escaped = html.escape(text, quote=False)
    escaped = _LINK_RE.sub(
        lambda m: f'<a href="{html.escape(m.group(2), quote=True)}" target="_blank" rel="noopener">{m.group(1)}</a>',
        escaped,
    )
    escaped = _BOLD_RE.sub(r"<strong>\1</strong>", escaped)
    escaped = _ITALIC_RE.sub(r"<em>\1</em>", escaped)
    escaped = _CODE_RE.sub(r"<code>\1</code>", escaped)
    return escaped


def _render_parts(lines: list, for_reading: bool = False) -> list:
    """One release's raw markdown body lines (subheadings, prose paragraphs,
    bullet lists, and their continuation lines) as a list of HTML blocks, in
    order: `<h4>`, `<p>` and `<ul>` strings.

    `for_reading` (Q248, V33) is the About page's reading of the same lines:
    a group of tracking codes is left out of every block (`strip_tracking_codes`),
    a paragraph that begins "Registered" is left out whole, and so is the section
    under a subheading that begins "Registered" (up to the next subheading)."""
    parts = []
    bullets = []
    paragraph = []
    clean = strip_tracking_codes if for_reading else (lambda text: text)
    skipping_section = False

    def flush_bullets():
        if bullets:
            if not skipping_section:
                items = "".join(f"<li>{_inline_markdown_to_html(clean(b))}</li>" for b in bullets)
                parts.append(f"<ul>{items}</ul>")
            bullets.clear()

    def flush_paragraph():
        if paragraph:
            joined = " ".join(paragraph).strip()
            registered = for_reading and _REGISTERED_RE.match(joined)
            if joined and not skipping_section and not registered:
                parts.append(f"<p>{_inline_markdown_to_html(clean(joined).strip())}</p>")
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
            skipping_section = bool(for_reading and _REGISTERED_RE.match(sub.group(1)))
            if not skipping_section:
                parts.append(f"<h4>{_inline_markdown_to_html(clean(sub.group(1)))}</h4>")
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
    return parts


def _render_body(lines: list) -> str:
    """One release's body as a single HTML string, the file as it is."""
    return "".join(_render_parts(lines))


def _version_sort_key(version: str) -> tuple:
    """Numeric sort key for a changelog heading's version — plain string
    comparison gets "5.2.10" < "5.2.9" wrong. v5.32.0 (Q38): the one
    parser in jen/version.py, so a beta heading (5.32.0-beta.1) sorts
    below its final release and above the previous stable; anything
    unparsable sorts lowest instead of crashing the listing."""
    from jen.version import parse_version

    return parse_version(version)


def parse_changelog(path=None, limit=None, for_reading=False) -> list:
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
            parts = _render_parts(body_lines, for_reading)
            current["html"] = "".join(parts)
            if for_reading:
                # Q248 (addition 15): the lead is the entry's first paragraph, the sentence that says what the release is; `rest` is everything after it
                lead = parts[0] if parts and parts[0].startswith("<p>") else ""
                current["lead"] = lead
                current["rest"] = "".join(parts[1:] if lead else parts)
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


def whats_new(limit=5, path=None) -> list:
    """The newest `limit` releases as the About page shows them (Q248, addition 15 and V33): `parse_changelog`'s entries read `for_reading` - no group of tracking
    codes, no "Registered" paragraph or section - and each with two more keys, `lead` (its first paragraph, as HTML) and `rest` (the HTML after it). The page shows
    the newest entry's lead and puts the rest, and the older entries, behind one closed "More"."""
    return parse_changelog(path=path, limit=limit, for_reading=True)
