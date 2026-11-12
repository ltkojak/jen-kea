"""
jen/services/timefmt.py
───────────────────────
v5.70.0-beta.1 (Q205, AU3) - every timestamp Jen prints is UTC TEXT, and now also a `<time>` element: the text stays UTC (a page without JavaScript, every existing test and the phone
column keep today's words), the element carries the machine-readable moment (`datetime="2026-10-31T14:05:00Z"`) and its kind (`data-jen-time="fmt|date|time|rel"`), and ONE nonce'd rewriter
in base.html shows it in the browser's zone when the reader's per-browser pick (`jen-time-pick`, beside the theme pick) is `local`. The four Jinja filters (`utcfmt`, `utcdate`, `utctime`,
`relfmt`) are thin callers of `time_element`. A value that is not a moment (a string, None) is printed as it always was; a naive datetime is read as UTC (Kea's and Jen's own clock).
"""

import contextlib
from datetime import datetime, timezone

from markupsafe import Markup, escape


def as_utc(value):
    """`value` as an aware UTC datetime, or None when it is not a datetime. A naive value IS UTC."""
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def iso_utc(value) -> str | None:
    moment = as_utc(value)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ") if moment else None


def time_element(value, kind: str, text: str, fmt: str | None = None) -> Markup:
    """`<time datetime=ISO data-jen-time=kind [data-jen-fmt=fmt]>text</time>`; `text` is the UTC wording and is escaped. Not a datetime: just the (escaped) text."""
    iso = iso_utc(value)
    if iso is None:
        return Markup(escape(text))
    extra = f' data-jen-fmt="{escape(fmt)}"' if fmt else ""
    return Markup(f'<time datetime="{iso}" data-jen-time="{escape(kind)}"{extra}>{escape(text)}</time>')


def fmt_filter(value, fmt="%Y-%m-%d %H:%M"):
    if not value:
        return "—"
    moment = as_utc(value)
    try:
        text = (moment or value).strftime(fmt) + " UTC"
    except Exception:
        return str(value)
    return time_element(value, "fmt", text, fmt)


def iso_filter(value, fmt="%Y-%m-%d %H:%M"):
    """`utcfmt` for a moment that was STORED as ISO-8601 text (Q230, AP11): a settings record keeps `2026-11-12T14:05:24+00:00`, `as_utc` answers None for a string, and `utcfmt`
    printed the text back unchanged - no UTC wording and no `<time>` element for the reader's zone. The text is parsed first (an offset or a `Z`; none is read as UTC); text
    that is not a moment is printed as it is."""
    if isinstance(value, str):
        text = value.strip()
        # text that is not a moment stays text: `fmt_filter` prints it as it always did (the text itself, or a dash for nothing)
        with contextlib.suppress(ValueError):
            value = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text)
    return fmt_filter(value, fmt)


def date_filter(value):
    if not value:
        return "—"
    moment = as_utc(value)
    try:
        text = (moment or value).strftime("%Y-%m-%d")
    except Exception:
        return str(value)
    return time_element(value, "date", text)


def time_filter(value):
    if not value:
        return "—"
    moment = as_utc(value)
    try:
        text = (moment or value).strftime("%H:%M:%S") + " UTC"
    except Exception:
        return str(value)
    return time_element(value, "time", text)


def rel_filter(value):
    from jen.services.reltime import relative_time

    text = relative_time(value)
    if not isinstance(value, datetime) or not value:
        return text
    return time_element(value, "rel", text)


__all__ = ["as_utc", "iso_utc", "time_element", "fmt_filter", "iso_filter", "date_filter", "time_filter", "rel_filter"]
