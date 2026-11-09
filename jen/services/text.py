"""
jen/services/text.py
────────────────────
Text helpers for templates (v5.70.0-beta.4, Q208 AX6).
"""

import re

from markupsafe import Markup, escape

#: ASCII digits only, up to eighteen (Q224, AJ16). `str.isdigit()` is True for a full-width or an Arabic-Indic digit, and `int()` then raises on it (a 500 from a form) or, in a
#: comprehension that filters with `isdigit()` and converts with `int()`, drops the whole selection on the floor. THE whole-number test for every form value and every path segment under
#: `jen/`; `tests/test_a_rollback_is_refused_before_its_set.py::TestOneWholeNumberTest` refuses an `isdigit()` anywhere under `jen/` (the plugins are their own repositories; Q225, AK9).
WHOLE_NUMBER = re.compile(r"[0-9]{1,18}")


def is_whole(text) -> bool:
    """Is `text` a str of ASCII digits - a whole number `int()` reads as written? False for a bool, a non-str, "", a sign, a space, a point, a full-width digit, or nineteen digits or more."""
    return isinstance(text, str) and WHOLE_NUMBER.fullmatch(text) is not None


def whole(text, default=None):
    """`int(text)` when `is_whole(text)`, else `default`."""
    return int(text) if is_whole(text) else default


def mark_match(text, q) -> Markup:
    """`text` with every case-insensitive occurrence of `q` wrapped in `<mark>` - the `|mark` filter.

    ESCAPING COMES FIRST: both `text` and `q` are escaped, and the search is made in the escaped strings, so the only markup in the result is the `<mark>` this function writes. A hostname
    or a MAC is client-supplied; a client that names itself `<mark>` or `</td>` is printed as that text and breaks nothing. An empty or missing `q` marks nothing. (A `q` such as `amp`
    can match inside an entity the escaping wrote - `&amp;` - and would split it; the match is made on whole characters of the ORIGINAL text instead, below, and each piece is escaped
    on its own.)
    """
    if text is None:
        return Markup("")
    s = str(text)
    needle = str(q) if q is not None else ""
    if not needle:
        return Markup(escape(s))  # nosec B704 - escape() output
    out = []
    last = 0
    for m in re.finditer(re.escape(needle), s, re.IGNORECASE):
        out.append(str(escape(s[last : m.start()])))
        out.append("<mark>" + str(escape(m.group(0))) + "</mark>")
        last = m.end()
    out.append(str(escape(s[last:])))
    return Markup("".join(out))  # nosec B704 - every piece in `out` is escape()d above, the only markup is the <mark> written here
