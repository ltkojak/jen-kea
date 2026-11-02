"""
jen/services/text.py
────────────────────
Text helpers for templates (v5.70.0-beta.4, Q208 AX6).
"""

import re

from markupsafe import Markup, escape


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
