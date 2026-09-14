"""
jen/services/csv_safe.py
────────────────────────
v5.30.0 (Q30, A3) — CSV formula-injection guard, shared by Jen's own
exports (reservations) and the plugins' (IPAM, Network Discovery).

A spreadsheet opens a CSV cell that starts with `=`, `+`, `-` or `@` as a
formula (and a leading tab / carriage return can smuggle one past the
first-character check). Every exported cell here carries operator- or
device-supplied text — a DHCP hostname, an IPAM label, a note — so a
hostname of `=HYPERLINK(...)` or `=cmd|' /C calc'!A0` would execute on
the operator's machine when they open Jen's export. The fix is the
standard one: prefix such a cell with a single quote so the spreadsheet
treats it as text. Numbers that legitimately start with `-` become
`'-5`; nothing Jen exports is a signed number, and a quote is the
documented, reversible escape.
"""

_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value) -> str:
    """The cell's text, prefixed with `'` when a spreadsheet would
    otherwise evaluate it. None becomes ""."""
    if value is None:
        return ""
    text = str(value)
    return f"'{text}" if text and text[0] in _FORMULA_LEADERS else text


def safe_row(values) -> list[str]:
    return [safe_cell(v) for v in values]
