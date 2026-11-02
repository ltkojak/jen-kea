"""
jen/services/forms.py
─────────────────────
A validation error printed under its field (v5.70.0-beta.4, Q208 AX4).

Every Jen route that refuses a form answers with `flash(message, "error")` and a redirect. `flash_field(field, message)` is the same thing for an error that names ONE field: the
message is kept in `session["field_errors"]` as `[field, message]`, `base.html` prints each as an alert carrying `data-field`, and one script moves it under the input whose id is
`f-<field>` (and ties it to the input with `aria-invalid` and `aria-describedby`). With scripts off, or when the page has no such input, it is an ordinary flash - the message is
never lost. The field name reaches an `id` attribute, so it is validated here against a strict pattern and a name that fails it is flashed, never stored.
"""

import re

from flask import flash, g, session

#: the characters an `id="f-<name>"` in Jen's templates uses (letters, digits, underscore, hyphen, brackets for `name[]` lists); anything else is not a field name
FIELD_NAME = re.compile(r"[a-z0-9_\-\[\]]{1,64}")
#: how many errors one redirect can carry (the session is a cookie: a handful of messages, never a list that grows without bound)
MAX_FIELD_ERRORS = 20
#: a message longer than this is cut (the cookie has a size limit and a message is a sentence, not a dump)
MAX_MESSAGE = 300


def flash_field(field: str, message: str) -> None:
    """Record `message` against the input `f-<field>`, or flash it when `field` is not a valid name or the list is full."""
    text = str(message)[:MAX_MESSAGE]
    if not isinstance(field, str) or not FIELD_NAME.fullmatch(field):
        flash(text, "error")
        return
    errors = session.get("field_errors")
    if not isinstance(errors, list):
        errors = []
    if len(errors) >= MAX_FIELD_ERRORS:
        flash(text, "error")
        return
    errors.append([field, text])
    session["field_errors"] = errors


def take_field_errors() -> list:
    """The pending field errors as `(field, message)` pairs, removed from the session. Called by the flash block of `base.html`; a second call in the same request gets the same list
    (a page that renders its layout twice must not lose them), and a partial that never renders the block leaves them for the next full page."""
    cached = getattr(g, "_field_errors", None)
    if cached is not None:
        return cached
    raw = session.pop("field_errors", None)
    out = []
    if isinstance(raw, list):
        for item in raw:
            if (
                isinstance(item, (list, tuple))
                and len(item) == 2
                and isinstance(item[0], str)
                and isinstance(item[1], str)
                and FIELD_NAME.fullmatch(item[0])
            ):
                out.append((item[0], item[1]))
    g._field_errors = out
    return out
