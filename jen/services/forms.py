"""
jen/services/forms.py
─────────────────────
A validation error printed under its field (v5.70.0-beta.4, Q208 AX4).

Every Jen route that refuses a form answers with `flash(message, "error")` and a redirect. `flash_field(field, message)` is the same thing for an error that names ONE field: the
message is kept in `session["field_errors"]` as `[field, message, form_path]`, `base.html` prints each as an alert carrying `data-field` and `data-form`, and one script moves it under
the input whose id is `f-<field>` (and ties it to the input with `aria-invalid` and `aria-describedby`) on the page the form was on. With scripts off, on any other page, or when the page
has no such input, it is an ordinary flash - the message is never lost. The field name reaches an `id` attribute, so it is validated here against a strict pattern and a name that fails it
is flashed, never stored.

v5.70.0-beta.5 (Q210, AZ5): the item carries `form_path` (the path of the page the form was on: the Referer's, when it is this site's) so an error raised for one form is never moved under
an input of a page it was not raised for - fifteen `f-<name>` ids are shared between pages; and the list is held to a BYTE budget as well as a count, because it travels in the signed
session cookie (4,093 bytes in all) and 16 incompressible 300-character messages passed that. A list beta.4 wrote (two-element items) is still read.
"""

import json
import re
from urllib.parse import urlsplit

from flask import flash, g, request, session

#: the characters an `id="f-<name>"` in Jen's templates uses (letters, digits, underscore, hyphen, brackets for `name[]` lists); anything else is not a field name
FIELD_NAME = re.compile(r"[a-z0-9_\-\[\]]{1,64}")
#: how many errors one redirect can carry (the session is a cookie: a handful of messages, never a list that grows without bound)
MAX_FIELD_ERRORS = 20
#: a message longer than this is cut (the cookie has a size limit and a message is a sentence, not a dump)
MAX_MESSAGE = 300
#: the serialized list may not pass this many bytes whatever the count: the session cookie is 4,093 bytes in all and carries the login too; what does not fit is flashed instead
MAX_FIELD_BYTES = 2000
#: a form path longer than this is not stored as one (it is "", the any-page reading)
MAX_FORM_PATH = 200


def _form_path() -> str:
    """The path of the page the form was on: the Referer's path when the Referer is this site's, else "" (unknown - the error may land on any page, as it did in beta.4)."""
    try:
        ref = urlsplit(request.referrer or "")
        if (
            ref.netloc
            and ref.netloc == request.host
            and ref.path.startswith("/")
            and not ref.path.startswith("//")
            and len(ref.path) <= MAX_FORM_PATH
        ):
            return ref.path
    except ValueError:
        pass
    return ""


def flash_field(field: str, message: str) -> None:
    """Record `message` against the input `f-<field>`, or flash it when `field` is not a valid name or the list is full (by count or by bytes)."""
    text = str(message)[:MAX_MESSAGE]
    if not isinstance(field, str) or not FIELD_NAME.fullmatch(field):
        flash(text, "error")
        return
    errors = session.get("field_errors")
    if not isinstance(errors, list):
        errors = []
    item = [field, text, _form_path()]
    if len(errors) >= MAX_FIELD_ERRORS or len(json.dumps(errors + [item])) > MAX_FIELD_BYTES:
        flash(text, "error")
        return
    errors.append(item)
    session["field_errors"] = errors


def take_field_errors() -> list:
    """The pending field errors as `(field, message, form_path)` triples, removed from the session. Called by the flash block of `base.html` and by the standalone pages that print their
    own (login, the forced password change, the second factor): a second call in the same request gets the same list (a page that renders its layout twice must not lose them), and a
    partial that never renders the block leaves them for the next full page. A two-element item (what beta.4 wrote) reads as `form_path == ""`."""
    cached = getattr(g, "_field_errors", None)
    if cached is not None:
        return cached
    raw = session.pop("field_errors", None)
    out = []
    if isinstance(raw, list):
        for item in raw:
            if (
                isinstance(item, (list, tuple))
                and len(item) in (2, 3)
                and isinstance(item[0], str)
                and isinstance(item[1], str)
                and FIELD_NAME.fullmatch(item[0])
                and (len(item) == 2 or isinstance(item[2], str))
            ):
                out.append((item[0], item[1], item[2] if len(item) == 3 else ""))
    g._field_errors = out
    return out
