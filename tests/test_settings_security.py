"""
tests/test_settings_security.py
───────────────────────────────
Q215 (Z18): Settings -> Access & Security shows the idle timeout the server APPLIES, not the stored text.

A hand-edited `session_timeout_minutes` row that is not a whole number of minutes in 0..1440 is read as 60 by the one reader (`session_timeout._global_minutes`, which logs it once). The form printed the
raw text, so it said `x` (or `99999`) while every session ran on 60 - and saving it back changed nothing the person could see.
"""

import re

import pytest

from tests.test_session_notice import _timeout_set


def _box(html):
    m = re.search(r'<input id="f-timeout_minutes"[^>]*\bvalue="([^"]*)"', html)
    assert m, "the timeout box is on the page"
    return m.group(1)


class TestTheFormShowsTheMinutesTheServerUses:
    @pytest.mark.parametrize(
        ("stored", "shown"),
        [
            ("45", "45"),
            ("0", "0"),  # never expire is a value, not a missing one
            ("00005", "5"),  # the reader takes zero-padded text as 5
            ("x", "60"),
            ("60.5", "60"),
            ("99999", "60"),
            ("-5", "60"),
            ("", "60"),
        ],
    )
    def test_the_form_shows_the_minutes_the_server_uses(self, logged_in_client, stored, shown):
        with _timeout_set(session_timeout_minutes=stored):
            html = logged_in_client.get("/settings/security").data.decode()
        assert _box(html) == shown, (stored, _box(html))
