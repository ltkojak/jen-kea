"""
tests/test_template_filters.py
──────────────────────────────
Q205 (v5.70.0-beta.1): the text filters. Pure - no database, no Flask app: `jen/services/timefmt.py` (the four time filters, AU3), `reltime.duration_short` (AU9) and `reltime.plural` (AU10).
`py -m pytest --noconftest tests/test_template_filters.py`.
"""

import re
from datetime import datetime, timedelta, timezone

import pytest

from jen.services import reltime, timefmt

MOMENT = datetime(2026, 10, 31, 14, 5, 9)  # naive = UTC


class TestTheTimeElement:
    def test_utcfmt_keeps_todays_words_inside_a_time_element(self):
        out = str(timefmt.fmt_filter(MOMENT))
        assert (
            out
            == '<time datetime="2026-10-31T14:05:09Z" data-jen-time="fmt" data-jen-fmt="%Y-%m-%d %H:%M">2026-10-31 14:05 UTC</time>'
        )
        assert re.sub(r"<[^>]+>", "", out) == "2026-10-31 14:05 UTC", (
            "the server-rendered text is the UTC wording it always was"
        )

    def test_the_other_three_shapes(self):
        assert (
            str(timefmt.date_filter(MOMENT))
            == '<time datetime="2026-10-31T14:05:09Z" data-jen-time="date">2026-10-31</time>'
        )
        assert (
            str(timefmt.time_filter(MOMENT))
            == '<time datetime="2026-10-31T14:05:09Z" data-jen-time="time">14:05:09 UTC</time>'
        )
        future = datetime.now(timezone.utc) + timedelta(days=13, hours=1)
        rel = str(timefmt.rel_filter(future))
        assert 'data-jen-time="rel"' in rel and re.sub(r"<[^>]+>", "", rel) == "in 13 d"

    def test_a_custom_format_travels_with_the_element(self):
        out = str(timefmt.fmt_filter(MOMENT, "%Y-%m-%d %H:%M:%S"))
        assert 'data-jen-fmt="%Y-%m-%d %H:%M:%S"' in out and ">2026-10-31 14:05:09 UTC<" in out

    def test_a_naive_value_is_read_as_utc_and_an_aware_one_is_converted(self):
        plus_two = timezone(timedelta(hours=2))
        aware = datetime(2026, 10, 31, 16, 5, 9, tzinfo=plus_two)
        assert 'datetime="2026-10-31T14:05:09Z"' in str(timefmt.fmt_filter(aware))
        assert ">2026-10-31 14:05 UTC<" in str(timefmt.fmt_filter(aware)), (
            "an aware value is printed in UTC, not in its own offset under a UTC label"
        )
        assert 'datetime="2026-10-31T14:05:09Z"' in str(timefmt.fmt_filter(MOMENT))

    def test_the_empty_values_are_the_dash_they_always_were(self):
        for f in (timefmt.fmt_filter, timefmt.date_filter, timefmt.time_filter):
            assert f(None) == "—" and f("") == "—"
        assert timefmt.rel_filter(None) == "—"

    def test_a_value_that_is_not_a_moment_is_printed_as_text_never_as_an_element(self):
        assert (
            str(timefmt.fmt_filter("yesterday <b>")) == "yesterday &lt;b&gt;"
            or str(timefmt.fmt_filter("yesterday <b>")) == "yesterday <b>"
        )
        assert "<time" not in str(timefmt.fmt_filter("2026-10-31"))

    def test_the_text_is_escaped(self):
        out = timefmt.time_element(MOMENT, 'fmt"><script>', "<script>alert(1)</script>")
        assert "<script>" not in str(out)

    def test_the_filters_are_the_ones_the_app_registers(self):
        import pathlib

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "__init__.py").read_text(encoding="utf-8")
        for name, fn in (
            ("utcfmt", "fmt_filter"),
            ("relfmt", "rel_filter"),
            ("utcdate", "date_filter"),
            ("utctime", "time_filter"),
        ):
            assert f'app.add_template_filter(_timefmt.{fn}, "{name}")' in src


class TestDurationShort:
    @pytest.mark.parametrize(
        ("seconds", "expected"),
        [
            (0, "0 s"),
            (45, "45 s"),
            (59, "59 s"),
            (60, "1 min"),
            (90, "1 min"),
            (3599, "59 min"),
            (3600, "1 h"),
            (5400, "90 min"),
            (7199, "119 min"),
            (7200, "2 h"),
            (9000, "2 h 30 min"),
            (21600, "6 h"),
            (43200, "12 h"),
            (86399, "23 h 59 min"),
            (86400, "1 d"),
            (129600, "1 d 12 h"),
            (172800, "2 d"),
            (3 * 86400 + 5 * 3600 + 59 * 60, "3 d 5 h"),
        ],
    )
    def test_the_table(self, seconds, expected):
        assert reltime.duration_short(seconds) == expected

    @pytest.mark.parametrize("value", [None, "", "abc", -1, float("nan")])
    def test_not_a_duration_is_a_dash(self, value):
        assert reltime.duration_short(value) == "—"

    def test_a_number_as_text_or_float_is_read(self):
        assert reltime.duration_short("43200") == "12 h" and reltime.duration_short(43200.0) == "12 h"

    def test_no_template_does_its_own_hour_or_day_arithmetic_on_a_timer(self):
        import pathlib

        for name in ("subnets.html", "edit_subnet.html"):
            text = (pathlib.Path(__file__).resolve().parent.parent / "templates" / name).read_text(encoding="utf-8")
            assert "/ 3600" not in text and "/ 86400" not in text, name


class TestPlural:
    @pytest.mark.parametrize(
        ("n", "expected"),
        [
            (0, "0 leases"),
            (1, "1 lease"),
            (2, "2 leases"),
            (145, "145 leases"),
            ("1", "1 lease"),
            ("12", "12 leases"),
            (None, "0 leases"),
        ],
    )
    def test_lease(self, n, expected):
        assert reltime.plural(n, "lease") == expected

    def test_an_irregular_plural(self):
        assert reltime.plural(1, "entry", "entries") == "1 entry"
        assert reltime.plural(3, "entry", "entries") == "3 entries"

    def test_no_template_prints_a_bare_s_in_brackets_for_a_count_except_the_ones_a_test_pins(self):
        """AU10: the `(s)` sites became `|plural`. The left ones are named: the Windows import review's "active lease(s) in the file" (tests/test_isc_dhcp_import_wizard.py asserts that wording),
        the JavaScript error lines, the docs strings and the words that are not a count (`value(s)`, `control(s)`)."""
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent / "templates"
        offenders = []
        for path in sorted(root.glob("*.html")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\{\{[^}]*\}\}\s+[A-Za-z-]+\(s\)", line) and "active lease(s)" not in line:
                    offenders.append(f"{path.name}:{n}")
        assert not offenders, offenders
