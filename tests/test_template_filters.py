"""
tests/test_template_filters.py
──────────────────────────────
Q205 (v5.70.0-beta.1): the text filters. Pure - no database, no Flask app: `jen/services/timefmt.py` (the four time filters, AU3), `reltime.duration_short` (AU9) and `reltime.plural` (AU10).
`py -m pytest --noconftest tests/test_template_filters.py`.
"""

import pathlib
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
            (3659, "1 h"),  # (SP: 60 whole minutes is an hour, not "60 min")
            (3660, "61 min"),
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


class TestNumber:
    """Q208 (AX5): a count carries thousands separators, always the US grouping."""

    @pytest.mark.parametrize(
        ("n", "expected"),
        [
            (1234567, "1,234,567"),
            (999, "999"),
            (1000, "1,000"),
            (0, "0"),
            ("12000", "12,000"),
            (None, "0"),
            ("x", "0"),
            (3.9, "3"),
            (-1234, "-1,234"),
        ],
    )
    def test_number(self, n, expected):
        assert reltime.number(n) == expected

    def test_an_infinite_float_reads_as_zero_not_as_a_500(self):
        """Q210 (AZ7, Y12): `int(float("inf"))` raises OverflowError, which neither coercion caught. No template can produce one today (every count is a COUNT(*), a len() or a settings integer), so this is a line."""
        assert (
            reltime.number(float("inf")) == "0"
            and reltime.number(float("-inf")) == "0"
            and reltime.number(float("nan")) == "0"
        )

    def test_plural_survives_an_infinite_float_too(self):
        assert reltime.plural(float("inf"), "lease") == "0 leases"
        assert reltime.plural(float("inf"), "entry", "entries") == "0 entries"

    def test_plural_groups_the_count_and_still_agrees(self):
        assert reltime.plural(12000, "lease") == "12,000 leases"
        assert reltime.plural(1000, "entry", "entries") == "1,000 entries"
        assert reltime.plural(1, "lease") == "1 lease"

    def test_the_filter_is_registered_beside_plural(self):
        import pathlib

        text = pathlib.Path("jen/__init__.py").read_text(encoding="utf-8")
        assert '_reltime.number, "number"' in text and '_reltime.plural, "plural"' in text


class TestNoBareCountInATemplate:
    """The grep of the item: every `{{ ... }}` whose expression names a count, a total, an active/free/used/size or the leases goes through `|number` or `|plural`. The ones that do not are
    reviewed here WITH their reason - an id, a timestamp, a percentage, a macro call, a form value or text - and the list is the test's: a new bare count fails until it is converted or argued."""

    # (second pass, SP-9: `reserved`, `dynamic`, `events` and the health summary's `ok|warn|fail|skip` are counts the first grep could not see)
    GREP = re.compile(
        r"\{\{ [^}]*(count|total|active|free|used|size|leases|reserved|dynamic|events|summary\.(?:ok|warn|fail|skip))\b[^}]*\}\}"
    )
    # (template, a fragment of the expression) -> why it is not a count to group
    REVIEWED = {
        ("_device_badge.html", "device_badge("): "a macro call: `size='sm'` is the badge's size, not a number printed",
        ("_device_rows.html", "empty_state("): "a macro call carrying a sentence",
        ("_lease_rows.html", "empty_state("): "a macro call carrying a sentence",
        ("_ip_version_control.html", "ip_version_control("): "a macro call (the word `leases` is a URL)",
        ("leases.html", "ip_version_control("): "a macro call (the word `leases` is a URL)",
        ("api_keys.html", "last_used"): "a timestamp through |utcfmt",
        (
            "base.html",
            "session_active",
        ): "an epoch second in a data attribute (the session state a deadline was computed from), read by script: a grouped value would not parse",
        ("force_password_change.html", "session_active"): "an epoch second in a data attribute, as on base.html",
        ("client.html", "fetched_at"): "a timestamp through |utcfmt",
        ("mfa_enroll.html", "last_used"): "a timestamp through |utcdate",
        ("mfa_trusted_devices.html", "last_used"): "a timestamp through |utcfmt",
        ("ipmap.html", "used[ip]"): "a lookup in the map of addresses in use: a type or a hostname, not a count",
        (
            "database.html",
            "schedule.keep_count",
        ): "the value of an <input type=number>: a grouped value would not parse",
        (
            "setup_recovery.html",
            "schedule.keep_count",
        ): "the value of an <input type=number>: a grouped value would not parse",
        (
            "settings_alerts.html",
            "pool_exhaustion_free",
        ): "the value of an <input type=number>: a grouped value would not parse",
        ("reports.html", "pool_used / s.pool_size * 100"): "a percentage",
        ("settings_kea.html", "kea_ca.refused"): "a list of sentences joined with '; '",
        ("servers.html", "badge-reserved"): "a CSS class name (the transport badge's tone), not a count",
        ("servers.html", "transport_refused"): "a sentence (a remembered refusal, in Kea's own words)",
        ("settings_kea.html", "badge-reserved"): "a CSS class name (the transport badge's tone), not a count",
        ("settings_kea.html", "c.refused"): "a sentence (a remembered refusal, in Kea's own words)",
        ("settings_kea.html", "test_detail or 'refused'"): "a sentence: Kea's own words",
        ("settings_kea.html", "probe.write.account"): "an account name",
        (
            "_leases6_results.html",
            "badge-reserved",
        ): "a CSS class name (`badge-dynamic` / `badge-reserved`), not a count",
    }

    def _hits(self):
        import pathlib

        out = []
        for path in sorted(pathlib.Path("templates").glob("*.html")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for m in self.GREP.finditer(line):
                    out.append((path.name, n, m.group(0)))
        return out

    def test_every_count_the_grep_finds_is_grouped_or_reviewed(self):
        bare = []
        for name, n, expr in self._hits():
            if "|number" in expr or "|plural" in expr or "csrf" in expr:
                continue
            if any(name == t and fragment in expr for (t, fragment) in self.REVIEWED):
                continue
            bare.append(f"{name}:{n}: {expr[:100]}")
        assert not bare, "a count printed without |number or |plural:\n  " + "\n  ".join(bare)

    def test_the_reviewed_list_is_live(self):
        hits = self._hits()
        for template, fragment in self.REVIEWED:
            assert any(name == template and fragment in expr for name, _n, expr in hits), (template, fragment)

    def test_the_grep_finds_what_it_is_for(self):
        assert (
            self.GREP.search("{{ s.active }}")
            and self.GREP.search("{{ total }}")
            and not self.GREP.search("{{ s.name }}")
        )

    def test_the_dashboards_placeholder_survives_the_filter(self):
        text = pathlib.Path("templates/dashboard.html").read_text(encoding="utf-8")
        assert "s.active|number if s.active is number else s.active" in text, (
            "the skeleton prints an ellipsis until the first refresh: |number would turn it into 0"
        )


class TestTheDashboardScriptGroups:
    def test_every_count_the_refresh_writes_is_grouped_with_the_us_locale(self):
        text = pathlib.Path("templates/dashboard.html").read_text(encoding="utf-8")
        for needle in (
            "activeEl.textContent = Number(s.active || 0).toLocaleString('en-US')",
            "active6El.textContent = Number(s6.active || 0).toLocaleString('en-US')",
            "ta.textContent = Number(totalActive).toLocaleString('en-US')",
            "td.textContent = Number(totalDynamic).toLocaleString('en-US')",
            "tr.textContent = Number(totalReserved).toLocaleString('en-US')",
        ):
            assert needle in text, needle

    def test_no_stat_value_is_written_with_a_bare_number(self):
        text = pathlib.Path("templates/dashboard.html").read_text(encoding="utf-8")
        assert not re.search(
            r"(activeEl|active6El|ta|td|tr)\.textContent = (s6?\.active|total(Active|Dynamic|Reserved));", text
        )
