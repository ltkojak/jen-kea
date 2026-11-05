"""
tests/test_bump_version.py
──────────────────────────
Q218 BH6 i - `tools/bump_version.py` dates the CHANGELOG heading in UTC. A release publishes in UTC and a heading dated by hand in local time was a day early (7.0.0-beta.3 was dated 2026-11-04 and
published 2026-11-05T06:07Z). Pure: runs under `--noconftest`.
"""

import datetime
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _tool():
    spec = importlib.util.spec_from_file_location("bump_version", ROOT / "tools" / "bump_version.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


UTC = datetime.timezone.utc
LOCAL_EVENING = datetime.datetime(
    2026, 11, 4, 22, 30, tzinfo=datetime.timezone(datetime.timedelta(hours=-5))
)  # 03:30 UTC the next day


class TestTheHeadingIsDatedInUtc:
    def test_a_local_evening_is_the_next_utc_day(self):
        entry = "## [7.0.0-beta.4] - 2026-11-04\n\nBeta. text.\n"
        out = _tool().dated_in_utc(entry, "7.0.0-beta.4", LOCAL_EVENING)
        assert out.startswith("## [7.0.0-beta.4] - 2026-11-05\n") and out.endswith("Beta. text.\n")

    def test_a_heading_with_no_date_gets_one_and_the_body_is_untouched(self):
        entry = "## [7.0.0-beta.4]\n\nBeta. A line that mentions [7.0.0-beta.4] - 2026-01-01 in prose.\n"
        out = _tool().dated_in_utc(entry, "7.0.0-beta.4", datetime.datetime(2026, 11, 5, 6, 7, tzinfo=UTC))
        assert (
            out.startswith("## [7.0.0-beta.4] - 2026-11-05\n")
            and "mentions [7.0.0-beta.4] - 2026-01-01 in prose" in out
        )

    def test_only_the_new_versions_heading_is_touched(self):
        entry = "## [7.0.0-beta.4] - 2026-11-04\n\n## [7.0.0-beta.3] - 2026-11-04\n"
        out = _tool().dated_in_utc(entry, "7.0.0-beta.4", datetime.datetime(2026, 11, 6, 1, 0, tzinfo=UTC))
        assert "## [7.0.0-beta.4] - 2026-11-06" in out and "## [7.0.0-beta.3] - 2026-11-04" in out

    def test_main_calls_it_before_the_entry_is_inserted(self):
        source = (ROOT / "tools" / "bump_version.py").read_text(encoding="utf-8")
        assert "entry = dated_in_utc(entry, new)" in source
