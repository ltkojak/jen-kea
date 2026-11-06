"""v7.0.0-beta.6 (Q220), widened by Q221 (AE2) - every module-level name under jen/ and plugins/ that is SHAPED like a cache or a time stamp, in either case, and every function under a cache
decorator, is on a reviewed list that says what the unit suite does about it.

One test's stubbed Kea must never answer for the next, and a cache that refreshes through Kea must never refresh inside a test that did not ask for it
(v7.0.0-beta.5's release run). A new name of that shape fails here until it is listed with what resets it; "UNRESET (registered)" is an open row, not an approval.

What this is NOT: an audit of every piece of module-level state. 7.0.0-beta.6's pattern was case-sensitive and missed `jen/services/kea.py::_HEALTH_CACHE` - a 120 s cache of each Kea's own
`version-get` answer, which let one test's stub answer the next with no Kea call. A name that is not shaped like a cache (`_ORACLE_VERDICTS`, `_write_hits`, a registry filled at import) is not seen
here; the whole-tree audit of module-level containers is registered (PENDING.md, the deferred test-hygiene item) and this file says so rather than claim it."""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PATTERN = re.compile(
    r"^(_[A-Za-z0-9_]*(?:cache|memo)[A-Za-z0-9_]*|_[A-Za-z0-9_]*_(?:at|ts)|_last_[A-Za-z0-9_]+)\s*(?::[^=\n]+)?=\s",
    re.M | re.I,
)
DECORATED = re.compile(r"^@(?:functools\.)?(?:lru_cache|cache)\b[^\n]*\n(?:@[^\n]*\n)*def ([A-Za-z0-9_]+)", re.M)

REVIEWED = {
    "jen/__init__.py::_ssl_configured_cache": "not time-based: one process's answer",
    "jen/extensions.py::_active_server_cache": "UNRESET (registered, Q220): 10 s, the active Kea server",
    "jen/models/db.py::_pool_failed_at": "a backoff stamp for a failed pool; nothing is fetched when it expires",
    "jen/models/user.py::_SETTINGS_CACHE_TTL": "a constant: the settings cache's lifetime",
    "jen/models/user.py::_settings_cache": "reset: clean_tables calls _invalidate_settings_cache",
    "jen/models/user.py::_settings_cache_ts": "reset with _settings_cache",
    "jen/routes/content.py::_CACHE": "a constant: the Cache-Control header of an uploaded file",
    "jen/services/alerts.py::_CONDITION_CACHE": "UNRESET (registered, Q221): 60 min, the alert conditions; the tests that read it clear it themselves (tests/test_alert_delivery.py)",
    "jen/services/auth.py::_last_prune": "a prune stamp; nothing is fetched",
    "jen/services/capabilities.py::_CACHE_TTL_S": "a constant: the version cache's lifetime",
    "jen/services/capabilities.py::_version_cache": "reset: _reset_capabilities_cache",
    "jen/services/events.py::_current_started_at": "the dispatcher's liveness stamp",
    "jen/services/events.py::_last_dispatch_at": "the dispatcher's liveness stamp",
    "jen/services/events.py::_last_drop_log": "a log throttle",
    "jen/services/explain_context.py::_evidence_memo": "UNRESET (registered, Q220): 30 s",
    "jen/services/explain_context.py::_log_cache": "UNRESET (registered, Q220): 30 s; its reads go through log_tail's seam, which _reset_log_tail answers",
    "jen/services/icons.py::icon_names": "an lru_cache over the shipped icon files: one process's answer, no Kea, no clock",
    "jen/services/kea.py::_HEALTH_CACHE": "reset: _reset_kea_health_cache (Q221) - 120 s, each Kea's last version-get answer; the reader never probes on a miss",
    "jen/services/log_tail.py::_cache": "reset: _reset_log_tail",
    "jen/services/onboarding.py::_PILL_CACHE_MAX": "a constant: the pill cache's size",
    "jen/services/onboarding.py::_PILL_CACHE_TTL": "a constant: the pill cache's lifetime",
    "jen/services/onboarding.py::_pill_cache": "inert: _nav_pill_is_inert (Q220)",
    "jen/services/plugins.py::_shipped_plugin_ids_cache": "not time-based: the shipped set of one process",
    "jen/services/subnet_context.py::_cfg_cache": "UNRESET (registered, Q220): 30 s, a Kea config",
    "jen/services/subnet_context.py::_host_ips_cache": "UNRESET (registered, Q220): 300 s",
    "plugins/wol/plugin.py::_last_sent": "a per-MAC send throttle",
}


def _found() -> set[str]:
    out = set()
    for top in ("jen", "plugins"):
        for path in sorted((ROOT / top).rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for m in [*PATTERN.finditer(text), *DECORATED.finditer(text)]:
                out.add(f"{path.relative_to(ROOT).as_posix()}::{m.group(1)}")
    return out


class TestEveryModuleLevelCacheIsReviewed:
    def test_the_tree_and_the_list_are_one(self):
        found = _found()
        assert found - set(REVIEWED) == set(), (
            "a module-level cache the list does not name: say what the unit suite does about it"
        )
        assert set(REVIEWED) - found == set(), "the list names a cache the tree no longer has"

    def test_every_entry_says_something(self):
        assert all(reason.strip() for reason in REVIEWED.values())

    def test_the_fixtures_the_list_names_exist(self):
        conftest = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
        for name in (
            "_nav_pill_is_inert",
            "_reset_capabilities_cache",
            "_reset_log_tail",
            "_invalidate_settings_cache",
            "_reset_kea_health_cache",
        ):
            assert name in conftest, name

    def test_the_pattern_is_case_blind_and_sees_a_decorator(self):
        """AE2, as a control on the instrument: the two shapes 7.0.0-beta.6's pattern could not see are found in a made-up module, and a plain constant is not."""
        sample = "_HEALTH_CACHE: dict = {}\n_Last_Seen = 0.0\nTIMEOUT = 5\n\n\n@lru_cache(maxsize=1)\ndef icon_names():\n    return ()\n"
        names = {m.group(1) for m in [*PATTERN.finditer(sample), *DECORATED.finditer(sample)]}
        assert names == {"_HEALTH_CACHE", "_Last_Seen", "icon_names"}

    def test_one_tests_kea_answer_is_gone_before_the_next(self):
        """The trap AE2 executed, closed by the fixture's own body: an answer left in the health cache is not there after the reset the unit suite runs around every test."""
        import tests.conftest as conftest
        from jen.services import kea

        kea._HEALTH_CACHE["a stub's server"] = {"up": True, "version": "9.9.9 (a stub's answer)", "at": 0.0}
        conftest.clear_kea_health_cache()
        assert kea._HEALTH_CACHE == {}
