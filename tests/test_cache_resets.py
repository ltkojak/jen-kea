"""v7.0.0-beta.6 (Q220) - every module-level cache or time stamp under jen/ and plugins/ is on a reviewed list that says what the unit suite does about it.

One test's stubbed Kea must never answer for the next, and a cache that refreshes through Kea must never refresh inside a test that did not ask for it
(v7.0.0-beta.5's release run). A new module-level cache fails here until it is listed with what resets it; "UNRESET (registered)" is an open row, not an approval."""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PATTERN = re.compile(
    r"^(_[A-Za-z0-9_]*(?:cache|memo)[A-Za-z0-9_]*|_[A-Za-z0-9_]*_(?:at|ts)|_last_[A-Za-z0-9_]+)\s*(?::[^=\n]+)?=\s",
    re.M,
)

REVIEWED = {
    "jen/__init__.py::_ssl_configured_cache": "not time-based: one process's answer",
    "jen/extensions.py::_active_server_cache": "UNRESET (registered, Q220): 10 s, the active Kea server",
    "jen/models/db.py::_pool_failed_at": "a backoff stamp for a failed pool; nothing is fetched when it expires",
    "jen/models/user.py::_settings_cache": "reset: clean_tables calls _invalidate_settings_cache",
    "jen/models/user.py::_settings_cache_ts": "reset with _settings_cache",
    "jen/services/auth.py::_last_prune": "a prune stamp; nothing is fetched",
    "jen/services/capabilities.py::_version_cache": "reset: _reset_capabilities_cache",
    "jen/services/events.py::_current_started_at": "the dispatcher's liveness stamp",
    "jen/services/events.py::_last_dispatch_at": "the dispatcher's liveness stamp",
    "jen/services/events.py::_last_drop_log": "a log throttle",
    "jen/services/explain_context.py::_evidence_memo": "UNRESET (registered, Q220): 30 s",
    "jen/services/explain_context.py::_log_cache": "UNRESET (registered, Q220): 30 s; its reads go through log_tail's seam, which _reset_log_tail answers",
    "jen/services/log_tail.py::_cache": "reset: _reset_log_tail",
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
            for m in PATTERN.finditer(path.read_text(encoding="utf-8")):
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
        ):
            assert name in conftest, name
