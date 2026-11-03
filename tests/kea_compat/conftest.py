"""
tests/kea_compat/conftest.py
─────────────────────────────
Q50 — Jen's service layer against a REAL kea-dhcp4 (3.0 LTS, 3.2 stable,
3.3 dev), run by .github/workflows/kea-compat.yml. Not part of the
default run: every test is skipped unless KEA_COMPAT_URL (the daemon's
http control socket) is set, so a plain `pytest` never notices this
directory. Read-mostly — the only writes are a throwaway reservation
(added and removed) and, in its own workflow step, tests/kea_compat/
test_config_write.py (Q211), which config-sets and config-writes on a
read-write /etc/kea and puts the original file back.

Overrides tests/conftest.py's two autouse DB fixtures the same way
tests/e2e/conftest.py does: this suite talks to Kea, not to Jen's own
database, and those fixtures would error every test without one.

Each test's outcome is written to $KEA_COMPAT_RESULTS (JSON) so the
workflow can render a version x check table in the job summary.
"""

import json
import os

import pytest

KEA_URL = os.environ.get("KEA_COMPAT_URL", "")
RESULTS = os.environ.get("KEA_COMPAT_RESULTS", "")
WRITE_OUT = os.environ.get(
    "KEA_COMPAT_WRITE_OUT", ""
)  # Q211: the config-write rows' facts; this hook adds each row's outcome under "rows"


@pytest.fixture(scope="session", autouse=True)
def test_database():
    yield


@pytest.fixture(autouse=True)
def clean_tables():
    yield


@pytest.fixture(scope="session", autouse=True)
def direct_mode():
    """Point Jen's Kea client at the daemon in direct mode, the way a
    deployment with a per-daemon http control socket runs."""
    if not KEA_URL:
        yield
        return
    from jen import extensions

    names = ("KEA_CONNECTION_MODE", "KEA_API_URL", "KEA_API_USER", "KEA_API_PASS")
    saved = {n: getattr(extensions, n) for n in names}
    extensions.KEA_CONNECTION_MODE = "direct"
    extensions.KEA_API_URL = KEA_URL
    extensions.KEA_API_USER = os.environ.get("KEA_COMPAT_USER", "")
    extensions.KEA_API_PASS = os.environ.get("KEA_COMPAT_PASS", "")
    yield
    for n, v in saved.items():
        setattr(extensions, n, v)


def pytest_collection_modifyitems(config, items):
    if KEA_URL:
        return
    skip = pytest.mark.skip(reason="KEA_COMPAT_URL not set - real-Kea suite runs only in kea-compat.yml")
    for item in items:
        if "kea_compat" in item.keywords or "kea_log" in item.keywords or "kea_write" in item.keywords:
            item.add_marker(skip)


def _record_write_row(report):
    """Q211: test_config_write.py's rows land in $KEA_COMPAT_WRITE_OUT beside their facts (the module keeps the facts, this keeps the outcomes)."""
    if report.when != "call" and not (report.when == "setup" and report.outcome != "passed"):
        return
    try:
        with open(WRITE_OUT) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {}
    data.setdefault("rows", {})[report.nodeid.split("::")[-1]] = report.outcome
    with open(WRITE_OUT, "w") as fh:
        json.dump(data, fh, indent=2)


def pytest_runtest_logreport(report):
    if WRITE_OUT and "test_config_write.py" in report.nodeid:
        _record_write_row(report)
    if not RESULTS:
        return
    if report.when != "call" and not (report.when == "setup" and report.outcome != "passed"):
        return
    try:
        with open(RESULTS) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {}
    # an expected failure (a `known_bug`) reports "skipped" with `wasxfail`; the summary table shows it as one
    outcome = "xfailed" if hasattr(report, "wasxfail") and report.outcome == "skipped" else report.outcome
    data[report.nodeid.split("::")[-1]] = outcome
    with open(RESULTS, "w") as fh:
        json.dump(data, fh)
