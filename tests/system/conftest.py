"""
tests/system/conftest.py
─────────────────────────
Q84 — the system-boundary suite. Jen under gunicorn, two Kea hosts, MariaDB
and two fault injectors, all real processes in one docker compose project
(tests/system/compose/), driven from this pytest process with `docker
compose` and `docker exec` only. Run by .github/workflows/system-tests.yml
(dispatch, weekly, -rc. tags); never by ci.yml or release.yml.

Every test is skipped unless JEN_SYSTEM_TESTS=1, so the default `pytest`
run never notices this directory. It overrides tests/conftest.py's autouse
fixtures the way tests/kea_compat/conftest.py does: this suite talks to a
compose stack, not to the unit suite's `jen_test` database.

Each test's outcome (and its named invariant) is written to $SYS_RESULTS
(JSON) so the workflow can render a per-scenario table in the job summary.
A scenario that fails because Jen really has the bug it names is marked
`known_bug(...)` (xfail, strict): it stays visible as "known bug" in the
table, and turns red the day the bug is fixed and the marker is stale.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

ENABLED = os.environ.get("JEN_SYSTEM_TESTS") == "1"
RESULTS = os.environ.get("SYS_RESULTS", "")


@pytest.fixture(scope="session", autouse=True)
def test_database():
    yield


@pytest.fixture(autouse=True)
def _reset_capabilities_cache():
    yield


@pytest.fixture(autouse=True)
def clean_tables():
    yield


def pytest_collection_modifyitems(config, items):
    if ENABLED:
        return
    skip = pytest.mark.skip(reason="JEN_SYSTEM_TESTS not set - the system suite runs only in system-tests.yml")
    for item in items:
        if "system" in item.keywords:
            item.add_marker(skip)


def _artifact_dir():
    from tests.system import stack

    d = stack.WORK / "results"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture(scope="session")
def stack():
    """The running compose project, with the helper installed on both Kea
    hosts the way an operator's 'Install helper' button does it."""
    if not ENABLED:
        pytest.skip("JEN_SYSTEM_TESTS not set")
    from tests.system import stack as st

    st.prepare_workdir()
    try:
        st.compose("up", "-d", "--build", timeout=1500)
        st.wait_for(
            lambda: st.kea_running(st.KEA_A) and st.kea_running(st.KEA_B), timeout=90, what="both kea-dhcp4 daemons"
        )
        st.wait_jen_healthy(timeout=150)
        st.wait_for(
            lambda: st.kea_answers("kea-a") and st.kea_answers("kea-b"), timeout=60, what="both Kea control sockets"
        )

        emitted, _p = st.jen_py(
            """
from jen.services import kea_host
out = []
with app.app_context():
    for s in extensions.KEA_SERVERS:
        r = kea_host.install_helper(s)
        out.append({"server": s["name"], **r})
        if r.get("ok"):
            out.append({"server": s["name"], "legacy": kea_host.remove_legacy_grant(s)})
emit(out)
"""
        )
        for row in emitted[0]:
            if "ok" in row and not row["ok"]:
                raise RuntimeError(f"helper install failed: {row}")

        # /etc/jen belongs to the service user (the restore scenario rewrites every file in it as that user)
        st.dexec(
            st.JEN,
            "sh",
            "-c",
            "cp /etc/resolv.conf /etc/jen/.resolv.sysorig && chmod 666 /etc/jen/.resolv.sysorig "
            "&& chown -R www-data:www-data /etc/jen",
            user="root",
        )
        st.BASELINE.update({n: st.kea_conf_bytes(n) for n in (st.KEA_A, st.KEA_B)})
        yield st
    finally:
        try:
            for name in ("jen", "kea-a", "kea-b", "mariadb", "dns", "updater"):
                p = st.compose("logs", "--no-color", "--tail", "400", name, check=False)
                (_artifact_dir() / f"{name}.log").write_text(p.stdout + p.stderr, encoding="utf-8", errors="replace")
        finally:
            if os.environ.get("SYS_KEEP") != "1":
                st.compose("down", "-v", "--remove-orphans", check=False)


@pytest.fixture(autouse=True)
def _reset(request):
    """Every scenario starts from the same place: both Kea hosts running the
    baseline config with sshd up, the resolver untouched and answering, and
    Jen healthy. A scenario breaks things on purpose; it must not leave them
    broken for the next."""
    if "system" not in request.keywords or not ENABLED:
        yield
        return
    st = request.getfixturevalue("stack")
    _heal(st)
    yield
    _heal(st)


def _heal(st):
    for node in (st.KEA_A, st.KEA_B):
        if not st.sshd_running(node):
            st.dexec(node, "/usr/sbin/sshd", check=False)
        st.sh(
            node,
            "for f in /usr/sbin /usr/bin /usr/local/sbin /usr/local/bin; do "
            '[ -f "$f/kea-dhcp4.real" ] && mv -f "$f/kea-dhcp4.real" "$f/kea-dhcp4"; done; true',
            check=False,
        )
        st.dexec(node, "sh", "-c", f"cat > {st.KEA_CONF}", input=st.BASELINE[node])
        st.dexec(node, "/usr/local/bin/keactl", "restart", check=False)
    st.dexec(
        st.JEN,
        "sh",
        "-c",
        "cat /etc/jen/.resolv.sysorig > /etc/resolv.conf; "
        "grep -v '# sys-test' /etc/hosts > /etc/jen/.hosts.tmp; cat /etc/jen/.hosts.tmp > /etc/hosts; rm -f /etc/jen/.hosts.tmp",
        user="root",
        check=False,
    )
    st.sh(st.JEN, "rm -f /tmp/s[0-9]*-*", check=False)
    st.sh(st.DNS, "rm -f /ctl/limit; touch /ctl/reset", check=False)
    st.wait_for(
        lambda: st.kea_answers("kea-a") and st.kea_answers("kea-b"), timeout=60, what="Kea control sockets after heal"
    )
    st.wait_jen_healthy(timeout=90)


# ── results file ─────────────────────────────────────────────────────────────


def pytest_runtest_logreport(report):
    if not RESULTS or "system" not in report.keywords:
        return
    if report.when != "call" and not (report.when in ("setup", "teardown") and report.outcome == "failed"):
        return
    if hasattr(report, "wasxfail"):
        status = "known-bug" if report.outcome == "skipped" else "failed"
    else:
        status = report.outcome
    try:
        with open(RESULTS) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {}
    name = report.nodeid.split("::")[-1]
    row = data.get(name, {})
    if row.get("status") in ("failed", "known-bug") and status == "passed":
        status = row["status"]  # a teardown pass doesn't erase a call failure
    row.update({"status": status, "seconds": round(report.duration, 1)})
    if report.outcome == "failed" and report.longreprtext:
        row["detail"] = report.longreprtext[-1500:]
    data[name] = row
    with open(RESULTS, "w") as fh:
        json.dump(data, fh)
