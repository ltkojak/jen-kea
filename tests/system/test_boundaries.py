"""
tests/system/test_boundaries.py
────────────────────────────────
Q84 — ten places Jen touches something it does not own, each broken on
purpose against real processes (see conftest.py / compose/). Every test
names the invariant it defends in its first docstring line and again in
its assert messages, so a red row in the job summary reads as a sentence.

Scenarios stand things in only where the real thing cannot exist in a
container (systemd, GitHub); each such stand-in is named in the test.
"""

import contextlib
import json
import re
import time

import pytest

from tests.system import stack as st

pytestmark = pytest.mark.system


def known_bug(reason):
    """xfail(strict): the scenario fails today because Jen really has the bug it
    names. It shows as `known bug` in the summary, and turns red the day the bug
    is fixed and this marker is stale."""
    return pytest.mark.xfail(strict=True, reason="KNOWN BUG: " + reason)


def emitted(out):
    return out[0] if out else None


def result_of(stdout):
    return next((json.loads(line[3:]) for line in stdout.splitlines() if line.startswith("@@ ")), None)


# ── 0. the harness itself ─────────────────────────────────────────────────────


def test_00_stack_is_up(stack):
    """The stack the scenarios stand on: Jen answers, both Kea hosts answer, and Jen
    reaches each one's helper over SSH."""
    assert st.jen_healthy()
    assert st.kea_answers("kea-a") and st.kea_answers("kea-b")
    out, _p = st.jen_py(
        """
from jen.services import kea_host
with app.app_context():
    emit([{"server": s["name"], **kea_host.check_helper(s)} for s in extensions.KEA_SERVERS])
"""
    )
    rows = emitted(out)
    assert [r["server"] for r in rows] == ["kea-a", "kea-b"], rows
    for r in rows:
        assert r.get("ok") and r.get("version"), f"the helper is not answering on {r['server']}: {r}"

    # v5.67.0-beta.6 (Q118) — the mirror of the install CI job's own new
    # assertion: this stack IS a container, so
    # jen.services.runtime.deployment() must say so, and every page whose
    # content depends on it must show the Docker wording, not the
    # systemd-only Update/Restart controls. Q114's rendered-unit JEN_ROOT
    # never applies here at all (no systemd unit exists in this container),
    # so this scenario could never have caught the bug the install job's
    # own new leg exists for — it proves the other half still works,
    # deliberately, the two together covering both answers.
    out, _p = st.jen_py(
        """
from jen.services import runtime
with app.app_context():
    emit({"deployment": runtime.deployment()})
"""
    )
    assert emitted(out)["deployment"] == "docker", "INVARIANT: this stack is a container, not systemd"

    web = st.Web().login()
    system_page = web.get("/settings/system").text
    assert "container image's job" in system_page, "INVARIANT: Docker wording shown for updates"
    assert "Update Now" not in system_page, "INVARIANT: no systemd Update control in a container"
    assert "Restart the container to restart Jen" in system_page, "INVARIANT: Docker wording shown for restart"
    assert 'data-confirm="Restart Jen now?"' not in system_page, "INVARIANT: no systemd Restart control in a container"

    plugins_page = web.get("/settings/plugins").text
    assert "Installed plugins live in" in plugins_page, "INVARIANT: Docker wording shown for plugin installs"
    assert "root-privileged service" not in plugins_page, "INVARIANT: no root-managed plugin wording in a container"


# ── 1. restore.py, MariaDB dies mid-import ────────────────────────────────────

RESTORE_SCRIPT = """
import gzip, hashlib, shutil
from pathlib import Path
from jen import JEN_VERSION
from jen.models import db as _db
from jen.models.migrations import MIGRATIONS
from jen.services import dbexport, recovery
from jen.tools import restore

def setting(v):
    with _db.jen_db() as c, c.cursor() as cur:
        cur.execute("INSERT INTO settings (setting_key, setting_value) VALUES ('sys_marker', %s) "
                    "ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)", (v,))
        c.commit()

live_cfg = Path("/etc/jen/jen.config").read_bytes()
setting("bundle")
export, _n = dbexport.export_jen()
manifest = {"jen_version": JEN_VERSION, "schema_version": MIGRATIONS[-1][0], "kea_versions": {}, "plugins": []}
blob = recovery.build({
    "manifest.json": json.dumps(manifest).encode(),
    "jen.config": live_cfg + b"\\n# written-by-the-bundle\\n",
    "jen_db.json.gz": gzip.compress(export),
    "content/icons/sys-bundle.png": b"from-the-bundle",
}, "correct-horse-battery")
Path("/tmp/s1.bundle").write_bytes(blob)

# live state the restore will overwrite, and that a rollback must bring back
setting("live")
Path("/var/lib/jen/icons").mkdir(parents=True, exist_ok=True)
Path("/var/lib/jen/icons/sys-live.bin").write_bytes(b"live-content")

state = {"imports": 0, "calls": 0, "fired": False}
real_import, real_exists = dbexport.import_jen, dbexport._table_exists

def import_wrapper(*a, **k):
    state["imports"] += 1
    state["calls"] = 0
    return real_import(*a, **k)

def exists_wrapper(conn, tbl):
    if state["imports"] == 1 and not state["fired"]:
        state["calls"] += 1
        if state["calls"] == 2:  # the FIRST table has been replaced; the second is next
            state["fired"] = True
            Path("/tmp/s1-at-table-2").write_text(tbl)
            for _ in range(600):
                if Path("/tmp/s1-proceed").exists():
                    break
                time.sleep(0.5)
    return real_exists(conn, tbl)

dbexport.import_jen, dbexport._table_exists = import_wrapper, exists_wrapper
rc = restore.run("/tmp/s1.bundle", "correct-horse-battery", no_stop=True)
emit({"rc": rc, "fired": state["fired"], "live_cfg_sha": hashlib.sha256(live_cfg).hexdigest()})
"""


def test_01_restore_rolls_back_when_mariadb_dies_mid_import(stack):
    """restore.py: MariaDB dying after the first table is replaced leaves Jen exactly as
    it was — rows, files, config — and Jen healthy."""
    st.sh(st.JEN, "rm -f /tmp/s1-*", check=False)
    proc = st.jen_py_bg(RESTORE_SCRIPT)
    try:
        st.sentinel_wait(st.JEN, "/tmp/s1-at-table-2", timeout=120)
        # the database restarts under the import (a crash + supervisor restart, or a failover)
        st.run(["docker", "kill", st.MARIADB])
        st.run(["docker", "start", st.MARIADB])
        st.wait_for(
            lambda: (
                st.dexec(st.MARIADB, "healthcheck.sh", "--connect", "--innodb_initialized", check=False).returncode == 0
            ),
            timeout=90,
            what="MariaDB back up",
        )
        st.sh(st.JEN, "touch /tmp/s1-proceed")
        stdout, stderr = proc.communicate(timeout=180)
    finally:
        if proc.poll() is None:
            proc.kill()
    result = result_of(stdout)
    assert result is not None, f"the restore process printed no result:\n{stdout[-1500:]}\n{stderr[-1500:]}"

    assert result["fired"], "the fault was never injected — the scenario proved nothing"
    assert result["rc"] == 1, (
        "INVARIANT: a restore that fails mid-import rolls back cleanly (exit 1, not 2 'ROLLBACK FAILED')\n"
        f"{stdout[-1500:]}\n{stderr[-1500:]}"
    )

    out, _p = st.jen_py(
        """
import hashlib
from pathlib import Path
from jen.models import db as _db
with _db.jen_db() as c, c.cursor() as cur:
    cur.execute("SELECT setting_value AS v FROM settings WHERE setting_key='sys_marker'")
    row = cur.fetchone()
emit({
    "marker": row["v"] if row else None,
    "cfg_sha": hashlib.sha256(Path("/etc/jen/jen.config").read_bytes()).hexdigest(),
    "live_file": Path("/var/lib/jen/icons/sys-live.bin").exists(),
    "bundle_file": Path("/var/lib/jen/icons/sys-bundle.png").exists(),
})
"""
    )
    after = emitted(out)
    assert after["marker"] == "live", f"INVARIANT: the database is back to its pre-restore rows, got {after}"
    assert after["cfg_sha"] == result["live_cfg_sha"], f"INVARIANT: jen.config is byte-identical to before, got {after}"
    assert after["live_file"] and not after["bundle_file"], (
        f"INVARIANT: content files are back as they were, got {after}"
    )

    st.sh(st.JEN, "rm -f /var/lib/jen/icons/sys-live.bin /tmp/s1.bundle", check=False)
    st.wait_jen_healthy(timeout=90)
    web = st.Web().login()
    r = web.get("/health-center/data")
    assert r.status_code == 200, "INVARIANT: Jen is healthy after the failed restore"
    checks = {c["id"]: c for c in r.json()["checks"]}
    assert checks["db_jen"]["status"] == "ok", f"INVARIANT: Jen reaches its database again: {checks['db_jen']}"


# ── 2. kea_changeset: B unreachable after preflight ───────────────────────────

CHANGESET_PRELUDE = """
import copy
from jen.services import kea_changeset as cs, kea_host

def mutate(cfg):
    c = copy.deepcopy(cfg)
    c["Dhcp4"]["valid-lifetime"] = 7200
    return c, "ok"
"""

CHANGESET_B_DIES = (
    CHANGESET_PRELUDE
    + """
real, seen = kea_host.test_config, []

def hooked(server, service, cfg, **kw):
    r = real(server, service, cfg, **kw)
    seen.append(server["name"])
    if len(seen) == 2:  # every target has now passed preflight
        open("/tmp/s2-preflighted", "w").close()
        for _ in range(240):
            if os.path.exists("/tmp/s2-proceed"):
                break
            time.sleep(0.5)
    return r

kea_host.test_config = hooked
try:
    res = cs.apply_change("dhcp4", mutate, "system-test edit")
    emit({"status": res.status, "lines": [l[1] for l in res.lines]})
except Exception as e:
    emit({"raised": type(e).__name__ + ": " + str(e)[:300]})
"""
)


def test_02_changeset_reverts_the_first_server_when_the_second_dies(stack):
    """kea_changeset: server A committed, then B's sshd dies after preflight -> A is reverted
    and both configs are byte-identical to what they were."""
    st.sh(st.JEN, "rm -f /tmp/s2-*", check=False)
    proc = st.jen_py_bg(CHANGESET_B_DIES)
    try:
        st.sentinel_wait(st.JEN, "/tmp/s2-preflighted", timeout=120)
        st.sshd_stop(st.KEA_B)
        st.sh(st.JEN, "touch /tmp/s2-proceed")
        stdout, stderr = proc.communicate(timeout=180)
    finally:
        if proc.poll() is None:
            proc.kill()
    result = result_of(stdout)
    assert result is not None, f"no result from the change set:\n{stdout[-1500:]}\n{stderr[-1500:]}"

    a, b = st.kea_conf_bytes(st.KEA_A), st.kea_conf_bytes(st.KEA_B)
    assert a == st.BASELINE[st.KEA_A] and b == st.BASELINE[st.KEA_B], (
        "INVARIANT: after a change set that could not finish, both servers hold the config they had before "
        f"(kea-a changed: {a != st.BASELINE[st.KEA_A]}, kea-b changed: {b != st.BASELINE[st.KEA_B]}); "
        f"apply_change said: {result}"
    )
    assert "raised" not in result, f"INVARIANT: apply_change never raises (its docstring): {result}"
    assert result["status"] in ("aborted", "rollback_failed"), result


# ── 3. the restart fails after a validated config was written ────────────────

CHANGESET_RESTART_FAILS = (
    CHANGESET_PRELUDE
    + """
real_action = kea_host.service_action

def hooked(server, service, action, *a, **k):
    if action == "restart" and not os.path.exists("/tmp/s3-proceed"):
        open("/tmp/s3-before-restart", "w").close()
        for _ in range(240):
            if os.path.exists("/tmp/s3-proceed"):
                break
            time.sleep(0.5)
    return real_action(server, service, action, *a, **k)

kea_host.service_action = hooked
try:
    only_a = [s for s in extensions.KEA_SERVERS if s["name"] == "kea-a"]
    res = cs.apply_change("dhcp4", mutate, "system-test edit", servers=only_a)
    emit({"status": res.status, "lines": [l[1] for l in res.lines]})
except Exception as e:
    emit({"raised": type(e).__name__ + ": " + str(e)[:300]})
"""
)


def test_03_a_failed_restart_leaves_the_previous_config_live(stack):
    """kea_changeset: a validated config whose restart fails (the daemon exits at start) is rolled
    back — the previous config is what is on disk."""
    st.sh(st.JEN, "rm -f /tmp/s3-*", check=False)
    proc = st.jen_py_bg(CHANGESET_RESTART_FAILS)
    try:
        st.sentinel_wait(st.JEN, "/tmp/s3-before-restart", timeout=120)
        # config-test has passed and the file is written; now the daemon cannot start ONCE: the wrapper
        # puts the real binary back (renaming over itself) and exits 1, so the rollback's second
        # restart runs the real daemon on the previous config
        wrapper = """#!/bin/sh
mv -f "$0.real" "$0"
exit 1
"""
        st.dexec(
            st.KEA_A,
            "sh",
            "-c",
            'b="$(command -v kea-dhcp4)"; mv "$b" "$b.real" && cat > "$b" && chmod 755 "$b" && chown root:root "$b"',
            input=wrapper,
        )
        st.sh(st.JEN, "touch /tmp/s3-proceed")
        stdout, stderr = proc.communicate(timeout=180)
    finally:
        if proc.poll() is None:
            proc.kill()
    result = result_of(stdout)
    assert result is not None, f"no result from the change set:\n{stdout[-1500:]}\n{stderr[-1500:]}"

    on_disk = st.kea_conf_bytes(st.KEA_A)
    assert on_disk == st.BASELINE[st.KEA_A], (
        "INVARIANT: when the restart of a newly written config fails, the previous config is the one on disk "
        f"(apply_change said: {result})"
    )
    assert result.get("status") == "rolled_back", f"INVARIANT: the outcome is reported as rolled_back: {result}"
    st.wait_for(lambda: st.kea_answers("kea-a"), timeout=30, what="kea-a answering on the previous config")


# ── 4. DNS reconcile against a resolver that goes silent ────────────────────

RECONCILE_SCRIPT = """
import threading
from jen.routes import ddns
from jen.services import dns_reconcile as dr

rows = [{"name": f"host{n}.sys.test", "ip": f"10.77.0.{n}", "source": "reservation"} for n in range(1, 31)]

def run():
    t0 = time.monotonic()
    res = dr.reconcile(rows, ddns._run_verify, suffix="")
    return res, time.monotonic() - t0

def pool_threads():
    return sum(1 for t in threading.enumerate() if t.name.startswith("dns-reconcile"))

res1, el1 = run()
n1 = pool_threads()
res2, el2 = run()
n2 = pool_threads()
emit({
    "rows": len(res1), "seconds": [round(el1, 1), round(el2, 1)], "threads": [n1, n2],
    "verdicts": sorted({r["verdict"] for r in res1}),
    "lookup_failed": sum(1 for r in res1 if r["verdict"] == "lookup-failed"),
    "ok": sum(1 for r in res1 if r["verdict"] == "ok"),
    "budget": dr.TOTAL_BUDGET_SECONDS, "pool": dr.POOL_WORKERS,
})
"""


def test_04_reconcile_returns_inside_its_budget_when_the_resolver_stalls(stack):
    """dns_reconcile: a resolver that goes silent after 20 answers cannot hold the run past its
    budget; unanswered rows read `lookup-failed`; the pool does not grow."""
    dns_ip = st.container_ip(st.DNS)
    hosts = [
        f"{st.container_ip(cont)} {name} # sys-test"
        for name, cont in (("mariadb", st.MARIADB), ("kea-a", st.KEA_A), ("kea-b", st.KEA_B))
    ]
    # names Jen needs keep resolving from /etc/hosts while the resolver is the fault injector
    st.dexec(
        st.JEN,
        "sh",
        "-c",
        "".join(f"echo '{h}' >> /etc/hosts; " for h in hosts) + f"echo 'nameserver {dns_ip}' > /etc/resolv.conf",
        user="root",
    )
    st.sh(st.DNS, "echo 20 > /ctl/limit; touch /ctl/reset")
    out, _p = st.jen_py(RECONCILE_SCRIPT, timeout=120)
    r = emitted(out)
    budget = r["budget"]
    assert all(s <= budget + 3 for s in r["seconds"]), (
        f"INVARIANT: a stalled resolver cannot hold a reconciliation past its {budget}s budget: {r}"
    )
    assert r["rows"] == 30, r
    assert set(r["verdicts"]) <= {"ok", "lookup-failed"}, (
        f"INVARIANT: rows the resolver never answered read lookup-failed, not a false mismatch: {r}"
    )
    assert r["lookup_failed"] >= 15, f"the resolver did stall: {r}"
    assert r["threads"][0] == r["threads"][1] <= r["pool"], (
        f"INVARIANT: repeated runs against a wedged resolver do not add threads: {r}"
    )


# ── 5. Trace while the log rotates ───────────────────────────────────────────

MAC = "aa:bb:cc:dd:ee:ff"


def test_05_trace_survives_the_log_rotating_under_it(stack):
    """Trace: the Kea log rotating while it is being tailed yields a bounded answer — a result or
    a plain 'not found' — never an exception or a hang."""
    st.dexec(
        st.KEA_A,
        "python3",
        "-",
        input=(
            f"line = 'INFO  [kea-dhcp4.packets/1.1] DHCP4_PACKET_RECEIVED hwaddr=[hwtype=1 {MAC}] '\n"
            f"with open('{st.KEA_LOG}', 'w') as f:\n"
            "    for i in range(220000):\n"
            "        f.write('2026-09-24 10:00:%02d.000 ' % (i % 60) + line + 'x' * 40 + '\\n')\n"
        ),
    )
    rotator = st.dexec_bg(
        st.KEA_A,
        "sh",
        "-c",
        f"i=0; while [ $i -lt 150 ]; do mv {st.KEA_LOG} {st.KEA_LOG}.1; cp {st.KEA_LOG}.1 {st.KEA_LOG}; i=$((i+1)); done",
    )
    try:
        web = st.Web().login()
        seen = []
        for _ in range(12):
            t0 = time.monotonic()
            r = web.get(f"/tools/trace?mac={MAC}&server=1")
            seen.append((r.status_code, round(time.monotonic() - t0, 1), "Traceback" in r.text))
        out, _p = st.jen_py(
            """
from jen.services import kea_host
res = []
with app.app_context():
    s = extensions.KEA_SERVERS[0]
    for _ in range(40):
        try:
            r = kea_host.tail_log(s, extensions.DHCP4_LOG, 1000, timeout=15, helper_only=True)
            res.append([r.get("code"), len(r.get("lines", []))])
        except Exception as e:
            res.append(["RAISED", type(e).__name__ + ": " + str(e)[:200]])
emit(res)
"""
        )
        direct = emitted(out)
    finally:
        rotator.wait(timeout=120)
    assert all(code == 200 and not tb for code, _t, tb in seen), (
        f"INVARIANT: the Trace page answers (200, no traceback) while the log rotates: {seen}"
    )
    assert max(t for _c, t, _tb in seen) < 25, f"INVARIANT: a rotating log cannot hang a request: {seen}"
    assert all(code in ("ok", "missing", "error") for code, _n in direct), (
        f"INVARIANT: tail_log never raises when the file is rotated under it: {direct}"
    )
    assert all(n <= 1000 for _c, n in direct), f"INVARIANT: the result stays bounded (<=1000 lines): {direct}"


# ── 6. the updater killed between extract and switch ─────────────────────────

DRIVER = "/repo/tests/system/updater_driver.py"


def test_06_updater_killed_mid_update_leaves_the_previous_release_serving(stack, record_property):
    """jen-update-root.py SIGKILLed after extract and before the `current` switch: the previous
    release still serves, a retry completes, and the crashed staging dir does not outlive a prune."""
    st.dexec(st.UPDATER, "python3", DRIVER, "layout")
    st.dexec(st.UPDATER, "rm", "-f", "/tmp/sys-updater.sentinel")
    proc = st.dexec_bg(st.UPDATER, "python3", DRIVER, "update", "--hang-after-extract")
    try:
        try:
            st.sentinel_wait(st.UPDATER, "/tmp/sys-updater.sentinel", timeout=90)
        except AssertionError:
            proc.kill()
            out, err = proc.communicate()
            raise AssertionError(
                f"the updater never reached the extract-done point:\n{out[-2500:]}\n{err[-2500:]}"
            ) from None
        pid = st.dexec(st.UPDATER, "cat", "/tmp/sys-updater.sentinel").stdout.strip()
        st.dexec(st.UPDATER, "kill", "-9", pid)
        proc.communicate(timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()

    current = st.dexec(st.UPDATER, "readlink", "/opt/jen/current").stdout.strip()
    assert current == "releases/5.0.0", f"INVARIANT: `current` still points at the release that was serving: {current}"
    served = st.dexec(
        st.UPDATER,
        "python3",
        "-c",
        "import sys; sys.path.insert(0, '/opt/jen/current/app'); import jen; print(jen.JEN_VERSION)",
    ).stdout.strip()
    assert served == "5.0.0", f"INVARIANT: the previous release still loads and reports its own version: {served}"
    leftover = st.sh(st.UPDATER, "ls -d /opt/jen/releases/*.staging-*").stdout.split()
    assert leftover, "the kill did not land mid-update (no staging dir) — the scenario proved nothing"

    # a retry completes on top of the crashed attempt
    retry = st.dexec(st.UPDATER, "python3", DRIVER, "update")
    result = result_of(retry.stdout)
    assert result and result["rc"] == 0 and result["current"] == "releases/5.0.1", (
        f"INVARIANT: the next update run completes despite the crashed attempt: {retry.stdout[-1500:]}"
    )

    # the crashed attempt's half-built staging dir must not outlive the next runs. Whatever the retry
    # already pruned is fine; anything left is aged past the one-day rule and pruned (a FRESH staging dir
    # is kept on purpose: a concurrent updater's must never be deleted from under it)
    listing = st.sh(st.UPDATER, "ls -la --time-style=full-iso /opt/jen/releases").stdout
    left_after_retry = st.sh(st.UPDATER, "ls -d /opt/jen/releases/*.staging-* 2>/dev/null || true").stdout.split()
    record_property("note", f"staging dirs left after the retry run: {left_after_retry or 'none'}")
    st.sh(
        st.UPDATER, 'for d in /opt/jen/releases/*.staging-*; do [ -d "$d" ] && touch -d \'2 days ago\' "$d"; done; true'
    )
    pruned = st.dexec(st.UPDATER, "python3", DRIVER, "prune")
    after = result_of(pruned.stdout)
    assert after and not any(".staging-" in n for n in after["releases"]), (
        "INVARIANT: no half-extracted staging dir survives the next prune once stale: "
        + f"{after}"
        + "\n"
        + f"left after the retry: {left_after_retry}"
        + "\n"
        + listing
        + "\n"
        + "retry output:"
        + "\n"
        + retry.stdout[-1800:]
    )


# ── 7. the recovery bundle over its size cap ────────────────────────────────

PASSPHRASE = "correct-horse-battery"


def test_07_recovery_bundle_over_the_cap_is_refused_cleanly(stack):
    """Recovery bundle: with a 50 MB /tmp, a bundle that would exceed the size cap is refused with the
    cap message and leaves no partial file behind."""
    df = st.dexec(st.JEN, "df", "-k", "/tmp").stdout.splitlines()[-1].split()
    assert int(df[1]) <= 52000, f"the harness's /tmp is not the small tmpfs the scenario is about: {df}"

    web = st.Web().login()
    form = {"passphrase": PASSPHRASE, "passphrase_confirm": PASSPHRASE}
    ok = web.post("/settings/databases/recovery-bundle", form, page="/settings/databases")
    assert ok.status_code == 200 and "attachment" in ok.headers.get("Content-Disposition", ""), (
        f"control: a normal recovery bundle downloads on this stack ({ok.status_code})"
    )
    assert ok.content.startswith(b"JENREC2"), "control: the download is a recovery bundle"

    try:
        st.dexec(
            st.JEN,
            "sh",
            "-c",
            "mkdir -p /var/lib/jen/icons && truncate -s 2200M /var/lib/jen/icons/sys-big.bin",
            user="www-data",
        )
        r = web.post("/settings/databases/recovery-bundle", form, page="/settings/databases", timeout=300)
    finally:
        st.sh(st.JEN, "rm -f /var/lib/jen/icons/sys-big.bin", user="www-data", check=False)
    assert r.status_code == 200 and "attachment" not in r.headers.get("Content-Disposition", ""), (
        f"INVARIANT: an over-cap bundle is refused, not streamed ({r.status_code})"
    )
    assert re.search(r"size cap", r.text), "INVARIANT: the refusal names the size cap"
    left = st.sh(st.JEN, "ls /tmp /var/lib/jen/tmp 2>/dev/null | grep -c 'tar.enc' || true").stdout.strip()
    assert left == "0", f"INVARIANT: a refused bundle leaves no partial file behind ({left} found)"
    assert st.jen_healthy(), "INVARIANT: Jen is still serving after the refusal"


# ── 8. HA maintenance with the partner unreachable ───────────────────────────


def test_08_ha_handover_with_the_partner_unreachable_reports_and_does_not_advance(stack):
    """HA maintenance stepper: kea-b unreachable at the handover step is reported to the operator and
    the flow stays where it was — nothing is sent to the wrong server, no step is skipped."""
    ips = {"kea-a": st.container_ip(st.KEA_A), "kea-b": st.container_ip(st.KEA_B)}
    for node, name in ((st.KEA_A, "kea-a"), (st.KEA_B, "kea-b")):
        st.dexec(node, "sh", "-c", f"cat > {st.KEA_CONF}", input=json.dumps(st.ha_kea_config(name, ips), indent=2))
    hooks = st.sh(
        st.KEA_A, "ls /usr/lib/kea/hooks; kea-dhcp4 -t /etc/kea/kea-dhcp4.conf 2>&1 | tail -n 12", check=False
    )
    for node in (st.KEA_A, st.KEA_B):
        r = st.dexec(node, "/usr/local/bin/keactl", "restart", check=False)
        if r.returncode != 0:
            why = st.sh(node, "grep -E 'ERROR|HA_|HOOKS' /var/log/kea/kea-dhcp4.log | tail -n 20", check=False).stdout
            raise AssertionError(
                f"the HA-configured daemon did not start on {node}:\n{r.stderr}\n{why}\n{hooks.stdout}"
            )
    st.wait_for(
        lambda: st.kea_answers("kea-a") and st.kea_answers("kea-b"), timeout=60, what="HA-configured daemons answering"
    )
    with contextlib.suppress(AssertionError):  # the flow's own preflight reports whatever state they are in
        st.wait_for(
            lambda: st.ha_state("kea-a") == "hot-standby" and st.ha_state("kea-b") == "hot-standby",
            timeout=90,
            what="the HA pair to settle",
        )

    web = st.Web().login()
    web.post("/servers/ha/maintenance/begin", {"down": "1"}, page="/servers/ha/maintenance")
    before = web.get("/servers/ha/maintenance/status").json()
    assert before.get("active") and before["step"] == "preflight", f"the flow did not start: {before}"

    st.dexec(st.KEA_B, "/usr/local/bin/keactl", "stop")  # the partner goes unreachable at step 2
    st.wait_for(lambda: not st.kea_answers("kea-b"), timeout=20, what="kea-b's daemon stopped")
    r = web.post("/servers/ha/maintenance/handover", page="/servers/ha/maintenance")
    assert "refused ha-maintenance-start" in r.text, (
        "INVARIANT: the operator is told the handover was refused when the partner is unreachable "
        f"(page said: {re.sub(r'<[^>]+>', ' ', r.text)[:600]!r})"
    )
    after = web.get("/servers/ha/maintenance/status").json()
    assert after["step"] == "preflight", f"INVARIANT: the stepper does not advance past a failed handover: {after}"
    web.post("/servers/ha/maintenance/finish", page="/servers/ha/maintenance")


# ── 9. Health Center with one Control Agent answering 500 ───────────────────


def test_09_health_center_renders_with_one_control_agent_failing(stack):
    """Health Center: one server's Control Agent answering HTTP 500 yields one FAIL row about it, and the
    page still renders every other check."""
    cfg_path = st.WORK / "jen-etc" / "jen.config"

    def checks():
        r = st.Web().login().get("/health-center/data")
        assert r.status_code == 200, f"the Health Center answered {r.status_code}"
        return {c["id"]: c for c in r.json()["checks"]}

    baseline = checks()
    base_fail = {i for i, c in baseline.items() if c["status"] == "fail"}
    try:
        cfg_path.write_text(st.jen_config(server2_url="http://broken-ca:8500/"), encoding="utf-8")
        st.run(["docker", "restart", st.JEN])
        st.wait_jen_healthy(timeout=120)
        broken = checks()
        page = st.Web().login().get("/health-center")
    finally:
        cfg_path.write_text(st.jen_config(), encoding="utf-8")
        st.run(["docker", "restart", st.JEN])
        st.wait_jen_healthy(timeout=120)

    assert page.status_code == 200 and "Health" in page.text, "INVARIANT: the Health Center page renders"
    assert set(broken) == set(baseline), "INVARIANT: every check still reports (none crashed the page)"
    assert not [c for c in broken.values() if c["detail"].startswith("check errored")], (
        "INVARIANT: no check blew up on a 5xx from a Control Agent"
    )
    new_fail = sorted(i for i, c in broken.items() if c["status"] == "fail" and i not in base_fail)
    assert new_fail == ["kea_reachable"], f"INVARIANT: exactly one FAIL row, about the reachability: {new_fail}"
    assert "kea-b" in broken["kea_reachable"]["detail"], f"the row names the failing server: {broken['kea_reachable']}"


# ── 10. a plugin install whose root-side result never arrives ────────────────

PLUGIN_SCRIPT = """
import os
from jen.models import db as _db
from jen.models.user import get_global_setting, set_global_setting
from jen.services import plugins

PID = "sys-plugin"
# there is no systemd in the container: the marker path is the real one, the unit trigger is the stand-in
plugins.is_systemd_host = lambda: True
plugins._start_plugin_install_unit = lambda: True

def row():
    with _db.jen_db() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM plugins WHERE id=%s", (PID,))
        return cur.fetchone()["n"]

with app.app_context():
    ok, msg = plugins.install_plugin(PID, {})
    polls = []
    for _ in range(12):
        polls.append(len(plugins.consume_plugin_results()))
        time.sleep(1)
    state = {
        "requested": ok, "msg": msg, "pending": plugins.request_is_pending(PID, "install"),
        "applied_polls": sum(polls), "row": row(), "enabled": plugins._is_enabled(PID),
        "restart_pending": get_global_setting("restart_pending", "false"),
    }
    # control: when the root side DOES answer, the same code applies it — so the assertions above were not vacuous
    with open(os.path.join(extensions.CONTENT_PLUGIN_REQUESTS_DIR, PID + ".install.result"), "w") as f:
        f.write("ok")
    consumed = plugins.consume_plugin_results()
    state["control_consumed"] = [c["id"] for c in consumed]
    state["control_restart_pending"] = get_global_setting("restart_pending", "false")
    # tidy: leave no trace of the control
    set_global_setting("restart_pending", "false")
    plugins.disable_plugin(PID)
    marker = plugins._request_marker_path(PID, "install")
    if os.path.exists(marker):
        os.remove(marker)
    emit(state)
"""


def test_10_plugin_install_without_a_root_result_stays_pending(stack):
    """Plugin install: a request whose root-side result never arrives stays 'pending' — never applied,
    never enabled, no restart flagged."""
    out, _p = st.jen_py(PLUGIN_SCRIPT, timeout=120)
    s = emitted(out)
    assert s["requested"] and s["pending"], f"the install was requested and is waiting for the root side: {s}"
    assert s["applied_polls"] == 0 and s["row"] == 0 and not s["enabled"], (
        f"INVARIANT: with no result from the root side the plugin is never applied: {s}"
    )
    assert s["restart_pending"] != "true", f"INVARIANT: no restart is flagged for an install that has not happened: {s}"
    assert s["control_consumed"] == ["sys-plugin"] and s["control_restart_pending"] == "true", (
        f"control: the same path applies a result once it does arrive: {s}"
    )


# ── 11. /api/v1/health with Kea blackholed (v5.65.6, Q95) ─────────────────────

UPDATER_PROBE = """
import importlib.util, json
spec = importlib.util.spec_from_file_location("jur", "/repo/jen-update-root.py")
jur = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jur)
jur._local_base_url = lambda: "http://jen:5050"   # the updater box reaches Jen over the compose network
running = jur._running_version()
confirmed = jur._confirm_running_version(running, attempts=1, delay=0) if running else None
print("@@ " + json.dumps({"running": running, "confirmed": confirmed}))
"""


def test_11_health_answers_fast_and_the_updater_confirms_with_kea_blackholed(stack):
    """/api/v1/health: with every Kea server frozen (connects succeed, nothing answers) it still answers
    200 inside 3 s, and the real updater's version confirmation reads it and succeeds."""
    slow = []
    try:
        st.run(["docker", "pause", st.KEA_A, st.KEA_B])
        deadline = time.monotonic() + 30  # long enough for the background poller to be stuck on a Kea call
        while time.monotonic() < deadline:
            t0 = time.monotonic()
            try:
                import urllib.request

                with urllib.request.urlopen(f"{st.JEN_URL}/api/v1/health", timeout=3) as r:
                    body = json.loads(r.read())
                    status = r.status
            except Exception as e:  # a timeout IS the failure this scenario exists for
                slow.append(f"no answer inside 3 s: {type(e).__name__}: {e}")
                break
            took = time.monotonic() - t0
            if status != 200 or took >= 3 or not body.get("jen_version"):
                slow.append(f"status {status}, {took:.1f}s, body {body}")
            time.sleep(1)
        proc = st.dexec(st.UPDATER, "python3", "-c", UPDATER_PROBE, check=False, timeout=60)
        probe = result_of(proc.stdout)
    finally:
        st.run(["docker", "unpause", st.KEA_A, st.KEA_B], check=False)
    assert not slow, (
        "INVARIANT: /api/v1/health never waits on Kea (a self-update or restore polls it with a 5 s timeout "
        f"and rolls back a healthy result when it does): {slow[:3]}"
    )
    assert probe and probe["running"], (
        f"the updater could not read Jen's running version with Kea frozen: {proc.stdout[-500:]}{proc.stderr[-500:]}"
    )
    assert probe["confirmed"] == probe["running"], (
        f"INVARIANT: the updater's version confirmation succeeds while Kea is down: {probe}"
    )
    st.wait_for(
        lambda: st.kea_answers("kea-a") and st.kea_answers("kea-b"), timeout=60, what="both Kea answering again"
    )


# ── 12. a rolled-back server whose restart fails is a persistent rollback_failed ──

CHANGESET_REVERT_RESTART_FAILS = CHANGESET_B_DIES.replace("/tmp/s2-", "/tmp/s12-").replace(
    'emit({"status": res.status, "lines": [l[1] for l in res.lines]})',
    'emit({"status": res.status, "needs_hands": res.needs_hands, "lines": [l[1] for l in res.lines]})',
)


def test_12_a_revert_whose_restart_fails_is_a_persistent_rollback_failed(stack):
    """kea_changeset: A commits, B dies, A is put back on its config and then will not restart -> the outcome
    is rollback_failed naming kea-a, and the Servers banner still says so in a fresh request."""
    st.sh(st.JEN, "rm -f /tmp/s12-*", check=False)
    proc = st.jen_py_bg(CHANGESET_REVERT_RESTART_FAILS)
    try:
        st.sentinel_wait(st.JEN, "/tmp/s12-preflighted", timeout=120)
        # kea-a's daemon can no longer START, for good (the harness heal puts the real binary back). Config
        # validation (`kea-dhcp4 -t`) must still work, or the commit itself fails instead of the revert's restart.
        wrapper = """#!/bin/sh
for a in "$@"; do
  if [ "$a" = "-t" ]; then exec "$0.real" "$@"; fi
done
exit 1
"""
        st.dexec(
            st.KEA_A,
            "sh",
            "-c",
            'b="$(command -v kea-dhcp4)"; mv "$b" "$b.real" && cat > "$b" && chmod 755 "$b" && chown root:root "$b"',
            input=wrapper,
        )
        st.sshd_stop(st.KEA_B)
        st.sh(st.JEN, "touch /tmp/s12-proceed")
        stdout, stderr = proc.communicate(timeout=180)
    finally:
        if proc.poll() is None:
            proc.kill()
    result = result_of(stdout)
    assert result is not None, f"no result from the change set:\n{stdout[-1500:]}\n{stderr[-1500:]}"
    assert "raised" not in result, f"INVARIANT: apply_change never raises: {result}"
    assert result["status"] == "rollback_failed", (
        f"INVARIANT: a revert whose restart fails is rollback_failed, not aborted: {result}"
    )
    assert result["needs_hands"] == ["kea-a"], f"INVARIANT: the server that would not restart is named: {result}"
    assert st.kea_conf_bytes(st.KEA_A) == st.BASELINE[st.KEA_A], "kea-a's config on disk is the one it had before"

    out, _p = st.jen_py("from jen.services import kea_changeset as cs\nemit(cs.attention())\ncs.clear_attention()\n")
    note = emitted(out)
    # v5.65.10 (Q99 a): the note is a LIST of unresolved incidents, and an earlier scenario's clean rollback is
    # still on it until a clean run clears it; this scenario's own outcome is the newest one
    note = note["incidents"][-1] if note and note.get("incidents") else None
    assert note and note["status"] == "rollback_failed" and note["needs_hands"] == ["kea-a"], (
        f"INVARIANT: the outcome is persisted for the Servers banner: {note}"
    )


# ── 13. Presence against a real MQTT broker (v5.65.12, Q101 c) ───────────────

S13_MAC = "de:ad:be:ef:13:01"
S13_STATE_TOPIC = f"jen/presence/{S13_MAC.replace(':', '-')}"
S13_ATTRS_TOPIC = f"{S13_STATE_TOPIC}/attributes"
S13_DISCOVERY_TOPIC = f"homeassistant/device_tracker/jen_{S13_MAC.replace(':', '')}/config"
S13_LEASE_IP = "10.99.0.150"


def _mosq_capture(port, seconds=100, auth=False):
    """A background `mosquitto_sub -v -t '#'` against one listener, self-terminating via the
    container's own `timeout` so the `docker exec` process exits on its own; `communicate()`
    then returns everything it saw. Started BEFORE the action that should publish - a non-retained
    message received before a subscriber connects is gone forever, so this cannot be a
    look-back-afterward check the way the retained-discovery one below is. `auth=True` is the
    password-file listener (1884): it refuses an anonymous connection outright, so a subscriber
    with no credentials never even connects - and produces exactly the empty-output failure this
    once did, credentials or not, so its own real connection error only shows up in stderr, never
    asserted on until this comment was added."""
    cred = f"-u {st.MOSQ_USER} -P {st.MOSQ_PASS} " if auth else ""
    return st.dexec_bg(
        st.MOSQUITTO, "sh", "-c", f"timeout {seconds} mosquitto_sub -h localhost -p {port} {cred}-v -t '#'"
    )


def _mosq_once(port, topic, timeout=15, tls=False):
    """One retained (or imminent) message on `topic`, read by a FRESH subscription - proves a
    retained flag actually stuck, since a fresh client gets a retained message immediately with
    no publish needed. Returncode 0 with output means a message arrived; mosquitto_sub itself
    exits 0 after -C 1 delivers. `tls=True` is the 8883 listener: mosquitto_sub does not infer
    TLS from the port number, it needs --cafile telling it to negotiate TLS at all - without it,
    a plain CONNECT sent straight to a TLS-only listener just hangs until this call's own timeout.
    The server cert's CN is 'mosquitto' (the container's own hostname, matching its docker-compose
    `hostname:`), so a TLS connection verifies against that name specifically, not 'localhost' -
    self-CN-mismatch would otherwise fail verification even though it is the same broker."""
    extra = ["--cafile", "/mosquitto/certs/ca.pem"] if tls else []
    return st.dexec(
        st.MOSQUITTO,
        "mosquitto_sub",
        "-h",
        "mosquitto" if tls else "localhost",
        "-p",
        str(port),
        *extra,
        "-v",
        "-t",
        topic,
        "-C",
        "1",
        "-W",
        str(timeout),
        check=False,
        timeout=timeout + 10,
    )


def _ensure_presence_enabled():
    """Bundled plugins ship disabled - Settings -> Plugins writes an empty marker file and the
    NEXT app start loads + migrates it (jen/services/plugins.py::enable_plugin, load_plugins()
    inside create_app()). The one long-lived gunicorn worker `sys-jen` already runs never re-runs
    create_app() on its own, so a marker written from a short-lived jen_py script needs a real
    container restart before pr_tracked/pr_state/pr_sinks exist at all - it lives under
    CONTENT_DIR (/var/lib/jen by default), the container's own writable layer, which `docker
    restart` (unlike recreating the container) always keeps."""
    out, _p = st.jen_py("""
from jen.services import plugins as plugins_svc
already = plugins_svc._is_enabled("presence")
if not already:
    plugins_svc.enable_plugin("presence")
emit({"already": already})
""")
    if emitted(out) and emitted(out).get("already"):
        return
    st.run(["docker", "restart", st.JEN])
    st.wait_jen_healthy(timeout=150)
    # check_alerts()'s own loop checks Kea up/down 6x (~30s) before it EVER reaches the lease-diff
    # section, even on its first iteration - /api/v1/health answering healthy says nothing about
    # that loop's own progress. Without this wait, a lease written right after the restart can
    # land INSIDE that first, `first_run=True` pass, which seeds it into the baseline with no
    # diff and no event at all (lease.new never fires for something that was "always there").
    time.sleep(40)


def _setup_scenario13(web):
    """Track S13_MAC and configure the two sinks through Presence's own real routes (never raw
    SQL for the sinks: add_sink() is what encrypts the TLS/password credential)."""
    web.post(
        "/management/presence/track",
        data={"mac": S13_MAC, "label": "Scenario13 Phone"},
        page="/management/presence/",
    )
    # the password-file listener (1884): exercises add_sink's username+password path
    web.post(
        "/management/presence/sinks/add",
        data={
            "name": "s13-plain",
            "kind": "mqtt",
            "url": f"mqtt://{st.MOSQ_USER}@mosquitto:{st.MOSQ_AUTH_PORT}",
            "credential": st.MOSQ_PASS,
            "topic_prefix": "jen/presence",
        },
        page="/management/presence/",
    )
    # the TLS listener (8883, the stack's own throwaway CA - SSL_CERT_FILE on the jen container
    # trusts it): retain on, HA discovery on
    web.post(
        "/management/presence/sinks/add",
        data={
            "name": "s13-tls",
            "kind": "mqtt",
            "url": f"mqtts://mosquitto:{st.MOSQ_TLS_PORT}",
            "topic_prefix": "jen/presence",
            "retain": "1",
            "discovery": "1",
        },
        page="/management/presence/",
    )


def _lease_up(kea_db_insert_sql=None):
    out, _p = st.jen_py(f"""
import jen.models.db as db_mod
with db_mod.kea_db() as kdb, kdb.cursor() as cur:
    cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", ("{S13_MAC.replace(":", "").upper()}",))
    cur.execute(
        "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
        "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, %s)",
        ("{S13_LEASE_IP}", "{S13_MAC.replace(":", "").upper()}", "scenario13-phone"),
    )
    kdb.commit()
emit({{"ok": True}})
""")
    assert emitted(out) and emitted(out)["ok"]


def _lease_down():
    out, _p = st.jen_py(f"""
import jen.models.db as db_mod
with db_mod.kea_db() as kdb, kdb.cursor() as cur:
    cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", ("{S13_MAC.replace(":", "").upper()}",))
    kdb.commit()
emit({{"ok": True}})
""")
    assert emitted(out) and emitted(out)["ok"]


def _wait_pr_state(online, timeout=90):
    """Poll pr_state directly - proves the transition was RECORDED (the alert loop's ~30 s cycle
    noticed the lease change and Presence's subscriber ran), independent of whether the MQTT send
    itself succeeded, which is what the sink checks are for."""

    def _check():
        out, _p = st.jen_py(f"""
import jen.models.db as db_mod
with db_mod.jen_db() as jdb, jdb.cursor() as cur:
    cur.execute("SELECT online FROM pr_state WHERE mac=%s", ("{S13_MAC}",))
    row = cur.fetchone()
emit({{"online": bool(row["online"]) if row else None}})
""")
        row = emitted(out)
        return row is not None and row["online"] == online

    st.wait_for(_check, timeout=timeout, interval=3, what=f"pr_state.online == {online} for {S13_MAC}")


def test_13_presence_against_a_real_mqtt_broker(stack):
    """Presence's hand-rolled MQTT 3.1.1 client has never met a real broker before this scenario.
    INVARIANT: a tracked device's online/offline transitions reach a real eclipse-mosquitto over
    plain (password-authenticated) and TLS listeners, with the state/attributes/discovery topics,
    retained flag and HA device_tracker discovery schema all as documented; a paused broker sets
    the sink's last_error without an unhandled exception, and a transition after it recovers both
    publishes again and clears last_error."""
    _ensure_presence_enabled()
    web = st.Web().login()
    _setup_scenario13(web)

    # ── online: both sinks publish; the plain one is non-retained (must be caught live).
    # A generous timeout here specifically: the container restart above means the alert loop's
    # own process just started, so this is its first_run SEED cycle (no diff at all, since
    # nothing was tracked before the restart) followed by the first REAL diff cycle that actually
    # notices the lease - up to two ~30s cycles, not one. ──
    capture = _mosq_capture(st.MOSQ_AUTH_PORT, seconds=160, auth=True)
    try:
        _lease_up()
        _wait_pr_state(True, timeout=150)
        stdout, stderr = capture.communicate(timeout=170)
    finally:
        if capture.poll() is None:
            capture.kill()
    assert f"{S13_STATE_TOPIC} online" in stdout, (
        f"INVARIANT: the plain (password-auth) sink publishes the state topic with payload 'online' "
        f"(mosquitto_sub -v saw stdout:\n{stdout[-2000:]}\nstderr:\n{stderr[-1000:]})"
    )
    assert S13_ATTRS_TOPIC in stdout, f"INVARIANT: the attributes topic is published too (saw:\n{stdout[-2000:]})"

    # ── the TLS sink: retained discovery message, schema verified against HA's own docs ──
    disc = _mosq_once(st.MOSQ_TLS_PORT, S13_DISCOVERY_TOPIC, tls=True)
    assert disc.returncode == 0 and S13_DISCOVERY_TOPIC in disc.stdout, (
        f"INVARIANT: a FRESH subscriber gets the retained HA discovery message with no new publish "
        f"needed - the retain flag stuck (got rc={disc.returncode}, stdout={disc.stdout[-500:]!r}, "
        f"stderr={disc.stderr[-500:]!r})"
    )
    payload = json.loads(disc.stdout.split(" ", 1)[1])
    # Home Assistant's documented MQTT device_tracker discovery schema (home-assistant.io/integrations/
    # device_tracker.mqtt/, read 2026-09-27): state_topic, payload_home/payload_not_home (default
    # "home"/"not_home" - Presence deliberately overrides both to match what it actually PUBLISHES on
    # state_topic, "online"/"offline", not HA's defaults), json_attributes_topic.
    assert payload["state_topic"] == S13_STATE_TOPIC
    assert payload["payload_home"] == "online" and payload["payload_not_home"] == "offline"
    assert payload["json_attributes_topic"] == S13_ATTRS_TOPIC

    state_once = _mosq_once(st.MOSQ_TLS_PORT, S13_STATE_TOPIC, tls=True)
    assert state_once.returncode == 0 and "online" in state_once.stdout, (
        f"INVARIANT: the TLS sink's own state topic is retained too (retain=1 on this sink): "
        f"stdout={state_once.stdout!r}, stderr={state_once.stderr!r}"
    )

    # ── offline: the lease goes away, no OTHER active lease remains ──
    capture = _mosq_capture(st.MOSQ_AUTH_PORT, auth=True)
    try:
        _lease_down()
        _wait_pr_state(False)
        stdout, stderr = capture.communicate(timeout=110)
    finally:
        if capture.poll() is None:
            capture.kill()
    assert f"{S13_STATE_TOPIC} offline" in stdout, (
        f"INVARIANT: losing its only lease publishes 'offline' (saw stdout:\n{stdout[-2000:]}\nstderr:\n{stderr[-1000:]})"
    )

    # ── a paused broker: last_error is set, no unhandled exception, the worker survives ──
    logs_before = st.compose("logs", "--no-color", "sys-jen", check=False).stdout
    st.run(["docker", "pause", st.MOSQUITTO])
    try:
        _lease_up()
        st.wait_for(
            lambda: (
                emitted(
                    st.jen_py(
                        "import jen.models.db as db_mod\n"
                        "with db_mod.jen_db() as jdb, jdb.cursor() as cur:\n"
                        '    cur.execute("SELECT last_error FROM pr_sinks WHERE name=%s", ("s13-plain",))\n'
                        "    row = cur.fetchone()\n"
                        'emit({"last_error": row["last_error"] if row else None})\n'
                    )[0]
                )
                or {}
            ).get("last_error"),
            timeout=90,
            interval=3,
            what="s13-plain.last_error set while the broker is paused",
        )
    finally:
        st.run(["docker", "unpause", st.MOSQUITTO])
    logs_after = st.compose("logs", "--no-color", "sys-jen", check=False).stdout
    new_log = logs_after[len(logs_before) :] if logs_after.startswith(logs_before) else logs_after
    assert "Traceback (most recent call last)" not in new_log, (
        f"INVARIANT: a paused broker is a caught, logged failure, never an unhandled exception in "
        f"Jen's own log:\n{new_log[-3000:]}"
    )

    # ── recovery: the next transition publishes again and clears last_error ──
    _lease_down()
    _wait_pr_state(False, timeout=90)  # the paused-broker attempt above still recorded 'online'
    capture = _mosq_capture(st.MOSQ_AUTH_PORT, auth=True)
    try:
        _lease_up()
        _wait_pr_state(True)
        stdout, stderr = capture.communicate(timeout=110)
    finally:
        if capture.poll() is None:
            capture.kill()
    assert f"{S13_STATE_TOPIC} online" in stdout, (
        f"INVARIANT: the worker thread is still alive and sending after the broker comes back "
        f"(saw stdout:\n{stdout[-2000:]}\nstderr:\n{stderr[-1000:]})"
    )
    out, _p = st.jen_py(
        "import jen.models.db as db_mod\n"
        "with db_mod.jen_db() as jdb, jdb.cursor() as cur:\n"
        '    cur.execute("SELECT last_error FROM pr_sinks WHERE name=%s", ("s13-plain",))\n'
        "    row = cur.fetchone()\n"
        'emit({"last_error": row["last_error"] if row else "MISSING"})\n'
    )
    assert emitted(out) == {"last_error": None}, (
        f"INVARIANT: a successful send clears the sink's last_error (v1.0.4, Q101 c - it used to stay "
        f"stuck once set): {emitted(out)}"
    )


# ── 14. the helper's signed update needs no sudoers grant at all ──────────────


def test_14_signed_helper_update(stack):
    """v5.66.0 (Q103) - the helper's own `update` op installs a candidate ONLY when it carries
    a valid signature under the jen-kea-helper namespace and a strictly higher HELPER_VERSION -
    never because Jen asked. INVARIANT: kea-a, given a throwaway signer via
    /etc/jen-kea-helper/allowed_signers, accepts a signed v99 candidate with NO sudoers grant
    present anywhere (the stack fixture already removed the legacy grant on both hosts - this
    is the proof that a signed update genuinely needs none); kea-b (no extra signer there)
    refuses the identical signature; a flipped byte is refused even on kea-a, whose own grant
    stays absent and whose version stays wherever the last accepted update left it."""
    for node in (st.KEA_A, st.KEA_B):
        assert not st.file_exists(node, "/etc/sudoers.d/jen-kea"), (
            f"{node} still has the legacy grant - a signed update proves nothing if it might "
            "have fallen back to that path instead"
        )

    # A throwaway ed25519 key, generated INSIDE the Jen container (never the real release key).
    st.dexec(st.JEN, "sh", "-c", "rm -f /tmp/s14_key* && ssh-keygen -t ed25519 -N '' -f /tmp/s14_key -q")
    pub = st.dexec(st.JEN, "cat", "/tmp/s14_key.pub").stdout.strip().split()
    signers_line = f"release@jen {pub[0]} {pub[1]}"

    # kea-a ONLY gets the extra-signers file (root-owned, not group/other-writable) - kea-b
    # never sees this throwaway key at all.
    st.dexec(
        st.KEA_A,
        "sh",
        "-c",
        f"mkdir -p /etc/jen-kea-helper && printf '%s\\n' {json.dumps(signers_line)} "
        "> /etc/jen-kea-helper/allowed_signers && chown root:root /etc/jen-kea-helper/allowed_signers "
        "&& chmod 644 /etc/jen-kea-helper/allowed_signers",
    )

    out, _p = st.jen_py(
        """
import re, subprocess
from jen.services import kea_host

# The REAL, unpatched source - captured once, before anything below ever reassigns
# kea_host._helper_source_bytes, so every candidate this scenario builds (including the
# build-only one) is derived from what actually shipped, never from a previous candidate.
base_src = kea_host._helper_source_bytes()
real_version = int(re.search(rb"^HELPER_VERSION = (\\d+)$", base_src, re.M).group(1))
real_build = int(re.search(rb"^HELPER_BUILD = (\\d+)$", base_src, re.M).group(1))


def make_candidate(version, build=None):
    # kea_host._helper_source_bytes() already knows the real path (extensions.JEN_ROOT-
    # relative) - a Docker image is /opt/jen/jen-kea-helper (flat), a bare-metal install is
    # /opt/jen/current/app/jen-kea-helper (versioned) - never hardcode either one here.
    src = re.sub(rb"^HELPER_VERSION = \\d+$", f"HELPER_VERSION = {version}".encode(), base_src, count=1, flags=re.M)
    if build is not None:
        src = re.sub(rb"^HELPER_BUILD = \\d+$", f"HELPER_BUILD = {build}".encode(), src, count=1, flags=re.M)
    return src


def sign(data, name):
    path = f"/tmp/{name}"
    with open(path, "wb") as f:
        f.write(data)
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", "/tmp/s14_key", "-n", "jen-kea-helper", path],
        check=True, capture_output=True,
    )
    with open(path + ".sig", "rb") as f:
        return f.read()


# v5.66.0-beta.4 (Q106) - the FIRST build-only signed update: same HELPER_VERSION as what's
# already installed, HELPER_BUILD one higher. Built and sent BEFORE candidate99 below, while
# kea-a is still at its pristine as-shipped (real_version, real_build) - the ordering check
# this proves lives in HELPER_VERSION equal but HELPER_BUILD higher, not a version bump.
candidate_build_only = make_candidate(real_version, real_build + 1)
sig_build_only = sign(candidate_build_only, "s14_cand_build_only")

# v5.66.0-beta.7 (Q109) - HELPER_BUILD is checked independently of HELPER_VERSION now (the
# exact fix this Q makes): a candidate whose build isn't ALSO higher than what's currently
# installed is "already", full stop, regardless of how much higher its version is. kea-a is
# already at build real_build+1 from the step above, so candidate99's own build must clear
# that too, not just its version.
candidate99 = make_candidate(99, real_build + 2)
sig99 = sign(candidate99, "s14_cand99")

# A SEPARATE, higher version AND build for the flip case: kea-a already reports 99/real_build+2
# after the call above, so a candidate that doesn't clear BOTH would short-circuit at "already"
# before ever reaching the signed path (never exercising the bad-signature check at all).
# Flipping a byte far from the "HELPER_VERSION = 100" / "HELPER_BUILD = ..." lines keeps the
# declared version/build intact while invalidating the signature computed over the UNFLIPPED
# bytes.
candidate100 = make_candidate(100, real_build + 3)
sig100 = sign(candidate100, "s14_cand100")
flipped = bytearray(candidate100)
flipped[-20] ^= 0xFF
flipped = bytes(flipped)

servers = {s["name"]: s for s in extensions.KEA_SERVERS}
results = {}
with app.app_context():
    # install_helper() computes its OWN `target` from _helper_source() (text) via
    # _source_version() - not from _helper_source_bytes() - so both must report v99 or it
    # short-circuits at "already" (current == target == 7) before ever reaching the signed path.
    #
    # v5.66.0-beta.2 (Q104, item g) - Jen now pre-verifies a signature LOCALLY, against the
    # real embedded RELEASE_SIGNERS, before ever sending it; a throwaway key can never pass
    # that (by design - it's not the real key), so stubbing the composed helper_signature()
    # would no longer reach the signed path at all. Stub _local_helper_signature() instead,
    # the same way the OLD stub bypassed Jen's fetch/local-read machinery to exercise only the
    # REMOTE (Kea host) verification this scenario is actually about. _fetch_helper_signature()
    # is stubbed to None too, so a bad-signature retry (also new in this Q) doesn't reach out
    # to the real network from inside the test container.
    kea_host._helper_source = lambda: candidate_build_only.decode()
    kea_host._helper_source_bytes = lambda: candidate_build_only
    kea_host._local_helper_signature = lambda candidate: sig_build_only
    kea_host._fetch_helper_signature = lambda candidate: None
    results["kea_a_build_only"] = kea_host.install_helper(servers["kea-a"])
    results["kea_a_build_only_check"] = kea_host.check_helper(servers["kea-a"])

    kea_host._helper_source = lambda: candidate99.decode()
    kea_host._helper_source_bytes = lambda: candidate99
    kea_host._local_helper_signature = lambda candidate: sig99
    kea_host._fetch_helper_signature = lambda candidate: None
    results["kea_a_signed"] = kea_host.install_helper(servers["kea-a"])
    results["kea_b_signed"] = kea_host.install_helper(servers["kea-b"])

    kea_host._helper_source = lambda: flipped.decode("utf-8", "replace")
    kea_host._helper_source_bytes = lambda: flipped
    kea_host._local_helper_signature = lambda candidate: sig100  # signed over candidate100, not the flipped bytes
    results["kea_a_flipped"] = kea_host.install_helper(servers["kea-a"])
results["real_version"] = real_version
results["real_build"] = real_build
emit(results)
"""
    )
    results = emitted(out)

    real_version, real_build = results["real_version"], results["real_build"]
    # v5.66.0-beta.4 (Q106) - the build-only path: same HELPER_VERSION, HELPER_BUILD one
    # higher, accepted through the signed update exactly like a version bump is.
    assert results["kea_a_build_only"] == {
        "ok": True,
        "version": real_version,
        "code": "upgraded",
        "detail": "",
    }, results["kea_a_build_only"]
    assert results["kea_a_build_only_check"]["version"] == real_version
    assert results["kea_a_build_only_check"]["build"] == real_build + 1, results["kea_a_build_only_check"]

    assert results["kea_a_signed"] == {"ok": True, "version": 99, "code": "upgraded", "detail": ""}, results[
        "kea_a_signed"
    ]
    assert results["kea_b_signed"]["ok"] is False
    assert results["kea_b_signed"]["code"] == "bad-signature", results["kea_b_signed"]
    assert results["kea_b_signed"]["version"] == 7, "kea-b must still report its pre-update version"
    assert results["kea_a_flipped"]["ok"] is False
    assert results["kea_a_flipped"]["code"] == "bad-signature", results["kea_a_flipped"]
    assert results["kea_a_flipped"]["version"] == 99, "the earlier accepted update must stand"

    for node in (st.KEA_A, st.KEA_B):
        assert not st.file_exists(node, "/etc/sudoers.d/jen-kea"), (
            f"{node} must still have no legacy grant - nothing above should have needed or created one"
        )


# ── 15. Every bundled plugin's data survives a full recovery/restore (Q107) ───

S15_PLUGINS = ("dns-sync", "ipam", "network-discovery", "presence", "switchport", "watchdog", "wol")
S15_TABLES_BY_PLUGIN = {
    "dns-sync": ["ds_targets", "ds_records"],
    "ipam": ["ipam_subnets", "ipam_static_entries", "ipam_assignment_history", "ipam_conflict_state"],
    "network-discovery": ["nd_scan_jobs", "nd_scan_results", "nd_known_hosts", "nd_settings"],
    "presence": ["pr_tracked", "pr_state", "pr_sinks"],
    "switchport": ["sp_switches", "sp_ports", "sp_mac_ports"],
    "watchdog": ["wd_targets", "wd_state", "wd_checks"],
    "wol": ["wol_hosts"],
}
S15_ALL_TABLES = [t for tables in S15_TABLES_BY_PLUGIN.values() for t in tables]
S15_WOL_MAC = "de:ad:be:ef:15:01"
S15_PRESENCE_MAC = "de:ad:be:ef:15:02"
S15_CONFLICT_MAC = "de:ad:be:ef:15:03"
S15_SWITCH_HOST = "10.99.0.202"
S15_PASSPHRASE = "s15-recovery-passphrase-is-long-enough"


def _s15_enable_all_plugins():
    """Bundled plugins ship disabled — same reasoning as _ensure_presence_enabled, generalised
    to all seven in one pass (one restart, not seven)."""
    out, _p = st.jen_py(
        f"""
from jen.services import plugins as plugins_svc
restarted = False
for pid in {S15_PLUGINS!r}:
    if not plugins_svc._is_enabled(pid):
        plugins_svc.enable_plugin(pid)
        restarted = True
emit({{"restarted": restarted}})
"""
    )
    if emitted(out) and emitted(out)["restarted"]:
        st.run(["docker", "restart", st.JEN])
        st.wait_jen_healthy(timeout=150)
        time.sleep(40)  # see _ensure_presence_enabled: the alert loop's first_run seed pass


def _s15_query_one(sql):
    out, _p = st.jen_py(
        f"""
import jen.models.db as db_mod
with db_mod.jen_db() as jdb, jdb.cursor() as cur:
    cur.execute({sql!r})
    row = cur.fetchone()
emit({{"row": row}})
"""
    )
    r = emitted(out)
    return r["row"] if r else None


def _s15_resolve(hostname):
    out, _p = st.jen_py(
        f"""
import socket
emit({{"ip": socket.gethostbyname({hostname!r})}})
"""
    )
    return emitted(out)["ip"]


def _s15_lease_up(ip, mac, hostname):
    hex_mac = mac.replace(":", "").upper()
    out, _p = st.jen_py(
        f"""
import jen.models.db as db_mod
with db_mod.kea_db() as kdb, kdb.cursor() as cur:
    cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", ({hex_mac!r},))
    cur.execute(
        "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
        "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, %s)",
        ({ip!r}, {hex_mac!r}, {hostname!r}),
    )
    kdb.commit()
emit({{"ok": True}})
"""
    )
    assert emitted(out) and emitted(out)["ok"]


def _s15_seed_all_plugins(web):
    """Rows in every one of the 20 tables the 7 bundled plugins own, through each plugin's own
    real route wherever one exists. Five tables (ds_records, ipam_conflict_state,
    nd_scan_results, sp_ports, sp_mac_ports, wd_state, wd_checks — six, actually, across four
    plugins) are only ever written by a periodic job against real network I/O (a Pi-hole/
    AdGuard server, an SNMP switch, an nmap-scanned subnet, a pinged/probed host): for those the
    real top-level function runs for real (the actual plan/apply/record code, the actual DB
    writes) and only the ONE external I/O call is stood in — watchdog's probe is the one
    exception that needs no stand-in at all, since a plain TCP connect to the stack's own real
    MariaDB is exactly the real thing. Never raw SQL for anything a route or the plugin's own
    code would normally write."""
    # ── dns-sync: ds_targets (real route) ──
    web.post(
        "/network/dns-sync/targets/add",
        data={
            "name": "s15-adguard",
            "kind": "adguard",
            "url": "http://s15-fake-adguard.invalid",
            "domain": "lan",
            "sources": ["ipam"],
            "scope_all": "on",
        },
        page="/network/dns-sync/",
    )
    ds_target_id = _s15_query_one("SELECT id FROM ds_targets WHERE name='s15-adguard'")["id"]
    web.post(f"/network/dns-sync/targets/{ds_target_id}/preview", page="/network/dns-sync/")
    web.post(f"/network/dns-sync/targets/{ds_target_id}/toggle", page="/network/dns-sync/")

    # ── ipam: ipam_subnets, ipam_static_entries, ipam_assignment_history (real routes) ──
    web.post(
        "/network/ipam/subnets/add",
        data={"name": "s15-net", "cidr": "10.15.0.0/24"},
        page="/network/ipam/",
    )
    ipam_subnet_id = _s15_query_one("SELECT id FROM ipam_subnets WHERE name='s15-net'")["id"]
    web.post(
        f"/network/ipam/entry/u/{ipam_subnet_id}",
        data={"ip": "10.15.0.50", "ipam_status": "static", "label": "s15-static", "hostname": "s15host"},
        page="/network/ipam/",
    )
    # ipam_conflict_state: a real Kea lease and a designated-static IPAM entry at the same IP in
    # the same real, Kea-managed subnet — _check_conflicts() below finds it for real, no stand-in.
    # Order matters: _designation_blocker() (plugins/ipam/plugin.py) deliberately REFUSES to newly
    # mark an address static/planned while a live lease already holds it — exactly the conflict
    # this seeds on purpose — so the entry has to be designated FIRST, with the lease added after
    # (a raw DB insert, not a route, so it never goes through that same block).
    web.post(
        "/network/ipam/entry/kea/1",
        data={"ip": "10.99.0.200", "ipam_status": "static", "label": "s15-conflict"},
        page="/network/ipam/",
    )
    _s15_lease_up("10.99.0.200", S15_CONFLICT_MAC, "s15-conflict-lease")

    # ── network-discovery: nd_settings, nd_known_hosts (real routes) ──
    web.post("/network/discovery/schedule/1", data={"every_hours": "24"}, page="/network/discovery/")
    web.post(
        "/network/discovery/known/1",
        data={"ip": "10.99.0.201", "note": "s15 known host"},
        page="/network/discovery/",
    )

    # ── switchport: sp_switches (real route) ──
    web.post(
        "/network/switchport/switches/add",
        data={"name": "s15-sw", "host": S15_SWITCH_HOST},
        page="/network/switchport/",
    )

    # ── watchdog: wd_targets (real route) — a genuinely reachable target: the stack's own MariaDB ──
    mariadb_ip = _s15_resolve("mariadb")
    web.post(
        "/network/watchdog/targets/add",
        data={"ip": mariadb_ip, "probe": "tcp:3306", "label": "s15-mariadb"},
        page="/network/watchdog/",
    )

    # ── wol: wol_hosts (real route) ──
    web.post(
        "/management/wol/favourites/add",
        data={"mac": S15_WOL_MAC, "label": "s15 host"},
        page="/management/wol/",
    )

    # ── presence: pr_tracked, pr_sinks (real routes) ──
    web.post(
        "/management/presence/track",
        data={"mac": S15_PRESENCE_MAC, "label": "s15 phone"},
        page="/management/presence/",
    )
    web.post(
        "/management/presence/sinks/add",
        data={
            "name": "s15-sink",
            "kind": "mqtt",
            "url": f"mqtt://{st.MOSQ_USER}@mosquitto:{st.MOSQ_AUTH_PORT}",
            "credential": st.MOSQ_PASS,
            "topic_prefix": "jen/presence",
        },
        page="/management/presence/",
    )

    # ── the six tables no route writes: the real code, only the one external I/O call stood in ──
    script = """
import sys
diag = {}
with app.app_context():
    import jen.models.db as _dbm

    # presence: pr_state — the real per-transition writer, no I/O involved at all
    sys.modules["jen_plugin_presence"]._apply_transition("__PRESENCE_MAC__", True)

    # ipam: ipam_conflict_state — the real periodic check, no I/O to stand in (a real Kea lease
    # and a real designated-static entry at the same IP already exist)
    with _dbm.jen_db() as _db, _db.cursor() as _cur:
        _cur.execute("SELECT ip, subnet_id, entry_status FROM ipam_static_entries WHERE ip='10.99.0.200'")
        diag["ipam_entry_before"] = _cur.fetchone()
    with _dbm.kea_db() as _kdb, _kdb.cursor() as _kcur:
        _kcur.execute("SELECT INET_NTOA(address) AS ip FROM lease4 WHERE address=INET_ATON('10.99.0.200')")
        diag["lease_before"] = _kcur.fetchone()
    ipam_mod = sys.modules["jen_plugin_ipam"]
    diag["kea_conflicts_found"] = len(list(ipam_mod._kea_conflicts()))
    ipam_mod._check_conflicts()

    # watchdog: wd_state, wd_checks — the real tick, a real TCP probe against real MariaDB
    with _dbm.jen_db() as _db, _db.cursor() as _cur:
        _cur.execute("SELECT id, ip, probe, enabled, interval_min FROM wd_targets WHERE label='s15-mariadb'")
        diag["wd_target_before"] = _cur.fetchone()
    sys.modules["jen_plugin_watchdog"]._tick()

    # dns-sync: ds_records — the real sync (plan/apply/ledger), the remote Pi-hole/AdGuard
    # HTTP calls stood in (this stack runs neither)
    with _dbm.jen_db() as _db, _db.cursor() as _cur:
        _cur.execute(
            "SELECT id, enabled, previewed_at, sources, subnet_ids FROM ds_targets WHERE id=__DS_TARGET_ID__"
        )
        diag["ds_target_before"] = _cur.fetchone()
        _cur.execute("SELECT hostname, ip FROM ipam_static_entries WHERE hostname='s15host'")
        diag["ipam_source_row"] = _cur.fetchone()
    ds_mod = sys.modules["jen_plugin_dns-sync"]
    ds_mod._fetch_remote = lambda target, sid=None: {}
    ds_mod._apply_add = lambda target, sid, name, ip: None
    ds_mod._apply_remove = lambda target, sid, name, ip: None
    ds_mod._sync_one_target(__DS_TARGET_ID__)

    # network-discovery: nd_scan_jobs, nd_scan_results — the real reserve/run path, nmap's own
    # network scan stood in (nothing on this stack's own network is a subnet Jen owns)
    nd_mod = sys.modules["jen_plugin_network-discovery"]
    subnet_map = nd_mod._subnet_map()
    cidr = subnet_map[1]["cidr"]
    job_id = nd_mod._reserve_scan(1)
    diag["nd_job_id"] = job_id
    nd_mod._scan_subnet = lambda cidr: {
        "hosts": [{"ip": "10.99.0.210", "mac": "aa:bb:cc:dd:ee:15", "hostname": "s15-nmap-host", "vendor": ""}]
    }
    if job_id is not None:
        nd_mod._run_scan_job(1, cidr, job_id, trigger="manual")

    # switchport: sp_ports, sp_mac_ports — the real poll, the SNMP walk stood in
    sp_mod = sys.modules["jen_plugin_switchport"]
    with _dbm.jen_db() as _db, _db.cursor() as _cur:
        _cur.execute("SELECT id, host, community, vlan_indexing FROM sp_switches WHERE name='s15-sw'")
        switch = _cur.fetchone()
    diag["switch"] = switch

    def _fake_walk(host, community, oid):
        if oid == sp_mod.OID_DOT1D_BASE_PORT_IFINDEX:
            return "." + oid + ".1 = INTEGER: 1001"
        if oid == sp_mod.OID_IF_NAME:
            return "." + oid + '.1001 = STRING: "Gi1/0/1"'
        if oid == sp_mod.OID_IF_ALIAS:
            return "." + oid + '.1001 = STRING: "s15-uplink"'
        if oid == sp_mod.OID_DOT1Q_TP_FDB_PORT:
            return "." + oid + ".10.170.85.187.204.221.238 = INTEGER: 1"
        return ""

    sp_mod._run_snmpbulkwalk = _fake_walk
    if switch is not None:
        sp_mod._poll_switch(switch)
emit({"ok": True, "diag": diag})
"""
    script = script.replace("__PRESENCE_MAC__", S15_PRESENCE_MAC).replace("__DS_TARGET_ID__", str(ds_target_id))
    out, _p = st.jen_py(script, timeout=120)
    r = emitted(out)
    assert r and r.get("ok"), f"seeding the no-route plugin tables failed:\n{_p.stdout[-2000:]}\n{_p.stderr[-2000:]}"
    return r.get("diag", {})


S15_BUNDLE_IN_CONTAINER = "/var/lib/jen/s15.bundle"


def _s15_build_recovery_bundle(web):
    """Through the real route — never dbexport.export_jen()/recovery.build() called directly —
    the same /settings/databases/recovery-bundle a superadmin would actually click. Returns the
    HOST path it was saved to; copying it INTO the container has to wait until after the
    DB-recreate restart just ahead, so it is never done here."""
    import tempfile

    web.login()  # refresh recent-auth: the route is step-up gated and seeding above took a while
    r = web.post(
        "/settings/databases/recovery-bundle",
        data={"passphrase": S15_PASSPHRASE, "passphrase_confirm": S15_PASSPHRASE},
        page="/settings/databases?tab=recovery",
    )
    assert r.status_code == 200 and r.content, f"recovery bundle build failed: {r.status_code} {r.text[:500]}"
    with tempfile.NamedTemporaryFile(suffix=".tar.enc", delete=False) as f:
        f.write(r.content)
        return f.name


def _s15_copy_bundle_into_container(local_path):
    """/tmp is out — compose.yml mounts it as a size-capped tmpfs specifically so the real
    recovery-bundle code never depends on its room, and a `docker cp` placed there right after
    the DB-recreate restart still was not there by the time restore.run() looked for it (this
    scenario's own first two rounds). /var/lib/jen is CONTENT_DIR itself — the same real,
    persistent directory Jen's own recovery-bundle build uses for its temp file — not mounted
    specially at all, so there is nothing here to be wiped. `docker cp` still writes the file as
    root, though, and restore.run() reads it as www-data (the same user jen_py always execs as) —
    a plain `chown` after the copy is what actually closes this out."""
    st.run(["docker", "cp", local_path, f"{st.JEN}:{S15_BUNDLE_IN_CONTAINER}"])
    # the image's own default exec user is www-data (Dockerfile: USER www-data), which cannot
    # chown a file `docker cp` just wrote as root — ask for root explicitly.
    st.dexec(st.JEN, "chown", "www-data:www-data", S15_BUNDLE_IN_CONTAINER, user="root")


def _s15_drop_and_recreate_jen_db():
    """The disaster-recovery case this scenario exists for: not a truncate, a genuinely empty
    database — the state a freshly installed Jen (or one restored onto new hardware) starts
    from. jen.* grants are on the schema NAME, not tied to its existence, so they survive."""
    st.dexec(st.MARIADB, "mariadb", "-uroot", "-psys_root_pw", "-e", "DROP DATABASE jen; CREATE DATABASE jen;")


def _s15_restore():
    out, _p = st.jen_py(
        f"""
from jen.tools import restore
rc = restore.run({S15_BUNDLE_IN_CONTAINER!r}, {S15_PASSPHRASE!r}, no_stop=True)
emit({{"rc": rc}})
""",
        timeout=180,
    )
    r = emitted(out)
    assert r and r["rc"] == 0, f"restore failed: {r}\n{_p.stdout[-2000:]}\n{_p.stderr[-2000:]}"
    # restore.run()'s own per-table "restored"/warning lines - not asserted on here (rc==0 is
    # the pass/fail signal), but carried along so a later empty-tables failure can show them
    # instead of a bare count.
    return _p.stdout


def _s15_fingerprint():
    """What a failed restore must leave exactly as it found it: who the users are and which plugins the
    `plugins` table says are installed (the bundle restores seven rows into it; the empty database this
    scenario starts from has none). Compared before and after the failing restore below."""
    out, _p = st.jen_py(
        """
import jen.models.db as db_mod
with db_mod.jen_db() as jdb, jdb.cursor() as cur:
    cur.execute("SELECT username, role FROM users ORDER BY username")
    users = cur.fetchall()
    cur.execute("SELECT id FROM plugins ORDER BY id")
    plugins = [r["id"] for r in cur.fetchall()]
emit({"users": users, "plugins": plugins})
"""
    )
    r = emitted(out)
    assert r is not None, f"no fingerprint:\n{_p.stdout[-1500:]}\n{_p.stderr[-1500:]}"
    return r


def _s15_a_failing_plugin_restore_is_rolled_back():
    """v5.67.0-beta.11 (Q123, item d) — the case this scenario never had: a recovery whose plugin data
    does NOT come back. One bundled plugin's migration replay is made to fail (the plugin's own code is
    present, so this is an error, not a warning), through the real restore.run() against the real bundle.
    INVARIANT: it exits non-zero, names the plugin, says it rolled back, and Jen's database is as it was
    before — the restore is not allowed to print "restored", start Jen and exit 0 over missing data.
    Stood in: only the failure itself (plugins.run_plugin_migrations answering "failed" for wol)."""
    before = _s15_fingerprint()
    out, p = st.jen_py(
        f"""
from jen.services import plugins
from jen.tools import restore
_real = plugins.run_plugin_migrations
def _fail_wol(manifest):
    if manifest.get("id") == "wol":
        return False, "simulated migration failure", 0
    return _real(manifest)
plugins.run_plugin_migrations = _fail_wol
rc = restore.run({S15_BUNDLE_IN_CONTAINER!r}, {S15_PASSPHRASE!r}, no_stop=True)
emit({{"rc": rc}})
""",
        timeout=240,
    )
    r = emitted(out)
    assert r is not None, f"the failing restore never answered:\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}"
    assert r["rc"] == 1, (
        f"a restore that lost a present plugin's data must exit 1 (rolled back), got {r}\n"
        f"{p.stdout[-2000:]}\n{p.stderr[-2000:]}"
    )
    assert "wol" in p.stderr and "wol_hosts" in p.stderr, (
        f"the error must name the plugin and the table:\n{p.stderr[-2000:]}"
    )
    assert "rolled back" in p.stderr, f"the restore must say it rolled back:\n{p.stderr[-2000:]}"
    after = _s15_fingerprint()
    assert after == before, f"the failed restore left the database changed:\nbefore {before}\nafter  {after}"


def _s15_row_counts():
    """{table: row count} for every plugin table, plus the `plugins` table's own rows — used
    both right after seeding (proving the seed itself landed) and after restore (the actual
    INVARIANT this scenario exists for)."""
    out, _p = st.jen_py(
        f"""
import jen.models.db as db_mod
counts = {{}}
with db_mod.jen_db() as jdb, jdb.cursor() as cur:
    cur.execute("SELECT id, version FROM plugins")
    plugin_rows = cur.fetchall()
    for t in {S15_ALL_TABLES!r}:
        cur.execute("SELECT COUNT(*) AS n FROM `" + t + "`")
        counts[t] = cur.fetchone()["n"]
emit({{"counts": counts, "plugin_rows": plugin_rows}})
"""
    )
    r = emitted(out)
    assert r, "no result from the row-count check"
    return r


def _s15_verify_rows(restore_stdout=""):
    r = _s15_row_counts()
    empty = [t for t, n in r["counts"].items() if n < 1]
    assert not empty, (
        f"INVARIANT: every plugin table has at least one row after restore — empty: {empty}\n"
        f"plugins table after restore: {r['plugin_rows']}\n"
        f"restore.run()'s own output:\n{restore_stdout[-3000:]}"
    )


def _s15_verify_pages(web):
    pages = {
        "dns-sync": "/network/dns-sync/",
        "ipam": "/network/ipam/",
        "network-discovery": "/network/discovery/",
        "presence": "/management/presence/",
        "switchport": "/network/switchport/",
        "watchdog": "/network/watchdog/",
        "wol": "/management/wol/",
    }
    for pid, path in pages.items():
        r = web.get(path)
        assert r.status_code == 200, f"{pid}'s main page answered {r.status_code} after restore"


def test_15_bundled_plugin_data_survives_a_full_recovery_restore(stack):
    """None of the 20 tables the 7 bundled plugins own were ever part of a backup, export,
    recovery bundle, or restore before this Q — every one silently vanished on a restore, and
    worse, a restored plugin_schema_migrations row made the next start believe the missing
    table's migration had already run, so it was never recreated either. INVARIANT: every
    plugin's schema AND its rows come back — through the real recovery-bundle route, a REAL
    empty-then-recreated Jen database (not a truncate), and the real restore.run() — and every
    plugin's own page still answers once Jen is back up."""
    _s15_enable_all_plugins()
    web = st.Web().login()
    seed_diag = _s15_seed_all_plugins(web)

    seeded = _s15_row_counts()
    empty_before_export = [t for t, n in seeded["counts"].items() if n < 1]
    assert not empty_before_export, (
        f"seeding itself never landed a row for: {empty_before_export} — "
        f"plugins table: {seeded['plugin_rows']}\ndiagnostics: {seed_diag}"
    )

    bundle_path = _s15_build_recovery_bundle(web)

    _s15_drop_and_recreate_jen_db()
    st.run(["docker", "restart", st.JEN])
    st.wait_jen_healthy(timeout=150)

    _s15_copy_bundle_into_container(bundle_path)
    _s15_a_failing_plugin_restore_is_rolled_back()
    restore_stdout = _s15_restore()

    # the restored `plugins` rows say every plugin is enabled again, but the one long-lived
    # gunicorn worker only picks that up (blueprints, routes) on its own next start — same
    # reasoning as _ensure_presence_enabled.
    st.run(["docker", "restart", st.JEN])
    st.wait_jen_healthy(timeout=150)

    _s15_verify_rows(restore_stdout)
    web2 = st.Web().login()
    _s15_verify_pages(web2)


# ── 16. investigation logging: on, reloaded, watched, put back ───────────────


def _s_enable_investigation_logging(web):
    """The superadmin's toggle (v5.68.0-beta.30, Q167): investigation logging is early access and off by default."""
    r = web.post(
        "/settings/infrastructure/investigation-logging-enabled", data={"enable": "true"}, page="/settings/kea"
    )
    assert r.status_code == 200 and "switched on" in r.text, (
        "INVARIANT: the superadmin can switch investigation logging on"
    )


S16_MAC = "02:50:00:00:16:01"
S16_SEND = r"""
import socket, struct
mac = bytes.fromhex("025000001601")
def opt(code, data):
    return bytes([code, len(data)]) + data
header = struct.pack("!BBBBIHH4s4s4s4s16s64s128s4s", 1, 1, 6, 1, 0x16000, 0, 0x8000, bytes(4), bytes(4), bytes(4),
                     socket.inet_aton("10.99.0.1"), mac.ljust(16, b"\0"), bytes(64), bytes(128), b"\x63\x82\x53\x63")
body = opt(53, b"\x01") + opt(61, b"\x01" + mac) + opt(12, b"s16-host") + opt(60, b"s16-vendor") + opt(55, bytes([1, 3, 6])) + b"\xff"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(header + body, ("kea-a", 67))
"""


def _s16_discover():
    st.dexec(st.JEN, "python3", "-", input=S16_SEND)
    time.sleep(3)


def _s16_count(needle):
    out = st.dexec(st.KEA_A, "sh", "-c", f"grep -c {needle} {st.KEA_LOG} || true").stdout.strip()
    return int(out or 0)


def _s16_pids():
    return st.dexec(st.KEA_A, "pgrep", "-x", "kea-dhcp4").stdout.split()


def test_16_investigation_logging_turns_on_reloads_shows_the_classes_and_is_put_back(stack):
    """Investigation logging: turned on for one server through apply_change it reaches the running daemon by
    config-reload (same process, no restart), a real DISCOVER then shows its class assignments in Trace and its packet
    options in Explain, and the sweep puts the level back after the deadline (the clock is the one stand-in: the
    sweep is called with a time six minutes on instead of waiting them out). Since 5.68.0-beta.30 it is opt-in: off by default, switched on by a superadmin under Settings -> Kea."""
    web = st.Web().login()
    off = web.post("/servers/1/investigation-logging/on", data={"minutes": "5", "back": "servers"}, page="/servers")
    assert "not switched on" in off.text, (
        "INVARIANT: investigation logging is off by default and turning it on is refused"
    )
    assert "investigation-logging/on" not in web.get("/servers").text, (
        "INVARIANT: with it off, no Turn on button is rendered"
    )
    _s_enable_investigation_logging(web)
    assert "investigation-logging/on" in web.get("/servers").text, "INVARIANT: switched on, the buttons are there"
    pids = _s16_pids()
    assert pids, "kea-dhcp4 is running on kea-a"
    before_classes = _s16_count("DHCP4_CLASSES_ASSIGNED")

    r = web.post("/servers/1/investigation-logging/on", data={"minutes": "5", "back": "servers"}, page="/servers")
    assert r.status_code == 200
    conf = st.kea_conf_bytes(st.KEA_A)
    assert '"jen-investigation"' in conf and '"debuglevel": 55' in conf, (
        f"INVARIANT: turning it on writes the DEBUG level and its restore record into the config: {conf[-600:]}"
    )
    assert _s16_pids() == pids, "INVARIANT: the new level reached the running daemon by config-reload, not by a restart"
    assert "Investigation logging is on for kea-a" in web.get("/servers").text, (
        "INVARIANT: the banner shows while it is on"
    )

    _s16_discover()
    assert _s16_count("DHCP4_CLASSES_ASSIGNED") > before_classes, (
        "INVARIANT: at DEBUG 55 Kea logs the class assignments"
    )
    trace = web.get(f"/tools/trace?mac={S16_MAC}&server=1").text
    assert "DHCP4_CLASSES_ASSIGNED" in trace, "INVARIANT: Trace shows the class assignment Kea logged"
    watch = web.get(f"/tools/trace?mac={S16_MAC}&server=1&watch=1&t=0", headers={"HX-Request": "true"}).text
    assert 'hx-trigger="every 3s"' in watch, "INVARIANT: the live watch polls every 3 seconds"
    explain = web.get(f"/tools/explain?mac={S16_MAC}&subnet=1").text
    assert "s16-vendor" in explain and "packet dump" in explain, (
        "INVARIANT: Explain's inputs come from the packet dump Kea logged"
    )

    out, _p = st.jen_py(
        """
from datetime import datetime, timedelta, timezone
from jen.services import investigation_logging as inv
with app.app_context():
    emit(inv.sweep(now=datetime.now(timezone.utc) + timedelta(minutes=6)))
"""
    )
    swept = emitted(out)
    assert swept["restored"] == ["kea-a"], f"INVARIANT: the sweep restores an expired entry: {swept}"
    conf = st.kea_conf_bytes(st.KEA_A)
    assert '"jen-investigation"' not in conf and '"debuglevel": 55' not in conf and '"severity": "INFO"' in conf, (
        f"INVARIANT: the restore puts the previous level back and removes the marker: {conf[-600:]}"
    )
    assert _s16_pids() == pids, "INVARIANT: the restore is a reload too"
    after_restore = _s16_count("DHCP4_CLASSES_ASSIGNED")
    _s16_discover()
    assert _s16_count("DHCP4_CLASSES_ASSIGNED") == after_restore, (
        "INVARIANT: after the restore Kea no longer logs at DEBUG"
    )
    # The sweep above ran in a second process, so the web process's 30 s settings cache may still hold the old index for a moment
    # (in the real app the scheduler and the web threads are one process and the write invalidates it) - the second stand-in.
    for _ in range(45):
        if "Investigation logging is on" not in web.get("/servers").text:
            break
        time.sleep(1)
    else:
        raise AssertionError("INVARIANT: once the sweep has restored it the banner goes away")


# ── 18. the Problems inbox: a client Kea NAKs is in the inbox within one sweep, and its Investigate link resolves ──────────────
S18_MAC = "02:50:00:00:18:01"
S18_SEND = r"""
import socket, struct, time
server = socket.inet_aton(socket.gethostbyname("kea-a"))
def opt(code, data):
    return bytes([code, len(data)]) + data
def packet(mac_hex, kind, xid, requested):
    mac = bytes.fromhex(mac_hex)
    header = struct.pack("!BBBBIHH4s4s4s4s16s64s128s4s", 1, 1, 6, 1, xid, 0, 0x8000, bytes(4), bytes(4), bytes(4),
                         socket.inet_aton("10.99.0.1"), mac.ljust(16, b"\0"), bytes(64), bytes(128), b"\x63\x82\x53\x63")
    body = opt(53, bytes([kind])) + opt(61, b"\x01" + mac) + opt(12, b"s18-host") + opt(55, bytes([1, 3, 6]))
    body += opt(50, socket.inet_aton(requested)) + opt(54, server)
    return header + body + b"\xff"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# a different client is granted 10.99.0.150 (a REQUEST that names the server and asks for a free pool address is ACKed) ...
sock.sendto(packet("025000001802", 3, 0x18100, "10.99.0.150"), ("kea-a", 67))
time.sleep(2)
# ... so the same request from the client under test is NAKed, three times (three transaction ids)
for i in range(3):
    sock.sendto(packet("025000001801", 3, 0x18001 + i, "10.99.0.150"), ("kea-a", 67))
    time.sleep(1)
"""

S18_CLEAN = """
from jen.models import db as d
with app.app_context():
    with d.jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM client_problems")
        cur.execute("DELETE FROM settings WHERE setting_key LIKE 'client_problems_wm:%' OR setting_key LIKE 'client_problems_clock:%'")
        cur.execute("DELETE FROM devices WHERE mac=%s", ("S18MAC",))
        S18_DEVICE
"""

S18_SWEEP = """
from jen.models import db as d
from jen.services import client_problems as cp
def rows():
    with d.jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT server_id, kind, `count`, subnet_id, resolved_at FROM client_problems WHERE mac=%s ORDER BY kind", ("S18MAC",))
        return cur.fetchall()
with app.app_context():
    first = cp.sweep()
    rows1 = rows()
    second = cp.sweep()
    emit({"first": first, "rows1": rows1, "second": second, "rows2": rows()})
"""


def test_17_a_client_kea_naks_is_in_the_problems_inbox_within_one_sweep(stack):
    """Problems inbox (scenario 18): three relayed requests for an address the server did not offer are NAKed by the real kea-dhcp4
    on kea-a; one sweep - the job the scheduler runs every five minutes, called directly (the one stand-in: nobody waits for the
    timer) - reads the log over SSH through the helper and puts the client in the inbox with its subnet; a second sweep over the same
    log adds nothing (the watermark); the page, the lazy answer, the dashboard widget and the Investigate link all resolve."""
    web = st.Web().login()
    device = (
        'cur.execute("INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, device_name, first_seen, last_seen) '
        "VALUES (%s, '10.99.0.199', 's18-host', 1, 's18 device', NOW(), NOW())\", (\"S18MAC\",))"
    )
    st.jen_py(S18_CLEAN.replace("S18_DEVICE", device).replace("S18MAC", S18_MAC))
    try:
        st.dexec(st.JEN, "python3", "-", input=S18_SEND)
        time.sleep(2)
        out, _p = st.jen_py(S18_SWEEP.replace("S18MAC", S18_MAC))
        got = emitted(out)
        naks = [r for r in got["rows1"] if r["kind"] == "nak" and r["server_id"] == 1]
        seen = st.dexec(st.KEA_A, "sh", "-c", f"grep -i '{S18_MAC}' {st.KEA_LOG} | tail -12 || true").stdout
        assert naks and naks[0]["count"] >= 1 and naks[0]["resolved_at"] is None, (
            f"INVARIANT: the NAK Kea sent is in the inbox after one sweep: {got}\nwhat kea-a logged for the client:\n{seen}"
        )
        assert naks[0]["subnet_id"] is None, (
            "INVARIANT: a NAK that names no address is NOT placed by where the client is now (v5.68.0-beta.9): the row is "
            "unattributed, so it is for callers who may see every subnet"
        )
        assert got["rows2"] == got["rows1"] and got["second"]["events"] == 0, (
            f"INVARIANT: a second sweep over the same log adds nothing (the watermark): {got}"
        )

        page = web.get("/problems")
        assert page.status_code == 200 and S18_MAC in page.text, "INVARIANT: the client is on the Problems page"
        assert f"/client?q={S18_MAC.replace(':', '%3A')}" in page.text, "INVARIANT: its row links to its investigation"
        assert web.get(f"/client?q={S18_MAC}").status_code == 200 and S18_MAC in web.get(f"/client?q={S18_MAC}").text, (
            "INVARIANT: the Investigate link resolves to the client"
        )
        assert web.get(f"/problems/answer?q={S18_MAC}").status_code == 200, "INVARIANT: the lazy answer renders"
        widget = web.get("/api/dashboard/catalog-data?widgets=problems").json()["problems"]
        assert widget["total"] >= 1 and S18_MAC in [t["who"] for t in widget["top"]], (
            f"INVARIANT: the dashboard widget lists it: {widget}"
        )
        filtered = web.get("/problems?server=1&kind=nak").text
        assert S18_MAC in filtered and "kea-a" in filtered, (
            "INVARIANT: the Servers page's link (server filter) finds it"
        )
    finally:
        st.jen_py(
            "from jen.models import db as d\nwith app.app_context():\n    with d.jen_db() as db, db.cursor() as cur:\n"
            f"        cur.execute('DELETE FROM client_problems')\n        cur.execute(\"DELETE FROM devices WHERE mac='{S18_MAC}'\")\n"
            "        cur.execute(\"DELETE FROM settings WHERE setting_key LIKE 'client_problems_wm:%' OR setting_key LIKE 'client_problems_clock:%'\")\n",
            check=False,
        )


# ── 19. the Kea host puts investigation logging back by itself ─────────────────
# v5.68.0-beta.29 (Q165). Nine betas restored the logger FROM JEN; this scenario takes Jen away three different ways after logging is on and asserts the HOST does it. The
# stand-ins, named: there is no systemd in a container, so `enable --now jen-kea-investigation.timer` starts a background loop that runs the real
# `jen-kea-helper --self-restore` every 5 s (tests/system/compose/kea-node/systemctl), and the clock is faked forward by rewriting the deadline in the host's own state file
# (a 5-minute session cannot be waited out). Everything else is real: Jen turns logging on through the web page, the helper is the one Jen installed, the restore is the
# real routine and the daemon re-reads its file on a real SIGHUP.

S19_LOGGER = r"""
import base64, json, urllib.request
req = urllib.request.Request("http://127.0.0.1:8004/", data=json.dumps({"command": "config-get"}).encode(),
                             headers={"Content-Type": "application/json", "Authorization": "Basic " + base64.b64encode(b"jen:jen_api_pw").decode()})
out = json.load(urllib.request.urlopen(req, timeout=8))
out = out[0] if isinstance(out, list) else out
loggers = (out.get("arguments") or {}).get("Dhcp4", {}).get("loggers", [])
entry = next((x for x in loggers if x.get("name") == "kea-dhcp4"), {})
print(json.dumps({"severity": entry.get("severity"), "debuglevel": entry.get("debuglevel"), "marker": "jen-investigation" in (entry.get("user-context") or {})}))
"""
S19_STATE = "/var/lib/jen-kea-helper/investigation-dhcp4.json"
S19_PAST = r"""
import json, datetime
p = "/var/lib/jen-kea-helper/investigation-dhcp4.json"
state = json.load(open(p))
state["until"] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)).isoformat(timespec="seconds")
json.dump(state, open(p, "w"))
print(state["until"])
"""


def _s19_logger():
    return json.loads(st.dexec(st.KEA_A, "python3", "-", input=S19_LOGGER).stdout.strip().splitlines()[-1])


def _s19_state():
    p = st.dexec(st.KEA_A, "cat", S19_STATE, check=False)
    return json.loads(p.stdout) if p.returncode == 0 and p.stdout.strip() else None


def _s19_on(web):
    r = web.post("/servers/1/investigation-logging/on", data={"minutes": "5", "back": "servers"}, page="/servers")
    assert r.status_code == 200
    conf = st.kea_conf_bytes(st.KEA_A)
    assert '"jen-investigation"' in conf, f"INVARIANT: turning it on writes the marker: {conf[-400:]}"
    logger = _s19_logger()
    assert logger["severity"] == "DEBUG" and logger["debuglevel"] == 55 and logger["marker"], (
        f"INVARIANT: the running daemon is at DEBUG 55: {logger}"
    )
    state = _s19_state()
    assert state and not state["restored_at"] and state["restore"], (
        f"INVARIANT: the Kea host holds its own record of the original level: {state}"
    )
    assert (
        st.dexec(st.KEA_A, "systemctl", "is-active", "jen-kea-investigation.timer", check=False).stdout.strip()
        == "active"
    ), "INVARIANT: the host's timer is running"


def _s19_deadline_passes():
    st.dexec(st.KEA_A, "python3", "-", input=S19_PAST)


def _s19_host_restored(pid):
    def done():
        logger = _s19_logger()
        state = _s19_state()
        conf = st.kea_conf_bytes(st.KEA_A)
        return (
            logger["severity"] != "DEBUG"
            and not logger["marker"]
            and '"jen-investigation"' not in conf
            and state
            and state["restored_at"]
            and state["how"] == "reload"
        )

    st.wait_for(done, timeout=60, interval=2, what="the Kea host to restore the logger by itself")
    assert st.dexec(st.KEA_A, "pgrep", "-x", "kea-dhcp4").stdout.split() == pid, (
        "INVARIANT: the host told the running daemon by SIGHUP - the process is the same one"
    )


def _s19_jen_back_and_clean(web):
    """Bring Jen back and let it settle: its sweep sees that the host already restored and drops the entry. The clock stand-in is the one of scenario 16 - the sweep is called
    with a time ten minutes on, because the deadline in Jen's own record is the real one and the host's was rewritten into the past."""
    st.wait_jen_healthy(timeout=180)
    out, _p = st.jen_py(
        """
from datetime import datetime, timedelta, timezone
from jen.services import investigation_logging as inv
with app.app_context():
    emit(inv.sweep(now=datetime.now(timezone.utc) + timedelta(minutes=10), full=True))
    emit([e["name"] for e in inv.active()])
"""
    )
    assert out[1] == [], f"INVARIANT: once Jen is back the host's restore is recognised and the entry goes: {out}"


def test_19_the_kea_host_puts_investigation_logging_back_with_jen_stopped_or_its_database_down_or_pointed_elsewhere(
    stack,
):
    """The Kea host restores investigation logging by itself: with Jen stopped, with Jen's database stopped, and with Jen's [kea_ssh] host pointed at another Kea."""
    web = st.Web().login()
    _s_enable_investigation_logging(web)
    pid = st.dexec(st.KEA_A, "pgrep", "-x", "kea-dhcp4").stdout.split()
    assert pid, "kea-dhcp4 is running on kea-a"
    try:
        # case 1 - Jen is not running at all
        _s19_on(web)
        _s19_deadline_passes()
        st.run(["docker", "stop", st.JEN])
        _s19_host_restored(pid)
        st.run(["docker", "start", st.JEN])
        _s19_jen_back_and_clean(web)

        # case 2 - Jen runs, its database does not (it cannot read its own record, let alone sweep)
        web = st.Web().login()
        _s19_on(web)
        _s19_deadline_passes()
        st.run(["docker", "stop", st.MARIADB])
        _s19_host_restored(pid)
        st.run(["docker", "start", st.MARIADB])
        st.wait_for(
            lambda: (
                st.dexec(st.MARIADB, "healthcheck.sh", "--connect", "--innodb_initialized", check=False).returncode == 0
            ),
            timeout=90,
            what="mariadb healthy again",
        )
        _s19_jen_back_and_clean(web)

        # case 3 - Jen's [kea_ssh] host is hand-edited to point at the OTHER Kea (kea-b): its settings no longer reach this one at all
        web = st.Web().login()
        _s19_on(web)
        _s19_deadline_passes()
        st.sh(st.JEN, "sed -i 's/^host = kea-a$/host = kea-b/' /etc/jen/jen.config")
        st.run(["docker", "restart", st.JEN])
        _s19_host_restored(pid)
        st.sh(st.JEN, "sed -i 's/^host = kea-b$/host = kea-a/' /etc/jen/jen.config")
        st.run(["docker", "restart", st.JEN])
        _s19_jen_back_and_clean(web)
    finally:
        st.dexec(st.JEN, "sed", "-i", "s/^host = kea-b$/host = kea-a/", "/etc/jen/jen.config", check=False)
        for container in (st.MARIADB, st.JEN):
            st.run(["docker", "start", container], check=False)
        with contextlib.suppress(Exception):
            st.wait_jen_healthy(timeout=180)


# ── 20. a failed tick does not stop the next one ────────────────────────────────────────────────────────────────────
def test_20_a_failed_restore_tick_exits_nonzero_and_the_next_tick_still_runs_and_finishes_the_job(stack):
    """v5.68.0-beta.30 (Q167): `--self-restore` exits 1 when a restore failed, and a systemd timer keeps scheduling a oneshot that exited nonzero (OnUnitActiveSec counts from the last activation,
    whatever its result). The stand-in loop does the same (the stand-in is named in scenario 19). The config the host must rewrite is moved away: every tick fails and says so in the host's state
    (`attempts` climbs, `last_error`), nothing is recorded as restored; moved back, the very next tick puts the logger back and the same daemon re-reads it."""
    web = st.Web().login()
    _s_enable_investigation_logging(web)
    pid = st.dexec(st.KEA_A, "pgrep", "-x", "kea-dhcp4").stdout.split()
    assert pid, "kea-dhcp4 is running on kea-a"
    held = st.KEA_CONF + ".held"
    try:
        _s19_on(web)
        _s19_deadline_passes()
        st.dexec(st.KEA_A, "mv", st.KEA_CONF, held)
        st.wait_for(
            lambda: (_s19_state() or {}).get("attempts", 0) >= 3,
            timeout=90,
            interval=2,
            what="three failed ticks (each one ran although the previous exited 1)",
        )
        state = _s19_state()
        assert not state["restored_at"] and state["last_error"], (
            f"INVARIANT: a failed restore is never recorded as done: {state}"
        )
        assert _s19_logger()["severity"] == "DEBUG", (
            "INVARIANT: the daemon is still at DEBUG while the restore cannot be done"
        )
    finally:
        st.dexec(st.KEA_A, "sh", "-c", f"[ -f {held} ] && mv {held} {st.KEA_CONF} || true", check=False)
    _s19_host_restored(pid)
    state = _s19_state()
    assert state["attempts"] >= 3 and state["needs_hand"] is False, (
        f"INVARIANT: a later success clears the hand flag: {state}"
    )
    _s19_jen_back_and_clean(web)
