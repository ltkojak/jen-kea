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
            'b="$(command -v kea-dhcp4)"; mv "$b" "$b.real" && cat > "$b" && chmod 755 "$b"',
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
            'b="$(command -v kea-dhcp4)"; mv "$b" "$b.real" && cat > "$b" && chmod 755 "$b"',
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
    assert note and note["status"] == "rollback_failed" and note["needs_hands"] == ["kea-a"], (
        f"INVARIANT: the outcome is persisted for the Servers banner: {note}"
    )
