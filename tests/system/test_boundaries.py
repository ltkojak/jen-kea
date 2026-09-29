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

candidate99 = make_candidate(99)
sig99 = sign(candidate99, "s14_cand99")

# A SEPARATE, higher version for the flip case: kea-a already reports 99 after the call
# above, so a candidate that ALSO declares 99 would short-circuit at "already" before ever
# reaching the signed path (never exercising the bad-signature check at all). Flipping a byte
# far from the "HELPER_VERSION = 100" line keeps the declared version intact while
# invalidating the signature computed over the UNFLIPPED bytes.
candidate100 = make_candidate(100)
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
