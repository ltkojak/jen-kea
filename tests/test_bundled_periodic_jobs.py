"""
tests/test_bundled_periodic_jobs.py
─────────────────────────────────────
v5.66.0-beta.9 (Q111) — the class of bug behind Host Watchdog's own `_tick()`
(v1.0.0 through v1.0.4: ran clean, wrote nothing, forever, because its SELECT
never fetched the one column its own pure `due_targets()` needed) gets a net.

Every bundled plugin with a `register_periodic` job is loaded for real against
a real, fully-built Jen app and a real test database (the same "enable every
plugin, build create_app(), inspect what actually registered" shape
tests/test_plugin_loading.py already established). Each plugin's own periodic
callback — the REAL function object `register_periodic` was handed, read back
from `jen.services.background._periodic` rather than called from a test-owned
stub — is invoked exactly once, after seeding one representative row through
that plugin's own tables (never a plugin-repo FakeDB: this runs against the
real jen_test database), with only the plugin's own network-touching
primitive(s) stubbed (ping/nmap/an AdGuard HTTP call/the neighbour-table
parse — the stubs answer, never raise).

Assertions: every job runs without raising, full stop. For the four plugins
whose job writes a state or history table when it actually does its work —
watchdog (wd_checks), network-discovery (nd_scan_results), dns-sync
(ds_records), presence (pr_state) — at least one row must exist afterward. A
job that runs clean and writes nothing over a seeded target is exactly the
failure this test exists to catch; ipam's conflict check and switchport's poll
only write when their own (harder to seed generically) conditions are met, so
only "ran without raising" is asserted for those two.

Needs the real database — a normal conftest test, not --noconftest.
"""

import json
import os
import sys

import jen.services.plugins as plugins_svc
from jen import extensions
from jen.models.db import jen_db
from jen.services import background


def _tables(db):
    with db.cursor() as cur:
        cur.execute("SHOW TABLES")
        return {next(iter(r.values())) for r in cur.fetchall()}


def _row_count(db, sql, params=()):
    with db.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()["n"]


def test_every_bundled_plugins_periodic_job_runs_and_writes(app, monkeypatch, tmp_path):
    monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", os.path.join(extensions.JEN_ROOT, "plugins"))
    monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "plugins-enabled"))

    shipped = plugins_svc.shipped_plugin_ids()
    assert shipped, "no bundled plugins found — PLUGIN_DIR_BUNDLED points at the wrong tree"
    for plugin_id in shipped:
        plugins_svc.enable_plugin(plugin_id)

    with jen_db() as db:
        tables_before = _tables(db)

    saved_loaded = dict(plugins_svc._loaded_plugins)
    plugins_svc._loaded_plugins.clear()
    saved_periodic = list(background._periodic)
    background._periodic.clear()
    # create_app() below re-runs AppConfig.apply(), which re-derives EVERY extensions.* global
    # from the real config file — overwriting the app fixture's own test values (extensions.
    # KEA_SERVERS's "Test Kea" name among them) for the rest of the process, not just this test.
    # A full snapshot/restore of the module's own __dict__ is the only way to undo that reliably
    # without hand-tracking every global AppConfig.apply() happens to touch.
    extensions_snapshot = dict(vars(extensions))

    seeded_lease4_hwaddrs = []
    seeded_jen_rows = []  # (table, where_col, where_val), deleted in this order at cleanup
    watchdog_label = "q111-watchdog-target"
    presence_mac = "aa:bb:cc:dd:ee:73"
    switch_name = "q111-switch"

    try:
        import jen as jen_pkg

        jen_pkg.create_app()

        jobs = {(j["plugin_id"], j["name"]): j["fn"] for j in background._periodic}
        expected = {
            ("watchdog", "probe-tick"),
            ("network-discovery", "scheduled-scans"),
            ("dns-sync", "reconcile"),
            ("presence", "neighbor-tick"),
            ("ipam", "conflict_check"),
            ("switchport", "poll"),
        }
        missing = expected - set(jobs)
        assert not missing, f"expected periodic job(s) never registered: {missing}"

        with jen_db() as db, db.cursor() as cur:
            # ── watchdog: one enabled target, the probe stubbed to answer up ──
            cur.execute(
                "INSERT INTO wd_targets (ip, mac, subnet_id, label, source, probe, interval_min, "
                "fails_to_down, enabled) VALUES (%s, %s, %s, %s, 'manual', 'ping', 5, 3, 1)",
                ("10.99.0.71", "aa:bb:cc:dd:ee:71", 1, watchdog_label),
            )
            wd_target_id = cur.lastrowid
            seeded_jen_rows.append(("wd_targets", "id", wd_target_id))

            # ── network-discovery: subnet 1 due for a scan ──
            cur.execute(
                "INSERT INTO nd_settings (subnet_id, every_hours) VALUES (%s, 1) ON DUPLICATE KEY UPDATE every_hours=1",
                (1,),
            )
            seeded_jen_rows.append(("nd_settings", "subnet_id", 1))

            # ── dns-sync: one enabled, previewed AdGuard target over subnet 1's leases ──
            cur.execute(
                "INSERT INTO ds_targets (name, kind, url, domain, sources, subnet_ids, enabled, previewed_at) "
                "VALUES (%s, 'adguard', %s, 'lan', 'leases', %s, 1, UTC_TIMESTAMP())",
                ("q111-dns-sync-target", "http://adguard.example.test", json.dumps([1])),
            )
            ds_target_id = cur.lastrowid
            seeded_jen_rows.append(("ds_targets", "id", ds_target_id))

            # ── presence: one tracked MAC, no pr_state row yet ──
            cur.execute(
                "INSERT INTO pr_tracked (mac, label, subnet_id) VALUES (%s, %s, %s)",
                (presence_mac, "q111-presence-target", 1),
            )
            seeded_jen_rows.append(("pr_tracked", "mac", presence_mac))

            # ── ipam: a genuine conflict — a live lease, no reservation, and a static entry
            # at the same address (the same rule _conflicts_in itself is pure-tested against) ──
            cur.execute(
                "INSERT INTO ipam_static_entries (ip, subnet_kind, subnet_id, label, entry_status, is_static) "
                "VALUES (%s, 'kea', %s, %s, 'static', 1)",
                ("10.99.0.74", 1, "q111-ipam-conflict"),
            )
            ipam_entry_id = cur.lastrowid
            seeded_jen_rows.append(("ipam_static_entries", "id", ipam_entry_id))

            # ── switchport: one enabled switch (its own SNMP walk is stubbed below) ──
            cur.execute(
                "INSERT INTO sp_switches (name, host, vlan_indexing, enabled) VALUES (%s, %s, 'none', 1)",
                (switch_name, "192.0.2.250"),
            )
            sp_switch_id = cur.lastrowid
            seeded_jen_rows.append(("sp_switches", "id", sp_switch_id))

            # lease4: dns-sync's own source, and the lease half of ipam's conflict
            for ip, hwaddr, hostname in (
                ("10.99.0.72", "AABBCCDDEE72", "q111dnssync"),
                ("10.99.0.74", "AABBCCDDEE74", "q111ipam"),
            ):
                cur.execute(
                    "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) "
                    "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 HOUR), 1, %s, 0)",
                    (ip, hwaddr, hostname),
                )
                seeded_lease4_hwaddrs.append(hwaddr)

        # ── stub each plugin's own network-touching primitive(s) ──
        wd_mod = sys.modules["jen_plugin_watchdog"]
        wd_mod._probe_target = lambda t: (True, 4, "")
        wd_mod._alert_transition = lambda target, new_state: None

        nd_mod = sys.modules["jen_plugin_network-discovery"]
        nd_mod._nmap_available = lambda: True
        nd_mod._scan_subnet = lambda cidr: {
            "hosts": [{"ip": "10.99.0.75", "mac": "aa:bb:cc:dd:ee:75", "hostname": "q111-scanned"}]
        }

        ds_mod = sys.modules["jen_plugin_dns-sync"]

        def _fake_http_call(method, url, headers=None, body=None, allow_self_signed=False):
            if url.endswith("/control/rewrite/list"):
                return 200, []
            return 200, None

        ds_mod._http_call = _fake_http_call

        pr_mod = sys.modules["jen_plugin_presence"]
        pr_mod._ip_binary = lambda: "/bin/true"
        pr_mod._local_networks = lambda ip_bin: ["10.99.0.0/24"]
        pr_mod._local_macs = lambda tracked, local_nets: tracked
        pr_mod.parse_neighbor_table = lambda text: {presence_mac: True}

        sp_mod = sys.modules["jen_plugin_switchport"]
        sp_mod._poll_switch = lambda switch: None

        # ── run every job exactly once ──
        for key in expected:
            try:
                jobs[key]()
            except Exception as e:
                raise AssertionError(f"periodic job {key} raised: {e!r}") from e

        # ── the class of bug this test exists for: did the job actually WRITE? ──
        with jen_db() as db:
            wd_checks = _row_count(db, "SELECT COUNT(*) AS n FROM wd_checks WHERE target_id=%s", (wd_target_id,))
            assert wd_checks >= 1, "watchdog's probe-tick ran but wrote no wd_checks row for the seeded target"

            nd_results = _row_count(
                db,
                "SELECT COUNT(*) AS n FROM nd_scan_results r JOIN nd_scan_jobs j ON j.id=r.job_id WHERE j.subnet_id=%s",
                (1,),
            )
            assert nd_results >= 1, "network-discovery's scheduled-scans ran but wrote no nd_scan_results row"

            ds_records = _row_count(db, "SELECT COUNT(*) AS n FROM ds_records WHERE target_id=%s", (ds_target_id,))
            assert ds_records >= 1, "dns-sync's reconcile ran but wrote no ds_records row for the seeded target"

            pr_state = _row_count(db, "SELECT COUNT(*) AS n FROM pr_state WHERE mac=%s", (presence_mac,))
            assert pr_state >= 1, "presence's neighbor-tick ran but wrote no pr_state row for the tracked mac"

            # ipam and switchport: only "ran without raising" is asserted (see module docstring) —
            # already covered by the loop above; nothing further to check here.

    finally:
        with jen_db() as db, db.cursor() as cur:
            for hwaddr in seeded_lease4_hwaddrs:
                cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (hwaddr,))
            cur.execute(
                "DELETE FROM wd_checks WHERE target_id IN (SELECT id FROM wd_targets WHERE label=%s)", (watchdog_label,)
            )
            cur.execute(
                "DELETE FROM wd_state WHERE target_id IN (SELECT id FROM wd_targets WHERE label=%s)", (watchdog_label,)
            )
            cur.execute(
                "DELETE FROM nd_scan_results WHERE job_id IN (SELECT id FROM nd_scan_jobs WHERE subnet_id=%s)", (1,)
            )
            cur.execute("DELETE FROM nd_scan_jobs WHERE subnet_id=%s", (1,))
            cur.execute("DELETE FROM pr_state WHERE mac=%s", (presence_mac,))
            cur.execute(
                "DELETE FROM sp_mac_ports WHERE switch_id IN (SELECT id FROM sp_switches WHERE name=%s)",
                (switch_name,),
            )
            for table, col, val in reversed(seeded_jen_rows):
                cur.execute(
                    f"DELETE FROM {table} WHERE {col}=%s",  # nosec B608 - table/col are fixed literals from this function's own tuples above, never request-derived
                    (val,),
                )

        plugins_svc._loaded_plugins.clear()
        plugins_svc._loaded_plugins.update(saved_loaded)
        background._periodic[:] = saved_periodic
        vars(extensions).clear()
        vars(extensions).update(extensions_snapshot)

        with jen_db() as db:
            tables_after = _tables(db)
            new_tables = tables_after - tables_before
            with db.cursor() as cur:
                for table in new_tables:
                    cur.execute(f"DROP TABLE IF EXISTS `{table}`")
                if "plugin_schema_migrations" not in new_tables:
                    # It already existed (another test's fixture created it first) — never drop a
                    # table this test doesn't own, just remove the rows THIS run inserted.
                    placeholders = ",".join(["%s"] * len(shipped))
                    cur.execute(
                        f"DELETE FROM plugin_schema_migrations WHERE plugin_id IN ({placeholders})",  # nosec B608 - a fixed-width %s placeholder list sized from len(shipped), never request-derived
                        tuple(shipped),
                    )
                for plugin_id in shipped:
                    cur.execute(
                        "DELETE FROM settings WHERE setting_key IN (%s, %s)",
                        (f"plugin_migrated_ok:{plugin_id}", f"plugin_migration_failed:{plugin_id}"),
                    )
