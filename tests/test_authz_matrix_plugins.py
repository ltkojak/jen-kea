"""
tests/test_authz_matrix_plugins.py
────────────────────────────────────
v5.65.2 (Q91 d) — the authorization matrix for the BUNDLED PLUGINS' client-facing routes.

tests/test_authz_matrix.py proves that a subnet-restricted caller sees no subnet-B client
through any core diagnostic surface. Plugin routes were structurally outside that invariant:
they registered after the surfaces were collected, `diagnostic_surface` was not exported to
them, and nothing scanned their files. Now they are inside it, and this module is the proof:
the SAME two subnets and the SAME B markers, run against a second app that has every bundled
plugin enabled, plus — for the routes that WRITE by id or address — a state check that the
request did not change a row in subnet B.

The recurring bug this round names: a route authorises on ONE thing (a `subnet_id` the caller
typed, or nothing at all for a by-id POST) and then acts on ANOTHER (the MAC's real subnet, a
row in a subnet the caller cannot see); and "no attributable subnet" is read as "allow".

A cell that FAILS TODAY is marked `xfail(strict=True)` with the release that fixes it (Q93 =
watchdog / dns-sync / IPAM, Q94 = switchport / wol / presence): strict, so the day the plugin
is fixed the cell turns red until the marker is removed — the marker is the to-do list, and
this file is what proves each fix. As of v5.65.5 every plugin fix has shipped and no cell is marked.

v5.65.8 (Q97 l) adds the other half of the invariant: TestAnAllowedCallerGetsAnAnswer, one row per
plugin API route with an UNRESTRICTED key expecting a 200 and a clean body. The refusal rows above
passed while IPAM's API answered every allowed caller with a 500, because nothing asked. Its three
cells were xfail(strict) tagged Q98 until IPAM 1.6.3 shipped (v5.65.9); none is marked now.
"""

import json
import os
import re
import shutil
import sys
import tempfile

import pytest

from jen import extensions
from jen.services import access
from tests.test_authz_matrix import (  # noqa: F401 - fixtures are used by name
    A_MAC,
    B_HOST,
    B_LEASE_IP,
    B_MAC,
    B_NAME,
    KEY_ROLES,
    MUST_NOT_SEE_B,
    SESSION_ROLES,
    _caller,
    _subnets,
    assert_no_marker,
    seeded,
)

# every test here runs on top of the shared two-subnet fixture
pytestmark = pytest.mark.usefixtures("seeded")


class FormBody(dict):
    """A row body sent as a form (`application/x-www-form-urlencoded`), for the routes that read
    `request.form`. A JSON body would leave the form empty, and the route would refuse it for
    being empty, which proves nothing about who may call it."""


N_MAC = "de:ad:be:ef:00:cd"  # a MAC Jen has never leased or reserved: no attributable subnet
NULL_LABEL = B_NAME + "-nullsubnet"  # contains the B marker
WD_B, WD_NULL = 9101, 9102
WOL_B, WOL_NULL = 9301, 9302
DS_B = 9201
SP_B = 9401
PR_SINK = 9501
IPAM_U = 9601

Q93 = "Q93 (watchdog 1.0.2 / dns-sync 1.0.2 / IPAM 1.6.1)"
Q94 = "Q94 (switchport 1.0.1 / wol 1.0.1 / presence 1.0.1)"


# ── a second app with every bundled plugin enabled ────────────────────────────


@pytest.fixture(scope="module")
def plugin_app():
    import jen as jen_pkg
    import jen.services.plugins as plugins_svc
    from jen.models.db import jen_db

    mp = pytest.MonkeyPatch()
    tmp = tempfile.mkdtemp(prefix="authz-plugins-")
    mp.setattr(extensions, "PLUGIN_DIR_BUNDLED", os.path.join(extensions.JEN_ROOT, "plugins"))
    mp.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", os.path.join(tmp, "plugins-enabled"))
    shipped = plugins_svc.shipped_plugin_ids()
    assert shipped, "no bundled plugins found"
    for plugin_id in shipped:
        plugins_svc.enable_plugin(plugin_id)

    with jen_db() as db, db.cursor() as cur:
        cur.execute("SHOW TABLES")
        tables_before = {next(iter(r.values())) for r in cur.fetchall()}
    saved_loaded = dict(plugins_svc._loaded_plugins)
    saved_surfaces = list(access.DIAGNOSTIC_SURFACES)
    plugins_svc._loaded_plugins.clear()

    # create_app() re-applies jen.config, overwriting the globals the test session patched
    # (KEA_SERVERS names, ...): put every extensions global back so no later test sees the difference
    saved_ext = {k: v for k, v in vars(extensions).items() if not k.startswith("__")}
    app = jen_pkg.create_app()
    for k, v in saved_ext.items():
        setattr(extensions, k, v)
    app.config.update({"TESTING": True, "SECRET_KEY": "test-secret-key-not-for-production", "WTF_CSRF_ENABLED": False})
    jen_pkg._ssl_configured_cache = False
    try:
        yield app
    finally:
        plugins_svc._loaded_plugins.clear()
        plugins_svc._loaded_plugins.update(saved_loaded)
        access.DIAGNOSTIC_SURFACES[:] = saved_surfaces
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW TABLES")
            tables_after = {next(iter(r.values())) for r in cur.fetchall()}
            new_tables = tables_after - tables_before
            for table in new_tables:
                cur.execute(f"DROP TABLE IF EXISTS `{table}`")
            if "plugin_schema_migrations" not in new_tables:
                marks = ",".join(["%s"] * len(shipped))
                cur.execute(f"DELETE FROM plugin_schema_migrations WHERE plugin_id IN ({marks})", tuple(shipped))
            for plugin_id in shipped:
                cur.execute(
                    "DELETE FROM settings WHERE setting_key IN (%s, %s)",
                    (f"plugin_migrated_ok:{plugin_id}", f"plugin_migration_failed:{plugin_id}"),
                )
        mp.undo()
        shutil.rmtree(tmp, ignore_errors=True)


def _wipe_created(cur):
    """Everything the mutation rows might have created, and the unmanaged-subnet seed."""
    cur.execute("DELETE FROM ipam_subnets WHERE id=%s OR name=%s", (IPAM_U, "created-by-matrix"))
    cur.execute("DELETE FROM ipam_static_entries WHERE label=%s", ("created-by-matrix",))
    cur.execute("DELETE FROM ds_targets WHERE name=%s", ("created-by-matrix",))
    cur.execute("DELETE FROM sp_switches WHERE name=%s", ("created-by-matrix",))
    cur.execute("DELETE FROM nd_scan_jobs WHERE subnet_id=2")
    cur.execute("DELETE FROM nd_settings WHERE subnet_id=2")
    cur.execute("DELETE FROM nd_known_hosts WHERE note=%s", ("created-by-matrix",))
    cur.execute("DELETE FROM wol_hosts WHERE label=%s", ("created-by-matrix",))


@pytest.fixture
def pclient(plugin_app):
    return plugin_app.test_client()


@pytest.fixture
def plugin_data(plugin_app, db):
    """Rows in each plugin's own tables that name subnet B (and one with no subnet at all)."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM wd_checks WHERE target_id IN (%s, %s)", (WD_B, WD_NULL))
        cur.execute("DELETE FROM wd_state WHERE target_id IN (%s, %s)", (WD_B, WD_NULL))
        cur.execute("DELETE FROM wd_targets WHERE id IN (%s, %s)", (WD_B, WD_NULL))
        cur.execute("DELETE FROM wol_hosts WHERE id IN (%s, %s)", (WOL_B, WOL_NULL))
        cur.execute("DELETE FROM pr_state WHERE mac IN (%s, %s)", (B_MAC, N_MAC))
        cur.execute("DELETE FROM pr_tracked WHERE mac IN (%s, %s)", (B_MAC, N_MAC))
        cur.execute("DELETE FROM ds_records WHERE target_id=%s", (DS_B,))
        cur.execute("DELETE FROM ds_targets WHERE id=%s", (DS_B,))
        cur.execute("DELETE FROM sp_mac_ports WHERE switch_id=%s", (SP_B,))
        cur.execute("DELETE FROM sp_ports WHERE switch_id=%s", (SP_B,))
        cur.execute("DELETE FROM sp_switches WHERE id=%s", (SP_B,))
        cur.execute("DELETE FROM pr_sinks WHERE id=%s OR name=%s", (PR_SINK, "created-by-matrix"))
        _wipe_created(cur)

        cur.execute(
            "INSERT INTO wd_targets (id, ip, mac, subnet_id, label, source, probe) VALUES "
            "(%s, '10.77.0.50', %s, 2, %s, 'manual', 'ping'), (%s, '192.0.2.77', NULL, NULL, %s, 'manual', 'ping')",
            (WD_B, B_MAC, B_NAME, WD_NULL, NULL_LABEL),
        )
        cur.execute(
            "INSERT INTO wd_checks (target_id, ok, rtt_ms, error) VALUES (%s, 0, NULL, 'timeout reaching 10.77.0.50')",
            (WD_B,),
        )
        cur.execute(
            "INSERT INTO wol_hosts (id, mac, ip, subnet_id, label) VALUES (%s, %s, '10.77.0.60', 2, %s), "
            "(%s, %s, NULL, NULL, %s)",
            (WOL_B, B_MAC, B_NAME, WOL_NULL, N_MAC, NULL_LABEL),
        )
        cur.execute(
            "INSERT INTO pr_tracked (mac, label, subnet_id, added_by) VALUES (%s, %s, 2, 'seed')", (B_MAC, B_NAME)
        )
        cur.execute(
            "INSERT INTO sp_switches (id, name, host, community) VALUES (%s, %s, '10.77.0.2', 'x')", (SP_B, B_NAME)
        )
        cur.execute("INSERT INTO sp_ports (switch_id, ifindex, ifname) VALUES (%s, 1, 'Gi0/1')", (SP_B,))
        cur.execute("INSERT INTO sp_mac_ports (mac, switch_id, ifindex, vlan) VALUES (%s, %s, 1, 10)", (N_MAC, SP_B))
        cur.execute(
            "INSERT INTO pr_sinks (id, name, kind, url, enabled) VALUES (%s, 'matrix-sink', 'http', 'http://192.0.2.1/hook', 1)",
            (PR_SINK,),
        )
        cur.execute(
            "INSERT INTO ipam_subnets (id, name, cidr) VALUES (%s, %s, '10.55.5.0/24')", (IPAM_U, B_NAME + "-unmanaged")
        )
        cur.execute(
            "INSERT INTO ds_targets (id, name, kind, url, domain, sources, subnet_ids, enabled, previewed_at) VALUES "
            "(%s, %s, 'pihole', 'http://10.77.0.53', 'lan', 'leases,reservations', '[2]', 1, NOW())",
            (DS_B, B_NAME),
        )
        cur.execute(
            "INSERT INTO ds_records (target_id, name, ip, source) VALUES (%s, %s, %s, 'lease')",
            (DS_B, B_HOST, B_LEASE_IP),
        )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM wd_checks WHERE target_id IN (%s, %s)", (WD_B, WD_NULL))
        cur.execute("DELETE FROM wd_state WHERE target_id IN (%s, %s)", (WD_B, WD_NULL))
        cur.execute("DELETE FROM wd_targets WHERE id IN (%s, %s) OR label=%s", (WD_B, WD_NULL, "created-by-matrix"))
        cur.execute("DELETE FROM wol_hosts WHERE id IN (%s, %s)", (WOL_B, WOL_NULL))
        cur.execute("DELETE FROM pr_state WHERE mac IN (%s, %s)", (B_MAC, N_MAC))
        cur.execute("DELETE FROM pr_tracked WHERE mac IN (%s, %s)", (B_MAC, N_MAC))
        cur.execute("DELETE FROM ds_records WHERE target_id=%s", (DS_B,))
        cur.execute("DELETE FROM ds_targets WHERE id=%s", (DS_B,))
        cur.execute("DELETE FROM sp_mac_ports WHERE switch_id=%s", (SP_B,))
        cur.execute("DELETE FROM sp_ports WHERE switch_id=%s", (SP_B,))
        cur.execute("DELETE FROM sp_switches WHERE id=%s", (SP_B,))
        cur.execute("DELETE FROM pr_sinks WHERE id=%s OR name=%s", (PR_SINK, "created-by-matrix"))
        _wipe_created(cur)
    db.commit()


@pytest.fixture
def wol_sends(plugin_app):
    """Every magic packet the WoL plugin would have sent, recorded instead of sent."""
    mod = sys.modules["jen_plugin_wol"]
    sent = []
    real = mod._send_wake
    mod._send_wake = lambda mac, cidr, secureon: sent.append(mac)
    mod._last_sent.clear()
    yield sent
    mod._send_wake = real
    mod._last_sent.clear()


# ── state checks (each returns "" when nothing changed, else what did) ────────


def _one(db, sql, params=()):
    db.commit()  # a fresh snapshot: the request ran on another connection
    with db.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def _wd_b_untouched(db, ctx):
    row = _one(db, "SELECT enabled FROM wd_targets WHERE id=%s", (WD_B,))
    if row is None:
        return "the subnet-B watchdog target was DELETED"
    return "" if row["enabled"] == 1 else "the subnet-B watchdog target was toggled"


def _wol_b_favourite_exists(db, ctx):
    return "" if _one(db, "SELECT id FROM wol_hosts WHERE id=%s", (WOL_B,)) else "the subnet-B favourite was DELETED"


def _no_wake_sent(db, ctx):
    return "" if not ctx["sends"] else f"a wake packet was sent to {ctx['sends']}"


def _pr_b_still_tracked(db, ctx):
    return (
        ""
        if _one(db, "SELECT mac FROM pr_tracked WHERE mac=%s", (B_MAC,))
        else "the subnet-B tracked device was UNTRACKED"
    )


def _pr_b_not_retagged(db, ctx):
    row = _one(db, "SELECT subnet_id, label FROM pr_tracked WHERE mac=%s", (B_MAC,))
    if not row:
        return "the subnet-B tracked device is gone"
    if row["subnet_id"] != 2 or row["label"] != B_NAME:
        return f"the B device was re-labelled/re-tagged to {row['label']!r} in subnet {row['subnet_id']}"
    return ""


def _wd_nothing_created(db, ctx):
    return (
        ""
        if not _one(db, "SELECT id FROM wd_targets WHERE label=%s", ("created-by-matrix",))
        else "a watchdog target was created outside the key's subnets"
    )


def _ds_b_untouched(db, ctx):
    row = _one(db, "SELECT enabled FROM ds_targets WHERE id=%s", (DS_B,))
    if row is None:
        return "the subnet-B DNS-sync target was DELETED"
    return "" if row["enabled"] == 1 else "the subnet-B DNS-sync target was toggled"


def _ds_nothing_created(db, ctx):
    return (
        ""
        if not _one(db, "SELECT id FROM ds_targets WHERE name=%s", ("created-by-matrix",))
        else "a DNS Sync target was created by a subnet-scoped caller"
    )


def _wol_b_intact(db, ctx):
    row = _one(db, "SELECT label FROM wol_hosts WHERE id=%s", (WOL_B,))
    if row is None:
        return "the subnet-B favourite is gone"
    if row["label"] != B_NAME:
        return f"the subnet-B favourite was re-labelled to {row['label']!r}"
    if _one(db, "SELECT id FROM wol_hosts WHERE label=%s", ("created-by-matrix",)):
        return "a favourite was created outside the caller's subnets"
    return ""


def _sp_b_untouched(db, ctx):
    row = _one(db, "SELECT enabled FROM sp_switches WHERE id=%s", (SP_B,))
    if row is None:
        return "the subnet-B switch was DELETED"
    if row["enabled"] != 1:
        return "the subnet-B switch was paused"
    port = _one(db, "SELECT is_uplink FROM sp_ports WHERE switch_id=%s AND ifindex=1", (SP_B,))
    if port is not None and port["is_uplink"] is not None:
        return "a port of the subnet-B switch was re-classified"
    if _one(db, "SELECT id FROM sp_switches WHERE name=%s", ("created-by-matrix",)):
        return "a switch was created by a subnet-scoped caller"
    return ""


def _ipam_unmanaged_untouched(db, ctx):
    if _one(db, "SELECT id FROM ipam_subnets WHERE name=%s", ("created-by-matrix",)):
        return "an unmanaged subnet was created by a subnet-scoped caller"
    return "" if _one(db, "SELECT id FROM ipam_subnets WHERE id=%s", (IPAM_U,)) else "an unmanaged subnet was DELETED"


def _ipam_no_entry(db, ctx):
    return (
        ""
        if not _one(db, "SELECT id FROM ipam_static_entries WHERE label=%s", ("created-by-matrix",))
        else "an IPAM entry was written in a subnet the caller cannot access"
    )


def _nd_nothing(db, ctx):
    if _one(db, "SELECT id FROM nd_scan_jobs WHERE subnet_id=2"):
        return "a scan was queued for a subnet the caller cannot access"
    if _one(db, "SELECT subnet_id FROM nd_settings WHERE subnet_id=2"):
        return "a scan schedule was set for a subnet the caller cannot access"
    if _one(db, "SELECT id FROM nd_known_hosts WHERE note=%s", ("created-by-matrix",)):
        return "a host was marked known by a caller who cannot access its subnet"
    return ""


# ── the rows ─────────────────────────────────────────────────────────────────

UI = ("viewer_A", "admin_A")
KEYS = ("key_read", "key_write")
_DENY = {200, 302, 403, 404}  # a refusal may be a redirect, a page carrying a notice, a 403 or a 404

# (label, method, path, json/form body, roles the row applies to, allowed codes, typed values,
#  state check | None, {role: xfail reason})
ROWS = [
    # ── Host Watchdog ────────────────────────────────────────────────────────
    ("watchdog page", "GET", "/network/watchdog/", None, UI, {200}, (), None, {}),
    (
        "watchdog api list (a target with no subnet carries the B marker in its label)",
        "GET",
        "/api/v1/plugins/watchdog/targets",
        None,
        KEYS,
        {200},
        (),
        None,
        {},
    ),
    (
        "watchdog target history (B's target, with an error naming a B address)",
        "GET",
        f"/network/watchdog/targets/{WD_B}/history",
        None,
        UI,
        _DENY,
        (),
        None,
        {},
    ),
    (
        "watchdog toggle B's target",
        "POST",
        f"/network/watchdog/targets/{WD_B}/toggle",
        None,
        UI,
        _DENY,
        (),
        _wd_b_untouched,
        {},
    ),
    (
        "watchdog delete B's target",
        "POST",
        f"/network/watchdog/targets/{WD_B}/delete",
        None,
        UI,
        _DENY,
        (),
        _wd_b_untouched,
        {},
    ),
    (
        "watchdog api add a target outside every subnet (no attributable subnet)",
        "POST",
        "/api/v1/plugins/watchdog/targets",
        {"ip": "192.0.2.99", "label": "created-by-matrix", "probe": "ping"},
        ("key_write",),
        {403, 404},
        (),
        _wd_nothing_created,
        {},
    ),
    (
        "watchdog api add a target inside subnet B",
        "POST",
        "/api/v1/plugins/watchdog/targets",
        {"ip": "10.77.0.99", "label": "created-by-matrix", "probe": "ping"},
        ("key_write",),
        {403, 404},
        (),
        _wd_nothing_created,
        {},
    ),
    # ── Wake & Actions ───────────────────────────────────────────────────────
    ("wol page", "GET", "/management/wol/", None, UI, {200}, (), None, {}),
    (
        "wol delete B's favourite",
        "POST",
        f"/management/wol/favourites/{WOL_B}/delete",
        None,
        UI,
        _DENY,
        (),
        _wol_b_favourite_exists,
        {},
    ),
    (
        "wol wake B's favourite",
        "POST",
        f"/management/wol/favourites/{WOL_B}/wake",
        None,
        UI,
        _DENY,
        (),
        _no_wake_sent,
        {},
    ),
    (
        "wol wake a B MAC from a row, naming subnet A in the query string",
        "POST",
        f"/management/wol/wake?mac={B_MAC}&subnet_id=1",
        None,
        UI,
        _DENY,
        (B_MAC,),
        _no_wake_sent,
        {},
    ),
    (
        "wol api wake a B MAC",
        "POST",
        "/api/v1/plugins/wol/wake",
        {"mac": B_MAC},
        ("key_write",),
        {403, 404},
        (B_MAC,),
        _no_wake_sent,
        {},
    ),
    (
        "wol api wake a MAC with no attributable subnet",
        "POST",
        "/api/v1/plugins/wol/wake",
        {"mac": N_MAC},
        ("key_write",),
        {403, 404},
        (N_MAC,),
        _no_wake_sent,
        {},
    ),
    # ── Presence ─────────────────────────────────────────────────────────────
    ("presence page", "GET", "/management/presence/", None, UI, {200}, (), None, {}),
    (
        "presence untrack B's device",
        "POST",
        f"/management/presence/untrack/{B_MAC}",
        None,
        UI,
        _DENY,
        (B_MAC,),
        _pr_b_still_tracked,
        {},
    ),
    (
        "presence track a B MAC from a row, naming subnet A in the query string",
        "POST",
        f"/management/presence/track-row?mac={B_MAC}&subnet_id=1&hostname=hijack",
        None,
        UI,
        _DENY,
        (B_MAC,),
        _pr_b_not_retagged,
        {},
    ),
    # ── Switch Port ──────────────────────────────────────────────────────────
    (
        "switchport api locate a MAC with no attributable subnet (seen on a switch named with the B marker)",
        "GET",
        f"/api/v1/plugins/switchport/locate/{N_MAC}",
        None,
        KEYS,
        {403, 404},
        (N_MAC,),
        None,
        {},
    ),
    (
        "switchport api locate a B MAC",
        "GET",
        f"/api/v1/plugins/switchport/locate/{B_MAC}",
        None,
        KEYS,
        {403, 404},
        (B_MAC,),
        None,
        {},
    ),
    (
        "switchport page locating a MAC with no attributable subnet",
        "GET",
        f"/network/switchport/?mac={N_MAC}",
        None,
        UI,
        {200},
        (N_MAC,),
        None,
        {},
    ),
    # ── DNS Sync ─────────────────────────────────────────────────────────────
    ("dns-sync page", "GET", "/network/dns-sync/", None, UI, {200}, (), None, {}),
    (
        "dns-sync records of B's target (filtered per record)",
        "GET",
        f"/network/dns-sync/targets/{DS_B}/records",
        None,
        UI,
        {200, 403, 404},
        (),
        None,
        {},
    ),
    (
        "dns-sync unbound export of B's target",
        "GET",
        f"/network/dns-sync/targets/{DS_B}/export-unbound",
        None,
        UI,
        _DENY,
        (),
        None,
        {},
    ),
    (
        "dns-sync toggle B's target",
        "POST",
        f"/network/dns-sync/targets/{DS_B}/toggle",
        None,
        UI,
        _DENY,
        (),
        _ds_b_untouched,
        {},
    ),
    (
        "dns-sync delete B's target",
        "POST",
        f"/network/dns-sync/targets/{DS_B}/delete",
        None,
        UI,
        _DENY,
        (),
        _ds_b_untouched,
        {},
    ),
    # ── IPAM (subnet id is explicit; it is checked) ──────────────────────────
    (
        "ipam api entries of subnet B",
        "GET",
        "/api/v1/plugins/ipam/entries?subnet_id=2",
        None,
        KEYS,
        {403, 404},
        (),
        None,
        {},
    ),
    ("ipam api next-free in subnet B", "GET", "/api/v1/plugins/ipam/next-free/2", None, KEYS, {403, 404}, (), None, {}),
    ("ipam page of subnet B", "GET", "/network/ipam/subnet/kea/2", None, UI, _DENY, (), None, {}),
    # ── v5.65.6 (Q95): a row for EVERY mutation route (the structural test below enforces it) ──
    (
        "watchdog add a target in subnet B",
        "POST",
        "/network/watchdog/targets/add",
        FormBody(ip="10.77.0.150", label="created-by-matrix", probe="ping", interval_min="5", fails_to_down="3"),
        UI,
        _DENY,
        (),
        _wd_nothing_created,
        {},
    ),
    (
        "watchdog watch a subnet-B host from a row, naming subnet A in the query string",
        "POST",
        "/network/watchdog/watch?ip=10.77.0.151&hostname=created-by-matrix&subnet_id=1",
        None,
        UI,
        _DENY,
        (),
        _wd_nothing_created,
        {},
    ),
    (
        "dns-sync add a target",
        "POST",
        "/network/dns-sync/targets/add",
        FormBody(
            name="created-by-matrix",
            kind="pihole",
            url="http://192.0.2.9",
            domain="lan",
            sources="leases",
            scope_all="on",
        ),
        UI,
        _DENY,
        (),
        _ds_nothing_created,
        {},
    ),
    (
        "dns-sync preview B's target",
        "POST",
        f"/network/dns-sync/targets/{DS_B}/preview",
        None,
        UI,
        _DENY,
        (),
        _ds_b_untouched,
        {},
    ),
    (
        "wol add a favourite for a subnet-B MAC",
        "POST",
        "/management/wol/favourites/add",
        FormBody(mac=B_MAC, label="created-by-matrix", ip="10.98.1.5", secureon=""),
        UI,
        _DENY,
        (B_MAC,),
        _wol_b_intact,
        {},
    ),
    (
        "presence track a subnet-B MAC",
        "POST",
        "/management/presence/track",
        FormBody(mac=B_MAC, label="created-by-matrix"),
        UI,
        _DENY,
        (B_MAC,),
        _pr_b_not_retagged,
        {},
    ),
    (
        "switchport add a switch in subnet B",
        "POST",
        "/network/switchport/switches/add",
        FormBody(name="created-by-matrix", host="10.77.0.9", vlan_indexing="none"),
        UI,
        _DENY,
        (),
        _sp_b_untouched,
        {},
    ),
    (
        "switchport pause B's switch",
        "POST",
        f"/network/switchport/switches/{SP_B}/toggle",
        None,
        UI,
        _DENY,
        (),
        _sp_b_untouched,
        {},
    ),
    (
        "switchport delete B's switch",
        "POST",
        f"/network/switchport/switches/{SP_B}/delete",
        None,
        UI,
        _DENY,
        (),
        _sp_b_untouched,
        {},
    ),
    (
        "switchport re-classify a port of B's switch",
        "POST",
        f"/network/switchport/ports/{SP_B}/1/uplink",
        FormBody(value="up"),
        UI,
        _DENY,
        (),
        _sp_b_untouched,
        {},
    ),
    (
        "ipam create an unmanaged subnet overlapping subnet B",
        "POST",
        "/network/ipam/subnets/add",
        FormBody(name="created-by-matrix", cidr="10.77.0.0/25"),
        UI,
        _DENY,
        (),
        _ipam_unmanaged_untouched,
        {},
    ),
    (
        "ipam delete an unmanaged subnet by id",
        "POST",
        f"/network/ipam/subnets/{IPAM_U}/delete",
        None,
        UI,
        _DENY,
        (),
        _ipam_unmanaged_untouched,
        {},
    ),
    (
        "ipam save an entry in subnet B",
        "POST",
        "/network/ipam/entry/kea/2",
        FormBody(ip="10.77.0.200", label="created-by-matrix", status="static"),
        UI,
        _DENY,
        (),
        _ipam_no_entry,
        {},
    ),
    (
        "ipam clear an entry in subnet B",
        "POST",
        "/network/ipam/entry/kea/2/delete",
        FormBody(ip="10.77.0.200"),
        UI,
        _DENY,
        (),
        _ipam_no_entry,
        {},
    ),
    (
        "ipam range action in subnet B",
        "POST",
        "/network/ipam/range/kea/2",
        FormBody(action="mark", first="10.77.0.200", last="10.77.0.201", label="created-by-matrix"),
        UI,
        _DENY,
        (),
        _ipam_no_entry,
        {},
    ),
    (
        "ipam import preview into subnet B",
        "POST",
        "/network/ipam/subnet/kea/2/import/preview",
        None,
        UI,
        _DENY,
        (),
        _ipam_no_entry,
        {},
    ),
    (
        "ipam import commit into subnet B",
        "POST",
        "/network/ipam/subnet/kea/2/import/commit",
        None,
        UI,
        _DENY,
        (),
        _ipam_no_entry,
        {},
    ),
    (
        "ipam api save an entry in subnet B",
        "POST",
        "/api/v1/plugins/ipam/entries",
        {"subnet_id": 2, "ip": "10.77.0.200", "label": "created-by-matrix"},
        KEYS,
        {403, 404},
        (),
        _ipam_no_entry,
        {},
    ),
    (
        "discovery start a scan of subnet B",
        "POST",
        "/network/discovery/scan/2",
        None,
        UI,
        _DENY,
        (),
        _nd_nothing,
        {},
    ),
    (
        "discovery set the scan schedule of subnet B",
        "POST",
        "/network/discovery/schedule/2",
        FormBody(every_hours="1"),
        UI,
        _DENY,
        (),
        _nd_nothing,
        {},
    ),
    (
        "discovery mark a host known in subnet B",
        "POST",
        "/network/discovery/known/2",
        FormBody(mac=B_MAC, note="created-by-matrix"),
        UI,
        _DENY,
        (B_MAC,),
        _nd_nothing,
        {},
    ),
]


def _cells():
    out = []
    for label, method, path, body, roles, codes, typed, verify, xfails in ROWS:
        for role in roles:
            marks = []
            if role in xfails:
                marks.append(pytest.mark.xfail(strict=True, reason=xfails[role]))
            out.append(
                pytest.param(label, method, path, body, role, codes, typed, verify, marks=marks, id=f"{label}|{role}")
            )
    return out


@pytest.mark.parametrize("label,method,path,body,role,codes,typed,verify", _cells())
def test_plugin_cell(pclient, db, plugin_data, wol_sends, label, method, path, body, role, codes, typed, verify):
    headers = _caller(pclient, db, role)
    kwargs = {"headers": headers} if headers else {}
    if isinstance(body, FormBody):
        kwargs["data"] = dict(body)
    elif body is not None:
        kwargs["data"] = json.dumps(body)
        kwargs.setdefault("headers", {"Content-Type": "application/json"})
    r = pclient.open(path, method=method, follow_redirects=False, **kwargs)
    assert r.status_code in codes, f"{label} as {role}: HTTP {r.status_code}, expected one of {sorted(codes)}"
    if role in MUST_NOT_SEE_B:
        assert_no_marker(r.data, ignore=typed)
        if r.status_code in (301, 302, 303):
            followed = pclient.open(
                path, method="GET", follow_redirects=True, **{"headers": headers} if headers else {}
            )
            assert_no_marker(followed.data, ignore=typed)
    if verify is not None:
        changed = verify(db, {"sends": wol_sends})
        assert not changed, f"{label} as {role}: {changed}"


class TestPluginFixtureIsReal:
    """Positive controls: the rows above prove nothing unless the plugins are loaded and the B data
    really is there for a caller who may see it."""

    def test_every_client_facing_endpoint_the_rows_use_exists(self, plugin_app):
        rules = {r.rule for r in plugin_app.url_map.iter_rules()}
        for needle in (
            "/network/watchdog/targets/<int:target_id>/toggle",
            "/management/wol/wake",
            "/management/presence/untrack/<mac>",
            "/api/v1/plugins/switchport/locate/<mac>",
            "/network/dns-sync/targets/<int:target_id>/export-unbound",
            "/api/v1/plugins/ipam/entries",
        ):
            assert needle in rules, f"{needle} is not registered — the plugin app did not load every plugin"

    def test_an_unrestricted_caller_sees_the_b_data(self, pclient, db, plugin_data):
        _caller(pclient, db, "superadmin")
        assert B_NAME in pclient.get("/network/watchdog/").data.decode()
        assert B_NAME in pclient.get("/management/wol/").data.decode()

    def test_an_unrestricted_caller_can_export_the_ledger(self, pclient, db, plugin_data):
        _caller(pclient, db, "superadmin")
        assert B_HOST in pclient.get(f"/network/dns-sync/targets/{DS_B}/export-unbound").data.decode()


class TestPresenceSinksAreSuperadminOnly:
    """v5.65.5 (Q94): every transition publishes every tracked client's MAC, label, IP, hostname and
    state to every enabled sink, so a sink is a cross-subnet exfiltration path for whoever can
    configure one. Configuring one (add, pause/enable, test, remove) is a superadmin action. The
    add route needs a real form body, which the matrix runner above cannot send, so this is its own
    test: a subnet-restricted admin and a viewer are refused on all four routes and nothing changes;
    a superadmin can."""

    ROUTES = (
        ("/management/presence/sinks/add", {"name": "created-by-matrix", "kind": "http", "url": "http://192.0.2.1/x"}),
        (f"/management/presence/sinks/{PR_SINK}/toggle", {}),
        (f"/management/presence/sinks/{PR_SINK}/test", {}),
        (f"/management/presence/sinks/{PR_SINK}/delete", {}),
    )

    @pytest.mark.parametrize("role", ["viewer_A", "admin_A"])
    def test_refused_and_nothing_changes(self, pclient, db, plugin_data, role):
        headers = _caller(pclient, db, role)
        for path, form in self.ROUTES:
            r = pclient.post(path, data=form, headers=headers or {}, follow_redirects=False)
            assert r.status_code in _DENY, f"{path} as {role}: HTTP {r.status_code}"
            assert_no_marker(r.data)
        assert _one(db, "SELECT id FROM pr_sinks WHERE name=%s", ("created-by-matrix",)) is None, "a sink was created"
        row = _one(db, "SELECT enabled FROM pr_sinks WHERE id=%s", (PR_SINK,))
        assert row is not None and row["enabled"] == 1, "the existing sink was removed or paused"

    def test_a_superadmin_can_configure_sinks(self, pclient, db, plugin_data):
        headers = _caller(pclient, db, "superadmin")
        add_path, add_form = self.ROUTES[0]
        pclient.post(add_path, data=add_form, headers=headers or {}, follow_redirects=False)
        assert _one(db, "SELECT id FROM pr_sinks WHERE name=%s", ("created-by-matrix",)) is not None
        pclient.post(self.ROUTES[1][0], data={}, headers=headers or {}, follow_redirects=False)
        row = _one(db, "SELECT enabled FROM pr_sinks WHERE id=%s", (PR_SINK,))
        assert row is not None and row["enabled"] == 0, "the superadmin's toggle did not take effect"


_ALL_KEY = "jen_authz_unrestricted_key"

# (label, method, path, body, xfail reason | None) - every plugin API route, once
POSITIVE_ROWS = [
    ("watchdog api list targets", "GET", "/api/v1/plugins/watchdog/targets", None, None),
    (
        "watchdog api add a target in subnet A",
        "POST",
        "/api/v1/plugins/watchdog/targets",
        {"ip": "10.98.1.99", "label": "created-by-matrix", "probe": "ping"},
        None,
    ),
    ("wol api wake a client in subnet A", "POST", "/api/v1/plugins/wol/wake", {"mac": A_MAC}, None),
    ("switchport api locate a client in subnet A", "GET", f"/api/v1/plugins/switchport/locate/{A_MAC}", None, None),
    ("ipam api entries of subnet A", "GET", "/api/v1/plugins/ipam/entries?subnet_id=1", None, None),
    (
        "ipam api save an entry in subnet A",
        "POST",
        "/api/v1/plugins/ipam/entries",
        {"subnet_id": 1, "ip": "10.98.1.200", "label": "created-by-matrix"},
        None,
    ),
    ("ipam api next-free in subnet A", "GET", "/api/v1/plugins/ipam/next-free/1", None, None),
]


def _unrestricted_key(db, can_write=1):
    """An API key with no subnet scope at all: the caller every refusal row above is the contrast to."""
    import hashlib

    from tests.test_api_key_authorization import _insert_api_key

    key_id = _insert_api_key(db, "_authz_unrestricted", created_by=1, subnet_access=None)
    with db.cursor() as cur:
        cur.execute(
            "UPDATE api_keys SET key_hash=%s, can_write=%s WHERE id=%s",
            (hashlib.sha256(_ALL_KEY.encode()).hexdigest(), can_write, key_id),
        )
    db.commit()
    return {"Authorization": f"Bearer {_ALL_KEY}", "Content-Type": "application/json"}


def _positive_cells():
    return [
        pytest.param(
            label, method, path, body, id=label, marks=[pytest.mark.xfail(strict=True, reason=xfail)] if xfail else []
        )
        for label, method, path, body, xfail in POSITIVE_ROWS
    ]


class TestAnAllowedCallerGetsAnAnswer:
    """v5.65.8 (Q97 l): the "allowed caller gets an answer" half of the invariant. An unrestricted key
    calls every plugin API route on subnet A's data and must get a 200, a JSON object with no `error`
    key, and no server-error text. (Subnet A's data only: an unrestricted key is entitled to B's, so a
    marker check would say nothing here - that is what the refusal rows are for.)"""

    @pytest.mark.parametrize("label,method,path,body", _positive_cells())
    def test_an_unrestricted_key_gets_a_200(self, pclient, db, plugin_data, wol_sends, label, method, path, body):
        headers = _unrestricted_key(db)
        kwargs = {"headers": headers}
        if body is not None:
            kwargs["data"] = json.dumps(body)
        r = pclient.open(path, method=method, follow_redirects=False, **kwargs)
        assert r.status_code == 200, f"{label}: HTTP {r.status_code}, {r.data[:200]!r}"
        text = r.data.decode("utf-8", "replace")
        assert "Traceback" not in text
        assert "Internal Server Error" not in text
        payload = r.get_json()
        assert isinstance(payload, dict), f"{label}: the body is not a JSON object"
        assert "error" not in payload, f"{label}: {payload}"

    def test_every_plugin_api_route_has_a_positive_row(self, plugin_app):
        rows = [(method, path.split("?")[0]) for (_label, method, path, _body, _x) in POSITIVE_ROWS]
        missing = []
        for rule in plugin_app.url_map.iter_rules():
            if not rule.rule.startswith("/api/v1/plugins/"):
                continue
            rx = _rule_regex(rule.rule)
            for method in sorted(rule.methods & {"GET", "POST", "PUT", "PATCH", "DELETE"}):
                if not any(m == method and rx.match(p) for m, p in rows):
                    missing.append(f"{method} {rule.rule}")
        assert not missing, f"plugin API routes with no positive-path row: {missing}"

    def test_a_plugin_write_route_shares_the_per_key_write_limit(
        self, pclient, db, plugin_data, wol_sends, monkeypatch
    ):
        """v5.65.8 (Q97 b): the limiter lives in api_key_required, so a plugin's write endpoint (one
        magic packet per call) is limited like the core ones instead of not at all."""
        from jen.services import api_auth

        monkeypatch.setattr(api_auth, "WRITE_RATE_PER_MINUTE", 2)
        api_auth._write_hits.clear()
        headers = _unrestricted_key(db)
        try:
            codes = [
                pclient.post("/api/v1/plugins/wol/wake", data=json.dumps({"mac": A_MAC}), headers=headers).status_code
                for _ in range(3)
            ]
            assert codes[2] == 429, codes
            assert 429 not in codes[:2], codes
            # a read is not a write: it is never counted
            assert pclient.get("/api/v1/plugins/watchdog/targets", headers=headers).status_code == 200
        finally:
            api_auth._write_hits.clear()


# Mutation routes whose behavioural coverage lives in a dedicated test (their bodies need a superadmin
# control the matrix runner has no notion of), mapped to that test.
COVERED_ELSEWHERE = {
    "/management/presence/sinks/add": "TestPresenceSinksAreSuperadminOnly",
    "/management/presence/sinks/<int:sink_id>/toggle": "TestPresenceSinksAreSuperadminOnly",
    "/management/presence/sinks/<int:sink_id>/test": "TestPresenceSinksAreSuperadminOnly",
    "/management/presence/sinks/<int:sink_id>/delete": "TestPresenceSinksAreSuperadminOnly",
}

_PLUGIN_PREFIXES = (
    "/network/watchdog",
    "/network/dns-sync",
    "/management/wol",
    "/management/presence",
    "/network/switchport",
    "/network/ipam",
    "/network/discovery",
    "/api/v1/plugins/",
)
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def _rule_regex(rule):
    parts = re.split(r"(<[^>]+>)", rule)
    return re.compile("^" + "".join("[^/]+" if part.startswith("<") else re.escape(part) for part in parts) + "$")


class TestEveryPluginMutationRouteHasARow:
    """v5.65.6 (Q95). The route scanner in tests/test_authz_matrix.py proves a reason was WRITTEN for a
    plugin route; it says nothing about the route's behaviour, and the IPAM unmanaged-subnet routes were
    filed under "scoped by a subnet id in the URL" while having no subnet id at all. This enumerates every
    POST/PUT/PATCH/DELETE rule under each bundled plugin from the live URL map and fails, naming the
    route, when none of the rows above (or the dedicated test named in COVERED_ELSEWHERE) exercises it.
    Read-only pages stay optional."""

    def test_every_mutation_route_has_a_row(self, plugin_app):
        rows = [(method, path.split("?")[0]) for (_label, method, path, *_rest) in ROWS]
        found, missing = 0, []
        for rule in plugin_app.url_map.iter_rules():
            if not rule.rule.startswith(_PLUGIN_PREFIXES):
                continue
            for method in sorted(rule.methods & _MUTATING):
                found += 1
                if rule.rule in COVERED_ELSEWHERE:
                    continue
                rx = _rule_regex(rule.rule)
                if not any(m == method and rx.match(p) for m, p in rows):
                    missing.append(f"{method} {rule.rule}")
        assert found >= 25, f"only {found} plugin mutation routes found - the plugin app did not load them all"
        assert not missing, (
            "plugin mutation routes with no authorization-matrix row (add one to ROWS in "
            f"tests/test_authz_matrix_plugins.py): {missing}"
        )

    def test_the_dedicated_tests_named_above_exist(self):
        for name in set(COVERED_ELSEWHERE.values()):
            assert name in globals(), f"{name} is named in COVERED_ELSEWHERE but does not exist"
