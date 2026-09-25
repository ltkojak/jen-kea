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
this file is what proves each fix.
"""

import json
import os
import shutil
import sys
import tempfile

import pytest

from jen import extensions
from jen.services import access
from tests.test_authz_matrix import (  # noqa: F401 - fixtures are used by name
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

N_MAC = "de:ad:be:ef:00:cd"  # a MAC Jen has never leased or reserved: no attributable subnet
NULL_LABEL = B_NAME + "-nullsubnet"  # contains the B marker
WD_B, WD_NULL = 9101, 9102
WOL_B, WOL_NULL = 9301, 9302
DS_B = 9201
SP_B = 9401

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

    app = jen_pkg.create_app()
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
    row = _one(db, "SELECT subnet_id FROM pr_tracked WHERE mac=%s", (B_MAC,))
    return "" if row and row["subnet_id"] == 2 else f"the B device's subnet was rewritten to {row and row['subnet_id']}"


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
        dict.fromkeys(KEYS, Q93 + ": None subnet read as allow in _api_list_targets"),
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
        dict.fromkeys(UI, Q93 + ": target_history has no subnet check"),
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
        {"admin_A": Q93 + ": toggle_target acts on any id"},
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
        {"admin_A": Q93 + ": delete_target acts on any id"},
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
        {"key_write": Q93 + ": _api_add_target lets a None subnet through"},
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
        {"admin_A": Q94 + ": delete_favourite acts on any id"},
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
        {"admin_A": Q94 + ": wake_from_row authorises the TYPED subnet, not the MAC's own"},
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
        {"key_write": Q94 + ": _api_wake lets a None subnet through"},
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
        {"admin_A": Q94 + ": untrack acts on any MAC"},
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
        {"admin_A": Q94 + ": track_from_row trusts the typed subnet_id"},
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
        dict.fromkeys(KEYS, Q94 + ": _api_locate lets a None subnet through"),
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
        dict.fromkeys(UI, Q94 + ": the locate form shows a MAC with no subnet to anyone"),
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
        dict.fromkeys(UI, Q93 + ": export_unbound writes the whole ledger, unfiltered"),
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
        {"admin_A": Q93 + ": toggle_target acts on any id"},
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
        {"admin_A": Q93 + ": delete_target acts on any id"},
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
    if body is not None:
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
