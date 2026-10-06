"""
tests/stored_object_fixtures.py
────────────────────────────────
v5.68.0-beta.12 (Q147) — the ONE "moved-client stored-object" fixture the three plugin matrices import
(tests/test_stored_objects_wol.py, _switchport.py, _presence.py).

The rule being proved (plugins/README.md "Stored data", docs/ARCHITECTURE.md section 2): a plugin's STORED object — a favourite, a tracked
device, a switch position — is judged by the subnet it was stored in, on every surface (page, add, delete, move, search, API, the
Investigation card), and where the client is NOW never widens that. A wake or any other act on a live host is the one thing judged on where
the host is now, and it never borrows a stored object the caller may not see. Two clients cover both directions:

  * DIRECTION 1 - `A_MAC`: in subnet A now (a lease), with everything the three plugins hold for it stored in subnet B: a favourite (with a
    SecureOn password) and a tracked row owned by B, and a position on a B switch that is NEWER than its position on an A switch.
  * DIRECTION 2 - `D_MAC`: in subnet B now (a device row), with everything stored in subnet A: a favourite (with a SecureOn password), a tracked
    row owned by A, and a position on an A switch.

`D_MAC` is deliberately not one of the leak markers: what is stored in A is the A caller's own data, and its MAC is part of it. The markers
that must never appear for an A-scoped caller are the B ones (the B subnet's name, its addresses), exactly as in tests/test_authz_matrix.py.
"""

import pytest

from tests.test_authz_matrix import A_MAC, _caller

D_MAC = "de:ad:be:ef:00:d1"  # now in subnet B (a device row), everything of its stored in subnet A
D_IP = "10.77.0.41"
SECUREON = "aa:bb:cc:dd"
SECUREON_BYTES = bytes.fromhex("aabbccdd")

# printed by what the plugins hold - one tag per object so a leak names its source
S1 = "ZZ-S1"  # direction 1: stored in B for A_MAC
S2 = "ZZ-S2"  # direction 2: stored in A for D_MAC
SW_B, SW_A, SW_D = 9421, 9422, 9423  # switch ids: a switch in B, one in A (A_MAC's older), one in A (D_MAC's)


def clean(cur):
    for mac in (A_MAC, D_MAC):
        cur.execute("DELETE FROM wol_hosts WHERE mac=%s", (mac,))
        cur.execute("DELETE FROM pr_state WHERE mac=%s", (mac,))
        cur.execute("DELETE FROM pr_tracked WHERE mac=%s", (mac,))
    cur.execute("DELETE FROM sp_mac_ports WHERE switch_id IN (%s, %s, %s)", (SW_B, SW_A, SW_D))
    cur.execute("DELETE FROM sp_ports WHERE switch_id IN (%s, %s, %s)", (SW_B, SW_A, SW_D))
    cur.execute("DELETE FROM sp_switches WHERE id IN (%s, %s, %s)", (SW_B, SW_A, SW_D))
    cur.execute("DELETE FROM devices WHERE mac=%s", (D_MAC,))
    cur.execute("DELETE FROM audit_log WHERE action='PRESENCE_MOVE'")


@pytest.fixture
def stored_objects(plugin_app, db, plugin_data):
    """See the module docstring. Needs the plugin app (every bundled plugin enabled) and the two-subnet matrix fixture."""
    from jen.plugin_api import encrypt_secret

    with plugin_app.app_context():
        secureon = encrypt_secret(SECUREON)
    with db.cursor() as cur:
        clean(cur)
        cur.execute(
            "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, device_name, first_seen, last_seen) VALUES "
            "(%s, %s, 'moved-host', 2, 'Moved to B', NOW(), NOW())",
            (D_MAC, D_IP),
        )
        # direction 1: stored in B, the client is in A
        cur.execute(
            "INSERT INTO wol_hosts (mac, ip, subnet_id, label, secureon) VALUES (%s, NULL, 2, %s, %s)",
            (A_MAC, S1 + "-wol", secureon),
        )
        cur.execute(
            "INSERT INTO pr_tracked (mac, label, subnet_id, added_by) VALUES (%s, %s, 2, 'seed')", (A_MAC, S1 + "-pr")
        )
        cur.execute("INSERT INTO pr_state (mac, online, since, last_seen) VALUES (%s, 1, NOW(), NOW())", (A_MAC,))
        # direction 2: stored in A, the client is in B
        cur.execute(
            "INSERT INTO wol_hosts (mac, ip, subnet_id, label, secureon) VALUES (%s, NULL, 1, %s, %s)",
            (D_MAC, S2 + "-wol", secureon),
        )
        cur.execute(
            "INSERT INTO pr_tracked (mac, label, subnet_id, added_by) VALUES (%s, %s, 1, 'seed')", (D_MAC, S2 + "-pr")
        )
        cur.execute("INSERT INTO pr_state (mac, online, since, last_seen) VALUES (%s, 1, NOW(), NOW())", (D_MAC,))
        cur.execute(
            "INSERT INTO sp_switches (id, name, host, community) VALUES (%s, %s, '10.77.0.2', 'x'), "
            "(%s, %s, '10.98.1.2', 'x'), (%s, %s, '10.98.1.3', 'x')",
            (SW_B, S1 + "-sw-b", SW_A, S1 + "-sw-a", SW_D, S2 + "-sw"),
        )
        cur.execute(
            "INSERT INTO sp_ports (switch_id, ifindex, ifname) VALUES (%s, 1, 'Gi2/0/9'), (%s, 1, 'Gi1/0/7'), (%s, 1, 'Gi1/0/8')",
            (SW_B, SW_A, SW_D),
        )
        cur.execute(
            "INSERT INTO sp_mac_ports (mac, switch_id, ifindex, vlan, last_seen) VALUES "
            "(%s, %s, 1, 30, NOW()), (%s, %s, 1, 20, DATE_SUB(NOW(), INTERVAL 1 HOUR)), (%s, %s, 1, 40, NOW())",
            (A_MAC, SW_B, A_MAC, SW_A, D_MAC, SW_D),
        )
    db.commit()
    yield
    with db.cursor() as cur:
        clean(cur)
    db.commit()


def as_admin_b(pclient, db):
    """An admin scoped to subnet B only - the owner of everything direction 1 stored."""
    from tests.conftest import restricted_client

    restricted_client(pclient, db, allowed_subnets=[2], role="admin", username="authz_admin_B")


def page(pclient, db, role, path):
    """GET `path` as `role` (a matrix role, or "admin_B") and return the body."""
    if role == "admin_B":
        as_admin_b(pclient, db)
    else:
        _caller(pclient, db, role)
    return pclient.get(path).data.decode("utf-8", "replace")


def one(db, sql, params=()):
    db.commit()  # a fresh snapshot: the request ran on another connection
    with db.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()
