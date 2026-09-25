"""
tests/test_authz_matrix.py
────────────────────────────
v5.49.0-beta.5 (Q55-J) — ONE authorization matrix over every diagnostic
surface. Two subnets: A (id 1, allowed) and B (id 2, denied) whose markers
are unique strings; a client in B with a device, an active lease, a
reservation, an alert_log row, an audit_log row and an events row that all
name it. Callers: a subnet-restricted viewer, an unrestricted admin, an admin
scoped to A, a superadmin, and an A-scoped read key and write key.

Each cell asserts the status AND — for every caller that must not see B —
that no B marker appears ANYWHERE in the body (flashes, error text, counts,
JSON) via one shared `assert_no_marker`. Adding a surface later is one row in
SURFACES. This is the test that would have caught Q54 C-F and Q55 B, C, I
before they shipped.

Marker note: the B client's CIDR is 10.77.0.0/24, not 10.99.0.0/24 — the
shared test config already names 10.99.0.0/24 for subnet 1, which would make
the marker ambiguous. Values a caller itself typed into the URL (the MAC in
?mac=) are removed from the body before scanning: a page may echo its input.
"""

import ast
import glob
import hashlib
import json
import re

import pytest

from jen import extensions
from jen.services import access

B_NAME = "ZZ-SECRET-B"
B_HOST = "secret-host-b"
B_MAC = "de:ad:be:ef:00:bb"
B_MAC_HEX = "DEADBEEF00BB"
B_LEASE_IP = "10.77.0.77"
B_RES_IP = "10.77.0.88"
A_MAC = "de:ad:be:ef:00:aa"
A_MAC_HEX = "DEADBEEF00AA"
# v5.65.2 (Q91): one hostname on a client in A and a client in B - the ambiguous-hostname fixture
SHARED_HOST = "shared-host"
A2_MAC = "de:ad:be:ef:00:a2"
B2_MAC = "de:ad:be:ef:00:b2"
# "4242 name": the fleet-wide reconcile summary seeded below — a distinctive AGGREGATE count
# that must never reach a subnet-scoped caller (Q56-2)
MARKERS = (B_NAME, B_HOST, B_MAC, B_MAC_HEX, "10.77.0.", "deadbeef00bb", "4242 name", B2_MAC, "deadbeef00b2")

RAW_READ = "jen_authz_read_key"
RAW_WRITE = "jen_authz_write_key"


def assert_no_marker(body, ignore=()):
    """No B marker anywhere in `body`, after removing values the caller itself
    supplied (`ignore`) — a page may legitimately echo its own input."""
    text = body if isinstance(body, str) else body.decode("utf-8", "replace")
    low = text.lower()
    for value in ignore:
        low = low.replace(str(value).lower(), "")
    for marker in MARKERS:
        assert marker.lower() not in low, f"subnet-B marker {marker!r} leaked into the response"


@pytest.fixture(autouse=True)
def _subnets(monkeypatch):
    monkeypatch.setattr(
        extensions,
        "SUBNET_MAP",
        {1: {"name": "Alpha-A", "cidr": "10.98.1.0/24"}, 2: {"name": B_NAME, "cidr": "10.77.0.0/24"}},
    )


@pytest.fixture
def seeded(db, mock_kea, monkeypatch):
    """A client in B (device + lease + reservation + alert + audit + event) and
    a control client in A. Trace and reconcile are stubbed so they can never
    reach SSH or a resolver."""
    from jen.routes import ddns
    from jen.services import kea_host

    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN (%s, %s)", (B_MAC_HEX, A_MAC_HEX))
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN (%s, %s)", (B_MAC_HEX, A_MAC_HEX))
        cur.execute("DELETE FROM events")
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) VALUES "
            "(INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 2, 0, %s), "
            "(INET_ATON('10.98.1.10'), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, 'alpha-host')",
            (B_LEASE_IP, B_MAC_HEX, B_HOST, A_MAC_HEX),
        )
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
            "VALUES (UNHEX(%s), 0, 2, INET_ATON(%s), %s)",
            (B_MAC_HEX, B_RES_IP, B_HOST),
        )
        cur.execute(
            "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, device_name, first_seen, last_seen) VALUES "
            "(%s, %s, %s, 2, %s, NOW(), NOW()), (%s, '10.98.1.10', 'alpha-host', 1, 'Alpha device', NOW(), NOW())",
            (B_MAC, B_LEASE_IP, B_HOST, B_HOST, A_MAC),
        )
        cur.execute(
            "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, device_name, first_seen, last_seen) VALUES "
            "(%s, '10.98.1.20', %s, 1, 'Shared in A', NOW(), NOW()), (%s, '10.77.0.20', %s, 2, 'Shared in B', NOW(), NOW())",
            (A2_MAC, SHARED_HOST, B2_MAC, SHARED_HOST),
        )
        cur.execute(
            "INSERT INTO alert_log (channel_type, alert_type, message, status) VALUES "
            "('telegram', 'new_lease', %s, 'sent')",
            (f"{B_HOST} {B_MAC} {B_LEASE_IP} {B_NAME}",),
        )
        cur.execute(
            "INSERT INTO audit_log (action, entity, details, username) VALUES ('NOTE', %s, %s, 'admin')",
            (B_HOST, f"{B_MAC} {B_LEASE_IP} {B_NAME}"),
        )
        cur.execute(
            "INSERT INTO events (kind, mac, ip, subnet_id, hostname, detail) VALUES ('lease.new', %s, %s, 2, %s, %s)",
            (B_MAC, B_LEASE_IP, B_HOST, f"{B_HOST} in {B_NAME}"),
        )
    db.commit()

    from jen.models.user import set_global_setting

    set_global_setting(
        "dns_reconcile_last",
        json.dumps({"ts": "2026-09-20T00:00:00+00:00", "total": 4242, "verdicts": {"ok": 4200, "wrong-ptr": 42}}),
    )
    monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}])
    log = [
        f"2026-09-20 10:00:00.100 INFO  [kea-dhcp4.leases/1] DHCP4_LEASE_ALLOC [hwtype=1 {B_MAC}]: "
        f"lease {B_LEASE_IP} has been allocated for 3600 seconds ({B_HOST})"
    ]
    monkeypatch.setattr(
        kea_host,
        "tail_log",
        lambda server, path, lines=200, **kw: {"ok": True, "code": "ok", "lines": log, "via": "helper"},
    )
    monkeypatch.setattr(ddns, "_run_verify", lambda hostname, ip: {"forward_ips": [ip], "reverse_name": hostname})

    # v5.57.0 (Q73) — register_search_provider() is a new authz surface:
    # /search now renders whatever a plugin's provider returns, so a
    # provider that (correctly, or not) hands back a B-subnet row must
    # be caught by the SAME subnet_id filter every other surface here
    # gets, not trusted on the plugin's word alone (the Q55 rule).
    from jen.services import search_providers as _search_providers

    _search_providers.register_search_provider(
        "authz-fake",
        title="Authz Fake",
        fn=lambda query, accessible_subnet_ids, all_subnets: [
            {"title": B_HOST, "subtitle": B_MAC, "href": "/x", "subnet_id": 2}
        ],
    )

    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN (%s, %s)", (B_MAC_HEX, A_MAC_HEX))
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN (%s, %s)", (B_MAC_HEX, A_MAC_HEX))
        cur.execute("DELETE FROM events")
        cur.execute("DELETE FROM api_keys WHERE name LIKE '_authz_%%'")
    db.commit()
    _search_providers._PROVIDERS.pop("authz-fake", None)


# role -> how the caller authenticates
SESSION_ROLES = {
    "viewer_A": {"role": "viewer", "allowed": [1]},
    "admin_A": {"role": "admin", "allowed": [1]},
    "admin_all": {"role": "admin", "allowed": None},
    "superadmin": {"role": "superadmin", "allowed": None},
}
KEY_ROLES = {"key_read": (RAW_READ, 0), "key_write": (RAW_WRITE, 1)}
MUST_NOT_SEE_B = {"viewer_A", "admin_A", "key_read", "key_write"}


def _caller(client, db, role):
    if role in SESSION_ROLES:
        from tests.conftest import restricted_client

        cfg = SESSION_ROLES[role]
        restricted_client(client, db, allowed_subnets=cfg["allowed"], role=cfg["role"], username=f"authz_{role}")
        return {}
    raw, can_write = KEY_ROLES[role]
    from tests.test_api_key_authorization import _insert_api_key

    key_id = _insert_api_key(db, f"_authz_{role}", created_by=1, subnet_access=[1])
    with db.cursor() as cur:
        cur.execute(
            "UPDATE api_keys SET key_hash=%s, can_write=%s WHERE id=%s",
            (hashlib.sha256(raw.encode()).hexdigest(), can_write, key_id),
        )
    db.commit()
    return {"Authorization": f"Bearer {raw}", "Content-Type": "application/json"}


# (label, method, path, json body, {role: allowed status codes}, values the caller typed)
# A denial may be a redirect (role gate), a 403, a 404 (no oracle) or a 200 page
# carrying a refusal notice; the marker assertion is what proves nothing leaked.
_ANY = {200, 302, 403, 404}
SURFACES = [
    (
        "explain by B mac",
        "GET",
        f"/tools/explain?mac={B_MAC}",
        None,
        {"viewer_A": _ANY, "admin_A": _ANY, "admin_all": {200}, "superadmin": {200}},
        (B_MAC,),
    ),
    (
        "trace by A mac (own subnet: Trace still needs unrestricted access)",
        "GET",
        f"/tools/trace?mac={A_MAC}",
        None,
        {"viewer_A": {302, 403}, "admin_A": {403}, "admin_all": {200}, "superadmin": {200}},
        (A_MAC,),
    ),
    (
        "trace by B mac",
        "GET",
        f"/tools/trace?mac={B_MAC}",
        None,
        {"viewer_A": {302, 403}, "admin_A": {403}, "admin_all": {200}, "superadmin": {200}},
        (B_MAC,),
    ),
    (
        "timeline by B mac",
        "GET",
        f"/timeline?mac={B_MAC}",
        None,
        {"viewer_A": {200, 403}, "admin_A": {200, 403}, "admin_all": {200}, "superadmin": {200}},
        (B_MAC,),
    ),
    (
        "timeline by B ip",
        "GET",
        f"/timeline?ip={B_LEASE_IP}",
        None,
        {"viewer_A": {200, 403}, "admin_A": {200, 403}, "admin_all": {200}, "superadmin": {200}},
        (B_LEASE_IP,),
    ),
    (
        "doctor",
        "GET",
        "/tools/doctor",
        None,
        {"viewer_A": {302, 403}, "admin_A": {302, 403}, "admin_all": {200}, "superadmin": {200}},
        (),
    ),
    (
        "reconcile limit 50",
        "GET",
        "/ddns/reconcile?limit=50",
        None,
        {"viewer_A": {302, 403}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (),
    ),
    (
        "reports",
        "GET",
        "/reports",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (),
    ),
    (
        "health center data",
        "GET",
        "/health-center/data",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (),
    ),
    (
        "servers",
        "GET",
        "/servers",
        None,
        {"viewer_A": _ANY, "admin_A": _ANY, "admin_all": {200}, "superadmin": {200}},
        (),
    ),
    (
        "search by host fragment",
        "GET",
        "/search?q=secret-host",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (),
    ),
    (
        "search by B ip fragment",
        "GET",
        "/search?q=0.77",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (),
    ),
    (
        # v5.57.0 (Q73) — the "authz-fake" search provider always returns a
        # B-subnet row (registered in `seeded` above); run_search_providers()
        # must drop it for a restricted caller the same way the core search
        # already does, not just when a well-behaved plugin filters first.
        "search provider row (plugin-provided) by B host",
        "GET",
        "/search?q=secret-host",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (),
    ),
    (
        "devices page",
        "GET",
        "/devices",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (),
    ),
    ("api devices list", "GET", "/api/v1/devices", None, {"key_read": {200}, "key_write": {200}}, ()),
    (
        "api device by B mac",
        "GET",
        f"/api/v1/devices/{B_MAC}",
        None,
        {"key_read": {403, 404}, "key_write": {403, 404}},
        (),
    ),
    (
        "api lease by B mac",
        "GET",
        f"/api/v1/leases/{B_MAC}",
        None,
        {"key_read": {403, 404}, "key_write": {403, 404}},
        (),
    ),
    (
        "api timeline by B mac",
        "GET",
        f"/api/v1/timeline/{B_MAC}",
        None,
        {"key_read": {403, 404}, "key_write": {403, 404}},
        (),
    ),
    ("api events", "GET", "/api/v1/events", None, {"key_read": {200}, "key_write": {200}}, ()),
    ("api health checks", "GET", "/api/v1/health/checks", None, {"key_read": {200}, "key_write": {200}}, ()),
    (
        "api patch B device",
        "PATCH",
        f"/api/v1/devices/{B_MAC}",
        {"name": "hijack"},
        {"key_read": {403}, "key_write": {403, 404}},
        (),
    ),
    (
        # v5.56.1 (Q68l) — the events_feed catalog widget now filters in
        # SQL before LIMIT instead of over-fetching and dropping rows in
        # Python; this is the same B-marker guard every other surface gets.
        "dashboard catalog-data events feed",
        "GET",
        "/api/dashboard/catalog-data?widgets=events_feed",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (),
    ),
    # v5.63.0 (Q82) — the Investigation page never 403s itself (a denial is
    # shown inline, in a 200 response); the marker check is what proves it,
    # same shape as Explain/Doctor/Reports above. Six rows, one per tab,
    # split across both identifier kinds the design calls for.
    (
        "client overview by B mac",
        "GET",
        f"/client?q={B_MAC}&tab=overview",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (B_MAC,),
    ),
    (
        "client explain tab by B mac",
        "GET",
        f"/client?q={B_MAC}&tab=explain",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (B_MAC,),
    ),
    (
        "client trace tab by B mac",
        "GET",
        f"/client?q={B_MAC}&tab=trace",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (B_MAC,),
    ),
    (
        # v5.65.2 (Q91 b): typing the address of a lease in B used to show the holder's MAC
        "client overview by B ip (the holder's MAC must not show)",
        "GET",
        f"/client?q={B_LEASE_IP}&tab=overview",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (B_LEASE_IP,),
    ),
    (
        # v5.65.2 (Q91 a): the same hostname on a client in A and one in B - the B MAC must not be listed
        "client by a hostname shared between A and B",
        "GET",
        f"/client?q={SHARED_HOST}",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (SHARED_HOST,),
    ),
    (
        "client timeline tab by B ip",
        "GET",
        f"/client?q={B_LEASE_IP}&tab=timeline",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (B_LEASE_IP,),
    ),
    (
        "client dns tab by B ip",
        "GET",
        f"/client?q={B_LEASE_IP}&tab=dns",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (B_LEASE_IP,),
    ),
    (
        "client config tab by B ip",
        "GET",
        f"/client?q={B_LEASE_IP}&tab=config",
        None,
        {"viewer_A": {200}, "admin_A": {200}, "admin_all": {200}, "superadmin": {200}},
        (B_LEASE_IP,),
    ),
]

CELLS = [
    pytest.param(label, method, path, body, role, codes, typed, id=f"{label}|{role}")
    for (label, method, path, body, expected, typed) in SURFACES
    for role, codes in expected.items()
]


@pytest.mark.parametrize("label,method,path,body,role,codes,typed", CELLS)
def test_cell(client, db, seeded, label, method, path, body, role, codes, typed):
    headers = _caller(client, db, role)
    kwargs = {"headers": headers} if headers else {}
    if body is not None:
        kwargs["data"] = json.dumps(body)
        kwargs.setdefault("headers", {"Content-Type": "application/json"})
    r = client.open(path, method=method, follow_redirects=False, **kwargs)
    assert r.status_code in codes, f"{label} as {role}: HTTP {r.status_code}, expected one of {sorted(codes)}"
    if role in MUST_NOT_SEE_B:
        assert_no_marker(r.data, ignore=typed)
        # a followed redirect (a role gate's flash page) must not leak either
        if r.status_code in (301, 302, 303):
            assert_no_marker(client.open(path, method=method, follow_redirects=True, **kwargs).data, ignore=typed)


class TestFixtureIsReal:
    """Positive controls: the matrix proves nothing unless B is really there for
    a caller who may see it."""

    def test_an_unrestricted_caller_can_see_the_b_client(self, client, db, seeded):
        _caller(client, db, "superadmin")
        body = client.get("/search?q=secret-host").data.decode()
        assert B_HOST in body

    def test_the_marker_helper_catches_a_leak(self):
        with pytest.raises(AssertionError):
            assert_no_marker(f"<p>{B_NAME}</p>")
        assert_no_marker(f"<input value='{B_MAC}'>", ignore=(B_MAC,))  # an echoed input is fine


# ── v5.62.1 (Q81) — SURFACES above and access.DIAGNOSTIC_SURFACES must name
# the same routes, in both directions, so a new diagnostic route can't ship
# without a matrix row, and a stale row can't outlive its route. ───────────


def _endpoint_for(app, method, path):
    """The Flask endpoint `method path` (query string stripped) resolves to."""
    adapter = app.url_map.bind("localhost")
    endpoint, _args = adapter.match(path.split("?", 1)[0], method=method)
    return endpoint


class TestDiagnosticSurfaceCoverage:
    def test_diagnostic_surfaces_and_matrix_rows_are_the_same_set(self, app):
        decorated = {endpoint for endpoint, _methods, _rule in access.DIAGNOSTIC_SURFACES}
        assert decorated, "access.DIAGNOSTIC_SURFACES is empty — collect_diagnostic_surfaces() didn't run"
        covered = {_endpoint_for(app, method, path) for (_label, method, path, _body, _expected, _typed) in SURFACES}
        only_decorated = decorated - covered
        only_surfaces = covered - decorated
        assert not only_decorated, (
            f"@diagnostic_surface route(s) with no SURFACES row — add one: {sorted(only_decorated)}"
        )
        assert not only_surfaces, (
            f"SURFACES row(s) whose route isn't @diagnostic_surface-decorated: {sorted(only_surfaces)}"
        )


# Routes that read or write a client table (lease4/hosts/devices/events/
# alert_log) but are a core CRUD/list page or an aggregate view, not a
# single-client lookup that could leak one client's data through another's
# caller — each already covered by its own page's subnet-restriction tests,
# not this matrix. A new entry here needs the same: a one-line reason AND a
# real test elsewhere, not a rubber stamp.
ROUTE_ALLOWLIST = {
    # Lease CRUD — add_subnet_restriction() in the query; tests/test_leases.py.
    "leases.leases": "list page, subnet-restricted at the query — tests/test_leases.py",
    "leases.delete_stale_leases": "bulk admin action, subnet-restricted — tests/test_leases.py",
    "leases.release_lease": "single-lease admin action, subnet-restricted — tests/test_leases.py",
    "leases.bulk_release_leases": "bulk admin action, subnet-restricted — tests/test_leases.py",
    "leases.ipmap": "subnet-scoped visualisation of the leases page's own data — tests/test_leases.py",
    # Reservation CRUD — add_subnet_restriction()/assert_subnet_access(); tests/test_reservations.py.
    "reservations.reservations": "list page, subnet-restricted at the query — tests/test_reservations.py",
    "reservations.add_reservation_post": "write route, subnet-restricted — tests/test_reservations.py",
    "reservations.edit_reservation": "single-object form, assert_subnet_access — tests/test_reservations.py",
    "reservations.edit_reservation_post": "write route, assert_subnet_access — tests/test_reservations.py",
    "reservations.delete_reservation": "write route, assert_subnet_access — tests/test_reservations.py",
    "reservations.export_reservations": "export of the already subnet-restricted list — tests/test_reservations.py",
    "reservations.import_reservations": "write route, subnet-restricted — tests/test_reservations.py",
    "reservations.bulk_delete_reservations": "bulk write route, subnet-restricted — tests/test_reservations.py",
    "reservations.bulk_export_reservations": "bulk export, subnet-restricted — tests/test_reservations.py",
    # Device CRUD — assert_subnet_access(); the list/detail view (devices.devices)
    # is the diagnostic surface and is decorated instead. tests/test_devices.py.
    "devices.edit_device": "write route, assert_subnet_access — tests/test_devices.py",
    "devices.delete_device": "write route, assert_subnet_access — tests/test_devices.py",
    "devices.bulk_delete_devices": "bulk write route, assert_subnet_access — tests/test_devices.py",
    # Dashboard — counts and top-N aggregate views, not a per-client lookup;
    # the one dashboard route that resolves a specific client (catalog-data's
    # events feed) is decorated instead. tests/test_dashboard.py.
    "dashboard.dashboard": "aggregate summary counts, subnet-filtered — tests/test_dashboard.py",
    "dashboard.api_stats": "aggregate counts, subnet-filtered — tests/test_dashboard.py",
    "dashboard.api_top_devices": "top-N aggregate, subnet-filtered — tests/test_dashboard.py",
    "dashboard.api_alert_summary": "aggregate counts, subnet-filtered — tests/test_dashboard.py",
    "dashboard.api_recent_leases": "recent-N aggregate, subnet-filtered — tests/test_dashboard.py",
    "dashboard.prometheus_metrics": "scrape endpoint, aggregate counts only, no per-client fields",
    # Subnet management — admin-scoped, not a per-client surface.
    "subnets.subnets": "subnet list with aggregate counts — tests/test_subnets.py",
    "subnets.delete_subnet": "write route, admin-only — tests/test_subnets.py",
    # Users — audit_log is the superadmin-only audit trail (unrestricted by
    # design, like Doctor); about is a static info page with lease COUNT()s only.
    "users.audit_log": "superadmin-only audit trail, unrestricted by design — tests/test_users.py",
    "users.about": "static info page, aggregate lease counts only, no per-client fields",
    # Other REST v1 routes — scoped via _api_key_subnet_ids()/filter_subnet_ids()
    # already; not in Q81's named six (devices/devices-by-mac/leases-by-mac/
    # timeline/events/health-checks). tests/test_api_key_authorization.py.
    "api.api_v1_subnets": "subnet list with aggregate counts, key-scoped — tests/test_api_key_authorization.py",
    "api.api_v1_leases": "lease list, key-scoped — tests/test_api_key_authorization.py",
    "api.api_v1_reservations": "reservation list, key-scoped — tests/test_api_key_authorization.py",
    "api.api_v1_reservation_create": "write route, key-scoped — tests/test_api_key_authorization.py",
    "api.api_v1_reservation_delete": "write route, key-scoped — tests/test_api_key_authorization.py",
}

_TABLE_PATTERN = re.compile(
    r"\b(?:FROM|JOIN|UPDATE|INTO)\s+`?(lease4|hosts|devices|events|alert_log)`?\b", re.IGNORECASE
)


def _routed_functions():
    """Every top-level `@bp.route(...)`-decorated function across
    jen/routes/*.py (not the settings/ subpackage — Q81 doesn't cover it),
    as (endpoint, path, source text)."""
    found = []
    for path in sorted(glob.glob("jen/routes/*.py")):
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        tree = ast.parse(src, filename=path)
        bp_name = None
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and any(getattr(t, "id", None) == "bp" for t in node.targets)
                and isinstance(node.value, ast.Call)
                and getattr(node.value.func, "id", "") == "Blueprint"
            ):
                bp_name = ast.literal_eval(node.value.args[0])
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            is_route = any(
                isinstance(d, ast.Call)
                and isinstance(d.func, ast.Attribute)
                and d.func.attr == "route"
                and getattr(d.func.value, "id", "") == "bp"
                for d in node.decorator_list
            )
            if not is_route:
                continue
            seg = ast.get_source_segment(src, node) or ""
            found.append((f"{bp_name}.{node.name}", path, seg))
    return found


class TestDiagnosticSurfaceScanner:
    """Q81's second guardrail: SURFACES only proves the routes it already
    knows about stay covered. This one catches the NEXT route someone adds
    that touches a client table without either decorating it or explaining
    why it's not a per-client diagnostic surface."""

    def test_every_client_table_route_is_decorated_or_allowlisted(self, app):
        decorated = {endpoint for endpoint, _methods, _rule in access.DIAGNOSTIC_SURFACES}
        offenders = []
        for endpoint, path, seg in _routed_functions():
            if not _TABLE_PATTERN.search(seg):
                continue
            if endpoint in decorated or endpoint in ROUTE_ALLOWLIST:
                continue
            offenders.append(f"{endpoint} ({path})")
        assert not offenders, "decorate it or allow-list it — " + ", ".join(offenders)

    def test_allowlist_has_no_stale_entries(self, app):
        """Every ROUTE_ALLOWLIST entry names a route that still exists and
        still isn't decorated — an entry that no longer applies just hides a
        route the scanner should be checking."""
        decorated = {endpoint for endpoint, _methods, _rule in access.DIAGNOSTIC_SURFACES}
        routed = {endpoint for endpoint, _path, _seg in _routed_functions()}
        stale = (set(ROUTE_ALLOWLIST) & decorated) | (set(ROUTE_ALLOWLIST) - routed)
        assert not stale, f"ROUTE_ALLOWLIST entry no longer applies (route removed or now decorated): {sorted(stale)}"


# ── v5.65.2 (Q91 d) — no route in the diagnostic files, and no plugin route, can hide ──────
#
# `_TABLE_PATTERN` above only sees SQL written inline in a route body, so a route that
# delegates to a service (the Q82 pattern) or to a plugin's own helper was invisible. These
# guards are stricter and simpler: every route in the diagnostic route files, and every
# route a bundled plugin registers, is either decorated `@diagnostic_surface` or named below
# WITH A REASON. "It calls a service" is no longer an escape. Purely static (AST) - they need
# no app and no database.

DIAGNOSTIC_ROUTE_FILES = ("client", "explain", "trace", "timeline", "search", "devices", "doctor", "health")

# By endpoint ("blueprint.function"), for the files above. Routes already named in ROUTE_ALLOWLIST
# (the devices CRUD) are not repeated here.
NAMED_ALLOWLIST = {
    "search.saved_searches": "a user's own saved query strings; no client table",
    "search.save_search": "writes a user's own saved query string; no client table",
    "search.delete_saved_search": "deletes a user's own saved query string; no client table",
    "search.api_saved_searches": "a user's own saved query strings, as JSON; no client table",
    "devices.save_device_settings": "per-user display settings for the devices page; no client table",
    "health.health_center": "the page shell over the same subnet-filtered run as the decorated health_center_data",
}

_PLUGIN_CLIENT_FACING = (
    "acts on, or reads, a client row chosen by an id or address in the request; left undecorated until the "
    "plugin fix (Q93/Q94) that the matching row in tests/test_authz_matrix_plugins.py is marked for - that row is the proof"
)
_PLUGIN_OWN = (
    "the plugin's own configuration or list, filtered by subnet in its own query; reads none of the client tables"
)
_PLUGIN_SUBNET_URL = "scoped by a subnet id in the URL and checked with the subnet helpers before any read"

# By "<plugin dir>:<function>". A plugin route is a `@bp.route` function or a function handed to
# `add_url_rule` through api_key_required(...).
PLUGIN_ROUTE_ALLOWLIST = {
    **{f"dns-sync:{fn}": _PLUGIN_CLIENT_FACING for fn in ("export_unbound", "target_records")},
    **{
        f"dns-sync:{fn}": _PLUGIN_OWN
        for fn in ("index", "add_target", "preview_target", "toggle_target", "delete_target")
    },
    **{
        f"watchdog:{fn}": _PLUGIN_CLIENT_FACING
        for fn in (
            "target_history",
            "toggle_target",
            "delete_target",
            "watch_from_row",
            "_api_list_targets",
            "_api_add_target",
        )
    },
    **{f"watchdog:{fn}": _PLUGIN_OWN for fn in ("index", "add_target")},
    **{
        f"wol:{fn}": _PLUGIN_CLIENT_FACING
        for fn in ("delete_favourite", "wake_favourite", "wake_from_row", "_api_wake")
    },
    **{f"wol:{fn}": _PLUGIN_OWN for fn in ("index", "add_favourite")},
    **{f"presence:{fn}": _PLUGIN_CLIENT_FACING for fn in ("track", "untrack", "track_from_row")},
    **{f"presence:{fn}": _PLUGIN_OWN for fn in ("index", "add_sink", "toggle_sink", "delete_sink", "test_sink")},
    **{f"switchport:{fn}": _PLUGIN_CLIENT_FACING for fn in ("index", "_api_locate")},
    **{f"switchport:{fn}": _PLUGIN_OWN for fn in ("add_switch", "toggle_switch", "delete_switch", "set_uplink")},
    **{
        f"ipam:{fn}": _PLUGIN_SUBNET_URL
        for fn in (
            "index",
            "subnet_detail",
            "subnet_detail_legacy",
            "export_csv",
            "history",
            "import_preview",
            "import_commit",
            "save_entry",
            "delete_entry",
            "range_action",
            "add_subnet",
            "delete_subnet",
            "_api_list_entries",
            "_api_save_entry",
            "_api_next_free",
        )
    },
    **{
        f"network-discovery:{fn}": _PLUGIN_SUBNET_URL
        for fn in ("index", "start_scan", "set_schedule", "results", "export_results", "mark_known", "api_scan_status")
    },
}


def _decorated_with(node, name):
    return any(isinstance(d, ast.Call) and getattr(d.func, "id", "") == name for d in node.decorator_list)


def _is_route_decorator(d):
    return isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "route"


def _core_route_keys():
    """{"blueprint.function": decorated?} for the routes in DIAGNOSTIC_ROUTE_FILES."""
    found = {}
    for name in DIAGNOSTIC_ROUTE_FILES:
        path = f"jen/routes/{name}.py"
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
        bp_name = None
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and getattr(node.value.func, "id", "") == "Blueprint"
            ):
                bp_name = ast.literal_eval(node.value.args[0])
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and any(_is_route_decorator(d) for d in node.decorator_list):
                found[f"{bp_name}.{node.name}"] = _decorated_with(node, "diagnostic_surface")
    return found


def _plugin_route_keys():
    """{"plugin-dir:function": decorated?} for every route every bundled plugin registers."""
    found = {}
    for path in sorted(glob.glob("plugins/*/plugin.py")):
        plugin_dir = path.replace("\\", "/").split("/")[1]
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
        funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        for name, node in funcs.items():
            if any(_is_route_decorator(d) for d in node.decorator_list):
                found[f"{plugin_dir}:{name}"] = _decorated_with(node, "diagnostic_surface")
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_url_rule"
                and len(node.args) >= 3
            ):
                view = node.args[2]
                target = view.args[0] if isinstance(view, ast.Call) and view.args else view
                if isinstance(target, ast.Name) and target.id in funcs:
                    found[f"{plugin_dir}:{target.id}"] = _decorated_with(funcs[target.id], "diagnostic_surface")
    return found


class TestEveryDiagnosticRouteIsAccountedFor:
    def test_the_diagnostic_route_files_have_no_unnamed_undecorated_route(self):
        offenders = [
            key
            for key, decorated in _core_route_keys().items()
            if not decorated and key not in NAMED_ALLOWLIST and key not in ROUTE_ALLOWLIST
        ]
        assert not offenders, "decorate with @diagnostic_surface, or name it (with a reason) - " + ", ".join(offenders)

    def test_every_plugin_route_is_decorated_or_named(self):
        keys = _plugin_route_keys()
        assert keys, "no plugin routes found - the scanner is broken"
        offenders = [k for k, decorated in keys.items() if not decorated and k not in PLUGIN_ROUTE_ALLOWLIST]
        assert not offenders, "decorate it with jen.plugin_api.diagnostic_surface, or name it - " + ", ".join(offenders)

    def test_the_named_lists_have_no_stale_entries(self):
        core, plugin = _core_route_keys(), _plugin_route_keys()
        stale_core = [k for k in NAMED_ALLOWLIST if k not in core or core[k]]
        stale_plugin = [k for k in PLUGIN_ROUTE_ALLOWLIST if k not in plugin or plugin[k]]
        assert not stale_core, f"NAMED_ALLOWLIST entry no longer applies (route gone or now decorated): {stale_core}"
        assert not stale_plugin, f"PLUGIN_ROUTE_ALLOWLIST entry no longer applies: {stale_plugin}"

    def test_the_scanners_really_see_the_routes(self):
        """A vacuous pass would hide a broken scanner: these routes exist and are found."""
        core, plugin = _core_route_keys(), _plugin_route_keys()
        assert core["client.client_page"] is True and core["search.save_search"] is False
        assert plugin["wol:_api_wake"] is False and plugin["watchdog:target_history"] is False
        assert "presence:track_from_row" in plugin and "dns-sync:export_unbound" in plugin


class TestPluginsCanJoinTheInvariant:
    def test_plugin_api_exports_the_same_decorator_core_uses(self):
        from jen import plugin_api

        assert plugin_api.diagnostic_surface is access.diagnostic_surface
        assert "diagnostic_surface" in plugin_api.__all__

    def test_surfaces_are_collected_after_the_plugins_load(self):
        """The collection used to run inside _register_blueprints(), before any plugin route existed."""
        import inspect

        import jen

        src = inspect.getsource(jen.create_app)
        assert "collect_diagnostic_surfaces(app)" in src
        assert src.index("load_plugins(app)") < src.index("collect_diagnostic_surfaces(app)")
        assert "collect_diagnostic_surfaces" not in inspect.getsource(jen._register_blueprints)

    def test_a_decorated_plugin_style_route_is_collected(self):
        from flask import Blueprint, Flask

        from jen.plugin_api import diagnostic_surface

        saved = list(access.DIAGNOSTIC_SURFACES)
        try:
            app = Flask("plugin-collect-check")
            bp = Blueprint("pluginish", __name__)

            @bp.route("/x/<mac>")
            @diagnostic_surface(subject="client")
            def lookup(mac):
                return ""

            @bp.route("/y")
            def unrelated():
                return ""

            app.register_blueprint(bp)
            access.collect_diagnostic_surfaces(app)
            assert [e for e, _m, _r in access.DIAGNOSTIC_SURFACES] == ["pluginish.lookup"]
        finally:
            access.DIAGNOSTIC_SURFACES[:] = saved
