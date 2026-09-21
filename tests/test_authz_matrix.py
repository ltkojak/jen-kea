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

import hashlib
import json

import pytest

from jen import extensions

B_NAME = "ZZ-SECRET-B"
B_HOST = "secret-host-b"
B_MAC = "de:ad:be:ef:00:bb"
B_MAC_HEX = "DEADBEEF00BB"
B_LEASE_IP = "10.77.0.77"
B_RES_IP = "10.77.0.88"
A_MAC = "de:ad:be:ef:00:aa"
A_MAC_HEX = "DEADBEEF00AA"
# "4242 name": the fleet-wide reconcile summary seeded below — a distinctive AGGREGATE count
# that must never reach a subnet-scoped caller (Q56-2)
MARKERS = (B_NAME, B_HOST, B_MAC, B_MAC_HEX, "10.77.0.", "deadbeef00bb", "4242 name")

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
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN (%s, %s)", (B_MAC_HEX, A_MAC_HEX))
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN (%s, %s)", (B_MAC_HEX, A_MAC_HEX))
        cur.execute("DELETE FROM events")
        cur.execute("DELETE FROM api_keys WHERE name LIKE '_authz_%%'")
    db.commit()


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
