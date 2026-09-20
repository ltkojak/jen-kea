"""
tests/test_moved_client_rbac.py
────────────────────────────────
v5.49.0-beta.4 (Q55 B, C, I) — a client that MOVED subnets, and objects with no
subnet at all, for subnet-restricted users and keys.

The regression fixture: a device Jen last saw in subnet A (1, allowed), whose
active lease and reservation are now in subnet B (2, denied). Before this
release, authorising on the ONE "subject" subnet (A) handed the caller B's
lease and reservation as well. Now every object is judged on its own subnet
(`access.filter_client_view`). Every assertion has an unrestricted twin that
still sees everything, and every RBAC fix here carries a refusal test.

`hosts`/`lease4` are not reset between tests — every row here is uniquely
named and removed by the fixtures.

The pure `TestFilterClientView` runs without a database
(`py -m pytest --noconftest tests/test_moved_client_rbac.py -k FilterClientView`).
"""

import hashlib

import pytest

from jen.services.access import filter_client_view

MAC = "aa:bb:cc:55:00:01"
MAC_HEX = "AABBCC550001"
A, B = 1, 2  # A is accessible to the restricted caller, B is not
DEVICE_IP_A = "10.99.0.55"
LEASE_IP_B = "10.99.9.77"
RES_IP_B = "10.99.9.88"
LEASE_IP_A = "10.99.0.66"
RAW_SCOPED = "jen_moved_scoped_key_55"
RAW_OPEN = "jen_moved_open_key_55"


# ── pure ──────────────────────────────────────────────────────────────────


def _view(dev_subnet, lease_subnet, res_subnet):
    return {
        "device": {
            "mac": MAC,
            "first_seen": "x",
            "last_seen": "y",
            "last_ip": "1.1.1.1",
            "last_hostname": "h",
            "last_subnet_id": dev_subnet,
            "device_name": "n",
            "owner": "o",
            "notes": "secret",
        },
        "lease": {"ip": "2.2.2.2", "subnet_id": lease_subnet} if lease_subnet is not None else None,
        "reservation": {"ip": "3.3.3.3", "subnet_id": res_subnet} if res_subnet is not None else None,
        "subnet_id": dev_subnet,
    }


class TestFilterClientView:
    def test_unrestricted_caller_gets_the_view_untouched(self):
        v = _view(B, A, B)
        assert filter_client_view(v, None) is v

    def test_device_in_allowed_lease_and_reservation_denied(self):
        out = filter_client_view(_view(A, B, B), {A})
        assert out["lease"] is None and out["reservation"] is None
        assert out["device"]["last_ip"] == "1.1.1.1" and out["subnet_id"] == A

    def test_device_in_denied_lease_in_allowed_hides_device_placement_and_keeps_lease(self):
        out = filter_client_view(_view(B, A, None), {A})
        assert out["lease"]["ip"] == "2.2.2.2"
        d = out["device"]
        assert d["mac"] == MAC and d["first_seen"] == "x"  # bookends stay
        assert all(
            d[k] is None for k in ("last_ip", "last_hostname", "last_subnet_id", "device_name", "owner", "notes")
        )
        assert out["subnet_id"] == A  # recomputed from what remains

    def test_unplaced_device_is_hidden_from_a_restricted_caller(self):
        out = filter_client_view(_view(None, None, None), {A})
        assert out["device"]["last_ip"] is None and out["device"]["notes"] is None
        assert out["subnet_id"] is None  # nothing remains -> callers refuse

    def test_nothing_accessible_leaves_no_subject_subnet(self):
        out = filter_client_view(_view(B, B, B), {A})
        assert out["lease"] is None and out["reservation"] is None and out["subnet_id"] is None

    def test_empty_access_set_hides_everything(self):
        out = filter_client_view(_view(A, A, A), set())
        assert out["lease"] is None and out["reservation"] is None and out["subnet_id"] is None


# ── DB-backed ─────────────────────────────────────────────────────────────


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (MAC_HEX,))
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (MAC_HEX,))
        cur.execute("DELETE FROM devices WHERE mac=%s", (MAC,))
        cur.execute("DELETE FROM api_keys WHERE name LIKE '_moved_probe_%%'")
        cur.execute("DELETE FROM events WHERE mac=%s", (MAC,))
    db.commit()


def _seed(db, *, device_subnet, lease=None, reservation=None, device_ip=DEVICE_IP_A):
    """`lease`/`reservation`: (subnet_id, ip) or None."""
    _clean(db)
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, device_name, notes, first_seen, last_seen) "
            "VALUES (%s, %s, 'moved-device-host', %s, 'Moved device', 'device-note', NOW(), NOW())",
            (MAC, device_ip, device_subnet),
        )
        if lease:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), %s, 0, 'moved-lease-host')",
                (lease[1], MAC_HEX, lease[0]),
            )
        if reservation:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, %s, INET_ATON(%s), 'moved-res-host')",
                (MAC_HEX, reservation[0], reservation[1]),
            )
    db.commit()


@pytest.fixture
def moved(db):
    """Device in A; lease AND reservation in B."""
    _seed(db, device_subnet=A, lease=(B, LEASE_IP_B), reservation=(B, RES_IP_B))
    yield
    _clean(db)


@pytest.fixture
def moved_inverse(db):
    """Device in B; lease in A."""
    _seed(db, device_subnet=B, lease=(A, LEASE_IP_A), device_ip="10.99.9.55")
    yield
    _clean(db)


def _restricted(client, db, username, subnets=(A,)):
    from tests.conftest import restricted_client

    c, _uid = restricted_client(client, db, allowed_subnets=list(subnets), role="admin", username=username)
    return c


def _key(db, name, raw, subnet_access):
    from tests.test_api_key_authorization import _insert_api_key

    key_id = _insert_api_key(db, name, created_by=1, subnet_access=subnet_access)
    with db.cursor() as cur:
        cur.execute("UPDATE api_keys SET key_hash=%s WHERE id=%s", (hashlib.sha256(raw.encode()).hexdigest(), key_id))
    db.commit()


def _h(raw):
    return {"Authorization": f"Bearer {raw}"}


DENIED = (LEASE_IP_B, RES_IP_B, "moved-lease-host", "moved-res-host")


class TestTimelinePageMovedClient:
    def test_restricted_user_sees_the_device_and_nothing_from_subnet_b(self, client, db, moved):
        c = _restricted(client, db, "moved_tl_restricted1")
        body = c.get(f"/timeline?mac={MAC}").data.decode()
        assert "Device first seen" in body  # the allowed device is shown
        for leaked in DENIED:
            assert leaked not in body

    def test_unrestricted_user_sees_everything(self, logged_in_client, moved):
        body = logged_in_client.get(f"/timeline?mac={MAC}").data.decode()
        assert LEASE_IP_B in body and RES_IP_B in body

    def test_inverse_device_in_b_lease_in_a_shows_lease_hides_device_placement(self, client, db, moved_inverse):
        c = _restricted(client, db, "moved_tl_restricted2")
        body = c.get(f"/timeline?mac={MAC}").data.decode()
        assert LEASE_IP_A in body  # the accessible lease is shown
        assert "10.99.9.55" not in body and "moved-device-host" not in body and "device-note" not in body
        assert "do not have access" not in body

    def test_only_denied_objects_means_refusal(self, client, db):
        _seed(db, device_subnet=B, lease=(B, LEASE_IP_B), reservation=(B, RES_IP_B))
        try:
            c = _restricted(client, db, "moved_tl_restricted3")
            body = c.get(f"/timeline?mac={MAC}").data.decode()
            assert "do not have access" in body
            for leaked in DENIED:
                assert leaked not in body
        finally:
            _clean(db)


class TestApiMovedClient:
    def test_scoped_key_timeline_has_no_lease_or_reservation(self, client, db, moved):
        _key(db, "_moved_probe_scoped", RAW_SCOPED, [A])
        r = client.get(f"/api/v1/timeline/{MAC}", headers=_h(RAW_SCOPED))
        assert r.status_code == 200, r.data
        data = r.get_json().get("data", r.get_json())
        assert data["lease"] is None and data["reservation"] is None
        raw = r.data.decode()
        for leaked in DENIED:
            assert leaked not in raw

    def test_unscoped_key_timeline_still_has_everything(self, client, db, moved):
        _key(db, "_moved_probe_open", RAW_OPEN, None)
        r = client.get(f"/api/v1/timeline/{MAC}", headers=_h(RAW_OPEN))
        assert r.status_code == 200
        assert LEASE_IP_B in r.data.decode() and RES_IP_B in r.data.decode()

    def test_scoped_key_device_endpoint_has_no_current_lease(self, client, db, moved):
        _key(db, "_moved_probe_scoped", RAW_SCOPED, [A])
        r = client.get(f"/api/v1/devices/{MAC}", headers=_h(RAW_SCOPED))
        assert r.status_code == 200, r.data
        raw = r.data.decode()
        assert LEASE_IP_B not in raw and "moved-lease-host" not in raw
        body = r.get_json()
        payload = body.get("data", body)
        assert payload["current_lease"] is None and payload["online"] is False

    def test_unscoped_key_device_endpoint_shows_the_lease(self, client, db, moved):
        _key(db, "_moved_probe_open", RAW_OPEN, None)
        r = client.get(f"/api/v1/devices/{MAC}", headers=_h(RAW_OPEN))
        assert LEASE_IP_B in r.data.decode()


class TestDevicesPageMovedClient:
    def test_restricted_user_sees_no_reservation_ip_from_subnet_b(self, client, db, moved):
        c = _restricted(client, db, "moved_dev_restricted1")
        body = c.get(f"/devices?search={MAC}").data.decode()
        assert MAC in body  # the device (subnet A) is listed
        assert RES_IP_B not in body

    def test_unrestricted_user_sees_the_reservation_ip(self, logged_in_client, moved):
        body = logged_in_client.get(f"/devices?search={MAC}").data.decode()
        assert RES_IP_B in body


class TestUnplacedDevices:
    """C (Global Search) and I (Devices edit/delete/bulk delete): an unplaced
    device (last_subnet_id NULL) is for unrestricted users only."""

    def _unplaced(self, db):
        _seed(db, device_subnet=None, device_ip="10.99.7.7")
        with db.cursor() as cur:
            cur.execute("SELECT id FROM devices WHERE mac=%s", (MAC,))
            return cur.fetchone()["id"]

    def test_search_hides_an_unplaced_device_from_a_restricted_user(self, client, db):
        self._unplaced(db)
        try:
            c = _restricted(client, db, "moved_search_restricted1")
            body = c.get("/search?q=aa:bb:cc:55:00:01").data.decode()
            assert "10.99.7.7" not in body and "Moved device" not in body
        finally:
            _clean(db)

    def test_search_hides_it_from_a_user_with_no_subnets_at_all(self, client, db):
        self._unplaced(db)
        try:
            c = _restricted(client, db, "moved_search_nosubnets1", subnets=())
            assert "10.99.7.7" not in c.get("/search?q=aa:bb:cc:55:00:01").data.decode()
        finally:
            _clean(db)

    def test_search_still_shows_it_to_an_unrestricted_user(self, logged_in_client, db):
        self._unplaced(db)
        try:
            assert "10.99.7.7" in logged_in_client.get("/search?q=aa:bb:cc:55:00:01").data.decode()
        finally:
            _clean(db)

    def test_restricted_edit_is_refused_and_changes_nothing(self, client, db):
        device_id = self._unplaced(db)
        try:
            c = _restricted(client, db, "moved_edit_restricted1")
            r = c.post(f"/devices/edit/{device_id}", data={"device_name": "HIJACKED", "owner": "x", "notes": "x"})
            assert r.status_code == 403
            with db.cursor() as cur:
                cur.execute("SELECT device_name FROM devices WHERE id=%s", (device_id,))
                assert cur.fetchone()["device_name"] == "Moved device"
        finally:
            _clean(db)

    def test_restricted_delete_is_refused_and_keeps_the_row(self, client, db):
        device_id = self._unplaced(db)
        try:
            c = _restricted(client, db, "moved_del_restricted1")
            r = c.post(f"/devices/delete/{device_id}", follow_redirects=True)
            assert b"do not have access" in r.data
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM devices WHERE id=%s", (device_id,))
                assert cur.fetchone()["n"] == 1
        finally:
            _clean(db)

    def test_restricted_bulk_delete_counts_it_as_an_error_and_keeps_the_row(self, client, db):
        device_id = self._unplaced(db)
        try:
            c = _restricted(client, db, "moved_bulk_restricted1")
            c.post("/devices/bulk-delete", data={"device_ids[]": [str(device_id)]}, follow_redirects=True)
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM devices WHERE id=%s", (device_id,))
                assert cur.fetchone()["n"] == 1
        finally:
            _clean(db)

    def test_unrestricted_admin_can_still_delete_it(self, logged_in_client, db):
        device_id = self._unplaced(db)
        try:
            logged_in_client.post(f"/devices/delete/{device_id}", follow_redirects=True)
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM devices WHERE id=%s", (device_id,))
                assert cur.fetchone()["n"] == 0
        finally:
            _clean(db)
