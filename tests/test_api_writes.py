"""
tests/test_api_writes.py
────────────────────────
v5.34.0 (Q33) — the API v1 write endpoints. Same Bearer auth and subnet
scope as the reads plus the per-key `can_write` flag (migration 25).
Kea is stubbed by the `mock_kea` fixture (every command answers result
0), so what's under test is Jen's gating, validation, bookkeeping and
audit — not Kea.
"""

import hashlib
import json

import pytest

from jen.models.db import kea_db
from tests.test_api_key_authorization import _insert_api_key

RAW_RW = "jen_rw_probe_key"
RAW_RO = "jen_ro_probe_key"
RAW_SCOPED = "jen_scoped_probe_key"


def _key_row(db, name, raw, can_write, subnet_access=None):
    key_id = _insert_api_key(db, name, created_by=1, subnet_access=subnet_access)
    with db.cursor() as cur:
        cur.execute(
            "UPDATE api_keys SET key_hash=%s, can_write=%s WHERE id=%s",
            (hashlib.sha256(raw.encode()).hexdigest(), can_write, key_id),
        )
    db.commit()
    return key_id


@pytest.fixture
def keys(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM api_keys WHERE name LIKE '_probe_%%'")
        cur.execute("DELETE FROM devices WHERE mac IN ('aa:bb:cc:00:00:01','aa:bb:cc:00:00:02')")
        cur.execute("DELETE FROM subnet_notes WHERE subnet_id=1")
        cur.execute("DELETE FROM audit_log WHERE details LIKE '[api-key:_probe_%%'")
    db.commit()
    ids = {
        "rw": _key_row(db, "_probe_rw", RAW_RW, 1),
        "ro": _key_row(db, "_probe_ro", RAW_RO, 0),
        "scoped": _key_row(db, "_probe_scoped", RAW_SCOPED, 1, subnet_access=[999]),
    }
    yield ids
    with db.cursor() as cur:
        cur.execute("DELETE FROM api_keys WHERE name LIKE '_probe_%%'")
        cur.execute("DELETE FROM devices WHERE mac IN ('aa:bb:cc:00:00:01','aa:bb:cc:00:00:02')")
        cur.execute("DELETE FROM subnet_notes WHERE subnet_id=1")
        cur.execute("DELETE FROM audit_log WHERE details LIKE '[api-key:_probe_%%'")
    db.commit()


def _h(raw):
    return {"Authorization": f"Bearer {raw}", "Content-Type": "application/json"}


def _post(client, path, raw, body):
    return client.post(path, data=json.dumps(body), headers=_h(raw))


class TestGate:
    def test_no_key_is_401(self, client, keys):
        r = client.post("/api/v1/reservations", data="{}", content_type="application/json")
        assert r.status_code == 401

    def test_read_only_key_is_403_on_every_write(self, client, keys, mock_kea):
        for method, path in (
            ("POST", "/api/v1/reservations"),
            ("DELETE", "/api/v1/reservations/1"),
            ("PATCH", "/api/v1/devices/aa:bb:cc:00:00:01"),
            ("POST", "/api/v1/subnets/1/notes"),
        ):
            r = client.open(path, method=method, data="{}", headers=_h(RAW_RO))
            assert r.status_code == 403, (method, path, r.data)
            assert "read-only" in r.get_json()["error"]

    def test_read_endpoints_still_work_with_a_read_only_key(self, client, keys, mock_kea):
        assert client.get("/api/v1/subnets", headers=_h(RAW_RO)).status_code == 200

    def test_rate_limit(self, client, keys, mock_kea, monkeypatch):
        from jen.services import api_auth

        monkeypatch.setattr(api_auth, "WRITE_RATE_PER_MINUTE", 3)
        api_auth._write_hits.clear()
        codes = [_post(client, "/api/v1/subnets/1/notes", RAW_RW, {"text": "x"}).status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        api_auth._write_hits.clear()


class TestReservations:
    def test_create_validates_and_audits(self, client, keys, mock_kea, db):
        r = _post(
            client,
            "/api/v1/reservations",
            RAW_RW,
            {"subnet_id": 1, "ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:01", "hostname": "printer"},
        )
        assert r.status_code == 201, r.data
        body = r.get_json()
        assert body["mac"] == "aa:bb:cc:dd:ee:01" and body["subnet_id"] == 1 and body["ip"] == "192.168.1.50"
        with db.cursor() as cur:
            cur.execute(
                "SELECT details FROM audit_log WHERE action='ADD_RESERVATION' AND details LIKE '[api-key:_probe_rw]%%' ORDER BY id DESC LIMIT 1"
            )
            assert "MAC=aa:bb:cc:dd:ee:01" in cur.fetchone()["details"]

    @pytest.mark.parametrize(
        "body,fragment",
        [
            ({"ip": "1.2.3.4", "mac": "aa:bb:cc:dd:ee:01"}, "subnet_id"),
            ({"subnet_id": 1, "ip": "not-an-ip", "mac": "aa:bb:cc:dd:ee:01"}, "invalid ip"),
            ({"subnet_id": 1, "ip": "192.168.1.5", "mac": "zz"}, "invalid mac"),
            (
                {"subnet_id": 1, "ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:01", "hostname": "bad host!"},
                "invalid hostname",
            ),
        ],
    )
    def test_create_rejects_bad_input(self, client, keys, mock_kea, body, fragment):
        r = _post(client, "/api/v1/reservations", RAW_RW, body)
        assert r.status_code == 400 and fragment in r.get_json()["error"]

    def test_create_unknown_subnet_is_404_and_scope_is_403(self, client, keys, mock_kea):
        r = _post(
            client, "/api/v1/reservations", RAW_RW, {"subnet_id": 4242, "ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:01"}
        )
        assert r.status_code == 404
        r = _post(
            client,
            "/api/v1/reservations",
            RAW_SCOPED,
            {"subnet_id": 1, "ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:01"},
        )
        assert r.status_code == 403

    def test_create_kea_refusal_is_502(self, client, keys, monkeypatch):
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **k: {"result": 1, "text": "Duplicate host"})
        r = _post(
            client, "/api/v1/reservations", RAW_RW, {"subnet_id": 1, "ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:01"}
        )
        assert r.status_code == 502 and "Duplicate host" in r.get_json()["error"]

    def test_delete_missing_is_404_and_delete_works(self, client, keys, mock_kea, db):
        r = client.delete("/api/v1/reservations/999999", headers=_h(RAW_RW))
        assert r.status_code == 404
        with kea_db() as kdb, kdb.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('AABBCCDDEE02'), 0, 1, INET_ATON('192.168.1.60'), '_probe_host')"
            )
            host_id = cur.lastrowid
            kdb.commit()
        try:
            r = client.delete(f"/api/v1/reservations/{host_id}", headers=_h(RAW_SCOPED))
            assert r.status_code == 403
            r = client.delete(f"/api/v1/reservations/{host_id}", headers=_h(RAW_RW))
            assert r.status_code == 200, r.data
            assert r.get_json()["mac"] == "aa:bb:cc:dd:ee:02"
            with db.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) c FROM audit_log WHERE action='DELETE_RESERVATION' AND details LIKE '[api-key:_probe_rw]%%'"
                )
                assert cur.fetchone()["c"] >= 1
        finally:
            with kea_db() as kdb, kdb.cursor() as cur:
                cur.execute("DELETE FROM hosts WHERE host_id=%s", (host_id,))
                kdb.commit()


class TestDevices:
    def _seed(self, db, mac, subnet_id=1):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, device_name, owner, notes, last_subnet_id) VALUES (%s, 'old', 'nobody', 'n', %s)",
                (mac, subnet_id),
            )
        db.commit()

    def test_patch_updates_only_sent_fields(self, client, keys, mock_kea, db):
        self._seed(db, "aa:bb:cc:00:00:01")
        r = client.patch(
            "/api/v1/devices/AA:BB:CC:00:00:01", data=json.dumps({"name": "Printer", "notes": None}), headers=_h(RAW_RW)
        )
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body["name"] == "Printer" and body["notes"] is None and body["owner"] == "nobody"

    def test_patch_rejects_empty_and_unknown(self, client, keys, mock_kea, db):
        self._seed(db, "aa:bb:cc:00:00:01")
        assert client.patch("/api/v1/devices/aa:bb:cc:00:00:01", data="{}", headers=_h(RAW_RW)).status_code == 400
        assert (
            client.patch(
                "/api/v1/devices/aa:bb:cc:00:00:99", data=json.dumps({"name": "x"}), headers=_h(RAW_RW)
            ).status_code
            == 404
        )
        assert (
            client.patch("/api/v1/devices/nope", data=json.dumps({"name": "x"}), headers=_h(RAW_RW)).status_code == 400
        )

    def test_patch_respects_subnet_scope(self, client, keys, mock_kea, db):
        self._seed(db, "aa:bb:cc:00:00:02", subnet_id=1)
        r = client.patch("/api/v1/devices/aa:bb:cc:00:00:02", data=json.dumps({"name": "x"}), headers=_h(RAW_SCOPED))
        assert r.status_code == 403


class TestScopedKeyOnUnplacedDevice:
    """v5.49.0-beta.2 (audit F) - a subnet-scoped write key may not PATCH a
    device Jen has never placed in a subnet; an unscoped key still can."""

    def _seed_unplaced(self, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, device_name, owner, notes, last_subnet_id) "
                "VALUES ('aa:bb:cc:00:00:01', 'old', 'nobody', 'n', NULL)"
            )
        db.commit()

    def test_scoped_key_refused(self, client, keys, mock_kea, db):
        self._seed_unplaced(db)
        r = client.patch("/api/v1/devices/aa:bb:cc:00:00:01", data=json.dumps({"name": "x"}), headers=_h(RAW_SCOPED))
        assert r.status_code == 403
        assert b"no known subnet" in r.data
        with db.cursor() as cur:
            cur.execute("SELECT device_name FROM devices WHERE mac='aa:bb:cc:00:00:01'")
            assert cur.fetchone()["device_name"] == "old"

    def test_unscoped_key_proceeds(self, client, keys, mock_kea, db):
        self._seed_unplaced(db)
        r = client.patch("/api/v1/devices/aa:bb:cc:00:00:01", data=json.dumps({"name": "x"}), headers=_h(RAW_RW))
        assert r.status_code == 200, r.data


class TestSubnetNotes:
    def test_set_clear_scope_and_404(self, client, keys, mock_kea, db):
        r = _post(client, "/api/v1/subnets/1/notes", RAW_RW, {"text": "  core switch closet  "})
        assert r.status_code == 200 and r.get_json()["notes"] == "core switch closet"
        with db.cursor() as cur:
            cur.execute("SELECT notes FROM subnet_notes WHERE subnet_id=1")
            assert cur.fetchone()["notes"] == "core switch closet"
        assert _post(client, "/api/v1/subnets/1/notes", RAW_RW, {"text": ""}).get_json()["notes"] == ""
        assert _post(client, "/api/v1/subnets/1/notes", RAW_SCOPED, {"text": "x"}).status_code == 403
        assert _post(client, "/api/v1/subnets/4242/notes", RAW_RW, {"text": "x"}).status_code == 404
        assert _post(client, "/api/v1/subnets/1/notes", RAW_RW, {"text": 5}).status_code == 400


class TestKeysPage:
    def test_create_form_offers_write_access_and_list_shows_it(self, logged_in_client, keys):
        page = logged_in_client.get("/settings/api-keys").get_data(as_text=True)
        assert 'name="can_write"' in page
        assert "read/write" in page and "read-only" in page

    def test_creating_a_key_with_writes_sets_the_flag(self, logged_in_client, keys, db):
        r = logged_in_client.post(
            "/settings/api-keys/create",
            data={"name": "_probe_created_rw", "subnet_ids": ["all"], "can_write": "1"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT can_write FROM api_keys WHERE name='_probe_created_rw'")
            assert cur.fetchone()["can_write"] == 1
        # End this connection's REPEATABLE-READ snapshot before the second
        # create, or the next SELECT can't see the row the route inserted.
        db.commit()
        r = logged_in_client.post(
            "/settings/api-keys/create",
            data={"name": "_probe_created_ro", "subnet_ids": ["all"]},
            follow_redirects=True,
        )
        with db.cursor() as cur:
            cur.execute("SELECT can_write FROM api_keys WHERE name='_probe_created_ro'")
            assert cur.fetchone()["can_write"] == 0
