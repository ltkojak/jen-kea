"""
tests/test_kea6_reservations.py
───────────────────────────────
DHCPv6 host reservations: get_ipv6_reservations(), DUID normalisation, the add/delete service functions and their routes, and the v6 Reservations view.

Split out of the monolithic tests/test_kea6.py in v5.6.1.
"""

import pytest

from jen import extensions


class TestGetIpv6Reservations:
    def _insert_host_with_reservations(
        self, db, host_id_var="h1", duid=b"\x00\x03\x00\x01\x00\x1a\x2b\x3c\x4d\x5e", subnet_id=1, reservations=()
    ):
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type,
                    dhcp6_subnet_id, hostname)
                VALUES (%s, 1, %s, %s)
            """,
                (duid, subnet_id, f"host-{host_id_var}"),
            )
            host_id = cur.lastrowid
            for res in reservations:
                cur.execute(
                    """
                    INSERT INTO ipv6_reservations (address, prefix_len, type,
                        dhcp6_iaid, host_id)
                    VALUES (%(address)s, %(prefix_len)s, %(type)s, %(iaid)s, %(host_id)s)
                """,
                    {**res, "host_id": host_id},
                )
        db.commit()
        return host_id

    def test_host_with_address_and_prefix_reservation(self, db, monkeypatch):
        """The core one-to-many case the plan calls out: a single device
        holding BOTH an IA_NA (address) and an IA_PD (delegated prefix)
        reservation at once."""
        import jen.models.db as db_mod

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import get_ipv6_reservations

        with db.cursor() as cur:
            cur.execute("DELETE FROM ipv6_reservations")
            cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
        db.commit()
        self._insert_host_with_reservations(
            db,
            subnet_id=1,
            reservations=[
                {"address": "2001:db8:1::10", "prefix_len": 128, "type": 0, "iaid": 1},
                {"address": "2001:db8:1:1000::", "prefix_len": 56, "type": 2, "iaid": 2},
            ],
        )
        results = get_ipv6_reservations(subnet_id=1)
        assert len(results) == 1
        host = results[0]
        assert len(host["reservations"]) == 2
        types = {r["type_name"] for r in host["reservations"]}
        assert types == {"IA_NA", "IA_PD"}

    def test_filters_by_v6_subnet_not_v4(self, db, monkeypatch):
        """dhcp6_subnet_id and dhcp4_subnet_id are independent columns on
        the same hosts row — filtering must use the v6 one only."""
        import jen.models.db as db_mod

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import get_ipv6_reservations

        with db.cursor() as cur:
            cur.execute("DELETE FROM ipv6_reservations")
            cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL OR dhcp4_subnet_id IS NOT NULL")
            # A host with a v4-only reservation (dhcp6_subnet_id NULL) must
            # never appear in v6 results.
            cur.execute(
                """
                INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type,
                    dhcp4_subnet_id, dhcp6_subnet_id, hostname)
                VALUES (%s, 0, 1, NULL, 'v4-only-host')
            """,
                (b"\xaa\xbb\xcc\xdd\xee\xff",),
            )
        db.commit()
        self._insert_host_with_reservations(
            db,
            subnet_id=1,
            reservations=[{"address": "2001:db8:1::20", "prefix_len": 128, "type": 0, "iaid": 1}],
        )
        results = get_ipv6_reservations(subnet_id=1)
        assert len(results) == 1
        assert results[0]["hostname"] == "host-h1"

    def test_no_reservations_table_rows_for_unreferenced_host(self, db, monkeypatch):
        import jen.models.db as db_mod

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import get_ipv6_reservations

        with db.cursor() as cur:
            cur.execute("DELETE FROM ipv6_reservations")
            cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
        db.commit()
        self._insert_host_with_reservations(db, subnet_id=3, reservations=[])
        results = get_ipv6_reservations(subnet_id=3)
        assert len(results) == 1
        assert results[0]["reservations"] == []


class TestNormalizeDuid:
    def test_bare_hex_normalizes_to_colon_separated(self):
        from jen.services.kea6 import normalize_duid

        assert normalize_duid("00030001001a2b3c4d5e") == "00:03:00:01:00:1a:2b:3c:4d:5e"

    def test_already_colon_separated_passthrough(self):
        from jen.services.kea6 import normalize_duid

        assert normalize_duid("00:03:00:01:00:1a:2b:3c:4d:5e") == "00:03:00:01:00:1a:2b:3c:4d:5e"

    def test_uppercase_normalized_to_lowercase(self):
        from jen.services.kea6 import normalize_duid

        assert normalize_duid("00:03:00:01:AA:BB:CC:DD:EE:FF") == "00:03:00:01:aa:bb:cc:dd:ee:ff"

    def test_odd_length_hex_rejected(self):
        from jen.services.kea6 import normalize_duid

        with pytest.raises(ValueError):
            normalize_duid("0003000")

    def test_non_hex_rejected(self):
        from jen.services.kea6 import normalize_duid

        with pytest.raises(ValueError):
            normalize_duid("zzzz")

    def test_empty_rejected(self):
        from jen.services.kea6 import normalize_duid

        with pytest.raises(ValueError):
            normalize_duid("")


class TestAddV6Reservation:
    def test_address_only_reservation(self, monkeypatch):
        from jen.services import kea6 as kea6_module

        captured = {}
        monkeypatch.setattr(
            kea6_module,
            "kea6_command",
            lambda cmd, arguments=None, server=None: (captured.update(cmd=cmd, args=arguments), {"result": 0})[1],
        )
        kea6_module.add_v6_reservation(
            1, "00:03:00:01:aa:bb:cc:dd:ee:ff", hostname="my-host", addresses=["2001:db8::10"]
        )
        assert captured["cmd"] == "reservation-add"
        res = captured["args"]["reservation"]
        assert res["subnet-id"] == 1
        assert res["duid"] == "00:03:00:01:aa:bb:cc:dd:ee:ff"
        assert res["ip-addresses"] == ["2001:db8::10"]
        assert res["hostname"] == "my-host"
        assert "prefixes" not in res

    def test_prefix_only_reservation(self, monkeypatch):
        from jen.services import kea6 as kea6_module

        captured = {}
        monkeypatch.setattr(
            kea6_module,
            "kea6_command",
            lambda cmd, arguments=None, server=None: (captured.update(args=arguments), {"result": 0})[1],
        )
        kea6_module.add_v6_reservation(1, "00:03:00:01:aa:bb:cc:dd:ee:ff", prefix="2001:db8:1:1000::", prefix_len=56)
        res = captured["args"]["reservation"]
        assert res["prefixes"] == ["2001:db8:1:1000::/56"]
        assert "ip-addresses" not in res

    def test_both_address_and_prefix_at_once(self, monkeypatch):
        """The core one-to-many case: a single DUID reserving both an
        address AND a delegated prefix simultaneously."""
        from jen.services import kea6 as kea6_module

        captured = {}
        monkeypatch.setattr(
            kea6_module,
            "kea6_command",
            lambda cmd, arguments=None, server=None: (captured.update(args=arguments), {"result": 0})[1],
        )
        kea6_module.add_v6_reservation(
            1, "00:03:00:01:aa:bb:cc:dd:ee:ff", addresses=["2001:db8::10"], prefix="2001:db8:1:1000::", prefix_len=56
        )
        res = captured["args"]["reservation"]
        assert res["ip-addresses"] == ["2001:db8::10"]
        assert res["prefixes"] == ["2001:db8:1:1000::/56"]

    def test_neither_address_nor_prefix_rejected_before_calling_kea(self, monkeypatch):
        from jen.services import kea6 as kea6_module

        called = {"count": 0}
        monkeypatch.setattr(
            kea6_module, "kea6_command", lambda *a, **kw: called.__setitem__("count", called["count"] + 1)
        )
        result = kea6_module.add_v6_reservation(1, "00:03:00:01:aa:bb:cc:dd:ee:ff")
        assert result["result"] != 0
        assert called["count"] == 0

    def test_prefix_without_prefix_len_rejected(self, monkeypatch):
        from jen.services import kea6 as kea6_module

        called = {"count": 0}
        monkeypatch.setattr(
            kea6_module, "kea6_command", lambda *a, **kw: called.__setitem__("count", called["count"] + 1)
        )
        result = kea6_module.add_v6_reservation(1, "00:03:00:01:aa:bb:cc:dd:ee:ff", prefix="2001:db8:1:1000::")
        assert result["result"] != 0
        assert called["count"] == 0


class TestDeleteV6Reservation:
    def test_sends_duid_identifier_type(self, monkeypatch):
        from jen.services import kea6 as kea6_module

        captured = {}
        monkeypatch.setattr(
            kea6_module,
            "kea6_command",
            lambda cmd, arguments=None, server=None: (captured.update(cmd=cmd, args=arguments), {"result": 0})[1],
        )
        kea6_module.delete_v6_reservation(1, "00030001aabbccddeeff")
        assert captured["cmd"] == "reservation-del"
        assert captured["args"]["identifier-type"] == "duid"
        assert captured["args"]["subnet-id"] == 1
        assert captured["args"]["identifier"] == "00:03:00:01:aa:bb:cc:dd:ee:ff"


class TestAddReservation6Route:
    def test_requires_admin(self, client, db):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[], role="viewer")
        resp = c.get("/reservations/add6", follow_redirects=False)
        assert resp.status_code == 302

    def test_redirects_when_no_v6_subnets(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.get("/reservations/add6", follow_redirects=False)
        assert resp.status_code == 302

    def test_post_success_redirects_to_v6_reservations(self, logged_in_client, monkeypatch):
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        monkeypatch.setattr(kea6_module, "add_v6_reservation", lambda *a, **kw: {"result": 0, "text": "ok"})
        resp = logged_in_client.post(
            "/reservations/add6",
            data={
                "subnet_id": "1",
                "duid": "00030001aabbccddeeff",
                "hostname": "my-host",
                "address": "2001:db8::10",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "view=v6" in resp.headers["Location"]

    def test_post_rejects_invalid_subnet(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        resp = logged_in_client.post(
            "/reservations/add6",
            data={
                "subnet_id": "999",
                "duid": "00030001aabbccddeeff",
                "address": "2001:db8::10",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid IPv6 subnet" in resp.data

    def test_post_rejects_missing_address_and_prefix(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        resp = logged_in_client.post(
            "/reservations/add6",
            data={
                "subnet_id": "1",
                "duid": "00030001aabbccddeeff",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Specify an address" in resp.data

    def test_post_rejects_invalid_duid(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        resp = logged_in_client.post(
            "/reservations/add6",
            data={
                "subnet_id": "1",
                "duid": "not-hex-zz",
                "address": "2001:db8::10",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"DUID" in resp.data

    def test_kea_failure_surfaces_error_and_stays_on_form(self, logged_in_client, monkeypatch):
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        monkeypatch.setattr(
            kea6_module, "add_v6_reservation", lambda *a, **kw: {"result": 1, "text": "duplicate reservation"}
        )
        resp = logged_in_client.post(
            "/reservations/add6",
            data={
                "subnet_id": "1",
                "duid": "00030001aabbccddeeff",
                "address": "2001:db8::10",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"duplicate reservation" in resp.data


class TestDeleteReservation6Route:
    def test_requires_admin(self, client, db):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=[], role="viewer")
        resp = c.post("/reservations/delete6", data={"subnet_id": "1", "duid": "aabbcc"}, follow_redirects=False)
        assert resp.status_code == 302

    def test_success_calls_kea6_delete(self, logged_in_client, monkeypatch):
        import jen.services.kea6 as kea6_module

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        captured = {}
        monkeypatch.setattr(
            kea6_module,
            "delete_v6_reservation",
            lambda subnet_id, duid, server=None: (captured.update(subnet_id=subnet_id, duid=duid), {"result": 0})[1],
        )
        resp = logged_in_client.post(
            "/reservations/delete6",
            data={
                "subnet_id": "1",
                "duid": "00030001aabbccddeeff",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert captured["subnet_id"] == 1
        assert captured["duid"] == "00:03:00:01:aa:bb:cc:dd:ee:ff"


class TestReservationsV6View:
    def _insert_host_with_reservations(
        self, db, duid=b"\x00\x03\x00\x01\x00\x1a\x2b\x3c\x4d\x5e", subnet_id=1, hostname="v6-host", reservations=()
    ):
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type,
                    dhcp6_subnet_id, hostname)
                VALUES (%s, 1, %s, %s)
            """,
                (duid, subnet_id, hostname),
            )
            host_id = cur.lastrowid
            for res in reservations:
                cur.execute(
                    """
                    INSERT INTO ipv6_reservations (address, prefix_len, type,
                        dhcp6_iaid, host_id)
                    VALUES (%(address)s, %(prefix_len)s, %(type)s, %(iaid)s, %(host_id)s)
                """,
                    {**res, "host_id": host_id},
                )
        db.commit()
        return host_id

    def test_segmented_control_absent_when_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        _invalidate_settings_cache()
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        assert b"segmented-control" not in resp.data

    def test_v6_view_redirects_when_no_v6_subnets(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.get("/reservations?view=v6", follow_redirects=False)
        assert resp.status_code == 302

    def test_v6_view_renders_one_to_many_reservations(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        with db.cursor() as cur:
            cur.execute("DELETE FROM ipv6_reservations")
            cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
        db.commit()
        self._insert_host_with_reservations(
            db,
            subnet_id=1,
            hostname="dual-res-host",
            reservations=[
                {"address": "2001:db8::10", "prefix_len": 128, "type": 0, "iaid": 1},
                {"address": "2001:db8:1000::", "prefix_len": 56, "type": 2, "iaid": 2},
            ],
        )
        resp = logged_in_client.get("/reservations?view=v6")
        assert resp.status_code == 200
        assert b"dual-res-host" in resp.data
        assert b"2001:db8::10" in resp.data
        assert b"2001:db8:1000::" in resp.data

    def test_v6_view_search_filters_by_hostname(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        with db.cursor() as cur:
            cur.execute("DELETE FROM ipv6_reservations")
            cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
        db.commit()
        self._insert_host_with_reservations(
            db,
            subnet_id=1,
            hostname="findme",
            reservations=[{"address": "2001:db8::1", "prefix_len": 128, "type": 0, "iaid": 1}],
        )
        self._insert_host_with_reservations(
            db,
            subnet_id=1,
            hostname="other",
            duid=b"\x00\x03\x00\x01\x99\x88\x77\x66\x55\xaa",
            reservations=[{"address": "2001:db8::2", "prefix_len": 128, "type": 0, "iaid": 1}],
        )
        resp = logged_in_client.get("/reservations?view=v6&search=findme")
        assert resp.status_code == 200
        assert b"findme" in resp.data
        assert b"other" not in resp.data
