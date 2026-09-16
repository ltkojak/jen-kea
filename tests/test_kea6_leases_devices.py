"""
tests/test_kea6_leases_devices.py
─────────────────────────────────
DHCPv6 leases and devices: DUID/MAC extraction, list_lease6(), the v6 Leases/Devices views, and the dashboard v6 summary.

Split out of the monolithic tests/test_kea6.py in v5.6.1.
"""

import pytest

from jen import extensions


class TestExtractMacFromDuid:
    def test_duid_ll_extracts_mac(self):
        from jen.services.kea6 import extract_mac_from_duid

        # DUID-LL: type=0003, hwtype=0001 (Ethernet), MAC 00:1a:2b:3c:4d:5e
        duid_hex = "00030001" + "001a2b3c4d5e"
        assert extract_mac_from_duid(duid_hex) == "00:1a:2b:3c:4d:5e"

    def test_duid_llt_extracts_mac(self):
        from jen.services.kea6 import extract_mac_from_duid

        # DUID-LLT: type=0001, hwtype=0001, time=12345678, MAC aa:bb:cc:dd:ee:ff
        duid_hex = "00010001" + "12345678" + "aabbccddeeff"
        assert extract_mac_from_duid(duid_hex) == "aa:bb:cc:dd:ee:ff"

    def test_duid_en_returns_none(self):
        from jen.services.kea6 import extract_mac_from_duid

        # DUID-EN (type=0002) — no embedded link-layer address
        duid_hex = "0002" + "0000abcd" + "deadbeef"
        assert extract_mac_from_duid(duid_hex) is None

    def test_duid_uuid_returns_none(self):
        from jen.services.kea6 import extract_mac_from_duid

        duid_hex = "0004" + "0" * 32
        assert extract_mac_from_duid(duid_hex) is None

    def test_malformed_or_empty_returns_none(self):
        from jen.services.kea6 import extract_mac_from_duid

        assert extract_mac_from_duid("") is None
        assert extract_mac_from_duid(None) is None
        assert extract_mac_from_duid("ab") is None
        assert extract_mac_from_duid("not-hex-zz") is None


class TestGetLease6Mac:
    def test_prefers_hwaddr_when_present(self):
        from jen.services.kea6 import get_lease6_mac

        # hwaddr present should win even though the DUID also decodes
        duid_hex = "00030001" + "aaaaaaaaaaaa"
        assert get_lease6_mac("001a2b3c4d5e", duid_hex) == "00:1a:2b:3c:4d:5e"

    def test_falls_back_to_duid_when_hwaddr_absent(self):
        from jen.services.kea6 import get_lease6_mac

        duid_hex = "00030001" + "001a2b3c4d5e"
        assert get_lease6_mac("", duid_hex) == "00:1a:2b:3c:4d:5e"
        assert get_lease6_mac(None, duid_hex) == "00:1a:2b:3c:4d:5e"

    def test_none_when_neither_source_usable(self):
        from jen.services.kea6 import get_lease6_mac

        duid_en_hex = "0002" + "0000abcd" + "deadbeef"
        assert get_lease6_mac("", duid_en_hex) is None


class TestListLease6:
    def _insert_lease(self, db, **overrides):
        row = {
            "address": "2001:db8:1::1",
            "duid": bytes.fromhex("00030001001a2b3c4d5e"),
            "valid_lifetime": 3600,
            "expire": "2026-08-15 00:00:00",
            "subnet_id": 1,
            "pref_lifetime": 1800,
            "lease_type": 0,
            "iaid": 1,
            "prefix_len": 128,
            "hostname": "test-host",
            "hwaddr": None,
            "state": 0,
        }
        row.update(overrides)
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                    subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                    hostname, hwaddr, state)
                VALUES (%(address)s, %(duid)s, %(valid_lifetime)s, %(expire)s,
                    %(subnet_id)s, %(pref_lifetime)s, %(lease_type)s, %(iaid)s,
                    %(prefix_len)s, %(hostname)s, %(hwaddr)s, %(state)s)
            """,
                row,
            )
        db.commit()

    def test_lists_basic_lease(self, db, monkeypatch):
        import jen.models.db as db_mod

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)  # keep fixture's conn alive
        from jen.services.kea6 import list_lease6

        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1")
        results = list_lease6()
        assert len(results) == 1
        r = results[0]
        assert r["address"] == "2001:db8:1::1"
        assert r["lease_type_name"] == "IA_NA"
        assert r["mac"] == "00:1a:2b:3c:4d:5e"  # DUID-LL fallback, no hwaddr
        assert r["mac_source"] == "duid"
        assert r["expired"] is False

    def test_filters_by_subnet_and_type(self, db, monkeypatch):
        import jen.models.db as db_mod

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import list_lease6

        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1", subnet_id=1, lease_type=0)
        self._insert_lease(db, address="2001:db8:2::1", subnet_id=2, lease_type=2, prefix_len=56)
        assert len(list_lease6(subnet_id=1)) == 1
        assert len(list_lease6(lease_type=2)) == 1
        assert list_lease6(lease_type=2)[0]["lease_type_name"] == "IA_PD"

    def test_hwaddr_present_wins_over_duid(self, db, monkeypatch):
        import jen.models.db as db_mod

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import list_lease6

        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1", hwaddr=bytes.fromhex("aabbccddeeff"))
        r = list_lease6()[0]
        assert r["mac"] == "aa:bb:cc:dd:ee:ff"
        assert r["mac_source"] == "hwaddr"

    def test_mac_source_empty_when_neither_source_usable(self, db, monkeypatch):
        """v5.45.0 (Q46) — DUID-EN has no embedded link-layer address, so
        neither hwaddr nor the DUID can produce a MAC at all."""
        import jen.models.db as db_mod

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        from jen.services.kea6 import list_lease6

        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1", duid=bytes.fromhex("00020000abcddeadbeef"))
        r = list_lease6()[0]
        assert r["mac"] == ""
        assert r["mac_source"] == ""


class TestLease6ByHwaddrMac:
    """v5.45.0 (Q46) — the Devices page's v4/v6 join: only leases with a
    real captured hwaddr are eligible, never a DUID-derived guess."""

    def _insert_lease(self, db, **overrides):
        row = {
            "address": "2001:db8:1::1",
            "duid": bytes.fromhex("00030001001a2b3c4d5e"),
            "valid_lifetime": 3600,
            "expire": "2026-08-15 00:00:00",
            "subnet_id": 1,
            "pref_lifetime": 1800,
            "lease_type": 0,
            "iaid": 1,
            "prefix_len": 128,
            "hostname": "",
            "hwaddr": None,
            "state": 0,
        }
        row.update(overrides)
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                    subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                    hostname, hwaddr, state)
                VALUES (%(address)s, %(duid)s, %(valid_lifetime)s, %(expire)s,
                    %(subnet_id)s, %(pref_lifetime)s, %(lease_type)s, %(iaid)s,
                    %(prefix_len)s, %(hostname)s, %(hwaddr)s, %(state)s)
            """,
                row,
            )
        db.commit()

    def test_only_hwaddr_leases_are_keyed(self, db, monkeypatch):
        import jen.models.db as db_mod
        from jen.services.kea6 import lease6_by_hwaddr_mac

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1", hwaddr=bytes.fromhex("aabbccddeeff"))
        self._insert_lease(db, address="2001:db8:1::2", hwaddr=None)  # DUID-only, must be excluded
        by_mac = lease6_by_hwaddr_mac()
        assert list(by_mac.keys()) == ["aa:bb:cc:dd:ee:ff"]
        assert by_mac["aa:bb:cc:dd:ee:ff"][0]["address"] == "2001:db8:1::1"

    def test_one_mac_can_carry_multiple_addresses(self, db, monkeypatch):
        import jen.models.db as db_mod
        from jen.services.kea6 import lease6_by_hwaddr_mac

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        mac = bytes.fromhex("aabbccddeeff")
        self._insert_lease(db, address="2001:db8:1::1", hwaddr=mac, lease_type=0)
        self._insert_lease(db, address="2001:db8:1::", prefix_len=56, hwaddr=mac, lease_type=2)
        by_mac = lease6_by_hwaddr_mac()
        assert len(by_mac["aa:bb:cc:dd:ee:ff"]) == 2


class TestLease6DevicesWithoutHwaddr:
    def _insert_lease(self, db, **overrides):
        row = {
            "address": "2001:db8:1::1",
            "duid": bytes.fromhex("00030001001a2b3c4d5e"),
            "valid_lifetime": 3600,
            "expire": "2026-08-15 00:00:00",
            "subnet_id": 1,
            "pref_lifetime": 1800,
            "lease_type": 0,
            "iaid": 1,
            "prefix_len": 128,
            "hostname": "",
            "hwaddr": None,
            "state": 0,
        }
        row.update(overrides)
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                    subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                    hostname, hwaddr, state)
                VALUES (%(address)s, %(duid)s, %(valid_lifetime)s, %(expire)s,
                    %(subnet_id)s, %(pref_lifetime)s, %(lease_type)s, %(iaid)s,
                    %(prefix_len)s, %(hostname)s, %(hwaddr)s, %(state)s)
            """,
                row,
            )
        db.commit()

    def test_hwaddr_leases_are_excluded(self, db, monkeypatch):
        import jen.models.db as db_mod
        from jen.services.kea6 import lease6_devices_without_hwaddr

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1", hwaddr=bytes.fromhex("aabbccddeeff"))
        assert lease6_devices_without_hwaddr() == []

    def test_duid_only_lease_grouped_by_duid(self, db, monkeypatch):
        import jen.models.db as db_mod
        from jen.services.kea6 import lease6_devices_without_hwaddr

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1", hostname="iot1")
        devices = lease6_devices_without_hwaddr()
        assert len(devices) == 1
        assert devices[0]["hostname"] == "iot1"
        assert devices[0]["addresses"][0]["address"] == "2001:db8:1::1"


class TestListLease6Devices:
    def _insert_lease(self, db, **overrides):
        row = {
            "address": "2001:db8:1::1",
            "duid": bytes.fromhex("00030001001a2b3c4d5e"),
            "valid_lifetime": 3600,
            "expire": "2026-08-15 00:00:00",
            "subnet_id": 1,
            "pref_lifetime": 1800,
            "lease_type": 0,
            "iaid": 1,
            "prefix_len": 128,
            "hostname": "",
            "hwaddr": None,
            "state": 0,
        }
        row.update(overrides)
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                    subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                    hostname, hwaddr, state)
                VALUES (%(address)s, %(duid)s, %(valid_lifetime)s, %(expire)s,
                    %(subnet_id)s, %(pref_lifetime)s, %(lease_type)s, %(iaid)s,
                    %(prefix_len)s, %(hostname)s, %(hwaddr)s, %(state)s)
            """,
                row,
            )
        db.commit()

    def test_groups_ia_na_and_ia_pd_into_one_device(self, db, monkeypatch):
        """The core case the plan calls out: one physical device holding
        both an address and a delegated-prefix lease must collapse to a
        single device row, not two."""
        import jen.models.db as db_mod
        from jen.services.kea6 import list_lease6_devices

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        same_duid = bytes.fromhex("00030001001a2b3c4d5e")
        self._insert_lease(db, address="2001:db8:1::1", duid=same_duid, lease_type=0, iaid=1, hostname="my-laptop")
        self._insert_lease(db, address="2001:db8:1:1000::", duid=same_duid, lease_type=2, iaid=2, prefix_len=56)
        devices = list_lease6_devices()
        assert len(devices) == 1
        assert len(devices[0]["addresses"]) == 2
        assert devices[0]["hostname"] == "my-laptop"

    def test_different_duids_are_different_devices(self, db, monkeypatch):
        import jen.models.db as db_mod
        from jen.services.kea6 import list_lease6_devices

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1", duid=bytes.fromhex("00030001001a2b3c4d5e"))
        self._insert_lease(db, address="2001:db8:1::2", duid=bytes.fromhex("000300019988776655aa"))
        devices = list_lease6_devices()
        assert len(devices) == 2

    def test_mac_extraction_feeds_manufacturer_lookup(self, db, monkeypatch):
        """DUID-LL with a real Apple OUI prefix should resolve a
        manufacturer via the existing fingerprint.lookup_oui table."""
        import jen.models.db as db_mod
        from jen.services import fingerprint as fp
        from jen.services.kea6 import list_lease6_devices

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        # Pick a real OUI prefix from the loaded DB so this test doesn't
        # depend on a specific vendor being present.
        if not fp.OUI_DB:
            pytest.skip("OUI_DB not loaded in this environment")
        real_oui = next(iter(fp.OUI_DB))  # e.g. "aa:bb:cc"
        mac_hex = real_oui.replace(":", "") + "001122"
        duid_hex = "00030001" + mac_hex
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        self._insert_lease(db, address="2001:db8:1::1", duid=bytes.fromhex(duid_hex))
        devices = list_lease6_devices()
        assert len(devices) == 1
        assert devices[0]["mac"] == f"{real_oui}:00:11:22"
        assert devices[0]["manufacturer"] == fp.OUI_DB[real_oui][0]

    def test_no_mac_no_wrong_guess(self, db, monkeypatch):
        """A DUID-EN (no embedded MAC at all) must yield an empty
        manufacturer/icon — never a fabricated vendor guess."""
        import jen.models.db as db_mod
        from jen.services.kea6 import list_lease6_devices

        monkeypatch.setattr(db_mod, "get_kea6_db", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
        db.commit()
        duid_en = bytes.fromhex("0002" + "0000abcd" + "deadbeef")
        self._insert_lease(db, address="2001:db8:1::1", duid=duid_en, hwaddr=None)
        devices = list_lease6_devices()
        assert len(devices) == 1
        assert devices[0]["mac"] == ""
        assert devices[0]["manufacturer"] == ""


class TestLeasesV6View:
    def test_segmented_control_absent_when_no_v6_subnets(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/leases")
            assert resp.status_code == 200
            assert b"segmented-control" not in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_segmented_control_absent_when_ipv6_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache

        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        _invalidate_settings_cache()
        resp = logged_in_client.get("/leases")
        assert resp.status_code == 200
        assert b"segmented-control" not in resp.data

    def test_segmented_control_present_when_enabled_and_configured(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/leases")
            assert resp.status_code == 200
            assert b"segmented-control" in resp.data
            assert b"IPv6" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_v6_view_redirects_when_no_v6_subnets_configured(self, logged_in_client, monkeypatch, db):
        """Direct/bookmarked ?view=v6 hit with no v6 subnets must not 500
        or silently show an empty v4-shaped page — it redirects back."""
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.get("/leases?view=v6", follow_redirects=False)
        assert resp.status_code == 302

    def test_v6_view_lists_lease6_rows(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
            cur.execute(
                """
                INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                    subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                    hostname, hwaddr, state)
                VALUES ('2001:db8::10', %s, 3600, '2026-08-15 00:00:00',
                    1, 1800, 0, 1, 128, 'v6-host', NULL, 0)
            """,
                (bytes.fromhex("00030001001a2b3c4d5e"),),
            )
        db.commit()
        resp = logged_in_client.get("/leases?view=v6")
        assert resp.status_code == 200
        assert b"2001:db8::10" in resp.data
        assert b"v6-host" in resp.data

    def test_v6_view_subnet_filter_rejects_v4_only_id(self, logged_in_client, monkeypatch, db):
        """A subnet id that's valid in SUBNET_MAP but not SUBNET6_MAP must
        fall back to 'all' rather than silently filtering to nothing."""
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        monkeypatch.setattr(extensions, "SUBNET_MAP", {99: {"name": "V4LAN", "cidr": "192.168.1.0/24"}})
        resp = logged_in_client.get("/leases?view=v6&subnet=99")
        assert resp.status_code == 200  # doesn't error, just falls back to all

    def test_v6_view_htmx_request_returns_partial_only(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64"}})
        resp = logged_in_client.get("/leases?view=v6", headers={"HX-Request": "true"})
        assert resp.status_code == 200
        assert b"page-header" not in resp.data  # partial, not the full page shell


class TestDevicesV6View:
    def test_segmented_control_absent_when_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        _invalidate_settings_cache()
        resp = logged_in_client.get("/devices")
        assert resp.status_code == 200
        assert b"segmented-control" not in resp.data

    def test_v6_view_redirects_when_no_v6_subnets(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        resp = logged_in_client.get("/devices?view=v6", follow_redirects=False)
        assert resp.status_code == 302

    def test_v6_view_renders_devices(self, logged_in_client, monkeypatch, db):
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
            cur.execute(
                """
                INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                    subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                    hostname, hwaddr, state)
                VALUES ('2001:db8::10', %s, 3600, '2026-08-15 00:00:00',
                    1, 1800, 0, 1, 128, 'my-phone', NULL, 0)
            """,
                (bytes.fromhex("00030001001a2b3c4d5e"),),
            )
        db.commit()
        resp = logged_in_client.get("/devices?view=v6")
        assert resp.status_code == 200
        assert b"my-phone" in resp.data
        assert b"2001:db8::10" in resp.data


class TestDevicesV4V6Join:
    """v5.45.0 (Q46) — the main (v4) Devices page now shows v6 data
    inline: a lease6 with a captured hwaddr joins onto the matching v4
    device row (by MAC); a lease6 with no hwaddr can't be safely
    attributed to one, so it gets its own "DUID only" row at the bottom
    instead, never merged."""

    def _clean(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease6")
            cur.execute("DELETE FROM devices WHERE mac='aa:bb:cc:dd:ee:01'")
        db.commit()

    def test_hwaddr_matched_lease_shows_v6_address_on_v4_row(self, logged_in_client, monkeypatch, db):
        from jen.models.user import set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "192.168.1.0/24"}})
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "LAN6", "cidr": "2001:db8:1::/64", "paired_subnet4_id": 1}}
        )
        try:
            self._clean(db)
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.5', 1)"
                )
                cur.execute(
                    """
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8:1::5', %s, 3600, '2026-08-15 00:00:00',
                        1, 1800, 0, 1, 128, '', %s, 0)
                """,
                    (bytes.fromhex("00030001001a2b3c4d5e"), bytes.fromhex("aabbccddee01")),
                )
            db.commit()
            resp = logged_in_client.get("/devices")
            assert resp.status_code == 200
            assert b"2001:db8:1::5" in resp.data
            assert b"DUID only" not in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")
            self._clean(db)

    def test_hwaddrless_lease_becomes_its_own_duid_only_row(self, logged_in_client, monkeypatch, db):
        from jen.models.user import set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute(
                    """
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8::20', %s, 3600, '2026-08-15 00:00:00',
                        1, 1800, 0, 1, 128, 'iot-bulb', NULL, 0)
                """,
                    (bytes.fromhex("0002" + "0000abcd" + "deadbeef"),),  # DUID-EN — no embedded MAC at all
                )
            db.commit()
            # logged_in_client is superadmin (all_subnets) — sees the
            # unpaired v6 subnet's DUID-only row.
            resp = logged_in_client.get("/devices")
            assert resp.status_code == 200
            assert b"DUID only" in resp.data
            assert b"iot-bulb" in resp.data
            assert b"2001:db8::20" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
            db.commit()

    def test_ipv6_column_and_rows_absent_when_disabled(self, logged_in_client, monkeypatch, db):
        """TestZeroBehaviorChange property: with v6 off, the v4 Devices
        page is byte-for-byte the same shape it always was — no IPv6
        column, no DUID-only rows, regardless of what's in lease6."""
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        resp = logged_in_client.get("/devices")
        assert resp.status_code == 200
        assert b'data-label="IPv6"' not in resp.data
        assert b"DUID only" not in resp.data


class TestDashboardV6Summary:
    def test_returns_none_when_disabled(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module
        from jen.models.user import _invalidate_settings_cache

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        _invalidate_settings_cache()
        assert dashboard_module._get_ipv6_dashboard_summary() is None

    def test_returns_none_when_no_v6_subnets(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        try:
            _invalidate_settings_cache()
            assert dashboard_module._get_ipv6_dashboard_summary() is None
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_returns_counts_when_enabled_and_configured(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {9: {"name": "V6LAN", "cidr": "2001:db8:9::/64", "paired_subnet4_id": None}}
        )
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute(
                    """
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8:9::1', %s, 3600, '2026-08-15 00:00:00',
                        9, 1800, 0, 1, 128, '', NULL, 0)
                """,
                    (bytes.fromhex("00030001001a2b3c4d5e"),),
                )
            db.commit()
            _invalidate_settings_cache()
            summary = dashboard_module._get_ipv6_dashboard_summary()
            assert summary == {"active": 1, "reserved": 0, "subnet_count": 1}
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_returns_none_on_error_rather_than_partial_counts(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module
        import jen.services.kea6 as kea6_module
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        monkeypatch.setattr(kea6_module, "list_lease6", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("db down")))
        try:
            _invalidate_settings_cache()
            assert dashboard_module._get_ipv6_dashboard_summary() is None
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_dashboard_shows_ipv4_only_label_when_v6_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        _invalidate_settings_cache()
        resp = logged_in_client.get("/")
        assert resp.status_code == 200
        assert b"IPv4 only" in resp.data

    def test_dashboard_shows_ipv6_card_when_enabled(self, logged_in_client, monkeypatch, db):
        """v5.45.0 (Q46) — the dashboard no longer renders a separate
        boxed "IPv6" section; an unpaired v6 subnet instead gets its own
        card in the same stat-grid as the v4 cards, tagged "v6", and the
        totals widget folds the v6 active/reserved numbers inline
        (asserted by TestDashboardMergedV4V6Grid below)."""
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/")
            assert resp.status_code == 200
            assert b"IPv4 only" not in resp.data
            assert b"V6LAN" in resp.data
            assert b"2001:db8::/64" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")


class TestDashboardMergedV4V6Grid:
    """v5.45.0 (Q46) — jen/routes/dashboard.py::_get_subnets6_data() and
    its rendering: one grid, a v4/v6 tag per card, paired subnets nested,
    unpaired ones standalone — mirrors TestSubnetsV6View in
    tests/test_kea6_subnets.py for the equivalent Subnets-page function,
    but access-filtered (see the function's own docstring)."""

    def test_get_subnets6_data_empty_when_disabled(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        assert dashboard_module._get_subnets6_data({1}) == []

    def test_get_subnets6_data_counts_leases_and_reservations(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module
        from jen.models.user import set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {7: {"name": "V6LAN", "cidr": "2001:db8:7::/64", "paired_subnet4_id": None}}
        )

        class _FakeUser:
            all_subnets = True

        monkeypatch.setattr(dashboard_module, "current_user", _FakeUser())
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute(
                    """
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8:7::1', %s, 3600, '2026-08-15 00:00:00',
                        7, 1800, 0, 1, 128, '', NULL, 0)
                """,
                    (bytes.fromhex("00030001001a2b3c4d5e"),),
                )
            db.commit()
            data = dashboard_module._get_subnets6_data(set())
            assert len(data) == 1
            assert data[0]["active"] == 1
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_unpaired_v6_subnet_excluded_for_restricted_user_without_all_subnets(self, monkeypatch, db):
        """The dashboard's own access bar: an unpaired v6 subnet is only
        visible to an all_subnets user, matching devices.py's
        _devices_v6() check — unlike the Subnets page, which shows every
        v6 subnet to any logged-in user today (a pre-existing gap out of
        this Q's scope)."""
        import jen.routes.dashboard as dashboard_module
        from jen.models.user import set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )

        class _FakeUser:
            all_subnets = False

        monkeypatch.setattr(dashboard_module, "current_user", _FakeUser())
        try:
            assert dashboard_module._get_subnets6_data(set()) == []
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_paired_v6_subnet_included_when_v4_side_is_accessible(self, monkeypatch, db):
        import jen.routes.dashboard as dashboard_module
        from jen.models.user import set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {2: {"name": "LAN6", "cidr": "2001:db8:2::/64", "paired_subnet4_id": 1}}
        )

        class _FakeUser:
            all_subnets = False

        monkeypatch.setattr(dashboard_module, "current_user", _FakeUser())
        try:
            data = dashboard_module._get_subnets6_data({1})
            assert len(data) == 1
            assert data[0]["paired_subnet4_id"] == 1
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_dashboard_paired_v6_subnet_nests_under_v4_card(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "192.168.1.0/24"}})
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "LAN6", "cidr": "2001:db8:1::/64", "paired_subnet4_id": 1}}
        )
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/")
            assert resp.status_code == 200
            body = resp.data.decode()
            assert "2001:db8:1::/64" in body
            # Nested once under the v4 card, not a second standalone card.
            assert body.count("2001:db8:1::/64") == 1
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_api_stats_includes_subnets6_when_enabled(self, logged_in_client, monkeypatch, mock_kea, db):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        try:
            _invalidate_settings_cache()
            resp = logged_in_client.get("/api/stats")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "subnets6" in data
        finally:
            set_global_setting("ipv6_enabled", "false")
