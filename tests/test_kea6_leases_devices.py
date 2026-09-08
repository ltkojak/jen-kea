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
            assert b"Active Leases" in resp.data
            assert b"pool-utilization percentage yet" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")
