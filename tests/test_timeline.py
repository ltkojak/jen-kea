"""
tests/test_timeline.py
────────────────────────
v5.42.0 (Q43) — jen.services.timeline.build_timeline() (the merge), the
GET /timeline page, and the two API endpoints (GET /api/v1/events,
GET /api/v1/timeline/{mac}). All DB-backed — the merge queries real
events/audit_log/alert_log/lease4/hosts/devices rows.
"""

import hashlib

from tests.test_api_key_authorization import _insert_api_key


def _key(db, admin_id, raw, name):
    key_id = _insert_api_key(db, name, created_by=admin_id)
    with db.cursor() as cur:
        cur.execute("UPDATE api_keys SET key_hash=%s WHERE id=%s", (hashlib.sha256(raw.encode()).hexdigest(), key_id))
    db.commit()


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM events")
        cur.execute("DELETE FROM audit_log WHERE entity LIKE '%aa:bb:cc:dd:ee%' OR details LIKE '%aa:bb:cc:dd:ee%'")
        cur.execute("DELETE FROM alert_log WHERE message LIKE '%aa:bb:cc:dd:ee%'")
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)='AABBCCDDEE01'")
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCCDDEE01'")
        cur.execute("DELETE FROM devices WHERE mac='aa:bb:cc:dd:ee:01'")
    db.commit()


class TestBuildTimeline:
    def test_events_row_matched_by_mac(self, db):
        from jen.services.timeline import build_timeline

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO events (kind, mac, ip, subnet_id, detail) VALUES ('lease.new', %s, '10.0.0.5', 1, 'x')",
                ("aa:bb:cc:dd:ee:01",),
            )
        db.commit()

        result = build_timeline(mac="aa:bb:cc:dd:ee:01")
        assert len(result["rows"]) == 1
        assert result["rows"][0]["kind"] == "lease.new"
        assert result["rows"][0]["source"] == "event"

    def test_audit_log_matched_by_like_on_entity_or_details(self, db):
        from jen.services.timeline import build_timeline

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (action, entity, details, username) VALUES "
                "('ADD_RESERVATION', '10.0.0.5', 'MAC=aa:bb:cc:dd:ee:01 hostname=x', 'admin')"
            )
        db.commit()

        result = build_timeline(mac="aa:bb:cc:dd:ee:01")
        assert any(r["source"] == "audit" and "admin" in r["detail"] for r in result["rows"])

    def test_alert_log_matched_by_like_on_message(self, db):
        from jen.services.timeline import build_timeline

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO alert_log (channel_type, alert_type, message, status) VALUES "
                "('telegram', 'new_lease', 'MAC: aa:bb:cc:dd:ee:01', 'ok')"
            )
        db.commit()

        result = build_timeline(mac="aa:bb:cc:dd:ee:01")
        assert any(r["source"] == "alert" and r["kind"] == "alert.new_lease" for r in result["rows"])

    def test_blank_mac_never_matches_everything_in_audit_or_alert_log(self, db):
        """The _NEVER_MATCH sentinel guards against a blank term
        degrading a LIKE clause to '%%' (which matches every row)."""
        from jen.services.timeline import build_timeline

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (action, entity, details) VALUES ('SOME_ACTION', 'unrelated', 'nothing to do with this ip')"
            )
        db.commit()

        result = build_timeline(ip="10.0.0.250")
        assert result["rows"] == []

    def test_device_lease_reservation_bookends(self, db):
        from jen.services.timeline import build_timeline

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES ('aa:bb:cc:dd:ee:01', '10.0.0.5', 1)"
            )
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
                "(inet_aton('10.0.0.5'), UNHEX('AABBCCDDEE01'), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)"
            )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address) VALUES "
                "(UNHEX('AABBCCDDEE01'), 0, 1, inet_aton('10.0.0.5'))"
            )
        db.commit()

        result = build_timeline(mac="aa:bb:cc:dd:ee:01")
        assert result["device"]["last_ip"] == "10.0.0.5"
        assert result["lease"]["ip"] == "10.0.0.5"
        assert result["reservation"]["ip"] == "10.0.0.5"
        assert result["subnet_id"] == 1

    def test_ip_resolves_to_mac_via_active_lease(self, db):
        from jen.services.timeline import build_timeline

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
                "(inet_aton('10.0.0.5'), UNHEX('AABBCCDDEE01'), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)"
            )
        db.commit()

        result = build_timeline(ip="10.0.0.5")
        assert result["mac"] == "aa:bb:cc:dd:ee:01"

    def test_no_record_anywhere_has_no_subnet(self, db):
        from jen.services.timeline import build_timeline

        _clean(db)
        result = build_timeline(mac="aa:bb:cc:dd:ee:01")
        assert result["subnet_id"] is None
        assert result["device"] is None
        assert result["lease"] is None
        assert result["reservation"] is None

    def test_v6_addresses_empty_when_no_mac(self, db):
        from jen.services.timeline import build_timeline

        _clean(db)
        result = build_timeline(ip="10.0.0.250")
        assert result["v6_addresses"] == []

    def test_v6_addresses_empty_when_disabled(self, db, monkeypatch):
        """v5.45.0 (Q46) — TestZeroBehaviorChange's property applies
        here too: no v6 lookup happens at all when ipv6 is off."""
        import jen.services.kea6 as kea6_module
        from jen.models.user import set_global_setting
        from jen.services.timeline import build_timeline

        set_global_setting("ipv6_enabled", "false")
        monkeypatch.setattr(
            kea6_module, "lease6_by_hwaddr_mac", lambda: (_ for _ in ()).throw(AssertionError("must not be called"))
        )
        _clean(db)
        result = build_timeline(mac="aa:bb:cc:dd:ee:01")
        assert result["v6_addresses"] == []

    def test_v6_addresses_populated_from_hwaddr_join(self, db):
        import jen.services.kea6 as kea6_module
        from jen.models.user import set_global_setting
        from jen.services.timeline import build_timeline

        set_global_setting("ipv6_enabled", "true")
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute(
                    """
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8::1', %s, 3600, '2026-08-15 00:00:00',
                        1, 1800, 0, 1, 128, '', %s, 0)
                """,
                    (bytes.fromhex("00030001001a2b3c4d5e"), bytes.fromhex("aabbccddee01")),
                )
            db.commit()
            _clean_lease6 = kea6_module.list_lease6()  # sanity: hwaddr present
            assert _clean_lease6[0]["mac_source"] == "hwaddr"
            result = build_timeline(mac="aa:bb:cc:dd:ee:01")
            assert result["v6_addresses"] == [
                {"address": "2001:db8::1", "type_name": "IA_NA", "prefix_len": 128, "subnet_id": 1}
            ]
        finally:
            set_global_setting("ipv6_enabled", "false")
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
            db.commit()


class TestTimelinePage:
    def test_requires_login(self, client):
        r = client.get("/timeline?mac=aa:bb:cc:dd:ee:01", follow_redirects=False)
        assert r.status_code in (301, 302, 308)

    def test_invalid_mac_flashes_and_shows_no_result(self, logged_in_client, db):
        _clean(db)
        r = logged_in_client.get("/timeline?mac=not-a-mac")
        assert r.status_code == 200
        assert b"isn" in r.data.lower()  # "isn't a MAC address"

    def test_no_match_renders_ok(self, logged_in_client, db):
        _clean(db)
        r = logged_in_client.get("/timeline?mac=aa:bb:cc:dd:ee:01")
        assert r.status_code == 200

    def test_restricted_user_denied_when_subnet_not_accessible(self, client, db):
        from tests.conftest import restricted_client

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES ('aa:bb:cc:dd:ee:01', '10.0.0.5', 1)"
            )
        db.commit()
        c, _uid = restricted_client(client, db, allowed_subnets=[2], role="viewer", username="tl_viewer1")
        r = c.get("/timeline?mac=aa:bb:cc:dd:ee:01")
        assert r.status_code == 200
        assert b"do not have access" in r.data

    def test_restricted_user_allowed_when_subnet_accessible(self, client, db):
        from tests.conftest import restricted_client

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES ('aa:bb:cc:dd:ee:01', '10.0.0.5', 1)"
            )
        db.commit()
        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="viewer", username="tl_viewer2")
        r = c.get("/timeline?mac=aa:bb:cc:dd:ee:01")
        assert r.status_code == 200
        assert b"do not have access" not in r.data


class TestEventsApi:
    def test_requires_key(self, client):
        r = client.get("/api/v1/events")
        assert r.status_code == 401

    def test_filters_by_kind(self, logged_in_client, db):
        from tests.test_api_key_authorization import _insert_admin_user

        _clean(db)
        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name='_events_api_probe'")
            cur.execute("INSERT INTO events (kind, mac, detail) VALUES ('lease.new', 'aa:bb:cc:dd:ee:01', 'a')")
            cur.execute("INSERT INTO events (kind, mac, detail) VALUES ('lease.expired', 'aa:bb:cc:dd:ee:01', 'b')")
        db.commit()
        admin_id = _insert_admin_user(db, "events_api_admin1")
        db.commit()
        raw = "jen_events_api_probe_key1"
        _key(db, admin_id, raw, "_events_api_probe")

        r = logged_in_client.get("/api/v1/events?kind=lease.new", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["count"] == 1
        assert data["events"][0]["kind"] == "lease.new"

    def test_invalid_since_is_rejected(self, logged_in_client, db):
        from tests.test_api_key_authorization import _insert_admin_user

        _clean(db)
        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name='_events_api_probe2'")
        db.commit()
        admin_id = _insert_admin_user(db, "events_api_admin2")
        db.commit()
        raw = "jen_events_api_probe_key2"
        _key(db, admin_id, raw, "_events_api_probe2")

        r = logged_in_client.get("/api/v1/events?since=not-a-date", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 400


class TestTimelineApi:
    def test_requires_key(self, client):
        r = client.get("/api/v1/timeline/aa:bb:cc:dd:ee:01")
        assert r.status_code == 401

    def test_invalid_mac_rejected(self, logged_in_client, db):
        from tests.test_api_key_authorization import _insert_admin_user

        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name='_tl_api_probe1'")
        db.commit()
        admin_id = _insert_admin_user(db, "tl_api_admin1")
        db.commit()
        raw = "jen_tl_api_probe_key1"
        _key(db, admin_id, raw, "_tl_api_probe1")

        r = logged_in_client.get("/api/v1/timeline/not-a-mac", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 400

    def test_scoped_key_denied_for_inaccessible_subnet(self, logged_in_client, db):
        from tests.test_api_key_authorization import _insert_admin_user

        _clean(db)
        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name='_tl_api_probe2'")
            cur.execute(
                "INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES ('aa:bb:cc:dd:ee:01', '10.0.0.5', 1)"
            )
        db.commit()
        admin_id = _insert_admin_user(db, "tl_api_admin2")
        db.commit()
        raw = "jen_tl_api_probe_key2"
        key_id = _insert_api_key(db, "_tl_api_probe2", created_by=admin_id, subnet_access=[2])
        with db.cursor() as cur:
            cur.execute(
                "UPDATE api_keys SET key_hash=%s WHERE id=%s", (hashlib.sha256(raw.encode()).hexdigest(), key_id)
            )
        db.commit()

        r = logged_in_client.get("/api/v1/timeline/aa:bb:cc:dd:ee:01", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 403

    def test_unrestricted_key_gets_the_merged_view(self, logged_in_client, db):
        from tests.test_api_key_authorization import _insert_admin_user

        _clean(db)
        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name='_tl_api_probe3'")
            cur.execute(
                "INSERT INTO events (kind, mac, ip, subnet_id, detail) VALUES "
                "('lease.new', 'aa:bb:cc:dd:ee:01', '10.0.0.5', 1, 'x')"
            )
        db.commit()
        admin_id = _insert_admin_user(db, "tl_api_admin3")
        db.commit()
        raw = "jen_tl_api_probe_key3"
        _key(db, admin_id, raw, "_tl_api_probe3")

        r = logged_in_client.get("/api/v1/timeline/aa:bb:cc:dd:ee:01", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["mac"] == "aa:bb:cc:dd:ee:01"
        assert len(data["rows"]) == 1
        assert data["rows"][0]["kind"] == "lease.new"
