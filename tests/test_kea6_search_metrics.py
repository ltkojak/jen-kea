"""
tests/test_kea6_search_metrics.py
─────────────────────────────────
DHCPv6 surfacing in cross-cutting features: global search, the Prometheus /metrics series, and plugin IPv6 notes.

Split out of the monolithic tests/test_kea6.py in v5.6.1.
"""

import configparser

import pytest

from jen import extensions


class TestGlobalSearchV6:
    def test_v6_absent_from_results_when_disabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        _invalidate_settings_cache()
        resp = logged_in_client.get("/search?q=findme")
        assert resp.status_code == 200
        assert b"IPv6 Leases" not in resp.data
        assert b"IPv6 Reservations" not in resp.data

    def test_v6_lease_found_when_enabled_superadmin(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

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
                    VALUES ('2001:db8::99', %s, 3600, '2026-08-15 00:00:00',
                        1, 1800, 0, 1, 128, 'findable-host', NULL, 0)
                """,
                    (bytes.fromhex("00030001001a2b3c4d5e"),),
                )
            db.commit()
            _invalidate_settings_cache()
            resp = logged_in_client.get("/search?q=findable")
            assert resp.status_code == 200
            assert b"findable-host" in resp.data
            assert b"IPv6 Leases" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_v6_reservation_found_when_enabled(self, logged_in_client, monkeypatch, db):
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM ipv6_reservations")
                cur.execute("DELETE FROM hosts WHERE dhcp6_subnet_id IS NOT NULL")
                cur.execute(
                    """
                    INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp6_subnet_id, hostname)
                    VALUES (%s, 1, 1, 'searchable-res')
                """,
                    (bytes.fromhex("00030001aabbccddeeff"),),
                )
                host_id = cur.lastrowid
                cur.execute(
                    """
                    INSERT INTO ipv6_reservations (address, prefix_len, type, dhcp6_iaid, host_id)
                    VALUES ('2001:db8::50', 128, 0, 1, %s)
                """,
                    (host_id,),
                )
            db.commit()
            _invalidate_settings_cache()
            resp = logged_in_client.get("/search?q=searchable-res")
            assert resp.status_code == 200
            assert b"searchable-res" in resp.data
            assert b"IPv6 Reservations" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_unpaired_v6_subnet_hidden_from_restricted_user(self, client, db, monkeypatch):
        """A restricted (non-all_subnets) user must not see results from
        an unpaired v6 subnet — there's no v4 subnet to inherit access
        from, so it's admin/all_subnets-only, not guessed at."""
        from jen.models.user import _invalidate_settings_cache, set_global_setting
        from tests.conftest import restricted_client

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {5: {"name": "Unpaired", "cidr": "2001:db8:5::/64", "paired_subnet4_id": None}}
        )
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute(
                    """
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8:5::1', %s, 3600, '2026-08-15 00:00:00',
                        5, 1800, 0, 1, 128, 'v6onlyresult', NULL, 0)
                """,
                    (bytes.fromhex("00030001001a2b3c4d5e"),),
                )
            db.commit()
            _invalidate_settings_cache()
            c, _uid = restricted_client(client, db, allowed_subnets=[1], role="viewer")
            resp = c.get("/search?q=v6onlyresult")
            assert resp.status_code == 200
            # The "IPv6 Leases" card only renders when results.leases6 is
            # non-empty — a reliable signal that avoids the false-positive
            # of the query text itself being echoed in the search box.
            assert b"IPv6 Leases" not in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_paired_v6_subnet_visible_to_user_with_v4_access(self, client, db, monkeypatch):
        from jen.models.user import _invalidate_settings_cache, set_global_setting
        from tests.conftest import restricted_client

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "LAN", "cidr": "192.168.1.0/24"}})
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "LAN6", "cidr": "2001:db8:1::/64", "paired_subnet4_id": 1}}
        )
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute(
                    """
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8:1::1', %s, 3600, '2026-08-15 00:00:00',
                        1, 1800, 0, 1, 128, 'paired-visible', NULL, 0)
                """,
                    (bytes.fromhex("00030001001a2b3c4d5e"),),
                )
            db.commit()
            _invalidate_settings_cache()
            c, _uid = restricted_client(client, db, allowed_subnets=[1], role="viewer")
            resp = c.get("/search?q=paired-visible")
            assert resp.status_code == 200
            assert b"paired-visible" in resp.data
        finally:
            set_global_setting("ipv6_enabled", "false")


class TestPrometheusMetricsV6:
    @pytest.fixture
    def metrics_open(self, monkeypatch):
        """v5.3.3 — /metrics now defaults to closed (401) without a
        configured metrics_token or explicit metrics_open=true. Every
        test in this class hits /metrics directly and needs to opt
        into the old open behavior to test what it actually intends to
        test — metric content/format, not access control (which has
        its own dedicated tests in test_dashboard.py). Two of these
        five tests didn't fail outright when this changed, since they
        assert specific text is ABSENT, and that's also (trivially,
        uselessly) true of a 401 page — but they were not actually
        testing what they claim to without this fixture."""

        from jen import extensions

        test_cfg = configparser.ConfigParser()
        test_cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        if "server" not in test_cfg:
            test_cfg["server"] = {}
        test_cfg["server"]["metrics_open"] = "true"
        monkeypatch.setattr(extensions, "cfg", test_cfg)

    def test_ipv6_enabled_gauge_always_present_even_when_off(self, client, mock_kea, db, metrics_open):
        from jen.models.user import _invalidate_settings_cache

        _invalidate_settings_cache()
        r = client.get("/metrics")
        text = r.data.decode()
        assert "# TYPE jen_ipv6_enabled gauge" in text
        assert "jen_ipv6_enabled 0" in text

    def test_v6_subnet_metrics_absent_when_disabled(self, client, mock_kea, monkeypatch, db, metrics_open):
        from jen.models.user import _invalidate_settings_cache

        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        _invalidate_settings_cache()
        r = client.get("/metrics")
        text = r.data.decode()
        assert "jen_subnet6_active_leases" not in text
        assert "jen_subnet6_reserved_hosts" not in text
        assert "# TYPE jen_kea6_up" not in text

    def test_v6_subnet_metrics_present_when_enabled_and_configured(
        self, client, mock_kea, monkeypatch, db, metrics_open
    ):
        import jen.services.kea6 as kea6_module
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        monkeypatch.setattr(kea6_module, "kea6_is_up", lambda *a, **kw: True)
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease6")
                cur.execute(
                    """
                    INSERT INTO lease6 (address, duid, valid_lifetime, expire,
                        subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                        hostname, hwaddr, state)
                    VALUES ('2001:db8::1', %s, 3600, '2026-08-15 00:00:00',
                        1, 1800, 0, 1, 128, '', NULL, 0)
                """,
                    (bytes.fromhex("00030001001a2b3c4d5e"),),
                )
            db.commit()
            _invalidate_settings_cache()
            r = client.get("/metrics")
            text = r.data.decode()
            assert "# TYPE jen_subnet6_active_leases gauge" in text
            assert 'jen_subnet6_active_leases{subnet="V6LAN",cidr="2001:db8::/64",type="IA_NA"} 1' in text
            assert "# TYPE jen_subnet6_reserved_hosts gauge" in text
            assert "jen_ipv6_enabled 1" in text
            assert "jen_kea6_up 1" in text
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_no_pool_size_or_utilization_metric_for_v6(self, client, mock_kea, monkeypatch, db, metrics_open):
        """Deliberate scope decision (matches the lease6_history schema
        from Phase 0/1): no finite comparable 'pool size' concept for a
        /64, so no jen_subnet6_pool_size/utilization_ratio metric exists
        at all — confirm that omission is intentional, not a bug."""
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        try:
            _invalidate_settings_cache()
            r = client.get("/metrics")
            text = r.data.decode()
            assert "jen_subnet6_pool_size" not in text
            assert "jen_subnet6_utilization_ratio" not in text
        finally:
            set_global_setting("ipv6_enabled", "false")

    def test_v4_metric_families_unaffected_by_v6_addition(self, client, mock_kea, monkeypatch, db, metrics_open):
        """Zero behavior change for the v4 path — every existing metric
        family must still be present and correctly formatted regardless
        of the v6 state."""
        from jen.models.user import _invalidate_settings_cache, set_global_setting

        set_global_setting("ipv6_enabled", "true")
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "V6LAN", "cidr": "2001:db8::/64", "paired_subnet4_id": None}}
        )
        try:
            _invalidate_settings_cache()
            r = client.get("/metrics")
            text = r.data.decode()
            for family in [
                "jen_subnet_active_leases",
                "jen_subnet_reserved_hosts",
                "jen_subnet_pool_size",
                "jen_subnet_utilization_ratio",
                "jen_alerts_sent_total",
                "jen_kea_up",
                "jen_server_up",
            ]:
                assert f"# HELP {family}" in text, f"missing HELP for {family}"
                assert f"# TYPE {family}" in text, f"missing TYPE for {family}"
        finally:
            set_global_setting("ipv6_enabled", "false")


class TestPluginIpv6Notes:
    def test_ipam_template_has_gated_note(self):
        content = open("plugins/ipam/templates/ipam/index.html").read()
        assert "{% if ipv6_enabled %}" in content
        assert "IPv4 addresses only" in content

    def test_network_discovery_template_has_gated_note(self):
        content = open("plugins/network-discovery/templates/network_discovery/index.html").read()
        assert "{% if ipv6_enabled %}" in content
        assert "IPv4 subnets only" in content

    def test_ipam_readme_documents_v4_only_scope(self):
        content = open("plugins/ipam/README.md").read()
        assert "IPv4 only" in content

    def test_network_discovery_readme_documents_v4_only_scope(self):
        content = open("plugins/network-discovery/README.md").read()
        assert "IPv4 only" in content
