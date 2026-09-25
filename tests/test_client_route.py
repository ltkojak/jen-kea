"""
tests/test_client_route.py
────────────────────────────
v5.63.0 (Q82) — GET /client: identifier resolution end to end (found,
not-found, ambiguous-hostname candidates, subnet-denied), each tab
renders without error, and Trace's gate is enforced the same way the
standalone /tools/trace page enforces it.
"""

import pytest

MAC = "aa:bb:cc:dd:ef:10"
MAC_HEX = "AABBCCDDEF10"
IP = "10.45.0.5"

CFG = {
    "valid-lifetime": 3600,
    "option-data": [{"name": "domain-name-servers", "data": "1.1.1.1"}],
    "subnet4": [{"id": 1, "subnet": "10.45.0.0/24", "pools": [{"pool": "10.45.0.2 - 10.45.0.200"}]}],
}


@pytest.fixture
def stub_config(monkeypatch):
    monkeypatch.setattr("jen.routes.client.dhcp4_config", lambda force=False: CFG)


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM devices WHERE mac=%s", (MAC,))
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (MAC_HEX,))
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (MAC_HEX,))
    db.commit()


@pytest.fixture
def seeded(db):
    _clean(db)
    with db.cursor() as cur:
        cur.execute("INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES (%s, %s, 1)", (MAC, IP))
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
            "(inet_aton(%s), UNHEX(%s), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)",
            (IP, MAC_HEX),
        )
    db.commit()
    yield
    _clean(db)


class TestNoIdentifier:
    def test_blank_form_renders(self, logged_in_client):
        r = logged_in_client.get("/client")
        assert r.status_code == 200
        assert b"Investigate a client" in r.data


class TestResolution:
    def test_found_mac_shows_tabs(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}")
        assert r.status_code == 200
        body = r.data.decode()
        assert MAC in body
        for tab in ("Overview", "Explain", "Trace", "Timeline", "Dns", "Config"):
            assert tab in body

    def test_found_by_ip_resolves_the_holder(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={IP}")
        assert r.status_code == 200
        assert MAC in r.data.decode()

    def test_not_found_shows_a_message(self, logged_in_client, db):
        _clean(db)
        r = logged_in_client.get("/client?q=aa:bb:cc:dd:ef:99")
        assert r.status_code == 200
        assert b"No client matched" in r.data

    def test_ambiguous_hostname_shows_candidates(self, logged_in_client, db):
        _clean(db)
        other = "aa:bb:cc:dd:ef:11"
        with db.cursor() as cur:
            cur.execute("INSERT INTO devices (mac, last_hostname, last_subnet_id) VALUES (%s, 'dupe-host', 1)", (MAC,))
            cur.execute(
                "INSERT INTO devices (mac, last_hostname, last_subnet_id) VALUES (%s, 'dupe-host', 1)", (other,)
            )
        db.commit()
        try:
            r = logged_in_client.get("/client?q=dupe-host")
            assert r.status_code == 200
            body = r.data.decode()
            assert "More than one client" in body
            assert MAC in body and other in body
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM devices WHERE mac IN (%s, %s)", (MAC, other))
            db.commit()


class TestSubnetRestriction:
    def test_restricted_viewer_outside_the_subnet_is_denied(self, client, db, seeded):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[999], role="viewer", username="_client_viewer")
        r = client.get(f"/client?q={MAC}")
        assert r.status_code == 200
        body = r.data.decode()
        # v5.65.2 (Q91 c): one answer for "denied" and "not found" - the page is no existence oracle
        assert "No client matched that identifier" in body
        assert "do not have access to this client" not in body
        assert IP not in body

    def test_restricted_viewer_inside_the_subnet_sees_it(self, client, db, seeded):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_client_viewer2")
        r = client.get(f"/client?q={MAC}")
        assert r.status_code == 200
        assert IP in r.data.decode()


class TestTabs:
    def test_overview_tab_lists_leases_and_reservations(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=overview")
        assert IP in r.data.decode()

    def test_explain_tab_embeds_via_htmx(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=explain")
        assert b"hx-get=" in r.data
        assert b"/tools/explain?mac=" in r.data

    def test_timeline_tab_embeds_via_htmx(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=timeline")
        assert b"hx-get=" in r.data
        assert b"/timeline?mac=" in r.data

    def test_trace_tab_embeds_via_htmx_for_an_unrestricted_admin(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=trace")
        assert b"/tools/trace?mac=" in r.data

    def test_trace_tab_refuses_a_restricted_admin(self, client, db, seeded):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="admin", username="_client_trace_admin")
        r = client.get(f"/client?q={MAC}&tab=trace")
        assert r.status_code == 200
        assert b"Trace needs admin access to every subnet" in r.data

    def test_dns_tab_with_no_hostname_says_so(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=dns")
        assert b"no named reservation or lease" in r.data

    def test_config_tab_shows_the_evaluation(self, logged_in_client, seeded, stub_config):
        r = logged_in_client.get(f"/client?q={MAC}&tab=config")
        assert r.status_code == 200
        assert b"Effective configuration" in r.data

    def test_an_invalid_tab_falls_back_to_overview(self, logged_in_client, seeded):
        r = logged_in_client.get(f"/client?q={MAC}&tab=nonsense")
        assert r.status_code == 200
        assert IP in r.data.decode()


class TestNavAndRowLinks:
    def test_nav_points_here(self):
        import pathlib

        repo = pathlib.Path(__file__).resolve().parent.parent
        assert '"url": "/client"' in (repo / "jen" / "routes" / "settings" / "nav.py").read_text(encoding="utf-8")

    def test_row_menus_offer_investigate(self):
        import pathlib

        repo = pathlib.Path(__file__).resolve().parent.parent
        for name in ("_lease_rows.html", "_reservation_row.html", "_device_rows.html"):
            assert "/client?q=" in (repo / "templates" / name).read_text(encoding="utf-8"), name


# ── v5.65.2 (Q91) ────────────────────────────────────────────────────────────

MAC_A = "aa:bb:cc:dd:ef:a1"
MAC_B = "aa:bb:cc:dd:ef:b1"
MAC_B_HEX = "AABBCCDDEFB1"
SHARED = "shared-printer"


@pytest.fixture
def shared_hostname(db):
    """The SAME hostname on a client in allowed subnet A (id 1) and one in denied subnet B (id 2)."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM devices WHERE mac IN (%s, %s)", (MAC_A, MAC_B))
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (MAC_B_HEX,))
        cur.execute(
            "INSERT INTO devices (mac, last_hostname, last_ip, last_subnet_id) VALUES "
            "(%s, %s, '10.45.0.21', 1), (%s, %s, '10.77.0.21', 2)",
            (MAC_A, SHARED, MAC_B, SHARED),
        )
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state, hostname) VALUES "
            "(inet_aton('10.77.0.21'), UNHEX(%s), 2, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0, %s)",
            (MAC_B_HEX, SHARED),
        )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM devices WHERE mac IN (%s, %s)", (MAC_A, MAC_B))
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (MAC_B_HEX,))
    db.commit()


class TestAmbiguousHostnameIsJudgedPerCandidate:
    """The B MAC must be absent for the caller scoped to A and present for an unrestricted one
    (Q91 a / a-prime): the candidates list is `view.candidates`, each judged like a subject."""

    def test_unrestricted_caller_sees_both_candidates(self, logged_in_client, shared_hostname):
        body = logged_in_client.get(f"/client?q={SHARED}").data.decode()
        assert "More than one client" in body
        assert MAC_A in body and MAC_B in body

    def test_scoped_caller_never_sees_the_b_mac(self, client, db, shared_hostname):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="admin", username="_client_shared_a")
        r = client.get(f"/client?q={SHARED}")
        body = r.data.decode()
        assert r.status_code == 200
        assert MAC_B not in body and "10.77.0.21" not in body
        # the one client the caller CAN see resolves straight to it, so it is not "ambiguous" at all
        assert MAC_A in body and "More than one client" not in body

    def test_a_hostname_that_exists_only_in_b_reads_as_not_found(self, client, db):
        from tests.conftest import restricted_client

        with db.cursor() as cur:
            cur.execute("DELETE FROM devices WHERE mac=%s", (MAC_B,))
            cur.execute(
                "INSERT INTO devices (mac, last_hostname, last_subnet_id) VALUES (%s, 'only-in-b', 2)", (MAC_B,)
            )
        db.commit()
        try:
            restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_client_only_b")
            body = client.get("/client?q=only-in-b").data.decode()
            assert "No client matched that identifier" in body and MAC_B not in body
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM devices WHERE mac=%s", (MAC_B,))
            db.commit()

    def test_the_template_renders_only_view_candidates(self):
        import pathlib

        text = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "client.html").read_text(
            encoding="utf-8"
        )
        assert "subject.candidates" not in text and "view.candidates" in text


class TestNoSubnetGuess:
    """Q91 f: the Config and Explain tabs never evaluate an arbitrary subnet."""

    def test_a_device_only_client_gets_a_picker_and_no_evaluation(self, logged_in_client, db, stub_config):
        _clean(db)
        with db.cursor() as cur:
            cur.execute("INSERT INTO devices (mac, last_hostname) VALUES (%s, 'no-subnet-host')", (MAC,))
        db.commit()
        try:
            for tab in ("config", "explain"):
                body = logged_in_client.get(f"/client?q={MAC}&tab={tab}").data.decode()
                assert 'name="subnet"' in body and "Which subnet should this be evaluated against" in body
                assert "Effective configuration" not in body and "hx-get=" not in body
        finally:
            _clean(db)

    def test_choosing_a_subnet_evaluates_it_and_says_it_was_chosen(self, logged_in_client, db, stub_config):
        _clean(db)
        with db.cursor() as cur:
            cur.execute("INSERT INTO devices (mac, last_hostname) VALUES (%s, 'no-subnet-host')", (MAC,))
        db.commit()
        try:
            body = logged_in_client.get(f"/client?q={MAC}&tab=config&subnet=1").data.decode()
            assert "Effective configuration" in body and "chosen" in body
        finally:
            _clean(db)

    def test_the_picker_lists_only_accessible_subnets(self, client, db, stub_config, monkeypatch):
        from jen import extensions
        from tests.conftest import restricted_client

        monkeypatch.setattr(
            extensions,
            "SUBNET_MAP",
            {1: {"name": "Alpha-A", "cidr": "10.45.0.0/24"}, 2: {"name": "ZZ-Bravo-B", "cidr": "10.77.0.0/24"}},
        )
        _clean(db)
        with db.cursor() as cur:
            cur.execute("INSERT INTO devices (mac, last_hostname, last_subnet_id) VALUES (%s, 'h', 1)", (MAC,))
        db.commit()
        try:
            restricted_client(client, db, allowed_subnets=[1], role="admin", username="_client_picker")
            body = client.get(f"/client?q={MAC}&tab=config").data.decode()
            assert "ZZ-Bravo-B" not in body
        finally:
            _clean(db)

    def test_a_lease_still_fixes_the_subnet_without_a_picker(self, logged_in_client, seeded, stub_config):
        body = logged_in_client.get(f"/client?q={MAC}&tab=config").data.decode()
        assert "Effective configuration" in body and "from the current lease" in body
        assert "Which subnet should this be evaluated against" not in body


class TestSearchBoxHonesty:
    def test_the_box_says_ipv4_not_ip(self, logged_in_client):
        body = logged_in_client.get("/client").data.decode()
        assert "MAC, IPv4 address or hostname" in body

    def test_an_ipv6_address_is_answered_not_reported_as_no_match(self, logged_in_client):
        body = logged_in_client.get("/client?q=2001:db8::10").data.decode()
        assert "IPv6 and DUID lookups are not supported yet" in body and "No client matched" not in body

    def test_a_duid_is_answered_too(self, logged_in_client):
        body = logged_in_client.get("/client?q=duid:00010001aabbccddeeff0011").data.decode()
        assert "IPv6 and DUID lookups are not supported yet" in body


class TestAlertLine:
    def test_the_matcher_is_word_bounded(self):
        from jen.routes.client import _alert_matcher

        m = _alert_matcher("", "10.0.0.5")
        assert m.search("lease 10.0.0.5 renewed") and m.search("10.0.0.5")
        assert not m.search("lease 10.0.0.50 renewed") and not m.search("host 110.0.0.5") and not m.search("10.0.0.5.7")
        mm = _alert_matcher("aa:bb:cc:dd:ef:10", "")
        assert mm.search("client AA:BB:CC:DD:EF:10 seen") and not mm.search("aa:bb:cc:dd:ef:100")

    def test_no_identifier_no_matcher(self):
        from jen.routes.client import _alert_matcher

        assert _alert_matcher("", "") is None

    def test_a_scoped_caller_gets_no_alert_line_and_an_unrestricted_one_does(self, client, db, seeded):
        from tests.conftest import restricted_client

        with db.cursor() as cur:
            cur.execute("DELETE FROM alert_log WHERE message LIKE %s", (f"%{IP}%",))
            cur.execute(
                "INSERT INTO alert_log (channel_type, alert_type, message, status) VALUES "
                "('telegram', 'zz_marker_alert', %s, 'sent'), ('telegram', 'zz_neighbour_alert', %s, 'sent')",
                (f"lease {IP} renewed", "lease 10.45.0.55 renewed"),
            )
        db.commit()
        try:
            restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_client_alert_viewer")
            assert b"zz_marker_alert" not in client.get(f"/client?q={MAC}").data
            admin = client.application.test_client()
            restricted_client(admin, db, allowed_subnets=None, role="admin", username="_client_alert_admin")
            body = admin.get(f"/client?q={MAC}").data
            assert b"zz_marker_alert" in body and b"zz_neighbour_alert" not in body
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_log WHERE alert_type IN ('zz_marker_alert', 'zz_neighbour_alert')")
            db.commit()
