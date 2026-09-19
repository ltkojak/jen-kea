"""
tests/test_trace_route.py
──────────────────────────
v5.48.0 (Q49) — GET /tools/trace: admin-only, subnet-restricted, tails the
log through kea_host.tail_log (stubbed here — no SSH, no helper). The
parsing itself is covered without a DB in tests/test_kea_log_trace.py.
"""

from tests.test_kea_log_trace import EXCHANGE, MAC, NAK

MAC_HEX = "AABBCCDDEE01"


def _stub_tail(monkeypatch, result):
    from jen.services import kea_host

    calls = []

    def fake(server, path, lines=200):
        calls.append((path, lines))
        return result

    monkeypatch.setattr(kea_host, "tail_log", fake)
    return calls


def _ok(lines):
    return {"ok": True, "code": "ok", "lines": lines, "via": "helper"}


def _servers(monkeypatch):
    from jen import extensions

    monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}])


def _lease(db, subnet_id=1):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (MAC_HEX,))
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
            "(INET_ATON('10.0.1.55'), UNHEX(%s), %s, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)",
            (MAC_HEX, subnet_id),
        )
    db.commit()


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (MAC_HEX,))
    db.commit()


class TestTraceRoute:
    def test_requires_admin(self, client, db, monkeypatch):
        from tests.conftest import restricted_client

        _servers(monkeypatch)
        restricted_client(client, db, allowed_subnets=None, role="viewer", username="trace_viewer1")
        r = client.get("/tools/trace", query_string={"mac": MAC}, follow_redirects=True)
        assert b"Admin access required." in r.data

    def test_blank_form_renders_without_reading_the_log(self, logged_in_client, monkeypatch):
        _servers(monkeypatch)
        calls = _stub_tail(monkeypatch, _ok([]))
        r = logged_in_client.get("/tools/trace")
        assert r.status_code == 200
        assert b"Client trace" in r.data
        assert calls == []

    def test_invalid_mac_is_refused_without_reading_the_log(self, logged_in_client, monkeypatch):
        _servers(monkeypatch)
        calls = _stub_tail(monkeypatch, _ok([]))
        r = logged_in_client.get("/tools/trace", query_string={"mac": "not-a-mac"})
        assert r.status_code == 200
        assert b"isn&#39;t a MAC address" in r.data or b"isn't a MAC address" in r.data
        assert calls == []

    def test_exchange_is_rendered(self, logged_in_client, db, monkeypatch):
        _servers(monkeypatch)
        _stub_tail(monkeypatch, _ok(EXCHANGE))
        _clean(db)
        r = logged_in_client.get("/tools/trace", query_string={"mac": MAC})
        assert r.status_code == 200
        body = r.data.decode()
        assert "offered 10.0.1.55" in body
        assert "allocated 10.0.1.55 for 3600 s" in body
        assert "DHCP4_LEASE_ALLOC" in body

    def test_nak_is_rendered_and_debug_is_acknowledged(self, logged_in_client, db, monkeypatch):
        _servers(monkeypatch)
        _stub_tail(monkeypatch, _ok(NAK))
        _clean(db)
        r = logged_in_client.get("/tools/trace", query_string={"mac": MAC})
        body = r.data.decode()
        assert "INIT-REBOOT address 10.9.9.9" in body
        assert "logs at DEBUG" in body

    def test_missing_log_says_where_to_set_the_path(self, logged_in_client, db, monkeypatch):
        _servers(monkeypatch)
        _stub_tail(monkeypatch, {"ok": False, "code": "missing", "detail": "log file not found"})
        _clean(db)
        r = logged_in_client.get("/tools/trace", query_string={"mac": MAC})
        assert b"dhcp4_log_path" in r.data

    def test_read_failure_shows_generic_message_not_the_detail(self, logged_in_client, db, monkeypatch):
        _servers(monkeypatch)
        _stub_tail(monkeypatch, {"ok": False, "code": "error", "detail": "permission denied /var/log/secret"})
        _clean(db)
        r = logged_in_client.get("/tools/trace", query_string={"mac": MAC})
        assert b"Could not read the Kea log" in r.data
        assert b"/var/log/secret" not in r.data

    def test_lines_are_clamped_to_the_helpers_cap(self, logged_in_client, db, monkeypatch):
        _servers(monkeypatch)
        calls = _stub_tail(monkeypatch, _ok([]))
        _clean(db)
        logged_in_client.get("/tools/trace", query_string={"mac": MAC, "lines": "999999"})
        assert calls[-1][1] == 1000

    def test_subnet_restricted_admin_is_refused_for_another_subnets_client(self, client, db, monkeypatch):
        from tests.conftest import restricted_client

        _servers(monkeypatch)
        calls = _stub_tail(monkeypatch, _ok(EXCHANGE))
        _lease(db, subnet_id=1)
        restricted_client(client, db, allowed_subnets=[999], role="admin", username="trace_restricted1")
        try:
            r = client.get("/tools/trace", query_string={"mac": MAC})
            assert r.status_code == 403
            assert calls == []
        finally:
            _clean(db)

    def test_subnet_restricted_admin_is_refused_for_an_unknown_client(self, client, db, monkeypatch):
        from tests.conftest import restricted_client

        _servers(monkeypatch)
        _stub_tail(monkeypatch, _ok(EXCHANGE))
        _clean(db)
        restricted_client(client, db, allowed_subnets=[1], role="admin", username="trace_restricted2")
        r = client.get("/tools/trace", query_string={"mac": MAC})
        assert r.status_code == 403

    def test_watch_arms_htmx_polling_and_stops_at_sixty_seconds(self, logged_in_client, db, monkeypatch):
        _servers(monkeypatch)
        _stub_tail(monkeypatch, _ok(EXCHANGE))
        _clean(db)
        first = logged_in_client.get("/tools/trace", query_string={"mac": MAC, "watch": "1"})
        assert b'hx-trigger="every 5s"' in first.data
        assert b"t=5" in first.data
        last = logged_in_client.get("/tools/trace", query_string={"mac": MAC, "watch": "1", "t": "60"})
        assert b"hx-trigger" not in last.data

    def test_htmx_request_returns_only_the_results_partial(self, logged_in_client, db, monkeypatch):
        _servers(monkeypatch)
        _stub_tail(monkeypatch, _ok(EXCHANGE))
        _clean(db)
        r = logged_in_client.get("/tools/trace", query_string={"mac": MAC}, headers={"HX-Request": "true"})
        assert r.status_code == 200
        assert b"page-header" not in r.data
        assert b'id="trace-results"' in r.data
