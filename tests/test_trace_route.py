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

    class _Calls(list):
        kwargs: list

    calls = _Calls()
    calls.kwargs = []

    def fake(server, path, lines=200, **kw):
        calls.append((path, lines))
        calls.kwargs.append(kw)
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


class TestTraceFailsClosedAcrossSubnets:
    """v5.49.0-beta.2 (audit E) - a MAC known in an allowed AND a denied subnet
    is refused outright; the log lines are not filtered per subnet."""

    def test_mac_spanning_allowed_and_denied_subnet_is_403(self, client, db, monkeypatch):
        from tests.conftest import restricted_client

        _servers(monkeypatch)
        calls = _stub_tail(monkeypatch, _ok(EXCHANGE))
        _lease(db, subnet_id=1)  # allowed to the user below
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (MAC_HEX,))
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address) "
                "VALUES (UNHEX(%s), 0, 999, INET_ATON('10.99.9.9'))",
                (MAC_HEX,),
            )
        db.commit()
        restricted_client(client, db, allowed_subnets=[1], role="admin", username="trace_span1")
        try:
            r = client.get("/tools/trace", query_string={"mac": MAC})
            assert r.status_code == 403
            assert calls == []
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (MAC_HEX,))
            db.commit()
            _clean(db)


class TestTraceTimeout:
    """v5.49.0-beta.5 (Q55-L) - a hung SSH must not hold a worker for the
    helper's 60 s default: Trace asks for 15."""

    def test_trace_passes_a_short_timeout(self, logged_in_client, db, monkeypatch):
        _servers(monkeypatch)
        calls = _stub_tail(monkeypatch, _ok(EXCHANGE))
        _clean(db)
        logged_in_client.get("/tools/trace", query_string={"mac": MAC})
        assert calls.kwargs and calls.kwargs[-1] == {"timeout": 15}

    def test_tail_log_hands_the_timeout_to_helper_call(self, monkeypatch):
        from jen.services import kea_host

        seen = {}

        def fake_helper_call(server, op, payload=None, timeout=60):
            seen["timeout"] = timeout
            return {"ok": True, "lines": []}

        monkeypatch.setattr(kea_host, "helper_call", fake_helper_call)
        monkeypatch.setattr(kea_host, "_record_from_resp", lambda *a, **k: None)
        kea_host.tail_log({"id": 1}, "/var/log/kea/x.log", 100, timeout=15)
        assert seen["timeout"] == 15
        kea_host.tail_log({"id": 1}, "/var/log/kea/x.log", 100)
        assert seen["timeout"] == 60  # unchanged default for every other caller


class TestTraceNeedsUnrestrictedAccess:
    """v5.49.0-beta.6 (Q56-1) - Kea's log has no per-line subnet boundary Jen
    can trust, so Trace joins config history and Doctor: unrestricted subnet
    access only."""

    def test_scoped_admin_is_refused_even_for_a_mac_in_their_own_subnet(self, client, db, monkeypatch):
        from tests.conftest import restricted_client

        _servers(monkeypatch)
        calls = _stub_tail(monkeypatch, _ok(EXCHANGE))
        _lease(db, subnet_id=1)
        restricted_client(client, db, allowed_subnets=[1], role="admin", username="trace_scoped_own")
        try:
            assert client.get("/tools/trace", query_string={"mac": MAC}).status_code == 403
            assert calls == []
        finally:
            _clean(db)

    def test_scoped_admin_is_refused_the_blank_form_too(self, client, db, monkeypatch):
        from tests.conftest import restricted_client

        _servers(monkeypatch)
        restricted_client(client, db, allowed_subnets=[1], role="admin", username="trace_scoped_blank")
        assert client.get("/tools/trace").status_code == 403

    def test_a_client_that_moved_out_of_a_denied_subnet_shows_none_of_its_old_lines(self, client, db, monkeypatch):
        """The regression named in the review: the MAC's CURRENT lease is in A
        (allowed), but the tail of the log still carries its earlier activity in
        B (denied)."""
        from tests.conftest import restricted_client

        _servers(monkeypatch)
        old_b_lines = [
            "2026-09-20 09:00:00.100 INFO  [kea-dhcp4.leases/1] DHCP4_LEASE_ALLOC "
            f"[hwtype=1 {MAC}]: lease 10.77.0.77 has been allocated for 3600 seconds (zz-secret-b-host)"
        ]
        calls = _stub_tail(monkeypatch, _ok(old_b_lines))
        _lease(db, subnet_id=1)
        restricted_client(client, db, allowed_subnets=[1], role="admin", username="trace_scoped_moved")
        try:
            r = client.get("/tools/trace", query_string={"mac": MAC})
            assert r.status_code == 403
            assert b"zz-secret-b-host" not in r.data and b"10.77.0.77" not in r.data
            assert calls == []  # the log is never even read for a scoped caller
        finally:
            _clean(db)

    def test_unrestricted_admin_still_traces(self, logged_in_client, db, monkeypatch):
        _servers(monkeypatch)
        _stub_tail(monkeypatch, _ok(EXCHANGE))
        _lease(db, subnet_id=1)
        try:
            assert logged_in_client.get("/tools/trace", query_string={"mac": MAC}).status_code == 200
        finally:
            _clean(db)

    def test_trace_links_are_hidden_from_scoped_users(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent / "templates"
        for name in ("explain.html", "_lease_rows.html", "_reservation_row.html"):
            lines = [ln for ln in (root / name).read_text(encoding="utf-8").splitlines() if "/tools/trace" in ln]
            assert lines and all("current_user.all_subnets" in ln for ln in lines), name
