"""
tests/test_trusted_proxy.py
───────────────────────────
v5.17.0 (Q6 6D) — jen/services/proxy.py::TrustedProxyMiddleware.
"""

import ipaddress

import pytest

from jen.services.proxy import TrustedProxyMiddleware

_NETS = [ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("10.0.0.0/8")]


def _run(mw, remote_addr, headers=None):
    """Drive the middleware once; return the environ it passed downstream."""
    seen = {}

    def downstream(environ, _start_response):
        seen.update(environ)
        return [b""]

    mw.wsgi_app = downstream
    environ = {"REMOTE_ADDR": remote_addr, "wsgi.url_scheme": "http"}
    for k, v in (headers or {}).items():
        environ["HTTP_" + k.upper().replace("-", "_")] = v
    mw(environ, lambda *a: None)
    return seen


class TestMiddlewareUnit:
    def _mw(self):
        return TrustedProxyMiddleware(None, _NETS)

    def test_untrusted_peer_headers_ignored(self):
        env = _run(self._mw(), "203.0.113.5", {"X-Forwarded-For": "1.2.3.4", "X-Forwarded-Proto": "https"})
        assert env["REMOTE_ADDR"] == "203.0.113.5"
        assert env["wsgi.url_scheme"] == "http"

    def test_trusted_peer_takes_the_forwarded_ip(self):
        env = _run(self._mw(), "127.0.0.1", {"X-Forwarded-For": "203.0.113.9"})
        assert env["REMOTE_ADDR"] == "203.0.113.9"

    def test_rightmost_non_proxy_hop_wins(self):
        env = _run(self._mw(), "10.1.1.1", {"X-Forwarded-For": "203.0.113.9, 198.51.100.7, 10.9.9.9"})
        # 10.9.9.9 is itself a trusted proxy → skip it, take 198.51.100.7
        assert env["REMOTE_ADDR"] == "198.51.100.7"

    def test_all_hops_trusted_falls_back_to_leftmost(self):
        env = _run(self._mw(), "127.0.0.1", {"X-Forwarded-For": "10.1.1.1, 10.2.2.2"})
        assert env["REMOTE_ADDR"] == "10.1.1.1"

    def test_proto_only_http_or_https(self):
        assert _run(self._mw(), "127.0.0.1", {"X-Forwarded-Proto": "https"})["wsgi.url_scheme"] == "https"
        assert _run(self._mw(), "127.0.0.1", {"X-Forwarded-Proto": "ftp"})["wsgi.url_scheme"] == "http"

    def test_garbage_xff_header_is_survivable(self):
        env = _run(self._mw(), "127.0.0.1", {"X-Forwarded-For": ",,  , not-an-ip ,"})
        # no usable non-proxy hop → leftmost token, whatever it is; no crash
        assert env["REMOTE_ADDR"] == "not-an-ip"

    def test_no_xff_leaves_remote_addr_alone(self):
        env = _run(self._mw(), "127.0.0.1", {})
        assert env["REMOTE_ADDR"] == "127.0.0.1"

    def test_empty_network_list_is_a_passthrough(self):
        mw = TrustedProxyMiddleware(None, [])
        env = _run(mw, "127.0.0.1", {"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"})
        assert env["REMOTE_ADDR"] == "127.0.0.1"
        assert env["wsgi.url_scheme"] == "http"


class TestAuditSeesTheRealClient:
    """Integration: with the middleware in front of the real app, the
    forwarded IP is what lands in the (now synchronous) audit log."""

    @pytest.fixture
    def _clean_audit(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM audit_log WHERE action='LOGIN'")
        db.commit()
        yield

    def test_forwarded_ip_is_recorded_when_proxy_trusted(self, app, db, _clean_audit):
        orig = app.wsgi_app
        app.wsgi_app = TrustedProxyMiddleware(orig, [ipaddress.ip_network("127.0.0.1/32")])
        try:
            c = app.test_client()
            c.post(
                "/login",
                data={"username": "admin", "password": "admin"},
                headers={"X-Forwarded-For": "203.0.113.9"},
            )
        finally:
            app.wsgi_app = orig
        with db.cursor() as cur:
            cur.execute("SELECT ip_address FROM audit_log WHERE action='LOGIN' ORDER BY id DESC LIMIT 1")
            assert cur.fetchone()["ip_address"] == "203.0.113.9"

    def test_forwarded_ip_is_ignored_without_the_setting(self, app, db, _clean_audit):
        c = app.test_client()
        c.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            headers={"X-Forwarded-For": "203.0.113.9"},
        )
        with db.cursor() as cur:
            cur.execute("SELECT ip_address FROM audit_log WHERE action='LOGIN' ORDER BY id DESC LIMIT 1")
            assert cur.fetchone()["ip_address"] == "127.0.0.1"
