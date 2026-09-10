"""
jen/services/proxy.py
─────────────────────
v5.17.0 (Q6 6D) — TrustedProxyMiddleware.

Installed by create_app() (wrapping app.wsgi_app, so it runs before Flask
sees the request) ONLY when [server] trusted_proxies is non-empty. When
the WSGI peer (REMOTE_ADDR) is inside one of the configured networks it
rewrites:

  * REMOTE_ADDR      <- the rightmost X-Forwarded-For entry that is NOT
                        itself a trusted proxy (falls back to the leftmost
                        if every hop is trusted)
  * wsgi.url_scheme  <- X-Forwarded-Proto, only when it is exactly
                        "http" or "https"

An untrusted peer's forwarding headers are attacker-controlled and are
ignored entirely. Rate limiting, audit IPs and MFA trusted-device IPs all
read request.remote_addr, so once this runs they see the real client.
"""

import ipaddress
import logging

logger = logging.getLogger(__name__)


class TrustedProxyMiddleware:
    def __init__(self, wsgi_app, networks):
        self.wsgi_app = wsgi_app
        self.networks = list(networks or [])

    def _is_trusted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def __call__(self, environ, start_response):
        peer = environ.get("REMOTE_ADDR", "")
        if self.networks and self._is_trusted(peer):
            chain = [h.strip() for h in environ.get("HTTP_X_FORWARDED_FOR", "").split(",") if h.strip()]
            if chain:
                environ["REMOTE_ADDR"] = next(
                    (h for h in reversed(chain) if not self._is_trusted(h)),
                    chain[0],
                )
            proto = environ.get("HTTP_X_FORWARDED_PROTO", "").strip().lower()
            if proto in ("http", "https"):
                environ["wsgi.url_scheme"] = proto
        return self.wsgi_app(environ, start_response)
