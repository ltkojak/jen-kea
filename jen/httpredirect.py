"""
jen/httpredirect.py
───────────────────
A tiny stdlib HTTP server whose only job is to 301-redirect every
request to the HTTPS port. v5.5.0.

When SSL is configured, gunicorn serves HTTPS on one port and this runs
on the plain-HTTP port so someone who types the old `http://host:5050`
URL still lands on the app. Before v5.5.0 this was a second Flask app
inside `run.py`; gunicorn can only terminate TLS process-wide, so the
redirect can't share its process. Kept deliberately dependency-free and
trivial — it never touches the database, config, or the Jen app.
"""

import logging
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger(__name__)

# A hostname (RFC 1123 labels), a dotted IPv4, or a bracketed IPv6 literal.
# Anything else in a Host header is not somewhere we'll redirect a browser.
_HOST_RE = re.compile(
    r"^(?:\[[0-9A-Fa-f:.]+\]"
    r"|[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?)$"
)


def safe_host(host_header):
    """
    v5.9.1 — the host part of a Host header, or None if it isn't a plain
    hostname / IPv4 / bracketed IPv6. Both redirect paths (this listener
    and the app's before_request) build `https://<host>:<port>/…` from the
    incoming Host; a value we'd never legitimately serve must not become a
    Location we send a browser to. Port suffixes are stripped.
    """
    h = (host_header or "").strip()
    if not h or len(h) > 253:
        return None
    if h.startswith("["):
        end = h.find("]")
        if end == -1:
            return None
        h = h[: end + 1]
    else:
        h = h.split(":", 1)[0]
    return h if _HOST_RE.match(h) else None


def _make_handler(https_port: int):
    class _RedirectHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _redirect(self):
            raw = self.headers.get("Host")
            host = safe_host(raw) if raw else "localhost"
            if host is None:
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            # self.path carries the query string too — preserved on purpose
            # (Settings tabs are ?tab=… since v5.9.0).
            location = f"https://{host}:{https_port}{self.path}"
            body = b"Redirecting to HTTPS.\n"
            self.send_response(301)
            self.send_header("Location", location)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        # Every method redirects — GET/HEAD/POST/etc.
        do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _redirect

        def log_message(self, *args):
            pass  # don't spam the journal with one line per redirect

    return _RedirectHandler


def make_server(http_port: int, https_port: int) -> ThreadingHTTPServer:
    """Build (but don't start) the redirect server."""
    # nosec B104 — binding all interfaces is intentional and matches what
    # gunicorn (and the pre-v5.5.0 werkzeug server) already do: Jen is a
    # LAN admin console meant to be reached on whatever interface the box
    # has. This listener only ever emits 301s to HTTPS — no app, no data.
    return ThreadingHTTPServer(("0.0.0.0", http_port), _make_handler(https_port))  # nosec B104


def serve_forever(http_port: int, https_port: int) -> None:
    """Blocking. Used by run.py when it has nothing else to do on the
    main thread (the SSL path, where gunicorn runs as a child process)."""
    srv = make_server(http_port, https_port)
    logger.info("HTTP->HTTPS redirect listening on :%d -> :%d", http_port, https_port)
    srv.serve_forever()
