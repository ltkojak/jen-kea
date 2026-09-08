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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger(__name__)


def _make_handler(https_port: int):
    class _RedirectHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _redirect(self):
            host = (self.headers.get("Host") or "").split(":")[0] or "localhost"
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
    return ThreadingHTTPServer(("0.0.0.0", http_port), _make_handler(https_port))


def serve_forever(http_port: int, https_port: int) -> None:
    """Blocking. Used by run.py when it has nothing else to do on the
    main thread (the SSL path, where gunicorn runs as a child process)."""
    srv = make_server(http_port, https_port)
    logger.info("HTTP->HTTPS redirect listening on :%d -> :%d", http_port, https_port)
    srv.serve_forever()
