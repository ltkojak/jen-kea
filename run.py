#!/usr/bin/env python3
"""
run.py — Jen entry point (v2.6.x+)
────────────────────────────────────
Creates the application via the jen package factory and starts the server.
jen.py is kept as a compatibility shim for deployments that reference it directly.
"""

import os
import ssl
import threading

from flask import Flask, redirect, request
from werkzeug.serving import make_server

from jen import JEN_VERSION, create_app
from jen import extensions
from jen.config import ssl_configured
from jen.services.alerts import check_alerts


def main():
    app = create_app()

    HTTP_PORT  = extensions.HTTP_PORT
    HTTPS_PORT = extensions.HTTPS_PORT

    # Start background alert/monitoring loop
    threading.Thread(target=check_alerts, daemon=True).start()

    if ssl_configured():
        print(f"Jen v{JEN_VERSION} — HTTPS:{HTTPS_PORT}  HTTP redirect:{HTTP_PORT}")
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert = extensions.SSL_COMBINED if os.path.exists(extensions.SSL_COMBINED) \
               else extensions.SSL_CERT
        ssl_ctx.load_cert_chain(cert, extensions.SSL_KEY)
        https_server = make_server("0.0.0.0", HTTPS_PORT, app, ssl_context=ssl_ctx)
        http_redirect = Flask("http_redirect")

        @http_redirect.route("/", defaults={"path": ""})
        @http_redirect.route("/<path:path>")
        def _redirect(path):
            host = request.host.split(":")[0]
            return redirect(f"https://{host}:{HTTPS_PORT}/{path}", code=301)

        http_server = make_server("0.0.0.0", HTTP_PORT, http_redirect)
        t1 = threading.Thread(target=https_server.serve_forever, daemon=True)
        t2 = threading.Thread(target=http_server.serve_forever, daemon=True)
        t1.start(); t2.start(); t1.join()
    else:
        print(f"Jen v{JEN_VERSION} — HTTP only, port {HTTP_PORT}")
        app.run(host="0.0.0.0", port=HTTP_PORT, debug=False)


if __name__ == "__main__":
    main()
