#!/usr/bin/env python3
"""
run.py — Jen entry point (v2.6.x+)
────────────────────────────────────
Starts the Jen application via the jen package factory.

Environment variable support (Docker / .env):
  If JEN_KEA_API_URL is set, a config file is auto-generated from env vars
  so Docker users don't need to mount a jen.config manually.

  Required env vars for auto-config:
    JEN_KEA_API_URL, JEN_KEA_API_USER, JEN_KEA_API_PASS
    JEN_KEA_DB_HOST, JEN_KEA_DB_USER, JEN_KEA_DB_PASS
    JEN_DB_HOST, JEN_DB_USER, JEN_DB_PASS

  Optional env vars:
    JEN_KEA_DB_NAME        (default: kea)
    JEN_DB_NAME            (default: jen)
    JEN_HTTP_PORT          (default: 5050)
    JEN_HTTPS_PORT         (default: 8443)
    JEN_KEA_SSH_HOST
    JEN_KEA_SSH_USER
    JEN_KEA_CONF           (default: /etc/kea/kea-dhcp4.conf)
    JEN_DDNS_PROVIDER      (default: none)
    JEN_DDNS_URL
    JEN_DDNS_TOKEN
    JEN_DDNS_ZONE
    JEN_DDNS_LOG           (default: /var/log/kea/kea-ddns.log)
    JEN_SUBNETS            (format: "1=Production,10.10.10.0/24;30=IoT,10.10.30.0/24")
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


def _build_config_from_env():
    """
    If JEN_KEA_API_URL is set, write /etc/jen/jen.config from environment
    variables. This allows Docker deployments without a mounted config file.
    Skips if /etc/jen/jen.config already exists and contains a valid api_url.
    """
    config_path = "/etc/jen/jen.config"

    # Check if we have env vars
    if not os.environ.get("JEN_KEA_API_URL"):
        return  # No env config — rely on mounted jen.config

    # Check if a valid config already exists
    if os.path.exists(config_path):
        try:
            import configparser
            cfg = configparser.ConfigParser()
            cfg.read(config_path)
            if cfg.get("kea", "api_url", fallback="").strip():
                return  # Valid config exists, don't overwrite
        except Exception:
            pass

    # Parse subnet env var: "1=Production,10.0.0.0/24;30=IoT,10.30.0.0/24"
    subnets_raw = os.environ.get("JEN_SUBNETS", "")
    subnet_lines = ""
    if subnets_raw:
        for entry in subnets_raw.split(";"):
            entry = entry.strip()
            if "=" in entry:
                sid, rest = entry.split("=", 1)
                subnet_lines += f"{sid.strip()} = {rest.strip()}\n"

    os.makedirs("/etc/jen", exist_ok=True)
    config_content = f"""# Jen - auto-generated from environment variables
[kea]
api_url  = {os.environ.get('JEN_KEA_API_URL', '')}
api_user = {os.environ.get('JEN_KEA_API_USER', '')}
api_pass = {os.environ.get('JEN_KEA_API_PASS', '')}
name     = {os.environ.get('JEN_KEA_NAME', 'Kea Server 1')}
role     = {os.environ.get('JEN_KEA_ROLE', 'primary')}
ha_mode  = {os.environ.get('JEN_HA_MODE', '')}

[kea_db]
host     = {os.environ.get('JEN_KEA_DB_HOST', '')}
user     = {os.environ.get('JEN_KEA_DB_USER', '')}
password = {os.environ.get('JEN_KEA_DB_PASS', '')}
database = {os.environ.get('JEN_KEA_DB_NAME', 'kea')}

[jen_db]
host     = {os.environ.get('JEN_DB_HOST', '')}
user     = {os.environ.get('JEN_DB_USER', '')}
password = {os.environ.get('JEN_DB_PASS', '')}
database = {os.environ.get('JEN_DB_NAME', 'jen')}

[server]
http_port  = {os.environ.get('JEN_HTTP_PORT', '5050')}
https_port = {os.environ.get('JEN_HTTPS_PORT', '8443')}

[kea_ssh]
host     = {os.environ.get('JEN_KEA_SSH_HOST', '')}
user     = {os.environ.get('JEN_KEA_SSH_USER', '')}
key_path = /etc/jen/ssh/jen_rsa
kea_conf = {os.environ.get('JEN_KEA_CONF', '/etc/kea/kea-dhcp4.conf')}

[subnets]
{subnet_lines}
[ddns]
log_path     = {os.environ.get('JEN_DDNS_LOG', '/var/log/kea/kea-ddns.log')}
provider     = {os.environ.get('JEN_DDNS_PROVIDER', 'none')}
api_url      = {os.environ.get('JEN_DDNS_URL', '')}
api_token    = {os.environ.get('JEN_DDNS_TOKEN', '')}
forward_zone = {os.environ.get('JEN_DDNS_ZONE', '')}
"""
    with open(config_path, "w") as f:
        f.write(config_content)

    # Set permissions if possible (may not be root in Docker)
    try:
        os.chmod(config_path, 0o640)
    except Exception:
        pass

    print(f"Jen: config generated from environment variables → {config_path}")


def main():
    # Auto-generate config from env vars if running in Docker
    _build_config_from_env()

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
