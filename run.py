#!/usr/bin/env python3
"""
run.py — Jen entrypoint / launcher (v5.5.0)
──────────────────────────────────────────
Not a server anymore. `run.py` loads configuration and then launches
**gunicorn** (`jen.wsgi:application`, `--workers 1 --threads N`):

  no SSL : `os.execvp` gunicorn on the HTTP port — this process is
           replaced, systemd owns gunicorn directly, SIGTERM flows
           straight to it.
  SSL    : spawn gunicorn (HTTPS) as a child, run the HTTP->HTTPS
           redirect (jen/httpredirect.py) on the main thread, and
           forward SIGTERM/SIGINT to gunicorn so a `systemctl restart`
           drains in-flight requests instead of cutting them.

One worker keeps the backup scheduler and alert loop a single-process
concern (they're started from jen/wsgi.py); `--threads` carries the
I/O-bound concurrency. The thread count is `[server] threads` in
jen.config (Settings -> Infrastructure), clamped 1-64.

**Werkzeug fallback.** If gunicorn can't be imported or launched — a
botched dependency install, a non-Linux dev box — `run.py` falls back
to the werkzeug server with a loud CRITICAL log. That path is a safety
net so the console never goes dark on a bad update; it is NOT a
supported way to run Jen in production.

Docker / .env auto-config
─────────────────────────
  If JEN_KEA_API_URL is set, a config file is auto-generated from env
  vars so Docker users don't need to mount a jen.config manually.

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
import sys

# ── venv re-exec (v5.8.0) ───────────────────────────────────────────────────
# Bare-metal Jen keeps its Python dependencies in /opt/jen/venv (built by
# install.sh, kept current by the self-updater) rather than system
# site-packages. jen.service still invokes the *system* python3 — so this
# file must be importable there — and we re-exec into the venv interpreter
# here, before `from jen import …` below pulls in a single dependency.
#
# Deliberately a re-exec and not a jen.service ExecStart change: the unit
# file then never has to change, and an in-app update from a pre-5.8.0
# install can't leave systemd pointing at a venv that isn't there yet. A
# missing venv (not built yet) or a broken one (an OS python bump stranded
# it — `sudo ./install.sh --repair` rebuilds) simply falls through to the
# current interpreter. Set JEN_NO_VENV_REEXEC=1 to opt out.
#
# "Are we already the venv interpreter?" is `sys.prefix == the venv dir`,
# NOT a realpath comparison of the executables: a POSIX venv's bin/python
# is a symlink chain back to the base interpreter, so both realpath to
# /usr/bin/pythonX.Y and the guard would wrongly conclude "already in the
# venv" and never re-exec (v5.8.0 shipped with exactly that bug).
_VENV_DIR = "/opt/jen/venv"


def _venv_reexec_target(venv_dir=_VENV_DIR):
    """The venv interpreter this process should re-exec into, or None to
    stay put — opted out, no venv present, or we're already running it."""
    if os.environ.get("JEN_NO_VENV_REEXEC") == "1":
        return None
    venv_python = os.path.join(venv_dir, "bin", "python")
    if not os.path.exists(venv_python):
        return None
    if os.path.abspath(sys.prefix) == os.path.abspath(venv_dir):
        return None
    return venv_python


_reexec_target = _venv_reexec_target()
if _reexec_target:
    try:
        os.execv(_reexec_target, [_reexec_target, os.path.abspath(__file__), *sys.argv[1:]])
    except OSError:
        # Broken venv (dangling interpreter symlink, etc.) — continue on
        # whatever interpreter we're already running under.
        pass

import logging  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402

from jen import JEN_VERSION, create_app, extensions  # noqa: E402
from jen.config import app_config, ssl_configured  # noqa: E402
from jen.logging_config import configure_logging  # noqa: E402

logger = logging.getLogger("jen.launch")

_TLS_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"


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

            # interpolation=None — same reason as AppConfig.load(): a DB/API
            # password can legitimately contain a literal '%', which default
            # BasicInterpolation chokes on when reading the value back.
            cfg = configparser.ConfigParser(interpolation=None)
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
api_url  = {os.environ.get("JEN_KEA_API_URL", "")}
api_user = {os.environ.get("JEN_KEA_API_USER", "")}
api_pass = {os.environ.get("JEN_KEA_API_PASS", "")}
name     = {os.environ.get("JEN_KEA_NAME", "Kea Server 1")}
role     = {os.environ.get("JEN_KEA_ROLE", "primary")}
ha_mode  = {os.environ.get("JEN_HA_MODE", "")}

[kea_db]
host     = {os.environ.get("JEN_KEA_DB_HOST", "")}
user     = {os.environ.get("JEN_KEA_DB_USER", "")}
password = {os.environ.get("JEN_KEA_DB_PASS", "")}
database = {os.environ.get("JEN_KEA_DB_NAME", "kea")}

[jen_db]
host     = {os.environ.get("JEN_DB_HOST", "")}
user     = {os.environ.get("JEN_DB_USER", "")}
password = {os.environ.get("JEN_DB_PASS", "")}
database = {os.environ.get("JEN_DB_NAME", "jen")}

[server]
http_port  = {os.environ.get("JEN_HTTP_PORT", "5050")}
https_port = {os.environ.get("JEN_HTTPS_PORT", "8443")}

[kea_ssh]
host     = {os.environ.get("JEN_KEA_SSH_HOST", "")}
user     = {os.environ.get("JEN_KEA_SSH_USER", "")}
key_path = /etc/jen/ssh/jen_rsa
kea_conf = {os.environ.get("JEN_KEA_CONF", "/etc/kea/kea-dhcp4.conf")}

[subnets]
{subnet_lines}
[ddns]
log_path     = {os.environ.get("JEN_DDNS_LOG", "/var/log/kea/kea-ddns.log")}
provider     = {os.environ.get("JEN_DDNS_PROVIDER", "none")}
api_url      = {os.environ.get("JEN_DDNS_URL", "")}
api_token    = {os.environ.get("JEN_DDNS_TOKEN", "")}
forward_zone = {os.environ.get("JEN_DDNS_ZONE", "")}
"""
    with open(config_path, "w") as f:
        f.write(config_content)

    # Set permissions if possible (may not be root in Docker)
    try:
        os.chmod(config_path, 0o640)
    except Exception:
        pass

    print(f"Jen: config generated from environment variables → {config_path}")


# ── gunicorn launch ─────────────────────────────────────────────────────────


def gunicorn_argv(bind: str, threads: int, certfile: str = "", keyfile: str = "") -> list[str]:
    """Build the gunicorn command line. Pure — unit-tested directly."""
    argv = [
        sys.executable,
        "-m",
        "gunicorn",
        "jen.wsgi:application",
        "--config",
        "python:jen.gunicorn_conf",
        "--workers",
        "1",
        "--threads",
        str(max(1, min(int(threads), 64))),
        "--timeout",
        "120",
        "--graceful-timeout",
        "30",
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
        "--name",
        "jen",
    ]
    if certfile:
        # --ciphers + the TLS 1.2 floor from jen/gunicorn_conf.py's
        # ssl_context hook (gunicorn has no CLI flag for the version floor).
        argv += ["--certfile", certfile, "--keyfile", keyfile, "--ciphers", _TLS_CIPHERS]
    argv += ["--bind", bind]
    return argv


def _ssl_cert_paths() -> tuple[str, str]:
    cert = extensions.SSL_COMBINED if os.path.exists(extensions.SSL_COMBINED) else extensions.SSL_CERT
    return cert, extensions.SSL_KEY


def _gunicorn_importable() -> bool:
    try:
        import gunicorn  # noqa: F401

        return True
    except Exception:
        return False


def main():
    # Logging from env only first — create_app()/config load below log
    # before extensions.cfg exists. Reconfigure once it's populated.
    configure_logging()
    _build_config_from_env()
    app_config.reload()
    configure_logging(extensions.cfg)

    http_port = extensions.HTTP_PORT
    https_port = extensions.HTTPS_PORT
    threads = extensions.WORKER_THREADS
    use_ssl = ssl_configured()

    if not _gunicorn_importable():
        logger.critical(
            "gunicorn is not importable — falling back to the werkzeug development "
            "server. This is NOT a supported way to run Jen in production. Install "
            "dependencies (pip install -r /opt/jen/requirements.txt) and restart. "
            "Running on werkzeug for now so the console stays up."
        )
        return _serve_werkzeug_fallback(use_ssl, http_port, https_port)

    if use_ssl:
        cert, key = _ssl_cert_paths()
        argv = gunicorn_argv(f"0.0.0.0:{https_port}", threads, certfile=cert, keyfile=key)
        print(f"Jen v{JEN_VERSION} — gunicorn HTTPS:{https_port}  HTTP redirect:{http_port}  threads:{threads}")
        try:
            proc = subprocess.Popen(argv)
        except (OSError, ValueError) as e:
            logger.critical("Could not start gunicorn (%s) — werkzeug fallback.", e)
            return _serve_werkzeug_fallback(use_ssl, http_port, https_port)

        def _forward(_signum, _frame):
            try:
                proc.send_signal(signal.SIGTERM)
            except Exception:
                pass

        signal.signal(signal.SIGTERM, _forward)
        signal.signal(signal.SIGINT, _forward)

        # Redirect responder in the background; main thread waits on gunicorn.
        import threading

        from jen.httpredirect import serve_forever

        threading.Thread(
            target=serve_forever,
            args=(http_port, https_port),
            name="jen-http-redirect",
            daemon=True,
        ).start()

        try:
            rc = proc.wait()
        except KeyboardInterrupt:
            proc.wait()
            rc = proc.returncode
        sys.exit(rc if rc is not None else 0)

    argv = gunicorn_argv(f"0.0.0.0:{http_port}", threads)
    print(f"Jen v{JEN_VERSION} — gunicorn HTTP:{http_port}  threads:{threads}")
    try:
        os.execvp(argv[0], argv)
    except OSError as e:
        logger.critical("Could not exec gunicorn (%s) — werkzeug fallback.", e)
        return _serve_werkzeug_fallback(use_ssl, http_port, https_port)


def _serve_werkzeug_fallback(use_ssl: bool, http_port: int, https_port: int):
    """The pre-v5.5.0 server, kept only as a safety net (see module
    docstring). Starts the background workers in-process since there's
    no gunicorn worker to do it."""
    import ssl
    import threading

    from flask import Flask, redirect, request
    from werkzeug.serving import make_server

    from jen.services.background import start_background_workers

    app = create_app()
    start_background_workers(app)

    if use_ssl:
        print(f"Jen v{JEN_VERSION} — [FALLBACK] werkzeug HTTPS:{https_port}  HTTP redirect:{http_port}")
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        ssl_ctx.set_ciphers(_TLS_CIPHERS)
        cert, key = _ssl_cert_paths()
        ssl_ctx.load_cert_chain(cert, key)
        https_server = make_server("0.0.0.0", https_port, app, ssl_context=ssl_ctx, threaded=True)

        http_redirect = Flask("http_redirect")

        @http_redirect.route("/", defaults={"path": ""})
        @http_redirect.route("/<path:path>")
        def _redirect(path):
            host = request.host.split(":")[0]
            return redirect(f"https://{host}:{https_port}/{path}", code=301)

        http_server = make_server("0.0.0.0", http_port, http_redirect, threaded=True)
        t1 = threading.Thread(target=https_server.serve_forever, daemon=True)
        t2 = threading.Thread(target=http_server.serve_forever, daemon=True)
        t1.start()
        t2.start()
        t1.join()
    else:
        print(f"Jen v{JEN_VERSION} — [FALLBACK] werkzeug HTTP only, port {http_port}")
        app.run(host="0.0.0.0", port=http_port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
