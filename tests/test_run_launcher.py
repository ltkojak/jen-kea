"""
tests/test_run_launcher.py
──────────────────────────
v5.5.0 — run.py stopped being a server and became a launcher that
builds a gunicorn command line. These test the command-line
construction (pure) and the SSL/non-SSL branching decisions.
"""

import sys

import run


class TestGunicornArgv:
    def test_non_ssl_binds_http_port_no_cert(self):
        argv = run.gunicorn_argv("0.0.0.0:5050", 8)
        assert argv[:4] == [sys.executable, "-m", "gunicorn", "jen.wsgi:application"]
        assert "--certfile" not in argv
        assert argv[-2:] == ["--bind", "0.0.0.0:5050"]
        assert "--workers" in argv and argv[argv.index("--workers") + 1] == "1"
        assert argv[argv.index("--threads") + 1] == "8"

    def test_ssl_adds_cert_key_ciphers(self):
        argv = run.gunicorn_argv("0.0.0.0:8443", 12, certfile="/etc/jen/ssl/x.crt", keyfile="/etc/jen/ssl/x.key")
        assert argv[argv.index("--certfile") + 1] == "/etc/jen/ssl/x.crt"
        assert argv[argv.index("--keyfile") + 1] == "/etc/jen/ssl/x.key"
        assert "--ciphers" in argv
        assert argv[argv.index("--threads") + 1] == "12"
        assert argv[-2:] == ["--bind", "0.0.0.0:8443"]

    def test_thread_count_is_clamped(self):
        assert run.gunicorn_argv("x", 0)[run.gunicorn_argv("x", 0).index("--threads") + 1] == "1"
        assert run.gunicorn_argv("x", 999)[run.gunicorn_argv("x", 999).index("--threads") + 1] == "64"
        assert run.gunicorn_argv("x", 4)[run.gunicorn_argv("x", 4).index("--threads") + 1] == "4"

    def test_always_single_worker(self):
        # The whole background-worker model depends on -w 1.
        for threads in (1, 8, 64):
            argv = run.gunicorn_argv("x", threads)
            assert argv[argv.index("--workers") + 1] == "1"

    def test_graceful_shutdown_flags_present(self):
        argv = run.gunicorn_argv("x", 8)
        assert "--graceful-timeout" in argv
        assert "--timeout" in argv


class TestFallbackDetection:
    def test_gunicorn_importable_is_true_here(self):
        # CI installs gunicorn via requirements.txt.
        assert run._gunicorn_importable() is True

    def test_module_is_importable_without_running_main(self):
        # Importing run.py must not start a server or touch the network.
        assert hasattr(run, "main")
        assert callable(run.main)
