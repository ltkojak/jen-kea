"""
tests/test_run_launcher.py
──────────────────────────
v5.5.0 — run.py stopped being a server and became a launcher that
builds a gunicorn command line. These test the command-line
construction (pure) and the SSL/non-SSL branching decisions.
"""

import configparser
import os
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

    def test_config_module_always_passed_for_tls_floor(self):
        # jen/gunicorn_conf.py's ssl_context hook is what restores the
        # TLS 1.2 minimum on the SSL path (gunicorn has no CLI flag for it).
        for kw in ({}, {"certfile": "/c.crt", "keyfile": "/c.key"}):
            argv = run.gunicorn_argv("x", 8, **kw)
            assert argv[argv.index("--config") + 1] == "python:jen.gunicorn_conf"

    def test_thread_count_is_clamped(self):
        assert run.gunicorn_argv("x", 0)[run.gunicorn_argv("x", 0).index("--threads") + 1] == "1"
        assert run.gunicorn_argv("x", 999)[run.gunicorn_argv("x", 999).index("--threads") + 1] == "64"
        assert run.gunicorn_argv("x", 4)[run.gunicorn_argv("x", 4).index("--threads") + 1] == "4"

    def test_always_single_worker(self):
        # The whole background-worker model depends on -w 1.
        for threads in (1, 8, 64):
            argv = run.gunicorn_argv("x", threads)
            assert argv[argv.index("--workers") + 1] == "1"

    def test_forwarded_allow_ips_omitted_when_unset(self):
        assert "--forwarded-allow-ips" not in run.gunicorn_argv("x", 8)
        assert "--forwarded-allow-ips" not in run.gunicorn_argv("x", 8, forwarded_allow_ips="  ,  ")

    def test_forwarded_allow_ips_passed_through_when_set(self):
        argv = run.gunicorn_argv("x", 8, forwarded_allow_ips=" 127.0.0.1 , 10.0.0.0/8 ")
        i = argv.index("--forwarded-allow-ips")
        assert argv[i + 1] == "127.0.0.1,10.0.0.0/8"

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


class TestGunicornChdir:
    def test_chdir_is_the_directory_holding_the_jen_package(self):
        """v5.65.1 (Q90) - gunicorn imports `jen.wsgi` from its CWD; the Docker image
        started in `/`. Passing --chdir makes the launch independent of where it began."""
        import os

        argv = run.gunicorn_argv("x", 8)
        chdir = argv[argv.index("--chdir") + 1]
        assert os.path.isdir(os.path.join(chdir, "jen")) and os.path.isfile(os.path.join(chdir, "run.py"))

    def test_chdir_present_with_and_without_tls(self):
        for kw in ({}, {"certfile": "/c.crt", "keyfile": "/c.key"}):
            assert "--chdir" in run.gunicorn_argv("x", 8, **kw)


class TestBuildConfigFromEnv:
    """v5.67.0-beta.7 (Q119, item e) — the README's own advertised "leave
    Kea blank, connect it later from /setup" path used to never write a
    jen.config at all when JEN_KEA_API_URL was unset — AppConfig.load()
    then raises FileNotFoundError and a blank-Kea container crash-loops
    forever. The real precondition is Jen's own database, the one thing
    AppConfig.load() genuinely can't run without."""

    def _clear_jen_env(self, monkeypatch):
        for key in list(os.environ):
            if key.startswith("JEN_"):
                monkeypatch.delenv(key, raising=False)

    def test_no_jen_db_host_writes_nothing(self, tmp_path, monkeypatch):
        self._clear_jen_env(monkeypatch)
        monkeypatch.setattr(run.extensions, "CONFIG_DIR", str(tmp_path))
        run._build_config_from_env()
        assert not (tmp_path / "jen.config").exists()

    def test_jen_db_present_with_no_kea_still_writes_a_config(self, tmp_path, monkeypatch):
        self._clear_jen_env(monkeypatch)
        monkeypatch.setenv("JEN_DB_HOST", "mysql")
        monkeypatch.setattr(run.extensions, "CONFIG_DIR", str(tmp_path))
        run._build_config_from_env()
        config_path = tmp_path / "jen.config"
        assert config_path.exists()
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(config_path)
        assert cfg.get("jen_db", "host") == "mysql"
        assert cfg.get("kea", "api_url") == ""

    def test_never_overwrites_an_existing_config_even_with_blank_kea(self, tmp_path, monkeypatch):
        self._clear_jen_env(monkeypatch)
        monkeypatch.setenv("JEN_DB_HOST", "mysql")
        monkeypatch.setattr(run.extensions, "CONFIG_DIR", str(tmp_path))
        config_path = tmp_path / "jen.config"
        config_path.write_text("# configured by hand, kea set up via /setup\n[kea]\napi_url = http://real-kea:8000\n")
        run._build_config_from_env()
        assert "real-kea" in config_path.read_text()

    def test_a_shipped_placeholder_value_is_written_as_blank(self, tmp_path, monkeypatch):
        """An old .env carried over from before this Q blanked the
        shipped placeholders must not write a literal 'YOUR-KEA-SERVER'
        into a fresh container's config."""
        self._clear_jen_env(monkeypatch)
        monkeypatch.setenv("JEN_DB_HOST", "mysql")
        monkeypatch.setenv("JEN_KEA_API_URL", "http://YOUR-KEA-SERVER:8000")
        monkeypatch.setenv("JEN_KEA_DB_HOST", "YOUR-KEA-SERVER")
        monkeypatch.setattr(run.extensions, "CONFIG_DIR", str(tmp_path))
        run._build_config_from_env()
        content = (tmp_path / "jen.config").read_text()
        assert "YOUR-KEA-SERVER" not in content

    def test_a_real_kea_value_passes_through_unchanged(self, tmp_path, monkeypatch):
        self._clear_jen_env(monkeypatch)
        monkeypatch.setenv("JEN_DB_HOST", "mysql")
        monkeypatch.setenv("JEN_KEA_API_URL", "http://10.0.0.5:8000")
        monkeypatch.setattr(run.extensions, "CONFIG_DIR", str(tmp_path))
        run._build_config_from_env()
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(tmp_path / "jen.config")
        assert cfg.get("kea", "api_url") == "http://10.0.0.5:8000"
