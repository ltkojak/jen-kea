"""
tests/test_appconfig.py
───────────────────────
AppConfig single-source-of-truth guarantees (v4.0.0).

Every write path must leave the on-disk file, extensions.cfg, and all
derived globals consistent — the stale-config bug class fixed in v3.8.1
must be structurally impossible.
"""

import configparser
import os

import pytest

from jen import extensions
from jen.config import app_config, invalid_subnet_name_reason, load_config, write_config_value, write_subnets_config


@pytest.fixture
def isolated_config(tmp_path):
    """Point AppConfig at a throwaway config file, restore afterwards."""
    original_path = extensions.CONFIG_FILE
    cfg = configparser.ConfigParser()
    cfg["kea"] = {"api_url": "http://1.2.3.4:8000", "api_user": "u1", "api_pass": "p1"}
    cfg["kea_db"] = {"host": "dbhost", "user": "du", "password": "dp", "database": "kea"}
    cfg["jen_db"] = {"host": "dbhost", "user": "ju", "password": "jp", "database": "jen"}
    cfg["server"] = {"http_port": "5050", "https_port": "8443"}
    cfg["subnets"] = {"1": "LAN, 192.168.1.0/24"}
    path = tmp_path / "jen.config"
    with open(path, "w") as f:
        cfg.write(f)
    extensions.CONFIG_FILE = str(path)
    app_config.reload()
    yield path
    extensions.CONFIG_FILE = original_path
    # Restore in-memory state for subsequent tests (conftest values)
    from tests.conftest import _patch_extensions

    _patch_extensions()


class TestAppConfig:
    def test_reload_derives_all_globals(self, isolated_config):
        assert extensions.KEA_API_URL == "http://1.2.3.4:8000"
        assert extensions.HTTP_PORT == 5050
        assert extensions.SUBNET_MAP == {1: {"name": "LAN", "cidr": "192.168.1.0/24"}}
        assert len(extensions.KEA_SERVERS) == 1

    def test_write_value_keeps_disk_and_memory_consistent(self, isolated_config):
        app_config.write_value("kea", "api_url", "http://5.6.7.8:8000")
        assert extensions.KEA_API_URL == "http://5.6.7.8:8000"
        assert extensions.KEA_SERVERS[0]["api_url"] == "http://5.6.7.8:8000"
        on_disk = configparser.ConfigParser()
        on_disk.read(str(isolated_config))
        assert on_disk.get("kea", "api_url") == "http://5.6.7.8:8000"

    def test_legacy_write_config_value_wrapper_reloads(self, isolated_config):
        write_config_value("server", "http_port", "6000")
        assert extensions.HTTP_PORT == 6000

    def test_write_subnets_reloads_subnet_map(self, isolated_config):
        write_subnets_config({2: {"name": "IoT", "cidr": "10.0.50.0/24"}})
        assert extensions.SUBNET_MAP == {2: {"name": "IoT", "cidr": "10.0.50.0/24"}}

    def test_write_subnets_refuses_a_name_with_a_comma_and_writes_nothing(self, isolated_config):
        # v5.67.0-beta.5 (Q117, item h) — a comma breaks write_subnets'
        # own "name, cidr" storage format (config.py's parser splits on
        # it), silently dropping the whole entry on the next reload. The
        # choke point refuses it outright instead, and leaves the
        # existing [subnets] section untouched (never a partial write).
        with pytest.raises(ValueError, match="comma"):
            write_subnets_config({2: {"name": "IoT, Lab", "cidr": "10.0.50.0/24"}})
        assert extensions.SUBNET_MAP == {1: {"name": "LAN", "cidr": "192.168.1.0/24"}}

    def test_write_subnets_refuses_an_empty_or_overlong_name(self, isolated_config):
        with pytest.raises(ValueError, match="required"):
            write_subnets_config({2: {"name": "", "cidr": "10.0.50.0/24"}})
        with pytest.raises(ValueError, match="64 characters"):
            write_subnets_config({2: {"name": "x" * 65, "cidr": "10.0.50.0/24"}})

    def _inject_raw_subnets_line(self, path, sid, raw_value):
        """Write a raw `[subnets]` line directly, bypassing write_subnets()
        entirely — simulates a pre-Q117 legacy name (or a comma-corrupted
        one) that could never have been written through the validated API
        in the first place."""
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(path)
        cfg.set("subnets", str(sid), raw_value)
        with open(path, "w") as f:
            cfg.write(f)
        app_config.reload()

    def test_write_subnets_tolerates_an_untouched_legacy_name_with_forbidden_chars(self, isolated_config):
        """v5.67.0-beta.7 (Q119, item g) — a name with '=', '[' or ']' was
        legal before Q117's validator existed and still parses fine
        (only a comma breaks the stored line's own format) — write_subnets()
        used to re-validate it on EVERY later write regardless, raising
        ValueError for a subnet this write never touched at all."""
        self._inject_raw_subnets_line(isolated_config, 1, "Rack[A]=East, 192.168.1.0/24")
        assert extensions.SUBNET_MAP[1]["name"] == "Rack[A]=East"  # confirms it's genuinely legal to derive_subnet_map

        new_map = dict(extensions.SUBNET_MAP)
        new_map[2] = {"name": "IoT", "cidr": "10.0.50.0/24"}
        write_subnets_config(new_map)  # must not raise

        assert extensions.SUBNET_MAP[1]["name"] == "Rack[A]=East"  # written back exactly as it was
        assert extensions.SUBNET_MAP[2]["name"] == "IoT"

    def test_write_subnets_still_refuses_a_legacy_name_that_is_actively_changed(self, isolated_config):
        """The tolerance is for an UNTOUCHED name only — renaming a legacy
        bad name to another bad one is a new write of that name and goes
        through the real validator, same as any other change."""
        self._inject_raw_subnets_line(isolated_config, 1, "Rack[A]=East, 192.168.1.0/24")
        new_map = dict(extensions.SUBNET_MAP)
        new_map[1] = {"name": new_map[1]["name"] + "=West", "cidr": new_map[1]["cidr"]}
        with pytest.raises(ValueError, match=r"\["):
            write_subnets_config(new_map)

    def test_write_subnets_repairs_and_restores_a_comma_corrupted_orphan(self, isolated_config):
        """v5.67.0-beta.7 (Q119, item g) — a name with a comma breaks
        derive_subnet_map()'s own "name, cidr" split (treated as
        malformed, silently dropped) — meaning it's invisible to
        SUBNET_MAP and would otherwise vanish outright (not just stay
        unchanged) the next time ANY unrelated write rebuilds the
        section from subnet_dict, which never heard of it. Recovered
        instead: comma replaced with a space, restored, visible again."""
        self._inject_raw_subnets_line(isolated_config, 9, "Office, Building A, 10.9.0.0/24")
        assert 9 not in extensions.SUBNET_MAP  # confirms it's genuinely invisible before the fix applies

        new_map = dict(extensions.SUBNET_MAP)
        new_map[2] = {"name": "IoT", "cidr": "10.0.50.0/24"}
        write_subnets_config(new_map)  # must not raise, and must not silently drop subnet 9

        assert extensions.SUBNET_MAP[9] == {"name": "Office  Building A", "cidr": "10.9.0.0/24"}
        assert extensions.SUBNET_MAP[2]["name"] == "IoT"
        assert extensions.SUBNET_MAP[1]["name"] == "LAN"  # the original untouched entry still survives too

    def test_mutate_rederives_kea_servers(self, isolated_config):
        def add_server(p):
            p.add_section("kea_server_2")
            p.set("kea_server_2", "api_url", "http://9.9.9.9:8000")
            p.set("kea_server_2", "name", "Standby")

        app_config.mutate(add_server)
        assert len(extensions.KEA_SERVERS) == 2
        assert extensions.KEA_SERVERS[1]["name"] == "Standby"
        # credentials fall back to primary values from the parser, not globals
        assert extensions.KEA_SERVERS[1]["api_user"] == "u1"

    def test_extensions_cfg_tracks_disk_after_mutation(self, isolated_config):
        def add_then_check(p):
            p.add_section("kea_server_2")
            p.set("kea_server_2", "api_url", "http://9.9.9.9:8000")

        app_config.mutate(add_then_check)
        app_config.mutate(lambda p: p.remove_section("kea_server_2"))
        assert len(extensions.KEA_SERVERS) == 1
        assert not extensions.cfg.has_section("kea_server_2")

    def test_write_values_batch(self, isolated_config):
        app_config.write_values([("kea_db", "host", "newhost"), ("jen_db", "host", "newhost")])
        assert extensions.KEA_DB_HOST == "newhost"
        assert extensions.JEN_DB_HOST == "newhost"

    def test_legacy_load_config_wrapper(self, isolated_config):
        app_config.write_value("kea_db", "host", "newhost")
        c = load_config()
        assert c.get("kea_db", "host") == "newhost"

    def test_load_raises_on_missing_file(self, isolated_config):
        extensions.CONFIG_FILE = "/nonexistent/jen.config"
        with pytest.raises(FileNotFoundError):
            app_config.load()

    def test_load_raises_on_missing_required(self, isolated_config, tmp_path):
        bad = tmp_path / "bad.config"
        bad.write_text("[kea]\napi_url = http://x\n")
        extensions.CONFIG_FILE = str(bad)
        with pytest.raises(ValueError):
            app_config.load()


class TestInvalidSubnetNameReason:
    """v5.67.0-beta.5 (Q117, item h) — the choke point's own validation,
    tested directly and purely (no config file needed): write_subnets()/
    write_subnets6() call this for every name before writing anything."""

    def test_a_normal_name_is_fine(self):
        assert invalid_subnet_name_reason("Office LAN") is None

    def test_empty_is_refused(self):
        assert invalid_subnet_name_reason("") == "Name is required"

    def test_over_64_chars_is_refused(self):
        assert invalid_subnet_name_reason("x" * 65) is not None
        assert invalid_subnet_name_reason("x" * 64) is None

    @pytest.mark.parametrize("bad_char", [",", "=", "[", "]"])
    def test_forbidden_storage_format_characters_are_refused(self, bad_char):
        assert invalid_subnet_name_reason(f"Office{bad_char}LAN") is not None

    def test_a_control_character_is_refused(self):
        assert invalid_subnet_name_reason("Office\nLAN") is not None
        assert invalid_subnet_name_reason("Office\tLAN") is not None


class TestTrustedProxies:
    """v5.17.0 (Q6 6D) — [server] trusted_proxies parsing."""

    def test_default_is_empty(self, isolated_config):
        assert extensions.TRUSTED_PROXIES == []

    def test_ips_and_cidrs_parse(self, isolated_config):
        import ipaddress

        app_config.write_value("server", "trusted_proxies", "127.0.0.1, 10.0.0.0/8 , ::1")
        nets = extensions.TRUSTED_PROXIES
        assert ipaddress.ip_address("10.9.9.9") in nets[1]
        assert ipaddress.ip_address("127.0.0.1") in nets[0]
        assert len(nets) == 3  # bare host became /32

    def test_a_bad_entry_is_skipped_not_fatal(self, isolated_config):
        from jen.config import _parse_trusted_proxies

        nets = _parse_trusted_proxies("10.0.0.0/8, not-an-ip, 192.168.0.0/16")
        assert len(nets) == 2


class TestKea3ConnectionMode:
    """v5.10.0 — [kea] connection_mode + api_ca / api_tls_verify, and
    the api6_url the server dicts carry for direct mode. connection_mode
    is optional: absent → 'ca' → every prior release's behavior."""

    def test_defaults_when_key_absent(self, isolated_config):
        assert extensions.KEA_CONNECTION_MODE == "ca"
        assert extensions.KEA_API_CA == ""
        assert extensions.KEA_API_TLS_VERIFY is True
        assert extensions.KEA_API_CLIENT_CERT == ""
        assert extensions.KEA_API_CLIENT_KEY == ""
        assert extensions.KEA_SERVERS[0]["api6_url"] == ""

    def test_direct_mode_and_tls_options_round_trip(self, isolated_config):
        app_config.write_values(
            [
                ("kea", "connection_mode", "direct"),
                ("kea", "api_ca", "/etc/jen/ssl/kea-ca.pem"),
                ("kea", "api_tls_verify", "false"),
                ("kea", "api_client_cert", "/etc/jen/ssl/client.pem"),
                ("kea", "api_client_key", "/etc/jen/ssl/client.key"),
            ]
        )
        assert extensions.KEA_CONNECTION_MODE == "direct"
        assert extensions.KEA_API_CA == "/etc/jen/ssl/kea-ca.pem"
        assert extensions.KEA_API_TLS_VERIFY is False
        assert extensions.KEA_API_CLIENT_CERT == "/etc/jen/ssl/client.pem"
        assert extensions.KEA_API_CLIENT_KEY == "/etc/jen/ssl/client.key"

    def test_derive_kea_servers_carries_api6_url_from_kea6_section(self, isolated_config):
        app_config.mutate(lambda p: (p.add_section("kea6"), p.set("kea6", "api_url", "http://kea6:8006")))
        assert extensions.KEA_SERVERS[0]["api6_url"] == "http://kea6:8006"

    def test_extra_server_api6_url_is_its_own_key(self, isolated_config):
        def add(p):
            p.add_section("kea_server_2")
            p.set("kea_server_2", "api_url", "http://s2:8000")
            p.set("kea_server_2", "api6_url", "http://s2:8006")

        app_config.mutate(add)
        assert extensions.KEA_SERVERS[1]["api6_url"] == "http://s2:8006"


class TestD2Config:
    """v5.23.0 (Q19) — [d2] api_url/api_user/api_pass (primary only, same
    ca-mode fallback shape as [kea6]) and per-server api_d2_* fields."""

    def test_defaults_when_section_absent(self, isolated_config):
        assert extensions.D2_API_URL == extensions.KEA_API_URL  # ca-mode fallback
        assert extensions.D2_API_USER == extensions.KEA_API_USER
        assert extensions.D2_API_PASS == extensions.KEA_API_PASS
        assert extensions.KEA_SERVERS[0]["api_d2_url"] == ""

    def test_d2_section_overrides_the_global(self, isolated_config):
        app_config.write_values(
            [
                ("d2", "api_url", "http://d2:53001"),
                ("d2", "api_user", "d2user"),
                ("d2", "api_pass", "d2pass"),
            ]
        )
        assert extensions.D2_API_URL == "http://d2:53001"
        assert extensions.D2_API_USER == "d2user"
        assert extensions.D2_API_PASS == "d2pass"
        # the primary server dict carries the RAW value, not the fallback —
        # jen.services.kea._endpoint_for's own `or` chain does the rest.
        assert extensions.KEA_SERVERS[0]["api_d2_url"] == "http://d2:53001"

    def test_no_fallback_to_kea_api_url_in_direct_mode(self, isolated_config):
        app_config.write_value("kea", "connection_mode", "direct")
        assert extensions.D2_API_URL == ""

    def test_extra_server_api_d2_url_is_its_own_key(self, isolated_config):
        def add(p):
            p.add_section("kea_server_2")
            p.set("kea_server_2", "api_url", "http://s2:8000")
            p.set("kea_server_2", "api_d2_url", "http://s2-d2:53001")

        app_config.mutate(add)
        assert extensions.KEA_SERVERS[1]["api_d2_url"] == "http://s2-d2:53001"


class TestAtomicWrite:
    """v5.10.4 — _write_parser() writes a sibling temp file and
    os.replace()s it into place: an interrupted write can't truncate
    jen.config, and a save only needs write access to /etc/jen (not the
    file), so a box whose jen.config was left root-owned by an older
    installer self-heals on its first Settings save."""

    def test_write_goes_through_a_tmp_file_and_os_replace(self, isolated_config, monkeypatch):
        calls = []
        real_replace = os.replace

        def spy_replace(src, dst):
            calls.append((str(src), str(dst)))
            return real_replace(src, dst)

        monkeypatch.setattr(os, "replace", spy_replace)
        app_config.write_value("kea", "api_url", "http://tmp.test:8000")

        assert calls, "write_value() did not go through os.replace()"
        src, dst = calls[-1]
        # v5.68.0-beta.15 (Q150): a UNIQUE temp name (`.jen.config.<random>.tmp`), O_EXCL 0600, in the target's own directory
        assert os.path.dirname(src) == os.path.dirname(dst)
        assert os.path.basename(src).startswith(".jen.config.") and src.endswith(".tmp")
        assert dst == str(isolated_config)
        assert not os.path.exists(src), "the .tmp file was left behind"
        assert extensions.KEA_API_URL == "http://tmp.test:8000"

    @pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX file-permission semantics only")
    def test_write_survives_a_read_only_config_file_in_a_writable_dir(self, isolated_config):
        if os.geteuid() == 0:
            pytest.skip("root bypasses the file mode bits this test relies on")

        os.chmod(str(isolated_config), 0o444)
        app_config.write_value("kea", "api_pass", "rotated-secret")

        assert extensions.KEA_API_PASS == "rotated-secret"
        mode = os.stat(str(isolated_config)).st_mode & 0o777
        assert mode == 0o600, oct(mode)


class TestWritersAreSerialized:
    """v5.68.0-beta.17 (Q152) - every writer is read-modify-write, and the app serves from threads: without ONE lock held from the read to
    the replace, two saves at once lose one of them (the second read misses the first write)."""

    ROUNDS = 200

    @staticmethod
    def _hammer(writers):
        import threading

        errors = []

        def run(fn):
            try:
                fn()
            except Exception as e:  # pragma: no cover - reported through the assertion below
                errors.append(e)

        threads = [threading.Thread(target=run, args=(w,)) for w in writers]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        assert not errors, errors

    def _writers(self):
        def a():
            for i in range(self.ROUNDS):
                app_config.write_value("race", f"a{i}", str(i), reload=False)

        def b():
            for i in range(self.ROUNDS):
                app_config.write_values([("race", f"b{i}", str(i))], reload=False)

        return a, b

    def _present(self, path):
        on_disk = configparser.ConfigParser(interpolation=None)
        on_disk.read(str(path))
        return set(on_disk["race"]) if on_disk.has_section("race") else set()

    def test_two_threads_writing_different_keys_lose_nothing(self, isolated_config):
        self._hammer(self._writers())
        expected = {f"a{i}" for i in range(self.ROUNDS)} | {f"b{i}" for i in range(self.ROUNDS)}
        assert self._present(isolated_config) == expected

    def test_the_test_has_power_without_the_lock_updates_are_lost(self, isolated_config, monkeypatch):
        """The same run with the lock replaced by a no-op loses writes, so a green result above is the lock's doing."""
        import contextlib

        from jen.config import AppConfig

        class NoLock:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        import jen.config as config_module

        monkeypatch.setattr(AppConfig, "_write_lock", NoLock())
        monkeypatch.setattr(
            config_module, "identity_lock", NoLock()
        )  # v5.68.0-beta.28 (Q164): every writer takes this one FIRST - it serialises threads too
        monkeypatch.setattr(
            config_module, "fcntl", None
        )  # v5.68.0-beta.18: the file lock serialises threads too; remove both
        real_write = AppConfig._write_parser

        def slow_write(self, parser):
            import time

            time.sleep(0.001)  # widen the read-modify-write window so the race is certain, not likely
            real_write(self, parser)

        monkeypatch.setattr(AppConfig, "_write_parser", slow_write)
        with contextlib.suppress(Exception):
            self._hammer(self._writers())
        expected = {f"a{i}" for i in range(self.ROUNDS)} | {f"b{i}" for i in range(self.ROUNDS)}
        assert self._present(isolated_config) != expected, (
            "no update was lost even without the lock - the test proves nothing"
        )

    def test_subnet_writers_and_value_writers_share_the_lock(self, isolated_config):
        def subnets():
            for _ in range(40):
                app_config.write_subnets({1: {"name": "LAN", "cidr": "192.168.1.0/24"}}, reload=False)

        def values():
            for i in range(self.ROUNDS):
                app_config.write_value("race", f"v{i}", str(i), reload=False)

        self._hammer([subnets, values])
        assert self._present(isolated_config) == {f"v{i}" for i in range(self.ROUNDS)}

    def test_a_writer_called_from_inside_mutate_raises_and_writes_nothing(self, isolated_config):
        """v5.68.0-beta.18 (Q153): `mutate` writes the parser it handed to its callback when the callback returns, so a nested writer would
        write to disk and be silently overwritten by the outer write of the parser read before. It is refused instead (it used to be
        'allowed' and discard its change - tests/test_appconfig.py codified 'the outer write then wins')."""
        import pytest

        for nested in (
            lambda: app_config.write_value("race", "inner", "1", reload=False),
            lambda: app_config.write_values([("race", "inner", "1")], reload=False),
            lambda: app_config.mutate(lambda p: None, reload=False),
        ):
            with pytest.raises(RuntimeError, match="mutate the parser you were given"):
                app_config.mutate(lambda p, nested=nested: nested(), reload=False)
        assert "inner" not in self._present(isolated_config)

    def test_the_callback_still_edits_the_parser_it_was_given(self, isolated_config):
        app_config.mutate(lambda p: (p.add_section("race"), p.set("race", "viaparser", "1")), reload=False)
        assert "viaparser" in self._present(isolated_config)

    def test_a_failed_callback_does_not_leave_the_guard_on(self, isolated_config):
        import pytest

        def boom(p):
            raise ValueError("callback failed")

        with pytest.raises(ValueError):
            app_config.mutate(boom, reload=False)
        app_config.write_value("race", "after", "1", reload=False)  # an ordinary writer works again
        assert "after" in self._present(isolated_config)
