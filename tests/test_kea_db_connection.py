"""
tests/test_kea_db_connection.py
────────────────────────────────
v5.67.0-beta.8 (Q120, item g) — the Kea database connection honours what the
operator typed: `[kea_db] port`, `[kea_db] ssl_ca`, and a pool that is torn
down when the settings change.

Before this, `[kea_db]` had no port at all (the pool dialled 3306 whatever was
typed into the setup wizard's test), the wizard's test ignored `ssl_ca`, and
`models/db.py::reset_pools()` had no caller — a pool built while the config
still held placeholders kept dialling them until a restart.

The port is proved against a REAL listening socket on an ephemeral port
(CLAUDE.md: probe behaviour is tested against real local servers, not a mock
of the call) — a connection that arrives there came from the real pool code.
"""

import configparser
import socket
import threading

import pymysql
import pytest

from jen import extensions
from jen.models import db as dbmod
from jen.services import dbexport

# what a dial that reaches a socket that does not speak MySQL raises
_DIAL_FAILS = (pymysql.err.MySQLError, OSError)


class _Listener:
    """A TCP listener that accepts and immediately closes — enough to see that a dial arrived on
    THIS port (pymysql then fails its handshake, which is the point: the test is about where the
    dial went, not about speaking MySQL)."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.accepted = 0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self.sock.accept()
            except OSError:
                continue
            self.accepted += 1
            client.close()

    def close(self):
        self._stop.set()
        self.sock.close()


@pytest.fixture
def listener():
    lst = _Listener()
    yield lst
    lst.close()


@pytest.fixture
def isolated_kea_pool(monkeypatch):
    """No pool state leaks in or out of the test."""
    monkeypatch.setattr(dbmod, "_kea_pool", None)
    monkeypatch.setattr(dbmod, "_kea6_pool", None)
    yield
    # monkeypatch restores the module globals


class TestDbPortConfig:
    def _cfg(self, **sections):
        cfg = configparser.ConfigParser()
        for name, values in sections.items():
            cfg.add_section(name)
            for k, v in values.items():
                cfg.set(name, k, v)
        return cfg

    def test_absent_is_the_default(self):
        from jen.config import _db_port

        assert _db_port(self._cfg(kea_db={"host": "h"}), "kea_db", 3306) == 3306
        assert _db_port(self._cfg(), "kea6_db", 3306) == 3306  # a missing section is fine too

    def test_a_valid_port_is_used(self):
        from jen.config import _db_port

        assert _db_port(self._cfg(kea_db={"port": "3307"}), "kea_db", 3306) == 3307

    @pytest.mark.parametrize("bad", ["abc", "0", "-1", "65536", "33 06"])
    def test_a_bad_port_is_ignored_not_raised(self, bad):
        from jen.config import _db_port

        assert _db_port(self._cfg(kea_db={"port": bad}), "kea_db", 3306) == 3306

    def test_kea6_inherits_the_kea_port_unless_it_sets_its_own(self, tmp_path, monkeypatch):
        from jen.config import _db_port

        cfg = self._cfg(kea_db={"port": "3307"}, kea6_db={})
        assert _db_port(cfg, "kea6_db", _db_port(cfg, "kea_db", 3306)) == 3307
        cfg.set("kea6_db", "port", "3310")
        assert _db_port(cfg, "kea6_db", 3307) == 3310


class TestPoolDialsTheConfiguredPort:
    def test_the_kea_pool_dials_the_typed_port(self, listener, monkeypatch, isolated_kea_pool):
        monkeypatch.setattr(extensions, "KEA_DB_HOST", "127.0.0.1")
        monkeypatch.setattr(extensions, "KEA_DB_PORT", listener.port)
        monkeypatch.setattr(extensions, "KEA_DB_USER", "u")
        monkeypatch.setattr(extensions, "KEA_DB_PASS", "p")
        monkeypatch.setattr(extensions, "KEA_DB_NAME", "kea")
        monkeypatch.setattr(extensions, "KEA_DB_SSL_CA", "")
        with pytest.raises(_DIAL_FAILS):  # the listener never speaks MySQL
            dbmod.get_kea_db()
        assert listener.accepted >= 1, "the pool never dialled the configured port"

    def test_the_kea6_pool_dials_its_own_port(self, listener, monkeypatch, isolated_kea_pool):
        monkeypatch.setattr(extensions, "KEA_DB_HOST", "127.0.0.1")
        monkeypatch.setattr(extensions, "KEA_DB_PORT", 1)  # a port nothing answers on
        monkeypatch.setattr(extensions, "KEA6_DB_HOST", "127.0.0.1")
        monkeypatch.setattr(extensions, "KEA6_DB_PORT", listener.port)
        for name in ("USER", "PASS"):
            monkeypatch.setattr(extensions, f"KEA_DB_{name}", "x")
            monkeypatch.setattr(extensions, f"KEA6_DB_{name}", "x")
        monkeypatch.setattr(extensions, "KEA_DB_NAME", "kea")
        monkeypatch.setattr(extensions, "KEA6_DB_NAME", "kea")
        monkeypatch.setattr(extensions, "KEA6_DB_SSL_CA", "")
        assert dbmod._kea6_targets_same_db() is False, "a different port is a different database"
        with pytest.raises(_DIAL_FAILS):
            dbmod.get_kea6_db()
        assert listener.accepted >= 1

    def test_v6_shares_the_v4_pool_only_when_the_port_matches_too(self, monkeypatch):
        for name in ("HOST", "USER", "PASS", "NAME"):
            monkeypatch.setattr(extensions, f"KEA_DB_{name}", "same")
            monkeypatch.setattr(extensions, f"KEA6_DB_{name}", "same")
        monkeypatch.setattr(extensions, "KEA_DB_PORT", 3306)
        monkeypatch.setattr(extensions, "KEA6_DB_PORT", 3306)
        assert dbmod._kea6_targets_same_db() is True
        monkeypatch.setattr(extensions, "KEA6_DB_PORT", 3307)
        assert dbmod._kea6_targets_same_db() is False

    def test_the_export_path_dials_the_same_port(self, listener, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_DB_HOST", "127.0.0.1")
        monkeypatch.setattr(extensions, "KEA_DB_PORT", listener.port)
        monkeypatch.setattr(extensions, "KEA_DB_SSL_CA", "")
        with pytest.raises(_DIAL_FAILS):
            dbexport._direct_kea_conn()
        assert listener.accepted >= 1


class TestConnectionTestUsesTheSameTlsAsThePool:
    def test_a_missing_ca_file_fails_the_test_instead_of_being_ignored(self, listener):
        ok, info = dbexport.test_connection(
            "127.0.0.1", listener.port, "u", "p", "kea", ssl_ca="/nonexistent/kea-db-ca.pem"
        )
        assert ok is False
        assert "kea-db-ca.pem" in info or "No such file" in info or "nonexistent" in info
        assert listener.accepted == 0, "the CA is loaded before anything is dialled"

    def test_without_a_ca_the_test_still_dials_the_given_port(self, listener):
        ok, _info = dbexport.test_connection("127.0.0.1", listener.port, "u", "p", "kea")
        assert ok is False  # the listener does not speak MySQL
        assert listener.accepted >= 1

    def test_the_migration_helpers_pass_no_ssl_by_default(self, monkeypatch):
        """Every migration target keeps the plaintext behaviour it always had."""
        seen = {}

        def fake_connect(**kw):
            seen.update(kw)
            raise RuntimeError("stop")

        monkeypatch.setattr(dbexport.pymysql, "connect", fake_connect)
        dbexport.test_connection("h", 3306, "u", "p", "d")
        assert "ssl" not in seen
        dbexport.test_connection("h", 3306, "u", "p", "d", ssl_ca="/some/ca.pem")
        assert seen["ssl"] == {"ca": "/some/ca.pem"}


class TestResetKeaPools:
    class _Pool:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    def test_resets_the_kea_pools_and_leaves_jens_own(self, monkeypatch):
        kea, kea6, jen = self._Pool(), self._Pool(), self._Pool()
        monkeypatch.setattr(dbmod, "_kea_pool", kea)
        monkeypatch.setattr(dbmod, "_kea6_pool", kea6)
        monkeypatch.setattr(dbmod, "_jen_pool", jen)
        dbmod.reset_kea_pools()
        assert dbmod._kea_pool is None and dbmod._kea6_pool is None
        assert kea.closed and kea6.closed
        assert dbmod._jen_pool is jen and not jen.closed

    def test_reset_pools_still_resets_all_three(self, monkeypatch):
        kea, kea6, jen = self._Pool(), self._Pool(), self._Pool()
        monkeypatch.setattr(dbmod, "_kea_pool", kea)
        monkeypatch.setattr(dbmod, "_kea6_pool", kea6)
        monkeypatch.setattr(dbmod, "_jen_pool", jen)
        dbmod.reset_pools()
        assert dbmod._jen_pool is None and dbmod._kea_pool is None and dbmod._kea6_pool is None
        assert jen.closed and kea.closed and kea6.closed

    def test_a_pool_whose_close_raises_is_still_forgotten(self, monkeypatch):
        class Bad:
            _idle_cache = []

            def close(self):
                raise RuntimeError("already closed")

        monkeypatch.setattr(dbmod, "_kea_pool", Bad())
        monkeypatch.setattr(dbmod, "_kea6_pool", None)
        dbmod.reset_kea_pools()
        assert dbmod._kea_pool is None

    def test_the_next_connection_uses_the_new_settings(self, listener, monkeypatch):
        """The failure this fixes: a pool built while the config held placeholders kept dialling them."""
        monkeypatch.setattr(dbmod, "_kea_pool", self._Pool())  # the stale pool, built against old settings
        monkeypatch.setattr(extensions, "KEA_DB_HOST", "127.0.0.1")
        monkeypatch.setattr(extensions, "KEA_DB_PORT", listener.port)
        monkeypatch.setattr(extensions, "KEA_DB_SSL_CA", "")
        dbmod.reset_kea_pools()
        with pytest.raises(_DIAL_FAILS):
            dbmod.get_kea_db()
        assert listener.accepted >= 1
        monkeypatch.setattr(dbmod, "_kea_pool", None)
