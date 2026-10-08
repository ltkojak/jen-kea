"""
tests/test_db_outage.py
───────────────────────
v5.68.0-beta.21 (Q156, item 8) - a Jen-database outage used to cost every settings read up to 20 seconds. A failed reload of the settings cache left its
timestamp alone, so the very next call reloaded again; `_jen_pool` stayed None after a failed creation, so every call re-attempted `_make_jen_pool()`
(connect timeout 10 s) and then a direct connect (10 s). Callers: `check_session_timeout` on every request, and about four reads per subnet per pass of
the alert loop - with kea_db up and jen_db down a pass took minutes and the 5-second kea_down cadence was lost.

No database: the connection is a stand-in that takes a fixed time to fail. `pytest --noconftest tests/test_db_outage.py`.
"""

import contextlib
import time

import pymysql
import pytest

from jen.models import db as dbmod
from jen.models import user as usermod

FAIL_AFTER_S = 0.15  # stands for the 10 s connect timeout


@pytest.fixture
def clean_settings_cache(monkeypatch):
    monkeypatch.setattr(usermod, "_settings_cache", {})
    monkeypatch.setattr(usermod, "_settings_cache_ts", 0)
    monkeypatch.setattr(usermod, "_settings_next_try", 0)


@pytest.fixture
def down(monkeypatch):
    """jen_db() that refuses after FAIL_AFTER_S, counting its attempts."""
    attempts = []

    @contextlib.contextmanager
    def jen_db():
        attempts.append(time.monotonic())
        time.sleep(FAIL_AFTER_S)
        raise pymysql.err.OperationalError(2003, "Can't connect to MySQL server")
        yield  # pragma: no cover

    monkeypatch.setattr(dbmod, "jen_db", jen_db)
    return attempts


class TestTheSettingsCacheUnderAnOutage:
    def test_fifty_reads_after_the_first_complete_in_under_a_second_and_cost_one_attempt(
        self, clean_settings_cache, down
    ):
        assert usermod.get_global_setting("some_key", "dflt") == "dflt"
        started = time.monotonic()
        for _ in range(49):
            assert usermod.get_global_setting("some_key", "dflt") == "dflt"
        assert time.monotonic() - started < 1.0, "every read paid for a reload again"
        assert len(down) == 1

    def test_a_failed_reload_is_retried_after_the_retry_window_not_before(
        self, clean_settings_cache, down, monkeypatch
    ):
        clock = {"now": 5000.0}
        monkeypatch.setattr(time, "time", lambda: clock["now"])
        usermod.get_global_setting("k", None)
        clock["now"] += usermod._SETTINGS_RETRY_S - 0.1
        usermod.get_global_setting("k", None)
        assert len(down) == 1
        clock["now"] += 0.2
        usermod.get_global_setting("k", None)
        assert len(down) == 2

    def test_the_last_good_values_keep_being_served_while_the_database_is_down(self, down, monkeypatch):
        monkeypatch.setattr(usermod, "_settings_cache", {"daily_summary_time": "06:30"})
        monkeypatch.setattr(usermod, "_settings_cache_ts", 1)  # long expired
        monkeypatch.setattr(usermod, "_settings_next_try", 0)
        assert usermod.get_global_setting("daily_summary_time", "07:00") == "06:30", (
            "the stale cache is served, not the default"
        )
        assert usermod.get_global_setting("daily_summary_time", "07:00") == "06:30"
        assert len(down) == 1

    def test_a_key_that_was_never_read_gets_its_default(self, clean_settings_cache, down):
        assert usermod.get_global_setting("never_stored", "dflt") == "dflt"

    def test_a_recovered_database_is_picked_up_after_the_window(self, clean_settings_cache, monkeypatch):
        clock = {"now": 9000.0}
        monkeypatch.setattr(time, "time", lambda: clock["now"])
        state = {"up": False}

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, args=None):
                pass

            def fetchall(self):
                return [{"setting_key": "k", "setting_value": "v"}]

        class Conn:
            def cursor(self):
                return Cur()

            def commit(self):
                pass

            def close(self):
                pass

        @contextlib.contextmanager
        def jen_db():
            if not state["up"]:
                raise pymysql.err.OperationalError(2003, "down")
            yield Conn()

        monkeypatch.setattr(dbmod, "jen_db", jen_db)
        assert usermod.get_global_setting("k", "dflt") == "dflt"
        state["up"] = True
        assert usermod.get_global_setting("k", "dflt") == "dflt", "inside the retry window: still no new attempt"
        clock["now"] += usermod._SETTINGS_RETRY_S + 0.1
        assert usermod.get_global_setting("k", "dflt") == "v"

    def test_saving_a_setting_clears_the_retry_hold(self, clean_settings_cache, monkeypatch):
        monkeypatch.setattr(usermod, "_settings_next_try", time.time() + 100)
        usermod._invalidate_settings_cache()
        assert usermod._settings_next_try == 0


class TestPoolCreationIsThrottled:
    @pytest.fixture
    def broken_pools(self, monkeypatch):
        monkeypatch.setattr(dbmod, "_jen_pool", None)
        monkeypatch.setattr(dbmod, "_kea_pool", None)
        monkeypatch.setattr(dbmod, "_pool_failed_at", {})
        made, connects = [], []

        def make():
            made.append(time.monotonic())
            raise pymysql.err.OperationalError(2003, "pool: can't connect")

        def connect(**kw):
            connects.append(kw.get("host"))
            raise pymysql.err.OperationalError(2003, "direct: can't connect")

        monkeypatch.setattr(dbmod, "_make_jen_pool", make)
        monkeypatch.setattr(dbmod, "_make_kea_pool", make)
        monkeypatch.setattr(dbmod.pymysql, "connect", connect)
        return made, connects

    def test_twenty_calls_make_the_pool_once_and_dial_directly_each_time(self, broken_pools):
        made, connects = broken_pools
        for _ in range(20):
            with pytest.raises(pymysql.err.OperationalError, match="direct"):
                dbmod.get_jen_db()
        assert len(made) == 1, "the pool (mincached connections, 10 s timeout) was re-attempted on every call"
        assert len(connects) == 20, "each call still tries its own direct connection, once"

    def test_the_pool_is_attempted_again_after_the_window(self, broken_pools, monkeypatch):
        made, _connects = broken_pools
        clock = {"now": 100.0}
        monkeypatch.setattr(dbmod.time, "monotonic", lambda: clock["now"])
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_jen_db()
        clock["now"] += dbmod._POOL_RETRY_S - 0.1
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_jen_db()
        assert len(made) == 1
        clock["now"] += 0.2
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_jen_db()
        assert len(made) == 2

    def test_the_kea_pool_is_throttled_the_same_way_and_independently(self, broken_pools):
        made, _connects = broken_pools
        for _ in range(5):
            with pytest.raises(pymysql.err.OperationalError):
                dbmod.get_kea_db()
        assert len(made) == 1
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_jen_db()
        assert len(made) == 2, "a failed Kea pool does not hold back the Jen pool"

    def test_a_successful_creation_clears_the_failure(self, monkeypatch):
        monkeypatch.setattr(dbmod, "_jen_pool", None)
        monkeypatch.setattr(dbmod, "_pool_failed_at", {"jen": time.monotonic() - 100})

        class Pool:
            def connection(self):
                return "a pooled connection"

        monkeypatch.setattr(dbmod, "_make_jen_pool", lambda: Pool())
        assert dbmod.get_jen_db() == "a pooled connection"
        assert "jen" not in dbmod._pool_failed_at

    def test_resetting_the_pools_after_a_settings_change_dials_at_once(self, broken_pools):
        made, _connects = broken_pools
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_jen_db()
        dbmod.reset_pools()
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_jen_db()
        assert len(made) == 2, "new credentials must not wait out the retry window"

    def test_the_direct_connect_runs_outside_the_pool_lock(self, broken_pools, monkeypatch):
        """A direct connect that hangs must not queue every other caller behind it."""
        import threading

        held = []

        def connect(**kw):
            held.append(dbmod._pool_lock.locked())
            raise pymysql.err.OperationalError(2003, "x")

        monkeypatch.setattr(dbmod.pymysql, "connect", connect)
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_jen_db()
        assert held == [False]
        assert isinstance(dbmod._pool_lock, type(threading.Lock()))
