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
    monkeypatch.setattr(usermod, "_settings_next_try_mono", 0)


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
        monkeypatch.setattr(time, "monotonic", lambda: clock["now"])
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
        monkeypatch.setattr(usermod, "_settings_next_try_mono", 0)
        assert usermod.get_global_setting("daily_summary_time", "07:00") == "06:30", (
            "the stale cache is served, not the default"
        )
        assert usermod.get_global_setting("daily_summary_time", "07:00") == "06:30"
        assert len(down) == 1

    def test_a_key_that_was_never_read_gets_its_default(self, clean_settings_cache, down):
        assert usermod.get_global_setting("never_stored", "dflt") == "dflt"

    def test_a_recovered_database_is_picked_up_after_the_window(self, clean_settings_cache, monkeypatch):
        clock = {"now": 9000.0}
        monkeypatch.setattr(time, "monotonic", lambda: clock["now"])
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
        monkeypatch.setattr(usermod, "_settings_next_try_mono", time.monotonic() + 100)
        usermod._invalidate_settings_cache()
        assert usermod._settings_next_try_mono == 0


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


class TestTheReloadIsSingleFlight:
    """v5.68.0-beta.22 (Q157, item 3): `_settings_next_try` moved only after a reload FAILED, so N threads that saw an expired cache all reloaded - with
    the database down and `check_session_timeout` on every request, a burst of requests was a burst of 10 s connects."""

    THREADS = 50

    @staticmethod
    def _run(threads, key="some_key", default="dflt"):
        import threading

        results, errors = [], []
        barrier = threading.Barrier(threads)

        def go():
            try:
                barrier.wait(10)
                started = time.monotonic()
                results.append((usermod.get_global_setting(key, default), time.monotonic() - started))
            except Exception as e:  # pragma: no cover
                errors.append(e)

        pool = [threading.Thread(target=go) for _ in range(threads)]
        for th in pool:
            th.start()
        for th in pool:
            th.join(30)
        assert not errors, errors
        return results

    def test_fifty_threads_during_an_outage_make_one_connect_attempt_and_all_return_within_its_time(
        self, monkeypatch, down
    ):
        monkeypatch.setattr(usermod, "_settings_cache", {"some_key": "stale-but-served"})
        monkeypatch.setattr(usermod, "_settings_cache_ts", 1)  # long expired
        monkeypatch.setattr(usermod, "_settings_next_try_mono", 0)
        monkeypatch.setattr(usermod, "_settings_ever_loaded", True)
        started = time.monotonic()
        results = self._run(self.THREADS)
        elapsed = time.monotonic() - started
        assert len(down) == 1, f"{len(down)} threads opened a connection: the retry is not single-flight"
        assert len(results) == self.THREADS and {value for value, _t in results} == {"stale-but-served"}
        assert elapsed < FAIL_AFTER_S * 3 + 1.0
        waited = sorted(t for _v, t in results)
        assert waited[-2] < FAIL_AFTER_S, "everyone but the holder returned the stale cache at once"

    def test_a_first_ever_load_during_an_outage_is_one_attempt_too_and_everyone_gets_the_default(
        self, clean_settings_cache, down, monkeypatch
    ):
        monkeypatch.setattr(usermod, "_settings_ever_loaded", False)
        results = self._run(self.THREADS)
        assert len(down) == 1
        assert {value for value, _t in results} == {"dflt"}
        assert max(t for _v, t in results) < FAIL_AFTER_S * 3 + 1.0

    def test_a_successful_refresh_updates_everyone(self, clean_settings_cache, monkeypatch):
        loads = []

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, args=None):
                loads.append(1)
                time.sleep(0.05)

            def fetchall(self):
                return [{"setting_key": "some_key", "setting_value": "fresh"}]

        class Conn:
            def cursor(self):
                return Cur()

            def commit(self):
                pass

            def close(self):
                pass

        @contextlib.contextmanager
        def jen_db():
            yield Conn()

        monkeypatch.setattr(dbmod, "jen_db", jen_db)
        monkeypatch.setattr(usermod, "_settings_ever_loaded", False)
        results = self._run(self.THREADS)
        assert loads == [1], "one reload for fifty readers"
        assert {value for value, _t in results} == {"fresh"}, "a first load is waited for, not answered with a default"
        assert usermod.settings_ever_loaded() is True

    def test_a_save_invalidates_and_allows_a_fresh_reload(self, monkeypatch):
        monkeypatch.setattr(usermod, "_settings_cache", {"k": "old"})
        monkeypatch.setattr(usermod, "_settings_cache_ts", time.time())
        monkeypatch.setattr(usermod, "_settings_next_try_mono", time.monotonic() + 100)
        usermod._invalidate_settings_cache()
        assert usermod._settings_cache_ts == 0 and usermod._settings_next_try_mono == 0

    def test_the_lock_is_released_after_a_failed_reload(self, clean_settings_cache, down):
        usermod.get_global_setting("k", None)
        assert usermod._settings_refresh_lock.acquire(blocking=False), "the refresh lock was left held"
        usermod._settings_refresh_lock.release()


class TestTheCooldownCountsFromTheEndOfTheFailure:
    """v5.68.0-beta.23 (Q158, item 3): beta.22 set `_settings_next_try = now + 5` from the reading taken BEFORE the connect. A failing connect that
    took 12 s (a 10 s timeout plus a pool creation) put the deadline 7 s in the past - the very next call connected again - and the threads that had
    waited behind the holder on a cold start re-checked against that past deadline and each connected too. The deadline is now taken from a monotonic
    clock AFTER the failed attempt ends, and a waiter re-checks with a fresh reading under the lock."""

    ATTEMPT_S = 12.0  # what the failing connect takes, on the stand-in clock

    @pytest.fixture
    def slow_down(self, monkeypatch):
        import threading

        clock = {"mono": 1000.0, "wall": 50000.0}
        guard = threading.Lock()
        attempts = []
        monkeypatch.setattr(time, "monotonic", lambda: clock["mono"])
        monkeypatch.setattr(time, "time", lambda: clock["wall"])

        @contextlib.contextmanager
        def jen_db():
            with guard:
                attempts.append((clock["mono"], clock["wall"]))
            time.sleep(0.05)  # real time, so the other threads queue behind this one
            with guard:  # ... and the failure takes ATTEMPT_S on the clock the code reads
                clock["mono"] += self.ATTEMPT_S
                clock["wall"] += self.ATTEMPT_S
            raise pymysql.err.OperationalError(2003, "Can't connect to MySQL server")
            yield  # pragma: no cover

        monkeypatch.setattr(dbmod, "jen_db", jen_db)
        return type("SlowDown", (), {"clock": clock, "attempts": attempts})

    def test_after_a_twelve_second_failure_the_very_next_call_does_not_connect_and_the_next_one_waits_five_seconds_from_its_end(
        self, clean_settings_cache, slow_down
    ):
        assert usermod.get_global_setting("k", "dflt") == "dflt"
        first_started, first_ended = slow_down.attempts[0][0], slow_down.clock["mono"]
        assert first_ended - first_started == self.ATTEMPT_S
        assert usermod.get_global_setting("k", "dflt") == "dflt" and len(slow_down.attempts) == 1, (
            "inside the cooldown: a deadline taken before the connect would already have passed (12 s > 5 s) and this call would connect"
        )
        slow_down.clock["mono"] = first_ended + usermod._SETTINGS_RETRY_S - 0.1
        slow_down.clock["wall"] += usermod._SETTINGS_RETRY_S - 0.1
        usermod.get_global_setting("k", "dflt")
        assert len(slow_down.attempts) == 1, "4.9 s after the failure ENDED"
        slow_down.clock["mono"] = first_ended + usermod._SETTINGS_RETRY_S + 0.1
        slow_down.clock["wall"] += 0.2
        usermod.get_global_setting("k", "dflt")
        assert len(slow_down.attempts) == 2, "5.1 s after it ended: eligible again"
        print(
            f"COOLDOWN failure ran {first_started:.1f}..{first_ended:.1f} (12 s); next call at {first_ended:.1f}: no connect; "
            f"4.9 s later: no connect; 5.1 s later ({slow_down.attempts[1][0]:.1f}): connect"
        )

    def test_ten_waiters_on_a_cold_start_make_one_connect_whatever_the_failure_took(
        self, clean_settings_cache, slow_down, monkeypatch
    ):
        import threading

        monkeypatch.setattr(usermod, "_settings_ever_loaded", False)
        results = []
        barrier = threading.Barrier(10)

        def go():
            barrier.wait(10)
            results.append(usermod.get_global_setting("k", "dflt"))

        pool = [threading.Thread(target=go) for _ in range(10)]
        for th in pool:
            th.start()
        for th in pool:
            th.join(30)
        assert len(results) == 10 and set(results) == {"dflt"}
        assert len(slow_down.attempts) == 1, (
            f"{len(slow_down.attempts)} connects: a waiter re-checked against a deadline that expired while the holder was failing"
        )

    def test_the_cache_ttl_is_still_wall_time(self, clean_settings_cache, monkeypatch):
        monkeypatch.setattr(usermod, "_settings_cache", {"k": "v"})
        monkeypatch.setattr(usermod, "_settings_cache_ts", time.time())
        monkeypatch.setattr(
            dbmod, "jen_db", lambda: (_ for _ in ()).throw(AssertionError("a fresh cache must not reload"))
        )
        assert usermod.get_global_setting("k", "dflt") == "v"


class TestTheKea6PoolIsThrottledToo:
    """v5.68.0-beta.22 (Q157, item 10): `get_kea6_db` still created its pool and direct-connected INSIDE `_pool_lock` with no failure mark - the shape
    Q156 fixed for the jen and kea pools. A separate, down v6 lease host cost ~20 s per call and serialised every other database caller."""

    @pytest.fixture
    def broken(self, monkeypatch):
        monkeypatch.setattr(dbmod, "_kea6_targets_same_db", lambda: False)
        monkeypatch.setattr(dbmod, "_kea6_pool", None)
        monkeypatch.setattr(dbmod, "_pool_failed_at", {})
        made, connects, held = [], [], []

        def make():
            made.append(1)
            raise pymysql.err.OperationalError(2003, "pool: can't connect")

        def connect(**kw):
            connects.append(kw.get("host"))
            held.append(dbmod._pool_lock.locked())
            raise pymysql.err.OperationalError(2003, "direct: can't connect")

        monkeypatch.setattr(dbmod, "_make_kea6_pool", make)
        monkeypatch.setattr(dbmod.pymysql, "connect", connect)
        return made, connects, held

    def test_twenty_calls_make_the_pool_once_and_dial_directly_each_time_outside_the_lock(self, broken):
        made, connects, held = broken
        for _ in range(20):
            with pytest.raises(pymysql.err.OperationalError, match="direct"):
                dbmod.get_kea6_db()
        assert len(made) == 1 and len(connects) == 20
        assert not any(held), "the direct connect ran while holding the pool lock"

    def test_the_pool_is_attempted_again_after_the_window(self, broken, monkeypatch):
        made, _connects, _held = broken
        clock = {"now": 100.0}
        monkeypatch.setattr(dbmod.time, "monotonic", lambda: clock["now"])
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_kea6_db()
        clock["now"] += dbmod._POOL_RETRY_S + 0.1
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_kea6_db()
        assert len(made) == 2

    def test_resetting_the_kea_pools_clears_the_kea6_mark(self, broken):
        made, _connects, _held = broken
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_kea6_db()
        dbmod.reset_kea_pools()
        with pytest.raises(pymysql.err.OperationalError):
            dbmod.get_kea6_db()
        assert len(made) == 2

    def test_the_three_pools_share_the_one_throttle(self):
        import inspect

        for fn in (dbmod.get_jen_db, dbmod.get_kea_db, dbmod.get_kea6_db):
            source = inspect.getsource(fn)
            assert "_pool_recently_failed(" in source and "_pool_failed_at[" in source, fn.__name__
