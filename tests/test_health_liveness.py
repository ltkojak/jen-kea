"""
tests/test_health_liveness.py
─────────────────────────────
v5.68.0-beta.19 (Q154) - Health proves liveness, not "was started once". `_background_workers` read "scheduler + alert loop running" from
`STARTED_AT is not None`, and `start_scheduler` catches its own failure and logs it, so a scheduler that never started was green forever; the
Problems sweep row said "skip - has not run yet" with no age limit. Both now look at what is actually alive and give a grace period, then fail.
No database: `background.liveness` and `client_problems.read_status` are stand-ins. `pytest --noconftest tests/test_health_liveness.py`.
"""

import time
from datetime import datetime, timedelta, timezone

import pytest

from jen import extensions
from jen.services import background, health
from jen.services import client_problems as cp
from jen.services import scheduler as sched

CORE = list(sched.CORE_JOB_IDS)
NOW = datetime(2026, 10, 7, 12, 0, 0)  # naive UTC, the module's own convention


def _live(
    *,
    scheduler_exists=True,
    running=True,
    jobs=None,
    alert=True,
    periodic=True,
    error="",
    dispatcher=True,
    depth=0,
    age=0.0,
    current=None,
    oldest=None,
    dropped_recent=0,
    dropped_total=None,
    plugin_jobs=None,
):
    return {
        "started_at": datetime.now(timezone.utc),
        "alert_thread": alert,
        "periodic_thread": periodic,
        "dispatcher": dispatcher,
        "queue_depth": depth,
        "dispatcher_status": {
            "running": dispatcher,
            "queue_depth": depth,
            "current_age_s": current if dispatcher else None,
            "oldest_queued_age_s": oldest if dispatcher else None,
            "last_dispatch_age_s": age if dispatcher else None,
            "dropped_recent": dropped_recent,
            "dropped_total": dropped_recent if dropped_total is None else dropped_total,
        },
        "periodic_jobs": plugin_jobs or [],
        "scheduler": {
            "exists": scheduler_exists,
            "running": running,
            "jobs": CORE if jobs is None else jobs,
            "error": error,
        },
    }


@pytest.fixture
def started(monkeypatch):
    monkeypatch.setattr(background, "STARTED_AT", datetime.now(timezone.utc) - timedelta(hours=2))


def _workers(monkeypatch, live):
    monkeypatch.setattr(background, "liveness", lambda: live)
    return health._background_workers({})


class TestBackgroundWorkersProveLiveness:
    def test_healthy_is_ok_and_says_what_is_alive(self, started, monkeypatch):
        c = _workers(monkeypatch, _live())
        assert c.status == "ok" and "alert loop" in c.detail and "4 jobs" in c.detail

    def test_the_test_server_is_still_a_skip(self, monkeypatch):
        monkeypatch.setattr(background, "STARTED_AT", None)
        assert health._background_workers({}).status == "skip"

    def test_a_scheduler_that_never_existed_fails_with_the_reason(self, started, monkeypatch):
        c = _workers(
            monkeypatch, _live(scheduler_exists=False, running=False, jobs=[], error="APScheduler is not installed")
        )
        assert (
            c.status == "fail"
            and "the scheduler is not running" in c.detail
            and "APScheduler is not installed" in c.detail
        )

    def test_a_scheduler_whose_start_raised_fails_with_the_exception(self, started, monkeypatch):
        c = _workers(monkeypatch, _live(running=False, error="the scheduler failed to start (RuntimeError: boom)"))
        assert c.status == "fail" and "RuntimeError: boom" in c.detail

    def test_a_scheduler_stopped_later_fails(self, started, monkeypatch):
        assert _workers(monkeypatch, _live(running=False)).status == "fail"

    def test_a_missing_core_job_is_named(self, started, monkeypatch):
        c = _workers(monkeypatch, _live(jobs=[j for j in CORE if j != "jen_client_problems_sweep"]))
        assert c.status == "fail" and "jen_client_problems_sweep" in c.detail

    @pytest.mark.parametrize(
        "kwargs,words", [({"alert": False}, "alert loop thread"), ({"periodic": False}, "periodic-job thread")]
    )
    def test_a_dead_thread_is_named(self, started, monkeypatch, kwargs, words):
        c = _workers(monkeypatch, _live(**kwargs))
        assert c.status == "fail" and words in c.detail


class TestTheSchedulerReportsItself:
    def test_status_before_anything_started(self, monkeypatch):
        monkeypatch.setattr(sched, "_scheduler", None)
        monkeypatch.setattr(sched, "_start_error", "")
        assert sched.scheduler_status() == {"exists": False, "running": False, "jobs": [], "error": ""}

    def test_start_scheduler_records_a_start_failure(self, monkeypatch):
        pytest.importorskip("apscheduler")
        from apscheduler.schedulers.background import BackgroundScheduler

        def refuse(self, *a, **k):
            raise RuntimeError("cannot start")

        monkeypatch.setattr(BackgroundScheduler, "start", refuse)
        monkeypatch.setattr(sched, "_scheduler", None)
        sched.start_scheduler(app=object())
        status = sched.scheduler_status()
        assert status["exists"] and not status["running"] and "cannot start" in status["error"]
        assert set(status["jobs"]) == set(CORE), "every core job is registered even though the start failed"

    def test_a_running_scheduler_lists_its_core_jobs(self, monkeypatch):
        pytest.importorskip("apscheduler")
        monkeypatch.setattr(sched, "_scheduler", None)
        sched.start_scheduler(app=object())
        try:
            status = sched.scheduler_status()
            assert status["running"] and status["error"] == "" and set(CORE) <= set(status["jobs"])
        finally:
            sched.stop_scheduler()

    def test_liveness_reads_real_threads(self, monkeypatch):
        import threading

        gate = threading.Event()
        t = threading.Thread(target=gate.wait, daemon=True)
        t.start()
        monkeypatch.setattr(background, "_alert_thread", t)
        monkeypatch.setattr(background, "_periodic_thread", None)
        live = background.liveness()
        assert live["alert_thread"] is True and live["periodic_thread"] is False
        gate.set()
        t.join(2)
        assert background.liveness()["alert_thread"] is False


class TestTheProblemsSweepRowHasANoRunLimit:
    @pytest.fixture(autouse=True)
    def _world(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}])
        monkeypatch.setattr(cp, "_now", lambda: NOW)
        monkeypatch.setattr(cp, "read_status", lambda servers=None: {"swept_at": None, "servers": []})

    def _started(self, monkeypatch, minutes_ago):
        monkeypatch.setattr(
            background, "STARTED_AT", (NOW - timedelta(minutes=minutes_ago)).replace(tzinfo=timezone.utc)
        )

    def test_the_first_minutes_after_start_are_a_skip(self, monkeypatch):
        self._started(monkeypatch, 3)
        c = health._problems_sweep({})
        assert c.status == "skip" and "has not run yet" in c.detail

    def test_thirty_minutes_with_no_run_is_a_failure(self, monkeypatch):
        self._started(monkeypatch, 31)
        c = health._problems_sweep({})
        assert c.status == "fail" and "has never run" in c.detail and "31 minutes" in c.detail

    def test_exactly_inside_the_grace_period_is_still_a_skip(self, monkeypatch):
        self._started(monkeypatch, cp.MISS_LIMIT * cp.SWEEP_INTERVAL_S // 60 - 1)
        assert health._problems_sweep({}).status == "skip"

    def test_the_test_server_with_no_workers_stays_a_skip(self, monkeypatch):
        monkeypatch.setattr(background, "STARTED_AT", None)
        assert health._problems_sweep({}).status == "skip"

    def test_a_sweep_that_has_run_is_judged_as_before(self, monkeypatch):
        self._started(monkeypatch, 600)
        monkeypatch.setattr(
            cp,
            "read_status",
            lambda servers=None: {
                "swept_at": NOW - timedelta(minutes=2),
                "servers": [
                    {"id": 1, "name": "kea-a", "last_read": NOW - timedelta(minutes=2), "last_error": "", "misses": 0}
                ],
            },
        )
        assert health._problems_sweep({}).status == "ok"


class TestTheEventDispatcherIsTheFourthWorker:
    """v5.68.0-beta.20 (Q155, item 8). `events.dispatcher_running()` existed and nothing read it: with the dispatcher thread dead `emit()` does not fail, it
    runs every subscriber INLINE on the thread that emitted - and Health stayed green."""

    def test_a_running_dispatcher_is_ok_and_its_queue_depth_is_shown(self, started, monkeypatch):
        c = _workers(monkeypatch, _live(depth=3))
        assert c.status == "ok" and "event dispatcher (3 queued)" in c.detail

    def test_a_stopped_dispatcher_with_the_others_alive_is_a_failure_that_says_what_it_means(
        self, started, monkeypatch
    ):
        """beta.20 made this a warning; beta.21 (Q156, item 10) makes a DEAD dispatcher thread a failure - a WEDGED one is the warning below."""
        c = _workers(monkeypatch, _live(dispatcher=False))
        assert c.status == "fail", "subscribers now run inline on the emitting thread, silently"
        assert "event dispatcher not running" in c.detail and "inline" in c.detail

    @pytest.mark.parametrize(
        "kwargs",
        [{"alert": False}, {"periodic": False}, {"running": False}, {"jobs": ["jen_backup"]}],
    )
    def test_any_other_worker_down_is_a_failure_even_with_the_dispatcher_up(self, started, monkeypatch, kwargs):
        assert _workers(monkeypatch, _live(**kwargs)).status == "fail"

    def test_the_dispatcher_down_with_another_worker_down_is_a_failure_naming_both(self, started, monkeypatch):
        c = _workers(monkeypatch, _live(alert=False, dispatcher=False))
        assert c.status == "fail" and "alert loop" in c.detail and "event dispatcher" in c.detail

    def test_liveness_reads_the_real_dispatcher_and_its_queue(self, monkeypatch):
        from jen.services import events

        events.stop_dispatcher()
        assert background.liveness()["dispatcher"] is False
        events.start_dispatcher()
        try:
            live = background.liveness()
            assert live["dispatcher"] is True and isinstance(live["queue_depth"], int)
        finally:
            events.stop_dispatcher()
        assert background.liveness()["dispatcher"] is False

    def test_the_dispatcher_really_stopped_is_not_ok_through_the_whole_chain(self, started, monkeypatch):
        """No stand-in dictionary: the real `liveness()` with the real dispatcher stopped and the other three presented as alive."""
        from jen.services import events

        events.stop_dispatcher()
        real = background.liveness()
        monkeypatch.setattr(
            background,
            "liveness",
            lambda: {**real, "alert_thread": True, "periodic_thread": True, "scheduler": _live()["scheduler"]},
        )
        assert health._background_workers({}).status == "fail"


def _job(plugin="ipam", name="scan", every=10, running=False, started_min_ago=None, history=None, error=""):
    started = datetime.now(timezone.utc) - timedelta(minutes=started_min_ago) if started_min_ago is not None else None
    return {
        "plugin_id": plugin,
        "name": name,
        "every_minutes": every,
        "running": running,
        "last_started": started,
        "last_finished": None,
        "last_error": error,
        "history": history or [],
    }


class TestAWedgedOrFailingPluginJobIsVisible:
    """v5.68.0-beta.21 (Q156, item 9): `periodic_jobs()` carries last_error / running / last_started and nothing outside the tests read it. A job still
    `running` is skipped for ever, and `_run_one_periodic` had no deadline - one wedged plugin job stopped that plugin's scheduled work permanently
    and nothing said so."""

    def test_a_job_running_for_more_than_twice_its_interval_fails_the_row_and_names_it(self, started, monkeypatch):
        c = _workers(
            monkeypatch,
            _live(plugin_jobs=[_job("network-discovery", "sweep", every=10, running=True, started_min_ago=25)]),
        )
        assert c.status == "fail"
        assert "network-discovery/sweep" in c.detail and "wedged" in c.detail

    def test_a_job_running_within_twice_its_interval_is_fine(self, started, monkeypatch):
        c = _workers(monkeypatch, _live(plugin_jobs=[_job(every=10, running=True, started_min_ago=19)]))
        assert c.status == "ok"

    def test_a_job_that_is_not_running_is_never_wedged_however_old_its_last_start(self, started, monkeypatch):
        assert _workers(monkeypatch, _live(plugin_jobs=[_job(running=False, started_min_ago=600)])).status == "ok"

    def test_three_failures_in_a_row_is_a_warning_with_the_last_error(self, started, monkeypatch):
        c = _workers(
            monkeypatch,
            _live(plugin_jobs=[_job("dns-sync", "push", history=[False, False, False], error="provider returned 502")]),
        )
        assert c.status == "warn"
        assert "dns-sync/push" in c.detail and "failed its last three runs" in c.detail and "502" in c.detail

    def test_two_failures_or_a_recovery_in_the_last_three_is_not_a_warning(self, started, monkeypatch):
        for history in ([False, False], [False, True, False], [True, False, False]):
            assert _workers(monkeypatch, _live(plugin_jobs=[_job(history=history)])).status == "ok", history

    def test_a_wedged_job_outranks_a_failing_one(self, started, monkeypatch):
        jobs = [_job("a", "x", history=[False] * 3), _job("b", "y", every=5, running=True, started_min_ago=30)]
        c = _workers(monkeypatch, _live(plugin_jobs=jobs))
        assert c.status == "fail" and "b/y" in c.detail


class TestPeriodicJobBookkeeping:
    @pytest.fixture(autouse=True)
    def _clean(self):
        background._periodic.clear()
        yield
        background._periodic.clear()

    def test_a_blocking_job_is_running_and_the_row_fails_after_the_deadline(self, started, monkeypatch):
        import threading

        release = threading.Event()
        background.register_periodic("slowplug", "block", lambda: release.wait(30), 5)
        try:
            now = datetime.now(timezone.utc)
            background._periodic[0]["next_due"] = now - timedelta(minutes=30)
            assert (
                background.run_due_periodic_jobs(now=now - timedelta(minutes=11)) == 1
            )  # "started" eleven minutes ago: 2 x 5 + 1
            (job,) = background.periodic_jobs()
            assert job["running"] is True and job["last_finished"] is None
            monkeypatch.setattr(background, "liveness", lambda: _live(plugin_jobs=background.periodic_jobs()))
            check = health._background_workers({})
            assert check.status == "fail" and "slowplug/block" in check.detail
        finally:
            release.set()

    def test_a_spawn_that_raises_leaves_running_false_and_records_the_error(self):
        background.register_periodic("plug", "job", lambda: None, 5)
        background._periodic[0]["next_due"] = datetime.now(timezone.utc) - timedelta(minutes=1)

        def boom(job):
            raise RuntimeError("can't start new thread")

        started = background.run_due_periodic_jobs(spawn=boom)
        (job,) = background.periodic_jobs()
        assert started == 0 and job["running"] is False
        assert "could not start" in job["last_error"] and job["history"] == [False]

    def test_a_job_that_could_not_start_is_tried_again_soon_not_a_whole_interval_later(self):
        """beta.21 advanced `next_due` by the interval BEFORE the spawn and the failure branch did not put it back; its test reset `next_due` by hand
        before the second run, which is the thing the claim ("the next tick tries again") depends on. Q157: the schedule is the code's, not the test's."""
        calls = []
        background.register_periodic("plug", "job", lambda: calls.append(1), 10)
        entry = background._periodic[0]
        now = datetime.now(timezone.utc)
        entry["next_due"] = now - timedelta(minutes=1)

        def boom(job):
            raise RuntimeError("no threads")

        background.run_due_periodic_jobs(now=now, spawn=boom)
        assert entry["start_failures"] == 1 and entry["next_due"] == now + timedelta(seconds=60), (
            entry["next_due"] - now
        )
        # nothing before the retry time, and the very next call after it runs the job - with next_due untouched by the test
        assert background.run_due_periodic_jobs(now=now + timedelta(seconds=59), spawn=boom) == 0
        assert (
            background.run_due_periodic_jobs(now=now + timedelta(seconds=61), spawn=background._run_one_periodic) == 1
        )
        assert calls == [1] and entry["history"] == [False, True] and entry["start_failures"] == 0

    def test_repeated_start_failures_back_off_to_the_interval_and_no_further(self):
        background.register_periodic("plug", "job", lambda: None, 5)
        entry = background._periodic[0]
        now = datetime.now(timezone.utc)
        waits = []

        def boom(job):
            raise RuntimeError("no threads")

        for _ in range(6):
            entry["next_due"] = now
            background.run_due_periodic_jobs(now=now, spawn=boom)
            waits.append(int((entry["next_due"] - now).total_seconds()))
        assert waits == [60, 120, 240, 300, 300, 300], waits  # 60 x 2^(n-1), capped at the 5-minute interval

    def test_a_real_thread_start_that_raises_is_handled_the_same_way(self, monkeypatch):
        import threading

        background.register_periodic("plug", "job", lambda: None, 5)
        entry = background._periodic[0]
        now = datetime.now(timezone.utc)
        entry["next_due"] = now - timedelta(minutes=1)

        class NoThreads:
            def __init__(self, *a, **k):
                pass

            def start(self):
                raise RuntimeError("can't start new thread")

        monkeypatch.setattr(threading, "Thread", NoThreads)
        assert background.run_due_periodic_jobs(now=now) == 0
        assert entry["running"] is False and entry["next_due"] == now + timedelta(seconds=60)

    def test_a_run_records_when_it_finished_and_keeps_the_last_three_outcomes(self):
        outcomes = iter([True, False, False, False, True])

        def fn():
            if not next(outcomes):
                raise ValueError("bad")

        background.register_periodic("plug", "job", fn, 5)
        job = background._periodic[0]
        for _ in range(5):
            job["running"] = True
            background._run_one_periodic(job)
        assert job["history"] == [False, False, True] and job["last_finished"] is not None and job["running"] is False

    def test_liveness_carries_the_jobs(self):
        background.register_periodic("plug", "job", lambda: None, 5)
        assert [j["name"] for j in background.liveness()["periodic_jobs"]] == ["job"]


class TestTheDispatcherIsJudgedByWhatIsWaitingNow:
    """v5.68.0-beta.21 (Q156, item 10) put the dispatcher's depth and last-dispatch age in Health; v5.68.0-beta.22 (Q157, item 4) judges it by what is
    waiting NOW. `_last_dispatch_at` is stamped when an event FINISHES, so after an idle hour the first burst - or one slow first subscriber - read
    as "stuck" while the first event had been in flight for milliseconds; and the lifetime drop total warned for the rest of the process after one
    historical overflow. The Health row now reads the event the dispatcher is on (`current_age_s`), the oldest one still queued
    (`oldest_queued_age_s`) and the drops of the last 10 minutes (`dropped_recent`)."""

    @pytest.fixture(autouse=True)
    def _no_drops_from_other_tests(self, monkeypatch):
        """test_events overflows the queue on purpose; its drops are 'recent' for ten minutes of wall clock, and the whole suite runs in less."""
        from jen.services import events

        monkeypatch.setattr(events, "_drop_times", events.collections.deque(maxlen=1000))
        monkeypatch.setattr(events, "_dropped_total", 0)

    def test_a_subscriber_running_for_more_than_a_minute_warns_and_names_the_age(self, started, monkeypatch):
        c = _workers(monkeypatch, _live(depth=7, current=90.0, oldest=88.0))
        assert (
            c.status == "warn"
            and "stuck" in c.detail
            and "90 s" in c.detail
            and "7 event(s) queued behind it" in c.detail
        )

    def test_an_old_queued_event_behind_a_moving_dispatcher_warns_as_behind(self, started, monkeypatch):
        c = _workers(monkeypatch, _live(depth=40, current=0.2, oldest=75.0))
        assert c.status == "warn" and "behind" in c.detail and "75 s" in c.detail

    def test_a_busy_but_moving_dispatcher_is_fine(self, started, monkeypatch):
        assert _workers(monkeypatch, _live(depth=300, current=0.3, oldest=2.0)).status == "ok"

    def test_an_idle_hour_then_a_burst_is_not_stuck(self, started, monkeypatch):
        """The beta.21 rule (depth > 0 and the last FINISHED event more than 60 s ago) warned here: the dispatcher had been idle for an hour."""
        c = _workers(monkeypatch, _live(depth=25, age=3600.0, current=0.01, oldest=0.05))
        assert c.status == "ok", c.detail

    def test_an_idle_dispatcher_with_an_old_last_dispatch_is_fine(self, started, monkeypatch):
        assert _workers(monkeypatch, _live(depth=0, age=3600.0)).status == "ok"

    def test_recent_drops_warn_and_the_lifetime_total_is_only_text(self, started, monkeypatch):
        c = _workers(monkeypatch, _live(dropped_recent=12, dropped_total=40))
        assert (
            c.status == "warn"
            and "12 event deliveries were dropped in the last 10 minutes" in c.detail
            and "40 since Jen started" in c.detail
        )

    def test_an_old_overflow_no_longer_warns(self, started, monkeypatch):
        assert _workers(monkeypatch, _live(dropped_recent=0, dropped_total=500)).status == "ok"

    def test_the_status_of_a_real_dispatcher(self):
        from jen.services import events

        events.stop_dispatcher()
        status = events.dispatcher_status()
        assert status["running"] is False and status["last_dispatch_age_s"] is None and status["current_age_s"] is None
        events.start_dispatcher()
        try:
            status = events.dispatcher_status()
            assert status["running"] is True and status["queue_depth"] == 0 and status["last_dispatch_age_s"] < 5
            assert status["current_age_s"] is None and status["oldest_queued_age_s"] is None
            assert status["dropped_total"] == events._dropped_total
            assert set(status) >= {
                "running",
                "queue_depth",
                "current_age_s",
                "oldest_queued_age_s",
                "last_dispatch_age_s",
                "dropped_recent",
                "dropped_total",
            }
        finally:
            events.stop_dispatcher()

    def test_a_subscriber_that_blocks_makes_the_current_age_grow_and_the_row_warn(self, started, monkeypatch):
        import threading

        from jen.services import events

        gate, entered = threading.Event(), threading.Event()

        def blocker(event):
            entered.set()
            gate.wait(30)

        events.stop_dispatcher()
        events.subscribe("*", blocker)
        events.start_dispatcher()
        try:
            for _ in range(5):
                events.emit("config.applied", detail="q157")
            assert entered.wait(10), "the subscriber was never called"
            deadline = time.monotonic() + 5
            while events.queue_depth() < 4 and time.monotonic() < deadline:
                time.sleep(0.05)
            assert events.queue_depth() >= 4, "the queue did not grow behind the blocked subscriber"
            fresh = events.dispatcher_status()
            assert fresh["current_age_s"] is not None and fresh["current_age_s"] < 60, (
                "a blocked subscriber that just started is not yet stuck"
            )
            assert fresh["oldest_queued_age_s"] is not None and fresh["oldest_queued_age_s"] < 60
            # two minutes pass: the clock the dispatcher reads is shifted, not slept
            shift = 120.0
            real_monotonic = time.monotonic
            monkeypatch.setattr(events.time, "monotonic", lambda: real_monotonic() + shift)
            aged = events.dispatcher_status()
            assert aged["current_age_s"] >= 120 and aged["oldest_queued_age_s"] >= 120
            real = background.liveness()
            monkeypatch.setattr(
                background,
                "liveness",
                lambda: {**real, "alert_thread": True, "periodic_thread": True, "scheduler": _live()["scheduler"]},
            )
            check = health._background_workers({})
            assert check.status == "warn" and "stuck" in check.detail and "running for 1" in check.detail, check.detail
        finally:
            gate.set()
            events.unsubscribe(blocker)
            events.stop_dispatcher()

    def test_an_idle_hour_then_one_event_and_a_burst_on_the_real_dispatcher_is_not_stuck(self, started, monkeypatch):
        import threading

        from jen.services import events

        done = threading.Event()
        seen = []

        def collector(event):
            seen.append(event["detail"])
            if len(seen) >= 6:
                done.set()

        events.stop_dispatcher()
        events.subscribe("*", collector)
        events.start_dispatcher()
        try:
            monkeypatch.setattr(events, "_last_dispatch_at", time.monotonic() - 3600)  # idle for an hour
            for n in range(6):
                events.emit("config.applied", detail=f"burst-{n}")
            assert done.wait(10)
            status = events.dispatcher_status()
            assert status["current_age_s"] is None or status["current_age_s"] < 5
            assert status["oldest_queued_age_s"] is None or status["oldest_queued_age_s"] < 5
            real = background.liveness()
            monkeypatch.setattr(
                background,
                "liveness",
                lambda: {**real, "alert_thread": True, "periodic_thread": True, "scheduler": _live()["scheduler"]},
            )
            assert health._background_workers({}).status == "ok"
        finally:
            events.unsubscribe(collector)
            events.stop_dispatcher()

    def test_a_full_queue_counts_recent_and_total_and_the_recent_count_expires_after_ten_minutes(self, monkeypatch):
        import queue

        from jen.services import events

        monkeypatch.setattr(events, "_queue", queue.Queue(maxsize=1))
        monkeypatch.setattr(events, "dispatcher_running", lambda: True)
        monkeypatch.setattr(events, "_dropped_total", 0)
        monkeypatch.setattr(events, "_drop_times", events.collections.deque(maxlen=1000))
        monkeypatch.setattr("jen.models.db.jen_db", lambda: (_ for _ in ()).throw(RuntimeError("no db")))
        events.emit("config.applied", detail="one")
        events.emit("config.applied", detail="two")  # the queue (size 1) is full: dropped
        events.emit("config.applied", detail="three")
        assert events._dropped_total == 2
        status = events.dispatcher_status()
        assert status["dropped_recent"] == 2 and status["dropped_total"] == 2
        real_monotonic = time.monotonic
        monkeypatch.setattr(events.time, "monotonic", lambda: real_monotonic() + events.DROP_WINDOW_S + 1)
        later = events.dispatcher_status()
        assert later["dropped_recent"] == 0 and later["dropped_total"] == 2, (
            "a full queue that drains: the warning clears after 10 minutes"
        )

    def test_a_queued_event_carries_its_enqueue_time_and_subscribers_never_see_it(self, monkeypatch):
        import queue

        from jen.services import events

        q = queue.Queue(maxsize=5)
        monkeypatch.setattr(events, "_queue", q)
        monkeypatch.setattr(events, "dispatcher_running", lambda: True)
        monkeypatch.setattr("jen.models.db.jen_db", lambda: (_ for _ in ()).throw(RuntimeError("no db")))
        event = events.emit("config.applied", detail="x")
        queued = q.get_nowait()
        assert isinstance(queued, tuple) and queued[0] is event and isinstance(queued[1], float)
        assert "_enqueued_at" not in event and set(event) == {
            "id",
            "kind",
            "mac",
            "ip",
            "subnet_id",
            "hostname",
            "server",
            "actor",
            "detail",
        }
